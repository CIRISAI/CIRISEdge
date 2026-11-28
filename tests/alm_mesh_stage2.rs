//! **ALM stage 2 over REAL loopback Reticulum** (`FSD/CIRIS_MESH.md`;
//! edge v44.0.0): the C3 subscribe/admit frames on the A/V links, roster
//! relays before the canonical, stale-frame handling, and the service tier.
//!
//! - **Roster relay** (`a_member_unreachable_directly_is_heard_through_a_roster_relay`):
//!   members `A`, `B`, `C` and a canonical-shaped transport node `T` (not a
//!   member). `B` and `C` share no interface (each is a TCP client of `A` and
//!   of `T` only), so neither can dial the other's call address — the
//!   hard-NAT shape. Their streams reach each other through `A`, a ROSTER
//!   member that offers relay and ADMITTED them (C3), never through `T`.
//! - **C3 admit / refuse** (`c3_admits_and_a_closed_relay_refuses_by_name`):
//!   a publisher admits its subscriber; a relay at service tier 1 refuses a
//!   new subscription `load_refuse:admit_closed`.
//! - **Stale frames** (`stale_media_is_dropped_by_age_and_the_hop_recovers`):
//!   a consumer that falls 1.5 s behind drops the media older than 800 ms by
//!   age, the hop counter skips past it, and later frames open and arrive;
//!   media rides leviculum's timed Channel frames between C3 peers.
//! - **Epoch roll** (`an_epoch_roll_reads_as_a_resync_on_a_live_link`,
//!   CIRISEdge#945): a real room commit is a meter resync, not a loss burst.
//! - **Layered standby** (`a_layered_standby_is_not_read_as_lossy_on_a_live_call`,
//!   CIRISEdge#945): the layers a standby never owed are not loss.
//! - **Link close** (`a_closed_primary_link_fails_over_on_a_live_call`,
//!   CIRISEdge#945): a primary's link closing fails over at once to a standby
//!   that is still delivering, with no wait for silence.
//! - **Layered primary** (`a_capped_primary_is_not_read_as_lossy_on_a_live_call`,
//!   `a_publisher_at_tier_two_is_not_read_as_lossy_on_a_live_call`,
//!   `a_primary_dropping_base_is_read_as_lossy_on_a_live_call`, CIRISEdge#945):
//!   gaps are read within what the path owed, so a cap or a shed is no loss
//!   and a real base drop still is.
//! - **Depth 0** (`a_member_claiming_depth_zero_is_not_the_publisher`,
//!   CIRISEdge#945): only the publisher the binding names holds depth 0.
//! - **Re-announce** (`a_reannounce_is_spread_over_its_parts`, CIRISEdge#945):
//!   the periodic binding is no burst for the egress meter to take for the
//!   uplink.
//!
//! Requires `transport-reticulum`:
//! `cargo test --features "transport-http transport-reticulum" --test alm_mesh_stage2`

#![cfg(feature = "transport-reticulum")]

mod common;

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::mls::cohort_group::mint_cohort_key_material;
use ciris_edge::mls::{CohortGroup, ScopeStateProvider};
use ciris_edge::scope_addressing::{ScopeAddressTable, ScopePrivacyDeriver};
use ciris_edge::scope_lifecycle::{ScopeLifecycle, ScopedDestinationSink};
use ciris_edge::telemetry::call_legs::{CALL_BITRATE, CALL_LEG_INSTRUMENTS, CALL_PATH};
use ciris_edge::transport::av_call::{
    Call, CallDeps, CallEvent, CallOptions, Frame, ReceivedFrame, RoomRoster, REANNOUNCE_PART_GAP,
};
use ciris_edge::transport::av_chunk_auth::StreamKeyVerifier;
use ciris_edge::transport::av_keep::{AvKeepTarget, StreamDekRegistrar};
use ciris_edge::transport::realtime_av::{
    stream_label, ChunkLayer, ReceiverLayerPolicy, CODEC_AV1_SVC,
};
use ciris_edge::transport::realtime_av_alm::controller::wire::encode;
use ciris_edge::transport::realtime_av_alm::controller::{
    ControlMsg, DecisionKind, Offer, Role, SubscribeRequest,
};
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport as _};
use ciris_edge::verify::RootingDirectory;
use ciris_edge::EdgeMetrics;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::encrypted_kv::XChaChaKvStore;
use ciris_persist::federation::{BlobError, FederationDirectory};
use ciris_persist::store::sqlite::SqliteBackend;
use common::directory_with;
use sha2::Digest as _;
use tokio::sync::mpsc;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("addr")
        .port()
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,ciris_edge=info".into()),
        )
        .with_test_writer()
        .try_init();
}

async fn wait_until<F, Fut>(budget: Duration, mut done: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if done().await {
            return true;
        }
        if tokio::time::Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A production-shaped identity (as `direct_links_805`).
struct Ident {
    key_id: String,
    ed: Arc<Ed25519SoftwareSigner>,
    pqc: Arc<MlDsa65SoftwareSigner>,
    ed_pub: Vec<u8>,
    pqc_pub_b64: String,
}

impl Ident {
    async fn new(alias: &str, seed: u8) -> Self {
        let mut ed = Ed25519SoftwareSigner::new(alias);
        ed.import_key(&[seed; 32]).expect("import ed key");
        let pqc =
            MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], format!("{alias}-pqc"))
                .expect("ml-dsa from seed");
        let ed_pub = ed.public_key().await.expect("ed pubkey");
        let pqc_pub_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            pqc.public_key().await.expect("pqc pubkey"),
        );
        let key_id = ciris_verify_core::fedcode::derive_key_id(ed.current_alias(), &ed_pub);
        Self {
            key_id,
            ed: Arc::new(ed),
            pqc: Arc::new(pqc),
            ed_pub,
            pqc_pub_b64,
        }
    }
    fn signer(&self) -> Arc<LocalSigner> {
        let classical: Arc<dyn HardwareSigner> = Arc::clone(&self.ed) as Arc<dyn HardwareSigner>;
        let pqc: Arc<dyn PqcSigner> = Arc::clone(&self.pqc) as Arc<dyn PqcSigner>;
        Arc::new(LocalSigner::new(self.key_id.clone(), classical, Some(pqc)))
    }
    async fn record(&self) -> ciris_persist::federation::KeyRecord {
        let ed_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &self.ed_pub);
        let mut envelope = serde_json::json!({});
        ciris_persist::federation::admission::bind_subject_into_envelope(
            &mut envelope,
            &self.key_id,
            "node",
            &ed_b64,
            Some(&self.pqc_pub_b64),
            None,
        )
        .expect("bind subject");
        let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope).expect("canon");
        let digest = sha2::Sha256::digest(&canonical);
        let (sig_classical, sig_pqc) =
            sign_bound_hybrid(&self.signer(), &canonical, "self registration")
                .await
                .expect("hybrid self-scrub");
        let now = ciris_edge::replication::attestation_bind::truncate_to_substrate_resolution(
            chrono::Utc::now(),
        );
        ciris_persist::federation::KeyRecord {
            key_id: self.key_id.clone(),
            pubkey_ed25519_base64: ed_b64,
            pubkey_ml_dsa_65_base64: Some(self.pqc_pub_b64.clone()),
            algorithm: "hybrid".to_string(),
            identity_type: "node".to_string(),
            identity_ref: self.key_id.clone(),
            valid_from: now,
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash: hex::encode(digest),
            scrub_signature_classical: sig_classical,
            scrub_signature_pqc: sig_pqc,
            scrub_key_id: self.key_id.clone(),
            scrub_timestamp: now,
            pqc_completed_at: Some(now),
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: Some(
                ciris_persist::federation::hardware_attestation::test_support::fresh_accord_holder_evidence(),
            ),
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }
}

/// One edge node: its transport (listener running), metrics, table and
/// lifecycle.
struct Node {
    key: Ident,
    port: u16,
    dir: Arc<SqliteBackend>,
    transport: Arc<ReticulumTransport>,
    metrics: EdgeMetrics,
    lifecycle: Arc<ScopeLifecycle>,
    /// Identity-plane frames this node received that carry [`PROBE_MARKER`]:
    /// when, and the bytes.
    probes: ProbeLog,
    _edge: ciris_edge::Edge,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// What a probe envelope starts with (the 45.3 FIRST-class witness).
const PROBE_MARKER: &[u8] = b"W1PROBE:";
/// Bulk envelopes queued ahead of each probe.
const PROBE_FILLERS: usize = 10;
/// Probe envelopes a node heard: when, and the bytes.
type ProbeLog = Arc<std::sync::Mutex<Vec<(tokio::time::Instant, Vec<u8>)>>>;

async fn node(
    key: Ident,
    dir: Arc<SqliteBackend>,
    base: &std::path::Path,
    peers: &[u16],
    transport_on: bool,
) -> Node {
    let mut transport = None;
    let mut port = 0;
    for _ in 0..16 {
        let mut c = ReticulumTransportConfig::new(base.join("transport.id"), &key.key_id);
        port = free_port();
        c.listen_addr = format!("127.0.0.1:{port}").parse().unwrap();
        c.announce_interval = Duration::from_secs(3);
        c.enable_transport = transport_on;
        c.bootstrap_peers = peers
            .iter()
            .map(|p| format!("127.0.0.1:{p}").parse().unwrap())
            .collect();
        let auth = ReticulumAuth {
            signer: Some(key.signer()),
            rooting: Some(Arc::clone(&dir) as Arc<dyn RootingDirectory>),
            resolver: None,
            hybrid_policy: ciris_edge::HybridPolicy::Strict,
            blackhole_rules: Some(
                Arc::clone(&dir) as Arc<dyn ciris_persist::federation::BlackholeRules>
            ),
            ..ReticulumAuth::default()
        };
        match ReticulumTransport::new(c, auth).await {
            Ok(t) => {
                transport = Some(Arc::new(t));
                break;
            }
            Err(e)
                if e.to_string().contains("Address already in use")
                    || e.to_string().contains("os error 98") => {}
            Err(e) => panic!("build reticulum transport: {e:?}"),
        }
    }
    let transport = transport.expect("bind retries exhausted");
    let edge = ciris_edge::Edge::builder()
        .directory(Arc::clone(&dir) as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .federation_directory(Arc::clone(&dir) as Arc<dyn FederationDirectory>)
        .queue(Arc::clone(&dir) as Arc<dyn ciris_edge::outbound::OutboundHandle>)
        .signer(key.signer())
        .transport(Arc::clone(&transport) as Arc<dyn ciris_edge::transport::Transport>)
        .config(ciris_edge::EdgeConfig {
            hybrid_policy: ciris_edge::HybridPolicy::Strict,
            ..ciris_edge::EdgeConfig::default()
        })
        .build()
        .expect("build the edge");
    let metrics = edge.metrics();
    let table = Arc::new(ScopeAddressTable::new(Arc::new(ScopePrivacyDeriver)));
    transport
        .install_scope_address_table(Arc::clone(&table))
        .expect("install the table");
    let lifecycle = Arc::new(ScopeLifecycle::new(
        Arc::clone(&table),
        Arc::clone(&transport) as Arc<dyn ScopedDestinationSink>,
        key.key_id.clone(),
        Duration::from_mins(5),
    ));
    let (tx, mut rx) = mpsc::channel::<InboundFrame>(256);
    let listener = Arc::clone(&transport);
    let probes: ProbeLog = Arc::default();
    let heard = Arc::clone(&probes);
    let tasks = vec![
        tokio::spawn(async move {
            let _ = listener.listen(tx).await;
        }),
        tokio::spawn(async move {
            while let Some(f) = rx.recv().await {
                if f.envelope_bytes.starts_with(PROBE_MARKER) {
                    heard
                        .lock()
                        .expect("probes")
                        .push((tokio::time::Instant::now(), f.envelope_bytes));
                }
            }
        }),
    ];
    Node {
        key,
        port,
        dir,
        transport,
        metrics,
        lifecycle,
        probes,
        _edge: edge,
        _tasks: tasks,
    }
}

/// A roster that answers as told (persist's active roster, stubbed: the
/// community rows are not what these witnesses are about).
struct Roster(bool);

#[async_trait::async_trait]
impl RoomRoster for Roster {
    async fn is_active_member(&self, _room: &str, _key_id: &str) -> Result<bool, String> {
        Ok(self.0)
    }
}

/// A keep door that counts every call (A4).
#[derive(Default)]
struct CountingRegistrar(AtomicU64);

#[async_trait::async_trait]
impl StreamDekRegistrar for CountingRegistrar {
    async fn register_stream_epoch_dek(
        &self,
        _target: &AvKeepTarget,
        _stream_id: &str,
        _epoch: u64,
        _dek: &[u8; 32],
    ) -> Result<(), BlobError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn store(tag: &str) -> ScopeStateProvider {
    ScopeStateProvider::new(Arc::new(
        XChaChaKvStore::open_in_memory(tag.as_bytes()).expect("in-memory scope state"),
    ))
}

/// `n` nodes wired as `dials` says (node `j` bootstraps to every `i` with
/// `(i, j)` in it), each holding every other's signed route and knowing every
/// other; the room's MLS group spans the first `members`. Node `canonical`,
/// when given, forwards for others (`enable_transport`) and is NOT a member:
/// the canonical's shape.
async fn topo(
    tag: &str,
    n: usize,
    members: usize,
    dials: &[(usize, usize)],
    canonical: Option<usize>,
) -> (Vec<Node>, Vec<CohortGroup>, tempfile::TempDir) {
    topo_capped(tag, n, members, dials, canonical, None).await
}

/// A node's UPLINK as a shared bottleneck: every byte the node sends back
/// down a TCP link another node dialled to it waits its turn in ONE FIFO
/// drained at `bytes_per_s` (0: unlimited), with no queue limit — a
/// bufferbloated home or cellular uplink. What others send to the node
/// passes at once. Turned on after setup.
struct CappedUplink {
    bytes_per_s: AtomicU64,
    next_free: tokio::sync::Mutex<tokio::time::Instant>,
    /// The longest any byte has waited to leave (µs): the peak queue delay.
    peak_us: AtomicU64,
    /// ReceiverMoves (RM6) — a fixed delay (ms) on what OTHERS send this
    /// node: a slow downlink. 0: none.
    down_delay_ms: AtomicU64,
}

impl CappedUplink {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            bytes_per_s: AtomicU64::new(0),
            next_free: tokio::sync::Mutex::new(tokio::time::Instant::now()),
            peak_us: AtomicU64::new(0),
            down_delay_ms: AtomicU64::new(0),
        })
    }

    /// How long a byte handed over now waits to leave.
    async fn queue_now(&self) -> Duration {
        let next = *self.next_free.lock().await;
        next.saturating_duration_since(tokio::time::Instant::now())
    }

    /// Delay everything others send this node by `ms` (its downlink).
    fn delay_down_ms(&self, ms: u64) {
        self.down_delay_ms.store(ms, Ordering::SeqCst);
    }

    /// How long a byte handed over now waits to leave (ms), when the queue
    /// is not being written this instant.
    fn queue_ms(&self) -> Option<u64> {
        let next = self.next_free.try_lock().ok()?;
        Some(
            u64::try_from(
                next.saturating_duration_since(tokio::time::Instant::now())
                    .as_millis(),
            )
            .unwrap_or(u64::MAX),
        )
    }

    /// The peak queue delay so far, and reset it.
    fn take_peak(&self) -> Duration {
        Duration::from_micros(self.peak_us.swap(0, Ordering::SeqCst))
    }

    fn cap_kbit(&self, kbit: u64) {
        self.bytes_per_s.store(kbit * 1000 / 8, Ordering::SeqCst);
    }

    /// When `n` bytes handed over now leave the bottleneck.
    async fn due(&self, n: usize) -> tokio::time::Instant {
        let rate = self.bytes_per_s.load(Ordering::SeqCst);
        let now = tokio::time::Instant::now();
        if rate == 0 {
            return now;
        }
        let mut next = self.next_free.lock().await;
        let start = (*next).max(now);
        let done = start + Duration::from_micros(n as u64 * 1_000_000 / rate);
        *next = done;
        let waited = u64::try_from(done.duration_since(now).as_micros()).unwrap_or(u64::MAX);
        self.peak_us.fetch_max(waited, Ordering::SeqCst);
        done
    }
}

/// A pipe in front of `port`'s listener whose return direction (the node's
/// sends) rides `uplink`. Returns the port to dial instead.
async fn capped_listener(port: u16, uplink: Arc<CappedUplink>) -> u16 {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the capped pipe");
    let front = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                return;
            };
            let Ok(node) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await else {
                continue;
            };
            let _ = client.set_nodelay(true);
            let _ = node.set_nodelay(true);
            let (mut client_rx, mut client_tx) = client.into_split();
            let (mut node_rx, mut node_tx) = node.into_split();
            // The node's downlink: passes at once, or after the set delay.
            let (dtx, mut drx) = mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
            let down = Arc::clone(&uplink);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                while let Ok(n) = client_rx.read(&mut buf).await {
                    if n == 0 {
                        return;
                    }
                    let d = down.down_delay_ms.load(Ordering::SeqCst);
                    let due = tokio::time::Instant::now() + Duration::from_millis(d);
                    if dtx.send((due, buf[..n].to_vec())).is_err() {
                        return;
                    }
                }
            });
            tokio::spawn(async move {
                while let Some((due, bytes)) = drx.recv().await {
                    tokio::time::sleep_until(due).await;
                    if node_tx.write_all(&bytes).await.is_err() {
                        return;
                    }
                }
            });
            let (tx, mut rx) = mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
            let up = Arc::clone(&uplink);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                while let Ok(n) = node_rx.read(&mut buf).await {
                    if n == 0 {
                        return;
                    }
                    // Paced in small pieces, as a link drains: one read of
                    // a deep queue is many frames, and one due time for all
                    // of them would deliver them as one burst.
                    for piece in buf[..n].chunks(512) {
                        let due = up.due(piece.len()).await;
                        if tx.send((due, piece.to_vec())).is_err() {
                            return;
                        }
                    }
                }
            });
            tokio::spawn(async move {
                while let Some((due, bytes)) = rx.recv().await {
                    tokio::time::sleep_until(due).await;
                    if client_tx.write_all(&bytes).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    front
}

/// 45.3 — a node's WHOLE uplink as the server matrix shapes it: `tc qdisc
/// netem rate {cap}kbit limit 1000` on the node's interface. ONE FIFO for
/// everything the node sends on every link (media, C3 control, identity and
/// replication traffic, Channel proofs), drained at a byte rate, holding at
/// most [`NETEM_LIMIT_PACKETS`] packets and TAIL-DROPPING a packet that
/// finds it full; a packet's delay is the queue ahead of it over the rate.
///
/// A packet here is one RNS packet: the in-process links are TCP, so the
/// pipe splits the node's byte stream at its HDLC frame boundaries (leviculum
/// frames every packet `0x7E … 0x7E`, nothing inside escapes to a raw flag)
/// and queues each frame as one packet, as the matrix's UDP and punched links
/// carry one RNS packet per datagram. A dropped frame is gone, as a dropped
/// datagram is: TCP's own retransmission would hide the loss the matrix
/// sees. Each packet is charged its bytes plus [`NETEM_OVERHEAD_BYTES`] (the
/// IP and UDP headers netem's rate counts). What others send the node passes
/// at once. Test-only; off (no rate, no limit, no delay) until capped.
struct NetemUplink {
    bytes_per_s: AtomicU64,
    q: std::sync::Mutex<std::collections::VecDeque<(u64, Vec<u8>)>>,
    wake: tokio::sync::Notify,
    conns: std::sync::Mutex<std::collections::HashMap<u64, mpsc::UnboundedSender<Vec<u8>>>>,
    next_conn: AtomicU64,
    enqueued: AtomicU64,
    dropped: AtomicU64,
    sent_packets: AtomicU64,
    sent_bytes: AtomicU64,
    backlog_bytes: AtomicU64,
    /// The packet limit (default [`NETEM_LIMIT_PACKETS`]).
    limit: AtomicU64,
    /// Media datagrams handed to the shaper (cumulative packets, bytes).
    media_packets: AtomicU64,
    media_bytes: AtomicU64,
    /// Audio datagrams (cumulative packets, wire bytes with the overhead).
    audio_packets: AtomicU64,
    audio_bytes: AtomicU64,
    /// The same for 60 ms audio packets (≥ 390 B).
    audio_long_packets: AtomicU64,
    audio_long_bytes: AtomicU64,
    /// What the node handed the shaper since the last
    /// [`NetemUplink::take_classes`], by [`rns_class`] and link.
    classes: std::sync::Mutex<ClassMap>,
}

/// What a node handed its shaper, by [`rns_class`] and link.
type ClassMap = std::collections::HashMap<(&'static str, Option<[u8; 16]>), ClassCount>;

/// One class's share of what a node handed its shaper.
#[derive(Debug, Clone, Copy, Default)]
struct ClassCount {
    packets: u64,
    bytes: u64,
    dropped: u64,
}

/// netem's `limit`: the packets its queue holds (the server's 1000).
const NETEM_LIMIT_PACKETS: usize = 1000;

/// The class of one HDLC-framed RNS packet (IFAC off, as in the harness), and
/// the link it rides when its destination is a link: packet type, then
/// context (leviculum `packet.rs`; `0xF0` is +ciris Datagram, the media lane).
fn rns_class(frame: &[u8]) -> (&'static str, Option<[u8; 16]>) {
    let mut b = Vec::with_capacity(48);
    let mut esc = false;
    for &x in frame {
        if b.len() >= 48 {
            break;
        }
        match (esc, x) {
            (_, 0x7E) => {}
            (false, 0x7D) => esc = true,
            (true, _) => {
                b.push(x ^ 0x20);
                esc = false;
            }
            (false, _) => b.push(x),
        }
    }
    let Some(&flags) = b.first() else {
        return ("empty", None);
    };
    if flags & 0x80 != 0 {
        return ("ifac", None);
    }
    let header_2 = flags & 0x40 != 0;
    let dest_at = if header_2 { 18 } else { 2 };
    let ctx = b.get(dest_at + 16).copied();
    let link = if (flags >> 2) & 0x03 == 0x03 {
        b.get(dest_at..dest_at + 16)
            .and_then(|d| <[u8; 16]>::try_from(d).ok())
    } else {
        None
    };
    let class = match (flags & 0x03, ctx) {
        (0x01, _) => "announce",
        (0x02, _) => "link_request",
        (0x03, Some(0xFF)) => "lrproof",
        (0x03, _) => "proof",
        (_, Some(0xF0)) => "media_datagram",
        (_, Some(0x0E)) => "channel",
        (_, Some(0xFA)) => "keepalive",
        (_, Some(0x01..=0x07)) => "resource",
        (_, Some(0x09)) => "request",
        (_, Some(0x0A)) => "response",
        (_, Some(0xFB)) => "link_identify",
        (_, Some(0xFC)) => "link_close",
        (_, Some(0xFE)) => "lrrtt",
        (_, Some(0x00)) => "data",
        _ => "data_other",
    };
    (class, link)
}
/// What netem's rate counts on top of an RNS packet: IPv4 (20) + UDP (8).
const NETEM_OVERHEAD_BYTES: u64 = 28;

/// One second of a [`NetemUplink`]'s counters.
#[derive(Debug, Clone, Copy, Default)]
struct NetemSecond {
    enqueued: u64,
    dropped: u64,
    sent_packets: u64,
    sent_bytes: u64,
    backlog_packets: u64,
    backlog_bytes: u64,
}

impl NetemUplink {
    fn new() -> Arc<Self> {
        let u = Arc::new(Self {
            bytes_per_s: AtomicU64::new(0),
            q: std::sync::Mutex::new(std::collections::VecDeque::new()),
            wake: tokio::sync::Notify::new(),
            conns: std::sync::Mutex::new(std::collections::HashMap::new()),
            next_conn: AtomicU64::new(0),
            enqueued: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            sent_packets: AtomicU64::new(0),
            sent_bytes: AtomicU64::new(0),
            backlog_bytes: AtomicU64::new(0),
            limit: AtomicU64::new(NETEM_LIMIT_PACKETS as u64),
            media_packets: AtomicU64::new(0),
            media_bytes: AtomicU64::new(0),
            audio_packets: AtomicU64::new(0),
            audio_bytes: AtomicU64::new(0),
            audio_long_packets: AtomicU64::new(0),
            audio_long_bytes: AtomicU64::new(0),
            classes: std::sync::Mutex::new(std::collections::HashMap::new()),
        });
        let d = Arc::clone(&u);
        tokio::spawn(async move { d.drain().await });
        u
    }

    /// Cap the uplink at `kbit` (0: lift; what is queued then leaves at once).
    fn cap_kbit(&self, kbit: u64) {
        self.bytes_per_s.store(kbit * 1000 / 8, Ordering::SeqCst);
        self.wake.notify_one();
    }

    fn register(&self, tx: mpsc::UnboundedSender<Vec<u8>>) -> u64 {
        let id = self.next_conn.fetch_add(1, Ordering::SeqCst);
        self.conns.lock().expect("conns").insert(id, tx);
        id
    }

    /// One packet the node sends on `conn`: queued, or tail-dropped when the
    /// capped queue is full.
    fn push(&self, conn: u64, pkt: Vec<u8>) {
        let capped = self.bytes_per_s.load(Ordering::SeqCst) > 0;
        let mut key = rns_class(&pkt);
        if key.0 == "media_datagram" && pkt.len() < AUDIO_PACKET_MAX {
            key.0 = "media_audio";
        }
        let limit = usize::try_from(self.limit.load(Ordering::SeqCst)).unwrap_or(usize::MAX);
        {
            let mut q = self.q.lock().expect("q");
            let full = capped && q.len() >= limit;
            {
                let mut c = self.classes.lock().expect("classes");
                let e = c.entry(key).or_default();
                e.packets += 1;
                e.bytes += pkt.len() as u64;
                e.dropped += u64::from(full);
            }
            if key.0 == "media_datagram" {
                self.media_packets.fetch_add(1, Ordering::SeqCst);
                self.media_bytes
                    .fetch_add(pkt.len() as u64, Ordering::SeqCst);
            } else if key.0 == "media_audio" {
                let (p, b) = if pkt.len() >= 390 {
                    (&self.audio_long_packets, &self.audio_long_bytes)
                } else {
                    (&self.audio_packets, &self.audio_bytes)
                };
                p.fetch_add(1, Ordering::SeqCst);
                b.fetch_add(pkt.len() as u64 + NETEM_OVERHEAD_BYTES, Ordering::SeqCst);
            }
            if full {
                self.dropped.fetch_add(1, Ordering::SeqCst);
                return;
            }
            self.backlog_bytes
                .fetch_add(pkt.len() as u64, Ordering::SeqCst);
            q.push_back((conn, pkt));
        }
        self.enqueued.fetch_add(1, Ordering::SeqCst);
        self.wake.notify_one();
    }

    /// The one drain: head first, each packet leaving after its
    /// transmission time at the rate (none uncapped).
    async fn drain(self: Arc<Self>) {
        let mut next_free = tokio::time::Instant::now();
        loop {
            let head = self.q.lock().expect("q").pop_front();
            let Some((conn, pkt)) = head else {
                self.wake.notified().await;
                continue;
            };
            let rate = self.bytes_per_s.load(Ordering::SeqCst);
            let now = tokio::time::Instant::now();
            if let Some(us) =
                ((pkt.len() as u64 + NETEM_OVERHEAD_BYTES) * 1_000_000).checked_div(rate)
            {
                next_free = next_free.max(now) + Duration::from_micros(us);
                tokio::time::sleep_until(next_free).await;
            } else {
                next_free = now;
            }
            self.backlog_bytes
                .fetch_sub(pkt.len() as u64, Ordering::SeqCst);
            self.sent_packets.fetch_add(1, Ordering::SeqCst);
            self.sent_bytes
                .fetch_add(pkt.len() as u64 + NETEM_OVERHEAD_BYTES, Ordering::SeqCst);
            let tx = self.conns.lock().expect("conns").get(&conn).cloned();
            if let Some(tx) = tx {
                let _ = tx.send(pkt);
            }
        }
    }

    /// What the node handed the shaper since the last call, by class and link.
    fn take_classes(&self) -> ClassMap {
        std::mem::take(&mut *self.classes.lock().expect("classes"))
    }

    /// Media datagrams handed to the shaper so far: (packets, bytes).
    fn media_totals(&self) -> (u64, u64) {
        (
            self.media_packets.load(Ordering::SeqCst),
            self.media_bytes.load(Ordering::SeqCst),
        )
    }

    /// Audio datagrams handed to the shaper so far: (wire bytes, packets),
    /// 20 ms ones and 60 ms ones.
    fn audio_totals(&self) -> ((u64, u64), (u64, u64)) {
        (
            (
                self.audio_bytes.load(Ordering::SeqCst),
                self.audio_packets.load(Ordering::SeqCst),
            ),
            (
                self.audio_long_bytes.load(Ordering::SeqCst),
                self.audio_long_packets.load(Ordering::SeqCst),
            ),
        )
    }

    /// Hold at most `packets` (netem's `limit`).
    fn set_limit(&self, packets: u64) {
        self.limit.store(packets, Ordering::SeqCst);
    }

    /// The counters now (cumulative, and the backlog).
    fn read(&self) -> NetemSecond {
        NetemSecond {
            enqueued: self.enqueued.load(Ordering::SeqCst),
            dropped: self.dropped.load(Ordering::SeqCst),
            sent_packets: self.sent_packets.load(Ordering::SeqCst),
            sent_bytes: self.sent_bytes.load(Ordering::SeqCst),
            backlog_packets: self.q.lock().expect("q").len() as u64,
            backlog_bytes: self.backlog_bytes.load(Ordering::SeqCst),
        }
    }
}

/// Split `buf` (appended to `carry`) into whole HDLC-framed packets: a
/// packet ends at a `0x7E` that follows at least one non-flag byte, and
/// carries every byte since the last packet's end, its opening flag
/// included, so the stream the peer reads is byte-identical when nothing
/// is dropped.
fn hdlc_packets(carry: &mut Vec<u8>, buf: &[u8]) -> Vec<Vec<u8>> {
    const FLAG: u8 = 0x7E;
    let mut out = Vec::new();
    for &b in buf {
        carry.push(b);
        if b == FLAG && carry.iter().rev().skip(1).any(|x| *x != FLAG) {
            out.push(std::mem::take(carry));
        }
    }
    out
}

/// A pipe in front of `port`'s listener whose return direction (the node's
/// sends) rides `uplink`, packet by packet. Returns the port to dial instead.
async fn netem_listener(port: u16, uplink: Arc<NetemUplink>) -> u16 {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the netem pipe");
    let front = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                return;
            };
            let Ok(node) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await else {
                continue;
            };
            let _ = client.set_nodelay(true);
            let _ = node.set_nodelay(true);
            let (mut client_rx, mut client_tx) = client.into_split();
            let (mut node_rx, mut node_tx) = node.into_split();
            // The node's downlink: unshaped.
            tokio::spawn(async move {
                let _ = tokio::io::copy(&mut client_rx, &mut node_tx).await;
            });
            let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
            let conn = uplink.register(tx);
            let up = Arc::clone(&uplink);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                let mut carry = Vec::new();
                while let Ok(n) = node_rx.read(&mut buf).await {
                    if n == 0 {
                        return;
                    }
                    for pkt in hdlc_packets(&mut carry, &buf[..n]) {
                        up.push(conn, pkt);
                    }
                }
            });
            tokio::spawn(async move {
                while let Some(bytes) = rx.recv().await {
                    if client_tx.write_all(&bytes).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    front
}

/// [`topo`], with node `capped.0`'s uplink a [`CappedUplink`]: every node that
/// dials it reaches it through [`capped_listener`]. The capped node must dial
/// nobody (its own outbound connections would bypass the cap).
async fn topo_capped(
    tag: &str,
    n: usize,
    members: usize,
    dials: &[(usize, usize)],
    canonical: Option<usize>,
    capped: Option<(usize, Arc<CappedUplink>)>,
) -> (Vec<Node>, Vec<CohortGroup>, tempfile::TempDir) {
    topo_shaped(
        tag,
        n,
        members,
        dials,
        canonical,
        capped.map(|(c, u)| (c, Shaper::Fluid(u))),
    )
    .await
}

/// The bottleneck in front of a capped node's egress.
#[derive(Clone)]
enum Shaper {
    /// [`CappedUplink`]: a byte rate, no queue limit, nothing dropped.
    Fluid(Arc<CappedUplink>),
    /// [`NetemUplink`]: the server matrix's shaper (rate + a packet FIFO
    /// that tail-drops).
    Netem(Arc<NetemUplink>),
}

/// [`topo_capped`] with any [`Shaper`].
#[allow(clippy::too_many_lines)] // `topo`'s body plus the capped pipe
async fn topo_shaped(
    tag: &str,
    n: usize,
    members: usize,
    dials: &[(usize, usize)],
    canonical: Option<usize>,
    capped: Option<(usize, Shaper)>,
) -> (Vec<Node>, Vec<CohortGroup>, tempfile::TempDir) {
    init_tracing();
    if let Some((c, _)) = &capped {
        assert!(
            dials.iter().all(|(_, j)| j != c),
            "the capped node dials nobody"
        );
    }
    let mut capped_port: Option<u16> = None;
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut keys = Vec::new();
    for i in 0..n {
        keys.push(
            Ident::new(
                &format!("node-{i}-call-{tag}"),
                sha2::Sha256::digest(tag.as_bytes())[0].wrapping_add(u8::try_from(i).unwrap()),
            )
            .await,
        );
    }
    let mut records = Vec::new();
    for k in &keys {
        records.push(k.record().await);
    }
    let mut nodes: Vec<Node> = Vec::new();
    for (i, key) in keys.into_iter().enumerate() {
        let dir = directory_with(records.clone()).await;
        let mut peers: Vec<u16> = Vec::new();
        for (a, _) in dials.iter().filter(|(_, j)| *j == i) {
            match &capped {
                Some((c, uplink)) if c == a => {
                    if capped_port.is_none() {
                        capped_port = Some(match uplink {
                            Shaper::Fluid(u) => {
                                capped_listener(nodes[*a].port, Arc::clone(u)).await
                            }
                            Shaper::Netem(u) => netem_listener(nodes[*a].port, Arc::clone(u)).await,
                        });
                    }
                    peers.push(capped_port.expect("the capped pipe"));
                }
                _ => peers.push(nodes[*a].port),
            }
        }
        nodes.push(
            node(
                key,
                dir,
                &tmp.path().join(format!("n{i}")),
                &peers,
                canonical == Some(i),
            )
            .await,
        );
    }
    for (i, from) in nodes.iter().enumerate() {
        let routes = from
            .dir
            .list_signed_transport_destinations_for(&from.key.key_id)
            .await
            .expect("list routes");
        for (j, to) in nodes.iter().enumerate() {
            if i != j {
                for r in &routes {
                    FederationDirectory::put_signed_transport_destination(&*to.dir, r)
                        .await
                        .expect("seed the route");
                }
            }
        }
    }
    let known = wait_until(Duration::from_mins(2), || async {
        for a in &nodes {
            for b in &nodes {
                if a.key.key_id != b.key.key_id && !a.transport.seek_peer(&b.key.key_id).await {
                    return false;
                }
            }
        }
        true
    })
    .await;
    assert!(known, "every node learns every other");

    // The room: node 0 founds it and adds the others, each applying the
    // commits that came before its own Add.
    let room = format!("room-call-{tag}");
    let first = CohortGroup::create(store(&format!("{tag}-0")), &room, &nodes[0].key.key_id, 16)
        .await
        .expect("found the room");
    let mut groups = vec![first];
    for (i, nd) in nodes.iter().enumerate().take(members).skip(1) {
        let (material, kp) = mint_cohort_key_material(&nd.key.key_id).expect("key material");
        let add = groups[0]
            .add_member(&nd.key.key_id, kp)
            .await
            .expect("add the member");
        for g in groups.iter().skip(1) {
            let _ = g
                .apply_remote_commit(add.commit())
                .await
                .expect("apply the Add");
        }
        let joined = CohortGroup::join(
            store(&format!("{tag}-{i}")),
            &room,
            material,
            add.welcome().expect("a Welcome"),
            16,
        )
        .await
        .expect("join from the Welcome");
        groups.push(joined);
    }
    (nodes, groups, tmp)
}

fn room_of(tag: &str) -> String {
    format!("room-call-{tag}")
}

fn av(m: &EdgeMetrics, label: &str) -> u64 {
    m.av_plane().get(label).copied().unwrap_or(0)
}

fn body(who: &str, seq: u64) -> Vec<u8> {
    let mut b = format!("{who}-frame-{seq:04}-").into_bytes();
    b.resize(96, b'.');
    b
}

/// How long a witness may look for media that ran undisturbed. A host can be
/// starved for a while, and a stretch needs a ceiling learned in that spell to
/// go stale; it cannot be starved for good, so running out is a failure.
const QUIET_BUDGET: Duration = Duration::from_mins(5);

/// Everything on `nodes` that says media really went missing or a commitment
/// really moved: what a stretch must not contain for its meters to mean what
/// a witness says they mean.
fn disturbances(nodes: &[Node]) -> u64 {
    nodes
        .iter()
        .map(|n| {
            [
                "av_chunk_dropped_congested",
                "av_frame_expired_sender",
                "av_frame_expired_late",
                "av_frame_stale_dropped",
                "alm_shed",
            ]
            .iter()
            .map(|label| av(&n.metrics, label))
            .sum::<u64>()
        })
        .sum()
}

/// The frames of `want` that arrive from `publisher`, in arrival order, until
/// all did or 5 s pass with none.
async fn collect_stretch(
    rx: &mut mpsc::Receiver<ReceivedFrame>,
    publisher: &str,
    want: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    let mut got = Vec::new();
    while got.len() < want.len() {
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(f)) if f.publisher == publisher && want.contains(&f.bytes) => got.push(f.bytes),
            Ok(Some(_)) => {}
            _ => break,
        }
    }
    got
}

/// One live call at a time in this binary. These witnesses read a call's own
/// meters, so a neighbouring call on the same host must not be what they
/// measure: without this, a 4-core runner carries four 3-node calls at once.
static ONE_CALL: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

async fn one_call() -> tokio::sync::SemaphorePermit<'static> {
    ONE_CALL.acquire().await.expect("never closed")
}

async fn wait_legs(call: &Call, n: usize) {
    assert!(
        wait_until(Duration::from_secs(30), || async { call.legs().len() >= n }).await,
        "the call's legs come up: {:?}",
        call.legs()
    );
}

/// Wait until `call` has verified `n` other publishers' stream key bindings:
/// the setup step after the legs (a hybrid verification each, once), before
/// which a receiver holds its first chunks in the link's queue.
async fn wait_bound(call: &Call, n: u64) {
    assert!(
        wait_until(Duration::from_secs(30), || async {
            call.chunk_auth_counts().bindings_installed >= n
        })
        .await,
        "the call verifies its peers' bindings: {:?}",
        call.chunk_auth_counts()
    );
}

// The options are moved into the call.
#[allow(clippy::large_types_passed_by_value)]
async fn join_loaded(
    node: &Node,
    group: &CohortGroup,
    tag: &str,
    opts: CallOptions,
    load: Option<Arc<ciris_edge::load_ladder::SharedLadder>>,
) -> Call {
    Call::join(
        &room_of(tag),
        &node.key.key_id,
        CallDeps {
            room_group: group.clone(),
            roster: Arc::new(Roster(true)),
            owners: Arc::clone(&node.dir) as Arc<dyn ciris_edge::transport::av_call::CallOwners>,
            transport: Arc::clone(&node.transport),
            lifecycle: Arc::clone(&node.lifecycle),
            registrar: Arc::new(CountingRegistrar::default()),
            events: None,
            metrics: Some(node.metrics.clone()),
            record: None,
            signer: node.key.signer(),
            verifier: Arc::clone(&node.dir) as Arc<dyn StreamKeyVerifier>,
            load,
        },
        opts,
    )
    .await
    .expect("join")
}

fn relay_opts() -> CallOptions {
    CallOptions {
        relay: true,
        ..CallOptions::default()
    }
}

/// The parent `call` chose for `stream`.
fn primary_for(
    call: &Call,
    stream: ciris_edge::transport::realtime_av::StreamId,
) -> Option<String> {
    call.alm_parents()
        .into_iter()
        .find(|p| p.stream == stream)
        .and_then(|p| p.primary)
}

/// **Roster relays before the canonical** (Eric 2026-11-02): `B` and `C`
/// cannot reach each other directly; each hears the other through `A`, a
/// roster member that offers relay — never through the canonical `T`.
// a, b, c, t: the nodes as the module docs name them.
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_member_unreachable_directly_is_heard_through_a_roster_relay() {
    let _call = one_call().await;
    let tag = "alm2-roster";
    // 0 = A, 1 = B, 2 = C (the room); 3 = T (canonical: transport on, no
    // member). B and C dial A; T dials everyone. B and C share nothing.
    let (nodes, groups, _tmp) = topo(
        tag,
        4,
        3,
        &[(0, 1), (0, 2), (0, 3), (1, 3), (2, 3)],
        Some(3),
    )
    .await;
    let (a, b, c, t) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
    let ca = join_loaded(a, &groups[0], tag, relay_opts(), None).await;
    let mut cb = join_loaded(b, &groups[1], tag, CallOptions::default(), None).await;
    let mut cc = join_loaded(c, &groups[2], tag, CallOptions::default(), None).await;

    wait_legs(&ca, 2).await;
    wait_legs(&cb, 1).await;
    wait_legs(&cc, 1).await;
    // The hard-NAT shape: B has no leg to C, C none to B (and never will).
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(cb.legs(), vec![a.key.key_id.clone()], "B reaches only A");
    assert_eq!(cc.legs(), vec![a.key.key_id.clone()], "C reaches only A");

    // ALM converges: each hears the other's stream through A (C4 chose it,
    // A's C2 admitted it, over C3).
    let converged = wait_until(Duration::from_secs(90), || async {
        primary_for(&cc, cb.stream()).as_deref() == Some(a.key.key_id.as_str())
            && primary_for(&cb, cc.stream()).as_deref() == Some(a.key.key_id.as_str())
    })
    .await;
    assert!(
        converged,
        "C's parents {:?} / B's parents {:?}; A's log {:?}",
        cc.alm_parents(),
        cb.alm_parents(),
        ca.alm_log()
    );
    for call in [&cb, &cc] {
        for p in call.alm_parents() {
            for parent in [p.primary.as_deref(), p.standby.as_deref()]
                .into_iter()
                .flatten()
            {
                assert_ne!(
                    parent, t.key.key_id,
                    "the canonical is never a media parent"
                );
            }
        }
    }
    let kids = ca.alm_relay_children(cb.stream());
    assert!(
        kids.iter().any(|(p, r)| *p == c.key.key_id
            && *r == ciris_edge::transport::realtime_av_alm::controller::Role::Primary),
        "A admitted C for B's stream: {kids:?}"
    );

    // B's frames reach C byte-identical and in order, through A. A starved
    // host really loses frames, and then something counts them: only that
    // earns another try. Frames gone with nothing to show for it are a bug.
    let mut rx_c = cc.frames().expect("C's frames");
    let deadline = tokio::time::Instant::now() + QUIET_BUDGET;
    let mut seq = 0;
    let forwarded_before = loop {
        assert!(
            wait_until(Duration::from_secs(90), || async {
                primary_for(&cc, cb.stream()).as_deref() == Some(a.key.key_id.as_str())
            })
            .await,
            "C is back on A: {:?}; A's log {:?}",
            cc.alm_parents(),
            ca.alm_log()
        );
        let from = seq;
        let forwarded_before = ca.alm_counts().forwarded;
        let lost_before = disturbances(&nodes);
        for _ in 0..40 {
            cb.publish(Frame::opaque(body("b", seq)))
                .await
                .expect("B publishes");
            seq += 1;
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let want: Vec<Vec<u8>> = (from..seq).map(|s| body("b", s)).collect();
        let got = collect_stretch(&mut rx_c, &b.key.key_id, &want).await;
        let order: Vec<usize> = got
            .iter()
            .filter_map(|g| want.iter().position(|w| w == g))
            .collect();
        assert!(
            order.windows(2).all(|w| w[0] < w[1]),
            "byte-identical, in order: {order:?}"
        );
        if got == want {
            break forwarded_before;
        }
        let plane = |metrics: &EdgeMetrics| {
            let mut v: Vec<(String, u64)> = metrics
                .av_plane()
                .into_iter()
                .filter(|(k, _)| !k.starts_with("alm_c3"))
                .collect();
            v.sort();
            v
        };
        let context = format!(
            "C heard {} of B's 40 frames: {order:?}; A forwarded {}; C reorder {:?}; C auth {:?}\n\
             plane B {:?}\nplane A {:?}\nplane C {:?}",
            got.len(),
            ca.alm_counts().forwarded - forwarded_before,
            cc.reorder_counts(),
            cc.chunk_auth_counts(),
            plane(&b.metrics),
            plane(&a.metrics),
            plane(&c.metrics),
        );
        assert!(
            disturbances(&nodes) > lost_before,
            "frames lost with nothing counting them: {context}"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "no whole stretch: {context}"
        );
    };
    assert!(ca.alm_counts().forwarded - forwarded_before >= 40);
    assert!(av(&a.metrics, "alm_c3_received") > 0 && av(&c.metrics, "alm_c3_sent") > 0);
    eprintln!(
        "[ALM2] roster relay: C<-A<-B 40/40 after {seq} sent, A forwarded {}, A admitted {}, C3 sent by C {}, log(A)={}",
        ca.alm_counts().forwarded - forwarded_before,
        ca.alm_counts().admitted,
        av(&c.metrics, "alm_c3_sent"),
        ca.alm_log().0
    );
    // v44 — a call says it is there, so a silent ALM is not read as no call,
    // and it says when its first frame came.
    let live = c.metrics.snapshot();
    assert_eq!(live.alm_active_calls, 1);
    assert!(live.alm_c3_peers >= 1, "C knows A speaks C3");
    assert_eq!(live.call_setup_duration_seconds["first_frame"].count, 1);
    // v45.1.7 — the receive side is published once a second: wait for the
    // rows B's stretch made, then read them.
    let rated = |n: &Node, member: &str, direction: &str| {
        common::call_leg_series(
            &n.metrics.snapshot().call_legs,
            CALL_BITRATE,
            member,
            direction,
        )
        .first()
        .is_some_and(|s| s.value > 0.0)
    };
    // Media flows while the rows are read: a rate falls to 0 a second after
    // its media stops, as it should.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let rows_came = loop {
        let _ = cb.publish(Frame::opaque(body("b", seq))).await;
        seq += 1;
        tokio::time::sleep(Duration::from_millis(50)).await;
        if rated(c, &b.key.key_id, "recv")
            && rated(a, &b.key.key_id, "recv")
            && rated(b, &a.key.key_id, "send")
        {
            break true;
        }
        if tokio::time::Instant::now() > deadline {
            break false;
        }
    };
    assert!(
        rows_came,
        "the leg rows come: C {:?}\nA {:?}\nB {:?}",
        c.metrics.snapshot().call_legs,
        a.metrics.snapshot().call_legs,
        b.metrics.snapshot().call_legs
    );
    call_legs_name_the_relay(&c.metrics.snapshot(), a, b, c, &cb);
    let at_a = a.metrics.snapshot();
    let at_b = b.metrics.snapshot();
    for (snap, who) in [(&at_a, "A"), (&at_b, "B")] {
        common::assert_call_legs_well_formed(&snap.call_legs);
        assert_eq!(snap.call_legs_overflow, 0, "{who}");
    }
    // A hears B first-hand on B's own link: direct, one TCP hop, no punch.
    for name in CALL_LEG_INSTRUMENTS.iter().map(|(n, ..)| *n) {
        assert_eq!(
            common::call_leg_series(&at_a.call_legs, name, &b.key.key_id, "recv").len(),
            1,
            "A's receive row for B carries {name}: {:?}",
            at_a.call_legs
        );
    }
    let path = common::call_leg_series(&at_a.call_legs, CALL_PATH, &b.key.key_id, "recv")[0];
    assert_eq!(
        common::call_leg_attr(path, "path"),
        Some("direct"),
        "{path:?}"
    );
    assert_eq!(
        common::call_leg_attr(path, "relay.key_id"),
        Some(""),
        "{path:?}"
    );
    assert_eq!(
        common::call_leg_attr(path, "punched"),
        Some("false"),
        "{path:?}"
    );
    // B's own stream on its one leg, to A: a send row with a rate.
    let sent = common::call_leg_series(&at_b.call_legs, CALL_BITRATE, &a.key.key_id, "send");
    assert_eq!(sent.len(), 1, "{:?}", at_b.call_legs);
    assert!(sent[0].value > 0.0, "B sent media to A: {:?}", sent[0]);
    assert_eq!(
        common::call_leg_attr(sent[0], "ciris.call.stream_id"),
        Some(stream_label(cb.stream()).as_str())
    );
    drop(cc);
    let ended = c.metrics.snapshot();
    assert_eq!(ended.alm_active_calls, 0, "a dropped call ends too");
    assert_eq!(ended.alm_c3_peers, 0, "and takes its members with it");
    assert_eq!(
        ended.call_setup_duration_seconds["ended"].count, 0,
        "its setup was already over"
    );
    assert!(
        ended.call_legs.is_empty(),
        "a call's leg series go with it: {:?}",
        ended.call_legs
    );
    drop(cb);
    drop(ca);
    for n in [a, b] {
        assert!(
            n.metrics.snapshot().call_legs.is_empty(),
            "no call, no legs"
        );
    }
}

/// v45.1.7 — C hears B only through A: every instrument on C's receive row
/// for B's stream, `relayed`, naming A as the relay.
fn call_legs_name_the_relay(
    live: &ciris_edge::observability::EdgeMetricsBundle,
    a: &Node,
    b: &Node,
    c: &Node,
    cb: &Call,
) {
    common::assert_call_legs_well_formed(&live.call_legs);
    assert_eq!(live.call_legs_overflow, 0);
    for name in CALL_LEG_INSTRUMENTS.iter().map(|(n, ..)| *n) {
        let rows = common::call_leg_series(&live.call_legs, name, &b.key.key_id, "recv");
        assert_eq!(
            rows.len(),
            1,
            "C's row for B carries {name}: {:?}",
            live.call_legs
        );
        let s = rows[0];
        assert_eq!(
            common::call_leg_attr(s, "ciris.call.stream_id"),
            Some(stream_label(cb.stream()).as_str())
        );
        assert_eq!(common::call_leg_attr(s, "ciris.media.kind"), Some("audio"));
        assert_eq!(common::call_leg_attr(s, "ciris.room.id"), Some(cb.room()));
    }
    let path = common::call_leg_series(&live.call_legs, CALL_PATH, &b.key.key_id, "recv")[0];
    assert_eq!(
        common::call_leg_attr(path, "path"),
        Some("relayed"),
        "{path:?}"
    );
    assert_eq!(
        common::call_leg_attr(path, "relay.key_id"),
        Some(a.key.key_id.as_str()),
        "the relay is A: {path:?}"
    );
    assert_eq!(common::call_leg_attr(path, "punched"), Some("false"));
    assert_eq!(
        common::call_leg_attr(path, "nat.local_type"),
        Some("unknown")
    );
    let rate = common::call_leg_series(&live.call_legs, CALL_BITRATE, &b.key.key_id, "recv")[0];
    assert!(rate.value > 0.0, "C heard B's media: {rate:?}");
    assert!(
        common::call_leg_series(&live.call_legs, CALL_PATH, &c.key.key_id, "recv").is_empty(),
        "no row for C itself"
    );
}

/// **A v1 peer behind a v2 relay still binds** (v45, binding v2): B names
/// its codecs (`{0xFF: opus}`), so it signs a v1 and a v2 binding per epoch.
/// A relays and parses v2; C does not (its `CAPS` lack `CAP_BINDING_V2`) and
/// reaches B only through A. C must get B's v1 binding from A, bind, and hear
/// B; A holds B's v2 map, C never sees one.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_v1_peer_behind_a_v2_relay_still_binds_and_hears() {
    use ciris_edge::transport::av_chunk_auth::{CodecMap, CodecToken};
    use ciris_edge::transport::realtime_av_alm::controller::wire::CAP_BINDING_V2;
    let _call = one_call().await;
    let tag = "alm2-v1-behind-v2";
    // 0 = A, 1 = B, 2 = C (the room); 3 = T (canonical: transport on, no
    // member), so B and C learn each other with no leg between them.
    let (nodes, groups, _tmp) = topo(
        tag,
        4,
        3,
        &[(0, 1), (0, 2), (0, 3), (1, 3), (2, 3)],
        Some(3),
    )
    .await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    c.transport.set_av_caps_withheld_for_test(CAP_BINDING_V2);
    let opus = CodecMap::new([CodecToken::Opus]).expect("map");
    let ca = join_loaded(a, &groups[0], tag, relay_opts(), None).await;
    let mut cb = join_loaded(
        b,
        &groups[1],
        tag,
        CallOptions {
            codecs: Some(opus),
            ..CallOptions::default()
        },
        None,
    )
    .await;
    let mut cc = join_loaded(c, &groups[2], tag, CallOptions::default(), None).await;
    wait_legs(&ca, 2).await;
    wait_legs(&cb, 1).await;
    wait_legs(&cc, 1).await;
    assert_eq!(cc.legs(), vec![a.key.key_id.clone()], "C reaches only A");
    let mut rx = cc.frames().expect("C's frames");
    let mut heard = false;
    for seq in 0..400u64 {
        cb.publish(Frame::opaque(body("b", seq)))
            .await
            .expect("B publishes");
        while let Ok(f) = rx.try_recv() {
            heard |= f.publisher == b.key.key_id;
        }
        if heard {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        heard,
        "C never heard B through A: C auth {:?}; C parents {:?}; A log {:?}",
        cc.chunk_auth_counts(),
        cc.alm_parents(),
        ca.alm_log()
    );
    assert_eq!(
        ca.stream_codecs(cb.stream()),
        Some(opus),
        "A holds B's v2 map"
    );
    assert_eq!(cc.stream_codecs(cb.stream()), None, "C was sent v1 only");
}

/// The first event on `rx` that `pick` takes, within `budget`.
async fn next_event<T>(
    rx: &mut tokio::sync::mpsc::Receiver<CallEvent>,
    budget: Duration,
    mut pick: impl FnMut(&CallEvent) -> Option<T>,
) -> Option<T> {
    tokio::time::timeout(budget, async {
        while let Some(e) = rx.recv().await {
            if let Some(t) = pick(&e) {
                return Some(t);
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

/// **Attendance** (v45): B leaves `backgrounded`, signed, and A reads
/// `AttendeeLeft { B, Backgrounded }` with B's stream; C is killed (every
/// leg to it closed, its stream silent, no signed end) and A reads it
/// `Lost`, and not before `ATTENDEE_LOST_AFTER`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_signed_leave_says_why_and_a_killed_node_is_lost_after_the_bound() {
    use ciris_edge::transport::av_call::{LeaveCause, ATTENDEE_LOST_AFTER};
    use ciris_edge::transport::av_chunk_auth::SignedEnd;
    let _call = one_call().await;
    let tag = "alm2-attendance";
    let (nodes, groups, _tmp) = topo(tag, 3, 3, &[(0, 1), (0, 2), (1, 2)], None).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let mut ca = join_loaded(a, &groups[0], tag, CallOptions::default(), None).await;
    let mut cb = join_loaded(b, &groups[1], tag, CallOptions::default(), None).await;
    let mut cc = join_loaded(c, &groups[2], tag, CallOptions::default(), None).await;
    for x in [&ca, &cb, &cc] {
        wait_legs(x, 2).await;
        wait_bound(x, 2).await;
    }
    let mut events = ca.events().expect("A's events");
    for seq in 0..10u64 {
        for (who, x) in [("b", &mut cb), ("c", &mut cc)] {
            x.publish(Frame::opaque(body(who, seq)))
                .await
                .expect("publish");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let b_stream = cb.stream();
    let c_stream = cc.stream();
    let _ = cb
        .leave_with(SignedEnd::Backgrounded)
        .await
        .expect("B leaves");
    let left = next_event(&mut events, Duration::from_secs(30), |e| match e {
        CallEvent::AttendeeLeft {
            key_id,
            stream,
            cause,
            ..
        } if *key_id == b.key.key_id => Some((*stream, *cause)),
        _ => None,
    })
    .await;
    assert_eq!(
        left,
        Some((b_stream, LeaveCause::Backgrounded)),
        "a signed leave says why"
    );
    // Kill C: every leg to it closed, nothing more from it.
    cc.close_leg_for_test(&a.key.key_id).await;
    ca.close_leg_for_test(&c.key.key_id).await;
    drop(cc);
    let killed = tokio::time::Instant::now();
    let mut seq = 100u64;
    let lost = tokio::time::timeout(Duration::from_mins(1), async {
        loop {
            // A keeps publishing, so its own leg to C is found gone.
            let _ = ca.publish(Frame::opaque(body("a", seq))).await;
            seq += 1;
            while let Ok(e) = events.try_recv() {
                if let CallEvent::AttendeeLeft {
                    key_id,
                    stream,
                    cause,
                    ..
                } = e
                {
                    if key_id == c.key.key_id {
                        return (stream, cause, killed.elapsed());
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("A reads C as left");
    assert_eq!((lost.0, lost.1), (c_stream, LeaveCause::Lost));
    assert!(
        lost.2 >= ATTENDEE_LOST_AFTER,
        "Lost only after the bound: {:?}",
        lost.2
    );
    assert_eq!(
        av(&b.metrics, "end_flush_unconfirmed"),
        0,
        "B's leave closed every leg on its Channel's proof, not the ceiling"
    );
}

/// **Lost, old-build shape** (45.3): C's call task dies with C's node still
/// up, still answering on the call's address and routing nothing (a build
/// before 45.3 dropped a call so; an old peer still does). A redials C after
/// its leg closes; the dial lands on a node with no live call, which closes
/// the link, so A holds no leg to C and reads it `Lost` within the bound.
/// Before 45.3 the router dropped the arrival and left the link up: A held a
/// leg to nowhere and never read C lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_node_that_answers_but_routes_no_call_is_read_lost_within_the_bound() {
    use ciris_edge::transport::av_call::{LeaveCause, ATTENDEE_LOST_AFTER};
    let _call = one_call().await;
    let tag = "alm2-lost-oldbuild";
    let (nodes, groups, _tmp) = topo(tag, 2, 2, &[(0, 1)], None).await;
    let (a, c) = (&nodes[0], &nodes[1]);
    let mut ca = join_loaded(a, &groups[0], tag, CallOptions::default(), None).await;
    let mut cc = join_loaded(c, &groups[1], tag, CallOptions::default(), None).await;
    for x in [&ca, &cc] {
        wait_legs(x, 1).await;
        wait_bound(x, 1).await;
    }
    let mut events = ca.events().expect("A's events");
    for seq in 0..10u64 {
        cc.publish(Frame::opaque(body("c", seq)))
            .await
            .expect("publish");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let c_stream = cc.stream();
    // C's legs go, and its call with them; its node stays up on the address.
    cc.close_leg_for_test(&a.key.key_id).await;
    let leg = ca.leg_link_for_test(&c.key.key_id);
    cc.drop_keeping_the_wire_for_test();
    if let Some(l) = leg {
        let _ = a.transport.link_teardown(&l).await;
    }
    let killed = tokio::time::Instant::now();
    // The bound: ATTENDEE_LOST_AFTER of no leg and silence, plus a redial
    // cycle (a dial, the far end's close) and the watch tick.
    let bound = ATTENDEE_LOST_AFTER + Duration::from_secs(10);
    let mut seq = 100u64;
    let lost = tokio::time::timeout(bound, async {
        loop {
            let _ = ca.publish(Frame::opaque(body("a", seq))).await;
            seq += 1;
            while let Ok(e) = events.try_recv() {
                if let CallEvent::AttendeeLeft {
                    key_id,
                    stream,
                    cause,
                    ..
                } = e
                {
                    if key_id == c.key.key_id {
                        return (stream, cause, killed.elapsed());
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("A reads C lost within {bound:?}: legs {:?}", ca.legs()));
    assert_eq!((lost.0, lost.1), (c_stream, LeaveCause::Lost));
    assert!(
        lost.2 >= ATTENDEE_LOST_AFTER,
        "not before the bound: {:?}",
        lost.2
    );
}

/// **Removed** (v45): the room's MLS group drops C's key; A's call rolls
/// and reads `AttendeeLeft { C, Removed }`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_removed_member_is_attendee_left_removed() {
    use ciris_edge::transport::av_call::LeaveCause;
    let _call = one_call().await;
    let tag = "alm2-removed";
    let (nodes, groups, _tmp) = topo(tag, 3, 3, &[(0, 1), (0, 2), (1, 2)], None).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let mut ca = join_loaded(a, &groups[0], tag, CallOptions::default(), None).await;
    let _cb = join_loaded(b, &groups[1], tag, CallOptions::default(), None).await;
    let mut cc = join_loaded(c, &groups[2], tag, CallOptions::default(), None).await;
    wait_legs(&ca, 2).await;
    wait_bound(&ca, 2).await;
    let c_stream = cc.stream();
    let mut events = ca.events().expect("A's events");
    // C attends: A hears its chunks (a binding alone is no presence).
    let mut frames = ca.frames().expect("A's frames");
    let mut heard_c = false;
    for seq in 0..200u64 {
        cc.publish(Frame::opaque(body("c", seq)))
            .await
            .expect("C publishes");
        while let Ok(f) = frames.try_recv() {
            heard_c |= f.publisher == c.key.key_id;
        }
        if heard_c {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(heard_c, "A hears C before the removal");
    let rm = groups[0]
        .remove_member(&c.key.key_id)
        .await
        .expect("remove C");
    let _ = groups[1]
        .apply_remote_commit(rm.commit())
        .await
        .expect("B applies");
    let mut got = None;
    for seq in 0..200u64 {
        let _ = ca.publish(Frame::opaque(body("a", seq))).await;
        while let Ok(e) = events.try_recv() {
            if let CallEvent::AttendeeLeft {
                key_id,
                stream,
                cause,
                ..
            } = e
            {
                if key_id == c.key.key_id {
                    got = Some((stream, cause));
                }
            }
        }
        if got.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(got, Some((c_stream, LeaveCause::Removed)));
}

/// **Replace in place** (v45): B replaces its stream mid-call while it keeps
/// publishing. A reads `StreamReplaced { B, old, new }` and no
/// `AttendeeLeft` for B, and hears every one of B's frames, old stream and
/// new, across the swap.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_replaced_stream_carries_on_with_no_leave() {
    let _call = one_call().await;
    let tag = "alm2-replace";
    let (nodes, groups, _tmp) = topo(tag, 2, 2, &[(0, 1)], None).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let mut ca = join_loaded(a, &groups[0], tag, CallOptions::default(), None).await;
    let mut cb = join_loaded(b, &groups[1], tag, CallOptions::default(), None).await;
    wait_legs(&ca, 1).await;
    wait_legs(&cb, 1).await;
    wait_bound(&ca, 1).await;
    let mut events = ca.events().expect("A's events");
    let mut frames = ca.frames().expect("A's frames");
    let old = cb.stream();
    let mut sent = Vec::new();
    for seq in 0..200u64 {
        if seq == 80 {
            let new = cb.replace_stream(None).await.expect("replace");
            assert_ne!(new, old);
        }
        let f = body("b", seq);
        cb.publish(Frame::opaque(f.clone())).await.expect("publish");
        sent.push(f);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let new = cb.stream();
    assert_ne!(new, old, "B publishes the new stream");
    let mut heard = std::collections::BTreeSet::new();
    let _ = tokio::time::timeout(Duration::from_secs(20), async {
        while heard.len() < sent.len() {
            match frames.recv().await {
                Some(f) if f.publisher == b.key.key_id => {
                    heard.insert(f.bytes);
                }
                Some(_) => {}
                None => break,
            }
        }
    })
    .await;
    let missing: Vec<usize> = sent
        .iter()
        .enumerate()
        .filter(|(_, f)| !heard.contains(*f))
        .map(|(i, _)| i)
        .collect();
    assert!(
        missing.is_empty(),
        "frames missing across the swap: {missing:?}"
    );
    let mut replaced = None;
    let mut left = false;
    while let Ok(e) = events.try_recv() {
        match e {
            CallEvent::StreamReplaced {
                publisher,
                old: o,
                new: n,
            } if publisher == b.key.key_id => replaced = Some((o, n)),
            CallEvent::AttendeeLeft { key_id, .. } if key_id == b.key.key_id => left = true,
            _ => {}
        }
    }
    assert_eq!(
        replaced,
        Some((old, new)),
        "StreamReplaced, from B's signed binding"
    );
    assert!(!left, "a replacement is not a leave");
    assert_eq!(
        av(&b.metrics, "replace_switch_unconfirmed"),
        0,
        "B switched on its legs' delivery proof, not the ceiling"
    );
}

/// 30 Hz video, each frame several chunks back to back: what keeps a leg's
/// Channel busy while a leave or a replacement waits on its proof (v45).
const VIDEO_TICK: Duration = Duration::from_millis(33);
const CHUNKS_PER_VIDEO_FRAME: u64 = 6;

/// One 30 Hz video frame's chunks from `call`, send errors ignored (a busy
/// window is the point, not a failure).
async fn video_frame(call: &mut Call, who: &str, frame: u64) {
    for k in 0..CHUNKS_PER_VIDEO_FRAME {
        let _ = call
            .publish(Frame::opaque(body(who, frame * CHUNKS_PER_VIDEO_FRAME + k)))
            .await;
    }
}

/// **A replacement under video is proved per message** (v45): B replaces its
/// stream while it keeps sending 30 Hz video (six chunks a frame), so B's leg
/// to A always has media in flight. The switch waits on the new bindings'
/// own delivery proof (their Channel sequence), not an empty tx ring, so it
/// never falls to the ceiling: `replace_switch_unconfirmed` stays 0, and A
/// reads `StreamReplaced` and no leave.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_replacement_under_video_is_proved_by_its_own_delivery() {
    let _call = one_call().await;
    let tag = "alm2-replace-video";
    let (nodes, groups, _tmp) = topo(tag, 2, 2, &[(0, 1)], None).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let mut ca = join_loaded(a, &groups[0], tag, CallOptions::default(), None).await;
    let mut cb = join_loaded(b, &groups[1], tag, CallOptions::default(), None).await;
    wait_legs(&ca, 1).await;
    wait_legs(&cb, 1).await;
    wait_bound(&ca, 1).await;
    let mut events = ca.events().expect("A's events");
    let old = cb.stream();
    for frame in 0..120u64 {
        if frame == 30 {
            let new = cb.replace_stream(None).await.expect("replace");
            assert_ne!(new, old);
        }
        video_frame(&mut cb, "b", frame).await;
        tokio::time::sleep(VIDEO_TICK).await;
    }
    let new = cb.stream();
    assert_ne!(new, old, "B publishes the new stream");
    let replaced = next_event(&mut events, Duration::from_secs(10), |e| match e {
        CallEvent::StreamReplaced {
            publisher,
            old: o,
            new: n,
        } if *publisher == b.key.key_id => Some((*o, *n)),
        CallEvent::AttendeeLeft { key_id, .. } if *key_id == b.key.key_id => {
            panic!("a replacement is not a leave")
        }
        _ => None,
    })
    .await;
    assert_eq!(replaced, Some((old, new)));
    assert_eq!(
        av(&b.metrics, "replace_switch_unconfirmed"),
        0,
        "the switch waited on the bindings' own proof, with video in flight"
    );
}

/// **A relay's leave under forwarded video is proved per message** (v45): A
/// relays B's 30 Hz video to C (B and C share no leg), and A leaves while B
/// keeps sending, so A's leg to C always has forwarded media in flight. Each
/// leg closes on the signed end's own delivery proof, never the ceiling:
/// `end_flush_unconfirmed` stays 0, and C reads `AttendeeLeft { A, Left }`.
// a, b, c, t: the nodes as the roster witness names them.
#[allow(clippy::many_single_char_names)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_relay_leaving_under_forwarded_video_proves_its_end_per_message() {
    use ciris_edge::transport::av_call::LeaveCause;
    use ciris_edge::transport::av_chunk_auth::SignedEnd;
    let _call = one_call().await;
    let tag = "alm2-leave-video";
    let (nodes, groups, _tmp) = topo(
        tag,
        4,
        3,
        &[(0, 1), (0, 2), (0, 3), (1, 3), (2, 3)],
        Some(3),
    )
    .await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let mut ca = join_loaded(a, &groups[0], tag, relay_opts(), None).await;
    let mut cb = join_loaded(b, &groups[1], tag, CallOptions::default(), None).await;
    let mut cc = join_loaded(c, &groups[2], tag, CallOptions::default(), None).await;
    wait_legs(&ca, 2).await;
    wait_legs(&cb, 1).await;
    wait_legs(&cc, 1).await;
    let b_stream = cb.stream();
    assert!(
        wait_until(Duration::from_secs(90), || async {
            primary_for(&cc, b_stream).as_deref() == Some(a.key.key_id.as_str())
        })
        .await,
        "C hears B through A: {:?}; A's log {:?}",
        cc.alm_parents(),
        ca.alm_log()
    );
    let mut events = cc.events().expect("C's events");
    // A attends (C hears its chunks: a binding alone is no presence).
    let mut frames = cc.frames().expect("C's frames");
    let mut heard_a = false;
    for seq in 0..200u64 {
        ca.publish(Frame::opaque(body("a", seq)))
            .await
            .expect("A publishes");
        while let Ok(f) = frames.try_recv() {
            heard_a |= f.publisher == a.key.key_id;
        }
        if heard_a {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(heard_a, "C hears A before it leaves");
    // B's video runs until told to stop, through A to C.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let video = {
        let stop = Arc::clone(&stop);
        tokio::spawn(async move {
            let mut frame = 0u64;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                video_frame(&mut cb, "b", frame).await;
                frame += 1;
                tokio::time::sleep(VIDEO_TICK).await;
            }
            cb
        })
    };
    let forwarded_before = ca.alm_counts().forwarded;
    assert!(
        wait_until(Duration::from_secs(30), || async {
            ca.alm_counts().forwarded >= forwarded_before + 60
        })
        .await,
        "A forwards B's video to C: {} forwarded",
        ca.alm_counts().forwarded - forwarded_before
    );
    let _ = ca.leave_with(SignedEnd::Left).await.expect("A leaves");
    let left = next_event(&mut events, Duration::from_secs(30), |e| match e {
        CallEvent::AttendeeLeft {
            key_id,
            cause,
            truncated,
            ..
        } if *key_id == a.key.key_id => Some((*cause, *truncated)),
        _ => None,
    })
    .await;
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _cb = video.await.expect("B's video task");
    assert_eq!(
        left,
        Some((LeaveCause::Left, false)),
        "a signed leave, whole"
    );
    assert_eq!(
        av(&a.metrics, "end_flush_unconfirmed"),
        0,
        "every leg closed on the end's own proof, with video in flight"
    );
}

/// What one receiver heard, per stream.
type Heard = std::collections::BTreeMap<
    ciris_edge::transport::realtime_av::StreamId,
    std::collections::BTreeSet<Vec<u8>>,
>;
/// Take every frame `publisher` sent off `frames` into `heard`.
fn drain_from(
    frames: &mut tokio::sync::mpsc::Receiver<ciris_edge::transport::av_call::ReceivedFrame>,
    heard: &mut Heard,
    publisher: &str,
) {
    while let Ok(f) = frames.try_recv() {
        if f.publisher == publisher {
            heard.entry(f.stream).or_default().insert(f.bytes);
        }
    }
}

/// **A share beside the camera** (v45, `Call::add_stream`): B publishes its
/// camera and a screen share at once; A reads `StreamAdded` for each with its
/// signed kind (media, share) and hears both, each as its own stream. B ends
/// the share alone (`end = 3`): A reads `StreamEnded { B, share, ended }`,
/// never `AttendeeLeft` or `StreamReplaced` for B, and keeps hearing B's
/// camera.
/// The share's end is proved per leg (`end_flush_unconfirmed` 0).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[allow(clippy::too_many_lines)] // one story, told in order
async fn a_share_beside_the_camera_is_heard_and_ends_alone() {
    use ciris_edge::telemetry::call_legs::CALL_CODEC;
    use ciris_edge::transport::av_call::LeaveCause;
    use ciris_edge::transport::av_chunk_auth::{
        CodecMap, CodecToken, STREAM_KIND_MEDIA, STREAM_KIND_SHARE,
    };
    let _call = one_call().await;
    let tag = "alm2-share";
    let (nodes, groups, _tmp) = topo(tag, 2, 2, &[(0, 1)], None).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let mut ca = join_loaded(a, &groups[0], tag, CallOptions::default(), None).await;
    let mut cb = join_loaded(b, &groups[1], tag, CallOptions::default(), None).await;
    wait_legs(&ca, 1).await;
    wait_legs(&cb, 1).await;
    wait_bound(&ca, 1).await;
    let mut events = ca.events().expect("A's events");
    let mut frames = ca.frames().expect("A's frames");
    let cam = cb.stream();
    // v45.1.7 — the share declares its codec (Codex on #1016: a share's send
    // rows read the class token, not the share's registered codec).
    let opus = CodecMap::new([CodecToken::Opus]).expect("map");
    let share = cb
        .add_stream(Some(opus))
        .await
        .expect("B shares its screen");
    assert_ne!(share, cam);
    assert_eq!(cb.streams().await, vec![cam, share]);
    wait_bound(&ca, 2).await;
    // A reads each stream's signed kind as its first binding installs.
    let mut kinds = std::collections::BTreeMap::new();
    while kinds.len() < 2 {
        let got = next_event(&mut events, Duration::from_secs(10), |e| match e {
            CallEvent::StreamAdded {
                publisher,
                stream,
                kind,
            } if *publisher == b.key.key_id => Some((*stream, *kind)),
            _ => None,
        })
        .await
        .expect("StreamAdded for each of B's streams");
        kinds.insert(got.0, got.1);
    }
    assert_eq!(kinds.get(&cam), Some(&STREAM_KIND_MEDIA));
    assert_eq!(kinds.get(&share), Some(&STREAM_KIND_SHARE));
    let mut heard = Heard::new();
    let bk = b.key.key_id.clone();
    let drain = |frames: &mut tokio::sync::mpsc::Receiver<_>, heard: &mut Heard| {
        drain_from(frames, heard, &bk);
    };
    for seq in 0..60u64 {
        cb.publish(Frame::opaque(body("cam", seq)))
            .await
            .expect("camera");
        cb.publish_on(share, Frame::opaque(body("share", seq)))
            .await
            .expect("share");
        drain(&mut frames, &mut heard);
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let both = wait_until(Duration::from_secs(20), || {
        drain(&mut frames, &mut heard);
        let n = |s| heard.get(&s).map_or(0, std::collections::BTreeSet::len);
        let ok = n(cam) >= 50 && n(share) >= 50;
        async move { ok }
    })
    .await;
    assert!(
        both,
        "A hears both streams: camera {}, share {}",
        heard.get(&cam).map_or(0, std::collections::BTreeSet::len),
        heard.get(&share).map_or(0, std::collections::BTreeSet::len)
    );
    // v45.1.7 — B's send row for the share names the share's codec.
    let share_label = stream_label(share);
    let snap = b.metrics.snapshot();
    let share_codec: Vec<_> =
        common::call_leg_series(&snap.call_legs, CALL_CODEC, &a.key.key_id, "send")
            .into_iter()
            .filter(|s| {
                common::call_leg_attr(s, "ciris.call.stream_id") == Some(share_label.as_str())
            })
            .collect();
    assert_eq!(share_codec.len(), 1, "{:?}", snap.call_legs);
    assert_eq!(
        common::call_leg_attr(share_codec[0], "codec"),
        Some("opus"),
        "the share's send row names its registered codec: {:?}",
        share_codec[0]
    );
    cb.end_stream(share).await.expect("B stops sharing");
    assert_eq!(cb.streams().await, vec![cam], "the camera carries on");
    assert!(
        cb.publish_on(share, Frame::opaque(body("share", 99)))
            .await
            .is_err(),
        "an ended share takes no more frames"
    );
    let ended = next_event(&mut events, Duration::from_secs(10), |e| match e {
        CallEvent::StreamEnded {
            publisher,
            stream,
            cause,
            ..
        } if *publisher == b.key.key_id => Some((*stream, *cause)),
        CallEvent::AttendeeLeft { key_id, .. } if *key_id == b.key.key_id => {
            panic!("ending a share is not a leave")
        }
        CallEvent::StreamReplaced { publisher, .. } if *publisher == b.key.key_id => {
            panic!("a share is not a replacement")
        }
        _ => None,
    })
    .await;
    assert_eq!(ended, Some((share, LeaveCause::Ended)), "end = 3, no leave");
    // The camera is untouched: its frames keep coming.
    let before = heard.get(&cam).map_or(0, std::collections::BTreeSet::len);
    for seq in 60..100u64 {
        cb.publish(Frame::opaque(body("cam", seq)))
            .await
            .expect("camera after the share");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let more = wait_until(Duration::from_secs(10), || {
        drain(&mut frames, &mut heard);
        let ok = heard.get(&cam).map_or(0, std::collections::BTreeSet::len) >= before + 30;
        async move { ok }
    })
    .await;
    assert!(more, "B's camera carries on after the share ends");
    while let Ok(e) = events.try_recv() {
        match e {
            CallEvent::AttendeeLeft { key_id, .. } if key_id == b.key.key_id => {
                panic!("no leave for B")
            }
            CallEvent::StreamReplaced { publisher, .. } if publisher == b.key.key_id => {
                panic!("no replacement for B")
            }
            _ => {}
        }
    }
    assert_eq!(av(&b.metrics, "end_flush_unconfirmed"), 0);
}

/// A video frame of `len` bytes, its first 8 bytes naming it.
fn video(tag: u64, len: usize) -> Frame {
    let mut bytes = tag.to_be_bytes().to_vec();
    bytes.extend((0..len.saturating_sub(8)).map(|i| u8::try_from(i % 251).unwrap()));
    Frame {
        codec_id: ciris_edge::transport::realtime_av::CODEC_TEMPORAL_LAYERED,
        layer: ChunkLayer::BASE,
        bytes,
    }
}

/// What a failed media witness prints for one end of the call: its A/V
/// counters, binding and reorder counts, and its ALM counts and parents.
fn call_diag(who: &str, call: &Call, node: &Node) -> String {
    let mut plane: Vec<(String, u64)> = node.metrics.av_plane().into_iter().collect();
    plane.sort();
    format!(
        "{who}: av {plane:?}; auth {:?}; reorder {:?}; alm {:?}; parents {:?}; lost {:?}",
        call.chunk_auth_counts(),
        call.reorder_counts(),
        call.alm_counts(),
        call.alm_parents(),
        call.frames_lost_by_layer(),
    )
}

/// One Ed25519 sign and one strict verify in this build, in microseconds
/// (the best of 20): what a publisher pays per chunk, and a receiver.
fn chunk_sig_cost_us() -> (u128, u128) {
    use ciris_crypto::{ClassicalSigner as _, Ed25519Signer, Ed25519Verifier};
    let key = Ed25519Signer::random().expect("key");
    let public = key.verifying_key().to_bytes();
    let msg = [7u8; 300];
    let (mut sign, mut verify) = (u128::MAX, u128::MAX);
    for _ in 0..20 {
        let t = std::time::Instant::now();
        let sig = key.sign(&msg).expect("sign");
        sign = sign.min(t.elapsed().as_micros());
        let t = std::time::Instant::now();
        assert!(Ed25519Verifier::new()
            .verify_strict(&public, &msg, &sig)
            .expect("verify"));
        verify = verify.min(t.elapsed().as_micros());
    }
    (sign, verify)
}

/// The first eight bytes of each frame: the tag [`video`] writes.
fn tags(frames: &[Vec<u8>]) -> Vec<u64> {
    frames
        .iter()
        .map(|f| {
            f.get(..8)
                .and_then(|b| <[u8; 8]>::try_from(b).ok())
                .map_or(u64::MAX, u64::from_be_bytes)
        })
        .collect()
}

/// How long a stream's receive view must stay unchanged to count as
/// settled: two offer rounds.
const VIEW_SETTLE_WINDOW: Duration = Duration::from_secs(2);

/// Wait until `stream`'s receive view at `call` holds still for
/// [`VIEW_SETTLE_WINDOW`] (its selector and admission settled: no Decision
/// or Shed on it); returns the view.
async fn wait_view_settled(
    call: &Call,
    stream: ciris_edge::transport::realtime_av::StreamId,
) -> u64 {
    let deadline = tokio::time::Instant::now() + Duration::from_mins(1);
    loop {
        let v = call.layer_view(stream);
        tokio::time::sleep(VIEW_SETTLE_WINDOW).await;
        if call.layer_view(stream) == v {
            return v;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the stream's view never settled"
        );
    }
}

/// **Framed video, unmarked audio** (v45, CC reading rc18): B joins with
/// `{h264, opus}`, so its binding signs `framing = 1`. It publishes a 30 KB
/// keyframe, then 3 KB P-frames at 30 Hz with Opus frames between them. The
/// keyframe and every P-frame larger than one chunk go as several fragments;
/// A hands each video frame out whole and byte-identical, and every audio
/// frame as sent (audio never carries the marker). Then A's leg withholds
/// every 7th chunk: each video frame missing a fragment is dropped whole and
/// counted `av_frame_incomplete`, and nothing partial is ever handed out.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn framed_video_arrives_whole_and_audio_unmarked() {
    use ciris_edge::transport::av_chunk_auth::{CodecMap, CodecToken};
    use ciris_edge::transport::realtime_av::{CODEC_OPAQUE, CODEC_TEMPORAL_LAYERED};
    let _call = one_call().await;
    let tag = "alm2-framed";
    let (nodes, groups, _tmp) = topo(tag, 2, 2, &[(0, 1)], None).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let phone = CallOptions {
        codecs: Some(CodecMap::new([CodecToken::Opus, CodecToken::H264]).expect("map")),
        ..CallOptions::default()
    };
    let mut ca = join_loaded(a, &groups[0], tag, CallOptions::default(), None).await;
    let mut cb = join_loaded(b, &groups[1], tag, phone, None).await;
    wait_legs(&ca, 1).await;
    wait_legs(&cb, 1).await;
    wait_bound(&ca, 1).await;
    let mut frames = ca.frames().expect("A's frames");
    let budget = cb.chunk_plaintext_budget().expect("a leg is up");
    let mut sent_video = Vec::new();
    let mut sent_audio = Vec::new();
    let unix_ms = || {
        u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_millis(),
        )
        .expect("ms")
    };
    let t0 = unix_ms();
    let key = cb.publish(video(0, 30_000)).await.expect("keyframe");
    assert_eq!(
        usize::from(key.fragments),
        30_000usize.div_ceil(budget - 8),
        "the keyframe is cut to the budget ({budget} B)"
    );
    sent_video.push(video(0, 30_000).bytes);
    for n in 1..=30u64 {
        let f = video(n, 3_000);
        sent_video.push(f.bytes.clone());
        cb.publish(f).await.expect("P-frame");
        let opus = body("opus", n);
        sent_audio.push(opus.clone());
        cb.publish(Frame::opaque(opus)).await.expect("audio");
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    let t1 = unix_ms();
    let mut got_video = Vec::new();
    let mut got_audio = Vec::new();
    let mut video_meta = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(20), async {
        while got_video.len() < sent_video.len() || got_audio.len() < sent_audio.len() {
            match frames.recv().await {
                Some(f) if f.publisher == b.key.key_id => match f.codec_id {
                    CODEC_OPAQUE => got_audio.push(f.bytes),
                    CODEC_TEMPORAL_LAYERED => {
                        video_meta.push((f.frame_seq, f.source_ts_ms));
                        got_video.push(f.bytes);
                    }
                    _ => {}
                },
                Some(_) => {}
                None => break,
            }
        }
    })
    .await;
    assert!(
        got_video == sent_video,
        "every video frame whole, in order: got tags {:?} of {}; A holds B's map {:?}; \
         published in {} ms; sign/verify {:?} us; B's legs {:?}\n{}\n{}",
        tags(&got_video),
        sent_video.len(),
        ca.stream_codecs(cb.stream()),
        t1 - t0,
        chunk_sig_cost_us(),
        cb.leg_info(),
        call_diag("A", &ca, a),
        call_diag("B", &cb, b),
    );
    assert_eq!(got_audio, sent_audio, "every audio frame as sent, unmarked");
    assert_eq!(av(&a.metrics, "av_frame_incomplete"), 0);
    // Eric 2026-11-10: each video frame carries its class's frame_seq (0, 1,
    // ... in order) and the publisher's signed source timestamp.
    let seqs: Vec<Option<u32>> = video_meta.iter().map(|(s, _)| *s).collect();
    let want: Vec<Option<u32>> = (0..u32::try_from(sent_video.len()).unwrap())
        .map(Some)
        .collect();
    assert_eq!(seqs, want, "frame_seq counts the video frames from 0");
    for (_, ts) in &video_meta {
        assert!(
            (t0..=t1).contains(ts),
            "source_ts {ts} within the send window {t0}..={t1}"
        );
    }
    assert!(
        video_meta.windows(2).all(|w| w[0].1 <= w[1].1),
        "source timestamps in order"
    );
    assert!(ca.frames_lost_by_layer().is_empty(), "nothing lost yet");

    // Loss: every 7th chunk to A withheld, once B's stream is settled at A
    // (no Decision or Shed on it for a window), so every lost base frame is
    // on a layer A is steadily getting.
    let b_stream = cb.stream();
    let view = wait_view_settled(&ca, b_stream).await;
    // Both ends of a loss gap must lie in one receive view to count. The
    // frames above may have come before A's first admission (its ADMIT is a
    // new view): three clean frames handed out in the settled view anchor
    // the gap's left end in it (45.3; the ADMIT's landing after frame 30 was
    // a timing accident that once happened to fall the other way).
    let anchor: Vec<Vec<u8>> = (90..93u64).map(|n| video(n, 3_000).bytes).collect();
    for n in 90..93u64 {
        cb.publish(video(n, 3_000)).await.expect("P-frame");
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    let mut anchored = 0usize;
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while anchored < anchor.len() {
            match frames.recv().await {
                Some(f) if f.publisher == b.key.key_id && anchor.contains(&f.bytes) => {
                    anchored += 1;
                }
                Some(_) => {}
                None => break,
            }
        }
    })
    .await;
    assert_eq!(anchored, anchor.len(), "the anchor frames arrive whole");
    assert_eq!(ca.layer_view(b_stream), view, "in the settled view");
    cb.withhold_from_for_test(&a.key.key_id, 7);
    let mut lossy = Vec::new();
    for n in 100..130u64 {
        let f = video(n, 3_000);
        lossy.push(f.bytes.clone());
        cb.publish(f).await.expect("P-frame");
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    // Loss ends; three clean frames close the last lossy frame's run.
    cb.withhold_from_for_test(&a.key.key_id, 0);
    for n in 200..203u64 {
        cb.publish(video(n, 3_000)).await.expect("P-frame");
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    let mut after = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(f) = frames.recv().await {
            if f.publisher == b.key.key_id && f.codec_id == CODEC_TEMPORAL_LAYERED {
                after.push(f.bytes);
            }
        }
    })
    .await;
    let dropped = av(&a.metrics, "av_frame_incomplete");
    let lost = ca.frames_lost_by_layer();
    assert_eq!(
        ca.layer_view(b_stream),
        view,
        "no Decision or Shed on B's stream during the lossy phase"
    );
    assert_eq!(
        lost.get(&(CODEC_TEMPORAL_LAYERED, (0, 0, 0)))
            .copied()
            .unwrap_or(0),
        dropped,
        "each dropped base frame is exactly one frame_seq gap on (0,0,0): {lost:?}"
    );
    assert!(
        lost.keys().all(|(class, _)| *class != CODEC_OPAQUE),
        "audio is never counted here"
    );
    assert!(dropped > 0, "a withheld fragment drops its frame, counted");
    let clean: Vec<Vec<u8>> = (200..203u64).map(|n| video(n, 3_000).bytes).collect();
    assert!(
        after.iter().all(|f| lossy.contains(f) || clean.contains(f)),
        "nothing partial is handed out"
    );
    after.retain(|f| lossy.contains(f));
    assert_eq!(
        after.len() + usize::try_from(dropped).unwrap(),
        lossy.len(),
        "each frame either whole or counted dropped, once"
    );
}

/// The receiver's event loop handles one arriving datagram per
/// [`LOADED_RECEIVER_DELAY`], deliberately: what a phone, or this box under
/// another build, does. The v45.0.0 gate saw this once by accident
/// (`framed_video_arrives_whole_and_audio_unmarked`, `av_datagram_shed_sink`
/// 8 right after the keyframe), so the witness makes the load itself and
/// never depends on what else runs.
const LOADED_RECEIVER_DELAY: Duration = Duration::from_millis(2);

/// **A keyframe reaches a loaded receiver whole** (v45). B publishes a
/// 30 KB keyframe: about 127 datagrams at the loopback budget, sent back to
/// back. A's event loop takes [`LOADED_RECEIVER_DELAY`] per datagram, so it
/// drains leviculum's data plane at about 500 datagrams/s while the burst
/// lands in a few ms. At leviculum's default data plane (128 events, a
/// datagram shed while 96 are queued) the burst's tail is shed at A's sink
/// (`av_datagram_shed_sink`) and the keyframe is lost whole, and v45.0.0 has
/// no repair. Edge's data plane (`DATA_CHANNEL_CAPACITY`, 1024) holds the
/// burst: nothing is shed, and the keyframe and the P-frames behind it
/// arrive whole and in order.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_keyframe_reaches_a_loaded_receiver_whole() {
    use ciris_edge::transport::av_chunk_auth::{CodecMap, CodecToken};
    let _call = one_call().await;
    let tag = "alm2-loaded";
    let (nodes, groups, _tmp) = topo(tag, 2, 2, &[(0, 1)], None).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let phone = CallOptions {
        codecs: Some(CodecMap::new([CodecToken::Opus, CodecToken::H264]).expect("map")),
        ..CallOptions::default()
    };
    let mut ca = join_loaded(a, &groups[0], tag, CallOptions::default(), None).await;
    let mut cb = join_loaded(b, &groups[1], tag, phone, None).await;
    wait_legs(&ca, 1).await;
    wait_legs(&cb, 1).await;
    // Both of B's bindings, v1 AND v2: the v2 carries the framing and goes
    // only after the CAPS exchange, later than v1. Publishing on v1 alone
    // raced it: the keyframe's chunks waited FRAMING_HOLD for a framing the
    // loaded receiver had not verified yet and were dropped as unknown under
    // a busy host (45.3; failed on v45.2.0 too). This witness is about the
    // data plane holding the burst, not about binding timing.
    wait_bound(&ca, 2).await;
    let mut frames = ca.frames().expect("A's frames");
    a.transport.refresh_metrics();
    let shed_before = av(&a.metrics, "av_datagram_shed_sink");
    a.transport
        .set_datagram_handling_delay_for_test(LOADED_RECEIVER_DELAY);
    let mut sent = vec![video(0, 30_000).bytes];
    let key = cb.publish(video(0, 30_000)).await.expect("keyframe");
    assert!(
        key.fragments > 100,
        "a keyframe of more than 100 datagrams: {}",
        key.fragments
    );
    // P-frames of 1 KB (5 datagrams) at 30 Hz: 150 datagrams/s, well under
    // what A drains, so only the keyframe's burst can overrun it.
    for n in 1..=10u64 {
        sent.push(video(n, 1_000).bytes);
        cb.publish(video(n, 1_000)).await.expect("P-frame");
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        while got.len() < sent.len() {
            match frames.recv().await {
                Some(f) if f.publisher == b.key.key_id => got.push(f.bytes),
                Some(_) => {}
                None => break,
            }
        }
    })
    .await;
    a.transport
        .set_datagram_handling_delay_for_test(Duration::ZERO);
    a.transport.refresh_metrics();
    let shed = av(&a.metrics, "av_datagram_shed_sink") - shed_before;
    assert!(
        got == sent && shed == 0,
        "every frame whole, in order, nothing shed at A's sink: got tags {:?} of {}; \
         shed {shed}; B's legs {:?}\n{}\n{}",
        tags(&got),
        sent.len(),
        cb.leg_info(),
        call_diag("A", &ca, a),
        call_diag("B", &cb, b),
    );
}

/// **A backgrounded camera beside a live share** (v45, CC review of
/// desktop sharing): B shares its screen, then backgrounds its camera
/// (`end = 2` on the camera stream). A reads `StreamEnded { camera,
/// backgrounded }`, never `AttendeeLeft`, and B's share keeps arriving.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_backgrounded_camera_beside_a_live_share_plays_the_share_on() {
    use ciris_edge::transport::av_call::LeaveCause;
    use ciris_edge::transport::av_chunk_auth::SignedEnd;
    let _call = one_call().await;
    let tag = "alm2-share-bg";
    let (nodes, groups, _tmp) = topo(tag, 2, 2, &[(0, 1)], None).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let mut ca = join_loaded(a, &groups[0], tag, CallOptions::default(), None).await;
    let mut cb = join_loaded(b, &groups[1], tag, CallOptions::default(), None).await;
    wait_legs(&ca, 1).await;
    wait_legs(&cb, 1).await;
    wait_bound(&ca, 1).await;
    let mut events = ca.events().expect("A's events");
    let mut frames = ca.frames().expect("A's frames");
    let cam = cb.stream();
    let share = cb.add_stream(None).await.expect("B shares");
    wait_bound(&ca, 2).await;
    for seq in 0..20u64 {
        cb.publish(Frame::opaque(body("cam", seq)))
            .await
            .expect("camera");
        cb.publish_on(share, Frame::opaque(body("share", seq)))
            .await
            .expect("share");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    cb.end_stream_as(cam, SignedEnd::Backgrounded)
        .await
        .expect("B backgrounds its camera");
    assert!(
        cb.publish(Frame::opaque(body("cam", 99))).await.is_err(),
        "the camera takes no more frames"
    );
    let ended = next_event(&mut events, Duration::from_secs(10), |e| match e {
        CallEvent::StreamEnded {
            publisher,
            stream,
            cause,
            ..
        } if *publisher == b.key.key_id => Some((*stream, *cause)),
        CallEvent::AttendeeLeft { key_id, .. } if *key_id == b.key.key_id => {
            panic!("a backgrounded camera beside a live share is no leave")
        }
        _ => None,
    })
    .await;
    assert_eq!(ended, Some((cam, LeaveCause::Backgrounded)));
    let mut heard = Heard::new();
    drain_from(&mut frames, &mut heard, &b.key.key_id);
    let before = heard.get(&share).map_or(0, std::collections::BTreeSet::len);
    for seq in 100..140u64 {
        cb.publish_on(share, Frame::opaque(body("share", seq)))
            .await
            .expect("the share after the camera");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let bk = b.key.key_id.clone();
    let more = wait_until(Duration::from_secs(10), || {
        drain_from(&mut frames, &mut heard, &bk);
        let ok = heard.get(&share).map_or(0, std::collections::BTreeSet::len) >= before + 30;
        async move { ok }
    })
    .await;
    assert!(more, "the share keeps arriving");
    while let Ok(e) = events.try_recv() {
        if let CallEvent::AttendeeLeft { key_id, .. } = e {
            assert_ne!(key_id, b.key.key_id, "no leave for B");
        }
    }
}

/// Every video frame `frames` hands out within `secs`.
async fn video_frames(
    frames: &mut tokio::sync::mpsc::Receiver<ReceivedFrame>,
    secs: u64,
) -> Vec<Vec<u8>> {
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(secs), async {
        while let Some(f) = frames.recv().await {
            if f.codec_id == ciris_edge::transport::realtime_av::CODEC_TEMPORAL_LAYERED {
                got.push(f.bytes);
            }
        }
    })
    .await;
    got
}

/// **Framed video through a relay** (v45): A relays B's framed stream
/// (`{h264, opus}`) to C (B and C share no leg). Every fragment is a whole
/// chunk A forwards unchanged (it never opens the inner seal), so C rebuilds
/// each frame byte-identical. Then A's leg to C loses every 7th forwarded
/// chunk: C gets each frame whole or counts it dropped
/// (`av_frame_incomplete`), never partial. (A relay cannot drop the rest of
/// a frame after one fragment fails: the marker is sealed. C's reassembly
/// drops the torn frame instead.)
// a, b, c: the nodes as the roster witness names them.
#[allow(clippy::many_single_char_names, clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn framed_video_through_a_relay_arrives_whole_or_counted() {
    use ciris_edge::transport::av_chunk_auth::{CodecMap, CodecToken};
    let _call = one_call().await;
    let tag = "alm2-framed-relay";
    let (nodes, groups, _tmp) = topo(
        tag,
        4,
        3,
        &[(0, 1), (0, 2), (0, 3), (1, 3), (2, 3)],
        Some(3),
    )
    .await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let phone = CallOptions {
        codecs: Some(CodecMap::new([CodecToken::Opus, CodecToken::H264]).expect("map")),
        ..CallOptions::default()
    };
    let ca = join_loaded(a, &groups[0], tag, relay_opts(), None).await;
    let mut cb = join_loaded(b, &groups[1], tag, phone, None).await;
    let mut cc = join_loaded(c, &groups[2], tag, CallOptions::default(), None).await;
    wait_legs(&ca, 2).await;
    wait_legs(&cb, 1).await;
    wait_legs(&cc, 1).await;
    let b_stream = cb.stream();
    assert!(
        wait_until(Duration::from_secs(90), || async {
            primary_for(&cc, b_stream).as_deref() == Some(a.key.key_id.as_str())
        })
        .await,
        "C hears B through A: {:?}",
        cc.alm_parents()
    );
    let mut frames = cc.frames().expect("C's frames");
    let forwarded_before = ca.alm_counts().forwarded;
    let mut sent = vec![video(0, 20_000).bytes];
    let key = cb.publish(video(0, 20_000)).await.expect("keyframe");
    assert!(key.fragments > 1, "the keyframe is fragmented");
    for n in 1..=20u64 {
        let f = video(n, 3_000);
        sent.push(f.bytes.clone());
        cb.publish(f).await.expect("P-frame");
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    let got = video_frames(&mut frames, 10).await;
    assert!(
        got == sent,
        "every frame whole through the relay: got tags {:?} of {}; C holds B's map {:?}, A {:?}\n{}\n{}\n{}",
        tags(&got),
        sent.len(),
        cc.stream_codecs(b_stream),
        ca.stream_codecs(b_stream),
        call_diag("C", &cc, c),
        call_diag("A", &ca, a),
        call_diag("B", &cb, b),
    );
    assert!(ca.alm_counts().forwarded - forwarded_before >= u64::from(key.fragments));
    assert_eq!(av(&c.metrics, "av_frame_incomplete"), 0);

    // Loss on the relay's leg to C.
    ca.withhold_forward_for_test(&c.key.key_id, 7);
    let mut lossy = Vec::new();
    for n in 100..130u64 {
        let f = video(n, 3_000);
        lossy.push(f.bytes.clone());
        cb.publish(f).await.expect("P-frame");
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    ca.withhold_forward_for_test(&c.key.key_id, 0);
    let clean: Vec<Vec<u8>> = (200..203u64).map(|n| video(n, 3_000).bytes).collect();
    for n in 200..203u64 {
        cb.publish(video(n, 3_000)).await.expect("P-frame");
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    let mut after = video_frames(&mut frames, 6).await;
    assert!(
        after.iter().all(|f| lossy.contains(f) || clean.contains(f)),
        "nothing partial is handed out"
    );
    after.retain(|f| lossy.contains(f));
    let dropped = av(&c.metrics, "av_frame_incomplete");
    assert!(
        dropped > 0,
        "a fragment lost on the relay's leg drops its frame"
    );
    assert_eq!(
        after.len() + usize::try_from(dropped).unwrap(),
        lossy.len(),
        "each frame whole or counted dropped, once"
    );
}

/// **A mixed call** (v45, CC's run-green witness for the framing hold): C
/// behaves as v44 (no `CAPS` bit 5, v1 bindings only) and reaches B only
/// through the relay A, so B never hears C's own `CAPS`. B plays C's audio;
/// C's video is held for a v2 binding that never comes, then dropped and
/// counted `av_frame_framing_unknown`, never parsed unframed. Nothing is
/// refused (no binding refusal at B) and nothing is evicted: C's audio keeps
/// playing after the drops.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_v44_publisher_behind_a_relay_plays_audio_and_its_video_is_held_then_dropped() {
    use ciris_edge::transport::realtime_av::CODEC_OPAQUE;
    use ciris_edge::transport::realtime_av_alm::controller::wire::CAP_BINDING_V2;
    let _call = one_call().await;
    let tag = "alm2-mixed";
    // 0 = A, 1 = B, 2 = C (the room); 3 = T (canonical: transport on, no
    // member), so B and C learn each other with no leg between them.
    let (nodes, groups, _tmp) = topo(
        tag,
        4,
        3,
        &[(0, 1), (0, 2), (0, 3), (1, 3), (2, 3)],
        Some(3),
    )
    .await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    c.transport.set_av_caps_withheld_for_test(CAP_BINDING_V2);
    let ca = join_loaded(a, &groups[0], tag, relay_opts(), None).await;
    let mut cb = join_loaded(b, &groups[1], tag, CallOptions::default(), None).await;
    let mut cc = join_loaded(c, &groups[2], tag, CallOptions::default(), None).await;
    wait_legs(&ca, 2).await;
    wait_legs(&cb, 1).await;
    wait_legs(&cc, 1).await;
    assert_eq!(cb.legs(), vec![a.key.key_id.clone()], "B reaches only A");
    let mut rx = cb.frames().expect("B's frames");
    let mut audio = 0usize;
    let mut video = 0usize;
    for seq in 0..400u64 {
        cc.publish(Frame::opaque(body("c-audio", seq)))
            .await
            .expect("audio");
        let _ = cc
            .publish(Frame {
                codec_id: CODEC_AV1_SVC,
                layer: ChunkLayer::BASE,
                bytes: body("c-video", seq),
            })
            .await;
        while let Ok(f) = rx.try_recv() {
            if f.publisher == c.key.key_id {
                if f.codec_id == CODEC_OPAQUE {
                    audio += 1;
                } else {
                    video += 1;
                }
            }
        }
        if audio >= 50 && av(&b.metrics, "av_frame_framing_unknown") >= 20 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(audio >= 50, "C's audio plays at B: {audio}");
    assert_eq!(video, 0, "C's video is never handed out unframed");
    let dropped = av(&b.metrics, "av_frame_framing_unknown");
    assert!(dropped >= 20, "held, then dropped and counted: {dropped}");
    assert_eq!(
        cb.chunk_auth_counts().bindings_refused,
        0,
        "nothing refused: C's v1 binding stands"
    );
    // Not evicted: C's audio still plays after the drops.
    let before = audio;
    for seq in 1_000..1_040u64 {
        cc.publish(Frame::opaque(body("c-audio", seq)))
            .await
            .expect("audio");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let more = wait_until(Duration::from_secs(10), || {
        while let Ok(f) = rx.try_recv() {
            if f.publisher == c.key.key_id && f.codec_id == CODEC_OPAQUE {
                audio += 1;
            }
        }
        let ok = audio >= before + 30;
        async move { ok }
    })
    .await;
    assert!(more, "C's stream stands at B after the drops");
}

/// **Per-leg stats** (v45): every leg a call reports names what carries it
/// and its MDU, so a gate can tell a punched UDP leg from a TCP one from a
/// relayed one. On loopback TCP every leg is `Interface`, with a link MDU,
/// a Channel limit and a frame budget above zero. (A leg's carrier may move
/// to datagrams when its peer's CAPS lands, so no two reads are compared.)
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn every_leg_reports_its_path_and_mdu() {
    let _call = one_call().await;
    let tag = "alm2-leginfo";
    let (nodes, groups, _tmp) = topo(tag, 3, 3, &[(0, 1), (0, 2), (1, 2)], None).await;
    let calls = [
        join_loaded(&nodes[0], &groups[0], tag, CallOptions::default(), None).await,
        join_loaded(&nodes[1], &groups[1], tag, CallOptions::default(), None).await,
        join_loaded(&nodes[2], &groups[2], tag, relay_opts(), None).await,
    ];
    for c in &calls {
        wait_legs(c, 2).await;
        let info = c.leg_info();
        assert_eq!(
            info.iter().map(|l| l.member.clone()).collect::<Vec<_>>(),
            c.legs(),
            "one entry per leg"
        );
        for l in &info {
            assert_eq!(
                l.path,
                ciris_edge::transport::av_call::LegPath::Interface,
                "a loopback TCP leg: {l:?}"
            );
            assert!(
                l.link_mdu > 0 && l.channel_limit > 0 && l.media_limit > 0 && l.frame_budget > 0,
                "{l:?}"
            );
            assert!(
                l.frame_budget < l.media_limit && l.media_limit <= l.link_mdu,
                "{l:?}"
            );
        }
    }
}

/// **C3 admit / refuse**: A's own stream admits B (C2 over C3); C, a relay
/// at service tier 1 (the host said `Warning`), refuses B's subscription
/// for A's stream by name, `load_refuse:admit_closed`. A closed relay offers
/// no room (v45), so no selector picks it: B is made to ask.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn c3_admits_and_a_closed_relay_refuses_by_name() {
    let _call = one_call().await;
    let tag = "alm2-c3";
    let (nodes, groups, _tmp) = topo(tag, 3, 3, &[(0, 1), (0, 2), (1, 2)], None).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let ladder = Arc::new(ciris_edge::load_ladder::SharedLadder::default());
    assert_eq!(
        ladder.set_host_pressure(ciris_edge::LoadPressure::Warning),
        ciris_edge::ServiceTier::AudioAndFiles
    );
    let ca = join_loaded(a, &groups[0], tag, CallOptions::default(), None).await;
    let cb = join_loaded(b, &groups[1], tag, CallOptions::default(), None).await;
    let cc = join_loaded(c, &groups[2], tag, relay_opts(), Some(Arc::clone(&ladder))).await;
    wait_legs(&ca, 2).await;
    wait_legs(&cb, 2).await;
    wait_legs(&cc, 2).await;

    let admitted = wait_until(Duration::from_mins(1), || async {
        ca.alm_own_children().iter().any(|(p, r)| {
            *p == b.key.key_id
                && *r == ciris_edge::transport::realtime_av_alm::controller::Role::Primary
        })
    })
    .await;
    assert!(
        admitted,
        "A admits B: {:?} log {:?}",
        ca.alm_own_children(),
        ca.alm_log()
    );
    // A's ledger moves when it decides; B's selector when the ADMIT lands.
    assert!(
        wait_until(Duration::from_secs(30), || async {
            primary_for(&cb, ca.stream()).as_deref() == Some(a.key.key_id.as_str())
        })
        .await,
        "B records A as its parent: {:?} log {:?}; A's ledger {:?} legs {:?} c3 peers {:?} sent {} failed {}",
        cb.alm_parents(),
        cb.alm_log(),
        ca.alm_own_children(),
        ca.legs(),
        ca.alm_c3_peers(),
        av(&a.metrics, "alm_c3_sent"),
        av(&a.metrics, "alm_c3_send_failed")
    );

    // C forwards A's stream only once it has a parent for it.
    assert!(
        wait_until(Duration::from_mins(1), || async {
            primary_for(&cc, ca.stream()).is_some()
        })
        .await,
        "C hears A: {:?}",
        cc.alm_parents()
    );
    cb.send_c3_for_test(
        &c.key.key_id,
        encode(
            ca.stream(),
            &ControlMsg::Subscribe(SubscribeRequest {
                subscriber: b.key.key_id.clone(),
                role: Role::Standby,
                forward_capable: false,
                layers: None,
            }),
        ),
    )
    .await;
    let refused = wait_until(Duration::from_mins(1), || async {
        cc.alm_counts()
            .refused
            .get("load_refuse:admit_closed")
            .copied()
            .unwrap_or(0)
            > 0
    })
    .await;
    assert!(
        refused,
        "C (tier 1) refuses by name: {:?}; B's parents {:?}",
        cc.alm_counts(),
        cb.alm_parents()
    );
    assert_eq!(cc.service_tier(), ciris_edge::ServiceTier::AudioAndFiles);
    assert!(
        cc.alm_relay_children(ca.stream()).is_empty(),
        "a closed relay admits nobody"
    );
    // The count moves as the frame lands; the label reaches the metrics on
    // C's next watch tick.
    assert!(
        wait_until(Duration::from_secs(5), || async {
            av(&c.metrics, "load_refuse:admit_closed") > 0
        })
        .await,
        "the refusal is counted under its token: {:?}",
        c.metrics.av_plane()
    );
    eprintln!(
        "[ALM2] c3: A admitted {:?}; C refused {:?}",
        ca.alm_own_children(),
        cc.alm_counts().refused
    );
}

/// **Stale frames (C5)**: B's consumer stalls 1.5 s while A publishes; the
/// media that waited past 800 ms is dropped by age before it is opened, the
/// hop counter skips past it, and the frames after the stall open and
/// arrive. Media between peers whose CAPS say they take datagrams rides
/// unordered datagrams (leviculum#102); timed Channel frames are the fallback
/// toward an older peer (`av_call_nat_805`).
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn stale_media_is_dropped_by_age_and_the_hop_recovers() {
    let _call = one_call().await;
    let tag = "alm2-stale";
    let (nodes, groups, _tmp) = topo(tag, 2, 2, &[(0, 1)], None).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let mut ca = join_loaded(a, &groups[0], tag, CallOptions::default(), None).await;
    let mut cb = join_loaded(b, &groups[1], tag, CallOptions::default(), None).await;
    wait_legs(&ca, 1).await;
    wait_legs(&cb, 1).await;
    wait_bound(&cb, 1).await;
    assert!(
        wait_until(Duration::from_secs(30), || async {
            ca.alm_c3_peers().len() == 1
        })
        .await,
        "A hears B's CAPS"
    );
    let mut rx = cb.frames().expect("B's frames");
    // A is B's parent before the stall: CALM rides the stalled pump too, and
    // an unsubscribed path is not metered, so the frames below must land on
    // a path that is.
    assert!(
        wait_until(Duration::from_secs(30), || async {
            primary_for(&cb, ca.stream()).as_deref() == Some(a.key.key_id.as_str())
        })
        .await,
        "A is B's primary: {:?}",
        cb.alm_log()
    );
    cb.stall_inbound_for_test(Duration::from_millis(1_500));
    for seq in 0..60 {
        ca.publish(Frame::opaque(body("a", seq)))
            .await
            .expect("publish");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(800)).await;
    for seq in 60..90 {
        ca.publish(Frame::opaque(body("a", seq)))
            .await
            .expect("publish");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // The 30 frames after the stall all arrive.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut got: Vec<Vec<u8>> = Vec::new();
    while !got.contains(&body("a", 89)) {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(f)) => got.push(f.bytes),
            _ => break,
        }
    }
    let stale = cb.alm_counts().stale_dropped;
    let after: usize = (60..90).filter(|s| got.contains(&body("a", *s))).count();
    eprintln!(
        "[ALM2] stale: dropped_by_age={stale} delivered={} after_stall={after}/30 datagrams_sent={} timed_sent={} unopened={}",
        got.len(),
        av(&a.metrics, "av_sent_datagram"),
        av(&a.metrics, "av_sent_timed"),
        av(&b.metrics, "av_call_frame_unopened")
    );
    assert!(stale > 0, "media older than 800 ms was dropped by age");
    assert_eq!(
        after, 30,
        "the hop recovered: every post-stall frame opened"
    );
    // The 30 post-stall frames arrived, so at least 30 left as datagrams.
    assert!(
        av(&a.metrics, "av_sent_datagram") >= 30 && av(&a.metrics, "av_sent_timed") == 0,
        "media rode datagrams, none a timed Channel frame (leviculum#102): {:?}",
        a.metrics.av_plane()
    );
    assert_eq!(
        av(&b.metrics, "av_call_frame_unopened"),
        0,
        "no frame failed its open"
    );
    assert_eq!(cb.legs(), vec![a.key.key_id.clone()], "the link stayed up");
    // CIRISEdge#945: those frames took hop counters and reached this node.
    // The lag was its own, so the path is not charged for them.
    assert_eq!(
        degraded_lines(&cb, &a.key.key_id),
        Vec::<String>::new(),
        "{:?}",
        cb.alm_log()
    );
}

/// **The periodic re-announce is no burst.** Sent back to back, its parts
/// fill the Channel window every 10 s and the egress meter reads that as the
/// uplink: on a loaded host nearly all a call's later congestion followed it,
/// and it kept any ceiling from going stale. A lower bound, so a slow host
/// cannot fail it. Mutation: without the gap the parts go in no time at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_reannounce_is_spread_over_its_parts() {
    let _call = one_call().await;
    let tag = "alm2-spread";
    let (nodes, groups, _tmp) = topo(tag, 2, 2, &[(0, 1)], None).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let ca = join_loaded(a, &groups[0], tag, CallOptions::default(), None).await;
    let cb = join_loaded(b, &groups[1], tag, CallOptions::default(), None).await;
    wait_legs(&ca, 1).await;
    wait_legs(&cb, 1).await;
    wait_bound(&cb, 1).await;
    // A hybrid binding is kilobytes over a base-MTU Channel: many parts.
    let started = tokio::time::Instant::now();
    ca.reannounce_for_test().await;
    let took = started.elapsed();
    eprintln!("[ALM2] re-announce took {took:?}");
    assert!(
        took >= REANNOUNCE_PART_GAP * 4,
        "spread over its parts, not one burst: {took:?}"
    );
}

/// **A lost ADMIT is resent, not withdrawn.** Every must-arrive C3 frame A
/// sends is refused on its first attempt, as a congested link refuses it. B
/// still records A as its parent from the resent ADMIT, and never has to
/// withdraw (its 3 s request timeout never fires). Mutation: without the
/// resend, B gets no ADMIT at all, times out and withdraws.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_refused_admit_is_resent_not_withdrawn() {
    let _call = one_call().await;
    let tag = "alm2-resend";
    let (nodes, groups, _tmp) = topo(tag, 2, 2, &[(0, 1)], None).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let ca = join_loaded(a, &groups[0], tag, CallOptions::default(), None).await;
    ca.fail_next_c3_for_test(u64::MAX);
    let cb = join_loaded(b, &groups[1], tag, CallOptions::default(), None).await;
    let recorded = wait_until(Duration::from_mins(1), || async {
        primary_for(&cb, ca.stream()).as_deref() == Some(a.key.key_id.as_str())
    })
    .await;
    assert!(
        recorded,
        "B records A from the resent ADMIT: {:?} log {:?}",
        cb.alm_parents(),
        cb.alm_log()
    );
    assert_eq!(
        cb.alm_log_count(
            ciris_edge::transport::realtime_av_alm::controller::DecisionKind::Unsubscribe
        ),
        0,
        "B never withdrew: {:?}",
        cb.alm_log()
    );
    assert!(
        av(&a.metrics, "alm_c3_resent") > 0,
        "A resent: {:?}",
        a.metrics.av_plane()
    );
}

/// The C7 lines that put `peer` in `PeerState::Degraded` (value 1).
fn degraded_lines(call: &Call, peer: &str) -> Vec<String> {
    let subject = format!("subj=Some({peer:?}) v=1 ");
    call.alm_log()
        .2
        .lines()
        .filter(|l| l.contains(" PeerState ") && l.contains(&subject))
        .map(str::to_owned)
        .collect()
}

/// `peer`'s latest C7 state in `call`'s log (value 1 is `Degraded`).
fn last_state(call: &Call, peer: &str) -> Option<i64> {
    log_lines(&call.alm_log().2, "PeerState", peer)
        .last()
        .map(|l| l.1)
}

/// Keep `call`'s frame queue moving, and report the newest epoch heard.
fn drain(call: &mut Call) -> (Arc<AtomicU64>, tokio::task::JoinHandle<()>) {
    let mut rx = call.frames().expect("the call's frames");
    let newest = Arc::new(AtomicU64::new(0));
    let seen = Arc::clone(&newest);
    let task = tokio::spawn(async move {
        while let Some(f) = rx.recv().await {
            seen.fetch_max(f.epoch.0, Ordering::Relaxed);
        }
    });
    (newest, task)
}

/// **CIRISEdge#945 item 1, on a live link.** A real room commit rolls A's
/// stream: `chunk_seq` back to 0 in a new epoch, with B's parent direct and
/// the loopback clean. B's path read nothing lost, so it stays Available.
/// Mutation: one sequence key across epochs reads the roll as a loss of about
/// 1.0 and the C7 log shows A going Degraded.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn an_epoch_roll_reads_as_a_resync_on_a_live_link() {
    let _call = one_call().await;
    let tag = "alm2-roll";
    let (nodes, groups, _tmp) = topo(tag, 2, 2, &[(0, 1)], None).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let mut ca = join_loaded(a, &groups[0], tag, CallOptions::default(), None).await;
    let mut cb = join_loaded(b, &groups[1], tag, CallOptions::default(), None).await;
    wait_legs(&ca, 1).await;
    wait_legs(&cb, 1).await;
    wait_bound(&cb, 1).await;
    let (newest, task) = drain(&mut cb);
    let parented = wait_until(Duration::from_secs(30), || async {
        primary_for(&cb, ca.stream()).as_deref() == Some(a.key.key_id.as_str())
    })
    .await;
    assert!(parented, "B chose A: {:?}", cb.alm_log());
    for seq in 0..150 {
        ca.publish(Frame::opaque(body("a", seq)))
            .await
            .expect("publish");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        degraded_lines(&cb, &a.key.key_id),
        Vec::<String>::new(),
        "clean before the roll"
    );
    let pre = ca.epoch().await;
    let up = groups[0].rotate().await.expect("rotate");
    let _ = groups[1]
        .apply_remote_commit(up.commit())
        .await
        .expect("B applies");
    for seq in 150..450 {
        ca.publish(Frame::opaque(body("a", seq)))
            .await
            .expect("publish");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(ca.epoch().await > pre, "A's stream rolled");
    assert!(
        wait_until(Duration::from_secs(5), || async {
            newest.load(Ordering::Relaxed) > pre.0
        })
        .await,
        "B heard the new epoch"
    );
    let lines = degraded_lines(&cb, &a.key.key_id);
    eprintln!(
        "[ALM2] roll: {} -> {}, Degraded lines {}",
        pre.0,
        ca.epoch().await.0,
        lines.len()
    );
    assert_eq!(lines, Vec::<String>::new(), "{:?}", cb.alm_log());
    task.abort();
}

/// **CIRISEdge#945 item 3, on a live call.** A publishes a base and an
/// enhancement layer; B's primary is A, its standby the relay C, which sends
/// it the base only. The enhancement chunks' sequence numbers are gaps on
/// that path it never owed. Mutation: reading them as loss puts C in Degraded.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_layered_standby_is_not_read_as_lossy_on_a_live_call() {
    let _call = one_call().await;
    let tag = "alm2-layered";
    let (nodes, groups, _tmp) = topo(tag, 3, 3, &[(0, 1), (0, 2), (1, 2)], None).await;
    let mut call = layered_call(&nodes, &groups, tag, None).await;
    let quiet = call.quiet_stretch(&nodes, 300, true).await;
    eprintln!(
        "[ALM2] layered standby: C forwarded {} of 150 base chunks, Degraded lines {}, after {} sheds, {} ceilings",
        quiet.forwarded,
        quiet.standby.len(),
        call.ca.alm_counts().shed,
        call.ca.alm_log_count(DecisionKind::Ceiling)
    );
    assert!(
        quiet.forwarded >= 140,
        "C really carried the base layer: {}",
        quiet.forwarded
    );
    assert_eq!(
        quiet.standby,
        Vec::<String>::new(),
        "{:?}",
        call.cb.alm_log()
    );
    assert_eq!(
        quiet.primary,
        Vec::<String>::new(),
        "{:?}",
        call.cb.alm_log()
    );
    call.abort();
}

/// Publish A's stream (base, then an enhancement layer) until C is B's
/// standby and A its primary, then `settle` chunks more. Evenly spaced: a
/// pair sent back to back into a Channel window is refused as Congested
/// (#591), and real loss is not what these are about.
async fn layered_until_standby(
    ca: &mut Call,
    cb: &Call,
    cc: &Call,
    a: &str,
    c: &str,
    from: &mut u64,
    settle: u64,
) {
    let mut standby_from = None;
    // A ceiling learned twice stands 60 s after its last congested window, a
    // third time 120 s, and until it goes A has no room for a second child.
    let deadline = tokio::time::Instant::now() + QUIET_BUDGET;
    while tokio::time::Instant::now() < deadline {
        let k = *from;
        *from += 1;
        ca.publish(layered("a", k)).await.expect("publish");
        tokio::time::sleep(Duration::from_millis(30)).await;
        let parents = cb.alm_parents();
        let p = parents.iter().find(|p| p.stream == ca.stream());
        let on =
            p.is_some_and(|p| p.primary.as_deref() == Some(a) && p.standby.as_deref() == Some(c));
        if on && standby_from.is_none() {
            standby_from = Some(k);
        }
        if standby_from.is_some_and(|at| k >= at + settle) {
            return;
        }
    }
    panic!(
        "C became B's standby: {:?} {:?}\nA's children {:?} committed {:?} counts {:?} log {:?}\n\
         C's parents {:?} forwards {:?} counts {:?} log {:?}",
        cb.alm_parents(),
        cb.alm_log(),
        ca.alm_own_children(),
        ca.alm_committed(),
        ca.alm_counts(),
        ca.alm_log().2,
        cc.alm_parents(),
        cc.alm_relay_children(ca.stream()),
        cc.alm_counts(),
        cc.alm_log().2,
    );
}

/// A chunk of a two-layer stream: even keys are base, odd keys enhancement.
fn layered(who: &str, k: u64) -> Frame {
    Frame {
        codec_id: CODEC_AV1_SVC,
        layer: if k.is_multiple_of(2) {
            ChunkLayer::BASE
        } else {
            ChunkLayer {
                spatial: 1,
                temporal: 0,
                quality: 0,
            }
        },
        bytes: body(who, k),
    }
}

/// `tail`'s C7 lines of `kind` about `peer`, each with its time and value.
fn log_lines(tail: &str, kind: &str, peer: &str) -> Vec<(u64, i64, String)> {
    let subject = format!("subj=Some({peer:?}) v=");
    tail.lines()
        .filter(|l| l.contains(&format!(" {kind} ")) && l.contains(&subject))
        .filter_map(|l| {
            let at = l.strip_prefix("t=")?.split(' ').next()?.parse().ok()?;
            let value = l.split(&subject).nth(1)?.split(' ').next()?.parse().ok()?;
            Some((at, value, l.to_owned()))
        })
        .collect()
}

/// The time of `tail`'s newest C7 line.
fn newest_line_at(tail: &str) -> u64 {
    tail.lines()
        .filter_map(|l| l.strip_prefix("t=")?.split(' ').next()?.parse().ok())
        .max()
        .unwrap_or(0)
}

/// **CIRISEdge#945 finding A, on real links.** B's primary is A, its standby
/// the relay C. A's leg to B closes and stays closed; C keeps delivering. The
/// failover must come from the close, on B's next tick. Before the fix B read
/// "subscribed" as "heard": A went Down, then Recovering, and the call sat on
/// a dead parent until silence made it Suspected (v=2), at 1.5 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_closed_primary_link_fails_over_on_a_live_call() {
    const DOWN: i64 = 3;
    const SUSPECT_SILENCE_MS: u64 = 1_500;
    let _call = one_call().await;
    let tag = "alm2-link-close";
    let (nodes, groups, _tmp) = topo(tag, 3, 3, &[(0, 1), (0, 2), (1, 2)], None).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let mut ca = join_loaded(a, &groups[0], tag, CallOptions::default(), None).await;
    let mut cb = join_loaded(b, &groups[1], tag, CallOptions::default(), None).await;
    let mut cc = join_loaded(c, &groups[2], tag, relay_opts(), None).await;
    wait_legs(&ca, 2).await;
    wait_legs(&cb, 2).await;
    wait_legs(&cc, 2).await;
    wait_bound(&cb, 2).await;
    wait_bound(&cc, 2).await;
    let (_, task_b) = drain(&mut cb);
    let (_, task_c) = drain(&mut cc);
    let mut k = 0;
    layered_until_standby(&mut ca, &cb, &cc, &a.key.key_id, &c.key.key_id, &mut k, 60).await;

    // Only what follows the close: a starved host may have marked anything.
    let closed_at = newest_line_at(&cb.alm_log().2);
    ca.close_leg_for_test(&b.key.key_id).await;
    let mut moved = false;
    for _ in 0..300 {
        ca.publish(layered("a", k)).await.expect("publish");
        k += 1;
        tokio::time::sleep(Duration::from_millis(30)).await;
        if primary_for(&cb, ca.stream()).as_deref() == Some(c.key.key_id.as_str()) {
            moved = true;
            break;
        }
    }
    let log = cb.alm_log().2;
    let (down_at, _, _) = log_lines(&log, "PeerState", &a.key.key_id)
        .into_iter()
        .find(|l| l.0 >= closed_at && l.1 == DOWN)
        .unwrap_or_else(|| panic!("the close marked A Down: {log}"));
    let (failover_at, state, line) = log_lines(&log, "Failover", &a.key.key_id)
        .into_iter()
        .find(|l| l.0 >= closed_at)
        .unwrap_or_else(|| panic!("B failed over: {log}"));
    eprintln!(
        "[ALM2] link close: failover {} ms after the close, in state {state}: {line}",
        failover_at - down_at
    );
    assert_eq!(state, DOWN, "from the close, not from silence: {log}");
    assert!(
        failover_at - down_at < SUSPECT_SILENCE_MS,
        "before silence could have done it: {log}"
    );
    assert!(moved, "C took over: {:?} {log}", cb.alm_parents());
    task_b.abort();
    task_c.abort();
}

/// Three members with A publishing layers; B's primary is A, its standby C.
struct Layered {
    ca: Call,
    cb: Call,
    cc: Call,
    tasks: [tokio::task::JoinHandle<()>; 2],
    k: u64,
}

/// What a stretch of undisturbed media showed.
struct Stretch {
    /// B's new `Degraded` lines about its primary, A.
    primary: Vec<String>,
    /// B's new `Degraded` lines about its standby, C.
    standby: Vec<String>,
    /// Chunks the relay C forwarded.
    forwarded: u64,
}

async fn layered_call(nodes: &[Node], groups: &[CohortGroup], tag: &str, load: Load) -> Layered {
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let mut ca = join_loaded(a, &groups[0], tag, CallOptions::default(), load).await;
    let mut cb = join_loaded(b, &groups[1], tag, CallOptions::default(), None).await;
    let mut cc = join_loaded(c, &groups[2], tag, relay_opts(), None).await;
    wait_legs(&ca, 2).await;
    wait_legs(&cb, 2).await;
    wait_legs(&cc, 2).await;
    wait_bound(&cb, 2).await;
    wait_bound(&cc, 2).await;
    let (_, task_b) = drain(&mut cb);
    let (_, task_c) = drain(&mut cc);
    let mut k = 0;
    layered_until_standby(&mut ca, &cb, &cc, &a.key.key_id, &c.key.key_id, &mut k, 90).await;
    Layered {
        ca,
        cb,
        cc,
        tasks: [task_b, task_c],
        k,
    }
}

type Load = Option<Arc<ciris_edge::load_ladder::SharedLadder>>;

impl Layered {
    /// `n` more chunks, evenly spaced.
    async fn publish(&mut self, n: u64) {
        for _ in 0..n {
            self.ca
                .publish(layered("a", self.k))
                .await
                .expect("publish");
            self.k += 1;
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }

    fn abort(&self) {
        for t in &self.tasks {
            t.abort();
        }
    }

    /// `n` chunks that ran undisturbed, and what B's meters read over them. A
    /// loaded host really loses media and really sheds (the congestion
    /// controller doing its work), so a call's lifetime counters say nothing
    /// about these paths: the witness is the stretch where nothing was lost,
    /// nobody moved (`parents_stay`: B on A with C its standby throughout)
    /// and neither path started out `Degraded`, which is how a misreading
    /// could otherwise hide in an earlier line. Running out of
    /// [`QUIET_BUDGET`] fails, so a path that never reads clean stays red.
    async fn quiet_stretch(&mut self, nodes: &[Node], n: u64, parents_stay: bool) -> Stretch {
        const DEGRADED: i64 = 1;
        let (a, c) = (nodes[0].key.key_id.clone(), nodes[2].key.key_id.clone());
        let deadline = tokio::time::Instant::now() + QUIET_BUDGET;
        loop {
            if parents_stay {
                layered_until_standby(&mut self.ca, &self.cb, &self.cc, &a, &c, &mut self.k, 0)
                    .await;
            }
            let disturbed = disturbances(nodes);
            let (from_a, from_c) = (degraded_lines(&self.cb, &a), degraded_lines(&self.cb, &c));
            let forwarded = self.cc.alm_counts().forwarded;
            let clean_start = last_state(&self.cb, &a) != Some(DEGRADED)
                && last_state(&self.cb, &c) != Some(DEGRADED);
            self.publish(n).await;
            let parents = self.cb.alm_parents();
            let p = parents.iter().find(|p| p.stream == self.ca.stream());
            let stayed = !parents_stay
                || p.is_some_and(|p| {
                    p.primary.as_deref() == Some(a.as_str())
                        && p.standby.as_deref() == Some(c.as_str())
                });
            if clean_start && stayed && disturbances(nodes) == disturbed {
                let fresh = |before: &[String], peer: &str| -> Vec<String> {
                    degraded_lines(&self.cb, peer)
                        .into_iter()
                        .filter(|l| !before.contains(l))
                        .collect()
                };
                return Stretch {
                    primary: fresh(&from_a, &a),
                    standby: fresh(&from_c, &c),
                    forwarded: self.cc.alm_counts().forwarded - forwarded,
                };
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no undisturbed stretch of {n} chunks: disturbances {}, parents {parents:?}, B's log {:?}",
                disturbances(nodes),
                self.cb.alm_log()
            );
        }
    }
}

/// **CIRISEdge#945 finding B, on a live call.** A caps B's leg at the base
/// layer, as a host cap and a C5 shed both do: half the `chunk_seq`s never go
/// to B. Nothing was lost, so A stays Available and B stays on it. Before the
/// fix each gap read as loss, about 0.5, and A went Degraded.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_capped_primary_is_not_read_as_lossy_on_a_live_call() {
    let _call = one_call().await;
    let tag = "alm2-capped";
    let (nodes, groups, _tmp) = topo(tag, 3, 3, &[(0, 1), (0, 2), (1, 2)], None).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let mut call = layered_call(&nodes, &groups, tag, None).await;
    call.ca
        .set_layer_policy(&b.key.key_id, ReceiverLayerPolicy::BLINKING_DOT)
        .await
        .expect("A caps B");
    let quiet = call.quiet_stretch(&nodes, 300, true).await;
    eprintln!(
        "[ALM2] capped primary: Degraded lines {}, after {} sheds, {} ceilings",
        quiet.primary.len(),
        call.ca.alm_counts().shed,
        call.ca.alm_log_count(DecisionKind::Ceiling)
    );
    assert_eq!(
        quiet.primary,
        Vec::<String>::new(),
        "{:?}",
        call.cb.alm_log()
    );
    assert_eq!(
        primary_for(&call.cb, call.ca.stream()).as_deref(),
        Some(a.key.key_id.as_str()),
        "{:?}",
        call.cb.alm_log()
    );
    call.abort();
}

/// **CIRISEdge#945 finding B, on a live call.** At service tier 2 a publisher
/// seals its layers and sends them to nobody. Its own shedding is nobody's
/// loss.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_publisher_at_tier_two_is_not_read_as_lossy_on_a_live_call() {
    let _call = one_call().await;
    let tag = "alm2-tier2";
    let (nodes, groups, _tmp) = topo(tag, 3, 3, &[(0, 1), (0, 2), (1, 2)], None).await;
    let ladder = Arc::new(ciris_edge::load_ladder::SharedLadder::default());
    let mut call = layered_call(&nodes, &groups, tag, Some(Arc::clone(&ladder))).await;
    assert_eq!(
        ladder.set_host_pressure(ciris_edge::LoadPressure::Critical),
        ciris_edge::ServiceTier::ChatAndContacts
    );
    assert!(
        wait_until(Duration::from_secs(5), || async {
            call.ca.service_tier() == ciris_edge::ServiceTier::ChatAndContacts
        })
        .await,
        "A reads tier 2"
    );
    let quiet = call.quiet_stretch(&nodes, 300, false).await;
    eprintln!(
        "[ALM2] tier 2: Degraded lines primary {} standby {}",
        quiet.primary.len(),
        quiet.standby.len()
    );
    assert_eq!(
        quiet.primary,
        Vec::<String>::new(),
        "{:?}",
        call.cb.alm_log()
    );
    assert_eq!(
        quiet.standby,
        Vec::<String>::new(),
        "{:?}",
        call.cb.alm_log()
    );
    call.abort();
}

/// **CIRISEdge#945 finding B, on a live call: the other side.** A never sends
/// B half its base chunks, while C's path delivers them. They take no hop
/// counter, so only the standby shows what A's path went past. A path really
/// dropping base must read lossy. Mutation: without that reading it is clean.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_primary_dropping_base_is_read_as_lossy_on_a_live_call() {
    let _call = one_call().await;
    let tag = "alm2-drops-base";
    let (nodes, groups, _tmp) = topo(tag, 3, 3, &[(0, 1), (0, 2), (1, 2)], None).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let mut call = layered_call(&nodes, &groups, tag, None).await;
    // Reads lossy from a clean start, over media that lost nothing but what
    // A withheld: real congestion reading lossy would prove nothing.
    let deadline = tokio::time::Instant::now() + QUIET_BUDGET;
    loop {
        call.ca.withhold_from_for_test(&b.key.key_id, 0);
        let _ = call.quiet_stretch(&nodes, 120, true).await;
        let before = degraded_lines(&call.cb, &a.key.key_id);
        let disturbed = disturbances(&nodes);
        // Every fourth seq: half the even, base ones, and no enhancement chunk.
        call.ca.withhold_from_for_test(&b.key.key_id, 4);
        call.publish(300).await;
        let lines: Vec<String> = degraded_lines(&call.cb, &a.key.key_id)
            .into_iter()
            .filter(|l| !before.contains(l))
            .collect();
        if disturbances(&nodes) == disturbed {
            eprintln!("[ALM2] dropping base: Degraded lines {}", lines.len());
            assert!(!lines.is_empty(), "{:?}", call.cb.alm_log());
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no undisturbed stretch: {:?}",
            call.cb.alm_log()
        );
    }
    call.abort();
}

/// **CIRISEdge#945 item 2, on real links.** `P` publishes; `C` cannot reach it
/// and hears it through the roster relay `R`. `F`, a member with a link to `C`
/// and no way to `P`, sends `C` real `OFFER`s claiming depth 0 on `P`'s
/// stream. Only `P` may hold depth 0, and the binding names `P`: `C` keeps
/// `P` as the publisher, stays on `R` and never asks `F`. Mutation: unchecked,
/// the offer renames the publisher and direct-first sends `C` to `F`.
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn a_member_claiming_depth_zero_is_not_the_publisher() {
    let _call = one_call().await;
    let tag = "alm2-depth0";
    // 0 = R, 1 = P, 2 = C, 3 = F (the room); 4 = T (transport only). P and C
    // dial R, F dials C, T dials everyone.
    let (nodes, groups, _tmp) = topo(
        tag,
        5,
        4,
        &[(0, 1), (0, 2), (2, 3), (0, 4), (1, 4), (2, 4), (3, 4)],
        Some(4),
    )
    .await;
    let (r, p, c, f) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
    let cr = join_loaded(r, &groups[0], tag, relay_opts(), None).await;
    let mut cp = join_loaded(p, &groups[1], tag, CallOptions::default(), None).await;
    let cc = join_loaded(c, &groups[2], tag, CallOptions::default(), None).await;
    let cf = join_loaded(f, &groups[3], tag, CallOptions::default(), None).await;
    wait_legs(&cr, 2).await;
    wait_legs(&cc, 2).await;
    wait_legs(&cp, 1).await;
    assert_eq!(cc.legs().len(), 2, "C reaches R and F: {:?}", cc.legs());
    assert!(
        wait_until(Duration::from_secs(30), || async {
            cf.alm_c3_peers().contains(&c.key.key_id)
        })
        .await,
        "F hears C's CAPS"
    );
    let forged = encode(
        cp.stream(),
        &ControlMsg::Offer(Offer {
            from: f.key.key_id.clone(),
            depth: 0,
            ancestry: Vec::new(),
            headroom_bps: 100_000_000,
            forwarder_headroom_bps: 100_000_000,
            upstream_latency_ms: 0,
            forwarding: true,
        }),
    );
    // The lie runs from before C has any parent until it settled on one.
    let stream = cp.stream();
    let mut relayed = false;
    for seq in 0..1_500u64 {
        cf.send_c3_for_test(&c.key.key_id, forged.clone()).await;
        cp.publish(Frame::opaque(body("p", seq)))
            .await
            .expect("publish");
        tokio::time::sleep(Duration::from_millis(40)).await;
        relayed = primary_for(&cc, stream).as_deref() == Some(r.key.key_id.as_str());
        if relayed && seq >= 250 {
            break;
        }
    }
    let parents = cc.alm_parents();
    let row = parents.iter().find(|x| x.stream == stream);
    let asked = cf
        .alm_counts()
        .refused
        .get("relay_upstream_unhealthy")
        .copied()
        .unwrap_or(0);
    eprintln!("[ALM2] depth 0: C's row {row:?}, F was asked {asked} times");
    assert_eq!(
        row.and_then(|x| x.publisher.as_deref()),
        Some(p.key.key_id.as_str()),
        "the binding names the publisher: {:?}",
        cc.alm_log()
    );
    assert!(relayed, "C stays on the relay: {:?}", cc.alm_log());
    assert_eq!(asked, 0, "C never asked F: {:?}", cc.alm_log());
    assert_ne!(
        row.and_then(|x| x.standby.as_deref()),
        Some(f.key.key_id.as_str()),
        "F is no standby either"
    );
    assert!(cc.alm_counts().offers_refused > 0, "counted");
    assert!(
        cc.alm_log_count(DecisionKind::OfferRefused) > 0,
        "in the C7 log"
    );
    assert!(
        av(&c.metrics, "alm_offer_refused:not_publisher") > 0,
        "{:?}",
        c.metrics.av_plane()
    );
}

/// **Calls cut — a relay turns off mid-call** (`Call::set_relay(false)`):
/// members `A` and `E` both relay; `B` and `C` reach each other only through
/// them (each a TCP client of A and E; `T` the canonical, no member). C hears
/// B through one of them, X. X turns relaying off: it sheds C make-before-
/// break, C re-parents to the other relay Y and keeps hearing B, the event
/// at C names Y, and X reports `RelayStatus { relaying: false }` and, once
/// its drain passes, forwards to nobody.
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_relay_that_turns_off_hands_its_children_to_another_relay() {
    let _call = one_call().await;
    let tag = "alm2-setrelay";
    // 0 = A, 1 = E (relays), 2 = B, 3 = C (the room's four); 4 = T.
    let (nodes, groups, _tmp) = topo(
        tag,
        5,
        4,
        &[
            (0, 1),
            (0, 2),
            (0, 3),
            (1, 2),
            (1, 3),
            (0, 4),
            (1, 4),
            (2, 4),
            (3, 4),
        ],
        Some(4),
    )
    .await;
    let (a, e, b, c, t) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3], &nodes[4]);
    let ca = join_loaded(a, &groups[0], tag, relay_opts(), None).await;
    let ce = join_loaded(e, &groups[1], tag, relay_opts(), None).await;
    let mut cb = join_loaded(b, &groups[2], tag, relay_opts(), None).await;
    let mut cc = join_loaded(c, &groups[3], tag, relay_opts(), None).await;
    let mut c_events = cc.events().expect("C's events");
    wait_legs(&cb, 2).await;
    wait_legs(&cc, 2).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!cc.legs().contains(&b.key.key_id), "C has no leg to B");

    let relays = [a.key.key_id.clone(), e.key.key_id.clone()];
    let on_a_relay =
        || async { primary_for(&cc, cb.stream()).is_some_and(|p| relays.contains(&p)) };
    assert!(
        wait_until(Duration::from_secs(90), on_a_relay).await,
        "C hears B through A or E: {:?}",
        cc.alm_parents()
    );
    let x = primary_for(&cc, cb.stream()).expect("a parent");
    let (cx, y) = if x == a.key.key_id {
        (&ca, e.key.key_id.clone())
    } else {
        (&ce, a.key.key_id.clone())
    };
    assert_ne!(x, t.key.key_id);
    let (relaying, kids) = cx.relay_status();
    assert!(relaying && kids >= 1, "X relays: {:?}", cx.relay_status());

    // X turns relaying off.
    cx.set_relay(false).await;
    assert!(!cx.relay_status().0);
    let moved = wait_until(Duration::from_secs(30), || async {
        primary_for(&cc, cb.stream()).as_deref() == Some(y.as_str())
    })
    .await;
    assert!(
        moved,
        "C re-parents to the other relay: {:?}; X's log {:?}",
        cc.alm_parents(),
        cx.alm_log()
    );
    // C still hears B, now through Y.
    let mut rx_c = cc.frames().expect("C's frames");
    let mut heard = 0;
    for seq in 0..40 {
        cb.publish(Frame::opaque(body("b", seq)))
            .await
            .expect("B publishes");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while let Ok(Some(f)) = tokio::time::timeout_at(deadline, rx_c.recv()).await {
        if f.publisher == b.key.key_id {
            heard += 1;
            if heard == 40 {
                break;
            }
        }
    }
    assert!(heard >= 36, "C keeps hearing B through Y: {heard} of 40");
    // X forwards to nobody once its drain passes, and said so.
    assert!(
        wait_until(Duration::from_secs(20), || async {
            cx.relay_status() == (false, 0)
        })
        .await,
        "X's children are gone: {:?}",
        cx.relay_status()
    );
    assert!(
        av(
            if x == a.key.key_id {
                &a.metrics
            } else {
                &e.metrics
            },
            "relay_shed:relay_off"
        ) >= 1
    );
    // C was told the path moved through Y.
    let mut through = Vec::new();
    while let Ok(ev) = c_events.try_recv() {
        if let ciris_edge::transport::av_call::CallEvent::MediaPathRestored {
            member,
            via,
            through: t,
        } = ev
        {
            if member == b.key.key_id {
                assert_eq!(via, ciris_edge::transport::media_path::PathKind::PeerRelay);
                through.push(t);
            }
        }
    }
    assert_eq!(
        through.last().cloned().flatten().as_deref(),
        Some(y.as_str()),
        "the last path event for B names Y: {through:?}"
    );
    drop(cc);
    drop(cb);
    drop(ce);
    drop(ca);
}

/// **Calls cut — a serve seat that IS a room member never relays**, audio
/// included, even joined with `relay: true`: members `A` (relays), `S` (a
/// serve seat in every node's canonical set, its own included), `B` and `C`
/// (each a TCP client of A and S only, so they reach each other only through
/// one of them). B and C hear each other through A, never S; S reports
/// `relaying: false` and forwards to nobody, and nobody takes it as a parent.
// The seat set lives on the node's Edge (`_edge`).
#[allow(
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::used_underscore_binding
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_serve_seat_in_the_room_never_relays() {
    let _call = one_call().await;
    let tag = "alm2-seat";
    // 0 = A, 1 = S (the seat), 2 = B, 3 = C; 4 = T.
    let (nodes, groups, _tmp) = topo(
        tag,
        5,
        4,
        &[
            (0, 1),
            (0, 2),
            (0, 3),
            (1, 2),
            (1, 3),
            (0, 4),
            (1, 4),
            (2, 4),
            (3, 4),
        ],
        Some(4),
    )
    .await;
    let (a, seat, b, c) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
    for n in &nodes {
        n._edge
            .recognised_seats()
            .write()
            .expect("the seat set")
            .insert(seat.key.key_id.clone());
    }
    let _ca = join_loaded(a, &groups[0], tag, relay_opts(), None).await;
    let cs = join_loaded(seat, &groups[1], tag, relay_opts(), None).await;
    let cb = join_loaded(b, &groups[2], tag, relay_opts(), None).await;
    let cc = join_loaded(c, &groups[3], tag, relay_opts(), None).await;
    wait_legs(&cb, 2).await;
    wait_legs(&cc, 2).await;
    assert_eq!(cs.relay_status(), (false, 0), "a seat never relays");
    let through_a = wait_until(Duration::from_secs(90), || async {
        primary_for(&cc, cb.stream()).as_deref() == Some(a.key.key_id.as_str())
            && primary_for(&cb, cc.stream()).as_deref() == Some(a.key.key_id.as_str())
    })
    .await;
    assert!(
        through_a,
        "B and C hear each other through A: C {:?} / B {:?}",
        cc.alm_parents(),
        cb.alm_parents()
    );
    // Long enough for several offer rounds: S is never a parent of anything
    // it does not publish, and relays nothing.
    for _ in 0..20 {
        for call in [&cb, &cc] {
            for p in call.alm_parents() {
                if p.publisher.as_deref() == Some(seat.key.key_id.as_str()) {
                    continue;
                }
                for parent in [p.primary.as_deref(), p.standby.as_deref()]
                    .into_iter()
                    .flatten()
                {
                    assert_ne!(parent, seat.key.key_id, "the seat is a media parent: {p:?}");
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(cs.relay_status(), (false, 0));
    // Asked outright, the seat refuses: B sends it a relay SUBSCRIBE for C's
    // stream (as a stale or misbehaving member would).
    let sub = encode(
        cc.stream(),
        &ControlMsg::Subscribe(SubscribeRequest {
            subscriber: b.key.key_id.clone(),
            role: Role::Primary,
            forward_capable: false,
            layers: None,
        }),
    );
    cb.send_c3_for_test(&seat.key.key_id, sub).await;
    assert!(
        wait_until(Duration::from_secs(10), || async {
            av(&seat.metrics, "relay_serve_seat") >= 1
        })
        .await,
        "the seat refuses a relay SUBSCRIBE by name: {:?}",
        seat.metrics.av_plane()
    );
    assert!(cs.relayed_to().is_empty(), "{:?}", cs.relayed_to());
    assert_eq!(cs.alm_counts().forwarded, 0);
}

/// Publish 600 B frames at 30 Hz from `cp` for `secs`, from `seq0`.
async fn publish_capped_for(cp: &mut Call, secs: u64, seq0: u64) -> u64 {
    publish_timed_for(cp, secs, seq0).await.0
}

/// Every frame each of `listeners` hears from `publisher`, counted as it
/// arrives (a call's frame queue holds 256: read only at the end, a count is
/// capped there).
struct FrameCounts {
    counts: Vec<Arc<AtomicU64>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl FrameCounts {
    fn read(&self) -> Vec<u64> {
        self.counts
            .iter()
            .map(|c| c.load(Ordering::SeqCst))
            .collect()
    }
}

impl Drop for FrameCounts {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

fn count_frames_from(listeners: &mut [Call], publisher: &str) -> FrameCounts {
    let mut counts = Vec::new();
    let mut tasks = Vec::new();
    for l in listeners.iter_mut() {
        let mut rx = l.frames().expect("frames");
        let c = Arc::new(AtomicU64::new(0));
        let n = Arc::clone(&c);
        let from = publisher.to_owned();
        tasks.push(tokio::spawn(async move {
            while let Some(f) = rx.recv().await {
                if f.publisher == from {
                    n.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
        counts.push(c);
    }
    FrameCounts { counts, tasks }
}

/// One listener's arrivals: each frame's seq and when it was handed out.
type ArrivalLog = Arc<std::sync::Mutex<Vec<(u64, tokio::time::Instant)>>>;

/// Every frame each of `listeners` hears from `publisher`: its seq (the
/// `body` prefix) and when it was handed out, recorded as it arrives.
struct FrameArrivals {
    got: Vec<ArrivalLog>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl FrameArrivals {
    fn read(&self) -> Vec<Vec<(u64, tokio::time::Instant)>> {
        self.got
            .iter()
            .map(|g| g.lock().expect("arrivals").clone())
            .collect()
    }
}

impl Drop for FrameArrivals {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

fn record_frames_from(listeners: &mut [Call], publisher: &str) -> FrameArrivals {
    let mut got = Vec::new();
    let mut tasks = Vec::new();
    for l in listeners.iter_mut() {
        let mut rx = l.frames().expect("frames");
        let g: ArrivalLog = Arc::default();
        let w = Arc::clone(&g);
        let from = publisher.to_owned();
        tasks.push(tokio::spawn(async move {
            while let Some(f) = rx.recv().await {
                if f.publisher == from {
                    if let Some(s) = seq_of(&f.bytes) {
                        w.lock()
                            .expect("arrivals")
                            .push((s, tokio::time::Instant::now()));
                    }
                }
            }
        }));
        got.push(g);
    }
    FrameArrivals { got, tasks }
}

/// One frame at the 30 Hz these witnesses publish at.
const FRAME_INTERVAL: Duration = Duration::from_millis(33);

/// How long each `publish()` call took: `(max, p95, p50)`.
// p95/p50 are read only through the Debug line in `publish_timed_for`.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
struct PublishLatency {
    max: Duration,
    p95: Duration,
    p50: Duration,
}

/// [`publish_capped_for`], timing every `publish()` call (the host's capture
/// loop waits on it).
async fn publish_timed_for(cp: &mut Call, secs: u64, seq0: u64) -> (u64, PublishLatency) {
    let size = cp.chunk_plaintext_budget().unwrap_or(240).min(600);
    let mut seq = seq0;
    let mut took: Vec<Duration> = Vec::new();
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < end {
        let mut b = body("p", seq);
        b.resize(size, b'.');
        let t = tokio::time::Instant::now();
        let _ = cp.publish(Frame::opaque(b)).await;
        took.push(t.elapsed());
        seq += 1;
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    took.sort();
    let at = |q: usize| {
        took.get((took.len() * q / 100).min(took.len().saturating_sub(1)))
            .copied()
    };
    let lat = PublishLatency {
        max: took.last().copied().unwrap_or_default(),
        p95: at(95).unwrap_or_default(),
        p50: at(50).unwrap_or_default(),
    };
    eprintln!("[G8] publish latency over {} calls: {lat:?}", took.len());
    (seq, lat)
}

/// Every link `m` saw closed by Channel retry exhaustion, either side
/// (A/V legs included: they are not identified, so `peer_activity` misses
/// them).
fn channel_exhausted(m: &EdgeMetrics) -> u64 {
    closed_by(m, "channel_exhausted")
}

/// Every link `m` saw closed with `cause`, inbound and outbound.
fn closed_by(m: &EdgeMetrics, cause: &str) -> u64 {
    m.inbound_link_closed_by_reason()
        .get(cause)
        .copied()
        .unwrap_or(0)
        + m.outbound_link_closed_by_reason()
            .get(cause)
            .copied()
            .unwrap_or(0)
}

/// Every link `m` saw torn down by something other than this node or its
/// peer choosing to (a retry exhaustion, a timeout, staleness).
fn torn_down(m: &EdgeMetrics) -> u64 {
    ["channel_exhausted", "timeout", "stale"]
        .iter()
        .map(|c| closed_by(m, c))
        .sum()
}

/// **Every pair has both legs within the setup bound, and keeps them,
/// uncapped** (rxmove's come-back trace): in the room of
/// [`a_capped_publisher_sheds_to_one_child_and_the_rest_are_relayed`] with
/// no cap, every member holds its own leg to every other member within
/// `SETUP_BOUND` of the last join, and the call's legs agree with what its
/// publisher can send on, for the whole stretch. Without the fix the early
/// joiners (P first) had no leg to the later ones for ~6 s: each dial began
/// before that member's address stood and sat out the 5 s no-path establish
/// timeout and a backoff, while P's ADMITs rode the members' paced in-links.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn every_pair_keeps_both_legs_uncapped() {
    /// One dial backoff floor (`DIAL_BACKOFF_MIN`, 1 s): once the last
    /// member has joined, every member it reaches dials back at once, with
    /// no backoff and no 5 s no-path establish timeout waited out (6.4 s
    /// without the fix). A setup over 1 s is a bug to find, not a bound to
    /// move (the lead's ruling, 2026-11-25: the 2 s this carried was set
    /// after seeing results up to 0.82 s).
    const SETUP_BOUND: Duration = Duration::from_secs(1);
    let _call = one_call().await;
    let tag = "alm2-legs";
    let (nodes, groups, _tmp) = topo_capped(
        tag,
        5,
        4,
        &[
            (0, 1),
            (0, 2),
            (0, 3),
            (1, 2),
            (1, 3),
            (2, 3),
            (0, 4),
            (1, 4),
            (2, 4),
            (3, 4),
        ],
        Some(4),
        None,
    )
    .await;
    let mut cp = join_loaded(&nodes[0], &groups[0], tag, relay_opts(), None).await;
    let mut listeners = Vec::new();
    for (i, g) in groups.iter().enumerate().skip(1) {
        listeners.push(join_loaded(&nodes[i], g, tag, relay_opts(), None).await);
    }
    let ids: Vec<String> = nodes[..4].iter().map(|n| n.key.key_id.clone()).collect();
    // Setup: from the last join until every node holds a leg to every other
    // member, in the call and in its dispatcher alike.
    let joined = tokio::time::Instant::now();
    let mut setup = None;
    let mut timeline: Vec<(u128, Vec<(usize, usize)>)> = Vec::new();
    while joined.elapsed() < Duration::from_secs(30) {
        let calls: Vec<&Call> = std::iter::once(&cp).chain(listeners.iter()).collect();
        let mut row = Vec::new();
        for c in &calls {
            row.push((c.legs().len(), c.dispatcher_legs_for_test().await.len()));
        }
        if timeline.last().is_none_or(|l| l.1 != row) {
            timeline.push((joined.elapsed().as_millis(), row.clone()));
        }
        if row.iter().all(|r| *r == (3, 3)) {
            setup = Some(joined.elapsed());
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    eprintln!("[LEGS] setup {setup:?}; timeline {timeline:?}");
    // The bound from mechanism: once the last member has joined, every
    // member it reaches dials back at once, with no wait on a no-path
    // establish timeout begun before that member's address stood.
    assert!(
        setup.is_some_and(|d| d <= SETUP_BOUND),
        "every pair has both legs within {SETUP_BOUND:?} of the last join: {setup:?}; timeline {timeline:?}"
    );
    let mut failed: Vec<String> = Vec::new();
    let c3_failed = |nodes: &[Node]| -> Vec<u64> {
        nodes
            .iter()
            .map(|n| av(&n.metrics, "alm_c3_send_failed"))
            .collect()
    };
    let c3_before = c3_failed(&nodes);
    let mut seq = 0;
    for second in 0..20u64 {
        seq = publish_timed_for(&mut cp, 1, seq).await.0;
        let calls: Vec<&Call> = std::iter::once(&cp).chain(listeners.iter()).collect();
        for (i, c) in calls.iter().enumerate() {
            let mut want: Vec<String> = ids.iter().filter(|m| **m != ids[i]).cloned().collect();
            want.sort();
            let (legs, held) = (c.legs(), c.dispatcher_legs_for_test().await);
            if legs != want || held != want {
                failed.push(format!(
                    "t+{second}s node {i}: legs {} of 3, dispatcher {} of 3 (agree: {})",
                    legs.len(),
                    held.len(),
                    legs == held
                ));
            }
        }
    }
    // Uncapped, no C3 frame is ever given up on: a period's offers to one
    // member are paced onto its link, not refused by its pacing gate.
    let c3_after = c3_failed(&nodes);
    let c3_lost: Vec<u64> = c3_after
        .iter()
        .zip(&c3_before)
        .map(|(a, b)| a.saturating_sub(*b))
        .collect();
    eprintln!("[LEGS] C3 frames given up on, per node, over 20 s: {c3_lost:?}");
    if c3_lost.iter().any(|n| *n > 0) {
        failed.push(format!("C3 frames given up on, per node: {c3_lost:?}"));
    }
    assert!(
        failed.is_empty(),
        "every pair keeps both legs: {failed:?}; legs gone on send {:?}",
        nodes
            .iter()
            .map(|n| av(&n.metrics, "av_leg_gone_on_send"))
            .collect::<Vec<_>>()
    );
}

/// **A listener whose pump falls behind still takes in every control
/// frame** (come-back, 45.2.0): a node's inbound A/V queue per link holds
/// 256 frames and drops the newest when full, and C3 frames (offers,
/// admits, refusals) rode the same queue as media, so a listener that fell
/// behind a media flood lost its answers while the transport had delivered
/// them (admits sent 67, taken in 42 in one come-back run). Here R's pump is
/// held 12 s while three members publish: its queues overflow with media
/// (the precondition, asserted), and every control frame sent to it in that
/// time must still be taken in once it drains: none is among the frames the
/// sink drops (`av_inbound_control_dropped`), and at least 90 % of the rate
/// it took them in before the hold is taken in over the hold and the drain.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_listener_whose_pump_falls_behind_still_takes_every_control_frame() {
    const HOLD: Duration = Duration::from_secs(12);
    const DRAIN_S: u64 = 4;
    let _call = one_call().await;
    let tag = "alm2-c3flood";
    let (nodes, groups, _tmp) = topo_capped(
        tag,
        5,
        4,
        &[
            (0, 1),
            (0, 2),
            (0, 3),
            (1, 2),
            (1, 3),
            (2, 3),
            (0, 4),
            (1, 4),
            (2, 4),
            (3, 4),
        ],
        Some(4),
        None,
    )
    .await;
    let mut calls = Vec::new();
    for (i, g) in groups.iter().enumerate() {
        calls.push(join_loaded(&nodes[i], g, tag, relay_opts(), None).await);
    }
    for c in &calls {
        wait_legs(c, 3).await;
    }
    // Settle, then R's rate of control frames taken in, unheld.
    let mut seq = publish_three(&mut calls, 4, 0).await;
    let c0 = calls[0].alm_counts().c3_received;
    seq = publish_three(&mut calls, 4, seq).await;
    let c1 = calls[0].alm_counts().c3_received;
    #[allow(clippy::cast_precision_loss)]
    let rate = (c1 - c0) as f64 / 4.0;
    let dropped_before = av(&nodes[0].metrics, "av_inbound_dropped_queue_full");
    calls[0].stall_inbound_for_test(HOLD);
    seq = publish_three(&mut calls, HOLD.as_secs(), seq).await;
    let _ = publish_three(&mut calls, DRAIN_S, seq).await;
    let c2 = calls[0].alm_counts().c3_received;
    let dropped = av(&nodes[0].metrics, "av_inbound_dropped_queue_full") - dropped_before;
    let control_dropped = av(&nodes[0].metrics, "av_inbound_control_dropped");
    #[allow(clippy::cast_precision_loss)]
    let want = 0.9 * rate * (HOLD.as_secs() + DRAIN_S) as f64;
    eprintln!(
        "[C3FLOOD] rate {rate:.1}/s unheld; taken in over hold+drain {}; want >= {want:.0}; media dropped at R's queues {dropped}; control frames among them {control_dropped}",
        c2 - c1
    );
    assert!(
        dropped > 0,
        "the precondition: R's queues overflowed ({dropped} dropped)"
    );
    assert_eq!(
        control_dropped, 0,
        "no control frame is shed with the media: {control_dropped} of the {dropped} dropped were C3"
    );
    #[allow(clippy::cast_precision_loss)]
    let got = (c2 - c1) as f64;
    assert!(
        got >= want,
        "every control frame is taken in: {got} taken in over the hold and drain, {want:.0} owed at {rate:.1}/s"
    );
    drop(calls);
}

/// **A member whose host never reads its frames keeps its place in the
/// tree** (45.2.0): delivery to the host is lossy, and no pump waits on it.
/// The other three publish and read; R's host never calls `frames()` (a
/// backgrounded app, a paused decoder). Once R's queues toward its host
/// fill, R must still take in control (its C3 count keeps rising every
/// second), keep a parent for every stream (never without one for more than
/// 1.5 s), and count what it dropped for its host. Mutation (2ba6adb): the
/// pumps awaited the full heard queue, R took in no C3 frame from then on,
/// and its parents and children were left to time out.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_member_whose_host_never_reads_frames_keeps_its_place() {
    const RUN_S: u64 = 90;
    const PARENTLESS_MAX: Duration = Duration::from_millis(1500);
    let _call = one_call().await;
    let tag = "alm2-noread";
    let (nodes, groups, _tmp) = topo_capped(
        tag,
        5,
        4,
        &[
            (0, 1),
            (0, 2),
            (0, 3),
            (1, 2),
            (1, 3),
            (2, 3),
            (0, 4),
            (1, 4),
            (2, 4),
            (3, 4),
        ],
        Some(4),
        None,
    )
    .await;
    let mut calls = Vec::new();
    for (i, g) in groups.iter().enumerate() {
        calls.push(join_loaded(&nodes[i], g, tag, relay_opts(), None).await);
    }
    for c in &calls {
        wait_legs(c, 3).await;
    }
    // The publishers' hosts read; R's (calls[0]) never does.
    let _read = count_frames_from(&mut calls[1..], &nodes[1].key.key_id);
    let streams: Vec<_> = (1..=3usize).map(|i| calls[i].stream()).collect();
    let mut seq = publish_three(&mut calls, 3, 0).await;
    let mut failed: Vec<String> = Vec::new();
    let mut parentless_since: Option<(usize, tokio::time::Instant)> = None;
    let mut last_c3 = calls[0].alm_counts().c3_received;
    let failover = || {
        calls[0].alm_log_count(
            ciris_edge::transport::realtime_av_alm::controller::DecisionKind::Failover,
        )
    };
    let failovers_before = failover();
    let sink_dropped_before = av(&nodes[0].metrics, "av_inbound_dropped_queue_full");
    let start = tokio::time::Instant::now();
    for sec in 0..RUN_S {
        seq = publish_three(&mut calls, 1, seq).await;
        let c3 = calls[0].alm_counts().c3_received;
        if sec >= 2 && c3 == last_c3 {
            failed.push(format!(
                "t+{sec}s: R took in no control frame this second ({c3})"
            ));
        }
        last_c3 = c3;
        let missing = streams
            .iter()
            .position(|st| primary_for(&calls[0], *st).is_none());
        match (missing, parentless_since) {
            (Some(i), None) => parentless_since = Some((i, tokio::time::Instant::now())),
            (Some(_), Some((i, t))) if t.elapsed() > PARENTLESS_MAX => {
                failed.push(format!(
                    "t+{sec}s: R without a parent for stream {i} for {:?}",
                    t.elapsed()
                ));
                parentless_since = None;
            }
            (None, _) => parentless_since = None,
            _ => {}
        }
    }
    let dropped = av(&nodes[0].metrics, "av_frame_dropped_host_not_reading");
    // Its parents keep delivering to it: a pump parked on the host stops
    // metering its parent's chunks, and the parent reads as silent.
    let failovers = calls[0]
        .alm_log_count(ciris_edge::transport::realtime_av_alm::controller::DecisionKind::Failover)
        - failovers_before;
    // Its pumps keep reading its links: a pump parked on the host leaves
    // its link's queue to fill, and the transport's sink drops at it.
    let sink_dropped = av(&nodes[0].metrics, "av_inbound_dropped_queue_full") - sink_dropped_before;
    if sink_dropped > 0 {
        failed.push(format!(
            "R's links' queues overflowed ({sink_dropped} dropped at the sink): its pumps stopped reading"
        ));
    }
    if failovers > 0 {
        failed.push(format!(
            "R failed over {failovers} times with nothing wrong upstream"
        ));
    }
    eprintln!(
        "[NOREAD] {RUN_S} s from {:?}: R dropped {dropped} for its host; C3 taken in {last_c3}; R failovers {failovers}; R sink drops {sink_dropped}; R reorder {:?}; failures {failed:?}",
        start.elapsed(),
        calls[0].reorder_counts()
    );
    assert!(
        failed.is_empty(),
        "R keeps its place while its host reads nothing: {failed:?}"
    );
    assert!(
        dropped > 0,
        "the precondition: R's queues toward its host filled ({dropped} dropped)"
    );
    drop(calls);
}

/// **A member whose host reads nothing still relays to its child**
/// (45.2.0): R's host never takes the call's frames NOR its events from the
/// moment it joins; P and C cannot reach each other, so C hears P only
/// through R (the roster-relay shape). C's hearing of P must be what a
/// reading relay gives: every second carries P's frames to C and C hears
/// at least 90 % of what P publishes. Mutation (2ba6adb): R's pumps parked
/// on its unread queues and C heard nothing from P from then on.
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_member_whose_host_reads_nothing_still_relays_to_its_child() {
    // Past R's host-bound queues (256 frames + 1024 heard) at ~30 frames/s.
    const RUN_S: u64 = 90;
    let _call = one_call().await;
    let tag = "alm2-noreadrelay";
    // 0 = R (relays, its host reads nothing), 1 = P, 2 = C; 3 = T. P and C
    // dial R; T dials everyone. P and C share nothing.
    let (nodes, groups, _tmp) = topo(
        tag,
        4,
        3,
        &[(0, 1), (0, 2), (0, 3), (1, 3), (2, 3)],
        Some(3),
    )
    .await;
    let (r, p) = (&nodes[0], &nodes[1]);
    // R: frames() and events() never taken.
    let cr = join_loaded(r, &groups[0], tag, relay_opts(), None).await;
    let mut cp = join_loaded(p, &groups[1], tag, CallOptions::default(), None).await;
    let mut cc = vec![join_loaded(&nodes[2], &groups[2], tag, CallOptions::default(), None).await];
    wait_legs(&cr, 2).await;
    wait_legs(&cp, 1).await;
    wait_legs(&cc[0], 1).await;
    let heard = count_frames_from(&mut cc, &p.key.key_id);
    let converged = wait_until(Duration::from_secs(90), || async {
        primary_for(&cc[0], cp.stream()).as_deref() == Some(r.key.key_id.as_str())
    })
    .await;
    assert!(converged, "the premise: C hears P through R");
    let mut seq = 0;
    let mut published = 0u64;
    let mut empty_seconds: Vec<u64> = Vec::new();
    let start_heard = heard.read()[0];
    let mut last = start_heard;
    for sec in 0..RUN_S {
        let (s2, _) = publish_timed_for(&mut cp, 1, seq).await;
        published += s2 - seq;
        seq = s2;
        let now = heard.read()[0];
        if sec >= 2 && now == last {
            empty_seconds.push(sec);
        }
        last = now;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    let got = heard.read()[0] - start_heard;
    let r_host_frames = av(&r.metrics, "av_frame_dropped_host_not_reading");
    let r_host_events = av(&r.metrics, "av_call_event_dropped_host_not_reading");
    let r_sink = av(&r.metrics, "av_inbound_dropped_queue_full");
    eprintln!(
        "[NOREADRELAY] C heard {got} of {published} of P through R; seconds with nothing {empty_seconds:?}; \
         R dropped for its host {r_host_frames} frames, {r_host_events} events; R sink drops {r_sink}"
    );
    assert!(
        r_host_frames > 0,
        "the precondition: R's host queues filled"
    );
    assert!(
        empty_seconds.is_empty(),
        "C heard P every second: {empty_seconds:?}"
    );
    assert!(
        got * 10 >= published * 9,
        "C hears P through R: {got} of {published}"
    );
    drop(cc);
    drop(cr);
}

/// **G8 — a publisher whose uplink is capped below its fan-out** (the
/// server's av_mesh cell, on loopback, with no tc): `P` publishes
/// 600 B at 30 Hz to `A`, `B` and `C`, who reach each other directly, every
/// member relaying (the host's member default). `P`'s uplink is then capped
/// at 250 kbit/s with an unbounded queue: about one copy of its stream on
/// the wire, a third of its fan-out.
///
/// What the design does (`docs/AV_ALM_DESIGN.md` §5.1, C2): `P` sheds to one
/// child make-before-break, the other two take that child as their relay,
/// and everyone keeps hearing `P` at about the one-copy rate. What must not
/// happen (CIRISEdge 45.1.9 matrix, leviculum#113): every link of `P`
/// torn down by Channel retry exhaustion within ~2 s of the cap.
#[allow(
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::cast_precision_loss
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_capped_publisher_sheds_to_one_child_and_the_rest_are_relayed() {
    let _call = one_call().await;
    let tag = "alm2-capped";
    let uplink = CappedUplink::new();
    // 0 = P (capped, dials nobody), 1..=3 = A, B, C (dial P and each other);
    // 4 = T (the canonical shape, dials everyone but P).
    let (nodes, groups, _tmp) = topo_capped(
        tag,
        5,
        4,
        &[
            (0, 1),
            (0, 2),
            (0, 3),
            (1, 2),
            (1, 3),
            (2, 3),
            (0, 4),
            (1, 4),
            (2, 4),
            (3, 4),
        ],
        Some(4),
        Some((0, Arc::clone(&uplink))),
    )
    .await;
    let p = &nodes[0];
    let mut cp = join_loaded(p, &groups[0], tag, relay_opts(), None).await;
    let mut listeners = Vec::new();
    for (i, g) in groups.iter().enumerate().skip(1) {
        listeners.push(join_loaded(&nodes[i], g, tag, relay_opts(), None).await);
    }
    wait_legs(&cp, 3).await;
    for l in &listeners {
        wait_legs(l, 3).await;
    }
    // Recorded as they arrive: each call's frame queue holds 256, and a
    // count read only at the end is capped there. Each frame's age is its
    // arrival less its publish() call, on the one process clock.
    let arrivals = record_frames_from(&mut listeners, &p.key.key_id);
    let pid = p.key.key_id.clone();
    let mut stamps: Vec<Stamp> = Vec::new();
    let mut looks = Vec::new();
    // Baseline: the full mesh carries P.
    let origin = tokio::time::Instant::now();
    let seq = publish_looking_stamped(
        &mut cp,
        &listeners,
        &uplink,
        origin,
        5,
        0,
        &mut looks,
        Some(&mut stamps),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let base: Vec<usize> = arrivals.read().iter().map(Vec::len).collect();
    assert!(
        base.iter().all(|n| *n as u64 * 10 >= seq * 9),
        "baseline: {base:?} of {seq}"
    );
    let sent_at: std::collections::HashMap<u64, tokio::time::Instant> =
        stamps.iter().map(|(q, t, _)| (*q, *t)).collect();
    // Each listener's floor: its quickest baseline frame (AGE's RM1 floor is
    // the same kind of minimum, learned from the stream's on-time chunks).
    let floor: Vec<Duration> = arrivals
        .read()
        .iter()
        .map(|g| {
            g.iter()
                .filter_map(|(q, at)| sent_at.get(q).map(|t| at.saturating_duration_since(*t)))
                .min()
                .unwrap_or_default()
        })
        .collect();
    let base_lat = stamps.iter().map(|(_, _, d)| *d).max().unwrap_or_default();

    // The cap: one copy of P's stream on the wire and a third to spare (the
    // server's cell, 250 kbit/s against ~190 kbit/s a copy, scaled to this
    // leg's frame: the frame plus ~170 B of chunk, signature, seal and link
    // framing, 30 a second), so three copies are ~2.3x what it carries.
    let frame = cp.chunk_plaintext_budget().unwrap_or(240).min(600) as u64;
    let copy_kbit = (frame + 170) * 8 * 30 / 1000;
    let exhausted_before: u64 = nodes.iter().map(|n| channel_exhausted(&n.metrics)).sum();
    let torn_before: u64 = nodes.iter().map(|n| torn_down(&n.metrics)).sum();
    uplink.cap_kbit(copy_kbit * 13 / 10);
    // Each link's close is logged on target `ciris_edge::link_close` (debug)
    // with its node, direction, plane, peer and reason; this line is the
    // origin its times are read from, and the names map key ids to roles.
    tracing::info!(
        target: "ciris_edge::link_close",
        names = ?nodes
            .iter()
            .zip(["P", "A", "B", "C", "T"])
            .map(|(n, r)| (r, n.key.key_id.clone()))
            .collect::<Vec<_>>(),
        "G8 cap on"
    );
    // When the first link is torn down after the cap, on P and on its peers
    // (the matrix: every node, 1.6-2.2 s after cap_on).
    let cap_on = tokio::time::Instant::now();
    let first_torn: Arc<std::sync::Mutex<Vec<Option<Duration>>>> =
        Arc::new(std::sync::Mutex::new(vec![None; nodes.len()]));
    let sampler = {
        let ms: Vec<EdgeMetrics> = nodes.iter().map(|n| n.metrics.clone()).collect();
        let base: Vec<u64> = ms.iter().map(torn_down).collect();
        let first = Arc::clone(&first_torn);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let mut f = first.lock().expect("first");
                for (i, m) in ms.iter().enumerate() {
                    if f[i].is_none() && torn_down(m) > base[i] {
                        f[i] = Some(cap_on.elapsed());
                    }
                }
            }
        })
    };
    let capped_from = seq;
    let _ = uplink.take_peak();
    let mut capped = Vec::new();
    let mut capped_stamps: Vec<Stamp> = Vec::new();
    let seq = publish_looking_stamped(
        &mut cp,
        &listeners,
        &uplink,
        cap_on,
        30,
        seq,
        &mut capped,
        Some(&mut capped_stamps),
    )
    .await;
    sampler.abort();
    let peak = uplink.take_peak();
    let sent = seq - capped_from;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let capped_lat = capped_stamps
        .iter()
        .map(|(_, _, d)| *d)
        .max()
        .unwrap_or_default();
    let sent_in_cap: std::collections::HashMap<u64, tokio::time::Instant> =
        capped_stamps.iter().map(|(q, t, _)| (*q, *t)).collect();
    let exhausted: u64 = nodes
        .iter()
        .map(|n| channel_exhausted(&n.metrics))
        .sum::<u64>()
        - exhausted_before;
    let torn: u64 = nodes.iter().map(|n| torn_down(&n.metrics)).sum::<u64>() - torn_before;
    let parents: Vec<Option<String>> = listeners
        .iter()
        .map(|l| primary_for(l, cp.stream()))
        .collect();
    let direct = parents
        .iter()
        .filter(|x| x.as_deref() == Some(pid.as_str()))
        .count();
    // Settled: P's uplink first queued 300 ms, that media's 300 ms on its
    // way, and a second for the moves (the deadline
    // `a_capped_publishers_children_move_themselves_and_come_back` holds the
    // children to).
    let late_at = capped
        .iter()
        .find(|l| l.queue_ms.is_some_and(|q| q >= 300))
        .map(|l| l.at);
    let settle = late_at.map(|t| t + Duration::from_millis(300) + Duration::from_secs(1));
    let settle_at = settle.map(|d| cap_on + d);
    // Per listener, over the capped run: frames delivered, the oldest one's
    // age above its floor, and the fresh ones after the settle (within
    // MEDIA_FRESH of their publish, above the floor).
    let got = arrivals.read();
    let mut delivered = Vec::new();
    let mut oldest = Vec::new();
    let mut fresh_settled = Vec::new();
    for (i, g) in got.iter().enumerate() {
        let mine: Vec<(Duration, tokio::time::Instant)> = g
            .iter()
            .filter_map(|(q, at)| {
                sent_in_cap
                    .get(q)
                    .map(|t| (at.saturating_duration_since(*t), *at))
            })
            .collect();
        delivered.push(mine.len());
        oldest.push(
            mine.iter()
                .map(|(a, _)| a.saturating_sub(floor[i]))
                .max()
                .unwrap_or_default(),
        );
        fresh_settled.push(
            mine.iter()
                .filter(|(a, at)| {
                    settle_at.is_some_and(|s| *at >= s) && a.saturating_sub(floor[i]) <= MEDIA_FRESH
                })
                .count(),
        );
    }
    let settled_secs = settle.map_or(0.0, |d| 30.0 - d.as_secs_f64());
    let direct_idx = parents
        .iter()
        .position(|x| x.as_deref() == Some(pid.as_str()));
    let context = format!(
        "copy {copy_kbit} kbit/s; sent {sent}; delivered {delivered:?}; floors {floor:?}; oldest above floor {oldest:?}; \
         fresh after settle {fresh_settled:?} over {settled_secs:.1} s (direct listener {direct_idx:?}); late at {late_at:?}; \
         peak queue {peak:?}; parents {parents:?}; P children {:?}; P counts {:?}; \
         ChannelExhausted {exhausted}; torn {torn}; first teardown after the cap (P, A, B, C, T) {:?}; P legs {:?}; \
         looks {:?}",
        cp.alm_own_children(),
        cp.alm_counts(),
        first_torn.lock().expect("first").clone(),
        cp.legs(),
        capped
            .iter()
            .step_by(5)
            .map(|l| (
                l.at.as_millis(),
                l.queue_ms,
                l.parents
                    .iter()
                    .map(|x| match x.as_deref() {
                        None => '-',
                        Some(x) if x == pid.as_str() => 'P',
                        Some(_) => 'r',
                    })
                    .collect::<String>()
            ))
            .collect::<Vec<_>>(),
    );
    // Every criterion is judged and every failure named, so a red run says
    // what each fix buys (G8: A and C in edge, leviculum#113).
    let mut failed: Vec<String> = Vec::new();
    if exhausted != 0 {
        failed.push(format!("links torn down by retry exhaustion: {exhausted}"));
    }
    if torn != 0 {
        failed.push(format!("links torn down (exhausted/timeout/stale): {torn}"));
    }
    if direct != 1 {
        failed.push(format!("P's direct children: {direct}, want 1"));
    }
    // E2: a publisher with any subscriber keeps at least one PRIMARY (never
    // only standbys).
    if !cp
        .alm_own_children()
        .iter()
        .any(|(_, r)| *r == ciris_edge::transport::realtime_av_alm::controller::Role::Primary)
    {
        failed.push(format!(
            "P has no primary child: {:?}",
            cp.alm_own_children()
        ));
    }
    // The host's capture loop waits on publish(): one call must never cost
    // it a frame, capped or not (G8: 45-60 ms a call, and seconds when a
    // leg redialled, with sends retried under the publisher lock).
    for (phase, lat) in [("uncapped", base_lat), ("capped", capped_lat)] {
        if lat >= FRAME_INTERVAL {
            failed.push(format!(
                "publish() {phase}: {lat:?}, over one frame interval"
            ));
        }
    }
    // 45.3 — the bar changed with row AGE. Before it, each listener had to
    // hear 70 % of what P published: true while relays passed on whatever
    // reached them, however late. Under AGE a receiver never delivers or
    // relays media more than MEDIA_FRESH (800 ms) above its floor, and a
    // capped uplink's queue is seconds deep, so most of what P published
    // during the cap is stale and dropped, by design. What AGE makes true,
    // and is judged instead:
    //   (1) after the settle no listener is without a parent;
    //   (2) no stale media is delivered: every frame within MEDIA_FRESH of
    //       its publish, above the listener's floor;
    //   (3) the relayed listeners get fresh media at a fraction of what the
    //       direct child gets (RELAYED_FRESH_SHARE, from this run's numbers).
    let Some(settle) = settle else {
        panic!("the cap never queued P's uplink 300 ms: {context}");
    };
    if let Some(l) = capped
        .iter()
        .find(|l| l.at > settle && l.parents.iter().any(Option::is_none))
    {
        failed.push(format!(
            "a listener without a parent at {:?} (settled {settle:?}): {:?}",
            l.at, l.parents
        ));
    }
    for (i, o) in oldest.iter().enumerate() {
        if *o > MEDIA_FRESH {
            failed.push(format!(
                "listener {i} was handed a frame {o:?} above its floor (stale past {MEDIA_FRESH:?})"
            ));
        }
    }
    if let Some(d) = direct_idx {
        let base = fresh_settled[d];
        for (i, n) in fresh_settled.iter().enumerate() {
            if i != d && (*n as f64) < base as f64 * RELAYED_FRESH_SHARE {
                failed.push(format!(
                    "relayed listener {i}: {n} fresh frames after the settle, under {RELAYED_FRESH_SHARE} of the direct child's {base}"
                ));
            }
        }
    }
    eprintln!("[G8] capped publisher: {context}; failed {failed:?}");
    assert!(failed.is_empty(), "{failed:?}: {context}");
    drop(arrivals);
    drop(listeners);
    drop(cp);
}

/// 45.3 — the share of the direct child's fresh frames each relayed listener
/// must get after the settle in
/// [`a_capped_publisher_sheds_to_one_child_and_the_rest_are_relayed`]. The
/// relayed ones hear the same copy one hop later, so they lose only what the
/// relay's extra hop drops or turns stale: on this bench, 13 runs (10 alone,
/// 3 under `taskset -c 0`), the worst relayed listener got 0.964 of the
/// direct child's count (541 of 561 over 28.4 s settled) and the median
/// about 0.99. 0.9 is about three times the worst shortfall seen: a relay
/// whose hop pushes a tenth of the direct child's fresh frames past the
/// budget is not relaying the one copy the cap carries.
const RELAYED_FRESH_SHARE: f64 = 0.9;

/// **G8 slow start — a call that STARTS on a capped uplink.** The same
/// room and cap as [`a_capped_publisher_sheds_to_one_child_and_the_rest_are_relayed`]
/// (one copy of `P`'s stream and a third to spare), but capped before the
/// call's first chunk: `P` starts at one direct child into its unmeasured
/// uplink, the others hear it through that child, and a step up that the
/// uplink cannot carry is taken back by the stall verdict before any link's
/// retry budget is spent. No link dies; every listener has a parent and
/// hears most of what `P` published.
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs staggered leg setup: on this 127 kbit uplink the setup alone (link, PQC transit KEX, hello, ~10 binding parts per leg, all legs at once) queues ~2 s before media; measured 1-2 of 3 legs up in 30 s and links torn down at 3.3-9.6 s during setup"]
async fn a_call_that_starts_on_a_capped_uplink_keeps_every_link() {
    let _call = one_call().await;
    let tag = "alm2-capstart";
    let uplink = CappedUplink::new();
    let (nodes, groups, _tmp) = topo_capped(
        tag,
        5,
        4,
        &[
            (0, 1),
            (0, 2),
            (0, 3),
            (1, 2),
            (1, 3),
            (2, 3),
            (0, 4),
            (1, 4),
            (2, 4),
            (3, 4),
        ],
        Some(4),
        Some((0, Arc::clone(&uplink))),
    )
    .await;
    let p = &nodes[0];
    let mut cp = join_loaded(p, &groups[0], tag, relay_opts(), None).await;
    // Capped before any leg is up or any chunk flows (the same scale as the
    // capped witness: a 600 B frame's copy plus ~170 B of framing, 30/s).
    let frame = cp.chunk_plaintext_budget().unwrap_or(240).min(600) as u64;
    let copy_kbit = (frame + 170) * 8 * 30 / 1000;
    uplink.cap_kbit(copy_kbit * 13 / 10);
    let exhausted_before: u64 = nodes.iter().map(|n| channel_exhausted(&n.metrics)).sum();
    let torn_before: u64 = nodes.iter().map(|n| torn_down(&n.metrics)).sum();
    tracing::info!(
        target: "ciris_edge::link_close",
        names = ?nodes
            .iter()
            .zip(["P", "A", "B", "C", "T"])
            .map(|(n, r)| (r, n.key.key_id.clone()))
            .collect::<Vec<_>>(),
        "G8 cap on"
    );
    let mut listeners = Vec::new();
    for (i, g) in groups.iter().enumerate().skip(1) {
        listeners.push(join_loaded(&nodes[i], g, tag, relay_opts(), None).await);
    }
    wait_legs(&cp, 3).await;
    for l in &listeners {
        wait_legs(l, 3).await;
    }
    let heard_of = count_frames_from(&mut listeners, &p.key.key_id);
    let _ = uplink.take_peak();
    let (sent, lat) = publish_timed_for(&mut cp, 20, 0).await;
    let peak = uplink.take_peak();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let heard = heard_of.read();
    let exhausted: u64 = nodes
        .iter()
        .map(|n| channel_exhausted(&n.metrics))
        .sum::<u64>()
        - exhausted_before;
    let torn: u64 = nodes.iter().map(|n| torn_down(&n.metrics)).sum::<u64>() - torn_before;
    let parents: Vec<Option<String>> = listeners
        .iter()
        .map(|l| primary_for(l, cp.stream()))
        .collect();
    let direct = parents
        .iter()
        .filter(|x| x.as_deref() == Some(p.key.key_id.as_str()))
        .count();
    let context = format!(
        "copy {copy_kbit} kbit/s; sent {sent}; heard {heard:?}; peak queue {peak:?}; parents {parents:?}; \
         P children {:?}; P counts {:?}; ChannelExhausted {exhausted}; torn {torn}",
        cp.alm_own_children(),
        (cp.alm_counts(), av(&p.metrics, "alm_uplink_stall")),
    );
    let mut failed: Vec<String> = Vec::new();
    if torn != 0 || exhausted != 0 {
        failed.push(format!(
            "links torn down: {torn} ({exhausted} by retry exhaustion)"
        ));
    }
    if direct != 1 {
        failed.push(format!("P's direct children: {direct}, want 1"));
    }
    if parents.iter().any(Option::is_none) {
        failed.push("a listener has no parent".to_owned());
    }
    if lat.max >= FRAME_INTERVAL {
        failed.push(format!("publish(): {lat:?}, over one frame interval"));
    }
    for (i, n) in heard.iter().enumerate() {
        if *n * 10 < sent * 7 {
            failed.push(format!("listener {i} heard {n} of {sent}"));
        }
    }
    eprintln!("[G8] capped from the start: {context}; failed {failed:?}");
    assert!(failed.is_empty(), "{failed:?}: {context}");
    drop(listeners);
    drop(cp);
}

/// **G8 — the kept child of a capped publisher is lost mid-cap** (the
/// model's T1/S3 case): the capped witness's room and cap; 12 s into the cap
/// P's leg to its one direct child is torn down. Then: every listener has a
/// parent again and P has a primary within [`KEPT_CHILD_RECOVER_BOUND`], no
/// other link is torn down, and the queue the redial and re-parenting add
/// stays bounded (serial redial: one leg setup in flight).
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_capped_publishers_kept_child_lost_mid_cap_is_recovered() {
    let _call = one_call().await;
    let tag = "alm2-capkill";
    let uplink = CappedUplink::new();
    let (nodes, groups, _tmp) = topo_capped(
        tag,
        5,
        4,
        &[
            (0, 1),
            (0, 2),
            (0, 3),
            (1, 2),
            (1, 3),
            (2, 3),
            (0, 4),
            (1, 4),
            (2, 4),
            (3, 4),
        ],
        Some(4),
        Some((0, Arc::clone(&uplink))),
    )
    .await;
    let p = &nodes[0];
    let mut cp = join_loaded(p, &groups[0], tag, relay_opts(), None).await;
    let mut listeners = Vec::new();
    for (i, g) in groups.iter().enumerate().skip(1) {
        listeners.push(join_loaded(&nodes[i], g, tag, relay_opts(), None).await);
    }
    wait_legs(&cp, 3).await;
    for l in &listeners {
        wait_legs(l, 3).await;
    }
    let heard_of = count_frames_from(&mut listeners, &p.key.key_id);
    let seq = publish_capped_for(&mut cp, 3, 0).await;
    let frame = cp.chunk_plaintext_budget().unwrap_or(240).min(600) as u64;
    let copy_kbit = (frame + 170) * 8 * 30 / 1000;
    let torn_before: u64 = nodes.iter().map(|n| torn_down(&n.metrics)).sum();
    uplink.cap_kbit(copy_kbit * 13 / 10);
    tracing::info!(
        target: "ciris_edge::link_close",
        names = ?nodes
            .iter()
            .zip(["P", "A", "B", "C", "T"])
            .map(|(n, r)| (r, n.key.key_id.clone()))
            .collect::<Vec<_>>(),
        "G8 cap on"
    );
    let stream = cp.stream();
    let p_key = p.key.key_id.clone();
    let ctl = async {
        tokio::time::sleep(Duration::from_secs(12)).await;
        let kept = listeners
            .iter()
            .position(|l| primary_for(l, stream).as_deref() == Some(p_key.as_str()));
        let _ = uplink.take_peak();
        let queue_at_kill = uplink.queue_now().await;
        let killed_at = tokio::time::Instant::now();
        if let Some(i) = kept {
            let key = nodes[i + 1].key.key_id.clone();
            for (peer, l, _, _) in p.transport.av_dialed_links_for_test() {
                if peer == key {
                    let _ = p.transport.link_teardown(&l).await;
                }
            }
        }
        let mut back = None;
        // Recovery is judged only once the torn child has noticed (its
        // parent is no longer P); before that the old state reads healthy.
        let mut noticed = false;
        let role_of = |k: &Option<String>| {
            k.as_deref().map_or("none".to_owned(), |k| {
                nodes
                    .iter()
                    .zip(["P", "A", "B", "C", "T"])
                    .find(|(n, _)| n.key.key_id == k)
                    .map_or("?".to_owned(), |(_, r)| (*r).to_owned())
            })
        };
        let mut last: Vec<Option<String>> = vec![None; listeners.len()];
        while killed_at.elapsed() < Duration::from_secs(13) {
            let parents: Vec<Option<String>> =
                listeners.iter().map(|l| primary_for(l, stream)).collect();
            for (i, p_now) in parents.iter().enumerate() {
                if *p_now != last[i] {
                    eprintln!(
                        "[G8KT] +{:.2}s listener {} parent {} -> {}",
                        killed_at.elapsed().as_secs_f64(),
                        ["A", "B", "C"][i],
                        role_of(&last[i]),
                        role_of(p_now)
                    );
                    last[i] = p_now.clone();
                }
            }
            if let Some(i) = kept {
                noticed |= parents[i].as_deref() != Some(p_key.as_str());
            }
            let p_has_primary = parents.iter().any(|x| x.as_deref() == Some(p_key.as_str()));
            if noticed && parents.iter().all(Option::is_some) && p_has_primary && back.is_none() {
                back = Some(killed_at.elapsed());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        (kept, back, uplink.take_peak(), queue_at_kill)
    };
    let ((sent, _lat), (kept, back, peak_after, queue_at_kill)) =
        tokio::join!(publish_timed_for(&mut cp, 25, seq), ctl);
    let torn: u64 = nodes.iter().map(|n| torn_down(&n.metrics)).sum::<u64>() - torn_before;
    let heard = heard_of.read();
    let parents: Vec<Option<String>> = listeners.iter().map(|l| primary_for(l, stream)).collect();
    let context = format!(
        "kept child {kept:?}; back after {back:?}; peak queue after the kill {peak_after:?}; \
         torn {torn}; parents {parents:?}; P children {:?}; heard {heard:?} of {sent}",
        cp.alm_own_children()
    );
    let mut failed: Vec<String> = Vec::new();
    if kept.is_none() {
        failed.push("no listener had P as its primary 12 s into the cap".to_owned());
    }
    // The mechanism's bound: the torn leg's close reaches the child through
    // P's queue, then the re-subscribe's ADMIT crosses it again: two queue
    // crossings + one offer period + one watch tick.
    let bound = queue_at_kill * 2 + Duration::from_secs(1) + Duration::from_millis(250);
    eprintln!("[G8K] queue at the kill {queue_at_kill:?}; recovery bound {bound:?}");
    if back.is_none_or(|b| b > bound) {
        failed.push(format!("not recovered within {bound:?}"));
    }
    if torn != 0 {
        failed.push(format!("links torn down besides the forced one: {torn}"));
    }
    // What was queued at the kill plus ONE leg's setup (link, PQC transit
    // KEX, hello, bindings: ~1 s at the cap): serial redial adds no more.
    let peak_bound = queue_at_kill + KEPT_CHILD_SETUP_QUEUE;
    if peak_after > peak_bound {
        failed.push(format!(
            "peak queue after the kill {peak_after:?} over {peak_bound:?}"
        ));
    }
    eprintln!("[G8K] kept child lost mid-cap: {context}; failed {failed:?}");
    eprintln!("[G8KL] P alm_log: {:?}", cp.alm_log().2);
    for (i, l) in listeners.iter().enumerate() {
        eprintln!("[G8KL] {} alm_log: {:?}", ["A", "B", "C"][i], l.alm_log().2);
    }
    assert!(failed.is_empty(), "{failed:?}: {context}");
    drop(listeners);
    drop(cp);
}

/// G8 — what one leg's setup (link, PQC transit KEX, hello, bindings) adds
/// to the queue at the cap: serial redial allows one in flight.
const KEPT_CHILD_SETUP_QUEUE: Duration = Duration::from_secs(1);

/// **45.2.0 — no calls on a shaped-only node** (Eric 2026-11-06: live A/V
/// rides unshaped links only). Node `S` sets `require_shaped_links`:
/// - its call start and join are refused `ShapedOnly`
///   (`shaped_only_no_media`), before anything starts;
/// - an A/V link another member dials to it is refused on ITS side (the
///   accepting door, not only the proposing one);
/// - a call among the others is unaffected: A, B and C hear each other.
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_shaped_only_node_neither_joins_nor_accepts_call_media() {
    let _call = one_call().await;
    let tag = "alm2-shaped";
    // 0..=2 = A, B, C; 3 = S (shaped-only). Full mesh, no canonical.
    let (nodes, groups, _tmp) = topo(
        tag,
        4,
        4,
        &[(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)],
        None,
    )
    .await;
    let (a, s) = (&nodes[0], &nodes[3]);
    let mut policy = s.transport.shaping_policy();
    policy.require_shaped_links = true;
    let _ = s.transport.set_shaping_policy(policy).await;

    // Start and join are refused by name.
    let refused = Call::join(
        &room_of(tag),
        &s.key.key_id,
        CallDeps {
            room_group: groups[3].clone(),
            roster: Arc::new(Roster(true)),
            owners: Arc::clone(&s.dir) as Arc<dyn ciris_edge::transport::av_call::CallOwners>,
            transport: Arc::clone(&s.transport),
            lifecycle: Arc::clone(&s.lifecycle),
            registrar: Arc::new(CountingRegistrar::default()),
            events: None,
            metrics: Some(s.metrics.clone()),
            record: None,
            signer: s.key.signer(),
            verifier: Arc::clone(&s.dir) as Arc<dyn StreamKeyVerifier>,
            load: None,
        },
        relay_opts(),
    )
    .await;
    assert!(
        matches!(
            refused,
            Err(ciris_edge::transport::av_call::CallError::ShapedOnly)
        ),
        "a shaped-only node's join is refused: {:?}",
        refused.as_ref().err()
    );
    assert!(av(&s.metrics, "shaped_only_no_media") >= 1);

    // The accepting door: S holds an A/V address (as a node that joined
    // before turning shaped-only would), A dials it, S refuses the arrival.
    let stream =
        ciris_edge::transport::realtime_av::StreamId(sha2::Sha256::digest(b"g8-shaped").into());
    let group = ciris_edge::av_addressing::stream_group_id(stream);
    let scope = ciris_edge::cohort_scope::CohortScope::Cohort {
        cohort_id: room_of(tag),
    };
    for n in [a, s] {
        n.lifecycle
            .joined(
                &scope,
                &group,
                1,
                &[0x5d; 32],
                &[a.key.key_id.as_str(), s.key.key_id.as_str()],
            )
            .expect("install the stream's group");
    }
    let mut s_arrivals = s.transport.take_av_arrivals().expect("S's arrivals");
    let address = a
        .lifecycle
        .table()
        .send_address(&scope, &group, &s.key.key_id)
        .expect("S's address");
    let dialled = a.transport.open_av_link(&s.key.key_id, &address).await;
    if dialled.is_ok() {
        let arrival = tokio::time::timeout(Duration::from_secs(20), s_arrivals.recv())
            .await
            .expect("the arrival reaches S")
            .expect("arrivals open");
        let accepted = s.transport.accept_av_arrival(arrival).await;
        assert!(
            accepted
                .as_ref()
                .err()
                .is_some_and(|e| e.to_string().contains("shaped_only_no_media")),
            "S refuses the A/V arrival by name: {:?}",
            accepted.as_ref().err()
        );
    }
    let before = av(&s.metrics, "shaped_only_no_media");
    assert!(before >= 2, "the accept door counted too: {before}");

    // A call among the others is unaffected.
    let mut ca = join_loaded(a, &groups[0], tag, relay_opts(), None).await;
    let mut cb = join_loaded(&nodes[1], &groups[1], tag, relay_opts(), None).await;
    let cc = join_loaded(&nodes[2], &groups[2], tag, relay_opts(), None).await;
    for call in [&ca, &cb, &cc] {
        assert!(
            wait_until(Duration::from_secs(30), || async {
                call.legs().iter().filter(|m| **m != s.key.key_id).count() >= 2
            })
            .await,
            "the others' legs come up: {:?}",
            call.legs()
        );
        assert!(
            !call.legs().contains(&s.key.key_id),
            "no leg to the shaped-only node: {:?}",
            call.legs()
        );
    }
    let mut rx = ca.frames().expect("A's frames");
    for seq in 0..20 {
        cb.publish(Frame::opaque(body("b", seq)))
            .await
            .expect("B publishes");
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let mut heard = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while let Ok(Some(f)) = tokio::time::timeout_at(deadline, rx.recv()).await {
        if f.publisher == nodes[1].key.key_id {
            heard += 1;
            if heard == 20 {
                break;
            }
        }
    }
    assert_eq!(heard, 20, "A hears B: the others' call runs");
}

/// **45.2.0 — a member that turns shaped-only MID-call ends its call**
/// (`EndCause::MediaRefused`, `shaped_only_no_media`): its legs are torn
/// down at once, so it sends no more unshaped media, and the others carry on.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_member_turning_shaped_only_mid_call_ends_its_call() {
    let _call = one_call().await;
    let tag = "alm2-midshaped";
    let (nodes, groups, _tmp) = topo(tag, 3, 3, &[(0, 1), (0, 2), (1, 2)], None).await;
    let ca = join_loaded(&nodes[0], &groups[0], tag, relay_opts(), None).await;
    let cb = join_loaded(&nodes[1], &groups[1], tag, relay_opts(), None).await;
    let cc = join_loaded(&nodes[2], &groups[2], tag, relay_opts(), None).await;
    for call in [&ca, &cb, &cc] {
        wait_legs(call, 2).await;
    }
    let c = &nodes[2];
    let mut policy = c.transport.shaping_policy();
    policy.require_shaped_links = true;
    let _ = c.transport.set_shaping_policy(policy).await;
    let ended = wait_until(Duration::from_secs(5), || async {
        matches!(
            cc.state(),
            ciris_edge::transport::av_call::CallState::Ended(
                ciris_edge::transport::av_call::EndCause::MediaRefused {
                    token: "shaped_only_no_media"
                }
            )
        )
    })
    .await;
    assert!(ended, "C's call ends by name: {:?}", cc.state());
    assert!(
        cc.legs().is_empty(),
        "C's legs are torn down: {:?}",
        cc.legs()
    );
    assert_eq!(av(&c.metrics, "av_call_ended_media_refused"), 1);
    // The others lose their legs to C and keep their own.
    for call in [&ca, &cb] {
        assert!(
            wait_until(Duration::from_secs(20), || async {
                !call.legs().contains(&c.key.key_id) && call.legs().len() == 1
            })
            .await,
            "the others carry on without C: {:?}",
            call.legs()
        );
    }
}

/// **45.2.0 — path events concern attendees only**: a room member who never
/// joins the call produces no `media_path_failed` or `media_path_restored` on
/// anyone, past the relay wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_member_who_never_joins_produces_no_path_event() {
    let _call = one_call().await;
    let tag = "alm2-absent";
    let (nodes, groups, _tmp) = topo(tag, 3, 3, &[(0, 1), (0, 2), (1, 2)], None).await;
    let mut ca = join_loaded(&nodes[0], &groups[0], tag, relay_opts(), None).await;
    let mut cb = join_loaded(&nodes[1], &groups[1], tag, relay_opts(), None).await;
    let mut events = [
        ca.events().expect("A's events"),
        cb.events().expect("B's events"),
    ];
    wait_legs(&ca, 1).await;
    wait_legs(&cb, 1).await;
    tokio::time::sleep(ciris_edge::transport::av_call::RELAY_WAIT * 2).await;
    let absent = &nodes[2].key.key_id;
    for (who, rx) in ["A", "B"].iter().zip(events.iter_mut()) {
        while let Ok(e) = rx.try_recv() {
            let about = match &e {
                CallEvent::MediaPathFailed { member, .. }
                | CallEvent::MediaPathRestored { member, .. } => Some(member),
                _ => None,
            };
            assert_ne!(
                about,
                Some(absent),
                "{who} raised a path event for a non-attendee: {e:?}"
            );
        }
    }
    drop((ca, cb));
}

// ── ReceiverMoves (docs/design/call_congestion, rows RM2–RM7) ─────────────

/// RM4 — `member`'s rank on `stream`, as edge computes it.
fn rank_of(stream: ciris_edge::transport::realtime_av::StreamId, member: &str) -> (u64, String) {
    (
        ciris_edge::transport::realtime_av_alm::controller::hash_rank(
            &stream.0,
            &member.to_owned(),
        ),
        member.to_owned(),
    )
}

/// One look at the room while `P` publishes: when (since the cap), `P`'s
/// uplink queue (ms), and each listener's primary for `P`'s stream.
#[derive(Debug, Clone)]
struct Look {
    at: Duration,
    queue_ms: Option<u64>,
    parents: Vec<Option<String>>,
    /// `P`'s own-stream children: (primaries, every child it feeds).
    own: (usize, usize),
}

/// Publish `P`'s 30 Hz stream for `secs` and look at the room every third
/// frame (~100 ms). Returns the next seq.
async fn publish_looking(
    cp: &mut Call,
    listeners: &[Call],
    uplink: &CappedUplink,
    origin: tokio::time::Instant,
    secs: u64,
    seq0: u64,
    looks: &mut Vec<Look>,
) -> u64 {
    publish_looking_stamped(cp, listeners, uplink, origin, secs, seq0, looks, None).await
}

/// One frame as `P` published it: its seq, when `publish()` was called, and
/// how long that call took (the host's capture loop waits on it).
type Stamp = (u64, tokio::time::Instant, Duration);

/// [`publish_looking`], stamping every frame into `stamps` when given.
#[allow(clippy::too_many_arguments)]
async fn publish_looking_stamped(
    cp: &mut Call,
    listeners: &[Call],
    uplink: &CappedUplink,
    origin: tokio::time::Instant,
    secs: u64,
    seq0: u64,
    looks: &mut Vec<Look>,
    mut stamps: Option<&mut Vec<Stamp>>,
) -> u64 {
    let size = cp.chunk_plaintext_budget().unwrap_or(240).min(600);
    let stream = cp.stream();
    let mut seq = seq0;
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < end {
        let mut b = body("p", seq);
        b.resize(size, b'.');
        let t = tokio::time::Instant::now();
        let _ = cp.publish(Frame::opaque(b)).await;
        if let Some(st) = stamps.as_deref_mut() {
            st.push((seq, t, t.elapsed()));
        }
        if seq.is_multiple_of(3) {
            looks.push(Look {
                at: origin.elapsed(),
                queue_ms: uplink.queue_ms(),
                parents: listeners.iter().map(|l| primary_for(l, stream)).collect(),
                own: {
                    let kids = cp.alm_own_children();
                    (
                        kids.iter()
                            .filter(|(_, r)| {
                                *r == ciris_edge::transport::realtime_av_alm::controller::Role::Primary
                            })
                            .count(),
                        kids.len(),
                    )
                },
            });
        }
        seq += 1;
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    seq
}

/// **ReceiverMoves — a capped publisher's children move themselves, and come
/// back once the cap lifts.** The room and cap of
/// [`a_capped_publisher_sheds_to_one_child_and_the_rest_are_relayed`] (one
/// copy of `P`'s stream and a third to spare, three children), held 20 s and
/// lifted. Judged on what each listener chose, looked at every ~100 ms:
/// 1. RM2/RM3: every child but the lowest-ranked (RM4) is on a member relay
///    within 1 s of its media turning late (`P`'s queue past 300 ms, plus the
///    300 ms that media takes to arrive), and stays there while the cap holds;
/// 2. exactly one direct child (the lowest-ranked) for the rest of the cap;
/// 3. no listener is ever without a parent (make-before-break);
/// 4. E1: once the children have moved, `P` feeds one child of its stream
///    while the cap holds (no fed standby); E2: `P` keeps a primary while
///    anyone subscribes;
/// 5. RM7: after the lift every child is direct again within the stated
///    bound, with at most two primary changes each (out and back): no
///    oscillation.
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_capped_publishers_children_move_themselves_and_come_back() {
    /// RM7's bound after the lift: the ceiling's staleness (60 s) + the
    /// dwell (10 s) + a window and the probe backoff.
    const RETURN_BOUND: Duration = Duration::from_secs(85);
    let _call = one_call().await;
    let tag = "alm2-rxmove";
    let uplink = CappedUplink::new();
    let (nodes, groups, _tmp) = topo_capped(
        tag,
        5,
        4,
        &[
            (0, 1),
            (0, 2),
            (0, 3),
            (1, 2),
            (1, 3),
            (2, 3),
            (0, 4),
            (1, 4),
            (2, 4),
            (3, 4),
        ],
        Some(4),
        Some((0, Arc::clone(&uplink))),
    )
    .await;
    let p = &nodes[0];
    let pid = p.key.key_id.clone();
    let mut cp = join_loaded(p, &groups[0], tag, relay_opts(), None).await;
    let mut listeners = Vec::new();
    for (i, g) in groups.iter().enumerate().skip(1) {
        listeners.push(join_loaded(&nodes[i], g, tag, relay_opts(), None).await);
    }
    wait_legs(&cp, 3).await;
    for l in &listeners {
        wait_legs(l, 3).await;
    }
    // Every listener's frames are read as they arrive, as a host does: a
    // call whose frames nobody reads fills its queues (256, then 1024 heard)
    // and its links' pumps wait on them, C3 included, so the witness judged
    // a harness that had stopped listening.
    let _drained = count_frames_from(&mut listeners, &pid);
    let stream = cp.stream();
    let names: Vec<String> = nodes[1..4].iter().map(|n| n.key.key_id.clone()).collect();
    let kept = (0..3)
        .min_by_key(|i| rank_of(stream, &names[*i]))
        .expect("three");
    // Baseline: the probe widens to the full mesh.
    let origin = tokio::time::Instant::now();
    let mut looks = Vec::new();
    let all_direct = |l: &Look| l.parents.iter().all(|x| x.as_deref() == Some(pid.as_str()));
    let mut seq = 0;
    // Slow start: the third child is relayed first and moves to P once the
    // probe has room and its dwell has passed.
    for _ in 0..20 {
        seq = publish_looking(&mut cp, &listeners, &uplink, origin, 2, seq, &mut looks).await;
        if looks.last().is_some_and(all_direct) {
            break;
        }
    }
    // Settled a little longer: offers and the standbys catch up.
    seq = publish_looking(&mut cp, &listeners, &uplink, origin, 3, seq, &mut looks).await;
    assert!(
        looks.last().is_some_and(all_direct),
        "baseline: the full mesh carries P: {:?}; looks {:?}; P children {:?}; logs: P {}\n A {}\n B {}\n C {}",
        looks.last(),
        looks
            .iter()
            .step_by(10)
            .map(|l| (l.at.as_millis(), l.parents.clone()))
            .collect::<Vec<_>>(),
        cp.alm_own_children(),
        cp.alm_log().2,
        listeners[0].alm_log().2,
        listeners[1].alm_log().2,
        listeners[2].alm_log().2,
    );
    let frame = cp.chunk_plaintext_budget().unwrap_or(240).min(600) as u64;
    let copy_kbit = (frame + 170) * 8 * 30 / 1000;
    let torn_before: Vec<u64> = nodes.iter().map(|n| torn_down(&n.metrics)).collect();
    uplink.cap_kbit(copy_kbit * 13 / 10);
    let cap_on = tokio::time::Instant::now();
    let mut capped = Vec::new();
    seq = publish_looking(&mut cp, &listeners, &uplink, cap_on, 20, seq, &mut capped).await;
    uplink.cap_kbit(0);
    let lift = cap_on.elapsed();
    let mut lifted = Vec::new();
    let _ = publish_looking(
        &mut cp,
        &listeners,
        &uplink,
        cap_on,
        RETURN_BOUND.as_secs() + 10,
        seq,
        &mut lifted,
    )
    .await;

    let mut failed: Vec<String> = Vec::new();
    let late_at = capped
        .iter()
        .find(|l| l.queue_ms.is_some_and(|q| q >= 300))
        .map(|l| l.at);
    let Some(late_at) = late_at else {
        panic!("the cap never queued P's uplink 300 ms: {capped:?}");
    };
    // Media queued 300 ms reaches the listeners 300 ms later.
    let deadline = late_at + Duration::from_millis(300) + Duration::from_secs(1);
    let relayed = |x: &Option<String>| x.as_deref().is_some_and(|x| x != pid.as_str());
    for i in (0..3).filter(|i| *i != kept) {
        let moved = capped.iter().find(|l| relayed(&l.parents[i])).map(|l| l.at);
        match moved {
            Some(at) if at <= deadline => {}
            other => failed.push(format!(
                "listener {i} on a relay at {other:?}, deadline {deadline:?} (late at {late_at:?})"
            )),
        }
    }
    let settled: Vec<&Look> = capped.iter().filter(|l| l.at > deadline).collect();
    for l in &settled {
        let direct: Vec<usize> = (0..3)
            .filter(|i| l.parents[*i].as_deref() == Some(pid.as_str()))
            .collect();
        if direct != vec![kept] {
            failed.push(format!(
                "at {:?} P's direct children {direct:?}, want only the lowest-ranked {kept}",
                l.at
            ));
            break;
        }
    }
    // E1 (RM3): once the children have moved, P feeds one copy of its
    // stream while the cap holds: no child kept as a (fed) standby.
    if let Some(l) = settled.iter().find(|l| l.own.1 > 1) {
        failed.push(format!(
            "E1: at {:?} P feeds {} children of its stream ({} primary)",
            l.at, l.own.1, l.own.0
        ));
    }
    // E2: P keeps a primary while anyone subscribes.
    if let Some(l) = capped
        .iter()
        .chain(&lifted)
        .find(|l| l.own.1 > 0 && l.own.0 == 0)
    {
        failed.push(format!(
            "E2: at {:?} P has {} subscribers and no primary",
            l.at, l.own.1
        ));
    }
    for l in capped.iter().chain(&lifted) {
        if l.parents.iter().any(Option::is_none) {
            failed.push(format!(
                "a listener without a parent at {:?}: {:?}",
                l.at, l.parents
            ));
            break;
        }
    }
    let back = lifted
        .iter()
        .find(|l| all_direct(l))
        .map(|l| l.at.checked_sub(lift).unwrap());
    match back {
        Some(b) if b <= RETURN_BOUND => {}
        other => failed.push(format!(
            "all direct again {other:?} after the lift (bound {RETURN_BOUND:?})"
        )),
    }
    if let Some(l) = lifted.last() {
        if !all_direct(l) {
            failed.push(format!("not all direct at the end: {:?}", l.parents));
        }
    }
    for i in 0..3 {
        let changes = capped
            .iter()
            .chain(&lifted)
            .collect::<Vec<_>>()
            .windows(2)
            .filter(|w| w[0].parents[i] != w[1].parents[i])
            .count();
        let most = if i == kept { 0 } else { 2 };
        if changes > most {
            failed.push(format!(
                "listener {i}: {changes} primary changes (at most {most})"
            ));
        }
    }
    let torn: Vec<u64> = nodes
        .iter()
        .zip(&torn_before)
        .map(|(n, b)| torn_down(&n.metrics) - b)
        .collect();
    let first_none = capped
        .iter()
        .chain(&lifted)
        .find(|l| l.parents.iter().any(Option::is_none))
        .map(|l| l.at);
    let context = format!(
        "links torn per node (P, A, B, C, T) {torn:?}; first parentless look {first_none:?}; \
         offers held for backlog per node {:?}; \
         kept {kept}; late at {late_at:?}; lift at {lift:?}; back after {back:?}; P children {:?}; \
         P counts {:?}; P labels: stall {} departure {}; listeners' late moves {:?}; capped looks {:?}",
        nodes
            .iter()
            .map(|n| {
                (
                    av(&n.metrics, "alm_offer_held:backlog"),
                    av(&n.metrics, "alm_c3_send_failed"),
                    av(&n.metrics, "alm_c3_sent"),
                    av(&n.metrics, "alm_c3_received"),
                )
            })
            .collect::<Vec<_>>(),
        cp.alm_own_children(),
        cp.alm_counts(),
        av(&p.metrics, "alm_uplink_stall"),
        av(&p.metrics, "alm_departure_congestion"),
        nodes[1..4]
            .iter()
            .map(|n| (av(&n.metrics, "alm_late_move"), av(&n.metrics, "alm_late_spared")))
            .collect::<Vec<_>>(),
        capped
            .iter()
            .step_by(5)
            .take(30)
            .map(|l| (l.at.as_millis(), l.queue_ms, l.parents.iter().map(|x| x.as_deref() == Some(pid.as_str())).collect::<Vec<_>>()))
            .collect::<Vec<_>>(),
    );
    eprintln!("[RM] capped then lifted: {context}; failed {failed:?}");
    if !failed.is_empty() {
        // What each node decided, and the looks around the first failure.
        let around = first_none.unwrap_or(lift);
        let near: Vec<_> = capped
            .iter()
            .chain(&lifted)
            .filter(|l| {
                l.at + Duration::from_secs(6) >= around && l.at <= around + Duration::from_secs(2)
            })
            .map(|l| (l.at.as_millis(), l.queue_ms, l.own, l.parents.clone()))
            .collect();
        eprintln!("[RM] looks around {around:?}: {near:?}");
        eprintln!("[RM] P log:\n{}", cp.alm_log().2);
        for (i, l) in listeners.iter().enumerate() {
            eprintln!("[RM] listener {i} log:\n{}", l.alm_log().2);
        }
    }
    assert!(failed.is_empty(), "{failed:?}: {context}");
    drop(listeners);
    drop(cp);
}

/// Calls 1, 2 and 3 each publish 30 Hz for `secs`.
async fn publish_three(calls: &mut [Call], secs: u64, seq0: u64) -> u64 {
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    let mut seq = seq0;
    while tokio::time::Instant::now() < end {
        for who in 1..=3usize {
            let size = calls[who].chunk_plaintext_budget().unwrap_or(240).min(600);
            let mut b = body(["r", "p", "q", "s"][who], seq);
            b.resize(size, b'.');
            let _ = calls[who].publish(Frame::opaque(b)).await;
        }
        seq += 1;
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    seq
}

/// **RM6 — a receiver whose own downlink is slow does not move.** Three
/// members publish (`P` and two others); `R`'s downlink then delays everything sent
/// to it by 400 ms. `P`'s stream reads late at `R`, and so do the others': the
/// lateness is `R`'s own, a relay would not help, and `R` stays a direct
/// child of `P` (the own-downlink guard is counted). The guard is read
/// before the rank spare (RM6 before RM4), so the witness holds whatever
/// `R`'s rank: no outcome depends on the random stream ids.
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_receiver_whose_own_downlink_is_slow_does_not_move() {
    let _call = one_call().await;
    let tag = "alm2-rxslow";
    let downlink = CappedUplink::new();
    // 0 = R (slow downlink, dials nobody), 1..=3 members, 4 = T.
    let (nodes, groups, _tmp) = topo_capped(
        tag,
        5,
        4,
        &[
            (0, 1),
            (0, 2),
            (0, 3),
            (1, 2),
            (1, 3),
            (2, 3),
            (0, 4),
            (1, 4),
            (2, 4),
            (3, 4),
        ],
        Some(4),
        Some((0, Arc::clone(&downlink))),
    )
    .await;
    let r = &nodes[0];
    let mut calls = Vec::new();
    for (i, g) in groups.iter().enumerate() {
        calls.push(join_loaded(&nodes[i], g, tag, relay_opts(), None).await);
    }
    for c in &calls {
        wait_legs(c, 3).await;
    }
    // Every member but R publishes. P: any of them that has R as a direct
    // child. No rank enters: the own-downlink guard is read before the
    // spare (RM6 before RM4), so it runs whichever child P keeps.
    let mut seq = 0;
    let mut chosen = None;
    for _ in 0..30 {
        seq = publish_three(&mut calls, 3, seq).await;
        chosen = (1..=3usize).find(|&p| {
            primary_for(&calls[0], calls[p].stream()).as_deref()
                == Some(nodes[p].key.key_id.as_str())
        });
        if chosen.is_some() {
            break;
        }
    }
    let Some(p) = chosen else {
        // Who each publisher feeds directly, with each child's rank (and
        // R's), so a miss says whether the tree or the ranks were wrong.
        let seen: Vec<String> = (1..=3usize)
            .map(|p| {
                let st = calls[p].stream();
                let pid = nodes[p].key.key_id.as_str();
                let kids: Vec<String> = (0..=3usize)
                    .filter(|i| *i != p)
                    .map(|i| {
                        format!(
                            "{i}:{}@{}",
                            primary_for(&calls[i], st).map_or("none".to_owned(), |x| if x == pid {
                                "direct".to_owned()
                            } else {
                                x[..6].to_owned()
                            }),
                            rank_of(st, &nodes[i].key.key_id).0
                        )
                    })
                    .collect();
                format!("P{p}: {kids:?}")
            })
            .collect();
        panic!("R is a direct child of some publisher within 90 s: {seen:?}");
    };
    let pid = nodes[p].key.key_id.clone();
    let pstream = calls[p].stream();
    let guarded_before = av(&r.metrics, "alm_late_guarded:own_downlink");
    let moves_before = av(&r.metrics, "alm_late_move");
    downlink.delay_down_ms(400);
    let mut left = None;
    let start = tokio::time::Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        seq = publish_three(&mut calls, 1, seq).await;
        let now = primary_for(&calls[0], pstream);
        if now.as_deref() != Some(pid.as_str()) {
            left = Some((start.elapsed(), now));
            break;
        }
    }
    let guarded = av(&r.metrics, "alm_late_guarded:own_downlink") - guarded_before;
    let moves = av(&r.metrics, "alm_late_move") - moves_before;
    let context = format!(
        "P = node {p}: R left P {left:?}; guarded {guarded}; late moves {moves}; spared {}; \
         R failovers {}; R stale {} expired-late {} datagram-late {}",
        av(&r.metrics, "alm_late_spared"),
        av(&r.metrics, "alm_failover"),
        av(&r.metrics, "av_frame_stale_dropped"),
        av(&r.metrics, "av_frame_expired_late"),
        av(&r.metrics, "av_datagram_late"),
    );
    eprintln!("[RM6] slow downlink: {context}");
    if left.is_some() {
        eprintln!("[RM6] R log:\n{}", calls[0].alm_log().2);
        eprintln!("[RM6] P log:\n{}", calls[p].alm_log().2);
    }
    // The row's must-never: no LATE move (RM6). A failover by silence is
    // another mechanism and is reported in the context, not judged here.
    assert_eq!(moves, 0, "R made a late move: {context}");
    assert!(
        guarded >= 1,
        "the guard never ran (R was not late?): {context}"
    );
    drop(calls);
}

// ── Calls cut — a room where nobody relays (phones on metered data) ──────

/// The longest a (listener, publisher) pair may go between consecutive
/// chunks in an uncapped room where nobody relays. The design's intent is no
/// gap beyond the cadence (the slow-start bridge exists so a refused member's
/// move costs it nothing); the uncapped witness
/// [`every_pair_keeps_both_legs_uncapped`] states no per-pair gap tolerance,
/// so this is the 1 s the calls cut asks for.
const NO_RELAY_GAP_BOUND: Duration = Duration::from_secs(1);

/// The uncapped room of [`every_pair_keeps_both_legs_uncapped`]: four members
/// reaching each other directly, node 4 the canonical shape.
const NO_RELAY_DIALS: [(usize, usize); 10] = [
    (0, 1),
    (0, 2),
    (0, 3),
    (1, 2),
    (1, 3),
    (2, 3),
    (0, 4),
    (1, 4),
    (2, 4),
    (3, 4),
];

/// What one listener heard, per stream, as it arrived.
type Arrivals = Arc<
    std::sync::Mutex<
        Vec<(
            ciris_edge::transport::realtime_av::StreamId,
            tokio::time::Instant,
        )>,
    >,
>;

/// One look at the room: each listener's primary for each publisher's
/// stream (a role label), and each publisher's own-stream children
/// (primaries, all).
#[derive(Debug, Clone, PartialEq)]
struct NoRelayLook {
    parents: Vec<Vec<Option<String>>>,
    kids: Vec<(usize, usize)>,
}

/// A four-member room in which every member joins with relay OFF and
/// publishes 30 Hz from its own start (`t0`), each listener's arrivals
/// recorded per stream as they come.
struct NoRelayRoom {
    tag: &'static str,
    nodes: Arc<Vec<Node>>,
    groups: Arc<Vec<CohortGroup>>,
    /// `N0`..`N3` for the members, `T` for the canonical, by key id.
    names: Vec<(String, String)>,
    origin: tokio::time::Instant,
    calls: Vec<Option<Call>>,
    joining: Vec<Option<tokio::task::JoinHandle<Call>>>,
    join_started: Vec<Option<tokio::time::Instant>>,
    joined: Vec<Option<tokio::time::Instant>>,
    /// Where a member's pair clocks start (and from when it publishes).
    t0: Vec<Option<tokio::time::Instant>>,
    /// Publish on install (a late joiner talks from its join).
    publish_on_join: bool,
    sends: Vec<Vec<tokio::time::Instant>>,
    seq: u64,
    arrivals: Vec<Arrivals>,
    events: Vec<Option<mpsc::Receiver<CallEvent>>>,
    /// (ms since origin, on node, event).
    path_events: Vec<(u128, usize, String)>,
    /// (ms since origin, look), only when it changed.
    looks: Vec<(u128, NoRelayLook)>,
    /// [listener][publisher]: first time the listener's primary was the
    /// publisher itself.
    first_direct: Vec<Vec<Option<tokio::time::Instant>>>,
    /// [publisher][child]: first time the child held a PRIMARY on the
    /// publisher's own stream.
    first_child: Vec<Vec<Option<tokio::time::Instant>>>,
    /// Every (ms, listener, publisher, parent) where a listener's primary
    /// for a publisher's stream was another member.
    member_parents: Vec<(u128, usize, usize, String)>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for NoRelayRoom {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
        for j in self.joining.iter().flatten() {
            j.abort();
        }
    }
}

impl NoRelayRoom {
    fn new(
        tag: &'static str,
        nodes: Vec<Node>,
        groups: Vec<CohortGroup>,
        publish_on_join: bool,
    ) -> Self {
        let names = nodes
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    n.key.key_id.clone(),
                    if i < 4 {
                        format!("N{i}")
                    } else {
                        "T".to_owned()
                    },
                )
            })
            .collect();
        Self {
            tag,
            nodes: Arc::new(nodes),
            groups: Arc::new(groups),
            names,
            origin: tokio::time::Instant::now(),
            calls: (0..4).map(|_| None).collect(),
            joining: (0..4).map(|_| None).collect(),
            join_started: vec![None; 4],
            joined: vec![None; 4],
            t0: vec![None; 4],
            publish_on_join,
            sends: vec![Vec::new(); 4],
            seq: 0,
            arrivals: (0..4)
                .map(|_| Arc::new(std::sync::Mutex::new(Vec::new())))
                .collect(),
            events: (0..4).map(|_| None).collect(),
            path_events: Vec::new(),
            looks: Vec::new(),
            first_direct: vec![vec![None; 4]; 4],
            first_child: vec![vec![None; 4]; 4],
            member_parents: Vec::new(),
            tasks: Vec::new(),
        }
    }

    fn ms(&self, t: tokio::time::Instant) -> u128 {
        t.saturating_duration_since(self.origin).as_millis()
    }

    fn name(&self, key_id: &str) -> String {
        self.names.iter().find(|(k, _)| k == key_id).map_or_else(
            || key_id[..8.min(key_id.len())].to_owned(),
            |(_, n)| n.clone(),
        )
    }

    /// Join member `i` with relay OFF, in the background.
    fn start_join(&mut self, i: usize) {
        self.join_started[i] = Some(tokio::time::Instant::now());
        let (nodes, groups, tag) = (Arc::clone(&self.nodes), Arc::clone(&self.groups), self.tag);
        self.joining[i] = Some(tokio::spawn(async move {
            join_loaded(
                &nodes[i],
                &groups[i],
                tag,
                CallOptions {
                    relay: false,
                    ..CallOptions::default()
                },
                None,
            )
            .await
        }));
    }

    async fn poll_joins(&mut self) {
        for i in 0..4 {
            if self.joining[i]
                .as_ref()
                .is_some_and(tokio::task::JoinHandle::is_finished)
            {
                let mut call = self.joining[i]
                    .take()
                    .expect("finished")
                    .await
                    .expect("join task");
                let mut rx = call.frames().expect("frames");
                let arr = Arc::clone(&self.arrivals[i]);
                self.tasks.push(tokio::spawn(async move {
                    while let Some(f) = rx.recv().await {
                        arr.lock()
                            .expect("arrivals")
                            .push((f.stream, tokio::time::Instant::now()));
                    }
                }));
                self.events[i] = call.events();
                self.calls[i] = Some(call);
                self.joined[i] = Some(tokio::time::Instant::now());
                if self.publish_on_join {
                    self.t0[i] = self.join_started[i];
                }
            }
        }
    }

    fn all_joined(&self) -> bool {
        self.calls.iter().all(Option::is_some)
    }

    // l and p index several per-member tables at once.
    #[allow(clippy::needless_range_loop)]
    fn look(&mut self) {
        let now = tokio::time::Instant::now();
        let streams: Vec<Option<ciris_edge::transport::realtime_av::StreamId>> = self
            .calls
            .iter()
            .map(|c| c.as_ref().map(Call::stream))
            .collect();
        let mut parents = vec![vec![None; 4]; 4];
        for l in 0..4 {
            let Some(cl) = &self.calls[l] else { continue };
            for p in (0..4).filter(|p| *p != l) {
                let Some(s) = streams[p] else { continue };
                let Some(x) = primary_for(cl, s) else {
                    continue;
                };
                if x == self.names[p].0 {
                    self.first_direct[l][p].get_or_insert(now);
                } else {
                    self.member_parents
                        .push((self.ms(now), l, p, self.name(&x)));
                }
                parents[l][p] = Some(self.name(&x));
            }
        }
        let mut kids = vec![(0, 0); 4];
        for p in 0..4 {
            let Some(cp) = &self.calls[p] else { continue };
            let own = cp.alm_own_children();
            kids[p] = (
                own.iter().filter(|(_, r)| *r == Role::Primary).count(),
                own.len(),
            );
            for (c, r) in &own {
                if *r == Role::Primary {
                    if let Some(ci) = self.names[..4].iter().position(|(k, _)| k == c) {
                        self.first_child[p][ci].get_or_insert(now);
                    }
                }
            }
        }
        let look = NoRelayLook { parents, kids };
        if self.looks.last().is_none_or(|(_, l)| *l != look) {
            self.looks.push((self.ms(now), look));
        }
        let at = self.ms(now);
        for i in 0..4 {
            let Some(rx) = self.events[i].as_mut() else {
                continue;
            };
            while let Ok(e) = rx.try_recv() {
                let line = match &e {
                    CallEvent::MediaPathFailed {
                        member,
                        cause,
                        detail,
                        ..
                    } => Some(format!("MediaPathFailed {member} {cause:?} {detail:?}")),
                    CallEvent::MediaPathRestored { member, via, .. } => {
                        Some(format!("MediaPathRestored {member} {via:?}"))
                    }
                    _ => None,
                };
                if let Some(line) = line {
                    let named = self
                        .names
                        .iter()
                        .fold(line, |s, (k, n)| s.replace(k.as_str(), n));
                    self.path_events.push((at, i, named));
                }
            }
        }
    }

    /// Without publishing: look and take joins until `done` or `budget`.
    async fn settle(&mut self, budget: Duration, done: impl Fn(&Self) -> bool) -> bool {
        let end = tokio::time::Instant::now() + budget;
        loop {
            self.poll_joins().await;
            self.look();
            if done(self) {
                return true;
            }
            if tokio::time::Instant::now() > end {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Every publishing member sends one frame; a look every third.
    async fn tick(&mut self) {
        for i in 0..4 {
            if self.t0[i].is_none() {
                continue;
            }
            let Some(c) = self.calls[i].as_mut() else {
                continue;
            };
            let size = c.chunk_plaintext_budget().unwrap_or(240).min(600);
            let mut b = body(["a", "b", "c", "d"][i], self.seq);
            b.resize(size, b'.');
            let _ = c.publish(Frame::opaque(b)).await;
            self.sends[i].push(tokio::time::Instant::now());
        }
        if self.seq.is_multiple_of(3) {
            self.look();
        }
        self.seq += 1;
        tokio::time::sleep(FRAME_INTERVAL).await;
    }

    async fn run_for(&mut self, d: Duration) {
        let end = tokio::time::Instant::now() + d;
        while tokio::time::Instant::now() < end {
            self.poll_joins().await;
            self.tick().await;
        }
    }

    /// Run until member `i` has joined, then `d` more.
    async fn run_past_join(&mut self, i: usize, d: Duration) {
        let budget = tokio::time::Instant::now() + Duration::from_mins(1);
        while self.calls[i].is_none() {
            assert!(
                tokio::time::Instant::now() < budget,
                "member {i} joins within 60 s"
            );
            self.poll_joins().await;
            self.tick().await;
        }
        self.run_for(d).await;
    }

    /// The per-pair table and every failure, the publishing having ended at
    /// `end`.
    #[allow(clippy::too_many_lines)]
    fn judge(&self, end: tokio::time::Instant) -> (String, Vec<String>) {
        let mut out = String::new();
        let mut failed = Vec::new();
        let ms = |t: Option<tokio::time::Instant>| t.map(|t| self.ms(t));
        let _ = writeln!(
            out,
            "joins (ms since origin) started {:?} done {:?}; pair clocks t0 {:?}; publishing ended {}",
            self.join_started.iter().map(|t| ms(*t)).collect::<Vec<_>>(),
            self.joined.iter().map(|t| ms(*t)).collect::<Vec<_>>(),
            self.t0.iter().map(|t| ms(*t)).collect::<Vec<_>>(),
            self.ms(end),
        );
        out.push_str(
            "pair L<-P: first chunk (ms from max(t0 L, t0 P)) | longest gap ms (at ms) | tail ms | heard/sent | first direct (ms from ref) | parents seen\n",
        );
        for l in 0..4 {
            let arr = self.arrivals[l].lock().expect("arrivals").clone();
            for p in (0..4).filter(|p| *p != l) {
                let (Some(tl), Some(tp)) = (self.t0[l], self.t0[p]) else {
                    failed.push(format!("N{l}<-N{p}: a member never started"));
                    continue;
                };
                let r = tl.max(tp);
                let Some(stream) = self.calls[p].as_ref().map(Call::stream) else {
                    continue;
                };
                let heard: Vec<tokio::time::Instant> = arr
                    .iter()
                    .filter(|(s, t)| *s == stream && *t >= r)
                    .map(|(_, t)| *t)
                    .collect();
                let sent = self.sends[p].iter().filter(|t| **t >= r).count();
                let first = heard.first().map(|t| t.duration_since(r));
                let (gap, gap_at) = heard
                    .windows(2)
                    .map(|w| (w[1].duration_since(w[0]), w[1]))
                    .max_by_key(|(g, _)| *g)
                    .map_or((Duration::ZERO, None), |(g, at)| (g, Some(at)));
                let tail = heard
                    .last()
                    .map_or(Duration::ZERO, |t| end.saturating_duration_since(*t));
                let direct = self.first_direct[l][p].map(|t| {
                    if t >= r {
                        t.duration_since(r).as_millis().to_string()
                    } else {
                        format!("-{}", r.duration_since(t).as_millis())
                    }
                });
                let mut seen: Vec<Option<String>> = Vec::new();
                for (_, lk) in &self.looks {
                    if seen.last() != Some(&lk.parents[l][p]) {
                        seen.push(lk.parents[l][p].clone());
                    }
                }
                let _ = writeln!(
            out,
                    "  N{l}<-N{p}: first {:?} | gap {} (at {:?}) | tail {} | {}/{} | direct {:?} | {:?}",
                    first.map(|d| d.as_millis()),
                    gap.as_millis(),
                    gap_at.map(|t| self.ms(t)),
                    tail.as_millis(),
                    heard.len(),
                    sent,
                    direct,
                    seen,
                );
                if heard.is_empty() {
                    failed.push(format!("N{l} never heard N{p}"));
                }
                if gap > NO_RELAY_GAP_BOUND {
                    failed.push(format!(
                        "N{l}<-N{p}: gap {} ms at {:?} ms, bound {} ms",
                        gap.as_millis(),
                        gap_at.map(|t| self.ms(t)),
                        NO_RELAY_GAP_BOUND.as_millis()
                    ));
                }
                if tail > NO_RELAY_GAP_BOUND {
                    failed.push(format!(
                        "N{l}<-N{p}: nothing for the last {} ms",
                        tail.as_millis()
                    ));
                }
            }
        }
        out.push_str("children admitted as PRIMARY on each publisher's own stream (ms since origin, in admission order; the 3rd is the one slow start refused):\n");
        for p in 0..4 {
            let mut kids: Vec<(u128, usize)> = (0..4)
                .filter_map(|c| self.first_child[p][c].map(|t| (self.ms(t), c)))
                .collect();
            kids.sort_unstable();
            let rel: Vec<String> = kids
                .iter()
                .map(|(t, c)| {
                    // From the later of the pair's two starts (the pair's
                    // own clock): the time it took to become direct.
                    let since = self.t0[*c].zip(self.t0[p]).map(|(a, b)| {
                        i128::try_from(*t).unwrap() - i128::try_from(self.ms(a.max(b))).unwrap()
                    });
                    format!("N{c}@{t} (+{since:?} from the pair's start)")
                })
                .collect();
            let _ = writeln!(out, "  N{p}: {rel:?}");
        }
        out.push_str("looks (ms since origin; parents[listener][publisher]; own (primaries, all) per publisher), on change:\n");
        for (t, lk) in &self.looks {
            let _ = writeln!(out, "  {t}: kids {:?} parents {:?}", lk.kids, lk.parents);
        }
        let _ = writeln!(out, "path events: {:?}", self.path_events);
        for (t, i, e) in &self.path_events {
            if e.starts_with("MediaPathFailed") {
                failed.push(format!("N{i} at {t} ms: {e}"));
            }
        }
        if let Some(first) = self.member_parents.first() {
            failed.push(format!(
                "a listener's parent was a member (nobody relays): first {first:?}, {} looks",
                self.member_parents.len()
            ));
        }
        (out, failed)
    }

    fn logs(&self) -> String {
        let mut s = String::new();
        for (i, c) in self.calls.iter().enumerate() {
            if let Some(c) = c {
                let tail = self
                    .names
                    .iter()
                    .fold(c.alm_log().2, |s, (k, n)| s.replace(k.as_str(), n));
                let _ = writeln!(s, "[NR] N{i} log:\n{tail}");
            }
        }
        s
    }
}

/// **Calls cut — a room where nobody relays hears every publisher
/// directly** (the server's metered-phone case: every member passes
/// `relay: false`). Four members, uncapped, all publishing 30 Hz for 25 s.
/// Slow start gives each publisher two direct children into its unmeasured
/// uplink and refuses the third for capacity; with no relay anywhere, that
/// member hears the publisher only through the slow-start bridge until the
/// probe widens and admits it. Judged per (listener, publisher) pair: heard,
/// no gap past [`NO_RELAY_GAP_BOUND`], no `MediaPathFailed` anywhere, and no
/// member ever a parent.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_room_where_nobody_relays_hears_every_publisher_directly() {
    let _call = one_call().await;
    let tag = "alm2-norelay";
    let (nodes, groups, _tmp) = topo(tag, 5, 4, &NO_RELAY_DIALS, Some(4)).await;
    let mut room = NoRelayRoom::new(tag, nodes, groups, false);
    for i in 0..4 {
        room.start_join(i);
    }
    let up = room
        .settle(Duration::from_mins(1), |r| {
            r.all_joined() && r.calls.iter().flatten().all(|c| c.legs().len() >= 3)
        })
        .await;
    assert!(up, "every member joins and holds 3 legs: {}", room.logs());
    let start = tokio::time::Instant::now();
    for i in 0..4 {
        room.t0[i] = Some(start);
    }
    room.run_for(Duration::from_secs(25)).await;
    let end = tokio::time::Instant::now();
    // Late arrivals of what was sent before `end`.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (table, failed) = room.judge(end);
    eprintln!("[NR] nobody relays, all at once:\n{table}failed {failed:?}");
    if !failed.is_empty() {
        eprintln!("{}", room.logs());
    }
    assert!(failed.is_empty(), "{failed:?}");
}

/// **Calls cut — late joiners in a room where nobody relays hear everyone**:
/// two members streaming for 6 s; the third joins, the fourth 6 s later,
/// every member with relay OFF, each publishing from its join. The fourth
/// is each first publisher's third child, the one slow start refuses into
/// an unmeasured uplink. Per pair, counted from the later of the two
/// members' starts: heard, no gap past [`NO_RELAY_GAP_BOUND`], no
/// `MediaPathFailed`.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn late_joiners_in_a_room_where_nobody_relays_hear_everyone() {
    let _call = one_call().await;
    let tag = "alm2-norelay-late";
    let (nodes, groups, _tmp) = topo(tag, 5, 4, &NO_RELAY_DIALS, Some(4)).await;
    let mut room = NoRelayRoom::new(tag, nodes, groups, true);
    room.start_join(0);
    room.start_join(1);
    let up = room
        .settle(Duration::from_mins(1), |r| {
            r.calls[..2]
                .iter()
                .all(|c| c.as_ref().is_some_and(|c| !c.legs().is_empty()))
        })
        .await;
    assert!(up, "the first two join and hold a leg: {}", room.logs());
    // The first two start streaming together, once they hold their leg.
    let start = tokio::time::Instant::now();
    room.t0[0] = Some(start);
    room.t0[1] = Some(start);
    room.run_for(Duration::from_secs(6)).await;
    room.start_join(2);
    room.run_for(Duration::from_secs(6)).await;
    room.start_join(3);
    room.run_past_join(3, Duration::from_secs(20)).await;
    let end = tokio::time::Instant::now();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (table, failed) = room.judge(end);
    eprintln!("[NR] nobody relays, late joiners:\n{table}failed {failed:?}");
    if !failed.is_empty() {
        eprintln!("{}", room.logs());
    }
    assert!(failed.is_empty(), "{failed:?}");
}

// ─── 45.3: the whole-uplink cap, as the server matrix applies it ─────────

/// One second of [`whole_uplink_cap`]'s samples.
struct UplinkSecond {
    s: u64,
    shaper: NetemSecond,
    /// Per node: (exhausted, timeout, stale) closes, cumulative.
    torn: Vec<Vec<u64>>,
    /// What m0 handed its shaper this second, by class and link.
    classes: ClassMap,
    /// m0's `av_send_congested` and `alm_c3_send_failed`, cumulative.
    congested: u64,
    c3_failed: u64,
    /// m0's `alm_c3_received`, and every node's `alm_c3_sent`, cumulative.
    c3_received: u64,
    c3_sent: Vec<u64>,
    /// m0's own A/V legs now: (member, srtt, learned srtt, min rtt, tx ring).
    rtt: Vec<LegRtt>,
}

/// One of m0's legs: (member, srtt, learned srtt, min rtt, tx ring).
type LegRtt = (String, Option<f64>, Option<f64>, Option<u64>, usize);

/// What one [`whole_uplink_cap`] run measured.
struct UplinkCapRun {
    /// Per listener: the fraction of m0's frames heard, over the cap.
    capped: Vec<f64>,
    /// Per listener: over the cap's first 10 s.
    first_10s: Vec<f64>,
    /// Per listener: the fraction of m0's frames heard within 800 ms of
    /// being published, over the cap after a 10 s settle.
    capped_fresh: Vec<f64>,
    /// Per listener: after the lift (from 2 s after it).
    lifted: Vec<f64>,
    /// Per listener: the longest gap between m0's frames under the cap.
    longest_gap: Vec<Duration>,
    /// Links torn down (exhausted/timeout/stale) under the cap, every node.
    torn_under_cap: u64,
    /// The cap applied (kbit/s), and the server's it stands for.
    cap_kbit: u64,
    /// Per listener: m0's audio heard within 800 ms after a 2 s settle.
    audio_fresh: Vec<f64>,
    /// Per listener: the longest audio gap after the settle.
    audio_gap: Vec<Duration>,
    /// Per listener: of m0's video frames delivered, the share within 800 ms.
    video_fresh_of_delivered: Vec<f64>,
    /// Per listener: the longest video gap after the settle.
    video_gap: Vec<Duration>,
    /// Per listener: the longest gap in DECODABLE video after the settle (a
    /// frame decodes if it is a keyframe or follows the last decoded one).
    video_decoded_gap: Vec<Duration>,
    /// `CallEvent::KeyframeWanted` events m0's host saw, and whether it
    /// honoured them.
    keyframe_events: (u64, bool),
    /// 45.3 (CC review, FIRST class) — a room removal and a chat row of the
    /// same size, sent m0 → m1 at one instant: before the cap...
    probe_uncapped: FirstProbe,
    /// ...and mid-cap, while m0's budget is in force and holding video.
    probe_capped: FirstProbe,
}

/// One FIRST-vs-BULK probe: each envelope's class (from edge's own
/// classifier), its delivery time (`None`: not heard within the wait), the
/// uplink FIFO's queue time at the send, and m0's held-video count across it.
#[derive(Debug, Clone, Default)]
struct FirstProbe {
    removal_class: Option<ciris_edge::transport::egress_budget::SendClass>,
    chat_class: Option<ciris_edge::transport::egress_budget::SendClass>,
    removal: Option<Duration>,
    chat: Option<Duration>,
    fifo_ms: u64,
    budget_bps: Option<f64>,
    video_held: (u64, u64),
}

/// The probe: a `membership:removal` Deliver and a `chat:` Deliver, each
/// classed by `ciris_edge::replication::egress_class::class_of` and sent by
/// `from` under that class at one instant, padded to one size; heard on
/// `to`'s identity plane. `cap_kbit` turns the FIFO's backlog into time.
async fn first_probe(
    from: &Node,
    to: &Node,
    uplink: &NetemUplink,
    cap_kbit: u64,
    tag: &str,
) -> FirstProbe {
    use ciris_edge::replication::egress_class::class_of;
    use ciris_edge::replication::protocol::{DeliverMessage, EnvelopeKind, ReplicationMessage};
    const SIZE: usize = 1_200;
    let deliver = |dimension: &str| {
        ReplicationMessage::Deliver(DeliverMessage {
            kind: EnvelopeKind::Attestation,
            envelopes: vec![serde_json::to_vec(&serde_json::json!({
                "attestation_id": "probe",
                "attestation_type": "membership",
                "attestation_envelope": {"dimension": dimension},
            }))
            .expect("row")],
        })
    };
    let removal_class = class_of(&deliver("membership:removal:v1"));
    let chat_class = class_of(&deliver("chat:message:v1"));
    let bytes = |what: &str| {
        let mut b = PROBE_MARKER.to_vec();
        b.extend_from_slice(format!("{tag}:{what}:").as_bytes());
        b.resize(SIZE, b'.');
        b
    };
    let held = |n: &Node| av(&n.metrics, "av_frame_held_budget");
    let held0 = held(from);
    let budget_bps = from.transport.egress_budget().rate_bps();
    let q = uplink.read();
    let fifo_ms = (q.backlog_bytes * 8).checked_div(cap_kbit).unwrap_or(0);
    // Bulk already waiting: ten envelopes of the same size queued ahead, as
    // a replication round's rows would be. A removal filed as bulk would
    // wait behind them; the chat row does.
    for k in 0..PROBE_FILLERS {
        let t = Arc::clone(&from.transport);
        let dest = to.key.key_id.clone();
        let b = bytes(&format!("filler{k}"));
        tokio::spawn(async move {
            let _ = ciris_edge::transport::egress_budget::sending_as(
                ciris_edge::transport::egress_budget::SendClass::Bulk,
                t.send(&dest, &b),
            )
            .await;
        });
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let sent = tokio::time::Instant::now();
    for (what, class) in [("removal", removal_class), ("chat", chat_class)] {
        let t = Arc::clone(&from.transport);
        let dest = to.key.key_id.clone();
        let b = bytes(what);
        tokio::spawn(async move {
            let _ =
                ciris_edge::transport::egress_budget::sending_as(class, t.send(&dest, &b)).await;
        });
    }
    let heard = |what: &str| {
        let want = format!("{tag}:{what}:");
        to.probes
            .lock()
            .expect("probes")
            .iter()
            .find(|(_, b)| b[PROBE_MARKER.len()..].starts_with(want.as_bytes()))
            .map(|(at, _)| at.saturating_duration_since(sent))
    };
    let until = sent + Duration::from_secs(30);
    while tokio::time::Instant::now() < until
        && (heard("removal").is_none() || heard("chat").is_none())
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    FirstProbe {
        removal_class: Some(removal_class),
        chat_class: Some(chat_class),
        removal: heard("removal"),
        chat: heard("chat"),
        fifo_ms,
        budget_bps,
        video_held: (held0, held(from)),
    }
}

/// The frame sequence number `body("w", seq)` carries.
fn seq_of(bytes: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(bytes.get(..32)?.split(|b| *b == b'.').next()?).ok()?;
    let rest = s.split("-frame-").nth(1)?;
    rest.split('-').next()?.parse().ok()
}

/// **45.3 — the server matrix's capped-uplink cell, in process.** `n`
/// members in a full mesh, every one publishing (600 B frames, or the leg's
/// budget, at 30 Hz) with relay on. After a settled baseline m0's WHOLE
/// uplink ([`NetemUplink`]: one FIFO for everything it sends, 1000 packets,
/// tail drop) is capped for `cap_s` seconds, then lifted.
///
/// **The kbit/s here are NOT the server's.** This harness's links are
/// loopback TCP with a link MDU of 431 B, so a frame is the leg's budget
/// (246 B), not 600 B in one datagram. One copy is MEASURED in the
/// baseline's last 5 s (a media packet is ~532 B on the wire with netem's
/// 28 B, so ~127 kbit/s against ~190 on the server), and the cap is the
/// server's 300 kbit/s scaled by that ratio (~200 kbit/s), so the same
/// number of copies fit (1.58). The FIFO limit is scaled the same way
/// (~666 packets), so a full queue is the server's seconds. [`NetemUplink`]
/// cuts the TCP stream at its frame ends and tail-drops whole frames, as
/// netem drops whole datagrams on the server's UDP links. The server's
/// replication load, which this harness lacks, is added as identity-link
/// bulk ([`W_BULK_KBIT_SERVER`]).
///
/// Known gap: no punched (UDP) interfaces in this harness, so an interface
/// lost behind the queue (and its links with it) cannot show here.
///
/// Recorded per second and printed: each listener's fraction of m0's frames
/// heard (by the second m0 SENT them), the shaper's counters, every listener's
/// parent for m0's stream when it changes, each node's link teardowns by
/// reason (run with `RUST_LOG=ciris_edge::link_close=debug` for each close's
/// plane and peer), and m0's `av_plane` deltas per phase.
#[allow(
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::type_complexity
)]
async fn whole_uplink_cap(tag: &str, n: usize, cap_s: u64, bulk_kbit_server: u64) -> UplinkCapRun {
    const SERVER_CAP_KBIT: u64 = 300;
    const SERVER_COPY_KBIT: u64 = 190;
    const BASELINE: Duration = Duration::from_secs(15);
    const AFTER_LIFT: Duration = Duration::from_secs(20);
    let uplink = NetemUplink::new();
    let mut dials = Vec::new();
    for i in 0..n {
        for j in (i + 1)..n {
            // (i, j): node j dials node i, so m0 dials nobody.
            dials.push((i, j));
        }
    }
    let (nodes, groups, _tmp) = topo_shaped(
        tag,
        n,
        n,
        &dials,
        None,
        Some((0, Shaper::Netem(Arc::clone(&uplink)))),
    )
    .await;
    // Every member publishes VIDEO (framed, single-layer base) with a codec
    // map, as a camera does: video and audio are told apart by the codec (a
    // stream of codec-opaque frames reads as audio).
    let camera = || CallOptions {
        relay: true,
        codecs: Some(
            ciris_edge::transport::av_chunk_auth::CodecMap::new([
                ciris_edge::transport::av_chunk_auth::CodecToken::Opus,
                ciris_edge::transport::av_chunk_auth::CodecToken::H264,
            ])
            .expect("map"),
        ),
        ..CallOptions::default()
    };
    let mut calls = Vec::new();
    for (i, g) in groups.iter().enumerate() {
        calls.push(join_loaded(&nodes[i], g, tag, camera(), None).await);
    }
    for c in &calls {
        wait_legs(c, n - 1).await;
        // The bench's no-drain baseline, on demand.
        c.set_drain_off_for_test(std::env::var_os("W_NO_DRAIN").is_some());
    }
    // Both bindings from every member (v2 carries the framing).
    for c in &calls {
        wait_bound(c, 2 * (n as u64 - 1)).await;
    }
    let m0 = nodes[0].key.key_id.clone();
    let m0_stream = calls[0].stream();
    // One fragment a frame: the budget less the framing marker.
    let frame = calls[0].chunk_plaintext_budget().unwrap_or(240).min(600) - 8;
    // m0's own host reads its frames, as a real host does.
    let m0_drain = {
        let mut rx = calls[0].frames().expect("m0's frames");
        tokio::spawn(async move { while rx.recv().await.is_some() {} })
    };
    // Every listener's arrivals of m0's frames: (seq, when).
    let arrivals: Vec<Arc<std::sync::Mutex<Vec<(u64, tokio::time::Instant)>>>> =
        (1..n).map(|_| Arc::default()).collect();
    let audio_arrivals: Vec<Arc<std::sync::Mutex<Vec<(u64, tokio::time::Instant)>>>> =
        (1..n).map(|_| Arc::default()).collect();
    // Every listener's m0 keyframes heard (by seq): the decoder model.
    let keyframes_heard: Vec<Arc<std::sync::Mutex<std::collections::BTreeSet<u64>>>> =
        (1..n).map(|_| Arc::default()).collect();
    let mut recorders = Vec::new();
    for (k, c) in calls.iter_mut().enumerate().skip(1) {
        let mut rx = c.frames().expect("frames");
        let log = Arc::clone(&arrivals[k - 1]);
        let alog = Arc::clone(&audio_arrivals[k - 1]);
        let klog = Arc::clone(&keyframes_heard[k - 1]);
        let from = m0.clone();
        recorders.push(tokio::spawn(async move {
            while let Some(f) = rx.recv().await {
                if f.publisher == from {
                    if let Some(s) = seq_of(&f.bytes) {
                        let audio = f.codec_id == ciris_edge::transport::realtime_av::CODEC_OPAQUE;
                        if !audio && f.bytes.starts_with(b"k-") {
                            klog.lock().expect("keyframes").insert(s);
                        }
                        let to = if audio { &alog } else { &log };
                        to.lock()
                            .expect("arrivals")
                            .push((s, tokio::time::Instant::now()));
                    }
                }
            }
        }));
    }
    // The publishers: every member, 30 Hz; m0's send instants by seq. Every
    // 250 ms the listeners' parents for m0's stream are read.
    let sent_at: Arc<std::sync::Mutex<Vec<tokio::time::Instant>>> = Arc::default();
    let audio_sent_at: Arc<std::sync::Mutex<Vec<tokio::time::Instant>>> = Arc::default();
    // m0's own view each second: (t, legs, direct children, relayed-to, tier).
    let m0_view: Arc<std::sync::Mutex<Vec<(u64, usize, usize, usize, String)>>> = Arc::default();
    let parents_log: Arc<std::sync::Mutex<Vec<(Duration, usize, Option<String>)>>> = Arc::default();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let t0 = tokio::time::Instant::now();
    // 45.3 — m0's host honours CallEvent::KeyframeWanted: its next video
    // frame is a keyframe (W_KEYFRAME_IGNORE: it does not, and only the GOP
    // brings one).
    let keyframe_due = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let keyframe_events = Arc::new(AtomicU64::new(0));
    let honour_keyframes = std::env::var_os("W_KEYFRAME_IGNORE").is_none();
    let m0_events = {
        let mut ev = calls[0].events().expect("m0's events");
        let (due, count) = (Arc::clone(&keyframe_due), Arc::clone(&keyframe_events));
        tokio::spawn(async move {
            while let Some(e) = ev.recv().await {
                if matches!(
                    e,
                    ciris_edge::transport::av_call::CallEvent::KeyframeWanted { .. }
                ) {
                    count.fetch_add(1, Ordering::SeqCst);
                    if honour_keyframes {
                        due.store(true, Ordering::SeqCst);
                    }
                }
            }
        })
    };
    let publisher = {
        let keyframe_due = Arc::clone(&keyframe_due);
        let sent_at = Arc::clone(&sent_at);
        let audio_sent_at = Arc::clone(&audio_sent_at);
        let parents_log = Arc::clone(&parents_log);
        let m0_view = Arc::clone(&m0_view);
        let stop = Arc::clone(&stop);
        let names: Vec<String> = nodes.iter().map(|x| x.key.key_id.clone()).collect();
        tokio::spawn(async move {
            let mut seq = 0u64;
            let mut aseq = 0u64;
            let mut long_audio = false;
            let mut long_audio_packets = 0u64;
            let mut last: Vec<Option<String>> = vec![None; calls.len()];
            let mut next_video = tokio::time::Instant::now();
            let mut audio_due = next_video;
            while !stop.load(Ordering::SeqCst) {
                // m0's audio between the video ticks: one Opus packet every
                // AUDIO_EVERY, as a host packetizes it.
                if audio_due < next_video {
                    tokio::time::sleep_until(audio_due).await;
                    // The host's congested-mode packetization: 60 ms Opus
                    // packets (one ~180 B chunk) while the node's media
                    // budget is under what 20 ms audio costs, 20 ms again
                    // once it is well over (CC rc23: one codec packet, one
                    // chunk, any frame length that fits).
                    let budget = calls[0].media_budget_bps();
                    if budget.is_some_and(|b| b < AUDIO_20MS_WIRE_BPS * 1.2) {
                        long_audio = true;
                    } else if budget.is_none_or(|b| b > AUDIO_20MS_WIRE_BPS * 2.0) {
                        long_audio = false;
                    }
                    let (bytes, every) = if long_audio {
                        (AUDIO_BYTES * 3, AUDIO_EVERY * 3)
                    } else {
                        (AUDIO_BYTES, AUDIO_EVERY)
                    };
                    let mut a = body("a", aseq);
                    a.resize(bytes, b'.');
                    audio_sent_at
                        .lock()
                        .expect("audio sent")
                        .push(tokio::time::Instant::now());
                    let _ = calls[0].publish(Frame::opaque(a)).await;
                    aseq += 1;
                    audio_due += every;
                    if long_audio {
                        long_audio_packets += 1;
                    }
                    continue;
                }
                tokio::time::sleep_until(next_video).await;
                next_video += FRAME_INTERVAL;
                // m0's keyframes: one a GOP, and the next frame after a
                // KeyframeWanted the host honours; two fragments each.
                let key = seq.is_multiple_of(KEYFRAME_EVERY)
                    || keyframe_due.swap(false, Ordering::SeqCst);
                for (i, c) in calls.iter_mut().enumerate() {
                    let m0_key = i == 0 && key;
                    let mut b = body(
                        if m0_key {
                            "k"
                        } else if i == 0 {
                            "w"
                        } else {
                            "o"
                        },
                        seq,
                    );
                    // One fragment, then two: 1.5 packets a frame.
                    b.resize(
                        if seq.is_multiple_of(2) && !m0_key {
                            frame
                        } else {
                            2 * frame - 16
                        },
                        b'.',
                    );
                    let b = Frame {
                        codec_id: ciris_edge::transport::realtime_av::CODEC_TEMPORAL_LAYERED,
                        layer: ChunkLayer::BASE,
                        bytes: b,
                    };
                    if i == 0 {
                        sent_at
                            .lock()
                            .expect("sent")
                            .push(tokio::time::Instant::now());
                    }
                    let _ = c.publish(b).await;
                }
                if seq.is_multiple_of(30) {
                    let c = &calls[0];
                    m0_view.lock().expect("view").push((
                        t0.elapsed().as_secs(),
                        c.legs().len(),
                        c.alm_own_children().len(),
                        c.relayed_to().len(),
                        format!(
                            "{:?} drain {:?} budget {:?}",
                            c.service_tier(),
                            c.uplink_drain(),
                            c.media_budget_bps().map(f64::round)
                        ),
                    ));
                }
                if seq.is_multiple_of(8) {
                    for (k, c) in calls.iter().enumerate().skip(1) {
                        let p = primary_for(c, m0_stream);
                        if p != last[k] {
                            let role = p.as_ref().and_then(|p| names.iter().position(|x| x == p));
                            parents_log.lock().expect("parents").push((
                                t0.elapsed(),
                                k,
                                role.map(|r| format!("m{r}")),
                            ));
                            last[k].clone_from(&p);
                        }
                    }
                }
                seq += 1;
            }
            eprintln!("[W] m0 sent {long_audio_packets} audio packets at 60 ms of {aseq}");
            calls
        })
    };
    // Per-second samples: the shaper, every node's teardowns by reason.
    let reasons = ["channel_exhausted", "timeout", "stale"];
    let sampler = {
        let up = Arc::clone(&uplink);
        let ms: Vec<EdgeMetrics> = nodes.iter().map(|x| x.metrics.clone()).collect();
        let stop = Arc::clone(&stop);
        let t = Arc::clone(&nodes[0].transport);
        let names: Vec<String> = nodes.iter().map(|x| x.key.key_id.clone()).collect();
        tokio::spawn(async move {
            let mut rows: Vec<UplinkSecond> = Vec::new();
            let mut labels: std::collections::HashMap<[u8; 16], String> =
                std::collections::HashMap::new();
            let mut s = 0u64;
            while !stop.load(Ordering::SeqCst) {
                tokio::time::sleep_until(t0 + Duration::from_secs(s + 1)).await;
                s += 1;
                let torn = ms
                    .iter()
                    .map(|m| reasons.iter().map(|r| closed_by(m, r)).collect())
                    .collect();
                // m0's links by plane, the A/V ones it dialled by member.
                let role = |k: &str| {
                    names
                        .iter()
                        .position(|x| x == k)
                        .map_or_else(|| k.to_owned(), |i| format!("m{i}"))
                };
                for (link, plane, dialled) in t.link_planes_for_test().await {
                    labels.entry(link).or_insert_with(|| {
                        format!("{}{}", plane.as_str(), if dialled { ">" } else { "<" })
                    });
                }
                let mut rtt = Vec::new();
                for d in t.av_links_for_test() {
                    if d.dialled {
                        labels.insert(d.link, format!("av>{}", role(&d.peer)));
                        if let Some(st) = t.av_link_stats(&d.link) {
                            rtt.push((
                                role(&d.peer),
                                st.srtt_ms,
                                st.learned_srtt_ms,
                                st.min_rtt_ms,
                                st.tx_ring,
                            ));
                        }
                    }
                }
                rtt.sort_by(|a, b| a.0.cmp(&b.0));
                let plane = ms[0].av_plane();
                let get = |k: &str| plane.get(k).copied().unwrap_or(0);
                rows.push(UplinkSecond {
                    s,
                    shaper: up.read(),
                    torn,
                    classes: up.take_classes(),
                    congested: get("av_send_congested"),
                    c3_failed: get("alm_c3_send_failed"),
                    c3_received: get("alm_c3_received"),
                    c3_sent: ms
                        .iter()
                        .map(|m| m.av_plane().get("alm_c3_sent").copied().unwrap_or(0))
                        .collect(),
                    rtt,
                });
            }
            (rows, labels)
        })
    };
    // The cap from what one copy MEASURES on the wire in the baseline's last
    // 5 s: the mean media packet (+ netem's 28 B) at the stream's 30 Hz. The
    // server's cell is 300 kbit/s for a ~190 kbit/s copy; the same ratio here.
    tokio::time::sleep(BASELINE.saturating_sub(Duration::from_secs(5))).await;
    let (p1, b1) = uplink.media_totals();
    tokio::time::sleep(Duration::from_secs(5)).await;
    let (p2, b2) = uplink.media_totals();
    let per_packet = (b2 - b1) / (p2 - p1).max(1) + NETEM_OVERHEAD_BYTES;
    let probe_uncapped = first_probe(&nodes[0], &nodes[1], &uplink, 0, "uncapped").await;
    // A copy: 1.5 video packets a frame at 30 Hz (frames alternate one and
    // two fragments, so a copy is ~190 kbit/s, the server's codec's).
    let copy_kbit = per_packet * 45 * 8 / 1000;
    let _ = SERVER_COPY_KBIT;
    // The server's cell as it is: 300 kbit/s, 1000 packets. Audio and
    // control cost what they cost per packet whatever the cap, so the cap is
    // NOT scaled (scaled, one audio copy was 71 % of it, against 47 % on the
    // server).
    let cap_kbit = SERVER_CAP_KBIT;
    let limit = NETEM_LIMIT_PACKETS as u64;
    uplink.set_limit(limit);
    // (b) The server's non-media that this harness lacks (replication rounds
    // and replies on the identity links): `bulk_kbit_server` of the server's
    // 300 kbit/s, scaled to this cap, sent from m0 to every member on its
    // identity link in 2 KB envelopes (Resources) on a fixed clock, one at
    // a time per member as edge's replication rounds are. From the cap on.
    let bulk_kbit = bulk_kbit_server * cap_kbit / SERVER_CAP_KBIT;
    let mut bulk = Vec::new();
    if bulk_kbit > 0 {
        const BULK_BYTES: usize = 2048;
        // One transfer at a time per member: edge's replication runs one
        // round per peer at once.
        const BULK_IN_FLIGHT: u64 = 1;
        let per_peer_bps = bulk_kbit * 1000 / (n as u64 - 1);
        let every = Duration::from_micros(BULK_BYTES as u64 * 8 * 1_000_000 / per_peer_bps.max(1));
        for peer in nodes.iter().skip(1) {
            let t = Arc::clone(&nodes[0].transport);
            let to = peer.key.key_id.clone();
            let stop = Arc::clone(&stop);
            bulk.push(tokio::spawn(async move {
                let blob: Arc<[u8]> = Arc::from(vec![0x42u8; BULK_BYTES]);
                let in_flight = Arc::new(AtomicU64::new(0));
                let mut tick = tokio::time::interval(every);
                while !stop.load(Ordering::SeqCst) {
                    tick.tick().await;
                    if in_flight.load(Ordering::SeqCst) >= BULK_IN_FLIGHT {
                        continue;
                    }
                    in_flight.fetch_add(1, Ordering::SeqCst);
                    let (t, to, blob, f) = (
                        Arc::clone(&t),
                        to.clone(),
                        Arc::clone(&blob),
                        Arc::clone(&in_flight),
                    );
                    tokio::spawn(async move {
                        // Bulk replication rows (chat, scores): edge classes
                        // them BULK from their row family; this stand-in says
                        // so itself (an unclassed send is FIRST).
                        let _ = ciris_edge::transport::egress_budget::sending_as(
                            ciris_edge::transport::egress_budget::SendClass::Bulk,
                            t.send(&to, &blob),
                        )
                        .await;
                        f.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            }));
        }
    }
    eprintln!(
        "[W] measured copy {copy_kbit} kbit/s ({per_packet} B a media packet on the wire); cap {cap_kbit} kbit/s; limit {limit} packets; bulk {bulk_kbit} kbit/s"
    );
    let plane_base = nodes[0].metrics.av_plane();
    let torn_before: u64 = nodes.iter().map(|x| torn_down(&x.metrics)).sum();
    // The uncapped control: every phase as it is, with no cap.
    let no_cap = std::env::var_os("W_NO_CAP").is_some();
    if !no_cap {
        uplink.cap_kbit(cap_kbit);
    }
    let cap_on = t0.elapsed();
    tracing::info!(
        target: "ciris_edge::link_close",
        names = ?nodes.iter().enumerate().map(|(i, x)| (format!("m{i}"), x.key.key_id.clone())).collect::<Vec<_>>(),
        cap_kbit,
        "W cap on"
    );
    // Mid-cap, once m0's budget is in force and holding video: the probe.
    let cap_end = tokio::time::Instant::now() + Duration::from_secs(cap_s);
    tokio::time::sleep(Duration::from_secs(cap_s / 2)).await;
    let mut probe_capped = FirstProbe::default();
    let held_at = av(&nodes[0].metrics, "av_frame_held_budget");
    while tokio::time::Instant::now() + Duration::from_secs(10) < cap_end {
        tokio::time::sleep(Duration::from_millis(250)).await;
        if !no_cap
            && nodes[0].transport.egress_budget().rate_bps().is_some()
            && av(&nodes[0].metrics, "av_frame_held_budget") > held_at
        {
            probe_capped = first_probe(&nodes[0], &nodes[1], &uplink, cap_kbit, "capped").await;
            break;
        }
    }
    tokio::time::sleep_until(cap_end).await;
    let torn_under_cap: u64 =
        nodes.iter().map(|x| torn_down(&x.metrics)).sum::<u64>() - torn_before;
    let plane_cap = nodes[0].metrics.av_plane();
    uplink.cap_kbit(0);
    let cap_off = t0.elapsed();
    tracing::info!(target: "ciris_edge::link_close", "W cap off");
    tokio::time::sleep(AFTER_LIFT).await;
    stop.store(true, Ordering::SeqCst);
    let calls = publisher.await.expect("publisher");
    m0_events.abort();
    let (rows, labels) = sampler.await.expect("sampler");
    for b in &bulk {
        b.abort();
    }
    m0_drain.abort();
    tokio::time::sleep(Duration::from_secs(2)).await;
    for r in &recorders {
        r.abort();
    }
    let plane_end = nodes[0].metrics.av_plane();
    // Per listener, per second m0 sent in: the fraction heard.
    let sent = sent_at.lock().expect("sent").clone();
    let sec_of = |i: usize| sent[i].duration_since(t0).as_secs();
    let last_sec = sent.last().map_or(0, |t| t.duration_since(t0).as_secs());
    let mut per_sec_sent = vec![0u64; last_sec as usize + 1];
    for i in 0..sent.len() {
        per_sec_sent[sec_of(i) as usize] += 1;
    }
    let in_window = |i: usize, from: Duration, to: Duration| {
        let t = sent[i].duration_since(t0);
        t >= from && t < to
    };
    let frac = |got: &std::collections::BTreeSet<u64>, from: Duration, to: Duration| {
        let want: Vec<usize> = (0..sent.len())
            .filter(|i| in_window(*i, from, to))
            .collect();
        if want.is_empty() {
            return 1.0;
        }
        want.iter().filter(|i| got.contains(&(**i as u64))).count() as f64 / want.len() as f64
    };
    let mut capped = Vec::new();
    let mut first_10s = Vec::new();
    let mut capped_fresh = Vec::new();
    let mut lifted = Vec::new();
    let mut longest_gap = Vec::new();
    let mut table = String::from("[W] heard fraction of m0's frames by send second (cap on at ");
    let _ = write!(table, "{cap_on:?}, off at {cap_off:?}; cap {cap_kbit} kbit/s for the server's {SERVER_CAP_KBIT}, copy {copy_kbit} kbit/s here)\n[W] s   ");
    for k in 1..n {
        let _ = write!(table, " m{k}  ");
    }
    table.push('\n');
    let mut per_listener_secs: Vec<Vec<u64>> = Vec::new();
    for a in &arrivals {
        let a = a.lock().expect("arrivals").clone();
        let got: std::collections::BTreeSet<u64> = a.iter().map(|(s, _)| *s).collect();
        capped.push(frac(&got, cap_on, cap_off));
        first_10s.push(frac(&got, cap_on, cap_on + Duration::from_secs(10)));
        {
            let mut fresh: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
            for (seq, t) in &a {
                if let Some(at) = usize::try_from(*seq).ok().and_then(|i| sent.get(i)) {
                    if t.saturating_duration_since(*at) <= MEDIA_FRESH {
                        fresh.insert(*seq);
                    }
                }
            }
            capped_fresh.push(frac(&fresh, cap_on + Duration::from_secs(10), cap_off));
        }
        lifted.push(frac(
            &got,
            cap_off + Duration::from_secs(2),
            cap_off + AFTER_LIFT.saturating_sub(Duration::from_secs(1)),
        ));
        let mut times: Vec<tokio::time::Instant> = a
            .iter()
            .map(|(_, t)| *t)
            .filter(|t| {
                let d = t.duration_since(t0);
                d >= cap_on && d < cap_off
            })
            .collect();
        times.sort();
        let mut gap = Duration::ZERO;
        let mut prev = t0 + cap_on;
        for t in times {
            gap = gap.max(t.duration_since(prev));
            prev = t;
        }
        gap = gap.max((t0 + cap_off).saturating_duration_since(prev));
        longest_gap.push(gap);
        let mut secs = vec![0u64; per_sec_sent.len()];
        for s in &got {
            if let Some(i) = usize::try_from(*s).ok().filter(|i| *i < sent.len()) {
                secs[sec_of(i) as usize] += 1;
            }
        }
        per_listener_secs.push(secs);
    }
    // Delivery latency: when the test took each frame out, minus when m0
    // published it; per 10 s of send time, per listener. A frame never heard
    // counts against every "within" column.
    let mut lat_table = String::from(
        "[W] latency by 10 s of m0's send time: listener window heard <=800ms <=1s <=2s p50 p95 max\n",
    );
    let windows = (last_sec / 10 + 1) as usize;
    for (k, a) in arrivals.iter().enumerate() {
        let a = a.lock().expect("arrivals").clone();
        let mut first: std::collections::BTreeMap<u64, tokio::time::Instant> =
            std::collections::BTreeMap::new();
        for (s, t) in &a {
            first.entry(*s).or_insert(*t);
        }
        for w in 0..windows {
            let from = Duration::from_secs(w as u64 * 10);
            let to = from + Duration::from_secs(10);
            let idx: Vec<usize> = (0..sent.len())
                .filter(|i| in_window(*i, from, to))
                .collect();
            if idx.is_empty() {
                continue;
            }
            let mut lats: Vec<Duration> = idx
                .iter()
                .filter_map(|i| {
                    first
                        .get(&(*i as u64))
                        .map(|t| t.saturating_duration_since(sent[*i]))
                })
                .collect();
            lats.sort();
            let total = idx.len() as f64;
            let within = |b: Duration| lats.iter().filter(|l| **l <= b).count() as f64 / total;
            let q = |p: usize| {
                lats.get((lats.len() * p / 100).min(lats.len().saturating_sub(1)))
                    .copied()
                    .unwrap_or_default()
            };
            let _ = writeln!(
                lat_table,
                "[W] m{} {:3}-{:3}s heard {:.3} {:.3} {:.3} {:.3} p50 {:?} p95 {:?} max {:?}",
                k + 1,
                w * 10,
                w * 10 + 10,
                lats.len() as f64 / total,
                within(Duration::from_millis(800)),
                within(Duration::from_secs(1)),
                within(Duration::from_secs(2)),
                q(50),
                q(95),
                lats.last().copied().unwrap_or_default(),
            );
        }
    }
    eprint!("{lat_table}");
    // 45.3 — the split bars. Audio: every m0 audio packet sent from 2 s into
    // the cap to its end, heard within 800 ms, and the longest audio gap.
    // Video: of the frames DELIVERED (sent over the same span), the share
    // within 800 ms, the longest video gap, and the video delivered against
    // what the cap leaves after non-media.
    let settle_from = cap_on + Duration::from_secs(2);
    let asent = audio_sent_at.lock().expect("audio sent").clone();
    let mut audio_fresh = Vec::new();
    let mut audio_gap = Vec::new();
    let mut video_fresh_of_delivered = Vec::new();
    let mut video_gap = Vec::new();
    let mut video_decoded_gap: Vec<Duration> = Vec::new();
    let mut resume_waits: Vec<Duration> = Vec::new();
    let mut video_fps = Vec::new();
    let gap_over = |times: &mut Vec<tokio::time::Instant>| {
        times.sort();
        let mut gap = Duration::ZERO;
        let mut prev = t0 + settle_from;
        for t in times.iter() {
            gap = gap.max(t.saturating_duration_since(prev));
            prev = *t;
        }
        gap.max((t0 + cap_off).saturating_duration_since(prev))
    };
    for (va, aa) in arrivals.iter().zip(&audio_arrivals) {
        let aa = aa.lock().expect("audio").clone();
        let want: Vec<usize> = (0..asent.len())
            .filter(|i| {
                let t = asent[*i].duration_since(t0);
                t >= settle_from && t < cap_off
            })
            .collect();
        let mut first: std::collections::BTreeMap<u64, tokio::time::Instant> =
            std::collections::BTreeMap::new();
        for (s, t) in &aa {
            first.entry(*s).or_insert(*t);
        }
        let fresh = want
            .iter()
            .filter(|i| {
                first
                    .get(&(**i as u64))
                    .is_some_and(|t| t.saturating_duration_since(asent[**i]) <= MEDIA_FRESH)
            })
            .count();
        audio_fresh.push(fresh as f64 / want.len().max(1) as f64);
        let mut at: Vec<tokio::time::Instant> = first
            .values()
            .copied()
            .filter(|t| {
                let d = t.duration_since(t0);
                d >= settle_from && d < cap_off
            })
            .collect();
        audio_gap.push(gap_over(&mut at));
        let va = va.lock().expect("video").clone();
        let mut vfirst: std::collections::BTreeMap<u64, tokio::time::Instant> =
            std::collections::BTreeMap::new();
        for (s, t) in &va {
            vfirst.entry(*s).or_insert(*t);
        }
        let delivered: Vec<(usize, tokio::time::Instant)> = vfirst
            .iter()
            .filter_map(|(s, t)| usize::try_from(*s).ok().map(|i| (i, *t)))
            .filter(|(i, _)| {
                sent.get(*i).is_some_and(|st| {
                    let d = st.duration_since(t0);
                    d >= settle_from && d < cap_off
                })
            })
            .collect();
        let in_time = delivered
            .iter()
            .filter(|(i, t)| t.saturating_duration_since(sent[*i]) <= MEDIA_FRESH)
            .count();
        video_fresh_of_delivered.push(if delivered.is_empty() {
            0.0
        } else {
            in_time as f64 / delivered.len() as f64
        });
        let span = cap_off.saturating_sub(settle_from).as_secs_f64().max(1.0);
        video_fps.push(delivered.len() as f64 / span);
        let mut vt: Vec<tokio::time::Instant> = delivered.iter().map(|(_, t)| *t).collect();
        video_gap.push(gap_over(&mut vt));
        // The decoder model: a frame decodes if it is a keyframe or the next
        // frame after the last one decoded (each frame refers to the one
        // before); a gap leaves video frozen until the next keyframe.
        let keys = keyframes_heard[video_decoded_gap.len()]
            .lock()
            .expect("keyframes")
            .clone();
        let mut by_arrival: Vec<(tokio::time::Instant, u64)> =
            vfirst.iter().map(|(s, t)| (*t, *s)).collect();
        by_arrival.sort();
        let mut last: Option<u64> = None;
        let mut decoded: Vec<tokio::time::Instant> = Vec::new();
        // Each resume: delivery back after a gap over 200 ms, until the
        // first decodable frame (the picture stays frozen meanwhile).
        let mut prev_arrival: Option<tokio::time::Instant> = None;
        let mut resumed_at: Option<tokio::time::Instant> = None;
        for (t, s) in by_arrival {
            let d = t.duration_since(t0);
            let in_cap = d >= settle_from && d < cap_off;
            if in_cap
                && prev_arrival
                    .is_some_and(|p| t.saturating_duration_since(p) > Duration::from_millis(200))
                && resumed_at.is_none()
            {
                resumed_at = Some(t);
            }
            prev_arrival = Some(t);
            if keys.contains(&s) || last.is_some_and(|l| s == l + 1) {
                last = Some(s);
                if let Some(r) = resumed_at.take() {
                    resume_waits.push(t.saturating_duration_since(r));
                }
                if in_cap {
                    decoded.push(t);
                }
            }
        }
        video_decoded_gap.push(gap_over(&mut decoded));
    }
    // What the cap leaves after non-media, over the cap after the settle.
    let mut nonmedia_bytes = 0u64;
    let mut audio_bytes = 0u64;
    let mut audio_pkts = 0u64;
    let mut video_bytes = 0u64;
    let mut secs = 0u64;
    for r in rows.iter().filter(|r| {
        let d = Duration::from_secs(r.s);
        d > settle_from && d <= cap_off
    }) {
        secs += 1;
        for ((class, _), c) in &r.classes {
            let wire = c.bytes + c.packets * NETEM_OVERHEAD_BYTES;
            match *class {
                "media_audio" => {
                    audio_bytes += wire;
                    audio_pkts += c.packets;
                }
                "media_datagram" => video_bytes += wire,
                _ => nonmedia_bytes += wire,
            }
        }
    }
    let per_s = |b: u64| b as f64 * 8.0 / 1000.0 / secs.max(1) as f64;
    let ((short_bytes, short_pkts), (long_bytes, long_pkts)) = uplink.audio_totals();
    let audio_pkt = short_bytes as f64 / short_pkts.max(1) as f64;
    let long_pkt = long_bytes as f64 / long_pkts.max(1) as f64;
    eprintln!(
        "[W] audio: within 800 ms after a 2 s settle {audio_fresh:.3?}; longest audio gap {audio_gap:?}; one audio copy on the wire: 20 ms {audio_pkt:.0} B a packet = {:.1} kbit/s ({short_pkts} packets), 60 ms {long_pkt:.0} B = {:.1} kbit/s ({long_pkts} packets)",
        audio_pkt * 8.0 * 50.0 / 1000.0,
        long_pkt * 8.0 * (50.0 / 3.0) / 1000.0,
    );
    eprintln!(
        "[W] video: delivered within 800 ms {video_fresh_of_delivered:.3?}; longest video gap after the settle {video_gap:?}; delivered {video_fps:.1?} frames/s of 30"
    );
    eprintln!(
        "[W] m0's uplink over the cap after the settle: non-media {:.1} kbit/s, audio {:.1} kbit/s ({:.1} pkt/s), video {:.1} kbit/s; the cap leaves {:.1} kbit/s after non-media",
        per_s(nonmedia_bytes),
        per_s(audio_bytes),
        audio_pkts as f64 / secs.max(1) as f64,
        per_s(video_bytes),
        cap_kbit as f64 - per_s(nonmedia_bytes),
    );
    for (s, want) in per_sec_sent.iter().enumerate() {
        let _ = write!(table, "[W] {s:3} ");
        for l in &per_listener_secs {
            let _ = write!(table, " {:.2}", l[s] as f64 / (*want).max(1) as f64);
        }
        table.push('\n');
    }
    eprint!("{table}");
    let mut prev = NetemSecond::default();
    let mut prev_torn: Vec<Vec<u64>> = Vec::new();
    for UplinkSecond {
        s, shaper: c, torn, ..
    } in &rows
    {
        let torn_delta: Vec<Vec<u64>> = torn
            .iter()
            .enumerate()
            .map(|(i, v)| {
                v.iter()
                    .enumerate()
                    .map(|(j, x)| x - prev_torn.get(i).map_or(*x, |p| p[j]))
                    .collect()
            })
            .collect();
        let any_torn = torn_delta.iter().flatten().any(|x| *x > 0);
        // The backlog in seconds at the cap rate (what a packet queued now
        // waits: the shed notice's delay). Rows outside the cap read it at
        // the cap rate too.
        let cap_rate = cap_kbit * 1000 / 8;
        eprintln!(
            "[W] shaper s={s:3} enq {:4} drop {:4} sent {:4} pkts {:7} B backlog {:4} pkts {:7} B {:6.2} s{}",
            c.enqueued - prev.enqueued,
            c.dropped - prev.dropped,
            c.sent_packets - prev.sent_packets,
            c.sent_bytes - prev.sent_bytes,
            c.backlog_packets,
            c.backlog_bytes,
            (c.backlog_bytes + c.backlog_packets * NETEM_OVERHEAD_BYTES) as f64 / cap_rate.max(1) as f64,
            if any_torn {
                format!("  TORN (exhausted, timeout, stale) per node {torn_delta:?}")
            } else {
                String::new()
            }
        );
        prev = *c;
        prev_torn.clone_from(torn);
    }
    // What m0 handed its shaper each second, by class (bytes/s, packets/s,
    // dropped), media split per link; and m0's own view on the same axis.
    let view = m0_view.lock().expect("view").clone();
    let mut prev_cong = 0u64;
    let mut prev_fail = 0u64;
    let mut prev_recv = 0u64;
    let mut prev_sent: Vec<u64> = Vec::new();
    for r in &rows {
        let mut by_class: std::collections::BTreeMap<&str, ClassCount> =
            std::collections::BTreeMap::new();
        let mut media: Vec<(String, ClassCount)> = Vec::new();
        let mut by_plane: std::collections::BTreeMap<String, ClassCount> =
            std::collections::BTreeMap::new();
        for ((class, link), n) in &r.classes {
            let e = by_class.entry(class).or_default();
            e.packets += n.packets;
            e.bytes += n.bytes;
            e.dropped += n.dropped;
            let label = link.map_or_else(
                || "-".to_owned(),
                |l| {
                    labels
                        .get(&l)
                        .cloned()
                        .unwrap_or_else(|| format!("?{}", hex::encode(&l[..3])))
                },
            );
            let p = by_plane
                .entry(format!(
                    "{class}@{}",
                    label
                        .split('>')
                        .next()
                        .unwrap_or(&label)
                        .split('<')
                        .next()
                        .unwrap_or(&label)
                ))
                .or_default();
            p.packets += n.packets;
            p.bytes += n.bytes;
            if *class == "media_datagram" {
                media.push((label, *n));
            }
        }
        media.sort_by(|a, b| a.0.cmp(&b.0));
        let mut line = format!("[W] class s={:3}", r.s);
        let mut total = ClassCount::default();
        for (class, n) in &by_class {
            total.packets += n.packets;
            total.bytes += n.bytes;
            total.dropped += n.dropped;
            let _ = write!(line, " {class} {}B/{}p/{}d", n.bytes, n.packets, n.dropped);
        }
        let _ = write!(
            line,
            " | total {}B {}p {}d | media",
            total.bytes, total.packets, total.dropped
        );
        for (l, n) in &media {
            let _ = write!(line, " {l}:{}p", n.packets);
        }
        let _ = write!(line, " | by plane");
        for (k, n) in &by_plane {
            let _ = write!(line, " {k}:{}B", n.bytes);
        }
        if let Some(v) = view.iter().find(|v| v.0 == r.s) {
            let _ = write!(
                line,
                " | m0 legs {} children {} relayed_to {} tier {}",
                v.1, v.2, v.3, v.4
            );
        }
        let _ = write!(
            line,
            " | congested {} c3_failed {}",
            r.congested - prev_cong,
            r.c3_failed - prev_fail
        );
        prev_cong = r.congested;
        prev_fail = r.c3_failed;
        let _ = write!(line, " | c3 in {}", r.c3_received - prev_recv);
        let _ = write!(line, " | c3 sent by node");
        for (i, x) in r.c3_sent.iter().enumerate() {
            let _ = write!(
                line,
                " m{i}:{}",
                x - prev_sent.get(i).copied().unwrap_or(*x)
            );
        }
        prev_recv = r.c3_received;
        prev_sent.clone_from(&r.c3_sent);
        let _ = write!(line, " | m0 legs rtt");
        for (m, srtt, learned, min, ring) in &r.rtt {
            let _ = write!(
                line,
                " {m}:srtt {} learned {} min {} ring {ring}",
                srtt.map_or("-".to_owned(), |x| format!("{x:.0}")),
                learned.map_or("-".to_owned(), |x| format!("{x:.0}")),
                min.map_or("-".to_owned(), |x| x.to_string()),
            );
        }
        eprintln!("{line}");
    }
    for (t, k, p) in parents_log.lock().expect("parents").iter() {
        eprintln!(
            "[W] parent {t:?} m{k} -> {}",
            p.as_deref().unwrap_or("none")
        );
    }
    let delta = |a: &std::collections::HashMap<String, u64>,
                 b: &std::collections::HashMap<String, u64>| {
        let mut v: Vec<(String, u64)> = b
            .iter()
            .map(|(k, x)| (k.clone(), x - a.get(k).copied().unwrap_or(0)))
            .filter(|(_, x)| *x > 0)
            .collect();
        v.sort();
        v
    };
    eprintln!(
        "[W] m0 av_plane under the cap: {:?}",
        delta(&plane_base, &plane_cap)
    );
    eprintln!(
        "[W] m0 av_plane after the lift: {:?}",
        delta(&plane_cap, &plane_end)
    );
    eprintln!(
        "[W] capped {capped:.3?}; within 800 ms after a 10 s settle {capped_fresh:.3?}; first 10 s {first_10s:.3?}; lifted {lifted:.3?}; longest gap {longest_gap:?}; torn under the cap {torn_under_cap}"
    );
    drop(calls);
    eprintln!("[W] FIRST probe uncapped {probe_uncapped:?}; capped {probe_capped:?}");
    resume_waits.sort();
    let rq = |q: usize| {
        resume_waits
            .get((resume_waits.len() * q / 100).min(resume_waits.len().saturating_sub(1)))
            .copied()
    };
    eprintln!(
        "[W] keyframes: {} KeyframeWanted at m0, honoured {honour_keyframes}; {} resumes after a >200 ms gap, frozen until decodable p50 {:?} p95 {:?} max {:?}; longest decodable-video gap after the settle {video_decoded_gap:?}; longest delivered-video gap {video_gap:?}",
        keyframe_events.load(Ordering::SeqCst),
        resume_waits.len(),
        rq(50),
        rq(95),
        resume_waits.last()
    );
    UplinkCapRun {
        capped,
        first_10s,
        capped_fresh,
        lifted,
        longest_gap,
        torn_under_cap,
        cap_kbit,
        audio_fresh,
        audio_gap,
        video_fresh_of_delivered,
        video_gap,
        video_decoded_gap,
        keyframe_events: (keyframe_events.load(Ordering::SeqCst), honour_keyframes),
        probe_uncapped,
        probe_capped,
    }
}

/// **45.3 (CC review) — a room removal leaves at once while video is held.**
/// The faithful whole-uplink bench (4 members, m0 capped at 300 kbit/s for
/// 40 s, bulk on the identity links). Mid-cap, while m0's budget is in force
/// and holding video, m0 sends m1 a `membership:removal` Deliver and a
/// `chat:` Deliver of one size at one instant, each classed by edge's own
/// classifier. The removal is FIRST: edge never holds it, so all it waits on
/// is the uplink's own FIFO. A 1.2 kB envelope is a Resource and crosses the
/// capped uplink twice (its advertisement, then its parts after m1's
/// request), so it must arrive within twice the FIFO's time at the send,
/// plus the same envelope's uncapped delivery and [`FIRST_PROBE_SLACK`]; and
/// before the chat row, which is BULK and waits behind the
/// [`PROBE_FILLERS`] bulk envelopes queued ahead of both. Mutation: the
/// removal filed as bulk waits behind them too.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_room_removal_leaves_at_once_while_video_is_held() {
    use ciris_edge::transport::egress_budget::SendClass;
    let _call = one_call().await;
    let r = whole_uplink_cap("w4-first", 4, 40, W_BULK_KBIT_SERVER).await;
    let (u, c) = (&r.probe_uncapped, &r.probe_capped);
    eprintln!("[FIRST] uncapped {u:?}; capped {c:?}");
    assert_eq!(
        c.removal_class,
        Some(SendClass::First),
        "a removal is FIRST"
    );
    assert_eq!(c.chat_class, Some(SendClass::Bulk), "a chat row is BULK");
    assert!(
        c.budget_bps.is_some(),
        "the probe ran under a budget: {c:?}"
    );
    assert!(
        c.video_held.1 > c.video_held.0,
        "video was being held across the probe: {c:?}"
    );
    let base = u.removal.expect("the uncapped removal arrived");
    let got = c.removal.expect("the capped removal arrived");
    let bound = base + Duration::from_millis(2 * c.fifo_ms) + FIRST_PROBE_SLACK;
    assert!(
        got <= bound,
        "the removal took {got:?} under the cap, bound {bound:?} (uncapped {base:?} + 2 x FIFO {} ms + slack)",
        c.fifo_ms
    );
    let chat = c.chat.expect("the capped chat row arrived");
    assert!(
        got < chat,
        "the removal ({got:?}) left ahead of the bulk queued before it (the chat row: {chat:?})"
    );
}

/// The removal's allowance past its two FIFO crossings and its uncapped
/// delivery: the FIFO grows between the crossings (it is read once, at the
/// send) and the receiver's request rides m1's own uplink.
const FIRST_PROBE_SLACK: Duration = Duration::from_millis(500);

/// m0's GOP: a keyframe every this many video frames (2 s at 30 Hz).
const KEYFRAME_EVERY: u64 = 60;

/// 45.3 — m0's audio: one Opus packet per 20 ms, 60 B (24 kbit/s), as a
/// host packetizes it.
const AUDIO_EVERY: Duration = Duration::from_millis(20);
const AUDIO_BYTES: usize = 60;
/// A media datagram this short on m0's wire is audio (the shaper cannot read
/// the sealed codec): a 20 ms audio packet is ~327 B and a 60 ms one ~447 B
/// before IP/UDP, a video fragment ~500 B.
const AUDIO_PACKET_MAX: usize = 480;
/// What one 20 ms audio copy costs on the wire (bits/s, measured: 355 B a
/// packet with IP/UDP, 50 a second).
const AUDIO_20MS_WIRE_BPS: f64 = 142_000.0;

/// 45.3 — how late a frame may land and still count as heard in time (the
/// receiver's media budget, `av_call::MEDIA_STALE_BUDGET`).
const MEDIA_FRESH: Duration = Duration::from_millis(800);

/// (b) The replication/identity load m0 adds, in the server's kbit/s (scaled
/// to the cap): the server's 130-150 kbit/s of non-media less what the
/// harness's own control, proofs and announces already offer (~25-45 kbit/s
/// at this cap, i.e. ~40-65 of the server's).
const W_BULK_KBIT_SERVER: u64 = 90;

/// The server matrix's bars for a capped cell, plus 45.3's latency bar.
fn uplink_cap_bars(r: &UplinkCapRun) -> Vec<String> {
    let mut failed = Vec::new();
    for (k, f) in r.audio_fresh.iter().enumerate() {
        if *f < 0.95 {
            failed.push(format!(
                "m{}: audio {f:.3} within {MEDIA_FRESH:?} after a 2 s settle (bar 0.95)",
                k + 1
            ));
        }
    }
    for (k, g) in r.audio_gap.iter().enumerate() {
        if *g > Duration::from_secs(1) {
            failed.push(format!("m{}: audio gap {g:?} (bar 1 s)", k + 1));
        }
    }
    for (k, f) in r.video_fresh_of_delivered.iter().enumerate() {
        if *f < 0.95 {
            failed.push(format!(
                "m{}: {f:.3} of the video delivered within {MEDIA_FRESH:?} (bar 0.95)",
                k + 1
            ));
        }
    }
    for (k, g) in r.video_gap.iter().enumerate() {
        if *g > Duration::from_secs(2) {
            failed.push(format!("m{}: video gap {g:?} (target 2 s)", k + 1));
        }
    }
    if r.torn_under_cap != 0 {
        failed.push(format!(
            "{} links torn down under the cap (bar 0)",
            r.torn_under_cap
        ));
    }
    for (k, f) in r.lifted.iter().enumerate() {
        if *f < 0.99 {
            failed.push(format!("m{} heard {f:.3} after the lift (bar 0.99)", k + 1));
        }
    }
    failed
}

/// **45.3 W6** — six members, every one publishing, relay on; m0's whole
/// uplink capped at the server's 300 kbit/s (scaled, see
/// [`whole_uplink_cap`]) for 90 s, then lifted. The server's bars: each
/// listener hears ≥ 0.9 of m0 over the cap, no gap over 5 s, no link torn
/// down under the cap, ≥ 0.99 after the lift. RED on v45.2.1 as the server
/// sees it (N=6/300: 0.81, teardowns from ~+10 s, the first 10 s at
/// 0.12-0.14). A 2-minute run on a quiet box: `--ignored`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "45.3 witness, red until the whole-uplink fixes: a 2-minute capped run, on a quiet box"]
async fn six_members_hear_a_publisher_whose_whole_uplink_is_capped() {
    let _call = one_call().await;
    let r = whole_uplink_cap("w6-uplink", 6, 90, W_BULK_KBIT_SERVER).await;
    let failed = uplink_cap_bars(&r);
    assert!(
        failed.is_empty(),
        "W6 at {} kbit/s: {failed:?}; heard {:.3?} (within 800 ms {:.3?}, longest gap {:?}); first 10 s {:.3?}; decodable-video gap {:?}; KeyframeWanted (seen, honoured) {:?}",
        r.cap_kbit,
        r.capped,
        r.capped_fresh,
        r.longest_gap,
        r.first_10s,
        r.video_decoded_gap,
        r.keyframe_events
    );
}

/// **45.3 W4** — [`six_members_hear_a_publisher_whose_whole_uplink_is_capped`]
/// at four members: the control (the server's N=4/300 passes at 0.96), so a
/// red W6 is the six members, not the shaper.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "45.3 witness control: a 2-minute capped run, on a quiet box"]
async fn four_members_hear_a_publisher_whose_whole_uplink_is_capped() {
    let _call = one_call().await;
    let r = whole_uplink_cap("w4-uplink", 4, 90, W_BULK_KBIT_SERVER).await;
    let failed = uplink_cap_bars(&r);
    assert!(
        failed.is_empty(),
        "W4 at {} kbit/s: {failed:?}; heard {:.3?} (within 800 ms {:.3?}, longest gap {:?}); first 10 s {:.3?}; decodable-video gap {:?}; KeyframeWanted (seen, honoured) {:?}",
        r.cap_kbit,
        r.capped,
        r.capped_fresh,
        r.longest_gap,
        r.first_10s,
        r.video_decoded_gap,
        r.keyframe_events
    );
}

/// [`hdlc_packets`] cuts a leviculum TCP stream at its frame ends, keeps
/// every byte (the stream is byte-identical when nothing drops), and carries
/// a frame split across reads.
#[test]
fn the_netem_pipe_cuts_the_stream_at_hdlc_frames_and_keeps_every_byte() {
    let stream: Vec<u8> = [
        &[0x7E, 1, 2, 0x7D, 0x5E, 3, 0x7E][..],
        &[0x7E, 4, 0x7E][..],
        &[0x7E, 0x7E, 5, 6, 0x7E][..],
    ]
    .concat();
    let mut carry = Vec::new();
    let mut got = Vec::new();
    for piece in stream.chunks(4) {
        got.extend(hdlc_packets(&mut carry, piece));
    }
    assert!(carry.is_empty(), "nothing left over: {carry:?}");
    assert_eq!(
        got,
        vec![
            vec![0x7E, 1, 2, 0x7D, 0x5E, 3, 0x7E],
            vec![0x7E, 4, 0x7E],
            vec![0x7E, 0x7E, 5, 6, 0x7E],
        ]
    );
    assert_eq!(got.concat(), stream);
}

/// **45.3 model R25, a two-person call** — A's uplink capped at half of one
/// copy of its media: with one leg, the backlog is still read, so the drain
/// starts, STALE media is dropped at the sender and the egress budget comes
/// into force. Before, `uplink_backlog` needed two outstanding legs, read
/// `None` for ever in a two-person call, and none of the three engaged.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_two_person_call_under_a_capped_uplink_engages_stale_and_the_budget() {
    let _call = one_call().await;
    let tag = "alm2-cap2";
    let uplink = CappedUplink::new();
    let (nodes, groups, _tmp) =
        topo_capped(tag, 2, 2, &[(0, 1)], None, Some((0, Arc::clone(&uplink)))).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let mut ca = join_loaded(a, &groups[0], tag, CallOptions::default(), None).await;
    let cb = join_loaded(b, &groups[1], tag, CallOptions::default(), None).await;
    wait_legs(&ca, 1).await;
    wait_legs(&cb, 1).await;
    wait_bound(&cb, 1).await;
    let size = ca.chunk_plaintext_budget().unwrap_or(240).min(600);
    let copy_kbit = (u64::try_from(size).unwrap_or(600) + 170) * 8 * 30 / 1000;
    uplink.cap_kbit(copy_kbit / 2);
    let mut budget_seen = false;
    let end = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut seq = 0;
    while tokio::time::Instant::now() < end {
        let mut f = body("a", seq);
        f.resize(size, b'.');
        let _ = ca.publish(Frame::opaque(f)).await;
        budget_seen |= ca.media_budget_bps().is_some();
        seq += 1;
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    let (drained, stale) = (
        av(&a.metrics, "alm_drain_entered"),
        av(&a.metrics, "av_chunk_dropped_stale_at_sender"),
    );
    eprintln!(
        "[R25] two-person capped: copy {copy_kbit} kbit/s, sent {seq}, drain {drained}, \
         stale at sender {stale}, budget seen {budget_seen}"
    );
    assert!(drained >= 1, "the drain started on the one leg");
    assert!(stale > 0, "STALE media was dropped at the sender");
    assert!(budget_seen, "the egress budget came into force");
    drop(cb);
    drop(ca);
}
