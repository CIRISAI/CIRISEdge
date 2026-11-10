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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::mls::cohort_group::mint_cohort_key_material;
use ciris_edge::mls::{CohortGroup, ScopeStateProvider};
use ciris_edge::scope_addressing::{ScopeAddressTable, ScopePrivacyDeriver};
use ciris_edge::scope_lifecycle::{ScopeLifecycle, ScopedDestinationSink};
use ciris_edge::transport::av_call::{
    Call, CallDeps, CallEvent, CallOptions, Frame, ReceivedFrame, RoomRoster, REANNOUNCE_PART_GAP,
};
use ciris_edge::transport::av_chunk_auth::StreamKeyVerifier;
use ciris_edge::transport::av_keep::{AvKeepTarget, StreamDekRegistrar};
use ciris_edge::transport::realtime_av::{ChunkLayer, ReceiverLayerPolicy, CODEC_AV1_SVC};
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
    _edge: ciris_edge::Edge,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

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
    let tasks = vec![
        tokio::spawn(async move {
            let _ = listener.listen(tx).await;
        }),
        tokio::spawn(async move { while rx.recv().await.is_some() {} }),
    ];
    Node {
        key,
        port,
        dir,
        transport,
        metrics,
        lifecycle,
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
    init_tracing();
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
        let peers: Vec<u16> = dials
            .iter()
            .filter(|(_, j)| *j == i)
            .map(|(a, _)| nodes[*a].port)
            .collect();
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
    drop(cc);
    let ended = c.metrics.snapshot();
    assert_eq!(ended.alm_active_calls, 0, "a dropped call ends too");
    assert_eq!(ended.alm_c3_peers, 0, "and takes its members with it");
    assert_eq!(
        ended.call_setup_duration_seconds["ended"].count, 0,
        "its setup was already over"
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
    let (nodes, groups, _tmp) = topo(tag, 3, 3, &[(0, 1), (0, 2)], None).await;
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
    let lost = tokio::time::timeout(Duration::from_secs(60), async {
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
async fn a_share_beside_the_camera_is_heard_and_ends_alone() {
    use ciris_edge::transport::av_call::LeaveCause;
    use ciris_edge::transport::av_chunk_auth::{STREAM_KIND_MEDIA, STREAM_KIND_SHARE};
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
    let share = cb.add_stream(None).await.expect("B shares its screen");
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
        heard.get(&cam).map_or(0, |h| h.len()),
        heard.get(&share).map_or(0, |h| h.len())
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
    let before = heard.get(&cam).map_or(0, |h| h.len());
    for seq in 60..100u64 {
        cb.publish(Frame::opaque(body("cam", seq)))
            .await
            .expect("camera after the share");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let more = wait_until(Duration::from_secs(10), || {
        drain(&mut frames, &mut heard);
        let ok = heard.get(&cam).map_or(0, |h| h.len()) >= before + 30;
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
    let key = cb.publish(video(0, 30_000)).await.expect("keyframe");
    assert_eq!(
        usize::from(key.fragments),
        30_000usize.div_ceil(budget - 4),
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
    let mut got_video = Vec::new();
    let mut got_audio = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(20), async {
        while got_video.len() < sent_video.len() || got_audio.len() < sent_audio.len() {
            match frames.recv().await {
                Some(f) if f.publisher == b.key.key_id => match f.codec_id {
                    CODEC_OPAQUE => got_audio.push(f.bytes),
                    CODEC_TEMPORAL_LAYERED => got_video.push(f.bytes),
                    _ => {}
                },
                Some(_) => {}
                None => break,
            }
        }
    })
    .await;
    assert_eq!(got_video, sent_video, "every video frame whole, in order");
    assert_eq!(got_audio, sent_audio, "every audio frame as sent, unmarked");
    assert_eq!(av(&a.metrics, "av_frame_incomplete"), 0);

    // Loss: every 7th chunk to A withheld.
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
    assert_eq!(got, sent, "every frame whole through the relay");
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
    let (nodes, groups, _tmp) = topo(tag, 3, 3, &[(0, 1), (0, 2)], None).await;
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
