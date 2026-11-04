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
    Call, CallDeps, CallOptions, Frame, ReceivedFrame, RoomRoster,
};
use ciris_edge::transport::av_chunk_auth::StreamKeyVerifier;
use ciris_edge::transport::av_keep::{AvKeepTarget, StreamDekRegistrar};
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
            hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
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
            hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
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
        Duration::from_secs(300),
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
    let known = wait_until(Duration::from_secs(120), || async {
        for a in &nodes {
            for b in &nodes {
                if a.key.key_id != b.key.key_id && !a.transport.knows_peer(&b.key.key_id).await {
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

/// Collect frames from `rx` until `want` frames of `publisher` arrived.
async fn collect_from(
    rx: &mut mpsc::Receiver<ReceivedFrame>,
    seen: &mut Vec<ReceivedFrame>,
    publisher: &str,
    want: usize,
) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while seen.iter().filter(|f| f.publisher == publisher).count() < want {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(f)) => seen.push(f),
            _ => return false,
        }
    }
    true
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
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_member_unreachable_directly_is_heard_through_a_roster_relay() {
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

    // B's frames reach C byte-identical and in order, through A.
    let mut rx_c = cc.frames().expect("C's frames");
    let forwarded_before = ca.alm_counts().forwarded;
    for seq in 0..40 {
        cb.publish(Frame::opaque(body("b", seq)))
            .await
            .expect("B publishes");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let mut seen = Vec::new();
    let whole = collect_from(&mut rx_c, &mut seen, &b.key.key_id, 40).await;
    if !whole {
        let plane = |m: &EdgeMetrics| {
            let mut v: Vec<(String, u64)> = m
                .av_plane()
                .into_iter()
                .filter(|(k, _)| !k.starts_with("alm_c3"))
                .collect();
            v.sort();
            v
        };
        let heard: Vec<u64> = seen
            .iter()
            .filter(|f| f.publisher == b.key.key_id)
            .map(|f| f.chunk_seq.0)
            .collect();
        panic!(
            "C heard {} of B's 40 frames: {heard:?}; A forwarded {}; C reorder {:?}; C auth {:?}\n\
             plane B {:?}\nplane A {:?}\nplane C {:?}",
            heard.len(),
            ca.alm_counts().forwarded - forwarded_before,
            cc.reorder_counts(),
            cc.chunk_auth_counts(),
            plane(&b.metrics),
            plane(&a.metrics),
            plane(&c.metrics),
        );
    }
    let got: Vec<Vec<u8>> = seen
        .iter()
        .filter(|f| f.publisher == b.key.key_id)
        .map(|f| f.bytes.clone())
        .collect();
    let want: Vec<Vec<u8>> = (0..40).map(|s| body("b", s)).collect();
    assert_eq!(got, want, "byte-identical, in order");
    assert!(ca.alm_counts().forwarded - forwarded_before >= 40);
    assert!(av(&a.metrics, "alm_c3_received") > 0 && av(&c.metrics, "alm_c3_sent") > 0);
    eprintln!(
        "[ALM2] roster relay: C<-A<-B 40/40, A forwarded {}, A admitted {}, C3 sent by C {}, log(A)={}",
        ca.alm_counts().forwarded - forwarded_before,
        ca.alm_counts().admitted,
        av(&c.metrics, "alm_c3_sent"),
        ca.alm_log().0
    );
}

/// **C3 admit / refuse**: A's own stream admits B (C2 over C3); C, a relay
/// at service tier 1 (the host said `Warning`), refuses B's subscription
/// for A's stream by name, `load_refuse:admit_closed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn c3_admits_and_a_closed_relay_refuses_by_name() {
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

    let admitted = wait_until(Duration::from_secs(60), || async {
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

    let refused = wait_until(Duration::from_secs(60), || async {
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
    assert!(av(&c.metrics, "load_refuse:admit_closed") > 0);
    eprintln!(
        "[ALM2] c3: A admitted {:?}; C refused {:?}",
        ca.alm_own_children(),
        cc.alm_counts().refused
    );
}

/// **Stale frames (C5)**: B's consumer stalls 1.5 s while A publishes; the
/// media that waited past 800 ms is dropped by age before it is opened, the
/// hop counter skips past it, and the frames after the stall open and
/// arrive. Media between C3 peers rides timed Channel frames.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn stale_media_is_dropped_by_age_and_the_hop_recovers() {
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
        "[ALM2] stale: dropped_by_age={stale} delivered={} after_stall={after}/30 timed_sent={} unopened={}",
        got.len(),
        av(&a.metrics, "av_sent_timed"),
        av(&b.metrics, "av_call_frame_unopened")
    );
    assert!(stale > 0, "media older than 800 ms was dropped by age");
    assert_eq!(
        after, 30,
        "the hop recovered: every post-stall frame opened"
    );
    assert!(
        av(&a.metrics, "av_sent_timed") > 0,
        "media rides timed frames"
    );
    assert_eq!(
        av(&b.metrics, "av_call_frame_unopened"),
        0,
        "no frame failed its open"
    );
    assert_eq!(cb.legs(), vec![a.key.key_id.clone()], "the link stayed up");
}
