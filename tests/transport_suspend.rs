//! **Mobile background: suspend and resume in-process** (step 1).
//!
//! Two nodes on loopback in the phone shape: A is the canonical (it listens),
//! B is client-only (one `TcpClient` interface, no listener) and runs a
//! `ReplicationRuntime` toward A. B is the node that goes to the background.
//!
//! - suspended mid-round, B holds no connected socket, no link and no edge
//!   task, and every sender gets `TransportError::Suspended` (a stuck send is
//!   cancelled with it; the replication scheduler draws no backoff);
//! - resumed, B's sends reach A again and a row A ships lands in B's
//!   directory through B's replication runtime — nothing rebuilt;
//! - suspend → resume cycles repeat with no fd or task growth;
//! - a suspend whose deadline is shorter than a stuck send returns by its
//!   deadline, and a node with a TCP server reports its listener honestly.
//!
//! `cargo test --features transport-reticulum --test transport_suspend`

#![cfg(feature = "transport-reticulum")]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::replication::attestation_bind::owner_binding_attestation;
use ciris_edge::replication::protocol::{DeliverMessage, ReplicationMessage};
use ciris_edge::replication::{
    wire_frame, EnvelopeKind, InboundRouter, ReplicationPeer, ReplicationRuntime,
    ReplicationRuntimeConfig, SchedulerConfig,
};
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumInterfaceConfig, ReticulumTransport, ReticulumTransportConfig,
    TcpClientInterfaceConfig,
};
use ciris_edge::transport::{InboundFrame, SuspendReport, Transport, TransportError};
use ciris_edge::verify::RootingDirectory;
use ciris_edge::EdgeMetrics;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::{Attestation, FederationDirectory};
use ciris_persist::store::sqlite::SqliteBackend;
use common::{build_reticulum_with_retry, directory_with};
use sha2::Digest as _;
use tokio::sync::{mpsc, Mutex};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("addr")
        .port()
}

/// A production-shaped identity (as in `reverse_link_resource_binding_722.rs`):
/// a hybrid keypair and a key id that binds its pubkey, so the announce yields
/// `owns_key`.
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
    fn ed_pub_b64(&self) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &self.ed_pub)
    }
    fn signer(&self) -> Arc<LocalSigner> {
        let classical: Arc<dyn HardwareSigner> = Arc::clone(&self.ed) as Arc<dyn HardwareSigner>;
        let pqc: Arc<dyn PqcSigner> = Arc::clone(&self.pqc) as Arc<dyn PqcSigner>;
        Arc::new(LocalSigner::new(self.key_id.clone(), classical, Some(pqc)))
    }
    async fn record(&self, identity_type: &str) -> ciris_persist::federation::KeyRecord {
        let mut envelope = serde_json::json!({});
        ciris_persist::federation::admission::bind_subject_into_envelope(
            &mut envelope,
            &self.key_id,
            identity_type,
            &self.ed_pub_b64(),
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
            pubkey_ed25519_base64: self.ed_pub_b64(),
            pubkey_ml_dsa_65_base64: Some(self.pqc_pub_b64.clone()),
            algorithm: "hybrid".to_string(),
            identity_type: identity_type.to_string(),
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

fn auth(signer: Arc<LocalSigner>, dir: &Arc<SqliteBackend>) -> ReticulumAuth {
    ReticulumAuth {
        signer: Some(signer),
        rooting: Some(Arc::clone(dir) as Arc<dyn RootingDirectory>),
        resolver: None,
        hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
        ..ReticulumAuth::default()
    }
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

/// ESTABLISHED TCP connections on loopback with `port` at either end — the
/// kernel's view, not the node's. Both nodes live in this process, so a
/// connection B holds to A shows up twice (B's end and A's accepted end).
fn established_on(port: u16) -> usize {
    let hex_port = format!("{port:04X}");
    ["/proc/self/net/tcp", "/proc/self/net/tcp6"]
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .flat_map(|t| t.lines().skip(1).map(str::to_owned).collect::<Vec<_>>())
        .filter(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            cols.len() > 3
                && cols[3] == "01"
                && (cols[1].ends_with(&format!(":{hex_port}"))
                    || cols[2].ends_with(&format!(":{hex_port}")))
        })
        .count()
}

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").map_or(0, Iterator::count)
}

/// The tests here measure process-wide state (fds, the kernel's TCP table);
/// they run one at a time.
static SERIAL: Mutex<()> = Mutex::const_new(());

struct Pair {
    a: Arc<ReticulumTransport>,
    b: Arc<ReticulumTransport>,
    port_a: u16,
    key_a: Ident,
    key_b: Ident,
    owner_a: Ident,
    b_dir: Arc<SqliteBackend>,
    _a_dir: Arc<SqliteBackend>,
    a_rx: Arc<Mutex<Vec<Vec<u8>>>>,
    rt_b: Arc<ReplicationRuntime>,
    metrics_b: EdgeMetrics,
    _tmp: tempfile::TempDir,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
    _a_runtime: OwnRuntime,
}

/// A's listener runs on its own runtime, as the canonical runs in its own
/// process: the per-link tasks its event loop spawns (e.g. the 10 s responder
/// handshake watch) then never count against B's runtime.
struct OwnRuntime(Option<tokio::runtime::Runtime>);

impl Drop for OwnRuntime {
    fn drop(&mut self) {
        if let Some(rt) = self.0.take() {
            rt.shutdown_background();
        }
    }
}

/// A listens (the canonical); B is client-only, holds A's hybrid-signed route
/// (so it can seal to A and attribute A's frames), and replicates
/// Attestations with A.
#[allow(clippy::too_many_lines)]
async fn pair(tag: &str) -> Pair {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "warn,ciris_edge=info".into()),
        )
        .with_test_writer()
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let key_a = Ident::new(&format!("canon-a-susp-{tag}"), 0x1a).await;
    let key_b = Ident::new(&format!("phone-b-susp-{tag}"), 0x1b).await;
    let owner_a = Ident::new(&format!("owner-a-susp-{tag}"), 0x4a).await;
    let records = vec![
        key_a.record("node").await,
        key_b.record("node").await,
        owner_a.record("user").await,
    ];
    let a_dir = directory_with(records.clone()).await;
    let b_dir = directory_with(records).await;

    let (a, addr_a) = build_reticulum_with_retry(|| {
        let base = tmp.path().to_path_buf();
        let signer = key_a.signer();
        let dir = Arc::clone(&a_dir);
        async move {
            let mut c = ReticulumTransportConfig::new(base.join("a/transport.id"), &signer.key_id);
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.announce_interval = Duration::from_secs(5);
            (c, auth(signer, &dir))
        }
    })
    .await;
    let port_a = addr_a.port();
    let (b, _) = build_reticulum_with_retry(|| {
        let base = tmp.path().to_path_buf();
        let signer = key_b.signer();
        let dir = Arc::clone(&b_dir);
        async move {
            let mut c = ReticulumTransportConfig::new(base.join("b/transport.id"), &signer.key_id);
            // The phone shape (CIRISServer b027129b): one TcpClient per
            // bootstrap peer, so no listener is ever built.
            c.interfaces = vec![ReticulumInterfaceConfig::TcpClient(
                TcpClientInterfaceConfig {
                    target_addr: addr_a,
                    transit: None,
                    ifac: None,
                },
            )];
            c.announce_interval = Duration::from_secs(5);
            (c, auth(signer, &dir))
        }
    })
    .await;
    // A's #406 producer published A's hybrid-signed route; B holds it.
    for r in a_dir
        .list_signed_transport_destinations_for(&key_a.key_id)
        .await
        .expect("list A's routes")
    {
        FederationDirectory::put_signed_transport_destination(&*b_dir, &r)
            .await
            .expect("seed A's route at B");
    }

    let (tx_a, mut rx_a) = mpsc::channel::<InboundFrame>(64);
    let (tx_b, mut rx_b) = mpsc::channel::<InboundFrame>(64);
    let metrics_b = EdgeMetrics::new();
    let rt_b = Arc::new(
        ReplicationRuntime::start(
            Arc::clone(&b_dir) as Arc<dyn FederationDirectory>,
            Arc::clone(&b) as Arc<dyn Transport>,
            vec![ReplicationPeer {
                peer_key_id: key_a.key_id.clone(),
                kind: EnvelopeKind::Attestation,
            }],
            ReplicationRuntimeConfig {
                scheduler: SchedulerConfig {
                    cadence: Duration::from_secs(3600),
                    round_timeout: Duration::from_secs(15),
                    ..SchedulerConfig::default()
                },
                local_key_id: Some(key_b.key_id.clone()),
                metrics: Some(metrics_b.clone()),
                ..Default::default()
            },
            None,
        )
        .await,
    );
    let router = InboundRouter::new(rt_b.registry());
    let a_rx: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let a_seen = Arc::clone(&a_rx);
    let (la, lb) = (Arc::clone(&a), Arc::clone(&b));
    let a_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("A's runtime");
    let tasks = vec![
        a_runtime.spawn(async move {
            let _ = la.listen(tx_a).await;
        }),
        tokio::spawn(async move {
            let _ = lb.listen(tx_b).await;
        }),
        tokio::spawn(async move {
            while let Some(f) = rx_a.recv().await {
                a_seen.lock().await.push(f.envelope_bytes);
            }
        }),
        tokio::spawn(async move {
            while let Some(frame) = rx_b.recv().await {
                let _ = router.try_route(&frame).await;
            }
        }),
    ];
    // Route heal: each learns the other from its announce.
    let known = wait_until(Duration::from_secs(60), || async {
        b.knows_peer(&key_a.key_id).await && a.knows_peer(&key_b.key_id).await
    })
    .await;
    assert!(known, "A and B learn each other from their announces");
    assert!(
        established_on(port_a) >= 2,
        "B's client is connected to A: {} established",
        established_on(port_a)
    );
    Pair {
        a,
        b,
        port_a,
        key_a,
        key_b,
        owner_a,
        b_dir,
        _a_dir: a_dir,
        a_rx,
        rt_b,
        metrics_b,
        _tmp: tmp,
        _tasks: tasks,
        _a_runtime: OwnRuntime(Some(a_runtime)),
    }
}

impl Pair {
    /// Attestation rounds B has run to an outcome (any outcome).
    fn rounds_run(&self) -> u64 {
        self.metrics_b
            .snapshot()
            .replication_round_duration_seconds
            .get(&EnvelopeKind::Attestation)
            .map_or(0, |h| h.count)
    }

    /// B → A, and A received it.
    async fn b_reaches_a(&self, body: &[u8]) {
        self.b
            .send(&self.key_a.key_id, body)
            .await
            .expect("B -> A delivered");
        let got = wait_until(Duration::from_secs(30), || async {
            self.a_rx.lock().await.iter().any(|f| f == body)
        })
        .await;
        assert!(got, "A received {:?}", String::from_utf8_lossy(body));
    }

    /// A ships one hybrid-signed row to B over the link B opened; true once it
    /// is admitted in B's directory by B's replication runtime.
    async fn a_row_lands_at_b(&self) -> bool {
        let att = owner_binding_attestation(
            &self.owner_a.key_id,
            &self.key_a.key_id,
            chrono::Utc::now(),
            &self.owner_a.signer(),
        )
        .await
        .expect("owner binding");
        let id = att.attestation_id.clone();
        self.a
            .send(&self.key_b.key_id, &deliver_frame(&att))
            .await
            .expect("A -> B over B's link");
        wait_until(Duration::from_secs(60), || async {
            self.b_dir
                .list_attestations_since(None, 1024)
                .await
                .expect("list")
                .iter()
                .any(|r| r.attestation.attestation_id == id)
        })
        .await
    }
}

fn deliver_frame(att: &Attestation) -> Vec<u8> {
    let bytes = serde_json::to_vec(att).expect("attestation json");
    wire_frame::wrap_for_kind(&ReplicationMessage::Deliver(DeliverMessage {
        kind: EnvelopeKind::Attestation,
        envelopes: vec![bytes],
    }))
}

/// The client-only node's report once fully suspended.
fn assert_quiet(r: &SuspendReport, what: &str) {
    assert!(r.quiescent, "{what}: quiescent: {r:?}");
    assert_eq!(r.links_open, 0, "{what}: no link: {r:?}");
    assert_eq!(r.interfaces_open, 0, "{what}: no interface: {r:?}");
    assert!(!r.listener_open, "{what}: no listener: {r:?}");
    assert_eq!(r.edge_tasks, 0, "{what}: no edge task: {r:?}");
    assert_eq!(r.sends_in_flight, 0, "{what}: no send in flight: {r:?}");
    assert_eq!(
        r.node_tasks, 2,
        "{what}: only leviculum's idle event loop + counter thread remain (until leviculum#90): {r:?}"
    );
}

/// **Suspended mid-round, then resumed.** B has a live link to A and a send
/// stuck mid-ship (the ship-delay seam holds it 60 s); a replication round is
/// kicked. `suspend` cancels the stuck send with `Suspended`, closes the link,
/// parks the listener and detaches the client: the kernel shows no
/// ESTABLISHED connection on A's port, the report shows no link, interface,
/// listener or edge task, a new send is refused with `Suspended`, and the
/// round refused meanwhile leaves no backoff. Resumed, B reaches A again and
/// a row A ships lands in B's directory through the same replication runtime.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn suspend_mid_round_leaves_nothing_open_and_resume_replicates() {
    let _serial = SERIAL.lock().await;
    let p = pair("mid").await;
    p.b_reaches_a(b"warm-up").await;
    assert!(p.b.link_count().await >= 1, "B holds a link to A");

    // A send stuck mid-ship, and a round toward A.
    p.b.delay_resource_ships_for_test(60_000);
    p.b.delay_channel_sends_for_test(60_000);
    let stuck = {
        let b = Arc::clone(&p.b);
        let dest = p.key_a.key_id.clone();
        tokio::spawn(async move { b.send(&dest, &vec![0x5a; 4096]).await })
    };
    p.rt_b.round_now(&p.key_a.key_id).await.expect("kick");
    let in_flight = wait_until(Duration::from_secs(10), || async {
        p.b.sends_in_flight_for_test() >= 1
    })
    .await;
    assert!(in_flight, "a send is in flight when the suspend lands");

    let started = Instant::now();
    let report = p.b.suspend(Duration::from_secs(10)).await;
    assert!(!report.already_suspended);
    assert_quiet(&report, "suspend mid-round");
    assert!(p.b.is_suspended());
    let stuck = tokio::time::timeout(Duration::from_secs(2), stuck)
        .await
        .expect("the stuck send ends with the suspend, not after its 60 s ship")
        .expect("join");
    assert!(
        matches!(stuck, Err(TransportError::Suspended)),
        "the stuck send is cancelled with Suspended: {stuck:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "quiescent well before the deadline: {:?}",
        started.elapsed()
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        p.rt_b.no_route_backoff().is_empty(),
        "the round the suspend cancelled draws no backoff: {:?}",
        p.rt_b.no_route_backoff()
    );
    let closed = wait_until(Duration::from_secs(5), || async {
        established_on(p.port_a) == 0
    })
    .await;
    assert!(
        closed,
        "no ESTABLISHED connection on A's port once B is suspended: {}",
        established_on(p.port_a)
    );
    let refused = p.b.send(&p.key_a.key_id, b"while suspended").await;
    assert!(
        matches!(refused, Err(TransportError::Suspended)),
        "a send while suspended is refused with Suspended: {refused:?}"
    );
    // A round while suspended is skipped quietly: no no-route backoff.
    let before = p.rounds_run();
    p.rt_b.round_now(&p.key_a.key_id).await.expect("kick");
    let ran = wait_until(Duration::from_secs(20), || async {
        p.rounds_run() > before
    })
    .await;
    assert!(ran, "a round toward A ran while B was suspended");
    // The scheduler records the round's class just after its duration.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        p.rt_b.no_route_backoff().is_empty(),
        "a round refused by the suspend draws no backoff: {:?}",
        p.rt_b.no_route_backoff()
    );
    let again = p.b.suspend(Duration::from_secs(5)).await;
    assert!(again.already_suspended, "suspend is idempotent: {again:?}");
    assert_quiet(&again, "second suspend");

    // Resume: same transport, same replication runtime.
    p.b.delay_resource_ships_for_test(0);
    p.b.delay_channel_sends_for_test(0);
    p.b.resume().await.expect("resume");
    assert!(!p.b.is_suspended());
    p.b.resume().await.expect("resume is idempotent");
    p.b_reaches_a(b"after resume").await;
    assert!(
        p.a_row_lands_at_b().await,
        "after resume a row A ships lands in B's directory through B's replication runtime"
    );
}

/// **Cycles.** Suspend → resume four times; each suspend is quiescent, each
/// resume reaches A, and from the second cycle on (the first warms lazy
/// state) the suspended points hold the same number of open fds and of live
/// tasks on this test's runtime. The tests in this file run one at a time
/// ([`SERIAL`]), so the process-wide fd count is this test's alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_suspend_resume_cycles_do_not_grow() {
    let _serial = SERIAL.lock().await;
    let p = pair("cycles").await;
    p.b_reaches_a(b"cycle-0").await;
    let mut marks = Vec::new();
    for i in 1..=4u8 {
        let r = p.b.suspend(Duration::from_secs(10)).await;
        assert_quiet(&r, &format!("cycle {i}"));
        let closed = wait_until(Duration::from_secs(5), || async {
            established_on(p.port_a) == 0
        })
        .await;
        assert!(closed, "cycle {i}: no ESTABLISHED connection on A's port");
        let tasks = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        marks.push((open_fds(), tasks));
        p.b.resume().await.expect("resume");
        p.b_reaches_a(format!("cycle-{i}").as_bytes()).await;
    }
    assert_eq!(
        marks[1], marks[3],
        "(open fds, live tasks) at the suspended points do not grow across cycles: {marks:?}"
    );
}

/// **The deadline holds.** A — the canonical, with a TCP server — is
/// suspended with a 1.5 s deadline while a send of its own is stuck. Its
/// listening socket cannot close in-process (until leviculum#90), so it can
/// never be quiescent: the suspend returns by its deadline, reports
/// `listener_open` and `quiescent: false`, and the stuck send still ends with
/// `Suspended`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn suspend_returns_by_its_deadline_and_reports_the_listener() {
    let _serial = SERIAL.lock().await;
    let p = pair("deadline").await;
    p.b_reaches_a(b"open a link").await;
    p.a.delay_resource_ships_for_test(60_000);
    p.a.delay_channel_sends_for_test(60_000);
    let stuck = {
        let a = Arc::clone(&p.a);
        let dest = p.key_b.key_id.clone();
        tokio::spawn(async move { a.send(&dest, &vec![0x6b; 4096]).await })
    };
    let in_flight = wait_until(Duration::from_secs(10), || async {
        p.a.sends_in_flight_for_test() >= 1
    })
    .await;
    assert!(in_flight, "A's send is in flight");
    let deadline = Duration::from_millis(1500);
    let started = Instant::now();
    let r = tokio::time::timeout(Duration::from_secs(5), p.a.suspend(deadline))
        .await
        .expect("suspend returns");
    let took = started.elapsed();
    assert!(
        took >= deadline && took < deadline + Duration::from_millis(750),
        "suspend returns at its deadline ({deadline:?}), not before and not long after: {took:?}"
    );
    assert!(r.listener_open, "A's TCP server is reported open: {r:?}");
    assert!(
        !r.quiescent,
        "a node with a listener is never reported quiescent: {r:?}"
    );
    assert_eq!(r.sends_in_flight, 0, "{r:?}");
    let stuck = tokio::time::timeout(Duration::from_secs(2), stuck)
        .await
        .expect("the stuck send ended")
        .expect("join");
    assert!(matches!(stuck, Err(TransportError::Suspended)), "{stuck:?}");
    p.a.delay_resource_ships_for_test(0);
    p.a.delay_channel_sends_for_test(0);
    p.a.resume().await.expect("resume A");
}
