//! CC 5.4.3 — link shaping (`CLM-link-shaping`, rc10): the witnesses.
//!
//! Two nodes, A listening and B dialling, each under its own
//! [`ShapingPolicy`]. The wire tap records every frame a node hands
//! leviculum, sealed, so a shaped link shows as a run of equal-length frames
//! (the agreed frame plus the seal's 25 bytes) in BOTH directions; the
//! `link_shaping` ledger says which were real and which cover.

#![cfg(feature = "transport-reticulum")]

mod common;

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::peer_obligation::{LivePeerObligations, SendSetRead};
use ciris_edge::replication::attestation_bind::{bind_attestation_envelope, AttestationColumns};
use ciris_edge::replication::{
    self_publish_set, InboundRouter, ReplicationRuntime, ReplicationRuntimeConfig, SchedulerConfig,
};
use ciris_edge::transport::link_shaping::{
    BudgetClass, DeviceKind, DeviceState, ShapedSharePolicy, ShapingPolicy, REFERENCE_FRAME_BYTES,
    SEAT_BYTES_PER_S,
};
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport, TransportError};
use ciris_edge::verify::RootingDirectory;
use ciris_edge::EdgeMetrics;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::{Attestation, FederationDirectory, SignedAttestation};
use ciris_persist::store::sqlite::SqliteBackend;
use common::directory_with;
use sha2::Digest as _;
use tokio::sync::Mutex;

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

/// A production-shaped identity: a hybrid keypair and a key id that BINDS the
/// pubkey fingerprint.
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
    async fn record(&self) -> ciris_persist::federation::KeyRecord {
        self.record_as("node").await
    }
    async fn record_as(&self, identity_type: &str) -> ciris_persist::federation::KeyRecord {
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
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// One node: its transport, the metrics bag attached to it, and every frame
/// its listener delivered upward.
struct Node {
    key: Ident,
    transport: Arc<ReticulumTransport>,
    metrics: EdgeMetrics,
    dir: Arc<SqliteBackend>,
    seen: Arc<Mutex<Vec<InboundFrame>>>,
    runtime: Option<Arc<ReplicationRuntime>>,
    ladder: Arc<ciris_edge::load_ladder::SharedLadder>,
}

impl Node {
    async fn received(&self, bytes: &[u8]) -> bool {
        self.seen
            .lock()
            .await
            .iter()
            .any(|f| f.envelope_bytes == bytes)
    }
}

/// Copy `from`'s signed routes (its transit pair rides them) into `to`.
async fn seed_route(from: &Node, to: &Node) {
    let routes = from
        .dir
        .list_signed_transport_destinations_for(&from.key.key_id)
        .await
        .expect("list routes");
    assert!(
        !routes.is_empty(),
        "{} published its route",
        from.key.key_id
    );
    for r in &routes {
        FederationDirectory::put_signed_transport_destination(&*to.dir, r)
            .await
            .expect("seed the route");
    }
}

struct Duo {
    a: Node,
    b: Node,
    _tmp: tempfile::TempDir,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Node {
    fn shaping(&self, label: &str) -> u64 {
        self.metrics.link_shaping().get(label).copied().unwrap_or(0)
    }
}

/// A witness that times shaped links takes the host; the rest share it. Shaped
/// links emit on a clock whether or not anything is queued, so stars of six
/// beside each other starve one another's links until they drop.
static HOST: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

async fn share_host() -> tokio::sync::RwLockReadGuard<'static, ()> {
    HOST.read().await
}

async fn whole_host() -> tokio::sync::RwLockWriteGuard<'static, ()> {
    HOST.write().await
}

/// A policy that shapes fast enough to witness on loopback: `bytes_per_s`
/// at the loopback MDU gives λ of a few frames per second.
fn policy(
    class: BudgetClass,
    bytes_per_s: u32,
    rho: f64,
    window_s: u64,
    strict: bool,
) -> ShapingPolicy {
    ShapingPolicy {
        class,
        bytes_per_s,
        rho,
        window: Duration::from_secs(window_s),
        node_cap_bytes_per_s: bytes_per_s.saturating_mul(8),
        require_shaped_links: strict,
        scope: ciris_edge::transport::link_shaping::ShapingScope::AllIdentityLinks,
        share: ShapedSharePolicy::DivideNoFloor,
        layer_reserve_links: ciris_edge::transport::link_shaping::DEFAULT_LAYER_RESERVE_LINKS,
    }
}

/// An `off` policy the suite names itself (not the library default), so
/// `CIRIS_EDGE_TEST_SHAPING=server` (tests/common) never turns it on.
fn explicit_off() -> ShapingPolicy {
    ShapingPolicy {
        layer_reserve_links: 0,
        ..ShapingPolicy::default()
    }
}

/// `A` listens, `B` dials; each holds the other's signed route.
async fn duo(tag: &str, policy_a: ShapingPolicy, policy_b: ShapingPolicy) -> Duo {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let keys = [
        Ident::new(&format!("node-a-shape-{tag}"), 0x2a).await,
        Ident::new(&format!("node-b-shape-{tag}"), 0x2b).await,
    ];
    let mut records = Vec::new();
    for k in &keys {
        records.push(k.record().await);
    }
    let [key_a, key_b] = keys;
    let mut tasks = Vec::new();
    let mut port_a = 0;
    let mut nodes = Vec::new();
    for (i, (key, policy)) in [(key_a, policy_a), (key_b, policy_b)]
        .into_iter()
        .enumerate()
    {
        let dir = directory_with(records.clone()).await;
        let metrics = EdgeMetrics::new();
        let (transport, addr) = common::build_reticulum_with_retry_metrics(
            || {
                let base = tmp.path().join(format!("n{i}"));
                let signer = key.signer();
                let dir = Arc::clone(&dir);
                let policy = policy.clone();
                async move {
                    let mut c =
                        ReticulumTransportConfig::new(base.join("transport.id"), &signer.key_id);
                    c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
                    if i > 0 {
                        c.bootstrap_peers = vec![format!("127.0.0.1:{port_a}").parse().unwrap()];
                    }
                    c.announce_interval = Duration::from_secs(5);
                    c.shaping = policy;
                    (c, auth(signer, &dir))
                }
            },
            metrics.clone(),
        )
        .await;
        if i == 0 {
            port_a = addr.port();
        }
        // As `EdgeBuilder::build` does.
        let ladder = Arc::new(ciris_edge::load_ladder::SharedLadder::default());
        ladder.attach_telemetry(Arc::clone(&metrics.telemetry));
        transport.attach_load_ladder(Arc::clone(&ladder));
        let seen: Arc<Mutex<Vec<InboundFrame>>> = Arc::new(Mutex::new(Vec::new()));
        let (tx, mut rx) = tokio::sync::mpsc::channel::<InboundFrame>(256);
        let listener = Arc::clone(&transport);
        tasks.push(tokio::spawn(async move {
            let _ = listener.listen(tx).await;
        }));
        let sink = Arc::clone(&seen);
        tasks.push(tokio::spawn(async move {
            while let Some(f) = rx.recv().await {
                sink.lock().await.push(f);
            }
        }));
        nodes.push(Node {
            key,
            transport,
            metrics,
            dir,
            seen,
            runtime: None,
            ladder,
        });
    }
    let b = nodes.pop().expect("b");
    let a = nodes.pop().expect("a");
    seed_route(&a, &b).await;
    seed_route(&b, &a).await;
    let known = wait_until(Duration::from_secs(60), || async {
        b.transport.knows_peer(&a.key.key_id).await && a.transport.knows_peer(&b.key.key_id).await
    })
    .await;
    assert!(known, "A and B learn each other's announce");
    Duo {
        a,
        b,
        _tmp: tmp,
        _tasks: tasks,
    }
}

/// Every frame a node handed leviculum on `link`, in order.
fn frames_on(tapped: &[([u8; 16], Vec<u8>)], link: [u8; 16]) -> Vec<Vec<u8>> {
    tapped
        .iter()
        .filter(|(l, _)| *l == link)
        .map(|(_, f)| f.clone())
        .collect()
}

/// The trailing run of equal-length frames: `(length, count)`.
fn trailing_run(frames: &[Vec<u8>]) -> (usize, usize) {
    let Some(last) = frames.last() else {
        return (0, 0);
    };
    let n = frames
        .iter()
        .rev()
        .take_while(|f| f.len() == last.len())
        .count();
    (last.len(), n)
}

/// A recognisable row payload of `len` bytes.
fn marked(marker: &[u8], len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    while v.len() < len {
        v.extend_from_slice(marker);
    }
    v.truncate(len);
    v
}

/// **Witness 1 + 3** — both at `home` with a loopback-sized budget: after the
/// handshake and the offers, every frame B hands the link is one length, and
/// so is every frame A hands it (the responder shapes back); cover frames
/// flow on both sides while nothing is said; a real row still crosses.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shaped_link_carries_one_frame_size_at_poisson_times_both_ways() {
    let _host = share_host().await;
    let fast = policy(BudgetClass::Home, 200_000, 0.5, 10, false);
    let t = duo("both", fast.clone(), fast).await;
    t.a.transport.set_link_wire_tap_for_test(true);
    t.b.transport.set_link_wire_tap_for_test(true);
    let marker = b"SHAPE-ROW-";
    let row = marked(marker, 3_000);
    t.b.transport
        .send(&t.a.key.key_id, &row)
        .await
        .expect("B -> A on a shaped link");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(&row).await
        })
        .await,
        "A delivered B's row through the shaper: {:?}",
        t.a.metrics.link_shaping()
    );
    assert_eq!(
        t.b.shaping("link_shaping_agreed"),
        1,
        "{:?}",
        t.b.metrics.link_shaping()
    );
    assert_eq!(
        t.a.shaping("link_shaping_agreed"),
        1,
        "{:?}",
        t.a.metrics.link_shaping()
    );
    // Say nothing for a while: cover keeps the stream going both ways.
    assert!(
        wait_until(Duration::from_secs(20), || async {
            t.b.shaping("link_shaping_frames_cover") >= 10
                && t.a.shaping("link_shaping_frames_cover") >= 10
        })
        .await,
        "cover flows both ways while idle: B {:?} A {:?}",
        t.b.metrics.link_shaping(),
        t.a.metrics.link_shaping()
    );
    assert!(t.b.shaping("link_shaping_frames_real") >= 1);
    assert!(t.a.shaping("link_shaping_cover_received") >= 1);
    // A's reply rides the same shaped link back.
    let reply = marked(b"SHAPE-REPLY-", 2_000);
    t.a.transport
        .send(&t.b.key.key_id, &reply)
        .await
        .expect("A -> B on the shaped link");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.b.received(&reply).await
        })
        .await,
        "B delivered A's reply"
    );
    assert!(t.a.shaping("link_shaping_frames_real") >= 1);
    // The wire: one frame length, both directions, no marker in the clear.
    let b_wire = t.b.transport.link_wire_tapped_for_test();
    let link = b_wire.first().expect("B dialled").0;
    let b_frames = frames_on(&b_wire, link);
    let (b_len, b_run) = trailing_run(&b_frames);
    assert!(
        b_run >= 10,
        "B's trailing run of equal frames: {b_run} × {b_len} B"
    );
    let a_frames = frames_on(&t.a.transport.link_wire_tapped_for_test(), link);
    let (a_len, a_run) = trailing_run(&a_frames);
    assert!(
        a_run >= 10,
        "A's trailing run of equal frames: {a_run} × {a_len} B"
    );
    assert_eq!(a_len, b_len, "both ends send the agreed frame size");
    assert!(
        b_frames
            .iter()
            .chain(a_frames.iter())
            .all(|f| !f.windows(marker.len()).any(|w| w == marker)),
        "no plaintext marker on the wire"
    );
    for n in [&t.a, &t.b] {
        let bad: Vec<_> = n
            .metrics
            .link_shaping()
            .into_iter()
            .filter(|(k, _)| k.contains("refused") || k.contains("dropped") || k.contains("failed"))
            .collect();
        assert!(bad.is_empty(), "nothing refused: {bad:?}");
    }
}

/// **Witness 2** — a peer older than `CLM-shaping-offered-never-refused` still
/// answers `off`, and the wire ends cleanly: the offers resolve to UNSHAPED by
/// agreement and the link runs bare (counted on both ends); a node that
/// REQUIRES shaped links refuses the same peer by name and the link closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_half_shaped_offer_leaves_the_link_unshaped_or_refused_by_policy() {
    let _host = share_host().await;
    let lenient = duo(
        "half",
        policy(BudgetClass::Home, 200_000, 0.5, 10, false),
        explicit_off(),
    )
    .await;
    lenient.b.transport.answer_off_like_an_old_peer_for_test();
    // A (shaping) dials B (off): A offers, B answers off.
    lenient
        .a
        .transport
        .send(&lenient.b.key.key_id, b"bare-by-agreement")
        .await
        .expect("A -> B, unshaped by agreement");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            lenient.b.received(b"bare-by-agreement").await
        })
        .await
    );
    assert_eq!(
        lenient.a.shaping("link_shaping_offered"),
        1,
        "{:?}",
        lenient.a.metrics.link_shaping()
    );
    assert_eq!(lenient.a.shaping("link_shaping_unshaped"), 1);
    assert_eq!(
        lenient.b.shaping("link_shaping_unshaped"),
        1,
        "{:?}",
        lenient.b.metrics.link_shaping()
    );
    assert_eq!(lenient.a.shaping("link_shaping_agreed"), 0);
    assert_eq!(
        lenient.a.shaping("link_shaping_frames_cover"),
        0,
        "nothing shaped"
    );
    drop(lenient);

    let strict = duo(
        "strict",
        policy(BudgetClass::Home, 200_000, 0.5, 10, true),
        explicit_off(),
    )
    .await;
    strict.b.transport.answer_off_like_an_old_peer_for_test();
    match strict
        .a
        .transport
        .send(&strict.b.key.key_id, b"never-sent")
        .await
    {
        Err(TransportError::LinkSealRefused { reason, .. }) => {
            assert_eq!(reason, "link_shaping_refused_unshaped_peer");
        }
        other => panic!("a strict node refuses an unshaped peer by name: {other:?}"),
    }
    // The send path may retry the dial once; each attempt is refused by name.
    assert!(strict.a.shaping("link_shaping_refused_unshaped_peer") >= 1);
    assert_eq!(strict.a.shaping("link_shaping_agreed"), 0);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(!strict.b.received(b"never-sent").await);
}

/// **Witness 5** — the knobs move the stream: at one λ, a burst of rows
/// takes longer under ρ = 0.25 than under ρ = 0.8 (the budget admits fewer
/// real frames per window), and the real share B emitted while the burst
/// drained stays under ρ; a short window at one ρ paces a burst that a long
/// one admits whole. That side is read from the budget, not from a race
/// between two timings a loaded host decides: the burst takes
/// `⌈40 / budget⌉` grants, so it spans at least all but its first and last
/// windows. At ρ = 0.25, since at ρ = 0.5 the budget barely binds and an
/// unpaced burst clears the same bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rho_and_the_window_move_the_real_share_and_the_delay() {
    #[allow(clippy::cast_precision_loss)] // frame counts, far below 2^52
    async fn burst_time(tag: &str, rho: f64, window_s: u64) -> (Duration, f64, usize) {
        let p = policy(BudgetClass::Home, 200_000, rho, window_s, false);
        let t = duo(tag, p.clone(), p).await;
        // Open and shape the link first, then measure the burst alone.
        t.b.transport
            .send(&t.a.key.key_id, b"open")
            .await
            .expect("open");
        assert!(
            wait_until(Duration::from_secs(30), || async {
                t.a.received(b"open").await
            })
            .await
        );
        let real0 = t.b.shaping("link_shaping_frames_real");
        let cover0 = t.b.shaping("link_shaping_frames_cover");
        let started = tokio::time::Instant::now();
        let mut rows = Vec::new();
        for i in 0..40u32 {
            let row = marked(format!("BURST-{tag}-{i:02}-").as_bytes(), 12_000);
            t.b.transport
                .send(&t.a.key.key_id, &row)
                .await
                .expect("queued on the shaped link");
            rows.push(row);
        }
        let all = wait_until(Duration::from_secs(120), || async {
            for r in &rows {
                if !t.a.received(r).await {
                    return false;
                }
            }
            true
        })
        .await;
        let took = started.elapsed();
        assert!(
            all,
            "[{tag}] the burst landed: {:?}",
            t.a.metrics.link_shaping()
        );
        let real = t.b.shaping("link_shaping_frames_real") - real0;
        let cover = t.b.shaping("link_shaping_frames_cover") - cover0;
        let budget = t.b.transport.shaping_status().links[0].real_frames_per_window;
        // The share of the slots the link owned, ρ·λ·W being the budget. Not of
        // the frames it emitted: a timer lagging on a loaded host emits fewer,
        // which reads as a larger share, and that measures the host and not ρ.
        let lambda = budget as f64 / (rho * window_s as f64);
        let share = real as f64 / (lambda * took.as_secs_f64()).max(1.0);
        eprintln!("[{tag}] rho={rho} W={window_s}s burst of 40 took {took:?}; real share {share:.2} ({real} real / {cover} cover), budget {budget} a window");
        (took, share, budget)
    }
    let _host = whole_host().await;
    // The budget bounds real frames PER WINDOW (ρ·λ·W), not per burst: at
    // ρ=0.8 the whole burst fits one window's budget and leaves back-to-back
    // (its share over the burst's own seconds is near 1); at ρ=0.25 it does
    // not, so the stream stays mostly cover while the burst drains and the
    // burst takes several windows.
    let (t_low, share_low, _) = burst_time("rho25", 0.25, 10).await;
    let (t_high, share_high, _) = burst_time("rho80", 0.8, 10).await;
    assert!(
        share_low <= 0.25 + 0.1,
        "real share under rho=0.25: {share_low:.2}"
    );
    assert!(
        share_high > share_low,
        "a larger ρ admits more real per window: {share_high:.2} vs {share_low:.2}"
    );
    assert!(
        t_low > t_high,
        "a tighter budget share delays the burst: rho=0.25 {t_low:?} vs rho=0.8 {t_high:?}"
    );
    let (t_short, _, short_budget) = burst_time("w2", 0.25, 2).await;
    let (_, _, long_budget) = burst_time("w30", 0.25, 30).await;
    assert!(
        long_budget >= 40,
        "W=30 s admits the burst whole: {long_budget}"
    );
    let grants = 40usize.div_ceil(short_budget);
    assert!(grants >= 6, "W=2 s does not: {short_budget} a window");
    let paced = Duration::from_secs(2) * u32::try_from(grants - 2).expect("a few");
    assert!(
        t_short >= paced,
        "a shorter window delays a burst: W=2 s {t_short:?}, at least {paced:?} for {grants} grants"
    );
}

/// An envelope-shaped payload of `len` bytes whose head names `message_type`
/// in its WIRE spelling (`MessageType`'s serde form, e.g. `BlobChunkBody`):
/// the transport reads only the head to classify bulk; the bytes cross as is.
fn typed_payload(message_type: &str, marker: &[u8], len: usize) -> Vec<u8> {
    let head = format!(
        r#"{{"edge_schema_version":"1","signing_key_id":"s","destination_key_id":"d","message_type":"{message_type}","body":""#
    );
    let mut v = head.into_bytes();
    v.extend(marked(marker, len));
    v.extend_from_slice(br#""}"#);
    v
}

/// **CC 5.4.3 rc16 two planes** — two server-class nodes, shaped both ways. A
/// row rides the shaped identity link; then a 1 MiB blob chunk, a four-chunk
/// DAG (B → A) and a 512 KiB content body (A → B, A the responder) all
/// complete on an UNSHAPED link of their own. The shaped link stays constant:
/// once shaped, every frame on it is the one agreed size (no frame larger
/// than the shaped MDU), its real-frame count stays a handful, and nothing
/// was refused as bulk. Mutation: route the bulk onto the shaped link and the
/// sends fail (`link_shaping_bulk_refused`) or the shaped wire grows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bulk_rides_an_unshaped_link_of_its_own_and_the_shaped_link_stays_constant() {
    let _host = share_host().await;
    let server = policy(BudgetClass::Server, 20_000, 0.5, 10, false);
    let t = duo("bulk", server.clone(), server).await;
    t.a.transport.set_link_wire_tap_for_test(true);
    t.b.transport.set_link_wire_tap_for_test(true);
    let row = typed_payload("AttestationGossip", b"BULK-ROW-", 2_000);
    t.b.transport
        .send(&t.a.key.key_id, &row)
        .await
        .expect("B -> A row on the shaped link");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(&row).await
        })
        .await,
        "the row crossed"
    );
    assert_eq!(
        t.b.shaping("link_shaping_agreed"),
        1,
        "{:?}",
        t.b.metrics.link_shaping()
    );

    let blob = typed_payload("BlobChunkBody", b"BLOB-1MIB-", 1 << 20);
    t.b.transport
        .send(&t.a.key.key_id, &blob)
        .await
        .expect("a 1 MiB blob chunk B -> A completes");
    let dag: Vec<Vec<u8>> = (0..4)
        .map(|i| {
            typed_payload(
                "BlobChunkBody",
                format!("DAG-CHUNK-{i}-").as_bytes(),
                256 * 1024,
            )
        })
        .collect();
    for c in &dag {
        t.b.transport
            .send(&t.a.key.key_id, c)
            .await
            .expect("a DAG chunk B -> A completes");
    }
    let body = typed_payload("ContentBody", b"CONTENT-A2B-", 512 * 1024);
    t.a.transport
        .send(&t.b.key.key_id, &body)
        .await
        .expect("a content body A -> B completes");
    assert!(
        wait_until(Duration::from_secs(60), || async {
            let mut all = t.a.received(&blob).await && t.b.received(&body).await;
            for c in &dag {
                all = all && t.a.received(c).await;
            }
            all
        })
        .await,
        "every bulk payload arrived"
    );

    for n in [&t.a, &t.b] {
        assert_eq!(
            n.shaping("link_shaping_bulk_refused"),
            0,
            "{:?}",
            n.metrics.link_shaping()
        );
    }
    assert!(
        t.b.shaping("link_shaping_frames_real") < 50,
        "the bulk never entered the shaper: {:?}",
        t.b.metrics.link_shaping()
    );
    let (shaped, wire) = assert_shaped_stream_constant(&t.b).await;
    let bulk_bytes: usize = wire
        .iter()
        .filter(|(l, _)| *l != shaped)
        .map(|(_, f)| f.len())
        .sum();
    assert!(
        bulk_bytes > (1 << 20) + 4 * 256 * 1024,
        "the bulk crossed on another link: {bulk_bytes} B"
    );
}

/// **CC 5.4.3, `CLM-shaped-link-one-hop`** — B is a NAT'd phone: it dials A
/// (the only link, shaped), and A cannot dial B. An unprompted 1 MiB Deliver
/// from A to B needs the bulk plane and no unshaped link to B exists. It is
/// refused by name, and not one fragment of it rides the shaped link: the
/// frames the link emits stay rows and cover, and B receives nothing. When a
/// dial works again the send goes on its own unshaped link. Mutation: fall
/// back onto the shaped link → this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_bulk_dial_is_refused_by_name_and_never_rides_the_shaped_link() {
    let _host = share_host().await;
    let server = policy(BudgetClass::Server, 100_000, 0.5, 10, false);
    let t = duo("fallback", server.clone(), server).await;
    let row = typed_payload("AttestationGossip", b"FB-ROW-", 2_000);
    t.b.transport
        .send(&t.a.key.key_id, &row)
        .await
        .expect("B dials A: the shaped link");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(&row).await
        })
        .await,
        "B's row crossed"
    );
    assert_eq!(
        t.a.shaping("link_shaping_agreed"),
        1,
        "{:?}",
        t.a.metrics.link_shaping()
    );
    t.a.transport.refuse_outbound_dials_for_test(true);
    let deliver = typed_payload("AttestationGossip", b"FB-DELIVER-", 1 << 20);
    let frames_before = t.a.shaping("link_shaping_frames_real");
    let err =
        t.a.transport
            .send(&t.b.key.key_id, &deliver)
            .await
            .expect_err("no unshaped link: the send is refused");
    assert!(
        err.to_string().contains("link_shaping_bulk_refused"),
        "by name: {err}"
    );
    assert_eq!(t.a.shaping("link_shaping_bulk_refused"), 1);
    assert_eq!(t.a.transport.refused_dials_for_test(), 1);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !t.b.received(&deliver).await,
        "nothing of it crossed the shaped link"
    );
    assert!(
        t.a.shaping("link_shaping_frames_real") <= frames_before + 2,
        "the shaped link carried rows and reports, not a file: {:?}",
        t.a.metrics.link_shaping()
    );
}

/// The first link `n` dialled is its shaped row link: wait until its stream
/// has run on for ten frames, then assert that once shaped every frame on it
/// is the one agreed size. Returns that link and the whole tap.
async fn assert_shaped_stream_constant(n: &Node) -> ([u8; 16], Vec<([u8; 16], Vec<u8>)>) {
    // The shaped link's stream runs on at λ (about one frame a second at
    // this budget) whatever the bulk plane did: let it accumulate a run.
    let shaped = n
        .transport
        .link_wire_tapped_for_test()
        .first()
        .expect("B dialled")
        .0;
    assert!(
        wait_until(Duration::from_secs(60), || async {
            let w = n.transport.link_wire_tapped_for_test();
            trailing_run(&frames_on(&w, shaped)).1 >= 10
        })
        .await,
        "the shaped link keeps its constant stream"
    );
    let wire = n.transport.link_wire_tapped_for_test();
    let frames = frames_on(&wire, shaped);
    let (size, run) = trailing_run(&frames);
    assert!(
        run >= 10,
        "the shaped link keeps its stream: {run} × {size} B"
    );
    let first = frames
        .iter()
        .position(|f| f.len() == size)
        .expect("shaped frames");
    assert!(
        frames[first..].iter().all(|f| f.len() == size),
        "once shaped, every frame on the shaped link is {size} B: {:?}",
        frames[first..]
            .iter()
            .map(Vec::len)
            .filter(|&l| l != size)
            .collect::<Vec<_>>()
    );
    (shaped, wire)
}

/// The negative cache: a second bulk send to the NAT'd peer goes straight to
/// its shaped link, with no second failed dial.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_cannot_be_dialled_costs_one_failed_dial_not_one_per_send() {
    let _host = share_host().await;
    let server = policy(BudgetClass::Server, 100_000, 0.5, 10, false);
    let t = duo("negative", server.clone(), server).await;
    let row = typed_payload("AttestationGossip", b"NEG-ROW-", 2_000);
    t.b.transport
        .send(&t.a.key.key_id, &row)
        .await
        .expect("B dials A");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(&row).await
        })
        .await
    );
    t.a.transport.refuse_outbound_dials_for_test(true);
    for marker in [&b"NEG-ONE-"[..], &b"NEG-TWO-"[..]] {
        let deliver = typed_payload("AttestationGossip", marker, 128 * 1024);
        let err =
            t.a.transport
                .send(&t.b.key.key_id, &deliver)
                .await
                .expect_err("a bulk Deliver to a peer A cannot dial is refused");
        assert!(
            err.to_string().contains("link_shaping_bulk_refused"),
            "{err}"
        );
    }
    assert_eq!(t.a.shaping("link_shaping_bulk_refused"), 2);
    assert_eq!(
        t.a.transport.refused_dials_for_test(),
        1,
        "the second send skipped the dial"
    );
}

/// **The row limit** (Eric, 2026-11-04): 64 KiB, whatever the type, and not
/// the window budget. This budget's window holds 1 MB, so the 512 KiB Deliver
/// fits it and moves only because of the limit. Mutation: raise
/// `SHAPED_ROW_MAX_BYTES` to the window budget → this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_512_kib_deliver_takes_the_bulk_link_and_a_4_kib_deliver_stays_shaped() {
    let _host = share_host().await;
    let server = policy(BudgetClass::Server, 200_000, 0.5, 10, false);
    let t = duo("rowlimit", server.clone(), server).await;
    t.b.transport.set_link_wire_tap_for_test(true);
    let small = typed_payload("AttestationGossip", b"ROW-4K-", 4 * 1024);
    t.b.transport
        .send(&t.a.key.key_id, &small)
        .await
        .expect("4 KiB");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(&small).await
        })
        .await
    );
    let wire = t.b.transport.link_wire_tapped_for_test();
    let shaped = wire.first().expect("B dialled").0;
    assert!(
        wire.iter().all(|(l, _)| *l == shaped),
        "4 KiB stayed on the shaped link: no second link"
    );
    let reals = t.b.shaping("link_shaping_frames_real");
    let big = typed_payload("AttestationGossip", b"ROW-512K-", 512 * 1024);
    t.b.transport
        .send(&t.a.key.key_id, &big)
        .await
        .expect("512 KiB");
    assert!(
        wait_until(Duration::from_secs(60), || async {
            t.a.received(&big).await
        })
        .await
    );
    let on_other_links: usize =
        t.b.transport
            .link_wire_tapped_for_test()
            .iter()
            .filter(|(l, _)| *l != shaped)
            .map(|(_, f)| f.len())
            .sum();
    assert!(
        on_other_links >= 512 * 1024,
        "512 KiB crossed on the bulk link: {on_other_links} B"
    );
    assert_eq!(
        t.b.shaping("link_shaping_frames_real"),
        reals,
        "no real frame of it entered the shaper"
    );
}

/// **The cap limits rate, not whether**, between two real nodes: A's node cap
/// is under one link's agreed rate, so its share is a fraction of it, and the
/// link is still shaped both ways and still carries a row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_over_the_node_cap_is_shaped_at_its_share() {
    let _host = share_host().await;
    let mut capped = policy(BudgetClass::Server, 100_000, 0.5, 10, false);
    capped.node_cap_bytes_per_s = 2_000;
    let t = duo(
        "share",
        capped,
        policy(BudgetClass::Server, 100_000, 0.5, 10, false),
    )
    .await;
    let row = typed_payload("AttestationGossip", b"SHARE-ROW-", 2_000);
    t.a.transport
        .send(&t.b.key.key_id, &row)
        .await
        .expect("A -> B");
    assert!(
        wait_until(Duration::from_secs(60), || async {
            t.b.received(&row).await
        })
        .await
    );
    assert_eq!(
        t.a.shaping("link_shaping_agreed"),
        1,
        "{:?}",
        t.a.metrics.link_shaping()
    );
    assert_eq!(
        t.b.shaping("link_shaping_agreed"),
        1,
        "{:?}",
        t.b.metrics.link_shaping()
    );
    assert_eq!(t.a.transport.shaped_link_count(), 1);
}

/// **The bound, on a real pair** (Eric, 2026-11-04): A is a server at its
/// shaped-link bound (`max_links` 0 stands for eight full). B, a shaping peer,
/// dials for a row: A refuses by name, the row link closes and never runs
/// unshaped, B's send fails with the token and its next row send fails
/// without a dial. B's 1 MiB bulk transfer still completes, on an unshaped
/// link of its own. Mutation: run the refused link unshaped for rows → fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn at_the_bound_a_shaping_peers_row_link_is_refused_and_its_bulk_still_crosses() {
    let _host = share_host().await;
    let mut full = policy(BudgetClass::Server, 100_000, 0.5, 10, true);
    full.share = ShapedSharePolicy::BoundedWithFloor {
        max_links: 0,
        floor_bytes_per_s: 100_000,
    };
    let t = duo(
        "bound",
        full,
        policy(BudgetClass::Server, 100_000, 0.5, 10, false),
    )
    .await;
    let row = typed_payload("AttestationGossip", b"BOUND-ROW-", 2_000);
    let err =
        t.b.transport
            .send(&t.a.key.key_id, &row)
            .await
            .expect_err("A at its bound refuses B's row link");
    assert!(
        err.to_string().contains("link_shaping_home_elsewhere"),
        "{err}"
    );
    assert!(
        wait_until(Duration::from_secs(10), || async {
            t.a.shaping("link_shaping_home_elsewhere") >= 1
        })
        .await,
        "A counts the refusal: {:?}",
        t.a.metrics.link_shaping()
    );
    assert_eq!(
        t.b.shaping("link_shaping_home_elsewhere"),
        1,
        "{:?}",
        t.b.metrics.link_shaping()
    );
    // v44 — one number used to count both ends. Only the refuser is at its
    // bound; the refused node's count says nothing about its own room.
    assert_eq!(t.a.shaping("link_shaping_home_elsewhere:given"), 1);
    assert_eq!(t.a.shaping("link_shaping_home_elsewhere:received"), 0);
    assert_eq!(t.b.shaping("link_shaping_home_elsewhere:received"), 1);
    assert_eq!(t.b.shaping("link_shaping_home_elsewhere:given"), 0);
    assert_eq!(t.a.transport.shaped_link_count(), 0);
    assert!(!t.a.received(&row).await, "the row never crossed unshaped");
    let err =
        t.b.transport
            .send(&t.a.key.key_id, &row)
            .await
            .expect_err("the next row send fails without a dial");
    assert!(
        err.to_string().contains("link_shaping_home_elsewhere"),
        "{err}"
    );
    assert_eq!(
        t.b.shaping("link_shaping_home_elsewhere"),
        1,
        "no second refusal on the wire"
    );
    let blob = typed_payload("BlobChunkBody", b"BOUND-BULK-", 1 << 20);
    t.b.transport
        .send(&t.a.key.key_id, &blob)
        .await
        .expect("bulk rides an unshaped link of its own");
    assert!(
        wait_until(Duration::from_secs(60), || async {
            t.a.received(&blob).await
        })
        .await
    );
    assert_eq!(
        t.a.transport.shaped_link_count(),
        0,
        "still nothing shaped at A"
    );
}

/// **`CLM-shaped-link-bound-refuse`, CIRISEdge#952** — eight shaped links do not
/// stop new connections. A is at its bound and is neither shaped-only nor in
/// the anonymous tier: B's row link stays up unshaped at BOTH ends, the row
/// crosses, and the next one rides the same link with no second offer. Two ends
/// that disagree would close on the first frame of the wrong kind. Mutation:
/// refuse past the bound regardless → this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn at_the_bound_a_ninth_shaping_peer_runs_unshaped_and_its_rows_move() {
    let _host = share_host().await;
    let mut full = policy(BudgetClass::Server, 100_000, 0.5, 10, false);
    full.share = ShapedSharePolicy::BoundedWithFloor {
        max_links: 0,
        floor_bytes_per_s: 100_000,
    };
    let t = duo(
        "ninth",
        full,
        policy(BudgetClass::Server, 100_000, 0.5, 10, false),
    )
    .await;
    let row = typed_payload("AttestationGossip", b"NINTH-ROW-", 2_000);
    t.b.transport
        .send(&t.a.key.key_id, &row)
        .await
        .expect("the ninth link runs");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(&row).await
        })
        .await,
        "the row crossed: {:?}",
        t.a.metrics.link_shaping()
    );
    assert_eq!(t.a.shaping("link_shaping_unshaped:past_bound"), 1);
    assert_eq!(t.a.shaping("link_shaping_home_elsewhere"), 0);
    assert_eq!(t.b.shaping("link_shaping_home_elsewhere"), 0);
    assert_eq!(t.a.transport.shaped_link_count(), 0, "unshaped at A");
    assert_eq!(t.b.transport.shaped_link_count(), 0, "and at B");
    let next = typed_payload("AttestationGossip", b"NINTH-NEXT-", 2_000);
    t.b.transport
        .send(&t.a.key.key_id, &next)
        .await
        .expect("the next row rides the same link");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(&next).await
        })
        .await
    );
    assert_eq!(
        t.a.shaping("link_shaping_unshaped:past_bound"),
        1,
        "one link, one answer"
    );
}

/// A dialler past its OWN bound offers nothing, so the peer never starts a
/// shaper alone. Mutation: offer past the bound → the views disagree.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn past_its_own_bound_a_dialler_offers_nothing_and_both_ends_agree() {
    let _host = share_host().await;
    let mut full = policy(BudgetClass::Server, 100_000, 0.5, 10, false);
    full.share = ShapedSharePolicy::BoundedWithFloor {
        max_links: 0,
        floor_bytes_per_s: 100_000,
    };
    let t = duo(
        "ownbound",
        policy(BudgetClass::Server, 100_000, 0.5, 10, false),
        full,
    )
    .await;
    let row = typed_payload("AttestationGossip", b"OWN-ROW-", 2_000);
    t.b.transport
        .send(&t.a.key.key_id, &row)
        .await
        .expect("B, past its bound, still connects");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(&row).await
        })
        .await
    );
    assert_eq!(t.b.shaping("link_shaping_unshaped:past_bound"), 1);
    assert_eq!(t.b.shaping("link_shaping_offered"), 0);
    assert_eq!(t.a.shaping("link_shaping_offered"), 0);
    assert_eq!(t.a.transport.shaped_link_count(), 0);
    assert_eq!(t.b.transport.shaped_link_count(), 0);
}

/// A peer whose class is Off is not a shaping peer: at A's bound its row
/// link runs unshaped, as CC 5.4.3 "either side off" says, and the row crosses.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn at_the_bound_an_off_peer_still_gets_an_ordinary_unshaped_link() {
    let _host = share_host().await;
    let mut full = policy(BudgetClass::Server, 100_000, 0.5, 10, false);
    full.share = ShapedSharePolicy::BoundedWithFloor {
        max_links: 0,
        floor_bytes_per_s: 100_000,
    };
    let t = duo("bound-off", full, explicit_off()).await;
    let row = typed_payload("AttestationGossip", b"OFF-ROW-", 2_000);
    t.b.transport
        .send(&t.a.key.key_id, &row)
        .await
        .expect("an off peer's row rides an unshaped link");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(&row).await
        })
        .await
    );
    assert_eq!(
        t.a.shaping("link_shaping_home_elsewhere"),
        0,
        "{:?}",
        t.a.metrics.link_shaping()
    );
    // An off peer sends no offer, so there is nothing for A to answer or
    // count: the row crossing on an unshaped link is the witness.
    assert_eq!(t.a.transport.shaped_link_count(), 0);
}

/// Frame size for the rate witness: about 37 frames/s at the seat row.
const RATE_FRAME_BYTES: u16 = 900;
/// How long the rate witness counts.
const RATE_WINDOW: Duration = Duration::from_secs(20);
/// A healthy stream is allowed to fall this far below λ: each gap is followed
/// by a timer wake and a send, which on a real link are not free (measured
/// about 5% at the 16 KB frame), so a real stream runs under a pure Poisson's.
const STREAM_SLOWDOWN_ALLOWED: f64 = 0.8;
/// The false-failure rate of each side of the rate witness.
const STREAM_FALSE_FAILURE: f64 = 1e-6;

/// `ln P(X = k)` for `X ~ Poisson(mu)`.
#[allow(clippy::cast_precision_loss)] // counts far below 2^52
fn poisson_ln_pmf(k: u64, mu: f64) -> f64 {
    let ln_factorial: f64 = (2..=k).map(|i| (i as f64).ln()).sum();
    k as f64 * mu.ln() - mu - ln_factorial
}

/// `P(X >= k)` for `X ~ Poisson(mu)`.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // a small positive μ
fn poisson_tail(k: u64, mu: f64) -> f64 {
    let far = k + 40 + (20.0 * mu.sqrt()) as u64;
    (k..far).map(|i| poisson_ln_pmf(i, mu).exp()).sum()
}

/// The counts a stream at rate `lambda` stays inside over `secs`, each side
/// failing an honest stream at most [`STREAM_FALSE_FAILURE`]: the floor from a
/// stream slowed by [`STREAM_SLOWDOWN_ALLOWED`], the ceiling from λ itself, as
/// nothing makes a stream run fast. Panics unless the floor also catches a
/// stream at HALF the rate, so a change of frame or window cannot quietly turn
/// this into a bound that passes a collapse.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // a small positive μ
fn stream_bounds(lambda: f64, secs: f64) -> (u64, u64) {
    let mu = lambda * secs;
    let slow = mu * STREAM_SLOWDOWN_ALLOWED;
    let mut floor = 0;
    let mut below = 0.0;
    loop {
        below += poisson_ln_pmf(floor, slow).exp();
        if below > STREAM_FALSE_FAILURE {
            break;
        }
        floor += 1;
    }
    let mut ceiling = mu as u64;
    while poisson_tail(ceiling + 1, mu) > STREAM_FALSE_FAILURE {
        ceiling += 1;
    }
    assert!(
        poisson_tail(floor, mu / 2.0) < STREAM_FALSE_FAILURE,
        "a stream at half the rate would pass a floor of {floor}"
    );
    (floor, ceiling)
}

/// The bounds come out as derived by hand, and they refuse to be built where
/// they could not see a stream at half the rate.
#[test]
fn stream_bounds_separate_a_healthy_rate_from_half_of_it() {
    let lambda = f64::from(SEAT_BYTES_PER_S) / f64::from(RATE_FRAME_BYTES);
    let (floor, ceiling) = stream_bounds(lambda, RATE_WINDOW.as_secs_f64());
    assert_eq!((floor, ceiling), (475, 866));
    assert!(
        std::panic::catch_unwind(|| stream_bounds(2.03, 10.0)).is_err(),
        "the old 10 s count at 2/s cannot see half the rate"
    );
}

/// **The `seat` class on a real pair** (CC 5.4.3 rc17, `CLM-seat-class`): two
/// nodes both named serve seats agree the table's 33,000 B/s (about 2 frames/s
/// at the loopback frame) and a row crosses; the frame stream runs at that
/// rate, bounded by [`stream_bounds`] at a smaller frame. A seat facing a node it cannot prove a seat runs at the normal class
/// (lower of the two offers).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_proved_seats_shape_at_the_seat_row_and_a_non_seat_gets_the_class() {
    let _host = share_host().await;
    let server = policy(BudgetClass::Server, 7_000, 0.5, 600, false);
    let t = duo("seats", server.clone(), server.clone()).await;
    let seats: std::collections::HashSet<String> = [t.a.key.key_id.clone(), t.b.key.key_id.clone()]
        .into_iter()
        .collect();
    t.a.transport.set_seats_for_test(seats.clone(), true);
    t.b.transport.set_seats_for_test(seats, true);
    let row = typed_payload("AttestationGossip", b"SEAT-ROW-", 2_000);
    t.b.transport
        .send(&t.a.key.key_id, &row)
        .await
        .expect("seat -> seat");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(&row).await
        })
        .await
    );
    let rates = t.b.transport.shaped_rates_for_test();
    assert!(
        rates.iter().any(|l| (l - 2.03).abs() < 0.05),
        "the seat link agreed 33,000 B/s: {rates:?}"
    );

    // The stream runs at that rate. The rate is bytes over frame, so a small
    // frame gives the count enough events to bound: this was once ~20 frames
    // in 10 s against 12..=32, which fails an honest stream about 1 run in 40
    // and cannot tell a stream at half the rate from a good one.
    let r = duo("seat-rate", server.clone(), server.clone()).await;
    let seats: std::collections::HashSet<String> = [r.a.key.key_id.clone(), r.b.key.key_id.clone()]
        .into_iter()
        .collect();
    for n in [&r.a, &r.b] {
        n.transport.set_seats_for_test(seats.clone(), true);
        n.transport
            .set_shaped_frame_cap_for_test(usize::from(RATE_FRAME_BYTES));
    }
    let row = typed_payload("AttestationGossip", b"SEAT-RATE-", 400);
    r.b.transport
        .send(&r.a.key.key_id, &row)
        .await
        .expect("seat -> seat");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            r.a.received(&row).await
        })
        .await
    );
    let lambda = r.b.transport.shaped_rates_for_test()[0];
    let nominal = f64::from(SEAT_BYTES_PER_S) / f64::from(RATE_FRAME_BYTES);
    assert!(
        (lambda / nominal - 1.0).abs() < 0.01,
        "the agreed rate is the seat row: {lambda} against {nominal}"
    );
    let (floor, ceiling) = stream_bounds(lambda, RATE_WINDOW.as_secs_f64());
    let count =
        || r.b.shaping("link_shaping_frames_real") + r.b.shaping("link_shaping_frames_cover");
    let frames0 = count();
    tokio::time::sleep(RATE_WINDOW).await;
    let frames = count() - frames0;
    eprintln!("seat stream: {frames} frames, bounds {floor}..={ceiling}");
    assert!(
        (floor..=ceiling).contains(&frames),
        "{frames} frames in {RATE_WINDOW:?} at {lambda}/s, bounds {floor}..={ceiling}"
    );

    // A seat and a node it cannot prove: the normal class.
    let u = duo("seat-nonseat", server.clone(), server).await;
    u.a.transport
        .set_seats_for_test([u.a.key.key_id.clone()].into_iter().collect(), true);
    let row = typed_payload("AttestationGossip", b"MIXED-ROW-", 2_000);
    u.b.transport
        .send(&u.a.key.key_id, &row)
        .await
        .expect("non-seat -> seat");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            u.a.received(&row).await
        })
        .await
    );
    let rates = u.b.transport.shaped_rates_for_test();
    assert!(
        rates.iter().all(|l| *l < 1.0),
        "the normal class: {rates:?}"
    );
}

/// CC 5.4.3 rc17 — one shaped link to a peer: a burst of concurrent rows from
/// a cold start shares it, so it spends one of the eight, at the full rate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_of_rows_to_a_peer_shares_one_shaped_link() {
    let _host = share_host().await;
    let server = policy(BudgetClass::Server, 100_000, 0.5, 10, false);
    let t = duo("oneline", server.clone(), server).await;
    let mut sends = Vec::new();
    let mut rows = Vec::new();
    for i in 0..8u8 {
        let row = typed_payload("AttestationGossip", format!("BURST-{i}-").as_bytes(), 2_000);
        rows.push(row.clone());
        let sender = Arc::clone(&t.b.transport);
        let to = t.a.key.key_id.clone();
        sends.push(tokio::spawn(async move { sender.send(&to, &row).await }));
    }
    for s in sends {
        s.await.expect("no panic").expect("a row sends");
    }
    for r in &rows {
        assert!(wait_until(Duration::from_secs(30), || async { t.a.received(r).await }).await);
    }
    assert_eq!(
        t.b.transport.shaped_link_count(),
        1,
        "one shaped link to the peer"
    );
    assert_eq!(t.b.shaping("link_shaping_agreed"), 1);
}

/// The announced owner-binding `delegates_to(owner → node)`, as
/// `attestation_bind::owner_binding_attestation` mints it.
async fn owner_binding_at(owner: &Ident, node: &str, cohort_scope: &str) -> Attestation {
    let asserted_at = ciris_edge::replication::attestation_bind::truncate_to_substrate_resolution(
        chrono::Utc::now(),
    );
    let attestation_id = format!("owner-binding-{node}");
    let subjects = vec![node.to_owned()];
    let mut envelope =
        ciris_persist::federation::self_at_login::owner_binding_delegates_to_envelope(
            node,
            &["infra:network_presence".to_string()],
        );
    bind_attestation_envelope(
        &mut envelope,
        asserted_at,
        &AttestationColumns {
            attestation_id: &attestation_id,
            attesting_key_id: &owner.key_id,
            attestation_type: "delegates_to",
            attested_key_id: node,
            subject_key_ids: &subjects,
            cohort_scope,
            weight: None,
        },
    );
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope).expect("canon");
    let digest = sha2::Sha256::digest(&canonical);
    let (sig_classical, sig_pqc) = sign_bound_hybrid(&owner.signer(), &canonical, "owner binding")
        .await
        .expect("hybrid sign");
    Attestation {
        attestation_id,
        attesting_key_id: owner.key_id.clone(),
        attested_key_id: node.to_owned(),
        attestation_type: "delegates_to".to_owned(),
        weight: None,
        asserted_at,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: sig_classical,
        scrub_signature_pqc: sig_pqc,
        scrub_key_id: owner.key_id.clone(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: subjects,
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope.to_owned(),
        // `tier` is where the row LIVES (persist's federation listings read
        // `tier = 'federation'` only — a `local` row is invisible to
        // `owner_of`); `cohort_scope` is the AUDIENCE. A claim's binding is a
        // federation-tier row at a `self` audience; the announce widens the
        // audience, never the tier.
        tier: "federation".to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    }
}

/// A policy with room: eight shaped links, each at the test's rate.
fn roomy(max_links: u32) -> ShapingPolicy {
    let mut p = policy(BudgetClass::Server, 100_000, 0.5, 10, false);
    p.share = ShapedSharePolicy::BoundedWithFloor {
        max_links,
        floor_bytes_per_s: 100_000,
    };
    p
}

/// One node of a referral witness.
#[allow(clippy::too_many_arguments)] // a test fixture, each a node's own fact
async fn start_node(
    tmp: &std::path::Path,
    key: Ident,
    policy: ShapingPolicy,
    device: DeviceState,
    records: Vec<ciris_persist::federation::KeyRecord>,
    bootstrap: Vec<u16>,
    publish: Option<Vec<String>>,
    silent: bool,
    tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) -> (Node, u16) {
    let dir = directory_with(records).await;
    let metrics = EdgeMetrics::new();
    let (transport, addr) = common::build_reticulum_with_retry_metrics(
        || {
            let base = tmp.join(&key.key_id);
            let signer = key.signer();
            let dir = Arc::clone(&dir);
            let policy = policy.clone();
            let bootstrap = bootstrap.clone();
            async move {
                let mut c =
                    ReticulumTransportConfig::new(base.join("transport.id"), &signer.key_id);
                c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
                c.bootstrap_peers = bootstrap
                    .iter()
                    .map(|p| format!("127.0.0.1:{p}").parse().unwrap())
                    .collect();
                c.announce_interval = Duration::from_secs(5);
                c.shaping = policy;
                c.device = device;
                (c, auth(signer, &dir))
            }
        },
        metrics.clone(),
    )
    .await;
    // Silent from birth: no announce of any kind has left this node.
    transport.set_unannounced_for_test(silent);
    // The production wiring when the node publishes: a runtime with no peers
    // of its own, rounds driven by the test.
    let mut runtime = None;
    if let Some(publish) = publish {
        runtime = Some(Arc::new(
            ReplicationRuntime::start(
                Arc::clone(&dir) as Arc<dyn FederationDirectory>,
                Arc::clone(&transport) as Arc<dyn Transport>,
                Vec::new(),
                ReplicationRuntimeConfig {
                    scheduler: SchedulerConfig {
                        cadence: Duration::from_secs(3600),
                        round_timeout: Duration::from_secs(15),
                        ..SchedulerConfig::default()
                    },
                    local_key_id: Some(key.key_id.clone()),
                    metrics: Some(metrics.clone()),
                    enable_bundle_bootstrap_peers: false,
                    ..Default::default()
                },
                Some(self_publish_set(publish)),
            )
            .await,
        ));
    }
    let router = runtime
        .as_ref()
        .map(|r: &Arc<ReplicationRuntime>| InboundRouter::new(r.registry()));
    let seen: Arc<Mutex<Vec<InboundFrame>>> = Arc::new(Mutex::new(Vec::new()));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<InboundFrame>(1024);
    let listener = Arc::clone(&transport);
    tasks.push(tokio::spawn(async move {
        let _ = listener.listen(tx).await;
    }));
    let sink = Arc::clone(&seen);
    tasks.push(tokio::spawn(async move {
        while let Some(f) = rx.recv().await {
            if let Some(router) = router.as_ref() {
                let _ = router.try_route(&f).await;
            }
            sink.lock().await.push(f);
        }
    }));
    (
        Node {
            key,
            transport,
            metrics,
            dir,
            seen,
            runtime,
            ladder: Arc::default(),
        },
        addr.port(),
    )
}

/// R, whose bound is its one link, and W, the node R holds that link to, with
/// room of its own. P, who has never heard of W, comes up later.
struct Referral {
    r: Node,
    w: Node,
    r_port: u16,
    w_port: u16,
    p_key: Option<Ident>,
    p_records: Vec<ciris_persist::federation::KeyRecord>,
    /// P must not hear of W until a referral names it.
    w_silent: bool,
    /// P runs a replication runtime.
    p_rounds: bool,
    tmp: tempfile::TempDir,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

async fn referral_pair(
    tag: &str,
    seed: u8,
    w_device: DeviceState,
    w_publishes: Option<&str>,
    w_silent: bool,
) -> Referral {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let r_key = Ident::new(&format!("node-r-{tag}"), seed).await;
    let w_key = Ident::new(&format!("node-w-{tag}"), seed + 1).await;
    let p_key = Ident::new(&format!("node-p-{tag}"), seed + 2).await;
    let (r_record, w_record, p_record) = (
        r_key.record().await,
        w_key.record().await,
        p_key.record().await,
    );
    let mut tasks = Vec::new();
    let all = vec![r_record.clone(), w_record.clone(), p_record.clone()];
    // Referrals close the link only on a node that refuses (CIRISEdge#952).
    let mut refuser = roomy(1);
    refuser.require_shaped_links = true;
    let (r, r_port) = start_node(
        tmp.path(),
        r_key,
        refuser,
        DeviceState::of(DeviceKind::Server),
        all.clone(),
        Vec::new(),
        None,
        false,
        &mut tasks,
    )
    .await;
    let publish = w_publishes.map(|z| vec![w_key.key_id.clone(), z.to_owned()]);
    let (w, w_port) = start_node(
        tmp.path(),
        w_key,
        roomy(8),
        w_device,
        all,
        vec![r_port],
        publish,
        w_silent,
        &mut tasks,
    )
    .await;
    seed_route(&r, &w).await;
    seed_route(&w, &r).await;
    if w_silent {
        // R, W's neighbour, holds W's binding out of band: W announces nothing.
        r.transport
            .prime_peer(
                &w.key.key_id,
                w.transport.local_named_dest_hash(),
                w.transport.local_transport_pubkey(),
            )
            .await
            .expect("W's own binding");
    }
    assert!(
        wait_until(Duration::from_secs(60), || async {
            w.transport.knows_peer(&r.key.key_id).await
                && r.transport.knows_peer(&w.key.key_id).await
        })
        .await,
        "R and W learn each other's announce"
    );
    let row = typed_payload("AttestationGossip", b"FILL-THE-BOUND-", 2_000);
    w.transport
        .send(&r.key.key_id, &row)
        .await
        .expect("W takes R's one slot");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            r.transport.shaped_link_count() == 1
                && r.transport.peer_free_slots(&w.key.key_id).is_some()
        })
        .await,
        "R holds W's first report"
    );
    Referral {
        r,
        w,
        r_port,
        w_port,
        p_key: Some(p_key),
        p_records: vec![p_record, r_record],
        w_silent,
        p_rounds: false,
        tmp,
        tasks,
    }
}

/// P, up now, knowing R and not W, is refused at R's bound.
async fn refused_peer(t: &mut Referral) -> Node {
    let key = t.p_key.take().expect("one P");
    let publish = t.p_rounds.then(|| vec![key.key_id.clone()]);
    let (p, _) = start_node(
        t.tmp.path(),
        key,
        roomy(8),
        DeviceState::of(DeviceKind::Server),
        t.p_records.clone(),
        vec![t.r_port, t.w_port],
        publish,
        false,
        &mut t.tasks,
    )
    .await;
    seed_route(&p, &t.r).await;
    seed_route(&t.r, &p).await;
    assert!(
        wait_until(Duration::from_secs(60), || async {
            p.transport.knows_peer(&t.r.key.key_id).await
        })
        .await
    );
    if t.w_silent {
        // Past W's announce interval, with a live interface to W: its
        // periodic announces are off too, so only a referral can name it.
        tokio::time::sleep(Duration::from_secs(8)).await;
        assert!(
            !p.transport.knows_peer(&t.w.key.key_id).await,
            "P has not heard of W"
        );
    }
    let row = typed_payload("AttestationGossip", b"REFUSED-ROW-", 2_000);
    let err = p
        .transport
        .send(&t.r.key.key_id, &row)
        .await
        .expect_err("R is at its bound");
    assert!(
        err.to_string().contains("link_shaping_home_elsewhere"),
        "{err}"
    );
    p
}

/// **The referral, end to end.** A node at its bound refuses a shaping peer,
/// and the refusal names W, a node with free slots that P has never heard of.
/// W is OWNED, and offering relay is what lets it be named (Eric 2026-11-04).
/// P dials it from the referral alone, W treats P as any shaping peer, and a
/// contact request and its acceptance cross that link while P's bulk to the
/// refuser still works. (The rows are typed bytes on the row plane: this pins
/// the transport, not persist's ceremony.) Mutation: empty the referrals → P
/// never reaches W and this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_peer_homes_on_a_referral_and_its_contact_completes_there() {
    let _host = share_host().await;
    let mut t = referral_pair(
        "home",
        0x3a,
        DeviceState::of(DeviceKind::Server),
        None,
        true,
    )
    .await;
    let owner = Ident::new("person-owns-w", 0x3f).await;
    t.r.dir
        .put_public_key(ciris_persist::prelude::SignedKeyRecord {
            record: owner.record_as("user").await,
        })
        .await
        .expect("the owner's key");
    let binding = owner_binding_at(&owner, &t.w.key.key_id, "federation").await;
    t.r.dir
        .put_attestation(SignedAttestation {
            attestation: binding,
        })
        .await
        .expect("W is owned, here");
    let w_id = t.w.key.key_id.clone();
    let r_id = t.r.key.key_id.clone();
    let p = refused_peer(&mut t).await;
    assert!(
        wait_until(Duration::from_secs(45), || async {
            p.transport.homed_on_referrals().contains(&w_id)
        })
        .await,
        "P homes on W: {:?}",
        p.metrics.link_shaping()
    );
    assert_eq!(t.r.shaping("link_shaping_referral_sent"), 1);
    assert_eq!(p.shaping("link_shaping_referral_homed"), 1);
    assert_eq!(p.transport.shaped_link_count(), 1, "shaped to W");

    let request = typed_payload("AttestationGossip", b"CONTACT-REQUEST-", 2_000);
    p.transport
        .send(&w_id, &request)
        .await
        .expect("the request");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.w.received(&request).await
        })
        .await
    );
    let acceptance = typed_payload("AttestationGossip", b"CONTACT-ACCEPT-", 2_000);
    t.w.transport
        .send(&p.key.key_id, &acceptance)
        .await
        .expect("the acceptance");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            p.received(&acceptance).await
        })
        .await
    );

    let blob = typed_payload("BlobChunkBody", b"REFERRAL-BULK-", 1 << 20);
    p.transport
        .send(&r_id, &blob)
        .await
        .expect("the refuser's bulk link");
    assert!(
        wait_until(Duration::from_secs(60), || async {
            t.r.received(&blob).await
        })
        .await
    );
}

/// **Offering relay is the consent.** W has free slots and its relay offering
/// off: it reports nothing, R names nobody, and P is left its fallback order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_with_its_relay_offering_off_is_never_referred() {
    let _host = share_host().await;
    let mut off = DeviceState::of(DeviceKind::Server);
    off.relay_override = Some(false);
    let mut t = referral_pair("off", 0x4a, off, None, false).await;
    assert_eq!(t.r.transport.peer_free_slots(&t.w.key.key_id), Some(0));
    let p = refused_peer(&mut t).await;
    assert!(
        wait_until(Duration::from_secs(20), || async {
            p.shaping("link_shaping_referral_exhausted") == 1
        })
        .await,
        "{:?}",
        p.metrics.link_shaping()
    );
    assert_eq!(t.r.shaping("link_shaping_referral_empty"), 1);
    assert_eq!(t.r.shaping("link_shaping_referral_sent"), 0);
    assert!(p.transport.homed_on_referrals().is_empty());
}

/// **A phone that loses Wi-Fi stops being referred on its next report.** A
/// relay-capable node of phone class, for when phones can relay: every v44
/// phone is client-only. The link stays up, so it is the report that takes the
/// phone out, not a close.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_phone_that_loses_wifi_stops_being_referred_on_the_next_report() {
    let _host = share_host().await;
    let mut capable = DeviceState::of(DeviceKind::Phone);
    capable.client_only = false;
    let mut t = referral_pair("wifi", 0x5a, capable, None, false).await;
    assert!(t.r.transport.peer_free_slots(&t.w.key.key_id) > Some(0));
    t.w.transport
        .onion()
        .set_device(capable.with_network(false, true));
    t.w.transport.onion_refresh();
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.r.transport.peer_free_slots(&t.w.key.key_id) == Some(0)
        })
        .await
    );
    assert_eq!(t.r.transport.shaped_link_count(), 1, "the link stayed up");
    let p = refused_peer(&mut t).await;
    assert!(
        wait_until(Duration::from_secs(20), || async {
            p.shaping("link_shaping_referral_exhausted") == 1
        })
        .await
    );
    assert_eq!(t.r.shaping("link_shaping_referral_sent"), 0);
}

/// CC 5.4.6 rc17 `CLM-referred-peer-is-proxy` — **a node that turns on the
/// Anonymous Tier stops being referred on its next report**: it holds the
/// anonymous identity alone and proxies nothing, so its free slots go to zero
/// with the link still up, and a refused peer gets no referral to it. The
/// opt-in alone does it: the tier need not be available. Mutation: drop the
/// opt-in from `relay_offering` → W keeps its slots and is referred.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_onion_enabled_node_reports_no_capacity_and_is_never_referred() {
    let _host = share_host().await;
    let mut t = referral_pair(
        "anon",
        0x7a,
        DeviceState::of(DeviceKind::Server),
        None,
        false,
    )
    .await;
    assert!(t.r.transport.peer_free_slots(&t.w.key.key_id) > Some(0));
    t.w.transport
        .onion()
        .set_policy(ciris_edge::onion::policy::OnionPolicy {
            enabled: true,
            ..ciris_edge::onion::policy::OnionPolicy::default()
        });
    t.w.transport.onion_refresh();
    assert!(!t.w.transport.onion().relay_offering());
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.r.transport.peer_free_slots(&t.w.key.key_id) == Some(0)
        })
        .await
    );
    assert_eq!(t.r.transport.shaped_link_count(), 1, "the link stayed up");
    let p = refused_peer(&mut t).await;
    assert!(
        wait_until(Duration::from_secs(20), || async {
            p.shaping("link_shaping_referral_exhausted") == 1
        })
        .await,
        "{:?}",
        p.metrics.link_shaping()
    );
    assert_eq!(t.r.shaping("link_shaping_referral_sent"), 0);
    assert!(p.transport.homed_on_referrals().is_empty());
}

/// **A homed node is really used.** Edge registers the node P homed on as a
/// replication peer on the bootstrap planes by itself: no host adds it, and a
/// host's later peer set does not drop it. A key record P can have from nowhere
/// else crosses on P's own round to W. Mutation: drop the forwarder → the
/// record never arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_homed_node_is_a_replication_peer_on_the_bootstrap_planes() {
    let _host = share_host().await;
    let z = Ident::new("node-z-rounds", 0x6f).await;
    let mut t = referral_pair(
        "rounds",
        0x6a,
        DeviceState::of(DeviceKind::Server),
        Some(&z.key_id),
        false,
    )
    .await;
    t.w.dir
        .put_public_key(ciris_persist::prelude::SignedKeyRecord {
            record: z.record().await,
        })
        .await
        .expect("Z's record, at W only");
    t.p_rounds = true;
    let w_id = t.w.key.key_id.clone();
    let p = refused_peer(&mut t).await;
    let held = || async {
        FederationDirectory::lookup_public_key(&*p.dir, &z.key_id)
            .await
            .ok()
            .flatten()
            .is_some()
    };
    assert!(
        wait_until(Duration::from_secs(45), || async {
            p.transport.homed_on_referrals().contains(&w_id)
        })
        .await
    );
    assert!(!held().await, "P holds nothing of Z yet");
    let runtime = p.runtime.as_ref().expect("P rounds");
    // The forwarder registers within moments; a host's peer set then keeps it.
    tokio::time::sleep(Duration::from_secs(1)).await;
    runtime
        .set_peers(Vec::new())
        .await
        .expect("a host's peer set");
    assert!(
        wait_until(Duration::from_secs(60), || async {
            let _ = runtime.round_now_all().await;
            tokio::time::sleep(Duration::from_millis(750)).await;
            held().await
        })
        .await,
        "Z's record crossed on P's own round to W: {:?}",
        p.metrics.link_shaping()
    );
}

/// E14 — **a client-only node never reports slots**: on Wi-Fi, charging, with
/// the user's relay override on and shaped links to spare.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_only_node_never_reports_slots() {
    let _host = share_host().await;
    let mut phone = DeviceState::of(DeviceKind::Phone);
    phone.relay_override = Some(true);
    let t = referral_pair("client", 0x7a, phone, None, false).await;
    assert_eq!(t.r.transport.peer_free_slots(&t.w.key.key_id), Some(0));
}

/// E17 and E2 — **Wi-Fi-only shaping.** A phone opted in on Wi-Fi and not on
/// cellular: the move to cellular closes its shaped link and rows then cross
/// unshaped; the move back closes that unshaped link at once (E2), and the next
/// row is shaped again. Mutation: one opt-in for both classes → the cellular leg
/// stays shaped. Mutation: leave the unshaped link open → the last leg does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wifi_only_shaping_renegotiates_to_off_on_cellular_and_back() {
    let _host = share_host().await;
    let mut wifi = DeviceState::of(DeviceKind::Phone);
    wifi.shaping_opt_in = true;
    let mut fast = ShapingPolicy::for_device(&wifi);
    fast.bytes_per_s = 100_000;
    let t = duo("e17", roomy(8), fast).await;
    let a_id = t.a.key.key_id.clone();
    let on_wifi = typed_payload("AttestationGossip", b"ON-WIFI-", 2_000);
    t.b.transport
        .send(&a_id, &on_wifi)
        .await
        .expect("a shaped row");
    assert!(
        wait_until(Duration::from_secs(60), || async {
            t.a.received(&on_wifi).await
        })
        .await
    );
    assert_eq!(t.b.transport.shaped_link_count(), 1);
    assert_eq!(t.b.shaping("link_shaping_policy_moved"), 0);

    let cellular = wifi.with_network(false, true);
    assert_eq!(
        t.b.transport.set_device_state(cellular).await,
        1,
        "renegotiated"
    );
    assert_eq!(t.b.shaping("link_shaping_policy_moved"), 1);
    assert_eq!(t.b.transport.shaped_link_count(), 0);
    let on_cell = typed_payload("AttestationGossip", b"ON-CELL-", 2_000);
    t.b.transport
        .send(&a_id, &on_cell)
        .await
        .expect("an unshaped row");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(&on_cell).await
        })
        .await
    );
    assert_eq!(t.b.transport.shaped_link_count(), 0, "off on cellular");

    assert_eq!(
        t.b.transport.set_device_state(wifi).await,
        1,
        "E2: closed at once"
    );
    let back = typed_payload("AttestationGossip", b"BACK-ON-WIFI-", 2_000);
    t.b.transport
        .send(&a_id, &back)
        .await
        .expect("a shaped row again");
    assert!(
        wait_until(Duration::from_secs(90), || async {
            t.a.received(&back).await
        })
        .await
    );
    assert_eq!(t.b.transport.shaped_link_count(), 1, "restored");
}

/// E10 — **a node that chose not to be listed is never referred.** W is owned,
/// offers relay and has free slots, and its owner binding is at `self` scope: it
/// has not announced, so R names nobody. Mutation: drop the binding test → R
/// names W.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owned_node_that_has_not_announced_is_never_referred() {
    let _host = share_host().await;
    let mut t = referral_pair(
        "self",
        0x8a,
        DeviceState::of(DeviceKind::Server),
        None,
        false,
    )
    .await;
    let owner = Ident::new("person-keeps-w", 0x8f).await;
    t.r.dir
        .put_public_key(ciris_persist::prelude::SignedKeyRecord {
            record: owner.record_as("user").await,
        })
        .await
        .expect("the owner's key");
    let binding = owner_binding_at(&owner, &t.w.key.key_id, "self").await;
    t.r.dir
        .put_attestation(SignedAttestation {
            attestation: binding,
        })
        .await
        .expect("W is owned, unannounced");
    assert!(t.r.transport.peer_free_slots(&t.w.key.key_id) > Some(0));
    let p = refused_peer(&mut t).await;
    assert!(
        wait_until(Duration::from_secs(20), || async {
            p.shaping("link_shaping_referral_exhausted") == 1
        })
        .await,
        "{:?}",
        p.metrics.link_shaping()
    );
    assert_eq!(t.r.shaping("link_shaping_referral_sent"), 0);
    assert_eq!(t.r.shaping("link_shaping_referral_withheld"), 1);
}

// ─── E15, `FSD/PRIVACY_MODES.md` §6.12: shed levers on shaped slots ────────

/// `n` reads what it owes a peer from its own directory and bridge, as
/// `Edge::build` wires it. `recognised` is the seats it holds from config.
fn read_obligations(n: &Node, recognised: &[&str]) -> Arc<RwLock<HashSet<String>>> {
    let recognised = Arc::new(RwLock::new(
        recognised.iter().map(|k| (*k).to_owned()).collect(),
    ));
    n.transport
        .install_peer_obligations(Arc::new(LivePeerObligations::new(
            Arc::clone(&n.dir) as Arc<dyn FederationDirectory>,
            n.key.key_id.clone(),
            Arc::clone(&recognised),
            n.runtime.as_ref().expect("a runtime").bridge(),
        )));
    recognised
}

/// One person, P, owning `nodes`: the rows live in `at`'s directory.
async fn own_nodes(at: &Node, seed: u8, nodes: &[&str]) {
    let owner = Ident::new("person-owns-the-star", seed).await;
    at.dir
        .put_public_key(ciris_persist::prelude::SignedKeyRecord {
            record: owner.record_as("user").await,
        })
        .await
        .expect("the owner's key");
    for node in nodes {
        at.dir
            .put_attestation(SignedAttestation {
                attestation: owner_binding_at(&owner, node, "self").await,
            })
            .await
            .expect("the owner binding");
    }
}

/// R, which reads obligations, and one spoke per name, each of which knows R.
struct Star {
    r: Node,
    spokes: Vec<Node>,
    _tmp: tempfile::TempDir,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

async fn star(tag: &str, seed: u8, spokes: usize) -> Star {
    star_of(tag, seed, spokes, roomy(8)).await
}

/// [`star`], with a shaped-only hub: the one that refuses (CIRISEdge#952).
async fn star_shaped_only(tag: &str, seed: u8, spokes: usize) -> Star {
    let mut hub = roomy(8);
    hub.require_shaped_links = true;
    star_of(tag, seed, spokes, hub).await
}

async fn star_of(tag: &str, seed: u8, spokes: usize, hub: ShapingPolicy) -> Star {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let r_key = Ident::new(&format!("node-r-{tag}"), seed).await;
    let mut keys = Vec::new();
    let mut records = vec![r_key.record().await];
    for i in 0..spokes {
        let key = Ident::new(
            &format!("node-s{i}-{tag}"),
            seed + 1 + u8::try_from(i).unwrap(),
        )
        .await;
        records.push(key.record().await);
        keys.push(key);
    }
    let mut tasks = Vec::new();
    let publish = Some(vec![r_key.key_id.clone()]);
    let (r, r_port) = start_node(
        tmp.path(),
        r_key,
        hub,
        DeviceState::of(DeviceKind::Server),
        records.clone(),
        Vec::new(),
        publish,
        false,
        &mut tasks,
    )
    .await;
    let mut nodes = Vec::new();
    // Each spoke has an interface to R and to the spokes before it, so a
    // referral to one of them can be dialled.
    let mut ports = vec![r_port];
    for key in keys {
        let (n, port) = start_node(
            tmp.path(),
            key,
            roomy(8),
            DeviceState::of(DeviceKind::Server),
            records.clone(),
            ports.clone(),
            None,
            false,
            &mut tasks,
        )
        .await;
        ports.push(port);
        seed_route(&r, &n).await;
        seed_route(&n, &r).await;
        assert!(
            wait_until(Duration::from_secs(60), || async {
                n.transport.knows_peer(&r.key.key_id).await
                    && r.transport.knows_peer(&n.key.key_id).await
            })
            .await,
            "the spoke and R know each other"
        );
        nodes.push(n);
    }
    Star {
        r,
        spokes: nodes,
        _tmp: tmp,
        _tasks: tasks,
    }
}

/// `n` dials R, and the link is shaped at R.
async fn shape_to(r: &Node, n: &Node, marker: &[u8]) {
    let row = typed_payload("AttestationGossip", marker, 2_000);
    n.transport
        .send(&r.key.key_id, &row)
        .await
        .expect("the spoke dials R");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            r.transport.peer_shaping(&n.key.key_id).shaped_now
        })
        .await,
        "shaped at R: {:?}",
        r.metrics.link_shaping()
    );
}

/// **Tier 1 on real links.** R holds W's shaped link and has room. At tier 1 a
/// stranger is refused with a referral to W and homes there, R's report on the
/// wire says zero, and the owner's device and a seat dial in as if nothing had
/// changed. Mutation: drop either exemption, or `load_refuses` → this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e15_tier_one_refuses_a_stranger_with_a_referral_and_admits_the_protected() {
    let _host = share_host().await;
    let t = star_shaped_only("t1", 0x90, 4).await;
    let Star {
        r,
        spokes,
        _tmp,
        _tasks,
    } = t;
    let [w, stranger, device, seat] = <[Node; 4]>::try_from(spokes).ok().expect("four");
    read_obligations(&r, &[seat.key.key_id.as_str()]);
    own_nodes(
        &r,
        0x9f,
        &[r.key.key_id.as_str(), device.key.key_id.as_str()],
    )
    .await;
    shape_to(&r, &w, b"T1-W-").await;
    assert!(
        wait_until(Duration::from_secs(30), || async {
            r.transport.peer_free_slots(&w.key.key_id).is_some()
                && w.transport.peer_free_slots(&r.key.key_id) > Some(0)
        })
        .await,
        "each holds the other's report"
    );
    assert_eq!(r.transport.shaping_status().free_slots, 7);

    r.transport
        .set_service_tier(ciris_edge::ServiceTier::AudioAndFiles);
    let status = r.transport.shaping_status();
    assert_eq!((status.free_slots, status.reported_slots), (0, 0));
    assert!(status.admit_closed);
    assert!(
        wait_until(Duration::from_secs(30), || async {
            w.transport.peer_free_slots(&r.key.key_id) == Some(0)
        })
        .await,
        "the zero crossed the wire to W"
    );

    let row = typed_payload("AttestationGossip", b"T1-STRANGER-", 2_000);
    let err = stranger
        .transport
        .send(&r.key.key_id, &row)
        .await
        .expect_err("a stranger at tier 1");
    assert!(
        err.to_string().contains("link_shaping_home_elsewhere"),
        "{err}"
    );
    assert_eq!(r.shaping("load_refuse:admit_closed"), 1);
    assert_eq!(r.shaping("link_shaping_referral_sent"), 1, "never bare");
    assert!(
        wait_until(Duration::from_secs(45), || async {
            stranger
                .transport
                .homed_on_referrals()
                .contains(&w.key.key_id)
        })
        .await,
        "the stranger homes on W: {:?}",
        stranger.metrics.link_shaping()
    );

    shape_to(&r, &device, b"T1-DEVICE-").await;
    shape_to(&r, &seat, b"T1-SEAT-").await;
    assert_eq!(
        r.shaping("load_refuse:admit_closed"),
        1,
        "the owner's device and the seat were admitted"
    );
    assert_eq!(r.transport.shaped_link_count(), 3);
    assert!(!r.received(&row).await, "the refused row stayed off");
}

/// **Admit-close stops a slot, not a connection** (CIRISEdge#952). At tier 1 a
/// node that did not opt in to refusing answers a stranger `off`, with its
/// referrals as a hint, and the link stays up unshaped at both ends: a load
/// tier is no more a reason to drop a dialler than eight shaped links are.
/// Mutation: refuse at tier 1 regardless → this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e15_tier_one_keeps_a_strangers_link_unshaped_on_a_node_that_did_not_opt_in() {
    let _host = share_host().await;
    let t = star("t1soft", 0xc0, 1).await;
    let Star {
        r,
        spokes,
        _tmp,
        _tasks,
    } = t;
    let [stranger] = <[Node; 1]>::try_from(spokes).ok().expect("one");
    read_obligations(&r, &[]);
    r.transport
        .set_service_tier(ciris_edge::ServiceTier::AudioAndFiles);
    let row = typed_payload("AttestationGossip", b"T1SOFT-ROW-", 2_000);
    stranger
        .transport
        .send(&r.key.key_id, &row)
        .await
        .expect("the link stands, unshaped");
    assert!(
        wait_until(Duration::from_secs(30), || async { r.received(&row).await }).await,
        "the row crossed: {:?}",
        r.metrics.link_shaping()
    );
    assert_eq!(r.shaping("load_refuse:admit_closed"), 1, "no slot, by name");
    assert_eq!(r.shaping("link_shaping_home_elsewhere"), 0);
    assert_eq!(r.transport.shaped_link_count(), 0);
    assert_eq!(stranger.transport.shaped_link_count(), 0);
}

/// **Tier 2 on real links.** Two strangers' links close newest first, one step
/// at a time. The owner's device, a seat and a link R dialled stand, and their
/// rows cross at the unchanged real budget, cover running at the unchanged
/// rate. A tombstone on the seat loses its protection on the next step, with
/// no restart: the roster is the active one. Mutation: drop the owner's or the
/// seat's exemption, read a baked roster, or never shed → this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e15_tier_two_closes_strangers_newest_first_and_never_the_protected() {
    let _host = whole_host().await;
    let mut whole = false;
    for (tag, seed) in [("t2", 0xa0), ("t2b", 0xc0), ("t2c", 0xd0)] {
        whole = Box::pin(tier_two_story(tag, seed)).await;
        if whole {
            break;
        }
    }
    assert!(whole, "every star lost a link before its five stood");
}

/// One star of the witness above: whether its five links stood together. The
/// order they shaped in is the witness, so a link a starved responder lost on
/// the way (leviculum spent its retries; the shaper says so) is a new star,
/// not a redial. A link gone with nothing counting it panics.
#[allow(clippy::too_many_lines)] // one tier's whole story, in order
async fn tier_two_story(tag: &str, seed: u8) -> bool {
    let t = star_shaped_only(tag, seed, 5).await;
    let Star {
        r,
        spokes,
        _tmp,
        _tasks,
    } = t;
    let [older, newer, device, seat, dialled] = <[Node; 5]>::try_from(spokes).ok().expect("five");
    read_obligations(&r, &[seat.key.key_id.as_str()]);
    own_nodes(
        &r,
        0xaf,
        &[r.key.key_id.as_str(), device.key.key_id.as_str()],
    )
    .await;
    shape_to(&r, &device, b"T2-DEVICE-").await;
    shape_to(&r, &seat, b"T2-SEAT-").await;
    shape_to(&r, &older, b"T2-OLDER-").await;
    shape_to(&r, &newer, b"T2-NEWER-").await;
    r.transport
        .send(
            &dialled.key.key_id,
            &typed_payload("AttestationGossip", b"T2-R-DIALS-", 2_000),
        )
        .await
        .expect("R dials the fifth");
    assert!(r.transport.peer_shaping(&dialled.key.key_id).shaped_now);
    if r.transport.shaped_link_count() != 5 {
        let failed: u64 = [&r, &older, &newer, &device, &seat, &dialled]
            .iter()
            .map(|n| n.shaping("link_shaping_send_failed"))
            .sum();
        eprintln!(
            "[T2] {tag}: {} of 5 stood, {failed} send failures",
            r.transport.shaped_link_count()
        );
        assert!(failed > 0, "a shaped link gone with nothing counting it");
        return false;
    }
    let sender_rates = || {
        r.transport
            .shaping_status()
            .links
            .into_iter()
            .map(|l| (l.peer, l.bytes_per_s))
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let rates_before = sender_rates();

    let is_shaped = |n: &Node| r.transport.peer_shaping(&n.key.key_id).shaped_now;
    // Lost to a starved host with the shaper saying so: not what is on trial.
    let lost = |n: &Node| {
        !is_shaped(n)
            && [&r, &older, &newer, &device, &seat, &dialled]
                .iter()
                .map(|n| n.shaping("link_shaping_send_failed"))
                .sum::<u64>()
                > 0
    };
    r.transport
        .set_service_tier(ciris_edge::ServiceTier::ChatAndContacts);
    assert!(
        wait_until(Duration::from_secs(15), || async { !is_shaped(&newer) }).await,
        "the newest closes"
    );
    if lost(&older) {
        return false;
    }
    assert!(is_shaped(&older), "and the older one has not yet");
    assert!(
        wait_until(Duration::from_secs(15), || async { !is_shaped(&older) }).await,
        "then the older"
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(r.shaping("load_shed:shaped"), 2, "and no third");
    for keeps in [&device, &seat, &dialled] {
        if lost(keeps) {
            return false;
        }
        assert!(is_shaped(keeps), "{} stands", keeps.key.key_id);
    }

    // Cover is not shed, and rows keep their place.
    let rates = sender_rates();
    assert_eq!(rates.len(), 3);
    for (peer, rate) in &rates {
        assert_eq!(Some(rate), rates_before.get(peer), "the sender's rate now");
    }
    let cover = r.shaping("link_shaping_frames_cover");
    assert!(
        wait_until(Duration::from_secs(20), || async {
            r.shaping("link_shaping_frames_cover") >= cover + 30
        })
        .await,
        "cover goes on at tier 2"
    );
    let row = typed_payload("AttestationGossip", b"T2-ROW-TO-DEVICE-", 2_000);
    r.transport
        .send(&device.key.key_id, &row)
        .await
        .expect("a row at tier 2");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            device.received(&row).await
        })
        .await
    );

    // A shed peer that redials is refused, with a referral frame.
    assert!(
        wait_until(Duration::from_secs(30), || async {
            older.transport.shaped_link_count() == 0 && newer.transport.shaped_link_count() == 0
        })
        .await,
        "the peers saw the close"
    );
    let again = typed_payload("AttestationGossip", b"T2-REDIAL-", 2_000);
    let refused = older
        .transport
        .send(&r.key.key_id, &again)
        .await
        .expect_err("redial at tier 2");
    assert!(
        refused.to_string().contains("link_shaping_home_elsewhere"),
        "{refused}"
    );
    if lost(&seat) {
        return false;
    }
    assert!(is_shaped(&seat));

    // The seat is retired by quorum: active state, read at the next step.
    r.dir
        .record_canonical_withdrawal(&seat.key.key_id, None, "sha256:e15-retired")
        .await
        .expect("tombstone");
    assert!(
        wait_until(Duration::from_secs(15), || async { !is_shaped(&seat) }).await,
        "a retired canonical sheds like anyone"
    );
    assert_eq!(r.shaping("load_shed:shaped"), 3);
    if lost(&device) {
        return false;
    }
    assert!(is_shaped(&device), "the owner's device still stands");
    if lost(&dialled) {
        return false;
    }
    assert!(is_shaped(&dialled));

    // The tier falls: nothing more closes and the door opens.
    r.transport
        .set_service_tier(ciris_edge::ServiceTier::FullOps);
    assert_eq!(r.transport.shaping_status().free_slots, 6);
    shape_to(&r, &newer, b"T2-BACK-").await;
    true
}

/// **Through `Edge`, the way the server drives it** (E8, E15): `Edge::build`
/// wires the read, `set_load_pressure` moves the tier, and `shaping_status`
/// reads what is true at that moment, the zero slots with a free bound, and
/// the refusal comes from the wiring the host gets.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e8_e15_status_and_shed_through_edge_track_the_load_pressure() {
    let _host = share_host().await;
    let t = star_shaped_only("edge", 0xc0, 1).await;
    let Star {
        r,
        spokes,
        _tmp,
        _tasks,
    } = t;
    let [stranger] = <[Node; 1]>::try_from(spokes).ok().expect("one");
    let edge = ciris_edge::Edge::builder()
        .directory(Arc::clone(&r.dir) as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .federation_directory(Arc::clone(&r.dir) as Arc<dyn FederationDirectory>)
        .queue(Arc::clone(&r.dir) as Arc<dyn ciris_edge::outbound::OutboundHandle>)
        .signer(r.key.signer())
        .transport(Arc::clone(&r.transport) as Arc<dyn Transport>)
        .reticulum_transport(Arc::clone(&r.transport))
        .config(ciris_edge::EdgeConfig {
            hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
            ..ciris_edge::EdgeConfig::default()
        })
        .build()
        .expect("build the edge");
    edge.install_replication_routing(r.runtime.as_ref().expect("a runtime"));

    let s = edge.shaping_status().expect("a transport");
    assert_eq!((s.class, s.service_tier), ("server", 0));
    assert_eq!((s.free_slots, s.max_links), (8, Some(8)));
    assert!(!s.frame_agreed);
    assert!(s.onion.confines_media);
    assert_eq!(
        s.relays_answering, None,
        "no deal is installed: no measure, not a zero"
    );

    assert_eq!(
        edge.set_load_pressure(ciris_edge::LoadPressure::Warning),
        ciris_edge::ServiceTier::AudioAndFiles
    );
    let s = edge.shaping_status().expect("a transport");
    assert_eq!((s.service_tier, s.free_slots), (1, 0));

    let row = typed_payload("AttestationGossip", b"EDGE-STRANGER-", 2_000);
    let err = stranger
        .transport
        .send(&r.key.key_id, &row)
        .await
        .expect_err("refused through the wiring Edge::build installs");
    assert!(
        err.to_string().contains("link_shaping_home_elsewhere"),
        "{err}"
    );
    assert_eq!(r.shaping("load_refuse:admit_closed"), 1);
    assert_eq!(
        edge.peer_shaping(&stranger.key.key_id)
            .expect("a transport")
            .shapes,
        Some(true),
        "a refused peer offered, so it shapes"
    );
    assert_eq!(
        edge.onion_status().expect("a transport"),
        r.transport.onion().status()
    );
    let json = serde_json::to_value(edge.shaping_status().expect("a transport")).expect("json");
    for field in [
        "class",
        "bytes_per_s",
        "node_cap_bytes_per_s",
        "figures",
        "device_figures",
        "service_tier",
        "shaped_links",
        "free_slots",
        "links",
        "peers",
        "relays_answering",
        "onion",
    ] {
        assert!(json.get(field).is_some(), "{field}");
    }
    assert_eq!(json["onion"]["confines_media"], serde_json::json!(true));
    assert!(json["figures"]["gap_p95_s"].is_f64());
}

/// **E8: a value follows the thing it reports.** The bound, the class, the
/// frame and each peer's shaping change on the running node, and the status
/// changes with them. Mutation: serve a stored value for any of them → this
/// fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e8_the_status_tracks_the_bound_the_class_and_the_peers() {
    let _host = share_host().await;
    let mut phone = DeviceState::of(DeviceKind::Phone).with_network(true, true);
    phone.shaping_opt_in = true;
    phone.shaping_opt_in_cellular = true;
    let t = duo(
        "status",
        roomy(1),
        policy(BudgetClass::Server, 100_000, 0.5, 10, false),
    )
    .await;
    let a = t.a.transport.shaping_status();
    assert_eq!((a.free_slots, a.shaped_links), (1, 0));
    assert!(!a.frame_agreed, "no link yet: the reference frame");
    let reference_gap = a.figures.as_ref().expect("shapes").gap_s;

    let row = typed_payload("AttestationGossip", b"STATUS-ROW-", 2_000);
    t.b.transport
        .send(&t.a.key.key_id, &row)
        .await
        .expect("B dials A");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.transport.shaping_status().shaped_links == 1
        })
        .await
    );
    let a = t.a.transport.shaping_status();
    assert_eq!(a.free_slots, 0, "the bound is reached");
    assert_eq!(a.counted_links, 1);
    assert!(a.frame_agreed);
    let link = &a.links[0];
    assert_eq!(link.peer.as_deref(), Some(t.b.key.key_id.as_str()));
    assert!(!link.dialled_here);
    let lambda = t.a.transport.shaped_rates_for_test()[0];
    // The offer carries λ to a thousandth, so the agreed gap and the share's
    // differ by that rounding and no more.
    assert!(
        (link.gap_s * lambda - 1.0).abs() < 0.01,
        "the agreed gap: {} at λ {lambda}",
        link.gap_s
    );
    let figures = a.figures.as_ref().expect("shapes");
    assert_eq!(figures.frame_bytes, link.frame_bytes);
    // A TCP link runs the shaped frame, the reference one (CC 5.4.3 rc17).
    assert_eq!(figures.frame_bytes, REFERENCE_FRAME_BYTES);
    assert!((figures.gap_s - reference_gap).abs() < 1e-9);
    assert_eq!(a.peers.len(), 1);
    assert_eq!(a.peers[0].shapes, Some(true));
    assert!(
        t.b.transport.shaping_status().links[0].dialled_here,
        "B dialled it"
    );

    // The bound falls away with the link.
    t.b.transport
        .link_teardown(&t.b.transport.shaped_link_ids_for_test()[0])
        .await
        .expect("teardown");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.transport.shaping_status().free_slots == 1
        })
        .await,
        "the slot is free again"
    );
    assert_eq!(
        t.a.transport.peer_shaping(&t.b.key.key_id).shapes,
        Some(true),
        "the fact outlives the link"
    );

    // The class follows the host's device facts, both networks on a phone.
    let n = Arc::clone(&t.a.transport);
    n.set_device_state(phone).await;
    let wifi = n.shaping_status();
    assert_eq!(wifi.class, "phone-wifi");
    assert_eq!(wifi.bytes_per_s, 1_400);
    assert_eq!(
        wifi.device_figures
            .iter()
            .map(|f| f.class)
            .collect::<Vec<_>>(),
        vec!["phone-wifi", "phone-cellular"]
    );
    n.set_device_state(phone.with_network(false, false)).await;
    let cell = n.shaping_status();
    assert_eq!(cell.class, "phone-cellular");
    assert_eq!(cell.bytes_per_s, 350);
    assert!(
        cell.figures.as_ref().unwrap().gap_s > 3.9 * wifi.figures.as_ref().unwrap().gap_s,
        "the gap moved with the class"
    );
    assert_eq!(
        cell.device_figures[0].class, "phone-wifi",
        "the other network's set stays on offer"
    );
}

/// E8, the peer side: a peer that answers `off`, an old one now, is on record as
/// not shaping.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e8_a_peer_that_answers_off_is_on_record_as_not_shaping() {
    let _host = share_host().await;
    let t = duo(
        "offpeer",
        policy(BudgetClass::Server, 100_000, 0.5, 10, false),
        explicit_off(),
    )
    .await;
    t.b.transport.answer_off_like_an_old_peer_for_test();
    assert_eq!(t.a.transport.peer_shaping(&t.b.key.key_id).shapes, None);
    let row = typed_payload("AttestationGossip", b"OFFPEER-", 2_000);
    t.a.transport
        .send(&t.b.key.key_id, &row)
        .await
        .expect("A dials B");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.transport.peer_shaping(&t.b.key.key_id).shapes == Some(false)
        })
        .await,
        "{:?}",
        t.a.metrics.link_shaping()
    );
    assert!(!t.a.transport.peer_shaping(&t.b.key.key_id).shaped_now);
}

// ─── `seat` class on the active roster ─────────────────────────────────────

/// A node with no send set to speak of: these witnesses are about seats.
struct NoSendSet;

#[async_trait::async_trait]
impl SendSetRead for NoSendSet {
    async fn reaches(&self, _local: &str, _peer: &str) -> Option<bool> {
        Some(false)
    }
}

/// `n` keeps its seats to its own directory, on the production cadence.
fn read_seats(n: &Node) {
    n.transport
        .install_peer_obligations(Arc::new(LivePeerObligations::new(
            Arc::clone(&n.dir) as Arc<dyn FederationDirectory>,
            n.key.key_id.clone(),
            Arc::new(RwLock::new(HashSet::new())),
            Arc::new(NoSendSet),
        )));
}

/// The role conferred on `keys`, in the bundle's spelling, as `at` holds it.
async fn confer(at: &Node, keys: &[&str]) {
    for key in keys {
        at.dir
            .test_seam_set_key_identity_type(key, "canonical,node")
            .await
            .expect("the role");
    }
}

/// `sender` dials `to` with a row and waits for the row: a fresh link.
async fn fresh_link(sender: &Node, to: &Node, marker: &[u8]) {
    let row = typed_payload("AttestationGossip", marker, 2_000);
    sender
        .transport
        .send(&to.key.key_id, &row)
        .await
        .expect("the dial");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            to.received(&row).await
        })
        .await,
        "the row crossed: {:?}",
        sender.metrics.link_shaping()
    );
}

/// Two servers at the class rate, A with a bound of one.
fn one_slot() -> ShapingPolicy {
    let mut p = policy(BudgetClass::Server, 7_000, 0.5, 600, false);
    p.share = ShapedSharePolicy::BoundedWithFloor {
        max_links: 1,
        floor_bytes_per_s: 7_000,
    };
    p
}

const SEAT_RATE: u32 = 33_000;

/// An agreed rate at `rate`: the offer carries λ to a thousandth, so it lands
/// a few bytes off.
fn at_rate(agreed: u32, rate: u32) -> bool {
    agreed.abs_diff(rate) * 100 < rate
}

/// **A canonical that joins after boot** (`CC 5.4.3`, Eric's rule): the role
/// lands in the directories of two running nodes and the next refresh makes
/// their next link a seat link, with no restart. It takes both ends: while
/// only A holds the proof the link runs at the class. Mutation: keep the boot
/// set → this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_canonical_that_joins_after_boot_gets_the_seat_class_from_both_proofs() {
    let _host = share_host().await;
    let t = duo("seat-joins", one_slot(), one_slot()).await;
    read_seats(&t.a);
    read_seats(&t.b);
    let (a_id, b_id) = (t.a.key.key_id.clone(), t.b.key.key_id.clone());

    confer(&t.a, &[a_id.as_str(), b_id.as_str()]).await;
    assert!(
        wait_until(Duration::from_secs(45), || async {
            t.a.transport.is_seat_link_for_test(&b_id)
        })
        .await,
        "A reads the roster on its own cadence"
    );
    fresh_link(&t.b, &t.a, b"JOIN-ONE-PROOF-").await;
    let link = t.a.transport.shaping_status().links[0].clone();
    assert!(
        at_rate(link.agreed_bytes_per_s, 7_000),
        "B has proved nothing yet: {}",
        link.agreed_bytes_per_s
    );
    t.b.transport
        .link_teardown(&t.b.transport.shaped_link_ids_for_test()[0])
        .await
        .expect("teardown");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.transport.shaped_link_count() == 0 && t.b.transport.shaped_link_count() == 0
        })
        .await
    );

    confer(&t.b, &[a_id.as_str(), b_id.as_str()]).await;
    assert!(
        wait_until(Duration::from_secs(45), || async {
            t.b.transport.is_seat_link_for_test(&a_id)
        })
        .await,
        "B reads it too"
    );
    fresh_link(&t.b, &t.a, b"JOIN-TWO-PROOFS-").await;
    let status = t.a.transport.shaping_status();
    assert!(
        at_rate(status.links[0].agreed_bytes_per_s, SEAT_RATE),
        "{:?}",
        status.links
    );
    assert!(status.links[0].seat);
    assert_eq!(status.counted_links, 0, "outside the bound");
    assert_eq!(status.free_slots, 1, "the bound's one slot stays free");
}

/// **A canonical retired after boot.** Two seats hold a seat link outside A's
/// bound of one. A tombstone lands, the next refresh closes the link with no
/// restart, and the redial runs at the class and takes the slot: it lost the
/// class and the exemption. Mutation: keep the boot set, or ignore the
/// tombstone, or leave the running link → this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_canonical_retired_after_boot_loses_the_seat_class_and_the_bound_exemption() {
    let _host = share_host().await;
    let t = duo("seat-retires", one_slot(), one_slot()).await;
    let (a_id, b_id) = (t.a.key.key_id.clone(), t.b.key.key_id.clone());
    for n in [&t.a, &t.b] {
        confer(n, &[a_id.as_str(), b_id.as_str()]).await;
        read_seats(n);
    }
    assert!(
        wait_until(Duration::from_secs(45), || async {
            t.a.transport.is_seat_link_for_test(&b_id) && t.b.transport.is_seat_link_for_test(&a_id)
        })
        .await,
        "both hold the seats"
    );
    fresh_link(&t.b, &t.a, b"RETIRE-SEAT-").await;
    let status = t.a.transport.shaping_status();
    assert!(
        at_rate(status.links[0].agreed_bytes_per_s, SEAT_RATE),
        "{:?}",
        status.links
    );
    assert_eq!((status.counted_links, status.free_slots), (0, 1));

    for n in [&t.a, &t.b] {
        n.dir
            .record_canonical_withdrawal(&b_id, None, "sha256:seat-retired")
            .await
            .expect("tombstone");
    }
    assert!(
        wait_until(Duration::from_secs(45), || async {
            t.a.transport.shaped_link_count() == 0 && t.b.transport.shaped_link_count() == 0
        })
        .await,
        "the seat link closes on the next refresh: {:?}",
        t.a.transport.shaping_status().links
    );
    assert!(!t.a.transport.is_seat_link_for_test(&b_id));
    assert!(
        t.a.shaping("link_shaping_seat_lost") + t.b.shaping("link_shaping_seat_lost") >= 1,
        "v44: a lost seat is counted, not only logged"
    );

    fresh_link(&t.b, &t.a, b"RETIRE-CLASS-").await;
    let status = t.a.transport.shaping_status();
    assert!(
        at_rate(status.links[0].agreed_bytes_per_s, 7_000),
        "the class: {:?}",
        status.links
    );
    assert!(!status.links[0].seat);
    assert_eq!(
        (status.counted_links, status.free_slots),
        (1, 0),
        "and it holds the bound's one slot"
    );
}

/// v44 — a real link through two real listeners moves the event path's
/// telemetry, each signal from where production books it, on the bag a host
/// reads. The liveness signals read true with nothing else to say.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_real_link_moves_the_event_path_telemetry() {
    let _host = share_host().await;
    let fast = policy(BudgetClass::Server, 100_000, 0.5, 10, false);
    let t = duo("tele", fast.clone(), fast).await;
    let row = marked(b"TELE-ROW-", 2_000);
    t.b.transport
        .send(&t.a.key.key_id, &row)
        .await
        .expect("B -> A shaped");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(&row).await
        })
        .await,
        "A delivered B's row"
    );
    let shown = wait_until(Duration::from_secs(5), || async {
        let s = t.a.metrics.snapshot();
        s.node_alive == 1 && s.shaping_links["counted"] >= 1
    })
    .await;
    assert!(shown, "the node tick has run since the link came up");

    let a = t.a.metrics.snapshot();
    let b = t.b.metrics.snapshot();
    // The event loop: the responder saw each of these, timed.
    assert!(a.event_handler_duration_seconds["link_established"].count >= 1);
    assert!(a.event_handler_duration_seconds["frame"].count >= 1);
    assert_eq!(a.event_handler_duration_seconds["keying_applied"].count, 1);
    assert!(a.leviculum_events_capacity["control"] > 0, "bridged, live");
    // Keying: on the responder only, on one budget or the other.
    let keyed = |s: &ciris_edge::observability::EdgeMetricsBundle| {
        s.seal_keying_duration_seconds["standing"].count
            + s.seal_keying_duration_seconds["stranger"].count
    };
    assert_eq!(keyed(&a), 1, "A answered B's handshake");
    assert_eq!(keyed(&b), 0, "the dialler decapsulates nothing");
    assert!(a.seal_keyer_workers["configured"] >= 1);
    assert_eq!(a.seal_keyer_queued["stranger"], 0, "and it drained");
    // Both directions of an offer, and the class it landed at.
    assert_eq!(t.b.shaping("link_shaping_offered:dialled"), 1);
    assert_eq!(t.b.shaping("link_shaping_offered:answered"), 0);
    assert_eq!(t.a.shaping("link_shaping_offered:answered"), 1);
    assert_eq!(t.a.shaping("link_shaping_agreed:server"), 1);
    assert_eq!(a.shaping_enabled, 1);

    // Shaping's secret: real frames left, and the bundle cannot say so yet.
    assert!(t.b.shaping("link_shaping_frames_real") >= 1, "they left");
    assert!(!b.link_shaping.contains_key("link_shaping_frames_real"));
    assert_eq!(b.shaping_frames_real_windowed["server"], 0);
    assert_eq!(b.shaping_row_wait_seconds["server"].count, 0);
    // A closed window with the floor met shows the production path filled it,
    // in this link's class.
    let windows = &t.b.metrics.telemetry.shaping_windows;
    windows.tick(u64::MAX / 2, |_| 3, |_| Duration::ZERO);
    let flushed = t.b.metrics.snapshot();
    assert_eq!(flushed.shaping_row_wait_seconds["server"].count, 1);
    assert_eq!(flushed.shaping_row_wait_seconds["home"].count, 0);

    // The behaviour: edge's own signal reaches the shapers on a tick, with no
    // `set_load_pressure` and no reader of `service_tier`. Nothing below reads
    // the tier through the Edge, so only the node tick can move the shaper.
    assert_eq!(t.a.transport.shaping_status().service_tier, 0);
    let raised = wait_until(Duration::from_secs(10), || async {
        t.a.ladder.report(ciris_edge::load_ladder::EdgeLoadSignals {
            relay_commit_ratio: 1.0,
            ..Default::default()
        });
        t.a.transport.shaping_status().service_tier == 1
    })
    .await;
    assert!(raised, "the raise reached the shapers on the tick");
    let s = t.a.metrics.snapshot();
    assert_eq!(s.load_tier, 1);
    assert_eq!(
        s.load_tier_changes_total["load_tier:1:edge:relay_commit"], 1,
        "and it says who put it there"
    );
    assert!(
        s.load_pressure_report_age_seconds < 0.0,
        "the host never spoke"
    );
    assert_eq!(s.shaping_free_slots, 0, "admit-close offers no slot");
}

/// The production shaped frame (CC 5.4.3 rc17: 1,400 B plaintext, the `SHPF`
/// header included, before the E1 seal), which a loopback TCP link (16,272 B
/// channel payload) runs at with no test cap.
const ONION_TEST_FRAME: usize = ciris_edge::transport::link_shaping::SHAPED_FRAME_BYTES as usize;

/// Both ends of `t` run the Anonymous Tier as relays: a deal of nine stand-in
/// relays per period (three a layer, every one answering), this node's hop
/// secret from `seed`, and a mixing delay of a millisecond.
fn onion_relay_on(
    n: &Node,
    seed: u8,
    deal: &ciris_edge::transport::onion_layers::LayerDeal,
) -> ciris_edge::onion::packet::HopKey {
    use ciris_edge::onion::packet::HopSecret;
    use ciris_edge::onion::relay::OnionRelay;
    let onion = n.transport.onion();
    onion.set_policy(ciris_edge::onion::policy::OnionPolicy {
        enabled: true,
        mix_mean_delay_ms: 1,
        ..ciris_edge::onion::policy::OnionPolicy::default()
    });
    onion.set_device(DeviceState::of(DeviceKind::Server));
    onion.install_deal(deal.clone());
    for layer in &deal.layers {
        for k in layer {
            onion.observe(
                k,
                ciris_edge::transport::onion_liveness::LivenessEvidence::ShapedLinkUp,
            );
        }
    }
    let relay = OnionRelay::new(
        HopSecret::from_xwing_seed(&[seed; 32]).expect("hop secret"),
        None,
    );
    let key = relay.hop_key().clone();
    onion.set_relay(Some(relay));
    assert_eq!(onion.tier(), Ok(()), "the tier is active");
    assert_eq!(onion.relaying(), Ok(()), "and this node relays");
    key
}

/// **CC 5.4.3 × 5.4.6 — an onion packet crosses a 1,400 B shaped link in
/// fragments and arrives intact.** An onion packet is a fixed 15,296 B
/// (`onion::packet::PACKET`); at the TCP channel payload MDU it rode one
/// shaped frame body, at the production 1,400 B frame (no test cap: the link
/// agrees it on its own) it is cut by the `CFRG` fragmenter into twelve. B publishes over a route A → B → A, so the packet crosses the
/// capped link three times (B→A, A→B, B→A), each time fragmented at the
/// sender's shaper, reassembled at the receiver and PEELED there: a single
/// wrong byte fails the hop's AEAD, and only an intact packet at the last hop
/// stores the payload. The exit holds exactly the payload B sent.
/// Mutation: break `frame_fragment::Reassembler` (e.g. drop a fragment's last
/// byte on reassembly) → no hop opens and the exit stays empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_onion_packet_crosses_a_1400_byte_shaped_link_in_fragments_and_arrives_intact() {
    use ciris_edge::onion::packet::PACKET;
    use ciris_edge::onion::tokens;
    use ciris_edge::transport::frame_fragment::FRAGMENT_HEADER_LEN;
    use ciris_edge::transport::link_shaping::body_capacity;
    use ciris_edge::transport::onion_layers::{period_of, LayerDeal};
    let _host = share_host().await;
    let fast = policy(BudgetClass::Server, 100_000, 0.5, 10, false);
    let t = duo("onion1400", fast.clone(), fast).await;
    t.a.transport.set_link_wire_tap_for_test(true);
    t.b.transport.set_link_wire_tap_for_test(true);
    // The link comes up shaped at the production frame.
    let hello = marked(b"ONION-LINK-UP-", 600);
    t.b.transport
        .send(&t.a.key.key_id, &hello)
        .await
        .expect("B -> A");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(&hello).await
        })
        .await
    );
    let link =
        t.b.transport
            .link_wire_tapped_for_test()
            .first()
            .expect("B dialled")
            .0;
    let (frame, _) =
        t.b.transport
            .shaped_agreement_for_test(link)
            .expect("the link is shaped");
    assert_eq!(
        usize::from(frame),
        ONION_TEST_FRAME,
        "agreed at the shaped frame, below the link's MDU"
    );
    // The onion frame (`CONP` ‖ packet) spans many shaped frames here.
    let onion_frame = 4 + PACKET;
    let per_fragment = body_capacity(frame) - FRAGMENT_HEADER_LEN;
    let fragments = onion_frame.div_ceil(per_fragment);
    assert!(fragments >= 11, "{onion_frame} B spans {fragments} frames");

    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap();
    let ids = |p: &str| (0..3).map(|i| format!("{p}{i}")).collect::<Vec<_>>();
    let deal = LayerDeal {
        period: period_of(now),
        layers: [ids("l1-"), ids("l2-"), ids("l3-")],
        capped: Vec::new(),
        available: true,
    };
    let key_a = onion_relay_on(&t.a, 0xa1, &deal);
    let key_b = onion_relay_on(&t.b, 0xb1, &deal);
    // Each hop names the next by the address its sender dials it at.
    let dest_a =
        t.b.transport
            .peer_dest_hash_for_test(&t.a.key.key_id)
            .await
            .expect("B resolves A");
    let dest_b =
        t.a.transport
            .peer_dest_hash_for_test(&t.b.key.key_id)
            .await
            .expect("A resolves B");
    // Layer 1 and 3 are A, layer 2 is B: the route is A → B → A.
    let resolve = move |k: &str| {
        if k.starts_with("l2-") {
            Some((dest_b, key_b.clone()))
        } else {
            Some((dest_a, key_a.clone()))
        }
    };
    let real_before = t.b.shaping("link_shaping_frames_real");
    let payload = marked(b"ONION-PAYLOAD-", 1_000);
    t.b.transport
        .onion_publish(&payload, &resolve)
        .await
        .expect("published on the shaped first hop");
    let mut exits = Vec::new();
    let stored = wait_until(Duration::from_secs(60), || {
        exits.extend(t.a.transport.onion().take_exits());
        let done = !exits.is_empty();
        async move { done }
    })
    .await;
    assert!(
        stored,
        "the packet reached its exit through three fragmented crossings: A {:?} B {:?}",
        t.a.transport.onion().counters(),
        t.b.transport.onion().counters()
    );
    assert_eq!(exits, vec![payload], "the exit holds exactly what B sent");
    let a_counts = t.a.transport.onion().counters();
    let b_counts = t.b.transport.onion().counters();
    assert_eq!(b_counts.get(tokens::PUBLISHED), Some(&1), "{b_counts:?}");
    assert_eq!(
        a_counts.get(tokens::FORWARDED),
        Some(&1),
        "hop 1 (A) opened and forwarded: {a_counts:?}"
    );
    assert_eq!(
        b_counts.get(tokens::FORWARDED),
        Some(&1),
        "hop 2 (B) opened and forwarded: {b_counts:?}"
    );
    // B sent the packet twice (hops 1 and 3), each time as `fragments` frames.
    let real = t.b.shaping("link_shaping_frames_real") - real_before;
    assert!(
        real >= 2 * fragments as u64,
        "B's packet crossings took {real} real frames, at least {}",
        2 * fragments
    );
    // And the wire never showed anything but the one sealed frame size.
    let sealed = ONION_TEST_FRAME + ciris_edge::transport::link_seal::SEAL_OVERHEAD;
    let b_frames = frames_on(&t.b.transport.link_wire_tapped_for_test(), link);
    let (b_len, b_run) = trailing_run(&b_frames);
    assert_eq!(b_len, sealed);
    assert!(
        b_run as u64 >= real,
        "{b_run} constant frames cover the {real} real ones"
    );
}

/// **Measurement, not a gate** — contact-like latency over a REAL loopback
/// shaped pair: `FM_K` request/response exchanges (B asks, A answers), `FM_REQ`
/// / `FM_RESP` bytes, at `FM_RATE` B/s per link (default 7,000, `server`) and
/// a frame capped at `FM_CAP` (0 = the production shaped frame, 1,400 B),
/// `FM_SAMPLES` contacts. Prints p50/p90.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement, not a gate"]
async fn measure_contact_round_trips_over_a_real_shaped_pair() {
    let env = |k: &str, d: usize| std::env::var(k).ok().map_or(d, |v| v.parse().expect(k));
    let (cap, rate, k, samples, req, resp) = (
        env("FM_CAP", 0),
        env("FM_RATE", 7_000),
        env("FM_K", 7),
        env("FM_SAMPLES", 5),
        env("FM_REQ", 400),
        env("FM_RESP", 400),
    );
    let _host = whole_host().await;
    let p = policy(
        BudgetClass::Server,
        u32::try_from(rate).unwrap(),
        0.5,
        600,
        false,
    );
    let t = duo(&format!("contact{cap}"), p.clone(), p).await;
    if cap > 0 {
        t.a.transport.set_shaped_frame_cap_for_test(cap);
        t.b.transport.set_shaped_frame_cap_for_test(cap);
    }
    t.b.transport.set_link_wire_tap_for_test(true);
    let hello = marked(b"CONTACT-UP-", 300);
    t.b.transport
        .send(&t.a.key.key_id, &hello)
        .await
        .expect("up");
    assert!(
        wait_until(Duration::from_secs(120), || async {
            t.a.received(&hello).await
        })
        .await
    );
    let link =
        t.b.transport
            .link_wire_tapped_for_test()
            .first()
            .expect("dialled")
            .0;
    let (frame, bps) =
        t.b.transport
            .shaped_agreement_for_test(link)
            .expect("shaped");
    let poll = |n: &Node, row: Vec<u8>| {
        let seen = Arc::clone(&n.seen);
        async move {
            loop {
                if seen.lock().await.iter().any(|f| f.envelope_bytes == row) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    };
    let mut v = Vec::new();
    for s in 0..samples {
        let start = std::time::Instant::now();
        for i in 0..k {
            let q = marked(format!("Q{s}-{i}-").as_bytes(), req);
            t.b.transport
                .send(&t.a.key.key_id, &q)
                .await
                .expect("request");
            poll(&t.a, q).await;
            let r = marked(format!("R{s}-{i}-").as_bytes(), resp);
            t.a.transport
                .send(&t.b.key.key_id, &r)
                .await
                .expect("response");
            poll(&t.b, r).await;
        }
        v.push(start.elapsed().as_secs_f64());
        println!("FMREAL sample {s} {:.2}s", v[v.len() - 1]);
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let q = |p: f64| v[((v.len() - 1) as f64 * p).round() as usize];
    println!(
        "FMREAL frame={frame} bytes_per_s={bps} k={k} req={req} resp={resp} samples={samples} p50={:.2}s p90={:.2}s min={:.2}s max={:.2}s",
        q(0.5),
        q(0.9),
        v[0],
        v[v.len() - 1]
    );
}
