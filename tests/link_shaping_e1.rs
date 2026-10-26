//! CC 5.4.3 — link shaping (`CLM-link-shaping`, rc10): the witnesses.
//!
//! Two nodes, A listening and B dialling, each under its own
//! [`ShapingPolicy`]. The wire tap records every frame a node hands
//! leviculum, sealed, so a shaped link shows as a run of equal-length frames
//! (the agreed frame plus the seal's 25 bytes) in BOTH directions; the
//! `link_shaping` ledger says which were real and which cover.

#![cfg(feature = "transport-reticulum")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::transport::link_shaping::{BudgetClass, ShapingPolicy};
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport, TransportError};
use ciris_edge::verify::RootingDirectory;
use ciris_edge::EdgeMetrics;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::FederationDirectory;
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
        let mut envelope = serde_json::json!({});
        ciris_persist::federation::admission::bind_subject_into_envelope(
            &mut envelope,
            &self.key_id,
            "node",
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

/// **Witness 2** — one side `off`: the offers resolve to UNSHAPED by
/// agreement and the link runs bare (counted on both ends); a node that
/// REQUIRES shaped links refuses the same peer by name and the link closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_half_shaped_offer_leaves_the_link_unshaped_or_refused_by_policy() {
    let lenient = duo(
        "half",
        policy(BudgetClass::Home, 200_000, 0.5, 10, false),
        ShapingPolicy::default(),
    )
    .await;
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
        ShapingPolicy::default(),
    )
    .await;
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
/// drained stays under ρ; a short window at one ρ delays a burst more than
/// a long one (the budget refills in smaller steps).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rho_and_the_window_move_the_real_share_and_the_delay() {
    #[allow(clippy::cast_precision_loss)] // frame counts, far below 2^52
    async fn burst_time(tag: &str, rho: f64, window_s: u64) -> (Duration, f64) {
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
        let share = real as f64 / (real + cover).max(1) as f64;
        eprintln!("[{tag}] rho={rho} W={window_s}s burst of 40 took {took:?}; real share {share:.2} ({real} real / {cover} cover)");
        (took, share)
    }
    // The budget bounds real frames PER WINDOW (ρ·λ·W), not per burst: at
    // ρ=0.8 the whole burst fits one window's budget and leaves back-to-back
    // (its share over the burst's own seconds is near 1); at ρ=0.25 it does
    // not, so the stream stays mostly cover while the burst drains and the
    // burst takes several windows.
    let (t_low, share_low) = burst_time("rho25", 0.25, 10).await;
    let (t_high, share_high) = burst_time("rho80", 0.8, 10).await;
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
    let (t_short, _) = burst_time("w2", 0.5, 2).await;
    let (t_long, _) = burst_time("w30", 0.5, 30).await;
    assert!(
        t_short > t_long,
        "a shorter window delays a burst more: W=2 s {t_short:?} vs W=30 s {t_long:?}"
    );
}
