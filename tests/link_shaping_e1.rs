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
        scope: ciris_edge::transport::link_shaping::ShapingScope::AllIdentityLinks,
        share: ciris_edge::transport::link_shaping::ShapedSharePolicy::DivideNoFloor,
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
        explicit_off(),
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
        explicit_off(),
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

/// **CC 5.4.3 rc16 two planes, the last resort** — B is a NAT'd phone: it
/// dials A (the only link, shaped), and A cannot dial B. An UNPROMPTED 1 MiB
/// Deliver from A to B is beyond the shaped link's reach (0.5 × 100 kB/s ×
/// 10 s = 500 kB), so it needs the bulk plane, and no unshaped link to B can
/// exist. It must not fail: it rides the shaped link in shaped-budget
/// fragments, slowly, counted `link_shaping_bulk_on_shaped_fallback`, and the
/// shaped link stays one frame size throughout (enough frames of it to have
/// carried the whole megabyte). Mutation: no fallback → the
/// send fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bulk_to_a_peer_reachable_only_over_its_shaped_link_rides_it_slowly_and_never_fails() {
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
    t.a.transport.set_link_wire_tap_for_test(true);
    let deliver = typed_payload("AttestationGossip", b"FB-DELIVER-", 1 << 20);
    t.a.transport
        .send(&t.b.key.key_id, &deliver)
        .await
        .expect("an unprompted 1 MiB Deliver to a peer A cannot dial completes");
    assert!(
        wait_until(Duration::from_secs(120), || async {
            t.b.received(&deliver).await
        })
        .await,
        "B received the 1 MiB Deliver over the shaped link: {:?}",
        t.a.metrics.link_shaping()
    );
    assert_eq!(
        t.a.shaping("link_shaping_bulk_on_shaped_fallback"),
        1,
        "{:?}",
        t.a.metrics.link_shaping()
    );
    assert_eq!(t.a.shaping("link_shaping_bulk_refused"), 0);
    assert_eq!(
        t.a.transport.refused_dials_for_test(),
        1,
        "the first send paid one failed dial"
    );
    let wire = t.a.transport.link_wire_tapped_for_test();
    let link = wire.first().expect("A sent on the link").0;
    assert!(
        wire.iter().all(|(l, _)| *l == link),
        "one link: the shaped one"
    );
    let frames = frames_on(&wire, link);
    let (size, run) = trailing_run(&frames);
    assert!(
        frames.iter().all(|f| f.len() == size) && run * size >= 1 << 20,
        "the shaped link stays one frame size while the bulk crosses: {run} × {size} B, others {:?}",
        frames.iter().map(Vec::len).filter(|&l| l != size).collect::<Vec<_>>()
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
        t.a.transport
            .send(&t.b.key.key_id, &deliver)
            .await
            .expect("a bulk Deliver to a peer A cannot dial completes");
        assert!(
            wait_until(Duration::from_secs(60), || async {
                t.b.received(&deliver).await
            })
            .await
        );
    }
    assert_eq!(t.a.shaping("link_shaping_bulk_on_shaped_fallback"), 2);
    assert_eq!(
        t.a.transport.refused_dials_for_test(),
        1,
        "the second send skipped the dial"
    );
}

/// `Delivered` is a transport ack to the durable dispatcher, so a fallback
/// whose link closes part-way must be an error it retries, never a success.
/// Mutation: report success once the fragments are queued → this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fallback_that_drops_part_way_is_an_error_the_dispatcher_retries() {
    let server = policy(BudgetClass::Server, 100_000, 0.5, 10, false);
    let t = duo("dropped", server.clone(), server).await;
    let row = typed_payload("AttestationGossip", b"DROP-ROW-", 2_000);
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
    t.a.transport.set_link_wire_tap_for_test(true);
    t.a.transport.refuse_outbound_dials_for_test(true);
    let sender = Arc::clone(&t.a.transport);
    let to = t.b.key.key_id.clone();
    let deliver = typed_payload("AttestationGossip", b"DROP-DELIVER-", 1 << 20);
    let send = tokio::spawn(async move { sender.send(&to, &deliver).await });
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.shaping("link_shaping_bulk_on_shaped_fallback") == 1
                && t.a.shaping("link_shaping_frames_real") >= 3
        })
        .await,
        "the fallback is under way: {:?}",
        t.a.metrics.link_shaping()
    );
    assert!(!send.is_finished(), "the send waits for the last fragment");
    let link = t.a.transport.link_wire_tapped_for_test()[0].0;
    t.a.transport.link_teardown(&link).await.expect("teardown");
    let out = tokio::time::timeout(Duration::from_secs(30), send)
        .await
        .expect("the send ends when the link does")
        .expect("no panic");
    let err = out.expect_err("a dropped fallback is not Delivered");
    assert!(
        err.to_string()
            .contains("link_shaping_bulk_fallback_interrupted"),
        "{err}"
    );
}

/// **The row limit** (Eric, 2026-11-04): 64 KiB, whatever the type, and not
/// the window budget. This budget's window holds 1 MB, so the 512 KiB Deliver
/// fits it and moves only because of the limit. Mutation: raise
/// `SHAPED_ROW_MAX_BYTES` to the window budget → this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_512_kib_deliver_takes_the_bulk_link_and_a_4_kib_deliver_stays_shaped() {
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
    use ciris_edge::transport::link_shaping::ShapedSharePolicy;
    let mut full = policy(BudgetClass::Server, 100_000, 0.5, 10, false);
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

/// A peer whose class is Off is not a shaping peer: at A's bound its row
/// link runs unshaped, as CC 5.4.3 "either side off" says, and the row crosses.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn at_the_bound_an_off_peer_still_gets_an_ordinary_unshaped_link() {
    use ciris_edge::transport::link_shaping::ShapedSharePolicy;
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
    assert_eq!(t.a.shaping("link_shaping_unshaped"), 1);
}
