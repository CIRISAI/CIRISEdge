//! CC 5.3.3.5 E1 (CIRIS Constitution rc9) — every byte edge sends over an RNS
//! link rides under a hybrid transit seal, keyed by the CC 3.3.6.2 transit KEX
//! that runs once per link as its FIRST frame and bound to that link's id.
//! Enforced at once: a peer that does not run the seal gets nothing.
//!
//! Every node here is the field shape (as `reverse_link_resource_binding_722`):
//! a self-signed hybrid key whose id binds its pubkey, a per-node directory,
//! and the dialler holding the dialled node's hybrid-signed
//! `SignedTransportDestination` (the row that publishes its transit pair; the
//! TransportDestination plane carries it in the field). `A` listens; `B` and
//! `C` are TCP clients of `A`.
//!
//! - a sealed exchange (Channel fragments and a Resource, both directions)
//!   crosses, and a tap of every frame handed to leviculum shows the handshake
//!   first and no plaintext row byte after it;
//! - a peer that never sends the handshake: the responder delivers and sends
//!   nothing, then refuses by name and closes the link;
//! - a non-`CTKX` first frame, and a classical-only suite: refused by name;
//! - a dial to a peer with no Rooted pair: refused, the link never made;
//! - a claim that is not the link's attributed peer: refused;
//! - first contact from an unannounced (unattributable) node rides sealed and
//!   is delivered; anything else on that link is refused.
//!
//! Requires the `transport-reticulum` feature:
//! `cargo test --features transport-reticulum --test link_seal_e1`

#![cfg(feature = "transport-reticulum")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::transport::reticulum::{
    HandshakeOverride, ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
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
    fn seal(&self, label: &str) -> u64 {
        self.metrics.link_seal().get(label).copied().unwrap_or(0)
    }
    async fn received(&self, bytes: &[u8]) -> bool {
        self.seen
            .lock()
            .await
            .iter()
            .any(|f| f.envelope_bytes == bytes)
    }
}

struct Trio {
    a: Node,
    b: Node,
    c: Node,
    _tmp: tempfile::TempDir,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
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

/// `A` listens; `B` and `C` dial it. `seed_a_at_clients`: whether `B` and `C`
/// hold `A`'s route (its transit pair). `c_unannounced`: `C` never announces,
/// on the network or on a link (an unowned fresh device).
async fn trio(tag: &str, seed_a_at_clients: bool, c_unannounced: bool) -> Trio {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let keys = [
        Ident::new(&format!("node-a-e1-{tag}"), 0x1a).await,
        Ident::new(&format!("node-b-e1-{tag}"), 0x1b).await,
        Ident::new(&format!("node-c-e1-{tag}"), 0x1c).await,
    ];
    let mut records = Vec::new();
    for k in &keys {
        records.push(k.record().await);
    }
    let [key_a, key_b, key_c] = keys;
    let mut tasks = Vec::new();
    let mut port_a = 0;
    let mut nodes = Vec::new();
    for (i, key) in [key_a, key_b, key_c].into_iter().enumerate() {
        let dir = directory_with(records.clone()).await;
        let metrics = EdgeMetrics::new();
        let (transport, addr) = common::build_reticulum_with_retry_metrics(
            || {
                let base = tmp.path().join(format!("n{i}"));
                let signer = key.signer();
                let dir = Arc::clone(&dir);
                async move {
                    let mut c =
                        ReticulumTransportConfig::new(base.join("transport.id"), &signer.key_id);
                    c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
                    if i > 0 {
                        c.bootstrap_peers = vec![format!("127.0.0.1:{port_a}").parse().unwrap()];
                    }
                    c.announce_interval = Duration::from_secs(5);
                    (c, auth(signer, &dir))
                }
            },
            metrics.clone(),
        )
        .await;
        if i == 0 {
            port_a = addr.port();
        }
        if i == 2 && c_unannounced {
            transport.set_unannounced_for_test(true);
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
    let c = nodes.pop().expect("c");
    let b = nodes.pop().expect("b");
    let a = nodes.pop().expect("a");
    if seed_a_at_clients {
        seed_route(&a, &b).await;
        seed_route(&a, &c).await;
    }
    seed_route(&b, &a).await;
    let known = wait_until(Duration::from_secs(60), || async {
        b.transport.knows_peer(&a.key.key_id).await
            && c.transport.knows_peer(&a.key.key_id).await
            && a.transport.knows_peer(&b.key.key_id).await
    })
    .await;
    assert!(known, "B and C learn A's announce, A learns B's");
    if c_unannounced {
        assert!(
            !a.transport.knows_peer(&c.key.key_id).await,
            "an unannounced C is unknown at A"
        );
    }
    Trio {
        a,
        b,
        c,
        _tmp: tmp,
        _tasks: tasks,
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
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

/// Every frame a node handed leviculum, per link: on a link it dialled the
/// handshake parts come first, and every other frame opens with the seal
/// version; no frame anywhere carries the plaintext marker.
fn assert_wire_is_sealed(tapped: &[([u8; 16], Vec<u8>)], marker: &[u8]) {
    assert!(!tapped.is_empty(), "the tap saw the links");
    let mut links: Vec<[u8; 16]> = tapped.iter().map(|(l, _)| *l).collect();
    links.dedup();
    for link in links {
        let frames: Vec<&Vec<u8>> = tapped
            .iter()
            .filter(|(l, _)| *l == link)
            .map(|(_, f)| f)
            .collect();
        let parts = frames.iter().take_while(|f| f.starts_with(b"CTKX")).count();
        for (i, f) in frames.iter().enumerate() {
            assert!(
                !contains(f, marker),
                "frame {i} on link {} carries plaintext row bytes",
                hex::encode(link)
            );
            if i >= parts {
                assert_eq!(
                    f[0],
                    0x01,
                    "frame {i} on link {} is neither a leading handshake part nor sealed",
                    hex::encode(link)
                );
            }
        }
    }
}

/// Whether `node` opened its first link with a handshake.
fn dialled_with_handshake(tapped: &[([u8; 16], Vec<u8>)]) -> bool {
    tapped.first().is_some_and(|(_, f)| f.starts_with(b"CTKX"))
}

/// **Witness 1** — a sealed exchange crosses both ways (Channel fragments and
/// a Resource), and nothing on the wire is plaintext.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sealed_exchange_crosses_and_the_wire_carries_no_plaintext_e1() {
    let t = trio("ok", true, false).await;
    t.b.transport.set_link_wire_tap_for_test(true);
    t.a.transport.set_link_wire_tap_for_test(true);

    // Channel-first (a few fragments) and Resource-sized (over eight
    // fragments at the 16 KB loopback MTU).
    let marker = b"E1-ROW-MARKER-";
    let small = marked(marker, 3_000);
    let big = marked(marker, 200_000);
    for frame in [&small, &big] {
        t.b.transport
            .send(&t.a.key.key_id, frame)
            .await
            .expect("B -> A, sealed");
        let landed = wait_until(Duration::from_secs(30), || async {
            t.a.received(frame).await
        })
        .await;
        assert!(landed, "A delivered B's {}-byte frame upward", frame.len());
    }
    // A answers on the link B opened (the reverse path), sealed as the
    // responder.
    let back_marker = b"E1-REPLY-MARKER-";
    let reply = marked(back_marker, 5_000);
    t.a.transport
        .send(&t.b.key.key_id, &reply)
        .await
        .expect("A -> B on B's link, sealed");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.b.received(&reply).await
        })
        .await,
        "B delivered A's reply upward"
    );

    let b_wire = t.b.transport.link_wire_tapped_for_test();
    assert!(
        dialled_with_handshake(&b_wire),
        "B's link opened with its handshake"
    );
    assert_wire_is_sealed(&b_wire, marker);
    let a_wire = t.a.transport.link_wire_tapped_for_test();
    assert_wire_is_sealed(&a_wire, back_marker);
    assert!(t.b.seal("link_seal_initiated") >= 1);
    assert!(t.a.seal("link_seal_accepted") >= 1);
    for (n, side) in [(&t.a, "A"), (&t.b, "B")] {
        let refused: Vec<_> = n
            .metrics
            .link_seal()
            .into_iter()
            .filter(|(k, _)| {
                k.starts_with("link_seal_refused") || k.starts_with("link_seal_dropped")
            })
            .collect();
        assert!(refused.is_empty(), "{side} refused nothing: {refused:?}");
    }
}

/// **Witness 2** — a peer that never sends the handshake: the responder
/// delivers nothing and sends nothing, then refuses it by name
/// (`link_seal_refused_timeout`) and closes the link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_never_sends_the_handshake_is_refused_and_closed_e1() {
    let t = trio("skip", true, false).await;
    t.a.transport.set_link_wire_tap_for_test(true);
    let dest =
        t.b.transport
            .peer_dest_hash_for_test(&t.a.key.key_id)
            .await
            .expect("A's dest at B");
    t.b.transport
        .set_handshake_override_for_test(HandshakeOverride::Skip);
    let opened =
        t.b.transport
            .link_open(&dest, Duration::from_secs(20))
            .await;
    assert!(
        opened.is_err(),
        "the seam leaves the link unkeyed: {opened:?}"
    );
    let refused = wait_until(Duration::from_secs(30), || async {
        t.a.seal("link_seal_refused_timeout") == 1
    })
    .await;
    assert!(refused, "A refused by name: {:?}", t.a.metrics.link_seal());
    assert!(
        wait_until(Duration::from_secs(10), || async {
            t.a.transport.link_count().await == 0
        })
        .await,
        "A closed the link"
    );
    assert!(
        t.a.transport.link_wire_tapped_for_test().is_empty(),
        "A sent nothing on a link that never keyed"
    );
    assert!(
        t.a.seen.lock().await.is_empty(),
        "A delivered nothing upward"
    );
    assert_eq!(t.a.seal("link_seal_accepted"), 0);
    assert_eq!(
        t.b.seal("link_seal_refused_frame_before_keys"),
        0,
        "nothing reached B before keys"
    );
}

/// **Witness 3** — a first frame that is not a transit KEX handshake (here a
/// plaintext envelope) is refused by name and the link closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_non_ctkx_first_frame_is_refused_by_name_e1() {
    let t = trio("plain", true, false).await;
    t.b.transport
        .set_handshake_override_for_test(HandshakeOverride::FirstFrame(
            br#"{"message_type":"OpaqueRequest","plaintext":true}"#.to_vec(),
        ));
    let _ =
        t.b.transport
            .send(&t.a.key.key_id, b"never-delivered")
            .await;
    let refused = wait_until(Duration::from_secs(20), || async {
        t.a.seal("link_seal_refused_not_a_handshake") == 1
    })
    .await;
    assert!(refused, "{:?}", t.a.metrics.link_seal());
    assert!(
        t.a.seen.lock().await.is_empty(),
        "A delivered nothing upward"
    );
}

/// **Witness 3b** — a well-framed handshake naming a classical-only suite is
/// refused by name (`link_seal_refused_suite`), never answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_classical_only_suite_is_refused_by_name_e1() {
    let t = trio("suite", true, false).await;
    let pair =
        ciris_persist::federation::self_at_login::transit_kex_pair_for(&*t.b.dir, &t.a.key.key_id)
            .await
            .expect("read A's pair")
            .expect("A publishes a pair");
    let (hs, _) = ciris_crypto::transit_kex::initiate(
        &[0u8; 16],
        &t.b.key.key_id,
        &t.a.key.key_id,
        &pair.x25519,
        &pair.ml_kem_768[..],
    )
    .expect("initiate");
    let mut bytes = hs.to_bytes();
    let id_len = usize::from(bytes[0]);
    let classical = b"transit_x25519_only_hkdf_sha256_____";
    bytes[1..=id_len].copy_from_slice(&classical[..id_len]);
    let frames = ciris_edge::transport::av_transit_handshake::fragment(&bytes, 16_000)
        .expect("one frame at the loopback MTU");
    assert_eq!(frames.len(), 1);
    t.b.transport
        .set_handshake_override_for_test(HandshakeOverride::FirstFrame(frames[0].clone()));
    let _ =
        t.b.transport
            .send(&t.a.key.key_id, b"never-delivered")
            .await;
    let refused = wait_until(Duration::from_secs(20), || async {
        t.a.seal("link_seal_refused_suite") == 1
    })
    .await;
    assert!(refused, "{:?}", t.a.metrics.link_seal());
    assert!(
        t.a.seen.lock().await.is_empty(),
        "A delivered nothing upward"
    );
}

/// **Witness 4** — a dial to a node with no Rooted transit pair (B never got
/// A's route) is refused by name and never made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_to_a_peer_with_no_rooted_pair_is_refused_and_never_made_e1() {
    let t = trio("nopair", false, false).await;
    match t.b.transport.send(&t.a.key.key_id, b"never-sent").await {
        Err(TransportError::LinkSealRefused { peer, reason, .. }) => {
            assert_eq!(peer, t.a.key.key_id);
            assert_eq!(reason, "link_seal_refused_no_pair");
        }
        other => panic!("a dial to a pair-less node must be refused by name: {other:?}"),
    }
    assert!(t.b.seal("link_seal_refused_no_pair") >= 1);
    assert_eq!(t.b.seal("link_seal_initiated"), 0, "nothing was keyed");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(t.a.transport.link_count().await, 0, "no link was ever made");
    assert_eq!(t.a.seal("link_seal_accepted"), 0);
}

/// **Witness 5** — B's handshake claims C while the link proves B: refused at
/// A by name, nothing B sends on it is delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claim_that_is_not_the_links_peer_is_refused_e1() {
    let t = trio("claim", true, false).await;
    t.b.transport
        .set_handshake_override_for_test(HandshakeOverride::Claim(t.c.key.key_id.clone()));
    let lie = marked(b"E1-LIAR-", 2_000);
    let _ = t.b.transport.send(&t.a.key.key_id, &lie).await;
    let refused = wait_until(Duration::from_secs(20), || async {
        t.a.seal("link_seal_refused_claim_mismatch") == 1
    })
    .await;
    assert!(refused, "{:?}", t.a.metrics.link_seal());
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !t.a.received(&lie).await,
        "nothing on the liar's link was delivered"
    );
}

/// **Witness 6** — the first-contact carve-out. An unannounced C (no binding
/// at A, so its links are unattributable there) dials A: the link is sealed,
/// and C's `OpaqueRequest` (the device-join plane) is delivered. A frame of
/// any other plane on that link is refused by name and the link closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_contact_rides_sealed_and_nothing_else_on_an_unattributed_link_e1() {
    let t = trio("fc", true, true).await;
    t.c.transport.set_link_wire_tap_for_test(true);
    let request = serde_json::to_vec(&serde_json::json!({
        "message_type": "OpaqueRequest",
        "signing_key_id": t.c.key.key_id,
        "body": {"kind": 2, "payload": "device-join-e1"},
    }))
    .expect("json");
    t.c.transport
        .send(&t.a.key.key_id, &request)
        .await
        .expect("C -> A, sealed first contact");
    let landed = wait_until(Duration::from_secs(30), || async {
        t.a.received(&request).await
    })
    .await;
    assert!(
        landed,
        "A delivered C's first contact: {:?}",
        t.a.metrics.link_seal()
    );
    {
        let seen = t.a.seen.lock().await;
        let f = seen
            .iter()
            .find(|f| f.envelope_bytes == request)
            .expect("the request");
        assert!(f.source_key_id.is_none(), "C is unattributed at A");
        assert!(f.link_key_id.is_none(), "C is unattributed at A");
    }
    assert!(t.a.seal("link_seal_accepted") >= 1);
    let c_wire = t.c.transport.link_wire_tapped_for_test();
    assert!(
        dialled_with_handshake(&c_wire),
        "C's link opened with its handshake"
    );
    assert_wire_is_sealed(&c_wire, b"device-join-e1");

    // Anything but first contact on that link: refused, closed.
    let other = b"{\"message_type\":\"OpaqueEvent\",\"body\":{}}".to_vec();
    let _ = t.c.transport.send(&t.a.key.key_id, &other).await;
    let refused = wait_until(Duration::from_secs(20), || async {
        t.a.seal("link_seal_refused_first_contact_only") == 1
    })
    .await;
    assert!(refused, "{:?}", t.a.metrics.link_seal());
    assert!(
        !t.a.received(&other).await,
        "the non-first-contact frame was not delivered"
    );
}
