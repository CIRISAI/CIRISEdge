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
    RouteAnswerOverride,
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
        self.record_as("node").await
    }
    /// [`Self::record`] registered under `kind` (CIRISEdge#888: an agent key).
    async fn record_as(&self, kind: &str) -> ciris_persist::federation::KeyRecord {
        let mut envelope = serde_json::json!({});
        ciris_persist::federation::admission::bind_subject_into_envelope(
            &mut envelope,
            &self.key_id,
            kind,
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
            identity_type: kind.to_string(),
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
    fn binding(&self, label: &str) -> u64 {
        self.metrics.peer_binding().get(label).copied().unwrap_or(0)
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
/// `c_fresh`: `C` is a fresh device whose directory holds only the baked
/// trust bundle (and its own key); it is given nothing about `A` but what
/// `A`'s announce carries.
async fn trio(tag: &str, seed_a_at_clients: bool, c_unannounced: bool, c_fresh: bool) -> Trio {
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
        let dir = if i == 2 && c_fresh {
            fresh_device_directory(records[2].clone()).await
        } else {
            directory_with(records.clone()).await
        };
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
        if !c_fresh {
            seed_route(&a, &c).await;
        }
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

/// A fresh device's directory: persist's baked trust bundle (its holders and
/// serve-nodes, admitted where the build's trust root admits them) and the
/// device's own key. Nothing about any other node.
async fn fresh_device_directory(own: ciris_persist::federation::KeyRecord) -> Arc<SqliteBackend> {
    let dir = directory_with(vec![own]).await;
    let bundle = ciris_persist::federation::genesis::canonical_genesis_bundle();
    for rec in bundle.holders.iter().chain(bundle.serve_nodes.iter()) {
        // A test build's trust root may refuse production rows; what the
        // fresh device holds is whatever the bundle can give it.
        let _ = dir.put_public_key(rec.clone()).await;
    }
    dir
}

/// A key-carrying first-contact `OpaqueRequest` (the device-join kind) as it
/// rides the wire, signed-by `signer` and introducing `record`. The signature
/// is not checked by the transport; the bindings it checks are the key ids.
fn first_contact_request(
    signer: &str,
    to: &str,
    record: &ciris_persist::federation::KeyRecord,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "edge_schema_version": "v2_0_0",
        "signing_key_id": signer,
        "destination_key_id": to,
        "message_type": "OpaqueRequest",
        "sent_at": chrono::Utc::now(),
        "nonce": vec![7u8; 16],
        "body": {
            "kind": 2,
            "payload": [1, 2, 3],
            // persist v59 — the sender's own `key:record:v1` row, the one
            // carriage of its key persist admits.
            "key_record_row": ciris_persist::federation::key_plane::plan_key_record_row(record, &None)
                .expect("key:record:v1 row"),
            "challenge": "00".repeat(32),
        },
        "signature": "unchecked-at-the-transport",
    }))
    .expect("json")
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
    let t = trio("ok", true, false, false).await;
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
    // CIRISEdge#879 — the on-link announce binds in BOTH directions on a clean
    // dial: the responder's (A's) announce at the dialler (B), which never
    // receives a LINKIDENTIFY, binds to the destination B dialled; B's at A
    // binds to B's identify. No `announce_frame_link_unidentified` drop.
    assert!(
        wait_until(Duration::from_secs(10), || async {
            t.b.binding("announce_frame_bound") >= 1 && t.a.binding("announce_frame_bound") >= 1
        })
        .await,
        "both ends bind the other's on-link announce: A {:?} B {:?}",
        t.a.metrics.peer_binding(),
        t.b.metrics.peer_binding()
    );
    for (n, side) in [(&t.a, "A"), (&t.b, "B")] {
        let drops = n.metrics.transport_inbound_drops();
        assert_eq!(
            drops
                .get("announce_frame_link_unidentified")
                .copied()
                .unwrap_or(0),
            0,
            "{side} dropped no on-link announce as unidentified: {drops:?}"
        );
        assert_eq!(
            drops
                .get("announce_frame_identity_mismatch")
                .copied()
                .unwrap_or(0),
            0,
            "{side}: {drops:?}"
        );
    }
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

/// **Witness 1b** — a Resource that beats the handshake is HELD, not lost.
/// The Resource and the Channel ride different event planes, so on a loaded
/// node a dialler's first Resource can complete at the responder before its
/// last handshake part (seen on the v43.1.0 tag CI, `link_seal_dropped_before_keys`).
/// The sender's Resource had completed, so dropping it lost a frame the
/// sender counts as delivered. Here B holds its handshake's last part back
/// until its Resource completes (`HandshakeOverride::DeferLastPart`): A holds
/// the sealed Resource (`link_seal_held_before_keys`), opens it once the link
/// is keyed, and delivers it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_resource_that_beats_the_handshake_is_held_and_delivered_e1() {
    let t = trio("resfirst", true, false, false).await;
    // No on-link announce from B (A already holds B's binding from its RNS
    // announce): the Channel then carries only the handshake, so holding its
    // last part back reorders nothing on the Channel itself.
    t.b.transport.set_unannounced_for_test(true);
    t.b.transport
        .set_handshake_override_for_test(HandshakeOverride::DeferLastPart);
    // Resource-sized: over eight fragments at the loopback MTU.
    let big = marked(b"E1-RESOURCE-FIRST-", 200_000);
    t.b.transport
        .send(&t.a.key.key_id, &big)
        .await
        .expect("B -> A, its Resource ahead of its last handshake part");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(&big).await
        })
        .await,
        "A delivered the Resource that beat the handshake: {:?}",
        t.a.metrics.link_seal()
    );
    assert!(
        t.a.seal("link_seal_held_before_keys") >= 1,
        "the Resource arrived before the keys and was held: {:?}",
        t.a.metrics.link_seal()
    );
    assert_eq!(t.a.seal("link_seal_dropped_before_keys"), 0);
}

/// **Witness 2** — a peer that never sends the handshake: the responder
/// delivers nothing and sends nothing, then refuses it by name
/// (`link_seal_refused_timeout`) and closes the link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_never_sends_the_handshake_is_refused_and_closed_e1() {
    let t = trio("skip", true, false, false).await;
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
    let t = trio("plain", true, false, false).await;
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
    let t = trio("suite", true, false, false).await;
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

/// **Witness 4** — B knows A ONLY by A's announce: no signed route row of
/// A's crossed, so no pair is authenticated to A from any held source. A
/// bare announce never supplies a pair (CC 3.3.6.2, rc9 I2): the dial does
/// not key on the announce, it FETCHES A's own signed route row over the
/// link as its first frame and keys on that (CC 5.3.3.5 E1 pre-seal route
/// fetch, `CLM-pre-seal-route-fetch`). Here A's receiver order refuses the
/// request (cap 0), so nothing is keyed, nothing is stored and nothing is
/// delivered; with the order open again the same dial seals.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bare_announce_supplies_no_pair_and_a_refused_fetch_keys_nothing_e1() {
    let t = trio("nopair", false, false, false).await;
    assert!(t.b.transport.knows_peer(&t.a.key.key_id).await);
    assert!(
        t.b.dir
            .list_signed_transport_destinations_for(&t.a.key.key_id)
            .await
            .expect("list")
            .is_empty(),
        "B holds no signed route row of A"
    );
    // The receiver order runs BEFORE the request is read: at cap 0 every
    // request is refused, counted, and nothing of it is looked up.
    t.a.transport.set_route_request_cap_for_test(0);
    match t.b.transport.send(&t.a.key.key_id, b"never-sent").await {
        Err(TransportError::LinkSealRefused { peer, reason, .. }) => {
            assert_eq!(peer, t.a.key.key_id);
            assert!(
                reason == "link_seal_refused_route_closed"
                    || reason == "link_seal_refused_route_timeout",
                "B's fetch is refused by name, not keyed another way: {reason}"
            );
        }
        other => panic!("a dial whose fetch is refused must be refused by name: {other:?}"),
    }
    assert_eq!(
        t.a.seal("link_seal_refused_route_rate_limited"),
        1,
        "{:?}",
        t.a.metrics.link_seal()
    );
    assert_eq!(
        t.a.seal("link_seal_route_requested"),
        0,
        "refused before it was read"
    );
    assert_eq!(t.a.seal("link_seal_route_answered"), 0);
    assert_eq!(t.a.seal("link_seal_accepted"), 0);
    assert_eq!(t.b.seal("link_seal_initiated"), 0, "nothing was keyed");
    assert!(
        t.b.dir
            .list_signed_transport_destinations_for(&t.a.key.key_id)
            .await
            .expect("list")
            .is_empty(),
        "the announce supplied no row and the refused fetch stored none"
    );
    assert!(
        t.a.seen.lock().await.is_empty(),
        "A delivered nothing upward"
    );

    // The order open again: the same dial fetches, verifies and seals.
    t.a.transport.set_route_request_cap_for_test(32);
    t.b.transport
        .send(&t.a.key.key_id, b"after-the-fetch")
        .await
        .expect("B -> A seals after the route fetch");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(b"after-the-fetch").await
        })
        .await,
        "A delivered B's frame once the link was sealed"
    );
    assert!(
        t.b.seal("link_seal_pair_route_fetch") >= 1,
        "{:?}",
        t.b.metrics.link_seal()
    );
}

/// Every frame a node handed leviculum on `link`, in order.
fn frames_on(tapped: &[([u8; 16], Vec<u8>)], link: [u8; 16]) -> Vec<Vec<u8>> {
    tapped
        .iter()
        .filter(|(l, _)| *l == link)
        .map(|(_, f)| f.clone())
        .collect()
}

/// **Route fetch 1** — two strangers seal after the pre-seal route fetch:
/// B holds nothing of A but its announce. B's first frame on the link is the
/// route request (`CTKR`), A's only unsealed frames are the answer (`CTKA`,
/// its own signed route row), B verifies the row, stores it, and its
/// handshake follows; then the exchange crosses sealed both ways. A second
/// send reuses the keyed link: no second request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_strangers_seal_after_the_pre_seal_route_fetch_e1() {
    let t = trio("fetch", false, false, false).await;
    t.b.transport.set_link_wire_tap_for_test(true);
    t.a.transport.set_link_wire_tap_for_test(true);
    assert!(
        t.b.dir
            .list_signed_transport_destinations_for(&t.a.key.key_id)
            .await
            .expect("list")
            .is_empty(),
        "B holds no signed route row of A before the dial"
    );
    let marker = b"E1-FETCH-MARKER-";
    let row = marked(marker, 3_000);
    t.b.transport
        .send(&t.a.key.key_id, &row)
        .await
        .expect("B -> A, fetched then sealed");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(&row).await
        })
        .await,
        "A delivered B's frame"
    );
    // B now holds A's own signed row, obtained over the link and admitted
    // through persist's authenticated door.
    let held =
        t.b.dir
            .list_signed_transport_destinations_for(&t.a.key.key_id)
            .await
            .expect("list");
    assert_eq!(held.len(), 1, "B holds A's fetched route row");
    assert_eq!(held[0].attesting_key_id, t.a.key.key_id);
    assert!(
        t.b.seal("link_seal_route_request_sent") >= 1,
        "{:?}",
        t.b.metrics.link_seal()
    );
    assert!(t.b.seal("link_seal_pair_route_fetch") >= 1);
    assert!(t.b.seal("link_seal_initiated") >= 1);
    assert!(
        t.a.seal("link_seal_route_requested") >= 1,
        "{:?}",
        t.a.metrics.link_seal()
    );
    assert!(t.a.seal("link_seal_route_answered") >= 1);
    assert!(t.a.seal("link_seal_accepted") >= 1);

    // The wire: B's first frame is the request, then its handshake, then
    // sealed frames; nothing carries the marker.
    let b_wire = t.b.transport.link_wire_tapped_for_test();
    let first_link = b_wire.first().expect("B sent on a link").0;
    let b_frames = frames_on(&b_wire, first_link);
    assert!(
        b_frames[0].starts_with(b"CTKR"),
        "B's first frame is the route request"
    );
    assert!(
        b_frames[1].starts_with(b"CTKX"),
        "B's handshake follows the answer"
    );
    let parts = 1 + b_frames[1..]
        .iter()
        .take_while(|f| f.starts_with(b"CTKX"))
        .count();
    for (i, f) in b_frames.iter().enumerate().skip(parts) {
        assert_eq!(f[0], 0x01, "B frame {i} is sealed");
    }
    assert!(
        b_frames.iter().all(|f| !contains(f, marker)),
        "no plaintext marker on B's wire"
    );

    // A sealed answer back on B's link, and the same link reused without a
    // second request.
    let reply = marked(b"E1-FETCH-REPLY-", 2_000);
    t.a.transport
        .send(&t.b.key.key_id, &reply)
        .await
        .expect("A -> B on B's link");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.b.received(&reply).await
        })
        .await,
        "B delivered A's reply"
    );
    let sent_before = t.b.seal("link_seal_route_request_sent");
    t.b.transport
        .send(&t.a.key.key_id, b"second-send")
        .await
        .expect("B -> A again");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(b"second-send").await
        })
        .await
    );
    assert_eq!(
        t.b.seal("link_seal_route_request_sent"),
        sent_before,
        "the keyed link is reused; a held row is not fetched again"
    );
}

/// **Route fetch 1b** — a FRESH stranger (its directory holds the baked
/// bundle and its own key, nothing of A) fetches A's key record WITH the
/// route: the answer carries A's `key:record:v1` row, admitted through
/// persist's key door before the route row is verified against it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_stranger_fetches_the_key_record_with_the_route_e1() {
    let t = trio("fetchfresh", false, false, true).await;
    assert!(
        t.c.dir
            .lookup_public_key(&t.a.key.key_id)
            .await
            .expect("lookup")
            .is_none(),
        "C holds no key record of A before the dial"
    );
    t.c.transport
        .send(&t.a.key.key_id, b"from-a-fresh-stranger")
        .await
        .expect("C -> A, key record and route fetched, then sealed");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(b"from-a-fresh-stranger").await
        })
        .await,
        "A delivered C's frame"
    );
    assert!(
        t.c.dir
            .lookup_public_key(&t.a.key.key_id)
            .await
            .expect("lookup")
            .is_some(),
        "C admitted A's key record from the answer"
    );
    assert_eq!(
        t.c.dir
            .list_signed_transport_destinations_for(&t.a.key.key_id)
            .await
            .expect("list")
            .len(),
        1,
        "C holds A's fetched route row"
    );
    assert!(
        t.c.seal("link_seal_pair_route_fetch") >= 1,
        "{:?}",
        t.c.metrics.link_seal()
    );
}

/// **Route fetch 2** — a responder whose first frames are not a route
/// answer: the dialler refuses the link by name, keys nothing, stores
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_route_answer_that_is_not_an_answer_refuses_the_link_e1() {
    let t = trio("fetchgarbage", false, false, false).await;
    t.a.transport
        .set_route_answer_override_for_test(RouteAnswerOverride::Garbage);
    match t.b.transport.send(&t.a.key.key_id, b"never-sent").await {
        Err(TransportError::LinkSealRefused { reason, .. }) => {
            assert_eq!(reason, "link_seal_refused_route_answer");
        }
        other => panic!("refused by name: {other:?}"),
    }
    assert_eq!(
        t.b.seal("link_seal_refused_route_answer"),
        1,
        "{:?}",
        t.b.metrics.link_seal()
    );
    assert_eq!(t.b.seal("link_seal_initiated"), 0, "nothing was keyed");
    assert!(
        t.b.dir
            .list_signed_transport_destinations_for(&t.a.key.key_id)
            .await
            .expect("list")
            .is_empty(),
        "nothing was stored"
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(t.a.seal("link_seal_accepted"), 0);
    assert!(t.a.seen.lock().await.is_empty());
}

/// **Route fetch 3** — an answer whose row is signed by, and about, ANOTHER
/// key (A answers with B's own row, which it holds) is refused by name and
/// never stored: the dialler keys only on the dialled key's own row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_route_answer_signed_by_another_key_is_refused_and_never_stored_e1() {
    let t = trio("fetchsigner", false, false, false).await;
    t.a.transport
        .set_route_answer_override_for_test(RouteAnswerOverride::RowOf(t.b.key.key_id.clone()));
    match t.b.transport.send(&t.a.key.key_id, b"never-sent").await {
        Err(TransportError::LinkSealRefused { reason, .. }) => {
            assert_eq!(reason, "link_seal_refused_route_answer_signer");
        }
        other => panic!("refused by name: {other:?}"),
    }
    assert_eq!(
        t.b.seal("link_seal_refused_route_answer_signer"),
        1,
        "{:?}",
        t.b.metrics.link_seal()
    );
    assert_eq!(t.b.seal("link_seal_initiated"), 0, "nothing was keyed");
    assert!(
        t.b.dir
            .list_signed_transport_destinations_for(&t.a.key.key_id)
            .await
            .expect("list")
            .is_empty(),
        "a row about another key was never stored under A"
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(t.a.seal("link_seal_accepted"), 0);
}

/// **Route fetch 4** — nothing is served before the seal on a fetched link:
/// A's unsealed frames on B's link are the answer parts and nothing else;
/// every frame after them (A's announce, its bundle, its replies) is sealed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_is_served_before_the_seal_on_a_fetched_link_e1() {
    let t = trio("fetchquiet", false, false, false).await;
    t.a.transport.set_link_wire_tap_for_test(true);
    t.b.transport
        .send(&t.a.key.key_id, b"quiet-until-sealed")
        .await
        .expect("B -> A");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(b"quiet-until-sealed").await
        })
        .await
    );
    // A speaks on the link (sealed) once keyed: wait for its announce to go
    // out, then read the wire.
    assert!(
        wait_until(Duration::from_secs(20), || async {
            !t.a.transport.link_wire_tapped_for_test().is_empty()
        })
        .await
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    let a_wire = t.a.transport.link_wire_tapped_for_test();
    let link = a_wire.first().expect("A sent on B's link").0;
    let frames = frames_on(&a_wire, link);
    let answer_parts = frames.iter().take_while(|f| f.starts_with(b"CTKA")).count();
    assert!(answer_parts >= 1, "A's first frames are the route answer");
    assert!(
        frames.len() > answer_parts,
        "A spoke on the link once it was sealed (its announce rides it)"
    );
    for (i, f) in frames.iter().enumerate().skip(answer_parts) {
        assert_eq!(f[0], 0x01, "A frame {i} after the answer is sealed");
        assert!(!f.starts_with(b"CTKA"), "no answer part after the seal");
    }
}

/// **Witness 5** — B's handshake claims C while the link proves B: refused at
/// A by name, nothing B sends on it is delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claim_that_is_not_the_links_peer_is_refused_e1() {
    let t = trio("claim", true, false, false).await;
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
    let t = trio("fc", true, true, false).await;
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

/// **CLM-first-contact-seal-key-bound (CC 3.2 adding-a-device (e))** — on an
/// unattributed sealed link the
/// request must be signed by the handshake's initiator key. An unannounced C
/// opens the link (its handshake names C) and sends a device-join signed by,
/// and introducing, B: refused by name (`link_seal_refused_first_contact_signer`),
/// not delivered, the link closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_first_contact_request_signed_by_a_key_other_than_the_handshake_initiator_is_refused_e1()
{
    let t = trio("fcsigner", true, true, false).await;
    let b_record = t.b.key.record().await;
    let forged = first_contact_request(&t.b.key.key_id, &t.a.key.key_id, &b_record);
    let _ = t.c.transport.send(&t.a.key.key_id, &forged).await;
    let refused = wait_until(Duration::from_secs(20), || async {
        t.a.seal("link_seal_refused_first_contact_signer") == 1
    })
    .await;
    assert!(refused, "{:?}", t.a.metrics.link_seal());
    assert!(
        !t.a.received(&forged).await,
        "the mis-signed request was not delivered"
    );
    assert_eq!(t.a.seal("link_seal_refused_first_contact_only"), 0);
}

/// **CLM-first-contact-seal-key-bound (CC 3.2 adding-a-device (e))** — the
/// matching code an owner compares
/// is derived from the handshake's initiator key: A reads the initiator off
/// the sealed link the request arrived on, and the code it derives
/// (`first_contact::first_contact_matching_code`, the v2 SAS) is the code over
/// C's own Ed25519 key. Named as any other key, the derivation refuses.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_matching_code_is_derived_from_the_handshake_initiator_key_e1() {
    use ciris_edge::first_contact::{first_contact_matching_code, MatchingCodeError};
    let t = trio("fccode", true, true, false).await;
    let c_record = t.c.key.record().await;
    let request = first_contact_request(&t.c.key.key_id, &t.a.key.key_id, &c_record);
    t.c.transport
        .send(&t.a.key.key_id, &request)
        .await
        .expect("C -> A, sealed first contact");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(&request).await
        })
        .await,
        "A delivered C's request: {:?}",
        t.a.metrics.link_seal()
    );
    let link = {
        let seen = t.a.seen.lock().await;
        seen.iter()
            .find(|f| f.envelope_bytes == request)
            .and_then(|f| f.reply_path.as_ref())
            .expect("the request's link")
            .token()
    };
    let initiator =
        t.a.transport
            .link_initiator_key_id(link)
            .expect("A responded on C's link");
    assert_eq!(initiator, t.c.key.key_id, "the handshake named C");
    let a_pub: [u8; 32] = t.a.key.ed_pub.clone().try_into().expect("32-byte key");
    let c_pub: [u8; 32] = t.c.key.ed_pub.clone().try_into().expect("32-byte key");
    let code = first_contact_matching_code(&a_pub, &request, &initiator).expect("the code");
    assert_eq!(
        code,
        ciris_edge::sas::peer_sas_digits_versioned(
            &a_pub,
            &c_pub,
            ciris_edge::sas::DEFAULT_SAS_DIGITS,
            ciris_edge::sas::SasVersion::V2,
        )
        .expect("sas"),
        "the code is over the initiator's own key"
    );
    assert!(matches!(
        first_contact_matching_code(&a_pub, &request, &t.b.key.key_id),
        Err(MatchingCodeError::KeysDisagree { .. })
    ));
}

// The fresh device that holds only a v4 bundle and reaches its owner's node
// in two hops (sealed to the bundle-seeded canonical, the owner node's route
// replicated from it, then a sealed first contact) is
// `sealed_cut_bundle_e1::a_fresh_device_reaches_its_owners_node_through_a_bundle_seeded_canonical_e1`:
// the test anchor it arms is process-wide, so it runs in that binary.

// ─── CC 3.2 adding-a-device (f): the pairing-pinned transit pair ─────

/// An `OpaqueResponse` / any other envelope of `message_type`, as A answers
/// on the link a request arrived on.
fn envelope_of(message_type: &str, from: &str, to: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "edge_schema_version": "v2_0_0",
        "signing_key_id": from,
        "destination_key_id": to,
        "message_type": message_type,
        "sent_at": chrono::Utc::now(),
        "nonce": vec![9u8; 16],
        "body": {"kind": 2, "status": 200, "payload": [4, 5, 6]},
        "signature": "unchecked-at-the-transport",
    }))
    .expect("json")
}

/// A pinned first contact from the fresh, unannounced C to A: returns C's
/// request and the link it rode, once A has delivered it.
async fn pinned_first_contact(t: &Trio) -> (Vec<u8>, [u8; 16]) {
    let pin = t.a.transport.pairing_transit_pin();
    let c_record = t.c.key.record().await;
    let request = first_contact_request(&t.c.key.key_id, &t.a.key.key_id, &c_record);
    let link =
        t.c.transport
            .send_first_contact_pinned(&pin, &request)
            .await
            .expect("C -> A over the pinned pair");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(&request).await
        })
        .await,
        "A delivered C's pinned first contact: {:?}",
        t.a.metrics.link_seal()
    );
    (request, link)
}

/// The link at A that `request` arrived on.
async fn arrival_link(node: &Node, bytes: &[u8]) -> ciris_edge::transport::ReplyPath {
    node.seen
        .lock()
        .await
        .iter()
        .find(|f| f.envelope_bytes == bytes)
        .and_then(|f| f.reply_path)
        .expect("the frame's link")
}

/// **CLM-pairing-payload-transit-pin (CC 3.2 adding-a-device (f)); CC
/// 5.3.3.5 E1** — a fresh device that holds no Rooted route for its owner's
/// node (no bundle row and no replicated route yet) seals its first contact
/// with the pair the owner's pairing payload pins: the handshake is the first
/// frame, every frame after it is sealed, A answers it unattributed under
/// CC 3.2 (e)'s key-bound rules, and A's `OpaqueResponse` comes back on that
/// link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_device_seals_first_contact_with_a_pairing_pinned_pair_e1() {
    let t = trio("pinok", true, true, true).await;
    assert!(
        ciris_persist::federation::self_at_login::transit_kex_pair_for(&*t.c.dir, &t.a.key.key_id)
            .await
            .expect("directory")
            .is_none(),
        "precondition: no Rooted pair for A at the fresh device"
    );
    t.c.transport.set_link_wire_tap_for_test(true);
    let (request, link) = pinned_first_contact(&t).await;
    assert!(t.c.transport.link_is_pinned_for_test(link));
    assert!(t.a.seal("link_seal_accepted") >= 1);
    {
        let seen = t.a.seen.lock().await;
        let f = seen
            .iter()
            .find(|f| f.envelope_bytes == request)
            .expect("the request");
        assert!(
            f.source_key_id.is_none() && f.link_key_id.is_none(),
            "C is unattributed at A"
        );
    }
    let wire = t.c.transport.link_wire_tapped_for_test();
    assert!(
        dialled_with_handshake(&wire),
        "the pinned link opened with its handshake"
    );
    assert_wire_is_sealed(&wire, b"\"key_record\"");
    // A answers on the link the request arrived on; C delivers it.
    let path = arrival_link(&t.a, &request).await;
    let response = envelope_of("OpaqueResponse", &t.a.key.key_id, &t.c.key.key_id);
    t.a.transport
        .send_on_reply_path_only(&t.c.key.key_id, &path, &response)
        .await
        .expect("A answers on C's link");
    assert!(
        wait_until(Duration::from_secs(20), || async {
            t.c.received(&response).await
        })
        .await,
        "C delivered A's answer: {:?}",
        t.c.metrics.link_seal()
    );
}

/// **CLM-pairing-payload-transit-pin (CC 3.2 adding-a-device (f))** — the pin
/// keys that one link and is never a route: after the pinned first contact the
/// fresh device's directory holds no signed route for A and
/// `transit_kex_pair_for` still answers `None`. An ordinary send to A neither
/// rides nor re-keys from the pinned link: it opens a fresh link and keys it
/// on A's own signed row fetched over that link (the pre-seal route fetch),
/// a row that is held as A's own, never as Rooted and never as the pin.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pinned_pair_is_never_stored_or_resolved_as_rooted_e1() {
    let t = trio("pinroot", true, true, true).await;
    let (_request, _link) = pinned_first_contact(&t).await;
    let routes =
        t.c.dir
            .list_signed_transport_destinations_for(&t.a.key.key_id)
            .await
            .expect("list");
    assert!(
        routes.is_empty(),
        "the pin was never written as a route: {routes:?}"
    );
    assert!(
        ciris_persist::federation::self_at_login::transit_kex_pair_for(&*t.c.dir, &t.a.key.key_id)
            .await
            .expect("directory")
            .is_none(),
        "the pin never resolves as Rooted"
    );
    let keyed = t.c.seal("link_seal_initiated");
    let pinned = t.c.seal("link_seal_pair_pin");
    // The send keys a fresh link on A's fetched row. C is UNANNOUNCED here
    // (an unowned fresh device), so A cannot attribute that link and the
    // ordinary row is refused at A by the first-contact carve-out: only the
    // first-contact plane rides an unattributed link (CC 3.2 (e)).
    let _ =
        t.c.transport
            .send(&t.a.key.key_id, b"an-ordinary-row")
            .await;
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.seal("link_seal_refused_first_contact_only") >= 1
        })
        .await,
        "A refused the ordinary row on the unattributed link: {:?}",
        t.a.metrics.link_seal()
    );
    assert!(!t.a.received(b"an-ordinary-row").await);
    assert_eq!(
        t.c.seal("link_seal_initiated"),
        keyed + 1,
        "a fresh link was keyed; the pinned one was not reused"
    );
    assert_eq!(
        t.c.seal("link_seal_pair_pin"),
        pinned,
        "the pin keyed nothing else"
    );
    assert_eq!(
        t.c.seal("link_seal_pair_route_fetch"),
        1,
        "{:?}",
        t.c.metrics.link_seal()
    );
    let routes =
        t.c.dir
            .list_signed_transport_destinations_for(&t.a.key.key_id)
            .await
            .expect("list");
    assert_eq!(
        routes.len(),
        1,
        "the fetched row, A's own, is what C now holds"
    );
    assert_eq!(
        routes[0].attesting_key_id, t.a.key.key_id,
        "held because it was fetched and verified as A's own, not because of the pin"
    );
}

/// **CLM-pairing-payload-transit-pin (CC 3.2 adding-a-device (f));
/// CLM-first-contact-seal-key-bound (CC 3.2 (e))** — the pinned link carries
/// the first-contact plane and nothing else, both ways: C cannot seal any
/// other frame on it (`link_seal_refused_first_contact_only`), a request
/// signed by another key is refused before any dial
/// (`link_seal_refused_first_contact_signer`), and a frame from A on that link
/// other than first contact is refused at C and the link closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pinned_pair_link_carries_only_first_contact_e1() {
    let t = trio("pinonly", true, true, true).await;
    let (request, link) = pinned_first_contact(&t).await;
    // Outbound: nothing but first contact seals on the pinned link.
    let other = b"{\"message_type\":\"OpaqueEvent\",\"body\":{}}".to_vec();
    let path = ciris_edge::transport::ReplyPath::new(
        ciris_edge::transport::TransportId::RETICULUM_RS,
        link,
    );
    assert!(
        t.c.transport
            .send_on_reply_path_only(&t.a.key.key_id, &path, &other)
            .await
            .is_err(),
        "no other send path seals on the pinned link"
    );
    assert!(!t.a.received(&other).await);
    // A request signed by another key: refused before any dial.
    let b_record = t.b.key.record().await;
    let forged = first_contact_request(&t.b.key.key_id, &t.a.key.key_id, &b_record);
    match t
        .c
        .transport
        .send_first_contact_pinned(&t.a.transport.pairing_transit_pin(), &forged)
        .await
    {
        Err(TransportError::LinkSealRefused { reason, .. }) => {
            assert_eq!(reason, "link_seal_refused_first_contact_signer");
        }
        other => panic!("a mis-signed pinned request must be refused: {other:?}"),
    }
    // Inbound: A's answer of another plane on the pinned link is refused at C.
    let a_path = arrival_link(&t.a, &request).await;
    let event = envelope_of("OpaqueEvent", &t.a.key.key_id, &t.c.key.key_id);
    let _ =
        t.a.transport
            .send_on_reply_path_only(&t.c.key.key_id, &a_path, &event)
            .await;
    assert!(
        wait_until(Duration::from_secs(20), || async {
            t.c.seal("link_seal_refused_first_contact_only") >= 1
        })
        .await,
        "{:?}",
        t.c.metrics.link_seal()
    );
    assert!(
        !t.c.received(&event).await,
        "the other plane was not delivered at C"
    );
}

/// **CLM-pairing-payload-transit-pin (CC 3.2 adding-a-device (f))** — a pin
/// that is not the dialled node's own transit pair is refused: one whose keys
/// are another node's (B's) keys a handshake A cannot answer to the same
/// keys, so A refuses the first sealed frame
/// (`link_seal_refused_open_failed`) and nothing is delivered; one whose
/// shape is wrong is refused before any dial (`link_seal_refused_pin`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pinned_pair_that_is_not_the_nodes_responder_keys_is_refused_e1() {
    let t = trio("pinbad", true, true, true).await;
    let c_record = t.c.key.record().await;
    let request = first_contact_request(&t.c.key.key_id, &t.a.key.key_id, &c_record);
    // B's keys, bound to A's id.
    let mut wrong = t.b.transport.pairing_transit_pin();
    wrong.node_key_id = t.a.key.key_id.clone();
    let _ =
        t.c.transport
            .send_first_contact_pinned(&wrong, &request)
            .await;
    assert!(
        wait_until(Duration::from_secs(20), || async {
            t.a.seal("link_seal_refused_open_failed") + t.a.seal("link_seal_refused_kex") >= 1
        })
        .await,
        "A refuses a link keyed to keys it does not hold: {:?}",
        t.a.metrics.link_seal()
    );
    assert!(!t.a.received(&request).await, "nothing was delivered");
    // A truncated ML-KEM key: refused before any dial.
    let mut short = t.a.transport.pairing_transit_pin();
    short.ml_kem_768_base64 = "AAAA".to_owned();
    match t
        .c
        .transport
        .send_first_contact_pinned(&short, &request)
        .await
    {
        Err(TransportError::LinkSealRefused { reason, .. }) => {
            assert_eq!(reason, "link_seal_refused_pin");
        }
        other => panic!("a malformed pin must be refused by name: {other:?}"),
    }
}

/// **CC 5.3.3.5 E1** — a dialler's sealed frames can reach the responder
/// before leviculum has processed the link's identify (the two ride apart; the
/// release CI's `inbound_reap_853` and `opaque_conformance` caught it). Judged
/// then, the link reads as unattributed: the on-link announce cannot bind it
/// and the first-contact carve-out refuses the next frame and closes it. The
/// responder HOLDS opened frames until the identity is proven and replays
/// them in order, so the announce binds first and the frame is delivered,
/// attributed. Here B sends its identify only after its first frames.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frames_that_beat_the_identify_are_held_and_delivered_e1() {
    let t = trio("idlast", true, false, false).await;
    t.b.transport.identify_last_for_test();
    let row = marked(b"E1-EARLY-ROW-", 2_000);
    t.b.transport
        .send(&t.a.key.key_id, &row)
        .await
        .expect("B -> A, identify last");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(&row).await
        })
        .await,
        "A delivered the frame that beat the identify: {:?}",
        t.a.metrics.link_seal()
    );
    {
        let seen = t.a.seen.lock().await;
        let f = seen
            .iter()
            .find(|f| f.envelope_bytes == row)
            .expect("the row");
        assert_eq!(
            f.link_key_id.as_deref(),
            Some(t.b.key.key_id.as_str()),
            "attributed to B once its identity is proven"
        );
    }
    assert_eq!(t.a.seal("link_seal_refused_first_contact_only"), 0);
    assert_eq!(t.a.seal("link_seal_dropped_held_overflow"), 0);
}

/// **CC 5.3.3.5 E1** — an unattributed link is not yet a first-contact link.
/// The release CI's `reticulum_loopback` and `inbound_reap_853` caught a known
/// peer's link judged as first contact: its identify missed (the responder
/// held a stale binding for it), and the binding that names it landed AFTER
/// the identify, healed in the cold-start worker from the dialler's own
/// announce, which raises no link event. The link stayed unattributed for its
/// lifetime and the carve-out refused its first ordinary frame. Here A holds a
/// stale binding for B before B dials: the link attributes by the same match
/// the identify makes, re-run once the binding lands (a frame that arrives
/// first waits for it, `link_seal_held_for_attribution`), the frame is
/// delivered attributed to B, and nothing is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_known_peer_whose_binding_lands_after_its_identify_is_not_first_contact_e1() {
    let t = trio("bindlate", true, false, false).await;
    t.a.transport
        .inject_rooted_peer_for_test(&t.b.key.key_id, [0x5a; 16], [0u8; 32])
        .await;
    let row = marked(b"E1-LATE-BINDING-ROW-", 2_000);
    t.b.transport
        .send(&t.a.key.key_id, &row)
        .await
        .expect("B -> A on a fresh link");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            t.a.received(&row).await
        })
        .await,
        "A delivered B's frame once the link attributed: {:?}",
        t.a.metrics.link_seal()
    );
    {
        let seen = t.a.seen.lock().await;
        let f = seen
            .iter()
            .find(|f| f.envelope_bytes == row)
            .expect("the row");
        assert_eq!(
            f.link_key_id.as_deref(),
            Some(t.b.key.key_id.as_str()),
            "attributed to B"
        );
    }
    assert_eq!(t.a.seal("link_seal_refused_first_contact_only"), 0);
}

// ─── v43 InvalidProof triage: a peer binding whose key is not the
// destination's. CIRISServer's canonical boot prime stored the canonical's
// FEDERATION Ed25519 (`inject_rooted_peer_for_test`, no X25519 half) at its
// NAMED destination; a joiner that kept that key failed every dial with
// leviculum's `InvalidProof`, and nothing healed it. ─────────────────────

/// B's binding for A as the Server's canonical prime wrote it: A's named
/// destination, A's federation key.
async fn prime_federation_key(t: &Trio) -> [u8; 16] {
    let dest = t.a.transport.local_named_dest_hash();
    let fed: [u8; 32] = t.a.key.ed_pub.clone().try_into().expect("32-byte ed25519");
    t.b.transport
        .inject_rooted_peer_for_test(&t.a.key.key_id, dest, fed)
        .await;
    dest
}

/// **(a)** A's own announce heals the federation key B holds at A's named
/// destination (only A's transport identity reproduces it), trust kept; B's
/// dial then proves with the binding alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owners_announce_heals_a_primed_federation_key_and_the_dial_proves() {
    let t = trio("keyheal", true, false, false).await;
    // The binding alone: leviculum's announce-learned key (b) stays out.
    t.b.transport.binding_key_only_for_test(true);
    prime_federation_key(&t).await;
    let healed = wait_until(Duration::from_secs(30), || async {
        t.b.binding("peer_binding_transport_key_healed") >= 1
    })
    .await;
    assert!(
        healed,
        "A's announce healed the key: {:?}",
        t.b.metrics.peer_binding()
    );
    let row = marked(b"KEY-HEALED-ROW-", 600);
    t.b.transport
        .send(&t.a.key.key_id, &row)
        .await
        .expect("B -> A on the healed binding");
    assert!(
        wait_until(Duration::from_secs(20), || async {
            t.a.received(&row).await
        })
        .await,
        "A delivered B's frame"
    );
    assert_eq!(t.b.binding("peer_binding_link_proof_refused"), 0);
    assert_eq!(t.b.binding("peer_binding_dial_key_from_announce"), 0);
}

/// **(b)** No announce has healed B's binding yet (A is silent), but B's
/// leviculum holds A's announce-learned identity, which reproduces A's
/// destination: the dial proves with that key, named and counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_proves_with_the_announce_learned_key_over_a_wrong_binding() {
    let t = trio("dialkey", true, false, false).await;
    t.a.transport.set_unannounced_for_test(true);
    prime_federation_key(&t).await;
    let row = marked(b"DIAL-KEY-ROW-", 600);
    t.b.transport
        .send(&t.a.key.key_id, &row)
        .await
        .expect("B -> A with the announce-learned key");
    assert!(
        wait_until(Duration::from_secs(20), || async {
            t.a.received(&row).await
        })
        .await,
        "A delivered B's frame"
    );
    assert!(
        t.b.binding("peer_binding_dial_key_from_announce") >= 1,
        "{:?}",
        t.b.metrics.peer_binding()
    );
    assert_eq!(t.b.binding("peer_binding_link_proof_refused"), 0);
}

/// **(c)** A dial whose proof does not verify against the binding is the
/// named `LinkProofRefused`, counted, never a 30 s `Timeout`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proof_that_fails_against_the_binding_is_named_not_a_timeout() {
    let t = trio("proofref", true, false, false).await;
    t.a.transport.set_unannounced_for_test(true);
    t.b.transport.binding_key_only_for_test(true);
    let dest = prime_federation_key(&t).await;
    let started = std::time::Instant::now();
    match t.b.transport.send(&t.a.key.key_id, b"never-proved").await {
        Err(TransportError::LinkProofRefused {
            key_id,
            target_dest,
        }) => {
            assert_eq!(key_id, t.a.key.key_id);
            assert_eq!(target_dest, hex::encode(dest));
        }
        other => panic!("a refused proof must be named: {other:?}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "named at once, not at a timeout"
    );
    assert!(t.b.binding("peer_binding_link_proof_refused") >= 1);
}

/// **(d)** `prime_peer` takes the full transport identity and refuses one
/// that does not reproduce the destination (the federation key, or another
/// node's identity); A's own identity primes, and B's dial proves with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prime_peer_refuses_a_key_that_is_not_the_destinations_e1() {
    let t = trio("primepeer", true, false, false).await;
    t.a.transport.set_unannounced_for_test(true);
    t.b.transport.binding_key_only_for_test(true);
    let dest = prime_federation_key(&t).await;
    let mut fed64 = [0u8; 64];
    fed64[32..].copy_from_slice(&t.a.key.ed_pub);
    for wrong in [fed64, t.c.transport.local_transport_pubkey()] {
        assert!(
            matches!(
                t.b.transport.prime_peer(&t.a.key.key_id, dest, wrong).await,
                Err(TransportError::Config(_))
            ),
            "a key that is not the destination's is refused"
        );
    }
    assert_eq!(t.b.binding("peer_binding_prime_refused"), 2);
    t.b.transport
        .prime_peer(
            &t.a.key.key_id,
            dest,
            t.a.transport.local_transport_pubkey(),
        )
        .await
        .expect("A's own transport identity primes");
    assert_eq!(t.b.binding("peer_binding_primed"), 1);
    let row = marked(b"PRIMED-ROW-", 600);
    t.b.transport
        .send(&t.a.key.key_id, &row)
        .await
        .expect("B -> A on the primed binding");
    assert!(
        wait_until(Duration::from_secs(20), || async {
            t.a.received(&row).await
        })
        .await,
        "A delivered B's frame"
    );
    assert_eq!(t.b.binding("peer_binding_link_proof_refused"), 0);
}

/// CIRISEdge#888 — the field case. A holds a SECOND binding to B's transport
/// identity, under a key that sorts first: an install's pre-split actor key
/// whose route was never retired. B's KEX claims its own node key. Before, A
/// attributed the link to whichever key a `HashMap` walk met first and, when
/// it was the other one, refused every handshake as a claim mismatch. Now the
/// claim, corroborated by B's own binding to the identity, decides.
/// `extra_kind` is how A's directory registers the extra key: `agent` (the
/// field case, decided by the node rule) or `node` (two node keys, which only
/// the corroborated claim can decide).
async fn shared_identity_witness(tag: &str, extra_kind: &str) {
    let t = trio(tag, true, false, false).await;
    let extra = Ident::new(&format!("aaa-pre-split-actor-{tag}"), 0x2e).await;
    assert!(extra.key_id < t.b.key.key_id, "the extra key sorts first");
    FederationDirectory::put_public_key(
        &*t.a.dir,
        ciris_persist::prelude::SignedKeyRecord {
            record: extra.record_as(extra_kind).await,
        },
    )
    .await
    .expect("register the extra key at A");
    t.a.transport
        .prime_peer(
            &extra.key_id,
            t.b.transport.local_named_dest_hash(),
            t.b.transport.local_transport_pubkey(),
        )
        .await
        .expect("A binds the extra key to B's transport identity");

    let frame = marked(b"E1-SHARED-IDENTITY-", 3_000);
    t.b.transport
        .send(&t.a.key.key_id, &frame)
        .await
        .expect("B -> A, sealed");
    let landed = wait_until(Duration::from_secs(30), || async {
        t.a.seen.lock().await.iter().any(|f| {
            f.envelope_bytes == frame
                && f.source_key_id
                    .as_ref()
                    .map(ciris_edge::transport::SourceKeyId::as_str)
                    == Some(t.b.key.key_id.as_str())
        })
    })
    .await;
    assert!(
        landed,
        "A delivered B's frame attributed to B's node key; seals {:?}, bindings {:?}",
        t.a.metrics.link_seal(),
        t.a.metrics.peer_binding()
    );
    assert_eq!(t.a.seal("link_seal_refused_claim_mismatch"), 0);
    assert!(
        t.a.binding("peer_binding_attribution_shared") >= 1,
        "the tie was met, not avoided: {:?}",
        t.a.metrics.peer_binding()
    );
    let rule = if extra_kind == "node" {
        // Two node keys: only the claim can pick B over the lower key id.
        "peer_binding_attribution_by_claim"
    } else {
        "peer_binding_attribution_by_node"
    };
    assert!(
        t.a.binding(rule) >= 1,
        "{rule}: {:?}",
        t.a.metrics.peer_binding()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_node_key_on_the_dialler_identity_yields_to_the_corroborated_claim_888() {
    shared_identity_witness("shared-claim", "node").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_agent_key_on_the_dialler_identity_never_takes_the_node_s_link_888() {
    shared_identity_witness("shared-agent", "agent").await;
}
