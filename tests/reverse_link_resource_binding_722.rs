//! CIRISEdge#722 — a frame carried as a Reticulum **Resource** on a
//! reverse-path link (B dialled A; A answers on the link B opened, #353) must
//! satisfy CIRISEdge#393 item 2 exactly as a link-Channel packet on the same
//! link does — and the row it carries must be ADMITTED at B, through edge's
//! dispatch, not merely delivered at the transport layer.
//!
//! `tests/reverse_link_716.rs` proves the bytes arrive; it never routes them
//! through a replication registry with a directory, so the #393 gate is not in
//! its path — which is why it was blind to this. Here every node is the field
//! shape: a self-signed hybrid key whose id binds its pubkey (so the announce
//! yields `owns_key`), a per-node directory, and B holding A's hybrid-signed
//! `SignedTransportDestination` — the row A's own #406 producer publishes at
//! transport construction, copied into B's directory the way the
//! TransportDestination plane would carry it.
//!
//! Two carriers of the SAME shape of row:
//! - **Resource** (the default for any frame over `CHANNEL_FIRST_MAX_FRAGMENTS`
//!   — every hybrid-signed row is: an ML-DSA-65 signature alone is 3309 bytes,
//!   and eight 409-byte Channel fragments carry 3272).
//! - **Channel** (`CFRG` fragments, the Busy fallback forced with
//!   `force_next_sends_busy_for_test`).
//!
//! Both rows must land in B's directory attributed to A. The negative control
//! keeps the gate's rule: with NO verified route for A at B, the Resource is
//! still refused at item 2 and its row never lands.
//!
//! Requires the `transport-reticulum` feature:
//! `cargo test --features transport-reticulum --test reverse_link_resource_binding_722`

#![cfg(feature = "transport-reticulum")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::replication::attestation_bind::{
    owner_binding_attestation, replication_consent_attestation, DEFAULT_CONSENT_PREFIXES,
};
use ciris_edge::replication::protocol::{DeliverMessage, ReplicationMessage};
use ciris_edge::replication::{
    wire_frame, EnvelopeKind, InboundRouter, ReplicationPeer, ReplicationRuntime,
    ReplicationRuntimeConfig, SchedulerConfig,
};
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport};
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

/// A production-shaped identity (as in `first_contact_ladder_659.rs`): a hybrid
/// keypair and a key id that BINDS the pubkey fingerprint (`derive_key_id`), so
/// Stage 1's `key_id_binds_pubkey` holds for the announce — `owns_key`, item 1.
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
    /// A self-signed registration the way persist mints one (subject-bound,
    /// CEG-canonical, hybrid-scrubbed). Minted ONCE per identity so every
    /// directory holds the same bytes.
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

/// What B's listener saw for one inbound frame, before routing it: the
/// attribution the #393 gate produced and the frame size (which names the
/// carrier: a signed row is far above one Channel MDU).
#[derive(Debug, Clone)]
struct Seen {
    source_key_id: Option<String>,
    bytes: usize,
}

struct Pair {
    a: Arc<ReticulumTransport>,
    key_a: Ident,
    key_b: Ident,
    owner_a: Ident,
    peers: Vec<Ident>,
    b_dir: Arc<SqliteBackend>,
    a_dir: Arc<SqliteBackend>,
    b_seen: Arc<Mutex<Vec<Seen>>>,
    _rt_b: Arc<ReplicationRuntime>,
    _tmp: tempfile::TempDir,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
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

/// B dialled A; A can only answer on that link's reverse path (A is never
/// taught a routable dest for B beyond what B's announce says, and prefers the
/// live inbound link either way, #353). `seed_route_at_b` copies A's
/// hybrid-signed route into B's directory — the item-2 operand.
// The pair is one linear fixture; splitting it would scatter the wiring.
#[allow(clippy::too_many_lines)]
async fn pair(tag: &str, seed_route_at_b: bool) -> Pair {
    let tmp = tempfile::tempdir().expect("tempdir");
    let key_a = Ident::new(&format!("node-a-722-{tag}"), 0x0a).await;
    let key_b = Ident::new(&format!("node-b-722-{tag}"), 0x0b).await;
    let owner_a = Ident::new(&format!("owner-a-722-{tag}"), 0x4a).await;
    // Eight registered peers A can consent to: eight distinct ~19 KB rows make
    // ONE Deliver above the Channel-first cap at this link's MDU (see
    // `RESOURCE_FRAME_MIN`), which is the only way to reach the Resource arm on
    // a 16 KB-MTU loopback link.
    let mut peers = Vec::with_capacity(8);
    for i in 0u8..8 {
        peers.push(Ident::new(&format!("peer-{i}-722-{tag}"), 0x80 | i).await);
    }
    let mut records = vec![
        key_a.record("node").await,
        key_b.record("node").await,
        owner_a.record("user").await,
    ];
    for p in &peers {
        records.push(p.record("node").await);
    }
    let a_dir = directory_with(records.clone()).await;
    let b_dir = directory_with(records).await;

    let (transport_a, addr_a) = build_reticulum_with_retry(|| {
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
    let (transport_b, _addr_b) = build_reticulum_with_retry(|| {
        let base = tmp.path().to_path_buf();
        let signer = key_b.signer();
        let dir = Arc::clone(&b_dir);
        async move {
            let mut c = ReticulumTransportConfig::new(base.join("b/transport.id"), &signer.key_id);
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.bootstrap_peers = vec![format!("127.0.0.1:{port_a}").parse().unwrap()];
            c.announce_interval = Duration::from_secs(5);
            (c, auth(signer, &dir))
        }
    })
    .await;

    // A's #406 producer published A's hybrid-signed reticulum route (on A's
    // NAMED dest — the dest A announces, hence the dest B's peers map records)
    // into A's directory at construction. B holds it iff the plane carried it.
    let a_routes = a_dir
        .list_signed_transport_destinations_for(&key_a.key_id)
        .await
        .expect("list A's routes");
    assert!(
        !a_routes.is_empty(),
        "#406 producer must publish A's signed route at transport construction"
    );
    assert!(
        a_routes
            .iter()
            .any(|r| r.signature.mldsa65_signature_base64.is_some()),
        "A's route must be hybrid-signed (item 2 requires the ML-DSA half)"
    );
    if seed_route_at_b {
        for r in &a_routes {
            FederationDirectory::put_signed_transport_destination(&*b_dir, r)
                .await
                .expect("seed A's route at B");
        }
    }

    // A drains; B taps + routes through the replication registry.
    let (tx_a, mut rx_a) = mpsc::channel::<InboundFrame>(64);
    let (tx_b, mut rx_b) = mpsc::channel::<InboundFrame>(64);
    let la = Arc::clone(&transport_a);
    let lb = Arc::clone(&transport_b);
    let runtime_b = Arc::new(
        ReplicationRuntime::start(
            Arc::clone(&b_dir) as Arc<dyn FederationDirectory>,
            Arc::clone(&transport_b) as Arc<dyn Transport>,
            vec![ReplicationPeer {
                peer_key_id: key_a.key_id.clone(),
                kind: EnvelopeKind::Attestation,
            }],
            ReplicationRuntimeConfig {
                scheduler: SchedulerConfig {
                    cadence: Duration::from_secs(3600),
                    round_timeout: Duration::from_secs(15),
                },
                local_key_id: Some(key_b.key_id.clone()),
                metrics: Some(EdgeMetrics::new()),
                ..Default::default()
            },
            None,
        )
        .await,
    );
    let router = InboundRouter::new(runtime_b.registry());
    let b_seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&b_seen);
    let a_first = Arc::new(tokio::sync::Notify::new());
    let a_first_tx = Arc::clone(&a_first);
    let tasks = vec![
        tokio::spawn(async move {
            let _ = la.listen(tx_a).await;
        }),
        tokio::spawn(async move {
            let _ = lb.listen(tx_b).await;
        }),
        tokio::spawn(async move {
            while let Some(f) = rx_a.recv().await {
                if f.envelope_bytes == b"round-open-722" {
                    a_first_tx.notify_one();
                }
            }
        }),
        tokio::spawn(async move {
            while let Some(frame) = rx_b.recv().await {
                seen.lock().await.push(Seen {
                    source_key_id: frame.source_key_id.as_ref().map(|s| s.as_str().to_owned()),
                    bytes: frame.envelope_bytes.len(),
                });
                let disposition = router.try_route(&frame).await;
                tracing::info!(?disposition, bytes = frame.envelope_bytes.len(), "B routed");
            }
        }),
    ];

    // Both peers learn each other from the ANNOUNCE (Advisory, owns_key).
    let known = wait_until(Duration::from_secs(60), || async {
        transport_b.knows_peer(&key_a.key_id).await && transport_a.knows_peer(&key_b.key_id).await
    })
    .await;
    assert!(known, "A and B must learn each other from their announces");

    // B dials A (the round-open): this is the link A answers on.
    transport_b
        .send(&key_a.key_id, b"round-open-722")
        .await
        .expect("B -> A");
    tokio::time::timeout(Duration::from_secs(60), a_first.notified())
        .await
        .expect("A receives B's round-open within 60s");

    Pair {
        a: transport_a,
        key_a,
        key_b,
        owner_a,
        peers,
        b_dir,
        a_dir,
        b_seen,
        _rt_b: runtime_b,
        _tmp: tmp,
        _tasks: tasks,
    }
}

/// One-row Attestation `Deliver` on the wire (the bare `Attestation`, #397).
fn deliver_frame(att: &Attestation) -> Vec<u8> {
    let bytes = serde_json::to_vec(att).expect("attestation json");
    wire_frame::wrap_for_kind(&ReplicationMessage::Deliver(DeliverMessage {
        kind: EnvelopeKind::Attestation,
        envelopes: vec![bytes],
    }))
}

/// TCP interfaces negotiate a 16384-byte link MTU (leviculum `TCP_HW_MTU`), so
/// the link-Channel MDU on loopback is 16297 and eight `CFRG` fragments carry
/// 8 × (16297 − 16) = 130 248 bytes. A frame above that skips Channel-first and
/// goes Resource-first — the arm this witness exists for. (At the field's
/// 500-byte base MTU the same threshold is 8 × (425 − 16) = 3272 bytes, which
/// every hybrid-signed row exceeds on its own.)
const RESOURCE_FRAME_MIN: usize = 8 * (16_297 - 16);

/// One Deliver of eight consent rows A → peer_i — above [`RESOURCE_FRAME_MIN`],
/// so it rides a Resource. Returns the frame and the row ids it carries.
async fn resource_deliver(p: &Pair) -> (Vec<u8>, Vec<String>) {
    let signer = p.key_a.signer();
    let mut envelopes = Vec::with_capacity(p.peers.len());
    let mut ids = Vec::with_capacity(p.peers.len());
    for peer in &p.peers {
        let att = replication_consent_attestation(
            &p.key_a.key_id,
            &peer.key_id,
            &DEFAULT_CONSENT_PREFIXES,
            chrono::Utc::now(),
            &signer,
        )
        .await
        .expect("consent");
        ids.push(att.attestation_id.clone());
        envelopes.push(serde_json::to_vec(&att).expect("attestation json"));
    }
    let frame = wire_frame::wrap_for_kind(&ReplicationMessage::Deliver(DeliverMessage {
        kind: EnvelopeKind::Attestation,
        envelopes,
    }));
    assert!(
        frame.len() > RESOURCE_FRAME_MIN,
        "the Resource leg needs a frame over the Channel-first cap at this link's MDU: \
         {} bytes <= {RESOURCE_FRAME_MIN}",
        frame.len()
    );
    (frame, ids)
}

async fn holds_all(dir: &SqliteBackend, ids: &[String]) -> bool {
    let rows = dir.list_attestations_since(None, 1024).await.expect("list");
    ids.iter()
        .all(|id| rows.iter().any(|r| &r.attestation.attestation_id == id))
}

async fn holds_any(dir: &SqliteBackend, ids: &[String]) -> bool {
    let rows = dir.list_attestations_since(None, 1024).await.expect("list");
    ids.iter()
        .any(|id| rows.iter().any(|r| &r.attestation.attestation_id == id))
}

async fn holds(dir: &SqliteBackend, attestation_id: &str) -> bool {
    dir.list_attestations_since(None, 1024)
        .await
        .expect("list")
        .iter()
        .any(|r| r.attestation.attestation_id == attestation_id)
}

/// How many link-Channel fragments this frame cuts to at the 500-byte-MTU
/// loopback link (link MDU 431, Channel MDU 425, `CFRG` payload 409).
fn fragments_at_field_mdu(frame: &[u8]) -> usize {
    ciris_edge::transport::frame_fragment::fragment(frame, 425).map_or(0, |f| f.len())
}

async fn dump(p: &Pair, label: &str) {
    let want = hex::encode(p.a.local_named_dest_hash());
    let rows = p
        .b_dir
        .list_signed_transport_destinations_for(&p.key_a.key_id)
        .await
        .unwrap_or_default();
    eprintln!(
        "[{label}] B holds {} signed route(s) for A (item 2 wants dest={want}):",
        rows.len()
    );
    for r in &rows {
        let td = &r.transport_destination;
        eprintln!(
            "    dest={} mldsa={} epoch={} provenance={:?}",
            td.destination,
            r.signature.mldsa65_signature_base64.is_some(),
            td.epoch,
            td.binding_provenance
        );
    }
    eprintln!("[{label}] B saw {:?}", p.b_seen.lock().await.as_slice());
}

/// The witness. Pre-fix: the Resource-carried row is refused at #393 item 2
/// ("no hybrid-verified SignedTransportDestination binds this (peer, dest)
/// pair") although B holds exactly that row, so it never lands; the Channel
/// carried row on the same link lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resource_and_channel_rows_on_a_reverse_link_both_admit_722() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .with_test_writer()
        .try_init();
    let p = pair("admit", true).await;
    let now = chrono::Utc::now();

    // Leg 1 — the RESOURCE carrier: a Deliver over the Channel-first cap at this
    // link's MDU (the default carrier for every signed row at the field's MTU).
    let (frame_resource, ids_resource) = resource_deliver(&p).await;
    p.a.send(&p.key_b.key_id, &frame_resource)
        .await
        .expect("A -> B over the reverse-path link (Resource)");
    let landed = wait_until(Duration::from_secs(90), || async {
        holds_all(&p.b_dir, &ids_resource).await
    })
    .await;
    if !landed {
        dump(&p, "resource").await;
    }
    assert!(
        landed,
        "the rows A shipped as a RESOURCE over the link B opened must be ADMITTED at B: \
         B holds A's hybrid-signed route, so #393 item 2 is satisfied for this (peer, \
         dest) pair exactly as it is for a packet (CIRISEdge#722)"
    );

    // Leg 2 — the CHANNEL carrier: one hybrid-signed row (over the cap at the
    // field's 425-byte Channel MDU — the number the issue asked for — but not at
    // this link's), with the Resource slot forced Busy so the frame can only
    // cross as CFRG fragments on the link Channel.
    let owner_binding =
        owner_binding_attestation(&p.owner_a.key_id, &p.key_a.key_id, now, &p.owner_a.signer())
            .await
            .expect("owner binding");
    let id_channel = owner_binding.attestation_id.clone();
    let frame_channel = deliver_frame(&owner_binding);
    let n = fragments_at_field_mdu(&frame_channel);
    assert!(
        n > 8,
        "a hybrid-signed row cuts to more than CHANNEL_FIRST_MAX_FRAGMENTS at the field \
         MDU (got {n} fragments for {} bytes)",
        frame_channel.len()
    );
    p.a.force_next_sends_busy_for_test(1_000);
    p.a.send(&p.key_b.key_id, &frame_channel)
        .await
        .expect("A -> B over the reverse-path link (Channel fragments)");
    let landed = wait_until(Duration::from_secs(60), || async {
        holds(&p.b_dir, &id_channel).await
    })
    .await;
    if !landed {
        dump(&p, "channel").await;
    }
    assert!(
        landed,
        "the row A shipped as CHANNEL fragments over the same link must be ADMITTED at B"
    );

    // Both frames were attributed to A at the transport (the field the gate
    // stamps) — the same answer for the two carriers.
    let seen = p.b_seen.lock().await.clone();
    let attributed: Vec<&Seen> = seen
        .iter()
        .filter(|s| s.bytes == frame_resource.len() || s.bytes == frame_channel.len())
        .collect();
    assert_eq!(
        attributed.len(),
        2,
        "B must have seen both frames: {seen:?}"
    );
    for s in attributed {
        assert_eq!(
            s.source_key_id.as_deref(),
            Some(p.key_a.key_id.as_str()),
            "both carriers attribute to A: {seen:?}"
        );
    }
    // The a_dir handle keeps A's directory alive for the whole run.
    drop(p.a_dir.clone());
}

/// Negative control — the gate's rule is untouched: with NO hybrid-verified
/// route for A at B, a Resource on the same link is still refused at item 2
/// (un-attributed ⇒ `SkippedNoSourceKeyId`, the row never lands).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resource_from_a_peer_with_no_verified_route_is_still_refused_722() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .with_test_writer()
        .try_init();
    let p = pair("refuse", false).await;
    let (frame, ids) = resource_deliver(&p).await;
    p.a.send(&p.key_b.key_id, &frame)
        .await
        .expect("A -> B delivers (delivery is not attribution)");
    // The frame arrives — and is un-attributed.
    let seen = wait_until(Duration::from_secs(90), || async {
        p.b_seen.lock().await.iter().any(|s| s.bytes == frame.len())
    })
    .await;
    assert!(seen, "B must receive the Resource frame at the transport");
    let landed = wait_until(Duration::from_secs(10), || async {
        holds_any(&p.b_dir, &ids).await
    })
    .await;
    assert!(
        !landed,
        "no verified SignedTransportDestination for A at B ⇒ item 2 refuses ⇒ the row must \
         NOT land (the gate's rule is unchanged, CIRISEdge#393)"
    );
    let seen = p.b_seen.lock().await.clone();
    let s = seen
        .iter()
        .find(|s| s.bytes == frame.len())
        .expect("frame seen");
    assert_eq!(
        s.source_key_id, None,
        "un-attributed at the transport (item 2 failed): {seen:?}"
    );
}
