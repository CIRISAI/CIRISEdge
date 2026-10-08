//! CIRISEdge#805 item 4 — the A/V spine rides the LIVE node.
//!
//! Two real `ReticulumTransport`s over loopback TCP, each the field shape
//! (as `link_plane_728`): a self-signed hybrid key whose id binds its pubkey,
//! a per-node directory, each side holding the other's hybrid-signed
//! `SignedTransportDestination` (so #393 item 2 holds both ways), and a
//! `ReplicationRuntime` routing every `InboundFrame` the transport listener
//! hands it. On top of that, a real call: A's `AvSession` (openmls X-Wing)
//! admits B through a signed Welcome, both install the session's addresses
//! through their own `ScopeLifecycle`, and A's `AvSpine` publishes.
//!
//! **The witness** (`av_chunks_ride_the_replicating_node_805`): A dials B's
//! A/V address on the SAME transport its replication runs on, attaches the
//! link to the spine, and publishes a stream of chunks while a replication
//! round and an identity-plane Deliver run between the same two nodes. Then:
//!
//! - B's A/V consumer receives EVERY chunk, in order, byte-identical, through
//!   the subscriber loop's two AEAD opens;
//! - the replication rows land at B and A's round completes;
//! - no A/V frame reached B's replication listener (every frame it saw was
//!   an envelope we can name), and the A/V sink delivered exactly the frames
//!   sent on the A/V link — counters, not logs;
//! - a replication frame FORCED onto the A/V link goes to the A/V sink (and is
//!   skipped there as malformed), never to the replication listener, and the
//!   stream continues past it;
//! - a chunk larger than the link's Channel is refused at send as the typed
//!   `ChunkTooLarge`, named in the fan-out, counted, and the next chunk still
//!   opens (the refused frame burned no hop counter).
//!
//! What is NOT witnessed over real links here: a 500-byte-MTU link. Loopback
//! TCP negotiates a 16 KiB link MTU, and no interface this harness can stand
//! up negotiates the base MTU. The size check reads the live link's MDU, so
//! the refusal below is the same code at any MTU; the 500-MTU arithmetic is
//! pinned by the transport's unit tests.
//!
//! Requires the `transport-reticulum` feature:
//! `cargo test --features transport-reticulum --test av_spine_live_node_805`

#![cfg(feature = "transport-reticulum")]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use ciris_crypto::{ml_kem, x25519, MlDsa65Signer};
use ciris_edge::av_addressing;
use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::mls::welcome_wrap::FederationDirectoryEntry;
use ciris_edge::replication::attestation_bind::{
    replication_consent_attestation, DEFAULT_CONSENT_PREFIXES,
};
use ciris_edge::replication::protocol::{DeliverMessage, ReplicationMessage};
use ciris_edge::replication::{
    wire_frame, EnvelopeKind, InboundRouter, ReplicationPeer, ReplicationRuntime,
    ReplicationRuntimeConfig, SchedulerConfig,
};
use ciris_edge::scope_addressing::{ScopeAddressTable, ScopePrivacyDeriver};
use ciris_edge::scope_lifecycle::{ScopeLifecycle, ScopedDestinationSink};
use ciris_edge::transport::av_sink::AvArrival;
use ciris_edge::transport::av_spine::{AvSpine, LegOutcome};
use ciris_edge::transport::federation_session::{OwnKexKeys, PeerKexPubkeys};
use ciris_edge::transport::realtime_av::{
    seal_av_inner, seal_av_outer, ChunkLayer, ChunkSeq, Epoch, EpochDek, StreamId, CODEC_OPAQUE,
};
use ciris_edge::transport::realtime_av_dispatcher::{AvInboundLink, AvSubscriberLink};
use ciris_edge::transport::realtime_av_mls::{mint_joiner_key_material, Member};
use ciris_edge::transport::realtime_av_runtime::{AvPublisher, AvSubscriber};
use ciris_edge::transport::realtime_av_session::AvSession;
use ciris_edge::transport::reticulum::{
    LinkPlane, ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, ReplyPath, Transport, TransportError, TransportId};
use ciris_edge::verify::RootingDirectory;
use ciris_edge::{CohortScope, EdgeMetrics};
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::sqlite::SqliteBackend;
use common::directory_with;
use sha2::Digest as _;
use tokio::sync::{mpsc, Mutex};

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

/// A production-shaped identity (see `link_plane_728`): a hybrid keypair and
/// a key id that BINDS the pubkey fingerprint, so the announce yields
/// `owns_key` (#393 item 1).
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

/// One frame B's replication listener saw, before routing it.
#[derive(Debug, Clone)]
struct Seen {
    source_key_id: Option<String>,
    bytes: Vec<u8>,
}

struct Side {
    key: Ident,
    dir: Arc<SqliteBackend>,
    transport: Arc<ReticulumTransport>,
    metrics: EdgeMetrics,
    runtime: Arc<ReplicationRuntime>,
    table: Arc<ScopeAddressTable>,
    lifecycle: Arc<ScopeLifecycle>,
    seen: Arc<Mutex<Vec<Seen>>>,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

fn auth(signer: Arc<LocalSigner>, dir: &Arc<SqliteBackend>) -> ReticulumAuth {
    ReticulumAuth {
        signer: Some(signer),
        rooting: Some(Arc::clone(dir) as Arc<dyn RootingDirectory>),
        resolver: None,
        hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
        // The operator deny-list (persist V052), so the A/V dial's blackhole
        // rule is exercised against a real store.
        blackhole_rules: Some(Arc::clone(dir) as Arc<dyn ciris_persist::federation::BlackholeRules>),
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

/// A transport built with NO metrics bag: the Edge built over it attaches its
/// own at `EdgeBuilder::build` (#810), which is the production path the
/// `av_plane` counters must reach.
async fn build_transport<F, Fut>(mut make: F) -> (Arc<ReticulumTransport>, u16)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = (ReticulumTransportConfig, ReticulumAuth)>,
{
    for _ in 0..16 {
        let (cfg, auth) = make().await;
        let port = cfg.listen_addr.port();
        match ReticulumTransport::new(cfg, auth).await {
            Ok(t) => return (Arc::new(t), port),
            Err(e)
                if e.to_string().contains("Address already in use")
                    || e.to_string().contains("os error 98") => {}
            Err(e) => panic!("build reticulum transport: {e:?}"),
        }
    }
    panic!("build reticulum transport: exhausted bind retries");
}

/// A runtime + router over `transport` for the Attestation plane with `peer`,
/// as production wires it; the listener records what it saw, then routes. The
/// scope table is installed EMPTY: the call's addresses arrive through the
/// lifecycle, exactly as a host's would.
async fn side(
    key: Ident,
    dir: Arc<SqliteBackend>,
    transport: Arc<ReticulumTransport>,
    metrics: EdgeMetrics,
    peer: &str,
) -> Side {
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
    let runtime = Arc::new(
        ReplicationRuntime::start(
            Arc::clone(&dir) as Arc<dyn FederationDirectory>,
            Arc::clone(&transport) as Arc<dyn Transport>,
            vec![ReplicationPeer {
                peer_key_id: peer.to_owned(),
                kind: EnvelopeKind::Attestation,
            }],
            ReplicationRuntimeConfig {
                scheduler: SchedulerConfig {
                    cadence: Duration::from_secs(3600),
                    round_timeout: Duration::from_secs(15),
                    ..SchedulerConfig::default()
                },
                local_key_id: Some(key.key_id.clone()),
                metrics: Some(metrics.clone()),
                ..Default::default()
            },
            None,
        )
        .await,
    );
    let (tx, mut rx) = mpsc::channel::<InboundFrame>(256);
    let listener = Arc::clone(&transport);
    let router = InboundRouter::new(runtime.registry());
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_tx = Arc::clone(&seen);
    let tasks = vec![
        tokio::spawn(async move {
            let _ = listener.listen(tx).await;
        }),
        tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                seen_tx.lock().await.push(Seen {
                    source_key_id: frame.source_key_id.as_ref().map(|s| s.as_str().to_owned()),
                    bytes: frame.envelope_bytes.clone(),
                });
                let _ = router.try_route(&frame).await;
            }
        }),
    ];
    Side {
        key,
        dir,
        transport,
        metrics,
        runtime,
        table,
        lifecycle,
        seen,
        _tasks: tasks,
    }
}

/// The production Edge over `transport`, built through `EdgeBuilder` with no
/// `with_metrics` anywhere: its bag is attached to the transport at build.
fn build_edge(
    key: &Ident,
    dir: &Arc<SqliteBackend>,
    transport: &Arc<ReticulumTransport>,
) -> ciris_edge::Edge {
    ciris_edge::Edge::builder()
        .directory(Arc::clone(dir) as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .federation_directory(Arc::clone(dir) as Arc<dyn FederationDirectory>)
        .queue(Arc::clone(dir) as Arc<dyn ciris_edge::outbound::OutboundHandle>)
        .signer(key.signer())
        .transport(Arc::clone(transport) as Arc<dyn Transport>)
        .config(ciris_edge::EdgeConfig {
            hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
            ..ciris_edge::EdgeConfig::default()
        })
        .build()
        .expect("build the edge")
}

struct Pair {
    a: Side,
    b: Side,
    /// The Edges whose `metrics()` bag the transports carry.
    edge_a: ciris_edge::Edge,
    edge_b: ciris_edge::Edge,
    peers: Vec<Ident>,
    _tmp: tempfile::TempDir,
}

/// Two nodes, each holding the other's hybrid-signed route (item 2), B
/// bootstrapped to A, both rooted to each other. Nothing has dialled yet.
async fn pair(tag: &str) -> Pair {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let key_a = Ident::new(&format!("node-a-805-{tag}"), 0x1a).await;
    let key_b = Ident::new(&format!("node-b-805-{tag}"), 0x1b).await;
    let mut peers = Vec::with_capacity(8);
    for i in 0u8..8 {
        peers.push(Ident::new(&format!("peer-{i}-805-{tag}"), 0x90 | i).await);
    }
    let mut records = vec![key_a.record("node").await, key_b.record("node").await];
    for p in &peers {
        records.push(p.record("node").await);
    }
    let a_dir = directory_with(records.clone()).await;
    let b_dir = directory_with(records).await;

    let (transport_a, port_a) = build_transport(|| {
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
    let (transport_b, _) = build_transport(|| {
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

    for (from, from_key, to) in [(&a_dir, &key_a, &b_dir), (&b_dir, &key_b, &a_dir)] {
        let routes = from
            .list_signed_transport_destinations_for(&from_key.key_id)
            .await
            .expect("list routes");
        assert!(
            routes
                .iter()
                .any(|r| r.signature.mldsa65_signature_base64.is_some()),
            "the route must be hybrid-signed (item 2 requires the ML-DSA half)"
        );
        for r in &routes {
            FederationDirectory::put_signed_transport_destination(&**to, r)
                .await
                .expect("seed the route");
        }
    }

    // The production attach (#810): each Edge hands its bag to its transport.
    let edge_a = build_edge(&key_a, &a_dir, &transport_a);
    let edge_b = build_edge(&key_b, &b_dir, &transport_b);
    let metrics_a = edge_a.metrics();
    let metrics_b = edge_b.metrics();
    assert!(
        transport_a
            .attached_metrics()
            .is_some_and(|m| m.is_same_bag(&metrics_a)),
        "EdgeBuilder::build attached A's bag to A's transport"
    );
    let peer_of_a = key_b.key_id.clone();
    let peer_of_b = key_a.key_id.clone();
    let a = side(key_a, a_dir, transport_a, metrics_a, &peer_of_a).await;
    let b = side(key_b, b_dir, transport_b, metrics_b, &peer_of_b).await;

    let known = wait_until(Duration::from_secs(60), || async {
        a.transport.knows_peer(&b.key.key_id).await && b.transport.knows_peer(&a.key.key_id).await
    })
    .await;
    assert!(known, "A and B must learn each other from their announces");
    Pair {
        a,
        b,
        edge_a,
        edge_b,
        peers,
        _tmp: tmp,
    }
}

// ─── the call ───────────────────────────────────────────────────────

const ROOM: &str = "room-805";

fn scope() -> CohortScope {
    CohortScope::Cohort {
        cohort_id: ROOM.to_owned(),
    }
}

#[allow(clippy::similar_names)]
fn fresh_joiner_xwing() -> (PeerKexPubkeys, OwnKexKeys) {
    let (x_sk, x_pk) = x25519::generate_ephemeral_keypair().expect("x25519 keypair");
    let (mlkem_sk, mlkem_pk) = ml_kem::generate_keypair().expect("ml-kem keypair");
    (
        PeerKexPubkeys {
            x25519_pub: x_pk,
            mlkem768_pub: mlkem_pk.clone(),
        },
        OwnKexKeys {
            x25519_priv: x_sk,
            mlkem768_priv: Some(mlkem_sk),
            mlkem768_pub: Some(mlkem_pk),
        },
    )
}

struct Call {
    stream: StreamId,
    spine: AvSpine,
    sub_dek: EpochDek,
}

/// A real MLS call: A creates the session, admits B through a signed Welcome,
/// B derives the SAME epoch DEK, and each side installs the session's scoped
/// addresses through its own lifecycle (A by opening the spine).
async fn open_call(p: &Pair) -> Call {
    let stream = StreamId(sha2::Sha256::digest(b"av-stream-805").into());
    let (mut session, _dek0) = AvSession::create(
        stream,
        &p.a.key.key_id,
        vec![Member {
            key_id: "seed-805".to_owned(),
            kex_pubkeys: PeerKexPubkeys {
                x25519_pub: [1u8; 32],
                mlkem768_pub: vec![0xAB; 1184],
            },
        }],
    )
    .expect("create the call");
    let (joiner_material, joiner_kp) =
        mint_joiner_key_material(&p.b.key.key_id).expect("mint joiner key material");
    let inviter = MlDsa65Signer::new().expect("inviter signer");
    let inviter_pk = ciris_crypto::PqcSigner::public_key(&inviter).expect("inviter pk");
    let (joiner_kex_pub, joiner_kex_secret) = fresh_joiner_xwing();
    let artifacts = session
        .admit_published_joiner(
            &p.b.key.key_id,
            joiner_kp,
            &joiner_kex_pub,
            &inviter,
            "inviter-805",
        )
        .expect("admit B");
    let pub_dek = EpochDek::from_bytes(*artifacts.new_dek.as_bytes());
    let mut sub_session = AvSession::new_joiner(stream, joiner_material);
    let sub_dek = sub_session
        .process_welcome(
            &artifacts.welcome_bytes[0],
            &joiner_kex_secret,
            move |id: &str| {
                (id == "inviter-805").then(|| FederationDirectoryEntry {
                    pk_id: id.to_owned(),
                    ml_dsa_pk: inviter_pk.clone(),
                    x_wing_pk: None,
                })
            },
        )
        .expect("B processes the Welcome");
    assert_eq!(sub_dek.as_bytes(), pub_dek.as_bytes(), "one epoch DEK");

    let publisher = AvPublisher::from_session(stream, session, pub_dek, vec![]).expect("publisher");
    let spine =
        AvSpine::open(scope(), Arc::clone(&p.a.lifecycle), publisher, None).expect("open the call");
    let snap = av_addressing::snapshot(&sub_session).expect("B's snapshot");
    let _ =
        p.b.lifecycle
            .install(&scope(), &snap)
            .expect("B installs the call");
    Call {
        stream,
        spine,
        sub_dek,
    }
}

// ─── replication load (as link_plane_728) ───────────────────────────

/// One Deliver of eight consent rows A → peer_i, Resource-sized.
async fn resource_deliver(p: &Pair) -> (Vec<u8>, Vec<String>) {
    let signer = p.a.key.signer();
    let mut envelopes = Vec::with_capacity(p.peers.len());
    let mut ids = Vec::with_capacity(p.peers.len());
    for peer in &p.peers {
        let att = replication_consent_attestation(
            &p.a.key.key_id,
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
    (frame, ids)
}

async fn holds_all(dir: &SqliteBackend, ids: &[String]) -> bool {
    let rows = dir.list_attestations_since(None, 1024).await.expect("list");
    ids.iter()
        .all(|id| rows.iter().any(|r| &r.attestation.attestation_id == id))
}

fn completed_rounds(m: &EdgeMetrics) -> u64 {
    m.snapshot()
        .replication_round_outcomes_total
        .get(&ciris_edge::observability::RoundOutcome::Completed)
        .copied()
        .unwrap_or(0)
}

fn av(m: &EdgeMetrics, label: &str) -> u64 {
    m.av_plane().get(label).copied().unwrap_or(0)
}

/// A small replication frame (one Channel packet) of a bootstrap kind.
fn small_bootstrap_frame(marker: u8) -> Vec<u8> {
    wire_frame::wrap_for_kind(&ReplicationMessage::Deliver(DeliverMessage {
        kind: EnvelopeKind::Key,
        envelopes: vec![vec![b'{', b' ', marker, b' ', b'}']],
    }))
}

/// The wire bytes one chunk of `plaintext_len` costs on a hop (both AEAD
/// layers + header), measured on the real seal rather than retyped.
fn wire_overhead() -> usize {
    let dek = EpochDek::from_bytes([7u8; 32]);
    let inner = seal_av_inner(
        &[0u8; 100],
        &dek,
        StreamId([1u8; 32]),
        Epoch(1),
        ChunkSeq(0),
        CODEC_OPAQUE,
        ChunkLayer::BASE,
    )
    .expect("seal inner");
    let sealed = seal_av_outer(&inner, &[9u8; 32], b"link", 0).expect("seal outer");
    sealed.to_bytes().len() - 100
}

fn chunk_body(i: usize, len: usize) -> Vec<u8> {
    let mut out = format!("av-805-chunk-{i:04}-").into_bytes();
    out.resize(len, u8::try_from(i % 251).expect("< 251"));
    out
}

const CHUNKS: usize = 40;

/// **The witness.** Fails on today's main: there is no A/V plane, so an A/V
/// link's frames go to `attribute_and_deliver` and out of B's replication
/// listener; the subscriber receives nothing and the `av_plane` ledger is
/// empty. (With this branch's route removed, the same test fails on the
/// "every chunk" assertion with B's listener holding the chunks.)
// One witness, read top to bottom: splitting it would scatter the single
// call whose stream, replication and refusal it asserts together.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn av_chunks_ride_the_replicating_node_805() {
    let p = pair("ride").await;
    let mut call = open_call(&p).await;
    let group = av_addressing::stream_group_id(call.stream);

    // Where A dials B, read from A's own table — the address B listens on.
    let b_addr =
        p.a.table
            .send_address(&scope(), &group, &p.b.key.key_id)
            .expect("A derives B's call address");
    assert_eq!(
        Some(b_addr),
        p.b.table.send_address(&scope(), &group, &p.b.key.key_id),
        "A and B derive the same address for B at this epoch"
    );

    // A cohort-group address is not an A/V address: refused by name.
    p.a.table
        .install_group(
            &scope(),
            "room-805-chat",
            1,
            &[0x33; 32],
            &[p.a.key.key_id.as_str(), p.b.key.key_id.as_str()],
        )
        .expect("install a chat group");
    let chat_addr =
        p.a.table
            .send_address(&scope(), "room-805-chat", &p.b.key.key_id)
            .expect("chat address");
    match p
        .a
        .transport
        .open_av_link(&p.b.key.key_id, &chat_addr)
        .await
    {
        Err(TransportError::Config(msg)) => {
            assert!(msg.contains("not an A/V session address"), "{msg}");
        }
        other => panic!("a non-A/V address must be refused by name: {other:?}"),
    }

    // A peer the operator blackholed by its FEDERATION destination is refused
    // an A/V link too, though the A/V address is one the operator never saw
    // (Codex on #813: the regular send path checks every candidate).
    let b_fed =
        p.a.transport
            .peer_dest_hash_for_test(&p.b.key.key_id)
            .await
            .expect("A knows B's federation destination");
    p.a.transport
        .routing_blackhole_add(&b_fed, None, Some("805 witness"))
        .await
        .expect("blackhole B");
    match p.a.transport.open_av_link(&p.b.key.key_id, &b_addr).await {
        Err(TransportError::PeerBlackholed { identity_hash, .. }) => {
            assert_eq!(
                identity_hash,
                b_fed.to_vec(),
                "refused on B's federation hash"
            );
        }
        other => panic!("a blackholed peer must be refused an A/V link: {other:?}"),
    }
    p.a.transport
        .routing_blackhole_remove(&b_fed)
        .await
        .expect("lift the blackhole");

    // The address must be the named peer's: B's call address under another
    // key id is refused by name, before any dial, so a link to B can never be
    // attributed to someone else (Codex on #813).
    let other = p.peers[0].key_id.clone();
    match p.a.transport.open_av_link(&other, &b_addr).await {
        Err(TransportError::Config(msg)) => assert!(
            msg.contains("belongs to member") && msg.contains(&p.b.key.key_id),
            "{msg}"
        ),
        other => panic!("B's address under another key id must be refused by name: {other:?}"),
    }

    // A dial that fails AFTER the link established (identify) leaves nothing
    // behind: no sink queue, no attribution record, no live A/V link (Codex on
    // #813). Two forced failures, then back to baseline.
    let sink_before = p.a.transport.av_sink_link_count_for_test();
    let dialed_before = p.a.transport.av_dialed_peer_count_for_test();
    p.a.transport.fail_next_derived_identifies_for_test(2);
    for _ in 0..2 {
        match p.a.transport.open_av_link(&p.b.key.key_id, &b_addr).await {
            Err(TransportError::Io(msg)) => assert!(msg.contains("forced failure"), "{msg}"),
            other => panic!("the forced identify failure must surface: {other:?}"),
        }
    }
    assert_eq!(p.a.transport.av_sink_link_count_for_test(), sink_before);
    assert_eq!(p.a.transport.av_dialed_peer_count_for_test(), dialed_before);
    let no_partial_links = wait_until(Duration::from_secs(20), || async {
        !p.a.transport
            .link_planes_for_test()
            .await
            .iter()
            .any(|(_, plane, _)| *plane == LinkPlane::Av)
    })
    .await;
    assert!(
        no_partial_links,
        "the partially opened A/V links were closed: {:?}",
        p.a.transport.link_planes_for_test().await
    );

    // B's A/V consumer, then A's link to B on the live node.
    let mut arrivals = p.b.transport.take_av_arrivals().expect("B's arrivals");
    let link =
        p.a.transport
            .open_av_link(&p.b.key.key_id, &b_addr)
            .await
            .expect("A dials B's A/V address");
    let channel_limit = link.sender.channel_limit().expect("the link is held");
    let av_link_id = link.link_id;
    let a_planes = p.a.transport.link_planes_for_test().await;
    assert!(
        a_planes
            .iter()
            .any(|(id, plane, dialed)| *id == av_link_id && *plane == LinkPlane::Av && *dialed),
        "A's link is on the A/V plane: {a_planes:?}"
    );
    let transit = [0x5c; 32];
    let hop_link_id = p.b.key.key_id.as_bytes().to_vec();
    call.spine
        .attach_downstream(AvSubscriberLink {
            subscriber: p.b.key.key_id.clone(),
            transit_key: transit,
            link_id: hop_link_id.clone(),
            outbound_send: Box::new(link.sender),
        })
        .expect("attach the hop");

    // Replication, concurrently: an identity-plane Deliver and driven rounds
    // between the same two transports.
    let (deliver, ids) = resource_deliver(&p).await;
    let a_transport = Arc::clone(&p.a.transport);
    let a_runtime = Arc::clone(&p.a.runtime);
    let b_key = p.b.key.key_id.clone();
    let replication = tokio::spawn(async move {
        a_transport
            .send(&b_key, &deliver)
            .await
            .expect("A -> B identity-plane Deliver");
        for _ in 0..6 {
            let _ = a_runtime.round_now_all().await;
            tokio::time::sleep(Duration::from_millis(700)).await;
        }
    });

    // The stream: CHUNKS chunks, the middle one followed by a replication
    // frame forced onto the A/V link.
    let overhead = wire_overhead();
    let body_len = (channel_limit - overhead).min(1200);
    let forced = small_bootstrap_frame(b'v');
    let mut sent = Vec::with_capacity(CHUNKS + 1);
    let mut b_sub = None;
    for i in 0..CHUNKS {
        let body = chunk_body(i, body_len);
        let fanout = call
            .spine
            .publish(&body, Instant::now())
            .await
            .expect("publish");
        assert_eq!(
            fanout.direct,
            LegOutcome::Delivered { reached: 1 },
            "chunk {i} went out on the A/V link"
        );
        sent.push((fanout.chunk_seq, body));
        if i == 0 {
            // B's consumer receives the link on its first frame.
            let Ok(arrival) = tokio::time::timeout(Duration::from_secs(20), arrivals.recv()).await
            else {
                let stream_prefix = &call.stream.0[..];
                let leaked =
                    p.b.seen
                        .lock()
                        .await
                        .iter()
                        .filter(|s| s.bytes.starts_with(stream_prefix))
                        .count();
                panic!(
                    "the A/V link never arrived at B's A/V consumer; {leaked} A/V chunk(s) \
                     reached B's REPLICATION listener instead; av_plane={:?}",
                    p.b.metrics.av_plane()
                );
            };
            let arrival: AvArrival = arrival.expect("arrivals open");
            assert_eq!(
                arrival.peer.as_str(),
                p.a.key.key_id,
                "attributed to A (#393)"
            );
            assert_eq!(arrival.link_id, av_link_id, "the link A dialled");
            let address = arrival.address.as_ref().expect("B's call address");
            assert_eq!(address.group().group_id(), group);
            assert_eq!(address.member_key_id(), p.b.key.key_id);
            b_sub = Some(
                AvSubscriber::subscribe(
                    call.stream,
                    &call.sub_dek,
                    &p.a.key.key_id,
                    AvInboundLink {
                        transit_key: transit,
                        link_id: hop_link_id.clone(),
                        inbound_recv: Box::new(arrival.inbound),
                    },
                )
                .expect("subscribe"),
            );
        }
        if i == CHUNKS / 2 {
            p.a.transport
                .send_on_reply_path_only(
                    &p.b.key.key_id,
                    &ReplyPath::new(TransportId::RETICULUM_RS, av_link_id),
                    &forced,
                )
                .await
                .expect("A forces a replication frame onto the A/V link");
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    // #720 — a chunk too large for the Channel is refused BY NAME at send.
    let oversized = chunk_body(9999, channel_limit);
    let fanout = call
        .spine
        .publish(&oversized, Instant::now())
        .await
        .expect("publish (the refusal is a leg outcome)");
    match fanout.direct {
        LegOutcome::Oversized { refusal } => {
            assert_eq!(
                refusal.channel_limit, channel_limit,
                "the live link's limit"
            );
            assert_eq!(refusal.frame_bytes, channel_limit + overhead);
        }
        other => panic!("an oversized chunk must be refused as ChunkTooLarge: {other:?}"),
    }
    assert_eq!(av(&p.a.metrics, "av_send_refused_chunk_too_large"), 1);
    // …and burned no hop counter: the next chunk still opens at B.
    let after = chunk_body(CHUNKS, body_len);
    let fanout = call
        .spine
        .publish(&after, Instant::now())
        .await
        .expect("publish after the refusal");
    assert_eq!(fanout.direct, LegOutcome::Delivered { reached: 1 });
    sent.push((fanout.chunk_seq, after));

    // B's consumer: every chunk, in order, byte-identical.
    let mut rx = b_sub.expect("subscribed");
    for (seq, body) in &sent {
        let got = tokio::time::timeout(Duration::from_secs(20), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("chunk {seq:?} never reached B's A/V consumer"))
            .expect("subscriber open");
        assert_eq!(got.chunk_seq, *seq, "in order");
        assert_eq!(got.stream_id, call.stream);
        assert_eq!(&got.plaintext, body, "byte-identical");
    }

    // Replication completed unaffected.
    replication.await.expect("replication task");
    assert!(
        wait_until(Duration::from_secs(60), || async {
            holds_all(&p.b.dir, &ids).await
        })
        .await,
        "B admits A's identity-plane rows while the call runs"
    );
    assert!(
        wait_until(Duration::from_secs(60), || async {
            if completed_rounds(&p.a.metrics) >= 1 {
                return true;
            }
            let _ = p.a.runtime.round_now_all().await;
            false
        })
        .await,
        "A's round toward B completes while the call runs: {:?}",
        p.a.metrics.snapshot().replication_round_outcomes_total
    );

    // No A/V frame reached B's replication listener, and the forced
    // replication frame did not either: everything it saw is an envelope we
    // can name, from A.
    let seen = p.b.seen.lock().await.clone();
    let stream_prefix = &call.stream.0[..];
    let leaked: Vec<usize> = seen
        .iter()
        .filter(|s| s.bytes.starts_with(stream_prefix) || s.bytes == forced)
        .map(|s| s.bytes.len())
        .collect();
    assert!(
        leaked.is_empty(),
        "an A/V-link frame reached B's replication listener: {leaked:?}"
    );
    assert!(
        seen.iter().any(
            |s| s.bytes.starts_with(&wire_frame::REPLICATION_FRAME_MAGIC)
                && s.source_key_id.as_deref() == Some(p.a.key.key_id.as_str())
        ),
        "B's listener did carry A's replication traffic (the control is live)"
    );

    // The A/V sink delivered exactly what rode the A/V link: CHUNKS + 1
    // chunks and the one forced frame — no replication frame from the
    // identity link, nothing dropped.
    let sent_on_av = u64::try_from(sent.len()).expect("small") + 1;
    assert_eq!(
        av(&p.b.metrics, "av_inbound_delivered"),
        sent_on_av,
        "B's A/V sink: {:?}",
        p.b.metrics.av_plane()
    );
    assert_eq!(av(&p.b.metrics, "av_link_arrived"), 1);
    // #853 — the A/V frames stamped the link's last-inbound liveness at B
    // (the responder), which the inbound idle reap reads: a call carrying
    // media is never read as idle.
    assert!(
        p.b.transport
            .link_last_inbound_for_test(av_link_id)
            .await
            .is_some(),
        "B stamped last-inbound for the A/V link it carries media on"
    );
    for drop in [
        "av_inbound_dropped_unattributed",
        "av_inbound_dropped_queue_full",
        "av_inbound_dropped_no_consumer",
        "av_inbound_dropped_arrivals_full",
        "av_inbound_dropped_resource",
    ] {
        assert_eq!(
            av(&p.b.metrics, drop),
            0,
            "{drop}: {:?}",
            p.b.metrics.av_plane()
        );
    }
    assert_eq!(
        av(&p.a.metrics, "av_sent"),
        u64::try_from(sent.len()).expect("small"),
        "A's sends: {:?}",
        p.a.metrics.av_plane()
    );
    assert_eq!(av(&p.a.metrics, "av_link_opened"), 1);

    // …and every one of those counters is in the bag PRODUCTION reads: the
    // Edges were built through `EdgeBuilder` with no `with_metrics`, so this
    // is `Edge::metrics()` — the snapshot the host, pyo3 and UniFFI export.
    let b_prod = p.edge_b.metrics().snapshot().av_plane;
    assert_eq!(
        b_prod.get("av_inbound_delivered").copied(),
        Some(sent_on_av),
        "B's Edge::metrics() snapshot: {b_prod:?}"
    );
    assert_eq!(b_prod.get("av_link_arrived").copied(), Some(1));
    let a_prod = p.edge_a.metrics().snapshot().av_plane;
    assert_eq!(
        a_prod.get("av_sent").copied(),
        Some(u64::try_from(sent.len()).expect("small")),
        "A's Edge::metrics() snapshot: {a_prod:?}"
    );
    assert_eq!(
        a_prod.get("av_send_refused_chunk_too_large").copied(),
        Some(1)
    );
    assert_eq!(a_prod.get("av_link_opened").copied(), Some(1));
}
