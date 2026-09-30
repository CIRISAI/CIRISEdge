//! CIRISEdge#728 — a link belongs to exactly one plane. Identity-plane
//! traffic (replication rounds and Delivers) never rides a link dialled to a
//! scope-derived address, and a frame that does is refused by name.
//!
//! The field (CIRISServer `selffiles`, v34.2.0): D2 installed the self room
//! and dialled D1's DERIVED address; D1 keyed that link to D2 at
//! `LinkIdentified` and its reverse-path selector then chose it — "the peer's
//! freshest live link" — for identity-plane Delivers; D2 dropped every one as
//! `UNATTRIBUTED` because its side of the link resolves to D1's derived
//! address, which is an arrival discriminator, not a peer identity
//! (`FSD/CIRIS_EDGE_TRANSPORT.md` §3.5).
//!
//! Every node here is the field shape (as `reverse_link_resource_binding_722`):
//! a self-signed hybrid key whose id binds its pubkey, a per-node directory,
//! each side holding the other's hybrid-signed `SignedTransportDestination`,
//! and a `ReplicationRuntime` routing inbound frames through the #393 gate.
//! Both transports own a `ScopeAddressTable` with the self room (members A and
//! B) and listen on their own derived address. B dials A's derived address —
//! and ONLY that — so the sole live link A holds to B is a scoped one.
//!
//! - **The witness** (fails on v34.2.0): A publishes identity-plane rows
//!   (Attestation, Resource-sized) to B; B ADMITS them, attributed to A, and
//!   A's round toward B completes within a bounded number of sweeps. Pre-fix
//!   the rows ride the scoped link and B logs
//!   `inbound frame UNATTRIBUTED — the link's destination matches NO rooted peer`.
//! - **Negatives**: a scoped body from A still lands on B's derived address
//!   (never the identity link that now exists); an identity-plane frame forced
//!   onto the scoped link is refused `identity_frame_on_scoped_link`; with no
//!   identity link live, A dials one rather than borrowing the scoped link.
//!
//! Requires the `transport-reticulum` feature:
//! `cargo test --features transport-reticulum --test link_plane_728`

#![cfg(feature = "transport-reticulum")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::replication::attestation_bind::{
    replication_consent_attestation, DEFAULT_CONSENT_PREFIXES,
};
use ciris_edge::replication::protocol::{DeliverMessage, ReplicationMessage};
use ciris_edge::replication::{
    wire_frame, EnvelopeKind, InboundRouter, ReplicationPeer, ReplicationRuntime,
    ReplicationRuntimeConfig, SchedulerConfig,
};
use ciris_edge::scope_addressing::{MemberAddress, ScopeAddressTable, ScopePrivacyDeriver};
use ciris_edge::transport::reticulum::{
    LinkPlane, ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
    DROP_IDENTITY_FRAME_ON_SCOPED_LINK,
};
use ciris_edge::transport::{InboundFrame, ReplyPath, Transport, TransportId};
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
                .unwrap_or_else(|_| "warn,ciris_edge=debug".into()),
        )
        .with_test_writer()
        .try_init();
}

/// A production-shaped identity: a hybrid keypair and a key id that BINDS the
/// pubkey fingerprint, so the announce yields `owns_key` (item 1).
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

/// What a listener saw for one inbound frame, before routing it.
#[derive(Debug, Clone)]
struct Seen {
    source_key_id: Option<String>,
    bytes: usize,
    /// The member whose derived address the frame arrived on (`arrival_scope`),
    /// or `None` for a federation arrival.
    arrival_member: Option<String>,
}

struct Side {
    key: Ident,
    dir: Arc<SqliteBackend>,
    transport: Arc<ReticulumTransport>,
    metrics: EdgeMetrics,
    runtime: Arc<ReplicationRuntime>,
    seen: Arc<Mutex<Vec<Seen>>>,
    /// This side's own derived address in the self room.
    own_address: MemberAddress,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Side {
    async fn saw(&self, bytes: usize) -> Option<Seen> {
        self.seen
            .lock()
            .await
            .iter()
            .find(|s| s.bytes == bytes)
            .cloned()
    }
}

struct Pair {
    a: Side,
    b: Side,
    /// Eight registered peers A can consent to: eight distinct ~19 KB rows make
    /// ONE Deliver above the Channel-first cap at this link's MDU, which is the
    /// only way to reach the Resource arm on a 16 KB-MTU loopback link.
    peers: Vec<Ident>,
    _tmp: tempfile::TempDir,
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

/// `common::build_reticulum_with_retry` with a metrics handle installed
/// before the transport is shared (`with_metrics` takes `self` by value).
async fn build_transport<F, Fut>(
    metrics: &EdgeMetrics,
    mut make: F,
) -> (Arc<ReticulumTransport>, u16)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = (ReticulumTransportConfig, ReticulumAuth)>,
{
    for _ in 0..16 {
        let (cfg, auth) = make().await;
        let port = cfg.listen_addr.port();
        match ReticulumTransport::new(cfg, auth).await {
            Ok(t) => return (Arc::new(t.with_metrics(Some(metrics.clone()))), port),
            Err(e)
                if e.to_string().contains("Address already in use")
                    || e.to_string().contains("os error 98") => {}
            Err(e) => panic!("build reticulum transport: {e:?}"),
        }
    }
    panic!("build reticulum transport: exhausted bind retries");
}

const SELF_ROOM: &str = "self:owner-728";
const SELF_EPOCH: u64 = 1;

/// One self room on `transport`: the table holds BOTH members' addresses (the
/// reverse index is per group, not per node); the node listens on its own.
fn install_self_room(transport: &ReticulumTransport, me: &str, members: &[&str]) -> MemberAddress {
    let table = Arc::new(ScopeAddressTable::new(Arc::new(ScopePrivacyDeriver)));
    table
        .install_group(
            &CohortScope::SelfOnly,
            SELF_ROOM,
            SELF_EPOCH,
            &[0x77; 32],
            members,
        )
        .expect("install the self room");
    let own = table
        .send_address(&CohortScope::SelfOnly, SELF_ROOM, me)
        .expect("own derived address");
    transport
        .register_scoped_destination(&own, &CohortScope::SelfOnly)
        .expect("listen on the derived address");
    transport
        .install_scope_address_table(table)
        .expect("install the table");
    own
}

/// A runtime + router over `transport` for the Attestation plane with `peer`,
/// as production wires it; the listener records what it saw, then routes.
async fn side(
    key: Ident,
    dir: Arc<SqliteBackend>,
    transport: Arc<ReticulumTransport>,
    metrics: EdgeMetrics,
    peer: &str,
    own_address: MemberAddress,
) -> Side {
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
                    // Rounds are driven by the test (`round_now_all`).
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
                    bytes: frame.envelope_bytes.len(),
                    arrival_member: frame
                        .arrival_scope
                        .as_ref()
                        .map(|a| a.member_key_id().to_owned()),
                });
                let disposition = router.try_route(&frame).await;
                tracing::info!(?disposition, bytes = frame.envelope_bytes.len(), "routed");
            }
        }),
    ];
    Side {
        key,
        dir,
        transport,
        metrics,
        runtime,
        seen,
        own_address,
        _tasks: tasks,
    }
}

/// Two nodes, each holding the other's hybrid-signed route (item 2), the self
/// room installed on both, B bootstrapped to A. Nothing has dialled yet.
async fn pair(tag: &str) -> Pair {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let key_a = Ident::new(&format!("node-a-728-{tag}"), 0x0a).await;
    let key_b = Ident::new(&format!("node-b-728-{tag}"), 0x0b).await;
    let mut peers = Vec::with_capacity(8);
    for i in 0u8..8 {
        peers.push(Ident::new(&format!("peer-{i}-728-{tag}"), 0x80 | i).await);
    }
    let mut records = vec![key_a.record("node").await, key_b.record("node").await];
    for p in &peers {
        records.push(p.record("node").await);
    }
    let a_dir = directory_with(records.clone()).await;
    let b_dir = directory_with(records).await;

    let metrics_a = EdgeMetrics::new();
    let metrics_b = EdgeMetrics::new();
    let (transport_a, port_a) = build_transport(&metrics_a, || {
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
    let (transport_b, _) = build_transport(&metrics_b, || {
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

    // Each side holds the other's hybrid-signed route (the #406 producer
    // published it at construction) — #393 item 2 holds in BOTH directions.
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

    let members = [key_a.key_id.as_str(), key_b.key_id.as_str()];
    let addr_a = install_self_room(&transport_a, &key_a.key_id, &members);
    let addr_b = install_self_room(&transport_b, &key_b.key_id, &members);
    assert_ne!(addr_a.as_bytes(), addr_b.as_bytes());

    let peer_of_a = key_b.key_id.clone();
    let peer_of_b = key_a.key_id.clone();
    let a = side(key_a, a_dir, transport_a, metrics_a, &peer_of_a, addr_a).await;
    let b = side(key_b, b_dir, transport_b, metrics_b, &peer_of_b, addr_b).await;

    let known = wait_until(Duration::from_secs(60), || async {
        a.transport.knows_peer(&b.key.key_id).await && b.transport.knows_peer(&a.key.key_id).await
    })
    .await;
    assert!(known, "A and B must learn each other from their announces");

    Pair {
        a,
        b,
        peers,
        _tmp: tmp,
    }
}

/// B dials A's DERIVED address (the self room) — the only link B ever opens
/// to A here — and A sees the body arrive on its own member address.
async fn open_scoped_link_b_to_a(p: &Pair, body: &[u8]) {
    p.b.transport
        .send_to_scoped_destination(&p.a.key.key_id, &p.a.own_address, body)
        .await
        .expect("B -> A on A's derived address");
    let landed = wait_until(Duration::from_secs(30), || async {
        p.a.saw(body.len()).await.is_some()
    })
    .await;
    assert!(landed, "A must receive B's scoped body");
    let seen = p.a.saw(body.len()).await.expect("seen");
    assert_eq!(
        seen.arrival_member.as_deref(),
        Some(p.a.key.key_id.as_str()),
        "the scoped body arrived on A's own derived address: {seen:?}"
    );
}

/// TCP interfaces negotiate a 16384-byte link MTU, so eight `CFRG` fragments
/// carry 8 × (16297 − 16) bytes; a frame above that goes Resource-first — the
/// carrier every hybrid-signed row takes at the field's 500-byte MTU.
const RESOURCE_FRAME_MIN: usize = 8 * (16_297 - 16);

/// One Deliver of eight consent rows A → peer_i — above [`RESOURCE_FRAME_MIN`].
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
    assert!(frame.len() > RESOURCE_FRAME_MIN, "{} bytes", frame.len());
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

/// Drive A's rounds toward B until `done`; the number of sweeps it took.
async fn drive_a_until<F, Fut>(p: &Pair, budget: Duration, mut done: F) -> Option<usize>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + budget;
    let mut sweeps = 0usize;
    loop {
        let _ = p.a.runtime.round_now_all().await;
        sweeps += 1;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        if done().await {
            return Some(sweeps);
        }
        if tokio::time::Instant::now() > deadline {
            return None;
        }
    }
}

/// The bound on A's driven sweeps to a COMPLETED round once the fix holds: the
/// first sweep dials B's identity destination (loopback establishes in
/// milliseconds) and runs the round; the slack is for the 1.5 s sweep grain.
const ROUND_BOUND: usize = 4;

/// The number of `identity_frame_on_scoped_link` refusals `m` booked.
fn scoped_link_refusals(m: &EdgeMetrics) -> u64 {
    m.transport_inbound_drops()
        .get(DROP_IDENTITY_FRAME_ON_SCOPED_LINK)
        .copied()
        .unwrap_or(0)
}

/// `(identity links, scoped links)` a side currently holds established, and
/// how many of the identity links it dialled itself.
async fn planes(side: &Side) -> (usize, usize, usize) {
    let all = side.transport.link_planes_for_test().await;
    let identity = all
        .iter()
        .filter(|(_, p, _)| *p == LinkPlane::Identity)
        .count();
    let scoped = all
        .iter()
        .filter(|(_, p, _)| *p == LinkPlane::Scoped)
        .count();
    let dialed_identity = all
        .iter()
        .filter(|(_, p, d)| *p == LinkPlane::Identity && *d)
        .count();
    (identity, scoped, dialed_identity)
}

/// Keep B re-dialling A's derived address every few seconds, so the scoped
/// link is always the FRESHEST link A holds to B — the field shape, and the
/// one a peer-only selector would keep choosing.
fn scoped_pinger(p: &Pair) -> tokio::task::JoinHandle<()> {
    let b = Arc::clone(&p.b.transport);
    let a_key = p.a.key.key_id.clone();
    let a_addr = p.a.own_address;
    tokio::spawn(async move {
        let mut n = 0u32;
        loop {
            tokio::time::sleep(Duration::from_secs(6)).await;
            n += 1;
            let body = format!("scoped-ping-728-{n:04}");
            let _ = b
                .send_to_scoped_destination(&a_key, &a_addr, body.as_bytes())
                .await;
        }
    })
}

/// A small replication frame (one Channel packet) of a BOOTSTRAP kind — the
/// kind the #402 carve-out lets cross an un-attributed identity link, and the
/// strongest form of the plane refusal.
fn small_bootstrap_frame(marker: u8) -> Vec<u8> {
    wire_frame::wrap_for_kind(&ReplicationMessage::Deliver(DeliverMessage {
        kind: EnvelopeKind::Key,
        envelopes: vec![vec![b'{', b' ', marker, b' ', b'}']],
    }))
}

/// **The witness.** Pre-fix (v34.2.0): A's send picks the scoped link B
/// opened — the only live link to B, keyed to B at `LinkIdentified` — and B
/// drops the Resource `UNATTRIBUTED` (dest = A's derived address); the rows
/// never land and no round completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identity_plane_rows_admit_while_a_scoped_link_is_live_728() {
    let p = pair("admit").await;
    open_scoped_link_b_to_a(&p, b"scoped-open-728").await;
    let _pinger = scoped_pinger(&p);

    // A publishes identity-plane rows to B as a Resource.
    let (frame, ids) = resource_deliver(&p).await;
    p.a.transport
        .send(&p.b.key.key_id, &frame)
        .await
        .expect("A -> B identity-plane Deliver");
    let landed = wait_until(Duration::from_secs(60), || async {
        holds_all(&p.b.dir, &ids).await
    })
    .await;
    let seen = p.b.saw(frame.len()).await;
    assert!(
        landed,
        "the identity-plane rows A published must be ADMITTED at B while B's scoped link to \
         A is live — B holds A's hybrid-signed route, so the only way this fails is the \
         Deliver riding the scoped link (B's side of it resolves to A's derived address, \
         not to a peer: `inbound frame UNATTRIBUTED`). B saw: {seen:?} (CIRISEdge#728)"
    );
    let seen = seen.expect("B saw the frame");
    assert_eq!(
        seen.source_key_id.as_deref(),
        Some(p.a.key.key_id.as_str()),
        "attributed to A at the transport: {seen:?}"
    );
    assert_eq!(
        seen.arrival_member, None,
        "an identity-plane frame arrives on the federation address: {seen:?}"
    );

    // And A's ROUND toward B completes within the bound — the same selection,
    // through the scheduler.
    let sweeps = drive_a_until(&p, Duration::from_secs(60), || async {
        completed_rounds(&p.a.metrics) >= 1
    })
    .await;
    assert!(
        sweeps.is_some_and(|s| s <= ROUND_BOUND),
        "A's round toward B must COMPLETE within {ROUND_BOUND} sweeps (took {sweeps:?}); \
         outcomes={:?}",
        p.a.metrics.snapshot().replication_round_outcomes_total
    );

    // Nothing B received from A was refused on plane, and nothing was
    // un-attributed: every replication frame B saw names A.
    assert_eq!(
        scoped_link_refusals(&p.b.metrics),
        0,
        "B booked no plane refusal"
    );
    let unattributed: Vec<Seen> =
        p.b.seen
            .lock()
            .await
            .iter()
            .filter(|s| s.source_key_id.is_none() && s.arrival_member.is_none())
            .cloned()
            .collect();
    assert!(
        unattributed.is_empty(),
        "B must never see an un-attributed identity-plane frame from A: {unattributed:?}"
    );
}

/// Negative (c) / I-3.5.2 — with ONLY a scoped link live to B, an
/// identity-plane send DIALS B's identity destination; it never borrows the
/// scoped link, which stays exactly what it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_identity_send_dials_rather_than_borrowing_the_scoped_link_728() {
    let p = pair("dial").await;
    open_scoped_link_b_to_a(&p, b"scoped-open-728-dial").await;
    let before = planes(&p.a).await;
    assert_eq!(
        before.0, 0,
        "precondition: A holds no identity-plane link to B (B only dialled A's derived \
         address): {before:?}"
    );
    assert!(before.1 >= 1, "the scoped link is live at A: {before:?}");

    let (frame, ids) = resource_deliver(&p).await;
    p.a.transport
        .send(&p.b.key.key_id, &frame)
        .await
        .expect("A -> B identity-plane Deliver");
    let landed = wait_until(Duration::from_secs(60), || async {
        holds_all(&p.b.dir, &ids).await
    })
    .await;
    assert!(landed, "B admits the rows (see the witness)");

    let after = planes(&p.a).await;
    assert!(
        after.2 >= 1,
        "A must have DIALLED an identity-plane link to B rather than riding the scoped \
         one: before={before:?} after={after:?} (identity, scoped, dialled-identity)"
    );
    assert!(
        after.1 >= 1,
        "the scoped link is untouched by the identity-plane send: {after:?}"
    );
    // And B classified the same links the same way from its end: the link IT
    // dialled is scoped, the link A dialled is identity-plane.
    let b_planes = planes(&p.b).await;
    assert!(
        b_planes.0 >= 1 && b_planes.1 >= 1 && b_planes.2 == 0,
        "B: one identity link (A's), one scoped link (its own): {b_planes:?}"
    );
}

/// Negative (a) / I-3.5.3 — a scoped body from A lands on B's DERIVED address
/// (`arrival_scope` names B's own member address), never on the identity link
/// that exists between them by then.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_scoped_body_rides_the_derived_link_not_the_identity_link_728() {
    let p = pair("scoped").await;
    open_scoped_link_b_to_a(&p, b"scoped-open-728-body").await;

    // Put an identity-plane link A → B in place first (A dials it).
    let (frame, ids) = resource_deliver(&p).await;
    p.a.transport
        .send(&p.b.key.key_id, &frame)
        .await
        .expect("A -> B identity-plane Deliver");
    assert!(
        wait_until(Duration::from_secs(60), || async {
            holds_all(&p.b.dir, &ids).await
        })
        .await,
        "B admits the rows (see the witness)"
    );
    let a_planes = planes(&p.a).await;
    assert!(
        a_planes.2 >= 1,
        "an identity link A → B is live: {a_planes:?}"
    );

    // A scoped body A → B, with that identity link live.
    let body = b"scoped-body-728-from-a".to_vec();
    p.a.transport
        .send_to_scoped_destination(&p.b.key.key_id, &p.b.own_address, &body)
        .await
        .expect("A -> B on B's derived address");
    let landed = wait_until(Duration::from_secs(30), || async {
        p.b.saw(body.len()).await.is_some()
    })
    .await;
    assert!(landed, "B must receive A's scoped body");
    let seen = p.b.saw(body.len()).await.expect("seen");
    assert_eq!(
        seen.arrival_member.as_deref(),
        Some(p.b.key.key_id.as_str()),
        "the scoped body arrived on B's OWN derived address, not on the identity link: {seen:?}"
    );
    // The identity-plane Deliver, by contrast, arrived on the federation address.
    let deliver_seen = p.b.saw(frame.len()).await.expect("B saw the Deliver");
    assert_eq!(deliver_seen.arrival_member, None, "{deliver_seen:?}");
    assert_eq!(scoped_link_refusals(&p.b.metrics), 0);
    assert_eq!(scoped_link_refusals(&p.a.metrics), 0);
}

/// Negative (b) / I-3.5.4 — an identity-plane frame FORCED onto the scoped
/// link (a bootstrap `Key` Deliver, pinned to the link by its reply path) is
/// refused `identity_frame_on_scoped_link` — named, counted, and never
/// delivered — not the generic `UNATTRIBUTED` miss.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_identity_frame_on_a_scoped_link_is_refused_by_name_728() {
    let p = pair("refuse").await;
    open_scoped_link_b_to_a(&p, b"scoped-open-728-refuse").await;

    let scoped_link =
        p.b.transport
            .link_planes_for_test()
            .await
            .into_iter()
            .find(|(_, plane, dialed)| *plane == LinkPlane::Scoped && *dialed)
            .map(|(id, _, _)| id)
            .expect("B holds the scoped link it dialled");
    let frame = small_bootstrap_frame(b'x');
    assert_eq!(scoped_link_refusals(&p.a.metrics), 0);
    p.b.transport
        .send_on_reply_path(
            &p.a.key.key_id,
            &ReplyPath::new(TransportId::RETICULUM_RS, scoped_link),
            &frame,
        )
        .await
        .expect("B forces a replication frame onto the scoped link");
    let refused = wait_until(Duration::from_secs(20), || async {
        scoped_link_refusals(&p.a.metrics) >= 1
    })
    .await;
    assert!(
        refused,
        "A must refuse the frame by name: transport_inbound_drops={:?}",
        p.a.metrics.transport_inbound_drops()
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        p.a.saw(frame.len()).await.is_none(),
        "a refused frame is never delivered to the sink: {:?}",
        p.a.seen.lock().await
    );
}
