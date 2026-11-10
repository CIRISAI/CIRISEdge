//! **CIRISEdge#971 — a canonical's own rounds to NAT'd clients ride the
//! links the clients opened.**
//!
//! Field (canonical-1, edge v44.1.1): every round the canonical started
//! toward a `ciris-client-*` node ended `no_route` after the 3 s path seek,
//! 189 of 189, while its responder rounds for the same clients were healthy.
//!
//! The production shape, over real Reticulum on loopback:
//!
//! - one canonical, which cannot dial anyone (`refuse_outbound_dials_for_test`:
//!   a NAT'd client has no address the canonical can reach), so a round it
//!   starts can only cross on a link a client opened;
//! - three clients that dial the canonical and run their own rounds toward it
//!   on every plane, announcing as a server-composed node does
//!   (`federation_visible`, the default);
//! - the canonical given initiators for the clients through `set_peers`, as
//!   CIRISServer's `replication_reconcile` does from its consent peers.
//!
//! The twin (CEWP `docs/kernel/kernel.js`, `Mesh::tick`) offers every row on
//! the link between two neighbours, in both directions; CC 5.2 has a seat offer
//! a person's node what is required or appropriate, and CC 5.3.3.5 E1 never
//! dials a client-only phone. So the canonical's round to a linked client must
//! ride that client's link, and must not seek or dial.
//!
//! `cargo test --features transport-reticulum --test canonical_nat_clients_971`

#![cfg(feature = "transport-reticulum")]

mod common;

use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::observability::RoundOutcome;
use ciris_edge::replication::attestation_bind::owner_binding_attestation;
use ciris_edge::replication::{
    self_publish_set, EnvelopeKind, InboundRouter, ReplicationPeer, ReplicationRuntime,
    ReplicationRuntimeConfig, SchedulerConfig,
};
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport};
use ciris_edge::verify::RootingDirectory;
use ciris_edge::EdgeMetrics;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::{Attestation, FederationDirectory, SignedAttestation};
use ciris_persist::store::sqlite::SqliteBackend;
use common::{build_reticulum_with_retry, directory_with};
use sha2::Digest as _;
use std::sync::Arc;
use std::time::Duration;

/// The planes a server-composed canonical rounds on with each consent peer.
const KINDS: [EnvelopeKind; 4] = [
    EnvelopeKind::Key,
    EnvelopeKind::IdentityOccurrence,
    EnvelopeKind::TransportDestination,
    EnvelopeKind::Attestation,
];

/// The canonical's round timeout: one kicked round's whole budget here.
const ROUND_TIMEOUT: Duration = Duration::from_secs(15);

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

/// A production-shaped identity: a hybrid keypair and a key id derived from
/// the pubkey, as persist derives it (see `membership_first_contact_756`).
struct Ident {
    key_id: String,
    ed: Arc<Ed25519SoftwareSigner>,
    pqc: Arc<MlDsa65SoftwareSigner>,
    ed_pub: Vec<u8>,
    pqc_pub_b64: String,
    records:
        tokio::sync::Mutex<std::collections::HashMap<String, ciris_persist::federation::KeyRecord>>,
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
            records: tokio::sync::Mutex::new(std::collections::HashMap::new()),
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
        if let Some(r) = self.records.lock().await.get(identity_type) {
            return r.clone();
        }
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
        let r = ciris_persist::federation::KeyRecord {
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
        };
        self.records
            .lock()
            .await
            .insert(identity_type.to_owned(), r.clone());
        r
    }
}

async fn put(dir: &SqliteBackend, att: Attestation) -> String {
    let id = att.attestation_id.clone();
    dir.put_attestation(SignedAttestation { attestation: att })
        .await
        .unwrap_or_else(|e| panic!("put {id}: {e:?}"));
    id
}

/// A node: its node key, its owner, its store (the owner-binding and the
/// node's own occurrence in it, as a server-composed node writes them).
struct Node {
    key: Ident,
    owner: Ident,
    dir: Arc<SqliteBackend>,
    metrics: EdgeMetrics,
    binding: String,
}

impl Node {
    async fn new(
        key: Ident,
        owner: Ident,
        known: Vec<ciris_persist::federation::KeyRecord>,
    ) -> Self {
        let mut records = vec![key.record("node").await, owner.record("user").await];
        records.extend(known);
        let dir = directory_with(records).await;
        let binding = put(
            &dir,
            owner_binding_attestation(
                &owner.key_id,
                &key.key_id,
                chrono::Utc::now(),
                &owner.signer(),
            )
            .await
            .expect("owner binding"),
        )
        .await;
        dir.put_identity_occurrence(
            common::node_signed_occurrence(
                &owner.key_id,
                &key.key_id,
                &key.signer(),
                ciris_persist::federation::types::device_class::PHONE,
            )
            .await,
        )
        .await
        .expect("the node's own occurrence");
        Self {
            key,
            owner,
            dir,
            metrics: EdgeMetrics::new(),
            binding,
        }
    }

    /// An UNCLAIMED node, as a fresh unsplit client install boots: its node
    /// key only. No owner, so no owner-binding, no occurrence, and (server
    /// `consent_for_canonicals`, peer.rs:783) no consent to any canonical.
    async fn unclaimed(key: Ident, known: Vec<ciris_persist::federation::KeyRecord>) -> Self {
        let mut records = vec![key.record("node").await];
        records.extend(known);
        let dir = directory_with(records).await;
        let owner = Ident::new(&format!("{}-no-owner", key.key_id), 0xee).await;
        Self {
            key,
            owner,
            dir,
            metrics: EdgeMetrics::new(),
            binding: String::new(),
        }
    }

    async fn holds_route_of(&self, key_id: &str) -> bool {
        !self
            .dir
            .list_signed_transport_destinations_for(key_id)
            .await
            .unwrap_or_default()
            .is_empty()
    }

    fn auth(&self) -> ReticulumAuth {
        ReticulumAuth {
            signer: Some(self.key.signer()),
            rooting: Some(Arc::clone(&self.dir) as Arc<dyn RootingDirectory>),
            resolver: None,
            hybrid_policy: ciris_edge::HybridPolicy::Strict,
            ..ReticulumAuth::default()
        }
    }

    async fn holds(&self, attestation_id: &str) -> bool {
        self.dir
            .get_attestation(attestation_id)
            .await
            .ok()
            .flatten()
            .is_some()
    }

    fn all_outcomes(&self) -> String {
        format!("{:?}", self.metrics.replication_round_outcomes_total.read())
    }

    fn outcomes(&self, outcome: RoundOutcome) -> u64 {
        self.metrics
            .replication_round_outcomes_total
            .read()
            .get(&outcome)
            .copied()
            .unwrap_or(0)
    }
}

fn peers_for(keys: &[&str]) -> Vec<ReplicationPeer> {
    keys.iter()
        .flat_map(|k| {
            KINDS.into_iter().map(move |kind| ReplicationPeer {
                peer_key_id: (*k).to_owned(),
                kind,
            })
        })
        .collect()
}

async fn start_runtime(
    node: &Node,
    transport: Arc<ReticulumTransport>,
    peers: Vec<ReplicationPeer>,
    cadence: Duration,
) -> Arc<ReplicationRuntime> {
    let publish = vec![node.key.key_id.clone(), node.owner.key_id.clone()];
    start_runtime_with(node, transport, peers, cadence, publish, false).await
}

/// [`start_runtime`] with the self-publish set and the bundle path chosen.
async fn start_runtime_with(
    node: &Node,
    transport: Arc<ReticulumTransport>,
    peers: Vec<ReplicationPeer>,
    cadence: Duration,
    publish: Vec<String>,
    bundle: bool,
) -> Arc<ReplicationRuntime> {
    let runtime = Arc::new(
        ReplicationRuntime::start(
            Arc::clone(&node.dir) as Arc<dyn FederationDirectory>,
            Arc::clone(&transport) as Arc<dyn Transport>,
            peers,
            ReplicationRuntimeConfig {
                disable_bundle_bootstrap_peers: !bundle,
                scheduler: SchedulerConfig {
                    cadence,
                    round_timeout: ROUND_TIMEOUT,
                    ..SchedulerConfig::default()
                },
                local_key_id: Some(node.key.key_id.clone()),
                metrics: Some(node.metrics.clone()),
                ..Default::default()
            },
            Some(self_publish_set(publish)),
        )
        .await,
    );
    let (tx, mut rx) = tokio::sync::mpsc::channel::<InboundFrame>(1024);
    let t = Arc::clone(&transport);
    tokio::spawn(async move {
        let _ = t.listen(tx).await;
    });
    let router = InboundRouter::new(runtime.registry());
    tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            let _ = router.try_route(&frame).await;
        }
    });
    runtime
}

/// CC 5.3.3.5 E1 — `to` holds `from`'s signed route (its transit pair), as
/// the TransportDestination plane or the genesis bundle would hand it.
async fn seed_route(from: &Node, to: &Node) {
    for r in from
        .dir
        .list_signed_transport_destinations_for(&from.key.key_id)
        .await
        .expect("own routes")
    {
        FederationDirectory::put_signed_transport_destination(&*to.dir, &r)
            .await
            .expect("seed the route");
    }
}

async fn wait_for_own_route(node: &Node, budget: Duration) {
    let deadline = tokio::time::Instant::now() + budget;
    while node
        .dir
        .list_signed_transport_destinations_for(&node.key.key_id)
        .await
        .unwrap_or_default()
        .is_empty()
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "#406 producer never published {}'s signed route",
            node.key.key_id
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
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

struct Mesh {
    canonical: Node,
    clients: Vec<Node>,
    t_canonical: Arc<ReticulumTransport>,
    rt_canonical: Arc<ReplicationRuntime>,
    _rt_clients: Vec<Arc<ReplicationRuntime>>,
    _tmp: tempfile::TempDir,
}

/// The canonical and `n` clients. `lose_first_establish`: the canonical
/// drops the `LinkEstablished` of the FIRST client's link (CIRISEdge#853, a
/// control-plane overflow), and the other clients start only after that link
/// is up, so the drop lands on it and on nothing else.
async fn mesh(tag: u8, n: u8, lose_first_establish: bool) -> Mesh {
    let tmp = tempfile::tempdir().expect("tempdir");
    let can_key = Ident::new(&format!("canonical-971-{tag}"), 0x40 ^ tag).await;
    let can_owner = Ident::new(&format!("steward-971-{tag}"), 0x41 ^ tag).await;
    let mut client_idents = Vec::new();
    for i in 0..n {
        client_idents.push((
            Ident::new(&format!("ciris-client-971-{tag}-{i}"), 0x50 ^ tag ^ (i * 2)).await,
            Ident::new(&format!("person-971-{tag}-{i}"), 0x60 ^ tag ^ (i * 2)).await,
        ));
    }
    let mut known_at_canonical = Vec::new();
    for (k, _) in &client_idents {
        known_at_canonical.push(k.record("node").await);
    }
    let can_record = can_key.record("node").await;
    let canonical = Node::new(can_key, can_owner, known_at_canonical).await;
    let mut clients = Vec::new();
    for (k, o) in client_idents {
        clients.push(Node::new(k, o, vec![can_record.clone()]).await);
    }

    let base = tmp.path().to_path_buf();
    let (t_canonical, addr) = build_reticulum_with_retry(|| async {
        let mut cfg = ReticulumTransportConfig::new(
            base.join("canonical/transport.id"),
            &canonical.key.key_id,
        );
        cfg.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        cfg.announce_interval = Duration::from_secs(5);
        (cfg, canonical.auth())
    })
    .await;
    // A NAT'd client has no address the canonical can reach: every dial it
    // makes fails as unroutable, and only links the clients open remain.
    t_canonical.refuse_outbound_dials_for_test(true);
    if lose_first_establish {
        t_canonical.drop_next_inbound_link_established_for_test();
    }
    let port = addr.port();
    // The canonical rounds only when kicked, so each kick's outcome is its own.
    let rt_canonical = start_runtime(
        &canonical,
        Arc::clone(&t_canonical),
        Vec::new(),
        Duration::from_secs(3600),
    )
    .await;
    wait_for_own_route(&canonical, Duration::from_secs(150)).await;

    let mut rt_clients = Vec::new();
    for (i, client) in clients.iter().enumerate() {
        let (t, _) = build_reticulum_with_retry(|| async {
            let mut cfg = ReticulumTransportConfig::new(
                base.join(format!("client-{i}/transport.id")),
                &client.key.key_id,
            );
            cfg.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            cfg.bootstrap_peers = vec![format!("127.0.0.1:{port}").parse().unwrap()];
            cfg.announce_interval = Duration::from_secs(5);
            (cfg, client.auth())
        })
        .await;
        wait_for_own_route(client, Duration::from_secs(150)).await;
        seed_route(&canonical, client).await;
        seed_route(client, &canonical).await;
        let rt = start_runtime(
            client,
            t,
            peers_for(&[canonical.key.key_id.as_str()]),
            Duration::from_secs(3),
        )
        .await;
        rt_clients.push(rt);
        // The first client's link is the one a lost establishment lands on.
        if i == 0 {
            let first = client.key.key_id.clone();
            let t = Arc::clone(&t_canonical);
            assert!(
                wait_until(Duration::from_secs(120), || {
                    let (t, first) = (Arc::clone(&t), first.clone());
                    async move { !t.reverse_links_for_test(&first).await.is_empty() }
                })
                .await,
                "the first client's link to the canonical comes up and is attributed"
            );
        }
    }
    // As CIRISServer's reconciler: every consent peer, every plane.
    let keys: Vec<&str> = clients.iter().map(|c| c.key.key_id.as_str()).collect();
    rt_canonical
        .set_peers(peers_for(&keys))
        .await
        .expect("the canonical's initiators");
    Mesh {
        canonical,
        clients,
        t_canonical,
        rt_canonical,
        _rt_clients: rt_clients,
        _tmp: tmp,
    }
}

/// Kick the canonical's rounds toward ONE client and say how they ended: how
/// many completed and how many ended `no_route` within one round's budget.
async fn kick_and_read(m: &Mesh, client: &Node) -> (u64, u64) {
    let (done0, none0) = (
        m.canonical.outcomes(RoundOutcome::Completed),
        m.canonical.outcomes(RoundOutcome::NoRoute),
    );
    m.rt_canonical
        .round_now(&client.key.key_id)
        .await
        .expect("kick");
    let want = u64::try_from(KINDS.len()).unwrap();
    let _ = wait_until(ROUND_TIMEOUT + Duration::from_secs(5), || async {
        let done = m.canonical.outcomes(RoundOutcome::Completed) - done0;
        let none = m.canonical.outcomes(RoundOutcome::NoRoute) - none0;
        done + none >= want
    })
    .await;
    (
        m.canonical.outcomes(RoundOutcome::Completed) - done0,
        m.canonical.outcomes(RoundOutcome::NoRoute) - none0,
    )
}

/// The rows each side must hold from the other once the clients' rounds have
/// run: the canonical's owner-binding at every client, every client's at the
/// canonical. A row the canonical's own rounds would carry is not lost when it
/// does not run them.
async fn rows_crossed(m: &Mesh) -> bool {
    for c in &m.clients {
        if !c.holds(&m.canonical.binding).await || !m.canonical.holds(&c.binding).await {
            return false;
        }
    }
    true
}

/// **The production shape, links intact.** Every client is linked; the
/// canonical's kicked rounds toward each must complete on that link, never
/// ending `no_route`; the clients' own rounds complete; nothing the clients
/// should hold is missing; and no round times out, so the #968 first-contact
/// ladder (which only an unanswered round arms) never fires.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_canonicals_rounds_to_linked_nat_clients_ride_their_links_971() {
    init_tracing();
    let m = mesh(1, 3, false).await;
    assert!(
        wait_until(Duration::from_secs(120), || rows_crossed(&m)).await,
        "the clients' own rounds carry both sides' rows"
    );
    for c in &m.clients {
        assert!(
            c.outcomes(RoundOutcome::Completed) > 0,
            "the client's own rounds complete"
        );
        let (done, none) = kick_and_read(&m, c).await;
        assert_eq!(
            none,
            0,
            "a canonical round to linked {} ended no_route: it did not find the client's \
             link (reverse links {:?}, planes {:?})",
            c.key.key_id,
            m.t_canonical.reverse_links_for_test(&c.key.key_id).await,
            m.t_canonical.link_planes_for_test().await
        );
        assert!(
            done > 0,
            "the canonical's rounds to {} complete",
            c.key.key_id
        );
    }
    assert_eq!(
        m.canonical.outcomes(RoundOutcome::TimedOut),
        0,
        "no canonical round goes unanswered, so the first-contact ladder never arms"
    );
}

/// **CIRISEdge#853 under #971.** The canonical lost the `LinkEstablished` of
/// the first client's link (a control-plane overflow). Edge recovers such a
/// link on its next frame, and its frames are attributed and served; the
/// canonical's own round toward that client must ride it too. If the
/// reverse-path lookup requires a plane record the lost event never wrote,
/// the round falls to the dial and ends `no_route`: the field's signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_link_whose_establishment_was_lost_carries_the_canonicals_round_971() {
    init_tracing();
    let m = mesh(2, 2, true).await;
    assert!(
        wait_until(Duration::from_secs(120), || rows_crossed(&m)).await,
        "the clients' own rounds carry both sides' rows, the lost establishment included"
    );
    let first = &m.clients[0];
    let links = m
        .t_canonical
        .reverse_links_for_test(&first.key.key_id)
        .await;
    assert!(!links.is_empty(), "the first client's link is attributed");
    let (done, none) = kick_and_read(&m, first).await;
    assert_eq!(
        none,
        0,
        "the canonical's round to {} ended no_route on a link whose establishment it lost \
         (reverse links {links:?}, planes {:?})",
        first.key.key_id,
        m.t_canonical.link_planes_for_test().await
    );
    assert!(done > 0, "the canonical's rounds ride the recovered link");
    let (done, none) = kick_and_read(&m, &m.clients[1]).await;
    assert_eq!(none, 0, "the second client's rounds are unaffected");
    assert!(done > 0);
}

/// The canonical and `n` UNCLAIMED, unsplit clients: announcing (the server's
/// `federation_visible` default), no owner, no consent to the canonical, and
/// their route rows NOT seeded at the canonical, so the only way the canonical
/// learns a client's transit pair is a round the client opens. The canonical
/// holds initiators for them, as its reconciler gives it.
///
/// `bootstrap_rounds`: the client rounds with the canonical on
/// [`BOOTSTRAP_ROUND_PLANES`] — exactly the peers the #881 bundle path (on by default)
/// (#881) adds for a bundle serve node (`bundle_bootstrap_peers`,
/// runtime.rs:895). Off is what CIRISServer 0.5.246 composes (compose.rs:5177
/// never sets the flag): such a client has no initiator toward the seat.
///
/// [`BOOTSTRAP_ROUND_PLANES`]: ciris_edge::replication::runtime::BOOTSTRAP_ROUND_PLANES
async fn unclaimed_mesh(tag: u8, n: u8, bootstrap_rounds: bool) -> Mesh {
    let tmp = tempfile::tempdir().expect("tempdir");
    let can_key = Ident::new(&format!("canonical-971u-{tag}"), 0x70 ^ tag).await;
    let can_owner = Ident::new(&format!("steward-971u-{tag}"), 0x71 ^ tag).await;
    let mut keys = Vec::new();
    for i in 0..n {
        keys.push(
            Ident::new(
                &format!("ciris-client-971u-{tag}-{i}"),
                0x80 ^ tag ^ (i * 2),
            )
            .await,
        );
    }
    let mut known_at_canonical = Vec::new();
    for k in &keys {
        known_at_canonical.push(k.record("node").await);
    }
    let can_record = can_key.record("node").await;
    let canonical = Node::new(can_key, can_owner, known_at_canonical).await;
    let mut clients = Vec::new();
    for k in keys {
        clients.push(Node::unclaimed(k, vec![can_record.clone()]).await);
    }
    let base = tmp.path().to_path_buf();
    let (t_canonical, addr) = build_reticulum_with_retry(|| async {
        let mut cfg = ReticulumTransportConfig::new(
            base.join("canonical/transport.id"),
            &canonical.key.key_id,
        );
        cfg.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        cfg.announce_interval = Duration::from_secs(5);
        (cfg, canonical.auth())
    })
    .await;
    // The served-set measurement reads every sealed frame on the seat's links.
    t_canonical.set_link_wire_tap_for_test(true);
    t_canonical.refuse_outbound_dials_for_test(true);
    let port = addr.port();
    let rt_canonical = start_runtime(
        &canonical,
        Arc::clone(&t_canonical),
        Vec::new(),
        Duration::from_secs(3600),
    )
    .await;
    wait_for_own_route(&canonical, Duration::from_secs(150)).await;
    let mut rt_clients = Vec::new();
    for (i, client) in clients.iter().enumerate() {
        let (t, _) = build_reticulum_with_retry(|| async {
            let mut cfg = ReticulumTransportConfig::new(
                base.join(format!("uclient-{i}/transport.id")),
                &client.key.key_id,
            );
            cfg.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            cfg.bootstrap_peers = vec![format!("127.0.0.1:{port}").parse().unwrap()];
            cfg.announce_interval = Duration::from_secs(5);
            (cfg, client.auth())
        })
        .await;
        wait_for_own_route(client, Duration::from_secs(150)).await;
        // The bundle seeds the seat's route at every device; the device's
        // route reaches the seat only in a round.
        seed_route(&canonical, client).await;
        let peers = if bootstrap_rounds {
            ciris_edge::replication::runtime::BOOTSTRAP_ROUND_PLANES
                .into_iter()
                .map(|kind| ReplicationPeer {
                    peer_key_id: canonical.key.key_id.clone(),
                    kind,
                })
                .collect()
        } else {
            Vec::new()
        };
        rt_clients.push(start_runtime(client, t, peers, Duration::from_secs(3)).await);
    }
    let keys: Vec<&str> = clients.iter().map(|c| c.key.key_id.as_str()).collect();
    rt_canonical
        .set_peers(peers_for(&keys))
        .await
        .expect("the canonical's initiators");
    Mesh {
        canonical,
        clients,
        t_canonical,
        rt_canonical,
        _rt_clients: rt_clients,
        _tmp: tmp,
    }
}

/// **The field's shape, as 0.5.246 composes it.** An unclaimed unsplit client
/// with no consent to the seat and no bundle bootstrap rounds never opens a
/// round to the canonical: its route row (its transit pair, CC 5.3.3.5 E1)
/// never reaches the seat, the seat never roots it, no responder round is
/// served for it, and every round the seat starts toward it ends `no_route`.
/// This pins the stranding the flag exists to prevent; it is not a fix.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unclaimed_client_without_bootstrap_rounds_is_never_rooted_at_the_seat_971() {
    init_tracing();
    let m = unclaimed_mesh(3, 2, false).await;
    tokio::time::sleep(Duration::from_secs(30)).await;
    for c in &m.clients {
        assert!(
            !m.canonical.holds_route_of(&c.key.key_id).await,
            "no round of the client's carried its route to the seat"
        );
        assert!(
            m.t_canonical
                .reverse_links_for_test(&c.key.key_id)
                .await
                .is_empty(),
            "the client holds no attributed link at the seat"
        );
    }
    let planes = u64::try_from(KINDS.len() * m.clients.len()).unwrap();
    assert_eq!(
        m.canonical.outcomes(RoundOutcome::Completed),
        0,
        "no round the seat started toward the clients completes: {}",
        m.canonical.all_outcomes()
    );
    assert!(
        m.canonical.outcomes(RoundOutcome::NoRoute) >= planes,
        "each client's first round on every plane ends no_route: {}",
        m.canonical.all_outcomes()
    );
    assert_eq!(
        m.canonical.outcomes(RoundOutcome::TimedOut),
        0,
        "no_route is never an unanswered round: the #968 ladder does not arm"
    );
}

/// **With the device's bootstrap rounds (#881).** The client's own Key /
/// IdentityOccurrence / TransportDestination rounds carry its route row
/// through the bootstrap carve-out (#402/#636); the seat roots it, and the
/// seat's next round toward it rides the link the client opened.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bootstrap_rounds_root_the_client_and_the_seats_round_rides_its_link_971() {
    init_tracing();
    let m = unclaimed_mesh(4, 2, true).await;
    for c in &m.clients {
        let key = c.key.key_id.clone();
        assert!(
            wait_until(Duration::from_secs(120), || {
                let key = key.clone();
                let can = &m.canonical;
                async move { can.holds_route_of(&key).await }
            })
            .await,
            "the client's bootstrap rounds carry its route row to the seat"
        );
        assert!(
            c.outcomes(RoundOutcome::Completed) > 0,
            "the client's own rounds complete: {}",
            c.all_outcomes()
        );
        let (done, none) = kick_and_read(&m, c).await;
        assert_eq!(
            none,
            0,
            "the seat's round to {} ended no_route (reverse links {:?})",
            c.key.key_id,
            m.t_canonical.reverse_links_for_test(&c.key.key_id).await
        );
        assert!(done > 0, "the seat's round rides the client's link");
    }
}

/// The seat's Attestation advertise sweeps so far: one send-set source line
/// per sweep (CIRISEdge#968, `advertise_send_set_{memo_hit,read}`).
fn sweeps(node: &Node) -> u64 {
    let a = node.metrics.advertise();
    a.get("advertise_send_set_memo_hit").copied().unwrap_or(0)
        + a.get("advertise_send_set_read").copied().unwrap_or(0)
}

/// The field's failing roster: NODE-typed keys the seat holds consent-derived
/// initiators for, that hold no link to it and no pair at it.
struct Roster {
    canonical: Node,
    t_canonical: Arc<ReticulumTransport>,
    rt_canonical: Arc<ReplicationRuntime>,
    /// A stale or offline key: a record at the seat, no node behind it, no path.
    ghost: Ident,
    /// A live node that announces (the seat learns a path to it) and never
    /// rounds with the seat: pairless at the seat.
    quiet: Node,
    quiet_transport: Arc<ReticulumTransport>,
    _tmp: tempfile::TempDir,
}

async fn roster(tag: u8) -> Roster {
    let tmp = tempfile::tempdir().expect("tempdir");
    let can_key = Ident::new(&format!("canonical-971r-{tag}"), 0x90 ^ tag).await;
    let can_owner = Ident::new(&format!("steward-971r-{tag}"), 0x91 ^ tag).await;
    let ghost = Ident::new(&format!("ciris-client-971r-ghost-{tag}"), 0x92 ^ tag).await;
    let quiet_key = Ident::new(&format!("ciris-client-971r-quiet-{tag}"), 0x93 ^ tag).await;
    let known = vec![ghost.record("node").await, quiet_key.record("node").await];
    let can_record = can_key.record("node").await;
    let canonical = Node::new(can_key, can_owner, known).await;
    let quiet = Node::unclaimed(quiet_key, vec![can_record]).await;
    let base = tmp.path().to_path_buf();
    let (t_canonical, addr) = build_reticulum_with_retry(|| async {
        let mut cfg = ReticulumTransportConfig::new(
            base.join("canonical/transport.id"),
            &canonical.key.key_id,
        );
        cfg.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        cfg.announce_interval = Duration::from_secs(5);
        (cfg, canonical.auth())
    })
    .await;
    t_canonical.refuse_outbound_dials_for_test(true);
    let port = addr.port();
    let rt_canonical = start_runtime(
        &canonical,
        Arc::clone(&t_canonical),
        Vec::new(),
        Duration::from_secs(3600),
    )
    .await;
    wait_for_own_route(&canonical, Duration::from_secs(150)).await;
    // The quiet node's transport only: it announces, and opens nothing.
    let (quiet_transport, _) = build_reticulum_with_retry(|| async {
        let mut cfg =
            ReticulumTransportConfig::new(base.join("quiet/transport.id"), &quiet.key.key_id);
        cfg.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        cfg.bootstrap_peers = vec![format!("127.0.0.1:{port}").parse().unwrap()];
        cfg.announce_interval = Duration::from_secs(5);
        (cfg, quiet.auth())
    })
    .await;
    {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<InboundFrame>(64);
        let t = Arc::clone(&quiet_transport);
        tokio::spawn(async move {
            let _ = t.listen(tx).await;
        });
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
    }
    // The field's 8: announced once (a binding at the seat, Advisory, at a
    // destination the seat holds no path to), never linked, no pair.
    t_canonical
        .inject_advisory_peer_with_transport_identity_for_test(
            &ghost.key_id,
            [0xab; 16],
            [0x5a; 64],
        )
        .await;
    Roster {
        canonical,
        t_canonical,
        rt_canonical,
        ghost,
        quiet,
        quiet_transport,
        _tmp: tmp,
    }
}

/// The seat's FIRST rounds toward `peer` on every plane, as the reconciler
/// starts them: `set_peers` with `peer` added (each new coordinator's first
/// tick fires at once). Returns (completed, no_route, wall time until every
/// plane ended, Attestation sweeps run). `already` are the peers set before.
async fn first_rounds(r: &Roster, already: &[&str], peer: &str) -> (u64, u64, Duration, u64) {
    let (done0, none0, sweeps0) = (
        r.canonical.outcomes(RoundOutcome::Completed),
        r.canonical.outcomes(RoundOutcome::NoRoute),
        sweeps(&r.canonical),
    );
    let mut keys: Vec<&str> = already.to_vec();
    keys.push(peer);
    let started = tokio::time::Instant::now();
    r.rt_canonical
        .set_peers(peers_for(&keys))
        .await
        .expect("the canonical's initiators");
    let want = u64::try_from(KINDS.len()).unwrap();
    let _ = wait_until(ROUND_TIMEOUT + Duration::from_secs(5), || async {
        let done = r.canonical.outcomes(RoundOutcome::Completed) - done0;
        let none = r.canonical.outcomes(RoundOutcome::NoRoute) - none0;
        done + none >= want
    })
    .await;
    (
        r.canonical.outcomes(RoundOutcome::Completed) - done0,
        r.canonical.outcomes(RoundOutcome::NoRoute) - none0,
        started.elapsed(),
        sweeps(&r.canonical) - sweeps0,
    )
}

/// **T3, the field's RED.** Two roster entries that never link in: a ghost
/// (a key with no node: no link, no path, no pair) and a quiet announcing
/// node (path learned, no pair). The ghost is undialable under CC 5.3.3.5 E1,
/// so a round toward it must cost nothing: booked `no_route` as before (so the
/// server's counts stay comparable), without the 3 s path seek and without an
/// advertise sweep. On 92012e5 it seeks about 3 s and sweeps first. The quiet
/// node has a path, so E1's pre-seal route fetch may dial it: here the dial is
/// refused at once (the NAT seam), and nothing may wait out a seek either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rounds_toward_undialable_roster_entries_cost_nothing_971() {
    init_tracing();
    let r = roster(5).await;
    let quiet = r.quiet.key.key_id.clone();
    let quiet_dest = r.quiet_transport.local_named_dest_hash();
    assert!(
        wait_until(Duration::from_secs(60), || {
            let t = Arc::clone(&r.t_canonical);
            async move {
                t.path_table_rows_for_test()
                    .iter()
                    .any(|(d, _, _)| *d == quiet_dest)
            }
        })
        .await,
        "the seat hears the quiet node's announce and learns a path to it"
    );
    let ghost = r.ghost.key_id.clone();
    for (name, already, peer) in [
        ("ghost", Vec::<&str>::new(), ghost.clone()),
        ("quiet", vec![ghost.as_str()], quiet.clone()),
    ] {
        let dials0 = r.t_canonical.refused_dials_for_test();
        let reach0 = r.canonical.metrics.replication_reach();
        let (done, none, took, swept) = first_rounds(&r, &already, &peer).await;
        let dials = r.t_canonical.refused_dials_for_test() - dials0;
        let reach = r.canonical.metrics.replication_reach();
        let delta = |label: &str| {
            reach.get(label).copied().unwrap_or(0) - reach0.get(label).copied().unwrap_or(0)
        };
        eprintln!(
            "971 T3 {name}: completed={done} no_route={none} took={took:?} sweeps={swept} all={}",
            r.canonical.all_outcomes()
        );
        assert_eq!(done, 0, "{name}: nothing can complete");
        assert_eq!(
            none,
            u64::try_from(KINDS.len()).unwrap(),
            "{name}: every plane's round is booked no_route, as on 0.5.245"
        );
        assert!(
            took < Duration::from_secs(1),
            "{name}: the round must not wait out a path seek toward a peer E1 never dials \
             (took {took:?})"
        );
        // The ghost has no link, no path and no pair: no rule lets the seat
        // dial it, so nothing may be spent on it. The quiet node has a path,
        // which E1's pre-seal route fetch (CLM-pre-seal-route-fetch,
        // reticulum.rs `dial_transit_pair`) may dial: its round stays a round.
        if name == "ghost" {
            assert_eq!(
                swept, 0,
                "ghost: no advertise sweep for a round no rule can carry"
            );
            assert_eq!(dials, 0, "ghost: never dialled");
            assert_eq!(
                delta("round_skipped_undialable"),
                u64::try_from(KINDS.len()).unwrap(),
                "ghost: every plane's round skipped at the start, and counted"
            );
            assert_eq!(delta("path_request_sent"), 0, "ghost: no path request");
        } else {
            // The pathed, pairless node keeps its dial (CC 5.3.3.5 E1's
            // pre-seal route fetch): the predicate must never widen to it.
            // Mutation: make `undialable_now` ignore the path, and no dial
            // is attempted here.
            assert!(
                dials > 0,
                "quiet: the dial is attempted (route fetch first)"
            );
            assert_eq!(
                delta("round_skipped_undialable") + delta("skipped_undialable"),
                0,
                "quiet: never skipped as undialable"
            );
        }
    }
    assert_eq!(
        r.canonical.outcomes(RoundOutcome::TimedOut),
        0,
        "the #968 ladder never arms"
    );
    drop(r.quiet_transport);
}

/// **T4, recovery.** The quiet entry comes alive: it rounds with the seat on
/// the bootstrap planes (#881), so its route row (its pair) reaches the seat
/// and roots it. The seat's next round toward it rides the link it opened and
/// carries what it should hold: the seat's own owner-binding (an allegiance
/// fact, CIRISEdge#671).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_undialable_entry_that_comes_alive_is_carried_on_its_link_971() {
    init_tracing();
    let r = roster(6).await;
    let quiet = r.quiet.key.key_id.clone();
    let (_, none, _, _) = first_rounds(&r, &[], &quiet).await;
    assert!(none > 0, "undialable before it comes alive");
    seed_route(&r.canonical, &r.quiet).await;
    wait_for_own_route(&r.quiet, Duration::from_secs(150)).await;
    let peers = ciris_edge::replication::runtime::BOOTSTRAP_ROUND_PLANES
        .into_iter()
        .map(|kind| ReplicationPeer {
            peer_key_id: r.canonical.key.key_id.clone(),
            kind,
        })
        .collect();
    let _rt_quiet = start_runtime(
        &r.quiet,
        Arc::clone(&r.quiet_transport),
        peers,
        Duration::from_secs(3),
    )
    .await;
    assert!(
        wait_until(Duration::from_secs(120), || async {
            r.canonical.holds_route_of(&quiet).await
        })
        .await,
        "its own bootstrap rounds carry its route row to the seat"
    );
    // Its attributed frames clear the seat's no-route backoff and kick the
    // seat's rounds (#794); they must complete on its link, unasked.
    let done0 = r.canonical.outcomes(RoundOutcome::Completed);
    assert!(
        wait_until(Duration::from_secs(60), || async {
            r.canonical.outcomes(RoundOutcome::Completed) > done0
                && r.quiet.holds(&r.canonical.binding).await
        })
        .await,
        "the seat's rounds ride the quiet node's link and carry the seat's binding to it \
         (reverse links {:?})",
        r.t_canonical.reverse_links_for_test(&quiet).await
    );
}

/// Sealed bytes on the seat's links so far (both directions, every frame).
fn tapped_bytes(t: &ReticulumTransport) -> usize {
    t.link_wire_tapped_for_test()
        .iter()
        .map(|(_, f)| f.len())
        .sum()
}

fn applied(node: &Node) -> std::collections::HashMap<EnvelopeKind, u64> {
    node.metrics.replication_applied_total.read().clone()
}

/// **What the seat serves an unclaimed device, per bootstrap plane** — for the
/// load sheet, not a pass criterion beyond "the device is served". Measured
/// on the first-contact window (the device's first bootstrap rounds until it
/// is rooted, plus 30 s) and on a following 30 s idle window: per plane, the
/// rows the seat offers this peer (its per-peer listing), the rows the device
/// admitted (its applied counter), the seat's withholds by reason, and the
/// sealed bytes on the seat's links. CC 5.2 / 5.4.6 bound what may move; this
/// records what does. Nothing here narrows the round.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_the_seat_serves_an_unclaimed_device_per_plane_971() {
    use ciris_edge::replication::ReplicationDirectory as _;
    init_tracing();
    let m = unclaimed_mesh(7, 1, true).await;
    let c = &m.clients[0];
    let bridge = m.rt_canonical.bridge();
    let mut offered = Vec::new();
    for kind in ciris_edge::replication::runtime::BOOTSTRAP_ROUND_PLANES {
        let refs = bridge
            .list_envelope_refs_for_peer(kind, Some(c.key.key_id.as_str()))
            .await;
        offered.push((kind, refs.len()));
    }
    let key = c.key.key_id.clone();
    assert!(
        wait_until(Duration::from_secs(120), || {
            let key = key.clone();
            let can = &m.canonical;
            async move { can.holds_route_of(&key).await }
        })
        .await,
        "the device roots at the seat"
    );
    tokio::time::sleep(Duration::from_secs(30)).await;
    let first_bytes = tapped_bytes(&m.t_canonical);
    let first_applied = applied(c);
    let first_withheld = m.canonical.metrics.snapshot().withholds_by_reason;
    tokio::time::sleep(Duration::from_secs(30)).await;
    let idle_bytes = tapped_bytes(&m.t_canonical) - first_bytes;
    let idle_applied: Vec<(EnvelopeKind, u64)> = applied(c)
        .into_iter()
        .map(|(k, n)| (k, n - first_applied.get(&k).copied().unwrap_or(0)))
        .collect();
    for (kind, n) in &offered {
        eprintln!(
            "971 served {kind:?}: offered_by_seat={n} admitted_first_contact={}",
            first_applied.get(kind).copied().unwrap_or(0)
        );
    }
    eprintln!(
        "971 served FIRST CONTACT: sealed_bytes={first_bytes} withheld_by_reason={first_withheld:?}"
    );
    eprintln!("971 served IDLE 30 s: sealed_bytes={idle_bytes} admitted={idle_applied:?}");
    assert!(
        first_applied.values().sum::<u64>() > 0,
        "the seat serves the device something on its bootstrap rounds"
    );
}

// ── CIRISEdge#971 (d) — bundle-seat mode: the required set by subject Pull ──

/// A seat whose Key offer to a stranger is `k` announced keys (its
/// self-publish set; on canonical-1 the relay selector's 2,690), and one
/// unclaimed device that holds the seat as a BUNDLE seat (not a consent peer).
struct BundleMesh {
    seat: Node,
    device: Node,
    t_seat: Arc<ReticulumTransport>,
    rt_seat: Arc<ReplicationRuntime>,
    rt_device: Arc<ReplicationRuntime>,
    _tmp: tempfile::TempDir,
}

async fn bundle_mesh(tag: u8, k: usize, bundle: bool) -> BundleMesh {
    let tmp = tempfile::tempdir().expect("tempdir");
    let seat_key = Ident::new(&format!("seat-971d-{tag}"), 0xa0 ^ tag).await;
    let seat_owner = Ident::new(&format!("steward-971d-{tag}"), 0xa1 ^ tag).await;
    let dev_key = Ident::new(&format!("ciris-client-971d-{tag}"), 0xa2 ^ tag).await;
    let mut announced = Vec::new();
    let mut records = vec![dev_key.record("node").await];
    for i in 0..k {
        let seed = 0x10u8.wrapping_add(u8::try_from(i % 0x90).expect("< 0x90")) ^ tag;
        let a = Ident::new(&format!("announced-971d-{tag}-{i}"), seed).await;
        records.push(a.record("node").await);
        announced.push(a.key_id.clone());
    }
    let seat_record = seat_key.record("node").await;
    let seat = Node::new(seat_key, seat_owner, records).await;
    let device = Node::unclaimed(dev_key, vec![seat_record]).await;
    let base = tmp.path().to_path_buf();
    let (t_seat, addr) = build_reticulum_with_retry(|| async {
        let mut cfg =
            ReticulumTransportConfig::new(base.join("seat/transport.id"), &seat.key.key_id);
        cfg.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        cfg.announce_interval = Duration::from_secs(5);
        (cfg, seat.auth())
    })
    .await;
    t_seat.refuse_outbound_dials_for_test(true);
    t_seat.set_link_wire_tap_for_test(true);
    let port = addr.port();
    let mut publish = vec![seat.key.key_id.clone(), seat.owner.key_id.clone()];
    publish.extend(announced);
    let rt_seat = start_runtime_with(
        &seat,
        Arc::clone(&t_seat),
        Vec::new(),
        Duration::from_secs(3600),
        publish,
        false,
    )
    .await;
    // The seat side of the filter's witness: every subject the device Pulls.
    rt_seat.bridge().record_pull_subjects_for_test();
    wait_for_own_route(&seat, Duration::from_secs(150)).await;
    let (t_dev, _) = build_reticulum_with_retry(|| async {
        let mut cfg =
            ReticulumTransportConfig::new(base.join("device/transport.id"), &device.key.key_id);
        cfg.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        cfg.bootstrap_peers = vec![format!("127.0.0.1:{port}").parse().unwrap()];
        cfg.announce_interval = Duration::from_secs(5);
        (cfg, device.auth())
    })
    .await;
    wait_for_own_route(&device, Duration::from_secs(150)).await;
    seed_route(&seat, &device).await;
    let rt_device = start_runtime_with(
        &device,
        t_dev,
        Vec::new(),
        Duration::from_secs(3),
        vec![device.key.key_id.clone()],
        bundle,
    )
    .await;
    // The baked bundle names the seat; a test directory never ran persist's
    // seed, so the seam stands in for it (the bundle path itself is
    // witnessed in runtime.rs (a)-(e)).
    // The device side: every row the seat delivers it.
    rt_device.bridge().record_deliveries_for_test();
    rt_device
        .adopt_bundle_seat_for_test(&seat.key.key_id)
        .await
        .expect("adopt the bundle seat");
    BundleMesh {
        seat,
        device,
        t_seat,
        rt_seat,
        rt_device,
        _tmp: tmp,
    }
}

/// CIRISEdge#971 — the seat-side property: every subject the device has
/// Pulled from the seat is one `allowed` names (the device, the seat, the
/// device's owner, or a name the seat itself delivered). Fails naming the
/// leaked subject.
fn assert_seat_was_asked_only_about(m: &BundleMesh, allowed: &[&str], stage: &str) {
    let seen = m
        .rt_seat
        .bridge()
        .pull_subjects_from_for_test(&m.device.key.key_id);
    for (kind, subject) in &seen {
        assert!(
            allowed.contains(&subject.as_str()),
            "{stage}: the device named {subject} to the seat in a {kind:?} Pull; allowed \
             only {allowed:?}"
        );
    }
}

/// Every `*key_id` string anywhere in a JSON row (its signer and subjects).
fn key_ids_in(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if let (true, Some(s)) = (k.ends_with("key_id"), v.as_str()) {
                    out.push(s.to_owned());
                }
                key_ids_in(v, out);
            }
        }
        serde_json::Value::Array(a) => a.iter().for_each(|v| key_ids_in(v, out)),
        _ => {}
    }
}

/// CIRISEdge#971 — the device-side bound that keeps "names the seat routed"
/// small: every row a no-consent seat delivered the device names the device,
/// the seat or the owner as its signer or subject, or is a key-level
/// Revocation (the `Projection::Global` offer). A room row here would make the
/// routed-name allowance a member-naming Pull. Fails naming the row's kind
/// and the key ids it carries.
fn assert_device_got_only_required_rows(m: &BundleMesh, allowed: &[&str], stage: &str) {
    let rows = m
        .rt_device
        .bridge()
        .deliveries_from_for_test(&m.seat.key.key_id);
    for (kind, bytes) in &rows {
        if *kind == EnvelopeKind::Revocation {
            continue;
        }
        let mut ids = Vec::new();
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) {
            key_ids_in(&v, &mut ids);
        }
        assert!(
            ids.iter().any(|id| allowed.contains(&id.as_str())),
            "{stage}: the seat delivered a {kind:?} row naming {ids:?}; allowed only rows \
             about {allowed:?}"
        );
    }
}

fn seat_was_asked_about(m: &BundleMesh, subject: &str) -> bool {
    m.rt_seat
        .bridge()
        .pull_subjects_from_for_test(&m.device.key.key_id)
        .iter()
        .any(|(_, s)| s == subject)
}

fn seat_bytes(m: &BundleMesh) -> usize {
    tapped_bytes(&m.t_seat)
}

/// The device's first contact through the bundle Pulls: the seat holds the
/// device's key and route, and its round on the round plane rides the
/// device's link.
async fn rooted(m: &BundleMesh) {
    let key = m.device.key.key_id.clone();
    assert!(
        wait_until(Duration::from_secs(120), || {
            let key = key.clone();
            let seat = &m.seat;
            async move { seat.holds_route_of(&key).await }
        })
        .await,
        "the device's own route reaches the seat by its offering Pull, not a Summary"
    );
}

/// (d)-1 **No Summary, and idle bytes independent of K.** At two offer sizes
/// the seat never builds its per-peer offer for the device on the four Pull
/// planes, and an idle cycle (in sync) costs the seat the same bytes, under a
/// constant bound. Mutation: let `BundlePull` skip nothing (schedule the four
/// planes as rounds), and `offers_built_for` is non-zero and the idle bytes
/// grow with K.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bundle_seat_is_asked_by_pull_and_its_idle_cost_does_not_grow_with_k_971() {
    init_tracing();
    let mut idle = Vec::new();
    for (tag, k) in [(11u8, 4usize), (12u8, 120usize)] {
        let m = bundle_mesh(tag, k, true).await;
        let built0 = m.rt_seat.bridge().offers_built_on_bundle_planes();
        rooted(&m).await;
        // Settle, then one idle cycle in sync.
        tokio::time::sleep(Duration::from_secs(10)).await;
        let delivered = |m: &BundleMesh| {
            let (rt, seat) = (Arc::clone(&m.rt_device), m.seat.key.key_id.clone());
            async move {
                let mut n = 0;
                for kind in ciris_edge::replication::runtime::BUNDLE_PULL_PLANES {
                    if let Some(c) = rt.registry().get_initiator(&seat, kind).await {
                        n += c.offers_delivered();
                    }
                }
                n
            }
        };
        let up0 = delivered(&m).await;
        let before = seat_bytes(&m);
        m.rt_device.bundle_pull_now().await;
        tokio::time::sleep(Duration::from_secs(10)).await;
        let cost = seat_bytes(&m) - before;
        let up = delivered(&m).await - up0;
        // The seat's only peer is this device, so the delta is the device's.
        let built = m.rt_seat.bridge().offers_built_on_bundle_planes() - built0;
        eprintln!(
            "971 (d) K={k}: idle_cycle_sealed_bytes={cost} offers_built={built} delivers_up={up}"
        );
        assert_eq!(
            built, 0,
            "K={k}: the seat never builds its whole offer for the device"
        );
        assert_eq!(up, 0, "K={k}: an in-sync cycle sends no Deliver up");
        // The round plane's offer is the revocations of keys in the seat's
        // self set and cohort (`Projection::Global`), not the corpus: none here,
        // whatever K is.
        {
            use ciris_edge::replication::ReplicationDirectory as _;
            let revs = m
                .rt_seat
                .bridge()
                .list_envelope_refs_for_peer(
                    EnvelopeKind::Revocation,
                    Some(m.device.key.key_id.as_str()),
                )
                .await;
            assert!(
                revs.is_empty(),
                "K={k}: the Revocation offer holds only revocations that exist"
            );
        }
        idle.push(cost);
    }
    // One idle cycle: 4 planes x 2 subjects x (a Pull up, a small Summary
    // down), plus the round plane's small exchange: a constant, not K.
    for c in &idle {
        assert!(*c < 64 * 1024, "an idle cycle stays under 64 KiB: {idle:?}");
    }
    let spread = idle[0].abs_diff(idle[1]);
    assert!(
        spread < 8 * 1024,
        "idle cost does not grow with K (4 vs 120 announced keys): {idle:?}"
    );
}

/// (d)-2 **Completeness from a bare directory through claim.** Unclaimed, the
/// device reaches "the seat holds its key and route and can reach it on its
/// link" by Pulls alone; claimed, its owner's key arrives by the owner Pull.
/// Nothing rides a whole-plane Summary (the seat's offer counter stays 0).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_reaches_the_seat_and_its_owner_by_pull_alone_971() {
    use ciris_persist::federation::FederationDirectory as _;
    init_tracing();
    let m = bundle_mesh(13, 4, true).await;
    let built0 = m.rt_seat.bridge().offers_built_on_bundle_planes();
    // Stage 1, bare: the seat holds nothing of the device yet.
    assert!(
        !m.seat.holds_route_of(&m.device.key.key_id).await,
        "bare: no route of the device at the seat"
    );
    let (dev, seat_id) = (m.device.key.key_id.clone(), m.seat.key.key_id.clone());
    assert_seat_was_asked_only_about(&m, &[&dev, &seat_id], "bare");
    assert_device_got_only_required_rows(&m, &[&dev, &seat_id], "bare");
    // Stage 2, rooted.
    rooted(&m).await;
    assert_seat_was_asked_only_about(&m, &[&dev, &seat_id], "rooted");
    assert_device_got_only_required_rows(&m, &[&dev, &seat_id], "rooted");
    assert!(
        m.seat
            .dir
            .lookup_public_key(&m.device.key.key_id)
            .await
            .ok()
            .flatten()
            .is_some(),
        "the seat holds the device's key"
    );
    assert!(
        wait_until(Duration::from_secs(60), || {
            let t = Arc::clone(&m.t_seat);
            let k = m.device.key.key_id.clone();
            async move { !t.reverse_links_for_test(&k).await.is_empty() }
        })
        .await,
        "the seat can reach the device on the device's own link"
    );
    // Stage 3, claimed. The owner signs the binding on the device (as the claim writes
    // it locally), and the seat holds the owner's announced occurrence.
    let owner = Ident::new("person-971d-owner", 0xb3).await;
    m.device
        .dir
        .put_public_key(ciris_persist::prelude::SignedKeyRecord {
            record: owner.record("user").await,
        })
        .await
        .expect("the owner's key at claim");
    put(
        &m.device.dir,
        owner_binding_attestation(
            &owner.key_id,
            &m.device.key.key_id,
            chrono::Utc::now(),
            &owner.signer(),
        )
        .await
        .expect("owner binding"),
    )
    .await;
    m.seat
        .dir
        .put_public_key(ciris_persist::prelude::SignedKeyRecord {
            record: owner.record("user").await,
        })
        .await
        .expect("the owner's key at the seat");
    // A second node of the same owner: its occurrence is at the seat only
    // (its key is known to both, as an announced owned node's is). The owner
    // Pull on the occurrence plane is the path that delivers it. Its ROUTE is
    // not in (d): an owned node's route comes from its owner (CC CLM-route-
    // handed-by-owner, CIRISEdge#972).
    let sibling = Ident::new("ciris-client-971d-sibling", 0xb4).await;
    for dir in [&m.seat.dir, &m.device.dir] {
        dir.put_public_key(ciris_persist::prelude::SignedKeyRecord {
            record: sibling.record("node").await,
        })
        .await
        .expect("the sibling's key");
    }
    m.seat
        .dir
        .put_identity_occurrence(
            common::node_signed_occurrence(
                &owner.key_id,
                &sibling.key_id,
                &sibling.signer(),
                ciris_persist::federation::types::device_class::PHONE,
            )
            .await,
        )
        .await
        .expect("the sibling's occurrence at the seat");
    let owner_pulls = |n: &Node| {
        n.metrics
            .bundle_pull()
            .get("pull_owner")
            .copied()
            .unwrap_or(0)
    };
    let before = owner_pulls(&m.device);
    m.rt_device.bundle_pull_now().await;
    assert!(
        owner_pulls(&m.device) > before,
        "a claimed device's timer cycle asks about its owner"
    );
    assert!(
        wait_until(Duration::from_secs(60), || {
            let dir = Arc::clone(&m.device.dir);
            let (sib, own) = (sibling.key_id.clone(), owner.key_id.clone());
            async move {
                dir.list_identity_occurrences_for(&own)
                    .await
                    .is_ok_and(|v| v.iter().any(|o| o.occurrence_key_id == sib))
            }
        })
        .await,
        "the owner Pull delivers a second owned node's occurrence"
    );
    assert_seat_was_asked_only_about(&m, &[&dev, &seat_id, &owner.key_id], "claimed");
    assert_device_got_only_required_rows(&m, &[&dev, &seat_id, &owner.key_id], "claimed");
    assert_eq!(
        m.rt_seat.bridge().offers_built_on_bundle_planes() - built0,
        0,
        "nothing rode a whole-plane Summary"
    );
}

/// (d)-3 **The Pull coordinators survive a reconcile.** `set_peers` converges
/// scheduled initiators only; the bundle Pull coordinators are registered for
/// their replies and never scheduled. Mutation: schedule them through
/// `register_initiator_peer`, and the empty `set_peers` removes them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bundle_pull_coordinators_survive_a_reconcile_tick_971() {
    init_tracing();
    let m = bundle_mesh(14, 4, true).await;
    m.rt_device.bundle_pull_now().await;
    m.rt_device.set_peers(Vec::new()).await.expect("reconcile");
    for kind in ciris_edge::replication::runtime::BUNDLE_PULL_PLANES {
        assert!(
            m.rt_device
                .registry()
                .get_initiator(&m.seat.key.key_id, kind)
                .await
                .is_some(),
            "{kind:?}: the Pull coordinator is still routed after the reconcile"
        );
    }
    let sent = m.rt_device.bundle_pulls_sent();
    m.rt_device.bundle_pull_now().await;
    assert!(m.rt_device.bundle_pulls_sent() > sent, "and it still pulls");
}

/// (d)-4 **Isolation: a seat the host names is a consent peer, untouched.**
/// Once the host's peer set names the seat, no bundle Pull is sent to it and
/// its planes are the host's ordinary rounds. Mutation: drop the host filter
/// in `BundlePull::targets`, and Pulls go to a consent peer too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_seat_the_host_names_rounds_as_a_consent_peer_971() {
    init_tracing();
    let m = bundle_mesh(15, 4, true).await;
    m.rt_device
        .set_peers(peers_for(&[m.seat.key.key_id.as_str()]))
        .await
        .expect("the host names the seat");
    let sent = m.rt_device.bundle_pulls_sent();
    m.rt_device.bundle_pull_now().await;
    assert_eq!(
        m.rt_device.bundle_pulls_sent(),
        sent,
        "no bundle Pull to a consent peer"
    );
    // The frames toward a consent peer come from the scheduled initiators
    // alone: with bundle mode on they are exactly the set bundle mode off
    // schedules for the same host peers.
    let off = bundle_mesh(19, 4, false).await;
    off.rt_device
        .set_peers(peers_for(&[off.seat.key.key_id.as_str()]))
        .await
        .expect("the host names the seat");
    let rename = |v: Vec<(String, EnvelopeKind)>, from: &str| {
        v.into_iter()
            .map(|(p, k)| (if p == from { "SEAT".to_owned() } else { p }, k))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        rename(
            m.rt_device.initiator_set_for_test().await,
            &m.seat.key.key_id
        ),
        rename(
            off.rt_device.initiator_set_for_test().await,
            &off.seat.key.key_id
        ),
        "bundle mode adds nothing to a consent peer's rounds"
    );
}

/// (d)-5 **The opt-out covers (d): the device sends the seat nothing.**
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_the_bundle_path_off_the_device_sends_the_seat_nothing_971() {
    init_tracing();
    let m = bundle_mesh(16, 4, false).await;
    tokio::time::sleep(Duration::from_secs(15)).await;
    m.rt_device.bundle_pull_now().await;
    assert_eq!(m.rt_device.bundle_pulls_sent(), 0, "no Pull");
    assert!(
        m.t_seat
            .reverse_links_for_test(&m.device.key.key_id)
            .await
            .is_empty(),
        "no link from the device"
    );
    assert_eq!(
        seat_bytes(&m),
        0,
        "nothing on the seat's links from the device"
    );
}

/// (d)-6 **A write asks only about itself, on its plane; only the timer asks
/// about the owner.** N local writes on one Pull plane send N self-subject
/// Pulls on that plane and nothing else; host kicks send this node's and the
/// seat's legs and never the owner's. Mutation: let a write run the whole
/// cycle, or let any kick pull the owner, and a count below moves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writes_and_kicks_never_spend_the_seats_lookup_budget_971() {
    init_tracing();
    let m = bundle_mesh(17, 4, true).await;
    rooted(&m).await;
    // Attributed (the loop's own cycle saw it, and so settled: its next timer
    // is at least I/2 out), so no background cycle runs in the counts below.
    assert!(
        wait_until(Duration::from_secs(120), || {
            let rt = Arc::clone(&m.rt_device);
            let seat = m.seat.key.key_id.clone();
            async move {
                rt.registry()
                    .get_initiator(&seat, EnvelopeKind::Revocation)
                    .await
                    .is_some()
            }
        })
        .await,
        "attributed"
    );
    let owner = Ident::new("person-971d-kick-owner", 0xb5).await;
    m.device
        .dir
        .put_public_key(ciris_persist::prelude::SignedKeyRecord {
            record: owner.record("user").await,
        })
        .await
        .expect("the owner's key");
    put(
        &m.device.dir,
        owner_binding_attestation(
            &owner.key_id,
            &m.device.key.key_id,
            chrono::Utc::now(),
            &owner.signer(),
        )
        .await
        .expect("owner binding"),
    )
    .await;
    let read = |label: &str| {
        m.device
            .metrics
            .bundle_pull()
            .get(label)
            .copied()
            .unwrap_or(0)
    };
    let planes = ciris_edge::replication::runtime::BUNDLE_PULL_PLANES;
    let on = |rt: &ReplicationRuntime| planes.map(|k| rt.bundle_pulls_sent_on(k));
    // N writes on the route plane, each after the last one's answer.
    const N: u64 = 4;
    let (owner0, self0, seat0, by0) = (
        read("pull_owner"),
        read("pull_self"),
        read("pull_seat"),
        on(&m.rt_device),
    );
    for _ in 0..N {
        m.rt_device
            .bundle_pull_wrote_now_for_test(EnvelopeKind::TransportDestination)
            .await;
        tokio::time::sleep(Duration::from_secs(4)).await;
    }
    let by = on(&m.rt_device);
    for (i, k) in planes.iter().enumerate() {
        let want = if *k == EnvelopeKind::TransportDestination {
            N
        } else {
            0
        };
        assert_eq!(by[i] - by0[i], want, "{k:?}: Pulls after {N} route writes");
    }
    assert_eq!(read("pull_self") - self0, N, "self-subject only");
    assert_eq!(read("pull_seat"), seat0, "no seat leg on a write");
    assert_eq!(read("pull_owner"), owner0, "no owner leg on a write");
    // Host kicks: self and seat, never the owner.
    for _ in 0..3 {
        m.rt_device.bundle_pull_host_kick_now_for_test().await;
        tokio::time::sleep(Duration::from_secs(4)).await;
    }
    assert!(read("pull_seat") > seat0, "a host kick asks about the seat");
    assert_eq!(read("pull_owner"), owner0, "no kick asked about the owner");
    // The real kick path coalesces: a burst of `round_now` is one cycle.
    let kick0 = read("cycle_kick");
    for _ in 0..5 {
        let _ = m.rt_device.round_now(&m.seat.key.key_id).await;
    }
    tokio::time::sleep(Duration::from_secs(35)).await;
    assert_eq!(read("cycle_kick") - kick0, 1, "five kicks, one cycle");
    assert_eq!(read("pull_owner"), owner0, "and still no owner leg");
    // The timer's cycle is the one that asks about the owner: once per
    // owner plane.
    m.rt_device.bundle_pull_now().await;
    assert_eq!(
        read("pull_owner") - owner0,
        3,
        "Key, occurrence, occurrence-revocation"
    );
}

/// (d)-7 **Bare stage: nothing a seat would drop is sent.** Until the seat
/// holds this node's key and route, an unattributed frame on a
/// non-bootstrap kind drops there (`routing_source`, replication/mod.rs), so
/// neither an IOR Pull nor the Revocation round is started; once the
/// offering Key and TD Pulls show both held, both start, and a reconcile keeps
/// them. Mutation: drop the `attributed` gate on the IOR leg, or register the
/// Revocation initiator at adopt, and a bare-stage assertion fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_seats_round_starts_once_it_holds_our_key_and_route_971() {
    init_tracing();
    let m = bundle_mesh(18, 4, true).await;
    // Bare: one cycle before anything reached the seat.
    m.rt_device.bundle_pull_now().await;
    assert_eq!(
        m.rt_device
            .bundle_pulls_sent_on(EnvelopeKind::IdentityOccurrenceRevocation),
        0,
        "bare: no occurrence-revocation Pull"
    );
    assert!(
        m.rt_device
            .registry()
            .get_initiator(&m.seat.key.key_id, EnvelopeKind::Revocation)
            .await
            .is_none(),
        "bare: no revocation round"
    );
    rooted(&m).await;
    assert!(
        wait_until(Duration::from_secs(120), || {
            let rt = Arc::clone(&m.rt_device);
            let seat = m.seat.key.key_id.clone();
            async move {
                rt.registry()
                    .get_initiator(&seat, EnvelopeKind::Revocation)
                    .await
                    .is_some()
            }
        })
        .await,
        "the revocation round starts by first-contact cycles, 30 s apart"
    );
    m.rt_device.bundle_pull_now().await;
    assert!(
        m.rt_device
            .bundle_pulls_sent_on(EnvelopeKind::IdentityOccurrenceRevocation)
            > 0,
        "attributed: the occurrence-revocation leg runs"
    );
    m.rt_device.set_peers(Vec::new()).await.expect("reconcile");
    assert!(
        m.rt_device
            .registry()
            .get_initiator(&m.seat.key.key_id, EnvelopeKind::Revocation)
            .await
            .is_some(),
        "a reconcile keeps an attributed seat's round"
    );
}

/// (d)-8 **The seat is never asked about a member, read at the seat.** A key
/// a person is waiting on (#904) and an unrouted repair name sit queued on
/// the device while its revocation round toward the attributed seat runs
/// every 3 s. The seat records the subject of every Pull it answers; it never
/// sees either name. Transition 1: the host names the seat (a consent peer
/// now) and the seat's rounds take both. Transition 2: the host drops it
/// while it stays a bundle seat; two new names stay unasked. Mutation: make
/// `names_only_required_subjects` return true, and stage A fails naming the
/// leaked subject.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_seat_is_never_asked_about_a_member_971() {
    use ciris_edge::replication::ReplicationDirectory as _;
    init_tracing();
    let m = bundle_mesh(20, 4, true).await;
    rooted(&m).await;
    assert!(
        wait_until(Duration::from_secs(120), || {
            let rt = Arc::clone(&m.rt_device);
            let seat = m.seat.key.key_id.clone();
            async move {
                rt.registry()
                    .get_initiator(&seat, EnvelopeKind::Revocation)
                    .await
                    .is_some()
            }
        })
        .await,
        "attributed: the seat's revocation round runs"
    );
    let (dev, seat_id) = (m.device.key.key_id.clone(), m.seat.key.key_id.clone());
    let bridge = m.rt_device.bridge();
    let (asked, unrouted) = (
        "ciris-client-971d-member-asked",
        "ciris-client-971d-member-unrouted",
    );
    bridge.request_signer(EnvelopeKind::Key, asked);
    bridge.note_missing_signer(EnvelopeKind::Attestation, unrouted, None);
    // Stage A: no consent, ten rounds.
    let outcomes0 = m.device.all_outcomes();
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert_ne!(m.device.all_outcomes(), outcomes0, "rounds ran meanwhile");
    assert_seat_was_asked_only_about(&m, &[&dev, &seat_id], "no consent");
    assert_device_got_only_required_rows(&m, &[&dev, &seat_id], "no consent");
    // Transition 1: the host names the seat; its rounds may take both.
    m.rt_device
        .set_peers(peers_for(&[seat_id.as_str()]))
        .await
        .expect("the host names the seat");
    assert!(
        wait_until(Duration::from_secs(60), || async {
            seat_was_asked_about(&m, asked) && seat_was_asked_about(&m, unrouted)
        })
        .await,
        "a consent peer's rounds take both names"
    );
    // Transition 2: the host drops it; it is still a bundle seat.
    m.rt_device.set_peers(Vec::new()).await.expect("drop it");
    let (asked2, unrouted2) = (
        "ciris-client-971d-member-asked-2",
        "ciris-client-971d-member-unrouted-2",
    );
    bridge.request_signer(EnvelopeKind::Key, asked2);
    bridge.note_missing_signer(EnvelopeKind::Attestation, unrouted2, None);
    tokio::time::sleep(Duration::from_secs(30)).await;
    for name in [asked2, unrouted2] {
        assert!(
            !seat_was_asked_about(&m, name),
            "dropped as a consent peer, the seat is not asked about {name}"
        );
        assert!(bridge.signer_queued(name), "{name} stays queued");
    }
}
