//! CC 5.3.4 (`CLM-bundle-seeds-transit-pairs`, CIRISPersist#1106) — the
//! offline-emitted signed route of a seated serve node, carried in a v4
//! genesis bundle, seeds that node's transit pair ROOTED at a fresh node's
//! open (no network), and only a holder-quorum re-bind rotates it.
//!
//! The rows are edge's own: the node's custody and signer go through
//! `reticulum::emit_route_from_custody` (the producer behind
//! `edge_node emit-transport-destination` and PyO3
//! `emit_transport_destination`), and that row is what the ceremony pins.
//! The bundle is persist's software test ceremony (three software holders,
//! quorum 2 of 3) with the serve-transport rows replaced by edge's; the open
//! is persist's own boot seed (`seed_family_and_canonical`), through the
//! ordinary transport door. Its own process: the test-anchor override is
//! armed through the environment.
//!
//! **Two hops from a bundle** (`a_fresh_device_reaches_its_owners_node_through_a_bundle_seeded_canonical_e1`):
//! a fresh device that holds only the v4 bundle seals to the seated canonical
//! the bundle names, replicates from it the owner node's signed
//! `transport_destination` (and the key that roots it), resolves the owner
//! node's transit pair ROOTED, and seals its first contact to that node
//! across the canonical. From the bundle alone the owner node is not
//! resolvable. Lives here, not in `link_seal_e1`, because the test anchor is
//! process-wide.
//!
//! `cargo test --features "transport-reticulum test-anchor" --test sealed_cut_bundle_e1`

#![cfg(all(feature = "transport-reticulum", feature = "test-anchor"))]

mod common;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::replication::bridge::KindPublishSelector;
use ciris_edge::replication::{
    self_publish_set, EnvelopeKind, InboundRouter, ReplicationPeer, ReplicationRuntime,
    ReplicationRuntimeConfig, SchedulerConfig,
};
use ciris_edge::transport::reticulum::{
    emit_route_from_custody, ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::transit_kex_custody::TransitKexSecret;
use ciris_edge::transport::{InboundFrame, Transport};
use ciris_edge::verify::RootingDirectory;
use ciris_edge::EdgeMetrics;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::genesis::{
    ceremony::CeremonyState, clear_test_ceremony_outputs, effective_accord_holder_records,
    install_test_ceremony_outputs, seed_family_and_canonical, sign_every_item,
    test_anchor_mldsa_seed, test_ceremony_inputs, test_rebind_row, GenesisBundle, TestAnchorBlock,
    TEST_ANCHOR_ENV_VARS, TEST_CEREMONY_NODE_KEY_ID,
};
use ciris_persist::federation::self_at_login::{
    transit_kex_pair_for, SignedTransportDestination, TransitKexPair,
};
use ciris_persist::federation::transport_rebind::SERVE_TRANSIT_PAIR_ROTATION_BEFORE_REBIND;
use ciris_persist::federation::{Error, FederationDirectory, SignedAttestation};
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::Digest as _;

const SEEDS: [[u8; 32]; 3] = [[0x31; 32], [0x32; 32], [0x33; 32]];
const NODE_SEED: [u8; 32] = [0x4E; 32];

/// One test at a time: the anchor override and the installed ceremony are
/// process-wide.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The test-anchor override, armed for the test's life.
struct Armed;

impl Armed {
    fn with(block: &TestAnchorBlock) -> Self {
        for (k, v) in block.env_pairs() {
            std::env::set_var(k, v);
        }
        for k in ["ENVIRONMENT", "CIRIS_ENV", "CIRIS_ENVIRONMENT"] {
            std::env::remove_var(k);
        }
        Self
    }
}

impl Drop for Armed {
    fn drop(&mut self) {
        clear_test_ceremony_outputs();
        for k in TEST_ANCHOR_ENV_VARS {
            std::env::remove_var(k);
        }
    }
}

fn at(offset_secs: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() + chrono::Duration::seconds(offset_secs)
}

/// The seated serve node's own hybrid signer: the test ceremony's node key
/// (`test-canonical-node-0`, from `NODE_SEED`), as edge holds it.
fn serve_node_signer() -> LocalSigner {
    let classical: Arc<dyn HardwareSigner> = Arc::new(
        Ed25519SoftwareSigner::from_bytes(&NODE_SEED, TEST_CEREMONY_NODE_KEY_ID).expect("ed25519"),
    );
    let pqc: Arc<dyn PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(
            &test_anchor_mldsa_seed(&NODE_SEED),
            format!("{TEST_CEREMONY_NODE_KEY_ID}-pqc"),
        )
        .expect("ml-dsa-65"),
    );
    LocalSigner::new(TEST_CEREMONY_NODE_KEY_ID, classical, Some(pqc))
}

/// A file-backed custody under `dir`: a transport identity (a copy of
/// `identity` when given, so a rotation keeps the node's link keys) and a
/// fresh transit seed beside it. Returns the identity path and the pair.
fn custody(dir: &Path, identity: Option<&Path>) -> (std::path::PathBuf, TransitKexPair) {
    std::fs::create_dir_all(dir).expect("custody dir");
    let path = dir.join("transport.id");
    match identity {
        Some(src) => {
            std::fs::copy(src, &path).expect("copy identity");
        }
        None => std::fs::write(
            &path,
            leviculum_std::generate_identity()
                .private_key_bytes()
                .expect("identity bytes"),
        )
        .expect("identity"),
    }
    let pair = TransitKexSecret::load_or_generate_file(&path)
        .expect("transit seed")
        .pair()
        .clone();
    (path, pair)
}

/// The test ceremony's v4 bundle, pinning `row` as the serve node's
/// transport destination; and its holders.
fn v4_bundle_pinning(
    row: &SignedTransportDestination,
) -> (
    TestAnchorBlock,
    Vec<ciris_persist::federation::accord_test_support::Identity>,
    GenesisBundle,
) {
    let (block, holders, mut inputs) =
        test_ceremony_inputs(&SEEDS, &NODE_SEED, at(-60), None).expect("ceremony inputs");
    inputs.serve_transport_destinations = vec![row.clone()];
    let mut state = CeremonyState::plan(inputs).expect("plan");
    sign_every_item(&mut state, &holders).expect("sign");
    let bundle = state.assemble().expect("assemble");
    assert_eq!(bundle.version, 4, "a v4 bundle");
    (block, holders, bundle)
}

/// A fresh node, opened from `bundle`: persist's own boot seed.
async fn open_from(bundle: &GenesisBundle) -> SqliteBackend {
    install_test_ceremony_outputs(bundle.clone());
    let d = SqliteBackend::open_in_memory().await.expect("open");
    d.run_migrations().await.expect("migrations");
    d.seed_genesis_accord_holders(&effective_accord_holder_records())
        .await
        .expect("seed holders");
    seed_family_and_canonical(&d).await.expect("the boot seed");
    d
}

/// **CC 5.3.4** — the offline-emitted row of a seated serve node, pinned in a
/// v4 bundle, makes a fresh node that holds nothing else resolve that node's
/// transit pair ROOTED at open: the custody's own pair. (Was seeded through
/// the put path before persist v59 carried bundle rows.)
#[tokio::test]
async fn an_offline_emitted_row_resolves_a_rooted_transit_pair_when_seeded_e1() {
    let _serial = SERIAL.lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let signer = serve_node_signer();
    let (identity, pair) = custody(&tmp.path().join("node"), None);
    let row = emit_route_from_custody(&signer, &identity, 1, at(-30))
        .await
        .expect("offline row");
    let (block, _holders, bundle) = v4_bundle_pinning(&row);
    let _armed = Armed::with(&block);
    let d = open_from(&bundle).await;
    let resolved = transit_kex_pair_for(&d, TEST_CEREMONY_NODE_KEY_ID)
        .await
        .expect("directory")
        .expect("a Rooted pair for the seated serve node, offline");
    assert_eq!(resolved, pair, "the custody's own pair");
}

/// **CC 5.3.4** (CIRISPersist#1106 I1158) — a bundle-seeded pair rotates only
/// by holder-quorum re-bind: the node's own re-emitted row with a new pair is
/// refused `serve_transit_pair_rotation_before_rebind` and the pinned pair
/// stands; a 2-of-3 holder re-bind carrying that row supersedes it, and the
/// new pair resolves.
#[tokio::test]
async fn a_quorum_rebind_supersedes_a_bundle_seeded_pair_e1() {
    let _serial = SERIAL.lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let signer = serve_node_signer();
    let (identity, pair_1) = custody(&tmp.path().join("node"), None);
    let row_1 = emit_route_from_custody(&signer, &identity, 1, at(-30))
        .await
        .expect("offline row");
    let (block, holders, bundle) = v4_bundle_pinning(&row_1);
    let _armed = Armed::with(&block);
    let d = open_from(&bundle).await;
    assert_eq!(
        transit_kex_pair_for(&d, TEST_CEREMONY_NODE_KEY_ID)
            .await
            .expect("directory"),
        Some(pair_1.clone())
    );

    // The node re-emits with a NEW transit pair (same link keys), epoch 2.
    let (identity_2, pair_2) = custody(&tmp.path().join("rotated"), Some(&identity));
    assert_ne!(pair_1, pair_2);
    let row_2 = emit_route_from_custody(&signer, &identity_2, 2, at(-1))
        .await
        .expect("rotated row");
    match FederationDirectory::put_signed_transport_destination(&d, &row_2).await {
        Err(Error::InvalidArgument(m))
            if m.starts_with(SERVE_TRANSIT_PAIR_ROTATION_BEFORE_REBIND) => {}
        other => panic!("the node alone must not rotate a seated pair: {other:?}"),
    }
    assert_eq!(
        transit_kex_pair_for(&d, TEST_CEREMONY_NODE_KEY_ID)
            .await
            .expect("directory"),
        Some(pair_1),
        "the pinned pair stands"
    );

    // The holders' 2-of-3 re-bind carrying the rotated row.
    let rebind = test_rebind_row(&[&holders[0], &holders[2]], &row_2, at(0)).expect("re-bind");
    d.put_attestation(SignedAttestation {
        attestation: rebind,
    })
    .await
    .expect("a 2-of-3 re-bind");
    assert_eq!(
        transit_kex_pair_for(&d, TEST_CEREMONY_NODE_KEY_ID)
            .await
            .expect("directory"),
        Some(pair_2),
        "the quorum re-bind supersedes, and the new pair resolves"
    );
}

// ─── two hops from a bundle ──────────────────────────────────────────

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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("addr")
        .port()
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

fn auth(signer: Arc<LocalSigner>, dir: &Arc<SqliteBackend>) -> ReticulumAuth {
    ReticulumAuth {
        signer: Some(signer),
        rooting: Some(Arc::clone(dir) as Arc<dyn RootingDirectory>),
        resolver: None,
        hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
        ..ReticulumAuth::default()
    }
}

/// A running node of the two-hop witness: its transport (listening, every
/// delivered frame kept) and its directory.
struct Hop {
    key_id: String,
    transport: Arc<ReticulumTransport>,
    metrics: EdgeMetrics,
    dir: Arc<SqliteBackend>,
    seen: Arc<tokio::sync::Mutex<Vec<InboundFrame>>>,
}

impl Hop {
    async fn received(&self, bytes: &[u8]) -> bool {
        self.seen
            .lock()
            .await
            .iter()
            .any(|f| f.envelope_bytes == bytes)
    }
    fn seal(&self, label: &str) -> u64 {
        self.metrics.link_seal().get(label).copied().unwrap_or(0)
    }
    async fn own_routes(&self) -> Vec<SignedTransportDestination> {
        self.dir
            .list_signed_transport_destinations_for(&self.key_id)
            .await
            .unwrap_or_default()
    }
}

/// Start `key_id`'s transport over `identity` (a custody path), listening on a
/// fresh port; `bootstrap` names the canonical to dial; `transport_node`
/// relays for others (the canonical). With `runtime`, the frames feed a
/// replication runtime's router; otherwise they are only kept.
#[allow(clippy::too_many_arguments)]
async fn hop(
    key_id: &str,
    signer: Arc<LocalSigner>,
    dir: Arc<SqliteBackend>,
    identity: std::path::PathBuf,
    bootstrap: Option<u16>,
    transport_node: bool,
) -> (Hop, u16, tokio::sync::mpsc::Receiver<InboundFrame>) {
    let metrics = EdgeMetrics::new();
    let (transport, addr) = common::build_reticulum_with_retry_metrics(
        || {
            let signer = Arc::clone(&signer);
            let dir = Arc::clone(&dir);
            let identity = identity.clone();
            async move {
                let mut c = ReticulumTransportConfig::new(identity, &signer.key_id)
                    .with_transport_node(transport_node);
                c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
                if let Some(p) = bootstrap {
                    c.bootstrap_peers = vec![format!("127.0.0.1:{p}").parse().unwrap()];
                }
                c.announce_interval = Duration::from_secs(3);
                (c, auth(signer, &dir))
            }
        },
        metrics.clone(),
    )
    .await;
    let (tx, rx) = tokio::sync::mpsc::channel::<InboundFrame>(1024);
    let listener = Arc::clone(&transport);
    tokio::spawn(async move {
        let _ = listener.listen(tx).await;
    });
    (
        Hop {
            key_id: key_id.to_owned(),
            transport,
            metrics,
            dir,
            seen: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        },
        addr.port(),
        rx,
    )
}

/// Feed `rx` to `router` (when given) and keep every frame on `hop`.
fn pump(
    hop: &Hop,
    mut rx: tokio::sync::mpsc::Receiver<InboundFrame>,
    router: Option<InboundRouter>,
) {
    let seen = Arc::clone(&hop.seen);
    tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if let Some(r) = &router {
                let _ = r.try_route(&frame).await;
            }
            seen.lock().await.push(frame);
        }
    });
}

/// A replication runtime over `hop`, peered with `peer` on the discovery
/// planes, with `selector` as its per-kind publish set.
async fn runtime(
    hop: &Hop,
    peer: &str,
    selector: Option<KindPublishSelector>,
) -> Arc<ReplicationRuntime> {
    let peers = [
        EnvelopeKind::Key,
        EnvelopeKind::TransportDestination,
        EnvelopeKind::Attestation,
    ]
    .into_iter()
    .map(|kind| ReplicationPeer {
        peer_key_id: peer.to_owned(),
        kind,
    })
    .collect();
    Arc::new(
        ReplicationRuntime::start(
            Arc::clone(&hop.dir) as Arc<dyn FederationDirectory>,
            Arc::clone(&hop.transport) as Arc<dyn Transport>,
            peers,
            ReplicationRuntimeConfig {
                scheduler: SchedulerConfig {
                    cadence: Duration::from_secs(3),
                    round_timeout: Duration::from_secs(15),
                    ..SchedulerConfig::default()
                },
                local_key_id: Some(hop.key_id.clone()),
                metrics: Some(hop.metrics.clone()),
                kind_publish_selector: selector,
                ..Default::default()
            },
            Some(self_publish_set([hop.key_id.as_str()])),
        )
        .await,
    )
}

/// A key-carrying first-contact `OpaqueRequest` (the device-join kind), as
/// `link_seal_e1` sends it.
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
            "key_record_row": ciris_persist::federation::key_plane::plan_key_record_row(record, &None)
                .expect("key:record:v1 row"),
            "challenge": "00".repeat(32),
        },
        "signature": "unchecked-at-the-transport",
    }))
    .expect("json")
}

/// The two-hop witness's knobs: `seed_canonical_row` puts the canonical's
/// route in the v4 bundle (the fail-before drops it).
#[allow(clippy::too_many_lines)] // one witness, hop by hop
async fn two_hops(seed_canonical_row: bool) {
    let _serial = SERIAL.lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");

    // The canonical `K`: the ceremony's seated serve node, its custody's row
    // pinned in the bundle.
    let k_signer = Arc::new(serve_node_signer());
    let (k_identity, k_pair) = custody(&tmp.path().join("k"), None);
    let k_row = emit_route_from_custody(&k_signer, &k_identity, 1, at(-30))
        .await
        .expect("K's offline row");
    let (block, _holders, bundle) = if seed_canonical_row {
        v4_bundle_pinning(&k_row)
    } else {
        let (block, holders, mut inputs) =
            test_ceremony_inputs(&SEEDS, &NODE_SEED, at(-60), None).expect("ceremony inputs");
        inputs.serve_transport_destinations = Vec::new();
        let mut state = CeremonyState::plan(inputs).expect("plan");
        sign_every_item(&mut state, &holders).expect("sign");
        (block, holders, state.assemble().expect("assemble"))
    };
    let _armed = Armed::with(&block);

    // The owner's node `O` and the fresh device `C`: hybrid self-signed keys.
    let o = Ident::new("owner-node-e1-2hop", 0x2c).await;
    let c = Ident::new("fresh-device-e1-2hop", 0x2d).await;
    let (o_record, c_record) = (o.record().await, c.record().await);

    // Every node opens from the bundle (persist's boot seed) and holds its
    // own key. The canonical also holds the two nodes' keys (the ladder's
    // convention: a node's own key registration is proven elsewhere).
    let k_dir = Arc::new(open_from(&bundle).await);
    let o_dir = Arc::new(open_from(&bundle).await);
    let c_dir = Arc::new(open_from(&bundle).await);
    for (dir, rec) in [
        (&k_dir, &o_record),
        (&k_dir, &c_record),
        (&o_dir, &o_record),
        (&c_dir, &c_record),
    ] {
        dir.put_public_key(ciris_persist::federation::SignedKeyRecord {
            record: rec.clone(),
        })
        .await
        .expect("register a node key");
    }

    // FROM THE BUNDLE ALONE: the canonical's pair resolves at the fresh
    // device; the owner node's does not.
    let k_at_c = transit_kex_pair_for(&*c_dir, TEST_CEREMONY_NODE_KEY_ID)
        .await
        .expect("directory");
    assert!(
        transit_kex_pair_for(&*c_dir, &o.key_id)
            .await
            .expect("directory")
            .is_none(),
        "the owner node is NOT resolvable from the bundle alone"
    );
    if seed_canonical_row {
        assert_eq!(
            k_at_c.as_ref(),
            Some(&k_pair),
            "the bundle seeds K's pair Rooted"
        );
    }

    let (k, k_port, k_rx) = hop(
        TEST_CEREMONY_NODE_KEY_ID,
        Arc::clone(&k_signer),
        Arc::clone(&k_dir),
        k_identity,
        None,
        true,
    )
    .await;
    let (o_hop, _, o_rx) = hop(
        &o.key_id,
        o.signer(),
        Arc::clone(&o_dir),
        tmp.path().join("o/transport.id"),
        Some(k_port),
        false,
    )
    .await;
    let (c_hop, _, c_rx) = hop(
        &c.key_id,
        c.signer(),
        Arc::clone(&c_dir),
        tmp.path().join("c/transport.id"),
        Some(k_port),
        false,
    )
    .await;
    pump(&o_hop, o_rx, None);

    // `O` published its route to the canonical (the row its transport emits,
    // through the canonical's ordinary door): the canonical holds it.
    assert!(
        wait_until(Duration::from_secs(60), || async {
            !o_hop.own_routes().await.is_empty() && !c_hop.own_routes().await.is_empty()
        })
        .await,
        "O and C emit their own routes"
    );
    for (from, to) in [(&o_hop, &k), (&c_hop, &k)] {
        for r in from.own_routes().await {
            FederationDirectory::put_signed_transport_destination(&*to.dir, &r)
                .await
                .expect("the canonical holds the node's route");
        }
    }

    // The canonical publishes the owner node on the key and route planes
    // (CIRISEdge#678's per-kind publish set, the seated roster).
    let selector = KindPublishSelector::from_sets(HashMap::from([
        (
            EnvelopeKind::Key,
            vec![TEST_CEREMONY_NODE_KEY_ID.to_owned(), o.key_id.clone()],
        ),
        (
            EnvelopeKind::TransportDestination,
            vec![TEST_CEREMONY_NODE_KEY_ID.to_owned(), o.key_id.clone()],
        ),
    ]));
    let rt_k = runtime(&k, &c.key_id, Some(selector)).await;
    pump(&k, k_rx, Some(InboundRouter::new(rt_k.registry())));
    let rt_c = runtime(&c_hop, TEST_CEREMONY_NODE_KEY_ID, None).await;
    pump(&c_hop, c_rx, Some(InboundRouter::new(rt_c.registry())));

    // HOP ONE: the fresh device seals to the canonical and replicates the
    // owner node's route (and the key that roots it) from it.
    let resolved = {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
        loop {
            let _ = rt_c.round_now_all().await;
            tokio::time::sleep(Duration::from_millis(1500)).await;
            if let Some(p) = transit_kex_pair_for(&*c_dir, &o.key_id)
                .await
                .expect("directory")
            {
                break Some(p);
            }
            if tokio::time::Instant::now() > deadline {
                break None;
            }
        }
    };
    assert!(
        c_hop.seal("link_seal_initiated") >= 1,
        "C sealed to the canonical: {:?}",
        c_hop.metrics.link_seal()
    );
    let held_routes = c_dir
        .list_signed_transport_destinations_for(&o.key_id)
        .await
        .map_or(0, |v| v.len());
    let held_key = FederationDirectory::lookup_public_key(&*c_dir, &o.key_id)
        .await
        .ok()
        .flatten()
        .is_some();
    let o_pair = resolved.unwrap_or_else(|| {
        panic!(
            "C resolves the owner node's pair Rooted from the canonical's rows: C holds \
             {held_routes} route(s) for O, O's key held = {held_key}; C seal {:?}; K seal {:?}",
            c_hop.metrics.link_seal(),
            k.metrics.link_seal()
        )
    });
    assert!(
        held_key && held_routes >= 1,
        "O's key and route crossed from the canonical (neither was seeded at C)"
    );
    assert_eq!(
        Some(&o_pair),
        o_hop.own_routes().await[0]
            .transit_kex_pair()
            .expect("O's row parses")
            .as_ref(),
        "the pair C resolved is the one O published"
    );

    // HOP TWO: C seals its first contact to O, across the canonical.
    assert!(
        wait_until(Duration::from_secs(60), || async {
            c_hop.transport.knows_peer(&o.key_id).await
        })
        .await,
        "C hears O's announce through the canonical"
    );
    let request = first_contact_request(&c.key_id, &o.key_id, &c_record);
    c_hop
        .transport
        .send(&o.key_id, &request)
        .await
        .expect("C -> O, a sealed first contact across the canonical");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            o_hop.received(&request).await
        })
        .await,
        "O delivered the fresh device's first contact: {:?}",
        o_hop.metrics.link_seal()
    );
    assert!(o_hop.seal("link_seal_accepted") >= 1, "O answered C's seal");
}

/// **CC 5.3.4 / CC 5.3.3.5 E1, two hops** — a fresh device holding only a v4
/// bundle (which seeds the canonical's transit pair) seals to the canonical,
/// replicates the owner node's signed route from it, resolves the owner
/// node's pair as Rooted, and seals its first contact to the owner node. From
/// the bundle alone the owner node is not resolvable.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_fresh_device_reaches_its_owners_node_through_a_bundle_seeded_canonical_e1() {
    two_hops(true).await;
}
