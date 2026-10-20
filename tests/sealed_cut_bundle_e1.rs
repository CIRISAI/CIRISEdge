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
//! `cargo test --features "transport-reticulum test-anchor" --test sealed_cut_bundle_e1`

#![cfg(all(feature = "transport-reticulum", feature = "test-anchor"))]

use std::path::Path;
use std::sync::Arc;

use ciris_edge::identity::LocalSigner;
use ciris_edge::transport::reticulum::emit_route_from_custody;
use ciris_edge::transport::transit_kex_custody::TransitKexSecret;
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
    match d.put_signed_transport_destination(&row_2).await {
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
