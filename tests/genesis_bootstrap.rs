//! CIRISEdge#281 — baked canonical-genesis bootstrap adoption.
//!
//! Field-provenance coverage for the four #281 invariants, driven against a
//! REAL persist sqlite backend seeded through persist's genuine genesis seed
//! chain (`seed_genesis_accord_holders` → `seed_family_and_canonical` — the
//! exact sequence `Engine` boot runs, 2-of-3 accord admission gate included):
//!
//! 1. **Zero-config recognition** — a fresh Edge with NO operator
//!    `canonical_bootstrap_peers` recognizes every baked genesis serve-node
//!    (`canonical_genesis_bundle().serve_nodes`, the CIRISPersist#551
//!    successor of the v13.1.0 `canonical_genesis_records()` the issue named).
//! 2. **Operator config AUGMENTS, never replaces** — the pre-#281 operator
//!    flow (declare + reseed) keeps working unchanged alongside the baked
//!    base.
//! 3. **#377 retirement honored** — a quorum-tombstoned canonical drops out
//!    of the recognition set on `refresh_canonical_retirements`, via
//!    persist's tombstone-aware `is_canonical_effective` read (never the bare
//!    role-membership form). Operator config does not outvote the quorum.
//! 4. **Bare-build fail-safe** — `baked_canonical_genesis_enabled = false`
//!    plus no operator config degrades to the pre-#281 empty set; an
//!    UNSEEDED directory (rows absent, no tombstones) never destroys
//!    provenance-based recognition.
//!
//! The only synthetic write is `record_canonical_withdrawal` itself: the
//! production quorum (2-of-3 YubiKey accord participations) is unreachable in
//! a test, and the V095 tombstone row this writes is byte-shape-identical to
//! what the verified `withdraw_canonical_role` orchestration records.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use ciris_edge::identity::LocalSigner;
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_edge::{
    baked_canonical_genesis_ids, reseed_canonical_bootstrap_peers, CanonicalBootstrapPeer, Edge,
    EdgeConfig, HybridPolicy,
};
use ciris_persist::federation::genesis::{
    effective_accord_holder_records, seed_family_and_canonical,
};
use ciris_persist::federation::{is_canonical_effective, FederationDirectory};
use ciris_persist::prelude::FederationDirectorySqlite;
use ciris_persist::store::sqlite::SqliteBackend;
use tokio::sync::mpsc;

struct NullTransport;

#[async_trait]
impl Transport for NullTransport {
    fn id(&self) -> TransportId {
        TransportId::HTTP
    }
    async fn send(&self, _: &str, _: &[u8]) -> Result<TransportSendOutcome, TransportError> {
        Ok(TransportSendOutcome::Delivered)
    }
    async fn listen(&self, _: mpsc::Sender<InboundFrame>) -> Result<(), TransportError> {
        Ok(())
    }
}

/// A persist sqlite backend carrying the REAL baked genesis: accord holders
/// (A1/B1/C1, hardware-custody evidence and all), the accord family, and the
/// 2-of-3-scrubbed canonical serve-node — admitted through the ordinary
/// admission gates, exactly as `Engine` boot seeds a production node.
async fn genesis_seeded_backend() -> Arc<SqliteBackend> {
    let backend = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open in-memory persist");
    backend
        .seed_genesis_accord_holders(&effective_accord_holder_records())
        .await
        .expect("seed accord holders");
    seed_family_and_canonical(backend.as_ref())
        .await
        .expect("seed family + canonical (the Engine boot sequence)");
    backend
}

/// An UNSEEDED backend — the bare-build shape (no genesis rows at all).
async fn bare_backend() -> Arc<SqliteBackend> {
    FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open in-memory persist")
}

async fn local_signer(tmp: &Path, key_id: &str) -> Arc<LocalSigner> {
    let seed_dir = tmp.join(format!("seed-{key_id}"));
    std::fs::create_dir_all(&seed_dir).expect("create seed dir");
    std::fs::write(seed_dir.join("ed25519.seed"), [0x42u8; 32]).expect("write seed");
    let (classical, _pqc) = ciris_keyring::load_local_seed(ciris_keyring::LocalSeedConfig {
        key_id: key_id.to_string(),
        key_path: seed_dir.join("ed25519.seed"),
        pqc_key_id: None,
        pqc_key_path: None,
    })
    .await
    .expect("load_local_seed");
    Arc::new(LocalSigner::new(key_id.to_string(), classical, None))
}

async fn build_edge(
    tmp: &Path,
    backend: Arc<SqliteBackend>,
    canonical: Vec<CanonicalBootstrapPeer>,
    config: EdgeConfig,
) -> Edge {
    let signer = local_signer(tmp, "edge-self-genesis-281").await;
    Edge::builder()
        .directory(backend.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .federation_directory(backend.clone() as Arc<dyn FederationDirectory>)
        .queue(backend)
        .signer(signer)
        .transport(Arc::new(NullTransport))
        .canonical_bootstrap_peers(canonical)
        .config(config)
        .build()
        .expect("build edge")
}

fn lenient_config() -> EdgeConfig {
    EdgeConfig {
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        ..EdgeConfig::default()
    }
}

fn operator_peer(key_id: &str) -> CanonicalBootstrapPeer {
    CanonicalBootstrapPeer {
        key_id: key_id.to_string(),
        alias: format!("alias-{key_id}"),
        // Any valid base64 works for `add_peer_record` (32-byte pubkey).
        pubkey_ed25519_base64: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [0x24u8; 32],
        ),
        transport_hint: Some(format!("tcp://{key_id}:4242")),
        description: Some(format!("operator fixture {key_id}")),
    }
}

// ─── #1 zero-config recognition ─────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_config_recognizes_baked_canonical_genesis() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let backend = genesis_seeded_backend().await;
    let edge = build_edge(tmp.path(), backend.clone(), Vec::new(), lenient_config()).await;

    let baked = baked_canonical_genesis_ids();
    assert!(!baked.is_empty(), "production bundle carries serve-nodes");
    for id in &baked {
        assert!(
            edge.is_canonical_peer(id),
            "ZERO-config edge must recognize baked canonical {id}"
        );
        // Tie to persist's authoritative tombstone-aware read: the seeded
        // row is canonical-effective (role conferred through the real
        // 2-of-3 gate, no tombstone).
        assert!(
            is_canonical_effective(backend.as_ref(), id)
                .await
                .expect("effective read"),
            "seeded baked canonical {id} must read canonical-effective"
        );
    }

    // A live (non-retired) canonical SURVIVES the retirement refresh — the
    // `Ok(true)` arm against the real seeded directory.
    assert_eq!(edge.refresh_canonical_retirements().await, 0);
    for id in &baked {
        assert!(
            edge.is_canonical_peer(id),
            "live canonical {id} must survive refresh"
        );
    }
}

// ─── #2 operator config augments, never replaces ────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_config_augments_baked_base() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let backend = genesis_seeded_backend().await;
    let op = operator_peer("op-canonical-281");

    // The pre-#281 operator flow, unchanged: reseed into persist, then
    // declare on the builder.
    let dir: Arc<dyn FederationDirectory> = backend.clone();
    reseed_canonical_bootstrap_peers(&dir, std::slice::from_ref(&op))
        .await
        .expect("operator reseed keeps working (back-compat)");
    let edge = build_edge(
        tmp.path(),
        backend.clone(),
        vec![op.clone()],
        lenient_config(),
    )
    .await;

    // BOTH sources recognized: union, not replacement.
    assert!(
        edge.is_canonical_peer(&op.key_id),
        "operator peer recognized"
    );
    for id in baked_canonical_genesis_ids() {
        assert!(edge.is_canonical_peer(&id), "baked base still recognized");
    }

    // The operator peer's directory row is `identity_type = "agent"` (the
    // #46 reseed contract) → `is_canonical_effective` reads false — but with
    // NO #377 tombstone that is NOT retirement: the refresh keeps it (the
    // fail-safe arm; absence of directory corroboration never destroys
    // provenance-based recognition).
    assert!(!is_canonical_effective(backend.as_ref(), &op.key_id)
        .await
        .expect("effective read"));
    assert_eq!(edge.refresh_canonical_retirements().await, 0);
    assert!(
        edge.is_canonical_peer(&op.key_id),
        "operator-declared peer without a tombstone survives refresh"
    );
}

// ─── #3 the #377 quorum tombstone retires a canonical ───────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tombstoned_canonical_drops_out_of_recognition() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let backend = genesis_seeded_backend().await;
    let edge = build_edge(tmp.path(), backend.clone(), Vec::new(), lenient_config()).await;

    let baked = baked_canonical_genesis_ids();
    let victim = baked.first().expect("bundle non-empty").clone();
    assert!(
        edge.is_canonical_peer(&victim),
        "recognized before retirement"
    );

    // The V095 tombstone the verified `withdraw_canonical_role`
    // orchestration records (quorum verification is upstream of this write).
    backend
        .record_canonical_withdrawal(&victim, None, "sha256:test-281-withdraw-proposal")
        .await
        .expect("record withdrawal tombstone");

    // persist's tombstone-aware read flips first…
    assert!(
        !is_canonical_effective(backend.as_ref(), &victim)
            .await
            .expect("effective read"),
        "is_canonical_effective must read false once the #377 tombstone exists"
    );
    // …and edge honors it: the retired canonical drops out of the
    // recognition set (hard-remove guard, EdgePeerInfo projection, and #108
    // delegation trust roots all read this set).
    assert_eq!(edge.refresh_canonical_retirements().await, 1);
    assert!(
        !edge.is_canonical_peer(&victim),
        "quorum-retired canonical must stop being trusted as canonical"
    );
    // Idempotent: a second refresh finds nothing more to retire.
    assert_eq!(edge.refresh_canonical_retirements().await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tombstone_outvotes_operator_declaration() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let backend = genesis_seeded_backend().await;
    let op = operator_peer("op-retired-canonical-281");
    let dir: Arc<dyn FederationDirectory> = backend.clone();
    reseed_canonical_bootstrap_peers(&dir, std::slice::from_ref(&op))
        .await
        .expect("operator reseed");
    let edge = build_edge(
        tmp.path(),
        backend.clone(),
        vec![op.clone()],
        lenient_config(),
    )
    .await;
    assert!(edge.is_canonical_peer(&op.key_id));

    backend
        .record_canonical_withdrawal(&op.key_id, None, "sha256:test-281-op-withdraw")
        .await
        .expect("record withdrawal tombstone");

    assert_eq!(edge.refresh_canonical_retirements().await, 1);
    assert!(
        !edge.is_canonical_peer(&op.key_id),
        "an accord-quorum retirement is not outvoted by operator config"
    );
}

// ─── #4 bare-build fail-safe ────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bare_build_degrades_to_pre_281_behavior() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let backend = bare_backend().await;

    // No baked base (the fail-safe lever), no operator config → the
    // pre-#281 empty recognition set, and refresh is a no-op.
    let config = EdgeConfig {
        baked_canonical_genesis_enabled: false,
        ..lenient_config()
    };
    let edge = build_edge(tmp.path(), backend.clone(), Vec::new(), config).await;
    assert!(
        edge.canonical_peer_ids().is_empty(),
        "no baked + no config = today's (pre-#281) empty set"
    );
    assert_eq!(edge.refresh_canonical_retirements().await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unseeded_directory_keeps_baked_recognition() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    // Directory has NO genesis rows and NO tombstones (a cold cohab node
    // before persist's engine seed, or a partial test harness): the baked
    // recognition stands — `is_canonical_effective == false` alone is not
    // retirement, only a positive #377 tombstone is.
    let backend = bare_backend().await;
    let edge = build_edge(tmp.path(), backend.clone(), Vec::new(), lenient_config()).await;
    let baked = baked_canonical_genesis_ids();
    for id in &baked {
        assert!(edge.is_canonical_peer(id));
    }
    assert_eq!(edge.refresh_canonical_retirements().await, 0);
    for id in &baked {
        assert!(
            edge.is_canonical_peer(id),
            "absence of directory corroboration must not destroy baked recognition"
        );
    }
}
