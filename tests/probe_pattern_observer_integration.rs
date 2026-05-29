//! Integration acceptance for CIRISEdge#39 — `ProbePatternObserver`
//! Counter-RII detector wired through `dispatch_inbound`.
//!
//! The detector's unit tests in
//! `src/detector/probe_pattern_observer.rs::tests` cover the math
//! (Shannon entropy, KS p-value, EWMA z-score) and the consent-role
//! gating in isolation. This integration suite exercises the
//! end-to-end wire path:
//!
//! 1. Construct a real `Edge` with a persist-backed federation
//!    directory + outbound queue.
//! 2. Drive verified envelopes through `dispatch_inbound_for_test`.
//! 3. Assert observation counts via the test-only
//!    `observation_count_for` accessor — the persist write-side
//!    admission for `EdgeDetectionEvent` rows does not yet exist
//!    (`DerivedSchema::put_edge_detection_event` is the persist
//!    follow-up filed alongside this issue), so the integration
//!    assertion is on the observer's internal state rather than on
//!    persist rows. Once the persist write API lands, this suite
//!    extends with `count_edge_detection_events_for(...)` reads.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::Utc;
use ciris_crypto::{ClassicalSigner, Ed25519Signer};
use ciris_edge::identity::{build_envelope, sign_envelope, LocalSigner};
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_edge::{
    ConsentRole, DetectionVerdict, Edge, EdgeConfig, HybridPolicy, InlineText, Message,
    OutboundHandle, ProbePatternConfig, ProbePatternObserver,
};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

// ─── Fixtures (lifted from tests/steward_topology.rs) ───────────────

struct FedKey {
    key_id: String,
    seed: [u8; 32],
}

impl FedKey {
    fn new(key_id: &str, seed_byte: u8) -> Self {
        Self {
            key_id: key_id.to_string(),
            seed: [seed_byte; 32],
        }
    }

    fn signer(&self) -> Ed25519Signer {
        Ed25519Signer::from_seed(&self.seed).expect("ed25519 from seed")
    }

    fn pubkey_b64(&self) -> String {
        B64.encode(self.signer().public_key().expect("pubkey"))
    }

    fn write_seed_dir(&self, base: &std::path::Path) -> PathBuf {
        let dir = base.join(format!("seed-{}", self.key_id));
        std::fs::create_dir_all(&dir).expect("create seed dir");
        std::fs::write(dir.join("ed25519.seed"), self.seed).expect("write seed");
        dir
    }

    async fn local_signer(&self, base: &std::path::Path) -> Arc<LocalSigner> {
        let seed_dir = self.write_seed_dir(base);
        let (classical, _pqc) = ciris_keyring::load_local_seed(ciris_keyring::LocalSeedConfig {
            key_id: self.key_id.clone(),
            key_path: seed_dir.join("ed25519.seed"),
            pqc_key_id: None,
            pqc_key_path: None,
        })
        .await
        .expect("load_local_seed");
        Arc::new(LocalSigner::new(self.key_id.clone(), classical, None))
    }
}

fn signed_record(subject: &FedKey, signer: &FedKey, identity_type: &str) -> KeyRecord {
    let envelope = serde_json::json!({ "key_id": subject.key_id });
    let canonical = serde_json::to_vec(&envelope).expect("serialize");
    let digest = Sha256::digest(&canonical);
    let sig = signer.signer().sign(digest.as_slice()).expect("sign");
    let ts = chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
        .unwrap()
        .into();
    KeyRecord {
        key_id: subject.key_id.clone(),
        pubkey_ed25519_base64: subject.pubkey_b64(),
        pubkey_ml_dsa_65_base64: None,
        algorithm: "hybrid".to_string(),
        identity_type: identity_type.to_string(),
        identity_ref: subject.key_id.clone(),
        valid_from: ts,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: B64.encode(sig),
        scrub_signature_pqc: None,
        scrub_key_id: signer.key_id.clone(),
        scrub_timestamp: ts,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        roles: Vec::new(),
        attestation_evidence: None,
    }
}

async fn directory_with(records: Vec<KeyRecord>) -> Arc<SqliteBackend> {
    let backend = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open in-memory persist directory");
    backend.run_migrations().await.expect("migrate");
    for rec in records {
        backend
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .expect("put_public_key");
    }
    backend
}

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

/// Build an Edge with the detector OPT-IN. A loose detector config
/// (low min_messages_per_window, small window) so the test can drive
/// 100 observations without spinning a real clock around.
///
/// v0.17.0 — also threads `derived_schema(directory.clone())` so the
/// detector's `emit_verdict` writes into
/// `cirislens.edge_detection_events` via persist's
/// `put_edge_detection_event` (#118). The same `SqliteBackend` backs
/// both the federation directory + the derived-schema admission, so
/// the test can read back via `get_edge_detection_events`.
async fn build_edge_with_detector_enabled(
    tmp: &tempfile::TempDir,
    me: &FedKey,
    directory: Arc<SqliteBackend>,
    queue: Arc<SqliteBackend>,
) -> Edge {
    let signer = me.local_signer(tmp.path()).await;
    let detector_cfg = ProbePatternConfig {
        enabled: true,
        window_seconds: 60,
        min_messages_per_window: 10,
        message_shape_entropy_threshold: 0.3,
        rate_anomaly_zscore: 3.0,
        timing_distribution_kolmogorov_smirnov_pvalue: 0.01,
        cohort_centroids: std::collections::HashMap::new(),
    };
    let config = EdgeConfig {
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        probe_pattern_observer_enabled: true,
        probe_pattern_observer_config: detector_cfg,
        ..EdgeConfig::default()
    };
    let schema: Arc<dyn ciris_edge::EdgeDetectionAdmission> = directory.clone();
    Edge::builder()
        .directory(directory as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .queue(queue as Arc<dyn OutboundHandle>)
        .signer(signer)
        .transport(Arc::new(NullTransport))
        .derived_schema(schema)
        .config(config)
        .build()
        .expect("build edge")
}

/// Build an Edge with the detector OPT-OUT (the production default).
async fn build_edge_with_detector_disabled(
    tmp: &tempfile::TempDir,
    me: &FedKey,
    directory: Arc<SqliteBackend>,
    queue: Arc<SqliteBackend>,
) -> Edge {
    let signer = me.local_signer(tmp.path()).await;
    let config = EdgeConfig {
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        probe_pattern_observer_enabled: false,
        ..EdgeConfig::default()
    };
    Edge::builder()
        .directory(directory as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .queue(queue as Arc<dyn OutboundHandle>)
        .signer(signer)
        .transport(Arc::new(NullTransport))
        .config(config)
        .build()
        .expect("build edge")
}

async fn build_inline_text_envelope(
    sender: &Arc<LocalSigner>,
    recipient_key_id: &str,
    text: &str,
) -> Vec<u8> {
    let msg = InlineText {
        text: text.to_string(),
    };
    let mut env = build_envelope(
        InlineText::TYPE,
        &sender.key_id,
        recipient_key_id,
        &msg,
        None,
    )
    .expect("build envelope");
    sign_envelope(sender, &mut env)
        .await
        .expect("sign envelope");
    serde_json::to_vec(&env).expect("serialize envelope")
}

// ─── Tests ──────────────────────────────────────────────────────────

/// 100 UnconsentedExternal envelopes drive 100 observations through
/// the detector. The sender is NOT in the federation_keys directory →
/// `classify_consent_role` resolves to `UnconsentedExternal` → the
/// observer records every one.
#[tokio::test]
async fn unconsented_external_traffic_drives_observations() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = FedKey::new("bootstrap-steward", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    // External sender — registered in the directory because the verify
    // pipeline needs a row to clear the envelope's hybrid signature.
    // The detector's UnconsentedExternal classification is the
    // *application-layer* contract (an attacker with a forged
    // signature would not appear in the verify path at all). For the
    // integration test, we override the classification via the
    // observer's `inject_role_for_test` hook to simulate the case
    // the production wire format will tag at the envelope level.
    let attacker = FedKey::new("external-attacker", 0xCC);

    let directory = directory_with(vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
        signed_record(&attacker, &bootstrap, "agent"),
    ])
    .await;
    let queue = directory.clone();

    let edge = build_edge_with_detector_enabled(&tmp, &me, directory.clone(), queue.clone()).await;
    let detector: &Arc<ProbePatternObserver> = edge
        .detector
        .as_ref()
        .expect("detector wired when probe_pattern_observer_enabled = true");
    // Override the role: the attacker is registered in the directory
    // (so verify clears them) but they're classified as
    // UnconsentedExternal at the detector tier. Production deployments
    // get this classification from the envelope-level consent_role
    // tag once SchemaVersion::V1_1_0 lands.
    detector
        .inject_role_for_test(&attacker.key_id, ConsentRole::UnconsentedExternal)
        .await;

    let attacker_signer = attacker.local_signer(tmp.path()).await;

    for i in 0..100 {
        let bytes =
            build_inline_text_envelope(&attacker_signer, &me.key_id, &format!("probe-{i}")).await;
        edge.dispatch_inbound_for_test(InboundFrame {
            envelope_bytes: bytes,
            transport: TransportId::HTTP,
            received_at: Utc::now(),
        })
        .await;
    }

    let count = detector.observation_count_for(&attacker.key_id).await;
    assert_eq!(
        count, 100,
        "100 inbound UnconsentedExternal envelopes must produce 100 observations; got {count}"
    );
}

/// 100 Peer-role envelopes drive ZERO observations — F-CR-3 suppresses
/// detection emission for the ordinary federation case.
#[tokio::test]
async fn peer_role_traffic_produces_no_observations() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = FedKey::new("bootstrap-steward", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let peer = FedKey::new("ordinary-peer", 0xDD);

    let directory = directory_with(vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
        signed_record(&peer, &bootstrap, "agent"),
    ])
    .await;
    let queue = directory.clone();

    let edge = build_edge_with_detector_enabled(&tmp, &me, directory.clone(), queue.clone()).await;
    let detector = edge.detector.as_ref().expect("detector wired");
    // Default classification (peer is in federation_keys) is
    // ConsentRole::Peer — F-CR-3 suppresses. We don't need
    // inject_role_for_test here because the production
    // classify_consent_role path already returns Peer for any key in
    // the federation directory.

    let peer_signer = peer.local_signer(tmp.path()).await;

    for i in 0..100 {
        let bytes =
            build_inline_text_envelope(&peer_signer, &me.key_id, &format!("ordinary-{i}")).await;
        edge.dispatch_inbound_for_test(InboundFrame {
            envelope_bytes: bytes,
            transport: TransportId::HTTP,
            received_at: Utc::now(),
        })
        .await;
    }

    let count = detector.observation_count_for(&peer.key_id).await;
    assert_eq!(
        count, 0,
        "Peer-role (in federation_keys) traffic must be F-CR-3 suppressed; got {count} obs"
    );
}

/// Detector OFF at the EdgeConfig level: `Edge::detector` is `None`
/// and 100 inbound envelopes from a would-be UnconsentedExternal
/// sender produce no detector state at all.
#[tokio::test]
async fn detector_disabled_is_a_full_noop() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = FedKey::new("bootstrap-steward", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let any = FedKey::new("any-sender", 0xEE);

    let directory = directory_with(vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
        signed_record(&any, &bootstrap, "agent"),
    ])
    .await;
    let queue = directory.clone();

    let edge = build_edge_with_detector_disabled(&tmp, &me, directory.clone(), queue.clone()).await;
    assert!(
        edge.detector.is_none(),
        "EdgeConfig::probe_pattern_observer_enabled=false must leave Edge::detector as None"
    );

    let signer = any.local_signer(tmp.path()).await;
    for i in 0..100 {
        let bytes = build_inline_text_envelope(&signer, &me.key_id, &format!("payload-{i}")).await;
        edge.dispatch_inbound_for_test(InboundFrame {
            envelope_bytes: bytes,
            transport: TransportId::HTTP,
            received_at: Utc::now(),
        })
        .await;
    }
    // Nothing to assert beyond `detector.is_none()` — the
    // dispatch_inbound hook's `if let Some(..)` branch is the no-op.
}

/// v0.17.0 — `emit_verdict` admits an `EdgeDetectionEvent` row into
/// `cirislens.edge_detection_events` via persist's
/// `put_edge_detection_event` (#118 / v3.1.1). Drives a synthetic
/// verdict through the detector + asserts the row appears via
/// `DerivedSchema::get_edge_detection_events`.
#[tokio::test]
async fn emit_verdict_writes_through_put_edge_detection_event() {
    use ciris_persist::derived::{DerivedSchema, EdgeEventFilter};

    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = FedKey::new("bootstrap-steward", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let suspect = FedKey::new("external-suspect", 0xCC);

    let directory = directory_with(vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
    ])
    .await;
    let queue = directory.clone();

    let edge = build_edge_with_detector_enabled(&tmp, &me, directory.clone(), queue.clone()).await;
    let detector = edge.detector.as_ref().expect("detector wired");

    let verdict = DetectionVerdict {
        signing_key_id: suspect.key_id.clone(),
        window_start: Utc::now() - chrono::Duration::seconds(60),
        window_end: Utc::now(),
        message_count: 42,
        shape_entropy: 0.12,
        rate_zscore: 4.5,
        ks_pvalue: 0.001,
        features_16: [0.0; 16],
    };
    detector.emit_verdict(&verdict).await;

    // Read back via the read-side accessor — the row must be present
    // with the four canonical fields the lens-core joiner consumes.
    let rows = directory
        .get_edge_detection_events(EdgeEventFilter {
            peer_key_id: Some(suspect.key_id.clone()),
            ..EdgeEventFilter::default()
        })
        .await
        .expect("get_edge_detection_events");
    assert_eq!(
        rows.len(),
        1,
        "exactly one row expected for suspect; got {}",
        rows.len()
    );
    let row = &rows[0];
    assert_eq!(row.detector_kind, "unconsented_external_probe");
    assert_eq!(row.subject_key_id, suspect.key_id);
    assert_eq!(row.severity, "warn");
    // The evidence JSON must carry the load-bearing statistic fields.
    assert_eq!(
        row.evidence.get("message_count").and_then(|v| v.as_u64()),
        Some(42),
        "evidence.message_count round-trips through persist",
    );
    assert!(
        row.evidence.get("shape_entropy").is_some(),
        "evidence.shape_entropy must be present"
    );
    assert!(
        row.evidence.get("features_16").is_some(),
        "evidence.features_16 (lens-core join key) must be present"
    );
}
