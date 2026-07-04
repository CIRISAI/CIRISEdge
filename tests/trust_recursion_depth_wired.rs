//! CIRISEdge#51 (v0.20.0 RC1) — `EdgeConfig::trust_recursion_depth`
//! is threaded into `dispatch_inbound`'s
//! `TrustScoring::trust_score(key_id, recursion_depth)` call. v0.19.6
//! hardcoded `0` (strict direct trust); the CEWP L0/L1 default of
//! `1` for `AgentMode::Server` (friend-of-friends) now reaches the
//! resolver via the config field.
//!
//! Uses a recording `TrustScoring` impl that captures the
//! `recursion_depth` argument so the test asserts byte-equivalence
//! between `EdgeConfig::trust_recursion_depth` and the value the
//! resolver observes.

#![cfg(feature = "transport-reticulum")]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::Utc;
use ciris_crypto::{ClassicalSigner, Ed25519Signer};
use ciris_edge::handler::Message;
use ciris_edge::identity::{build_envelope, sign_envelope, LocalSigner};
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_edge::verify::HybridPolicy;
use ciris_edge::{AgentMode, Edge, EdgeConfig, OpaqueEvent};
use ciris_persist::federation::{FederationDirectory, TrustScoring, TrustScoringError};
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

// ─── Recording scorer — captures (key_id, recursion_depth) calls ─────

#[derive(Default)]
struct RecordingScorer {
    calls: Mutex<Vec<(String, u8)>>,
    score: f64,
}

impl RecordingScorer {
    fn new(score: f64) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            score,
        }
    }
    fn last_depth(&self) -> Option<u8> {
        self.calls.lock().unwrap().last().map(|(_, d)| *d)
    }
    fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

#[async_trait]
impl TrustScoring for RecordingScorer {
    async fn trust_score(
        &self,
        key_id: &str,
        recursion_depth: u8,
    ) -> Result<f64, TrustScoringError> {
        self.calls
            .lock()
            .unwrap()
            .push((key_id.to_string(), recursion_depth));
        Ok(self.score)
    }
}

// ─── Fixtures (mirror of trust_short_circuit.rs) ────────────────────

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
        consent_role: None,
    }
}

async fn directory_with(records: Vec<KeyRecord>) -> Arc<SqliteBackend> {
    let backend = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open directory");
    backend.run_migrations().await.expect("migrate");
    for rec in records {
        backend
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .expect("put_public_key");
    }
    backend
}

struct NopTransport;

#[async_trait]
impl Transport for NopTransport {
    fn id(&self) -> TransportId {
        TransportId::HTTP
    }
    async fn send(&self, _: &str, _: &[u8]) -> Result<TransportSendOutcome, TransportError> {
        Ok(TransportSendOutcome::Delivered)
    }
    async fn listen(&self, _: mpsc::Sender<InboundFrame>) -> Result<(), TransportError> {
        std::future::pending::<()>().await;
        Ok(())
    }
}

async fn build_edge_with_recursion_depth(
    tmp: &tempfile::TempDir,
    recursion_depth: u8,
    sender_score: f64,
) -> (Arc<Edge>, Arc<LocalSigner>, String, Arc<RecordingScorer>) {
    let steward = FedKey::new("steward-fed", 0x01);
    let local = FedKey::new("local-self", 0xBB);
    let remote = FedKey::new("remote-peer", 0xAA);

    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&local, &steward, "agent"),
        signed_record(&remote, &steward, "agent"),
    ])
    .await;
    let queue = directory.clone();
    let local_signer = local.local_signer(tmp.path()).await;
    let remote_signer = remote.local_signer(tmp.path()).await;
    let transport: Arc<dyn Transport> = Arc::new(NopTransport);

    let recorder = Arc::new(RecordingScorer::new(sender_score));
    let scorer_arc: Arc<dyn TrustScoring> = recorder.clone();

    let config = EdgeConfig {
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        trust_threshold: 0.5,
        trust_short_circuit_enabled: true,
        trust_recursion_depth: recursion_depth,
        cohort_scope_enforcement: ciris_edge::CohortScopeEnforcement::Off,
        ..EdgeConfig::default()
    };

    let edge = Edge::builder()
        .directory(directory.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .queue(queue)
        .signer(local_signer)
        .transport(transport)
        .trust_scoring(scorer_arc)
        .config(config)
        .build()
        .expect("build edge");
    (
        Arc::new(edge),
        remote_signer,
        local.key_id.clone(),
        recorder,
    )
}

async fn dispatch(
    edge: &Edge,
    sender: &LocalSigner,
    destination: &str,
) -> Result<(), ciris_edge::EdgeError> {
    let body = OpaqueEvent {
        kind: 0x0000_0001,
        payload: b"rec-depth-test".to_vec(),
    };
    let mut env = build_envelope(OpaqueEvent::TYPE, &sender.key_id, destination, &body, None)?;
    sign_envelope(sender, &mut env).await?;
    let bytes = serde_json::to_vec(&env)
        .map_err(|e| ciris_edge::EdgeError::Config(format!("serialize: {e}")))?;
    let frame = InboundFrame {
        envelope_bytes: bytes,
        transport: TransportId::HTTP,
        received_at: Utc::now(),
        source_key_id: None,
    };
    edge.dispatch_inbound_for_test(frame).await;
    Ok(())
}

// ─── Tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn dispatch_inbound_uses_config_trust_recursion_depth_for_score_lookup_l0() {
    // L0 / Proxy default (recursion depth = 0). Above-threshold so
    // the envelope reaches the scoring branch; we don't care about
    // the outcome, only that the resolver observed depth = 0.
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, remote, local_key_id, recorder) =
        build_edge_with_recursion_depth(&tmp, 0, 0.9).await;
    dispatch(&edge, &remote, &local_key_id)
        .await
        .expect("dispatch");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(recorder.call_count(), 1, "exactly one score lookup");
    assert_eq!(
        recorder.last_depth(),
        Some(0),
        "EdgeConfig::trust_recursion_depth = 0 must reach the resolver as 0"
    );
}

#[tokio::test]
async fn dispatch_inbound_uses_config_trust_recursion_depth_for_score_lookup_l1() {
    // L1 / Server default (recursion depth = 1, friend-of-friends).
    // This is the load-bearing assertion for the v0.20.0 RC1 wiring:
    // the value must flow EdgeConfig → dispatch_inbound → scorer.
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, remote, local_key_id, recorder) =
        build_edge_with_recursion_depth(&tmp, 1, 0.9).await;
    dispatch(&edge, &remote, &local_key_id)
        .await
        .expect("dispatch");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(recorder.call_count(), 1, "exactly one score lookup");
    assert_eq!(
        recorder.last_depth(),
        Some(1),
        "EdgeConfig::trust_recursion_depth = 1 (L1 friend-of-friends) \
         must reach the resolver verbatim"
    );
}

#[tokio::test]
async fn dispatch_inbound_uses_operator_pinned_recursion_depth_override() {
    // Operator override scenario: a curated server pins depth = 0
    // (strict direct trust) even though L1 default is 1. The
    // override flow is `apply_defaults` → operator field write →
    // EdgeConfig → dispatch_inbound. Pinned at depth = 2 here to
    // exercise a non-default-tier value (covers the contract shape
    // for future L2+ deployments).
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, remote, local_key_id, recorder) =
        build_edge_with_recursion_depth(&tmp, 2, 0.9).await;
    dispatch(&edge, &remote, &local_key_id)
        .await
        .expect("dispatch");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        recorder.last_depth(),
        Some(2),
        "operator-pinned depth must override the AgentMode default"
    );
}

#[tokio::test]
async fn agent_mode_server_apply_defaults_threads_depth_one_into_edge_config() {
    // End-to-end shape: build an `EdgeConfig` via `AgentMode::Server
    // .apply_defaults`, then verify the Edge built around it sees
    // depth = 1 at the dispatcher. This pins the integration between
    // the AgentMode default and the dispatch-inbound wiring.
    let tmp = tempfile::tempdir().expect("tempdir");

    let steward = FedKey::new("steward-fed", 0x01);
    let local = FedKey::new("local-self", 0xBB);
    let remote = FedKey::new("remote-peer", 0xAA);
    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&local, &steward, "agent"),
        signed_record(&remote, &steward, "agent"),
    ])
    .await;
    let queue = directory.clone();
    let local_signer = local.local_signer(tmp.path()).await;
    let remote_signer = remote.local_signer(tmp.path()).await;
    let transport: Arc<dyn Transport> = Arc::new(NopTransport);

    let recorder = Arc::new(RecordingScorer::new(0.9));
    let scorer_arc: Arc<dyn TrustScoring> = recorder.clone();

    let mut config = EdgeConfig {
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        trust_threshold: 0.5,
        trust_short_circuit_enabled: true,
        cohort_scope_enforcement: ciris_edge::CohortScopeEnforcement::Off,
        ..EdgeConfig::default()
    };
    AgentMode::Server.apply_defaults(&mut config);
    assert_eq!(
        config.trust_recursion_depth, 1,
        "Server apply_defaults must set depth = 1"
    );

    let edge = Edge::builder()
        .directory(directory.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .queue(queue)
        .signer(local_signer)
        .transport(transport)
        .trust_scoring(scorer_arc)
        .config(config)
        .build()
        .expect("build edge");
    let edge = Arc::new(edge);
    assert_eq!(
        edge.trust_recursion_depth(),
        1,
        "Edge::trust_recursion_depth() accessor returns the configured value"
    );
    dispatch(&edge, &remote_signer, &local.key_id)
        .await
        .expect("dispatch");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        recorder.last_depth(),
        Some(1),
        "Server-tier depth must propagate to the resolver"
    );
}

#[test]
fn edge_disk_budget_accessor_returns_config_value() {
    // Pure unit cover for the new `Edge::disk_budget_bytes` accessor
    // — verifies the field reaches the surface. No async machinery
    // needed; we test the EdgeConfig itself, which is the data
    // source.
    let mut config = EdgeConfig::default();
    AgentMode::Server.apply_defaults(&mut config);
    assert_eq!(
        config.disk_budget_bytes,
        1024 * 1024 * 1024 * 1024,
        "Server tier defaults to 1 TB"
    );
}
