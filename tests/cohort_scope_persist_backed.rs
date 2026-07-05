//! CIRISEdge#48-A completion (v0.19.6) — cohort_scope consumer-side
//! check sourced from persist's `peer_metadata_for` accessor
//! (CIRISPersist#127, v3.4.1). The v0.19.1 in-process
//! `cohort_membership` HashMap registry is REMOVED at v0.19.6; the
//! persist directory is the single source of truth.
//!
//! These tests pin the new persist-backed lookup path AND the
//! v0.19.1 `Cohort{id}` arm that was deferred (the consumer-side
//! check now applies to `Cohort` as well as `SelfOnly` / `Family`).

#![cfg(feature = "transport-reticulum")]

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::Utc;
use ciris_crypto::{ClassicalSigner, Ed25519Signer};
use ciris_edge::events::EventKind;
use ciris_edge::handler::Message;
use ciris_edge::identity::{build_envelope, sign_envelope, LocalSigner};
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_edge::verify::HybridPolicy;
use ciris_edge::{CohortScope, CohortScopeEnforcement, Edge, EdgeConfig, OpaqueEvent};
use ciris_persist::federation::types::PeerPolicyBlob;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

// ─── Fixtures (mirrors cohort_scope_refusal.rs shape) ───────────────

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
        additional_scrubs: Vec::new(),
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

fn config_strict() -> EdgeConfig {
    EdgeConfig {
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        cohort_scope_enforcement: CohortScopeEnforcement::Strict,
        ..EdgeConfig::default()
    }
}

/// Build an Edge with a persist directory + optional `cohort_scope`
/// stored against `remote` via `update_peer_policy`. Returns:
/// (edge, remote_signer, local_key_id, directory).
async fn build_edge_with_remote_policy(
    tmp: &tempfile::TempDir,
    remote_policy_blob: Option<serde_json::Value>,
) -> (Arc<Edge>, Arc<LocalSigner>, String, Arc<SqliteBackend>) {
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

    if let Some(blob) = remote_policy_blob {
        directory
            .add_peer_record(
                &remote.key_id,
                &remote.pubkey_b64(),
                ciris_persist::federation::types::identity_type::AGENT,
                None,
            )
            .await
            .expect("add_peer_record remote");
        directory
            .update_peer_policy(&remote.key_id, PeerPolicyBlob::new(blob))
            .await
            .expect("update_peer_policy remote");
    }

    let federation_directory_dyn: Arc<dyn FederationDirectory> = directory.clone();
    let edge = Edge::builder()
        .directory(directory.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .federation_directory(federation_directory_dyn)
        .queue(queue)
        .signer(local_signer)
        .transport(transport)
        .config(config_strict())
        .build()
        .expect("build edge");
    (
        Arc::new(edge),
        remote_signer,
        local.key_id.clone(),
        directory,
    )
}

async fn dispatch(
    edge: &Edge,
    sender: &LocalSigner,
    destination: &str,
    cohort_scope: Option<CohortScope>,
) -> Result<(), ciris_edge::EdgeError> {
    let body = OpaqueEvent {
        kind: 0x0000_0001,
        payload: b"scope-test".to_vec(),
    };
    let mut env = build_envelope(OpaqueEvent::TYPE, &sender.key_id, destination, &body, None)?;
    env.cohort_scope = cohort_scope;
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
async fn cohort_scope_lookup_uses_persist_peer_metadata_for() {
    // Seed remote's cohort_scope as Family via persist's
    // update_peer_policy. The consumer-side check at dispatch_inbound
    // must read it back via peer_metadata_for and admit.
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, remote_signer, local_key_id, _dir) = build_edge_with_remote_policy(
        &tmp,
        Some(serde_json::json!({"cohort_scope": {"kind": "family"}})),
    )
    .await;
    let mut rx = edge.events().subscribe_resources();
    dispatch(
        &edge,
        &remote_signer,
        &local_key_id,
        Some(CohortScope::Family),
    )
    .await
    .expect("dispatch");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    while let Ok(ev) = rx.try_recv() {
        assert_ne!(
            ev.resource_kind.as_deref(),
            Some("cohort_scope_violation"),
            "persist-backed lookup found Family match; no violation expected"
        );
    }
}

#[tokio::test]
async fn cohort_scope_missing_policy_blob_treated_as_public() {
    // Remote has no policy_blob (no add_peer_record / no
    // update_peer_policy). The lookup must return None → treated as
    // Public → restricted claim (Family) is rejected.
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, remote_signer, local_key_id, _dir) = build_edge_with_remote_policy(&tmp, None).await;
    let mut rx = edge.events().subscribe_resources();
    dispatch(
        &edge,
        &remote_signer,
        &local_key_id,
        Some(CohortScope::Family),
    )
    .await
    .expect("dispatch");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut saw_violation = false;
    while let Ok(ev) = rx.try_recv() {
        if ev.resource_kind.as_deref() == Some("cohort_scope_violation") {
            saw_violation = true;
            break;
        }
    }
    assert!(
        saw_violation,
        "absent policy_blob = Public default → Family claim must reject"
    );
}

#[tokio::test]
async fn cohort_scope_malformed_policy_blob_treated_as_public() {
    // Remote's policy_blob carries a malformed cohort_scope value
    // (`"kind": "definitely_not_a_real_kind"`). The lookup must
    // log + return None → Public default → restricted claim rejects.
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, remote_signer, local_key_id, _dir) = build_edge_with_remote_policy(
        &tmp,
        Some(serde_json::json!({"cohort_scope": {"kind": "garbage", "extra": 42}})),
    )
    .await;
    let mut rx = edge.events().subscribe_resources();
    dispatch(
        &edge,
        &remote_signer,
        &local_key_id,
        Some(CohortScope::Family),
    )
    .await
    .expect("dispatch");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut saw_violation = false;
    while let Ok(ev) = rx.try_recv() {
        if ev.resource_kind.as_deref() == Some("cohort_scope_violation") {
            saw_violation = true;
            break;
        }
    }
    assert!(
        saw_violation,
        "malformed policy_blob.cohort_scope must default to Public + reject restricted claim"
    );
}

#[tokio::test]
async fn cohort_id_scope_consumer_check_now_works() {
    // v0.19.1 deferred the `Cohort{id}` consumer-side check pending
    // the persist read accessor. v0.19.6 lands it: the same
    // peer_metadata_for path drives both Family and Cohort{id}
    // membership lookup. Seed the remote with cohort_id "alpha";
    // an envelope claiming "alpha" admits, "beta" rejects.
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, remote_signer, local_key_id, _dir) = build_edge_with_remote_policy(
        &tmp,
        Some(serde_json::json!({
            "cohort_scope": {"kind": "cohort", "cohort_id": "alpha"}
        })),
    )
    .await;

    // Matching cohort_id admits.
    let mut rx = edge.events().subscribe_resources();
    dispatch(
        &edge,
        &remote_signer,
        &local_key_id,
        Some(CohortScope::Cohort {
            cohort_id: "alpha".to_string(),
        }),
    )
    .await
    .expect("dispatch alpha");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    while let Ok(ev) = rx.try_recv() {
        assert_ne!(
            ev.resource_kind.as_deref(),
            Some("cohort_scope_violation"),
            "matching cohort_id should NOT trigger violation"
        );
    }

    // Non-matching cohort_id rejects.
    let mut rx2 = edge.events().subscribe_resources();
    dispatch(
        &edge,
        &remote_signer,
        &local_key_id,
        Some(CohortScope::Cohort {
            cohort_id: "beta".to_string(),
        }),
    )
    .await
    .expect("dispatch beta");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut saw_violation = false;
    while let Ok(ev) = rx2.try_recv() {
        if ev.resource_kind.as_deref() == Some("cohort_scope_violation")
            && matches!(ev.kind, EventKind::ResourcePressure)
        {
            saw_violation = true;
            break;
        }
    }
    assert!(
        saw_violation,
        "non-matching cohort_id MUST trigger violation (v0.19.6 closes the v0.19.1-deferred arm)"
    );
}

#[tokio::test]
async fn edge_peer_cohort_scope_from_persist_accessor_returns_decoded() {
    // Direct accessor test — `Edge::peer_cohort_scope_from_persist`
    // returns the decoded `CohortScope` for the remote peer.
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, _remote_signer, _local_key_id, _dir) = build_edge_with_remote_policy(
        &tmp,
        Some(serde_json::json!({"cohort_scope": {"kind": "family"}})),
    )
    .await;
    let observed = edge.peer_cohort_scope_from_persist("remote-peer").await;
    assert_eq!(observed, Some(CohortScope::Family));
    let absent = edge.peer_cohort_scope_from_persist("never-seeded").await;
    assert_eq!(absent, None, "no row → None (defaults to Public at caller)");
}
