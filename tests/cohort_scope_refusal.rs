//! CIRISEdge#48-A (v0.19.1) — cohort_scope refusal at
//! outbound_enqueue + consumer-side symmetric check.
//!
//! Producer-side: edge owns the wire-format locality dividend at the
//! outbound boundary. `Delivery::Federation` / `Delivery::Mandatory`
//! refuse to fan out any restricted scope (`SelfOnly` / `Family` /
//! `Cohort`); point-to-point (`Ephemeral` / `Durable`) refuse when the
//! recipient is not authorized for the scope.
//!
//! Consumer-side: `dispatch_inbound` refuses inbound envelopes whose
//! claimed `SelfOnly` / `Family` scope doesn't match the sender's
//! directory-recorded scope; emits a moderation-signal event.

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
use ciris_edge::outbound::{PeerDirectory, StewardDirectory, StewardKey};
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_edge::verify::HybridPolicy;
use ciris_edge::{
    CohortScope, CohortScopeEnforcement, Edge, EdgeConfig, EdgeError, FederationAnnouncement,
    InlineText, InlineTextDurable, StewardDirective,
};
use ciris_persist::federation::types::PeerPolicyBlob;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

// ─── Fixtures ───────────────────────────────────────────────────────

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

/// No-op transport — enough for outbound enforcement tests that
/// refuse BEFORE the transport call.
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

/// Static peer-directory stub for `send_mandatory` fan-out tests.
struct StaticPeerDir {
    peers: Vec<String>,
}

#[async_trait]
impl PeerDirectory for StaticPeerDir {
    async fn list_recipients(&self) -> Result<Vec<String>, ciris_persist::outbound::Error> {
        Ok(self.peers.clone())
    }
}

/// Static steward-directory stub for `send_federation` fan-out tests.
struct StaticStewardDir {
    stewards: Vec<StewardKey>,
}

#[async_trait]
impl StewardDirectory for StaticStewardDir {
    async fn current_stewards(&self) -> Result<Vec<StewardKey>, ciris_persist::outbound::Error> {
        Ok(self.stewards.clone())
    }
}

fn config_with_enforcement(mode: CohortScopeEnforcement) -> EdgeConfig {
    EdgeConfig {
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        cohort_scope_enforcement: mode,
        ..EdgeConfig::default()
    }
}

/// Build an Edge wired with peer/steward directories so the
/// federation-class / mandatory-class fan-out tests reach
/// outbound_enqueue.
async fn build_edge_with_directories(
    tmp: &tempfile::TempDir,
    enforcement: CohortScopeEnforcement,
    extra_peers: Vec<String>,
) -> (Arc<Edge>, String, String) {
    let steward = FedKey::new("steward-fed", 0x01);
    let local = FedKey::new("local-self", 0xBB);
    let peer_family = FedKey::new("remote-family", 0xAA);
    let peer_public = FedKey::new("remote-public", 0xCC);

    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&local, &steward, "agent"),
        signed_record(&peer_family, &steward, "agent"),
        signed_record(&peer_public, &steward, "agent"),
    ])
    .await;
    let queue = directory.clone();
    let local_signer = local.local_signer(tmp.path()).await;

    let peer_dir_stub: Arc<dyn PeerDirectory> = Arc::new(StaticPeerDir {
        peers: {
            let mut p = vec![peer_family.key_id.clone(), peer_public.key_id.clone()];
            p.extend(extra_peers);
            p
        },
    });
    let steward_dir_stub: Arc<dyn StewardDirectory> = Arc::new(StaticStewardDir {
        stewards: vec![StewardKey {
            key_id: steward.key_id.clone(),
            identity_ref: steward.key_id.clone(),
        }],
    });

    // v0.19.6 (CIRISEdge#48-A completion) — declare the family peer's
    // cohort_scope via persist's `add_peer_record` + `update_peer_policy`.
    // The v0.19.1 in-process `declare_peer_cohort_scope` shim is removed;
    // the persist directory is the single source of truth.
    directory
        .add_peer_record(
            &peer_family.key_id,
            &peer_family.pubkey_b64(),
            ciris_persist::federation::types::identity_type::AGENT,
            None,
        )
        .await
        .expect("add_peer_record family");
    directory
        .update_peer_policy(
            &peer_family.key_id,
            PeerPolicyBlob::new(serde_json::json!({"cohort_scope": {"kind": "family"}})),
        )
        .await
        .expect("update_peer_policy family");
    let federation_directory_dyn: Arc<dyn FederationDirectory> = directory.clone();
    let transport: Arc<dyn Transport> = Arc::new(NopTransport);
    let edge = Edge::builder()
        .directory(directory.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .federation_directory(federation_directory_dyn)
        .queue(queue)
        .signer(local_signer)
        .transport(transport)
        .peer_directory(peer_dir_stub)
        .steward_directory(steward_dir_stub)
        .config(config_with_enforcement(enforcement))
        .build()
        .expect("build edge");
    let edge = Arc::new(edge);
    (edge, peer_family.key_id, peer_public.key_id)
}

// ─── Producer-side: Federation-class delivery refusal ───────────────

fn fixture_announcement() -> FederationAnnouncement {
    FederationAnnouncement {
        priority: ciris_edge::AnnouncementPriority::Informational,
        kind: ciris_edge::AnnouncementKind::PolicyUpdate,
        title: "Test".to_string(),
        body: "body".to_string(),
        authority_class: ciris_edge::AuthorityClass::BootstrapSeed,
        accord_payload: None,
        supersedes: None,
        expires_at: Utc::now() + chrono::Duration::hours(1),
        evidence_refs: Vec::new(),
        accord_signatures: Vec::new(),
    }
}

fn fixture_steward_directive() -> StewardDirective {
    StewardDirective {
        title: "Test".to_string(),
        body: "body".to_string(),
    }
}

#[tokio::test]
async fn federation_delivery_with_self_scope_rejected() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, _fam, _pub_) =
        build_edge_with_directories(&tmp, CohortScopeEnforcement::Strict, vec![]).await;
    let err = edge
        .send_federation_with_cohort_scope(
            fixture_steward_directive(),
            None,
            Some(CohortScope::SelfOnly),
        )
        .await
        .expect_err("locality scope MUST refuse federation fan-out");
    assert!(
        matches!(
            err,
            EdgeError::CohortScopeRefusedFederation {
                cohort_scope: CohortScope::SelfOnly
            }
        ),
        "expected CohortScopeRefusedFederation(SelfOnly); got {err:?}"
    );
}

#[tokio::test]
async fn federation_delivery_with_family_scope_rejected() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, _fam, _pub_) =
        build_edge_with_directories(&tmp, CohortScopeEnforcement::Strict, vec![]).await;
    let err = edge
        .send_federation_with_cohort_scope(
            fixture_steward_directive(),
            None,
            Some(CohortScope::Family),
        )
        .await
        .expect_err("Family scope MUST refuse federation fan-out");
    assert!(
        matches!(
            err,
            EdgeError::CohortScopeRefusedFederation {
                cohort_scope: CohortScope::Family
            }
        ),
        "expected CohortScopeRefusedFederation(Family); got {err:?}"
    );
}

#[tokio::test]
async fn federation_delivery_with_public_scope_allowed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, _fam, _pub_) =
        build_edge_with_directories(&tmp, CohortScopeEnforcement::Strict, vec![]).await;
    let handles = edge
        .send_federation_with_cohort_scope(
            fixture_steward_directive(),
            None,
            Some(CohortScope::Public),
        )
        .await
        .expect("Public scope MUST allow federation fan-out");
    assert!(
        !handles.is_empty(),
        "fan-out should produce at least one handle"
    );
}

// ─── Producer-side: Mandatory-class refusal ─────────────────────────

#[tokio::test]
async fn mandatory_delivery_with_self_scope_rejected() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, _fam, _pub_) =
        build_edge_with_directories(&tmp, CohortScopeEnforcement::Strict, vec![]).await;
    let err = edge
        .send_mandatory_with_cohort_scope(fixture_announcement(), Some(CohortScope::SelfOnly))
        .await
        .expect_err("SelfOnly MUST refuse mandatory broadcast");
    assert!(
        matches!(
            err,
            EdgeError::CohortScopeRefusedMandatory {
                cohort_scope: CohortScope::SelfOnly
            }
        ),
        "expected CohortScopeRefusedMandatory(SelfOnly); got {err:?}"
    );
}

#[tokio::test]
async fn mandatory_delivery_with_family_scope_rejected() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, _fam, _pub_) =
        build_edge_with_directories(&tmp, CohortScopeEnforcement::Strict, vec![]).await;
    let err = edge
        .send_mandatory_with_cohort_scope(fixture_announcement(), Some(CohortScope::Family))
        .await
        .expect_err("Family scope MUST refuse mandatory broadcast");
    assert!(
        matches!(
            err,
            EdgeError::CohortScopeRefusedMandatory {
                cohort_scope: CohortScope::Family
            }
        ),
        "expected CohortScopeRefusedMandatory(Family); got {err:?}"
    );
}

// ─── Producer-side: point-to-point recipient check ──────────────────

#[tokio::test]
async fn durable_delivery_with_family_scope_to_family_recipient_allowed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, fam_recipient, _pub_) =
        build_edge_with_directories(&tmp, CohortScopeEnforcement::Strict, vec![]).await;
    let handle = edge
        .send_durable_with_cohort_scope(
            &fam_recipient,
            InlineTextDurable {
                text: "x".to_string(),
            },
            Some(CohortScope::Family),
        )
        .await
        .expect("family recipient MUST accept Family-scope durable");
    // The handle exists; that's the success observable.
    let _ = handle;
}

#[tokio::test]
async fn durable_delivery_with_family_scope_to_non_family_recipient_rejected() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, _fam, pub_recipient) =
        build_edge_with_directories(&tmp, CohortScopeEnforcement::Strict, vec![]).await;
    let err = edge
        .send_durable_with_cohort_scope(
            &pub_recipient,
            InlineTextDurable {
                text: "x".to_string(),
            },
            Some(CohortScope::Family),
        )
        .await
        .expect_err("non-family recipient MUST refuse Family-scope durable");
    match err {
        EdgeError::CohortScopeRefusedRecipient {
            cohort_scope: CohortScope::Family,
            recipient_key_id,
        } => assert_eq!(recipient_key_id, pub_recipient),
        other => {
            panic!("expected CohortScopeRefusedRecipient(Family, {pub_recipient}); got {other:?}")
        }
    }
}

#[tokio::test]
async fn ephemeral_delivery_with_family_scope_to_family_recipient_allowed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, fam_recipient, _pub_) =
        build_edge_with_directories(&tmp, CohortScopeEnforcement::Strict, vec![]).await;
    // `send` returns Err because ephemeral request-response correlation
    // is not wired (Phase 2 TODO in edge.rs); the cohort_scope check
    // must NOT block the call before reaching that point — the error
    // we want to see is the Config(Phase 2) wire, NOT a
    // CohortScopeRefused.
    let err = edge
        .send_with_cohort_scope(
            &fam_recipient,
            InlineText {
                text: "x".to_string(),
            },
            Some(CohortScope::Family),
        )
        .await
        .expect_err("ephemeral request-response returns Phase-2 error");
    match err {
        EdgeError::CohortScopeRefusedRecipient { .. } => {
            panic!("family recipient must NOT trigger cohort_scope refusal");
        }
        EdgeError::Config(msg) => {
            assert!(
                msg.contains("Phase 2") || msg.contains("correlation"),
                "expected Phase 2 message; got {msg}"
            );
        }
        // Transport-shaped errors are also acceptable — the test's
        // point is that we DON'T see a CohortScopeRefusedRecipient.
        EdgeError::Transport(_) | EdgeError::Unreachable(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

// ─── Consumer-side ──────────────────────────────────────────────────

/// Helper: sign + dispatch a synthetic envelope through the public
/// `dispatch_inbound_for_test` surface.
async fn dispatch_with_cohort_scope(
    edge: &Edge,
    sender: &LocalSigner,
    destination: &str,
    cohort_scope: Option<CohortScope>,
) -> Result<(), EdgeError> {
    let body = InlineText {
        text: "scope-test".to_string(),
    };
    let mut env = build_envelope(InlineText::TYPE, &sender.key_id, destination, &body, None)?;
    env.cohort_scope = cohort_scope;
    sign_envelope(sender, &mut env).await?;
    let bytes =
        serde_json::to_vec(&env).map_err(|e| EdgeError::Config(format!("serialize: {e}")))?;
    let frame = InboundFrame {
        envelope_bytes: bytes,
        transport: TransportId::HTTP,
        received_at: Utc::now(),
        source_key_id: None,
    };
    edge.dispatch_inbound_for_test(frame).await;
    Ok(())
}

async fn build_edge_with_remote_peer(
    tmp: &tempfile::TempDir,
    enforcement: CohortScopeEnforcement,
    declare_remote_as_family: bool,
) -> (Arc<Edge>, Arc<LocalSigner>, String) {
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

    // v0.19.6 (CIRISEdge#48-A completion) — seed remote's cohort_scope
    // via persist's `update_peer_policy`. The persist-backed
    // `peer_metadata_for` lookup at `dispatch_inbound` is the source
    // of truth; `declare_peer_cohort_scope` is removed.
    if declare_remote_as_family {
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
            .update_peer_policy(
                &remote.key_id,
                PeerPolicyBlob::new(serde_json::json!({"cohort_scope": {"kind": "family"}})),
            )
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
        .config(config_with_enforcement(enforcement))
        .build()
        .expect("build edge");
    let edge = Arc::new(edge);
    (edge, remote_signer, local.key_id.clone())
}

#[tokio::test]
async fn inbound_with_family_scope_from_authorized_sender_dispatched() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, remote_signer, local_key_id) =
        build_edge_with_remote_peer(&tmp, CohortScopeEnforcement::Strict, true).await;
    // No tracing assertion needed — the test passes if dispatch
    // does not panic AND no `cohort_scope_violation` event fires.
    let mut resource_rx = edge.events().subscribe_resources();
    dispatch_with_cohort_scope(
        &edge,
        &remote_signer,
        &local_key_id,
        Some(CohortScope::Family),
    )
    .await
    .expect("dispatch");
    // Drain the channel briefly — must not see a cohort_scope_violation.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    while let Ok(ev) = resource_rx.try_recv() {
        assert!(
            !ev.resource_kind
                .as_deref()
                .unwrap_or("")
                .contains("cohort_scope_violation"),
            "no violation event expected; got {ev:?}"
        );
    }
}

#[tokio::test]
async fn inbound_with_family_scope_from_unauthorized_sender_rejected_with_cohort_scope_violation() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, remote_signer, local_key_id) =
        build_edge_with_remote_peer(&tmp, CohortScopeEnforcement::Strict, false).await;
    let mut resource_rx = edge.events().subscribe_resources();
    dispatch_with_cohort_scope(
        &edge,
        &remote_signer,
        &local_key_id,
        Some(CohortScope::Family),
    )
    .await
    .expect("dispatch");
    // Allow the broadcast event to land.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut saw_violation = false;
    while let Ok(ev) = resource_rx.try_recv() {
        if ev.resource_kind.as_deref().unwrap_or("") == "cohort_scope_violation" {
            saw_violation = true;
            break;
        }
    }
    assert!(
        saw_violation,
        "expected cohort_scope_violation resource event on consumer-side reject"
    );
}

#[tokio::test]
async fn inbound_emits_moderation_signal_on_cohort_scope_violation() {
    // The moderation-signal observable IS the ResourceEvent named
    // `cohort_scope_violation` per the consumer-side enforcement
    // hook. Confirm the kind tag is `ResourceUpdated` (the resource
    // event family lens-core monitors).
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, remote_signer, local_key_id) =
        build_edge_with_remote_peer(&tmp, CohortScopeEnforcement::Strict, false).await;
    let mut resource_rx = edge.events().subscribe_resources();
    dispatch_with_cohort_scope(
        &edge,
        &remote_signer,
        &local_key_id,
        Some(CohortScope::SelfOnly),
    )
    .await
    .expect("dispatch");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut saw_event = false;
    while let Ok(ev) = resource_rx.try_recv() {
        if ev.resource_kind.as_deref().unwrap_or("") == "cohort_scope_violation" {
            saw_event = true;
            assert!(
                matches!(ev.kind, EventKind::ResourcePressure),
                "moderation signal should be ResourcePressure; got {:?}",
                ev.kind
            );
            break;
        }
    }
    assert!(
        saw_event,
        "expected moderation-signal event for SelfOnly violation"
    );
}

// ─── Config modes ───────────────────────────────────────────────────

#[tokio::test]
async fn warn_only_mode_logs_but_allows() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, _fam, _pub_) =
        build_edge_with_directories(&tmp, CohortScopeEnforcement::WarnOnly, vec![]).await;
    // Federation fan-out with Family scope — would refuse in Strict
    // mode, but WarnOnly must allow + warn.
    let handles = edge
        .send_federation_with_cohort_scope(
            fixture_steward_directive(),
            None,
            Some(CohortScope::Family),
        )
        .await
        .expect("WarnOnly mode must allow Family-scope federation fan-out");
    assert!(
        !handles.is_empty(),
        "WarnOnly mode must still produce handles for federation fan-out"
    );
}

#[tokio::test]
async fn off_mode_disables_enforcement() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, _fam, pub_recipient) =
        build_edge_with_directories(&tmp, CohortScopeEnforcement::Off, vec![]).await;
    // Point-to-point Family scope to a non-family recipient — Off
    // mode skips the recipient check entirely.
    let _ = edge
        .send_durable_with_cohort_scope(
            &pub_recipient,
            InlineTextDurable {
                text: "x".to_string(),
            },
            Some(CohortScope::Family),
        )
        .await
        .expect("Off mode must skip cohort_scope refusal entirely");
}

#[test]
fn strict_mode_is_default() {
    let cfg = EdgeConfig::default();
    assert_eq!(
        cfg.cohort_scope_enforcement,
        CohortScopeEnforcement::Strict,
        "wire-format invariant: default MUST be Strict per CIRISEdge#48-A"
    );
}
