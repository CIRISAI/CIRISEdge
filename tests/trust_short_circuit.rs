//! CIRISEdge#48-B (v0.19.6) — trust short-circuit at
//! `dispatch_inbound`. Verified envelopes whose `signing_key_id`
//! resolves below [`EdgeConfig::trust_threshold`] are dropped
//! AFTER verify and BEFORE handler dispatch; a moderation signal
//! (`EventKind::TrustShortCircuited`) fires on the resource channel
//! so lens-core can downweight the sender.
//!
//! Persist v3.4.0 (CIRISPersist#123) ships the
//! `TrustScoring + AdmissionGate + MemoryTrustScoring` triple; edge
//! consumes the `Arc<dyn TrustScoring>` directly via
//! `EdgeBuilder::trust_scoring(...)`. The
//! `MemoryTrustScoring::set_score` fixture is the test substrate.
//!
//! These tests use the same SQLite directory fixture pattern as
//! `tests/cohort_scope_refusal.rs` (post v0.19.6 rework).

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
use ciris_edge::{Edge, EdgeConfig, OpaqueEvent};
use ciris_persist::federation::{FederationDirectory, MemoryTrustScoring, TrustScoring};
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

/// Configured `EdgeConfig` for a trust-short-circuit fixture.
fn config_with_trust(threshold: f64, enabled: bool) -> EdgeConfig {
    EdgeConfig {
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        trust_threshold: threshold,
        trust_short_circuit_enabled: enabled,
        // The cohort_scope consumer-side check runs first; pin its
        // posture to `Off` so these tests measure only the
        // trust-short-circuit logic in isolation.
        cohort_scope_enforcement: ciris_edge::CohortScopeEnforcement::Off,
        ..EdgeConfig::default()
    }
}

/// Build an Edge wired with an optional `MemoryTrustScoring` and a
/// configurable `(threshold, enabled)` pair.
async fn build_edge(
    tmp: &tempfile::TempDir,
    threshold: f64,
    enabled: bool,
    scores: &[(&str, f64)],
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

    let mut memory_scorer = MemoryTrustScoring::new();
    for (k, v) in scores {
        memory_scorer.set_score(*k, *v);
    }
    let scorer_arc: Arc<dyn TrustScoring> = Arc::new(memory_scorer);

    let edge = Edge::builder()
        .directory(directory.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .queue(queue)
        .signer(local_signer)
        .transport(transport)
        .trust_scoring(scorer_arc)
        .config(config_with_trust(threshold, enabled))
        .build()
        .expect("build edge");
    (Arc::new(edge), remote_signer, local.key_id.clone())
}

/// Build an Edge with NO `trust_scoring` arc wired (verifies the
/// short-circuit is structurally disabled when the scorer is absent).
async fn build_edge_without_scorer(
    tmp: &tempfile::TempDir,
    threshold: f64,
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

    let edge = Edge::builder()
        .directory(directory.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .queue(queue)
        .signer(local_signer)
        .transport(transport)
        .config(config_with_trust(threshold, true))
        .build()
        .expect("build edge");
    (Arc::new(edge), remote_signer, local.key_id.clone())
}

async fn dispatch(
    edge: &Edge,
    sender: &LocalSigner,
    destination: &str,
) -> Result<(), ciris_edge::EdgeError> {
    let body = OpaqueEvent {
        kind: 1,
        payload: b"trust-test".to_vec(),
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
async fn inbound_below_threshold_dropped() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Threshold 0.5, sender at 0.2 → dropped.
    let (edge, remote_signer, local_key_id) =
        build_edge(&tmp, 0.5, true, &[("remote-peer", 0.2)]).await;
    let mut rx = edge.events().subscribe_resources();
    let m_before = edge.metrics().inbound_dropped_low_trust();
    dispatch(&edge, &remote_signer, &local_key_id)
        .await
        .expect("dispatch");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        edge.metrics().inbound_dropped_low_trust(),
        m_before + 1,
        "below-threshold envelope must increment the drop counter"
    );
    let mut saw_event = false;
    while let Ok(ev) = rx.try_recv() {
        if matches!(ev.kind, EventKind::TrustShortCircuited) {
            saw_event = true;
            assert_eq!(
                ev.peer_key_id.as_deref(),
                Some("remote-peer"),
                "moderation signal carries the offender key_id"
            );
            assert_eq!(
                ev.measurement,
                Some(0.2),
                "measurement is the observed score"
            );
            assert!(
                ev.message.contains("0.5"),
                "threshold rides on message: got {}",
                ev.message
            );
            break;
        }
    }
    assert!(
        saw_event,
        "expected TrustShortCircuited event on resource channel"
    );
}

#[tokio::test]
async fn inbound_above_threshold_dispatched() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Threshold 0.5, sender at 0.8 → admitted.
    let (edge, remote_signer, local_key_id) =
        build_edge(&tmp, 0.5, true, &[("remote-peer", 0.8)]).await;
    let m_before = edge.metrics().inbound_dropped_low_trust();
    dispatch(&edge, &remote_signer, &local_key_id)
        .await
        .expect("dispatch");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        edge.metrics().inbound_dropped_low_trust(),
        m_before,
        "above-threshold envelope must NOT increment the drop counter"
    );
}

#[tokio::test]
async fn inbound_at_threshold_dispatched() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Threshold 0.5, sender exactly at 0.5 → admitted (the
    // short-circuit condition is `score < threshold`, strict <).
    let (edge, remote_signer, local_key_id) =
        build_edge(&tmp, 0.5, true, &[("remote-peer", 0.5)]).await;
    let m_before = edge.metrics().inbound_dropped_low_trust();
    dispatch(&edge, &remote_signer, &local_key_id)
        .await
        .expect("dispatch");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        edge.metrics().inbound_dropped_low_trust(),
        m_before,
        "boundary score == threshold must admit, not drop"
    );
}

#[tokio::test]
async fn trust_score_default_zero_with_zero_threshold_allows_all() {
    // Bootstrap-permissive shape: threshold 0.0, scorer wired but
    // returns 0.0 for known keys + KeyNotFound for unknowns. The
    // short-circuit code path GATES on `trust_threshold > 0.0`, so
    // 0.0 must skip the scoring call entirely.
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, remote_signer, local_key_id) =
        build_edge(&tmp, 0.0, true, &[("remote-peer", 0.0)]).await;
    let m_before = edge.metrics().inbound_dropped_low_trust();
    dispatch(&edge, &remote_signer, &local_key_id)
        .await
        .expect("dispatch");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        edge.metrics().inbound_dropped_low_trust(),
        m_before,
        "threshold 0.0 must short-circuit to admit BEFORE calling the resolver"
    );
}

#[tokio::test]
async fn disabled_flag_overrides_threshold_check() {
    // Even with threshold 1.0 (would normally reject everyone), the
    // `enabled = false` flag must skip the check entirely.
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, remote_signer, local_key_id) =
        build_edge(&tmp, 1.0, false, &[("remote-peer", 0.0)]).await;
    let m_before = edge.metrics().inbound_dropped_low_trust();
    dispatch(&edge, &remote_signer, &local_key_id)
        .await
        .expect("dispatch");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        edge.metrics().inbound_dropped_low_trust(),
        m_before,
        "disabled flag MUST override threshold; no drop"
    );
}

#[tokio::test]
async fn dropped_inbound_emits_moderation_signal_on_event_bus() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, remote_signer, local_key_id) =
        build_edge(&tmp, 0.5, true, &[("remote-peer", 0.1)]).await;
    let mut rx = edge.events().subscribe_resources();
    dispatch(&edge, &remote_signer, &local_key_id)
        .await
        .expect("dispatch");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut saw_kind = false;
    let mut saw_resource_kind = false;
    while let Ok(ev) = rx.try_recv() {
        if matches!(ev.kind, EventKind::TrustShortCircuited) {
            saw_kind = true;
            if ev.resource_kind.as_deref() == Some("trust_short_circuit") {
                saw_resource_kind = true;
            }
        }
    }
    assert!(saw_kind, "EventKind::TrustShortCircuited must fire");
    assert!(
        saw_resource_kind,
        "resource_kind tag must be 'trust_short_circuit' for lens-core grep"
    );
}

#[tokio::test]
async fn dropped_inbound_increments_metrics_counter() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, remote_signer, local_key_id) =
        build_edge(&tmp, 0.5, true, &[("remote-peer", 0.1)]).await;
    let snap_before = edge.metrics().snapshot();
    dispatch(&edge, &remote_signer, &local_key_id)
        .await
        .expect("dispatch");
    dispatch(&edge, &remote_signer, &local_key_id)
        .await
        .expect("dispatch");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let snap_after = edge.metrics().snapshot();
    assert_eq!(
        snap_after.inbound_dropped_low_trust,
        snap_before.inbound_dropped_low_trust + 2,
        "snapshot must reflect both drops"
    );
}

#[tokio::test]
async fn no_scorer_wired_disables_short_circuit() {
    // Threshold raised to 1.0 BUT no `trust_scoring` arc wired.
    // The short-circuit must stay structurally disabled (the
    // bootstrap-permissive cohabitation posture for v0.19.6).
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, remote_signer, local_key_id) = build_edge_without_scorer(&tmp, 1.0).await;
    let m_before = edge.metrics().inbound_dropped_low_trust();
    dispatch(&edge, &remote_signer, &local_key_id)
        .await
        .expect("dispatch");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        edge.metrics().inbound_dropped_low_trust(),
        m_before,
        "absent scorer must structurally disable the short-circuit"
    );
}

#[tokio::test]
async fn typed_error_variant_carries_score_threshold() {
    // Exercise the `EdgeError::TrustShortCircuit` discriminant at
    // construction time. The dispatch-inbound path itself returns
    // unit (the error is logged + projected through the event bus),
    // but the typed variant is the wire-string contract surface
    // downstream UniFFI / PyO3 consumers grep on.
    let err = ciris_edge::EdgeError::TrustShortCircuit {
        signing_key_id: "rogue".to_string(),
        score: 0.1,
        threshold: 0.5,
    };
    let msg = format!("{err}");
    assert!(msg.contains("rogue"), "key_id rides on the Display: {msg}");
    assert!(msg.contains("0.1"), "score rides on the Display: {msg}");
    assert!(msg.contains("0.5"), "threshold rides on the Display: {msg}");
    assert!(
        msg.contains("48-B"),
        "issue tag rides on the Display: {msg}"
    );
}

// ─── CIRISEdge#208 — runtime override surface ──────────────────────

/// `set_trust_threshold_override(Some(t))` flips the trust short-circuit
/// ON for the duration of the override AND raises the effective threshold
/// even when `EdgeConfig::trust_threshold = 0.0` (the bootstrap-permissive
/// default). The conformance harness drives the intake-gate test through
/// this codepath via `PyEdge::set_trust_threshold`.
#[tokio::test]
async fn override_threshold_drops_envelope_under_zero_default_threshold() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Build with config threshold = 0.0 (bootstrap-permissive default);
    // sender scored at 0.2. Production posture: the envelope is admitted.
    let (edge, remote_signer, local_key_id) =
        build_edge(&tmp, 0.0, true, &[("remote-peer", 0.2)]).await;
    let m_before = edge.metrics().inbound_dropped_low_trust();

    // Install a 0.5 override — now the envelope must drop because the
    // override forces `trust_short_circuit_enabled = true` AND
    // `effective_threshold = 0.5 > 0.2 (sender's score)`.
    edge.set_trust_threshold_override(Some(0.5));

    let outcome = build_outcome(&edge, &remote_signer, &local_key_id).await;
    assert_eq!(
        outcome, "trust_short_circuited",
        "override threshold 0.5 must short-circuit a sender scored 0.2"
    );
    assert_eq!(
        edge.metrics().inbound_dropped_low_trust(),
        m_before + 1,
        "override threshold drop must increment the metrics counter"
    );

    // Clearing the override restores the bootstrap-permissive posture.
    edge.set_trust_threshold_override(None);
    let after = build_outcome(&edge, &remote_signer, &local_key_id).await;
    assert_eq!(
        after, "received",
        "clearing the override returns to config.trust_threshold = 0.0 (admit-all)"
    );
}

/// `install_trust_scoring_override(Some(scorer))` overrides the builder-
/// wired scorer for the duration of the override. Pairs with
/// `set_trust_threshold_override` so the harness can drive a Python
/// callback as the scorer without re-building the Edge.
#[tokio::test]
async fn override_scorer_supersedes_builder_wired_scorer() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Builder wires a scorer that VOUCHES for the remote at 0.9.
    let (edge, remote_signer, local_key_id) =
        build_edge(&tmp, 0.5, true, &[("remote-peer", 0.9)]).await;
    let m_before = edge.metrics().inbound_dropped_low_trust();

    // Override with a scorer that DENIES the remote (0.1).
    let mut overriding = MemoryTrustScoring::new();
    overriding.set_score("remote-peer", 0.1);
    let overriding_arc: Arc<dyn TrustScoring> = Arc::new(overriding);
    edge.install_trust_scoring_override(Some(overriding_arc));

    let outcome = build_outcome(&edge, &remote_signer, &local_key_id).await;
    assert_eq!(
        outcome, "trust_short_circuited",
        "the override scorer (0.1) must supersede the builder-wired scorer (0.9)"
    );
    assert_eq!(
        edge.metrics().inbound_dropped_low_trust(),
        m_before + 1,
        "override scorer drop must increment the metrics counter"
    );

    // Clearing the override returns to the builder-wired scorer (0.9 ≥ 0.5).
    edge.install_trust_scoring_override(None);
    let after = build_outcome(&edge, &remote_signer, &local_key_id).await;
    assert_eq!(
        after, "received",
        "clearing the scorer override returns to the builder-wired scorer"
    );
}

/// `dispatch_inbound_observed_outcome_for_test` returns "verify_failed"
/// when the envelope is dropped at the verify pipeline (signature
/// failure, misroute, replay, body-too-large) — the third arm of the
/// wire-string outcome triple.
#[tokio::test]
async fn observed_outcome_returns_verify_failed_for_misrouted_envelope() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (edge, remote_signer, _local_key_id) =
        build_edge(&tmp, 0.0, true, &[("remote-peer", 0.5)]).await;

    // Misroute: address an envelope to a key_id that ISN'T the local
    // signer's. The verify pipeline rejects at AV-8 (Misrouted).
    let outcome = build_outcome(&edge, &remote_signer, "not-the-local-key").await;
    assert_eq!(
        outcome, "verify_failed",
        "misrouted envelope must surface as verify_failed (neither trust drop nor handler dispatch)"
    );
}

/// CIRISEdge#211 — the conformance harness mints senders from raw seed
/// bytes via `Ed25519SoftwareSigner::import_key` (the same path
/// `PyEdge::build_signed_inbound_envelope` takes). This test mirrors the
/// Python flow EXACTLY using `Ed25519SoftwareSigner`, not the
/// `Ed25519Signer::from_seed` path the other tests use, and verifies the
/// trust gate fires through the same codepath the harness's
/// `dispatch_inbound_bytes` will hit.
#[tokio::test]
async fn build_signed_envelope_from_software_signer_drives_trust_gate() {
    use ciris_keyring::Ed25519SoftwareSigner;

    let tmp = tempfile::tempdir().expect("tempdir");
    // Builder wires `remote-peer` at 0.2 (below threshold 0.5). The seed
    // here is the same one persist's `FedKey::new("remote-peer", 0xAA)`
    // uses (0xAA repeating × 32) so the pubkey registered in
    // `federation_keys` matches the pubkey the software signer derives
    // from this seed.
    let (edge, _ignore_remote_signer, local_key_id) =
        build_edge(&tmp, 0.5, true, &[("remote-peer", 0.2)]).await;

    // Re-build the sender via the software-signer path (the harness's
    // path), not the `FedKey::local_signer` path.
    let seed = [0xAAu8; 32];
    let mut sw = Ed25519SoftwareSigner::new("remote-peer");
    sw.import_key(&seed).expect("import seed");
    let signer = LocalSigner::new(
        "remote-peer".to_string(),
        Arc::new(sw) as Arc<dyn ciris_keyring::HardwareSigner>,
        None,
    );

    // Build → sign → serialize: byte-for-byte what
    // `PyEdge::build_signed_inbound_envelope` produces.
    let body = OpaqueEvent {
        kind: 1,
        payload: b"211-software-signer-test".to_vec(),
    };
    let mut env = build_envelope(
        OpaqueEvent::TYPE,
        &signer.key_id,
        &local_key_id,
        &body,
        None,
    )
    .expect("build envelope");
    sign_envelope(&signer, &mut env)
        .await
        .expect("sign envelope");
    let bytes = serde_json::to_vec(&env).expect("serialize envelope");

    // Drive through `dispatch_inbound_bytes`'s underlying helper.
    let m_before = edge.metrics().inbound_dropped_low_trust();
    let frame = InboundFrame {
        envelope_bytes: bytes,
        transport: TransportId::HTTP,
        received_at: Utc::now(),
        source_key_id: None,
    };
    let outcome = edge.dispatch_inbound_observed_outcome_for_test(frame).await;

    // The trust gate must fire: the harness's hand-rolled envelope (in
    // Python) couldn't pass verify in #211's repro; THIS path proves the
    // software-signer build pipeline DOES pass verify and reach the
    // trust short-circuit. If this test ever regresses to
    // "verify_failed", `build_signed_inbound_envelope` is broken at the
    // canonicalization layer.
    assert_eq!(
        outcome, "trust_short_circuited",
        "software-signer envelope must pass verify + trip the trust gate \
         (sender 0.2 < threshold 0.5)"
    );
    assert_eq!(
        edge.metrics().inbound_dropped_low_trust(),
        m_before + 1,
        "low-trust drop counter must increment"
    );
}

/// Helper: build + sign an envelope, drive through the observed-outcome
/// dispatcher, return the wire-string outcome.
async fn build_outcome(edge: &Edge, sender: &LocalSigner, destination: &str) -> &'static str {
    let body = OpaqueEvent {
        kind: 1,
        payload: b"208-override-test".to_vec(),
    };
    let mut env = build_envelope(OpaqueEvent::TYPE, &sender.key_id, destination, &body, None)
        .expect("build envelope");
    sign_envelope(sender, &mut env)
        .await
        .expect("sign envelope");
    let bytes = serde_json::to_vec(&env).expect("serialize envelope");
    let frame = InboundFrame {
        envelope_bytes: bytes,
        transport: TransportId::HTTP,
        received_at: Utc::now(),
        source_key_id: None,
    };
    edge.dispatch_inbound_observed_outcome_for_test(frame).await
}
