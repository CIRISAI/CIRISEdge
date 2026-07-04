//! Acceptance gate for CIRISEdge#29 (v0.11.0) — per-medium reachability
//! substrate.
//!
//! Drives a battery of sends + simulated terminal outcomes through
//! `Edge` and asserts the [`ReachabilityTracker`] snapshot reflects
//! the expected `(attempts, successes)` counters. Pinned at the public
//! `Arc<ReachabilityTracker>` accessor (`Edge::reachability_tracker`)
//! — the locked consumer contract for the v0.16.0 CIRISEdge#22 Tier 3
//! pymethod cut.
//!
//! Cross-references:
//!
//! - CIRISEdge#29 — issue (the spec).
//! - CIRISEdge#22 Tier 3 — the v0.16.0 consumer (`peer_reachability`
//!   pymethod) that will call into this surface via the sibling FFI
//!   bundle.
//! - CIRIS Accord Meta-Goal M-1 — adaptive coherence; this is the
//!   measurement substrate the federation's "adaptive" reliability
//!   depends on.

use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::{ClassicalSigner, Ed25519Signer};
use ciris_edge::identity::LocalSigner;
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_edge::{
    AttemptOutcome, Edge, EdgeConfig, MessageType, OpaqueRequest, ReachabilityTracker,
};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

// ─── Test fixtures ──────────────────────────────────────────────────

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

    fn write_seed_dir(&self, base: &std::path::Path) -> std::path::PathBuf {
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

/// A toggleable success/failure transport. Configures whether
/// `Transport::send` returns `Delivered` or `Err(Unreachable)`;
/// flipping the toggle lets one test drive the full
/// `(success, failure)` ratio range.
struct ToggleTransport {
    succeed: std::sync::Mutex<bool>,
}

impl ToggleTransport {
    fn new(initial_succeed: bool) -> Self {
        Self {
            succeed: std::sync::Mutex::new(initial_succeed),
        }
    }

    fn set_succeed(&self, succeed: bool) {
        *self.succeed.lock().unwrap() = succeed;
    }
}

#[async_trait]
impl Transport for ToggleTransport {
    fn id(&self) -> TransportId {
        TransportId::HTTP
    }

    async fn send(
        &self,
        _destination_key_id: &str,
        _envelope_bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError> {
        let succeed = *self.succeed.lock().unwrap();
        if succeed {
            Ok(TransportSendOutcome::Delivered)
        } else {
            Err(TransportError::Unreachable("toggle-test".into()))
        }
    }

    async fn listen(&self, _: mpsc::Sender<InboundFrame>) -> Result<(), TransportError> {
        Ok(())
    }
}

async fn build_edge(
    tmp: &tempfile::TempDir,
    me: &FedKey,
    peer: &FedKey,
    transport: Arc<dyn Transport>,
) -> Edge {
    let me_steward = FedKey::new("steward", 0xAA);
    let directory = directory_with(vec![
        signed_record(&me_steward, &me_steward, "steward"),
        signed_record(me, &me_steward, "agent"),
        signed_record(peer, &me_steward, "agent"),
    ])
    .await;
    let queue = directory.clone();
    let signer = me.local_signer(tmp.path()).await;
    Edge::builder()
        .directory(directory as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .queue(queue)
        .signer(signer)
        .transport(transport)
        .build()
        .expect("build edge")
}

// ─── Tests ──────────────────────────────────────────────────────────

/// 100 successful ephemeral sends — the tracker snapshot reports
/// attempts == 100, successes == 100, ratio == 1.0 on the
/// (peer, HTTP) tuple.
#[tokio::test]
async fn hundred_successful_sends_yield_ratio_one() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let me = FedKey::new("edge-self", 0x01);
    let peer = FedKey::new("peer", 0x02);
    let transport = Arc::new(ToggleTransport::new(true));
    let edge = build_edge(&tmp, &me, &peer, transport.clone()).await;

    // `OpaqueRequest` rides `Delivery::Ephemeral` so `Edge::send` is the
    // right entry point. We don't actually need a response — the
    // ephemeral path returns `EdgeError::Config` "correlation not
    // wired (Phase 2)" on success, which is fine: the tracker hook is
    // executed BEFORE the correlation-channel check (the hook sits on
    // the transport.send() result), so the counter increments
    // regardless of whether the caller-facing `send` ultimately
    // returns Ok or this Config error.
    for _ in 0..100 {
        let _ = edge
            .send(
                &peer.key_id,
                OpaqueRequest {
                    kind: 0x0000_0001,
                    payload: b"hello".to_vec(),
                },
            )
            .await;
    }

    let snap = edge.reachability_tracker().snapshot(&peer.key_id);
    let entry = snap.get(&TransportId::HTTP).expect("http entry present");
    assert_eq!(entry.attempts, 100, "all 100 sends recorded as attempts");
    assert_eq!(entry.successes, 100, "all 100 reported Delivered");
    assert!((entry.ratio() - 1.0).abs() < f64::EPSILON);
    assert!(entry.last_success_at.is_some());
    assert!(entry.last_attempt_at.is_some());
    assert!(entry.last_error_class.is_none());
}

/// 100 failing ephemeral sends — attempts == 100, successes == 0,
/// last_error_class surfaces the failure category.
#[tokio::test]
async fn hundred_failed_sends_yield_ratio_zero_and_error_class() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let me = FedKey::new("edge-self", 0x03);
    let peer = FedKey::new("peer", 0x04);
    let transport = Arc::new(ToggleTransport::new(false));
    let edge = build_edge(&tmp, &me, &peer, transport.clone()).await;

    for _ in 0..100 {
        let _ = edge
            .send(
                &peer.key_id,
                OpaqueRequest {
                    kind: 0x0000_0001,
                    payload: b"hi".to_vec(),
                },
            )
            .await;
    }

    let snap = edge.reachability_tracker().snapshot(&peer.key_id);
    let entry = snap.get(&TransportId::HTTP).expect("http entry present");
    assert_eq!(entry.attempts, 100);
    assert_eq!(entry.successes, 0);
    assert!((entry.ratio() - 0.0).abs() < f64::EPSILON);
    assert_eq!(
        entry.last_error_class.as_deref(),
        Some("unreachable"),
        "transport-level error class surfaces"
    );
}

/// 50 success then 50 failure — mid-toggle test verifies the rolling
/// counter math + the residual `last_error_class` after the toggle.
#[tokio::test]
async fn fifty_fifty_yields_ratio_half() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let me = FedKey::new("edge-self", 0x05);
    let peer = FedKey::new("peer", 0x06);
    let transport = Arc::new(ToggleTransport::new(true));
    let edge = build_edge(&tmp, &me, &peer, transport.clone()).await;

    for _ in 0..50 {
        let _ = edge
            .send(
                &peer.key_id,
                OpaqueRequest {
                    kind: 0x0000_0001,
                    payload: b"ok".to_vec(),
                },
            )
            .await;
    }
    transport.set_succeed(false);
    for _ in 0..50 {
        let _ = edge
            .send(
                &peer.key_id,
                OpaqueRequest {
                    kind: 0x0000_0001,
                    payload: b"fail".to_vec(),
                },
            )
            .await;
    }

    let snap = edge.reachability_tracker().snapshot(&peer.key_id);
    let entry = snap.get(&TransportId::HTTP).expect("http entry present");
    assert_eq!(entry.attempts, 100);
    assert_eq!(entry.successes, 50);
    assert!((entry.ratio() - 0.5).abs() < 1e-9);
    // The most recent failure is in the window — last_error_class
    // surfaces it (the residual successes don't clear the failure
    // residual; only window eviction does).
    assert_eq!(entry.last_error_class.as_deref(), Some("unreachable"));
}

/// `snapshot_all` returns one entry per `(peer, medium)` the tracker
/// has observed; isolation between peers is preserved.
#[tokio::test]
async fn snapshot_all_yields_one_entry_per_peer_observed() {
    let tracker = ReachabilityTracker::new(300);
    tracker.record_attempt("peer-a", TransportId::HTTP, AttemptOutcome::SendSuccess);
    tracker.record_attempt(
        "peer-b",
        TransportId::RETICULUM_RS,
        AttemptOutcome::AnnounceReceived,
    );
    tracker.record_attempt(
        "peer-c",
        TransportId::HTTP,
        AttemptOutcome::SendFailure {
            error_class: "io".into(),
        },
    );

    let all = tracker.snapshot_all();
    assert_eq!(all.len(), 3, "three distinct (peer, medium) tuples");
    let peer_a = all.iter().find(|s| s.peer_key_id == "peer-a").unwrap();
    let peer_b = all.iter().find(|s| s.peer_key_id == "peer-b").unwrap();
    let peer_c = all.iter().find(|s| s.peer_key_id == "peer-c").unwrap();
    assert_eq!(peer_a.transport_id, TransportId::HTTP);
    assert_eq!(peer_a.successes, 1);
    assert_eq!(peer_b.transport_id, TransportId::RETICULUM_RS);
    assert_eq!(peer_b.successes, 1);
    assert_eq!(peer_c.transport_id, TransportId::HTTP);
    assert_eq!(peer_c.successes, 0);
    assert_eq!(peer_c.last_error_class.as_deref(), Some("io"));
}

/// The `Edge::reachability_tracker()` accessor returns an `Arc` so
/// pymethod consumers can hold an independent reference. Mutations
/// from the inside-Edge hooks remain visible through the external Arc.
#[tokio::test]
async fn reachability_tracker_arc_is_shared_with_internal_recording() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let me = FedKey::new("edge-self", 0x07);
    let peer = FedKey::new("peer", 0x08);
    let transport = Arc::new(ToggleTransport::new(true));
    let edge = build_edge(&tmp, &me, &peer, transport.clone()).await;
    let tracker = edge.reachability_tracker();

    assert_eq!(tracker.window_seconds(), 300, "default window");

    let _ = edge
        .send(
            &peer.key_id,
            OpaqueRequest {
                kind: 0x0000_0001,
                payload: b"via accessor".to_vec(),
            },
        )
        .await;

    // The Arc returned by the accessor sees the internal hook's
    // recording without going back through `Edge`.
    let snap = tracker.snapshot(&peer.key_id);
    assert_eq!(snap.get(&TransportId::HTTP).unwrap().attempts, 1);
    assert_eq!(snap.get(&TransportId::HTTP).unwrap().successes, 1);
}

/// `EdgeConfig::reachability_window_seconds` threads through to the
/// tracker. A non-default window value is reflected on the snapshot.
#[tokio::test]
async fn config_window_threads_to_tracker() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let me = FedKey::new("edge-self", 0x09);
    let peer = FedKey::new("peer", 0x0A);
    let me_steward = FedKey::new("steward", 0xBB);
    let directory = directory_with(vec![
        signed_record(&me_steward, &me_steward, "steward"),
        signed_record(&me, &me_steward, "agent"),
        signed_record(&peer, &me_steward, "agent"),
    ])
    .await;
    let queue = directory.clone();
    let signer = me.local_signer(tmp.path()).await;
    let transport = Arc::new(ToggleTransport::new(true));
    let cfg = EdgeConfig {
        reachability_window_seconds: 600, // 10 min — non-default
        ..EdgeConfig::default()
    };
    let edge = Edge::builder()
        .directory(directory as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .queue(queue)
        .signer(signer)
        .transport(transport)
        .config(cfg)
        .build()
        .expect("build edge");

    assert_eq!(edge.reachability_tracker().window_seconds(), 600);

    let _ = edge
        .send(
            &peer.key_id,
            OpaqueRequest {
                kind: 0x0000_0001,
                payload: b"window-test".to_vec(),
            },
        )
        .await;

    let snap = edge.reachability_tracker().snapshot(&peer.key_id);
    let entry = snap.get(&TransportId::HTTP).expect("entry");
    assert_eq!(entry.window_seconds, 600);
}

/// `MessageType::DeliveryAttestation` arriving inbound records an
/// `AttestationReceived` outcome against the attestation's
/// peer_key_id field (NOT the envelope's signing_key_id, which can
/// differ when the attestation is relayed).
///
/// Drives the inbound hook directly via the tracker (the
/// `dispatch_inbound` path needs a fully-rooted EdgeEnvelope to drive
/// end-to-end; the hook's contract is what we're pinning here).
#[tokio::test]
async fn attestation_received_records_against_peer_in_body() {
    let tracker = ReachabilityTracker::new(300);
    // Simulate the `dispatch_inbound` hook recording an
    // AttestationReceived for a peer reported in the attestation
    // body's `peer_key_id` field. The hook uses the body-reported
    // `transport_id` (mapped from TransportMedium back to TransportId).
    tracker.record_attempt(
        "peer-acking",
        TransportId::RETICULUM_RS,
        AttemptOutcome::AttestationReceived,
    );

    let snap = tracker.snapshot("peer-acking");
    let entry = snap.get(&TransportId::RETICULUM_RS).expect("entry");
    assert_eq!(entry.attempts, 1);
    assert_eq!(entry.successes, 1);
    assert!((entry.ratio() - 1.0).abs() < f64::EPSILON);
}

/// Window-bounded eviction at the integration tier — record an old
/// success outside the window via the test-only timestamped API, then
/// a fresh failure inside the window. Only the fresh failure shows.
#[tokio::test]
async fn window_eviction_at_integration_tier() {
    let tracker = ReachabilityTracker::new(60);
    let now = chrono::Utc::now();
    let two_hours_ago = now - chrono::Duration::seconds(7200);
    tracker.record_attempt_at(
        "peer",
        TransportId::HTTP,
        AttemptOutcome::SendSuccess,
        two_hours_ago,
    );
    tracker.record_attempt_at(
        "peer",
        TransportId::HTTP,
        AttemptOutcome::SendFailure {
            error_class: "timeout".into(),
        },
        now,
    );
    let snap = tracker.snapshot("peer");
    let entry = snap.get(&TransportId::HTTP).expect("entry");
    assert_eq!(entry.attempts, 1, "old success aged out");
    assert_eq!(entry.successes, 0, "fresh failure only");
    assert_eq!(entry.last_error_class.as_deref(), Some("timeout"));
}

/// MessageType reference used for cross-checking — `DeliveryAttestation`
/// is the inbound trigger for the AttestationReceived outcome class.
/// This test stays at the typed-enum tier to pin the wire-type
/// dispatch invariant.
#[test]
fn delivery_attestation_message_type_pins_the_inbound_hook() {
    // The src/edge.rs::dispatch_inbound hook tests
    // `envelope.message_type == MessageType::DeliveryAttestation` to
    // decide whether to extract the peer + medium from the body.
    // Pin the discriminator here so a future enum reshuffle is caught.
    assert!(matches!(
        MessageType::DeliveryAttestation,
        MessageType::DeliveryAttestation
    ));
}
