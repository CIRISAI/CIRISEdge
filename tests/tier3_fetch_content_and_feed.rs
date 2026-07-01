//! CIRISEdge#22 Tier 3 — Rust-side acceptance for the three Edge
//! primitives the PyO3 surface wraps:
//!
//! 1. `Edge::fetch_content` — content-addressable fetch + pending-
//!    correlation by `body.sha256`.
//! 2. `Edge::subscribe_verified_feed` — broadcast channel carrying
//!    every verified envelope.
//! 3. `Edge::reachability_tracker` — already covered by
//!    `reachability_integration.rs`; the surface check here just
//!    confirms the snapshot ratio shape.
//!
//! The PyO3 surface (`PyEdge::peer_reachability` /
//! `PyEdge::fetch_content` / `PyEdge::subscribe_feed`) lives at
//! `src/ffi/pyo3.rs` — these tests exercise the underlying Edge
//! primitives the pymethods call into.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::{ClassicalSigner, Ed25519Signer};
use ciris_edge::identity::{build_envelope, sign_envelope, LocalSigner};
use ciris_edge::messages::{ContentBody, OpaqueEvent};
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_edge::verify::HybridPolicy;
use ciris_edge::{
    AttemptOutcome, ContentResult, Edge, EdgeConfig, Message, MessageType, OutboundHandle,
};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{Backend, FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

// ─── Test fixtures (same pattern as content_fetch.rs) ────────────────

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

    async fn local_signer(&self, base: &std::path::Path) -> Arc<LocalSigner> {
        let dir = base.join(format!("seed-{}", self.key_id));
        std::fs::create_dir_all(&dir).expect("create seed dir");
        let path = dir.join("ed25519.seed");
        std::fs::write(&path, self.seed).expect("write seed");
        let (classical, _pqc) = ciris_keyring::load_local_seed(ciris_keyring::LocalSeedConfig {
            key_id: self.key_id.clone(),
            key_path: path,
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

async fn build_edge(
    tmp: &tempfile::TempDir,
    me: &FedKey,
    directory: Arc<SqliteBackend>,
    queue: Arc<SqliteBackend>,
) -> Edge {
    let signer = me.local_signer(tmp.path()).await;
    let config = EdgeConfig {
        hybrid_policy: HybridPolicy::Ed25519Fallback,
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

// ─── Tests ───────────────────────────────────────────────────────────

/// `Edge::fetch_content` returns the bytes when a matching ContentBody
/// is signalled into the pending-fetch correlation map. Drives the
/// happy path via the test-only `complete_pending_fetch_for_test`
/// helper since the real wire path needs a full Reticulum loopback
/// (already covered by `tests/content_fetch.rs`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tier3_fetch_content_returns_bytes_on_match() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = FedKey::new("bootstrap-steward", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let peer = FedKey::new("holder-peer", 0xBB);

    let directory = directory_with(vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
        signed_record(&peer, &bootstrap, "agent"),
    ])
    .await;
    let queue = directory.clone();
    let edge = Arc::new(build_edge(&tmp, &me, directory.clone(), queue.clone()).await);

    let sha = [0x42u8; 32];
    let expected_bytes = b"the bytes the operator wanted".to_vec();
    let expected_bytes_clone = expected_bytes.clone();

    // Spawn the fetch first; the producer signals after a short delay.
    let edge_for_fetch = edge.clone();
    let peer_key_id = peer.key_id.clone();
    let fetch_task = tokio::spawn(async move {
        edge_for_fetch
            .fetch_content(&peer_key_id, sha, Duration::from_secs(5))
            .await
    });

    // Give the fetch a moment to register the pending entry, then
    // signal it directly via the test helper.
    tokio::time::sleep(Duration::from_millis(20)).await;
    edge.complete_pending_fetch_for_test(sha, ContentResult::Bytes(expected_bytes_clone));

    let result = fetch_task.await.expect("task").expect("fetch");
    match result {
        ContentResult::Bytes(b) => assert_eq!(b, expected_bytes),
        other => panic!("expected Bytes, got {other:?}"),
    }
}

/// `Edge::fetch_content` returns ContentMiss when a miss is signalled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tier3_fetch_content_surfaces_content_miss() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = FedKey::new("bootstrap-steward", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let peer = FedKey::new("holder-peer", 0xBB);

    let directory = directory_with(vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
        signed_record(&peer, &bootstrap, "agent"),
    ])
    .await;
    let queue = directory.clone();
    let edge = Arc::new(build_edge(&tmp, &me, directory.clone(), queue.clone()).await);

    let sha = [0x99u8; 32];
    let edge_for_fetch = edge.clone();
    let peer_key_id_miss = peer.key_id.clone();
    let fetch_task = tokio::spawn(async move {
        edge_for_fetch
            .fetch_content(&peer_key_id_miss, sha, Duration::from_secs(5))
            .await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    edge.complete_pending_fetch_for_test(
        sha,
        ContentResult::ContentMiss {
            reason: "NotHeld".to_string(),
        },
    );

    let result = fetch_task.await.expect("task").expect("fetch");
    match result {
        ContentResult::ContentMiss { reason } => assert_eq!(reason, "NotHeld"),
        other => panic!("expected ContentMiss, got {other:?}"),
    }
}

/// `Edge::fetch_content` returns a typed timeout error when no
/// response arrives within the supplied duration.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tier3_fetch_content_times_out_cleanly() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = FedKey::new("bootstrap-steward", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let peer = FedKey::new("holder-peer", 0xBB);

    let directory = directory_with(vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
        signed_record(&peer, &bootstrap, "agent"),
    ])
    .await;
    let queue = directory.clone();
    let edge = build_edge(&tmp, &me, directory.clone(), queue.clone()).await;

    let result = edge
        .fetch_content(&peer.key_id, [0x77; 32], Duration::from_millis(80))
        .await;
    let err = result.expect_err("must time out");
    let msg = format!("{err}");
    assert!(
        msg.to_lowercase().contains("timeout") || msg.contains("fetch_content"),
        "error must indicate timeout / fetch_content failure, got: {msg}"
    );
}

/// `Edge::subscribe_verified_feed` delivers every verified envelope.
/// We use the test-only fan-out helper so the test stays hermetic.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tier3_subscribe_feed_observes_fanout() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = FedKey::new("bootstrap-steward", 0x01);
    let me = FedKey::new("edge-self", 0xAA);

    let directory = directory_with(vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
    ])
    .await;
    let queue = directory.clone();
    let edge = build_edge(&tmp, &me, directory.clone(), queue.clone()).await;

    let mut rx = edge.subscribe_verified_feed();
    assert!(
        edge.verified_feed_subscriber_count() >= 1,
        "broadcast::receiver_count must reflect the new subscriber",
    );

    // Build a tiny fake envelope just to populate fields; the fan-out
    // helper takes a constructed snapshot, not a verify-pipeline run.
    let env = build_envelope(
        OpaqueEvent::TYPE,
        &me.key_id,
        "any-recipient",
        &OpaqueEvent {
            kind: 0x0000_0001,
            payload: b"hello".to_vec(),
        },
        None,
    )
    .expect("build envelope");
    let snapshot = ciris_edge::VerifiedEnvelopeSnapshot {
        envelope: env,
        body_sha256: [0xAA; 32],
        transport_id: TransportId::HTTP,
        received_at: chrono::Utc::now(),
    };
    edge.fan_out_verified_envelope_for_test(snapshot);

    let received = tokio::time::timeout(Duration::from_millis(200), rx.recv())
        .await
        .expect("did not lag")
        .expect("channel open");
    assert_eq!(received.envelope.message_type, MessageType::OpaqueEvent);
    assert_eq!(received.transport_id, TransportId::HTTP);
    assert_eq!(received.body_sha256, [0xAA; 32]);
}

/// `Edge::reachability_tracker` snapshot ratio shape — the
/// substrate that `PyEdge::peer_reachability` projects into the
/// Python dict. The tracker itself is exhaustively tested in
/// `src/reachability.rs::tests`; this gate confirms the Edge-level
/// accessor exposes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tier3_peer_reachability_snapshot_round_trip() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = FedKey::new("bootstrap-steward", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let peer = FedKey::new("ping-peer", 0xBB);

    let directory = directory_with(vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
        signed_record(&peer, &bootstrap, "agent"),
    ])
    .await;
    let queue = directory.clone();
    let edge = build_edge(&tmp, &me, directory.clone(), queue.clone()).await;

    let tracker = edge.reachability_tracker();
    tracker.record_attempt(&peer.key_id, TransportId::HTTP, AttemptOutcome::SendSuccess);
    tracker.record_attempt(
        &peer.key_id,
        TransportId::HTTP,
        AttemptOutcome::SendFailure {
            error_class: "timeout".into(),
        },
    );
    tracker.record_attempt(&peer.key_id, TransportId::HTTP, AttemptOutcome::SendSuccess);
    let snap = tracker.snapshot(&peer.key_id);
    let entry = snap
        .get(&TransportId::HTTP)
        .expect("HTTP entry present after attempts");
    assert_eq!(entry.attempts, 3);
    assert_eq!(entry.successes, 2);
    let ratio = entry.ratio();
    assert!(
        (ratio - 2.0 / 3.0).abs() < 1e-9,
        "ratio must be 2/3 = 0.6666...; got {ratio}",
    );
}

/// dispatch_inbound's ContentBody arm correlates by body.sha256 with
/// any in-flight fetch_content waiter. Drives a full verified
/// ContentBody envelope through `dispatch_inbound_for_test` and
/// asserts the fetch_content future resolves with the bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tier3_dispatch_inbound_signals_fetch_content() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = FedKey::new("bootstrap-steward", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let peer = FedKey::new("holder-peer", 0xCC);

    let directory = directory_with(vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
        signed_record(&peer, &bootstrap, "agent"),
    ])
    .await;
    let queue = directory.clone();
    let edge = Arc::new(build_edge(&tmp, &me, directory.clone(), queue.clone()).await);

    let bytes = b"content body payload".to_vec();
    let bytes_clone = bytes.clone();
    let sha: [u8; 32] = Sha256::digest(&bytes_clone).into();

    // Spawn the fetch first.
    let edge_for_fetch = edge.clone();
    let peer_key_id = peer.key_id.clone();
    let fetch_task = tokio::spawn(async move {
        edge_for_fetch
            .fetch_content(&peer_key_id, sha, Duration::from_secs(5))
            .await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Build + sign a ContentBody envelope from the peer.
    let body = ContentBody {
        sha256: sha,
        bytes: bytes.clone(),
        attestation_ref: None,
    };
    let peer_signer = peer.local_signer(tmp.path()).await;
    let mut env = build_envelope(
        MessageType::ContentBody,
        &peer.key_id,
        &me.key_id,
        &body,
        None,
    )
    .expect("build envelope");
    sign_envelope(&peer_signer, &mut env)
        .await
        .expect("sign envelope");
    let frame_bytes = serde_json::to_vec(&env).expect("serialize");

    edge.dispatch_inbound_for_test(InboundFrame {
        envelope_bytes: frame_bytes,
        transport: TransportId::HTTP,
        received_at: chrono::Utc::now(),
        source_key_id: None,
    })
    .await;

    let result = fetch_task.await.expect("task").expect("fetch");
    match result {
        ContentResult::Bytes(b) => assert_eq!(b, bytes),
        other => panic!("expected Bytes, got {other:?}"),
    }
}
