//! CIRISEdge#28 (v0.19.0) acceptance gate — EdgeMetrics counter +
//! gauge behaviour at the load-bearing call sites
//! (`Edge::send` / `Edge::send_durable` / `dispatch_inbound`).
//!
//! Mirrors the test pattern in `tests/content_fetch.rs` for the
//! receiver-side dispatch path; the send-side tests stand up a
//! pair-of-peers fixture and exercise the metrics increments through
//! the public API. Uses an in-memory federation directory backed by
//! `FederationDirectorySqlite::open(":memory:")` per the established
//! convention.

#![cfg(feature = "transport-reticulum")]

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::{ClassicalSigner, Ed25519Signer};
use ciris_edge::handler::{Handler, HandlerContext, HandlerError, Message};
use ciris_edge::identity::{build_envelope, sign_envelope, LocalSigner};
use ciris_edge::messages::sha256_of;
use ciris_edge::observability::{DeliveryClass, VerifyErrorClass};
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_edge::verify::HybridPolicy;
use ciris_edge::{
    ContentFetch, Edge, EdgeConfig, EdgeMetrics, HintShape, MessageType, OpaqueEvent, OpaqueRequest,
};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, Mutex};

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
        consent_role: None,
        additional_scrubs: Vec::new(),
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

fn test_edge_config() -> EdgeConfig {
    EdgeConfig {
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        ..EdgeConfig::default()
    }
}

/// Transport that records the outcome of each `send` call. Used by the
/// metric-on-send tests so we can drive both success and failure
/// classes from the call site.
#[derive(Clone)]
struct ConfigurableTransport {
    id: TransportId,
    next: Arc<Mutex<Vec<Result<TransportSendOutcome, TransportError>>>>,
}

impl ConfigurableTransport {
    fn new(id: TransportId, mut script: Vec<Result<TransportSendOutcome, TransportError>>) -> Self {
        script.reverse();
        Self {
            id,
            next: Arc::new(Mutex::new(script)),
        }
    }
}

#[async_trait]
impl Transport for ConfigurableTransport {
    fn id(&self) -> TransportId {
        self.id
    }
    async fn send(&self, _: &str, _: &[u8]) -> Result<TransportSendOutcome, TransportError> {
        let mut guard = self.next.lock().await;
        guard.pop().unwrap_or(Ok(TransportSendOutcome::Delivered))
    }
    async fn listen(&self, _: mpsc::Sender<InboundFrame>) -> Result<(), TransportError> {
        // never produces traffic in these tests
        std::future::pending::<()>().await;
        Ok(())
    }
}

async fn signed_envelope_bytes<M: Message>(
    sender: &LocalSigner,
    destination_key_id: &str,
    body: &M,
) -> Vec<u8> {
    let mut env = build_envelope(M::TYPE, &sender.key_id, destination_key_id, body, None)
        .expect("build envelope");
    sign_envelope(sender, &mut env)
        .await
        .expect("sign envelope");
    serde_json::to_vec(&env).expect("serialize envelope")
}

async fn build_edge(
    tmp: &tempfile::TempDir,
    transport: Arc<dyn Transport>,
) -> (Arc<Edge>, Arc<LocalSigner>, String) {
    let steward = FedKey::new("steward-fed", 0x01);
    let local = FedKey::new("local-self", 0xBB);
    let peer = FedKey::new("remote-peer", 0xAA);

    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&local, &steward, "agent"),
        signed_record(&peer, &steward, "agent"),
    ])
    .await;
    let queue = directory.clone();
    let local_signer = local.local_signer(tmp.path()).await;

    let edge = Edge::builder()
        .directory(directory.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .queue(queue)
        .signer(local_signer)
        .transport(transport)
        .config(test_edge_config())
        .build()
        .expect("build edge");

    // peer's signer so a separate test can drive inbound envelopes
    let peer_signer = peer.local_signer(tmp.path()).await;
    (Arc::new(edge), peer_signer, peer.key_id.clone())
}

struct NopHandler<M: Message<Response = ()>>(std::marker::PhantomData<M>);

#[async_trait]
impl<M> Handler<M> for NopHandler<M>
where
    M: Message<Response = ()> + Send + Sync + 'static,
{
    async fn handle(&self, _: M, _: HandlerContext) -> Result<(), HandlerError> {
        Ok(())
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

/// Counter increments on a successful `Edge::send` of an ephemeral
/// `OpaqueRequest`. Note: `Edge::send` returns Err for OpaqueRequest (the
/// Phase-2 ephemeral request-response correlation isn't wired); we
/// expect the transport-side counter to register regardless because the
/// envelope DID ship before the correlation gap kicks in.
#[tokio::test]
async fn metrics_counter_increments_on_send() {
    let tmp = tempfile::tempdir().unwrap();
    let transport = Arc::new(ConfigurableTransport::new(
        TransportId::RETICULUM_RS,
        vec![Ok(TransportSendOutcome::Delivered)],
    )) as Arc<dyn Transport>;
    let (edge, _peer_signer, peer_key_id) = build_edge(&tmp, transport).await;

    let _ = edge
        .send(
            &peer_key_id,
            OpaqueRequest {
                kind: 0x0000_0001,
                payload: b"hi".to_vec(),
            },
        )
        .await;

    let snap = edge.metrics().snapshot();
    assert_eq!(
        snap.envelopes_sent_total
            .get(&MessageType::OpaqueRequest)
            .copied()
            .unwrap_or(0),
        1
    );
    let bytes_out = snap
        .transport_bytes_out_total
        .get(&TransportId::RETICULUM_RS)
        .copied()
        .unwrap_or(0);
    assert!(bytes_out > 0, "transport bytes out should be > 0");
}

/// Counter increments on a verified inbound envelope through
/// `dispatch_inbound`. Drives the receiver path with an injected
/// inbound frame and inspects the metric snapshot after the dispatch
/// task completes.
#[tokio::test]
async fn metrics_counter_increments_on_receive() {
    let tmp = tempfile::tempdir().unwrap();
    let transport =
        Arc::new(ConfigurableTransport::new(TransportId::HTTP, vec![])) as Arc<dyn Transport>;
    let (edge, peer_signer, _peer_key_id) = build_edge(&tmp, transport).await;

    // Register a no-op handler so the typed dispatch arm succeeds.
    edge.register_handler::<ContentFetch, _>(NopHandler::<ContentFetch>(std::marker::PhantomData))
        .await
        .expect("register");

    let fetch = ContentFetch {
        sha256: sha256_of(b"observe me"),
        response_hint: Some(HintShape {
            max_body_bytes: Some(1024),
            prefer_chunked: false,
        }),
    };
    let envelope_bytes = signed_envelope_bytes(&peer_signer, edge.signer_key_id(), &fetch).await;
    let frame = InboundFrame {
        envelope_bytes,
        transport: TransportId::HTTP,
        received_at: chrono::Utc::now(),
        source_key_id: None,
    };
    edge.dispatch_inbound_for_test(frame).await;

    let snap = edge.metrics().snapshot();
    assert_eq!(
        snap.envelopes_received_total
            .get(&MessageType::ContentFetch)
            .copied()
            .unwrap_or(0),
        1
    );
    assert!(
        snap.transport_bytes_in_total
            .get(&TransportId::HTTP)
            .copied()
            .unwrap_or(0)
            > 0
    );
}

/// `send_failures_total` accumulates per `(TransportId, error-class)`.
#[tokio::test]
async fn metrics_send_failure_classified_by_transport_and_error() {
    let tmp = tempfile::tempdir().unwrap();
    let transport = Arc::new(ConfigurableTransport::new(
        TransportId::RETICULUM_RS,
        vec![Err(TransportError::Unreachable("test".into()))],
    )) as Arc<dyn Transport>;
    let (edge, _peer_signer, peer_key_id) = build_edge(&tmp, transport).await;

    let _ = edge
        .send(
            &peer_key_id,
            OpaqueRequest {
                kind: 0x0000_0001,
                payload: b"fail-me".to_vec(),
            },
        )
        .await;

    let snap = edge.metrics().snapshot();
    let count = snap
        .send_failures_total
        .get(&(TransportId::RETICULUM_RS, "unreachable".to_string()))
        .copied()
        .unwrap_or(0);
    assert_eq!(
        count, 1,
        "unreachable transport-error counted under RETICULUM_RS"
    );
}

/// `durable_queue_depth` accumulates per delivery class on
/// `send_durable`. The metric is a monotonic cumulative count of
/// enqueues — consumers diff it against persist's `queue_depth` for
/// the resident count (see EdgeMetrics docstring).
#[tokio::test]
async fn metrics_durable_queue_depth_tracks_send_durable() {
    let tmp = tempfile::tempdir().unwrap();
    let transport =
        Arc::new(ConfigurableTransport::new(TransportId::HTTP, vec![])) as Arc<dyn Transport>;
    let (edge, _peer_signer, peer_key_id) = build_edge(&tmp, transport).await;

    // `OpaqueEvent` is `Delivery::Durable { .. }`.
    let msg = OpaqueEvent {
        kind: 0x0000_0001,
        payload: b"durable text".to_vec(),
    };
    let _ = edge.send_durable(&peer_key_id, msg).await;

    let snap = edge.metrics().snapshot();
    assert_eq!(
        snap.durable_queue_depth
            .get(&DeliveryClass::Durable)
            .copied()
            .unwrap_or(0),
        1
    );
    assert_eq!(
        snap.envelopes_sent_total
            .get(&MessageType::OpaqueEvent)
            .copied()
            .unwrap_or(0),
        1
    );
}

/// `transport_bytes_{in,out}_total` increment per-transport. The
/// inbound side fires through `dispatch_inbound_for_test`; the
/// outbound side fires through a real `Edge::send` with a configured
/// transport.
#[tokio::test]
async fn metrics_transport_bytes_io_counted() {
    let tmp = tempfile::tempdir().unwrap();
    let transport = Arc::new(ConfigurableTransport::new(
        TransportId::RETICULUM_RS,
        vec![Ok(TransportSendOutcome::Delivered)],
    )) as Arc<dyn Transport>;
    let (edge, peer_signer, peer_key_id) = build_edge(&tmp, transport).await;

    // outbound side
    let _ = edge
        .send(
            &peer_key_id,
            OpaqueRequest {
                kind: 0x0000_0001,
                payload: b"outbound".to_vec(),
            },
        )
        .await;

    // inbound side — distinct TransportId to keep the assertions
    // disambiguated.
    let fetch = ContentFetch {
        sha256: sha256_of(b"inbound"),
        response_hint: None,
    };
    let envelope_bytes = signed_envelope_bytes(&peer_signer, edge.signer_key_id(), &fetch).await;
    let frame = InboundFrame {
        envelope_bytes,
        transport: TransportId::HTTP,
        received_at: chrono::Utc::now(),
        source_key_id: None,
    };
    edge.dispatch_inbound_for_test(frame).await;

    let snap = edge.metrics().snapshot();
    assert!(
        snap.transport_bytes_out_total
            .get(&TransportId::RETICULUM_RS)
            .copied()
            .unwrap_or(0)
            > 0
    );
    assert!(
        snap.transport_bytes_in_total
            .get(&TransportId::HTTP)
            .copied()
            .unwrap_or(0)
            > 0
    );
}

/// `peer_reachability_ratio` reflects the reachability tracker.
/// Verified through the live `EdgeMetrics::set_peer_reachability` API
/// (the PyO3 snapshot mirrors the tracker on each call; this test
/// drives the same API directly).
#[tokio::test]
async fn metrics_peer_reachability_ratio_reflects_tracker() {
    let m = EdgeMetrics::new();
    m.set_peer_reachability("peer-x", "reticulum-rs", 0.5);
    m.set_peer_reachability("peer-y", "http", 1.0);
    let snap = m.snapshot();
    assert!(
        (snap.peer_reachability_ratio[&("peer-x".to_string(), "reticulum-rs".to_string())] - 0.5)
            .abs()
            < f64::EPSILON
    );
    assert!(
        (snap.peer_reachability_ratio[&("peer-y".to_string(), "http".to_string())] - 1.0).abs()
            < f64::EPSILON
    );
}

/// Verify-failure class accumulates on `dispatch_inbound`. Drives an
/// inbound frame whose body is not a valid envelope; the verify
/// pipeline's typed error maps to `VerifyErrorClass::SchemaInvalid`.
#[tokio::test]
async fn metrics_verify_failure_classified_by_error() {
    let tmp = tempfile::tempdir().unwrap();
    let transport =
        Arc::new(ConfigurableTransport::new(TransportId::HTTP, vec![])) as Arc<dyn Transport>;
    let (edge, _peer_signer, _peer_key_id) = build_edge(&tmp, transport).await;

    let frame = InboundFrame {
        envelope_bytes: b"not-a-real-envelope".to_vec(),
        transport: TransportId::HTTP,
        received_at: chrono::Utc::now(),
        source_key_id: None,
    };
    edge.dispatch_inbound_for_test(frame).await;

    let snap = edge.metrics().snapshot();
    assert_eq!(
        snap.verify_failures_total
            .get(&VerifyErrorClass::SchemaInvalid)
            .copied()
            .unwrap_or(0),
        1
    );
}
