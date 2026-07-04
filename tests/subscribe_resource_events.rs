//! CIRISEdge#34 (v0.19.0) — subscribe_resource_events acceptance gate.
//!
//! Verifies the ResourceEvent emission path: `send_durable` enqueues
//! surface a `durable_queue_depth` ResourcePressure event, and direct
//! `events.emit_resource` calls (transport-buffer pressure observation
//! sites) land on the subscribe_resources channel.

#![cfg(feature = "transport-reticulum")]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::{ClassicalSigner, Ed25519Signer};
use ciris_edge::events::{EventBus, EventKind, EventSeverity, NetworkEvent, ResourceEvent};
use ciris_edge::identity::LocalSigner;
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_edge::verify::HybridPolicy;
use ciris_edge::{Edge, EdgeConfig, OpaqueEvent};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

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
        Ed25519Signer::from_seed(&self.seed).unwrap()
    }
    fn pubkey_b64(&self) -> String {
        B64.encode(self.signer().public_key().unwrap())
    }
    fn write_seed_dir(&self, base: &std::path::Path) -> std::path::PathBuf {
        let dir = base.join(format!("seed-{}", self.key_id));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ed25519.seed"), self.seed).unwrap();
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
        .unwrap();
        Arc::new(LocalSigner::new(self.key_id.clone(), classical, None))
    }
}

fn signed_record(subject: &FedKey, signer: &FedKey, identity_type: &str) -> KeyRecord {
    let envelope = serde_json::json!({ "key_id": subject.key_id });
    let canonical = serde_json::to_vec(&envelope).unwrap();
    let digest = Sha256::digest(&canonical);
    let sig = signer.signer().sign(digest.as_slice()).unwrap();
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
    let backend = FederationDirectorySqlite::open(":memory:").await.unwrap();
    backend.run_migrations().await.unwrap();
    for rec in records {
        backend
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .unwrap();
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

/// `send_durable` increments the durable_queue_depth gauge AND emits a
/// `ResourcePressure` event on the resource channel. Verifies the
/// emission path edge-internal.
#[tokio::test]
async fn subscribe_resource_events_yields_durable_queue_pressure() {
    let tmp = tempfile::tempdir().unwrap();
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

    // Pre-build the bus + a receiver before `Edge::builder().build()`
    // so we don't miss the emission timing window.
    let bus = Arc::new(EventBus::default());
    let mut rx = bus.subscribe_resources();

    let edge = Edge::builder()
        .directory(directory.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .queue(queue)
        .signer(local_signer)
        .transport(Arc::new(NopTransport) as Arc<dyn Transport>)
        .events(bus.clone())
        .config(EdgeConfig {
            hybrid_policy: HybridPolicy::Ed25519Fallback,
            ..EdgeConfig::default()
        })
        .build()
        .unwrap();

    let _ = edge
        .send_durable(
            &peer.key_id,
            OpaqueEvent {
                kind: 0x0000_0001,
                payload: b"queueme".to_vec(),
            },
        )
        .await;

    let ev = tokio::time::timeout(Duration::from_millis(500), rx.recv())
        .await
        .expect("did not lag")
        .expect("did not close");
    assert_eq!(ev.kind, EventKind::ResourcePressure);
    let proj = ResourceEvent::from_event(&ev).expect("projection");
    assert_eq!(proj.resource_kind, "durable_queue_depth");
    assert!(proj.measurement >= 1.0);
    assert_eq!(proj.unit, "count");
}

/// Direct `emit_resource` API exercise — covers the transport-buffer
/// pressure observation site shape (the emission site lives in the
/// Reticulum transport's path-table hooks; the wire shape is what
/// downstream consumers parse, so we drive that surface directly).
#[tokio::test]
async fn subscribe_resource_events_yields_transport_buffer_pressure() {
    let bus = Arc::new(EventBus::default());
    let mut rx = bus.subscribe_resources();
    bus.emit_resource(NetworkEvent::resource(
        "transport_buffer_pressure",
        0.75,
        "ratio",
        EventSeverity::Warning,
        "outbound queue 75% full",
    ));
    let ev = tokio::time::timeout(Duration::from_millis(200), rx.recv())
        .await
        .expect("did not lag")
        .expect("did not close");
    let proj = ResourceEvent::from_event(&ev).expect("projection");
    assert_eq!(proj.resource_kind, "transport_buffer_pressure");
    assert!((proj.measurement - 0.75).abs() < f64::EPSILON);
    assert_eq!(proj.unit, "ratio");
    assert_eq!(proj.severity, EventSeverity::Warning);
}
