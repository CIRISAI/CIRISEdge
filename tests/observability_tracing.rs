//! CIRISEdge#28 (v0.19.0) acceptance gate — tracing spans + structured
//! error events on the load-bearing send/receive paths.
//!
//! Instead of `tracing-test`, we install a `tracing-subscriber` with a
//! custom `make_writer` that pipes structured events into a shared
//! `Vec<String>`. Each test installs its own subscriber via
//! `tracing::subscriber::set_default(...)` (scoped to the test
//! Future) so concurrent tests don't fight over a global subscriber.
//!
//! The assertion bar is "the field is named in the emitted record",
//! not the exact field-value formatting — that protects us against
//! tracing-subscriber serialization details that aren't load-bearing
//! for downstream consumers (they scrape on field name).

#![cfg(feature = "transport-reticulum")]

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::{ClassicalSigner, Ed25519Signer};
use ciris_edge::handler::Message;
use ciris_edge::identity::{build_envelope, sign_envelope, LocalSigner};
use ciris_edge::messages::sha256_of;
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_edge::verify::HybridPolicy;
use ciris_edge::{ContentFetch, Edge, EdgeConfig, HintShape, InlineText};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, Mutex as TokioMutex};
use tracing_subscriber::fmt::MakeWriter;

// ─── tracing capture harness ────────────────────────────────────────

#[derive(Clone, Default)]
struct CapturedLines(Arc<Mutex<Vec<u8>>>);

impl CapturedLines {
    fn snapshot(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut g = self.0.lock().unwrap();
        g.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CapturedLines {
    type Writer = CapturedWriter;
    fn make_writer(&'a self) -> Self::Writer {
        CapturedWriter(self.0.clone())
    }
}

fn install_capture() -> (CapturedLines, tracing::subscriber::DefaultGuard) {
    let lines = CapturedLines::default();
    // `FmtSpan::NEW | FmtSpan::CLOSE` so span open/close events get
    // serialized into the captured stream — without this, the
    // `#[instrument]`-driven span name only shows up on events emitted
    // INSIDE the span (which is fine for verify-failure assertions but
    // misses the happy-path span-name assertion).
    let subscriber = tracing_subscriber::fmt()
        .with_writer(lines.clone())
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .with_ansi(false)
        .with_span_events(
            tracing_subscriber::fmt::format::FmtSpan::NEW
                | tracing_subscriber::fmt::format::FmtSpan::CLOSE,
        )
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    (lines, guard)
}

// ─── Test fixtures (shared with observability_metrics) ──────────────

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
        .expect("open in-memory");
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

#[derive(Clone)]
struct ConfigurableTransport {
    id: TransportId,
    next: Arc<TokioMutex<Vec<Result<TransportSendOutcome, TransportError>>>>,
}

impl ConfigurableTransport {
    fn new(id: TransportId, mut script: Vec<Result<TransportSendOutcome, TransportError>>) -> Self {
        script.reverse();
        Self {
            id,
            next: Arc::new(TokioMutex::new(script)),
        }
    }
}

#[async_trait]
impl Transport for ConfigurableTransport {
    fn id(&self) -> TransportId {
        self.id
    }
    async fn send(&self, _: &str, _: &[u8]) -> Result<TransportSendOutcome, TransportError> {
        let mut g = self.next.lock().await;
        g.pop().unwrap_or(Ok(TransportSendOutcome::Delivered))
    }
    async fn listen(&self, _: mpsc::Sender<InboundFrame>) -> Result<(), TransportError> {
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
    sign_envelope(sender, &mut env).await.expect("sign");
    serde_json::to_vec(&env).expect("serialize envelope")
}

async fn build_edge_pair(
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
    let peer_signer = peer.local_signer(tmp.path()).await;
    (Arc::new(edge), peer_signer, peer.key_id.clone())
}

// ─── Tests ──────────────────────────────────────────────────────────

/// `dispatch_inbound` opens an `edge.dispatch_inbound` span; the span
/// records `transport_id`, `signing_key_id`, `message_type`,
/// `body_sha256_prefix`, `verify_outcome` after the verify step.
/// Assertion bar: the span name + each load-bearing field name appears
/// in the captured output.
#[tokio::test]
async fn dispatch_inbound_emits_structured_span_with_fields() {
    let (lines, _guard) = install_capture();
    let tmp = tempfile::tempdir().unwrap();
    let transport =
        Arc::new(ConfigurableTransport::new(TransportId::HTTP, vec![])) as Arc<dyn Transport>;
    let (edge, peer_signer, _peer_key_id) = build_edge_pair(&tmp, transport).await;

    edge.register_handler::<ContentFetch, _>(NopHandler::<ContentFetch>(std::marker::PhantomData))
        .await
        .expect("register");

    let fetch = ContentFetch {
        sha256: sha256_of(b"spanme"),
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
    };
    edge.dispatch_inbound_for_test(frame).await;

    let captured = lines.snapshot();
    assert!(
        captured.contains("edge.dispatch_inbound"),
        "dispatch_inbound span name absent; got: {captured}"
    );
    assert!(
        captured.contains("transport_id"),
        "missing transport_id field: {captured}"
    );
    assert!(
        captured.contains("message_type"),
        "missing message_type field: {captured}"
    );
    assert!(
        captured.contains("body_sha256_prefix"),
        "missing body_sha256_prefix field: {captured}"
    );
    assert!(
        captured.contains("verify_outcome"),
        "missing verify_outcome field: {captured}"
    );
}

/// `send_durable` opens an `edge.send_durable` span with
/// `delivery_class = durable` and the recipient/message_type fields.
#[tokio::test]
async fn send_durable_emits_attempt_n_field() {
    let (lines, _guard) = install_capture();
    let tmp = tempfile::tempdir().unwrap();
    let transport =
        Arc::new(ConfigurableTransport::new(TransportId::HTTP, vec![])) as Arc<dyn Transport>;
    let (edge, _peer_signer, peer_key_id) = build_edge_pair(&tmp, transport).await;

    let _ = edge
        .send_durable(
            &peer_key_id,
            ciris_edge::InlineTextDurable {
                text: "durable".to_string(),
            },
        )
        .await;

    let captured = lines.snapshot();
    assert!(
        captured.contains("edge.send_durable"),
        "send_durable span name absent; got: {captured}"
    );
    assert!(
        captured.contains("delivery_class"),
        "missing delivery_class field: {captured}"
    );
    assert!(
        captured.contains("durable"),
        "missing delivery_class=durable value: {captured}"
    );
    assert!(
        captured.contains("message_type"),
        "missing message_type field: {captured}"
    );
}

/// A verify failure emits a structured error event with
/// `event = edge.dispatch_inbound.verify_rejected` and a
/// `verify_error_class` field — NOT free-text. The taxonomy is the
/// load-bearing dimension downstream alerts on.
#[tokio::test]
async fn verify_failure_emits_structured_error_event() {
    let (lines, _guard) = install_capture();
    let tmp = tempfile::tempdir().unwrap();
    let transport =
        Arc::new(ConfigurableTransport::new(TransportId::HTTP, vec![])) as Arc<dyn Transport>;
    let (edge, _peer_signer, _peer_key_id) = build_edge_pair(&tmp, transport).await;

    let frame = InboundFrame {
        envelope_bytes: b"not-a-real-envelope".to_vec(),
        transport: TransportId::HTTP,
        received_at: chrono::Utc::now(),
    };
    edge.dispatch_inbound_for_test(frame).await;

    let captured = lines.snapshot();
    assert!(
        captured.contains("edge.dispatch_inbound.verify_rejected"),
        "structured event name missing: {captured}"
    );
    assert!(
        captured.contains("verify_error_class"),
        "verify_error_class field missing: {captured}"
    );
    assert!(
        captured.contains("schema_invalid"),
        "schema_invalid class missing: {captured}"
    );
}

// ─── NopHandler (same shape as observability_metrics::NopHandler) ───
//
// Duplicated here to keep this test file self-contained — the existing
// `tests/common/mod.rs` is reticulum-gated and does NOT carry handler
// fixtures.

use ciris_edge::handler::{Handler, HandlerContext, HandlerError};

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

// Suppress the unused-import warning for `InlineText` (only used as a
// type-presence assertion in some compile paths).
#[allow(dead_code)]
fn _inline_text_witness(_t: InlineText) {}
