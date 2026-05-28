//! Acceptance gate for CIRISEdge#21 — `MessageType::ContentFetch` /
//! `MessageType::ContentBody` / `MessageType::ContentMiss`
//! (v0.8.0 content-addressable byte transport, Phase 1).
//!
//! Cross-references:
//!
//! - CIRISEdge#21 spec body — wire shape + delivery class + AV-13
//!   ceiling + receiver-side SHA integrity invariant.
//! - CIRISPersist#103 (v2.3+) — `BlobStorage::list_holders`
//!   substrate-tier counterpart of `PeerResolver::resolve_holders`.
//!
//! This suite drives the Phase 1 wire surface end-to-end through a
//! controlled in-process pipeline: a test transport injects inbound
//! envelopes, edge's `run` loop verifies + AV-13/integrity-gates +
//! dispatches to a registered handler, and a oneshot channel
//! observes whether the handler fired. The pattern mirrors
//! `tests/federation_announcement.rs` — same persist SQLite fixture
//! pattern, same `FedKey` seed generator, same `NullTransport` shape
//! plus a small `InjectTransport` for the receive path.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::{ClassicalSigner, Ed25519Signer};
use ciris_edge::handler::{Delivery, Handler, HandlerContext, HandlerError, Message};
use ciris_edge::identity::{build_envelope, sign_envelope, LocalSigner};
use ciris_edge::messages::sha256_of;
use ciris_edge::transport::reticulum::PeerResolver;
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_edge::verify::HybridPolicy;
use ciris_edge::{
    AttestationRef, ContentBody, ContentFetch, ContentMiss, Edge, EdgeConfig, HintShape,
    MessageType, MissReason, DEFAULT_MAX_CONTENT_BODY_BYTES,
};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch, Mutex};

// ─── Fixtures ───────────────────────────────────────────────────────

/// A test federation identity: deterministic seed + key_id + the keys
/// derived from it. Same shape as `tests/federation_announcement.rs`.
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
        Arc::new(LocalSigner {
            key_id: self.key_id.clone(),
            classical,
            pqc: None,
        })
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

/// Test-side `EdgeConfig` — relaxes the production
/// [`HybridPolicy::Strict`] default to `Ed25519Fallback` so the
/// hybrid-pending `KeyRecord` fixtures (`pqc_completed_at: None`)
/// don't reject at the verify pipeline. Real deployments default
/// `Strict`; the content-fetch wire surface is policy-agnostic so
/// the test bar is "does verify+dispatch land?", independent of the
/// PQC policy.
fn test_edge_config() -> EdgeConfig {
    EdgeConfig {
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        ..EdgeConfig::default()
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

/// Inbound-injecting test transport. `listen` clones the
/// caller-supplied mpsc receiver of envelope bytes and forwards every
/// item as an [`InboundFrame`] to the edge's dispatch loop. `send` is
/// a no-op (we are only testing the receive path).
struct InjectTransport {
    inbound: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
}

impl InjectTransport {
    fn new(rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            inbound: Mutex::new(Some(rx)),
        }
    }
}

#[async_trait]
impl Transport for InjectTransport {
    fn id(&self) -> TransportId {
        TransportId::HTTP
    }
    async fn send(&self, _: &str, _: &[u8]) -> Result<TransportSendOutcome, TransportError> {
        Ok(TransportSendOutcome::Delivered)
    }
    async fn listen(&self, sink: mpsc::Sender<InboundFrame>) -> Result<(), TransportError> {
        let rx = {
            let mut guard = self.inbound.lock().await;
            guard
                .take()
                .ok_or_else(|| TransportError::Config("listen called twice".into()))?
        };
        let mut rx = rx;
        while let Some(bytes) = rx.recv().await {
            let frame = InboundFrame {
                envelope_bytes: bytes,
                transport: TransportId::HTTP,
                received_at: chrono::Utc::now(),
            };
            if sink.send(frame).await.is_err() {
                break;
            }
        }
        Ok(())
    }
}

/// Handler that signals on a oneshot when it fires. `M::Response = ()`
/// for every CIRISEdge#21 family type, so the handler return type is
/// `()`.
struct SignalHandler<M: Message<Response = ()>> {
    tx: Mutex<Option<tokio::sync::oneshot::Sender<M>>>,
}

impl<M: Message<Response = ()>> SignalHandler<M> {
    fn new() -> (Self, tokio::sync::oneshot::Receiver<M>) {
        let (tx, rx) = tokio::sync::oneshot::channel::<M>();
        (
            Self {
                tx: Mutex::new(Some(tx)),
            },
            rx,
        )
    }
}

#[async_trait]
impl<M> Handler<M> for SignalHandler<M>
where
    M: Message<Response = ()> + Send + Sync + 'static,
{
    async fn handle(&self, msg: M, _: HandlerContext) -> Result<(), HandlerError> {
        if let Some(tx) = self.tx.lock().await.take() {
            let _ = tx.send(msg);
        }
        Ok(())
    }
}

/// Build a steward-signed federation directory with the two parties
/// for these tests (sender + receiver), open an `Edge` rooted on the
/// receiver, wire it to an `InjectTransport`, register the supplied
/// handler, and spawn `Edge::run`. Returns:
///
/// - the sender mpsc::Sender that the test pushes encoded envelopes
///   into (the receiver's inbound side),
/// - the watch::Sender to drive shutdown,
/// - the sender's `LocalSigner` (so the test can sign outbound
///   envelopes against the receiver),
/// - the shared persist `SqliteBackend` (for federation_blobs seeding
///   in the holder-resolution test),
/// - the receiver's `key_id`.
async fn setup<M, H>(
    tmp: &tempfile::TempDir,
    handler: Option<H>,
    config: EdgeConfig,
) -> (
    mpsc::Sender<Vec<u8>>,
    watch::Sender<bool>,
    Arc<LocalSigner>,
    Arc<SqliteBackend>,
    String,
)
where
    M: Message<Response = ()>,
    H: Handler<M> + 'static,
{
    let steward = FedKey::new("steward-fed", 0x01);
    let sender = FedKey::new("content-sender", 0xAA);
    let receiver = FedKey::new("content-receiver", 0xBB);

    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&sender, &steward, "agent"),
        signed_record(&receiver, &steward, "agent"),
    ])
    .await;
    let queue = directory.clone();
    let sender_signer = sender.local_signer(tmp.path()).await;
    let receiver_signer = receiver.local_signer(tmp.path()).await;

    let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(32);
    let transport = Arc::new(InjectTransport::new(inbound_rx));

    let edge = Edge::builder()
        .directory(directory.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .queue(queue)
        .signer(receiver_signer)
        .transport(transport)
        .config(config)
        .build()
        .expect("build edge");

    if let Some(h) = handler {
        edge.register_handler::<M, _>(h)
            .await
            .expect("register handler");
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = edge.run(shutdown_rx).await;
    });
    // Give the listener a moment to claim the receiver before the
    // test starts pushing.
    tokio::time::sleep(Duration::from_millis(20)).await;

    (
        inbound_tx,
        shutdown_tx,
        sender_signer,
        directory,
        receiver.key_id.clone(),
    )
}

/// Sign an envelope around `body`, addressed from `sender` to
/// `destination`, and return the JSON bytes ready for inbound
/// injection.
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

// ─── Tests ──────────────────────────────────────────────────────────

/// Round-trip — sender enqueues a `ContentFetch`; the receiver's
/// registered handler observes the parsed body with the SHA the
/// sender asked for. Pins the wire-shape end-to-end (encode → verify
/// → handler dispatch).
///
/// AV category: forensic completeness (handler sees the verified body
/// it would respond to). No adversarial axis — pure happy-path round
/// trip, the FSD §3.4 baseline.
#[tokio::test]
async fn content_fetch_round_trip() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (handler, fetch_rx) = SignalHandler::<ContentFetch>::new();
    let (inbound, shutdown, sender, _dir, recv_key_id) =
        setup::<ContentFetch, _>(&tmp, Some(handler), test_edge_config()).await;

    let sha = sha256_of(b"hello federation");
    let fetch = ContentFetch {
        sha256: sha,
        response_hint: Some(HintShape {
            max_body_bytes: Some(1024 * 1024),
            prefer_chunked: false,
        }),
    };
    let bytes = signed_envelope_bytes(&sender, &recv_key_id, &fetch).await;
    inbound.send(bytes).await.expect("inject");

    let received = tokio::time::timeout(Duration::from_secs(2), fetch_rx)
        .await
        .expect("fetch handler did not fire within 2s")
        .expect("oneshot");
    assert_eq!(received.sha256, sha);
    assert_eq!(
        received
            .response_hint
            .as_ref()
            .and_then(|h| h.max_body_bytes),
        Some(1024 * 1024)
    );
    assert!(received.response_hint.is_some() && !received.response_hint.unwrap().prefer_chunked);
    let _ = shutdown.send(true);
}

/// `ContentMiss` round-trip — sender enqueues a `ContentMiss { reason:
/// NotHeld }`; the receiver's handler observes the parsed body. This
/// exercises the fail-over surface (CIRISEdge#21 spec point 3 — a
/// fetcher must be able to receive a typed miss to move to a
/// different peer).
#[tokio::test]
async fn content_miss_round_trip() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (handler, miss_rx) = SignalHandler::<ContentMiss>::new();
    let (inbound, shutdown, sender, _dir, recv_key_id) =
        setup::<ContentMiss, _>(&tmp, Some(handler), test_edge_config()).await;

    let sha = sha256_of(b"unknown-sha-target");
    let miss = ContentMiss {
        sha256: sha,
        reason: MissReason::NotHeld,
    };
    let bytes = signed_envelope_bytes(&sender, &recv_key_id, &miss).await;
    inbound.send(bytes).await.expect("inject");

    let received = tokio::time::timeout(Duration::from_secs(2), miss_rx)
        .await
        .expect("miss handler did not fire within 2s")
        .expect("oneshot");
    assert_eq!(received.sha256, sha);
    assert_eq!(received.reason, MissReason::NotHeld);
    let _ = shutdown.send(true);
}

/// **AV-content-integrity** (CIRISEdge#21 spec point 2 — receiver MUST
/// verify `sha256(bytes) == claimed_sha256`). A tampered `ContentBody`
/// where the claimed SHA doesn't match `sha256(bytes)` MUST NOT reach
/// the application handler. The integrity gate lives in
/// `dispatch_inbound` between verify-pipeline and handler dispatch
/// (`src/edge.rs::validate_content_body`).
///
/// AV category: spoof — the envelope signature verified (the
/// responder really did send these bytes claiming this SHA), but the
/// content-addressed contract was violated. Pure transport-layer
/// signature trust is insufficient under content-addressing; the
/// receiver re-hashes.
#[tokio::test]
async fn content_body_sha_integrity_check_rejects_tampered_bytes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (handler, mut body_rx) = SignalHandler::<ContentBody>::new();
    let (inbound, shutdown, sender, _dir, recv_key_id) =
        setup::<ContentBody, _>(&tmp, Some(handler), test_edge_config()).await;

    // Tampered ContentBody: claims `sha256(b"honest")` but ships
    // `b"forgery"`. The envelope signature will verify (we sign over
    // the canonical bytes of the lie); the content-addressed integrity
    // check is what rejects this.
    let bytes_payload = b"forgery".to_vec();
    let claimed_sha = sha256_of(b"honest");
    assert_ne!(
        claimed_sha,
        sha256_of(&bytes_payload),
        "fixture must be a genuine mismatch — guard against an editor reflex"
    );

    let tampered = ContentBody {
        sha256: claimed_sha,
        bytes: bytes_payload,
        attestation_ref: None,
    };
    let env_bytes = signed_envelope_bytes(&sender, &recv_key_id, &tampered).await;
    inbound.send(env_bytes).await.expect("inject");

    // The handler MUST NOT fire — the integrity check intercepts the
    // envelope before dispatch. Wait a beat to let the dispatcher
    // process; assert the oneshot stays pending.
    tokio::time::sleep(Duration::from_millis(300)).await;
    match body_rx.try_recv() {
        Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {} // expected
        Ok(b) => panic!(
            "tampered ContentBody reached handler — integrity gate broken (got sha {:?})",
            b.sha256
        ),
        Err(e) => panic!("oneshot closed unexpectedly: {e}"),
    }
    let _ = shutdown.send(true);
}

/// **AV-13 content-body oversize** (CIRISEdge#21 spec point 7). A
/// `ContentBody` whose `bytes.len()` exceeds
/// `EdgeConfig::max_content_body_bytes` MUST reject before reaching
/// the application handler. Reject reuses the existing AV-13 family
/// error variant (`VerifyError::BodyTooLarge`) at the
/// `validate_content_body` gate; the user-visible signal is that the
/// handler never fires.
///
/// To keep the test fast we configure a small cap (1 KiB) on the
/// edge under test, then ship a 2 KiB body. The integrity check
/// inside `validate_content_body` runs AFTER the size check, so the
/// `sha256` field of the oversized body is a real hash of the bytes
/// — the rejection is purely on size.
#[tokio::test]
async fn content_body_oversized_rejected_per_av13() {
    let tmp = tempfile::tempdir().expect("tempdir");

    // Tight cap to keep the test cheap. Production default is
    // DEFAULT_MAX_CONTENT_BODY_BYTES = 16 MiB; the AV-13 family
    // variant + error message shape is the contract — the numeric
    // ceiling is just configuration. Also raise `max_body_bytes` for
    // the envelope-level pre-check so the envelope-wrapped body
    // reaches the content-specific gate.
    let cfg = EdgeConfig {
        max_content_body_bytes: 1024,
        max_body_bytes: 64 * 1024,
        ..test_edge_config()
    };
    let (handler, mut body_rx) = SignalHandler::<ContentBody>::new();
    let (inbound, shutdown, sender, _dir, recv_key_id) =
        setup::<ContentBody, _>(&tmp, Some(handler), cfg).await;

    // 2 KiB > 1 KiB cap.
    let payload = vec![0xABu8; 2048];
    let sha = sha256_of(&payload);
    let body = ContentBody {
        sha256: sha,
        bytes: payload,
        attestation_ref: None,
    };
    let env_bytes = signed_envelope_bytes(&sender, &recv_key_id, &body).await;
    inbound.send(env_bytes).await.expect("inject");

    tokio::time::sleep(Duration::from_millis(300)).await;
    match body_rx.try_recv() {
        Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {} // expected
        Ok(b) => panic!(
            "oversized ContentBody reached handler — AV-13 gate broken (got {} bytes)",
            b.bytes.len()
        ),
        Err(e) => panic!("oneshot closed unexpectedly: {e}"),
    }
    // Pin the default const at its issue-spec'd value — a regression
    // that silently lowers the production ceiling is a wire contract
    // change and must be a deliberate version bump.
    assert_eq!(
        DEFAULT_MAX_CONTENT_BODY_BYTES,
        16 * 1024 * 1024,
        "CIRISEdge#21 Phase 1 spec point 7 — 16 MiB default ceiling"
    );
    let _ = shutdown.send(true);
}

/// `MissReason` round-trips correctly for every variant — the
/// fetcher's fail-over logic branches on this enum, so each variant
/// must survive an end-to-end encode/verify/dispatch hop. Pins the
/// wire-shape contract for ALL four reasons in one tokio task per
/// reason.
#[tokio::test]
async fn content_miss_reasons_distinct() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // We need one Edge per reason to avoid the SignalHandler
    // single-shot from collapsing the cases; build a small inline
    // driver instead of taking the multi-edge route.
    for reason in [
        MissReason::NotHeld,
        MissReason::Withdrawn,
        MissReason::Revoked,
        MissReason::PolicyDenied,
    ] {
        let (handler, miss_rx) = SignalHandler::<ContentMiss>::new();
        let (inbound, shutdown, sender, _dir, recv_key_id) =
            setup::<ContentMiss, _>(&tmp, Some(handler), test_edge_config()).await;
        let miss = ContentMiss {
            sha256: [0x11; 32],
            reason,
        };
        let env = signed_envelope_bytes(&sender, &recv_key_id, &miss).await;
        inbound.send(env).await.expect("inject");
        let received = tokio::time::timeout(Duration::from_secs(2), miss_rx)
            .await
            .expect("miss handler did not fire")
            .expect("oneshot");
        assert_eq!(received.reason, reason);
        let _ = shutdown.send(true);
    }
}

/// `PeerResolver::resolve_holders` returns the advertised holder set.
/// The trait method's default impl returns an empty `Vec` (so v0.7.x
/// impls don't break); a production impl wraps persist's
/// `BlobStorage::list_holders` (CIRISPersist#103). This test pins the
/// override surface by implementing the trait against a fake "advertised
/// peers" `HashMap<sha256, Vec<key_id>>` and asserts the lookup.
#[tokio::test]
async fn peer_resolver_resolve_holders_returns_advertised_set() {
    use std::collections::HashMap;

    struct StaticHolders {
        holders: HashMap<[u8; 32], Vec<String>>,
    }

    impl PeerResolver for StaticHolders {
        fn resolve(&self, _: &str) -> Option<[u8; 64]> {
            None
        }
        fn resolve_holders(&self, sha256: &[u8; 32]) -> Vec<String> {
            self.holders.get(sha256).cloned().unwrap_or_default()
        }
    }

    let sha_a = [0xAA; 32];
    let sha_b = [0xBB; 32];

    let mut holders = HashMap::new();
    holders.insert(
        sha_a,
        vec!["peer-alpha".to_string(), "peer-bravo".to_string()],
    );
    holders.insert(sha_b, vec!["peer-charlie".to_string()]);
    let resolver = StaticHolders { holders };

    let advertised_a = resolver.resolve_holders(&sha_a);
    assert_eq!(advertised_a.len(), 2, "two holders advertised for sha_a");
    assert!(advertised_a.contains(&"peer-alpha".to_string()));
    assert!(advertised_a.contains(&"peer-bravo".to_string()));

    let advertised_b = resolver.resolve_holders(&sha_b);
    assert_eq!(advertised_b, vec!["peer-charlie".to_string()]);

    // Unknown SHA — typed empty-not-found, never a silent hang
    // (MISSION.md §3 anti-pattern 6).
    let unknown = resolver.resolve_holders(&[0xFF; 32]);
    assert!(unknown.is_empty(), "unknown sha must return empty Vec");
}

/// Default-impl conformance: a `PeerResolver` that does NOT override
/// `resolve_holders` returns an empty `Vec`. Pins the v0.7.x
/// backward-compatibility invariant — pre-v0.8.0 impls must keep
/// compiling and behave conservatively (no peers claimed) rather than
/// e.g. panic.
#[test]
fn peer_resolver_resolve_holders_default_is_empty() {
    struct LegacyResolver;
    impl PeerResolver for LegacyResolver {
        fn resolve(&self, _: &str) -> Option<[u8; 64]> {
            None
        }
        // No resolve_holders override — exercises the default impl.
    }

    let r = LegacyResolver;
    let result = r.resolve_holders(&[0x55; 32]);
    assert!(
        result.is_empty(),
        "default impl must return empty Vec — v0.7.x-era resolvers \
         keep compiling under the v0.8.0 trait extension"
    );
}

/// `AttestationRef` round-trips on a `ContentBody` — the optional
/// pointer field survives encode/verify/dispatch. The fetcher uses
/// the attestation_id + signing_key_id to look up the federation
/// attestation that named this SHA (out-of-band, persist's
/// `federation_attestations` index).
#[tokio::test]
async fn content_body_with_attestation_ref_round_trip() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (handler, body_rx) = SignalHandler::<ContentBody>::new();
    let (inbound, shutdown, sender, _dir, recv_key_id) =
        setup::<ContentBody, _>(&tmp, Some(handler), test_edge_config()).await;

    let payload = b"valid honest bytes".to_vec();
    let sha = sha256_of(&payload);
    let body = ContentBody {
        sha256: sha,
        bytes: payload,
        attestation_ref: Some(AttestationRef {
            attestation_id: "22222222-2222-2222-2222-222222222222".into(),
            signing_key_id: "registry-author-01".into(),
        }),
    };
    let env_bytes = signed_envelope_bytes(&sender, &recv_key_id, &body).await;
    inbound.send(env_bytes).await.expect("inject");

    let received = tokio::time::timeout(Duration::from_secs(2), body_rx)
        .await
        .expect("body handler did not fire")
        .expect("oneshot");
    assert_eq!(received.sha256, sha);
    let aref = received
        .attestation_ref
        .as_ref()
        .expect("attestation_ref must survive round-trip");
    assert_eq!(aref.attestation_id, "22222222-2222-2222-2222-222222222222");
    assert_eq!(aref.signing_key_id, "registry-author-01");
    let _ = shutdown.send(true);
}

/// Wire-contract pin (mirrors `federation_announcement_wire_contract_pinned`).
/// All three CIRISEdge#21 family types MUST declare
/// `Delivery::Ephemeral` — point-to-point, retryable per spec point 5.
/// A regression that promotes them to `Mandatory` would silently
/// broadcast every byte fetch federation-wide; to `Durable` would
/// persist MiB-scale payload bodies in the outbound queue.
#[test]
fn content_fetch_wire_contract_pinned() {
    assert!(matches!(ContentFetch::DELIVERY, Delivery::Ephemeral));
    assert!(matches!(ContentBody::DELIVERY, Delivery::Ephemeral));
    assert!(matches!(ContentMiss::DELIVERY, Delivery::Ephemeral));

    assert_eq!(ContentFetch::TYPE, MessageType::ContentFetch);
    assert_eq!(ContentBody::TYPE, MessageType::ContentBody);
    assert_eq!(ContentMiss::TYPE, MessageType::ContentMiss);
}
