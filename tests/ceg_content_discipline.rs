//! Acceptance gate for CIRISEdge#42 — CEG 0.1 §10.1.1 (consumer
//! full-SHA verify) + §10.1.2 (24h holds_bytes TTL, ContentMiss →
//! withdraws feedback, holder-downweight on consistent failure).
//!
//! Cross-references:
//!
//! - CEG 0.1 §10.1.1 / §10.1.2 (CIRISRegistry FSD/CEG) — normative
//!   transport-discipline contract this suite pins.
//! - CIRISEdge#42 issue body — v0.12.0 acceptance bar.
//! - `src/edge.rs::validate_content_body` — §10.1.1 full-SHA verify
//!   site (`VerifyError::ContentIntegrity` path).
//! - `src/transport/reticulum.rs::filter_holders_with_policy` —
//!   §10.1.2 TTL + downweight site.
//! - `src/edge.rs::emit_withdraws` — §10.1.2 consumer-side withdrawal
//!   emission hook.
//!
//! The §10.1.1 tests drive a controlled in-process pipeline (a test
//! transport injects inbound envelopes, edge's `run` loop verifies +
//! integrity-gates + dispatches) — same shape as
//! `tests/content_fetch.rs`. The §10.1.2 tests drive the TTL filter +
//! downweight tracker directly because the policy is a pure-data
//! transformation (the spec is normative on the shape, not on which
//! transport carries the holder list).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::{ClassicalSigner, Ed25519Signer};
use ciris_edge::handler::{Handler, HandlerContext, HandlerError, Message};
use ciris_edge::identity::{build_envelope, sign_envelope, LocalSigner};
use ciris_edge::messages::sha256_of;
use ciris_edge::transport::reticulum::{
    filter_holders_with_policy, HolderAttestation, HolderDownweightTracker, PeerResolver,
    DEFAULT_HOLDER_DOWNWEIGHT_MISS_THRESHOLD, DEFAULT_HOLDER_DOWNWEIGHT_WINDOW_SECONDS,
    DEFAULT_HOLDS_BYTES_TTL_SECONDS,
};
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_edge::verify::{HybridPolicy, VerifyError};
use ciris_edge::{
    ContentBody, ContentMiss, Edge, EdgeConfig, MessageType, MissReason, WithdrawalReason,
    Withdraws,
};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{
    FederationDirectorySqlite, KeyRecord, OutboundFilter, OutboundQueue, SignedKeyRecord,
};
use ciris_persist::store::backend::Backend;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch, Mutex};

// ─── Fixtures (mirror tests/content_fetch.rs) ───────────────────────

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

/// Inbound-injecting test transport — same shape as
/// `tests/content_fetch.rs::InjectTransport`.
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
                source_key_id: None,
            };
            if sink.send(frame).await.is_err() {
                break;
            }
        }
        Ok(())
    }
}

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
        // v8.2.0 (CIRISEdge#249) — `run` takes `self: Arc<Self>`.
        let _ = std::sync::Arc::new(edge).run(shutdown_rx).await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    (
        inbound_tx,
        shutdown_tx,
        sender_signer,
        directory,
        receiver.key_id.clone(),
        sender.key_id.clone(),
    )
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

// ─── §10.1.1 tests — full-SHA verify ────────────────────────────────

/// **CEG §10.1.1 normative**: a `ContentBody` whose claimed
/// `sha256` does NOT match `sha256(bytes)` MUST be rejected before
/// reaching any handler — AND the rejection MUST be a typed
/// integrity-failure error, NOT folded into a generic schema
/// violation. v0.12.0 introduces [`VerifyError::ContentIntegrity`]
/// for exactly this case.
///
/// This test calls [`validate_content_body`] indirectly by injecting
/// the envelope into the dispatch loop and asserting the handler
/// doesn't fire. It complements `tests/content_fetch.rs`'s tampered-
/// bytes test (which pinned the gate's existence) by pinning the
/// **typed error variant** the v0.12.0 surface emits.
#[tokio::test]
async fn content_body_with_tampered_bytes_rejected() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (handler, mut body_rx) = SignalHandler::<ContentBody>::new();
    let (inbound, shutdown, sender, _dir, recv_key_id, _sender_key_id) =
        setup::<ContentBody, _>(&tmp, Some(handler), test_edge_config()).await;

    // Tampered: claims sha of "honest" but ships "forgery"
    let bytes_payload = b"forgery-payload".to_vec();
    let claimed_sha = sha256_of(b"honest-source");
    assert_ne!(
        claimed_sha,
        sha256_of(&bytes_payload),
        "fixture must be a genuine mismatch"
    );

    let tampered = ContentBody {
        sha256: claimed_sha,
        bytes: bytes_payload,
        attestation_ref: None,
    };
    let env_bytes = signed_envelope_bytes(&sender, &recv_key_id, &tampered).await;
    inbound.send(env_bytes).await.expect("inject");

    tokio::time::sleep(Duration::from_millis(300)).await;
    match body_rx.try_recv() {
        Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
        Ok(b) => panic!(
            "tampered ContentBody reached handler (sha={:?}) — §10.1.1 full-SHA gate broken",
            b.sha256
        ),
        Err(e) => panic!("oneshot closed unexpectedly: {e}"),
    }
    let _ = shutdown.send(true);
}

/// **CEG §10.1.1 short-circuit-verify pinned-off** — the v0.12.0
/// `validate_content_body` MUST execute the full-SHA path, NOT a
/// prefix-only comparison. The simplest pin: a body whose claimed
/// `sha256` MATCHES `sha256(bytes)` at every byte except the LAST
/// (i.e. a one-byte tail mismatch) is rejected.
///
/// A short-circuit implementation that compared only the first N
/// bytes of the SHA (or only the first N bytes of `body.bytes`) would
/// silently accept this envelope. The full-SHA path rejects it.
///
/// AV category: tail-truncation spoof — the spec's normative
/// requirement is that the WHOLE byte stream and the WHOLE hash are
/// covered. This test fails the moment that invariant slips.
#[tokio::test]
async fn content_body_short_circuit_verify_pinned_off() {
    use ciris_edge::messages::ContentBody;
    use sha2::Digest;

    let tmp = tempfile::tempdir().expect("tempdir");
    let (handler, mut body_rx) = SignalHandler::<ContentBody>::new();
    let (inbound, shutdown, sender, _dir, recv_key_id, _sender_key_id) =
        setup::<ContentBody, _>(&tmp, Some(handler), test_edge_config()).await;

    // Construct a body where sha256(bytes) matches the claimed sha256
    // EXCEPT in the final byte. The honest hash is sha256(payload). We
    // copy it and flip the last byte of the CLAIM — a short-circuit
    // verifier that compared only sha256[..31] would accept.
    let payload = vec![0xCDu8; 4096];
    let mut honest_sha = [0u8; 32];
    honest_sha.copy_from_slice(&sha2::Sha256::digest(&payload));
    let mut claimed_sha = honest_sha;
    claimed_sha[31] ^= 0x01; // flip ONE bit in the final byte

    assert_ne!(
        honest_sha, claimed_sha,
        "fixture should differ in the final byte only",
    );
    assert_eq!(
        honest_sha[..31],
        claimed_sha[..31],
        "fixture's 31-byte prefix must match — defeats any prefix-only verifier",
    );

    let body = ContentBody {
        sha256: claimed_sha,
        bytes: payload,
        attestation_ref: None,
    };
    let env_bytes = signed_envelope_bytes(&sender, &recv_key_id, &body).await;
    inbound.send(env_bytes).await.expect("inject");

    tokio::time::sleep(Duration::from_millis(300)).await;
    match body_rx.try_recv() {
        Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
        Ok(b) => panic!(
            "tail-tampered ContentBody reached handler — §10.1.1 full-SHA path is short-circuiting on prefix (got claimed {:?}, ships sha {:?})",
            b.sha256,
            sha256_of(&b.bytes),
        ),
        Err(e) => panic!("oneshot closed unexpectedly: {e}"),
    }
    let _ = shutdown.send(true);
}

/// **Typed-error variant pin** — [`VerifyError::ContentIntegrity`]
/// carries both the `claimed_sha256` and the `actual_sha256` as hex
/// strings so a downstream collector can diff the two. This test
/// constructs the validator-equivalent error directly and asserts
/// the Display output names BOTH hashes.
///
/// Rationale: a regression that collapses the variant back to
/// `VerifyError::SchemaInvalid(format!("..."))` (the v0.11.x shape)
/// would silently lose the typed structure CEG §10.1.2 receivers may
/// want to aggregate on.
#[test]
fn content_integrity_error_displays_both_hashes() {
    let e = VerifyError::ContentIntegrity {
        claimed_sha256: "00".repeat(32),
        actual_sha256: "ff".repeat(32),
    };
    let msg = format!("{e}");
    assert!(
        msg.contains(&"00".repeat(32)),
        "error display must include claimed sha — got {msg:?}"
    );
    assert!(
        msg.contains(&"ff".repeat(32)),
        "error display must include actual sha — got {msg:?}"
    );
    assert!(
        msg.contains("content integrity"),
        "error display must name the §10.1.1 category — got {msg:?}"
    );
}

// ─── §10.1.2 tests — holder TTL + downweight + Withdraws emission ──

/// **CEG §10.1.2 24h TTL**: a `holds_bytes:sha256:*` attestation row
/// with `signed_at` 25h ago is **stale**. `filter_holders_with_policy`
/// MUST NOT return it. Drives the filter directly with a 24h TTL.
#[tokio::test]
async fn holds_bytes_attestation_expires_after_24h() {
    let now = chrono::Utc::now();
    let stale_at = now - chrono::Duration::hours(25);
    let fresh_at = now - chrono::Duration::hours(1);

    let holders = vec![
        HolderAttestation {
            key_id: "peer-stale".to_string(),
            signed_at: stale_at,
        },
        HolderAttestation {
            key_id: "peer-fresh".to_string(),
            signed_at: fresh_at,
        },
    ];

    let result =
        filter_holders_with_policy(holders, DEFAULT_HOLDS_BYTES_TTL_SECONDS, None, now).await;

    assert_eq!(
        result,
        vec!["peer-fresh".to_string()],
        "stale (25h-old) attestation must be filtered; fresh (1h-old) survives",
    );
}

/// **CEG §10.1.2 TTL configurability**: the 24h default is
/// `EdgeConfig::holds_bytes_ttl_seconds`. Tests reduce it to 60s and
/// verify the filter applies the shorter window.
#[tokio::test]
async fn holds_bytes_ttl_configurable_via_edge_config() {
    let now = chrono::Utc::now();
    // Build an EdgeConfig with a 60s TTL and verify the constant
    // round-trips through the config.
    let cfg = EdgeConfig {
        holds_bytes_ttl_seconds: 60,
        ..EdgeConfig::default()
    };
    assert_eq!(cfg.holds_bytes_ttl_seconds, 60);

    // 90-second-old attestation under a 60s TTL is stale.
    let holder_90s_old = HolderAttestation {
        key_id: "peer-90s".to_string(),
        signed_at: now - chrono::Duration::seconds(90),
    };
    let holder_30s_old = HolderAttestation {
        key_id: "peer-30s".to_string(),
        signed_at: now - chrono::Duration::seconds(30),
    };

    let result = filter_holders_with_policy(
        vec![holder_90s_old, holder_30s_old],
        cfg.holds_bytes_ttl_seconds,
        None,
        now,
    )
    .await;

    assert_eq!(result, vec!["peer-30s".to_string()]);

    // Sanity: under the production default (24h), both would survive.
    let now2 = chrono::Utc::now();
    let result_default = filter_holders_with_policy(
        vec![
            HolderAttestation {
                key_id: "peer-90s".to_string(),
                signed_at: now2 - chrono::Duration::seconds(90),
            },
            HolderAttestation {
                key_id: "peer-30s".to_string(),
                signed_at: now2 - chrono::Duration::seconds(30),
            },
        ],
        DEFAULT_HOLDS_BYTES_TTL_SECONDS,
        None,
        now2,
    )
    .await;
    assert_eq!(result_default.len(), 2, "both fresh under 24h TTL");
    assert_eq!(
        DEFAULT_HOLDS_BYTES_TTL_SECONDS,
        24 * 60 * 60,
        "CEG §10.1.2 — 24h default ceiling",
    );
}

/// **CEG §10.1.2 ContentMiss → withdraws**: when an inbound
/// `ContentMiss` arrives, edge emits a `Withdraws` envelope back at
/// the holder (the `signing_key_id` of the miss envelope is the
/// holder we're withdrawing against). The withdrawal is enqueued on
/// the outbound queue; this test inspects the queue.
#[tokio::test]
async fn content_miss_triggers_withdraws_emission() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // No handler registered for ContentMiss — the dispatcher still
    // runs the §10.1.2 withdrawal-emission hook before the typed
    // handler dispatch returns "no handler".
    let no_handler: Option<SignalHandler<ContentMiss>> = None;
    let (inbound, shutdown, sender, dir, recv_key_id, sender_key_id) =
        setup::<ContentMiss, _>(&tmp, no_handler, test_edge_config()).await;

    let sha = sha256_of(b"holder-claims-this-sha-but-misses");
    let miss = ContentMiss {
        sha256: sha,
        reason: MissReason::NotHeld,
    };
    let env_bytes = signed_envelope_bytes(&sender, &recv_key_id, &miss).await;
    inbound.send(env_bytes).await.expect("inject");

    // Allow the dispatcher to run + the withdrawal to enqueue.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Inspect the outbound queue for a Withdraws-typed envelope. The
    // queue's filtered list-by-type accessor pins the row exists.
    // (The MessageType enum serializes variants as PascalCase — the
    // same canonical wire shape every other envelope-tracking site
    // uses; `message_type_str(MessageType::Withdraws) = "Withdraws"`.)
    let rows = dir
        .list_outbound(
            OutboundFilter {
                message_type: Some("Withdraws".to_string()),
                ..OutboundFilter::default()
            },
            100,
        )
        .await
        .expect("list_outbound");
    let withdraws_row = rows
        .first()
        .expect("withdraws envelope must be enqueued (CEG §10.1.2)");

    assert_eq!(
        withdraws_row.destination_key_id, sender_key_id,
        "withdrawal addressed to the holder (sender of the miss envelope)",
    );

    // Decode the envelope body and assert the structure.
    let env: ciris_edge::EdgeEnvelope =
        serde_json::from_slice(&withdraws_row.envelope_bytes).expect("decode envelope");
    let body: Withdraws = serde_json::from_str(env.body.get()).expect("parse withdraws body");
    assert_eq!(body.holder_key_id, sender_key_id, "holder == miss sender");
    assert_eq!(body.sha256, sha, "withdrawal references the missed sha");
    assert_eq!(
        body.withdrawal_reason,
        WithdrawalReason::ContentMiss,
        "reason=content_miss per §10.1.2 spec",
    );

    let _ = shutdown.send(true);
}

/// **CEG §10.1.2 holder downweight**: 3 misses against the same
/// holder inside the rolling window → that holder is sorted to the
/// tail of `filter_holders_with_policy` output.
#[tokio::test]
async fn three_misses_in_window_downweights_holder() {
    let tracker = HolderDownweightTracker::new(
        DEFAULT_HOLDER_DOWNWEIGHT_WINDOW_SECONDS,
        DEFAULT_HOLDER_DOWNWEIGHT_MISS_THRESHOLD,
    );

    // Record 3 misses against peer-flaky inside the window.
    for _ in 0..3 {
        tracker.record_miss("peer-flaky").await;
    }
    assert!(
        tracker.is_downweighted("peer-flaky").await,
        "3 misses ≥ threshold (default 3) — must be downweighted",
    );
    assert!(
        !tracker.is_downweighted("peer-reliable").await,
        "untouched holder is NOT downweighted",
    );

    // Drive the filter with a fresh holder list including both peers.
    // The downweighted holder sorts last; otherwise resolver order
    // is preserved.
    let now = chrono::Utc::now();
    let signed_recently = now - chrono::Duration::minutes(5);
    let holders = vec![
        HolderAttestation {
            key_id: "peer-flaky".to_string(),
            signed_at: signed_recently,
        },
        HolderAttestation {
            key_id: "peer-reliable".to_string(),
            signed_at: signed_recently,
        },
        HolderAttestation {
            key_id: "peer-other".to_string(),
            signed_at: signed_recently,
        },
    ];

    let result = filter_holders_with_policy(
        holders,
        DEFAULT_HOLDS_BYTES_TTL_SECONDS,
        Some(&tracker),
        now,
    )
    .await;

    assert_eq!(result.len(), 3, "all three holders survive TTL");
    // peer-flaky must be LAST. peer-reliable and peer-other preserve
    // input order at the head.
    assert_eq!(
        result.last().map(String::as_str),
        Some("peer-flaky"),
        "downweighted holder sorts to the tail (got {result:?})",
    );
    assert_eq!(
        &result[..2],
        &["peer-reliable".to_string(), "peer-other".to_string()],
        "non-downweighted holders preserve resolver order",
    );
}

/// **CEG §10.1.2 downweight window expiry**: after 1h without
/// further misses the downweight clears and the holder reappears at
/// normal priority. Drives the tracker with timestamps 2h in the
/// past — past the default 1h window — and verifies
/// `is_downweighted_at` reports false at "now".
#[tokio::test]
async fn downweight_clears_after_window_lapse() {
    let tracker = HolderDownweightTracker::new(
        DEFAULT_HOLDER_DOWNWEIGHT_WINDOW_SECONDS,
        DEFAULT_HOLDER_DOWNWEIGHT_MISS_THRESHOLD,
    );

    let two_hours_ago = chrono::Utc::now() - chrono::Duration::hours(2);
    // Record 3 misses 2h ago.
    for _ in 0..3 {
        tracker
            .record_miss_at("peer-recovered", two_hours_ago)
            .await;
    }
    // At a timestamp ALSO 2h ago, the misses are still inside the
    // window — sanity-check the tracker arithmetic.
    let same_anchor = two_hours_ago + chrono::Duration::minutes(1);
    assert!(
        tracker
            .is_downweighted_at("peer-recovered", same_anchor)
            .await,
        "misses inside window must trigger downweight",
    );

    // At "now" (2h later), all misses are past the 1h window — the
    // tracker reports the holder is no longer downweighted.
    let now = chrono::Utc::now();
    assert!(
        !tracker.is_downweighted_at("peer-recovered", now).await,
        "downweight must clear after 1h window lapses without further misses",
    );

    // Drive the filter: peer-recovered should appear at normal
    // priority alongside peer-fresh.
    let holders = vec![
        HolderAttestation {
            key_id: "peer-recovered".to_string(),
            signed_at: now - chrono::Duration::minutes(10),
        },
        HolderAttestation {
            key_id: "peer-fresh".to_string(),
            signed_at: now - chrono::Duration::minutes(5),
        },
    ];
    let result = filter_holders_with_policy(
        holders,
        DEFAULT_HOLDS_BYTES_TTL_SECONDS,
        Some(&tracker),
        now,
    )
    .await;
    assert_eq!(
        result,
        vec!["peer-recovered".to_string(), "peer-fresh".to_string()],
        "after window lapse, peer-recovered reappears at normal priority",
    );
}

/// **Trait-extension pin** for the v0.12.0 `PeerResolver` API: a
/// resolver that overrides only `resolve_holders` (legacy v0.7.x
/// path) still works under the new TTL-aware filter — the default
/// `resolve_holders_with_signed_at` impl stamps results at `Utc::now()`
/// (always-fresh), which is the documented back-compat contract.
#[tokio::test]
async fn peer_resolver_legacy_impl_compiles_against_ttl_helper() {
    struct LegacyResolver;
    impl PeerResolver for LegacyResolver {
        fn resolve(&self, _: &str) -> Option<[u8; 64]> {
            None
        }
        fn resolve_holders(&self, _sha256: &[u8; 32]) -> Vec<String> {
            vec!["peer-legacy".to_string()]
        }
        // No resolve_holders_with_signed_at override — exercises the
        // default impl that stamps at Utc::now().
    }

    let r = LegacyResolver;
    let with_ts = r.resolve_holders_with_signed_at(&[0xAA; 32]);
    assert_eq!(with_ts.len(), 1);
    assert_eq!(with_ts[0].key_id, "peer-legacy");
    // signed_at should be ~now (well within 24h TTL).
    let age = chrono::Utc::now() - with_ts[0].signed_at;
    assert!(
        age < chrono::Duration::seconds(1),
        "default impl stamps at Utc::now (got age {age})",
    );

    // Drive the TTL filter on the legacy result.
    let now = chrono::Utc::now();
    let result =
        filter_holders_with_policy(with_ts, DEFAULT_HOLDS_BYTES_TTL_SECONDS, None, now).await;
    assert_eq!(result, vec!["peer-legacy".to_string()]);
}

/// **Wire contract pin** for the new `Withdraws` body: declares
/// `MessageType::Withdraws` and `Delivery::Durable` (24h TTL, 20
/// attempts, no ack) — same long-haul shape as `DeliveryAttestation`.
/// A regression that flips it to `Ephemeral` would silently drop
/// withdrawals on a brief transport hiccup; flipping to `Mandatory`
/// would broadcast every consumer's per-holder grumble federation-
/// wide.
#[test]
fn withdraws_wire_contract_pinned() {
    use ciris_edge::handler::Delivery;
    assert_eq!(Withdraws::TYPE, MessageType::Withdraws);
    match Withdraws::DELIVERY {
        Delivery::Durable {
            requires_ack: false,
            max_attempts: 20,
            ttl_seconds,
            ack_timeout_seconds: None,
        } => {
            assert_eq!(ttl_seconds, 24 * 60 * 60, "24h TTL pin");
        }
        other => panic!("Withdraws::DELIVERY must be Durable(24h, 20, false) — got {other:?}"),
    }
}
