//! Acceptance gate for CIRISEdge#19 — AccordCarrier wire-layer 2-of-3
//! multi-sig authority verification at edge's `dispatch_inbound`.
//!
//! Defense-in-depth on the v0.6.0 `FederationAnnouncement` consumer-side
//! gate: a compromised peer can no longer propagate an invalid
//! CONSTITUTIONAL envelope past the first hop running verified edge
//! code. Failures REFUSE propagation and emit a substrate-signed
//! [`DeliveryRefusalAttestation`] so adversarial suppression of
//! legitimate accords stays distinguishable from suppression of forged
//! ones (issue body §"Ask" point 4).
//!
//! Cross-references:
//!
//! - CIRISEdge#19 (this issue).
//! - CIRISPersist v2.7.0 — `FederationDirectory::list_keys_by_identity_type`
//!   (the persist-side surface the wire-layer hook calls).
//! - `FSD-002 §7` HUMANITY_ACCORD constitutional layer.
//!
//! The suite drives `Edge::dispatch_inbound_for_test` directly so the
//! wire-layer gate is exercised without standing up a Reticulum mesh:
//! each test seeds persist's federation directory with an
//! `accord_holder` set, constructs a `FederationAnnouncement` body
//! with the appropriate signature set, wraps it in a signed
//! `EdgeEnvelope`, and asserts the outcome (acceptance attestation
//! emitted xor refusal attestation emitted xor neither when the body
//! is not AccordCarrier).

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::Utc;
use ciris_crypto::{ClassicalSigner, Ed25519Signer};
use ciris_edge::identity::{build_envelope, sign_envelope, LocalSigner};
use ciris_edge::messages::{
    AccordSignature, AnnouncementKind, AnnouncementPriority, AuthorityClass,
    DeliveryRefusalAttestation, FederationAnnouncement, MessageType, RefusalReason,
    ACCORD_THRESHOLD_M_OF_N,
};
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_edge::verify::HybridPolicy;
use ciris_edge::{Edge, EdgeConfig, EdgeEnvelope, OutboundHandle};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{
    FederationDirectorySqlite, KeyRecord, OutboundFilter, OutboundRow, SignedKeyRecord,
};
use ciris_persist::store::backend::Backend;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

/// Initialize a tracing subscriber once per process — emits warn/debug
/// lines from `dispatch_inbound` on `RUST_LOG=ciris_edge=debug` so a
/// test failure diagnoses itself.
fn init_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("ciris_edge=info")),
            )
            .with_test_writer()
            .try_init();
    });
}

// ─── Fixture helpers ────────────────────────────────────────────────

/// A test federation identity: deterministic seed + key_id + the keys
/// derived from it. Same shape as `tests/federation_announcement.rs::FedKey`;
/// duplicated here to keep the suite self-contained (per the issue
/// body's "mirror federation_announcement.rs shape" guidance).
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

    /// Sign the given canonical bytes with this identity's seed.
    fn sign(&self, canonical: &[u8]) -> Vec<u8> {
        self.signer().sign(canonical).expect("sign")
    }
}

/// Build a scrub-signed `KeyRecord`. `subject` is the row's key;
/// `signer` is who scrub-signed it. For `accord_holder` rows, attaches
/// the platform-attestation evidence persist v2.5.0+ requires (V048
/// schema gate); other identity_types get `attestation_evidence: None`.
fn signed_record(subject: &FedKey, signer: &FedKey, identity_type: &str) -> KeyRecord {
    let envelope = serde_json::json!({ "key_id": subject.key_id });
    let canonical = serde_json::to_vec(&envelope).expect("serialize");
    let digest = Sha256::digest(&canonical);
    let sig = signer.signer().sign(digest.as_slice()).expect("sign");
    let ts = chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
        .unwrap()
        .into();
    let attestation_evidence = if identity_type == "accord_holder" {
        // Mirror the persist v2.5.0+ test fixture shape — see
        // CIRISPersist `sqlite.rs::fed_key_with_identity_type`.
        Some(serde_json::json!({
            "platform_attestation": {
                "Android": {
                    "key_attestation_chain": [
                        vec![0x30u8, 0x82, 0x01, 0x00],
                        vec![0x30u8, 0x82, 0x02, 0x00],
                    ],
                    "play_integrity_token": "eyJhbGciOiJIUzI1NiJ9.fake.token",
                    "strongbox_backed": true,
                }
            },
            "nonce_captured_at": Utc::now().to_rfc3339(),
        }))
    } else {
        None
    };
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
        attestation_evidence,
    }
}

/// Open an in-memory persist SQLite backend and seed it with rows.
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

/// A no-op transport — we drive the inbound side via
/// `Edge::dispatch_inbound_for_test`, never the listener loop.
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
    // Test fixtures are Ed25519-only (no ML-DSA-65 seed); relax the
    // default `HybridPolicy::Strict` so verify accepts hybrid-pending
    // rows. Same pattern as `tests/content_fetch.rs::test_edge_config`.
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

/// Build a `FederationAnnouncement` body with the given priority and
/// no accord-holder signatures attached. Tests add signatures via
/// [`with_accord_sigs`] before signing the envelope.
fn announcement(priority: AnnouncementPriority) -> FederationAnnouncement {
    FederationAnnouncement {
        priority,
        kind: AnnouncementKind::AccordCarrier,
        title: "CONSTITUTIONAL halt — CIRISEdge#19 test".into(),
        body: "exercise the wire-layer 2-of-3 multi-sig gate".into(),
        authority_class: AuthorityClass::HumanityAccord,
        accord_payload: None, // payload bytes are application-tier; the wire-layer gate is signature-set only
        supersedes: None,
        expires_at: chrono::DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
        evidence_refs: vec![],
        accord_signatures: vec![],
    }
}

/// Attach one `AccordSignature` produced by `holder`'s seed over the
/// announcement's canonical bytes. Returns the announcement with the
/// signature appended.
fn with_accord_sig(mut ann: FederationAnnouncement, holder: &FedKey) -> FederationAnnouncement {
    let canonical = ann
        .canonical_bytes_for_accord_signatures()
        .expect("canonical bytes");
    let sig = holder.sign(&canonical);
    ann.accord_signatures.push(AccordSignature {
        key_id: holder.key_id.clone(),
        signature_ed25519_base64: B64.encode(sig),
    });
    ann
}

/// Build a verified `EdgeEnvelope` carrying `ann` as its body, signed
/// by `sender` and addressed to `recipient_key_id`.
async fn build_envelope_signed_by(
    sender: &Arc<LocalSigner>,
    recipient_key_id: &str,
    ann: &FederationAnnouncement,
) -> Vec<u8> {
    let mut env = build_envelope(
        MessageType::FederationAnnouncement,
        &sender.key_id,
        recipient_key_id,
        ann,
        None,
    )
    .expect("build envelope");
    sign_envelope(sender, &mut env)
        .await
        .expect("sign envelope");
    serde_json::to_vec(&env).expect("serialize envelope")
}

/// Snapshot the outbound queue rows of the given `message_type`. Used
/// to assert that (a) the refusal/acceptance attestation was emitted
/// and (b) no other side-effect rows materialized.
async fn outbound_rows_of(queue: &Arc<SqliteBackend>, message_type: &str) -> Vec<OutboundRow> {
    OutboundHandle::list_outbound(
        &**queue,
        OutboundFilter {
            message_type: Some(message_type.to_string()),
            ..Default::default()
        },
        100,
    )
    .await
    .expect("list_outbound")
}

/// Decode the body of an outbound row as a `DeliveryRefusalAttestation`.
fn parse_refusal(row: &OutboundRow) -> DeliveryRefusalAttestation {
    let env: EdgeEnvelope = serde_json::from_slice(&row.envelope_bytes).expect("envelope parse");
    serde_json::from_str(env.body.get()).expect("refusal body parse")
}

// ─── Tests ──────────────────────────────────────────────────────────

/// Happy path — 2 of 3 valid signatures from distinct accord-holders
/// satisfies [`ACCORD_THRESHOLD_M_OF_N`]; edge propagates the
/// announcement and emits the v0.6.0 acceptance `DeliveryAttestation`.
/// No `DeliveryRefusalAttestation` row appears.
#[tokio::test]
async fn accord_carrier_2_of_3_valid_propagates() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let steward = FedKey::new("steward-fed", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let sender = FedKey::new("steward-sender", 0xBB);
    let h1 = FedKey::new("accord-holder-1", 0x11);
    let h2 = FedKey::new("accord-holder-2", 0x22);
    let h3 = FedKey::new("accord-holder-3", 0x33);

    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&me, &steward, "agent"),
        signed_record(&sender, &steward, "steward"),
        signed_record(&h1, &steward, "accord_holder"),
        signed_record(&h2, &steward, "accord_holder"),
        signed_record(&h3, &steward, "accord_holder"),
    ])
    .await;
    let queue = directory.clone();

    let edge = build_edge(&tmp, &me, directory, queue.clone()).await;
    let sender_signer = sender.local_signer(tmp.path()).await;
    let ann = announcement(AnnouncementPriority::AccordCarrier);
    let ann = with_accord_sig(ann, &h1);
    let ann = with_accord_sig(ann, &h2); // 2 of 3 — threshold met

    let env_bytes = build_envelope_signed_by(&sender_signer, &me.key_id, &ann).await;
    edge.dispatch_inbound_for_test(InboundFrame {
        envelope_bytes: env_bytes,
        transport: TransportId::HTTP,
        received_at: Utc::now(),
    })
    .await;

    // Acceptance attestation enqueued; no refusal row.
    assert_eq!(
        outbound_rows_of(&queue, "DeliveryAttestation").await.len(),
        1,
        "AccordCarrier with valid 2-of-3 multi-sig must propagate and emit DeliveryAttestation"
    );
    assert_eq!(
        outbound_rows_of(&queue, "DeliveryRefusalAttestation")
            .await
            .len(),
        0,
        "valid 2-of-3 multi-sig must NOT emit a refusal attestation"
    );
}

/// 1 of 3 valid — threshold not met. Edge refuses to propagate; the
/// announcement does NOT emit a `DeliveryAttestation`; a
/// `DeliveryRefusalAttestation` with
/// `reason: InsufficientAccordSignatures { found: 1, required: 2 }`
/// is emitted instead.
#[tokio::test]
async fn accord_carrier_1_of_3_refuses_and_emits_refusal() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let steward = FedKey::new("steward-fed", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let sender = FedKey::new("steward-sender", 0xBB);
    let h1 = FedKey::new("accord-holder-1", 0x11);
    let h2 = FedKey::new("accord-holder-2", 0x22);
    let h3 = FedKey::new("accord-holder-3", 0x33);

    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&me, &steward, "agent"),
        signed_record(&sender, &steward, "steward"),
        signed_record(&h1, &steward, "accord_holder"),
        signed_record(&h2, &steward, "accord_holder"),
        signed_record(&h3, &steward, "accord_holder"),
    ])
    .await;
    let queue = directory.clone();

    let edge = build_edge(&tmp, &me, directory, queue.clone()).await;
    let sender_signer = sender.local_signer(tmp.path()).await;
    let ann = announcement(AnnouncementPriority::AccordCarrier);
    let ann = with_accord_sig(ann, &h1); // only 1 of required 2

    let env_bytes = build_envelope_signed_by(&sender_signer, &me.key_id, &ann).await;
    edge.dispatch_inbound_for_test(InboundFrame {
        envelope_bytes: env_bytes,
        transport: TransportId::HTTP,
        received_at: Utc::now(),
    })
    .await;

    // No acceptance attestation — propagation refused.
    assert_eq!(
        outbound_rows_of(&queue, "DeliveryAttestation").await.len(),
        0,
        "1-of-3 must NOT propagate; the acceptance attestation MUST NOT emit"
    );
    let refusals = outbound_rows_of(&queue, "DeliveryRefusalAttestation").await;
    assert_eq!(
        refusals.len(),
        1,
        "exactly one refusal attestation enqueued"
    );
    let refusal = parse_refusal(&refusals[0]);
    assert_eq!(
        refusal.refusal_reason,
        RefusalReason::InsufficientAccordSignatures {
            found: 1,
            required: ACCORD_THRESHOLD_M_OF_N.0,
        },
        "refusal must carry InsufficientAccordSignatures with found=1 required=2"
    );
}

/// 3 of 3 valid — over-threshold is fine. Acceptance attestation
/// emits as normal.
#[tokio::test]
async fn accord_carrier_3_of_3_propagates() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let steward = FedKey::new("steward-fed", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let sender = FedKey::new("steward-sender", 0xBB);
    let h1 = FedKey::new("accord-holder-1", 0x11);
    let h2 = FedKey::new("accord-holder-2", 0x22);
    let h3 = FedKey::new("accord-holder-3", 0x33);

    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&me, &steward, "agent"),
        signed_record(&sender, &steward, "steward"),
        signed_record(&h1, &steward, "accord_holder"),
        signed_record(&h2, &steward, "accord_holder"),
        signed_record(&h3, &steward, "accord_holder"),
    ])
    .await;
    let queue = directory.clone();

    let edge = build_edge(&tmp, &me, directory, queue.clone()).await;
    let sender_signer = sender.local_signer(tmp.path()).await;
    let ann = announcement(AnnouncementPriority::AccordCarrier);
    let ann = with_accord_sig(ann, &h1);
    let ann = with_accord_sig(ann, &h2);
    let ann = with_accord_sig(ann, &h3); // 3 of 3 — over threshold

    let env_bytes = build_envelope_signed_by(&sender_signer, &me.key_id, &ann).await;
    edge.dispatch_inbound_for_test(InboundFrame {
        envelope_bytes: env_bytes,
        transport: TransportId::HTTP,
        received_at: Utc::now(),
    })
    .await;

    assert_eq!(
        outbound_rows_of(&queue, "DeliveryAttestation").await.len(),
        1,
        "over-threshold (3 of 3) must propagate normally"
    );
    assert_eq!(
        outbound_rows_of(&queue, "DeliveryRefusalAttestation")
            .await
            .len(),
        0
    );
}

/// 2 cryptographically valid + 1 with bad bytes. Threshold met by the
/// 2 valid sigs → propagate. The invalid sig was checked and
/// rejected, but did NOT cause refusal because 2-of-3 satisfies the
/// threshold.
#[tokio::test]
async fn accord_carrier_2_valid_1_invalid_propagates() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let steward = FedKey::new("steward-fed", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let sender = FedKey::new("steward-sender", 0xBB);
    let h1 = FedKey::new("accord-holder-1", 0x11);
    let h2 = FedKey::new("accord-holder-2", 0x22);
    let h3 = FedKey::new("accord-holder-3", 0x33);

    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&me, &steward, "agent"),
        signed_record(&sender, &steward, "steward"),
        signed_record(&h1, &steward, "accord_holder"),
        signed_record(&h2, &steward, "accord_holder"),
        signed_record(&h3, &steward, "accord_holder"),
    ])
    .await;
    let queue = directory.clone();

    let edge = build_edge(&tmp, &me, directory, queue.clone()).await;
    let sender_signer = sender.local_signer(tmp.path()).await;
    let mut ann = announcement(AnnouncementPriority::AccordCarrier);
    ann = with_accord_sig(ann, &h1);
    ann = with_accord_sig(ann, &h2);
    // Append a third entry claiming to be from h3 but with junk bytes.
    ann.accord_signatures.push(AccordSignature {
        key_id: h3.key_id.clone(),
        signature_ed25519_base64: B64.encode([0xEEu8; 64]),
    });

    let env_bytes = build_envelope_signed_by(&sender_signer, &me.key_id, &ann).await;
    edge.dispatch_inbound_for_test(InboundFrame {
        envelope_bytes: env_bytes,
        transport: TransportId::HTTP,
        received_at: Utc::now(),
    })
    .await;

    // 2 valid sigs meet the threshold; the invalid sig is rejected
    // but doesn't sink the announcement.
    assert_eq!(
        outbound_rows_of(&queue, "DeliveryAttestation").await.len(),
        1,
        "2 valid + 1 invalid must propagate (threshold satisfied by valid sigs alone)"
    );
    assert_eq!(
        outbound_rows_of(&queue, "DeliveryRefusalAttestation")
            .await
            .len(),
        0
    );
}

/// Persist holds NO accord-holder keys → refusal emits with
/// `reason: NoAccordHoldersConfigured` (substrate not bootstrapped
/// for constitutional traffic; the trust chain has no root).
#[tokio::test]
async fn accord_carrier_0_accord_holders_in_directory_refuses_with_no_accord_holders_configured() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let steward = FedKey::new("steward-fed", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let sender = FedKey::new("steward-sender", 0xBB);
    let h1 = FedKey::new("would-be-holder-1", 0x11);
    let h2 = FedKey::new("would-be-holder-2", 0x22);

    // Directory has stewards + agents but NO accord_holder rows.
    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&me, &steward, "agent"),
        signed_record(&sender, &steward, "steward"),
    ])
    .await;
    let queue = directory.clone();

    let edge = build_edge(&tmp, &me, directory, queue.clone()).await;
    let sender_signer = sender.local_signer(tmp.path()).await;
    let ann = announcement(AnnouncementPriority::AccordCarrier);
    // Even a perfectly-signed envelope refuses — without accord_holder
    // rows in persist, edge CANNOT verify the multi-sig and so refuses
    // (the conservative safe-default per CIRISEdge#19 issue body).
    let ann = with_accord_sig(ann, &h1);
    let ann = with_accord_sig(ann, &h2);

    let env_bytes = build_envelope_signed_by(&sender_signer, &me.key_id, &ann).await;
    edge.dispatch_inbound_for_test(InboundFrame {
        envelope_bytes: env_bytes,
        transport: TransportId::HTTP,
        received_at: Utc::now(),
    })
    .await;

    assert_eq!(
        outbound_rows_of(&queue, "DeliveryAttestation").await.len(),
        0
    );
    let refusals = outbound_rows_of(&queue, "DeliveryRefusalAttestation").await;
    assert_eq!(refusals.len(), 1);
    assert_eq!(
        parse_refusal(&refusals[0]).refusal_reason,
        RefusalReason::NoAccordHoldersConfigured,
        "missing accord-holder directory must refuse with NoAccordHoldersConfigured"
    );
}

/// 2 valid signatures from the SAME accord-holder key — the threshold
/// is "DISTINCT holders", so this counts as 1; threshold not met,
/// refuses. Pins the duplicate-holders invariant from CIRISEdge#19.
#[tokio::test]
async fn accord_carrier_duplicate_signatures_from_same_holder_count_once() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let steward = FedKey::new("steward-fed", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let sender = FedKey::new("steward-sender", 0xBB);
    let h1 = FedKey::new("accord-holder-1", 0x11);
    let h2 = FedKey::new("accord-holder-2", 0x22);
    let h3 = FedKey::new("accord-holder-3", 0x33);

    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&me, &steward, "agent"),
        signed_record(&sender, &steward, "steward"),
        signed_record(&h1, &steward, "accord_holder"),
        signed_record(&h2, &steward, "accord_holder"),
        signed_record(&h3, &steward, "accord_holder"),
    ])
    .await;
    let queue = directory.clone();

    let edge = build_edge(&tmp, &me, directory, queue.clone()).await;
    let sender_signer = sender.local_signer(tmp.path()).await;
    let mut ann = announcement(AnnouncementPriority::AccordCarrier);
    // Two signatures both from h1 — the canonical bytes are the same
    // because the body up to (but excluding) the accord_signatures
    // field is what gets signed; both sigs are valid against the
    // same canonical bytes, but they come from the same holder.
    ann = with_accord_sig(ann, &h1);
    // Re-sign (will produce an identical signature, but the dedup
    // invariant fires on key_id, not signature bytes).
    let canonical = ann
        .canonical_bytes_for_accord_signatures()
        .expect("canonical");
    ann.accord_signatures.push(AccordSignature {
        key_id: h1.key_id.clone(),
        signature_ed25519_base64: B64.encode(h1.sign(&canonical)),
    });

    let env_bytes = build_envelope_signed_by(&sender_signer, &me.key_id, &ann).await;
    edge.dispatch_inbound_for_test(InboundFrame {
        envelope_bytes: env_bytes,
        transport: TransportId::HTTP,
        received_at: Utc::now(),
    })
    .await;

    assert_eq!(
        outbound_rows_of(&queue, "DeliveryAttestation").await.len(),
        0
    );
    let refusals = outbound_rows_of(&queue, "DeliveryRefusalAttestation").await;
    assert_eq!(refusals.len(), 1);
    assert_eq!(
        parse_refusal(&refusals[0]).refusal_reason,
        RefusalReason::InsufficientAccordSignatures {
            found: 1,
            required: ACCORD_THRESHOLD_M_OF_N.0,
        },
        "duplicate signatures from the same holder must collapse to 1 distinct verifier"
    );
}

/// Non-`AccordCarrier` announcements bypass the wire-layer threshold
/// check — the v0.6.0 acceptance-attestation path runs unmodified
/// (already-passing behavior preserved).
#[tokio::test]
async fn accord_carrier_non_accord_class_announcements_skip_threshold_check() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let steward = FedKey::new("steward-fed", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let sender = FedKey::new("steward-sender", 0xBB);

    // No accord-holder rows in persist — and yet a non-AccordCarrier
    // priority announcement MUST propagate normally because the
    // wire-layer threshold check is bypassed for non-AccordCarrier
    // priorities.
    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&me, &steward, "agent"),
        signed_record(&sender, &steward, "steward"),
    ])
    .await;
    let queue = directory.clone();

    let edge = build_edge(&tmp, &me, directory, queue.clone()).await;
    let sender_signer = sender.local_signer(tmp.path()).await;
    let mut ann = announcement(AnnouncementPriority::Advisory);
    // The non-AccordCarrier path doesn't care about accord_signatures;
    // leave it empty.
    ann.kind = AnnouncementKind::PolicyUpdate;
    ann.authority_class = AuthorityClass::RootWa;

    let env_bytes = build_envelope_signed_by(&sender_signer, &me.key_id, &ann).await;
    edge.dispatch_inbound_for_test(InboundFrame {
        envelope_bytes: env_bytes,
        transport: TransportId::HTTP,
        received_at: Utc::now(),
    })
    .await;

    // Acceptance attestation emits; no refusal.
    assert_eq!(
        outbound_rows_of(&queue, "DeliveryAttestation").await.len(),
        1,
        "Advisory-priority announcement must propagate without wire-layer threshold check"
    );
    assert_eq!(
        outbound_rows_of(&queue, "DeliveryRefusalAttestation")
            .await
            .len(),
        0
    );
}

/// Wire round-trip — encode + verify the new attestation type;
/// canonical bytes deterministic; cross-repo wire-shape pin.
///
/// Verifies (a) JSON round-trip preserves every field including the
/// `refusal_reason` discriminator, (b) `canonical_bytes` is
/// deterministic given the same input, (c) classical Ed25519 signature
/// over `canonical_bytes` verifies against the claimed peer pubkey.
#[tokio::test]
async fn delivery_refusal_attestation_signature_round_trips() {
    use ciris_crypto::{ClassicalVerifier, Ed25519Verifier};
    use ciris_edge::messages::TransportMedium;

    init_tracing();

    let peer = FedKey::new("edge-refuser", 0x77);
    let refusal_template = DeliveryRefusalAttestation {
        announcement_id: "11111111-2222-3333-4444-555555555555".into(),
        announcement_canonical_hash_base64: B64.encode([0x42u8; 32]),
        peer_key_id: peer.key_id.clone(),
        peer_pubkey_ed25519_base64: peer.pubkey_b64(),
        refused_at: chrono::DateTime::parse_from_rfc3339("2026-06-01T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc),
        transport_id: TransportMedium::Reticulum,
        refusal_reason: RefusalReason::InsufficientAccordSignatures {
            found: 1,
            required: 2,
        },
        signature_classical_base64: String::new(),
        signature_pqc_base64: None,
    };

    // canonical_bytes is deterministic.
    let canonical_a = refusal_template.canonical_bytes().expect("canonical a");
    let canonical_b = refusal_template.canonical_bytes().expect("canonical b");
    assert_eq!(
        canonical_a, canonical_b,
        "canonical_bytes must be deterministic"
    );

    // Sign + populate the signature; verify against the pubkey.
    let sig = peer.sign(&canonical_a);
    let mut refusal = refusal_template.clone();
    refusal.signature_classical_base64 = B64.encode(&sig);

    let pubkey_bytes = peer.signer().public_key().expect("pubkey");
    let verified = Ed25519Verifier::new()
        .verify(&pubkey_bytes, &canonical_a, &sig)
        .expect("verify Ok");
    assert!(verified, "self-signed refusal must verify");

    // JSON round-trip preserves every field (the wire shape persist's
    // admission deserializes from when this type is admitted at v0.11+).
    let json = serde_json::to_string(&refusal).expect("json ser");
    let back: DeliveryRefusalAttestation = serde_json::from_str(&json).expect("json de");
    assert_eq!(back, refusal);

    // The other RefusalReason variants also round-trip.
    for reason in [
        RefusalReason::InvalidAccordSignature,
        RefusalReason::NoAccordHoldersConfigured,
        RefusalReason::InsufficientAccordSignatures {
            found: 0,
            required: 2,
        },
    ] {
        let mut r = refusal.clone();
        r.refusal_reason = reason.clone();
        let s = serde_json::to_string(&r).expect("ser");
        let back: DeliveryRefusalAttestation = serde_json::from_str(&s).expect("de");
        assert_eq!(back.refusal_reason, reason);
    }
}
