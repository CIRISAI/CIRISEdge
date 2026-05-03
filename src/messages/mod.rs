//! Wire envelope + message-type discriminator + concrete message types.
//!
//! Mission: every byte the host code touches has been verified against
//! persist's federation directory. The envelope shape is the contract.
//! See [`FSD/CIRIS_EDGE.md`](../../FSD/CIRIS_EDGE.md) §3.4.
//!
//! Canonicalization for verify is `Engine.canonicalize_envelope_for_signing()`
//! only — never re-implemented in edge (CIRISPersist#7 closure; AV-5).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::handler::{Delivery, Message};

/// Wire-format schema version. Pinned by edge release tag; downstream
/// peers gate on a strict allowlist (AV-7).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SchemaVersion {
    /// Phase 1 baseline.
    V1_0_0,
}

/// Discriminator for the body union. Edge dispatches on this *after*
/// verify; handlers receive the parsed body struct, not raw bytes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// Trace batches from agent → lens. Ephemeral.
    AccordEventsBatch,
    /// Build-manifest publication primitive → registry. Durable.
    BuildManifestPublication,
    /// Data-subject access request — DSAR chain. Durable, requires_ack.
    DSARRequest,
    DSARResponse,
    /// Federation-directory gossip — peer-attests-key. Durable, fire-and-forget.
    AttestationGossip,
    /// New-peer key registration → directory. Durable, requires_ack.
    PublicKeyRegistration,
    /// Directory query — "do you have this key_id?". Ephemeral request-response.
    FederationKeyDirectoryQuery,
}

/// The signed wire envelope. Carries one verified message + the
/// metadata needed for replay protection, hybrid PQC verify, and
/// content-derived ACK matching.
///
/// Canonical bytes for signature are
/// `Engine.canonicalize_envelope_for_signing()` applied to this struct
/// (which strips `signature` and `signature_pqc` before canonicalizing).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EdgeEnvelope {
    /// Wire-format version. Strict allowlist enforced (AV-7).
    pub edge_schema_version: SchemaVersion,
    /// Sender's `federation_keys.key_id`.
    pub signing_key_id: String,
    /// Recipient's `federation_keys.key_id`. Mismatch → typed
    /// `misrouted` reject before body parse (AV-8).
    pub destination_key_id: String,
    /// Body discriminator.
    pub message_type: MessageType,
    /// Per-message timestamp; replay-window arithmetic baseline.
    pub sent_at: DateTime<Utc>,
    /// Random per-message nonce; replay-window key with `signing_key_id`
    /// (AV-3).
    pub nonce: [u8; 16],
    /// Canonical-bytes-shaped body. Preserved verbatim via `RawValue`
    /// so signature verification sees exactly what the sender signed
    /// (AV-5; never re-serialized).
    pub body: Box<RawValue>,
    /// Ed25519 signature over canonical-bytes. Base64.
    pub signature: String,
    /// ML-DSA-65 PQC signature (base64). Required when sender's
    /// `federation_keys` row is hybrid-complete; `None` for hybrid-
    /// pending rows. Consumer policy ([`crate::HybridPolicy`]) selects
    /// acceptance (OQ-11 closure; CIRISPersist v0.4.1 surface).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_pqc: Option<String>,
    /// 32-byte `body_sha256` of the original envelope this is a
    /// response/ACK to. Set on response envelopes; `None` on first-
    /// touch envelopes. Used by sender's `edge_outbound_queue` to
    /// match ACKs to originals (FSD/EDGE_OUTBOUND_QUEUE.md; OQ-09
    /// closure).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<[u8; 32]>,
}

// ─── Phase 1 message types ──────────────────────────────────────────
//
// Each type below implements [`Message`], declaring its wire
// discriminator + delivery class. Wire shapes wrap persist's existing
// types via `#[serde(transparent)]` newtypes where applicable —
// preserves byte-equivalence with the existing TRACE_WIRE_FORMAT and
// federation-directory schemas.

/// Trace batch from agent → lens. Ephemeral; lens's handler calls
/// `engine.receive_and_persist` on the verified envelope bytes
/// (which does the trace-level hash-chain verify + scrub + persist).
///
/// Wire shape is the existing `BatchEnvelope` from `ciris-persist`'s
/// schema — transparent newtype preserves byte-equivalence with the
/// agent's TRACE_WIRE_FORMAT.md emitter.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
pub struct AccordEventsBatch(pub ciris_persist::schema::BatchEnvelope);

/// Lens's response to an `AccordEventsBatch`. Counts the events that
/// landed (not all may insert if scrub rejects or dedup fires).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccordEventsResponse {
    pub trace_events_inserted: u32,
    pub trace_llm_calls_inserted: u32,
    pub deduplicated: u32,
}

impl Message for AccordEventsBatch {
    const TYPE: MessageType = MessageType::AccordEventsBatch;
    const DELIVERY: Delivery = Delivery::Ephemeral;
    type Response = AccordEventsResponse;
}

/// Hybrid-signed build manifest published to the registry. Durable;
/// the registry must eventually receive it.
///
/// Body wraps a `serde_json::Value` for now — the BuildManifest type
/// lives in `ciris-build-sign` (CIRISVerify) and isn't on the prelude
/// re-export path. TODO: swap to typed shape once registry-side
/// integration confirms the field set.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
pub struct BuildManifestPublication(pub serde_json::Value);

/// Registry's response to a `BuildManifestPublication`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BuildManifestPublicationResponse {
    pub registered: bool,
    pub manifest_id: String,
}

impl Message for BuildManifestPublication {
    const TYPE: MessageType = MessageType::BuildManifestPublication;
    const DELIVERY: Delivery = Delivery::Durable {
        requires_ack: true,
        max_attempts: 100,
        ttl_seconds: 7 * 24 * 60 * 60, // 7 days
        ack_timeout_seconds: Some(300),
    };
    type Response = BuildManifestPublicationResponse;
}

/// Data-subject access request — "delete all traces for
/// `(agent_id_hash, signature_key_id)`" (per CIRISPersist#15 per-key
/// scope). Durable; requires_ack so the requester knows when the
/// deletion landed.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DSARRequest {
    pub target_agent_id_hash: String,
    pub target_signature_key_id: String,
    pub requested_by: String,
    pub justification: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DSARResponse {
    pub deleted_trace_events: u64,
    pub deleted_trace_llm_calls: u64,
    pub completed_at: DateTime<Utc>,
}

impl Message for DSARRequest {
    const TYPE: MessageType = MessageType::DSARRequest;
    const DELIVERY: Delivery = Delivery::Durable {
        requires_ack: true,
        max_attempts: 20,
        ttl_seconds: 24 * 60 * 60, // 24 hours
        ack_timeout_seconds: Some(600),
    };
    type Response = DSARResponse;
}

/// Federation-directory gossip — peer A vouches for peer B's key.
/// Durable, fire-and-forget (no ack).
///
/// Transparent over `SignedAttestation` from persist — same wire
/// shape as the directory's existing attestation rows.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
pub struct AttestationGossip(pub ciris_persist::prelude::SignedAttestation);

impl Message for AttestationGossip {
    const TYPE: MessageType = MessageType::AttestationGossip;
    const DELIVERY: Delivery = Delivery::Durable {
        requires_ack: false,
        max_attempts: 10,
        ttl_seconds: 60 * 60, // 1 hour
        ack_timeout_seconds: None,
    };
    type Response = ();
}

/// New peer registers a public key with the federation directory.
/// Durable, requires_ack (registration must land).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
pub struct PublicKeyRegistration(pub ciris_persist::prelude::SignedKeyRecord);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PublicKeyRegistrationResponse {
    pub registered: bool,
    pub key_id: String,
}

impl Message for PublicKeyRegistration {
    const TYPE: MessageType = MessageType::PublicKeyRegistration;
    const DELIVERY: Delivery = Delivery::Durable {
        requires_ack: true,
        max_attempts: 50,
        ttl_seconds: 3 * 24 * 60 * 60, // 3 days
        ack_timeout_seconds: Some(300),
    };
    type Response = PublicKeyRegistrationResponse;
}

/// Synchronous query — "do you have this key_id?". Ephemeral
/// request-response.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FederationKeyDirectoryQuery {
    pub key_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FederationKeyDirectoryQueryResponse {
    pub key_record: Option<ciris_persist::prelude::KeyRecord>,
}

impl Message for FederationKeyDirectoryQuery {
    const TYPE: MessageType = MessageType::FederationKeyDirectoryQuery;
    const DELIVERY: Delivery = Delivery::Ephemeral;
    type Response = FederationKeyDirectoryQueryResponse;
}
