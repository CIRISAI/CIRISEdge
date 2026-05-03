//! Wire envelope + message-type discriminator.
//!
//! Mission: every byte the host code touches has been verified against
//! persist's federation directory. The envelope shape is the contract.
//! See [`FSD/CIRIS_EDGE.md`](../../FSD/CIRIS_EDGE.md) §3.4.
//!
//! Canonicalization for verify is `Engine.canonicalize_envelope()` only —
//! never re-implemented in edge (CIRISPersist#7 closure; AV-5).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

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
    /// Build-manifest publication agent/primitive → registry. Durable.
    BuildManifestPublication,
    /// Data-subject access request (DSAR) chain. Durable, requires_ack.
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
/// Canonical bytes for signature are `Engine.canonicalize_envelope()`
/// applied to this struct minus `signature` and `signature_pqc`.
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
    /// Ed25519 signature over `canonicalize_envelope(envelope - signatures)`.
    /// Base64.
    pub signature: String,
    /// ML-DSA-65 PQC signature (base64). Required when sender's
    /// `federation_keys` row is hybrid-complete (`pqc_completed_at IS
    /// NOT NULL`); MAY be `None` for hybrid-pending rows. Consumer
    /// policy ([`crate::HybridPolicy`]) selects acceptance.
    /// (OQ-11 closure; CIRISPersist v0.4.0 verify_hybrid_via_directory.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_pqc: Option<String>,
    /// 32-byte `body_sha256` of the original envelope this is a
    /// response/ACK to. Set on response envelopes; `None` on
    /// first-touch envelopes. Used by sender's `edge_outbound_queue`
    /// to match ACKs to originals
    /// (FSD/EDGE_OUTBOUND_QUEUE.md; OQ-09 closure).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<[u8; 32]>,
}

impl EdgeEnvelope {
    /// Compute the body's sha256 — the forensic join key persist's
    /// indices use, and the `in_reply_to` content-derived ACK match
    /// key. Implementation pending; see also `Engine.canonicalize_envelope`.
    #[must_use]
    pub fn body_sha256(&self) -> [u8; 32] {
        todo!("sha256 over self.body.get().as_bytes() — confirm against persist's body_sha256 indexing")
    }
}
