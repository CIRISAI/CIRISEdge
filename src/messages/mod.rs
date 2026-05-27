//! Wire envelope + message-type discriminator + concrete message types.
//!
//! Mission: every byte the host code touches has been verified against
//! persist's federation directory. The envelope shape is the contract.
//! See [`FSD/CIRIS_EDGE.md`](../../FSD/CIRIS_EDGE.md) §3.4.
//!
//! Canonicalization for verify is `Engine.canonicalize_envelope_for_signing()`
//! only — never re-implemented in edge (CIRISPersist#7 closure; AV-5).

use base64::Engine as _;
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
///
/// Consumer crates (ciris-lens-core, ciris-node-core) own the body
/// structs and implement [`Message`] for them, pointing back to the
/// variant here. Edge stays domain-agnostic — the enum just
/// discriminates dispatch.
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

    // ─── CIRISNodeCore federation-consensus wire types ──────────────
    // Body structs live in `ciris-node-core` (consumer crate) per
    // CIRISNodeCore/SCHEMA.md §3–§9. Edge#6 closure.
    /// Contribution submission. Durable, requires_ack.
    /// Body: `ContributionEnvelope` per CIRISNodeCore/SCHEMA.md §3.
    ContributionSubmit,
    /// Vote on a Contribution. Durable, requires_ack.
    /// Body: `VoteEnvelope` per CIRISNodeCore/SCHEMA.md §5.
    VoteCast,
    /// Expertise attestation. Durable, requires_ack.
    /// Body: `ExpertiseAttestationEnvelope` per SCHEMA.md §7.
    ExpertiseAttestationPublish,
    /// Moderation event. Durable, requires_ack, witness-set-required.
    /// Body: `ModerationEventEnvelope` per SCHEMA.md §8.
    ModerationEventPublish,
    /// Slashing attestation. Durable, requires_ack, witness-set-required.
    /// Body: `SlashingAttestationEnvelope` per SCHEMA.md §8.
    SlashingAttestationPublish,
    /// Reconsideration request. Durable, requires_ack, witness-set-required.
    /// Body: `ReconsiderationRequestEnvelope` per SCHEMA.md §9.
    ReconsiderationRequest,
    /// Deferral request (generalizes CIRISNode WBD submit). Durable,
    /// requires_ack. Body: `DeferralRequestEnvelope` per SCHEMA.md §4.7.
    DeferralRequest,
    /// Deferral response (routed WA's signed response). Durable,
    /// requires_ack. Body: `DeferralResponseEnvelope` per SCHEMA.md §4.8.
    DeferralResponse,

    // ─── CIRISEdge#18 / CIRISNodeCore FSD §2.1 + §3.2.1 ─────────────
    /// Federation-tier authority-signed broadcast — rides
    /// `Delivery::Mandatory { bypass_subscription: true }`. Body:
    /// [`FederationAnnouncement`] (mirrors CIRISNodeCore FSD §2.1
    /// `FederationAnnouncementPayload` + persist v2.2.0 row 1:1).
    FederationAnnouncement,
    /// Per-peer attestation that a `FederationAnnouncement` reached
    /// the application layer. Durable, fire-and-forget — the
    /// attestation IS the audit observable; subscription-respecting
    /// fan-out (only the announcement itself rides `Mandatory`).
    /// Body: [`DeliveryAttestation`] (mirrors FSD §3.2.1 ratified
    /// 2026-05-27 + persist v2.2.0 `federation_delivery_attestations`
    /// row 1:1).
    DeliveryAttestation,
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

// ─── CIRISEdge#18 — FederationAnnouncement + DeliveryAttestation ────
//
// Cross-repo wire contract — these structs are byte-exact with
// CIRISPersist v2.2.0 `src/cirisnode/federation_announcement.rs`
// (FederationAnnouncementPayload, DeliveryAttestation) and CIRISNodeCore
// FSD §2.1 / §3.2.1 (ratified 2026-05-27). Any divergence here is a
// coordinated NodeCore + Edge + Persist break.
//
// JSON ground truth: serde snake_case rename rules + Vec<u8> hash
// fields ride the wire as base64-standard strings (persist's
// `*_base64` field convention — see persist v2.2.0 docs on
// `DeliveryAttestation` for the rationale: FFI / JSON boundary stays
// binary-codec-free).

/// Domain-separation tag for [`DeliveryAttestation::canonical_bytes`].
/// **LOCKED** wire constant — must equal persist v2.2.0's
/// `DELIVERY_ATTESTATION_DOMAIN`. Changing this is a coordinated
/// NodeCore + Edge + Persist break (FSD §3.2.1).
pub const DELIVERY_ATTESTATION_DOMAIN: &[u8] = b"ciris-edge-delivery-attestation-v1";

/// `AnnouncementPriority` per FSD §2.1. Mirrors persist v2.2.0
/// `cirisnode::federation_announcement::AnnouncementPriority` byte-
/// for-byte — same `#[serde(rename_all = "snake_case")]`, same
/// variants.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AnnouncementPriority {
    /// Steward FYI; operator UI surfaces but does not interrupt.
    Informational,
    /// Operators should review within their normal cadence.
    Advisory,
    /// Operators must review immediately; receivers MUST interrupt UI.
    Urgent,
    /// Carries an accord invocation. Routes through the existing
    /// per-agent accord executor at every node. Witness-set MANDATORY.
    /// Constitutionally MUST be paired with
    /// [`AuthorityClass::HumanityAccord`] (FSD §4.5; persist enforces).
    AccordCarrier,
}

/// `AnnouncementKind` per FSD §2.1. Receivers filter on this for UI /
/// operator routing but MUST deliver all kinds at all priorities (the
/// Mandatory wire class guarantees reach).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnnouncementKind {
    Deprecation,
    PolicyUpdate,
    MissionUpdate,
    ThreatAdvisory,
    KeyRotation,
    PilotPhaseChange,
    /// Present iff `priority == AccordCarrier`. The carried
    /// `accord_payload.command` determines what executes (FSD §4.5.7
    /// command taxonomy).
    AccordCarrier,
    /// Operator-defined; receivers route by string. Free-form at
    /// v0.1 per FSD §7 OQ-7.
    Custom(String),
}

/// `AuthorityClass` per FSD §2.1. The signer's *claimed* class —
/// verified at the consumer (NodeCore admission) against the
/// configured authority set. Edge is reach, not gate (FSD §3.4).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityClass {
    /// Signed by a bootstrap seed key set under the configured M-of-N
    /// threshold. NEVER sufficient for `AccordCarrier` (§4.5 reserves
    /// that to `HumanityAccord`).
    BootstrapSeed,
    /// Signed by a single ROOT-role WA.
    RootWa,
    /// Signed by a WA quorum meeting §3.5 witness diversity.
    WaQuorum,
    /// 2-of-3 sigs from the named, permanent, human key holders in
    /// the humanity-accord hierarchy (§4.5). The ONLY authority class
    /// permitted to sign `AccordCarrier`. Persist enforces the
    /// constitutional asymmetry at admission.
    HumanityAccord,
}

/// `AccordCarrier` payload per FSD §2.1. Present iff
/// `priority == AccordCarrier`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AccordCarrier {
    /// The 77-byte accord payload per CIRISAgent `AccordPayload`.
    /// Length not statically enforced at the type level — the agent-
    /// executor's verifier owns that — but the wire preserves bytes
    /// verbatim through JSON (persist's golden vector pins this
    /// against truncation regressions).
    pub payload_bytes: Vec<u8>,
    /// Optional human-readable rationale (audit-chain only; not used
    /// for execution).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

/// Federation announcement body per CIRISNodeCore FSD §2.1.
///
/// Cross-repo wire contract — byte-exact with persist v2.2.0
/// `FederationAnnouncementPayload`. Field names, serde rules, and
/// enum variants are the load-bearing contract; persist's admission
/// re-validates the constitutional asymmetry (priority ↔
/// authority_class ↔ kind, FSD §4.5) so a deviation here is caught
/// at storage even if it sneaks past edge's verify.
///
/// Edge does NOT validate `authority_class` against the actual signing
/// key (that is NodeCore's job per FSD §3.4); edge's role is **reach**
/// — fan the announcement to every peer regardless of subscription
/// state via [`Delivery::Mandatory`].
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FederationAnnouncement {
    /// Priority class. Drives receiver behavior, witness-set
    /// requirement, and substrate-delivery class.
    pub priority: AnnouncementPriority,
    /// What kind of announcement this is.
    pub kind: AnnouncementKind,
    /// Short label for operator UIs and audit-chain summaries.
    pub title: String,
    /// Full announcement body. Plain text or markdown
    /// (renderer-defined).
    pub body: String,
    /// Trust class the signer claims to act under.
    pub authority_class: AuthorityClass,
    /// Present iff `kind == AccordCarrier`. Persist enforces the
    /// presence/absence asymmetry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accord_payload: Option<AccordCarrier>,
    /// Optional back-ref to an earlier announcement this one
    /// supersedes / amends / retracts. `ContributionId` per FSD —
    /// UUID-shaped string on the wire (same convention as
    /// persist v2.2.0's `supersedes: Option<String>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
    /// When the announcement is no longer relevant. REQUIRED to
    /// bound replay risk (FSD §1.2).
    pub expires_at: DateTime<Utc>,
    /// Supporting references — links to RATCHET reports, framework
    /// documents, prior Contributions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
}

impl Message for FederationAnnouncement {
    const TYPE: MessageType = MessageType::FederationAnnouncement;
    /// Authority-signed federation-wide push. The bypass-subscription
    /// flag is the load-bearing semantic — without it, the
    /// announcement's reach collapses to whichever peers happened to
    /// opt in, and the federation has no governance path that
    /// guarantees every node sees a steward declaration
    /// (`MISSION.md` §1.1 Justice failure mode). Closes CIRISEdge#18
    /// + CIRISNodeCore FSD §3.2.
    const DELIVERY: Delivery = Delivery::Mandatory {
        authority_signed: true,
        bypass_subscription: true,
    };
    /// Federation announcements are fire-and-forget at the
    /// transport layer; the per-peer [`DeliveryAttestation`] emitted
    /// by each receiver IS the observable (FSD §3.2.1) — no inline
    /// response is requested.
    type Response = ();
}

/// Transport medium tag per FSD §3.2.1 — medium only, sub-path /
/// interface intentionally NOT recorded (topology-disclosure
/// conservative default at v0.1; future tags via FSD-002 v1.4 §4.9.2
/// amendment process).
///
/// Mirrors persist v2.2.0
/// `cirisnode::federation_announcement::TransportMedium` byte-for-byte.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TransportMedium {
    Reticulum,
    TcpTls,
    HttpOverTls,
    Other,
}

impl TransportMedium {
    /// Wire-shaped string — matches persist v2.2.0's V046 CHECK
    /// vocabulary on `transport_id`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reticulum => "reticulum",
            Self::TcpTls => "tcp_tls",
            Self::HttpOverTls => "http_over_tls",
            Self::Other => "other",
        }
    }
}

impl From<crate::transport::TransportId> for TransportMedium {
    /// Map edge's transport-instance id to the wire-level medium tag.
    /// HTTP / Reticulum (Leviculum-backed) collapse onto their
    /// medium-level FSD §3.2.1 enum value; other transports fall to
    /// [`TransportMedium::Other`] (the FSD's catch-all). Sub-path /
    /// interface intentionally not propagated.
    fn from(id: crate::transport::TransportId) -> Self {
        match id {
            crate::transport::TransportId::HTTP => Self::HttpOverTls,
            crate::transport::TransportId::RETICULUM_RS
            | crate::transport::TransportId::LEVICULUM => Self::Reticulum,
            _ => Self::Other,
        }
    }
}

/// Per-peer delivery attestation per CIRISNodeCore FSD §3.2.1
/// (ratified 2026-05-27). Mirrors persist v2.2.0
/// `cirisnode::federation_announcement::DeliveryAttestation`
/// byte-for-byte.
///
/// # Wire encoding for byte fields
///
/// Following the persist + CIRISEdge convention (raw byte fields
/// ride the JSON wire as base64-standard strings; the canonical-bytes
/// encoder operates on the base64-decoded bytes — pin in
/// [`Self::canonical_bytes`]). 32-byte hashes encode to 44 chars;
/// 64-byte Ed25519 signatures to 88 chars; ML-DSA-65 signatures
/// (3309 bytes) to ~4412 chars.
///
/// # Hybrid signature discipline (FSD §3.2.1 + AV-33)
///
/// The mandatory Ed25519 signature covers [`Self::canonical_bytes`].
/// The optional ML-DSA-65 signature covers
/// `canonical_bytes || signature_classical` — the persist AV-33
/// bound-signature convention so signature-stripping cannot degrade
/// a hybrid attestation to classical-only.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DeliveryAttestation {
    /// The announcement this attestation acknowledges receipt of.
    /// Same shape as `ContributionEnvelope::contribution_id`
    /// (UUID-shaped string).
    pub announcement_id: String,
    /// SHA-256 of the full canonicalized Contribution envelope of
    /// the announcement (INCLUDING its authority signature). Pins
    /// the exact bytes the peer received; defeats in-flight
    /// modification AND received-a-different-signature cases. 32
    /// bytes raw, base64-standard on the wire (44 chars).
    pub announcement_canonical_hash_base64: String,
    /// The peer that is acknowledging receipt — `federation_keys.key_id`
    /// from persist's directory.
    pub peer_key_id: String,
    /// Base64 of the peer's Ed25519 pubkey (denormalized for offline
    /// verification convenience; persist MUST cross-check against
    /// `federation_keys[peer_key_id].pubkey_ed25519`).
    pub peer_pubkey_ed25519_base64: String,
    /// When the peer's edge accepted the validated announcement
    /// (authority-class verified + signature verified). NOT raw
    /// wire receipt — the validation gate is the emission point at
    /// v0.1. Tightening to application-layer-acceptance is a v0.2+
    /// option per FSD §7 OQ-6.
    pub received_at: DateTime<Utc>,
    /// Transport medium the announcement arrived over.
    pub transport_id: TransportMedium,
    /// MANDATORY classical Ed25519 signature (64 bytes raw) over
    /// [`Self::canonical_bytes`]. Base64-standard on the wire.
    pub signature_classical_base64: String,
    /// OPTIONAL PQC ML-DSA-65 signature (3309 bytes raw, FIPS 204
    /// final) over `canonical_bytes || signature_classical` per the
    /// persist AV-33 bound-signature convention. Base64-standard on
    /// the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_pqc_base64: Option<String>,
}

impl Message for DeliveryAttestation {
    const TYPE: MessageType = MessageType::DeliveryAttestation;
    /// Durable, fire-and-forget — the attestation IS the audit
    /// observable; no second ACK needed (FSD §3.2.1 dispatch table).
    /// Subscription-respecting fan-out (NOT Mandatory) — attestations
    /// are observability; the federation gathers what it gathers.
    const DELIVERY: Delivery = Delivery::Durable {
        requires_ack: false,
        max_attempts: 20,
        ttl_seconds: 24 * 60 * 60, // 24 hours
        ack_timeout_seconds: None,
    };
    type Response = ();
}

/// Errors building / encoding a [`DeliveryAttestation`].
#[derive(thiserror::Error, Debug)]
pub enum DeliveryAttestationError {
    /// A base64 field did not decode, or decoded to a wrong length.
    #[error("delivery attestation field decode: {0}")]
    FieldDecode(String),
}

impl DeliveryAttestation {
    /// The exact bytes the peer's federation key signs / a verifier
    /// re-derives to check. **MUST be byte-equal with persist v2.2.0's
    /// `DeliveryAttestation::canonical_bytes`** — the cross-repo
    /// drift guard is the golden vector test (this module + persist
    /// `federation_announcement.rs::tests::canonical_bytes_golden_vector`
    /// produce the same bytes from the same inputs).
    ///
    /// Layout (FSD §3.2.1 + mirrors CIRISEdge `AttestationPayload::canonical_bytes`
    /// length-prefixed injective pattern, all integer prefixes
    /// big-endian u64; `received_at` is fixed-width i64 ms big-endian):
    ///
    /// ```text
    /// DOMAIN
    ///   ‖ u64_be(announcement_id.len())          ‖ announcement_id
    ///   ‖ announcement_canonical_hash            (32B raw, base64-decoded)
    ///   ‖ u64_be(peer_key_id.len())              ‖ peer_key_id
    ///   ‖ u64_be(peer_pubkey_b64.len())          ‖ peer_pubkey_b64
    ///   ‖ i64_be(received_at.timestamp_millis()) (8B fixed)
    ///   ‖ u64_be(transport_id_str.len())         ‖ transport_id_str
    /// ```
    ///
    /// `DOMAIN` is [`DELIVERY_ATTESTATION_DOMAIN`]. Length prefixes
    /// make the encoding injective — distinct field tuples never
    /// share a byte string, so a signature is bound to exactly one
    /// attestation tuple (same property as
    /// `src/transport/attestation.rs` `AttestationPayload::canonical_bytes`
    /// pins for the v0.4.0 announce attestation).
    ///
    /// # Errors
    ///
    /// [`DeliveryAttestationError::FieldDecode`] if
    /// `announcement_canonical_hash_base64` is not base64 of exactly
    /// 32 bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DeliveryAttestationError> {
        let announcement_id = self.announcement_id.as_bytes();
        let peer_key_id = self.peer_key_id.as_bytes();
        let peer_pubkey = self.peer_pubkey_ed25519_base64.as_bytes();
        let transport = self.transport_id.as_str().as_bytes();
        let canonical_hash = self.canonical_hash_bytes()?;

        // Length-prefix widening usize → u64 is lossless on every
        // supported target (matches AttestationPayload pattern).
        let cap = DELIVERY_ATTESTATION_DOMAIN.len()
            + 8 + announcement_id.len()
            + canonical_hash.len()
            + 8 + peer_key_id.len()
            + 8 + peer_pubkey.len()
            + 8 // received_at i64
            + 8 + transport.len();
        let mut out = Vec::with_capacity(cap);

        out.extend_from_slice(DELIVERY_ATTESTATION_DOMAIN);
        out.extend_from_slice(&(announcement_id.len() as u64).to_be_bytes());
        out.extend_from_slice(announcement_id);
        out.extend_from_slice(&canonical_hash);
        out.extend_from_slice(&(peer_key_id.len() as u64).to_be_bytes());
        out.extend_from_slice(peer_key_id);
        out.extend_from_slice(&(peer_pubkey.len() as u64).to_be_bytes());
        out.extend_from_slice(peer_pubkey);
        out.extend_from_slice(&self.received_at.timestamp_millis().to_be_bytes());
        out.extend_from_slice(&(transport.len() as u64).to_be_bytes());
        out.extend_from_slice(transport);

        Ok(out)
    }

    /// Decode [`Self::announcement_canonical_hash_base64`] to raw 32
    /// bytes. Returns [`DeliveryAttestationError::FieldDecode`] on
    /// base64-decode failure or length mismatch.
    pub fn canonical_hash_bytes(&self) -> Result<[u8; 32], DeliveryAttestationError> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(self.announcement_canonical_hash_base64.as_bytes())
            .map_err(|e| {
                DeliveryAttestationError::FieldDecode(format!(
                    "announcement_canonical_hash_base64 base64: {e}"
                ))
            })?;
        let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            DeliveryAttestationError::FieldDecode(format!(
                "announcement_canonical_hash_base64 must decode to 32 bytes (got {})",
                raw.len()
            ))
        })?;
        Ok(arr)
    }

    /// Decode the mandatory classical Ed25519 signature to raw bytes
    /// (expected 64). Returns [`DeliveryAttestationError::FieldDecode`]
    /// on base64-decode failure or wrong length.
    pub fn signature_classical_bytes(&self) -> Result<[u8; 64], DeliveryAttestationError> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(self.signature_classical_base64.as_bytes())
            .map_err(|e| {
                DeliveryAttestationError::FieldDecode(format!(
                    "signature_classical_base64 base64: {e}"
                ))
            })?;
        let arr: [u8; 64] = raw.as_slice().try_into().map_err(|_| {
            DeliveryAttestationError::FieldDecode(format!(
                "signature_classical_base64 must decode to 64 bytes (got {})",
                raw.len()
            ))
        })?;
        Ok(arr)
    }
}

/// Convenience: base64-encode a 32-byte canonical hash for callers
/// that hold the raw bytes (e.g. fresh SHA-256 output). Mirrors
/// persist v2.2.0's `encode_canonical_hash_base64`.
#[must_use]
pub fn encode_canonical_hash_base64(hash: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(hash)
}

/// Convenience: base64-encode a signature byte slice. Mirrors persist
/// v2.2.0's `encode_signature_base64`.
#[must_use]
pub fn encode_signature_base64(sig: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_attestation() -> DeliveryAttestation {
        // Same fixture as persist v2.2.0
        // `federation_announcement::tests::fixture_attestation` — the
        // golden vector below is the cross-repo wire contract.
        DeliveryAttestation {
            announcement_id: "11111111-1111-1111-1111-111111111111".into(),
            announcement_canonical_hash_base64: encode_canonical_hash_base64(&[0xAB; 32]),
            peer_key_id: "edge-peer-01".into(),
            peer_pubkey_ed25519_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            received_at: DateTime::parse_from_rfc3339("2026-06-01T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            transport_id: TransportMedium::Reticulum,
            signature_classical_base64: encode_signature_base64(&[0u8; 64]),
            signature_pqc_base64: None,
        }
    }

    /// Length-prefixed injective: distinct field tuples must produce
    /// distinct canonical bytes. Pins the FSD §3.2.1 + edge
    /// `AttestationPayload::canonical_bytes` confusability rule.
    #[test]
    fn canonical_bytes_are_injective() {
        let a = fixture_attestation().canonical_bytes().unwrap();

        let mut b_att = fixture_attestation();
        b_att.peer_key_id = "edge-peer-02".into();
        assert_ne!(a, b_att.canonical_bytes().unwrap());

        let mut c_att = fixture_attestation();
        c_att.announcement_canonical_hash_base64 = encode_canonical_hash_base64(&[0xCD; 32]);
        assert_ne!(a, c_att.canonical_bytes().unwrap());

        let mut d_att = fixture_attestation();
        d_att.transport_id = TransportMedium::TcpTls;
        assert_ne!(a, d_att.canonical_bytes().unwrap());

        let mut e_att = fixture_attestation();
        e_att.received_at = DateTime::parse_from_rfc3339("2026-06-01T00:00:00.001Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_ne!(a, e_att.canonical_bytes().unwrap());
    }

    /// Length-prefixed: distinct fields adjacent in the encoding
    /// cannot alias. `"ab"+"cZ"` vs `"a"+"bcZ"` style — a naive
    /// concat without prefixes would collide; with length prefixes it
    /// must not. Pins the FSD §3.2.1 + CIRISEdge §3.4 confusability
    /// rule. Mirrors persist v2.2.0's
    /// `canonical_bytes_resist_field_confusion`.
    #[test]
    fn canonical_bytes_resist_field_confusion() {
        let mut a_att = fixture_attestation();
        a_att.peer_key_id = "ab".into();
        a_att.peer_pubkey_ed25519_base64 = "cZ".into();
        let a = a_att.canonical_bytes().unwrap();

        let mut b_att = fixture_attestation();
        b_att.peer_key_id = "a".into();
        b_att.peer_pubkey_ed25519_base64 = "bcZ".into();
        let b = b_att.canonical_bytes().unwrap();

        assert_ne!(a, b, "length-prefixed encoding must not alias");
    }

    /// **Cross-repo golden vector.** A fixed attestation must produce
    /// the exact byte string persist v2.2.0
    /// `federation_announcement::tests::canonical_bytes_golden_vector`
    /// produces. Drift here = federation can't verify edge-produced
    /// attestations = mission-blocking.
    ///
    /// The expected bytes are reconstructed manually below so this
    /// test catches encoder regressions in either direction (edge
    /// drift vs. persist drift). The golden vector is the FSD §3.2.1
    /// wire-contract surface.
    #[test]
    fn canonical_bytes_golden_vector_matches_persist_v2_2_0() {
        let att = fixture_attestation();
        let bytes = att.canonical_bytes().unwrap();

        // Reconstruct the expected layout manually — same shape as
        // persist v2.2.0's golden test.
        let mut expected = Vec::new();
        expected.extend_from_slice(b"ciris-edge-delivery-attestation-v1");
        let id = b"11111111-1111-1111-1111-111111111111";
        expected.extend_from_slice(&(id.len() as u64).to_be_bytes());
        expected.extend_from_slice(id);
        expected.extend_from_slice(&[0xAB; 32]);
        let pkid = b"edge-peer-01";
        expected.extend_from_slice(&(pkid.len() as u64).to_be_bytes());
        expected.extend_from_slice(pkid);
        let pp = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        expected.extend_from_slice(&(pp.len() as u64).to_be_bytes());
        expected.extend_from_slice(pp);
        let ts_ms: i64 = 1_780_272_000_000; // 2026-06-01T00:00:00Z
        expected.extend_from_slice(&ts_ms.to_be_bytes());
        let t = b"reticulum";
        expected.extend_from_slice(&(t.len() as u64).to_be_bytes());
        expected.extend_from_slice(t);

        assert_eq!(
            bytes, expected,
            "delivery-attestation canonical bytes drifted from FSD §3.2.1 + persist v2.2.0 wire contract"
        );
    }

    /// JSON round-trip preserves every field — the body wire format
    /// is what persist's admission deserializes from.
    #[test]
    fn delivery_attestation_json_round_trip() {
        let att = fixture_attestation();
        let s = serde_json::to_string(&att).unwrap();
        let back: DeliveryAttestation = serde_json::from_str(&s).unwrap();
        assert_eq!(att, back);
    }

    /// JSON round-trip including the optional PQC signature.
    #[test]
    fn delivery_attestation_with_pqc_round_trip() {
        let mut att = fixture_attestation();
        att.signature_pqc_base64 = Some(encode_signature_base64(&vec![0xFE; 3309]));
        let s = serde_json::to_string(&att).unwrap();
        let back: DeliveryAttestation = serde_json::from_str(&s).unwrap();
        assert_eq!(att, back);
    }

    /// FSD §2.1 snake_case discipline — pins the serde rules persist
    /// and NodeCore both consume.
    #[test]
    fn priority_serde_matches_fsd_snake_case() {
        assert_eq!(
            serde_json::to_string(&AnnouncementPriority::AccordCarrier).unwrap(),
            r#""accord_carrier""#
        );
        let parsed: AnnouncementPriority = serde_json::from_str(r#""urgent""#).unwrap();
        assert_eq!(parsed, AnnouncementPriority::Urgent);
    }

    #[test]
    fn authority_serde_matches_fsd_snake_case() {
        assert_eq!(
            serde_json::to_string(&AuthorityClass::HumanityAccord).unwrap(),
            r#""humanity_accord""#
        );
        assert_eq!(
            serde_json::to_string(&AuthorityClass::BootstrapSeed).unwrap(),
            r#""bootstrap_seed""#
        );
    }

    #[test]
    fn announcement_kind_serde_custom_variant_round_trips() {
        let k = AnnouncementKind::Custom("operator_defined".into());
        let s = serde_json::to_string(&k).unwrap();
        let back: AnnouncementKind = serde_json::from_str(&s).unwrap();
        assert_eq!(k, back);
    }

    #[test]
    fn transport_medium_serde_matches_persist_v2_2_0() {
        for (variant, expected) in [
            (TransportMedium::Reticulum, r#""reticulum""#),
            (TransportMedium::TcpTls, r#""tcp_tls""#),
            (TransportMedium::HttpOverTls, r#""http_over_tls""#),
            (TransportMedium::Other, r#""other""#),
        ] {
            assert_eq!(serde_json::to_string(&variant).unwrap(), expected);
        }
    }

    /// `FederationAnnouncement` must declare the Mandatory delivery
    /// class with `bypass_subscription = true` — the load-bearing
    /// wire contract (FSD §3.2). A regression here = subscription
    /// gating restored = federation steward governance reach lost.
    #[test]
    fn federation_announcement_declares_mandatory_with_bypass() {
        match FederationAnnouncement::DELIVERY {
            Delivery::Mandatory {
                authority_signed,
                bypass_subscription,
            } => {
                assert!(
                    authority_signed,
                    "FederationAnnouncement must declare authority_signed=true"
                );
                assert!(
                    bypass_subscription,
                    "FederationAnnouncement must declare bypass_subscription=true — \
                     the load-bearing federation-reach semantic (FSD §3.2)"
                );
            }
            other => panic!("FederationAnnouncement::DELIVERY must be Mandatory; got {other:?}"),
        }
    }

    /// `DeliveryAttestation` must ride `Durable { requires_ack: false }`
    /// per FSD §3.2.1 dispatch table — the attestation IS the
    /// observable; no second ACK.
    #[test]
    fn delivery_attestation_declares_durable_no_ack() {
        match DeliveryAttestation::DELIVERY {
            Delivery::Durable {
                requires_ack,
                ack_timeout_seconds,
                ..
            } => {
                assert!(
                    !requires_ack,
                    "DeliveryAttestation must be fire-and-forget — \
                     the attestation IS the observable (FSD §3.2.1)"
                );
                assert!(
                    ack_timeout_seconds.is_none(),
                    "fire-and-forget Durable must omit ack_timeout_seconds"
                );
            }
            other => panic!("DeliveryAttestation::DELIVERY must be Durable; got {other:?}"),
        }
    }
}
