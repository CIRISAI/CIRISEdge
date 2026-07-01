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

use crate::cohort_scope::CohortScope;
use crate::handler::{Delivery, FederationPriority, Message};
use crate::key_boundary::KeyBoundaryScope;

/// Wire-format schema version. Pinned by edge release tag; downstream
/// peers gate on a strict allowlist (AV-7).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum SchemaVersion {
    /// CC 0.7 opaque-vocabulary wire break (CIRISEdge#241, v8.0.0). The
    /// coordinated strict-flip: `V1_0_0` is REMOVED from the enum, so any
    /// envelope carrying the legacy `"v1_0_0"` discriminator fails typed
    /// deserialize at the verify pipeline's Step-2 gate (AV-14) — a typed
    /// reject, not a silent downgrade. `V2_0_0` is the sole allowlisted
    /// schema version and the crate-wide default.
    #[default]
    V2_0_0,
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
    // ─── CC 0.7 opaque wire vocabulary (CIRISEdge#241, v8.0.0) ──────
    //
    // WIRE_VOCABULARY.md v1.0.1 §3.3. Edge carries `payload` as OPAQUE
    // bytes: NO typed struct, NO canonical_bytes, NO Message-semantic
    // knowledge for any migrant. The outer `EdgeEnvelope` signature
    // stays transport-tier; the APP owns inner canonicalization + any
    // inner signature. MISSION §1.3 "edge is reach, not meaning".
    /// Opaque ephemeral request. Body: [`OpaqueRequest`]
    /// (`{kind, payload}`). `Response = OpaqueResponse`. Unknown `kind`
    /// at the receiver → `OpaqueResponse { status: 501 }` (never a
    /// silent drop, MISSION §6 anti-pattern 7).
    OpaqueRequest,
    /// Opaque ephemeral response. Body: [`OpaqueResponse`]
    /// (`{kind, status, payload}`). No `Response`. Correlated back to
    /// the pending [`Self::OpaqueRequest`] via the envelope `in_reply_to`.
    OpaqueResponse,
    /// Opaque persistent event. Body: [`OpaqueEvent`] (`{kind, payload}`).
    /// Rides `Delivery::Durable`; fanned out to per-`kind` subscribers
    /// on receipt (the generic successor of the ripped inline-text
    /// subscriber pattern). No `Response`.
    OpaqueEvent,
    /// Build-manifest publication primitive → registry. Durable.
    BuildManifestPublication,
    /// Data-subject access request — DSAR chain. Durable, requires_ack.
    DSARRequest,
    DSARResponse,
    /// Federation-directory gossip — peer-attests-key. Durable, fire-and-forget.
    AttestationGossip,
    /// New-peer key registration → directory. Durable, requires_ack.
    PublicKeyRegistration,

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
    /// CIRISEdge#19 — per-peer refusal attestation emitted when edge
    /// declines to propagate a `priority == AccordCarrier`
    /// `FederationAnnouncement` because the 2-of-3 accord-holder
    /// multi-sig threshold was not met (or no accord-holders are
    /// configured in persist). Durable, fire-and-forget — the refusal
    /// IS the observable; the steward end aggregates them and can
    /// distinguish adversarial suppression of legitimate accords from
    /// suppression of forged ones via the [`RefusalReason`] field.
    /// Body: [`DeliveryRefusalAttestation`].
    DeliveryRefusalAttestation,

    // ─── CIRISEdge#21 — content-addressable byte transport ──────────
    //
    // Phase 1 (v0.8.0) whole-file flow. The chunked-large-file variant
    // `ContentChunk` is intentionally NOT enumerated here; it lands in
    // edge#21-phase2 once the Phase 1 surface has settled (S3-pointer
    // flow + `{ sha256, offset, total, bytes, final }` shape are the
    // open questions, FSD §1.4 batch). Phase 1 ships whole-file only
    // and AV-13's 16 MiB ceiling on `ContentBody.bytes` is the hard cap.
    /// Request to fetch the bytes that hash to `sha256`. Ephemeral
    /// request/response — point-to-point, retryable (edge#21 spec
    /// point 5; not `Mandatory`, byte fetch is on-demand pull). Body:
    /// [`ContentFetch`]. Any peer holding the bytes may respond with
    /// [`MessageType::ContentBody`]; a peer that does not hold them
    /// (or refuses to serve) responds with [`MessageType::ContentMiss`].
    ContentFetch,
    /// Response carrying the bytes for a [`MessageType::ContentFetch`].
    /// Receiver MUST verify `sha256(bytes) == claimed_sha256` on
    /// receipt — content-addressed integrity is the trust primitive
    /// (edge#21 spec point 2; the bytes themselves are unsigned, trust
    /// rides the attestation that named the SHA). Body:
    /// [`ContentBody`]. AV-13 ceiling (default 16 MiB) applies.
    ContentBody,
    /// Response indicating the responder will not serve the requested
    /// SHA — `NotHeld` / `Withdrawn` / `Revoked` / `PolicyDenied`.
    /// Required so the fetcher fails over to a different peer instead
    /// of hanging (edge#21 spec point 3). Body: [`ContentMiss`].
    ContentMiss,

    // ─── CIRISEdge#55 (v2.5.0) — chunked-blob swarm fetch ──────────
    //
    // The Phase-2 chunked path the v0.8.0 ContentChunk comment above
    // deferred. Now landing against the stable persist#145 substrate:
    // `BlobStorage::list_holders` for candidate discovery, `ChunkManifest`
    // for the chunk-list shape, and `BlobStorage::put_blob_chunk` for
    // atomic per-chunk SHA verification + store (returns ChunkMismatch
    // on hash failure — the trust primitive). Edge owns the carrier op +
    // the adaptive scheduler; persist owns the verify-on-write seam.
    //
    // Three variants mirror the Phase-1 ContentFetch / ContentBody /
    // ContentMiss triple exactly — same Ephemeral delivery class, same
    // typed-envelope response shape, same MissReason vocabulary. The
    // discriminator differs: BlobChunk* carries BOTH `blob_sha256`
    // (overall blob, manifest-bound) and `chunk_sha256` (this specific
    // chunk). Two SHAs because the scheduler maintains per-blob state
    // (which chunks pending) and per-chunk responses correlate at the
    // chunk-SHA level (one outstanding chunk-request may be answered by
    // any holder).
    /// Request the bytes of a single chunk identified by
    /// `(blob_sha256, chunk_sha256)`. Ephemeral, retryable. Any peer
    /// listed in `BlobStorage::list_holders(blob_sha256)` may respond
    /// with [`MessageType::BlobChunkBody`]; a peer that does not hold
    /// the chunk responds with [`MessageType::BlobChunkMiss`]. Body:
    /// [`BlobChunkFetch`].
    BlobChunkFetch,
    /// Response carrying the chunk bytes for a
    /// [`MessageType::BlobChunkFetch`]. Receiver hands the bytes to
    /// `persist.put_blob_chunk(blob_sha, chunk_sha, bytes)` which
    /// atomically verifies `sha256(bytes) == chunk_sha256` and stores
    /// (or returns `ChunkMismatch` on hash failure). Body:
    /// [`BlobChunkBody`].
    BlobChunkBody,
    /// Response indicating the responder will not serve the requested
    /// chunk. Same [`MissReason`] vocabulary as
    /// [`MessageType::ContentMiss`] — `NotHeld` (try another peer)
    /// vs `Withdrawn`/`Revoked` (gone federation-wide) vs
    /// `PolicyDenied` (this responder only). Body:
    /// [`BlobChunkMiss`].
    BlobChunkMiss,

    // ─── CIRISEdge#20 (v0.10.0) — Federation steward class ──────────
    /// Steward-class federation directive — rides
    /// `Delivery::Federation { priority: StewardClass }`. Edge derives
    /// the recipient set dynamically from persist's `federation_keys`
    /// directory where `identity_type = "steward"` on every
    /// [`crate::Edge::send_federation`] call. Body:
    /// [`StewardDirective`]. The DeliveryAttestation emission hook
    /// fires on this wire type the same way it fires on
    /// [`Self::FederationAnnouncement`] (FSD §3.2.1 per-peer
    /// attestation shape, reused — see CIRISEdge#20 ask #3).
    StewardDirective,

    // ─── CIRISEdge#41 (v0.11.1) — typed Goal federation transport ───
    /// CIRISLensCore F-3 detector family input. Wraps the persist v2.10.0
    /// (CIRISPersist#114) typed [`ciris_persist::federation::goal::Goal`]
    /// primitive whose `MetaGoalAlignment` is a structural construction-
    /// time invariant — every Goal that crosses the wire carries an M-1
    /// alignment payload. Durable; lens-core's `Handler<GoalDeclaration>`
    /// must land the row (cohabitation pattern). Body:
    /// [`GoalDeclaration`].
    GoalDeclaration,
    /// CIRISEdge#41 (v0.11.1) — single-signer retirement of a previously-
    /// declared Goal. Mirrors persist v2.10.0's `retire_goal` API
    /// (`(goal_id, retired_at)` shape); the envelope's hybrid signature
    /// IS the proof-of-authority (no body-internal signatures at v0.11.1).
    /// Quorum-signed retirement for `GoalScope::Federation` goals deferred
    /// to a future amendment per CIRISEdge#41 body §"Out of scope". Body:
    /// [`GoalRetirement`].
    GoalRetirement,

    // ─── CIRISEdge#42 (v0.12.0) — CEG §10.1.2 ContentMiss feedback ──
    /// CEG 0.1 §10.1.2 — consumer-side feedback emitted when a
    /// `ContentFetch` attempt returned a `ContentMiss` (or otherwise
    /// failed full-SHA verify) against a holder that advertised
    /// `holds_bytes:sha256:{prefix}` for the requested SHA. The
    /// withdrawal is signed by the consumer's local key and shipped
    /// via the existing federation evidence path (`Delivery::Durable`).
    /// Receivers aggregate per `(holder_key_id, sha256)` and apply the
    /// downweight policy in their own `PeerResolver`. Body:
    /// [`Withdraws`].
    Withdraws,

    // ─── CIRISEdge#184 (v6.3.0) — swarm-converger wire-up ───────────
    /// Federation-level fountain holding claim. Signed wire discriminator
    /// for the substrate's
    /// [`crate::holonomic::swarm_rarity::FountainHoldingClaim`] body
    /// (locked v1 canonical-bytes layout per
    /// [`crate::holonomic::swarm_rarity::HOLDING_CLAIM_DOMAIN`]). The
    /// FountainSwarmRuntime publisher emits one envelope per held
    /// `content_id` per cohort peer on each `publish_cadence` tick;
    /// inbound dispatch routes verified envelopes into
    /// [`crate::swarm::FountainSwarmRuntime::register_observed_claim`].
    ///
    /// Ephemeral, fire-and-forget — the substrate composes whether or
    /// not peers respond, and stale observations age out via the
    /// runtime's TTL prune.
    ///
    /// Closes the v5.2.0 wire-tier deferral (the runtime's publisher
    /// shipped `canonical_bytes` raw until this discriminator landed).
    FountainHoldingClaim,
}

/// CIRISEdge#37 — `testimonial_witness` envelope slot per FSD-002
/// §3.6.3 v1.4 + §5.14. A **preservation primitive**: edge propagates
/// the witness verbatim across federation forwarding and does NOT
/// interpret the `payload` (that lives at the joint-correlation tier
/// in `ciris-lens-core`). Edge's only obligation is byte-fidelity —
/// the field is included in the canonical envelope bytes verbatim so
/// the originator's signature commits to it.
///
/// # Wire shape
///
/// ```json
/// {
///   "kind": "ratchet-conscience",
///   "payload": { ... opaque to edge ... },
///   "issuer_key_id": "lens-detector-01",
///   "issued_at": "2026-05-29T00:00:00.000Z"
/// }
/// ```
///
/// `payload` carries an arbitrary `serde_json::Value` — including
/// nested objects, arrays, numbers, strings, null. Edge does not
/// touch it. Consumers (lens-core's joint-correlation detector
/// family, ratchet-conscience evaluators, registry attestation
/// audit) decode `kind` + `payload` according to their own contract.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TestimonialWitness {
    /// Witness kind tag — opaque to edge. Examples in CIRIS 3.0:
    /// `"ratchet-conscience"` (RATCHET-stage attestation),
    /// `"lens-detector"` (lens-core detector emission),
    /// `"registry-attest"` (registry-side l-tier attestation).
    /// New kinds land in consumer crates without an edge break.
    pub kind: String,
    /// Opaque witness payload. Edge preserves byte-for-byte; consumer
    /// interprets according to `kind`. May be any JSON value.
    pub payload: serde_json::Value,
    /// The signer attesting this witness — `federation_keys.key_id`.
    /// Edge does NOT verify this against the envelope's
    /// `signing_key_id` (the witness may be relayed by a forwarder).
    /// Consumers verify per their own trust chain.
    pub issuer_key_id: String,
    /// When the witness was issued (UTC; serializes via chrono's
    /// default RFC-3339 representation).
    pub issued_at: DateTime<Utc>,
}

/// The signed wire envelope. Carries one verified message + the
/// metadata needed for replay protection, hybrid PQC verify, and
/// content-derived ACK matching.
///
/// Canonical bytes for signature are
/// `Engine.canonicalize_envelope_for_signing()` applied to this struct
/// (which strips `signature` and `signature_pqc` before canonicalizing).
///
/// # v0.16.0 — wire compliance fields
///
/// Two CIRIS 3.0 wire-form fields land here:
///
/// - [`Self::testimonial_witness`] (D13, CIRISEdge#37): preservation
///   primitive per FSD-002 §3.6.3 v1.4 + §5.14. Edge propagates
///   verbatim, signs over it as part of canonical envelope bytes,
///   does NOT interpret the payload (joint-correlation tier owns
///   that). `Option`-wrapped with `skip_serializing_if`: existing
///   v0.15.x envelopes round-trip byte-equal.
/// - [`Self::key_boundary_scope`] (D26 + CIRISEdge#38): wire-form
///   scope slot per FSD-002 §3.4 (`process` / `tenant` / `channel` /
///   `cohort` / `data_class`). Defaults to
///   [`KeyBoundaryScope::Process`] (AV-17 process-wide invariant —
///   the v0.15.x default). `Option`-wrapped + skip: pre-v0.16.0
///   envelopes round-trip byte-equal AND deserialize-default to
///   `None` (which downstream interprets as `Process` semantics, per
///   the legacy parse rule in [`crate::key_boundary`]).
///
/// Both fields are part of the canonical bytes WHEN PRESENT and
/// omitted from canonical bytes when `None` — symmetric serialize /
/// verify path, no special-casing.
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
    /// CIRISEdge#37 — `testimonial_witness` preservation primitive
    /// per FSD-002 §3.6.3 v1.4 + §5.14. Edge propagates verbatim and
    /// signs over it as part of canonical envelope bytes; payload is
    /// opaque to edge (joint-correlation tier owns interpretation).
    ///
    /// `Option`-wrapped with `skip_serializing_if`: when `None`, the
    /// field is OMITTED from JSON, so existing v0.15.x envelopes
    /// round-trip byte-equal and pre-v0.16.0 consumers ignore the
    /// field (serde default). When `Some`, the field IS part of the
    /// signed canonical bytes — symmetric on the verify path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub testimonial_witness: Option<TestimonialWitness>,
    /// CIRISEdge#38 + D26 — `key_boundary:{scope}` slot per FSD-002
    /// §3.4 + IEEE Ch6. Edge today carries an AV-17 process-wide
    /// `key_boundary:no_seed_in_heap` invariant; this field extends
    /// the wire form to express per-tenant / per-channel / per-cohort
    /// / per-data-class scoping WITHOUT a wire break.
    ///
    /// `Option`-wrapped with `skip_serializing_if`: when `None`, the
    /// field is OMITTED from JSON — both v0.15.x and v0.16.0 default
    /// envelopes round-trip byte-equal. When `Some`, the scope IS
    /// part of canonical bytes (future scope-binding enforcement at
    /// v0.16.1+ verifies against the value committed here).
    ///
    /// **v0.16.0 is wire-only**: edge does NOT enforce
    /// scope-binding (refusing cross-scope verify, etc.). The slot
    /// lands so consumers can write and parse the value; enforcement
    /// follows in a later cut. See `src/key_boundary.rs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_boundary_scope: Option<KeyBoundaryScope>,
    /// CIRISEdge#48-A (v0.19.1) — `cohort_scope` slot per
    /// CIRISNodeCore SCHEMA §3.2 + FSD `FEDERATION_SCALING_MODEL.md`.
    /// Carries the originator's declared cohort scope; edge structurally
    /// enforces the wire-format locality dividend at
    /// `Edge::send_*` (producer side) and at `dispatch_inbound`
    /// (consumer side) per [`crate::cohort_scope::CohortScope`].
    ///
    /// `Option`-wrapped with `skip_serializing_if`: when `None`, the
    /// field is OMITTED from JSON, so existing v0.19.0 envelopes
    /// round-trip byte-equal and deserialize-default to `None` (which
    /// edge interprets as [`CohortScope::Public`] — the legacy
    /// implicit behaviour). When `Some`, the scope IS part of canonical
    /// bytes and edge enforces the producer-side refusal + consumer-
    /// side symmetric check per the [`CohortScope`] semantics.
    ///
    /// Default enforcement posture is
    /// [`crate::cohort_scope::CohortScopeEnforcement::Strict`] per
    /// CIRISEdge#48-A.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cohort_scope: Option<CohortScope>,
}

// ─── Phase 1 message types ──────────────────────────────────────────
//
// Each type below implements [`Message`], declaring its wire
// discriminator + delivery class. Wire shapes wrap persist's existing
// types via `#[serde(transparent)]` newtypes where applicable —
// preserves byte-equivalence with the existing TRACE_WIRE_FORMAT and
// federation-directory schemas.

// ─── CC 0.7 opaque wire vocabulary (CIRISEdge#241, v8.0.0) ──────────
//
// WIRE_VOCABULARY.md v1.0.1 §3.3. These three types are the ENTIRE
// domain-facing message surface edge exposes after the CC 0.7 break.
// `payload` is OPAQUE bytes — edge holds no typed struct, no
// canonical_bytes, no Message-semantic knowledge for any migrant. The
// APP owns inner canonicalization + any inner signature. The
// body-size cap (AV-13, `MAX_BODY_BYTES`) applies to `payload` via the
// outer envelope size gate. MISSION §1.3 "edge is reach, not meaning"
// + §6 anti-pattern 2 "edge re-implements no canonicalization".

/// Opaque ephemeral request (`Delivery::Ephemeral`). `kind` is an
/// app-owned discriminator; `payload` is opaque bytes edge never
/// interprets. The receiver dispatches on `kind`; an unknown `kind`
/// replies [`OpaqueResponse`] `{ status: 501 }` (never a silent drop).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OpaqueRequest {
    /// App-owned message discriminator. Edge routes on it but assigns
    /// it no meaning.
    pub kind: u32,
    /// Opaque application payload. Edge preserves byte-for-byte.
    pub payload: Vec<u8>,
}

/// Opaque ephemeral response to an [`OpaqueRequest`]. `status` is an
/// app-owned code (the `501` unknown-kind reject is the one edge-level
/// reserved value). No wire `Response` — this IS the response.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OpaqueResponse {
    /// Echoes the request `kind` (or the unknown `kind` on a 501).
    pub kind: u32,
    /// App-owned status code. `501` is edge's reserved unknown-kind
    /// reject; every other value is app-defined.
    pub status: u16,
    /// Opaque application payload. Edge preserves byte-for-byte.
    pub payload: Vec<u8>,
}

/// Opaque persistent event (`Delivery::Durable`, fire-and-forget). On
/// receipt edge fans it out to every subscriber registered for its
/// `kind` — the generic successor of the ripped inline-text subscriber
/// subsystem.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OpaqueEvent {
    /// App-owned event discriminator. Subscribers register per-`kind`.
    pub kind: u32,
    /// Opaque application payload. Edge preserves byte-for-byte.
    pub payload: Vec<u8>,
}

impl Message for OpaqueRequest {
    const TYPE: MessageType = MessageType::OpaqueRequest;
    const DELIVERY: Delivery = Delivery::Ephemeral;
    type Response = OpaqueResponse;
}

impl Message for OpaqueResponse {
    const TYPE: MessageType = MessageType::OpaqueResponse;
    const DELIVERY: Delivery = Delivery::Ephemeral;
    type Response = ();
}

impl Message for OpaqueEvent {
    const TYPE: MessageType = MessageType::OpaqueEvent;
    const DELIVERY: Delivery = Delivery::Durable {
        requires_ack: false,
        max_attempts: 10,
        ttl_seconds: 24 * 60 * 60, // 24 hours
        ack_timeout_seconds: None,
    };
    type Response = ();
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
    /// CIRISEdge#19 — multi-sig set carrying the accord-holder
    /// signatures over [`Self::canonical_bytes_for_accord_signatures`].
    /// Empty for non-`AccordCarrier` priority (the field is
    /// `#[serde(default, skip_serializing_if = "Vec::is_empty")]` so
    /// pre-v0.10 wire shapes deserialize unchanged).
    ///
    /// For `priority == AccordCarrier`, edge's wire-layer verify hook
    /// (`src/edge.rs::dispatch_inbound`) enforces ≥ 2 valid signatures
    /// from DISTINCT `identity_type = accord_holder` keys in persist's
    /// federation directory before propagating. Failures emit a
    /// [`DeliveryRefusalAttestation`] with the appropriate
    /// [`RefusalReason`]. See [`ACCORD_THRESHOLD_M_OF_N`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accord_signatures: Vec<AccordSignature>,
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

// ─── CIRISEdge#19 — AccordCarrier 2-of-3 multi-sig ──────────────────
//
// Wire-layer authority verification for `priority == AccordCarrier`
// federation announcements. The multi-sig set lives on the
// `FederationAnnouncement` body (NOT on the surrounding `EdgeEnvelope`
// — that envelope already carries exactly one classical Ed25519 + one
// optional ML-DSA-65 signature from the originating sender). The
// substrate verifies the multi-sig threshold at every hop, refusing
// to propagate envelopes that fail it; refusal is OBSERVABLE via the
// [`DeliveryRefusalAttestation`] sibling type so the steward end can
// distinguish adversarial suppression of legitimate accords from
// suppression of forged ones.

/// CIRISEdge#19 — 2-of-3 multi-sig threshold for `AccordCarrier`
/// envelopes (issue body §"Ask" point 3). The first element is
/// `M` (threshold count of distinct valid signatures required); the
/// second is `N` (canonical accord-holder set size — informational at
/// the wire layer, the actual N comes from persist's
/// `list_keys_by_identity_type("accord_holder")` result). Pinned as a
/// constant so a future tuning (e.g. 3-of-5 if the human-held key set
/// expands) is discoverable from a grep.
pub const ACCORD_THRESHOLD_M_OF_N: (u32, u32) = (2, 3);

/// Domain-separation tag for [`FederationAnnouncement::canonical_bytes_for_accord_signatures`].
/// **LOCKED** wire constant — changing this is a coordinated
/// NodeCore + Edge + Persist break. The accord-holder signers sign
/// these canonical bytes; edge's wire-layer hook re-derives them and
/// verifies each signature in [`FederationAnnouncement::accord_signatures`]
/// against the corresponding accord-holder pubkey looked up in persist.
pub const FEDERATION_ANNOUNCEMENT_ACCORD_SIG_DOMAIN: &[u8] =
    b"ciris-edge-federation-announcement-accord-v1";

/// One accord-holder signature over a [`FederationAnnouncement`]'s
/// canonical bytes (per [`FEDERATION_ANNOUNCEMENT_ACCORD_SIG_DOMAIN`]).
/// The wire-layer hook in `dispatch_inbound` enforces:
///
/// 1. `key_id` resolves to an `identity_type = accord_holder` row in
///    persist's federation directory.
/// 2. `signature_ed25519_base64` verifies against that row's pubkey
///    over [`FederationAnnouncement::canonical_bytes_for_accord_signatures`].
/// 3. Distinct `key_id`s across the [`FederationAnnouncement::accord_signatures`]
///    vector — duplicate signatures from the same holder count once
///    (CIRISEdge#19 distinct-holders invariant).
///
/// At least [`ACCORD_THRESHOLD_M_OF_N`].0 distinct + valid entries are
/// required to pass; otherwise the announcement is REFUSED with a
/// [`DeliveryRefusalAttestation`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AccordSignature {
    /// The accord-holder's `federation_keys.key_id` — looked up in
    /// persist (`identity_type = accord_holder`) for verification.
    pub key_id: String,
    /// Base64-standard Ed25519 signature (64 bytes raw, 88 chars b64)
    /// over [`FederationAnnouncement::canonical_bytes_for_accord_signatures`].
    pub signature_ed25519_base64: String,
}

impl FederationAnnouncement {
    /// Canonical bytes the accord-holder set signs (and edge's
    /// wire-layer hook re-derives + verifies). Length-prefixed
    /// injective encoding, mirroring [`DeliveryAttestation::canonical_bytes`]
    /// — distinct field tuples never share a byte string, so a
    /// signature is bound to exactly one announcement payload.
    ///
    /// **Crucially excludes [`Self::accord_signatures`]** — the
    /// signers are signing the *announcement*, not their own signature
    /// set (which would be self-referential and prevent verification).
    /// The signed bytes also exclude the `evidence_refs` ordering
    /// stability would require — for v0.10 we include them
    /// deterministically (sorted by string order is unnecessary; the
    /// wire shape preserves order from the producer).
    ///
    /// Layout (all integer prefixes big-endian u64; `expires_at` is
    /// fixed-width i64 ms big-endian):
    ///
    /// ```text
    /// DOMAIN
    ///   ‖ u64_be(priority_str.len())          ‖ priority_str
    ///   ‖ u64_be(kind_json.len())             ‖ kind_json  (serde JSON repr)
    ///   ‖ u64_be(title.len())                 ‖ title
    ///   ‖ u64_be(body.len())                  ‖ body
    ///   ‖ u64_be(authority_class_str.len())   ‖ authority_class_str
    ///   ‖ u8(accord_payload.is_some() as u8)
    ///   ‖ (when Some)  u64_be(payload_bytes.len()) ‖ payload_bytes
    ///   ‖ u8(supersedes.is_some() as u8)
    ///   ‖ (when Some)  u64_be(s.len())              ‖ s
    ///   ‖ i64_be(expires_at.timestamp_millis())
    ///   ‖ u64_be(evidence_refs.len() as u64)
    ///   ‖ for each ref: u64_be(ref.len()) ‖ ref
    /// ```
    ///
    /// `DOMAIN` is [`FEDERATION_ANNOUNCEMENT_ACCORD_SIG_DOMAIN`].
    ///
    /// # Errors
    ///
    /// Returns the underlying `serde_json::Error` if `kind` or
    /// `accord_payload` cannot serialize — only possible for a
    /// `Custom(String)` variant containing un-encodable bytes, which
    /// the wire-level deserializer would have rejected upstream.
    pub fn canonical_bytes_for_accord_signatures(&self) -> Result<Vec<u8>, serde_json::Error> {
        let priority_str = match self.priority {
            AnnouncementPriority::Informational => "informational",
            AnnouncementPriority::Advisory => "advisory",
            AnnouncementPriority::Urgent => "urgent",
            AnnouncementPriority::AccordCarrier => "accord_carrier",
        };
        let authority_class_str = match self.authority_class {
            AuthorityClass::BootstrapSeed => "bootstrap_seed",
            AuthorityClass::RootWa => "root_wa",
            AuthorityClass::WaQuorum => "wa_quorum",
            AuthorityClass::HumanityAccord => "humanity_accord",
        };
        // `kind` carries a `Custom(String)` variant — serde JSON repr
        // is the most compact deterministic encoding. The wire shape
        // is what the receiver re-derives, so this is byte-stable.
        let kind_json = serde_json::to_string(&self.kind)?;
        let payload_bytes_opt: Option<Vec<u8>> = match self.accord_payload.as_ref() {
            Some(p) => Some(serde_json::to_vec(p)?),
            None => None,
        };

        let mut out = Vec::new();
        out.extend_from_slice(FEDERATION_ANNOUNCEMENT_ACCORD_SIG_DOMAIN);

        write_len_prefixed(&mut out, priority_str.as_bytes());
        write_len_prefixed(&mut out, kind_json.as_bytes());
        write_len_prefixed(&mut out, self.title.as_bytes());
        write_len_prefixed(&mut out, self.body.as_bytes());
        write_len_prefixed(&mut out, authority_class_str.as_bytes());

        match payload_bytes_opt.as_ref() {
            Some(b) => {
                out.push(1u8);
                write_len_prefixed(&mut out, b);
            }
            None => out.push(0u8),
        }

        match self.supersedes.as_ref() {
            Some(s) => {
                out.push(1u8);
                write_len_prefixed(&mut out, s.as_bytes());
            }
            None => out.push(0u8),
        }

        out.extend_from_slice(&self.expires_at.timestamp_millis().to_be_bytes());
        out.extend_from_slice(&(self.evidence_refs.len() as u64).to_be_bytes());
        for r in &self.evidence_refs {
            write_len_prefixed(&mut out, r.as_bytes());
        }

        Ok(out)
    }
}

fn write_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// CIRISEdge#19 — why a [`DeliveryRefusalAttestation`] was emitted in
/// place of normal propagation. Distinguishes adversarial suppression
/// of legitimate accords (`NoAccordHoldersConfigured` — substrate isn't
/// bootstrapped) from suppression of forged ones
/// (`InsufficientAccordSignatures` / `InvalidAccordSignature` —
/// envelope failed the threshold check).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum RefusalReason {
    /// Multi-sig threshold not met. `found` counts DISTINCT
    /// accord-holders whose signatures verified; `required` is the
    /// threshold from [`ACCORD_THRESHOLD_M_OF_N`].0.
    InsufficientAccordSignatures { found: u32, required: u32 },
    /// One or more sigs failed verification against the accord-holder
    /// key set. Emitted when every signature in the
    /// [`FederationAnnouncement::accord_signatures`] vector either
    /// references an unknown key_id, references a non-accord-holder
    /// key_id, or has a bad signature against the canonical bytes.
    InvalidAccordSignature,
    /// Persist's federation directory has NO `identity_type =
    /// accord_holder` rows — the substrate is not bootstrapped for
    /// constitutional traffic. This is the case the issue body calls
    /// out as load-bearing: a missing accord-holder set means edge
    /// CANNOT verify any AccordCarrier announcement; refusing is
    /// correct even for a perfectly-signed envelope, because the
    /// downstream trust chain has no root.
    NoAccordHoldersConfigured,
    /// CIRISEdge#108 part 2 (v3.2.0) — the envelope signer could not
    /// be tied back to a trusted root via a non-retracted, in-scope
    /// federation-tier `delegates_to` chain.
    ///
    /// Carries the `required_scope` (one of `act_on_behalf`,
    /// `message_io`, `network_presence`, `sub_delegation` —
    /// `SELF_AT_LOGIN_DELEGATION_SCOPE` per CEG §8.1.12.7) and a
    /// `kind`-tagged sub-reason discriminator so a federation
    /// collector can distinguish "no trust roots configured" (the
    /// substrate-not-bootstrapped story) from "signer has no inbound
    /// delegation" / "delegation present but retracted" / "delegation
    /// present but missing required scope".
    DelegationNotAuthorized {
        /// The scope token the wire-tier gate required for this
        /// MessageType (e.g. `message_io` for InlineText).
        required_scope: String,
        /// Sub-reason discriminator. Mirrors the `kind`-tag
        /// discipline of the outer `RefusalReason` enum so a single
        /// JSON parse on the receiver yields a typed structured
        /// reason.
        sub_reason: DelegationRefusalSubReason,
    },
}

/// CIRISEdge#108 part 2 (v3.2.0) — taxonomy of WHY a
/// [`RefusalReason::DelegationNotAuthorized`] fired. Distinguishes
/// substrate-bootstrap failures (`NoTrustRoots`) from envelope-content
/// failures (`SignerUnreached`, `RetractedAtRoot`, `MissingScope`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum DelegationRefusalSubReason {
    /// Edge holds no canonical bootstrap peers — the substrate is
    /// not bootstrapped for delegation-gated traffic. Refusing is
    /// correct even for a perfectly-signed envelope with a perfectly-
    /// formed delegation chain, because the chain has no root.
    NoTrustRoots,
    /// One or more trust roots are configured, but BFS from each
    /// (via persist's `build_delegation_graph` semantics) never
    /// reaches `envelope.signing_key_id`. Either the signer was
    /// never delegated to, or the delegation lives at a deeper
    /// depth than this edge's `delegation_graph_max_depth`.
    SignerUnreached,
    /// A `delegates_to` edge to the signer exists in the graph, but
    /// it carries a `withdraws` / `recants` retraction (CEG 0.6
    /// §3.2.3). Distinct from `SignerUnreached` so a steward end can
    /// see "the chain WAS valid, then the granter retracted" — a
    /// load-bearing forensic signal.
    RetractedAtRoot,
    /// A non-retracted `delegates_to` edge to the signer exists, but
    /// none of the chain edges carry the required scope token (e.g.
    /// the user delegated `network_presence` but not `message_io`).
    MissingScope,
    /// Persist's [`ciris_persist::federation::FederationDirectory`]
    /// surface returned an error walking the graph. Treated as a
    /// substrate fault — refusing is the conservative safe default
    /// (same posture as `NoAccordHoldersConfigured` on the
    /// AccordCarrier gate).
    SubstrateUnavailable,
}

/// Domain-separation tag for [`DeliveryRefusalAttestation::canonical_bytes`].
/// **LOCKED** wire constant — mirrors the [`DELIVERY_ATTESTATION_DOMAIN`]
/// pattern. Changing this is a coordinated NodeCore + Edge + Persist
/// break (CIRISEdge#19).
pub const DELIVERY_REFUSAL_ATTESTATION_DOMAIN: &[u8] =
    b"ciris-edge-delivery-refusal-attestation-v1";

/// Per-peer refusal attestation emitted when edge declines to
/// propagate a `priority == AccordCarrier` `FederationAnnouncement`
/// because the 2-of-3 accord-holder multi-sig threshold was not met
/// (or because persist's federation directory holds no accord-holder
/// rows). The refusal IS the observable — a federation collector
/// aggregating these per peer can distinguish adversarial suppression
/// of legitimate accords from suppression of forged ones via
/// [`Self::refusal_reason`].
///
/// # Wire shape
///
/// Mirrors [`DeliveryAttestation`] exactly (same fields, same base64
/// encoding rules, same hybrid-signature discipline) plus the
/// [`Self::refusal_reason`] discriminator.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DeliveryRefusalAttestation {
    /// The refused announcement's id — UUID-shaped string. Derived
    /// from the announcement envelope's `body_sha256` (deterministic
    /// at the receiver, same convention as [`DeliveryAttestation::announcement_id`]).
    pub announcement_id: String,
    /// SHA-256 of the full canonicalized announcement envelope the
    /// peer received and refused. 32 bytes raw, base64-standard on
    /// the wire (44 chars).
    pub announcement_canonical_hash_base64: String,
    /// The peer that is refusing — `federation_keys.key_id`.
    pub peer_key_id: String,
    /// Base64 of the peer's Ed25519 pubkey (denormalized — see
    /// [`DeliveryAttestation::peer_pubkey_ed25519_base64`]).
    pub peer_pubkey_ed25519_base64: String,
    /// When the peer's edge refused (the wire-layer verify gate fired).
    pub refused_at: DateTime<Utc>,
    /// Transport medium the announcement arrived over.
    pub transport_id: TransportMedium,
    /// Why the peer refused.
    pub refusal_reason: RefusalReason,
    /// MANDATORY classical Ed25519 signature (64 bytes raw) over
    /// [`Self::canonical_bytes`]. Base64-standard on the wire.
    pub signature_classical_base64: String,
    /// OPTIONAL PQC ML-DSA-65 signature over `canonical_bytes ||
    /// signature_classical` per the persist AV-33 bound-signature
    /// convention. Base64-standard on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_pqc_base64: Option<String>,
}

impl Message for DeliveryRefusalAttestation {
    const TYPE: MessageType = MessageType::DeliveryRefusalAttestation;
    /// Same wire class as [`DeliveryAttestation`] (FSD §3.2.1
    /// dispatch table — fire-and-forget Durable). The refusal IS the
    /// observable; no second ACK.
    const DELIVERY: Delivery = Delivery::Durable {
        requires_ack: false,
        max_attempts: 20,
        ttl_seconds: 24 * 60 * 60, // 24 hours
        ack_timeout_seconds: None,
    };
    type Response = ();
}

impl DeliveryRefusalAttestation {
    /// The exact bytes the peer's federation key signs / a verifier
    /// re-derives. Length-prefixed injective encoding mirroring
    /// [`DeliveryAttestation::canonical_bytes`]; the
    /// [`Self::refusal_reason`] field is serialized via its
    /// `serde_json` representation (which is the wire shape the
    /// receiver re-derives — byte-stable across implementations).
    ///
    /// # Errors
    ///
    /// [`DeliveryAttestationError::FieldDecode`] if
    /// `announcement_canonical_hash_base64` is not base64 of exactly
    /// 32 bytes; underlying `serde_json::Error` (re-mapped to
    /// `FieldDecode`) on refusal-reason serialization failure
    /// (structurally impossible at the type level — all
    /// [`RefusalReason`] variants serialize).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DeliveryAttestationError> {
        let announcement_id = self.announcement_id.as_bytes();
        let peer_key_id = self.peer_key_id.as_bytes();
        let peer_pubkey = self.peer_pubkey_ed25519_base64.as_bytes();
        let transport = self.transport_id.as_str().as_bytes();
        let canonical_hash = self.canonical_hash_bytes()?;
        let reason_json = serde_json::to_string(&self.refusal_reason).map_err(|e| {
            DeliveryAttestationError::FieldDecode(format!("refusal_reason serialize: {e}"))
        })?;
        let reason_bytes = reason_json.as_bytes();

        let cap = DELIVERY_REFUSAL_ATTESTATION_DOMAIN.len()
            + 8 + announcement_id.len()
            + canonical_hash.len()
            + 8 + peer_key_id.len()
            + 8 + peer_pubkey.len()
            + 8 // refused_at i64
            + 8 + transport.len()
            + 8 + reason_bytes.len();
        let mut out = Vec::with_capacity(cap);

        out.extend_from_slice(DELIVERY_REFUSAL_ATTESTATION_DOMAIN);
        write_len_prefixed(&mut out, announcement_id);
        out.extend_from_slice(&canonical_hash);
        write_len_prefixed(&mut out, peer_key_id);
        write_len_prefixed(&mut out, peer_pubkey);
        out.extend_from_slice(&self.refused_at.timestamp_millis().to_be_bytes());
        write_len_prefixed(&mut out, transport);
        write_len_prefixed(&mut out, reason_bytes);

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

// ─── CIRISEdge#20 — StewardDirective (Federation class) ─────────────
//
// v0.10.0 — first concrete consumer of `Delivery::Federation { priority:
// StewardClass }`. Edge ships the wire class so future cross-repo
// federation traffic (cross-attestations / revocations / rule
// amendments) can ride it; v0.10.0 itself only mints this one body
// type as the canonical Federation-class wire shape. The receiver
// identifies the class at the wire layer through this MessageType
// (the `Delivery` enum is sender-side trait-level, not on the wire),
// which gates the DeliveryAttestation emission hook
// (`is_federation_attestation_emitting_type` in this module).

/// Body for a steward-class federation directive. Minimal shape at
/// v0.10.0 — title + body strings carrying the steward's signed
/// statement; consumer-side routing branches on the title / body
/// content. Future v0.x cuts may add structured fields (rotation
/// payloads, revocation references) without a wire break — the wire
/// shape ratchets only on serde-additive changes.
///
/// Ships as the canonical [`Delivery::Federation`] body type. Receivers
/// (every steward in the federation directory at send time) auto-emit a
/// per-peer [`DeliveryAttestation`] on verified receipt — same shape
/// as the `FederationAnnouncement` path (FSD §3.2.1, CIRISEdge#20 ask
/// #3 reused-attestation contract).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct StewardDirective {
    /// Short label for operator UIs and audit-chain summaries.
    pub title: String,
    /// Full directive body. Plain text or markdown
    /// (renderer-defined).
    pub body: String,
}

impl Message for StewardDirective {
    const TYPE: MessageType = MessageType::StewardDirective;
    /// Federation class, steward-priority routing. Defaults mirror
    /// the `FederationAnnouncement` long-haul shape: 14d TTL, 100
    /// attempts, no inline-response ACK (the per-peer
    /// [`DeliveryAttestation`] emitted on verified receipt IS the
    /// audit observable — same convention as the Mandatory class).
    const DELIVERY: Delivery = Delivery::Federation {
        priority: FederationPriority::StewardClass,
        requires_ack: false,
        max_attempts: 100,
        ttl_seconds: 14 * 24 * 60 * 60,
        ack_timeout_seconds: None,
    };
    type Response = ();
}

/// Wire-types that trigger the
/// [`crate::messages::DeliveryAttestation`] emission hook in
/// `dispatch_inbound`. v0.6.0 ratified the per-peer attestation for
/// [`MessageType::FederationAnnouncement`] (FSD §3.2.1); CIRISEdge#20
/// extends the same shape onto [`MessageType::StewardDirective`] —
/// steward-class messages need the SAME audit observable as
/// Mandatory-class so federation reach is verifiable across both
/// push paths.
///
/// Free function (not a method on `MessageType`) so future Federation
/// or attestation-emitting wire types can be appended without
/// adjusting the receive-time match on the `MessageType` enum body —
/// dispatch_inbound's single call site is the contract.
#[must_use]
pub fn is_federation_attestation_emitting_type(mt: &MessageType) -> bool {
    matches!(
        mt,
        MessageType::FederationAnnouncement | MessageType::StewardDirective
    )
}

// ─── CIRISEdge#21 — ContentFetch / ContentBody / ContentMiss ────────
//
// Phase 1 (v0.8.0) content-addressable byte transport. The bytes
// themselves are unsigned; integrity is the SHA-256 invariant
// (`sha256(bytes) == claimed_sha256` re-checked on receipt). Trust
// rides the attestation that named the SHA — `attestation_ref` is a
// lightweight pointer to that attestation, not a full embedded copy.
//
// Phase 2 (`MessageType::ContentChunk` + `{ sha256, offset, total,
// bytes, final }` shape + S3-pointer flow for >16 MiB) is a follow-up
// (edge#21-phase2). Phase 1 ships whole-file `ContentBody` only;
// AV-13's 16 MiB ceiling on `ContentBody.bytes` is the hard cap.

/// Default AV-13 body-size ceiling for [`ContentBody::bytes`] —
/// 16 MiB per CIRISEdge#21 Phase 1 spec point 7. Configurable per
/// deployment via [`crate::EdgeConfig::max_content_body_bytes`]; the
/// default const is exposed so consumers can pin their config to the
/// canonical value rather than re-deriving it.
///
/// Bodies exceeding this size reject with the existing AV-13 family
/// error ([`crate::verify::VerifyError::BodyTooLarge`]); larger files
/// require the Phase 2 chunked path or the S3-pointer flow (bytes via
/// `external_ref`, edge only carries the manifest).
pub const DEFAULT_MAX_CONTENT_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Caller-supplied preferences accompanying a [`ContentFetch`]. The
/// responder is free to ignore the hint (the wire shape is advisory),
/// but production servers SHOULD honor `max_body_bytes` so fetchers
/// can advertise low-memory ceilings.
///
/// `prefer_chunked` captures the request shape for Phase 2
/// (edge#21-phase2 `MessageType::ContentChunk`) — Phase 1 responders
/// always answer with whole-file [`ContentBody`] regardless of the
/// flag. Capturing the field at v0.8.0 means a Phase 2 receiver can
/// branch on it without a wire-format break.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HintShape {
    /// Maximum `ContentBody.bytes.len()` the requester is willing to
    /// accept on the response. `None` = no preference (responder
    /// applies its own AV-13 ceiling). Responders MAY answer with
    /// [`ContentMiss { reason: PolicyDenied }`](MissReason::PolicyDenied)
    /// if the held body exceeds this hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_bytes: Option<u64>,
    /// If `true`, the requester prefers a chunked response (Phase 2
    /// `ContentChunk`). Phase 1 responders ignore this — they always
    /// answer with whole-file [`ContentBody`]. The field exists so
    /// Phase 2 receivers can branch without a wire break.
    #[serde(default)]
    pub prefer_chunked: bool,
}

/// Lightweight pointer to the attestation that vouches for a
/// [`ContentBody`]. Carried OPTIONALLY on the response — present when
/// the responder wants to vouch via a specific federation attestation;
/// absent when the responder is source-neutral (any peer holding the
/// bytes may answer, per CIRISEdge#21 spec point 8).
///
/// NOT a full embedded attestation — the consumer fetches the
/// attestation row out of band (persist's `federation_attestations`
/// index, keyed by `attestation_id`) and re-verifies it against
/// `federation_keys[signing_key_id]`. Edge is reach, not gate
/// (`MISSION.md` §1.3).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AttestationRef {
    /// The `federation_attestations.attestation_id` (UUID-shaped) the
    /// caller should fetch out of band to verify the bytes' provenance.
    pub attestation_id: String,
    /// The `federation_keys.key_id` that signed the referenced
    /// attestation. Denormalized so a consumer can route the
    /// `federation_keys` lookup without first fetching the attestation
    /// row — same convenience pattern as
    /// [`DeliveryAttestation::peer_pubkey_ed25519_base64`].
    pub signing_key_id: String,
}

/// Request to fetch the bytes that hash to `sha256`. Per CIRISEdge#21
/// spec point 1.
///
/// Any peer holding the bytes may respond with [`ContentBody`]; a
/// peer that does not (or refuses to serve under policy) responds
/// with [`ContentMiss`] so the fetcher can fail over to another peer
/// rather than hang (FSD §3.4 fail-loud invariant).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ContentFetch {
    /// SHA-256 of the bytes the requester wants. Raw 32 bytes — JSON
    /// wire shape rides as the standard `[u8; 32]` serde encoding (an
    /// array of integers, matching `EdgeEnvelope::nonce`'s precedent).
    pub sha256: [u8; 32],
    /// Optional fetcher-side preference shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_hint: Option<HintShape>,
}

impl Message for ContentFetch {
    const TYPE: MessageType = MessageType::ContentFetch;
    /// Standard point-to-point, retryable — CIRISEdge#21 spec point 5
    /// ("Standard (point-to-point, retryable). Not Mandatory").
    /// Edge's existing `Delivery::Ephemeral` IS the request/response
    /// class; no new variant is introduced (issue body item 4:
    /// "do not add a new `Standard` variant unless the codebase
    /// already uses that name").
    const DELIVERY: Delivery = Delivery::Ephemeral;
    /// The peer chooses ContentBody xor ContentMiss; both are typed
    /// envelopes carrying their own bodies, NOT inline responses to
    /// `ContentFetch`. `()` here marks the wire-level
    /// "no inline response struct" property (mirrors `FederationAnnouncement`'s
    /// `type Response = ()` — the observable is a separate envelope).
    type Response = ();
}

/// Response carrying the bytes for a [`ContentFetch`].
///
/// # Integrity invariant (CIRISEdge#21 spec point 2)
///
/// The receiver MUST verify `sha256(bytes) == sha256` on receipt and
/// reject mismatches; this is the content-addressed integrity gate.
/// Edge's `dispatch_inbound` enforces it before handler dispatch (see
/// `src/edge.rs::dispatch_inbound`). A consumer that bypasses
/// `dispatch_inbound` MUST re-implement the check — the wire envelope
/// signature only binds the (sha256, bytes) pair to the *responder*,
/// not to the *content*; trust in the content rides the attestation
/// named in `attestation_ref` (if present) or the originally-named
/// attestation the fetcher was acting on.
///
/// # Size bound (AV-13)
///
/// `bytes.len()` is bounded by [`DEFAULT_MAX_CONTENT_BODY_BYTES`] at
/// the default `EdgeConfig`. Phase 1 ships whole-file only; >16 MiB
/// requires the Phase 2 chunked path (`MessageType::ContentChunk`,
/// edge#21-phase2) or the S3-pointer flow.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ContentBody {
    /// SHA-256 the responder claims the `bytes` field hashes to.
    /// Verified on receipt against `sha256(bytes)` (the integrity
    /// invariant; see type-level docs).
    pub sha256: [u8; 32],
    /// The bytes themselves. Bounded by
    /// [`DEFAULT_MAX_CONTENT_BODY_BYTES`] (AV-13 family).
    pub bytes: Vec<u8>,
    /// Optional pointer to the federation attestation that vouches
    /// for the bytes. Absent = source-neutral response (any peer
    /// holding the bytes may answer, CIRISEdge#21 spec point 8); the
    /// fetcher already has the attestation that named the SHA out of
    /// band and is just resolving the bytes here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_ref: Option<AttestationRef>,
}

impl Message for ContentBody {
    const TYPE: MessageType = MessageType::ContentBody;
    /// Same wire class as the [`ContentFetch`] it responds to —
    /// point-to-point, retryable.
    const DELIVERY: Delivery = Delivery::Ephemeral;
    type Response = ();
}

/// Reason a [`ContentMiss`] was returned instead of a [`ContentBody`].
/// Mirrors CIRISEdge#21 spec point 3 — the reason discriminates
/// "fetcher should try another peer" (`NotHeld`) vs "the bytes are
/// gone federation-wide" (`Withdrawn` / `Revoked`) vs "this peer's
/// policy denied" (`PolicyDenied`).
///
/// The serde rules MUST be `snake_case` — pinned by the cross-repo
/// wire convention (`AnnouncementPriority` precedent, FSD §2.1).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MissReason {
    /// The responder does not hold the bytes for this SHA. Fetcher
    /// SHOULD try another peer from
    /// [`PeerResolver::resolve_holders`](crate::transport::reticulum::PeerResolver::resolve_holders).
    NotHeld,
    /// The bytes were withdrawn at the federation tier — the
    /// originating attestation was retracted (FSD §3.2.1
    /// `supersedes` / retraction chain). Trying another peer is
    /// unlikely to help.
    Withdrawn,
    /// The originating signer's key was revoked (the
    /// `federation_revocations` directory holds the row). Bytes the
    /// revoked key vouched for are no longer trusted federation-wide.
    Revoked,
    /// This responder's local policy denied the fetch (e.g.
    /// authorization tier, rate-limit, jurisdictional gate). Other
    /// peers MAY still serve the bytes — the fetcher SHOULD retry
    /// elsewhere.
    PolicyDenied,
    /// v3.5.0 (CIRISEdge#116 / CIRISPersist#149) — this responder is
    /// under disk pressure and is shedding proxy serves first to
    /// protect local/family content. The fetcher SHOULD retry
    /// elsewhere; trying this peer again imminently is unlikely to
    /// succeed (pressure recovers on a monitor-loop cadence, not
    /// per-request). Distinct from `PolicyDenied` so dashboards can
    /// surface the pressure signal honestly + so the scheduler can
    /// down-weight the peer for the rest of the session without
    /// demoting it for policy reasons.
    ///
    /// Surfaces on the wire when a consumer-side handler calls
    /// `Engine::serve_blob_to_peer` and gets
    /// `BlobError::DiskPressureProxyRefused`. The translation is
    /// operator-tier (consumer maps the typed substrate refusal to
    /// this typed wire refusal).
    DiskPressure,
}

/// Response indicating the responder will not serve the requested
/// SHA. Per CIRISEdge#21 spec point 3 — required so the fetcher can
/// fail over instead of hanging on a peer that silently dropped the
/// request.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ContentMiss {
    /// SHA-256 the requester asked for — echoed back so the fetcher
    /// can correlate the miss to the in-flight fetch even when many
    /// are outstanding (the wire `in_reply_to` covers the envelope
    /// correlation; this field covers the body-level correlation).
    pub sha256: [u8; 32],
    /// Why the responder is missing or refusing.
    pub reason: MissReason,
}

impl Message for ContentMiss {
    const TYPE: MessageType = MessageType::ContentMiss;
    /// Same wire class as the [`ContentFetch`] it responds to —
    /// point-to-point, retryable.
    const DELIVERY: Delivery = Delivery::Ephemeral;
    type Response = ();
}

// ─── CIRISEdge#55 — chunked-blob swarm wire shapes ──────────────────

/// Fetch one chunk of a chunked blob (v2.5.0, CIRISEdge#55).
///
/// Distinct from [`ContentFetch`] in two ways:
///   - Carries TWO SHAs: `blob_sha256` (overall, bound by the
///     `ChunkManifest`) and `chunk_sha256` (this specific chunk).
///   - Modeled for swarm-style multi-peer scheduling — the requester
///     issues many of these concurrently across the set returned by
///     `BlobStorage::list_holders(blob_sha256)`, with per-peer EWMA +
///     in-flight caps.
///
/// Same [`Delivery::Ephemeral`] class as [`ContentFetch`] — point-to-
/// point, retryable, no Mandatory fan-out. Any peer holding the chunk
/// may respond with [`BlobChunkBody`]; a peer that does not (or
/// refuses under policy) responds with [`BlobChunkMiss`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlobChunkFetch {
    /// SHA-256 of the OVERALL blob (manifest-bound). Lets the
    /// responder cheaply scope the lookup to a single blob's chunk set
    /// instead of a full index scan.
    pub blob_sha256: [u8; 32],
    /// SHA-256 of the SPECIFIC chunk requested. The
    /// [`ChunkManifest`](https://github.com/CIRISAI/CIRISPersist)
    /// (persist v4.1, CIRISPersist#142) is what binds this to a byte
    /// range inside `blob_sha256`.
    pub chunk_sha256: [u8; 32],
    /// Optional fetcher-side preference shape. Reuses the
    /// [`HintShape`] vocabulary from [`ContentFetch`] — no new
    /// hint-class is introduced for swarm-fetch; the scheduler-side
    /// logic (EWMA, in-flight cap) is fetcher-local and not wire-bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_hint: Option<HintShape>,
}

impl Message for BlobChunkFetch {
    const TYPE: MessageType = MessageType::BlobChunkFetch;
    const DELIVERY: Delivery = Delivery::Ephemeral;
    /// Like [`ContentFetch`], the peer chooses BlobChunkBody xor
    /// BlobChunkMiss; both are typed envelopes carrying their own
    /// bodies. `()` marks the wire-level "no inline response struct".
    type Response = ();
}

/// Response carrying the bytes for a [`BlobChunkFetch`].
///
/// # Integrity invariant (CIRISEdge#55 / CIRISPersist#145 seam)
///
/// The receiver does NOT verify in-handler; it hands the body to
/// `BlobStorage::put_blob_chunk(blob_sha256, chunk_sha256, &bytes)`
/// which atomically verifies `sha256(bytes) == chunk_sha256` and
/// stores. On hash failure persist returns `ChunkMismatch`; the
/// scheduler treats that as evidence the responder is dishonest and
/// demotes them from the candidate set for the rest of the session.
///
/// This is the §10.1.1 verify-on-write seam — edge transports bytes,
/// persist owns SHA verification + persistence in one atomic step.
///
/// # Size bound
///
/// `bytes.len()` is bounded by [`DEFAULT_MAX_CONTENT_BODY_BYTES`] (the
/// same AV-13 ceiling that bounds [`ContentBody`]) — individual
/// chunks above that ceiling SHOULD NOT exist (the persist chunk
/// boundary is set well below). Operators using non-default chunk
/// sizes MUST keep chunks under the ceiling.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlobChunkBody {
    /// SHA-256 of the OVERALL blob — echoed back from the request for
    /// scheduler-side correlation when many fetches are outstanding
    /// across multiple blobs.
    pub blob_sha256: [u8; 32],
    /// SHA-256 the responder claims this chunk hashes to. Verified by
    /// `BlobStorage::put_blob_chunk` on receipt.
    pub chunk_sha256: [u8; 32],
    /// The chunk bytes. Bounded by [`DEFAULT_MAX_CONTENT_BODY_BYTES`]
    /// (AV-13 ceiling).
    pub bytes: Vec<u8>,
}

impl Message for BlobChunkBody {
    const TYPE: MessageType = MessageType::BlobChunkBody;
    const DELIVERY: Delivery = Delivery::Ephemeral;
    type Response = ();
}

/// Response indicating the responder will not serve the requested
/// chunk. Same [`MissReason`] vocabulary as [`ContentMiss`] — the
/// scheduler's reaction differs per reason: `NotHeld` → try another
/// holder; `Withdrawn` / `Revoked` → abort the whole fetch (chunk is
/// gone federation-wide); `PolicyDenied` → demote this responder for
/// the rest of the session.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlobChunkMiss {
    /// SHA-256 of the OVERALL blob — echoed for correlation.
    pub blob_sha256: [u8; 32],
    /// SHA-256 the requester asked for — echoed for body-level
    /// correlation (envelope-level correlation rides
    /// `in_reply_to`).
    pub chunk_sha256: [u8; 32],
    /// Why the responder is missing or refusing.
    pub reason: MissReason,
}

impl Message for BlobChunkMiss {
    const TYPE: MessageType = MessageType::BlobChunkMiss;
    const DELIVERY: Delivery = Delivery::Ephemeral;
    type Response = ();
}

/// Compute the SHA-256 of a byte slice. The receiver-side integrity
/// check (`sha256(bytes) == ContentBody.sha256`) calls this; exposed
/// pub so consumers building [`ContentBody`] can compute the field
/// without re-importing `sha2` themselves.
///
/// Implementation uses the `sha2` crate directly (same dep edge
/// already carries for `body_sha256`); no extra wrapper.
#[must_use]
pub fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
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

// ─── CIRISEdge#41 (v0.11.1) — GoalDeclaration / GoalRetirement ──────
//
// Federation transport for the typed `Goal` primitive landed in
// CIRISPersist#114 (persist v2.10.0). The F-3 detector family
// (CIRISLensCore#23 / #24 / #26) aggregates goals across the
// federation by `goal_id`; without these wire types the only
// goal-shaped data crossing the federation was the agent's untyped
// `deferred_goals: serde_json::Value` blob in the continuity-awareness
// snapshot — not typed, not signed as a goal, not addressable by
// `goal_id`. This module closes the transport gap.
//
// **Persist field-name note.** The CIRISEdge#41 issue body refers to
// an `m1_rationale` field that the canonical bytes MUST include.
// Persist v2.10.0's [`Goal`] structure carries that data on
// `goal.meta_goal_alignment.rationale: String` (the M-1 rationale)
// alongside `goal.meta_goal_alignment.dimension: M1Dimension` (which
// M-1 dimension the goal serves). The canonical-bytes encoder below
// includes BOTH — dimension + rationale — so the F-3 detector input
// is byte-stably bound to both the dimensional claim and the
// declarer's reasoning. Excluding the rationale would let a declarer
// trivially route around F-3 (same dimension, different
// reasoning-content, same canonical bytes — exactly the
// attractor-capture failure mode MISSION.md §1 names).
//
// **Persist does NOT export `SignedGoalRetirement`.** The CIRISEdge#41
// issue body sketches a `pub struct GoalRetirement(pub
// ciris_persist::schema::SignedGoalRetirement)` shape, but persist
// v2.10.0's `retire_goal` API takes only `(goal_id: Uuid, retired_at:
// DateTime<Utc>)` — there is no `SignedGoalRetirement` type. The wire
// shape below is a self-contained payload (goal_id, retired_at,
// retired_by_key_id, optional reason); the envelope's hybrid Ed25519 +
// ML-DSA-65 signature provides the cryptographic binding (same shape
// every other federation primitive uses — edge does not double-sign
// inside the body). Quorum-signed retirements for
// `GoalScope::Federation` defer to a future amendment per the issue
// body §"Out of scope".

/// Domain-separation tag for [`GoalDeclaration::canonical_bytes`].
/// **LOCKED** wire constant — mirrors [`DELIVERY_ATTESTATION_DOMAIN`]
/// pattern. Changing this is a coordinated CIRISEdge + CIRISLensCore +
/// CIRISPersist break.
pub const GOAL_DECLARATION_DOMAIN: &[u8] = b"ciris-edge-goal-declaration-v1";

/// Domain-separation tag for [`GoalRetirement::canonical_bytes`].
/// **LOCKED** wire constant — mirrors [`DELIVERY_ATTESTATION_DOMAIN`]
/// pattern. Changing this is a coordinated CIRISEdge + CIRISLensCore +
/// CIRISPersist break.
pub const GOAL_RETIREMENT_DOMAIN: &[u8] = b"ciris-edge-goal-retirement-v1";

/// Federation transport wrapper for the persist v2.10.0 (CIRISPersist#114)
/// typed [`ciris_persist::federation::goal::Goal`] primitive.
///
/// Transparent newtype — the wire body is the persist `Goal`'s
/// `serde_json` form verbatim. Receivers deserialize into
/// `ciris_persist::federation::goal::Goal` and hand to lens-core's
/// `Handler<GoalDeclaration>` which calls
/// `FederationDirectory::put_goal` per the cohabitation pattern.
///
/// # Wire-level invariants
///
/// 1. **M-1 alignment is structural.** Persist's `Goal::new` takes
///    [`MetaGoalAlignment`](ciris_persist::federation::goal::MetaGoalAlignment)
///    by value (not `Option`), so a `Goal` cannot deserialize without
///    it — the receiver's deserializer rejects bodies missing the field.
/// 2. **Canonical bytes include `meta_goal_alignment` (dimension +
///    rationale).** See [`GoalDeclaration::canonical_bytes`] — required
///    so a declarer cannot route around F-3 by varying rationale
///    while keeping the same canonical bytes.
/// 3. **Durable delivery.** Goals are federation evidence; F-3
///    aggregation requires they reach every interested peer (not
///    best-effort). Same shape as [`BuildManifestPublication`].
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
pub struct GoalDeclaration(pub ciris_persist::federation::goal::Goal);

/// Lens-core's response to a [`GoalDeclaration`]. Distinguishes accept
/// (the goal landed in the `goals` table — `accepted = true`,
/// `reason = None`) from reject (`accepted = false`,
/// `reason = Some(...)` — e.g. duplicate `goal_id`, declared_by mismatch
/// against envelope sender, scope-policy violation).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GoalDeclarationResponse {
    /// `true` iff the goal landed in persist; `false` if lens-core
    /// rejected (and `reason` is populated).
    pub accepted: bool,
    /// Echo of the declared goal's `goal_id` (correlation key for the
    /// originating declarer; the envelope's `in_reply_to` covers the
    /// envelope-level correlation, this field covers body-level).
    pub goal_id: uuid::Uuid,
    /// `None` on accept; populated on reject with a short human-readable
    /// rationale. NOT a closed-vocabulary enum at v0.11.1 — lens-core
    /// owns the rejection taxonomy; future cuts may type-narrow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Message for GoalDeclaration {
    const TYPE: MessageType = MessageType::GoalDeclaration;
    /// Durable, requires_ack — federation evidence for F-3
    /// aggregation; the response carries accept/reject and lens-core
    /// must observably succeed or fail. Same long-haul shape as
    /// [`BuildManifestPublication`] (week-long TTL, 100 attempts,
    /// 5-minute ack timeout) — goals are slow-cadence federation
    /// state, not chat-tier.
    const DELIVERY: Delivery = Delivery::Durable {
        requires_ack: true,
        max_attempts: 100,
        ttl_seconds: 7 * 24 * 60 * 60, // 7 days
        ack_timeout_seconds: Some(300),
    };
    type Response = GoalDeclarationResponse;
}

impl GoalDeclaration {
    /// Canonical bytes for the GoalDeclaration body — length-prefixed
    /// injective encoding, mirroring [`DeliveryAttestation::canonical_bytes`]
    /// pattern. Includes:
    ///
    /// - `goal_id` (UUID string form, 36 bytes)
    /// - `declared_by_key_id`
    /// - `declared_at` (i64 ms big-endian, 8 bytes fixed)
    /// - `goal_text`
    /// - `scope_kind` (string token: `"single_declarer"` / `"cohort"` /
    ///   `"federation"`)
    /// - optional `cohort_id` (length-prefixed Option discriminant)
    /// - `meta_goal_alignment.dimension` (string token)
    /// - **`meta_goal_alignment.rationale`** — the load-bearing
    ///   M-1 rationale field per CIRISEdge#41 + CIRISPersist#114
    ///   §"Why M-1 is structural"
    ///
    /// Excludes `retired_at` (a declaration cannot carry a retirement
    /// marker — the wire shape is pre-retirement by construction;
    /// retirement rides [`GoalRetirement`]).
    ///
    /// `DOMAIN` is [`GOAL_DECLARATION_DOMAIN`]. Length prefixes make
    /// the encoding injective — distinct field tuples never share a
    /// byte string.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let g = &self.0;
        let goal_id_str = g.goal_id.to_string();
        let dimension_str = g.meta_goal_alignment.dimension.as_str();
        let scope_kind_str = g.scope.scope_kind_str();
        let cohort_id_opt = g.scope.cohort_id();

        let mut out = Vec::new();
        out.extend_from_slice(GOAL_DECLARATION_DOMAIN);
        write_len_prefixed(&mut out, goal_id_str.as_bytes());
        write_len_prefixed(&mut out, g.declared_by_key_id.as_bytes());
        out.extend_from_slice(&g.declared_at.timestamp_millis().to_be_bytes());
        write_len_prefixed(&mut out, g.goal_text.as_bytes());
        write_len_prefixed(&mut out, scope_kind_str.as_bytes());
        match cohort_id_opt {
            Some(c) => {
                out.push(1u8);
                write_len_prefixed(&mut out, c.as_bytes());
            }
            None => out.push(0u8),
        }
        write_len_prefixed(&mut out, dimension_str.as_bytes());
        // **Load-bearing field.** The F-3 detector family is predicated
        // on the declarer having claimed an M-1 rationale; binding the
        // rationale bytes into the canonical-bytes domain prevents a
        // declarer from holding the SAME canonical bytes while
        // mutating the rationale (the trivial attractor-capture
        // route-around). See module-level note + CIRISEdge#41.
        write_len_prefixed(&mut out, g.meta_goal_alignment.rationale.as_bytes());

        out
    }
}

/// Federation transport of a single-signer goal retirement. The
/// envelope's hybrid Ed25519 + ML-DSA-65 signature IS the
/// proof-of-authority — there are no body-internal signatures at
/// v0.11.1 (quorum-signed retirements deferred per CIRISEdge#41
/// §"Out of scope").
///
/// Maps onto persist v2.10.0's `retire_goal(goal_id, retired_at)`
/// API; receivers (lens-core's `Handler<GoalRetirement>`) call that
/// directly per the cohabitation pattern. `retired_by_key_id` is
/// cross-checked against the originating goal's `declared_by_key_id`
/// at the consumer (lens-core enforcement; edge is reach, not gate
/// per MISSION.md §1.3).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GoalRetirement {
    /// The `goal_id` of the previously-declared [`Goal`] to retire.
    pub goal_id: uuid::Uuid,
    /// Wall-clock at retirement. Sealed into the signed envelope —
    /// the receiver passes this through to `retire_goal`.
    pub retired_at: DateTime<Utc>,
    /// `federation_keys.key_id` of the party retiring the goal.
    /// MUST match (lens-core enforcement) the originating
    /// `declared_by_key_id` for `GoalScope::SingleDeclarer` and
    /// `GoalScope::Cohort` goals; `GoalScope::Federation` retirement
    /// requires quorum and is deferred at v0.11.1.
    pub retired_by_key_id: String,
    /// Optional human-readable rationale (audit-chain only; not used
    /// for retirement enforcement at v0.11.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Receiver's response to a [`GoalRetirement`]. The `retired_at` is
/// echoed back — lens-core MAY clamp / round (persist's `retire_goal`
/// is idempotent, so the canonical timestamp is the first-write one),
/// so the response carries the stored value rather than the sender's
/// proposed value.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GoalRetirementResponse {
    /// `true` iff the retirement landed (or was already retired —
    /// persist's `retire_goal` is idempotent per CIRISPersist#114).
    pub accepted: bool,
    /// Canonical `retired_at` as stored in persist — the first-write
    /// timestamp on idempotent re-retire; the sender's proposed value
    /// otherwise.
    pub retired_at: DateTime<Utc>,
}

impl Message for GoalRetirement {
    const TYPE: MessageType = MessageType::GoalRetirement;
    /// Durable, requires_ack — an unrecorded retirement looks the
    /// same as a live goal to the F-3 detector (the false-positive
    /// failure mode CIRISEdge#41 §"Delivery posture" calls out). Same
    /// long-haul shape as [`GoalDeclaration`].
    const DELIVERY: Delivery = Delivery::Durable {
        requires_ack: true,
        max_attempts: 100,
        ttl_seconds: 7 * 24 * 60 * 60, // 7 days
        ack_timeout_seconds: Some(300),
    };
    type Response = GoalRetirementResponse;
}

impl GoalRetirement {
    /// Canonical bytes for the GoalRetirement body — length-prefixed
    /// injective encoding, mirroring [`DeliveryAttestation::canonical_bytes`]
    /// pattern. Includes goal_id, retired_at (i64 ms big-endian),
    /// retired_by_key_id, and the optional reason (Option discriminant
    /// + len-prefixed bytes when present).
    ///
    /// `DOMAIN` is [`GOAL_RETIREMENT_DOMAIN`].
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let goal_id_str = self.goal_id.to_string();
        let mut out = Vec::new();
        out.extend_from_slice(GOAL_RETIREMENT_DOMAIN);
        write_len_prefixed(&mut out, goal_id_str.as_bytes());
        out.extend_from_slice(&self.retired_at.timestamp_millis().to_be_bytes());
        write_len_prefixed(&mut out, self.retired_by_key_id.as_bytes());
        match self.reason.as_ref() {
            Some(r) => {
                out.push(1u8);
                write_len_prefixed(&mut out, r.as_bytes());
            }
            None => out.push(0u8),
        }
        out
    }
}

// ─── CIRISEdge#42 (v0.12.0) — Withdraws (CEG §10.1.2) ───────────────
//
// Consumer-side feedback: when a `ContentFetch` returns a `ContentMiss`
// (the holder advertised `holds_bytes:sha256:{prefix}` but didn't
// actually serve the bytes), the consumer signs a `Withdraws`
// attestation against the `(holder_key_id, sha256)` pair and ships it
// via the existing federation evidence path. Receivers aggregate per
// holder and apply the downweight policy in their own `PeerResolver`.
//
// The withdrawal is NOT the same as a `holds_bytes` retraction by the
// holder itself — that would be a `holds_bytes` attestation with
// `is_active = false` (or a `superseded` row) at the substrate tier.
// `Withdraws` is consumer-emitted: the consumer is saying "this
// holder advertised holding these bytes but failed to deliver".

/// Reason a [`Withdraws`] was emitted. The taxonomy is closed at
/// v0.12.0 — receivers branching on this field can rely on the full
/// set being known.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalReason {
    /// The holder responded with [`MessageType::ContentMiss`] — the
    /// canonical CEG §10.1.2 case. The consumer's fetch attempt
    /// completed (no transport failure) but the holder declined to
    /// serve the bytes despite advertising the `holds_bytes`
    /// attestation.
    ContentMiss,
    /// The holder served a [`ContentBody`] but the SHA-256 of
    /// `body.bytes` did not match `body.sha256`. CEG §10.1.1
    /// content-integrity failure — the consumer MUST withdraw the
    /// holder per the spec.
    IntegrityFailure,
    /// The holder did not respond within the consumer's fetch
    /// timeout. CEG §10.1.2 explicitly lists timeout-as-miss because
    /// a holder advertising bytes it cannot deliver fails the
    /// federation's reach guarantee.
    Timeout,
}

/// CEG §10.1.2 consumer-side withdrawal attestation. Signed by the
/// consumer's federation key (via the surrounding envelope's
/// hybrid Ed25519 + ML-DSA-65 signature — no body-internal signature).
/// Receivers aggregate per `(holder_key_id, sha256)` and apply the
/// downweight policy in their own [`crate::transport::reticulum::PeerResolver`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Withdraws {
    /// The holder whose `holds_bytes:sha256:{prefix}` attestation is
    /// being withdrawn against. `federation_keys.key_id`.
    pub holder_key_id: String,
    /// The SHA-256 the holder advertised holding. 32 bytes raw,
    /// base64-standard on the wire (44 chars), same convention as
    /// [`ContentBody::sha256`].
    pub sha256: [u8; 32],
    /// Why the consumer is withdrawing — see [`WithdrawalReason`].
    pub withdrawal_reason: WithdrawalReason,
    /// When the consumer observed the failure that triggered the
    /// withdrawal. NOT raw send-time — the consumer's observation
    /// is the load-bearing input for the receiver's downweight
    /// window arithmetic.
    pub observed_at: DateTime<Utc>,
}

impl Message for Withdraws {
    const TYPE: MessageType = MessageType::Withdraws;
    /// Durable, fire-and-forget — the withdrawal IS the audit
    /// observable; no second ACK needed. Same long-haul shape as
    /// [`DeliveryAttestation`] (24h TTL, 20 attempts) — withdrawals
    /// are federation evidence at the same cadence as attestations.
    const DELIVERY: Delivery = Delivery::Durable {
        requires_ack: false,
        max_attempts: 20,
        ttl_seconds: 24 * 60 * 60,
        ack_timeout_seconds: None,
    };
    type Response = ();
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

    // ─── CIRISEdge#21 unit tests ────────────────────────────────────

    /// `ContentFetch` / `ContentBody` / `ContentMiss` MUST all declare
    /// `Delivery::Ephemeral` — point-to-point, retryable per
    /// CIRISEdge#21 spec point 5. A regression that promotes them to
    /// `Mandatory` would silently broadcast content fetches across
    /// the federation; promotion to `Durable` would persist large
    /// payload bodies in the outbound queue. Both are wrong.
    #[test]
    fn content_fetch_family_declares_ephemeral() {
        assert!(matches!(ContentFetch::DELIVERY, Delivery::Ephemeral));
        assert!(matches!(ContentBody::DELIVERY, Delivery::Ephemeral));
        assert!(matches!(ContentMiss::DELIVERY, Delivery::Ephemeral));
        assert_eq!(ContentFetch::TYPE, MessageType::ContentFetch);
        assert_eq!(ContentBody::TYPE, MessageType::ContentBody);
        assert_eq!(ContentMiss::TYPE, MessageType::ContentMiss);
    }

    /// CIRISEdge#55 — the chunked-blob swarm triple mirrors the
    /// whole-file ContentFetch family exactly: same Ephemeral
    /// delivery class, same TYPE-discriminator round-trip.
    #[test]
    fn blob_chunk_fetch_family_declares_ephemeral() {
        assert!(matches!(BlobChunkFetch::DELIVERY, Delivery::Ephemeral));
        assert!(matches!(BlobChunkBody::DELIVERY, Delivery::Ephemeral));
        assert!(matches!(BlobChunkMiss::DELIVERY, Delivery::Ephemeral));
        assert_eq!(BlobChunkFetch::TYPE, MessageType::BlobChunkFetch);
        assert_eq!(BlobChunkBody::TYPE, MessageType::BlobChunkBody);
        assert_eq!(BlobChunkMiss::TYPE, MessageType::BlobChunkMiss);
    }

    /// CIRISEdge#55 — round-trip both SHAs through JSON serde.
    /// Catches accidental wire-shape drift between Fetch / Body / Miss
    /// (all three must carry the same SHA pair).
    #[test]
    fn blob_chunk_wire_shapes_round_trip_through_json() {
        let blob = [7u8; 32];
        let chunk = [11u8; 32];
        let fetch = BlobChunkFetch {
            blob_sha256: blob,
            chunk_sha256: chunk,
            response_hint: None,
        };
        let body = BlobChunkBody {
            blob_sha256: blob,
            chunk_sha256: chunk,
            bytes: vec![1, 2, 3],
        };
        let miss = BlobChunkMiss {
            blob_sha256: blob,
            chunk_sha256: chunk,
            reason: MissReason::NotHeld,
        };
        let f_rt: BlobChunkFetch =
            serde_json::from_str(&serde_json::to_string(&fetch).unwrap()).unwrap();
        let b_rt: BlobChunkBody =
            serde_json::from_str(&serde_json::to_string(&body).unwrap()).unwrap();
        let m_rt: BlobChunkMiss =
            serde_json::from_str(&serde_json::to_string(&miss).unwrap()).unwrap();
        assert_eq!(f_rt, fetch);
        assert_eq!(b_rt, body);
        assert_eq!(m_rt, miss);
    }

    /// `MissReason` serde rules MUST be `snake_case` — pinned by the
    /// cross-repo wire convention.
    #[test]
    fn miss_reason_serde_matches_snake_case() {
        assert_eq!(
            serde_json::to_string(&MissReason::NotHeld).unwrap(),
            r#""not_held""#
        );
        assert_eq!(
            serde_json::to_string(&MissReason::Withdrawn).unwrap(),
            r#""withdrawn""#
        );
        assert_eq!(
            serde_json::to_string(&MissReason::Revoked).unwrap(),
            r#""revoked""#
        );
        assert_eq!(
            serde_json::to_string(&MissReason::PolicyDenied).unwrap(),
            r#""policy_denied""#
        );
        // Round-trip every variant.
        for reason in [
            MissReason::NotHeld,
            MissReason::Withdrawn,
            MissReason::Revoked,
            MissReason::PolicyDenied,
        ] {
            let s = serde_json::to_string(&reason).unwrap();
            let back: MissReason = serde_json::from_str(&s).unwrap();
            assert_eq!(reason, back);
        }
    }

    /// `sha256_of` is the integrity-check helper; pin it against a
    /// known vector so a regression in the digest path is caught.
    /// `sha256("")` = the empty-string SHA-256 (RFC 6234 test vector).
    #[test]
    fn sha256_of_empty_matches_rfc_6234() {
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(sha256_of(b""), expected);
    }

    /// `ContentBody` JSON round-trip preserves every field — the
    /// integrity-check property `sha256(bytes) == sha256` must survive
    /// the wire serialization.
    #[test]
    fn content_body_json_round_trip_preserves_integrity_invariant() {
        let bytes: Vec<u8> = (0u8..64).collect();
        let sha = sha256_of(&bytes);
        let body = ContentBody {
            sha256: sha,
            bytes: bytes.clone(),
            attestation_ref: Some(AttestationRef {
                attestation_id: "11111111-1111-1111-1111-111111111111".into(),
                signing_key_id: "edge-peer-01".into(),
            }),
        };
        let s = serde_json::to_string(&body).unwrap();
        let back: ContentBody = serde_json::from_str(&s).unwrap();
        assert_eq!(body, back);
        // Integrity invariant survives round-trip.
        assert_eq!(sha256_of(&back.bytes), back.sha256);
    }

    // ─── CC 0.7 opaque wire vocabulary (CIRISEdge#241, v8.0.0) ──────

    /// Delivery-class pins for the three opaque wire types.
    /// `OpaqueRequest` / `OpaqueResponse` are ephemeral; `OpaqueEvent`
    /// is durable, fire-and-forget. A regression that flipped these
    /// would break the request/response correlation + subscriber
    /// fan-out contracts (WIRE_VOCABULARY.md §3.3).
    #[test]
    fn opaque_delivery_classes_pinned() {
        assert_eq!(OpaqueRequest::TYPE, MessageType::OpaqueRequest);
        assert_eq!(OpaqueResponse::TYPE, MessageType::OpaqueResponse);
        assert_eq!(OpaqueEvent::TYPE, MessageType::OpaqueEvent);
        assert!(matches!(OpaqueRequest::DELIVERY, Delivery::Ephemeral));
        assert!(matches!(OpaqueResponse::DELIVERY, Delivery::Ephemeral));
        match OpaqueEvent::DELIVERY {
            Delivery::Durable { requires_ack, .. } => {
                assert!(!requires_ack, "OpaqueEvent is fire-and-forget");
            }
            other => panic!("OpaqueEvent must be Durable; got {other:?}"),
        }
    }

    /// Opaque bodies round-trip: `payload` is preserved byte-for-byte
    /// and edge assigns no meaning to `kind` / `status`.
    #[test]
    fn opaque_bodies_round_trip() {
        let req = OpaqueRequest {
            kind: 42,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let back: OpaqueRequest =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(req, back);

        let resp = OpaqueResponse {
            kind: 42,
            status: 501,
            payload: b"unknown kind".to_vec(),
        };
        let back: OpaqueResponse =
            serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
        assert_eq!(resp, back);

        let ev = OpaqueEvent {
            kind: 7,
            payload: vec![1, 2, 3],
        };
        let back: OpaqueEvent = serde_json::from_str(&serde_json::to_string(&ev).unwrap()).unwrap();
        assert_eq!(ev, back);
    }

    /// `ContentFetch` JSON round-trip with and without a hint.
    #[test]
    fn content_fetch_json_round_trip_with_and_without_hint() {
        let fetch_nohint = ContentFetch {
            sha256: [0xAB; 32],
            response_hint: None,
        };
        let s = serde_json::to_string(&fetch_nohint).unwrap();
        let back: ContentFetch = serde_json::from_str(&s).unwrap();
        assert_eq!(fetch_nohint, back);

        let fetch_hint = ContentFetch {
            sha256: [0xCD; 32],
            response_hint: Some(HintShape {
                max_body_bytes: Some(1024 * 1024),
                prefer_chunked: true,
            }),
        };
        let s = serde_json::to_string(&fetch_hint).unwrap();
        let back: ContentFetch = serde_json::from_str(&s).unwrap();
        assert_eq!(fetch_hint, back);
    }
}
