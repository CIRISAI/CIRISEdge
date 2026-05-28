//! Typed handler dispatch.
//!
//! Mission: dispatch verified messages to the right host code through
//! typed contracts that prevent mission-violating behaviors. No
//! `&[u8]` past parse; no `serde_json::Value` in handler signatures.
//! Every message type has a Rust struct with `serde::Deserialize`;
//! handlers receive parsed structs, not raw bytes.
//!
//! See [`MISSION.md`](../../MISSION.md) §2 (`handler/`) and
//! [`FSD/CIRIS_EDGE.md`](../../FSD/CIRIS_EDGE.md) §3.2.
//!
//! # Delivery class
//!
//! Per OQ-09, the delivery class lives on the message type, not the
//! call site. `Message::DELIVERY` declares whether a message ships
//! over `Edge::send` (ephemeral) or `Edge::send_durable` (persistent
//! queue). `register_handler` enforces the contract at compile time.

use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Serialize};

use crate::messages::MessageType;
use crate::transport::TransportId;
use crate::verify::VerifyOutcome;

/// Delivery class for a message type. Declared as a const on
/// [`Message`]; copied to `edge_outbound_queue` per row at enqueue
/// time so policy changes don't retroactively break in-flight rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Ships over `Edge::send`. Caller-owned retry. Failure visible
    /// as `EdgeError::Unreachable`. Persist's AV-9 dedup is the
    /// recovery mechanism for "message dropped in transit, sender
    /// retries" cases.
    Ephemeral,
    /// Ships over `Edge::send_durable`. Edge-owned persistent queue
    /// (`cirislens.edge_outbound_queue`); caller gets a
    /// [`DurableHandle`] to observe outcome. Per-row policy:
    Durable {
        /// If `true`, transport-level delivery is not terminal —
        /// receiver must sign + return an ACK envelope before the row
        /// transitions to `delivered`.
        requires_ack: bool,
        /// Hard cap on retry attempts before the row abandons with
        /// `abandoned_reason='max_attempts'`.
        max_attempts: u32,
        /// Time-to-live; rows older than this abandon with
        /// `abandoned_reason='ttl_expired'` regardless of retry state.
        ttl_seconds: u64,
        /// Per-row ACK-timeout (only meaningful when `requires_ack=true`).
        /// `None` here is rejected at enqueue when `requires_ack=true`.
        ack_timeout_seconds: Option<u64>,
    },
    /// Ships over `Edge::send_federation`. High-priority recipient
    /// class — routed-with-preference fan-out to a dynamically-
    /// derived subset of the directory (currently the steward set,
    /// per CIRISEdge#20). DISTINCT from [`Self::Mandatory`]:
    /// Federation routes with preference but **does NOT bypass**
    /// per-peer subscription filters; it is the substrate's high-
    /// priority class between best-effort gossip and the federation-
    /// wide push of Mandatory. The recipient set is re-resolved on
    /// every send (`Edge::send_federation` calls the configured
    /// [`crate::outbound::StewardDirectory`] each invocation) so
    /// steward rotation (Registry FSD-002 §2.1) propagates without
    /// caching.
    ///
    /// Per-row durability config mirrors the [`Self::Durable`] class:
    /// receiver SHOULD sign + return an ACK (per
    /// [`crate::DeliveryAttestation`] per FSD §3.2.1 — the same
    /// attestation shape `FederationAnnouncement` introduced) so the
    /// audit observable is uniform across the federation push paths.
    /// Closes CIRISEdge#20.
    Federation {
        /// High-priority recipient class. v0.10.0 ships ONE
        /// ([`FederationPriority::StewardClass`]); future classes
        /// (`AccordHolderClass` for #19-adjacent uses, etc.) extend
        /// this enum without breaking the wire — the priority is a
        /// routing hint, not a wire-format dimension.
        priority: FederationPriority,
        /// Same semantics as [`Self::Durable::requires_ack`]: receiver
        /// MUST sign + return an ACK envelope ([`crate::DeliveryAttestation`]
        /// per FSD §3.2.1) before the row transitions to `delivered`.
        requires_ack: bool,
        /// Hard cap on retry attempts before the row abandons with
        /// `abandoned_reason='max_attempts'`.
        max_attempts: u32,
        /// Time-to-live; rows older than this abandon with
        /// `abandoned_reason='ttl_expired'`.
        ttl_seconds: u64,
        /// Per-row ACK-timeout (only meaningful when `requires_ack=true`).
        ack_timeout_seconds: Option<u64>,
    },
    /// Ships over `Edge::send_mandatory`. Federation-tier broadcast
    /// that bypasses any subscription / per-peer filter at the
    /// dispatcher: the message fans out to **every peer** in the
    /// federation directory regardless of subscription state.
    ///
    /// This is the substrate-side wire shape that makes a
    /// `FederationAnnouncement` actually reach every node — without
    /// the bypass, "Mandatory" would just be a name. Closes
    /// CIRISEdge#18 + CIRISNodeCore FSD §3.2 (substrate contract).
    ///
    /// The trust gate (authority-class verify, witness-set check) is
    /// applied by the **consumer** (CIRISNodeCore on receipt) per
    /// FSD §3.1 — edge's job is reach, NodeCore's job is whether the
    /// message is honored. Edge does NOT validate `authority_signed`
    /// at the wire layer for v0.1; the flag is a contract marker so
    /// consumer-side code can route based on it without re-parsing
    /// the envelope body.
    Mandatory {
        /// Always `true` for the FSD §2.1 `FederationAnnouncement`
        /// primitive — only authority-signed messages may ride the
        /// Mandatory class. The flag is a wire-level contract marker
        /// (not a verify gate at edge); CIRISNodeCore's admission
        /// code is the authority-class checker per FSD §3.4.
        authority_signed: bool,
        /// Always `true` — the load-bearing semantics. The
        /// dispatcher fans out regardless of any per-peer
        /// subscription filter; receivers cannot opt out at the
        /// transport layer (MISSION.md §1.1 Justice: independence
        /// must not become silent suppression of a federation-wide
        /// signal).
        bypass_subscription: bool,
    },
}

/// High-priority recipient class for [`Delivery::Federation`]
/// (CIRISEdge#20). v0.10.0 ships ONE variant — `StewardClass`. Future
/// classes (`AccordHolderClass` for the #19-adjacent verify set, etc.)
/// extend this enum without breaking the wire — the priority is a
/// substrate-routing hint, not a wire-format dimension, so no
/// receiver-side `MessageType` discriminator changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationPriority {
    /// Per-install regional stewards (US / EU / APAC) per Registry
    /// FSD-002 §2.1. Edge derives the recipient set dynamically from
    /// persist's `federation_keys` directory where
    /// `identity_type = "steward"` (persist v2.7.0
    /// [`FederationDirectory::list_keys_by_identity_type`](ciris_persist::federation::FederationDirectory::list_keys_by_identity_type)).
    /// Recomputed on every [`crate::Edge::send_federation`] call — no
    /// caching — so steward rotation (FSD-002 §2.1 rotation arc)
    /// propagates immediately.
    StewardClass,
}

/// A typed message that can ride the federation wire. Each message
/// type implements this with const items declaring its discriminator
/// and delivery class.
///
/// # Example
///
/// ```ignore
/// pub struct AccordEventsBatch { /* ... */ }
/// pub struct AccordEventsResponse { /* ... */ }
///
/// impl Message for AccordEventsBatch {
///     const TYPE: MessageType = MessageType::AccordEventsBatch;
///     const DELIVERY: Delivery = Delivery::Ephemeral;
///     type Response = AccordEventsResponse;
/// }
/// ```
pub trait Message: DeserializeOwned + Serialize + Send + 'static {
    /// Wire discriminator.
    const TYPE: MessageType;
    /// Delivery class — determines `send` vs `send_durable` dispatch.
    const DELIVERY: Delivery;
    /// Receiver's response type. Use `()` for fire-and-forget messages.
    type Response: DeserializeOwned + Serialize + Send + 'static;
}

/// A [`Message`] whose body wraps a single inline-text payload —
/// SPEAK responses, LLM prompts, WBD bodies, DSAR text. Implementors
/// can be sent via [`crate::Edge::send_inline`] /
/// [`crate::Edge::send_durable_inline`], which run the configured
/// `speak_pipeline` (Classify + Scrub + EncryptAndStore) on the text
/// before signing + shipping — the cleartext never leaves the
/// process. Per FSD §1.4 "encryption boundary collapse" and
/// CIRISAgent#756 Q1 (outbound SPEAK transit-touch).
pub trait InlineTextMessage: Message {
    /// The inline text body. Pipeline scrub stages mutate this in
    /// place via [`Self::set_text`].
    fn text(&self) -> &str;
    /// Replace the inline text. Called by edge after the pipeline
    /// has transformed the text (e.g., scrubbed PII spans,
    /// substituted `{SECRET:uuid:description}` placeholders).
    fn set_text(&mut self, text: String);
}

/// Per-message context delivered to the handler alongside the parsed
/// body. Forensic-completeness invariant: every field surfaces a join
/// key into persist's structured logs (AV's "forensic completeness"
/// test category).
#[derive(Debug, Clone)]
pub struct HandlerContext {
    /// Already resolved against `federation_keys.identity_ref` by the
    /// verify pipeline; handlers can authorize on this without
    /// re-querying persist.
    pub signing_key_id: String,
    /// 32-byte forensic join key — matches persist's
    /// `body_sha256_prefix` index. Also the `in_reply_to` ACK key
    /// when responding.
    pub body_sha256: [u8; 32],
    /// Which transport carried this message (TCP / Reticulum / LoRa /
    /// HTTP-fallback). Enables transport-aware metric tagging.
    pub transport: TransportId,
    /// Hybrid PQC verify outcome; handlers SHOULD check this before
    /// taking high-stakes actions if their consumer policy is
    /// permissive.
    pub verify_outcome: VerifyOutcome,
    /// When edge received the envelope (post-verify, pre-dispatch).
    pub received_at: DateTime<Utc>,
}

/// Errors a handler may return. Edge maps these to typed wire reject
/// codes returned to the sender (no silent drops — `MISSION.md` §3
/// anti-pattern 6, `THREAT_MODEL.md` AV-22 review discipline).
#[derive(thiserror::Error, Debug)]
pub enum HandlerError {
    /// Body deserialized but failed message-type-specific schema
    /// constraints; wire reject `schema_invalid`.
    #[error("schema invalid: {0}")]
    SchemaInvalid(String),
    /// Application-layer policy rejected the request; wire reject
    /// `application_rejected`.
    #[error("application rejected: {0}")]
    ApplicationRejected(String),
    /// Persist-layer error during handler execution; wire reject
    /// `persist_unavailable`.
    #[error("persist error: {0}")]
    Persist(String),
    /// Caught panic — verify pipeline re-raises as
    /// `handler_panicked` (TM §8 fail-secure table).
    #[error("handler panicked: {0}")]
    Panicked(String),
}

/// Trait that hosts implement for each `Message` they want to receive.
#[async_trait::async_trait]
pub trait Handler<M: Message>: Send + Sync + 'static {
    async fn handle(&self, msg: M, ctx: HandlerContext) -> Result<M::Response, HandlerError>;
}

/// Returned by `Edge::send_durable`. Caller polls the handle to
/// observe the outcome of an enqueued durable message. Backed by
/// `Engine.outbound_status(queue_id)` (FSD/EDGE_OUTBOUND_QUEUE.md §4).
#[derive(Debug, Clone)]
pub struct DurableHandle {
    /// `cirislens.edge_outbound_queue.queue_id` — primary key in the
    /// substrate. Persist's `QueueId = String` (UUID-shaped); stored
    /// as String to avoid a redundant UUID-string round-trip.
    pub queue_id: String,
}

/// Terminal outcome of a durable send.
#[derive(Debug)]
pub enum DurableOutcome {
    Delivered {
        /// Receiver's signed ACK envelope, if `requires_ack=true` was
        /// declared on the message type. `None` for fire-and-forget
        /// durable types (e.g. `AttestationGossip`).
        ack: Option<crate::EdgeEnvelope>,
        delivered_at: DateTime<Utc>,
    },
    Abandoned {
        reason: AbandonReason,
        abandoned_at: DateTime<Utc>,
        last_error_class: Option<String>,
    },
}

/// Snapshot of an in-flight durable send.
#[derive(Debug)]
pub enum DurableStatus {
    Pending {
        attempt_count: u32,
        next_attempt_after: DateTime<Utc>,
    },
    Sending,
    AwaitingAck {
        transport_delivered_at: DateTime<Utc>,
    },
    Terminal(DurableOutcome),
}

/// Reasons a durable send may abandon — mirror of persist's
/// `abandoned_reason` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbandonReason {
    MaxAttempts,
    TtlExpired,
    OperatorCancel,
}
