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
#[derive(Debug)]
pub struct DurableHandle {
    /// `cirislens.edge_outbound_queue.queue_id` — primary key in the
    /// substrate.
    pub queue_id: uuid::Uuid,
    // Owns no engine reference here; lookups go through Edge.
}

impl DurableHandle {
    /// Block until the row reaches a terminal state (delivered or
    /// abandoned) and return the outcome. Implementation pending.
    pub async fn await_outcome(&self) -> Result<DurableOutcome, crate::EdgeError> {
        todo!("poll Engine.outbound_status; reuse a watch channel if available")
    }

    /// Non-blocking peek at current outbound state.
    pub async fn status(&self) -> Result<DurableStatus, crate::EdgeError> {
        todo!("Engine.outbound_status snapshot")
    }
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
