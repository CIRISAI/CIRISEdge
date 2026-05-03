//! Transport abstraction.
//!
//! Mission: carry signed bytes between sovereign peers across the
//! network media that exist in the world. M-1 says "diverse sentient
//! beings may pursue their own flourishing" — diverse includes
//! off-grid, low-bandwidth, unreliable-uplink, adversary-controlled.
//!
//! Reticulum-native by default (canonical wire); HTTP/HTTPS fallback
//! for cloud deployments where Reticulum can't run. Same `Transport`
//! trait shape covers Beechat's reticulum-rs, Lew_Palm's Leviculum
//! (OQ-07 closure: optionality is mission-aligned per PoB §3.2),
//! plus Phase 3 LoRa / serial / I²P transports.
//!
//! See [`MISSION.md`](../../MISSION.md) §2 (`transport/`).

use chrono::{DateTime, Utc};

#[cfg(feature = "transport-http")]
pub mod http;

// Implementations land in subsequent commits; trait shape sealed Phase 1.
//
// pub mod reticulum;  // OQ-07 first impl
// pub mod leviculum;  // OQ-07 second impl, gated on AV-25 byte-equivalence
// pub mod lora;       // Phase 3
// pub mod serial;     // Phase 3
// pub mod i2p;        // Phase 3

/// Identifier for a transport instance. Used in metrics tags and
/// structured logs ("which transport carried this message").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransportId(pub &'static str);

impl TransportId {
    pub const HTTP: Self = Self("http");
    pub const RETICULUM_RS: Self = Self("reticulum-rs");
    pub const LEVICULUM: Self = Self("leviculum");
    pub const LORA: Self = Self("lora");
    pub const SERIAL: Self = Self("serial");
    pub const I2P: Self = Self("i2p");
}

/// Outcome of a transport-level send. Sender-visible; the dispatch
/// loop maps this to outbound-queue state transitions
/// (FSD/EDGE_OUTBOUND_QUEUE.md §4).
#[derive(Debug)]
pub enum TransportSendOutcome {
    /// Transport accepted the bytes. For `Delivery::Durable` with
    /// `!requires_ack`, this is terminal. For `requires_ack=true`,
    /// the row transitions to `awaiting_ack`.
    Delivered,
    /// Receiver returned a typed wire reject. The dispatch loop
    /// inspects `class` to decide retry vs delivered (e.g.
    /// `replay_detected` → mark_replay_resolved → delivered, per
    /// OQ-09 closure).
    Reject { class: String, detail: String },
}

/// Errors a transport may surface. Edge maps these to typed wire
/// reject codes for `Edge::send`; `Edge::send_durable` translates them
/// to `mark_transport_failed` calls.
#[derive(thiserror::Error, Debug)]
pub enum TransportError {
    #[error("destination unreachable: {0}")]
    Unreachable(String),
    #[error("transport timeout after {0:?}")]
    Timeout(std::time::Duration),
    #[error("transport configuration error: {0}")]
    Config(String),
    #[error("transport-level i/o error: {0}")]
    Io(String),
    #[error("envelope too large: {actual} bytes > {limit}")]
    BodyTooLarge { actual: usize, limit: usize },
}

/// One inbound frame from a transport — raw envelope bytes plus the
/// transport-level metadata that survives across the verify pipeline.
#[derive(Debug)]
pub struct InboundFrame {
    pub envelope_bytes: Vec<u8>,
    pub transport: TransportId,
    pub received_at: DateTime<Utc>,
}

/// The trait every transport implements. Edge holds a
/// `Vec<Box<dyn Transport>>`; multiple transports active simultaneously
/// is the multi-medium reach M-1 demands.
#[async_trait::async_trait]
pub trait Transport: Send + Sync + 'static {
    /// Stable identifier for metrics + logs.
    fn id(&self) -> TransportId;

    /// Send the byte-exact signed envelope to the peer addressed by
    /// `destination_key_id`. The transport resolves the address from
    /// the key (Reticulum: `dest = sha256(pubkey)[..16]`; HTTP:
    /// configured per-peer base URL; LoRa: configured radio addr).
    async fn send(
        &self,
        destination_key_id: &str,
        envelope_bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError>;

    /// Listen for inbound frames; deliver them to `sink`. Returns when
    /// the listener task exits (graceful shutdown or fatal error).
    async fn listen(
        &self,
        sink: tokio::sync::mpsc::Sender<InboundFrame>,
    ) -> Result<(), TransportError>;
}
