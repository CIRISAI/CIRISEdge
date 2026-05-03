//! Edge — top-level construct.
//!
//! Holds the persist engine handle, the registered transports, the
//! verify pipeline, the typed handler dispatch table, and the durable-
//! outbound dispatcher. Single shape across every CIRIS peer (lens,
//! agent, registry); peers compose around edge, not into it
//! (`MISSION.md` §3 anti-pattern 6).

use crate::handler::{DurableHandle, Handler, Message};
use crate::transport::Transport;
use crate::verify::HybridPolicy;

/// Top-level edge handle. Construct via [`Edge::builder`].
pub struct Edge {
    // engine: ciris_persist::Engine,
    // transports: Vec<Box<dyn Transport>>,
    // handlers: HandlerRegistry,
    // verify: VerifyPipeline,
    // outbound_dispatcher: Option<OutboundDispatcher>,
    // config: EdgeConfig,
}

/// Builder for [`Edge`]. See the FSD §3.2 example for the call shape.
#[allow(dead_code)]
pub struct EdgeBuilder {
    // engine: Option<ciris_persist::Engine>,
    transports: Vec<Box<dyn Transport>>,
    config: EdgeConfig,
}

/// Top-level configuration. Defaults match the v0.1.0 P0 invariants
/// (`docs/THREAT_MODEL.md` §10).
#[derive(Debug, Clone)]
pub struct EdgeConfig {
    /// Consumer-side hybrid PQC acceptance policy (OQ-11).
    pub hybrid_policy: HybridPolicy,
    /// Replay-window width for `(signing_key_id, nonce)` LRU (AV-3,
    /// OQ-08). Default 5 minutes.
    pub replay_window_seconds: u64,
    /// Maximum envelope body size; AV-13 P0 invariant.
    pub max_body_bytes: usize,
    /// Maximum nested-data depth at envelope deserialize; AV-14 P0
    /// invariant. Mirrors persist's `MAX_DATA_DEPTH=32`.
    pub max_data_depth: u32,
    /// Self steward key_id — used for the AV-8 `destination_key_id`
    /// check. Read from `Engine.steward_key_id()` at builder time.
    pub self_steward_key_id: String,
}

impl Default for EdgeConfig {
    fn default() -> Self {
        Self {
            hybrid_policy: HybridPolicy::Strict,
            replay_window_seconds: 300,
            max_body_bytes: 8 * 1024 * 1024,
            max_data_depth: 32,
            self_steward_key_id: String::new(),
        }
    }
}

/// Top-level error type. Wraps verify, transport, persist, and config
/// errors with consistent `From` impls.
#[derive(thiserror::Error, Debug)]
pub enum EdgeError {
    #[error("verify error: {0}")]
    Verify(#[from] crate::VerifyError),
    #[error("transport error: {0}")]
    Transport(#[from] crate::TransportError),
    #[error("destination unreachable: {0}")]
    Unreachable(String),
    #[error("persist error: {0}")]
    Persist(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("handler not registered for message type: {0:?}")]
    NoHandler(crate::MessageType),
    #[error("schema-version mismatch on registered handler: {0}")]
    HandlerSchemaMismatch(String),
}

impl Edge {
    /// Start building an edge instance.
    #[must_use]
    pub fn builder() -> EdgeBuilder {
        EdgeBuilder {
            transports: Vec::new(),
            config: EdgeConfig::default(),
        }
    }

    /// Register a typed handler for message type `M`. Compile-time
    /// guarantee: `M::DELIVERY` is consistent with the dispatch path
    /// (ephemeral handlers don't get a durable queue; durable
    /// handlers don't get the request-response shortcut).
    pub fn register_handler<M, H>(&mut self, _handler: H) -> Result<(), EdgeError>
    where
        M: Message,
        H: Handler<M>,
    {
        todo!("HandlerRegistry insert keyed on M::TYPE; reject duplicate registrations")
    }

    /// Send an ephemeral message. Caller-owned retry — failure is
    /// visible as `EdgeError::Unreachable` (OQ-09 closure).
    /// Compile-time enforcement of `M::DELIVERY = Ephemeral` lands
    /// once the const-eval guard is stable; for now the runtime check
    /// rejects misuse.
    pub async fn send<M: Message>(
        &self,
        _destination_key_id: &str,
        _msg: M,
    ) -> Result<M::Response, EdgeError> {
        todo!("ephemeral path: sign → transport.send → await typed response")
    }

    /// Send a durable message. Edge-owned retry; the returned handle
    /// observes the eventual outcome (OQ-09 closure;
    /// FSD/EDGE_OUTBOUND_QUEUE.md §4).
    pub async fn send_durable<M: Message>(
        &self,
        _destination_key_id: &str,
        _msg: M,
    ) -> Result<DurableHandle, EdgeError> {
        todo!(
            "durable path: sign → Engine.enqueue_outbound → return DurableHandle; \
             dispatch loop runs separately and processes the queue"
        )
    }

    /// Run the listeners + dispatch loops + outbound dispatcher.
    /// Returns when graceful shutdown completes.
    pub async fn run(self) -> Result<(), EdgeError> {
        todo!(
            "spawn one tokio task per transport listener; \
             spawn outbound dispatcher (claim_pending_outbound loop); \
             spawn ack-timeout sweep + ttl sweep + claim-expiry sweep; \
             join all on shutdown signal"
        )
    }
}

impl EdgeBuilder {
    /// Add a transport instance. Multiple transports can be active
    /// simultaneously (multi-medium reach per M-1).
    #[must_use]
    pub fn transport(mut self, transport: Box<dyn Transport>) -> Self {
        self.transports.push(transport);
        self
    }

    /// Configure verify, replay-window, body-size, etc.
    #[must_use]
    pub fn config(mut self, config: EdgeConfig) -> Self {
        self.config = config;
        self
    }

    /// Build the edge instance. Validates config, queries persist for
    /// the steward key_id, primes the verify pipeline.
    pub fn build(self) -> Result<Edge, EdgeError> {
        todo!(
            "validate transports.len() > 0; query Engine.steward_key_id; \
             construct VerifyPipeline; construct OutboundDispatcher if any \
             registered handler declares Delivery::Durable"
        )
    }
}
