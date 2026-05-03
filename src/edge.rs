//! Edge — top-level construct.
//!
//! Holds the persist directory + outbound queue handles, the
//! steward signer, the registered transports, the verify pipeline,
//! the typed handler dispatch table, and the durable-outbound
//! dispatcher. Single shape across every CIRIS peer (lens, agent,
//! registry); peers compose around edge, not into it
//! (`MISSION.md` §3 anti-pattern 6).

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use futures::future::BoxFuture;
use tokio::sync::{mpsc, watch, Mutex};

use crate::handler::{
    AbandonReason, Delivery, DurableHandle, DurableOutcome, DurableStatus, Handler, HandlerContext,
    HandlerError, Message,
};
use crate::identity::{build_envelope, envelope_body_sha256, sign_envelope, StewardSigner};
use crate::messages::{EdgeEnvelope, MessageType};
use crate::outbound::{run_dispatcher, run_sweeps, DispatcherConfig, OutboundHandle};
use crate::transport::{InboundFrame, Transport, TransportSendOutcome};
use crate::verify::{HybridPolicy, VerifiedEnvelope, VerifyDirectory, VerifyError, VerifyPipeline};

// ─── Public configuration ───────────────────────────────────────────

/// Top-level configuration. Defaults match the v0.1.0 P0 invariants
/// (`docs/THREAT_MODEL.md` §10).
#[derive(Debug, Clone)]
pub struct EdgeConfig {
    /// Consumer-side hybrid PQC acceptance policy (OQ-11).
    pub hybrid_policy: HybridPolicy,
    /// Replay-window width (AV-3, OQ-08). Default 5 minutes.
    pub replay_window_seconds: u64,
    /// Replay-window capacity (AV-12). Default 100k.
    pub max_replay_entries: usize,
    /// Max envelope body size at the verify pipeline; AV-13 P0.
    pub max_body_bytes: usize,
    /// Outbound dispatcher tunables.
    pub dispatcher: DispatcherConfig,
}

impl Default for EdgeConfig {
    fn default() -> Self {
        Self {
            hybrid_policy: HybridPolicy::Strict,
            replay_window_seconds: 300,
            max_replay_entries: 100_000,
            max_body_bytes: 8 * 1024 * 1024,
            dispatcher: DispatcherConfig::default(),
        }
    }
}

/// Top-level error type.
#[derive(thiserror::Error, Debug)]
pub enum EdgeError {
    #[error("verify error: {0}")]
    Verify(#[from] VerifyError),
    #[error("transport error: {0}")]
    Transport(#[from] crate::TransportError),
    #[error("destination unreachable: {0}")]
    Unreachable(String),
    #[error("persist error: {0}")]
    Persist(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("handler error: {0}")]
    Handler(#[from] HandlerError),
    #[error("no handler registered for message type: {0:?}")]
    NoHandler(MessageType),
    #[error("delivery class mismatch: {0:?} declared {1} but called as {2}")]
    DeliveryClassMismatch(MessageType, &'static str, &'static str),
}

// ─── Type-erased handler dispatch ───────────────────────────────────
//
// `Handler<M>` is generic over the typed message; the registry stores
// erased closures that take a verified envelope and produce response
// bytes. Each `register_handler<M, H>` call captures the typed
// handler in a closure that does parse → dispatch → serialize.

type ErasedHandlerFn = Arc<
    dyn for<'a> Fn(&'a EdgeEnvelope, HandlerContext) -> BoxFuture<'a, Result<Vec<u8>, HandlerError>>
        + Send
        + Sync,
>;

struct RegisteredHandler {
    erased: ErasedHandlerFn,
}

// ─── Edge ───────────────────────────────────────────────────────────

/// Top-level edge handle. Construct via [`Edge::builder`].
pub struct Edge {
    verify: Arc<VerifyPipeline>,
    queue: Arc<dyn OutboundHandle>,
    signer: Arc<StewardSigner>,
    transports: Vec<Arc<dyn Transport>>,
    handlers: Arc<Mutex<HashMap<MessageType, RegisteredHandler>>>,
    config: EdgeConfig,
}

/// Builder for [`Edge`]. See FSD §3.2 for the call shape.
pub struct EdgeBuilder {
    directory: Option<Arc<dyn VerifyDirectory>>,
    queue: Option<Arc<dyn OutboundHandle>>,
    signer: Option<Arc<StewardSigner>>,
    transports: Vec<Arc<dyn Transport>>,
    config: EdgeConfig,
}

impl Edge {
    #[must_use]
    pub fn builder() -> EdgeBuilder {
        EdgeBuilder {
            directory: None,
            queue: None,
            signer: None,
            transports: Vec::new(),
            config: EdgeConfig::default(),
        }
    }

    /// Register a typed handler for message type `M`. Compile-time
    /// guarantee: the handler signature matches `M::Response`. Runtime
    /// guarantee: dispatch only fires post-verify (AV-9 invariant).
    pub async fn register_handler<M, H>(&self, handler: H) -> Result<(), EdgeError>
    where
        M: Message,
        H: Handler<M>,
    {
        let handler = Arc::new(handler);
        let erased: ErasedHandlerFn = Arc::new(move |env: &EdgeEnvelope, ctx: HandlerContext| {
            let handler = handler.clone();
            let body_str = env.body.get().to_string();
            Box::pin(async move {
                let parsed: M = serde_json::from_str(&body_str)
                    .map_err(|e| HandlerError::SchemaInvalid(format!("body parse: {e}")))?;
                let response = handler.handle(parsed, ctx).await?;
                serde_json::to_vec(&response)
                    .map_err(|e| HandlerError::SchemaInvalid(format!("response serialize: {e}")))
            })
        });

        let mut handlers = self.handlers.lock().await;
        handlers.insert(M::TYPE, RegisteredHandler { erased });
        Ok(())
    }

    /// Send an ephemeral message. Caller-owned retry — failure is
    /// visible (OQ-09 closure). Compile-time: `M::DELIVERY` must be
    /// `Ephemeral`; runtime check rejects `Durable` mis-use.
    pub async fn send<M: Message>(
        &self,
        destination_key_id: &str,
        msg: M,
    ) -> Result<M::Response, EdgeError> {
        if !matches!(M::DELIVERY, Delivery::Ephemeral) {
            return Err(EdgeError::DeliveryClassMismatch(
                M::TYPE,
                "Durable",
                "Ephemeral",
            ));
        }

        let envelope_bytes = self
            .build_signed_envelope(destination_key_id, &msg, None)
            .await?;

        if self.transports.is_empty() {
            return Err(EdgeError::Config("no transport configured".into()));
        }
        let transport = &self.transports[0];

        let outcome = transport
            .send(destination_key_id, &envelope_bytes)
            .await
            .map_err(EdgeError::Transport)?;

        match outcome {
            TransportSendOutcome::Delivered => {
                // Phase 1 simplification: ephemeral request-response is
                // not yet wired through a correlation channel. Lens
                // cutover doesn't need request-response on the outbound
                // side; the inbound side does (handlers return typed
                // responses, edge serializes back). Returning a default
                // response here is incorrect for real ephemeral
                // request-response — TODO Phase 2: wire correlation
                // via in_reply_to + body_sha256 + a oneshot map.
                Err(EdgeError::Config(
                    "ephemeral request-response correlation not wired (Phase 2)".into(),
                ))
            }
            TransportSendOutcome::Reject { class, detail } => {
                Err(EdgeError::Unreachable(format!("reject {class}: {detail}")))
            }
        }
    }

    /// Send a durable message. Edge-owned retry; the returned handle
    /// observes the eventual outcome (OQ-09 closure).
    pub async fn send_durable<M: Message>(
        &self,
        destination_key_id: &str,
        msg: M,
    ) -> Result<DurableHandle, EdgeError> {
        let (requires_ack, max_attempts, ttl_seconds, ack_timeout_seconds) = match M::DELIVERY {
            Delivery::Ephemeral => {
                return Err(EdgeError::DeliveryClassMismatch(
                    M::TYPE,
                    "Ephemeral",
                    "Durable",
                ));
            }
            Delivery::Durable {
                requires_ack,
                max_attempts,
                ttl_seconds,
                ack_timeout_seconds,
            } => (
                requires_ack,
                i32::try_from(max_attempts).unwrap_or(i32::MAX),
                i64::try_from(ttl_seconds).unwrap_or(i64::MAX),
                ack_timeout_seconds.map(|s| i64::try_from(s).unwrap_or(i64::MAX)),
            ),
        };

        let envelope_bytes = self
            .build_signed_envelope(destination_key_id, &msg, None)
            .await?;
        let envelope: EdgeEnvelope = serde_json::from_slice(&envelope_bytes)
            .map_err(|e| EdgeError::Config(format!("re-parse own envelope: {e}")))?;
        let body_sha256 = envelope_body_sha256(&envelope);
        let body_size_bytes = i32::try_from(envelope_bytes.len()).unwrap_or(i32::MAX);

        let queue_id = self
            .queue
            .enqueue_outbound(
                &self.signer.key_id,
                destination_key_id,
                &message_type_str(&envelope.message_type),
                "1.0.0",
                &envelope_bytes,
                &body_sha256,
                body_size_bytes,
                requires_ack,
                ack_timeout_seconds,
                max_attempts,
                ttl_seconds,
                Utc::now(),
            )
            .await
            .map_err(|e| EdgeError::Persist(format!("enqueue_outbound: {e}")))?;

        Ok(DurableHandle { queue_id })
    }

    /// Run the listeners + dispatch loops + outbound dispatcher.
    /// Returns when the shutdown signal fires.
    pub async fn run(self, shutdown_rx: watch::Receiver<bool>) -> Result<(), EdgeError> {
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<InboundFrame>(1024);

        // Spawn one listener per transport.
        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        for transport in &self.transports {
            let t = transport.clone();
            let tx = inbound_tx.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) = t.listen(tx).await {
                    tracing::error!(transport = ?t.id(), error = %e, "transport listen exited");
                }
            }));
        }
        // Drop our copy of the sender; only the listeners hold it.
        drop(inbound_tx);

        // Spawn outbound dispatcher + sweeps.
        {
            let q = self.queue.clone();
            let ts = self.transports.clone();
            let cfg = self.config.dispatcher.clone();
            let sd = shutdown_rx.clone();
            tasks.push(tokio::spawn(async move {
                run_dispatcher(q, ts, cfg, sd).await;
            }));
        }
        {
            let q = self.queue.clone();
            let sd = shutdown_rx.clone();
            tasks.push(tokio::spawn(async move {
                run_sweeps(q, sd).await;
            }));
        }

        // Inbound dispatch loop — verify + handler dispatch +
        // ACK matching.
        let verify = self.verify.clone();
        let handlers = self.handlers.clone();
        let queue = self.queue.clone();
        let mut shutdown = shutdown_rx;
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!("edge: shutdown signal received");
                    break;
                }
                Some(frame) = inbound_rx.recv() => {
                    let v = verify.clone();
                    let h = handlers.clone();
                    let q = queue.clone();
                    tokio::spawn(async move {
                        dispatch_inbound(frame, &v, &h, &q).await;
                    });
                }
                else => break,
            }
        }

        for t in tasks {
            let _ = t.await;
        }
        Ok(())
    }

    /// Build + sign an envelope around a typed message. Internal
    /// helper used by both [`Self::send`] and [`Self::send_durable`].
    async fn build_signed_envelope<M: Message>(
        &self,
        destination_key_id: &str,
        msg: &M,
        in_reply_to: Option<[u8; 32]>,
    ) -> Result<Vec<u8>, EdgeError> {
        let mut envelope = build_envelope(
            M::TYPE,
            &self.signer.key_id,
            destination_key_id,
            msg,
            in_reply_to,
        )?;
        sign_envelope(&self.signer, &mut envelope).await?;
        let bytes = serde_json::to_vec(&envelope)
            .map_err(|e| EdgeError::Config(format!("envelope serialize: {e}")))?;
        if bytes.len() > self.config.max_body_bytes {
            return Err(EdgeError::Config(format!(
                "envelope {} bytes exceeds max_body_bytes {}",
                bytes.len(),
                self.config.max_body_bytes
            )));
        }
        Ok(bytes)
    }
}

/// Inbound dispatch: verify → maybe-ACK-match → handler dispatch.
async fn dispatch_inbound(
    frame: InboundFrame,
    verify: &VerifyPipeline,
    handlers: &Mutex<HashMap<MessageType, RegisteredHandler>>,
    queue: &Arc<dyn OutboundHandle>,
) {
    let received_at = frame.received_at;
    let transport = frame.transport;
    let verified = match verify.verify(&frame.envelope_bytes, transport).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(transport = ?transport, error = %e, "verify rejected");
            return;
        }
    };

    let VerifiedEnvelope {
        envelope,
        body_sha256,
        verify_outcome,
        ..
    } = verified;

    // ACK matching — if envelope.in_reply_to is set, this is a
    // response to one of our outbound durable rows. Look up + mark
    // ack_received before dispatching to the application handler.
    if let Some(in_reply_to) = envelope.in_reply_to {
        match queue.match_ack_to_outbound(&in_reply_to).await {
            Ok(Some(row)) => {
                if let Err(e) = queue
                    .mark_ack_received(&row.queue_id, &frame.envelope_bytes)
                    .await
                {
                    tracing::error!(error = %e, "mark_ack_received failed");
                }
                // Don't dispatch to a handler — ACK envelopes are
                // bookkeeping, not application-level events.
                return;
            }
            Ok(None) => {
                tracing::debug!(
                    in_reply_to = ?in_reply_to,
                    "in_reply_to set but no matching outbound row; dropping",
                );
                return;
            }
            Err(e) => {
                tracing::error!(error = %e, "match_ack_to_outbound failed");
                return;
            }
        }
    }

    // Application handler dispatch.
    let registered = {
        let handlers = handlers.lock().await;
        handlers
            .get(&envelope.message_type)
            .map(|h| h.erased.clone())
    };
    let Some(erased) = registered else {
        tracing::warn!(
            message_type = ?envelope.message_type,
            "no handler registered; dropping",
        );
        return;
    };

    let ctx = HandlerContext {
        signing_key_id: envelope.signing_key_id.clone(),
        body_sha256,
        transport,
        verify_outcome,
        received_at,
    };

    match (erased)(&envelope, ctx).await {
        Ok(_response_bytes) => {
            // Phase 1: response bytes are computed but not wired back
            // through the transport's response channel. Lens cutover
            // doesn't need outbound responses (lens always receives,
            // never replies). When Phase 2 wires register_handler
            // responses through the transport, this is where the
            // response envelope assembles + signs + ships back.
        }
        Err(e) => {
            tracing::error!(
                message_type = ?envelope.message_type,
                error = %e,
                "handler error",
            );
        }
    }
}

// ─── Builder ────────────────────────────────────────────────────────

impl EdgeBuilder {
    #[must_use]
    pub fn directory(mut self, directory: Arc<dyn VerifyDirectory>) -> Self {
        self.directory = Some(directory);
        self
    }

    #[must_use]
    pub fn queue(mut self, queue: Arc<dyn OutboundHandle>) -> Self {
        self.queue = Some(queue);
        self
    }

    #[must_use]
    pub fn signer(mut self, signer: Arc<StewardSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    #[must_use]
    pub fn transport(mut self, transport: Arc<dyn Transport>) -> Self {
        self.transports.push(transport);
        self
    }

    #[must_use]
    pub fn config(mut self, config: EdgeConfig) -> Self {
        self.config = config;
        self
    }

    pub fn build(self) -> Result<Edge, EdgeError> {
        let directory = self
            .directory
            .ok_or_else(|| EdgeError::Config("directory not set".into()))?;
        let queue = self
            .queue
            .ok_or_else(|| EdgeError::Config("outbound queue not set".into()))?;
        let signer = self
            .signer
            .ok_or_else(|| EdgeError::Config("steward signer not set".into()))?;
        if self.transports.is_empty() {
            return Err(EdgeError::Config("no transport configured".into()));
        }

        let verify = Arc::new(VerifyPipeline::new(
            directory,
            self.config.hybrid_policy,
            signer.key_id.clone(),
            self.config.max_body_bytes,
            self.config.replay_window_seconds,
            self.config.max_replay_entries,
        ));

        Ok(Edge {
            verify,
            queue,
            signer,
            transports: self.transports,
            handlers: Arc::new(Mutex::new(HashMap::new())),
            config: self.config,
        })
    }
}

// ─── DurableHandle helpers ──────────────────────────────────────────

impl DurableHandle {
    /// Snapshot via persist's `outbound_status`. Implementation lands
    /// here so DurableHandle stays a thin wire-format type without an
    /// engine reference.
    pub async fn status_via(&self, queue: &dyn OutboundHandle) -> Result<DurableStatus, EdgeError> {
        let row = queue
            .outbound_status(&self.queue_id)
            .await
            .map_err(|e| EdgeError::Persist(format!("outbound_status: {e}")))?;
        match row {
            Some(r) => Ok(map_row_to_status(&r)),
            None => Err(EdgeError::Persist(format!(
                "outbound row {} not found",
                self.queue_id
            ))),
        }
    }
}

fn map_row_to_status(row: &ciris_persist::prelude::OutboundRow) -> DurableStatus {
    use ciris_persist::prelude::OutboundStatus as P;
    let attempt_count = u32::try_from(row.attempt_count).unwrap_or(0);
    match row.status {
        P::Pending => DurableStatus::Pending {
            attempt_count,
            next_attempt_after: row.next_attempt_after,
        },
        P::Sending => DurableStatus::Sending,
        P::AwaitingAck => DurableStatus::AwaitingAck {
            transport_delivered_at: row.transport_delivered_at.unwrap_or_else(Utc::now),
        },
        P::Delivered => DurableStatus::Terminal(DurableOutcome::Delivered {
            ack: None,
            delivered_at: row.delivered_at.unwrap_or_else(Utc::now),
        }),
        P::Abandoned => {
            let reason = match row.abandoned_reason {
                Some(ciris_persist::prelude::AbandonedReason::MaxAttempts) => {
                    AbandonReason::MaxAttempts
                }
                Some(ciris_persist::prelude::AbandonedReason::TtlExpired) => {
                    AbandonReason::TtlExpired
                }
                Some(ciris_persist::prelude::AbandonedReason::OperatorCancel) => {
                    AbandonReason::OperatorCancel
                }
                None => AbandonReason::MaxAttempts,
            };
            DurableStatus::Terminal(DurableOutcome::Abandoned {
                reason,
                abandoned_at: row.abandoned_at.unwrap_or_else(Utc::now),
                last_error_class: row.last_error_class.clone(),
            })
        }
    }
}

fn message_type_str(mt: &MessageType) -> String {
    serde_json::to_value(mt)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{mt:?}"))
}
