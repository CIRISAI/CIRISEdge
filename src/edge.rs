//! Edge — top-level construct.
//!
//! Holds the persist directory + outbound queue handles, the
//! local signer, the registered transports, the verify pipeline,
//! the typed handler dispatch table, and the durable-outbound
//! dispatcher. Single shape across every CIRIS peer (lens, agent,
//! registry); peers compose around edge, not into it
//! (`MISSION.md` §3 anti-pattern 6).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine as _;
use chrono::Utc;
use futures::future::BoxFuture;
use tokio::sync::{mpsc, watch, Mutex};

use crate::handler::{
    AbandonReason, Delivery, DurableHandle, DurableOutcome, DurableStatus, Handler, HandlerContext,
    HandlerError, InlineTextMessage, Message,
};
use crate::identity::{build_envelope, envelope_body_sha256, sign_envelope, LocalSigner};
use crate::messages::{EdgeEnvelope, MessageType};
use crate::outbound::{
    run_dispatcher, run_sweeps, DispatcherConfig, OutboundHandle, PeerDirectory,
    PeerSubscriptionFilter,
};
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
    signer: Arc<LocalSigner>,
    transports: Vec<Arc<dyn Transport>>,
    handlers: Arc<Mutex<HashMap<MessageType, RegisteredHandler>>>,
    /// Optional pipeline run on outbound inline-text envelopes
    /// (SPEAK responses, LLM prompts, WBD bodies, DSAR text). When
    /// `Some`, `send_inline` / `send_durable_inline` invoke this
    /// before signing — classify, scrub, encrypt-and-store secret
    /// spans per FSD §1.4. When `None`, those methods skip the
    /// pipeline and behave identically to `send` / `send_durable`.
    /// Construct via `default_speak_pipeline(secrets, actor_id)` in
    /// `ciris_persist::pipeline`. Closes CIRISAgent#756 Q1.
    speak_pipeline:
        Option<Arc<ciris_persist::pipeline::Pipeline<ciris_persist::prelude::InlineTextEnvelope>>>,
    /// Optional peer-enumeration adapter consumed by
    /// [`Edge::send_mandatory`] to fan out a `Delivery::Mandatory`
    /// envelope to every peer in the directory (CIRISEdge#18 / FSD
    /// §3.2). When `None`, `send_mandatory` returns a typed config
    /// error — the federation broadcast cannot pick recipients.
    peer_directory: Option<Arc<dyn PeerDirectory>>,
    /// Optional per-peer subscription filter. Consulted by
    /// subscription-respecting code paths; **deliberately bypassed**
    /// by `Delivery::Mandatory` (the load-bearing wire change of
    /// CIRISEdge#18; the bypass is exercised in
    /// `tests/federation_announcement_mandatory.rs`).
    subscription_filter: Option<Arc<dyn PeerSubscriptionFilter>>,
    config: EdgeConfig,
}

/// Builder for [`Edge`]. See FSD §3.2 for the call shape.
pub struct EdgeBuilder {
    directory: Option<Arc<dyn VerifyDirectory>>,
    queue: Option<Arc<dyn OutboundHandle>>,
    signer: Option<Arc<LocalSigner>>,
    transports: Vec<Arc<dyn Transport>>,
    speak_pipeline:
        Option<Arc<ciris_persist::pipeline::Pipeline<ciris_persist::prelude::InlineTextEnvelope>>>,
    peer_directory: Option<Arc<dyn PeerDirectory>>,
    subscription_filter: Option<Arc<dyn PeerSubscriptionFilter>>,
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
            speak_pipeline: None,
            peer_directory: None,
            subscription_filter: None,
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
            let declared = match M::DELIVERY {
                Delivery::Ephemeral => "Ephemeral",
                Delivery::Durable { .. } => "Durable",
                Delivery::Mandatory { .. } => "Mandatory",
            };
            return Err(EdgeError::DeliveryClassMismatch(
                M::TYPE,
                declared,
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
            Delivery::Mandatory { .. } => {
                return Err(EdgeError::DeliveryClassMismatch(
                    M::TYPE,
                    "Mandatory",
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

    /// Send an inline-text message — runs the configured
    /// `speak_pipeline` on the text body (classify + scrub +
    /// encrypt-and-store) before signing + shipping. When no
    /// pipeline is configured, behaves identically to
    /// [`Self::send`]. Cleartext secrets are substituted with
    /// `{SECRET:uuid:description}` placeholders before the envelope
    /// is signed, so the wire payload never carries unredacted
    /// sensitive spans. Per FSD §1.4 and CIRISAgent#756 Q1.
    pub async fn send_inline<M: InlineTextMessage>(
        &self,
        destination_key_id: &str,
        mut msg: M,
    ) -> Result<M::Response, EdgeError> {
        self.run_speak_pipeline(&mut msg).await?;
        self.send(destination_key_id, msg).await
    }

    /// Durable variant of [`Self::send_inline`] — same pipeline-then-
    /// sign path, but enqueues to `cirislens.edge_outbound_queue` for
    /// edge-owned retry. Returns a [`DurableHandle`] to observe the
    /// eventual outcome.
    pub async fn send_durable_inline<M: InlineTextMessage>(
        &self,
        destination_key_id: &str,
        mut msg: M,
    ) -> Result<DurableHandle, EdgeError> {
        self.run_speak_pipeline(&mut msg).await?;
        self.send_durable(destination_key_id, msg).await
    }

    /// Send a federation-tier authority-signed broadcast — fans the
    /// signed envelope to **every peer** in the [`PeerDirectory`]
    /// regardless of any subscription filter. Closes CIRISEdge#18
    /// + CIRISNodeCore FSD §3.2 (substrate-tier Mandatory wire class).
    ///
    /// The load-bearing semantic is in
    /// [`Delivery::Mandatory::bypass_subscription`]: even when a
    /// [`PeerSubscriptionFilter`] is configured, this path does NOT
    /// consult it. The federation's governance reach requires that
    /// every node observe an authority-signed announcement; the
    /// subscription model belongs to the application layer, not the
    /// substrate.
    ///
    /// Returns one [`DurableHandle`] per peer the announcement was
    /// enqueued to — callers may observe each independently. The
    /// local steward's own `key_id` is filtered out (a Mandatory
    /// fan-out does not loopback through edge).
    ///
    /// # Errors
    ///
    /// - [`EdgeError::DeliveryClassMismatch`] when `M::DELIVERY` is
    ///   not `Delivery::Mandatory`.
    /// - [`EdgeError::Config`] when no peer directory is configured
    ///   on the [`EdgeBuilder`] — the substrate broadcast cannot pick
    ///   recipients without it.
    /// - [`EdgeError::Persist`] on enqueue failure.
    pub async fn send_mandatory<M: Message>(
        &self,
        msg: M,
    ) -> Result<Vec<DurableHandle>, EdgeError> {
        let (max_attempts, ttl_seconds) = match M::DELIVERY {
            Delivery::Ephemeral => {
                return Err(EdgeError::DeliveryClassMismatch(
                    M::TYPE,
                    "Ephemeral",
                    "Mandatory",
                ));
            }
            Delivery::Durable { .. } => {
                return Err(EdgeError::DeliveryClassMismatch(
                    M::TYPE,
                    "Durable",
                    "Mandatory",
                ));
            }
            Delivery::Mandatory {
                authority_signed: _,
                bypass_subscription,
            } => {
                // Edge does not gate on authority_signed (NodeCore's
                // job per FSD §3.4); the flag is a wire contract
                // marker. Refuse to fan out if a Mandatory variant
                // somehow sets bypass_subscription=false — that is a
                // programmer mistake that, if accepted, would silently
                // turn a federation broadcast back into an opt-in.
                if !bypass_subscription {
                    return Err(EdgeError::Config(format!(
                        "Mandatory message_type {:?} declared bypass_subscription=false; \
                         refusing to fan out (FSD §3.2 wire contract)",
                        M::TYPE
                    )));
                }
                // FSD §3.2.1 dispatch contract on FederationAnnouncement
                // itself (the only Mandatory consumer at v0.1) — the
                // announcement is durable + fire-and-forget. The
                // per-peer DeliveryAttestation IS the audit observable;
                // no edge-level ACK is requested. v0.1 defaults: 14d
                // TTL, 100 attempts (mirrors BuildManifestPublication's
                // long-haul durability since announcements are
                // similarly durable substrate-tier records).
                (100i32, 14 * 24 * 60 * 60i64)
            }
        };

        let peer_dir = self.peer_directory.as_ref().ok_or_else(|| {
            EdgeError::Config(
                "send_mandatory: no PeerDirectory configured on EdgeBuilder \
                 (federation broadcast cannot enumerate recipients)"
                    .into(),
            )
        })?;

        let peers = peer_dir
            .list_recipients()
            .await
            .map_err(|e| EdgeError::Persist(format!("PeerDirectory::list_recipients: {e}")))?;

        let mut handles = Vec::with_capacity(peers.len());
        for peer in peers {
            // Local steward never gets its own Mandatory fan-out —
            // sender == receiver would loopback through edge's verify
            // (AV-8 self-destination is structurally a misroute) and
            // waste a queue row.
            if peer == self.signer.key_id {
                continue;
            }
            // **Bypass-subscription invariant** — DO NOT consult
            // `self.subscription_filter` here. Mandatory is the FSD
            // §3.2 wire-level expression of "federation-wide push
            // regardless of per-peer opt-in"; calling
            // `is_subscribed(peer, M::TYPE)` here would re-introduce
            // the opt-in gate this class exists to remove.
            let envelope_bytes = self.build_signed_envelope(&peer, &msg, None).await?;
            let envelope: EdgeEnvelope = serde_json::from_slice(&envelope_bytes)
                .map_err(|e| EdgeError::Config(format!("re-parse own envelope: {e}")))?;
            let body_sha256 = envelope_body_sha256(&envelope);
            let body_size_bytes = i32::try_from(envelope_bytes.len()).unwrap_or(i32::MAX);

            let queue_id = self
                .queue
                .enqueue_outbound(
                    &self.signer.key_id,
                    &peer,
                    &message_type_str(&envelope.message_type),
                    "1.0.0",
                    &envelope_bytes,
                    &body_sha256,
                    body_size_bytes,
                    false, // requires_ack: false — attestation IS observable
                    None,  // ack_timeout_seconds: None
                    max_attempts,
                    ttl_seconds,
                    Utc::now(),
                )
                .await
                .map_err(|e| EdgeError::Persist(format!("enqueue_outbound (mandatory): {e}")))?;
            handles.push(DurableHandle { queue_id });
        }
        Ok(handles)
    }

    /// Test/diagnostics helper — `true` if `peer_key_id` would be
    /// admitted by the configured [`PeerSubscriptionFilter`] for
    /// `message_type`. When no filter is configured, returns `true`
    /// (everything is "subscribed" in the default open posture).
    ///
    /// `Delivery::Mandatory` paths deliberately do NOT call this —
    /// see [`Self::send_mandatory`]. Exposed so the
    /// `tests/federation_announcement_mandatory.rs` round-trip can
    /// assert the bypass property: a peer whose filter would reject
    /// the MessageType MUST still receive the Mandatory broadcast.
    pub async fn would_subscription_accept(
        &self,
        peer_key_id: &str,
        message_type: &MessageType,
    ) -> bool {
        let Some(filter) = self.subscription_filter.as_ref() else {
            return true;
        };
        filter.is_subscribed(peer_key_id, message_type).await
    }

    /// Run the configured outbound `speak_pipeline` over the
    /// message's text body. Mutates `msg` in place via
    /// `InlineTextMessage::set_text`. No-op when no pipeline is
    /// configured. Logs sidecar via tracing.
    async fn run_speak_pipeline<M: InlineTextMessage>(&self, msg: &mut M) -> Result<(), EdgeError> {
        let Some(pipeline) = self.speak_pipeline.as_ref() else {
            return Ok(());
        };
        let mut env = ciris_persist::prelude::InlineTextEnvelope::new(msg.text().to_string());
        let mut state = ciris_persist::pipeline::PipelineState::default();
        pipeline
            .run(&mut env, &mut state)
            .await
            .map_err(|e| EdgeError::Persist(format!("speak_pipeline: {e}")))?;
        tracing::debug!(
            stages = ?state.stages_executed,
            fields_modified = state.fields_modified,
            pii_scrubbed = state.pii_scrubbed,
            "speak_pipeline ran"
        );
        msg.set_text(env.text);
        Ok(())
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
        // ACK matching + FederationAnnouncement→DeliveryAttestation
        // emission (FSD §3.2.1 v0.1 emission gate: post-verify,
        // pre-application-layer-handler).
        let verify = self.verify.clone();
        let handlers = self.handlers.clone();
        let queue = self.queue.clone();
        let signer = self.signer.clone();
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
                    let s = signer.clone();
                    tokio::spawn(async move {
                        dispatch_inbound(frame, &v, &h, &q, &s).await;
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

/// Inbound dispatch: verify → maybe-ACK-match → FederationAnnouncement
/// attestation-emission (FSD §3.2.1 v0.1 gate) → handler dispatch.
async fn dispatch_inbound(
    frame: InboundFrame,
    verify: &VerifyPipeline,
    handlers: &Mutex<HashMap<MessageType, RegisteredHandler>>,
    queue: &Arc<dyn OutboundHandle>,
    signer: &Arc<LocalSigner>,
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

    // FSD §3.2.1 v0.1 emission gate — post-verify-pipeline, the
    // announcement has cleared edge's signature + freshness + replay
    // gates. NodeCore's authority-class verifier runs at the consumer
    // handler; for v0.1 edge emits at this point (per the FSD's
    // pragmatic gate). Application-layer-acceptance tightening is a
    // v0.2+ option per FSD §7 OQ-6.
    if envelope.message_type == MessageType::FederationAnnouncement {
        if let Err(e) =
            emit_delivery_attestation(&envelope, body_sha256, transport, signer, queue).await
        {
            // The attestation is observability; a failure to emit
            // does NOT block application-layer dispatch. Log and
            // continue (FSD §3.2.1 — missing-attestation-as-
            // delivery-gap is the legitimate observable).
            tracing::warn!(
                error = %e,
                "FederationAnnouncement received but DeliveryAttestation emission failed",
            );
        }
    }

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
    /// Sovereign-mode convenience: load steward identity from
    /// filesystem seeds via `ciris-keyring`, open persist's
    /// SQLite-backed federation directory + edge outbound queue at
    /// `db_path`, and return a fully-wired builder. Caller still
    /// adds transports + (optionally) a `speak_pipeline` before
    /// `build()`. Use this in deployments that have no
    /// `ciris_persist::Engine` in-process (Reticulum-only sovereign
    /// agents, Pi/iOS hosts). Closes the sovereign half of
    /// CIRISLensCore#7 / CIRISPersist#43 / CIRISVerify#20.
    ///
    /// `key_id` is the steward identity advertised on outbound
    /// envelopes (`federation_keys.key_id`). `seed_path` points at
    /// the directory containing `ed25519.seed` (and optionally
    /// `ml_dsa_65.seed`); the constructor reads both and produces
    /// `Arc<dyn HardwareSigner>` + optional `Arc<dyn PqcSigner>` via
    /// the keyring loader.
    pub async fn from_keyring_seed_dir(
        key_id: impl Into<String>,
        seed_dir: PathBuf,
        db_path: PathBuf,
    ) -> Result<Self, EdgeError> {
        let key_id = key_id.into();
        let pqc_seed = seed_dir.join("ml_dsa_65.seed");
        let pqc_pair = pqc_seed
            .exists()
            .then(|| (Some(format!("{key_id}-pqc")), Some(pqc_seed)));
        let (pqc_key_id, pqc_key_path) = pqc_pair.unwrap_or((None, None));

        let config = ciris_keyring::LocalSeedConfig {
            key_id: key_id.clone(),
            key_path: seed_dir.join("ed25519.seed"),
            pqc_key_id,
            pqc_key_path,
        };
        let (classical, pqc) = ciris_keyring::load_local_seed(config)
            .await
            .map_err(|e| EdgeError::Config(format!("load_local_seed: {e}")))?;

        let directory = ciris_persist::prelude::FederationDirectorySqlite::open(&db_path)
            .await
            .map_err(|e| EdgeError::Persist(format!("FederationDirectorySqlite::open: {e}")))?;
        let queue = ciris_persist::prelude::EdgeOutboundQueueSqlite::open(&db_path)
            .await
            .map_err(|e| EdgeError::Persist(format!("EdgeOutboundQueueSqlite::open: {e}")))?;

        let signer = Arc::new(LocalSigner {
            key_id,
            classical,
            pqc,
        });

        Ok(Edge::builder()
            .directory(directory)
            .queue(queue)
            .signer(signer))
    }

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
    pub fn signer(mut self, signer: Arc<LocalSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    #[must_use]
    pub fn transport(mut self, transport: Arc<dyn Transport>) -> Self {
        self.transports.push(transport);
        self
    }

    /// Configure the outbound inline-text pipeline. When set, edge
    /// runs it on every `send_inline` / `send_durable_inline` call
    /// before signing + shipping. Construct via
    /// `ciris_persist::pipeline::default_speak_pipeline(secrets,
    /// actor_id)` for the canonical Classify + Scrub + EncryptAndStore
    /// stage set, or compose stages directly. Optional — when unset,
    /// `send_inline` falls through to the ephemeral `send` path
    /// without transit-touch.
    #[must_use]
    pub fn speak_pipeline(
        mut self,
        pipeline: Arc<
            ciris_persist::pipeline::Pipeline<ciris_persist::prelude::InlineTextEnvelope>,
        >,
    ) -> Self {
        self.speak_pipeline = Some(pipeline);
        self
    }

    /// Wire a [`PeerDirectory`] adapter for `Edge::send_mandatory`
    /// fan-out (CIRISEdge#18). Without it `send_mandatory` returns
    /// [`EdgeError::Config`] — the federation broadcast has no
    /// recipient enumeration.
    #[must_use]
    pub fn peer_directory(mut self, dir: Arc<dyn PeerDirectory>) -> Self {
        self.peer_directory = Some(dir);
        self
    }

    /// Wire a [`PeerSubscriptionFilter`] for subscription-respecting
    /// code paths. **Not consulted by `Delivery::Mandatory`** — the
    /// bypass-subscription wire contract (FSD §3.2 + CIRISEdge#18).
    #[must_use]
    pub fn subscription_filter(mut self, filter: Arc<dyn PeerSubscriptionFilter>) -> Self {
        self.subscription_filter = Some(filter);
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
            .ok_or_else(|| EdgeError::Config("local signer not set".into()))?;
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
            speak_pipeline: self.speak_pipeline,
            peer_directory: self.peer_directory,
            subscription_filter: self.subscription_filter,
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

/// Derive a deterministic UUID `announcement_id` from the announcement
/// envelope's `body_sha256` — the bytes the peer actually received.
///
/// Persist's `put_delivery_attestation` parses `announcement_id` as a
/// UUID (`Uuid::parse_str`), so the wire field is constrained to that
/// shape. In production NodeCore stamps the surrounding Contribution
/// envelope with its `contribution_id` and the receiver propagates
/// that; for edge's v0.1 emission gate we don't yet wrap the
/// announcement in a NodeCore Contribution at the edge layer, so the
/// pragmatic choice is to derive the id from the body bytes
/// themselves.
///
/// Properties: same envelope bytes → same `announcement_id` at every
/// peer (the persist PK `(announcement_id, peer_key_id)` correctly
/// collates attestations from many peers to one announcement). Same
/// envelope bytes at the same peer → same `(announcement_id,
/// peer_key_id)` → persist's INSERT is idempotent on replay
/// (FSD §3.2.1 "AV: replayed attestation collapsed").
///
/// The UUID layout uses the body_sha256's first 16 bytes verbatim
/// with the v4 (random) variant + version bits set — wire-format
/// valid UUID without dragging in `uuid::v5` (no extra dependency
/// surface beyond the v4 feature already enabled).
fn derive_announcement_id_from_body_hash(body_sha256: &[u8; 32]) -> String {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&body_sha256[..16]);
    // Set RFC 4122 variant bits (top of byte 8 = 10xxxxxx).
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    // Set version 4 bits (top of byte 6 = 0100xxxx). Edge's emission
    // is deterministic-from-hash but the wire constraint is "any
    // RFC 4122 UUID" — the version bits just need to be syntactically
    // valid; v4 keeps the surface compatible with persist's parse.
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    uuid::Uuid::from_bytes(bytes).to_string()
}

/// Build, sign, and enqueue a [`crate::DeliveryAttestation`] for a
/// freshly-verified [`crate::FederationAnnouncement`] envelope. The
/// attestation rides `Delivery::Durable { requires_ack: false }`
/// (FSD §3.2.1 dispatch contract) — subscription-respecting fan-out
/// (NOT Mandatory), per-peer queued for delivery to whichever
/// federation collector is downstream of the local edge.
///
/// The peer's federation Ed25519 (and optional ML-DSA-65) key signs
/// the canonical-bytes encoding from
/// [`crate::DeliveryAttestation::canonical_bytes`] — byte-equal with
/// persist v2.2.0's encoder so a federation collector can verify the
/// attestation via `verify_hybrid_via_directory` against
/// `federation_keys[peer_key_id]`.
async fn emit_delivery_attestation(
    envelope: &EdgeEnvelope,
    body_sha256: [u8; 32],
    transport: crate::transport::TransportId,
    signer: &Arc<LocalSigner>,
    queue: &Arc<dyn OutboundHandle>,
) -> Result<(), EdgeError> {
    use crate::messages::{
        encode_canonical_hash_base64, encode_signature_base64, DeliveryAttestation, TransportMedium,
    };

    let announcement_id = derive_announcement_id_from_body_hash(&body_sha256);
    let peer_pubkey_bytes = signer
        .classical
        .public_key()
        .await
        .map_err(|e| EdgeError::Persist(format!("local pubkey: {e}")))?;
    let peer_pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(&peer_pubkey_bytes);

    // Canonical hash = SHA-256 of the full envelope-as-received. The
    // FSD §3.2.1 wire field is "SHA-256 of the full canonicalized
    // Contribution envelope INCLUDING its authority signature" — at
    // the edge layer the "full envelope" IS the EdgeEnvelope JSON,
    // and `body_sha256` already covers the body (which carries the
    // FederationAnnouncement payload). For v0.1, using body_sha256
    // pins the announcement payload bytes the peer received; the
    // surrounding signature is in the EdgeEnvelope and re-verified
    // upstream against `federation_keys[envelope.signing_key_id]`.
    let canonical_hash_b64 = encode_canonical_hash_base64(&body_sha256);

    // Build the attestation with a placeholder signature first so we
    // can produce canonical bytes (the signature itself is over
    // canonical_bytes, not part of canonical_bytes).
    let received_at = chrono::Utc::now();
    let mut att = DeliveryAttestation {
        announcement_id,
        announcement_canonical_hash_base64: canonical_hash_b64,
        peer_key_id: signer.key_id.clone(),
        peer_pubkey_ed25519_base64: peer_pubkey_b64,
        received_at,
        transport_id: TransportMedium::from(transport),
        signature_classical_base64: String::new(),
        signature_pqc_base64: None,
    };

    let canonical = att
        .canonical_bytes()
        .map_err(|e| EdgeError::Config(format!("delivery_attestation canonical_bytes: {e}")))?;

    // Mandatory classical Ed25519 sign.
    let ed25519_sig = signer
        .classical
        .sign(&canonical)
        .await
        .map_err(|e| EdgeError::Persist(format!("attestation classical sign: {e}")))?;
    att.signature_classical_base64 = encode_signature_base64(&ed25519_sig);

    // Optional PQC ML-DSA-65 over `canonical || classical_sig` per
    // persist's AV-33 bound-signature convention (FSD §3.2.1).
    if let Some(pqc) = signer.pqc.as_ref() {
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed25519_sig);
        let pqc_sig = pqc
            .sign(&bound)
            .await
            .map_err(|e| EdgeError::Persist(format!("attestation pqc sign: {e}")))?;
        att.signature_pqc_base64 = Some(encode_signature_base64(&pqc_sig));
    }

    // Wrap in a typed envelope. Destination is the **original
    // announcement sender** (envelope.signing_key_id) — the federation
    // steward / collector who'll aggregate the per-peer attestations.
    // FSD §3.2 "missing-attestation-as-delivery-gap" is observable at
    // the steward end.
    let envelope_bytes = {
        let mut env = build_envelope(
            MessageType::DeliveryAttestation,
            &signer.key_id,
            &envelope.signing_key_id,
            &att,
            None,
        )?;
        sign_envelope(signer, &mut env).await?;
        serde_json::to_vec(&env)
            .map_err(|e| EdgeError::Config(format!("attestation envelope serialize: {e}")))?
    };
    let env: EdgeEnvelope = serde_json::from_slice(&envelope_bytes)
        .map_err(|e| EdgeError::Config(format!("re-parse attestation envelope: {e}")))?;
    let body_sha256_att = envelope_body_sha256(&env);
    let body_size_bytes = i32::try_from(envelope_bytes.len()).unwrap_or(i32::MAX);

    // Match DeliveryAttestation::DELIVERY exactly (FSD §3.2.1 dispatch
    // table — fire-and-forget Durable).
    let (max_attempts, ttl_seconds) = match crate::DeliveryAttestation::DELIVERY {
        Delivery::Durable {
            max_attempts,
            ttl_seconds,
            ..
        } => (
            i32::try_from(max_attempts).unwrap_or(i32::MAX),
            i64::try_from(ttl_seconds).unwrap_or(i64::MAX),
        ),
        _ => (20, 24 * 60 * 60),
    };

    queue
        .enqueue_outbound(
            &signer.key_id,
            &envelope.signing_key_id,
            &message_type_str(&MessageType::DeliveryAttestation),
            "1.0.0",
            &envelope_bytes,
            &body_sha256_att,
            body_size_bytes,
            false, // requires_ack: false (FSD §3.2.1)
            None,
            max_attempts,
            ttl_seconds,
            Utc::now(),
        )
        .await
        .map_err(|e| EdgeError::Persist(format!("enqueue_outbound (attestation): {e}")))?;

    Ok(())
}
