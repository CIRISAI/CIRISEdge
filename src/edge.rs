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
use std::sync::atomic::{AtomicU64, Ordering};
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
use crate::messages::{
    AnnouncementPriority, EdgeEnvelope, FederationAnnouncement, MessageType, RefusalReason,
    ACCORD_THRESHOLD_M_OF_N,
};
use crate::outbound::{
    run_dispatcher, run_sweeps, DispatcherConfig, OutboundHandle, PeerDirectory,
    PeerSubscriptionFilter,
};
use crate::transport::{InboundFrame, Transport, TransportSendOutcome};
use crate::verify::{
    AccordHolderKey, HybridPolicy, VerifiedEnvelope, VerifyDirectory, VerifyError, VerifyPipeline,
};

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
    /// Max [`crate::messages::ContentBody::bytes`] size accepted on
    /// inbound dispatch (CIRISEdge#21 v0.8.0). Extends the AV-13 body-
    /// size family with a separate cap for the content-addressable
    /// byte-fetch path — `max_body_bytes` already gates the envelope
    /// at verify-pipeline entry, but `ContentBody.bytes` may
    /// reasonably exceed the envelope cap (a JSON envelope wrapping
    /// 16 MiB of bytes serializes to ~21 MiB with base64), so the
    /// content-fetch path lifts the envelope cap and re-applies a
    /// content-specific cap on the bytes field after parse. Default
    /// [`crate::messages::DEFAULT_MAX_CONTENT_BODY_BYTES`] = 16 MiB
    /// (CIRISEdge#21 Phase 1 spec point 7). Oversized rejects with
    /// the existing AV-13 family error
    /// ([`crate::verify::VerifyError::BodyTooLarge`]).
    pub max_content_body_bytes: usize,
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
            // CIRISEdge#21 v0.8.0 — separate AV-13 cap for
            // `ContentBody.bytes`. A consumer that wants to actually
            // receive 16 MiB `ContentBody` payloads must also raise
            // `max_body_bytes` accordingly (`bytes: Vec<u8>`
            // serializes to ~3x its raw size as JSON integer-array,
            // so 16 MiB raw ≈ 48 MiB envelope-wire); the
            // content-fetch path's `dispatch_inbound` enforces THIS
            // field post-parse on the bytes vector itself. The
            // envelope-level cap is the cheap pre-check; this is the
            // body-level pin.
            max_content_body_bytes: crate::messages::DEFAULT_MAX_CONTENT_BODY_BYTES,
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

/// Inline-text inbound subscriber registry entry (CIRISEdge#22 Tier 2).
///
/// Each entry holds an unbounded sender that the inbound dispatcher
/// pushes `(sender_key_id, body_text)` tuples onto. A Python-owned
/// drainer thread (spawned in [`crate::ffi::pyo3`] when
/// `register_inline_text_handler` is called) receives from the matching
/// receiver, acquires the GIL, and invokes the user-supplied Python
/// callback. Dropping the sender (via [`Edge::unregister_inline_text_subscriber`])
/// causes the drainer to observe a closed channel and exit cleanly —
/// the subscription-lifecycle invariant the Python `SubscriptionHandle`
/// enforces.
///
/// Unbounded by design: dropping events under back-pressure would
/// degrade the CommunicationBus-replacement semantic the Python adapter
/// builds on. Subscribers that can't keep up must drop their handle —
/// a closed channel removes the entry from the registry on the next
/// dispatch (lazy cleanup, no separate sweep needed).
pub(crate) type InlineTextSubscriber = mpsc::UnboundedSender<(String, String)>;

/// Top-level edge handle. Construct via [`Edge::builder`].
pub struct Edge {
    verify: Arc<VerifyPipeline>,
    queue: Arc<dyn OutboundHandle>,
    signer: Arc<LocalSigner>,
    transports: Vec<Arc<dyn Transport>>,
    handlers: Arc<Mutex<HashMap<MessageType, RegisteredHandler>>>,
    /// Inline-text inbound fan-out registry (CIRISEdge#22 Tier 2;
    /// v0.9.0). Distinct from `handlers` because the typed handler
    /// dispatch supports exactly **one** handler per [`MessageType`] —
    /// the Python `register_inline_text_handler` surface must accept
    /// multiple concurrent subscribers (one per `EdgeCommunicationAdapter`
    /// consumer at minimum). Subscriptions are keyed by an
    /// monotonically-increasing u64 (`inline_text_next_id`); the Python
    /// `SubscriptionHandle::unsubscribe` removes by id.
    inline_text_subscribers: Arc<std::sync::Mutex<HashMap<u64, InlineTextSubscriber>>>,
    /// Subscription id allocator for [`Self::inline_text_subscribers`].
    /// `AtomicU64::fetch_add` so the allocator is lock-free.
    inline_text_next_id: Arc<AtomicU64>,
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

    /// Register an inbound inline-text subscriber (CIRISEdge#22 Tier 2;
    /// v0.9.0). Every verified [`crate::MessageType::InlineText`]
    /// envelope dispatched through [`Self::run`]'s inbound loop is
    /// fanned out to every subscriber registered here, as a
    /// `(sender_key_id, body_text)` tuple pushed onto the returned
    /// receiver.
    ///
    /// The caller owns the receiver — drop it (or call
    /// [`Self::unregister_inline_text_subscriber`] with the returned id)
    /// to stop the fan-out. The dispatcher lazy-prunes entries whose
    /// `send` returns `Err(SendError)` (closed receiver), so dropping
    /// the receiver alone is sufficient for correctness — the explicit
    /// unregister exists for tests and for the Python
    /// `SubscriptionHandle::unsubscribe` surface which needs synchronous
    /// removal (so a subsequent inbound that arrives before the next
    /// dispatch's lazy prune cannot fire a callback the consumer
    /// considers detached).
    ///
    /// # Used by
    ///
    /// [`crate::ffi::pyo3::PyEdge::register_inline_text_handler`] — the
    /// Python-facing surface CIRISAgent 2.9.5's `EdgeCommunicationAdapter`
    /// consumes. The Rust-level method exists so the same fan-out is
    /// reachable to non-Python embedders (uniffi / swift-bridge shells
    /// landing in Phase 3).
    pub fn register_inline_text_subscriber(
        &self,
    ) -> (u64, mpsc::UnboundedReceiver<(String, String)>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let id = self.inline_text_next_id.fetch_add(1, Ordering::Relaxed);
        let mut subs = self
            .inline_text_subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        subs.insert(id, tx);
        (id, rx)
    }

    /// Remove an inline-text subscriber by id. Idempotent — returns
    /// `true` if the id was registered, `false` if not (matches persist
    /// `PyEngine::unsubscribe` ergonomics).
    pub fn unregister_inline_text_subscriber(&self, id: u64) -> bool {
        let mut subs = self
            .inline_text_subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        subs.remove(&id).is_some()
    }

    /// Snapshot count of live inline-text subscribers. Diagnostics
    /// helper — used by the Python tests to verify the lifecycle (a
    /// `SubscriptionHandle::unsubscribe` or `__exit__` must observe the
    /// count drop).
    pub fn inline_text_subscriber_count(&self) -> usize {
        self.inline_text_subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Manually fan out an InlineText payload to every subscriber.
    /// Public for tests + future non-dispatcher embedders that want to
    /// inject a synthetic inbound without going through the verify
    /// pipeline. The production inbound path calls the free-function
    /// equivalent from [`dispatch_inbound`].
    pub fn fan_out_inline_text_for_test(&self, sender_key_id: &str, body_text: &str) {
        fan_out_inline_text(&self.inline_text_subscribers, sender_key_id, body_text);
    }

    /// CIRISEdge#19 — synchronous one-shot driver for the inbound
    /// dispatch pipeline. Test-only helper: lets integration suites
    /// drive a single `InboundFrame` through the same code path
    /// `Edge::run` invokes per inbound message, then observe outbound
    /// queue state (refusal attestation, acceptance attestation, etc.)
    /// without standing up the full listener / dispatcher topology.
    ///
    /// The production callers are the `Edge::run` listener loop; this
    /// shares the same `dispatch_inbound` body, so a regression in
    /// the wire-layer gate is caught from either entry point.
    pub async fn dispatch_inbound_for_test(&self, frame: InboundFrame) {
        let directory = self.verify.directory();
        dispatch_inbound(
            frame,
            &self.verify,
            &self.handlers,
            &self.queue,
            &self.signer,
            &self.inline_text_subscribers,
            self.config.max_content_body_bytes,
            &directory,
        )
        .await;
    }

    /// Rust-level accessor returning a clone of the outbound queue
    /// `Arc`. Used by [`crate::ffi::pyo3::PyDurableHandle`] to poll
    /// `outbound_status` for `await_ack` semantics independently of
    /// the `PyEdge`'s lifetime.
    #[must_use]
    pub fn outbound_queue_handle(&self) -> Arc<dyn OutboundHandle> {
        self.queue.clone()
    }

    /// Rust-level accessor returning the local signer's `key_id` —
    /// the `signing_key_id` field on outbound envelopes. Used by the
    /// PyO3 `send_inline_text` body-sha256 pre-computation step.
    #[must_use]
    pub fn signer_key_id(&self) -> &str {
        &self.signer.key_id
    }

    /// Pub-crate variant of [`Self::run_speak_pipeline`] reachable
    /// from `crate::ffi::pyo3`. The Python `send_inline_text` /
    /// `send_durable_inline_text` wrappers need to run the pipeline
    /// against a typed `InlineText` body to compute the post-pipeline
    /// `body_sha256` BEFORE calling `send_inline` (which would consume
    /// the message). Idempotent — running it twice produces the same
    /// bytes.
    pub async fn run_speak_pipeline_for_external<M: InlineTextMessage>(
        &self,
        msg: &mut M,
    ) -> Result<(), EdgeError> {
        self.run_speak_pipeline(msg).await
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
        // pre-application-layer-handler) + InlineText fan-out
        // (CIRISEdge#22 Tier 2; the EdgeCommunicationAdapter inbound
        // path).
        let verify = self.verify.clone();
        let handlers = self.handlers.clone();
        let queue = self.queue.clone();
        let signer = self.signer.clone();
        let inline_subs = self.inline_text_subscribers.clone();
        let max_content_body_bytes = self.config.max_content_body_bytes;
        let mut shutdown = shutdown_rx;
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!("edge: shutdown signal received");
                    break;
                }
                Some(frame) = inbound_rx.recv() => {
                    let verify_clone = verify.clone();
                    let handlers_clone = handlers.clone();
                    let queue_clone = queue.clone();
                    let signer_clone = signer.clone();
                    let its = inline_subs.clone();
                    let directory_clone = verify_clone.directory();
                    tokio::spawn(async move {
                        dispatch_inbound(
                            frame,
                            &verify_clone,
                            &handlers_clone,
                            &queue_clone,
                            &signer_clone,
                            &its,
                            max_content_body_bytes,
                            &directory_clone,
                        ).await;
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

/// Inbound dispatch: verify → maybe-ACK-match → `ContentBody`
/// AV-13/integrity gate (CIRISEdge#21 v0.8.0) → `FederationAnnouncement`
/// `AccordCarrier` 2-of-3 multi-sig wire-layer gate (CIRISEdge#19,
/// v0.10.0) → `FederationAnnouncement` attestation-emission (FSD §3.2.1
/// v0.1 gate) → `InlineText` fan-out (CIRISEdge#22 Tier 2 v0.9.0) →
/// typed handler dispatch.
#[allow(clippy::too_many_lines)] // dispatch is the load-bearing pipeline composition site
#[allow(clippy::too_many_arguments)] // composition site for all dispatch primitives
async fn dispatch_inbound(
    frame: InboundFrame,
    verify: &VerifyPipeline,
    handlers: &Mutex<HashMap<MessageType, RegisteredHandler>>,
    queue: &Arc<dyn OutboundHandle>,
    signer: &Arc<LocalSigner>,
    inline_text_subscribers: &std::sync::Mutex<HashMap<u64, InlineTextSubscriber>>,
    max_content_body_bytes: usize,
    directory: &Arc<dyn VerifyDirectory>,
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

    // CIRISEdge#21 v0.8.0 — `ContentBody` AV-13 size cap + content-
    // addressed integrity check, applied post-verify and BEFORE
    // handler dispatch. The signature on the envelope binds the
    // (sha256, bytes) pair to the responder; this gate binds the
    // bytes to the SHA. Without this re-hash the content-addressed
    // invariant collapses to "trust whatever the responder said the
    // SHA was" — which defeats the entire point of byte-fetch over a
    // federation directory.
    //
    // Reject reasons map to the existing AV-13 family error
    // (`VerifyError::BodyTooLarge`) and a typed integrity-mismatch
    // log (handlers never see a bad ContentBody). Fail-loud at the
    // `tracing::warn!` boundary — no silent drops (MISSION.md §3
    // anti-pattern 6).
    if envelope.message_type == MessageType::ContentBody {
        match validate_content_body(&envelope, max_content_body_bytes) {
            Ok(()) => {}
            Err(e) => {
                tracing::warn!(
                    transport = ?transport,
                    error = %e,
                    body_sha256 = ?body_sha256,
                    "ContentBody rejected at dispatch gate (AV-13 / integrity)",
                );
                return;
            }
        }
    }

    // CIRISEdge#19 v0.10.0 — wire-layer 2-of-3 multi-sig authority
    // gate for `priority == AccordCarrier`. Defense in depth on the
    // v0.6.0 application-tier `FederationAnnouncement` consumer check:
    // a compromised peer can no longer propagate an invalid
    // CONSTITUTIONAL envelope past the first hop running verified
    // edge code. Failures REFUSE propagation and emit a substrate-
    // signed `DeliveryRefusalAttestation` (so adversarial suppression
    // of legitimate accords stays distinguishable from suppression of
    // forged ones).
    //
    // The accord-multi-sig set lives on the `FederationAnnouncement`
    // BODY (not on the surrounding `EdgeEnvelope`'s single sender
    // signature) — re-parse the body once here for the gate. The
    // existing `DeliveryAttestation` emission below stays bypassed on
    // refusal (the refusal IS the observable for AccordCarrier; a
    // refused envelope MUST NOT also emit an acceptance attestation).
    if envelope.message_type == MessageType::FederationAnnouncement {
        match serde_json::from_str::<FederationAnnouncement>(envelope.body.get()) {
            Ok(ann) if ann.priority == AnnouncementPriority::AccordCarrier => {
                match verify_accord_carrier(&ann, directory).await {
                    Ok(()) => {
                        // Threshold met — fall through to the normal
                        // v0.6.0 acceptance attestation + handler
                        // dispatch path.
                    }
                    Err(reason) => {
                        tracing::warn!(
                            announcement_id = ?derive_announcement_id_from_body_hash(&body_sha256),
                            ?reason,
                            "AccordCarrier FederationAnnouncement REFUSED at wire-layer multi-sig gate (CIRISEdge#19)",
                        );
                        if let Err(e) = emit_delivery_refusal_attestation(
                            &envelope,
                            body_sha256,
                            transport,
                            signer,
                            queue,
                            reason,
                        )
                        .await
                        {
                            tracing::warn!(
                                error = %e,
                                "DeliveryRefusalAttestation emission failed (CIRISEdge#19)",
                            );
                        }
                        // Drop the announcement from edge's downstream
                        // propagation — no handler dispatch, no
                        // acceptance attestation.
                        return;
                    }
                }
            }
            Ok(_) => {
                // Non-AccordCarrier priority: the wire-layer gate is
                // bypassed (FSD §4.5 reserves the multi-sig
                // requirement to AccordCarrier; other priorities ride
                // the single-signature envelope path).
            }
            Err(e) => {
                // Body did not parse as FederationAnnouncement — let
                // the existing acceptance attestation emit attempt
                // continue and the typed-handler dispatch path
                // discover the schema issue. The substrate is not
                // additionally responsible for app-layer schema gates.
                tracing::debug!(
                    error = %e,
                    "FederationAnnouncement body parse failed at AccordCarrier gate; downstream paths handle",
                );
            }
        }
    }

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

    // CIRISEdge#22 Tier 2 (v0.9.0) — InlineText fan-out. The Python
    // `register_inline_text_handler` surface supports multiple
    // concurrent subscribers, which the singleton `handlers` HashMap
    // does not (one entry per `MessageType`). Fan out to every
    // registered subscriber here; the typed-handler dispatch still
    // runs below (so a Rust-side typed `Handler<InlineText>` registered
    // via `register_handler` continues to work, parallel to the
    // Python fan-out).
    //
    // We parse the body once here; the typed-handler path re-parses
    // (via the erased handler closure) — the cost is negligible
    // (the body is already a `RawValue`), and keeping the two paths
    // independent is structurally simpler than threading a parsed
    // body through the erased dispatch.
    if envelope.message_type == MessageType::InlineText {
        match serde_json::from_str::<crate::messages::InlineText>(envelope.body.get()) {
            Ok(inline) => {
                fan_out_inline_text(
                    inline_text_subscribers,
                    &envelope.signing_key_id,
                    &inline.text,
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    transport = ?transport,
                    "InlineText body parse failed at dispatch fan-out",
                );
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
        // InlineText with no typed Rust handler is not an error — the
        // Python fan-out above is the intended consumer. Suppress the
        // `no handler registered` warning for that one type.
        if envelope.message_type != MessageType::InlineText {
            tracing::warn!(
                message_type = ?envelope.message_type,
                "no handler registered; dropping",
            );
        }
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
            inline_text_subscribers: Arc::new(std::sync::Mutex::new(HashMap::new())),
            inline_text_next_id: Arc::new(AtomicU64::new(1)),
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

/// Pub-crate re-export so [`crate::ffi::pyo3::PyDurableHandle`] can
/// reuse the same outbound-row → DurableStatus mapping the
/// `DurableHandle::status_via` Rust method uses. Only the pyo3
/// surface consumes it today (CIRISEdge#22 Tier 2; v0.9.0); the
/// `#[cfg]` gate matches the consumer so the non-pyo3 build doesn't
/// see a dead-code warning.
#[cfg(feature = "pyo3")]
pub(crate) fn map_outbound_row_to_status(
    row: &ciris_persist::prelude::OutboundRow,
) -> DurableStatus {
    map_row_to_status(row)
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

/// Fan out an inbound InlineText payload to every subscriber in the
/// registry. Lazily prunes entries whose `send` returns `Err` (the
/// Python `SubscriptionHandle` has gone out of scope without an
/// explicit `unsubscribe()` — channel-closed semantics from the
/// drainer-thread side). Free-function form because `dispatch_inbound`
/// is itself a free function — the `Edge::fan_out_inline_text` method
/// (on the type) is a thin wrapper around this same logic for
/// non-dispatcher callers (tests, future embedders).
fn fan_out_inline_text(
    inline_text_subscribers: &std::sync::Mutex<HashMap<u64, InlineTextSubscriber>>,
    sender_key_id: &str,
    body_text: &str,
) {
    let mut subs = inline_text_subscribers
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if subs.is_empty() {
        return;
    }
    let payload = (sender_key_id.to_string(), body_text.to_string());
    let mut dead: Vec<u64> = Vec::new();
    for (id, tx) in subs.iter() {
        if tx.send(payload.clone()).is_err() {
            dead.push(*id);
        }
    }
    for id in dead {
        subs.remove(&id);
    }
}

fn message_type_str(mt: &MessageType) -> String {
    serde_json::to_value(mt)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{mt:?}"))
}

/// Validate a `ContentBody`-typed envelope against (a) the AV-13
/// content-body cap and (b) the content-addressed integrity invariant
/// (`sha256(bytes) == claimed_sha256`). CIRISEdge#21 v0.8.0 spec
/// points 2 + 7.
///
/// Returns:
///
/// - `Ok(())` — the body parsed, `bytes.len() <=
///   max_content_body_bytes`, and `sha256(bytes) == claimed_sha256`.
/// - `Err(VerifyError::BodyTooLarge { .. })` — the AV-13 family error
///   reused: oversized rejects look identical to envelope-tier AV-13
///   rejects so a downstream metric collector sees one error category.
/// - `Err(VerifyError::SchemaInvalid(_))` — body did not parse OR the
///   integrity check failed. The integrity-mismatch case folds to
///   `SchemaInvalid` (the envelope's typed `MessageType::ContentBody`
///   was advertised but the body bytes don't match their own claimed
///   SHA — a typed schema violation under the content-addressed
///   contract).
fn validate_content_body(
    envelope: &EdgeEnvelope,
    max_content_body_bytes: usize,
) -> Result<(), VerifyError> {
    use crate::messages::{sha256_of, ContentBody};

    let body: ContentBody = serde_json::from_str(envelope.body.get())
        .map_err(|e| VerifyError::SchemaInvalid(format!("ContentBody body parse: {e}")))?;

    // AV-13 family — oversized rejects with the same error variant as
    // the envelope-tier check (`VerifyError::BodyTooLarge`). One error
    // category across the AV-13 surface.
    if body.bytes.len() > max_content_body_bytes {
        return Err(VerifyError::BodyTooLarge {
            actual: body.bytes.len(),
            limit: max_content_body_bytes,
        });
    }

    // Content-addressed integrity gate (CIRISEdge#21 spec point 2).
    // `sha256(bytes) == claimed_sha256` is the WHOLE POINT of the
    // content-fetch primitive; a mismatch is a typed schema violation
    // under the content-addressed contract.
    let actual = sha256_of(&body.bytes);
    if actual != body.sha256 {
        return Err(VerifyError::SchemaInvalid(format!(
            "ContentBody integrity check failed: claimed sha256={} \
             but sha256(bytes)={}",
            hex_encode(&body.sha256),
            hex_encode(&actual),
        )));
    }

    Ok(())
}

/// Cheap hex-encode helper for diagnostic log lines. Uses
/// `std::fmt::Write` over the byte slice (clippy:
/// `format_push_string` lints away a `format!`-append). Not
/// security-critical; just makes mismatch errors actionable.
fn hex_encode(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
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

/// CIRISEdge#19 — wire-layer accord-multi-sig gate. Returns `Ok(())`
/// iff ≥ [`ACCORD_THRESHOLD_M_OF_N`].0 valid signatures from DISTINCT
/// accord-holder keys cover the announcement's canonical bytes;
/// returns the appropriate [`RefusalReason`] otherwise.
///
/// # Algorithm (CIRISEdge#19 issue body §"Ask")
///
/// 1. Query `directory.list_accord_holders()` — persist's `federation_keys`
///    rows where `identity_type = 'accord_holder'`.
/// 2. If the accord-holder set is empty → `NoAccordHoldersConfigured`
///    (substrate isn't bootstrapped for constitutional traffic;
///    refusal IS correct even for a perfectly-signed envelope, because
///    the trust chain has no root).
/// 3. Derive the canonical bytes the accord-holders sign via
///    [`FederationAnnouncement::canonical_bytes_for_accord_signatures`].
/// 4. For each `AccordSignature` in the announcement, verify it
///    against the matching accord-holder pubkey. Track DISTINCT
///    holders whose signatures verify (duplicate signatures from the
///    same holder count once — CIRISEdge#19 distinct-holders
///    invariant).
/// 5. If at least `ACCORD_THRESHOLD_M_OF_N.0` distinct holders
///    verified → `Ok(())`. Otherwise:
///    - If at least one signature *did* verify (but threshold not
///      met) → `InsufficientAccordSignatures { found, required }`.
///    - If ZERO signatures verified AND there was at least one
///      signature attempt → `InvalidAccordSignature`.
///    - If ZERO signatures were provided at all → that collapses to
///      `InsufficientAccordSignatures { found: 0, required }` —
///      same forensic conclusion (the envelope didn't satisfy the
///      threshold).
async fn verify_accord_carrier(
    ann: &FederationAnnouncement,
    directory: &Arc<dyn VerifyDirectory>,
) -> Result<(), RefusalReason> {
    let required = ACCORD_THRESHOLD_M_OF_N.0;
    let holders: Vec<AccordHolderKey> = match directory.list_accord_holders().await {
        Ok(v) => v,
        Err(e) => {
            // Substrate fault: persist call failed. Treat as
            // "not configured" — refusing is the conservative
            // safe-default for the substrate-unavailable case (the
            // alternative would be to silently propagate, defeating
            // the wire-layer gate's defense-in-depth purpose).
            tracing::warn!(
                error = %e,
                "list_accord_holders failed; treating as NoAccordHoldersConfigured",
            );
            return Err(RefusalReason::NoAccordHoldersConfigured);
        }
    };
    if holders.is_empty() {
        return Err(RefusalReason::NoAccordHoldersConfigured);
    }

    let canonical = ann
        .canonical_bytes_for_accord_signatures()
        .map_err(|_e| RefusalReason::InvalidAccordSignature)?;

    // Build a key_id → pubkey map for O(1) per-sig lookup. The holder
    // set is small (3 by FSD spec), so a Vec scan is fine; map is
    // future-proofing if 3-of-5 ships.
    let by_id: std::collections::HashMap<&str, &[u8; 32]> = holders
        .iter()
        .map(|h| (h.key_id.as_str(), &h.pubkey_ed25519))
        .collect();

    let mut verified_holders = std::collections::HashSet::<String>::new();
    let mut any_attempted = false;
    for sig in &ann.accord_signatures {
        any_attempted = true;
        // The presented key_id MUST appear in the accord-holder set;
        // a sig from a non-accord-holder counts as zero verifications
        // toward the threshold. We don't even attempt verification
        // against a non-accord-holder pubkey.
        let Some(pubkey_bytes) = by_id.get(sig.key_id.as_str()) else {
            continue;
        };
        if verify_ed25519_signature(pubkey_bytes, &canonical, &sig.signature_ed25519_base64) {
            verified_holders.insert(sig.key_id.clone());
        }
    }

    let found = u32::try_from(verified_holders.len()).unwrap_or(u32::MAX);
    if found >= required {
        return Ok(());
    }

    // Forensic discrimination: at least one signature verified but
    // threshold not met → `InsufficientAccordSignatures`. ZERO
    // verified AND at least one signature was attempted →
    // `InvalidAccordSignature` (every signature was either against a
    // non-accord-holder key or had bad bytes). ZERO signatures at all
    // → `InsufficientAccordSignatures { found: 0, required }` —
    // same threshold-not-met forensic story.
    if found == 0 && any_attempted {
        Err(RefusalReason::InvalidAccordSignature)
    } else {
        Err(RefusalReason::InsufficientAccordSignatures { found, required })
    }
}

/// Verify one Ed25519 signature against a 32-byte pubkey and the
/// canonical bytes. Returns `false` on base64-decode failure, wrong
/// signature length, or signature-verification failure (any error is
/// "this signature does not pass"; the gate's job is to count
/// confirming verifications, not surface error taxonomy).
fn verify_ed25519_signature(pubkey: &[u8; 32], canonical: &[u8], sig_b64: &str) -> bool {
    use ciris_crypto::ClassicalVerifier as _;

    let Ok(sig_bytes) = base64::engine::general_purpose::STANDARD.decode(sig_b64.as_bytes()) else {
        return false;
    };
    if sig_bytes.len() != 64 {
        return false;
    }
    // Use ciris-crypto's verifier — the same primitive persist's
    // verify_hybrid_via_directory composes (single-source-of-truth
    // for Ed25519 verify across the federation).
    matches!(
        ciris_crypto::Ed25519Verifier::new().verify(pubkey, canonical, &sig_bytes),
        Ok(true)
    )
}

/// CIRISEdge#19 — build, sign, and enqueue a [`crate::DeliveryRefusalAttestation`]
/// for a `priority == AccordCarrier` `FederationAnnouncement` envelope
/// that failed the wire-layer multi-sig threshold check. Mirrors
/// [`emit_delivery_attestation`] exactly (same Ed25519 + optional
/// PQC bound-signature discipline, same UUID derivation, same
/// Durable fire-and-forget queue contract); the refusal IS the
/// observable that lets a steward end distinguish adversarial
/// suppression of legitimate accords from suppression of forged ones.
async fn emit_delivery_refusal_attestation(
    envelope: &EdgeEnvelope,
    body_sha256: [u8; 32],
    transport: crate::transport::TransportId,
    signer: &Arc<LocalSigner>,
    queue: &Arc<dyn OutboundHandle>,
    refusal_reason: RefusalReason,
) -> Result<(), EdgeError> {
    use crate::messages::{
        encode_canonical_hash_base64, encode_signature_base64, DeliveryRefusalAttestation,
        TransportMedium,
    };

    let announcement_id = derive_announcement_id_from_body_hash(&body_sha256);
    let peer_pubkey_bytes = signer
        .classical
        .public_key()
        .await
        .map_err(|e| EdgeError::Persist(format!("local pubkey: {e}")))?;
    let peer_pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(&peer_pubkey_bytes);
    let canonical_hash_b64 = encode_canonical_hash_base64(&body_sha256);

    let refused_at = chrono::Utc::now();
    let mut refusal = DeliveryRefusalAttestation {
        announcement_id,
        announcement_canonical_hash_base64: canonical_hash_b64,
        peer_key_id: signer.key_id.clone(),
        peer_pubkey_ed25519_base64: peer_pubkey_b64,
        refused_at,
        transport_id: TransportMedium::from(transport),
        refusal_reason,
        signature_classical_base64: String::new(),
        signature_pqc_base64: None,
    };

    let canonical = refusal.canonical_bytes().map_err(|e| {
        EdgeError::Config(format!("delivery_refusal_attestation canonical_bytes: {e}"))
    })?;

    let ed25519_sig = signer
        .classical
        .sign(&canonical)
        .await
        .map_err(|e| EdgeError::Persist(format!("refusal classical sign: {e}")))?;
    refusal.signature_classical_base64 = encode_signature_base64(&ed25519_sig);

    if let Some(pqc) = signer.pqc.as_ref() {
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed25519_sig);
        let pqc_sig = pqc
            .sign(&bound)
            .await
            .map_err(|e| EdgeError::Persist(format!("refusal pqc sign: {e}")))?;
        refusal.signature_pqc_base64 = Some(encode_signature_base64(&pqc_sig));
    }

    let envelope_bytes = {
        let mut env = build_envelope(
            MessageType::DeliveryRefusalAttestation,
            &signer.key_id,
            &envelope.signing_key_id,
            &refusal,
            None,
        )?;
        sign_envelope(signer, &mut env).await?;
        serde_json::to_vec(&env)
            .map_err(|e| EdgeError::Config(format!("refusal envelope serialize: {e}")))?
    };
    let env: EdgeEnvelope = serde_json::from_slice(&envelope_bytes)
        .map_err(|e| EdgeError::Config(format!("re-parse refusal envelope: {e}")))?;
    let body_sha256_refusal = envelope_body_sha256(&env);
    let body_size_bytes = i32::try_from(envelope_bytes.len()).unwrap_or(i32::MAX);

    // Same Durable fire-and-forget shape as DeliveryAttestation.
    let (max_attempts, ttl_seconds) = match crate::DeliveryRefusalAttestation::DELIVERY {
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
            &message_type_str(&MessageType::DeliveryRefusalAttestation),
            "1.0.0",
            &envelope_bytes,
            &body_sha256_refusal,
            body_size_bytes,
            false, // requires_ack: false (refusal IS the observable)
            None,
            max_attempts,
            ttl_seconds,
            Utc::now(),
        )
        .await
        .map_err(|e| EdgeError::Persist(format!("enqueue_outbound (refusal): {e}")))?;

    Ok(())
}
