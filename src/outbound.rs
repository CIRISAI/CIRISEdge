//! Outbound queue adapter + dispatcher loop.
//!
//! Two pieces:
//!
//! - [`OutboundHandle`] — adapter trait that erases `OutboundQueue`'s
//!   RPIT-in-trait so edge can hold `Arc<dyn OutboundHandle>` (same
//!   pattern as [`crate::verify::VerifyDirectory`]).
//! - [`run_dispatcher`] — the background tokio task spawned by
//!   `Edge::run` that polls `claim_pending_outbound`, attempts
//!   transport delivery, calls `mark_transport_*` accordingly. Plus
//!   periodic `sweep_*` tasks for ACK timeouts, TTL, and expired
//!   claims.
//!
//! See [`FSD/EDGE_OUTBOUND_QUEUE.md`](../../FSD/EDGE_OUTBOUND_QUEUE.md)
//! §4 for the Engine surface this composes against.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ciris_persist::federation::types::identity_type as persist_identity_type;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::outbound::Error as PersistOutboundError;
use ciris_persist::prelude::{
    OutboundFailureOutcome, OutboundFilter, OutboundQueue, OutboundRow, QueueId,
};

use crate::transport::{Transport, TransportError, TransportSendOutcome};

/// Adapter trait that erases `FederationDirectory`'s generics for the
/// peer-enumeration use case driving `Edge::send_mandatory` fan-out
/// (CIRISEdge#18 / FSD §3.2 substrate contract).
///
/// `Edge::send_mandatory` enqueues one durable row per peer returned
/// by [`Self::list_recipients`], so the FederationAnnouncement reaches
/// every peer in the directory **regardless of subscription state**
/// (the load-bearing wire change — without it `Mandatory` is just a
/// name).
///
/// The trait is intentionally narrow — one method, returning peer
/// `key_id`s — so any directory shape (in-memory test fixture, persist
/// `federation_keys` view, Reticulum-rooted-peer-map snapshot) can
/// implement it. Production deployments wrap their
/// `FederationDirectory` to surface the set of currently-reachable
/// peers; tests stub it with a static `Vec`.
#[async_trait]
pub trait PeerDirectory: Send + Sync + 'static {
    /// Enumerate the federation `key_id`s edge should fan out to for
    /// `Delivery::Mandatory` messages. The returned set is
    /// authoritative — a Mandatory enqueue produces one outbound row
    /// per element. The local steward's own key_id MAY appear
    /// (callers/tests decide); `Edge::send_mandatory` filters it out
    /// before enqueue (self-delivery would create a loopback at the
    /// dispatcher).
    async fn list_recipients(&self) -> Result<Vec<String>, PersistOutboundError>;
}

/// Steward identity row surfaced by [`StewardDirectory`] for
/// CIRISEdge#20 high-priority federation fan-out. Carries the minimum
/// fields edge needs to address the steward (the `key_id` —
/// `federation_keys.key_id`) plus a forensic-logging join key
/// (`identity_ref` — the steward's logical identity reference).
///
/// Distinct from persist's full [`ciris_persist::prelude::KeyRecord`]:
/// edge does not need the public-key bytes / signature columns / row
/// hash here — the verify pipeline already roots envelopes against
/// `federation_keys`. This is a routing-table view, not a verification
/// view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StewardKey {
    /// `federation_keys.key_id` — the destination address for
    /// `Edge::send_federation` fan-out.
    pub key_id: String,
    /// `federation_keys.identity_ref` — the steward's logical
    /// identity. Surfaced for forensic logging (operator UIs / audit
    /// log lines say "fanned out to US steward X" rather than just
    /// printing the opaque key_id). Not load-bearing for routing.
    pub identity_ref: String,
}

/// CIRISEdge#20 — recipient enumeration for the steward-class
/// federation fan-out. Distinct from [`PeerDirectory`] (which is the
/// every-peer enumeration consumed by `Delivery::Mandatory`) because
/// the steward class is a **dynamically-derived subset** of the
/// federation: any `federation_keys` row with
/// `identity_type = "steward"` (persist's
/// [`identity_type::STEWARD`](ciris_persist::federation::types::identity_type::STEWARD))
/// at the moment `Edge::send_federation` is called.
///
/// `current_stewards` is recomputed on every send — there is no
/// caching layer here; that is the load-bearing semantic supporting
/// the issue's ask #4 ("dynamic topology adjustment when steward set
/// changes"). Steward identity rotations per Registry FSD-002 §2.1
/// propagate to the gossip topology atomically: the next
/// `send_federation` call sees the post-rotation set without any
/// edge-side cache invalidation.
///
/// Production deployments wrap their `FederationDirectory` (an
/// `Arc<dyn FederationDirectory>`) — the blanket impl in this module
/// resolves stewards via persist v2.7.0's
/// [`list_keys_by_identity_type`](ciris_persist::federation::FederationDirectory::list_keys_by_identity_type).
/// Tests stub it with a `Vec<StewardKey>`.
#[async_trait]
pub trait StewardDirectory: Send + Sync + 'static {
    /// Enumerate the current steward set. Returns `Vec<StewardKey>`
    /// keyed by `federation_keys.key_id`; persist returns rows in
    /// stable lex order so callers can deterministically subset.
    ///
    /// Returns an empty `Vec` when no steward rows are present —
    /// callers (`Edge::send_federation`) MUST surface this as a typed
    /// error rather than a silent no-op (MISSION.md §3 anti-pattern
    /// 6 / FSD §3.4 fail-loud invariant).
    async fn current_stewards(&self) -> Result<Vec<StewardKey>, PersistOutboundError>;
}

/// Blanket impl: any `Arc<dyn FederationDirectory>` is a
/// `StewardDirectory`. Calls persist v2.7.0's
/// [`list_keys_by_identity_type`](ciris_persist::federation::FederationDirectory::list_keys_by_identity_type)
/// with [`identity_type::STEWARD`](ciris_persist::federation::types::identity_type::STEWARD)
/// and projects the returned `KeyRecord`s onto the [`StewardKey`]
/// routing-view shape. Persist's `Error` is mapped onto
/// [`PersistOutboundError::Backend`] so the call site sees one error
/// taxonomy across both directory-enumeration paths
/// (`PeerDirectory::list_recipients` and `StewardDirectory::current_stewards`).
#[async_trait]
impl<D: FederationDirectory + Send + Sync + 'static> StewardDirectory for D {
    async fn current_stewards(&self) -> Result<Vec<StewardKey>, PersistOutboundError> {
        let rows = self
            .list_keys_by_identity_type(persist_identity_type::STEWARD)
            .await
            .map_err(|e| {
                PersistOutboundError::Backend(format!("StewardDirectory::current_stewards: {e}"))
            })?;
        Ok(rows
            .into_iter()
            .map(|r| StewardKey {
                key_id: r.key_id,
                identity_ref: r.identity_ref,
            })
            .collect())
    }
}

/// Optional per-peer subscription filter applied by `send_durable` to
/// produce the subset of peers that "subscribed" to receive a given
/// `MessageType`. **Bypassed by `Delivery::Mandatory`** (FSD §3.2 —
/// the wire-level expression of "federation-wide push regardless of
/// per-peer opt-in").
///
/// When `None` on [`crate::Edge`], `send_durable` addresses the single
/// `destination_key_id` argument as today (no broadcast). When `Some`,
/// it is consulted only by code paths that elect to call into it —
/// in v0.1 that is reserved to a future Phase 2 multi-cast `send_durable`
/// shape; for now the filter exists primarily so the **bypass** of
/// `Delivery::Mandatory` is observable in tests (a peer whose filter
/// would drop a `MessageType::FederationAnnouncement` MUST still
/// receive it via the Mandatory broadcast).
#[async_trait]
pub trait PeerSubscriptionFilter: Send + Sync + 'static {
    /// Return `true` if `peer_key_id` is subscribed to messages of
    /// `message_type`. The filter is consulted in subscription-
    /// respecting code paths; `Mandatory` deliberately does NOT
    /// consult it.
    async fn is_subscribed(&self, peer_key_id: &str, message_type: &crate::MessageType) -> bool;
}

/// Adapter trait that erases `OutboundQueue`'s RPIT generics. Blanket
/// impl over any `OutboundQueue`; edge holds `Arc<dyn OutboundHandle>`.
#[async_trait]
pub trait OutboundHandle: Send + Sync + 'static {
    #[allow(clippy::too_many_arguments)]
    async fn enqueue_outbound(
        &self,
        sender_key_id: &str,
        destination_key_id: &str,
        message_type: &str,
        edge_schema_version: &str,
        envelope_bytes: &[u8],
        body_sha256: &[u8; 32],
        body_size_bytes: i32,
        requires_ack: bool,
        ack_timeout_seconds: Option<i64>,
        max_attempts: i32,
        ttl_seconds: i64,
        initial_next_attempt_after: DateTime<Utc>,
    ) -> Result<QueueId, PersistOutboundError>;

    async fn claim_pending_outbound(
        &self,
        batch_size: i64,
        claim_duration_seconds: i64,
        claimed_by: &str,
    ) -> Result<Vec<OutboundRow>, PersistOutboundError>;

    async fn mark_transport_delivered(
        &self,
        queue_id: &str,
        transport: &str,
    ) -> Result<(), PersistOutboundError>;

    async fn mark_transport_failed(
        &self,
        queue_id: &str,
        error_class: &str,
        error_detail: &str,
        transport: &str,
        next_attempt_after: DateTime<Utc>,
    ) -> Result<OutboundFailureOutcome, PersistOutboundError>;

    async fn mark_replay_resolved(&self, queue_id: &str) -> Result<(), PersistOutboundError>;

    async fn match_ack_to_outbound(
        &self,
        in_reply_to_sha256: &[u8; 32],
    ) -> Result<Option<OutboundRow>, PersistOutboundError>;

    async fn mark_ack_received(
        &self,
        queue_id: &str,
        ack_envelope_bytes: &[u8],
    ) -> Result<(), PersistOutboundError>;

    async fn sweep_ack_timeouts(&self) -> Result<i64, PersistOutboundError>;
    async fn sweep_ttl_expired(&self) -> Result<i64, PersistOutboundError>;
    async fn sweep_expired_claims(&self) -> Result<i64, PersistOutboundError>;

    async fn outbound_status(
        &self,
        queue_id: &str,
    ) -> Result<Option<OutboundRow>, PersistOutboundError>;

    async fn list_outbound(
        &self,
        filter: OutboundFilter,
        limit: i64,
    ) -> Result<Vec<OutboundRow>, PersistOutboundError>;
}

#[async_trait]
impl<Q: OutboundQueue + Send + Sync + 'static> OutboundHandle for Q {
    async fn enqueue_outbound(
        &self,
        sender_key_id: &str,
        destination_key_id: &str,
        message_type: &str,
        edge_schema_version: &str,
        envelope_bytes: &[u8],
        body_sha256: &[u8; 32],
        body_size_bytes: i32,
        requires_ack: bool,
        ack_timeout_seconds: Option<i64>,
        max_attempts: i32,
        ttl_seconds: i64,
        initial_next_attempt_after: DateTime<Utc>,
    ) -> Result<QueueId, PersistOutboundError> {
        OutboundQueue::enqueue_outbound(
            self,
            sender_key_id,
            destination_key_id,
            message_type,
            edge_schema_version,
            envelope_bytes,
            body_sha256,
            body_size_bytes,
            requires_ack,
            ack_timeout_seconds,
            max_attempts,
            ttl_seconds,
            initial_next_attempt_after,
        )
        .await
    }

    async fn claim_pending_outbound(
        &self,
        batch_size: i64,
        claim_duration_seconds: i64,
        claimed_by: &str,
    ) -> Result<Vec<OutboundRow>, PersistOutboundError> {
        OutboundQueue::claim_pending_outbound(self, batch_size, claim_duration_seconds, claimed_by)
            .await
    }

    async fn mark_transport_delivered(
        &self,
        queue_id: &str,
        transport: &str,
    ) -> Result<(), PersistOutboundError> {
        OutboundQueue::mark_transport_delivered(self, &queue_id.to_string(), transport).await
    }

    async fn mark_transport_failed(
        &self,
        queue_id: &str,
        error_class: &str,
        error_detail: &str,
        transport: &str,
        next_attempt_after: DateTime<Utc>,
    ) -> Result<OutboundFailureOutcome, PersistOutboundError> {
        OutboundQueue::mark_transport_failed(
            self,
            &queue_id.to_string(),
            error_class,
            error_detail,
            transport,
            next_attempt_after,
        )
        .await
    }

    async fn mark_replay_resolved(&self, queue_id: &str) -> Result<(), PersistOutboundError> {
        OutboundQueue::mark_replay_resolved(self, &queue_id.to_string()).await
    }

    async fn match_ack_to_outbound(
        &self,
        in_reply_to_sha256: &[u8; 32],
    ) -> Result<Option<OutboundRow>, PersistOutboundError> {
        OutboundQueue::match_ack_to_outbound(self, in_reply_to_sha256).await
    }

    async fn mark_ack_received(
        &self,
        queue_id: &str,
        ack_envelope_bytes: &[u8],
    ) -> Result<(), PersistOutboundError> {
        OutboundQueue::mark_ack_received(self, &queue_id.to_string(), ack_envelope_bytes).await
    }

    async fn sweep_ack_timeouts(&self) -> Result<i64, PersistOutboundError> {
        OutboundQueue::sweep_ack_timeouts(self).await
    }

    async fn sweep_ttl_expired(&self) -> Result<i64, PersistOutboundError> {
        OutboundQueue::sweep_ttl_expired(self).await
    }

    async fn sweep_expired_claims(&self) -> Result<i64, PersistOutboundError> {
        OutboundQueue::sweep_expired_claims(self).await
    }

    async fn outbound_status(
        &self,
        queue_id: &str,
    ) -> Result<Option<OutboundRow>, PersistOutboundError> {
        OutboundQueue::outbound_status(self, &queue_id.to_string()).await
    }

    async fn list_outbound(
        &self,
        filter: OutboundFilter,
        limit: i64,
    ) -> Result<Vec<OutboundRow>, PersistOutboundError> {
        OutboundQueue::list_outbound(self, filter, limit).await
    }
}

// ─── Dispatcher loop ────────────────────────────────────────────────

/// Dispatcher configuration. Tunable per deployment.
#[derive(Debug, Clone)]
pub struct DispatcherConfig {
    /// Worker identifier — written to `claimed_by` for forensics.
    pub worker_id: String,
    /// Max rows claimed per poll.
    pub batch_size: i64,
    /// Soft-claim duration; a row whose claim expires reverts to
    /// `pending` via `sweep_expired_claims`.
    pub claim_duration_seconds: i64,
    /// Sleep when no rows are pending. Trade-off: lower = faster
    /// reaction; higher = less DB churn.
    pub idle_poll_interval: Duration,
    /// Initial backoff on transport failure.
    pub initial_backoff: Duration,
    /// Backoff cap.
    pub max_backoff: Duration,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            worker_id: format!("edge-{}", uuid::Uuid::new_v4()),
            batch_size: 32,
            claim_duration_seconds: 30,
            idle_poll_interval: Duration::from_millis(500),
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(3600),
        }
    }
}

/// Compute next-attempt timestamp using exponential backoff with
/// jitter. `attempt` is the post-increment count (1, 2, 3...).
fn compute_next_attempt(attempt: i32, initial: Duration, max: Duration) -> DateTime<Utc> {
    let factor = 2_u32.saturating_pow(u32::try_from(attempt - 1).unwrap_or(0).min(20));
    let backoff_secs = initial.as_secs().saturating_mul(u64::from(factor));
    let capped = backoff_secs.min(max.as_secs());
    // Crude ±12.5% jitter via uuid randomness.
    let jitter_pct = (uuid::Uuid::new_v4().as_u128() % 25) as i64 - 12;
    let jittered = i64::try_from(capped).unwrap_or(i64::MAX) * (100 + jitter_pct) / 100;
    Utc::now() + chrono::Duration::seconds(jittered.max(1))
}

/// Run the outbound dispatcher loop. Returns when `shutdown` fires.
pub async fn run_dispatcher(
    queue: Arc<dyn OutboundHandle>,
    transports: Vec<Arc<dyn Transport>>,
    config: DispatcherConfig,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    if transports.is_empty() {
        tracing::warn!("dispatcher: no transports configured; outbound loop idle");
        return;
    }

    loop {
        if *shutdown.borrow() {
            tracing::info!("dispatcher: shutdown signal received");
            return;
        }

        let claimed = match queue
            .claim_pending_outbound(
                config.batch_size,
                config.claim_duration_seconds,
                &config.worker_id,
            )
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!(error = %e, "dispatcher: claim_pending_outbound failed");
                tokio::select! {
                    () = tokio::time::sleep(config.idle_poll_interval) => {}
                    _ = shutdown.changed() => {}
                }
                continue;
            }
        };

        if claimed.is_empty() {
            tokio::select! {
                () = tokio::time::sleep(config.idle_poll_interval) => {}
                _ = shutdown.changed() => {}
            }
            continue;
        }

        for row in claimed {
            dispatch_one(&*queue, &transports, &row, &config).await;
        }
    }
}

async fn dispatch_one(
    queue: &dyn OutboundHandle,
    transports: &[Arc<dyn Transport>],
    row: &OutboundRow,
    config: &DispatcherConfig,
) {
    // Transport selection: first configured transport for now.
    // TODO Phase 2 — per-row transport preference based on
    // destination's reachability map.
    let transport = &transports[0];
    let outcome = transport
        .send(&row.destination_key_id, &row.envelope_bytes)
        .await;

    let attempt = row.attempt_count + 1;

    match outcome {
        Ok(TransportSendOutcome::Delivered) => {
            if let Err(e) = queue
                .mark_transport_delivered(&row.queue_id, transport.id().0)
                .await
            {
                tracing::error!(
                    queue_id = ?row.queue_id, error = %e,
                    "dispatcher: mark_transport_delivered failed"
                );
            }
        }
        Ok(TransportSendOutcome::Reject { class, detail: _ }) if class == "replay_detected" => {
            // Receiver already has the message (idempotent recovery).
            if let Err(e) = queue.mark_replay_resolved(&row.queue_id).await {
                tracing::error!(
                    queue_id = ?row.queue_id, error = %e,
                    "dispatcher: mark_replay_resolved failed"
                );
            }
        }
        Ok(TransportSendOutcome::Reject { class, detail }) => {
            let next_attempt =
                compute_next_attempt(attempt, config.initial_backoff, config.max_backoff);
            if let Err(e) = queue
                .mark_transport_failed(
                    &row.queue_id,
                    &class,
                    &detail,
                    transport.id().0,
                    next_attempt,
                )
                .await
            {
                tracing::error!(
                    queue_id = ?row.queue_id, error = %e,
                    "dispatcher: mark_transport_failed failed"
                );
            }
        }
        Err(e) => {
            let class = match &e {
                TransportError::Unreachable(_) => "unreachable",
                TransportError::Timeout(_) => "timeout",
                TransportError::Config(_) => "config",
                TransportError::Io(_) => "io",
                TransportError::BodyTooLarge { .. } => "body_too_large",
            };
            let next_attempt =
                compute_next_attempt(attempt, config.initial_backoff, config.max_backoff);
            if let Err(err) = queue
                .mark_transport_failed(
                    &row.queue_id,
                    class,
                    &format!("{e}"),
                    transport.id().0,
                    next_attempt,
                )
                .await
            {
                tracing::error!(
                    queue_id = ?row.queue_id, error = %err,
                    "dispatcher: mark_transport_failed failed"
                );
            }
        }
    }
}

/// Run the periodic-sweep tasks. Spawned alongside `run_dispatcher`.
pub async fn run_sweeps(
    queue: Arc<dyn OutboundHandle>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut tick_ack = tokio::time::interval(Duration::from_secs(30));
    let mut tick_ttl = tokio::time::interval(Duration::from_secs(60));
    let mut tick_claim = tokio::time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tick_ack.tick() => {
                if let Err(e) = queue.sweep_ack_timeouts().await {
                    tracing::warn!(error = %e, "sweep_ack_timeouts failed");
                }
            }
            _ = tick_ttl.tick() => {
                if let Err(e) = queue.sweep_ttl_expired().await {
                    tracing::warn!(error = %e, "sweep_ttl_expired failed");
                }
            }
            _ = tick_claim.tick() => {
                if let Err(e) = queue.sweep_expired_claims().await {
                    tracing::warn!(error = %e, "sweep_expired_claims failed");
                }
            }
        }
    }
}
