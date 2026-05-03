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
use ciris_persist::outbound::Error as PersistOutboundError;
use ciris_persist::prelude::{
    OutboundFailureOutcome, OutboundFilter, OutboundQueue, OutboundRow, QueueId,
};

use crate::transport::{Transport, TransportError, TransportSendOutcome};

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
