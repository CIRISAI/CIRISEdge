//! CIRISEdge#960 — the outbound queue reached through persist's
//! `outbound_queue_ops_capsule`, never through a concrete backend.
//!
//! The raw `outbound_queue_capsule` hands edge a `BackendDispatch`: the
//! concrete `Arc<SqliteBackend>` / `Arc<PostgresBackend>` persist's `.so`
//! built. Every `OutboundQueue` method called on it is monomorphic, so it runs
//! EDGE's compiled copy of persist's backend code (edge's tokio, edge's
//! deadpool, edge's sqlite bindings) against objects laid out by the wheel.
//! A layout change in persist (CIRISPersist#1231: `persist_rt` became
//! `persist_timer` in 61.1) makes that undefined behaviour across a skew, and
//! twice it crashed (CIRISServer#705, the 44.0 cohabitation SIGSEGV).
//!
//! [`OpsOutboundQueue`] is the consumer half of persist's C-ABI queue
//! vtable, the mirror of `ciris_persist::ffi::directory_capsule::
//! build_ops_directory` for the directory. Each method serializes an
//! [`OutboundQueueOp`], calls `vtable.build_op` (which runs INSIDE persist's
//! `.so`, against persist's own compiled backend), spawns the returned task
//! through the same `executor_capsule`, and awaits the serialized
//! [`OutboundQueueOpResult`] on a oneshot. No persist internal runs on edge's
//! copy.
//!
//! The structured `ciris_persist::outbound::Error` does not cross the ABI:
//! persist flattens it to `Error::to_string()`. [`error_from_wire`] reads the
//! variant back from the message's leading text (the `#[error]` prefixes of
//! that enum), so a caller that branches on `NotFound` or
//! `InvalidTransition` sees the variant it saw on the concrete backend.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ciris_persist::ffi::executor_capsule::{AsyncExecutor, TaskOpaque};
use ciris_persist::ffi::outbound_queue_capsule::{
    OutboundQueueHandle, OutboundQueueOp, OutboundQueueOpResult, OUTBOUND_QUEUE_ABI_VERSION,
};
use ciris_persist::outbound::{
    Error as PersistOutboundError, OutboundFailureOutcome, OutboundFilter, OutboundRow,
    OutboundStatus, QueueId,
};

use crate::outbound::OutboundHandle;

/// The consumer-side [`OutboundHandle`] over a received
/// `outbound_queue_ops_capsule`. Holds a reference copy of the capsule's
/// `{ data, vtable }` (the PyCapsule destructor owns the drop, exactly as
/// for the directory and executor capsules) and the executor that spawns
/// each op onto persist's runtime.
pub struct OpsOutboundQueue {
    handle: OutboundQueueHandle,
    executor: Arc<AsyncExecutor>,
}

impl OpsOutboundQueue {
    /// Wrap a received queue capsule.
    ///
    /// # Errors
    ///
    /// The capsule's vtable `abi_version` is not the
    /// [`OUTBOUND_QUEUE_ABI_VERSION`] this edge was built against: a skewed
    /// wheel is refused before any op is dispatched through it.
    pub fn new(handle: OutboundQueueHandle, executor: Arc<AsyncExecutor>) -> Result<Self, String> {
        if handle.vtable.abi_version != OUTBOUND_QUEUE_ABI_VERSION {
            return Err(format!(
                "outbound queue ops proxy: capsule ABI version mismatch (capsule={}, \
                 expected={OUTBOUND_QUEUE_ABI_VERSION}) — ciris-persist pin skew",
                handle.vtable.abi_version
            ));
        }
        Ok(Self { handle, executor })
    }

    /// The C-ABI completion callback persist invokes exactly once, from a
    /// persist worker, when an op's future finishes.
    ///
    /// # Safety
    ///
    /// Invoked only as the `result_cb` handed to `build_op` in
    /// [`Self::run_op`]; that pairing is the only provenance of `ctx` and
    /// `(ptr, len)`.
    #[allow(unsafe_code)]
    unsafe extern "C" fn result_trampoline(ctx: *mut c_void, ptr: *const u8, len: usize) {
        // SAFETY: `ctx` is the `Box::into_raw`'d oneshot Sender `run_op`
        // created for THIS op; the `build_op` contract fires the callback
        // exactly once, so the Box is reclaimed exactly once.
        let tx = unsafe { Box::from_raw(ctx.cast::<tokio::sync::oneshot::Sender<Vec<u8>>>()) };
        // SAFETY: `(ptr, len)` name `len` readable bytes valid only for this
        // call; they are copied out before returning.
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
        // A dropped receiver means the awaiting call was cancelled; the
        // result is discarded.
        let _ = tx.send(bytes);
    }

    #[allow(unsafe_code)]
    async fn run_op(
        &self,
        op: &OutboundQueueOp,
    ) -> Result<OutboundQueueOpResult, PersistOutboundError> {
        let op_bytes = serde_json::to_vec(op).map_err(|e| {
            PersistOutboundError::Backend(format!("outbound queue ops proxy: op serialize: {e}"))
        })?;
        let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        let ctx: *mut c_void = Box::into_raw(Box::new(tx)).cast::<c_void>();
        // SAFETY: `handle` came from persist's `outbound_queue_ops_capsule`
        // and its `abi_version` was checked in `new`, so `data` and `vtable`
        // are a matched pair. `op_bytes` stays alive across the call
        // (`build_op` parses it synchronously). `result_trampoline` + `ctx`
        // meet the callback contract: `ctx` is a Send-able boxed Sender valid
        // until the callback fires once from a persist worker.
        let task: *mut TaskOpaque = unsafe {
            (self.handle.vtable.build_op)(
                self.handle.data,
                op_bytes.as_ptr(),
                op_bytes.len(),
                Self::result_trampoline,
                ctx,
            )
        };
        drop(op_bytes);
        // SAFETY: `task` is the boxed op-future this vtable's `build_op` just
        // returned, the shape `executor_capsule`'s `spawn` reconstructs, and
        // it is spawned exactly once. The executor capsule is alive (rooted
        // in the Python engine for the edge's lifetime).
        unsafe { (self.executor.vtable.spawn)(self.executor.data, task) };
        let result_bytes = rx.await.map_err(|_| {
            PersistOutboundError::Backend(
                "outbound queue ops proxy: op producer dropped without responding".into(),
            )
        })?;
        serde_json::from_slice::<OutboundQueueOpResult>(&result_bytes).map_err(|e| {
            PersistOutboundError::Backend(format!(
                "outbound queue ops proxy: result deserialize: {e}"
            ))
        })
    }
}

/// Read the structured error back from persist's flattened
/// `Error::to_string()`. The prefixes are the `#[error]` strings of
/// `ciris_persist::outbound::Error`; a message with none of them (an op
/// parse failure, a future variant) is a `Backend` error carrying the whole
/// text.
fn error_from_wire(msg: String) -> PersistOutboundError {
    if let Some(rest) = msg.strip_prefix("invalid argument: ") {
        PersistOutboundError::InvalidArgument(rest.to_string())
    } else if let Some(rest) = msg.strip_prefix("queue_id not found: ") {
        PersistOutboundError::NotFound(rest.to_string())
    } else if let Some(rest) = msg.strip_prefix("invalid state transition: ") {
        PersistOutboundError::InvalidTransition(rest.to_string())
    } else if let Some(rest) = msg.strip_prefix("backend: ") {
        PersistOutboundError::Backend(rest.to_string())
    } else {
        PersistOutboundError::Backend(msg)
    }
}

fn unexpected(op: &str, got: &OutboundQueueOpResult) -> PersistOutboundError {
    PersistOutboundError::Backend(format!(
        "outbound queue ops proxy: {op} answered an unexpected result variant: {got:?}"
    ))
}

#[async_trait]
impl OutboundHandle for OpsOutboundQueue {
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
        let op = OutboundQueueOp::EnqueueOutbound {
            sender_key_id: sender_key_id.to_string(),
            destination_key_id: destination_key_id.to_string(),
            message_type: message_type.to_string(),
            edge_schema_version: edge_schema_version.to_string(),
            envelope_bytes: envelope_bytes.to_vec(),
            body_sha256: *body_sha256,
            body_size_bytes,
            requires_ack,
            ack_timeout_seconds,
            max_attempts,
            ttl_seconds,
            initial_next_attempt_after,
        };
        match self.run_op(&op).await? {
            OutboundQueueOpResult::Enqueued(id) => Ok(id),
            OutboundQueueOpResult::Err(e) => Err(error_from_wire(e)),
            other => Err(unexpected("enqueue_outbound", &other)),
        }
    }

    async fn claim_pending_outbound(
        &self,
        batch_size: i64,
        claim_duration_seconds: i64,
        claimed_by: &str,
    ) -> Result<Vec<OutboundRow>, PersistOutboundError> {
        let op = OutboundQueueOp::ClaimPendingOutbound {
            batch_size,
            claim_duration_seconds,
            claimed_by: claimed_by.to_string(),
        };
        match self.run_op(&op).await? {
            OutboundQueueOpResult::Rows(rows) => Ok(rows),
            OutboundQueueOpResult::Err(e) => Err(error_from_wire(e)),
            other => Err(unexpected("claim_pending_outbound", &other)),
        }
    }

    async fn mark_transport_delivered(
        &self,
        queue_id: &str,
        transport: &str,
    ) -> Result<(), PersistOutboundError> {
        let op = OutboundQueueOp::MarkTransportDelivered {
            queue_id: queue_id.to_string(),
            transport: transport.to_string(),
        };
        self.unit("mark_transport_delivered", &op).await
    }

    async fn mark_transport_failed(
        &self,
        queue_id: &str,
        error_class: &str,
        error_detail: &str,
        transport: &str,
        next_attempt_after: DateTime<Utc>,
    ) -> Result<OutboundFailureOutcome, PersistOutboundError> {
        let op = OutboundQueueOp::MarkTransportFailed {
            queue_id: queue_id.to_string(),
            error_class: error_class.to_string(),
            error_detail: error_detail.to_string(),
            transport: transport.to_string(),
            next_attempt_after,
        };
        match self.run_op(&op).await? {
            OutboundQueueOpResult::FailureOutcome(o) => Ok(o),
            OutboundQueueOpResult::Err(e) => Err(error_from_wire(e)),
            other => Err(unexpected("mark_transport_failed", &other)),
        }
    }

    async fn mark_replay_resolved(&self, queue_id: &str) -> Result<(), PersistOutboundError> {
        let op = OutboundQueueOp::MarkReplayResolved {
            queue_id: queue_id.to_string(),
        };
        self.unit("mark_replay_resolved", &op).await
    }

    async fn match_ack_to_outbound(
        &self,
        in_reply_to_sha256: &[u8; 32],
    ) -> Result<Option<OutboundRow>, PersistOutboundError> {
        let op = OutboundQueueOp::MatchAckToOutbound {
            in_reply_to_sha256: *in_reply_to_sha256,
        };
        self.maybe_row("match_ack_to_outbound", &op).await
    }

    async fn mark_ack_received(
        &self,
        queue_id: &str,
        ack_envelope_bytes: &[u8],
    ) -> Result<(), PersistOutboundError> {
        let op = OutboundQueueOp::MarkAckReceived {
            queue_id: queue_id.to_string(),
            ack_envelope_bytes: ack_envelope_bytes.to_vec(),
        };
        self.unit("mark_ack_received", &op).await
    }

    async fn sweep_ack_timeouts(&self) -> Result<i64, PersistOutboundError> {
        self.count("sweep_ack_timeouts", &OutboundQueueOp::SweepAckTimeouts {})
            .await
    }

    async fn sweep_ttl_expired(&self) -> Result<i64, PersistOutboundError> {
        self.count("sweep_ttl_expired", &OutboundQueueOp::SweepTtlExpired {})
            .await
    }

    async fn sweep_expired_claims(&self) -> Result<i64, PersistOutboundError> {
        self.count(
            "sweep_expired_claims",
            &OutboundQueueOp::SweepExpiredClaims {},
        )
        .await
    }

    async fn outbound_status(
        &self,
        queue_id: &str,
    ) -> Result<Option<OutboundRow>, PersistOutboundError> {
        let op = OutboundQueueOp::OutboundStatusOf {
            queue_id: queue_id.to_string(),
        };
        self.maybe_row("outbound_status", &op).await
    }

    async fn list_outbound(
        &self,
        filter: OutboundFilter,
        limit: i64,
    ) -> Result<Vec<OutboundRow>, PersistOutboundError> {
        match self
            .run_op(&OutboundQueueOp::ListOutbound { filter, limit })
            .await?
        {
            OutboundQueueOpResult::Rows(rows) => Ok(rows),
            OutboundQueueOpResult::Err(e) => Err(error_from_wire(e)),
            other => Err(unexpected("list_outbound", &other)),
        }
    }

    async fn outbound_counts(&self) -> Result<HashMap<OutboundStatus, u64>, PersistOutboundError> {
        match self.run_op(&OutboundQueueOp::OutboundCounts {}).await? {
            OutboundQueueOpResult::Counts(c) => Ok(c),
            OutboundQueueOpResult::Err(e) => Err(error_from_wire(e)),
            other => Err(unexpected("outbound_counts", &other)),
        }
    }
}

impl OpsOutboundQueue {
    async fn unit(&self, name: &str, op: &OutboundQueueOp) -> Result<(), PersistOutboundError> {
        match self.run_op(op).await? {
            OutboundQueueOpResult::Unit => Ok(()),
            OutboundQueueOpResult::Err(e) => Err(error_from_wire(e)),
            other => Err(unexpected(name, &other)),
        }
    }

    async fn count(&self, name: &str, op: &OutboundQueueOp) -> Result<i64, PersistOutboundError> {
        match self.run_op(op).await? {
            OutboundQueueOpResult::Count(n) => Ok(n),
            OutboundQueueOpResult::Err(e) => Err(error_from_wire(e)),
            other => Err(unexpected(name, &other)),
        }
    }

    async fn maybe_row(
        &self,
        name: &str,
        op: &OutboundQueueOp,
    ) -> Result<Option<OutboundRow>, PersistOutboundError> {
        match self.run_op(op).await? {
            OutboundQueueOpResult::MaybeRow(row) => Ok(row),
            OutboundQueueOpResult::Err(e) => Err(error_from_wire(e)),
            other => Err(unexpected(name, &other)),
        }
    }
}

#[cfg(test)]
mod tests {
    //! The proxy against persist's own vtable, in-process: every
    //! `OutboundHandle` method round-trips through `build_op` + the executor
    //! and answers what the concrete backend answers.

    use super::*;
    use ciris_persist::ffi::outbound_queue_capsule::build_persist_outbound_queue;
    use ciris_persist::store::Backend as _;

    #[test]
    fn error_from_wire_reads_every_variant_back() {
        for e in [
            PersistOutboundError::InvalidArgument("a".into()),
            PersistOutboundError::NotFound("q1".into()),
            PersistOutboundError::InvalidTransition("t".into()),
            PersistOutboundError::Backend("b".into()),
        ] {
            let back = error_from_wire(e.to_string());
            assert_eq!(
                std::mem::discriminant(&back),
                std::mem::discriminant(&e),
                "{e} -> {back}"
            );
            assert_eq!(back.to_string(), e.to_string());
        }
        assert!(matches!(
            error_from_wire("outbound op parse failure: x".into()),
            PersistOutboundError::Backend(m) if m == "outbound op parse failure: x"
        ));
    }

    #[test]
    fn a_skewed_abi_version_is_refused() {
        // A vtable copy whose version is not ours: `new` refuses it before
        // any op could be dispatched.
        static SKEWED: ciris_persist::ffi::outbound_queue_capsule::OutboundQueueVTable =
            ciris_persist::ffi::outbound_queue_capsule::OutboundQueueVTable {
                abi_version: OUTBOUND_QUEUE_ABI_VERSION + 1,
                _reserved: 0,
                build_op: ciris_persist::ffi::outbound_queue_capsule::PERSIST_OUTBOUND_QUEUE_VTABLE
                    .build_op,
                drop: ciris_persist::ffi::outbound_queue_capsule::PERSIST_OUTBOUND_QUEUE_VTABLE
                    .drop,
            };
        let rt = Arc::new(tokio::runtime::Runtime::new().expect("runtime"));
        let executor =
            Arc::new(ciris_persist::ffi::executor_capsule::build_persist_executor(Arc::clone(&rt)));
        let handle = OutboundQueueHandle {
            data: std::ptr::null_mut(),
            vtable: &SKEWED,
        };
        let err = OpsOutboundQueue::new(handle, executor)
            .err()
            .expect("a skewed ABI version is refused");
        assert!(err.contains("ABI version mismatch"), "{err}");
    }

    #[test]
    fn every_op_round_trips_through_the_vtable() {
        let rt = Arc::new(tokio::runtime::Runtime::new().expect("runtime"));
        let executor =
            Arc::new(ciris_persist::ffi::executor_capsule::build_persist_executor(Arc::clone(&rt)));
        rt.block_on(async {
            let backend = ciris_persist::prelude::FederationDirectorySqlite::open(":memory:")
                .await
                .expect("open sqlite");
            backend.run_migrations().await.expect("migrate");
            let handle =
                build_persist_outbound_queue(ciris_persist::BackendDispatch::Sqlite(backend));
            let q = OpsOutboundQueue::new(handle, Arc::clone(&executor)).expect("abi matches");

            // An unknown row is the typed NotFound / None, as on the backend.
            assert!(q
                .outbound_status("no-such-row")
                .await
                .expect("status")
                .is_none());
            assert!(q
                .match_ack_to_outbound(&[7u8; 32])
                .await
                .expect("ack")
                .is_none());
            assert_eq!(q.sweep_ack_timeouts().await.expect("sweep"), 0);
            assert_eq!(q.sweep_ttl_expired().await.expect("sweep"), 0);
            assert_eq!(q.sweep_expired_claims().await.expect("sweep"), 0);
            assert!(q.outbound_counts().await.expect("counts").is_empty());
            assert!(q
                .claim_pending_outbound(10, 30, "w")
                .await
                .expect("claim")
                .is_empty());
            assert!(q
                .list_outbound(OutboundFilter::default(), 10)
                .await
                .expect("list")
                .is_empty());
            // A refused argument comes back as the variant the backend raised.
            let refused = q
                .enqueue_outbound(
                    "s",
                    "d",
                    "opaque_event",
                    "2.0.0",
                    &[],
                    &[0u8; 32],
                    0,
                    false,
                    None,
                    3,
                    60,
                    Utc::now(),
                )
                .await
                .expect_err("a zero-length envelope is refused");
            assert!(
                matches!(refused, PersistOutboundError::InvalidArgument(_)),
                "{refused:?}"
            );
        });
        drop(executor);
    }
}
