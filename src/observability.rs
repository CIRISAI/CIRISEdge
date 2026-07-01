//! Observability — structured logs + OTLP metrics + health probes.
//!
//! Mission: every message in or out is auditable. Federation trust
//! requires that any peer can answer "what did you receive, what did
//! you send, what was the verify outcome, when, from whom" — without
//! forensic archaeology.
//! ([`MISSION.md`](../../MISSION.md) §2 `observability/`.)
//!
//! # CIRISEdge#28 v0.19.0 — Observability surface
//!
//! Three load-bearing capabilities ship in this cut:
//!
//! 1. **Tracing spans** — `tracing::instrument` annotations on every
//!    `Edge::send*` / `dispatch_inbound` / transport `send` call site,
//!    with structured fields (`recipient_key_id`, `message_type`,
//!    `delivery_class`, `transport_id`, `signing_key_id`,
//!    `body_sha256_prefix`, `verify_outcome`, `attempt_n`). Consumers
//!    (CIRISLens, CIRISAgent UI) tail the tracing-subscriber-emitted
//!    structured logs and join on the same fields persist's forensic
//!    indices key on.
//!
//! 2. **EdgeMetrics struct** — a snapshot-able counter / gauge bag
//!    living on [`crate::Edge`]. Every send / receive / verify-failure
//!    / transport-bytes path increments the appropriate counter; the
//!    `metrics_snapshot` reads project the live state into a typed
//!    `EdgeMetricsBundle` consumers (PyO3 / UniFFI) can render. The
//!    struct uses `Arc<parking_lot::RwLock<HashMap<...>>>` per the
//!    Cargo.toml note — `parking_lot` is already a v0.11.0 dep
//!    (CIRISEdge#29 `ReachabilityTracker`); `dashmap` is intentionally
//!    NOT pulled (extra license surface + the contention pattern
//!    counter-bumps produce doesn't justify a sharded map).
//!
//! 3. **Pymethod surface** — [`crate::ffi::pyo3::PyEdge::metrics_snapshot`]
//!    returns a Python `dict` of `dict`s; consumers call it repeatedly
//!    for change-detection. The shape is documented on the pymethod.
//!
//! # Structured log fields (per-message)
//!
//! - `signing_key_id` — sender's federation_keys.key_id
//! - `body_sha256_prefix` — joins to persist's forensic indices
//!   (Bridge already trained on this join key during the v0.2.x
//!   debug)
//! - `verify_result` — typed reject code or `verified`
//! - `handler_duration_ms` — handler-time, excludes verify
//! - `transport` — TransportId (http / reticulum-rs / lora / ...)
//!
//! # Counter labels
//!
//! Stable label cardinality:
//!
//! - `envelopes_sent_total[MessageType]` — every successful send/enqueue
//! - `envelopes_received_total[MessageType]` — every verified inbound envelope
//! - `send_failures_total[(TransportId, ErrorClass)]` — typed transport faults
//! - `verify_failures_total[VerifyErrorClass]` — typed verify pipeline rejects
//! - `transport_bytes_in_total[TransportId]` — bytes-counted by the
//!   listener side
//! - `transport_bytes_out_total[TransportId]` — bytes-counted by the
//!   send side
//!
//! Gauges:
//!
//! - `durable_queue_depth[DeliveryClass]` — count of currently-queued
//!   send_durable / send_mandatory / send_federation envelopes
//! - `peer_reachability_ratio[(peer_key_id, medium)]` — rolling
//!   reachability window ratio, mirror of `ReachabilityTracker::snapshot_all`

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::messages::MessageType;
use crate::transport::TransportId;

/// Classification of a `VerifyError` for metrics labelling. Mirrors
/// the discriminator on [`crate::verify::VerifyError`] but is `Copy +
/// Eq + Hash` so it can sit in a `HashMap` key. Strings (the typed
/// `VerifyError` payload) are deliberately excluded — high-cardinality
/// label values explode metric storage downstream (Prometheus / OTLP),
/// and the classification is the load-bearing dimension consumers
/// alert on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerifyErrorClass {
    BodyTooLarge,
    SchemaInvalid,
    UnsupportedSchemaVersion,
    Misrouted,
    ReplayDetected,
    UnknownKey,
    SignatureMismatch,
    PqcPendingStrictReject,
    CanonicalizationFailed,
    VerifyUnavailable,
    ContentIntegrity,
}

impl VerifyErrorClass {
    /// Snake-case stable label string. Used as the dict-key on the
    /// PyO3 `metrics_snapshot` surface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BodyTooLarge => "body_too_large",
            Self::SchemaInvalid => "schema_invalid",
            Self::UnsupportedSchemaVersion => "unsupported_schema_version",
            Self::Misrouted => "misrouted",
            Self::ReplayDetected => "replay_detected",
            Self::UnknownKey => "unknown_key",
            Self::SignatureMismatch => "signature_mismatch",
            Self::PqcPendingStrictReject => "pqc_pending_strict_reject",
            Self::CanonicalizationFailed => "canonicalization_failed",
            Self::VerifyUnavailable => "verify_unavailable",
            Self::ContentIntegrity => "content_integrity",
        }
    }

    /// Classify a live [`crate::verify::VerifyError`] for counter
    /// labelling. Lives here (not on `VerifyError`) so the metrics
    /// taxonomy can evolve independently of the typed error tree.
    #[must_use]
    pub fn from_verify_error(e: &crate::verify::VerifyError) -> Self {
        use crate::verify::VerifyError as V;
        match e {
            V::BodyTooLarge { .. } => Self::BodyTooLarge,
            V::SchemaInvalid(_) => Self::SchemaInvalid,
            V::UnsupportedSchemaVersion(_) => Self::UnsupportedSchemaVersion,
            V::Misrouted => Self::Misrouted,
            V::ReplayDetected => Self::ReplayDetected,
            V::UnknownKey(_) => Self::UnknownKey,
            V::SignatureMismatch(_) => Self::SignatureMismatch,
            V::PqcPendingStrictReject => Self::PqcPendingStrictReject,
            V::CanonicalizationFailed(_) => Self::CanonicalizationFailed,
            V::VerifyUnavailable(_) => Self::VerifyUnavailable,
            V::ContentIntegrity { .. } => Self::ContentIntegrity,
        }
    }
}

/// Delivery-class discriminator for the durable-queue gauge.
/// Distinct from [`crate::handler::Delivery`] (the type-level message
/// trait) — this is the runtime label used in the metric key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeliveryClass {
    Ephemeral,
    Durable,
    Mandatory,
    Federation,
}

impl DeliveryClass {
    /// Snake-case stable label string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ephemeral => "ephemeral",
            Self::Durable => "durable",
            Self::Mandatory => "mandatory",
            Self::Federation => "federation",
        }
    }
}

/// The live counter/gauge bag every [`crate::Edge`] owns.
///
/// # Concurrency
///
/// Every field is `Arc<RwLock<HashMap<_, _>>>` over `parking_lot::RwLock`
/// — uncontended write path is ~20ns (parking_lot is already on the
/// dep graph for [`crate::ReachabilityTracker`]; no new license surface).
/// `dashmap` was rejected for the same Cargo.toml-§125 reasoning the
/// reachability tracker captured: extra license surface, contention-
/// tuning we don't need.
///
/// # Cloning
///
/// `EdgeMetrics` is `Clone`; every field is an `Arc`, so a clone is
/// cheap. [`crate::Edge`] stores one and threads clones into
/// `dispatch_inbound` / the durable dispatcher loop / transport listen
/// loops.
#[derive(Debug, Clone, Default)]
pub struct EdgeMetrics {
    /// Per-[`MessageType`] count of envelopes the local edge has
    /// successfully signed + offered to a transport (or enqueued, for
    /// durable / mandatory / federation classes). Incremented at the
    /// success exit of [`crate::Edge::send`] / `send_durable` /
    /// `send_mandatory` / `send_federation`.
    pub envelopes_sent_total: Arc<RwLock<HashMap<MessageType, u64>>>,
    /// Per-[`MessageType`] count of envelopes the local edge has
    /// successfully verified at the inbound path. Incremented in
    /// `dispatch_inbound` after a successful `VerifyPipeline::verify`,
    /// keyed on the verified envelope's `message_type` field.
    pub envelopes_received_total: Arc<RwLock<HashMap<MessageType, u64>>>,
    /// Per-(transport, error-class) count of failed sends. The
    /// `String` is the snake-case error class produced by the same
    /// `transport_error_class` mapping the reachability tracker uses
    /// (`unreachable`, `timeout`, `config`, `io`, `body_too_large`,
    /// `peer_blackholed`).
    pub send_failures_total: Arc<RwLock<HashMap<(TransportId, String), u64>>>,
    /// Per-[`VerifyErrorClass`] count of inbound verify rejects.
    /// Incremented in `dispatch_inbound` when `VerifyPipeline::verify`
    /// returns `Err`.
    pub verify_failures_total: Arc<RwLock<HashMap<VerifyErrorClass, u64>>>,
    /// Gauge — current count of in-flight durable-class envelopes
    /// per delivery class. Incremented at enqueue, decremented at
    /// dispatch (success OR terminal abandon).
    ///
    /// **Note**: v0.19.0 wires the increment side only — the
    /// dispatcher's terminal-state handling lives on persist's
    /// `OutboundHandle` surface, and the bookkeeping there isn't
    /// edge-internal. The gauge captures cumulative enqueues and
    /// consumers diff it against the persist-side `queue_depth` UDL
    /// read for the resident count. The metric name was held stable
    /// for downstream consumers; the semantic gap is documented on
    /// the pymethod surface.
    pub durable_queue_depth: Arc<RwLock<HashMap<DeliveryClass, u64>>>,
    /// Per-transport byte count for inbound frames. Incremented by
    /// the inbound listener side when it pushes an [`crate::transport::InboundFrame`].
    pub transport_bytes_in_total: Arc<RwLock<HashMap<TransportId, u64>>>,
    /// Per-transport byte count for outbound envelopes. Incremented
    /// at the success exit of [`crate::transport::Transport::send`]
    /// invocations (`Edge::send` direct path, durable dispatcher loop).
    pub transport_bytes_out_total: Arc<RwLock<HashMap<TransportId, u64>>>,
    /// Gauge — per-(peer, medium) reachability ratio. Mirror of the
    /// reachability tracker; consumers can read the mirror without
    /// reaching across to [`crate::ReachabilityTracker`].
    pub peer_reachability_ratio: Arc<RwLock<HashMap<(String, String), f64>>>,
    /// CIRISEdge#48-B (v0.19.6) — count of inbound envelopes dropped
    /// at `dispatch_inbound` because the verified sender's trust
    /// score fell below [`crate::EdgeConfig::trust_threshold`].
    /// Incremented only on the dispatch-time drop path; envelopes
    /// admitted at-or-above threshold do NOT touch this counter.
    /// Single `Arc<AtomicU64>` (not a per-key bag) — the offending
    /// `signing_key_id` already rides on the matching
    /// `EventKind::TrustShortCircuited` event.
    pub inbound_dropped_low_trust: Arc<std::sync::atomic::AtomicU64>,
}

impl EdgeMetrics {
    /// Construct an empty metric bag.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the `envelopes_sent_total` counter for `mt`.
    pub fn inc_sent(&self, mt: &MessageType) {
        let mut guard = self.envelopes_sent_total.write();
        *guard.entry(mt.clone()).or_insert(0) += 1;
    }

    /// Increment the `envelopes_received_total` counter for `mt`.
    pub fn inc_received(&self, mt: &MessageType) {
        let mut guard = self.envelopes_received_total.write();
        *guard.entry(mt.clone()).or_insert(0) += 1;
    }

    /// Increment the `send_failures_total` counter for the
    /// (transport, error-class) pair.
    pub fn inc_send_failure(&self, transport: TransportId, error_class: &str) {
        let mut guard = self.send_failures_total.write();
        *guard
            .entry((transport, error_class.to_string()))
            .or_insert(0) += 1;
    }

    /// Increment the `verify_failures_total` counter for `class`.
    pub fn inc_verify_failure(&self, class: VerifyErrorClass) {
        let mut guard = self.verify_failures_total.write();
        *guard.entry(class).or_insert(0) += 1;
    }

    /// Add `bytes` to the inbound byte counter for `transport`.
    pub fn add_bytes_in(&self, transport: TransportId, bytes: u64) {
        let mut guard = self.transport_bytes_in_total.write();
        *guard.entry(transport).or_insert(0) += bytes;
    }

    /// Add `bytes` to the outbound byte counter for `transport`.
    pub fn add_bytes_out(&self, transport: TransportId, bytes: u64) {
        let mut guard = self.transport_bytes_out_total.write();
        *guard.entry(transport).or_insert(0) += bytes;
    }

    /// Record an enqueue against the durable-queue gauge.
    pub fn inc_durable_queue(&self, class: DeliveryClass) {
        let mut guard = self.durable_queue_depth.write();
        *guard.entry(class).or_insert(0) += 1;
    }

    /// CIRISEdge#48-B (v0.19.6) — increment the
    /// `inbound_dropped_low_trust` counter. Called from
    /// `dispatch_inbound` once per drop.
    pub fn inc_inbound_dropped_low_trust(&self) {
        self.inbound_dropped_low_trust
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// CIRISEdge#48-B (v0.19.6) — read the
    /// `inbound_dropped_low_trust` counter. Used by tests + the
    /// metrics snapshot projection.
    #[must_use]
    pub fn inbound_dropped_low_trust(&self) -> u64 {
        self.inbound_dropped_low_trust
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Update the per-peer reachability ratio gauge. Replaces (does
    /// not accumulate) — the underlying tracker computes the rolling
    /// ratio and the gauge mirrors it.
    pub fn set_peer_reachability(&self, peer_key_id: &str, medium: &str, ratio: f64) {
        let mut guard = self.peer_reachability_ratio.write();
        guard.insert((peer_key_id.to_string(), medium.to_string()), ratio);
    }

    /// Snapshot all counters + gauges as plain `HashMap`s — the
    /// projection consumers (PyO3 / UniFFI / Prometheus exposition)
    /// render into their respective wire shapes. Each `HashMap` is a
    /// fresh clone of the live state; the live map is unlocked
    /// immediately after the clone so emitters aren't blocked across
    /// the projection step.
    #[must_use]
    pub fn snapshot(&self) -> EdgeMetricsBundle {
        EdgeMetricsBundle {
            envelopes_sent_total: self.envelopes_sent_total.read().clone(),
            envelopes_received_total: self.envelopes_received_total.read().clone(),
            send_failures_total: self.send_failures_total.read().clone(),
            verify_failures_total: self.verify_failures_total.read().clone(),
            durable_queue_depth: self.durable_queue_depth.read().clone(),
            transport_bytes_in_total: self.transport_bytes_in_total.read().clone(),
            transport_bytes_out_total: self.transport_bytes_out_total.read().clone(),
            peer_reachability_ratio: self.peer_reachability_ratio.read().clone(),
            inbound_dropped_low_trust: self.inbound_dropped_low_trust(),
        }
    }
}

/// Point-in-time projection of [`EdgeMetrics`]. Returned by
/// [`EdgeMetrics::snapshot`]; consumed by the PyO3 / UniFFI projection
/// methods. Owned `HashMap`s — emitters can keep writing through the
/// underlying `Arc<RwLock<_>>` while a consumer renders the bundle.
#[derive(Debug, Clone, Default)]
pub struct EdgeMetricsBundle {
    pub envelopes_sent_total: HashMap<MessageType, u64>,
    pub envelopes_received_total: HashMap<MessageType, u64>,
    pub send_failures_total: HashMap<(TransportId, String), u64>,
    pub verify_failures_total: HashMap<VerifyErrorClass, u64>,
    pub durable_queue_depth: HashMap<DeliveryClass, u64>,
    pub transport_bytes_in_total: HashMap<TransportId, u64>,
    pub transport_bytes_out_total: HashMap<TransportId, u64>,
    pub peer_reachability_ratio: HashMap<(String, String), f64>,
    /// CIRISEdge#48-B (v0.19.6) — cumulative count of envelopes
    /// dropped at `dispatch_inbound` due to trust short-circuit.
    pub inbound_dropped_low_trust: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::MessageType;
    use crate::transport::TransportId;

    #[test]
    fn inc_sent_accumulates_per_message_type() {
        let m = EdgeMetrics::new();
        m.inc_sent(&MessageType::OpaqueEvent);
        m.inc_sent(&MessageType::OpaqueEvent);
        m.inc_sent(&MessageType::FederationAnnouncement);
        let snap = m.snapshot();
        assert_eq!(snap.envelopes_sent_total[&MessageType::OpaqueEvent], 2);
        assert_eq!(
            snap.envelopes_sent_total[&MessageType::FederationAnnouncement],
            1
        );
    }

    #[test]
    fn send_failure_keyed_by_transport_and_error_class() {
        let m = EdgeMetrics::new();
        m.inc_send_failure(TransportId::RETICULUM_RS, "unreachable");
        m.inc_send_failure(TransportId::RETICULUM_RS, "unreachable");
        m.inc_send_failure(TransportId::HTTP, "timeout");
        let snap = m.snapshot();
        assert_eq!(
            snap.send_failures_total[&(TransportId::RETICULUM_RS, "unreachable".to_string())],
            2
        );
        assert_eq!(
            snap.send_failures_total[&(TransportId::HTTP, "timeout".to_string())],
            1
        );
    }

    #[test]
    fn verify_failure_class_from_verify_error_taxonomy() {
        use crate::verify::VerifyError;
        let cases = [
            (VerifyError::Misrouted, VerifyErrorClass::Misrouted),
            (
                VerifyError::ReplayDetected,
                VerifyErrorClass::ReplayDetected,
            ),
            (
                VerifyError::UnknownKey("k".into()),
                VerifyErrorClass::UnknownKey,
            ),
            (
                VerifyError::SignatureMismatch("s".into()),
                VerifyErrorClass::SignatureMismatch,
            ),
        ];
        for (e, want) in cases {
            assert_eq!(VerifyErrorClass::from_verify_error(&e), want);
        }
    }

    #[test]
    fn bytes_in_out_counted_per_transport() {
        let m = EdgeMetrics::new();
        m.add_bytes_in(TransportId::RETICULUM_RS, 1024);
        m.add_bytes_in(TransportId::RETICULUM_RS, 2048);
        m.add_bytes_out(TransportId::HTTP, 512);
        let snap = m.snapshot();
        assert_eq!(
            snap.transport_bytes_in_total[&TransportId::RETICULUM_RS],
            3072
        );
        assert_eq!(snap.transport_bytes_out_total[&TransportId::HTTP], 512);
    }

    #[test]
    fn peer_reachability_gauge_replaces_not_accumulates() {
        let m = EdgeMetrics::new();
        m.set_peer_reachability("peer-1", "reticulum-rs", 0.5);
        m.set_peer_reachability("peer-1", "reticulum-rs", 0.9);
        let snap = m.snapshot();
        let v = snap.peer_reachability_ratio[&("peer-1".to_string(), "reticulum-rs".to_string())];
        assert!((v - 0.9).abs() < f64::EPSILON);
    }
}
