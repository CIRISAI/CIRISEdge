//! Per-medium reachability substrate (CIRISEdge#29; v0.11.0).
//!
//! Tracks delivery success per `(peer_key_id, TransportId)` tuple via
//! in-process ring-buffer counters bounded by a rolling time window.
//! Precursor to CIRISEdge#22 Tier 3's `peer_reachability` pymethod —
//! that surface (the Python `dict[str, float]` of medium → ratio) is
//! NOT exposed in this scope; the sibling agent's FFI bundle (#31 +
//! #34 + #35) owns `src/ffi/pyo3.rs`. This module exposes the public
//! Rust API + `Arc<ReachabilityTracker>` on [`crate::Edge`] so that
//! the pyo3 consumer in v0.16.0 can call [`ReachabilityTracker::snapshot`]
//! / [`ReachabilityTracker::snapshot_all`] and shape the result into
//! a `PyDict` without re-implementing the bookkeeping.
//!
//! # Consumer contract (locked surface for #22 Tier 3 / v0.16.0)
//!
//! ```ignore
//! // Per-peer, every medium that has carried at least one attempt to
//! // this peer in the rolling window. Empty map → no measurement yet
//! // (consumer SHOULD render "unknown" not "0.0").
//! let snap: HashMap<TransportId, PeerMediumReachability> =
//!     edge.reachability_tracker().snapshot(peer_key_id);
//!
//! // Federation-wide snapshot — every (peer, medium) the tracker has
//! // observed. Drives the Trust Topology drilldown UI.
//! let all: Vec<PeerMediumReachability> =
//!     edge.reachability_tracker().snapshot_all();
//! ```
//!
//! Per CIRIS Accord Meta-Goal M-1 (adaptive coherence): the
//! federation's resilience depends on knowing which transports are
//! working with which peers. Without measurement, "adaptive" is
//! aspirational.
//!
//! # Hook sites (for cross-reference)
//!
//! - `src/edge.rs::Edge::send` — ephemeral send-path completion.
//! - `src/edge.rs::dispatch_one_with_tracker` (outbound) — durable
//!   queue dispatcher: Delivered → success, Reject/Err → failure
//!   (a Delivered terminal in the durable queue is the strongest
//!   evidence outside of an explicit DeliveryAttestation).
//! - `src/edge.rs::dispatch_inbound` — when a verified
//!   [`crate::MessageType::DeliveryAttestation`] envelope names a
//!   peer, that's the strongest evidence (the peer cryptographically
//!   confirmed receipt) — records `AttestationReceived`.
//! - `src/transport/reticulum.rs::resolve_announce_cold_start` —
//!   when a peer's announce attestation roots successfully, records
//!   `AnnounceReceived` (passive, lower-weight evidence: the peer is
//!   on the air, but we haven't actually delivered to them yet).
//!
//! # Storage
//!
//! In-process. **No persist substrate** — per CIRISEdge#29 scope
//! "in-process ring buffer for the rolling window (don't bloat persist
//! with per-attempt rows)". An aggregate-rollup persist substrate is
//! a follow-up (filed as `persist#NN` when this tracker stabilizes —
//! the issue body §"Optional persistence" deferral).

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;

use crate::transport::TransportId;

// ─── Outcome taxonomy ───────────────────────────────────────────────

/// One observed delivery outcome for a `(peer, medium)` tuple.
///
/// The variants are the four wire-shaped evidence classes plus the
/// two passive-evidence classes:
///
/// 1. **`SendSuccess`** — `Transport::send` returned `Ok(Delivered)`
///    on an ephemeral send. The transport accepted the bytes; the
///    peer MAY or may not have actually processed them (no
///    DeliveryAttestation for ephemeral sends).
/// 2. **`SendFailure`** — `Transport::send` returned `Err(_)` or
///    `Ok(Reject)`. Carries the typed error class so the snapshot's
///    `last_error_class` surfaces the most recent failure category to
///    the Trust Topology drilldown.
/// 3. **`DurableDelivered`** — a durable queue row transitioned to
///    `Delivered` (FSD/EDGE_OUTBOUND_QUEUE.md §4). Stronger than
///    `SendSuccess` because the durable dispatcher only marks
///    Delivered after the transport-tier ack (Reticulum: ResourceCompleted
///    on sender side).
/// 4. **`DurableAbandoned`** — a durable queue row transitioned to
///    `Abandoned` (max_attempts or ttl_expired). Carries the reason
///    string for the same diagnostic surface as `SendFailure`.
/// 5. **`AttestationReceived`** — the strongest evidence class. The
///    peer cryptographically confirmed delivery via a
///    `DeliveryAttestation` envelope. Counts as both an attempt and
///    a success.
/// 6. **`AnnounceReceived`** — the weakest evidence class. The peer
///    is on the air (its announce attestation rooted) but no delivery
///    has been confirmed. Counts as an attempt+success so a peer that
///    is reachable but has had no traffic still shows reachable; if
///    real traffic is failing the failure outcomes will outweigh.
#[derive(Debug, Clone)]
pub enum AttemptOutcome {
    /// `Transport::send` returned `Ok(Delivered)` on an ephemeral send.
    SendSuccess,
    /// `Transport::send` returned `Err(_)` or `Ok(Reject)`. The
    /// `error_class` is the [`crate::TransportError`] variant name or
    /// the reject class string.
    SendFailure { error_class: String },
    /// Durable queue row → `Delivered` terminal.
    DurableDelivered,
    /// Durable queue row → `Abandoned` terminal.
    DurableAbandoned { reason: String },
    /// Peer cryptographically confirmed receipt via
    /// `DeliveryAttestation`. Strongest evidence.
    AttestationReceived,
    /// Peer's announce attestation rooted successfully. Weakest
    /// evidence — proof of liveness, not of delivery.
    AnnounceReceived,
}

impl AttemptOutcome {
    /// Whether this outcome counts as a "success" in the
    /// `successes / attempts` ratio. Failures are explicitly the only
    /// false case — everything else (including the passive
    /// `AnnounceReceived` signal) is evidence of reachability.
    #[must_use]
    pub fn is_success(&self) -> bool {
        !matches!(
            self,
            Self::SendFailure { .. } | Self::DurableAbandoned { .. }
        )
    }

    /// Diagnostic string for the `last_error_class` field on
    /// [`PeerMediumReachability`]. `Some(_)` only for failure
    /// outcomes; `None` for successes (so a failure followed by a
    /// success leaves the snapshot showing only the residual failure
    /// class until evicted by the window).
    #[must_use]
    pub fn error_class(&self) -> Option<String> {
        match self {
            Self::SendFailure { error_class } => Some(error_class.clone()),
            Self::DurableAbandoned { reason } => Some(reason.clone()),
            _ => None,
        }
    }
}

// ─── Snapshot type ──────────────────────────────────────────────────

/// A point-in-time snapshot of one `(peer, medium)` tuple's
/// reachability counters. Returned from [`ReachabilityTracker::snapshot`]
/// and [`ReachabilityTracker::snapshot_all`] — a frozen view of the
/// rolling window at call time (subsequent attempts won't mutate it).
#[derive(Debug, Clone)]
pub struct PeerMediumReachability {
    pub peer_key_id: String,
    pub transport_id: TransportId,
    /// Rolling window the counters cover, in seconds. Matches
    /// [`crate::EdgeConfig::reachability_window_seconds`] at tracker
    /// construction time.
    pub window_seconds: u64,
    pub attempts: u64,
    pub successes: u64,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_attempt_at: Option<DateTime<Utc>>,
    /// Most recent failure's classifier string (if any failures fall
    /// in the rolling window). `None` when no failures present in the
    /// window — even if there's a residual lingering from a prior
    /// failure that has since been evicted.
    pub last_error_class: Option<String>,
}

impl PeerMediumReachability {
    /// `successes / attempts` ratio, clamped to `[0.0, 1.0]`. Returns
    /// `0.0` when there are no attempts in the window — consumer code
    /// SHOULD distinguish "no measurement" (attempts == 0) from
    /// "measured zero" (attempts > 0, ratio == 0.0) before rendering
    /// the value as health: the empty snapshot means "unknown", not
    /// "unreachable".
    #[must_use]
    pub fn ratio(&self) -> f64 {
        if self.attempts == 0 {
            return 0.0;
        }
        // Saturating arithmetic on u64-to-f64: attempts > 0 here so
        // the division is well-defined; the only edge is
        // `successes > attempts` (the bookkeeping invariants below
        // make that structurally impossible, but the clamp keeps the
        // contract robust against a future invariant bug).
        //
        // Precision: u64-to-f64 loses bits above 2^53 (≈9 quadrillion).
        // The ring buffer caps at `MAX_ENTRIES` (10k) so both numerator
        // and denominator fit comfortably under that bound; the lint is
        // a false positive for this domain.
        #[allow(clippy::cast_precision_loss)]
        let raw = (self.successes as f64) / (self.attempts as f64);
        raw.clamp(0.0, 1.0)
    }
}

// ─── Ring buffer ────────────────────────────────────────────────────

/// Per-`(peer, medium)` ring buffer of recorded attempts. Capacity
/// is bounded by both:
///
/// - **Time** — entries older than `window_seconds` are evicted on
///   every `record_attempt` (the eviction is amortized into the
///   write path so reads stay cheap).
/// - **Count** — a hard cap of [`Self::MAX_ENTRIES`] entries keeps
///   memory bounded even under pathological burst rates (e.g. a
///   misconfigured retry loop hammering the same peer). When the
///   cap is hit, the oldest entry is dropped to make room — the
///   ring-buffer invariant.
///
/// Using `VecDeque` not a raw array because the eviction pattern is
/// "drop from front" — `VecDeque::pop_front` is O(1). The hard cap
/// makes the worst-case memory per peer-medium predictable
/// (`MAX_ENTRIES * sizeof(RecordedAttempt)`).
#[derive(Debug, Default)]
struct AttemptRingBuffer {
    entries: VecDeque<RecordedAttempt>,
}

#[derive(Debug, Clone)]
struct RecordedAttempt {
    at: DateTime<Utc>,
    outcome: AttemptOutcome,
}

impl AttemptRingBuffer {
    /// Hard upper bound on entries per `(peer, medium)`. At
    /// 10k attempts and `sizeof(RecordedAttempt)` ≈ 64 bytes, this
    /// is ~640 KiB per peer-medium worst case — affordable for the
    /// expected peer count (low thousands) and prevents a pathological
    /// retry storm from blowing out memory.
    const MAX_ENTRIES: usize = 10_000;

    fn push(&mut self, at: DateTime<Utc>, outcome: AttemptOutcome, window_seconds: u64) {
        // Amortized time-based eviction. Cheap because the buffer is
        // sorted by `at` ascending (we only ever push to the back) —
        // drop from the front until we find an entry inside the
        // window.
        let cutoff =
            at - chrono::Duration::seconds(i64::try_from(window_seconds).unwrap_or(i64::MAX));
        while let Some(front) = self.entries.front() {
            if front.at < cutoff {
                self.entries.pop_front();
            } else {
                break;
            }
        }
        // Hard-count cap.
        while self.entries.len() >= Self::MAX_ENTRIES {
            self.entries.pop_front();
        }
        self.entries.push_back(RecordedAttempt { at, outcome });
    }

    /// Compose a [`PeerMediumReachability`] snapshot — folds the
    /// in-window entries into the four counters.
    fn snapshot(
        &self,
        peer_key_id: &str,
        transport_id: TransportId,
        window_seconds: u64,
        now: DateTime<Utc>,
    ) -> PeerMediumReachability {
        let cutoff =
            now - chrono::Duration::seconds(i64::try_from(window_seconds).unwrap_or(i64::MAX));
        let mut attempts: u64 = 0;
        let mut successes: u64 = 0;
        let mut last_success_at: Option<DateTime<Utc>> = None;
        let mut last_attempt_at: Option<DateTime<Utc>> = None;
        let mut last_error_class: Option<String> = None;
        let mut last_error_at: Option<DateTime<Utc>> = None;
        for entry in &self.entries {
            if entry.at < cutoff {
                continue;
            }
            attempts = attempts.saturating_add(1);
            if entry.outcome.is_success() {
                successes = successes.saturating_add(1);
                if last_success_at.map_or(true, |prev| entry.at > prev) {
                    last_success_at = Some(entry.at);
                }
            }
            if last_attempt_at.map_or(true, |prev| entry.at > prev) {
                last_attempt_at = Some(entry.at);
            }
            if let Some(cls) = entry.outcome.error_class() {
                if last_error_at.map_or(true, |prev| entry.at > prev) {
                    last_error_at = Some(entry.at);
                    last_error_class = Some(cls);
                }
            }
        }
        PeerMediumReachability {
            peer_key_id: peer_key_id.to_string(),
            transport_id,
            window_seconds,
            attempts,
            successes,
            last_success_at,
            last_attempt_at,
            last_error_class,
        }
    }
}

// ─── Tracker ────────────────────────────────────────────────────────

/// In-process per-`(peer, medium)` reachability tracker. Thread-safe;
/// shared across the edge dispatch loops via `Arc<ReachabilityTracker>`.
///
/// # Concurrency
///
/// Backed by a single `parking_lot::RwLock<HashMap<...>>`. Rationale
/// over alternatives:
///
/// - **`parking_lot::RwLock` (chosen)** — single MIT-licensed lock,
///   already a transitive dep (`Cargo.lock` carries `parking_lot
///   0.12.x` via tokio). Reads (`snapshot`) can run concurrent under
///   the read guard; writes (`record_attempt`) take the write guard.
///   The lock is held briefly — push to one VecDeque + amortized
///   eviction; no I/O under the lock.
/// - **`dashmap`** — would let readers and writers proceed
///   concurrently per-shard, but adds a new top-level dep + license
///   surface (MIT) when the lock contention is structurally low: the
///   tracker writes are off the hot path (post-send / post-receive,
///   not in the verify pipeline), and `snapshot_all` is a diagnostic /
///   pymethod surface called at human cadence (not per-message).
/// - **`std::sync::RwLock`** — viable but slower under contention
///   (writer-preference vs `parking_lot`'s configurable fairness,
///   plus parking_lot's faster uncontended path).
///
/// **Decision**: `parking_lot::RwLock` — zero new license surface,
/// minimal API surface, sufficient for the expected workload.
///
/// # Concurrency-tested
///
/// `tests::concurrent_writes_no_data_races` drives ≥100 concurrent
/// `record_attempt` calls and asserts the post-state matches the
/// expected `(attempts, successes)` from the sum of inputs — i.e.,
/// no lost-update / data race.
pub struct ReachabilityTracker {
    inner: RwLock<HashMap<TrackerKey, AttemptRingBuffer>>,
    window_seconds: u64,
}

/// Key into the tracker's outer map. The `(peer_key_id,
/// TransportId)` tuple is a stable lookup — `TransportId` is `Copy`
/// (it's just a `&'static str`) so cloning the key is cheap.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TrackerKey {
    peer_key_id: String,
    transport_id: TransportId,
}

impl ReachabilityTracker {
    /// Construct a tracker with the supplied rolling window in seconds.
    /// Mirrors [`crate::EdgeConfig::reachability_window_seconds`]
    /// (default 300s = 5min).
    #[must_use]
    pub fn new(window_seconds: u64) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            window_seconds,
        }
    }

    /// The configured rolling window in seconds. Visible for
    /// diagnostic / pymethod surface (`peer_reachability` returns
    /// values WRT this window).
    #[must_use]
    pub fn window_seconds(&self) -> u64 {
        self.window_seconds
    }

    /// Record one attempt against the `(peer, medium)` tuple. The
    /// timestamp is `Utc::now()`; this is the canonical entry point
    /// every hook site calls. Cheap path — pushes one entry into a
    /// per-tuple ring buffer + amortized window eviction.
    pub fn record_attempt(
        &self,
        peer_key_id: &str,
        transport_id: TransportId,
        outcome: AttemptOutcome,
    ) {
        self.record_attempt_at(peer_key_id, transport_id, outcome, Utc::now());
    }

    /// Test-only variant of [`Self::record_attempt`] that takes a
    /// caller-supplied timestamp — lets the window-eviction test drive
    /// deterministic ageing without mocking the system clock.
    pub fn record_attempt_at(
        &self,
        peer_key_id: &str,
        transport_id: TransportId,
        outcome: AttemptOutcome,
        at: DateTime<Utc>,
    ) {
        let key = TrackerKey {
            peer_key_id: peer_key_id.to_string(),
            transport_id,
        };
        let mut map = self.inner.write();
        let buf = map.entry(key).or_default();
        buf.push(at, outcome, self.window_seconds);
    }

    /// Snapshot every medium that has carried at least one attempt to
    /// `peer_key_id` in the rolling window. Empty map → no measurement
    /// for this peer.
    ///
    /// Consumer surface (CIRISEdge#22 Tier 3): the pyo3 method
    /// `peer_reachability(key_id)` calls this and shapes the result
    /// into `dict[str, float]` keyed by `TransportId::name()`.
    #[must_use]
    pub fn snapshot(&self, peer_key_id: &str) -> HashMap<TransportId, PeerMediumReachability> {
        let now = Utc::now();
        let map = self.inner.read();
        let mut out = HashMap::new();
        for (key, buf) in map.iter() {
            if key.peer_key_id != peer_key_id {
                continue;
            }
            let snap = buf.snapshot(&key.peer_key_id, key.transport_id, self.window_seconds, now);
            // Filter out tuples whose window-bounded counts are all
            // zero — they exist in the outer map because some attempt
            // WAS recorded historically, but every entry has aged out.
            // The pymethod surface should not show them.
            if snap.attempts == 0 {
                continue;
            }
            out.insert(key.transport_id, snap);
        }
        out
    }

    /// Federation-wide snapshot — every `(peer, medium)` the tracker
    /// has observed in the rolling window. Drives the Trust Topology
    /// drilldown UI surface. Result vector order is unspecified.
    #[must_use]
    pub fn snapshot_all(&self) -> Vec<PeerMediumReachability> {
        let now = Utc::now();
        let map = self.inner.read();
        let mut out = Vec::with_capacity(map.len());
        for (key, buf) in map.iter() {
            let snap = buf.snapshot(&key.peer_key_id, key.transport_id, self.window_seconds, now);
            if snap.attempts == 0 {
                continue;
            }
            out.push(snap);
        }
        out
    }
}

impl std::fmt::Debug for ReachabilityTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let map = self.inner.read();
        f.debug_struct("ReachabilityTracker")
            .field("window_seconds", &self.window_seconds)
            .field("entries", &map.len())
            .finish()
    }
}

/// Helper for use sites that hold an `Option<Arc<ReachabilityTracker>>` —
/// `record_attempt` is a no-op when the tracker is absent. Lets call
/// sites stay terse without a wrapping `if let`.
pub(crate) fn record_if_tracking(
    tracker: Option<&Arc<ReachabilityTracker>>,
    peer_key_id: &str,
    transport_id: TransportId,
    outcome: AttemptOutcome,
) {
    if let Some(t) = tracker {
        t.record_attempt(peer_key_id, transport_id, outcome);
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PEER: &str = "edge-test-peer";
    const TEST_WINDOW: u64 = 300;

    #[test]
    fn ratio_zero_when_no_attempts() {
        let snap = PeerMediumReachability {
            peer_key_id: TEST_PEER.into(),
            transport_id: TransportId::HTTP,
            window_seconds: TEST_WINDOW,
            attempts: 0,
            successes: 0,
            last_success_at: None,
            last_attempt_at: None,
            last_error_class: None,
        };
        assert!((snap.ratio() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn ratio_correct_for_mixed_outcomes() {
        // 3 success / 4 attempts → 0.75
        let tracker = ReachabilityTracker::new(TEST_WINDOW);
        tracker.record_attempt(TEST_PEER, TransportId::HTTP, AttemptOutcome::SendSuccess);
        tracker.record_attempt(
            TEST_PEER,
            TransportId::HTTP,
            AttemptOutcome::DurableDelivered,
        );
        tracker.record_attempt(
            TEST_PEER,
            TransportId::HTTP,
            AttemptOutcome::SendFailure {
                error_class: "unreachable".into(),
            },
        );
        tracker.record_attempt(
            TEST_PEER,
            TransportId::HTTP,
            AttemptOutcome::AttestationReceived,
        );
        let snap = tracker.snapshot(TEST_PEER);
        let entry = snap.get(&TransportId::HTTP).expect("http entry present");
        assert_eq!(entry.attempts, 4);
        assert_eq!(entry.successes, 3);
        assert!((entry.ratio() - 0.75).abs() < 1e-9);
    }

    #[test]
    fn record_attempt_increments_attempts_and_conditionally_successes() {
        let tracker = ReachabilityTracker::new(TEST_WINDOW);
        // One success.
        tracker.record_attempt(TEST_PEER, TransportId::HTTP, AttemptOutcome::SendSuccess);
        let snap = tracker.snapshot(TEST_PEER);
        let entry = snap.get(&TransportId::HTTP).unwrap();
        assert_eq!(entry.attempts, 1);
        assert_eq!(entry.successes, 1);
        assert!(entry.last_success_at.is_some());
        assert!(entry.last_attempt_at.is_some());
        assert!(entry.last_error_class.is_none());

        // One failure — attempts increments, successes does not, and
        // last_error_class surfaces.
        tracker.record_attempt(
            TEST_PEER,
            TransportId::HTTP,
            AttemptOutcome::SendFailure {
                error_class: "timeout".into(),
            },
        );
        let snap = tracker.snapshot(TEST_PEER);
        let entry = snap.get(&TransportId::HTTP).unwrap();
        assert_eq!(entry.attempts, 2);
        assert_eq!(entry.successes, 1);
        assert_eq!(entry.last_error_class.as_deref(), Some("timeout"));
    }

    #[test]
    fn separate_peers_separate_buckets() {
        let tracker = ReachabilityTracker::new(TEST_WINDOW);
        tracker.record_attempt("peer-a", TransportId::HTTP, AttemptOutcome::SendSuccess);
        tracker.record_attempt(
            "peer-b",
            TransportId::HTTP,
            AttemptOutcome::SendFailure {
                error_class: "unreachable".into(),
            },
        );
        let snap_a = tracker.snapshot("peer-a");
        let snap_b = tracker.snapshot("peer-b");
        assert_eq!(snap_a.get(&TransportId::HTTP).unwrap().attempts, 1);
        assert_eq!(snap_a.get(&TransportId::HTTP).unwrap().successes, 1);
        assert_eq!(snap_b.get(&TransportId::HTTP).unwrap().attempts, 1);
        assert_eq!(snap_b.get(&TransportId::HTTP).unwrap().successes, 0);
    }

    #[test]
    fn separate_mediums_separate_buckets() {
        let tracker = ReachabilityTracker::new(TEST_WINDOW);
        tracker.record_attempt(TEST_PEER, TransportId::HTTP, AttemptOutcome::SendSuccess);
        tracker.record_attempt(
            TEST_PEER,
            TransportId::RETICULUM_RS,
            AttemptOutcome::SendFailure {
                error_class: "timeout".into(),
            },
        );
        let snap = tracker.snapshot(TEST_PEER);
        assert_eq!(snap.len(), 2);
        assert_eq!(snap.get(&TransportId::HTTP).unwrap().successes, 1);
        assert_eq!(snap.get(&TransportId::RETICULUM_RS).unwrap().successes, 0);
    }

    #[test]
    fn window_eviction_drops_old_attempts() {
        let tracker = ReachabilityTracker::new(60); // 60-second window
        let now = Utc::now();
        let two_hours_ago = now - chrono::Duration::seconds(7200);
        // Old success — should age out.
        tracker.record_attempt_at(
            TEST_PEER,
            TransportId::HTTP,
            AttemptOutcome::SendSuccess,
            two_hours_ago,
        );
        // Recent failure — should remain.
        tracker.record_attempt_at(
            TEST_PEER,
            TransportId::HTTP,
            AttemptOutcome::SendFailure {
                error_class: "io".into(),
            },
            now,
        );
        let snap = tracker.snapshot(TEST_PEER);
        let entry = snap.get(&TransportId::HTTP).unwrap();
        // Old success is evicted: attempts == 1 (the recent failure
        // only), successes == 0.
        assert_eq!(entry.attempts, 1);
        assert_eq!(entry.successes, 0);
        assert_eq!(entry.last_error_class.as_deref(), Some("io"));
    }

    #[test]
    fn snapshot_all_returns_every_observed_tuple() {
        let tracker = ReachabilityTracker::new(TEST_WINDOW);
        tracker.record_attempt("peer-a", TransportId::HTTP, AttemptOutcome::SendSuccess);
        tracker.record_attempt(
            "peer-b",
            TransportId::RETICULUM_RS,
            AttemptOutcome::AnnounceReceived,
        );
        let all = tracker.snapshot_all();
        assert_eq!(all.len(), 2);
        let mut seen_a_http = false;
        let mut seen_b_ret = false;
        for snap in all {
            if snap.peer_key_id == "peer-a" && snap.transport_id == TransportId::HTTP {
                seen_a_http = true;
            }
            if snap.peer_key_id == "peer-b" && snap.transport_id == TransportId::RETICULUM_RS {
                seen_b_ret = true;
            }
        }
        assert!(seen_a_http);
        assert!(seen_b_ret);
    }

    #[test]
    fn announce_received_counts_as_success() {
        // Per the AttemptOutcome doc: AnnounceReceived is passive
        // evidence of liveness; it counts as both attempt and success
        // so a peer that's reachable-but-no-traffic shows reachable.
        let tracker = ReachabilityTracker::new(TEST_WINDOW);
        tracker.record_attempt(
            TEST_PEER,
            TransportId::RETICULUM_RS,
            AttemptOutcome::AnnounceReceived,
        );
        let snap = tracker.snapshot(TEST_PEER);
        let entry = snap.get(&TransportId::RETICULUM_RS).unwrap();
        assert_eq!(entry.attempts, 1);
        assert_eq!(entry.successes, 1);
        assert!((entry.ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn durable_abandoned_records_reason_as_error_class() {
        let tracker = ReachabilityTracker::new(TEST_WINDOW);
        tracker.record_attempt(
            TEST_PEER,
            TransportId::HTTP,
            AttemptOutcome::DurableAbandoned {
                reason: "ttl_expired".into(),
            },
        );
        let snap = tracker.snapshot(TEST_PEER);
        let entry = snap.get(&TransportId::HTTP).unwrap();
        assert_eq!(entry.attempts, 1);
        assert_eq!(entry.successes, 0);
        assert_eq!(entry.last_error_class.as_deref(), Some("ttl_expired"));
    }

    #[test]
    fn attestation_received_counts_as_attempt_and_success() {
        let tracker = ReachabilityTracker::new(TEST_WINDOW);
        tracker.record_attempt(
            TEST_PEER,
            TransportId::HTTP,
            AttemptOutcome::AttestationReceived,
        );
        let snap = tracker.snapshot(TEST_PEER);
        let entry = snap.get(&TransportId::HTTP).unwrap();
        assert_eq!(entry.attempts, 1);
        assert_eq!(entry.successes, 1);
        assert!((entry.ratio() - 1.0).abs() < f64::EPSILON);
        assert!(entry.last_error_class.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_writes_no_data_races() {
        // Stress test — 100 tasks each record 100 attempts. The tracker's
        // post-state MUST reflect the full 10_000 successful records
        // (no lost updates / data races). Detects the classic "read
        // counter / increment / write counter" race that a non-locked
        // primitive would surface.
        let tracker = Arc::new(ReachabilityTracker::new(TEST_WINDOW));
        let mut handles = Vec::new();
        for task_id in 0..100 {
            let t = tracker.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..100 {
                    let outcome = if task_id % 2 == 0 {
                        AttemptOutcome::SendSuccess
                    } else {
                        AttemptOutcome::SendFailure {
                            error_class: "io".into(),
                        }
                    };
                    // All tasks pound the same (peer, medium) tuple so
                    // the lock is genuinely contested.
                    t.record_attempt(TEST_PEER, TransportId::HTTP, outcome);
                }
            }));
        }
        for h in handles {
            h.await.expect("task panicked");
        }
        let snap = tracker.snapshot(TEST_PEER);
        let entry = snap.get(&TransportId::HTTP).expect("http entry present");
        // 100 tasks × 100 records each = 10_000 attempts.
        // 50 even-id tasks × 100 successes each = 5_000 successes.
        assert_eq!(entry.attempts, 10_000);
        assert_eq!(entry.successes, 5_000);
        assert!((entry.ratio() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn record_if_tracking_is_noop_when_none() {
        // Drives the Option-guarded helper used by call sites that
        // hold an `Option<Arc<ReachabilityTracker>>`. Default Edge
        // construction sets the tracker, but defensive handling is
        // structurally cleaner for the hook points.
        let none: Option<&Arc<ReachabilityTracker>> = None;
        record_if_tracking(
            none,
            TEST_PEER,
            TransportId::HTTP,
            AttemptOutcome::SendSuccess,
        );
        // Survives without panic — the only contract.

        let tracker = Arc::new(ReachabilityTracker::new(TEST_WINDOW));
        record_if_tracking(
            Some(&tracker),
            TEST_PEER,
            TransportId::HTTP,
            AttemptOutcome::SendSuccess,
        );
        assert_eq!(
            tracker
                .snapshot(TEST_PEER)
                .get(&TransportId::HTTP)
                .unwrap()
                .attempts,
            1
        );
    }

    #[test]
    fn ring_buffer_caps_at_max_entries() {
        // Pathological burst — 20_000 attempts blow past the 10_000
        // cap. Should drop the oldest and keep at most MAX_ENTRIES.
        let tracker = ReachabilityTracker::new(TEST_WINDOW);
        for _ in 0..20_000 {
            tracker.record_attempt(TEST_PEER, TransportId::HTTP, AttemptOutcome::SendSuccess);
        }
        let snap = tracker.snapshot(TEST_PEER);
        let entry = snap.get(&TransportId::HTTP).unwrap();
        // attempts must be at most the ring cap. The count can be a
        // few off if amortized time-eviction kicked too (it shouldn't
        // here — everything's "now"), but the cap is the load-bearing
        // invariant.
        assert!(
            entry.attempts <= AttemptRingBuffer::MAX_ENTRIES as u64,
            "attempts {} exceeded ring cap {}",
            entry.attempts,
            AttemptRingBuffer::MAX_ENTRIES
        );
    }
}
