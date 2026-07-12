//! `LogThrottle` — a bounded "first-N-per-window, then a suppressed-count
//! summary" gate for **attacker-triggerable** log sites (CIRISEdge#317).
//!
//! ## Why this exists
//!
//! Announces and link establishment are unauthenticated / advisory-admitted
//! (CC 3.3.6.2 — an unauthenticated announce is a routing hint, never dropped),
//! so a peer can flood a node with them. The library installs **no** tracing
//! subscriber (the embedding binary does — see [`crate::observability`]), and
//! the common `fmt::init()` default ships INFO-and-above to storage. So any
//! per-announce / per-link / per-frame INFO or WARN line is an attacker-driven
//! **storage-write amplification** and a log-flood DoS.
//!
//! The two anti-DoS levers this codebase already uses are (1) demote high-volume
//! detail to `DEBUG` (suppressed under the default INFO filter) and (2) count,
//! don't log-per-event ([`crate::observability::EdgeMetrics`]). `LogThrottle` is
//! the third: for the RCA-critical signals that MUST stay loggable at WARN/INFO
//! (so a single genuinely-broken run still self-diagnoses, the #317 acceptance
//! bar), emit the first `max_per_window` occurrences per key — which carry the
//! full operand payload — then collapse the rest to one `suppressed=<n>` summary
//! when the window rolls.
//!
//! ## Bounded so it can't become the DoS
//!
//! The per-key bucket map is itself cardinality-capped with front-drop eviction
//! (mirroring [`crate::transport::reachability`]'s ring buffer), because the
//! throttle keys are attacker-controlled (`link_id`, `verify_class`, …). An
//! unbounded key map would just relocate the memory-exhaustion vector into the
//! mitigation. Keying on a **low-cardinality** discriminant (e.g. the
//! `provenance` enum, the `RouteOutcome` variant) is preferred where possible;
//! where the key is attacker-chosen (`link_id`) the cap is the backstop.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The caller's decision after consulting the throttle.
#[derive(Debug, PartialEq, Eq)]
pub enum ThrottleDecision {
    /// Within budget — emit the full log line. `suppressed_prev` is the number
    /// of occurrences dropped in the *previous* window for this key (non-zero
    /// only on the call that rolled the window); log it as a `suppressed=<n>`
    /// field/summary so the flood is visible without per-event lines.
    Emit { suppressed_prev: u64 },
    /// Over budget this window — do not emit. The drop is counted internally and
    /// surfaced as `suppressed_prev` when the window next rolls.
    Suppress,
}

struct Bucket {
    window_start: Instant,
    emitted: u32,
    suppressed: u64,
}

struct State {
    buckets: HashMap<String, Bucket>,
    /// Eviction order; front is oldest. Capped at `max_keys`.
    order: VecDeque<String>,
}

/// A bounded first-N-per-window log gate. Cheap to hold as a process-global
/// `static OnceLock<LogThrottle>` per log site (MSRV 1.75 — `OnceLock`, not
/// `LazyLock`) — the throttle is about total log rate, so shared state across
/// instances is correct, and it never affects program behavior (only whether a
/// line is written).
pub struct LogThrottle {
    state: Mutex<State>,
    max_per_window: u32,
    window: Duration,
    max_keys: usize,
}

impl LogThrottle {
    /// `max_per_window` full lines per key per `window`; the per-key map is
    /// capped at `max_keys` (front-drop) so an attacker cycling keys can't grow
    /// it unbounded.
    pub fn new(max_per_window: u32, window: Duration, max_keys: usize) -> Self {
        Self {
            state: Mutex::new(State {
                buckets: HashMap::new(),
                order: VecDeque::new(),
            }),
            max_per_window,
            window,
            max_keys,
        }
    }

    /// Consult the throttle for `key` at `now`. Pure w.r.t. wall-clock: the
    /// caller passes `Instant::now()` so this is testable without a clock.
    pub fn check_at(&self, key: &str, now: Instant) -> ThrottleDecision {
        let mut st = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Fast path: existing bucket.
        if let Some(b) = st.buckets.get_mut(key) {
            if now.duration_since(b.window_start) >= self.window {
                // Window rolled — surface the suppressed count, reset.
                let suppressed_prev = b.suppressed;
                b.window_start = now;
                b.emitted = 1;
                b.suppressed = 0;
                return ThrottleDecision::Emit { suppressed_prev };
            }
            if b.emitted < self.max_per_window {
                b.emitted += 1;
                return ThrottleDecision::Emit { suppressed_prev: 0 };
            }
            b.suppressed += 1;
            return ThrottleDecision::Suppress;
        }

        // New key — evict oldest if at capacity (front-drop, like the
        // reachability ring buffer) so the map stays bounded under key churn.
        if st.order.len() >= self.max_keys {
            if let Some(evict) = st.order.pop_front() {
                st.buckets.remove(&evict);
            }
        }
        st.order.push_back(key.to_string());
        st.buckets.insert(
            key.to_string(),
            Bucket {
                window_start: now,
                emitted: 1,
                suppressed: 0,
            },
        );
        ThrottleDecision::Emit { suppressed_prev: 0 }
    }

    /// Convenience wrapper using the real clock.
    pub fn check(&self, key: &str) -> ThrottleDecision {
        self.check_at(key, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_n_emit_then_suppress_within_window() {
        let t = LogThrottle::new(3, Duration::from_secs(60), 16);
        let t0 = Instant::now();
        // First 3 within budget.
        for _ in 0..3 {
            assert_eq!(
                t.check_at("k", t0),
                ThrottleDecision::Emit { suppressed_prev: 0 }
            );
        }
        // Next 5 suppressed.
        for _ in 0..5 {
            assert_eq!(t.check_at("k", t0), ThrottleDecision::Suppress);
        }
    }

    #[test]
    fn window_roll_surfaces_suppressed_count() {
        let t = LogThrottle::new(1, Duration::from_secs(60), 16);
        let t0 = Instant::now();
        assert_eq!(
            t.check_at("k", t0),
            ThrottleDecision::Emit { suppressed_prev: 0 }
        );
        // 4 suppressed in this window.
        for _ in 0..4 {
            assert_eq!(t.check_at("k", t0), ThrottleDecision::Suppress);
        }
        // Next window: first call surfaces the 4 dropped.
        let t1 = t0 + Duration::from_secs(61);
        assert_eq!(
            t.check_at("k", t1),
            ThrottleDecision::Emit { suppressed_prev: 4 }
        );
    }

    #[test]
    fn key_map_is_bounded_under_churn() {
        // max_keys = 4; cycle 1000 distinct keys → map never exceeds the cap.
        let t = LogThrottle::new(1, Duration::from_secs(60), 4);
        let t0 = Instant::now();
        for i in 0..1000 {
            let _ = t.check_at(&format!("attacker-key-{i}"), t0);
        }
        let st = t.state.lock().unwrap();
        assert!(st.buckets.len() <= 4, "bucket map bounded at max_keys");
        assert!(st.order.len() <= 4, "eviction order bounded at max_keys");
    }

    #[test]
    fn independent_keys_have_independent_budgets() {
        let t = LogThrottle::new(1, Duration::from_secs(60), 16);
        let t0 = Instant::now();
        assert_eq!(
            t.check_at("a", t0),
            ThrottleDecision::Emit { suppressed_prev: 0 }
        );
        // Different key still has its own budget.
        assert_eq!(
            t.check_at("b", t0),
            ThrottleDecision::Emit { suppressed_prev: 0 }
        );
        assert_eq!(t.check_at("a", t0), ThrottleDecision::Suppress);
    }
}
