//! §3.1 lifetime-average λ inequality book-keeper (CIRISEdge#175,
//! v6.1.0).
//!
//! Per FSD §3.1:
//!
//! > λ_scope tuned so cover emission dominates real publication on a
//! > lifetime-average inequality across the measurement window — the
//! > budget anchor is §2.6 maintenance throughput.
//!
//! The [`BudgetMeter`] tracks `(real_count, cover_count)` per scope
//! over the active window and surfaces:
//!
//! - [`BudgetState::UnderBudget`] — real < target_rate, scheduler
//!   should pop the next REAL envelope if available; emit COVER
//!   only if the queue is empty.
//! - [`BudgetState::OverBudget`] — real ≥ target_rate, scheduler
//!   must back-pressure the real publication into the next window.
//!
//! The implementation is a simple rolling-window counter. More
//! sophisticated EWMA + KS-test-aware variants are possible (FSD §9
//! references a KS-test acceptance criterion for the lifetime
//! inequality at p > 0.01) but live above this layer — this layer
//! is the load-bearing accounting primitive.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::poisson::ScopeKey;

/// One window's worth of per-scope counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct WindowCounters {
    real: u32,
    cover: u32,
}

/// Tunable budget thresholds per scope.
#[derive(Debug, Clone, Copy)]
struct ScopeBudget {
    /// Maximum real emissions per measurement window. Real
    /// publications above this cap back-pressure into the next
    /// window.
    target_real_per_window: u32,
    /// Window duration in milliseconds.
    window_ms: u64,
    /// When the current window started.
    window_started_at: Instant,
    /// Current window counters.
    counters: WindowCounters,
}

impl ScopeBudget {
    fn new(target_real_per_window: u32, window: Duration) -> Self {
        Self {
            target_real_per_window,
            // Saturate at u64::MAX for absurdly large windows; the
            // u128 from `as_millis()` is bounded for any realistic
            // configuration (~584M years at u64 millis).
            window_ms: u64::try_from(window.as_millis()).unwrap_or(u64::MAX),
            window_started_at: Instant::now(),
            counters: WindowCounters::default(),
        }
    }

    fn roll_if_expired(&mut self, now: Instant) {
        let elapsed_ms = u64::try_from(now.duration_since(self.window_started_at).as_millis())
            .unwrap_or(u64::MAX);
        if elapsed_ms >= self.window_ms {
            self.window_started_at = now;
            self.counters = WindowCounters::default();
        }
    }
}

/// State returned by [`BudgetMeter::query`] — the scheduler's
/// dispatch decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetState {
    /// Real-emission budget is available — scheduler should pop the
    /// next real envelope at this scope and emit it. If the real
    /// queue is empty, scheduler emits a cover envelope.
    UnderBudget {
        /// Real emissions remaining in this window.
        real_remaining: u32,
        /// Cover emissions so far in this window.
        cover_so_far: u32,
    },
    /// Real-emission budget exhausted — scheduler MUST emit cover
    /// (not real) at this timer fire, and the next real publication
    /// at this scope back-pressures into the next window.
    OverBudget {
        /// Cover emissions so far in this window.
        cover_so_far: u32,
    },
    /// No budget configured for this scope. Scheduler should
    /// treat this as "no emission at this scope" (the rate is
    /// also zero in the [`crate::emission::PoissonScheduler`], so
    /// no timer fires here in practice).
    Unconfigured,
}

/// Per-scope budget book-keeper.
///
/// Cheap to clone via the internal `Mutex<HashMap>`. Designed for
/// the scheduler-loop pattern: register each scope's
/// `(target_real_per_window, window)` once, then on every timer
/// fire call [`Self::query`] → drive a dispatch decision → call
/// [`Self::record_real`] / [`Self::record_cover`] after emission.
#[derive(Default)]
pub struct BudgetMeter {
    inner: Mutex<HashMap<ScopeKey, ScopeBudget>>,
}

impl BudgetMeter {
    /// Construct an empty budget meter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure `(target_real_per_window, window)` for `scope`.
    /// Replaces any prior configuration; resets the current window.
    pub fn configure(&self, scope: ScopeKey, target_real_per_window: u32, window: Duration) {
        let mut g = self.inner.lock();
        g.insert(scope, ScopeBudget::new(target_real_per_window, window));
    }

    /// Query the budget state for `scope` AT [`Instant::now`].
    /// The query also rolls the window if it has expired since the
    /// last record.
    #[must_use]
    pub fn query(&self, scope: &ScopeKey) -> BudgetState {
        self.query_at(scope, Instant::now())
    }

    /// Query at an explicit instant — test seam.
    #[must_use]
    pub fn query_at(&self, scope: &ScopeKey, now: Instant) -> BudgetState {
        let mut g = self.inner.lock();
        let Some(budget) = g.get_mut(scope) else {
            return BudgetState::Unconfigured;
        };
        budget.roll_if_expired(now);
        if budget.counters.real >= budget.target_real_per_window {
            BudgetState::OverBudget {
                cover_so_far: budget.counters.cover,
            }
        } else {
            BudgetState::UnderBudget {
                real_remaining: budget.target_real_per_window - budget.counters.real,
                cover_so_far: budget.counters.cover,
            }
        }
    }

    /// Record one real emission against `scope`.
    pub fn record_real(&self, scope: &ScopeKey) {
        let mut g = self.inner.lock();
        if let Some(b) = g.get_mut(scope) {
            b.roll_if_expired(Instant::now());
            b.counters.real = b.counters.real.saturating_add(1);
        }
    }

    /// Record one cover emission against `scope`.
    pub fn record_cover(&self, scope: &ScopeKey) {
        let mut g = self.inner.lock();
        if let Some(b) = g.get_mut(scope) {
            b.roll_if_expired(Instant::now());
            b.counters.cover = b.counters.cover.saturating_add(1);
        }
    }

    /// Snapshot of `(real_count, cover_count)` for `scope` in the
    /// current window.
    #[must_use]
    pub fn snapshot(&self, scope: &ScopeKey) -> Option<(u32, u32)> {
        let g = self.inner.lock();
        g.get(scope).map(|b| (b.counters.real, b.counters.cover))
    }
}

impl std::fmt::Debug for BudgetMeter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let g = self.inner.lock();
        f.debug_struct("BudgetMeter")
            .field("scopes", &g.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unconfigured_scope_returns_unconfigured() {
        let m = BudgetMeter::new();
        let s = ScopeKey::federation();
        assert_eq!(m.query(&s), BudgetState::Unconfigured);
    }

    #[test]
    fn under_budget_path() {
        let m = BudgetMeter::new();
        let s = ScopeKey::community("alpha".into());
        m.configure(s.clone(), 10, Duration::from_secs(60));
        let state = m.query(&s);
        assert!(matches!(
            state,
            BudgetState::UnderBudget {
                real_remaining: 10,
                cover_so_far: 0
            }
        ));
        m.record_real(&s);
        m.record_cover(&s);
        let state2 = m.query(&s);
        assert!(matches!(
            state2,
            BudgetState::UnderBudget {
                real_remaining: 9,
                cover_so_far: 1
            }
        ));
    }

    #[test]
    fn over_budget_after_target_real_emissions() {
        let m = BudgetMeter::new();
        let s = ScopeKey::self_scope();
        m.configure(s.clone(), 3, Duration::from_secs(60));
        for _ in 0..3 {
            m.record_real(&s);
        }
        assert!(matches!(m.query(&s), BudgetState::OverBudget { .. }));
    }

    #[test]
    fn window_roll_resets_counters() {
        let m = BudgetMeter::new();
        let s = ScopeKey::family(None);
        m.configure(s.clone(), 2, Duration::from_millis(1));
        m.record_real(&s);
        m.record_real(&s);
        assert!(matches!(m.query(&s), BudgetState::OverBudget { .. }));
        std::thread::sleep(Duration::from_millis(5));
        // Window expired — query rolls.
        let state = m.query(&s);
        assert!(matches!(
            state,
            BudgetState::UnderBudget {
                real_remaining: 2,
                cover_so_far: 0
            }
        ));
    }

    #[test]
    fn snapshot_reports_counts() {
        let m = BudgetMeter::new();
        let s = ScopeKey::community("c".into());
        m.configure(s.clone(), 5, Duration::from_secs(60));
        m.record_real(&s);
        m.record_real(&s);
        m.record_cover(&s);
        assert_eq!(m.snapshot(&s), Some((2, 1)));
    }
}
