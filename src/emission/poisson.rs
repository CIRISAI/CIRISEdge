//! §3.1 per-scope Poisson timer (CIRISEdge#175, v6.1.0).
//!
//! Each peer samples `t_next ~ Exp(λ_scope)` from a peer-local
//! CSPRNG seeded at process start. The CSPRNG seed source is the
//! OS entropy pool ([`rand::rngs::OsRng`] reseeded into a
//! [`rand_chacha::ChaCha20Rng`]) — **NEVER** derived from public
//! snapshot inputs (FSD §3.1 jitter-seed-source rule).
//!
//! # The math
//!
//! `Exp(λ)` is sampled via the inverse-CDF method:
//!
//! ```text
//!     u ← uniform(0, 1)   (CSPRNG-driven)
//!     t = -ln(u) / λ
//! ```
//!
//! `λ` is the per-scope emission rate in emissions/second. `t` is
//! the inter-emission interval in seconds. We carry it as
//! [`std::time::Duration`] to keep the scheduler integration
//! straightforward.
//!
//! Per FSD §3.1: λ_scope is tuned so cover emission dominates real
//! publication on a lifetime-average inequality across the
//! measurement window. The Poisson sampler itself is unaware of the
//! cover/real distinction — it just produces inter-emission timing.
//! The cover-vs-real decision is the scheduler's, driven by the
//! `BudgetMeter`.

use std::collections::HashMap;
use std::time::Duration;

use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use super::envelope::EmissionScopeTag;

/// Scheduler-local scope key — `(scope_tag, optional cohort_id)`.
/// `cohort_id` is the FSD §3.4 per-community separation: each
/// community's timing is independent of every other community's.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ScopeKey {
    /// Coarse scope.
    pub scope: EmissionScopeTag,
    /// Optional sub-scope identifier (community/family id). `None`
    /// at federation and self scope, `Some` at family/community.
    pub sub_scope: Option<String>,
}

impl ScopeKey {
    /// Federation-scope key (Commons / plaintext).
    #[must_use]
    pub fn federation() -> Self {
        Self {
            scope: EmissionScopeTag::Federation,
            sub_scope: None,
        }
    }
    /// Self-scope key.
    #[must_use]
    pub fn self_scope() -> Self {
        Self {
            scope: EmissionScopeTag::SelfScope,
            sub_scope: None,
        }
    }
    /// Family-scope key, optionally identified by `family_id`.
    #[must_use]
    pub fn family(family_id: Option<String>) -> Self {
        Self {
            scope: EmissionScopeTag::Family,
            sub_scope: family_id,
        }
    }
    /// Community-scope key for `community_id`.
    #[must_use]
    pub fn community(community_id: String) -> Self {
        Self {
            scope: EmissionScopeTag::Community,
            sub_scope: Some(community_id),
        }
    }
}

/// Per-scope Poisson timing scheduler (CSPRNG-driven).
///
/// Cheap to clone (`Arc`-shared inner mutable state); every
/// [`Scheduler`] instance the runtime hands out shares the same
/// CSPRNG so multiple emission paths feed timing from one
/// peer-local entropy source.
///
/// [`Scheduler`]: super::scheduler::Scheduler
pub struct PoissonScheduler {
    inner: Mutex<Inner>,
}

struct Inner {
    /// Per-scope Poisson rate (emissions/second). Configured via
    /// [`PoissonScheduler::set_rate`].
    rates: HashMap<ScopeKey, f64>,
    /// CSPRNG. Seeded at construction from `OsRng`; FSD §3.1
    /// jitter-seed-source compliance.
    rng: ChaCha20Rng,
}

impl PoissonScheduler {
    /// Construct a Poisson scheduler with `OsRng`-derived CSPRNG
    /// seed. The seed bytes are pulled at construction time and
    /// never re-seeded.
    #[must_use]
    pub fn new() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self {
            inner: Mutex::new(Inner {
                rates: HashMap::new(),
                rng: ChaCha20Rng::from_seed(seed),
            }),
        }
    }

    /// Construct with an explicit 32-byte seed. **Test-only** —
    /// production code path MUST use [`Self::new`] so the seed
    /// comes from `OsRng` (FSD §3.1 jitter-seed-source rule).
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            inner: Mutex::new(Inner {
                rates: HashMap::new(),
                rng: ChaCha20Rng::from_seed(seed),
            }),
        }
    }

    /// Set the Poisson rate λ (emissions/second) for `scope`.
    /// A rate of `0.0` disables emission for that scope (the
    /// `next_interval` call returns `None`).
    pub fn set_rate(&self, scope: ScopeKey, lambda: f64) {
        let mut g = self.inner.lock();
        g.rates.insert(scope, lambda);
    }

    /// Read the configured rate for `scope`, or `0.0` if no rate
    /// is registered.
    #[must_use]
    pub fn rate(&self, scope: &ScopeKey) -> f64 {
        let g = self.inner.lock();
        g.rates.get(scope).copied().unwrap_or(0.0)
    }

    /// Sample `t_next ~ Exp(λ)` for `scope`. Returns `None` if no
    /// rate is registered for `scope` (or if `λ <= 0.0`).
    ///
    /// The inverse-CDF method: `t = -ln(u) / λ` with `u` drawn
    /// from the CSPRNG on `(0.0, 1.0)`.
    pub fn next_interval(&self, scope: &ScopeKey) -> Option<Duration> {
        let mut g = self.inner.lock();
        let lambda = *g.rates.get(scope)?;
        if !lambda.is_finite() || lambda <= 0.0 {
            return None;
        }
        // Draw u from (0.0, 1.0]. The `rand::Rng::gen` half-open
        // [0, 1) draw is bumped off 0 by reading and adding
        // f64::MIN_POSITIVE, since -ln(0) is +inf. This caps the
        // worst-case interval at -ln(MIN_POSITIVE)/λ ≈ 745/λ
        // seconds — large but bounded.
        let u: f64 = g.rng.gen::<f64>().max(f64::MIN_POSITIVE);
        let t_sec = -u.ln() / lambda;
        Some(Duration::from_secs_f64(t_sec))
    }

    /// Fill `buf` with CSPRNG bytes from the peer-local stream.
    /// Used by [`super::envelope::seal_envelope`] callers to draw
    /// the 24-byte XChaCha nonce + cover-envelope pseudo-random
    /// under-encryption bytes (FSD §3.1 — CSPRNG-driven nonces
    /// and cover payloads).
    pub fn fill_bytes(&self, buf: &mut [u8]) {
        let mut g = self.inner.lock();
        g.rng.fill_bytes(buf);
    }
}

impl Default for PoissonScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for PoissonScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let g = self.inner.lock();
        f.debug_struct("PoissonScheduler")
            .field("registered_scopes", &g.rates.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_scheduler_has_no_rates() {
        let s = PoissonScheduler::new();
        let scope = ScopeKey::federation();
        assert!(s.rate(&scope).abs() < f64::EPSILON);
        assert!(s.next_interval(&scope).is_none());
    }

    #[test]
    fn set_rate_drives_intervals() {
        let s = PoissonScheduler::from_seed([0x42; 32]);
        let scope = ScopeKey::community("alpha".into());
        s.set_rate(scope.clone(), 10.0);
        assert!((s.rate(&scope) - 10.0).abs() < f64::EPSILON);
        // Draw 10 samples — all finite, all positive, all bounded
        // by the worst-case -ln(MIN_POSITIVE)/λ.
        for _ in 0..10 {
            let t = s.next_interval(&scope).unwrap();
            assert!(t.as_secs_f64() > 0.0);
            assert!(t.as_secs_f64() < 100.0, "interval bounded {t:?}");
        }
    }

    #[test]
    fn zero_lambda_disables() {
        let s = PoissonScheduler::from_seed([0u8; 32]);
        let scope = ScopeKey::self_scope();
        s.set_rate(scope.clone(), 0.0);
        assert!(s.next_interval(&scope).is_none());
        s.set_rate(scope.clone(), -1.0);
        assert!(s.next_interval(&scope).is_none());
    }

    #[test]
    fn empirical_mean_close_to_one_over_lambda() {
        // Sanity check — over N draws the empirical mean should be
        // within 5% of 1/λ for λ = 5.
        let s = PoissonScheduler::from_seed([0xAA; 32]);
        let scope = ScopeKey::federation();
        s.set_rate(scope.clone(), 5.0);
        let n = 5_000;
        let mut total = 0.0;
        for _ in 0..n {
            total += s.next_interval(&scope).unwrap().as_secs_f64();
        }
        let mean = total / f64::from(n);
        let expected = 1.0 / 5.0;
        let rel_err = (mean - expected).abs() / expected;
        assert!(
            rel_err < 0.05,
            "empirical mean {mean} too far from {expected} (rel_err {rel_err})"
        );
    }

    #[test]
    fn fill_bytes_advances_stream() {
        let s = PoissonScheduler::from_seed([0; 32]);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        s.fill_bytes(&mut a);
        s.fill_bytes(&mut b);
        assert_ne!(a, b, "two CSPRNG draws should differ");
    }

    #[test]
    fn from_seed_reproducible() {
        let a = PoissonScheduler::from_seed([0x77; 32]);
        let b = PoissonScheduler::from_seed([0x77; 32]);
        a.set_rate(ScopeKey::federation(), 1.0);
        b.set_rate(ScopeKey::federation(), 1.0);
        let s = ScopeKey::federation();
        let t_a = a.next_interval(&s).unwrap();
        let t_b = b.next_interval(&s).unwrap();
        assert_eq!(t_a, t_b, "same seed → same first draw");
    }
}
