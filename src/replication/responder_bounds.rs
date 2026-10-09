//! CIRISEdge#856 — the responder's no-progress backoff.
//!
//! A peer whose rounds open and never complete costs the responder a full
//! round of work each time — a Summary of its holdings, a Diff, often a
//! Deliver — and gets nothing from it. Whatever the reason (a build that cannot
//! take the reply, a link that dies under it, a peer that simply stops), the
//! responder sees one thing: rounds it served that never finished. After
//! [`NoProgressPolicy::after_failed_rounds`] of them in a row it serves that
//! peer's rounds at a backed-off cadence (exponential, capped), and the first
//! round that completes ends the backoff.
//!
//! "Progress" is the responder's own observation — the driver reached a
//! completion arm — never anything the peer asserts. A round dropped by the
//! backoff was not served, so it neither extends nor clears the streak.

use std::time::{Duration, Instant};

use crate::rate_limit::Backoff;

/// When a peer's rounds are backed off, and how far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoProgressPolicy {
    /// Consecutive served rounds that never completed before the backoff
    /// starts. `0` disables the backoff.
    pub after_failed_rounds: u32,
    /// The window between served rounds once backed off: `base` after the
    /// K-th failure, doubling per further failure, capped.
    pub backoff: Backoff,
}

impl NoProgressPolicy {
    /// Three: one lost round is weather, three in a row is the peer.
    pub const DEFAULT_AFTER_FAILED_ROUNDS: u32 = 3;
    /// One served round per minute at first, one per fifteen at the cap.
    pub const DEFAULT_BACKOFF: Backoff = Backoff::new(60, 900);
    /// The backoff off.
    pub const DISABLED: Self = Self {
        after_failed_rounds: 0,
        backoff: Self::DEFAULT_BACKOFF,
    };
}

impl Default for NoProgressPolicy {
    fn default() -> Self {
        Self {
            after_failed_rounds: Self::DEFAULT_AFTER_FAILED_ROUNDS,
            backoff: Self::DEFAULT_BACKOFF,
        }
    }
}

/// What the driver does with a round that just opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundAdmission {
    /// Serve it.
    Serve,
    /// Drop it unserved (counted `backed_off`).
    BackedOff,
}

/// One `(peer, kind)` responder's progress record. Owned by its driver task,
/// so it is plain state: three words, bounded by the responder registry.
#[derive(Debug, Clone)]
pub struct NoProgress {
    policy: NoProgressPolicy,
    /// Consecutive served rounds that opened and never completed.
    streak: u32,
    /// A served round is open and has not completed.
    open: bool,
    /// When the last served round opened.
    last_served: Option<Instant>,
}

impl NoProgress {
    #[must_use]
    pub fn new(policy: NoProgressPolicy) -> Self {
        Self {
            policy,
            streak: 0,
            open: false,
            last_served: None,
        }
    }

    /// A round opened at `now`: serve it, or drop it under the backoff.
    pub fn on_round_open(&mut self, now: Instant) -> RoundAdmission {
        if self.open {
            // The round served before this one never completed.
            self.open = false;
            self.streak = self.streak.saturating_add(1);
        }
        let k = self.policy.after_failed_rounds;
        if k > 0 && self.streak >= k {
            let window = Duration::from_secs(
                self.policy
                    .backoff
                    .window_secs(self.streak.saturating_sub(k).saturating_add(1)),
            );
            if self
                .last_served
                .is_some_and(|at| now.saturating_duration_since(at) < window)
            {
                return RoundAdmission::BackedOff;
            }
        }
        self.open = true;
        self.last_served = Some(now);
        RoundAdmission::Serve
    }

    /// The served round completed: the peer is making progress again.
    pub fn on_round_completed(&mut self) {
        self.open = false;
        self.streak = 0;
    }

    /// Consecutive served rounds that never completed.
    #[must_use]
    pub fn streak(&self) -> u32 {
        self.streak
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(k: u32, base: u64, cap: u64) -> NoProgressPolicy {
        NoProgressPolicy {
            after_failed_rounds: k,
            backoff: Backoff::new(base, cap),
        }
    }

    #[test]
    fn rounds_are_served_until_k_never_complete() {
        let t0 = Instant::now();
        let mut p = NoProgress::new(policy(3, 60, 900));
        for i in 0..4 {
            assert_eq!(
                p.on_round_open(t0 + Duration::from_secs(i)),
                RoundAdmission::Serve,
                "round {i}"
            );
        }
        assert_eq!(p.streak(), 3);
        assert_eq!(
            p.on_round_open(t0 + Duration::from_secs(5)),
            RoundAdmission::BackedOff
        );
    }

    #[test]
    fn the_backoff_doubles_per_failure_and_caps() {
        let t0 = Instant::now();
        let mut p = NoProgress::new(policy(1, 10, 25));
        assert_eq!(p.on_round_open(t0), RoundAdmission::Serve);
        // streak 1: window 10 s from the last served open (t0).
        assert_eq!(
            p.on_round_open(t0 + Duration::from_secs(9)),
            RoundAdmission::BackedOff
        );
        assert_eq!(
            p.on_round_open(t0 + Duration::from_secs(10)),
            RoundAdmission::Serve
        );
        // That one failed too: streak 2, window 20 s.
        let t1 = t0 + Duration::from_secs(10);
        assert_eq!(
            p.on_round_open(t1 + Duration::from_secs(19)),
            RoundAdmission::BackedOff
        );
        assert_eq!(
            p.on_round_open(t1 + Duration::from_secs(20)),
            RoundAdmission::Serve
        );
        // streak 3: 40 s capped to 25 s.
        let t2 = t1 + Duration::from_secs(20);
        assert_eq!(
            p.on_round_open(t2 + Duration::from_secs(24)),
            RoundAdmission::BackedOff
        );
        assert_eq!(
            p.on_round_open(t2 + Duration::from_secs(25)),
            RoundAdmission::Serve
        );
    }

    #[test]
    fn dropped_rounds_do_not_extend_the_streak() {
        let t0 = Instant::now();
        let mut p = NoProgress::new(policy(1, 100, 100));
        p.on_round_open(t0);
        for i in 1..50 {
            assert_eq!(
                p.on_round_open(t0 + Duration::from_secs(i)),
                RoundAdmission::BackedOff
            );
        }
        assert_eq!(p.streak(), 1);
    }

    #[test]
    fn one_completion_recovers() {
        let t0 = Instant::now();
        let mut p = NoProgress::new(policy(1, 100, 100));
        p.on_round_open(t0);
        assert_eq!(
            p.on_round_open(t0 + Duration::from_secs(100)),
            RoundAdmission::Serve
        );
        p.on_round_completed();
        assert_eq!(p.streak(), 0);
        for i in 101..110 {
            assert_eq!(
                p.on_round_open(t0 + Duration::from_secs(i)),
                RoundAdmission::Serve,
            );
            p.on_round_completed();
        }
    }

    #[test]
    fn k_zero_disables() {
        let t0 = Instant::now();
        let mut p = NoProgress::new(NoProgressPolicy::DISABLED);
        for i in 0..100 {
            assert_eq!(
                p.on_round_open(t0 + Duration::from_millis(i)),
                RoundAdmission::Serve
            );
        }
    }
}
