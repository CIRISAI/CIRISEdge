//! C6 — per-candidate peer health.
//!
//! ```text
//!   Available ⇄ Degraded
//!       │          │  silent ≥ suspect
//!       ▼          ▼
//!     Suspected ──silent ≥ down / link gone / loop──▶ Down
//!       │ heard again                                   │ heard / offer again
//!       ▼                                               ▼
//!     Recovering ──clean for recover_clean_ms──▶ Available
//! ```
//!
//! **Suspicion is not a trust verdict.** Health is about delivery; it moves
//! a peer down the selector's ranking and drives failover, and it NEVER
//! emits a trust or scores-plane signal. Eligibility (trust) is a separate
//! flag the caller sets from the trust gate; health never touches it.

use super::ControllerConfig;

/// A candidate's delivery health.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PeerState {
    /// Delivering within thresholds (or unmeasured and not known bad).
    Available,
    /// Delivering, but loss at or above the degraded threshold, or
    /// end-to-end latency over the stream class's budget.
    Degraded,
    /// Subscribed and silent past the suspect threshold.
    Suspected,
    /// Link gone, silent past the down threshold, or a loop.
    Down,
    /// Heard again after Suspected/Down; must stay clean to be Available.
    Recovering,
}

/// The state machine for one candidate.
#[derive(Debug, Clone, Copy)]
pub struct PeerHealth {
    state: PeerState,
    since_ms: u64,
    clean_since_ms: Option<u64>,
}

impl PeerHealth {
    /// A fresh candidate starts Available.
    #[must_use]
    pub fn new(now_ms: u64) -> Self {
        Self {
            state: PeerState::Available,
            since_ms: now_ms,
            clean_since_ms: None,
        }
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> PeerState {
        self.state
    }

    /// When the current state was entered.
    #[must_use]
    pub fn since_ms(&self) -> u64 {
        self.since_ms
    }

    fn go(&mut self, to: PeerState, now_ms: u64) -> Option<(PeerState, PeerState)> {
        if self.state == to {
            return None;
        }
        let from = self.state;
        self.state = to;
        self.since_ms = now_ms;
        self.clean_since_ms = (to == PeerState::Recovering).then_some(now_ms);
        Some((from, to))
    }

    /// Force Down (link gone, loop, shed).
    pub fn mark_down(&mut self, now_ms: u64) -> Option<(PeerState, PeerState)> {
        self.go(PeerState::Down, now_ms)
    }

    /// A liveness proof while not subscribed (an offer arrived): a Down or
    /// Suspected peer starts Recovering, but only once it has stayed so for
    /// `hold_ms`. An offer proves the forwarder is alive, not that it
    /// delivers (a black hole keeps offering), so it cannot clear a verdict
    /// that delivery earned right away.
    pub fn on_alive(&mut self, now_ms: u64, hold_ms: u64) -> Option<(PeerState, PeerState)> {
        match self.state {
            PeerState::Down | PeerState::Suspected
                if now_ms.saturating_sub(self.since_ms) >= hold_ms =>
            {
                self.go(PeerState::Recovering, now_ms)
            }
            _ => None,
        }
    }

    /// Re-evaluate. `silent_ms` is `Some` only while subscribed (time since
    /// the path last delivered, or since the subscription began);
    /// `degraded` is the meter's verdict for the last window.
    pub fn update(
        &mut self,
        now_ms: u64,
        silent_ms: Option<u64>,
        degraded: bool,
        cfg: &ControllerConfig,
    ) -> Option<(PeerState, PeerState)> {
        if let Some(silent) = silent_ms {
            if silent >= cfg.down_silence_ms {
                return self.go(PeerState::Down, now_ms);
            }
            if silent >= cfg.suspect_silence_ms {
                return match self.state {
                    PeerState::Down => None,
                    _ => self.go(PeerState::Suspected, now_ms),
                };
            }
        }
        let heard = silent_ms.is_some();
        match self.state {
            PeerState::Suspected | PeerState::Down if heard => {
                self.go(PeerState::Recovering, now_ms)
            }
            PeerState::Recovering => {
                if degraded {
                    self.clean_since_ms = Some(now_ms);
                    None
                } else if now_ms.saturating_sub(self.clean_since_ms.unwrap_or(now_ms))
                    >= cfg.recover_clean_ms
                {
                    self.go(PeerState::Available, now_ms)
                } else {
                    None
                }
            }
            PeerState::Available if degraded => self.go(PeerState::Degraded, now_ms),
            PeerState::Degraded if !degraded => self.go(PeerState::Available, now_ms),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_the_states() {
        let cfg = ControllerConfig::interactive();
        let mut h = PeerHealth::new(0);
        assert_eq!(
            h.update(100, Some(0), true, &cfg).map(|t| t.1),
            Some(PeerState::Degraded)
        );
        assert_eq!(
            h.update(200, Some(cfg.suspect_silence_ms), false, &cfg)
                .map(|t| t.1),
            Some(PeerState::Suspected)
        );
        assert_eq!(
            h.update(300, Some(cfg.down_silence_ms), false, &cfg)
                .map(|t| t.1),
            Some(PeerState::Down)
        );
        assert_eq!(
            h.on_alive(400, cfg.down_hold_ms),
            None,
            "an offer alone does not clear Down"
        );
        assert_eq!(
            h.on_alive(300 + cfg.down_hold_ms, cfg.down_hold_ms)
                .map(|t| t.1),
            Some(PeerState::Recovering)
        );
        let t = 300 + cfg.down_hold_ms;
        assert_eq!(h.update(t + 100, Some(0), false, &cfg), None);
        assert_eq!(
            h.update(t + cfg.recover_clean_ms, Some(0), false, &cfg)
                .map(|t| t.1),
            Some(PeerState::Available)
        );
    }
}
