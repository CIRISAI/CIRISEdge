//! CIRISEdge#926 — the link stall guard: a link whose Channel acknowledges
//! nothing is dead in one direction, and stops being chosen.
//!
//! # The field incident (2026-10-31, edge v43.3.0)
//!
//! On the reverse-path links one peer had opened, every frame the other node
//! sent stalled `0/N landed … stalled="fragment_pacing_timeout"`, one-fragment
//! frames included. Each round retried the same link (Channel first, then the
//! Resource busy-retry, then a dial with no route) for about fourteen minutes,
//! until leviculum closed it `ChannelExhausted`. The likely cause was a
//! one-sided punch (leviculum#89): the peer moved the link onto a punched
//! interface and sent its proofs and Channel acks to a socket this node had
//! already released. Whatever the cause, a Channel that takes nothing in is a
//! window full of frames nobody acknowledges.
//!
//! # The rule
//!
//! Every Channel send edge makes on a link is observed ([`ChannelLanding`]):
//!
//! - a send that lands at least one fragment ends the link's stall run;
//! - a send that lands NONE because the window never opened (the pacing wait
//!   ran out, the frame budget ran out, or the shaper's queue is full behind a
//!   window that never drains) extends it;
//! - a send refused locally (no seal keys, a frame the shaper cannot carry, a
//!   send error from a link that is already gone) says nothing about the peer
//!   and leaves the run as it is.
//!
//! The peer's own acknowledgements count too: leviculum's per-link
//! `bytes_delivered` grows with every delivery proof (Channel envelopes and
//! completed Resources). A run whose link delivered anything since it began
//! starts over, so a slow link whose window opens late, whose sends time out
//! while its acks still arrive, is never judged dead.
//!
//! The link is DEAD after [`STALL_MAX_ZERO_SENDS`] zero-landing sends in a
//! run, or once a run has lasted [`STALL_BOUND`] (measured from the start of
//! its first send, so one send stalling that long trips it alone). The
//! transport then stops choosing it (no reverse-path pick, no pool hand-out)
//! and closes it, so the next send dials a fresh link; a link on a punched
//! interface is first moved back onto its relayed path instead (leviculum#83
//! `retire_direct_link`) and starts a fresh run there.
//!
//! The state machine is [`stall_step`], pure, so every rule is a unit test.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Zero-landing Channel sends in one run that make a link dead.
pub const STALL_MAX_ZERO_SENDS: u32 = 3;

/// How long one stall run may last before the link is dead, whatever its
/// count. Above one frame's whole Channel budget (15 s), so a single send
/// reaches it only under a seam; two zero-landing sends this far apart, with
/// no delivery proof between them, do.
pub const STALL_BOUND: Duration = Duration::from_secs(30);

/// Above this many tracked links, entries for links that are gone are pruned
/// on the next observation (a run is otherwise forgotten only when it ends).
const PRUNE_ABOVE: usize = 256;

/// What one Channel send said about its link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelLanding {
    /// At least one fragment went onto the Channel.
    Landed,
    /// None did, because the window never opened: the peer is not
    /// acknowledging.
    Starved,
    /// None did, for a local reason that says nothing about the peer.
    Refused,
}

impl ChannelLanding {
    /// Classify a Channel send by how many fragments landed and, when it
    /// stopped short, why (the `stalled` reason of the transport's fragment
    /// sender).
    #[must_use]
    pub fn classify(sent: usize, total: usize, stalled: Option<&str>) -> Self {
        if sent > 0 || total == 0 {
            return Self::Landed;
        }
        match stalled {
            Some("fragment_pacing_timeout" | "frame_budget_exhausted") => Self::Starved,
            // `link_unsealed`, `link_send_error`, `shaping_body_too_large`, a
            // sequence that did not stop (cannot happen with `sent == 0 < total`),
            // or `shaping_queue_full`: a SHAPED link's queue filling behind its
            // Poisson window is load, not a dead Channel (CC 5.4.3; its cover
            // stream and the shaper's own ticket wait are its liveness), so a
            // slow shaped link never reads as stalled.
            _ => Self::Refused,
        }
    }
}

/// One link's current stall run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StallRun {
    /// Zero-landing sends in this run.
    pub zero_sends: u32,
    /// When the run's first send began.
    pub since: Instant,
    /// The link's `bytes_delivered` when the run began: any growth is a
    /// delivery proof from the peer, which ends the run.
    pub delivered: u64,
    /// The link was judged dead: never chosen again.
    pub dead: bool,
}

/// What [`stall_step`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StallVerdict {
    /// Nothing to do.
    Healthy,
    /// The run grew, below the bound.
    Stalling {
        /// Zero-landing sends so far.
        zero_sends: u32,
    },
    /// The link just became dead: act on it (once).
    Dead {
        /// Zero-landing sends in the run.
        zero_sends: u32,
        /// How long the run lasted.
        stalled_for: Duration,
    },
}

/// One observation. `prev` is the link's run, `delivered` its
/// `bytes_delivered` now (`None` when the node no longer holds the link),
/// `started` when this send began and `now` when it ended. Returns the run to
/// keep (`None` forgets the link) and the verdict.
#[must_use]
pub fn stall_step(
    prev: Option<StallRun>,
    landing: ChannelLanding,
    delivered: Option<u64>,
    started: Instant,
    now: Instant,
) -> (Option<StallRun>, StallVerdict) {
    match landing {
        ChannelLanding::Landed => {
            // A dead link stays dead: it is already being closed.
            let kept = prev.filter(|r| r.dead);
            (kept, StallVerdict::Healthy)
        }
        ChannelLanding::Refused => (prev, StallVerdict::Healthy),
        ChannelLanding::Starved => {
            if let Some(run) = prev.filter(|r| r.dead) {
                return (Some(run), StallVerdict::Healthy);
            }
            let delivered = delivered.unwrap_or(0);
            let mut run = match prev {
                // No proof since the run began: it goes on.
                Some(run) if delivered <= run.delivered => run,
                // First stall, or the peer acknowledged something since: a
                // fresh run, from this send.
                _ => StallRun {
                    zero_sends: 0,
                    since: started,
                    delivered,
                    dead: false,
                },
            };
            run.zero_sends += 1;
            let stalled_for = now.saturating_duration_since(run.since);
            if run.zero_sends >= STALL_MAX_ZERO_SENDS || stalled_for >= STALL_BOUND {
                run.dead = true;
                (
                    Some(run),
                    StallVerdict::Dead {
                        zero_sends: run.zero_sends,
                        stalled_for,
                    },
                )
            } else {
                (
                    Some(run),
                    StallVerdict::Stalling {
                        zero_sends: run.zero_sends,
                    },
                )
            }
        }
    }
}

/// The transport's per-link stall runs, keyed by link id.
#[derive(Debug, Default)]
pub struct LinkStallGuard {
    runs: std::sync::Mutex<HashMap<[u8; 16], StallRun>>,
}

impl LinkStallGuard {
    /// Observe one Channel send on `link` (see [`stall_step`]). `live` says
    /// whether a link is still held, for pruning.
    pub fn observe(
        &self,
        link: [u8; 16],
        landing: ChannelLanding,
        delivered: Option<u64>,
        started: Instant,
        live: impl Fn(&[u8; 16]) -> bool,
    ) -> StallVerdict {
        let mut runs = self
            .runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (next, verdict) = stall_step(
            runs.get(&link).copied(),
            landing,
            delivered,
            started,
            Instant::now(),
        );
        match next {
            Some(run) => {
                runs.insert(link, run);
            }
            None => {
                runs.remove(&link);
            }
        }
        if runs.len() > PRUNE_ABOVE {
            runs.retain(|id, _| live(id));
        }
        verdict
    }

    /// Was `link` judged dead? A dead link is never chosen for a send.
    #[must_use]
    pub fn is_dead(&self, link: &[u8; 16]) -> bool {
        self.runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(link)
            .is_some_and(|r| r.dead)
    }

    /// Forget `link`'s run: it moved back onto its relayed path and starts
    /// over there.
    pub fn forget(&self, link: &[u8; 16]) {
        self.runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(link);
    }

    /// Zero-landing sends in `link`'s current run (0 when it has none).
    #[must_use]
    pub fn zero_sends(&self, link: &[u8; 16]) -> u32 {
        self.runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(link)
            .map_or(0, |r| r.zero_sends)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: ChannelLanding = ChannelLanding::Starved;
    const L: ChannelLanding = ChannelLanding::Landed;

    fn step_at(
        prev: Option<StallRun>,
        landing: ChannelLanding,
        delivered: u64,
        t0: Instant,
        at_secs: u64,
    ) -> (Option<StallRun>, StallVerdict) {
        let t = t0 + Duration::from_secs(at_secs);
        stall_step(
            prev,
            landing,
            Some(delivered),
            t,
            t + Duration::from_secs(3),
        )
    }

    #[test]
    fn classify_names_the_window_never_opening() {
        for r in [
            "fragment_pacing_timeout",
            "frame_budget_exhausted",
            "shaping_queue_full",
        ] {
            assert_eq!(ChannelLanding::classify(0, 1, Some(r)), S, "{r}");
        }
        for r in ["link_unsealed", "link_send_error", "shaping_body_too_large"] {
            assert_eq!(
                ChannelLanding::classify(0, 3, Some(r)),
                ChannelLanding::Refused,
                "{r}"
            );
        }
        // A slow link that lands SOME fragments is not starved.
        assert_eq!(
            ChannelLanding::classify(1, 7, Some("fragment_pacing_timeout")),
            L
        );
        assert_eq!(ChannelLanding::classify(7, 7, None), L);
    }

    #[test]
    fn three_zero_landing_sends_make_a_link_dead() {
        let t0 = Instant::now();
        let (r, v) = step_at(None, S, 10, t0, 0);
        assert_eq!(v, StallVerdict::Stalling { zero_sends: 1 });
        let (r, v) = step_at(r, S, 10, t0, 4);
        assert_eq!(v, StallVerdict::Stalling { zero_sends: 2 });
        let (r, v) = step_at(r, S, 10, t0, 8);
        assert!(
            matches!(v, StallVerdict::Dead { zero_sends: 3, .. }),
            "{v:?}"
        );
        assert!(r.is_some_and(|r| r.dead));
        // Acted on once: a further stall on a dead link is no new verdict.
        let (_, v) = step_at(r, S, 10, t0, 12);
        assert_eq!(v, StallVerdict::Healthy);
    }

    #[test]
    fn a_landed_send_resets_the_run() {
        let t0 = Instant::now();
        let (r, _) = step_at(None, S, 10, t0, 0);
        let (r, _) = step_at(r, S, 10, t0, 4);
        let (r, v) = step_at(r, L, 10, t0, 8);
        assert_eq!((r, v), (None, StallVerdict::Healthy));
        let (r, v) = step_at(r, S, 10, t0, 12);
        assert_eq!(v, StallVerdict::Stalling { zero_sends: 1 });
        let (_, v) = step_at(r, S, 10, t0, 16);
        assert_eq!(v, StallVerdict::Stalling { zero_sends: 2 });
    }

    #[test]
    fn a_delivery_proof_restarts_the_run() {
        // A slow link: its sends time out, but the peer's acks keep arriving.
        let t0 = Instant::now();
        let (r, _) = step_at(None, S, 10, t0, 0);
        let (r, _) = step_at(r, S, 10, t0, 4);
        let (r, v) = step_at(r, S, 11, t0, 8);
        assert_eq!(v, StallVerdict::Stalling { zero_sends: 1 });
        let (r, v) = step_at(r, S, 11, t0, 12);
        assert_eq!(v, StallVerdict::Stalling { zero_sends: 2 });
        let (_, v) = step_at(r, S, 12, t0, 40);
        assert_eq!(v, StallVerdict::Stalling { zero_sends: 1 });
    }

    #[test]
    fn a_run_past_the_bound_is_dead_below_the_count() {
        let t0 = Instant::now();
        let (r, _) = step_at(None, S, 10, t0, 0);
        let (_, v) = step_at(r, S, 10, t0, STALL_BOUND.as_secs());
        assert!(
            matches!(v, StallVerdict::Dead { zero_sends: 2, .. }),
            "{v:?}"
        );
        // One send stalling past the bound trips it alone.
        let (_, v) = stall_step(None, S, Some(0), t0, t0 + STALL_BOUND);
        assert!(
            matches!(v, StallVerdict::Dead { zero_sends: 1, .. }),
            "{v:?}"
        );
    }

    #[test]
    fn a_local_refusal_neither_counts_nor_resets() {
        let t0 = Instant::now();
        let (r, _) = step_at(None, S, 10, t0, 0);
        let (r, v) = step_at(r, ChannelLanding::Refused, 10, t0, 4);
        assert_eq!(v, StallVerdict::Healthy);
        assert_eq!(r.map(|r| r.zero_sends), Some(1));
        let (r, v) = step_at(None, ChannelLanding::Refused, 10, t0, 0);
        assert_eq!((r, v), (None, StallVerdict::Healthy));
    }

    #[test]
    fn the_guard_keeps_runs_per_link() {
        let g = LinkStallGuard::default();
        let (a, b) = ([1u8; 16], [2u8; 16]);
        let t = Instant::now();
        for _ in 0..2 {
            g.observe(a, S, Some(0), t, |_| true);
        }
        g.observe(b, S, Some(0), t, |_| true);
        assert_eq!((g.zero_sends(&a), g.zero_sends(&b)), (2, 1));
        assert!(matches!(
            g.observe(a, S, Some(0), t, |_| true),
            StallVerdict::Dead { .. }
        ));
        assert!(g.is_dead(&a) && !g.is_dead(&b));
        g.forget(&a);
        assert!(!g.is_dead(&a));
    }
}
