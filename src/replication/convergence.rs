//! Wait for the mesh to converge — once, in one place.
//!
//! # The problem this replaces
//!
//! Every plane in this crate is eventually consistent: you dispatch a Pull, and
//! the rows arrive later through the ordinary Diff/Deliver flow.
//! [`ReplicationRuntime::pull_subject_testimony`] is therefore
//! FIRE-AND-FORGET — it returns once the sends are queued, and tells the caller
//! nothing about whether the answer landed.
//!
//! So every caller that actually needs the answer wrote its own loop:
//!
//! ```ignore
//! loop {
//!     if we_have_it().await { break }
//!     if started.elapsed() >= timeout { return Err(..) }
//!     sleep(Duration::from_millis(500)).await;
//! }
//! ```
//!
//! That shape appeared four times in the harness alone, and it is what a
//! downstream consumer (CIRISServer's chat harness) would be forced to write
//! next. It is also wrong in the ways hand-rolled polls usually are: a fixed
//! 500ms floor on every lookup even when the row arrived in 3ms, no distinction
//! between "timed out" and "never going to happen", and nothing to report
//! afterwards about how long convergence actually took.
//!
//! # The shape
//!
//! One [`ConvergenceSignal`] per node, bumped at the single admission choke, and
//! [`ConvergenceWaiter::await_until`] for everyone who waits. A waiter sleeps
//! until an envelope is ADMITTED and then re-checks its own predicate, so the
//! common case wakes in microseconds instead of on a poll boundary.
//!
//! # Why `watch` and not `Notify`
//!
//! [`tokio::sync::Notify`] stores at most ONE permit: notify twice before a
//! waiter parks and the second notification is gone. Under replication load
//! notifications outnumber waiters constantly, so that lost-wakeup is the
//! normal case, not the corner. A [`watch`] channel carries a monotonic
//! generation instead — a waiter that missed ten bumps still sees the value
//! moved, and every waiter is woken rather than one.
//!
//! The ordering inside the loop is the load-bearing part: `borrow_and_update`
//! marks the current generation seen BEFORE the predicate runs. An admit landing
//! between the check and the park therefore advances the generation past the one
//! we marked, and `changed()` returns immediately instead of parking forever on
//! a notification that already happened.
//!
//! # Why the timer is not `tokio::time`
//!
//! CIRISEdge#217: this crate is driven by foreign runtimes (the PyO3 consumers
//! bring their own), and `tokio::time` needs a tokio reactor to be entered.
//! `futures_timer::Delay` needs none. `tokio::sync` is fine — the sync
//! primitives are reactor-free.
//!
//! # Why there is still a poll floor
//!
//! Not every condition a caller waits on is signalled by admission. Route
//! reachability lives in the transport's table; a roster is a file another
//! container writes. So `await_until` wakes on EITHER the signal OR the floor,
//! whichever comes first: signalled conditions are fast, unsignalled ones still
//! make progress, and no caller has to know which kind theirs is.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;

/// How long a waiter sleeps before re-checking a condition that admission does
/// not signal. Chosen to be invisible next to a mesh round while still bounding
/// the unsignalled case.
pub const DEFAULT_POLL_FLOOR: Duration = Duration::from_millis(250);

/// The node's admission generation: bumped once per ADMITTED envelope.
///
/// Cheap enough to bump on the hot path — a `watch::send_modify` on an
/// uncontended lock — and carries no payload, because a waiter re-reads the
/// state it actually cares about rather than trusting a message about it.
#[derive(Debug)]
pub struct ConvergenceSignal {
    tx: watch::Sender<u64>,
}

impl Default for ConvergenceSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl ConvergenceSignal {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tx: watch::channel(0).0,
        }
    }

    /// Shared handle — what the bridge holds and the runtime hands out.
    #[must_use]
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Announce that local state CHANGED (an envelope was admitted).
    ///
    /// Call only for [`ApplyOutcome::Admitted`]. A duplicate or a refusal did
    /// not change what a waiter can observe, and waking every waiter on the
    /// node for a row it already held is how a signal becomes a busy-loop with
    /// extra steps.
    ///
    /// [`ApplyOutcome::Admitted`]: super::summary::ApplyOutcome::Admitted
    pub fn note_admitted(&self) {
        // Wraps at u64::MAX after ~584 years at a billion admits/sec. The
        // waiters compare for CHANGE, not order, so a wrap is harmless anyway.
        self.tx.send_modify(|generation| {
            *generation = generation.wrapping_add(1);
        });
    }

    /// A waiter. Subscribing is cheap; do it before dispatching the work you
    /// intend to wait on, so nothing that lands in between is missed.
    #[must_use]
    pub fn subscribe(&self) -> ConvergenceWaiter {
        ConvergenceWaiter {
            rx: self.tx.subscribe(),
            poll_floor: DEFAULT_POLL_FLOOR,
        }
    }

    /// Live waiter count — for tests and diagnostics.
    #[must_use]
    pub fn waiters(&self) -> usize {
        self.tx.receiver_count()
    }
}

/// How a wait ended. Not a `bool`: "it converged" and "we gave up" carry
/// different remedies, and the timing belongs in whatever the caller reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Converged {
    /// The predicate held. `checks` counts how many times it ran — 1 means the
    /// state was already there and nothing was waited for.
    Yes { waited: Duration, checks: u32 },
    /// The budget elapsed with the predicate still false.
    TimedOut { waited: Duration, checks: u32 },
}

impl Converged {
    #[must_use]
    pub fn is_converged(self) -> bool {
        matches!(self, Converged::Yes { .. })
    }

    #[must_use]
    pub fn waited(self) -> Duration {
        match self {
            Converged::Yes { waited, .. } | Converged::TimedOut { waited, .. } => waited,
        }
    }

    #[must_use]
    pub fn checks(self) -> u32 {
        match self {
            Converged::Yes { checks, .. } | Converged::TimedOut { checks, .. } => checks,
        }
    }
}

/// A subscription to the node's admission generation.
#[derive(Debug, Clone)]
pub struct ConvergenceWaiter {
    rx: watch::Receiver<u64>,
    poll_floor: Duration,
}

impl ConvergenceWaiter {
    /// A waiter attached to NO signal — it only ever wakes on the poll floor.
    ///
    /// For conditions nothing in this crate signals: a transport route table, a
    /// file another process writes. The caller still gets one code path, one
    /// deadline, and one outcome type.
    #[must_use]
    pub fn unsignalled() -> Self {
        ConvergenceSignal::new().subscribe()
    }

    /// Override the re-check interval for unsignalled conditions.
    #[must_use]
    pub fn with_poll_floor(mut self, floor: Duration) -> Self {
        self.poll_floor = floor.max(Duration::from_millis(1));
        self
    }

    /// Wait until `predicate` holds, or `budget` elapses.
    ///
    /// Wakes on an admission or on the poll floor, whichever comes first, so a
    /// signalled condition resolves as soon as the row lands rather than on the
    /// next poll boundary.
    ///
    /// The predicate is checked BEFORE any waiting, so a condition that already
    /// holds costs one check and no sleep. It runs again after every wakeup;
    /// keep it cheap, and make it a question about observable state rather than
    /// about a message having arrived.
    pub async fn await_until<F, Fut>(&mut self, budget: Duration, mut predicate: F) -> Converged
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = bool>,
    {
        let started = Instant::now();
        let mut checks = 0_u32;
        loop {
            // Mark the current generation seen BEFORE checking. An admit that
            // lands between here and the park advances past it, so `changed()`
            // returns at once. Reversing these two lines reintroduces exactly
            // the lost-wakeup this type exists to avoid.
            self.rx.borrow_and_update();

            checks += 1;
            if predicate().await {
                return Converged::Yes {
                    waited: started.elapsed(),
                    checks,
                };
            }

            let Some(remaining) = budget.checked_sub(started.elapsed()) else {
                return Converged::TimedOut {
                    waited: started.elapsed(),
                    checks,
                };
            };
            if remaining.is_zero() {
                return Converged::TimedOut {
                    waited: started.elapsed(),
                    checks,
                };
            }

            // Race the signal against the shorter of {poll floor, remaining
            // budget}. `futures_timer` rather than `tokio::time` — CIRISEdge#217.
            let nap = remaining.min(self.poll_floor);
            let changed = self.rx.changed();
            let delay = futures_timer::Delay::new(nap);
            futures::pin_mut!(changed, delay);
            match futures::future::select(changed, delay).await {
                // Signalled, or the floor elapsed: either way, re-check.
                futures::future::Either::Left((Ok(()), _))
                | futures::future::Either::Right(((), _)) => {}
                // Every sender dropped: no admission will ever be signalled
                // again. Keep waiting on the floor rather than reporting a
                // premature timeout — the condition may be satisfied by
                // something outside this crate, which is precisely the
                // unsignalled case.
                futures::future::Either::Left((Err(_), _)) => {
                    futures_timer::Delay::new(nap).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    /// A condition that already holds costs ONE check and no sleep.
    #[tokio::test]
    async fn an_already_true_condition_does_not_wait() {
        let mut w = ConvergenceWaiter::unsignalled();
        let out = w
            .await_until(Duration::from_secs(30), || async { true })
            .await;
        assert!(out.is_converged());
        assert_eq!(out.checks(), 1, "no re-check should have been needed");
        assert!(
            out.waited() < Duration::from_millis(50),
            "waited {:?} for a condition that was already true",
            out.waited()
        );
    }

    /// The signal wakes the waiter — proven by beating the poll floor.
    ///
    /// The floor is set far above the signal latency, so passing this on a
    /// polling implementation is not possible: it would have to sleep the whole
    /// floor before noticing.
    #[tokio::test]
    async fn an_admission_wakes_the_waiter_faster_than_the_floor() {
        let signal = ConvergenceSignal::shared();
        let mut w = signal.subscribe().with_poll_floor(Duration::from_secs(10));
        let ready = Arc::new(AtomicBool::new(false));

        let flip = {
            let (signal, ready) = (Arc::clone(&signal), Arc::clone(&ready));
            tokio::spawn(async move {
                futures_timer::Delay::new(Duration::from_millis(30)).await;
                ready.store(true, Ordering::SeqCst);
                signal.note_admitted();
            })
        };

        let out = w
            .await_until(Duration::from_secs(30), || {
                let ready = Arc::clone(&ready);
                async move { ready.load(Ordering::SeqCst) }
            })
            .await;
        flip.await.unwrap();

        assert!(out.is_converged());
        assert!(
            out.waited() < Duration::from_secs(5),
            "waited {:?} — that is the poll floor, so the signal did not wake it",
            out.waited()
        );
    }

    /// A never-true condition times out AT the budget, and says so.
    #[tokio::test]
    async fn a_condition_that_never_holds_times_out() {
        let mut w = ConvergenceWaiter::unsignalled().with_poll_floor(Duration::from_millis(10));
        let out = w
            .await_until(Duration::from_millis(120), || async { false })
            .await;
        assert!(!out.is_converged(), "must not report convergence: {out:?}");
        assert!(
            out.waited() >= Duration::from_millis(110),
            "gave up early at {:?}",
            out.waited()
        );
        assert!(out.checks() > 1, "should have re-checked while waiting");
    }

    /// With NO signal at all, the floor still makes progress. This is the
    /// transport-route / roster-file case.
    #[tokio::test]
    async fn an_unsignalled_condition_still_converges_on_the_floor() {
        let mut w = ConvergenceWaiter::unsignalled().with_poll_floor(Duration::from_millis(10));
        let calls = Arc::new(AtomicU32::new(0));
        let out = w
            .await_until(Duration::from_secs(5), || {
                let calls = Arc::clone(&calls);
                // False for the first few checks, then true — nothing ever
                // calls `note_admitted`.
                async move { calls.fetch_add(1, Ordering::SeqCst) >= 3 }
            })
            .await;
        assert!(out.is_converged(), "{out:?}");
        assert!(out.checks() >= 4);
    }

    /// **The lost-wakeup guard.** An admission that lands BEFORE the waiter
    /// parks must not be missed.
    ///
    /// `Notify` fails this shape once the permit is consumed; `watch` plus
    /// `borrow_and_update`-before-predicate does not. The floor is huge, so a
    /// missed wakeup shows up as a timeout rather than a slow pass.
    #[tokio::test]
    async fn a_signal_that_arrives_before_the_park_is_not_lost() {
        let signal = ConvergenceSignal::shared();
        let mut w = signal.subscribe().with_poll_floor(Duration::from_secs(30));

        // Several bumps with nobody parked. A single-permit primitive collapses
        // these to one, then loses it to the first check.
        for _ in 0..5 {
            signal.note_admitted();
        }

        let checks = Arc::new(AtomicU32::new(0));
        let signal_bg = Arc::clone(&signal);
        let bg = tokio::spawn(async move {
            futures_timer::Delay::new(Duration::from_millis(40)).await;
            signal_bg.note_admitted();
        });

        let out = w
            .await_until(Duration::from_secs(10), || {
                let checks = Arc::clone(&checks);
                // False on the first check, true afterwards: the waiter MUST
                // park and then be woken by the background admit.
                async move { checks.fetch_add(1, Ordering::SeqCst) > 0 }
            })
            .await;
        bg.await.unwrap();

        assert!(out.is_converged(), "the wakeup was lost: {out:?}");
        assert!(
            out.waited() < Duration::from_secs(5),
            "woke on the floor ({:?}), not on the signal",
            out.waited()
        );
    }

    /// One admission wakes EVERY waiter — the property `Notify::notify_one`
    /// does not have, and the reason a chat node can have many lookups in
    /// flight at once.
    #[tokio::test]
    async fn one_admission_wakes_every_waiter() {
        let signal = ConvergenceSignal::shared();
        let ready = Arc::new(AtomicBool::new(false));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let mut w = signal.subscribe().with_poll_floor(Duration::from_secs(30));
            let ready = Arc::clone(&ready);
            tasks.push(tokio::spawn(async move {
                w.await_until(Duration::from_secs(10), || {
                    let ready = Arc::clone(&ready);
                    async move { ready.load(Ordering::SeqCst) }
                })
                .await
            }));
        }
        // Let them all park before the single bump.
        futures_timer::Delay::new(Duration::from_millis(50)).await;
        ready.store(true, Ordering::SeqCst);
        signal.note_admitted();

        for t in tasks {
            let out = t.await.unwrap();
            assert!(out.is_converged(), "a waiter was not woken: {out:?}");
            assert!(
                out.waited() < Duration::from_secs(5),
                "waiter fell through to the floor at {:?}",
                out.waited()
            );
        }
    }

    /// A dropped signal does not turn into a spin or a premature timeout.
    #[tokio::test]
    async fn a_dropped_signal_degrades_to_the_floor() {
        let signal = ConvergenceSignal::shared();
        let mut w = signal
            .subscribe()
            .with_poll_floor(Duration::from_millis(10));
        drop(signal);

        let calls = Arc::new(AtomicU32::new(0));
        let out = w
            .await_until(Duration::from_secs(5), || {
                let calls = Arc::clone(&calls);
                async move { calls.fetch_add(1, Ordering::SeqCst) >= 3 }
            })
            .await;
        assert!(out.is_converged(), "{out:?}");
    }
}
