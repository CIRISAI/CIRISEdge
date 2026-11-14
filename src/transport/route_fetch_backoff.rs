//! CIRISEdge#993 — **per-destination backoff after a failed pre-seal route
//! fetch.**
//!
//! A dial with no transit pair for the peer asks the peer for its own signed
//! route row as the link's first frame (CC 5.3.3.5 E1, `route_fetch`). When
//! that fetch fails (the responder holds no row with a pair, refuses by its
//! node-wide rate, times out, or answers wrong), the dialler books the seal
//! refusal and closes the link — and before this, nothing remembered it. Every
//! caller dialled again on its own schedule: the durable outbound drain
//! retries each queued row on its own per-row ladder, so N rows queued toward
//! such a peer were N independent redials. Two idle 45.1.0 nodes that could
//! not seal churned ~1,700 link up/down a minute each
//! (tools/scenarios/cohab_reticulum_two_node.py, the control set).
//!
//! Now repeated failed fetches put the DESTINATION into a backoff that every
//! dial shares: while it holds, a dial that would need a route fetch fails
//! fast, before any link opens, as `link_seal_route_fetch_backed_off`. The
//! FIRST failure is free: one immediate retry is kept, because the dialler
//! cannot see what changed on the far side (a responder whose request cap
//! reopened, a row minted on its next announce) or on its own (a replaced PQC
//! commitment), and that retry is the CC 5.3.3.5 E1 contract the existing
//! witnesses hold. From the SECOND consecutive failure the window starts at
//! [`ROUTE_FETCH_BACKOFF_BASE`] and doubles per failure to
//! [`ROUTE_FETCH_BACKOFF_CAP`]. A storm is consecutive failures by
//! definition, so it is cut after two dials per destination. A fetch that succeeds clears it; a dial
//! that already holds a pair (from the peer's replicated route row, a rooted
//! binding, or a pairing pin) never consults it, so a pair arriving by
//! replication ends the backoff for that peer at once.
//!
//! Bounded: at most [`ROUTE_FETCH_BACKOFF_ENTRIES`] destinations; past that,
//! the entry whose window ends first is dropped (a dropped entry only costs
//! one more fetch).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The first window after a failed route fetch.
pub(crate) const ROUTE_FETCH_BACKOFF_BASE: Duration = Duration::from_secs(5);
/// The longest window.
pub(crate) const ROUTE_FETCH_BACKOFF_CAP: Duration = Duration::from_mins(5);
/// The most destinations remembered.
pub(crate) const ROUTE_FETCH_BACKOFF_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Copy)]
struct Entry {
    failures: u32,
    until: Instant,
}

/// Consecutive failures before a destination is backed off (the first is
/// free: see the module doc).
pub(crate) const ROUTE_FETCH_FAILURES_BEFORE_BACKOFF: u32 = 2;

/// The window after `failures` consecutive failed fetches: none below
/// [`ROUTE_FETCH_FAILURES_BEFORE_BACKOFF`].
fn window(failures: u32) -> Duration {
    if failures < ROUTE_FETCH_FAILURES_BEFORE_BACKOFF {
        return Duration::ZERO;
    }
    let doublings = (failures - ROUTE_FETCH_FAILURES_BEFORE_BACKOFF).min(16);
    ROUTE_FETCH_BACKOFF_BASE
        .checked_mul(1u32 << doublings)
        .unwrap_or(ROUTE_FETCH_BACKOFF_CAP)
        .min(ROUTE_FETCH_BACKOFF_CAP)
}

/// Destinations whose last route fetch failed, and until when a dial to each
/// that needs a fetch is refused.
#[derive(Debug, Default)]
pub(crate) struct RouteFetchBackoff {
    inner: Mutex<HashMap<String, Entry>>,
}

impl RouteFetchBackoff {
    /// When the backoff toward `destination` ends, if it holds at `now`.
    pub(crate) fn blocked_until(&self, destination: &str, now: Instant) -> Option<Instant> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .get(destination)
            .map(|e| e.until)
            .filter(|until| *until > now)
    }

    /// A route fetch toward `destination` failed at `now`. Returns the window
    /// it is now refused for.
    pub(crate) fn note_failure(&self, destination: &str, now: Instant) -> Duration {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if inner.len() >= ROUTE_FETCH_BACKOFF_ENTRIES && !inner.contains_key(destination) {
            if let Some(first) = inner
                .iter()
                .min_by_key(|(_, e)| e.until)
                .map(|(k, _)| k.clone())
            {
                inner.remove(&first);
            }
        }
        let failures = inner
            .get(destination)
            .map_or(1, |e| e.failures.saturating_add(1));
        let w = window(failures);
        inner.insert(
            destination.to_owned(),
            Entry {
                failures,
                until: now + w,
            },
        );
        w
    }

    /// A route fetch toward `destination` succeeded: no backoff.
    pub(crate) fn clear(&self, destination: &str) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(destination);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_fetch_refuses_the_destination_for_a_window_that_doubles_to_the_cap() {
        let b = RouteFetchBackoff::default();
        let t0 = Instant::now();
        assert_eq!(b.blocked_until("peer", t0), None, "nothing failed yet");
        assert_eq!(
            b.note_failure("peer", t0),
            Duration::ZERO,
            "the first failure is free"
        );
        assert_eq!(
            b.blocked_until("peer", t0),
            None,
            "one immediate retry is kept"
        );
        assert_eq!(b.note_failure("peer", t0), ROUTE_FETCH_BACKOFF_BASE);
        assert_eq!(
            b.blocked_until("peer", t0),
            Some(t0 + ROUTE_FETCH_BACKOFF_BASE)
        );
        assert_eq!(b.blocked_until("other", t0), None, "per destination");
        assert_eq!(
            b.blocked_until("peer", t0 + ROUTE_FETCH_BACKOFF_BASE),
            None,
            "the window ends"
        );
        assert_eq!(b.note_failure("peer", t0), ROUTE_FETCH_BACKOFF_BASE * 2);
        assert_eq!(b.note_failure("peer", t0), ROUTE_FETCH_BACKOFF_BASE * 4);
        for _ in 0..20 {
            b.note_failure("peer", t0);
        }
        assert_eq!(
            b.note_failure("peer", t0),
            ROUTE_FETCH_BACKOFF_CAP,
            "capped"
        );
    }

    #[test]
    fn a_fetch_that_succeeds_clears_the_backoff() {
        let b = RouteFetchBackoff::default();
        let t0 = Instant::now();
        b.note_failure("peer", t0);
        b.note_failure("peer", t0);
        assert!(b.blocked_until("peer", t0).is_some());
        b.clear("peer");
        assert_eq!(b.blocked_until("peer", t0), None);
        assert_eq!(
            b.note_failure("peer", t0),
            Duration::ZERO,
            "the ladder starts over, first failure free"
        );
    }

    #[test]
    fn the_register_is_bounded() {
        let b = RouteFetchBackoff::default();
        let t0 = Instant::now();
        for i in 0..=ROUTE_FETCH_BACKOFF_ENTRIES {
            b.note_failure(&format!("peer-{i}"), t0);
        }
        assert_eq!(b.len(), ROUTE_FETCH_BACKOFF_ENTRIES);
    }
}
