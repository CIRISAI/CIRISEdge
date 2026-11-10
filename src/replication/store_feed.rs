//! CIRISEdge#971 — **one drain of persist's serve cursor, many consumers.**
//!
//! Before v45 each of the four CIRISEdge#930 key-plane memos kept its own
//! position on `list_attestations_since` and drained it on every listing, so
//! one peer's round over the four key planes read the same delta four times.
//! The holdings index ([`super::holdings_index`]) needs the same delta. This
//! is the one position both read from.
//!
//! # Consumers
//!
//! - **The holdings index** takes every row as it is drained (a hash insert
//!   under a short synchronous lock, so it is applied inside the drain).
//! - **The four key-plane memos** take their rows LATER, on their own next
//!   listing, through an inbox per memo. A memo's lock is held across its
//!   whole listing and its dirt check may read the store
//!   ([`super::key_plane_memo::dirt_of`] resolves a `withdraws` target), so
//!   the drain cannot apply it in place without taking four memo locks under
//!   the feed lock, which a listing holding one memo and waiting on the feed
//!   would deadlock. The lock order is always memo, then feed; never the
//!   reverse.
//!
//! An inbox keeps only the rows [`dirt_of`](super::key_plane_memo::dirt_of)
//! can find dirty (a key-plane family row, an occurrence-revocation carrier, a
//! `withdraws`). One that overflows [`INBOX_CAP`] (a memo nobody listed
//! through a write burst) collapses to "the whole plane is dirty", which is
//! what a memo rebuild costs and never a stale answer.
//!
//! # A failed drain
//!
//! A drain the store did not serve marks every inbox overflowed (no memo
//! answer is vouched for: the CIRISEdge#930 "forget" rule, for all four at
//! once) and leaves the position where it was, so the next drain retries the
//! same delta. The caller marks the holdings index suspect.
//!
//! # Coalescing and spacing
//!
//! A caller passes the instant its ask began. A drain that STARTED at or after
//! that instant has read everything committed before the ask, so the caller
//! takes its inbox without draining again: N concurrent callers share one
//! drain.
//!
//! Sequential callers are spaced. An idle round must cost no store read
//! (Eric, 2026-11-09), and at a seat the asks arrive at round rate, so a probe
//! per ask (one indexed read returning nothing) is the cost being removed,
//! not a small constant to keep. A drain that started less than the spacing
//! ago ([`FEED_PROBE_SPACING`], `BridgeConfig::feed_probe_spacing`) covers a
//! later ask too, UNLESS a door marked the feed dirty after that drain began
//! ([`FeedDirt`]). Every write edge itself sees marks it: the apply choke on
//! an `Admitted` outcome, and every door a host reports a local write through
//! (`invalidate_send_set_memos`: a kick, `note_local_write(s)`, a released
//! signer). A host write that bypasses all of those is seen within the
//! spacing: a stated staleness bound, harmless in both directions (a held row
//! fetched once more as a `Duplicate`, or a key-plane offer one round late).
//! Spacing zero is the pre-spacing behaviour (a probe per sequential ask).
//!
//! # Where a cursor starts
//!
//! With the holdings index on, both cursors start at the head of the log
//! (`None`), so the first drain walks every served row once and the set knows
//! every record by its key (an attestation's `attestation_id`, a route's
//! `(occurrence_key_id, transport_kind)`). A rewrite of a record held before
//! boot (a PQC completion, a re-seal, a superseding route) then replaces its
//! hash at once instead of leaving the old one until an audit. With the index
//! off, the Attestation cursor starts [`CURSOR_LAG`] before now, as #930's
//! memos always did.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ciris_persist::federation::key_plane::KeyPlaneFamily;
use ciris_persist::federation::occurrence_revocation_carrier::is_carrier_row;
use ciris_persist::federation::types::{attestation_type::WITHDRAWS, Attestation};

use super::key_plane_memo::{KeyPlaneRead, ResumeCursor, CURSOR_LAG};

/// Rows an inbox holds before it collapses to "the whole plane is dirty".
pub(crate) const INBOX_CAP: usize = 4096;

/// The minimum spacing between two probes of one cursor when no door has
/// marked the feed dirty (module docs). At 5 s the idle cost of both cursors
/// is at most 0.4 indexed reads a second however many peers round, against
/// one per ask without it, and a write no door reports reaches a listing at
/// most 5 s late, under a sixth of a 30 s round.
pub(crate) const FEED_PROBE_SPACING: Duration = Duration::from_secs(5);

/// The dirt generation: bumped by every door edge sees a write through, read
/// at a drain's start. Lock-free, so a synchronous door (the apply choke)
/// marks it without the feed's async lock.
#[derive(Debug, Default)]
pub(crate) struct FeedDirt(AtomicU64);

impl FeedDirt {
    /// A door saw a write: the next ask of either cursor probes.
    pub(crate) fn mark(&self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }

    /// The generation now.
    #[must_use]
    pub(crate) fn generation(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

/// The rows one memo has not applied yet.
#[derive(Debug, Default)]
pub(crate) struct Pending {
    /// Rows its dirt check must see, oldest first.
    pub(crate) rows: Vec<Arc<Attestation>>,
    /// The inbox overflowed or a drain failed: drop the whole plane.
    pub(crate) overflowed: bool,
}

/// Can `row` dirty any key-plane memo? The union of the non-`Clean` arms of
/// [`super::key_plane_memo::dirt_of`]; a row outside it is `Clean` for all four.
#[must_use]
pub(crate) fn may_dirty_a_key_plane(row: &Attestation) -> bool {
    KeyPlaneFamily::of_row(row).is_some()
        || is_carrier_row(row)
        || row.attestation_type == WITHDRAWS
}

/// One cursor, the instant its last completed drain began, and the dirt
/// generation that drain read at its start.
#[derive(Debug, Default)]
pub(crate) struct Position {
    cursor: Option<ResumeCursor>,
    /// `true` once the cursor has been placed (a `None` cursor is also "the
    /// head of the log", so placement is tracked apart from the value).
    placed: bool,
    last_started: Option<Instant>,
    clean_through: Option<u64>,
}

/// Why an ask needs no drain of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Covered {
    /// A drain that began at or after the ask completed (concurrent asks).
    Coalesced,
    /// The last drain began inside the spacing and no door marked the feed
    /// dirty since it began.
    Spaced,
}

impl Position {
    /// The cursor to drain from. A first drain starts at the head of the log
    /// when `from_head` (the holdings index is on: every record is keyed, see
    /// the module docs), else [`CURSOR_LAG`] before `wall` (the CIRISEdge#930
    /// rule: the drain carries it to the end of the log before any consumer
    /// answers from it).
    pub(crate) fn cursor(
        &mut self,
        wall: chrono::DateTime<chrono::Utc>,
        from_head: bool,
    ) -> Option<ResumeCursor> {
        if !self.placed {
            self.placed = true;
            if !from_head {
                let lag = chrono::Duration::from_std(CURSOR_LAG)
                    .unwrap_or_else(|_| chrono::Duration::zero());
                self.cursor = Some((wall - lag, String::new()));
            }
        }
        self.cursor.clone()
    }

    pub(crate) fn advance(&mut self, cursor: ResumeCursor) {
        self.placed = true;
        self.cursor = Some(cursor);
    }

    /// Does an ask that began at `asked_at` need no drain of its own? `now`
    /// and `generation` (the [`FeedDirt`] generation now) decide the spacing.
    #[must_use]
    pub(crate) fn covers(
        &self,
        asked_at: Instant,
        now: Instant,
        generation: u64,
        spacing: Duration,
    ) -> Option<Covered> {
        let started = self.last_started?;
        if started >= asked_at {
            return Some(Covered::Coalesced);
        }
        let inside = now.saturating_duration_since(started) < spacing;
        (inside && self.clean_through == Some(generation)).then_some(Covered::Spaced)
    }

    /// A drain that started at `started`, when the dirt generation was
    /// `generation`, completed.
    pub(crate) fn completed(&mut self, started: Instant, generation: u64) {
        self.last_started = Some(started);
        self.clean_through = Some(generation);
    }
}

/// The feed: the Attestation serve cursor (holdings + key-plane memos), the
/// route serve cursor (holdings only), and the four memo inboxes.
#[derive(Debug, Default)]
pub(crate) struct FeedState {
    pub(crate) attestations: Position,
    pub(crate) routes: Position,
    inboxes: [Pending; 4],
}

impl FeedState {
    /// Queue a drained row for every memo it may dirty.
    pub(crate) fn distribute(&mut self, row: &Attestation) {
        if !may_dirty_a_key_plane(row) {
            return;
        }
        let shared = Arc::new(row.clone());
        for inbox in &mut self.inboxes {
            if inbox.overflowed {
                continue;
            }
            if inbox.rows.len() >= INBOX_CAP {
                inbox.rows.clear();
                inbox.overflowed = true;
                continue;
            }
            inbox.rows.push(Arc::clone(&shared));
        }
    }

    /// A drain failed: no memo answer is vouched for.
    pub(crate) fn fail(&mut self) {
        for inbox in &mut self.inboxes {
            inbox.rows.clear();
            inbox.overflowed = true;
        }
    }

    /// Take `read`'s inbox.
    pub(crate) fn take(&mut self, read: KeyPlaneRead) -> Pending {
        std::mem::take(&mut self.inboxes[read.index()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalescing_is_by_drain_start() {
        let mut p = Position::default();
        let asked = Instant::now();
        assert_eq!(
            p.covers(asked, asked, 0, Duration::ZERO),
            None,
            "nothing drained yet"
        );
        p.completed(asked, 0);
        assert_eq!(
            p.covers(asked, asked, 0, Duration::ZERO),
            Some(Covered::Coalesced),
            "a drain that began with the ask covers it"
        );
        let later = asked + Duration::from_millis(1);
        assert_eq!(
            p.covers(later, later, 0, Duration::ZERO),
            None,
            "spacing zero: an ask after the drain began needs its own"
        );
    }

    /// The spacing, from explicit instants (no sleeping): inside it and clean
    /// an ask is covered; a dirt mark or the spacing's end makes it probe.
    #[test]
    fn a_clean_ask_inside_the_spacing_is_covered_and_dirt_ends_it() {
        let spacing = Duration::from_secs(5);
        let mut p = Position::default();
        let t0 = Instant::now();
        p.completed(t0, 7);
        let ask = t0 + Duration::from_secs(1);
        assert_eq!(p.covers(ask, ask, 7, spacing), Some(Covered::Spaced));
        assert_eq!(
            p.covers(ask, ask, 8, spacing),
            None,
            "a door marked the feed dirty"
        );
        let late = t0 + spacing;
        assert_eq!(
            p.covers(late, late, 7, spacing),
            None,
            "the spacing ran out"
        );
    }

    #[test]
    fn the_first_cursor_starts_a_lag_before_now_with_the_index_off() {
        let mut p = Position::default();
        let wall = chrono::Utc::now();
        let (at, id) = p.cursor(wall, false).expect("seeded");
        assert!(id.is_empty());
        assert_eq!(
            wall - at,
            chrono::Duration::from_std(CURSOR_LAG).expect("fits")
        );
    }

    #[test]
    fn the_first_cursor_starts_at_the_head_with_the_index_on() {
        let mut p = Position::default();
        assert_eq!(
            p.cursor(chrono::Utc::now(), true),
            None,
            "the head of the log"
        );
        p.advance((chrono::Utc::now(), "a".into()));
        assert!(p.cursor(chrono::Utc::now(), true).is_some(), "placed once");
    }

    #[test]
    fn a_failed_drain_overflows_every_inbox() {
        let mut f = FeedState::default();
        f.fail();
        for read in KeyPlaneRead::ALL {
            assert!(f.take(read).overflowed);
        }
        assert!(
            !f.take(KeyPlaneRead::KeyRecord).overflowed,
            "taking clears it"
        );
    }
}
