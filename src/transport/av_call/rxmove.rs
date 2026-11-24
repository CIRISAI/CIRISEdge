//! ReceiverMoves — what a call's receiver reads, and does, when a
//! publisher's uplink queues (`docs/design/call_congestion/CallCongestion.md`,
//! the decision table's rows RM1–RM7 and N4, checked by `CallCongestion.tla`).
//!
//! Pure state, no I/O: the clocks are passed in, so a field log replays. The
//! call's [`super::alm::AlmState`] owns one of each per stream (or per
//! stream and path) and asks them on every chunk and every watch tick.

/// RM1 — the floor is re-anchored upward at most this often (the hosts'
/// clocks drift; a floor that never rises would read drift as queueing).
pub(super) const FLOOR_REANCHOR_MS: u64 = 30_000;
/// RM1 — only a sample at most this far above the floor re-anchors it: a
/// sample that close is not late, so a queued stream never moves its floor.
pub(super) const FLOOR_NEAR_MS: i64 = 50;

/// RM1 — one stream's latency floor: the smallest clock offset
/// (`wall − source_ts_ms`) seen for it, with when it was set.
///
/// Transition (RM1): observable, a verified chunk's signed `source_ts_ms`
/// against this node's wall clock; state, the floor and its age; action, a
/// lower offset replaces the floor at once, and a sample within
/// [`FLOOR_NEAR_MS`] of a floor older than [`FLOOR_REANCHOR_MS`] re-anchors
/// it (clock drift); the latency is the offset above the floor; must never,
/// re-anchor from a late sample (45.2.0 before RM1 replaced a 30 s old floor
/// with whatever came next, so after 30 s of queueing the latency read zero
/// and the late signal was gone).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LatencyFloor {
    floor: i64,
    at_ms: u64,
}

impl LatencyFloor {
    /// A floor at `offset`, set at `now_ms`.
    pub(super) fn new(offset: i64, now_ms: u64) -> Self {
        Self {
            floor: offset,
            at_ms: now_ms,
        }
    }

    /// The floor (ms of clock offset).
    #[cfg(test)]
    pub(super) fn floor(&self) -> i64 {
        self.floor
    }

    /// Fold one chunk's clock offset; returns its latency above the floor
    /// (ms, never negative).
    pub(super) fn sample(&mut self, offset: i64, now_ms: u64) -> i64 {
        let near = offset.saturating_sub(self.floor) <= FLOOR_NEAR_MS;
        let old = now_ms.saturating_sub(self.at_ms) >= FLOOR_REANCHOR_MS;
        if offset < self.floor || (near && old) {
            *self = Self::new(offset, now_ms);
        }
        offset.saturating_sub(self.floor).max(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RM1 — a better floor wins at once.
    #[test]
    fn a_lower_offset_is_the_new_floor_at_once() {
        let mut f = LatencyFloor::new(100, 0);
        assert_eq!(f.sample(80, 10), 0);
        assert_eq!(f.floor(), 80);
        assert_eq!(f.sample(130, 20), 50);
    }

    /// RM1 — a queued stream never moves its floor, however long it queues;
    /// drift (a sample near an old floor) still re-anchors it, slowly.
    #[test]
    fn a_late_stream_never_re_anchors_and_drift_does() {
        let mut f = LatencyFloor::new(0, 0);
        for t in (0..120_000).step_by(20) {
            assert_eq!(f.sample(500, t), 500, "late at {t} ms");
        }
        assert_eq!(f.floor(), 0);
        // Drift: on-time samples 30 ms above the floor, past the re-anchor age.
        assert_eq!(f.sample(30, 120_000), 0, "re-anchored to the drifted floor");
        assert_eq!(f.floor(), 30);
        // Not again before the next re-anchor age.
        assert_eq!(f.sample(60, 130_000), 30);
        assert_eq!(f.floor(), 30);
    }
}
