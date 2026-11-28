//! ReceiverMoves — what a call's receiver reads, and does, when a
//! publisher's uplink queues (`docs/design/call_congestion/CallCongestion.md`,
//! the decision table's rows RM1–RM7 and N4, checked by `CallCongestion.tla`).
//!
//! Pure state, no I/O: the clocks are passed in, so a field log replays. The
//! call's [`super::alm::AlmState`] owns one of each per stream (or per
//! stream and path) and asks them on every chunk and every watch tick.

use crate::transport::realtime_av::StreamId;
use crate::transport::realtime_av_alm::controller::hash_rank;

/// RM1 — the floor is re-anchored upward at most this often (the hosts'
/// clocks drift; a floor that never rises would read drift as queueing).
pub(super) const FLOOR_REANCHOR_MS: u64 = 30_000;
/// RM1 — only a sample at most this far above the floor re-anchors it: a
/// sample that close is not late, so a queued stream never moves its floor.
pub(super) const FLOOR_NEAR_MS: i64 = 50;

/// RM1 — one stream's latency floor: the smallest CONFIRMED clock offset
/// (`wall − source_ts_ms`) seen for it, with when it was set.
///
/// Transition (RM1, 45.3 confirm0): observable, a verified chunk's signed
/// `source_ts_ms` against this node's wall clock; state, the floor, its age
/// and one unconfirmed candidate; action, an offset below the floor (or the
/// first offset of an empty floor) becomes the candidate, and the NEXT
/// offset within [`FLOOR_NEAR_MS`] of it confirms it, the floor becoming the
/// LOWER of the pair; a sample within [`FLOOR_NEAR_MS`] above a floor older
/// than [`FLOOR_REANCHOR_MS`] re-anchors it upward (clock drift); the
/// latency is the offset above the floor (zero while none is confirmed);
/// must never, (a) re-anchor from a late sample (45.2.0 before RM1 replaced
/// a 30 s old floor with whatever came next, so after 30 s of queueing the
/// latency read zero and the late signal was gone), nor (b) take a floor
/// from one chunk alone: one chunk from a publisher clock stepped ahead
/// would read every later chunk as late until the epoch rolled (model row
/// R27 AGE, `AgeFloor.tla`, NoFalseStale; confirm0 is the variant that
/// passes all five properties). A queue only raises offsets, so it can
/// neither propose nor confirm a lower floor. Limit, stated: a clock that
/// steps BACK and stays reads as a standing queue, which no receiver can
/// tell apart; it is late until the epoch rolls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LatencyFloor {
    floor: Option<i64>,
    at_ms: u64,
    candidate: Option<i64>,
}

impl LatencyFloor {
    /// A floor already confirmed at `offset`, set at `now_ms` (tests).
    #[cfg(test)]
    pub(super) fn new(offset: i64, now_ms: u64) -> Self {
        Self {
            floor: Some(offset),
            at_ms: now_ms,
            candidate: None,
        }
    }

    /// No floor yet: the stream's first chunk only proposes one.
    pub(super) fn empty(now_ms: u64) -> Self {
        Self {
            floor: None,
            at_ms: now_ms,
            candidate: None,
        }
    }

    /// The confirmed floor (ms of clock offset), if any.
    pub(super) fn confirmed(&self) -> Option<i64> {
        self.floor
    }

    /// The floor (ms of clock offset); 0 while none is confirmed (tests).
    #[cfg(test)]
    pub(super) fn floor(&self) -> i64 {
        self.floor.unwrap_or(0)
    }

    /// Fold one chunk's clock offset; returns its latency above the floor
    /// (ms, never negative; 0 while no floor is confirmed).
    pub(super) fn sample(&mut self, offset: i64, now_ms: u64) -> i64 {
        let below = |f: Option<i64>| f.is_none_or(|f| offset < f);
        match self.candidate.take() {
            Some(c) if offset.abs_diff(c) <= FLOOR_NEAR_MS.unsigned_abs() => {
                let lo = c.min(offset);
                if self.floor.is_none_or(|f| lo < f) {
                    self.floor = Some(lo);
                    self.at_ms = now_ms;
                }
            }
            _ => {
                if below(self.floor) {
                    self.candidate = Some(offset);
                }
            }
        }
        if let Some(f) = self.floor {
            let near = offset >= f && offset.saturating_sub(f) <= FLOOR_NEAR_MS;
            let old = now_ms.saturating_sub(self.at_ms) >= FLOOR_REANCHOR_MS;
            if near && old {
                self.floor = Some(offset);
                self.at_ms = now_ms;
            }
        }
        self.floor.map_or(0, |f| offset.saturating_sub(f).max(0))
    }
}

/// RM2 — the latency at or above which a publisher's own delivery is late.
pub(super) const LATE_MS: f64 = 300.0;
/// RM6 — the latency at or above which another source also reads late (the
/// own-downlink guard).
pub(super) const OTHER_LATE_MS: f64 = 150.0;
/// RM2 — the span a reading takes the median over (about one watch tick of
/// chunks: one late chunk is not a late stream).
pub(super) const READING_MS: u64 = 250;
/// RM2 — the fewest chunks a reading is made of. Under the queue a child
/// receives only its share of the uplink: three copies into a 1.3-copy cap
/// is about 13 chunks a second each, three or four a span.
pub(super) const READING_MIN_SAMPLES: usize = 2;
/// RM2 — the least time a sustained reading's chunks arrive over.
pub(super) const READING_SPAN_MS: u64 = 200;

/// RM2 — one path's latency readings for one stream: the chunks of the last
/// two [`READING_MS`] spans, `(call ms, latency ms)`.
#[derive(Debug, Clone, Default)]
pub(super) struct Reading {
    samples: std::collections::VecDeque<(u64, f64)>,
}

impl Reading {
    /// One chunk's latency at `now_ms`.
    pub(super) fn push(&mut self, now_ms: u64, latency_ms: f64) {
        self.samples.push_back((now_ms, latency_ms));
        while self
            .samples
            .front()
            .is_some_and(|(t, _)| t + 2 * READING_MS < now_ms)
        {
            self.samples.pop_front();
        }
    }

    /// The median of `v` (non-empty).
    fn median(mut v: Vec<f64>) -> f64 {
        v.sort_by(f64::total_cmp);
        v[v.len() / 2]
    }

    /// The reading now: the median of the chunks of the last [`READING_MS`],
    /// when there are at least [`READING_MIN_SAMPLES`] of them.
    pub(super) fn current(&self, now_ms: u64) -> Option<f64> {
        let v: Vec<f64> = self
            .samples
            .iter()
            .filter(|(t, _)| now_ms.saturating_sub(*t) < READING_MS)
            .map(|(_, l)| *l)
            .collect();
        (v.len() >= READING_MIN_SAMPLES).then(|| Self::median(v))
    }

    /// RM2 — whether the path reads late on a SUSTAINED, non-falling
    /// reading: the chunks of the last two [`READING_MS`] spans, at least
    /// [`READING_MIN_SAMPLES`] in each half and arriving over at least
    /// [`READING_SPAN_MS`], split by arrival into an older and a newer half: both halves'
    /// medians at or above `bar`, the newer not below the older. One late
    /// sample is not enough: in the model it made two children leave at
    /// 1.5x where one would do (CallCongestion R13), and a falling reading is
    /// a queue already draining. Split by count, not by clock: a queue
    /// delivers in bursts, and a burst must not read as no reading.
    pub(super) fn sustained_late(&self, now_ms: u64, bar: f64) -> bool {
        let recent: Vec<(u64, f64)> = self
            .samples
            .iter()
            .filter(|(t, _)| now_ms.saturating_sub(*t) < 2 * READING_MS)
            .copied()
            .collect();
        if recent.len() < 2 * READING_MIN_SAMPLES {
            return false;
        }
        let span = recent.last().map_or(0, |l| l.0) - recent.first().map_or(0, |f| f.0);
        if span < READING_SPAN_MS {
            return false;
        }
        let (old, new) = recent.split_at(recent.len() / 2);
        let older = Self::median(old.iter().map(|(_, l)| *l).collect());
        let newer = Self::median(new.iter().map(|(_, l)| *l).collect());
        older >= bar && newer >= bar && newer >= older
    }
}

/// RM4 — `member`'s rank on `stream` ([`hash_rank`]), with the key as the
/// tie-break: the order a publisher's shed and every receiver share.
pub(super) fn rank(stream: StreamId, member: &str) -> (u64, String) {
    (hash_rank(&stream.0, &member.to_owned()), member.to_owned())
}

/// RM4 — the lowest-ranked of `members` on `stream`.
pub(super) fn lowest<'a>(
    stream: StreamId,
    members: impl IntoIterator<Item = &'a String>,
) -> Option<&'a String> {
    members.into_iter().min_by_key(|m| rank(stream, m))
}

/// RM4 — whether `me` is spared on `stream`: it is the lowest-ranked of the
/// publisher's direct children it knows of, itself and `directs` (from the
/// members' fresh offers). Transition: observable, the offers' depth and
/// ancestry; state, this node is a direct child; action, a spared node never
/// moves on late media (the publisher's shed keeps exactly it); must never,
/// spare on a stale offer (the caller passes only fresh ones).
pub(super) fn spared(stream: StreamId, me: &str, directs: &[String]) -> bool {
    let mine = rank(stream, me);
    directs
        .iter()
        .filter(|d| d.as_str() != me)
        .all(|d| rank(stream, d) > mine)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RM1 (45.3 confirm0) — a better floor wins on its confirming pair,
    /// taking the lower of the two: one chunk alone proposes, the next within
    /// FLOOR_NEAR_MS confirms.
    #[test]
    fn a_lower_offset_is_the_new_floor_once_its_pair_confirms_it() {
        let mut f = LatencyFloor::new(100, 0);
        assert_eq!(f.sample(80, 10), 0);
        assert_eq!(f.floor(), 100, "one chunk only proposes");
        assert_eq!(f.sample(90, 20), 10);
        assert_eq!(f.floor(), 80, "confirmed: the lower of the pair");
        assert_eq!(f.sample(130, 30), 50);
    }

    /// R27 AGE (`AgeFloor.tla`, NoFalseStale under confirm0) — one chunk
    /// from a publisher clock 2 s AHEAD (its offset 2 s low) poisons nothing:
    /// not mid-stream, and not as the stream's FIRST chunk. Mutation: taking
    /// a lower offset at once (45.2/45.3 before confirm0) reads every later
    /// chunk 2 s late and fails both.
    #[test]
    fn one_chunk_from_a_stepped_clock_never_sets_the_floor() {
        let mut f = LatencyFloor::new(1_000, 0);
        assert_eq!(f.sample(-1_000, 10), 0, "the stepped chunk");
        assert_eq!(f.sample(1_005, 20), 5, "the next is on time");
        assert_eq!(f.floor(), 1_000);
        // As an empty floor's first chunk.
        let mut f = LatencyFloor::empty(0);
        assert_eq!(f.sample(-1_000, 0), 0);
        assert_eq!(f.confirmed(), None, "a first chunk only proposes");
        assert_eq!(f.sample(1_005, 20), 0);
        assert_eq!(f.sample(1_010, 40), 5);
        assert_eq!(f.confirmed(), Some(1_005), "the on-time pair");
    }

    /// R27 AGE (LivesAfterShift) — a clock that steps AHEAD and stays: the
    /// floor follows on the first pair after the step and the stream lives.
    /// One that steps BACK and stays reads late until the epoch rolls (no
    /// receiver can tell it from a standing queue): the stated limit.
    #[test]
    fn a_clock_stepped_ahead_is_followed_and_one_stepped_back_reads_late() {
        let mut f = LatencyFloor::new(1_000, 0);
        assert_eq!(f.sample(-1_000, 10), 0);
        assert_eq!(f.sample(-995, 20), 5);
        assert_eq!(f.floor(), -1_000, "followed");
        assert_eq!(f.sample(-990, 30), 10, "lives");
        let mut f = LatencyFloor::new(1_000, 0);
        for t in (10..120_000).step_by(20) {
            assert_eq!(f.sample(3_000, t), 2_000, "stepped back, at {t} ms");
        }
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

    /// RM2 — one late chunk, or one late reading, is not a late stream; two
    /// late readings, not falling, are; a falling one is not.
    #[test]
    fn a_reading_is_late_only_when_sustained_and_not_falling() {
        let mut r = Reading::default();
        for t in (0..1_000).step_by(20) {
            r.push(t, 10.0);
        }
        r.push(1_000, 900.0);
        assert!(!r.sustained_late(1_000, LATE_MS), "one sample");
        let mut t = 1_000;
        while t < 1_250 {
            t += 20;
            r.push(t, 400.0);
        }
        assert!(!r.sustained_late(t, LATE_MS), "one late reading");
        while t < 1_520 {
            t += 20;
            r.push(t, 400.0);
        }
        assert!(r.sustained_late(t, LATE_MS), "two, level");
        while t < 1_780 {
            t += 20;
            r.push(t, 350.0);
        }
        assert!(!r.sustained_late(t, LATE_MS), "falling: a queue draining");
        assert!(!r.sustained_late(t + 600, LATE_MS), "no chunks, no reading");
    }

    /// RM4 — exactly one of a set of direct children is spared, and it is
    /// the lowest-ranked.
    #[test]
    fn exactly_the_lowest_ranked_child_is_spared() {
        let s = StreamId([3; 32]);
        let kids: Vec<String> = ["k1", "k2", "k3", "k4"].map(String::from).to_vec();
        let spared_ones: Vec<&String> = kids.iter().filter(|k| spared(s, k, &kids)).collect();
        assert_eq!(spared_ones, vec![lowest(s, &kids).expect("four")]);
        // Alone (no offer seen), a direct child is spared: it may be the one.
        assert!(spared(s, "k2", &[]));
    }
}
