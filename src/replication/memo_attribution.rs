//! 45.1.9 (attribution) — why a memo lookup went to the store.
//!
//! Each hot-path memo counts every lookup under one reason
//! ([`crate::observability::MemoReadLabels`]): answered (`hit`), waited on
//! another caller's read (`joined`), or read because the answer was never
//! filled or was evicted (`miss`), had expired (`ttl`), or was dropped by an
//! event while it was live (`invalidated`).
//!
//! A memo drops its entry on an event, so by the next lookup the entry is
//! gone and "dropped" looks like "never filled". [`DropMarks`] keeps the
//! difference: the door that drops an entry marks its key, the next lookup
//! that finds the key absent reads the mark, and a fill clears it. Every
//! operation is one hash lookup; a whole-memo drop moves the keys it drops
//! (the drop was already O(entries)). This is telemetry only: no answer is
//! read from a mark, and a lost mark only turns a reason into `miss`.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::observability::{EdgeMetrics, MemoReadLabels};

/// Why a lookup went to the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FallThrough {
    /// Never filled, or evicted.
    Miss,
    /// The answer expired.
    Ttl,
    /// An event dropped the answer while it was live.
    Invalidated,
}

impl FallThrough {
    /// The label `labels` counts this reason under.
    pub(crate) const fn label(self, labels: &MemoReadLabels) -> &'static str {
        match self {
            Self::Miss => labels.miss,
            Self::Ttl => labels.ttl,
            Self::Invalidated => labels.invalidated,
        }
    }

    /// The reason a dropped entry leaves: `Invalidated` when it was live,
    /// `Ttl` when it had expired already (the read was owed anyway).
    pub(crate) const fn of_drop(live: bool) -> Self {
        if live {
            Self::Invalidated
        } else {
            Self::Ttl
        }
    }
}

/// Count one lookup answered from the memo.
pub(crate) fn book_hit(metrics: Option<&EdgeMetrics>, labels: &MemoReadLabels) {
    if let Some(m) = metrics {
        labels.inc(m, labels.hit);
    }
}

/// Count one lookup that waited on a read in flight.
pub(crate) fn book_joined(metrics: Option<&EdgeMetrics>, labels: &MemoReadLabels) {
    if let (Some(m), Some(joined)) = (metrics, labels.joined) {
        labels.inc(m, joined);
    }
}

/// Count one store read under its reason.
pub(crate) fn book_read(metrics: Option<&EdgeMetrics>, labels: &MemoReadLabels, why: FallThrough) {
    if let Some(m) = metrics {
        labels.inc(m, why.label(labels));
    }
}

/// The most keys one memo's marks hold. Past it a drop is not marked and its
/// next read counts as `miss`; the memos themselves are bounded by their own
/// working sets, so this only caps what a burst of drops can leave behind.
pub(crate) const DROP_MARKS_CAP: usize = 16_384;

/// The keys an event (or an expiry sweep) dropped from a keyed memo, and the
/// reason each left (see the module docs).
#[derive(Debug)]
pub(crate) struct DropMarks<K> {
    marks: HashMap<K, FallThrough>,
}

impl<K> Default for DropMarks<K> {
    fn default() -> Self {
        Self {
            marks: HashMap::new(),
        }
    }
}

impl<K: Hash + Eq> DropMarks<K> {
    /// `key`'s entry was dropped; `live` says whether it was still fresh.
    pub(crate) fn dropped(&mut self, key: K, live: bool) {
        if self.marks.len() < DROP_MARKS_CAP || self.marks.contains_key(&key) {
            self.marks.insert(key, FallThrough::of_drop(live));
        }
    }

    /// The whole memo was dropped: mark every key it held. The marks are
    /// emptied first when these would not fit under [`DROP_MARKS_CAP`], so a
    /// key marked long ago and never asked since cannot crowd out new marks.
    pub(crate) fn dropped_all(&mut self, dropped: impl IntoIterator<Item = (K, bool)>) {
        let dropped = dropped.into_iter();
        if self.marks.len().saturating_add(dropped.size_hint().0) > DROP_MARKS_CAP {
            self.marks.clear();
        }
        for (key, live) in dropped {
            self.dropped(key, live);
        }
    }

    /// Why a lookup that found `key` absent is reading it.
    pub(crate) fn cause<Q>(&self, key: &Q) -> FallThrough
    where
        K: std::borrow::Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.marks.get(key).copied().unwrap_or(FallThrough::Miss)
    }

    /// `key` was filled: its next drop is a new story.
    pub(crate) fn filled<Q>(&mut self, key: &Q)
    where
        K: std::borrow::Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.marks.remove(key);
    }

    /// Marks held.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.marks.len()
    }
}

/// The mark of a single-slot memo (the consent send set): what emptied it.
#[derive(Debug, Default)]
pub(crate) struct SlotMark(AtomicU8);

const SLOT_UNMARKED: u8 = 0;
const SLOT_TTL: u8 = 1;
const SLOT_INVALIDATED: u8 = 2;

impl SlotMark {
    /// The slot's value was dropped; `live` says whether it was still fresh.
    pub(crate) fn dropped(&self, live: bool) {
        let v = if live { SLOT_INVALIDATED } else { SLOT_TTL };
        self.0.store(v, Ordering::Relaxed);
    }

    /// The slot was filled.
    pub(crate) fn filled(&self) {
        self.0.store(SLOT_UNMARKED, Ordering::Relaxed);
    }

    /// Why a read of the slot is happening: `expired` when a value is present
    /// past its TTL, else what emptied it.
    pub(crate) fn cause(&self, expired: bool) -> FallThrough {
        if expired {
            return FallThrough::Ttl;
        }
        match self.0.load(Ordering::Relaxed) {
            SLOT_INVALIDATED => FallThrough::Invalidated,
            SLOT_TTL => FallThrough::Ttl,
            _ => FallThrough::Miss,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dropped_key_reads_as_its_drop_and_a_fill_clears_it_attribution_1019x() {
        let mut m: DropMarks<String> = DropMarks::default();
        assert_eq!(m.cause("a"), FallThrough::Miss);
        m.dropped("a".into(), true);
        m.dropped("b".into(), false);
        assert_eq!(m.cause("a"), FallThrough::Invalidated);
        assert_eq!(m.cause("b"), FallThrough::Ttl);
        m.filled("a");
        assert_eq!(m.cause("a"), FallThrough::Miss);
        m.dropped_all([("c".to_owned(), true)]);
        assert_eq!(
            m.cause("b"),
            FallThrough::Ttl,
            "a whole drop keeps what fits"
        );
        assert_eq!(m.cause("c"), FallThrough::Invalidated);
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn the_marks_stop_at_their_cap_attribution_1019x() {
        let mut m: DropMarks<usize> = DropMarks::default();
        for k in 0..=DROP_MARKS_CAP {
            m.dropped(k, true);
        }
        assert_eq!(m.len(), DROP_MARKS_CAP);
        assert_eq!(m.cause(&DROP_MARKS_CAP), FallThrough::Miss);
        m.dropped(0, false);
        assert_eq!(m.cause(&0), FallThrough::Ttl, "a held key is re-marked");
        m.dropped_all([(DROP_MARKS_CAP + 1, true)]);
        assert_eq!(m.len(), 1, "a whole drop past the cap starts over");
        assert_eq!(m.cause(&(DROP_MARKS_CAP + 1)), FallThrough::Invalidated);
    }

    #[test]
    fn a_slot_reads_present_expiry_first_attribution_1019x() {
        let s = SlotMark::default();
        assert_eq!(s.cause(false), FallThrough::Miss);
        s.dropped(true);
        assert_eq!(s.cause(false), FallThrough::Invalidated);
        assert_eq!(s.cause(true), FallThrough::Ttl);
        s.filled();
        assert_eq!(s.cause(false), FallThrough::Miss);
        s.dropped(false);
        assert_eq!(s.cause(false), FallThrough::Ttl);
    }
}
