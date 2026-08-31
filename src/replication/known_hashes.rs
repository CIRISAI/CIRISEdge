//! CIRISEdge#552 — hashes this node KNOWS EXIST but whose bodies it does not
//! hold.
//!
//! # The one invariant
//!
//! `want = remote ∖ holdings`. This set is **not holdings**. A hash in here has
//! never been fetched, verified or admitted — it is hearsay from a peer's
//! Summary. If it ever reaches the holdings side of that difference, the node
//! concludes it already has everything it has merely heard of and silently
//! stops fetching: CIRISEdge#416's non-convergence with the sign flipped, and
//! invisible, because nothing errors and anti-entropy just goes quiet.
//!
//! That is why this type yields no [`EnvelopeRef`](super::protocol::EnvelopeRef)
//! and never will. `diff_refs` takes `&[EnvelopeRef]`; a set that cannot produce
//! one cannot be passed to it by accident. Adding such an accessor "for
//! symmetry" is the single change that would undo this module.
//!
//! # Ageing
//!
//! Entries age on **last advertised**, never first seen. CIRISPersist#776 is the
//! cautionary case: a prune aged on `asserted_at`, a value its writer freezes,
//! so the cutoff never advanced — and both consumers independently refused to
//! call it rather than reporting a fault. `last_advertised` moves because the
//! advertise axis re-sweeps and wraps, which is also what makes eviction
//! recoverable. Ageing column and recovery mechanism are the same fact; built
//! from different columns, that is the bug.
//!
//! # Eviction
//!
//! The caller supplies a cutoff — never a period. Recovery latency is one wrap
//! of the peer's rolling re-sweep (`corpus ÷ page_budget × cadence`), and all
//! three inputs live on this side. Passing a cutoff rather than a period keeps
//! one owner for that number instead of a frozen copy on the other side of a
//! boundary.
//!
//! # Disclosure
//!
//! The advertising peer is recorded because it is the holder map — the
//! difference between knowing Frank exists and knowing who to ask. It is an
//! OBSERVATION ("this peer advertised H to me"), not a claim, it is derived from
//! Summaries this node already received, and it is **local only**: no
//! replication policy kind, no wire-index coverage, nothing that reaches an
//! envelope. Serialising it "for debugging" is how it becomes a who-holds-what
//! index for the whole corpus.

use std::collections::HashMap;

use super::protocol::EnvelopeKind;

/// A hash known to exist, and where it was last heard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHash {
    /// Unix seconds when a peer last advertised it. The ageing column.
    pub last_advertised_unix: u64,
    /// The peer that last advertised it — the holder map. Local only.
    pub last_advertised_by: String,
}

/// Bounded set of known-but-not-held hashes.
#[derive(Debug)]
pub struct KnownHashes {
    entries: HashMap<(EnvelopeKind, [u8; 32]), KnownHash>,
    cap: usize,
}

impl KnownHashes {
    /// Default cap. Sized like the other bounded memories in this crate: large
    /// enough that a real federation directory fits, small enough that a
    /// hostile peer advertising nonsense cannot grow it without bound.
    pub const DEFAULT_CAP: usize = 262_144;

    #[must_use]
    pub fn new() -> Self {
        Self::with_cap(Self::DEFAULT_CAP)
    }

    #[must_use]
    pub fn with_cap(cap: usize) -> Self {
        Self {
            entries: HashMap::new(),
            cap: cap.max(1),
        }
    }

    /// Record that `peer` advertised `hash` for `kind` at `now`.
    ///
    /// Re-noting an existing entry advances `last_advertised_unix` — that is the
    /// re-sweep keeping it alive, and the reason ageing on first-seen would be
    /// wrong.
    pub fn note(&mut self, kind: EnvelopeKind, hash: [u8; 32], peer: &str, now: u64) {
        if self.entries.len() >= self.cap && !self.entries.contains_key(&(kind, hash)) {
            // At cap: drop the least-recently-advertised entry. Evicting is
            // recoverable — the peer's rolling re-sweep wraps and re-offers it.
            if let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(_, v)| v.last_advertised_unix)
                .map(|(k, _)| *k)
            {
                self.entries.remove(&victim);
            }
        }
        let slot = self.entries.entry((kind, hash)).or_insert(KnownHash {
            last_advertised_unix: now,
            last_advertised_by: peer.to_owned(),
        });
        // Monotonic: a peer with a lagging clock must not age an entry the
        // re-sweep just refreshed.
        if now >= slot.last_advertised_unix {
            slot.last_advertised_unix = now;
            peer.clone_into(&mut slot.last_advertised_by);
        }
    }

    /// Is this hash known (without being held)?
    #[must_use]
    pub fn contains(&self, kind: EnvelopeKind, hash: &[u8; 32]) -> bool {
        self.entries.contains_key(&(kind, *hash))
    }

    /// Who last advertised it — the holder to ask. Local only.
    #[must_use]
    pub fn holder(&self, kind: EnvelopeKind, hash: &[u8; 32]) -> Option<&str> {
        self.entries
            .get(&(kind, *hash))
            .map(|e| e.last_advertised_by.as_str())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop entries not advertised since `cutoff_unix`.
    ///
    /// The CALLER computes the cutoff, because recovery latency is one wrap of
    /// the advertise re-sweep and its inputs live on this side. A cutoff younger
    /// than one wrap evicts entries the re-sweep has not come back around to,
    /// and the set thrashes against the mechanism that refills it.
    pub fn evict_advertised_before(&mut self, cutoff_unix: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, v| v.last_advertised_unix >= cutoff_unix);
        before - self.entries.len()
    }
}

impl Default for KnownHashes {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::KnownHashes;
    use crate::replication::protocol::EnvelopeKind;

    fn h(n: u8) -> [u8; 32] {
        [n; 32]
    }

    /// A known hash is recorded with its holder, so a later fetch knows who to
    /// ask rather than broadcasting.
    #[test]
    fn a_noted_hash_is_known_and_carries_its_holder() {
        let mut k = KnownHashes::new();
        k.note(EnvelopeKind::Attestation, h(1), "peer-a", 100);
        assert!(k.contains(EnvelopeKind::Attestation, &h(1)));
        assert_eq!(k.holder(EnvelopeKind::Attestation, &h(1)), Some("peer-a"));
    }

    /// Kind is part of the key. The same content hash on two planes is two
    /// records, and collapsing them would let a fetch on one plane satisfy a
    /// want on another.
    #[test]
    fn the_same_hash_on_two_planes_is_two_entries() {
        let mut k = KnownHashes::new();
        k.note(EnvelopeKind::Attestation, h(1), "peer-a", 100);
        assert!(!k.contains(EnvelopeKind::Key, &h(1)));
        assert_eq!(k.len(), 1);
    }

    /// CIRISPersist#776's lesson, applied. Re-advertisement REFRESHES the entry;
    /// if this aged on first-seen the cutoff would never advance for a record the
    /// re-sweep keeps offering, and eviction would delete live knowledge.
    #[test]
    fn re_advertising_refreshes_the_ageing_column() {
        let mut k = KnownHashes::new();
        k.note(EnvelopeKind::Attestation, h(1), "peer-a", 100);
        k.note(EnvelopeKind::Attestation, h(1), "peer-b", 500);

        assert_eq!(
            k.evict_advertised_before(400),
            0,
            "it was re-advertised at 500"
        );
        assert!(k.contains(EnvelopeKind::Attestation, &h(1)));
        assert_eq!(
            k.holder(EnvelopeKind::Attestation, &h(1)),
            Some("peer-b"),
            "the holder is the peer that most recently offered it"
        );
    }

    /// A lagging peer clock must not age an entry backwards — the same
    /// monotonic discipline the liveness stamp uses, for the same reason.
    #[test]
    fn a_backwards_clock_cannot_age_an_entry() {
        let mut k = KnownHashes::new();
        k.note(EnvelopeKind::Attestation, h(1), "peer-a", 500);
        k.note(EnvelopeKind::Attestation, h(1), "peer-late", 100);
        assert_eq!(k.evict_advertised_before(400), 0, "500 must stand");
        assert_eq!(
            k.holder(EnvelopeKind::Attestation, &h(1)),
            Some("peer-a"),
            "a stale advertisement must not take over the holder slot either"
        );
    }

    /// Eviction drops only what the cutoff names.
    #[test]
    fn eviction_drops_only_entries_older_than_the_cutoff() {
        let mut k = KnownHashes::new();
        k.note(EnvelopeKind::Attestation, h(1), "peer-a", 100);
        k.note(EnvelopeKind::Attestation, h(2), "peer-a", 900);
        assert_eq!(k.evict_advertised_before(500), 1);
        assert!(!k.contains(EnvelopeKind::Attestation, &h(1)));
        assert!(k.contains(EnvelopeKind::Attestation, &h(2)));
    }

    /// At the cap the LEAST RECENTLY ADVERTISED entry goes, not an arbitrary
    /// one: eviction is recoverable via the re-sweep, so the entry furthest from
    /// its last refresh is the cheapest to re-learn.
    #[test]
    fn at_the_cap_the_stalest_entry_is_evicted() {
        let mut k = KnownHashes::with_cap(2);
        k.note(EnvelopeKind::Attestation, h(1), "p", 100);
        k.note(EnvelopeKind::Attestation, h(2), "p", 900);
        k.note(EnvelopeKind::Attestation, h(3), "p", 950);

        assert_eq!(k.len(), 2);
        assert!(
            !k.contains(EnvelopeKind::Attestation, &h(1)),
            "stalest goes"
        );
        assert!(k.contains(EnvelopeKind::Attestation, &h(3)));
    }

    /// Re-noting an entry at the cap must not evict anything — it is a refresh,
    /// not an insert. Getting this wrong would make a busy set evict itself.
    #[test]
    fn refreshing_at_the_cap_evicts_nothing() {
        let mut k = KnownHashes::with_cap(2);
        k.note(EnvelopeKind::Attestation, h(1), "p", 100);
        k.note(EnvelopeKind::Attestation, h(2), "p", 200);
        k.note(EnvelopeKind::Attestation, h(1), "p", 300);
        assert_eq!(k.len(), 2);
        assert!(k.contains(EnvelopeKind::Attestation, &h(2)));
    }
}
