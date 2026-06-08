//! Local-state-to-summary computation + diff logic.
//!
//! Edge's `Session` (in [`super::session`]) sits above this surface;
//! callers wiring a live deployment provide a [`StateProvider`] /
//! [`StateApplier`] pair over their `FederationDirectory` and the
//! Session orchestrates rounds.
//!
//! ## Bounded-staleness signal
//!
//! [`StalenessSignal`] is the consumer-facing telemetry surfaced by
//! the Session at the end of each round. Consumers (lens, agent,
//! verify-coord) condition τ_partial on this signal — when staleness
//! is bounded and below the consumer's tolerance, normal R1 quorum
//! applies; when staleness is unknown or above tolerance, the consumer
//! degrades to τ_partial / partition-mode semantics.

use std::collections::{BTreeMap, BTreeSet};

use super::protocol::{EnvelopeKind, EnvelopeRef};

/// Snapshot of the envelopes a peer holds locally per
/// [`EnvelopeKind`]. The state machine consumes this to build
/// [`super::protocol::SummaryMessage`]s and to identify which envelopes
/// need to be delivered to the peer.
///
/// Use `BTreeMap` (sorted, deterministic iteration) rather than
/// `HashMap` so the on-wire `SummaryMessage::refs` order is stable
/// across runs — a test that pins exact bytes can be deterministic;
/// in production it makes diff computation predictable for
/// debugging.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LocalState {
    /// Per-kind set of `(envelope_hash, seq)`. Storing seq inside the
    /// map lets the diff logic prefer the higher-seq variant when two
    /// peers have the same content-hash at different seqs (shouldn't
    /// happen — content-hash collisions across seqs would be a
    /// canonical-bytes bug — but the data model has a slot for it).
    pub by_kind: BTreeMap<EnvelopeKind, BTreeMap<[u8; 32], u64>>,
}

impl LocalState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an envelope to local state. Idempotent on (kind,
    /// envelope_hash) — re-inserting updates seq if the new seq is
    /// higher, otherwise no-op.
    pub fn insert(&mut self, kind: EnvelopeKind, envelope_hash: [u8; 32], seq: u64) {
        let entry = self.by_kind.entry(kind).or_default();
        let slot = entry.entry(envelope_hash).or_insert(seq);
        if seq > *slot {
            *slot = seq;
        }
    }

    /// Build a [`super::protocol::SummaryMessage`]-shaped list for
    /// `kind`. Iteration order is BTreeMap-stable.
    pub fn refs_for(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        self.by_kind
            .get(&kind)
            .map(|inner| {
                inner
                    .iter()
                    .map(|(h, s)| EnvelopeRef {
                        envelope_hash: *h,
                        seq: *s,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Count envelopes for `kind` — useful for staleness telemetry.
    pub fn count(&self, kind: EnvelopeKind) -> usize {
        self.by_kind.get(&kind).map_or(0, BTreeMap::len)
    }
}

/// Trait the live Session calls to read local state. Production
/// adapter (follow-up PR) wraps `FederationDirectory`'s
/// `list_attestations` / `list_federation_keys` / `list_revocations`
/// surfaces.
pub trait StateProvider: Send + Sync {
    /// Snapshot local state for the given kind. Implementations
    /// should be cheap (the state is read once per anti-entropy
    /// round); callers don't memoize.
    fn local_refs(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef>;

    /// Return the byte-exact signed envelope for the given content
    /// hash, or `None` if the envelope isn't in local state. Called
    /// during the Deliver-message construction step.
    fn fetch_envelope(&self, kind: EnvelopeKind, envelope_hash: &[u8; 32]) -> Option<Vec<u8>>;
}

/// Trait the live Session calls to apply received envelopes. Wraps
/// persist's `put_*` admit surface; the impl is responsible for
/// validating the envelope (signature + canonical-bytes hash) before
/// committing to local state. Errors NOT surfaced by this trait —
/// the apply path is idempotent (a duplicate apply hits persist's
/// R1/Q1 dedupe and returns no-op).
pub trait StateApplier: Send + Sync {
    /// Apply one envelope to local state. The receiver MUST verify
    /// the signed envelope's signature + canonical-bytes hash before
    /// admitting; if validation fails the apply silently no-ops
    /// (the merge layer in persist is the canonical anti-rollback
    /// authority). Returns `true` if the apply admitted a new
    /// envelope (changed local state), `false` if it was a duplicate
    /// or refused.
    fn apply_envelope(&mut self, kind: EnvelopeKind, envelope_bytes: &[u8]) -> bool;
}

/// Compute the diff between two summaries — which hashes the LOCAL
/// peer doesn't have that the REMOTE peer claims to have. This is
/// the input to a `DiffMessage::want` field.
pub fn diff_refs(local: &[EnvelopeRef], remote: &[EnvelopeRef]) -> Vec<[u8; 32]> {
    let local_set: BTreeSet<[u8; 32]> = local.iter().map(|r| r.envelope_hash).collect();
    remote
        .iter()
        .filter(|r| !local_set.contains(&r.envelope_hash))
        .map(|r| r.envelope_hash)
        .collect()
}

/// The freshness signal exposed to consumers per [`EnvelopeKind`].
/// Drives τ_partial / partition-mode semantics in
/// CIRISVerify#48/#49 consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StalenessSignal {
    /// Local state matches the most recent remote summary received
    /// for this kind. Consumers may operate in normal R1 mode.
    InSync,
    /// Local state is missing N envelopes vs the most recent remote
    /// summary. Bounded staleness — consumers can decide whether to
    /// degrade based on N.
    BoundedBy { missing: u64 },
    /// No anti-entropy round has completed for this kind since
    /// process start (or since the local clock was last reset).
    /// Consumers SHOULD treat this as worst-case stale.
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(seed: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = seed;
        a
    }

    /// Insert + idempotent re-insert + count.
    #[test]
    fn local_state_inserts_and_counts() {
        let mut s = LocalState::new();
        s.insert(EnvelopeKind::Key, h(1), 100);
        s.insert(EnvelopeKind::Key, h(2), 200);
        s.insert(EnvelopeKind::Attestation, h(3), 50);
        assert_eq!(s.count(EnvelopeKind::Key), 2);
        assert_eq!(s.count(EnvelopeKind::Attestation), 1);
        assert_eq!(s.count(EnvelopeKind::Revocation), 0);
        // Re-insert same (kind, hash) at higher seq updates seq.
        s.insert(EnvelopeKind::Key, h(1), 150);
        let refs = s.refs_for(EnvelopeKind::Key);
        let r1 = refs.iter().find(|r| r.envelope_hash == h(1)).unwrap();
        assert_eq!(r1.seq, 150);
        // Re-insert at lower seq is a no-op.
        s.insert(EnvelopeKind::Key, h(1), 120);
        let refs2 = s.refs_for(EnvelopeKind::Key);
        let r1b = refs2.iter().find(|r| r.envelope_hash == h(1)).unwrap();
        assert_eq!(r1b.seq, 150);
    }

    /// `refs_for` returns BTreeMap-sorted output — deterministic
    /// ordering matters for test stability + protocol determinism.
    #[test]
    fn refs_for_is_sorted_by_envelope_hash() {
        let mut s = LocalState::new();
        // Insert in non-sorted order.
        s.insert(EnvelopeKind::Key, h(9), 1);
        s.insert(EnvelopeKind::Key, h(1), 2);
        s.insert(EnvelopeKind::Key, h(5), 3);
        let refs = s.refs_for(EnvelopeKind::Key);
        // BTreeMap stable ordering by key.
        assert_eq!(refs[0].envelope_hash, h(1));
        assert_eq!(refs[1].envelope_hash, h(5));
        assert_eq!(refs[2].envelope_hash, h(9));
    }

    /// Empty kind returns empty refs.
    #[test]
    fn refs_for_empty_kind_returns_empty() {
        let s = LocalState::new();
        assert!(s.refs_for(EnvelopeKind::Community).is_empty());
    }

    /// Diff of disjoint local vs remote — local wants everything.
    #[test]
    fn diff_disjoint_wants_everything() {
        let local: Vec<EnvelopeRef> = vec![];
        let remote = vec![
            EnvelopeRef {
                envelope_hash: h(1),
                seq: 1,
            },
            EnvelopeRef {
                envelope_hash: h(2),
                seq: 2,
            },
        ];
        let want = diff_refs(&local, &remote);
        assert_eq!(want, vec![h(1), h(2)]);
    }

    /// Diff of identical sets — want is empty.
    #[test]
    fn diff_identical_wants_nothing() {
        let local = vec![
            EnvelopeRef {
                envelope_hash: h(1),
                seq: 1,
            },
            EnvelopeRef {
                envelope_hash: h(2),
                seq: 2,
            },
        ];
        let remote = local.clone();
        let want = diff_refs(&local, &remote);
        assert!(want.is_empty());
    }

    /// Partial overlap — want is the remote-minus-local set.
    #[test]
    fn diff_partial_overlap() {
        let local = vec![EnvelopeRef {
            envelope_hash: h(1),
            seq: 1,
        }];
        let remote = vec![
            EnvelopeRef {
                envelope_hash: h(1),
                seq: 1,
            },
            EnvelopeRef {
                envelope_hash: h(2),
                seq: 2,
            },
            EnvelopeRef {
                envelope_hash: h(3),
                seq: 3,
            },
        ];
        let want = diff_refs(&local, &remote);
        assert_eq!(want, vec![h(2), h(3)]);
    }

    /// Local has hashes the remote doesn't — those don't show up in
    /// our wants. The reverse-direction Summary/Diff from the remote
    /// would pick them up.
    #[test]
    fn diff_local_has_extras_ignored() {
        let local = vec![
            EnvelopeRef {
                envelope_hash: h(1),
                seq: 1,
            },
            EnvelopeRef {
                envelope_hash: h(2),
                seq: 2,
            },
        ];
        let remote = vec![EnvelopeRef {
            envelope_hash: h(1),
            seq: 1,
        }];
        let want = diff_refs(&local, &remote);
        assert!(
            want.is_empty(),
            "local extras shouldn't appear in want list"
        );
    }
}
