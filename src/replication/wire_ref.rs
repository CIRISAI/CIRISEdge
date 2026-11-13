//! **The ref of served bytes** (persist 61.3.0, CIRISPersist#1252; CC 3.3.4,
//! CC 2.6.1.8).
//!
//! A peer advertises, and is asked for, rows by their content-hash ref. Until
//! persist 61.3.0 the ref of every row was `sha256(served bytes)`, and edge
//! took it itself wherever it held bytes. Since 61.3.0 a cosignable group row
//! (an assembled `membership:widening:v1` / `membership:removal:v1` carrying
//! cosignatures) is named by its ACT: persist's
//! [`attestation_wire_hash`](ciris_persist::federation::wire_index::attestation_wire_hash),
//! the hash of the row re-planned with no cosignatures. Two nodes that hold
//! one act with different sufficient subsets, or other randomised ML-DSA
//! bytes, then advertise the same ref and stay quiet on a diff.
//!
//! [`envelope_ref`] is edge's ONE ref rule for served bytes: persist's for an
//! Attestation-index plane, `sha256` everywhere else. [`plain_ref`] is the
//! pre-61.3 rule, which a 61.2 peer still advertises; edge accepts it for a
//! body it asked for (`Session`) and remembers it as held when the row it
//! names is held under the act ref ([`super::bridge`]'s held-equivalent set).

use sha2::{Digest as _, Sha256};

use super::protocol::EnvelopeKind;

/// `sha256(bytes)`: the ref of every row before persist 61.3.0, and of every
/// row that is not a cosigned group row since.
#[must_use]
pub fn plain_ref(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The bytes persist serializes a cosignature list as when it is not empty.
/// A row without it is named by its own bytes, so the check keeps the common
/// path to one hash.
const NON_EMPTY_COSIGNATURES: &[u8] = b"\"cosignatures\":[{";

/// **THE ref of served bytes on `kind`**: persist's
/// `attestation_wire_hash` for a plane that rides persist's Attestation
/// index, `sha256(bytes)` for every other plane and for bytes that do not
/// decode as an attestation row.
#[must_use]
pub fn envelope_ref(kind: EnvelopeKind, bytes: &[u8]) -> [u8; 32] {
    if kind.persist_index_kind() != Some("Attestation")
        || !bytes
            .windows(NON_EMPTY_COSIGNATURES.len())
            .any(|w| w == NON_EMPTY_COSIGNATURES)
    {
        return plain_ref(bytes);
    }
    match serde_json::from_slice::<ciris_persist::federation::Attestation>(bytes) {
        Ok(row) => ciris_persist::federation::wire_index::attestation_wire_hash(&row),
        Err(_) => plain_ref(bytes),
    }
}

/// Is `bytes` on `kind` named by something other than its own hash (an
/// assembled cosigned group row)? Then a 61.2 peer advertises it under a ref
/// this node's index never holds.
#[must_use]
pub fn is_act_named(kind: EnvelopeKind, bytes: &[u8]) -> bool {
    envelope_ref(kind, bytes) != plain_ref(bytes)
}

/// How many offered refs [`HeldEquivalentRefs`] remembers before it forgets
/// the oldest. An evicted ref costs one more fetch, answered as held again.
pub const HELD_EQUIVALENT_CAPACITY: usize = 16_384;

/// **Refs a peer offers for content this node holds under another ref**
/// (persist 61.3.0, CIRISPersist#1252, its (b)). A 61.2 peer advertises an
/// assembled cosigned row by the hash of its bytes, a node holding another
/// sufficient subset of the same act advertises the same act ref but other
/// bytes, and a cosign signature row with other randomised ML-DSA bytes has
/// another hash: persist settles each as held (`HeldEquivalent`, or a
/// duplicate of the act), but none of those refs is in this node's index, so
/// the receive diff would want it again every round. Remembered here, apart
/// from the holdings index (which stays exactly persist's index, and whose
/// audit would remove a ref persist does not hold), and taken out of every
/// receive diff. Bounded; never advertised.
#[derive(Debug, Default)]
pub struct HeldEquivalentRefs {
    inner: std::sync::Mutex<(
        std::collections::HashSet<[u8; 32]>,
        std::collections::VecDeque<[u8; 32]>,
    )>,
}

impl HeldEquivalentRefs {
    /// Remember `r` as held. Returns whether it was new.
    pub fn note(&self, r: [u8; 32]) -> bool {
        let Ok(mut g) = self.inner.lock() else {
            return false;
        };
        let (set, order) = &mut *g;
        if !set.insert(r) {
            return false;
        }
        order.push_back(r);
        while order.len() > HELD_EQUIVALENT_CAPACITY {
            if let Some(old) = order.pop_front() {
                set.remove(&old);
            }
        }
        true
    }

    /// Is `r` remembered as held?
    #[must_use]
    pub fn contains(&self, r: &[u8; 32]) -> bool {
        self.inner.lock().is_ok_and(|g| g.0.contains(r))
    }

    /// `want` without the refs remembered as held.
    #[must_use]
    pub fn filter_want(&self, want: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
        let Ok(g) = self.inner.lock() else {
            return want;
        };
        if g.0.is_empty() {
            return want;
        }
        want.into_iter().filter(|h| !g.0.contains(h)).collect()
    }

    /// How many refs are remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().map_or(0, |g| g.0.len())
    }

    /// Whether none is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A row with no cosignature, and bytes that are no row, keep their own
    /// hash on every plane.
    #[test]
    fn a_row_without_cosignatures_is_named_by_its_own_bytes() {
        let bytes = br#"{"not":"a row","cosignatures":[]}"#;
        for kind in [
            EnvelopeKind::Attestation,
            EnvelopeKind::TransportDestination,
        ] {
            assert_eq!(envelope_ref(kind, bytes), plain_ref(bytes));
            assert!(!is_act_named(kind, bytes));
        }
        let garbage = br#"{"cosignatures":[{"x":1}]}"#;
        assert_eq!(
            envelope_ref(EnvelopeKind::Attestation, garbage),
            plain_ref(garbage),
            "bytes that do not decode keep the plain ref"
        );
    }

    /// The set is bounded and forgets the oldest ref first.
    #[test]
    fn the_held_equivalent_set_is_bounded_oldest_first() {
        let s = HeldEquivalentRefs::default();
        let r = |n: usize| {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&(n as u64).to_le_bytes());
            b
        };
        for n in 0..=HELD_EQUIVALENT_CAPACITY {
            assert!(s.note(r(n)));
        }
        assert!(!s.note(r(1)), "a ref already held is not new");
        assert_eq!(s.len(), HELD_EQUIVALENT_CAPACITY);
        assert!(!s.contains(&r(0)), "the oldest is forgotten");
        assert_eq!(s.filter_want(vec![r(0), r(1)]), vec![r(0)]);
    }
}
