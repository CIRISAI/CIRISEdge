//! §3.3 announce-suppression policy (CIRISEdge#175, v6.1.0).
//!
//! Per CEWP `SCOPE_PRIVACY.md` §3.3:
//!
//! > No RNS announce for group-scoped destinations. Group members
//! > resolve each other's destinations from the cached directory +
//! > per-group HKDF. Per-destination announce control is a small
//! > Leviculum extension.
//!
//! This module owns the **edge-side decision** "should this
//! destination be announced mesh-wide?". The Leviculum upstream
//! exposes per-destination announce control via a future
//! extension surface; until that lands, edge guards every
//! announce emission at the boundary so even a Leviculum without
//! per-destination control honors the §3.3 suppression contract.
//!
//! # Decision rule
//!
//! [`should_suppress_announce`] returns `true` for destinations whose
//! [`CohortScope`] is anything other than [`CohortScope::Public`].
//! `SelfOnly`, `Family`, and `Cohort` destinations are group-scoped
//! per the FSD §2.1 lattice and MUST NOT be announced mesh-wide;
//! only `Public` (federation Commons) destinations announce.
//!
//! # Upstream gap (documented for v6.2.0 / Leviculum-next)
//!
//! The Leviculum repo (`~/Leviculum`, vendored as `reticulum-core` /
//! `reticulum-std` via `CIRISAI/leviculum` fork at SHA
//! `6b005e9d85874d4db025c090626c29b966d94e9e` in this cut's
//! `Cargo.lock`) does NOT yet expose per-destination announce
//! control. The current surface
//! ([`reticulum_core::traits`]) tracks `announce_rate_table` +
//! `get_announce` / `set_announce` keyed on destination hash, but
//! has no "suppress-this-destination" opt-in. The recommended
//! upstream extension shape:
//!
//! ```rust,ignore
//! pub trait AnnounceControl {
//!     /// Mark a destination hash as announce-suppressed —
//!     /// Leviculum's announce dispatcher SKIPS announce emission
//!     /// for marked destinations even when the periodic-announce
//!     /// timer fires.
//!     fn suppress_announce(&self, dest_hash: &[u8; 16]);
//!     /// Unmark a destination hash.
//!     fn unsuppress_announce(&self, dest_hash: &[u8; 16]);
//!     /// Query.
//!     fn is_announce_suppressed(&self, dest_hash: &[u8; 16]) -> bool;
//! }
//! ```
//!
//! The edge-side [`AnnounceSuppressionRegistry`] below mirrors this
//! shape so the upstream patch is a one-line `impl AnnounceControl`
//! delegation when it lands.

use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::cohort_scope::CohortScope;

/// FSD §3.3 announce-suppression decision rule. Returns `true` iff
/// the destination's [`CohortScope`] is anything other than
/// [`CohortScope::Public`] — group-scoped destinations
/// (`SelfOnly` / `Family` / `Cohort`) are suppressed.
#[must_use]
pub fn should_suppress_announce(scope: &CohortScope) -> bool {
    !matches!(scope, CohortScope::Public)
}

/// In-memory announce-suppression registry. Mirrors the
/// recommended Leviculum `AnnounceControl` trait shape so the
/// upstream patch is a thin delegation.
///
/// Clone-cheap (`Arc<RwLock<HashSet>>` inner). Multiple Edge
/// surfaces (announce-emission gate, scope-policy admin) share one
/// registry.
#[derive(Default, Clone)]
pub struct AnnounceSuppressionRegistry {
    inner: Arc<RwLock<HashSet<[u8; 16]>>>,
}

impl AnnounceSuppressionRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark `dest_hash` as announce-suppressed. The
    /// announce-emission gate at the substrate boundary MUST
    /// consult [`Self::is_suppressed`] before every announce
    /// emission.
    pub fn suppress(&self, dest_hash: [u8; 16]) {
        self.inner.write().insert(dest_hash);
    }

    /// Unmark `dest_hash`. Future announces for the destination
    /// flow normally.
    pub fn unsuppress(&self, dest_hash: &[u8; 16]) {
        self.inner.write().remove(dest_hash);
    }

    /// `true` iff `dest_hash` is currently announce-suppressed.
    #[must_use]
    pub fn is_suppressed(&self, dest_hash: &[u8; 16]) -> bool {
        self.inner.read().contains(dest_hash)
    }

    /// Number of suppressed destinations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// `true` iff no destinations are suppressed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_scope_announces() {
        assert!(!should_suppress_announce(&CohortScope::Public));
    }

    #[test]
    fn group_scopes_suppressed() {
        assert!(should_suppress_announce(&CohortScope::SelfOnly));
        assert!(should_suppress_announce(&CohortScope::Family));
        assert!(should_suppress_announce(&CohortScope::Cohort {
            cohort_id: "alpha".into()
        }));
    }

    #[test]
    fn registry_round_trip() {
        let r = AnnounceSuppressionRegistry::new();
        let h = [0xAAu8; 16];
        assert!(r.is_empty());
        assert!(!r.is_suppressed(&h));
        r.suppress(h);
        assert_eq!(r.len(), 1);
        assert!(r.is_suppressed(&h));
        r.unsuppress(&h);
        assert!(!r.is_suppressed(&h));
        assert!(r.is_empty());
    }

    #[test]
    fn registry_multiple_destinations() {
        let r = AnnounceSuppressionRegistry::new();
        for i in 0..5u8 {
            r.suppress([i; 16]);
        }
        assert_eq!(r.len(), 5);
        for i in 0..5u8 {
            assert!(r.is_suppressed(&[i; 16]));
        }
    }
}
