//! §3.3 announce-suppression policy (CIRISEdge#175, v6.1.0;
//! Leviculum v0.7.0 `AnnounceControl` adoption v7.0.0 CIRISEdge#195).
//!
//! Per CEWP `SCOPE_PRIVACY.md` §3.3:
//!
//! > No RNS announce for group-scoped destinations. Group members
//! > resolve each other's destinations from the cached directory +
//! > per-group HKDF. Per-destination announce control is a small
//! > Leviculum extension.
//!
//! This module owns the **edge-side decision** "should this
//! destination be announced mesh-wide?". v7.0.0 (CIRISEdge#195) lands
//! the upstream half: Leviculum v0.7.0 ships an `AnnounceControl`
//! trait on `NodeCore` that consults a caller-supplied policy on every
//! scheduled announce; the policy here installs onto the leviculum
//! node via `NodeCore::set_announce_control`.
//!
//! # Decision rule
//!
//! Suppress every destination whose [`CohortScope`] resolves to
//! anything other than `CryptoTier::Plaintext` (i.e.
//! [`ciris_persist::federation::types::cohort_scope::CryptoTier`])
//! — i.e. group-scoped destinations (`SelfOnly`, `Family`, `Cohort`)
//! whose announce would leak a membership delta. Commons-tier scopes
//! (`Public` → federation/species/biosphere) announce normally.
//!
//! The mapping `DestinationHash → CohortScope` is operator state: the
//! [`ScopePrivacyAnnouncePolicy`] keeps an in-memory table populated
//! as scoped destinations are created (the same table the explicit-
//! hash routable destinations register against). Lookups are O(1) hash
//! map probes — small enough to honor leviculum's "synchronous, must
//! not block" contract on `should_suppress_announce`.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::cohort_scope::CohortScope;

#[cfg(feature = "_reticulum-module")]
use leviculum_core::{AnnounceControl, DestinationHash};

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
///
/// v7.0.0 (CIRISEdge#195): retained as the legacy in-process side-
/// table. Production should construct a [`ScopePrivacyAnnouncePolicy`]
/// and install it on the leviculum node via
/// `NodeCore::set_announce_control(...)` — the policy below carries
/// the load-bearing scope→tier dispatch the upstream contract
/// needs.
#[derive(Default, Clone)]
pub struct AnnounceSuppressionRegistry {
    inner: Arc<RwLock<std::collections::HashSet<[u8; 16]>>>,
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

/// v7.0.0 (CIRISEdge#195) — installs onto a Leviculum v0.7.0
/// `NodeCore` via `NodeCore::set_announce_control(...)` and gates
/// every scheduled announce on the destination's
/// [`CohortScope`]-derived [`CryptoTier`]:
///
/// - [`CryptoTier::InvisibleEncrypted`] (`self` / `family`) → suppress
/// - [`CryptoTier::CommunityDek`] (`community` / `affiliations`) → suppress
/// - [`CryptoTier::Plaintext`] (Commons, infrastructure communities,
///   unrecognized scopes) → allow
///
/// The mapping `DestinationHash → CohortScope` is operator state.
/// Production wires it through [`Self::register_destination_scope`] as
/// edge admits each scoped destination (the same scope it stamps onto
/// the destination's outbound envelopes).
///
/// **Explicit-hash interop guard**: an explicit-hash destination
/// (`Destination::with_explicit_hash`) is wire-incompatible with
/// Python-RNS announces — leviculum returns
/// `AnnounceError::ExplicitHashCannotAnnounce` if it ever tries to
/// announce one. Edge's scope-privacy destinations are constructed
/// explicit-hash, so they MUST be registered here (Commons-scope or
/// otherwise) before the leviculum node would otherwise try to
/// announce them. The default-suppress posture below makes the
/// safest call: unknown destination hashes are suppressed, matching
/// the "never try to announce an explicit hash" contract.
///
/// [`CryptoTier`]: ciris_persist::federation::types::cohort_scope::CryptoTier
/// [`CryptoTier::InvisibleEncrypted`]: ciris_persist::federation::types::cohort_scope::CryptoTier::InvisibleEncrypted
/// [`CryptoTier::CommunityDek`]: ciris_persist::federation::types::cohort_scope::CryptoTier::CommunityDek
/// [`CryptoTier::Plaintext`]: ciris_persist::federation::types::cohort_scope::CryptoTier::Plaintext
#[derive(Default, Clone)]
pub struct ScopePrivacyAnnouncePolicy {
    /// `dest_hash → cohort scope` table. Unknown hashes fall through
    /// to default-suppress: scope-privacy destinations MUST register
    /// here, and a missing registration is safer-than-leak.
    scopes: Arc<RwLock<HashMap<[u8; 16], CohortScope>>>,
}

impl ScopePrivacyAnnouncePolicy {
    /// Construct an empty policy. Production wires
    /// [`Self::register_destination_scope`] for each scoped
    /// destination edge admits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the cohort scope of `dest_hash`. The policy's
    /// `should_suppress_announce` will subsequently dispatch on this
    /// scope. Repeated registrations overwrite the prior scope.
    pub fn register_destination_scope(&self, dest_hash: [u8; 16], scope: CohortScope) {
        self.scopes.write().insert(dest_hash, scope);
    }

    /// Forget `dest_hash`. Subsequent lookups fall through to
    /// default-suppress. Idempotent.
    pub fn forget(&self, dest_hash: &[u8; 16]) {
        self.scopes.write().remove(dest_hash);
    }

    /// Suppress-decision for `dest_hash`. Surface for direct testing
    /// without a Leviculum `NodeCore` involved.
    ///
    /// # Decision
    ///
    /// - Registered + Commons-scope (`Public`) → `false` (allow).
    /// - Registered + group-scope (`SelfOnly` / `Family` / `Cohort`)
    ///   → `true` (suppress).
    /// - Unregistered → `true` (default-suppress: safer-than-leak;
    ///   explicit-hash destinations cannot be announced anyway).
    #[must_use]
    pub fn decide(&self, dest_hash: &[u8; 16]) -> bool {
        match self.scopes.read().get(dest_hash) {
            Some(scope) => {
                use ciris_persist::federation::types::cohort_scope::CryptoTier;
                matches!(
                    scope.crypto_tier(),
                    CryptoTier::InvisibleEncrypted | CryptoTier::CommunityDek
                )
            }
            None => true,
        }
    }

    /// Count of registered scopes. Test/operator surface.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scopes.read().len()
    }

    /// `true` iff no scopes are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scopes.read().is_empty()
    }
}

// v7.0.0 (CIRISEdge#195) — Leviculum `AnnounceControl` adoption. The
// impl is gated on the `_reticulum-module` feature so this module's
// trait + decision surface is usable from features that don't pull
// in leviculum (e.g. unit tests for the dispatch logic).
#[cfg(feature = "_reticulum-module")]
impl AnnounceControl for ScopePrivacyAnnouncePolicy {
    fn should_suppress_announce(&self, destination_hash: &DestinationHash) -> bool {
        self.decide(destination_hash.as_bytes())
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

    // ─── ScopePrivacyAnnouncePolicy ─────────────────────────────────

    #[test]
    fn scope_privacy_policy_allows_commons_tier() {
        let p = ScopePrivacyAnnouncePolicy::new();
        let h = [0x11u8; 16];
        p.register_destination_scope(h, CohortScope::Public);
        assert!(
            !p.decide(&h),
            "Commons (Public/federation) destinations must announce"
        );
    }

    #[test]
    fn scope_privacy_policy_suppresses_invisible_encrypted_tier() {
        let p = ScopePrivacyAnnouncePolicy::new();
        let h_self = [0x22u8; 16];
        let h_family = [0x33u8; 16];
        p.register_destination_scope(h_self, CohortScope::SelfOnly);
        p.register_destination_scope(h_family, CohortScope::Family);
        assert!(
            p.decide(&h_self),
            "SelfOnly → InvisibleEncrypted → suppress",
        );
        assert!(
            p.decide(&h_family),
            "Family → InvisibleEncrypted → suppress",
        );
    }

    #[test]
    fn scope_privacy_policy_suppresses_community_dek_tier() {
        let p = ScopePrivacyAnnouncePolicy::new();
        let h_cohort = [0x44u8; 16];
        p.register_destination_scope(
            h_cohort,
            CohortScope::Cohort {
                cohort_id: "alpha".into(),
            },
        );
        assert!(p.decide(&h_cohort), "Cohort → CommunityDek → suppress");
    }

    #[test]
    fn scope_privacy_policy_unregistered_defaults_to_suppress() {
        // Default-suppress posture: an unregistered hash is safer-
        // than-leak. Edge MUST register every scope-privacy
        // destination before announce time; the policy refuses to
        // announce anything it doesn't recognize.
        let p = ScopePrivacyAnnouncePolicy::new();
        let h_unknown = [0x77u8; 16];
        assert!(
            p.decide(&h_unknown),
            "unregistered hash must default-suppress (explicit-hash destinations cannot be announced)",
        );
    }

    #[test]
    fn scope_privacy_policy_forget_clears_registration() {
        let p = ScopePrivacyAnnouncePolicy::new();
        let h = [0x55u8; 16];
        p.register_destination_scope(h, CohortScope::Public);
        assert!(!p.decide(&h), "Commons allowed before forget");
        p.forget(&h);
        assert!(
            p.decide(&h),
            "forgotten hash falls back to default-suppress",
        );
    }

    #[test]
    fn scope_privacy_policy_overwrite_replaces_scope() {
        let p = ScopePrivacyAnnouncePolicy::new();
        let h = [0x66u8; 16];
        p.register_destination_scope(h, CohortScope::Public);
        assert!(!p.decide(&h));
        // Operator re-classifies the destination as group-scoped.
        p.register_destination_scope(h, CohortScope::SelfOnly);
        assert!(p.decide(&h), "re-registration must promote suppression");
        assert_eq!(p.len(), 1);
    }
}
