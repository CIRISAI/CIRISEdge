//! v6.0.0 (CIRISEdge#175, FSD §3.2) — default cohort_scope flip +
//! scope echo.
//!
//! The §3.2 rule: `cohort_scope` defaults to the smallest scope
//! consistent with the publisher's audience context. Federation
//! scope is **opt-in**. The default flip MUST NEVER return Public.
//!
//! This test exercises [`CohortScope::default_for_audience`] across
//! the four (community_context, family_context) input combinations;
//! the CC 1.13.3.4 invariant is that no input combination yields
//! Public.

use ciris_edge::{CohortScope, CryptoTier};

#[test]
fn default_with_community_context_yields_cohort_scope() {
    let s = CohortScope::default_for_audience(Some("alpha"), false);
    assert_eq!(
        s,
        CohortScope::Cohort {
            cohort_id: "alpha".into()
        }
    );
    assert_eq!(s.crypto_tier(), CryptoTier::CommunityDek);
}

#[test]
fn default_with_family_context_yields_family() {
    let s = CohortScope::default_for_audience(None, true);
    assert_eq!(s, CohortScope::Family);
    assert_eq!(s.crypto_tier(), CryptoTier::InvisibleEncrypted);
}

#[test]
fn default_without_context_yields_self() {
    let s = CohortScope::default_for_audience(None, false);
    assert_eq!(s, CohortScope::SelfOnly);
    assert_eq!(s.crypto_tier(), CryptoTier::InvisibleEncrypted);
}

#[test]
fn default_community_wins_over_family() {
    let s = CohortScope::default_for_audience(Some("beta"), true);
    assert_eq!(
        s,
        CohortScope::Cohort {
            cohort_id: "beta".into()
        }
    );
}

#[test]
fn explicit_public_is_federation_opt_in() {
    // §3.2 — operators opt up to federation explicitly; the wire
    // representation is the existing `Public` variant.
    let s = CohortScope::Public;
    assert_eq!(s.crypto_tier(), CryptoTier::Plaintext);
    assert!(!s.is_restricted());
}

#[test]
fn default_never_returns_public_under_any_input() {
    // CC 1.13.3.4 invariant — anonymity-by-default at every scope
    // below federation. The default flip MUST NEVER return Public.
    for (cid, fam) in [
        (Some("c"), true),
        (Some("c"), false),
        (None, true),
        (None, false),
    ] {
        let s = CohortScope::default_for_audience(cid, fam);
        assert_ne!(
            s,
            CohortScope::Public,
            "input ({cid:?}, {fam}) must not default to Public"
        );
    }
}

#[test]
fn scope_echo_returns_chosen_scope() {
    // §3.2 scope echo — every publication carries the chosen scope
    // back to the operator API. v6.0.0 ships the resolver; PyO3
    // surface is the v6.1.0 wiring (the resolver itself is the
    // wire-format invariant).
    let s = CohortScope::default_for_audience(Some("comm-1"), false);
    let echo = s.kind_token();
    assert_eq!(echo, "cohort");

    let s = CohortScope::default_for_audience(None, true);
    assert_eq!(s.kind_token(), "family");

    let s = CohortScope::default_for_audience(None, false);
    assert_eq!(s.kind_token(), "self");
}
