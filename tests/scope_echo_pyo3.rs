//! v6.1.0 (CIRISEdge#175, FSD §3.2) — scope-echo / `PublishOutcome`
//! invariants exercised at the Rust surface (the PyO3 surface
//! drives the same path; this test pins the underlying rule).
//!
//! The §3.2 invariants:
//!
//! 1. The default flip NEVER returns `CohortScope::Public`
//!    (federation is opt-in).
//! 2. The active community_id, when present, wins over family
//!    context.
//! 3. `PublishOutcome` carries the chosen scope + caller-stated
//!    audience for the operator-facing "published at scope=X to
//!    audience=Y" surface.

use ciris_edge::{CohortScope, PublishOutcome};

#[test]
fn resolve_default_scope_prefers_smallest_scope() {
    // Community-active wins.
    assert_eq!(
        CohortScope::default_for_audience(Some("alpha"), false),
        CohortScope::Cohort {
            cohort_id: "alpha".into()
        }
    );
    assert_eq!(
        CohortScope::default_for_audience(Some("beta"), true),
        CohortScope::Cohort {
            cohort_id: "beta".into()
        }
    );
    // Family next.
    assert_eq!(
        CohortScope::default_for_audience(None, true),
        CohortScope::Family
    );
    // Self otherwise.
    assert_eq!(
        CohortScope::default_for_audience(None, false),
        CohortScope::SelfOnly
    );
}

#[test]
fn default_scope_never_returns_public() {
    // §3.2 invariant — anonymity-by-default. Federation is
    // strictly opt-in.
    for (cid, fam) in [
        (Some("c"), true),
        (Some("c"), false),
        (None, true),
        (None, false),
    ] {
        let s = CohortScope::default_for_audience(cid, fam);
        assert_ne!(s, CohortScope::Public, "default MUST NEVER be Public");
    }
}

#[test]
fn publish_outcome_carries_scope_and_audience() {
    let outcome = PublishOutcome::new(CohortScope::Family, "agent-bob");
    assert_eq!(outcome.scope, CohortScope::Family);
    assert_eq!(outcome.audience, "agent-bob");
    assert_eq!(outcome.holder_count, 0);
    assert!(outcome.record_id_hex.is_none());
}

#[test]
fn publish_outcome_with_record_carries_holder_count_and_record_id() {
    let outcome = PublishOutcome::with_record(
        CohortScope::Cohort {
            cohort_id: "alpha".into(),
        },
        "community/alpha",
        30,
        "deadbeef",
    );
    assert_eq!(
        outcome.scope,
        CohortScope::Cohort {
            cohort_id: "alpha".into()
        }
    );
    assert_eq!(outcome.audience, "community/alpha");
    assert_eq!(outcome.holder_count, 30);
    assert_eq!(outcome.record_id_hex.as_deref(), Some("deadbeef"));
}
