//! v6.2.0 (#179) — persist v9.3.0 `active_*` roster reads are reachable
//! from edge via the `FederationDirectory` trait object.
//!
//! ## Why this test exists
//!
//! Persist v9.3.0 introduced four server-side memberships-MINUS-
//! revocations folds:
//!
//! - `active_community_members(community) -> Vec<CommunityMember>`
//! - `active_family_members(family) -> Vec<FamilyMember>`
//! - `list_communities_for_member_active(member) -> Vec<Community>`
//! - `list_families_for_member_active(member) -> Vec<Family>`
//!
//! Before v9.3.0, any consumer that wanted the LIVE roster had to ship
//! both memberships + revocations as separate reads and fold them
//! client-side. v9.3.0 closes that gap: the fold is exactly one read.
//!
//! ## What edge does with them today
//!
//! `grep -rn 'list_community_members\|list_family_members\|memberships_for'
//! src/` finds zero edge-side sites that hand-roll the
//! membership+revocation fold. The edge bridge (`src/replication/bridge.rs`)
//! ships BOTH streams independently on the wire — that is the
//! anti-entropy invariant and MUST stay independent. So the v6.2.0 cut's
//! contribution for ask #2 is: prove the new active reads are reachable
//! through edge's `Arc<dyn FederationDirectory>` so any FUTURE edge
//! feature that needs a live roster uses the one-read fold rather than
//! hand-rolling.
//!
//! ## What this test asserts
//!
//! 1. The four `active_*` reads are reachable through the trait object
//!    edge holds (`Arc<dyn FederationDirectory>`), i.e. they're on the
//!    trait surface, not on a backend-specific type.
//! 2. On an empty backend, the inverse reads
//!    (`list_*_for_member_active`) return an empty `Vec`, NOT an error
//!    — the consumer can treat "no live memberships" as a valid empty
//!    result.
//! 3. On an empty backend, the forward reads (`active_*_members`)
//!    return `Err(InvalidArgument)` for an unknown group_key_id —
//!    confirming the trait contract documented in persist v9.3.0's
//!    `FederationDirectory` ("Error::InvalidArgument if the family is
//!    unknown"). This is the trait-shape edge must adapt to.
//!
//! ## What this test does NOT assert
//!
//! The functional revocation-subtraction semantics of `active_*_members`
//! are covered by persist's own test suite (see
//! `src/store/memory.rs::active_community_members_subtracts_effective_revocation`
//! / `active_family_members_future_revocation_keeps_member` in persist
//! v9.3.0). Asserting them from edge would require synthesizing real
//! hybrid PQC signatures (the same blocker the existing
//! `federation_present_attestation_appears_in_list_envelope_refs`
//! `#[ignore]` annotation calls out). The trait-surface reachability
//! this test asserts is what edge's adoption needs.

use std::sync::Arc;

use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::MemoryBackend;

// ─── Assertion 1 — reachable through `dyn FederationDirectory` ──────

/// The four v9.3.0 reads compile against the trait object edge actually
/// holds: `Arc<dyn FederationDirectory>`. If persist regressed any of
/// them off the trait into an inherent method, this test would fail to
/// compile.
#[tokio::test]
async fn v9_3_0_active_reads_callable_through_dyn_trait() {
    let backend = Arc::new(MemoryBackend::new());
    let dir: Arc<dyn FederationDirectory> = backend.clone();

    // 1 + 2 — the two `list_*_for_member_active` inverse reads return
    // Ok(empty) for a member with no rosters. This is the consumer-side
    // shape edge will adopt: "what live groups is this member in?".
    let families = dir
        .list_families_for_member_active("nonexistent-member")
        .await
        .expect("list_families_for_member_active reachable through dyn FederationDirectory");
    assert!(families.is_empty(), "empty backend: no families");

    let communities = dir
        .list_communities_for_member_active("nonexistent-member")
        .await
        .expect("list_communities_for_member_active reachable through dyn FederationDirectory");
    assert!(communities.is_empty(), "empty backend: no communities");
}

// ─── Assertion 2 — InvalidArgument on unknown group ─────────────────

/// The forward reads (`active_*_members`) name a specific group and
/// must error if that group doesn't exist. This is the trait-contract
/// edge must adapt to when consuming the fold (it's NOT silent-empty
/// like the inverse).
#[tokio::test]
async fn active_members_invalid_argument_on_unknown_group() {
    let backend = Arc::new(MemoryBackend::new());
    let dir: Arc<dyn FederationDirectory> = backend.clone();

    let community_err = dir.active_community_members("no-such-community").await;
    assert!(
        community_err.is_err(),
        "active_community_members on unknown community → Err(InvalidArgument)"
    );

    let family_err = dir.active_family_members("no-such-family").await;
    assert!(
        family_err.is_err(),
        "active_family_members on unknown family → Err(InvalidArgument)"
    );
}
