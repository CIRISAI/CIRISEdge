//! v6.2.0 (#179) — persist v9.3.0 delegation / MLS-authority reads are
//! reachable from edge.
//!
//! ## Why this test exists
//!
//! Persist v9.3.0 (CIRISPersist#249 Cut C) introduced public free-fn
//! readers that consolidate the delegation-graph walks every consumer
//! was previously hand-rolling:
//!
//! - `reachable_under_scope(seed, scope, max_depth) -> bool`
//! - `is_owner_bound(key_id) -> bool`
//! - `owner_binding_chain(key_id) -> Vec<KeyId>`
//! - `moderators_of(community_id, duty) -> Vec<KeyId>`
//! - `duty_holders_for_community(community_id, duty) -> HashSet<KeyId>`
//! - `duty_holders_for_content(content_sha, community_id, duty) -> HashSet<KeyId>`
//!
//! All on `Rust + FFI`, all taking `&dyn FederationDirectory`.
//!
//! ## What edge still hand-rolls (intentional — see commit message)
//!
//! `src/edge.rs::verify_self_at_login_delegation` walks
//! `build_delegation_graph` from MULTIPLE trust roots and discriminates
//! REFUSAL reasons (`RetractedAtRoot` / `MissingScope` /
//! `SignerUnreached` / `SubstrateUnavailable` /
//! `NoTrustRoots`) — the forensic granularity is load-bearing for the
//! `DelegationRefusalSubReason` enum and is consumed by tests. Persist's
//! `reachable_under_scope` answers REACHABILITY ONLY (`bool`), so a
//! drop-in replacement would lose the forensic-refusal discrimination.
//!
//! This cut therefore:
//! 1. Bumps persist to v9.3.0 so the new readers are AVAILABLE.
//! 2. Asserts (this test) that they're REACHABLE through edge's
//!    `Arc<dyn FederationDirectory>`.
//! 3. Documents that the hand-rolled walk in `verify_self_at_login_delegation`
//!    stays in place pending a v6.3.0 refusal-reason extension to
//!    `reachable_under_scope` or a sibling `reachable_under_scope_refusal`
//!    that returns a richer enum.
//!
//! ## What this test asserts
//!
//! 1. The five v9.3.0 free-fn readers compile against the trait object
//!    edge holds (`&dyn FederationDirectory`).
//! 2. On an empty backend:
//!    - `reachable_under_scope` returns `Ok(false)` for any pair (the
//!      walk terminates with no edges found).
//!    - `is_owner_bound` returns `Ok(false)` for an unknown key (no
//!      `user`-role record exists).
//!    - `owner_binding_chain` returns `Ok(empty)` for an unknown key
//!      (no chain exists).
//!    - `moderators_of` returns `Ok(empty)` for an unknown community
//!      (no authority roots resolvable).
//!    - `duty_holders_for_community` returns `Ok(empty)` likewise.
//!
//! These are the empty-state shapes edge will branch on when it adopts
//! these reads (e.g. an admission gate that calls `is_owner_bound` and
//! refuses on `false`). The actual delegation-walk semantics are
//! covered by persist's own test suite (see persist v9.3.0
//! `src/store/sqlite.rs::reachable_under_scope_scoped_attenuated_walk_sqlite`
//! and the matching memory-backend tests).
//!
//! ## What this test does NOT assert
//!
//! Functional walk semantics (attenuation, sub-delegation gating,
//! retraction handling) require seeding `delegates_to` attestations
//! through persist's admission gate, which requires real hybrid PQC
//! signatures (the same blocker the existing
//! `federation_present_attestation_appears_in_list_envelope_refs`
//! `#[ignore]` annotation in `src/replication/bridge.rs` calls out).
//! Those semantics are persist-side and covered there.

use std::sync::Arc;

use ciris_persist::federation::admission;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::MemoryBackend;

// ─── Assertion 1 — reachable through `&dyn FederationDirectory` ─────

/// All five v9.3.0 free-fn delegation/authority reads compile and
/// dispatch through `&dyn FederationDirectory` — the trait object edge
/// actually holds via `Arc<dyn FederationDirectory>`.
#[tokio::test]
async fn v9_3_0_delegation_reads_callable_through_dyn_trait() {
    let backend = Arc::new(MemoryBackend::new());
    let dir: Arc<dyn FederationDirectory> = backend.clone();

    // reachable_under_scope — empty graph → not reachable.
    let reachable = admission::reachable_under_scope(
        dir.as_ref(),
        "issuer-key",
        "target-key",
        "act_on_behalf",
        8,
    )
    .await
    .expect("reachable_under_scope reachable through dyn trait");
    assert!(
        !reachable,
        "empty backend → no delegation chain → reachable_under_scope false"
    );

    // is_owner_bound — unknown key → not bound.
    let bound = admission::is_owner_bound(dir.as_ref(), "unknown-key")
        .await
        .expect("is_owner_bound reachable through dyn trait");
    assert!(!bound, "empty backend → unknown key NOT owner-bound");

    // owner_binding_chain — unknown key → empty chain.
    let chain = admission::owner_binding_chain(dir.as_ref(), "unknown-key")
        .await
        .expect("owner_binding_chain reachable through dyn trait");
    assert!(
        chain.is_empty(),
        "empty backend → no chain for unknown key, got {chain:?}"
    );

    // moderators_of — unknown community → empty moderator set.
    let mods = admission::moderators_of(dir.as_ref(), "no-such-community", "moderate")
        .await
        .expect("moderators_of reachable through dyn trait");
    assert!(
        mods.is_empty(),
        "empty backend → no moderators of unknown community, got {mods:?}"
    );

    // duty_holders_for_community — unknown community → empty holder
    // set.
    let holders =
        admission::duty_holders_for_community(dir.as_ref(), "no-such-community", "moderate")
            .await
            .expect("duty_holders_for_community reachable through dyn trait");
    assert!(
        holders.is_empty(),
        "empty backend → no duty holders, got {holders:?}"
    );
}

// ─── Assertion 2 — reachability bool semantics on the self-pair ─────

/// `reachable_under_scope(k, k, _, _)` — the trivial reachability claim
/// "does k reach itself?" — is `true` if and only if persist treats the
/// seed as the depth-0 visited node. The persist v9.3.0 implementation
/// uses BFS with the seed at depth 0 and emits reachability only on
/// FORWARD edges, so a self-pair on an empty graph is `false`. We
/// assert that semantics here so any future persist regression (e.g.
/// silently treating the seed as auto-reachable) is caught at edge's
/// adoption boundary.
#[tokio::test]
async fn reachable_under_scope_self_pair_is_false_on_empty_graph() {
    let backend = Arc::new(MemoryBackend::new());
    let dir: Arc<dyn FederationDirectory> = backend.clone();

    let self_reachable =
        admission::reachable_under_scope(dir.as_ref(), "same-key", "same-key", "moderate", 4)
            .await
            .expect("reachable_under_scope reachable");
    assert!(
        !self_reachable,
        "self-pair on empty graph: no edge → not reachable"
    );
}
