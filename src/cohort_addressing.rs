//! Cohort → scoped-address wiring (CIRISEdge#499).
//!
//! The join between [`crate::mls::CohortGroup`] (which holds the MLS
//! group and therefore the epoch secret) and
//! [`crate::scope_addressing::ScopeAddressTable`] (which holds the
//! derived addresses). It is a separate module rather than a method on
//! either because each has a property worth not breaking:
//!
//! - `scope_addressing` is **entirely synchronous** — no `async fn`, no
//!   `.await` anywhere — so a lock guard cannot be held across a
//!   suspension point even by accident (CIRISEdge#217). Adding an
//!   `async` installer there would end that guarantee for the sake of
//!   one function.
//! - `mls::cohort_group` deliberately does not reach into transport
//!   concerns; addressing is one.
//!
//! So the async part lives here, and it is the ONLY async in the path:
//! read the secret, then call the table's sync verbs.
//!
//! # The secret never outlives the call
//!
//! [`CohortSecret`] is borrowed for the duration of an install and
//! dropped; what persists in the table is only the 16-byte public
//! addresses derived from it. That is the same discipline
//! `ScopeAddressTable` already documents for `exporter_secret`.
//!
//! # Rotation
//!
//! MLS epochs advance per-member at slightly different wall-clock
//! moments, so an epoch bump must never be a hard cutover. The two
//! verbs here map onto the table's three phases:
//!
//! ```text
//! join a cohort        → install_cohort_addresses   (phase 0: the only epoch)
//! epoch advanced       → advance_cohort_addresses   (phase 1 + 2: install_next, activate_next)
//! convergence elapsed  → ScopeAddressTable::seal_rotation (phase 3, caller's timing)
//! ```
//!
//! Sealing is deliberately NOT done here. Phases 1 and 2 are driven by
//! a fact this module can observe — the group's epoch changed — but
//! phase 3 is a *timing* decision about how long stragglers get, and
//! guessing it here would either strand slow peers or hold a superseded
//! address open indefinitely.

use crate::mls::{CohortGroup, CohortGroupError};
use crate::scope_lifecycle::ScopeGroupSnapshot;

/// Why a cohort's addresses could not be installed.
#[derive(Debug, thiserror::Error)]
pub enum CohortAddressError {
    /// The group's exporter secret could not be derived — corrupted
    /// group state.
    #[error("cohort exporter: {0}")]
    Exporter(#[from] CohortGroupError),
}

/// **The adapter.** Reduce a community to the one shape the lifecycle
/// takes.
///
/// Identical in form to [`crate::av_addressing::snapshot`] — that is the
/// point. Downstream writes the same two lines whether it is standing up
/// a community or a call inside one:
///
/// ```ignore
/// let snap = cohort_addressing::snapshot(&community).await?;
/// lifecycle.install(&scope, &snap)?;
/// ```
///
/// `async` only because a `CohortGroup`'s state lives behind the async
/// mutex that gives it its single-writer property; the A/V twin is sync
/// for the same reason inverted. That difference is exactly why the
/// lifecycle takes a value rather than a trait — a common trait would
/// have to be async and would not be `dyn`-safe.
///
/// The group id is namespaced (`cohort:{community_id}`) so a community
/// and a call running inside it cannot collide in the table.
///
/// # Errors
/// [`CohortAddressError::Exporter`] on corrupted group state.
pub async fn snapshot(group: &CohortGroup) -> Result<ScopeGroupSnapshot, CohortAddressError> {
    // Three separate reads rather than one lock: a concurrent commit
    // could in principle land between them, which is harmless HERE —
    // a torn read yields a merely-stale (epoch, roster, secret), and the
    // table refuses a stale epoch on install rather than mixing epochs.
    // It is not a substitute for the group's own single-writer lock,
    // which is what actually serializes commits.
    let epoch = group.epoch().await;
    let members = group.member_key_ids().await;
    // The DESTINATION plane specifically — never the record plane's,
    // and never the A/V DEK seed.
    let secret = group.destination_secret().await?;
    Ok(ScopeGroupSnapshot {
        group_id: format!("cohort:{}", group.community_id()),
        epoch,
        members,
        destination_secret: *secret.as_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cohort_scope::CohortScope;
    use crate::mls::cohort_group::mint_cohort_key_material;
    use crate::mls::{CohortGroup, ScopeStateProvider};
    use crate::scope_addressing::{MemberAddress, ScopeAddressTable, ScopePrivacyDeriver};
    use crate::scope_lifecycle::{ScopeLifecycle, ScopedDestinationSink};
    use ciris_persist::encrypted_kv::XChaChaKvStore;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[derive(Default)]
    struct Sink(Mutex<Vec<[u8; 16]>>);
    impl ScopedDestinationSink for Sink {
        fn register(&self, a: &MemberAddress, _s: &CohortScope) -> Result<(), String> {
            self.0.lock().unwrap().push(*a.as_bytes());
            Ok(())
        }
        fn retire(&self, _a: &MemberAddress, _s: &CohortScope) -> Result<(), String> {
            Ok(())
        }
    }

    fn store() -> ScopeStateProvider {
        ScopeStateProvider::new(Arc::new(
            XChaChaKvStore::open_in_memory(b"cohort-addressing-test").unwrap(),
        ))
    }

    fn node(own: &str) -> (ScopeLifecycle, Arc<ScopeAddressTable>) {
        let table = Arc::new(ScopeAddressTable::new(Arc::new(ScopePrivacyDeriver)));
        let life = ScopeLifecycle::new(
            Arc::clone(&table),
            Arc::new(Sink::default()),
            own,
            Duration::from_secs(300),
        );
        (life, table)
    }

    fn scope() -> CohortScope {
        CohortScope::Cohort {
            cohort_id: "neighbourhood".to_owned(),
        }
    }

    #[tokio::test]
    async fn two_members_of_one_community_derive_each_others_addresses() {
        // THE property the feature rests on, driven through exactly the
        // two lines downstream writes. If the two nodes disagree,
        // nothing errors anywhere: an RNS destination nobody registered
        // is simply never delivered to.
        let a = CohortGroup::create(store(), "c-addr", "node-a", 16)
            .await
            .unwrap();
        let (material, kp) = mint_cohort_key_material("node-b").unwrap();
        let add = a.add_member("node-b", kp).await.unwrap();
        let b = CohortGroup::join(store(), "c-addr", material, add.welcome().unwrap(), 16)
            .await
            .unwrap();

        let (life_a, table_a) = node("node-a");
        let (life_b, table_b) = node("node-b");
        life_a
            .install(&scope(), &snapshot(&a).await.unwrap())
            .unwrap();
        life_b
            .install(&scope(), &snapshot(&b).await.unwrap())
            .unwrap();

        let gid = format!("cohort:{}", a.community_id());
        for member in ["node-a", "node-b"] {
            assert_eq!(
                table_a
                    .send_address(&scope(), &gid, member)
                    .unwrap()
                    .as_bytes(),
                table_b
                    .send_address(&scope(), &gid, member)
                    .unwrap()
                    .as_bytes(),
                "both members must derive the SAME address for {member}",
            );
        }
        // Per-member, never a shared group hash: a shared one puts both
        // nodes under a single RNS routing entry.
        assert_ne!(
            table_a
                .send_address(&scope(), &gid, "node-a")
                .unwrap()
                .as_bytes(),
            table_a
                .send_address(&scope(), &gid, "node-b")
                .unwrap()
                .as_bytes(),
        );
    }

    #[tokio::test]
    async fn an_epoch_advance_re_addresses_without_deafening_the_old_epoch() {
        let g = CohortGroup::create(store(), "c-rot", "node-a", 16)
            .await
            .unwrap();
        let (life, table) = node("node-a");
        let first = life
            .install(&scope(), &snapshot(&g).await.unwrap())
            .unwrap();

        let _commit = g.rotate().await.unwrap();
        let t0 = std::time::Instant::now();
        let second = life
            .advance(&scope(), &snapshot(&g).await.unwrap(), t0)
            .unwrap();

        assert_ne!(first.own_address.as_bytes(), second.own_address.as_bytes());
        // Make-before-break: the old address still answers until sealed.
        assert!(table
            .accepts_inbound(first.own_address.as_bytes())
            .is_some());
        assert!(table
            .accepts_inbound(second.own_address.as_bytes())
            .is_some());
        life.seal_due(t0 + Duration::from_secs(300));
        assert!(table
            .accepts_inbound(first.own_address.as_bytes())
            .is_none());
        assert!(table
            .accepts_inbound(second.own_address.as_bytes())
            .is_some());
    }

    #[tokio::test]
    async fn a_different_community_yields_unrelated_addresses() {
        // Unlinkability: one node in two communities presents two
        // addresses nothing correlates without the group secrets.
        let one = CohortGroup::create(store(), "c-one", "node-a", 16)
            .await
            .unwrap();
        let two = CohortGroup::create(store(), "c-two", "node-a", 16)
            .await
            .unwrap();
        let (life, table) = node("node-a");
        life.install(&scope(), &snapshot(&one).await.unwrap())
            .unwrap();
        life.install(&scope(), &snapshot(&two).await.unwrap())
            .unwrap();
        assert_ne!(
            table
                .send_address(&scope(), "cohort:c-one", "node-a")
                .unwrap()
                .as_bytes(),
            table
                .send_address(&scope(), "cohort:c-two", "node-a")
                .unwrap()
                .as_bytes(),
        );
    }

    #[tokio::test]
    async fn the_snapshot_carries_the_destination_plane_not_the_record_plane() {
        // Guards the plane split from the inside. Note the two-member
        // agreement test CANNOT catch this: both members would use the
        // same wrong secret and still agree with each other.
        let g = CohortGroup::create(store(), "c-plane", "node-a", 16)
            .await
            .unwrap();
        let snap = snapshot(&g).await.unwrap();
        assert_eq!(
            snap.destination_secret,
            *g.destination_secret().await.unwrap().as_bytes(),
        );
        assert_ne!(
            snap.destination_secret,
            *g.record_secret().await.unwrap().as_bytes(),
            "record and destination planes must not be interchangeable",
        );
    }

    #[tokio::test]
    async fn the_group_id_namespaces_a_community_apart_from_a_call() {
        // A community and an A/V call inside it are separate groups with
        // separate secrets; their table ids must not collide either.
        let g = CohortGroup::create(store(), "c-ns", "node-a", 16)
            .await
            .unwrap();
        let snap = snapshot(&g).await.unwrap();
        assert_eq!(snap.group_id, "cohort:c-ns");
        assert!(
            !snap.group_id.starts_with("av-stream:"),
            "the two namespaces must be disjoint",
        );
    }
}
