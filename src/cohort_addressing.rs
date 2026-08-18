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

use crate::cohort_scope::CohortScope;
use crate::mls::{CohortGroup, CohortGroupError};
use crate::scope_addressing::{ScopeAddressError, ScopeAddressTable};

/// Why a cohort's addresses could not be installed.
#[derive(Debug, thiserror::Error)]
pub enum CohortAddressError {
    /// The group's exporter secret could not be derived — corrupted
    /// group state.
    #[error("cohort exporter: {0}")]
    Exporter(#[from] CohortGroupError),
    /// The address table refused the install.
    #[error("scope address table: {0}")]
    Table(#[from] ScopeAddressError),
}

/// Install a cohort's scoped addresses at its CURRENT epoch.
///
/// Call once, after joining or creating the group. The group id in the
/// table is the `community_id`, and the members are the group's own
/// roster — so the table's view cannot drift from MLS's without the
/// roster itself changing.
///
/// # Errors
/// [`CohortAddressError::Exporter`] on corrupted group state;
/// [`CohortAddressError::Table`] if the community is already installed
/// (use [`advance_cohort_addresses`] for a later epoch).
pub async fn install_cohort_addresses(
    table: &ScopeAddressTable,
    scope: &CohortScope,
    group: &CohortGroup,
) -> Result<usize, CohortAddressError> {
    let (epoch, members, secret) = read_epoch(group).await?;
    Ok(table.install_group(
        scope,
        group.community_id(),
        epoch,
        secret.as_bytes(),
        &members,
    )?)
}

/// Move a cohort's addresses onto a NEW epoch, make-before-break.
///
/// Runs phases 1 and 2 together: the new epoch's addresses become
/// reachable, then become the ones we send on, while the superseded
/// epoch stays accepted for receive. A peer that advanced before us is
/// answered the whole time, and a straggler that has not yet advanced
/// keeps being addressed on the old epoch until the caller seals.
///
/// Both phases run against the SAME secret read, so the addresses
/// installed and the addresses activated cannot come from two different
/// epochs — which is the failure a naive `install_next(); activate();`
/// pair would have if the group advanced between them.
///
/// # Errors
/// [`CohortAddressError::Exporter`] on corrupted group state;
/// [`CohortAddressError::Table`] if the community is not installed, or
/// the epoch is already live.
pub async fn advance_cohort_addresses(
    table: &ScopeAddressTable,
    scope: &CohortScope,
    group: &CohortGroup,
) -> Result<usize, CohortAddressError> {
    let (epoch, members, secret) = read_epoch(group).await?;
    let installed = table.install_next(
        scope,
        group.community_id(),
        epoch,
        secret.as_bytes(),
        &members,
    )?;
    table.activate_next(scope, group.community_id())?;
    Ok(installed)
}

/// Read `(epoch, roster, destination secret)` for the group's current
/// epoch.
///
/// The three are read through separate locks rather than one, so a
/// concurrent commit could in principle land between them. That is
/// harmless *here* and worth stating: a torn read yields a
/// `(secret, roster)` pair that is merely stale, and the table refuses
/// a stale epoch on install (`AddressCollision` / the epoch checks)
/// rather than silently mixing epochs. It is not a substitute for the
/// group's own single-writer lock, which is what actually serializes
/// commits.
async fn read_epoch(
    group: &CohortGroup,
) -> Result<(u64, Vec<String>, crate::mls::CohortSecret), CohortGroupError> {
    let epoch = group.epoch().await;
    let members = group.member_key_ids().await;
    // The DESTINATION plane secret specifically — never the record
    // plane's, and never the A/V DEK seed. See
    // `CohortGroup::destination_secret`.
    let secret = group.destination_secret().await?;
    Ok((epoch, members, secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mls::cohort_group::mint_cohort_key_material;
    use crate::mls::{CohortGroup, ScopeStateProvider};
    use crate::scope_addressing::ScopePrivacyDeriver;
    use ciris_persist::encrypted_kv::XChaChaKvStore;
    use std::sync::Arc;

    fn store() -> ScopeStateProvider {
        ScopeStateProvider::new(Arc::new(
            XChaChaKvStore::open_in_memory(b"cohort-addressing-test").unwrap(),
        ))
    }

    fn table() -> ScopeAddressTable {
        ScopeAddressTable::new(Arc::new(ScopePrivacyDeriver))
    }

    fn scope() -> CohortScope {
        CohortScope::Cohort {
            cohort_id: "neighbourhood".to_owned(),
        }
    }

    #[tokio::test]
    async fn two_members_of_one_cohort_derive_each_others_addresses() {
        // THE property the whole feature rests on. Both nodes hold the
        // same MLS group, so both must compute the same 16 bytes for a
        // given member — otherwise each addresses a hash the other
        // never registered, and nothing errors anywhere: an RNS
        // destination nobody registered is simply never delivered to.
        let a = CohortGroup::create(store(), "c-addr", "node-a", 16)
            .await
            .unwrap();
        let (material, kp) = mint_cohort_key_material("node-b").unwrap();
        let add = a.add_member("node-b", kp).await.unwrap();
        let b = CohortGroup::join(store(), "c-addr", material, add.welcome().unwrap(), 16)
            .await
            .unwrap();

        let (ta, tb) = (table(), table());
        install_cohort_addresses(&ta, &scope(), &a).await.unwrap();
        install_cohort_addresses(&tb, &scope(), &b).await.unwrap();

        for member in ["node-a", "node-b"] {
            let from_a = ta.send_address(&scope(), "c-addr", member).unwrap();
            let from_b = tb.send_address(&scope(), "c-addr", member).unwrap();
            assert_eq!(
                from_a.as_bytes(),
                from_b.as_bytes(),
                "both members must derive the SAME address for {member}",
            );
        }

        // Per-member, not per-group: a shared hash would put both nodes
        // under one RNS routing entry.
        assert_ne!(
            ta.send_address(&scope(), "c-addr", "node-a")
                .unwrap()
                .as_bytes(),
            ta.send_address(&scope(), "c-addr", "node-b")
                .unwrap()
                .as_bytes(),
        );
    }

    #[tokio::test]
    async fn an_epoch_advance_re_addresses_without_deafening_the_old_epoch() {
        let a = CohortGroup::create(store(), "c-rot", "node-a", 16)
            .await
            .unwrap();
        let t = table();
        install_cohort_addresses(&t, &scope(), &a).await.unwrap();
        let before = *t
            .send_address(&scope(), "c-rot", "node-a")
            .unwrap()
            .as_bytes();

        let _rotated = a.rotate().await.unwrap();
        advance_cohort_addresses(&t, &scope(), &a).await.unwrap();

        let after = *t
            .send_address(&scope(), "c-rot", "node-a")
            .unwrap()
            .as_bytes();
        assert_ne!(before, after, "an epoch bump must move the address");

        // Make-before-break: the OLD address is still accepted for
        // receive, so a peer that has not yet advanced still reaches us.
        assert!(
            t.accepts_inbound(&before).is_some(),
            "the superseded epoch must stay accepted until seal",
        );
        assert!(t.accepts_inbound(&after).is_some());

        // ...and only stops after the caller seals.
        t.seal_rotation(&scope(), "c-rot").unwrap();
        assert!(
            t.accepts_inbound(&before).is_none(),
            "a sealed epoch is no longer ours",
        );
        assert!(t.accepts_inbound(&after).is_some());
    }

    #[tokio::test]
    async fn a_different_cohort_yields_unrelated_addresses() {
        // Unlinkability: the same node in two cohorts presents two
        // addresses nothing correlates without the group secrets.
        let one = CohortGroup::create(store(), "c-one", "node-a", 16)
            .await
            .unwrap();
        let two = CohortGroup::create(store(), "c-two", "node-a", 16)
            .await
            .unwrap();
        let t = table();
        install_cohort_addresses(&t, &scope(), &one).await.unwrap();
        install_cohort_addresses(&t, &scope(), &two).await.unwrap();

        assert_ne!(
            t.send_address(&scope(), "c-one", "node-a")
                .unwrap()
                .as_bytes(),
            t.send_address(&scope(), "c-two", "node-a")
                .unwrap()
                .as_bytes(),
            "one node in two cohorts must present unrelated addresses",
        );
    }

    #[tokio::test]
    async fn the_record_plane_secret_would_produce_different_addresses() {
        // Guards the plane split from the inside: if this module ever
        // reached for `record_secret` instead, every address would
        // change and every peer would silently stop resolving us. The
        // assertion is that the two planes are NOT interchangeable.
        let g = CohortGroup::create(store(), "c-plane", "node-a", 16)
            .await
            .unwrap();
        let t = table();
        install_cohort_addresses(&t, &scope(), &g).await.unwrap();
        let via_destination = *t
            .send_address(&scope(), "c-plane", "node-a")
            .unwrap()
            .as_bytes();

        let record = g.record_secret().await.unwrap();
        let other = table();
        other
            .install_group(
                &scope(),
                "c-plane",
                g.epoch().await,
                record.as_bytes(),
                &["node-a"],
            )
            .unwrap();
        assert_ne!(
            via_destination,
            *other
                .send_address(&scope(), "c-plane", "node-a")
                .unwrap()
                .as_bytes(),
            "record and destination planes must not be interchangeable",
        );
    }
}
