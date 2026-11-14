//! 45.1.1 — a pull parked for want of its room's scope install is woken by
//! the install, once.
//!
//! Field (CIRISServer 0.5.247 `big_room`, nroom3b, Carol): the room's group
//! was not in the scope address table when the first pull ran (03:39:59,
//! holders dropped, "NOT INSTALLED"), the install landed two seconds later,
//! and nothing tied the two together: the bounded retry ladder was the only
//! way back, and once it was spent the body read `not_fetched` for good.

use std::collections::HashSet;
use std::sync::Arc;

use super::key_wake::{Awaiting, KeyWaits};
use super::meaning::fixture::bare_row;
use super::scope::{table_key, BlobScopeRouter, ContentScope};
use crate::scope_addressing::{ScopeAddressTable, StubDeriver};
use crate::CohortScope;

const ROOM: &str = "chat:room:v1:57f7fb170354401cbe15423aa23d9926";

fn room() -> ContentScope {
    ContentScope::Group {
        scope: CohortScope::Cohort {
            cohort_id: ROOM.to_owned(),
        },
        group_id: ROOM.to_owned(),
    }
}

/// Parked on a group that is not installed: no wake until the table installs
/// it, one wake when it does, and none again for a pull that fails once more
/// against the unchanged table. Red with the table's generation bump removed
/// from `install_group`: the install is never seen.
#[test]
fn a_pull_parked_on_its_rooms_install_is_woken_by_the_install_once() {
    let table = Arc::new(ScopeAddressTable::new(Arc::new(StubDeriver)));
    let router = BlobScopeRouter::new(Some(Arc::clone(&table)));
    let (scope, group) = table_key(&room()).expect("a room has a table key");
    let waits = KeyWaits::new(8);
    let sha = [0x24; 32];
    let row = bare_row(ciris_persist::federation::types::cohort_scope::COMMUNITY);
    let installed = |s: &CohortScope, g: &str| router.group_installed(s, g);

    // The pull ran with no install, read the generation, and parked.
    waits.park(
        sha,
        &row,
        Awaiting::Scope {
            scope: scope.clone(),
            group: group.clone(),
            generation: router.table_generation(),
        },
    );
    assert_eq!(
        waits.wake_installed(router.table_generation(), installed),
        0,
        "nothing installed yet: no wake"
    );
    assert!(waits.take_woken(&HashSet::default()).is_empty());

    // The scope lifecycle installs the room.
    table
        .install_group(
            &scope,
            &group,
            2,
            &[7u8; 32],
            &["native-carol", "native-alice"],
        )
        .expect("install");
    assert!(router.group_installed(&scope, &group));
    assert_eq!(
        waits.wake_installed(router.table_generation(), installed),
        1,
        "the install wakes the parked pull"
    );
    let woken = waits.take_woken(&HashSet::default());
    assert_eq!(woken.len(), 1, "woken once");
    assert_eq!(woken[0].0, sha);

    // The re-pull fails again (say, its holder is not a member) and parks at
    // the generation it read: the unchanged table wakes nothing, so a pull
    // that cannot succeed is not re-pulled every tick.
    waits.park(
        sha,
        &row,
        Awaiting::Scope {
            scope,
            group,
            generation: router.table_generation(),
        },
    );
    assert_eq!(
        waits.wake_installed(router.table_generation(), installed),
        0
    );
    assert!(waits.take_woken(&HashSet::default()).is_empty());
}

/// A holder-parked pull of room content is woken by the room's install too
/// (a holder dropped as unroutable leaves the fetch with nobody to ask), and
/// a holder-parked pull with no group is not.
#[test]
fn a_holder_parked_room_pull_is_woken_by_the_install_and_a_groupless_one_is_not() {
    let table = Arc::new(ScopeAddressTable::new(Arc::new(StubDeriver)));
    let router = BlobScopeRouter::new(Some(Arc::clone(&table)));
    let (scope, group) = table_key(&room()).expect("table key");
    let waits = KeyWaits::new(8);
    let row = bare_row(ciris_persist::federation::types::cohort_scope::COMMUNITY);
    let gen0 = router.table_generation();
    waits.park(
        [1; 32],
        &row,
        Awaiting::Holder {
            group: Some((scope.clone(), group.clone())),
            generation: gen0,
        },
    );
    waits.park(
        [2; 32],
        &row,
        Awaiting::Holder {
            group: None,
            generation: gen0,
        },
    );
    table
        .install_group(
            &scope,
            &group,
            1,
            &[9u8; 32],
            &["native-carol", "native-bob"],
        )
        .expect("install");
    assert_eq!(
        waits.wake_installed(router.table_generation(), |s, g| router
            .group_installed(s, g)),
        1
    );
    let woken: Vec<[u8; 32]> = waits
        .take_woken(&HashSet::default())
        .into_iter()
        .map(|(sha, _)| sha)
        .collect();
    assert_eq!(woken, vec![[1; 32]]);
}
