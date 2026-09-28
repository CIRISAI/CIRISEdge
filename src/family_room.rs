//! **The family room** — a family's members' devices, as an addressable group
//! (CIRISEdge#646 family half, `FSD/CONTENT_TRANSFER.md` §6.4.1).
//!
//! The self room's machinery with ONE predicate swapped. A self room's
//! members are the nodes of one principal ([`crate::self_room::roster`] →
//! `nodes_owned_by(identity)`); a family room's are the nodes of every
//! ACTIVE MEMBER of the family. Membership is a roster fact and principal
//! equality is a directory fact, so each is asked of its own authority:
//!
//! - who belongs — persist's `active_family_members`, the AUTHORIZED roster
//!   fold (record ∪ `FamilyMembershipWidening` − revocations by
//!   `effective_at`, only events whose signers had standing under the
//!   family's `consensus_protocol` — persist v49 #910/#908). Edge never
//!   decides whether a roster change counts;
//! - person → nodes — `nodes_owned_by(member)`, the same walk the send set's
//!   node half uses (CIRISEdge#524), so the room and the row's recipients
//!   cannot disagree about a person's devices;
//! - what to do about the difference — [`crate::self_room::decide`], unchanged:
//!   it is a rule over a sorted node set and a held tree and knows nothing of
//!   why a node belongs.
//!
//! Like the self room this module is the RULE's inputs and nothing else — no
//! IO beyond directory reads; the host drives the lifecycle.

use std::collections::BTreeMap;

use ciris_persist::federation::FederationDirectory;

use crate::scope_lifecycle::ScopeGroupSnapshot;
use crate::scope_room::ScopeRoom;

/// The family room of `family_key_id`.
#[must_use]
pub fn room(family_key_id: &str) -> ScopeRoom {
    ScopeRoom::family(family_key_id)
}

/// **Who belongs**, resolved to nodes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FamilyRoster {
    /// Every active member's nodes, sorted and deduplicated — the input
    /// [`crate::self_room::decide`] takes (the creator rule is an ordering
    /// over it, so every node must compute the same set).
    pub nodes: Vec<String>,
    /// Which PERSON each node came through (member → their nodes, sorted).
    /// A member's own second device is here because the member is.
    pub by_member: BTreeMap<String, Vec<String>>,
    /// Active members with no node yet (an owner binding that has not
    /// replicated). Reported, never guessed, and not an error: the member
    /// joins the room when their node appears.
    pub unresolved: Vec<String>,
}

/// The family's **active members** (persons), by persist's authorized fold.
///
/// # Errors
/// The directory read failed, or the family is unknown — refused by name
/// (persist's `InvalidArgument`), never answered with an empty roster.
pub async fn members(
    directory: &dyn FederationDirectory,
    family_key_id: &str,
) -> Result<Vec<String>, String> {
    let mut members: Vec<String> = directory
        .active_family_members(family_key_id)
        .await
        .map_err(|e| format!("active members of family {family_key_id}: {e}"))?
        .into_iter()
        .map(|m| m.key_id)
        .collect();
    members.sort();
    members.dedup();
    Ok(members)
}

/// **Who belongs**, as nodes: every active member's nodes.
///
/// # Errors
/// As [`members`].
pub async fn roster(
    directory: &dyn FederationDirectory,
    family_key_id: &str,
    lens: &dyn crate::contact::DirectoryLens,
) -> Result<FamilyRoster, String> {
    let mut out = FamilyRoster::default();
    for member in members(directory, family_key_id).await? {
        let mut nodes = lens.nodes_owned_by(&member).await;
        nodes.sort();
        nodes.dedup();
        if nodes.is_empty() {
            out.unresolved.push(member);
            continue;
        }
        out.nodes.extend(nodes.iter().cloned());
        out.by_member.insert(member, nodes);
    }
    out.nodes.sort();
    out.nodes.dedup();
    Ok(out)
}

/// **Which family rooms this node owes**: the families its owner is an
/// active member of (the member-side twin of the same fold). A node with no
/// owner is its own principal. Sorted.
///
/// # Errors
/// The directory read failed.
pub async fn families_of(
    directory: &dyn FederationDirectory,
    own_node: &str,
    lens: &dyn crate::contact::DirectoryLens,
) -> Result<Vec<String>, String> {
    let principal = lens
        .owner_of(own_node)
        .await
        .unwrap_or_else(|| own_node.to_owned());
    let mut ids: Vec<String> = directory
        .list_families_for_member_active(&principal)
        .await
        .map_err(|e| format!("active families of {principal}: {e}"))?
        .into_iter()
        .map(|f| f.family_key_id)
        .collect();
    ids.sort();
    ids.dedup();
    Ok(ids)
}

/// **What the lifecycle installs** — the family room's derived addresses at
/// its current epoch. [`crate::self_room::snapshot`] keyed by
/// [`ScopeRoom::family`].
///
/// # Errors
/// [`CohortAddressError`](crate::cohort_addressing::CohortAddressError) when
/// the group cannot export its destination secret.
pub async fn snapshot(
    group: &crate::mls::CohortGroup,
    family_key_id: &str,
) -> Result<ScopeGroupSnapshot, crate::cohort_addressing::CohortAddressError> {
    let epoch = group.epoch().await;
    let members = group.member_key_ids().await;
    let secret = group.destination_secret().await?;
    Ok(ScopeGroupSnapshot {
        group_id: room(family_key_id).table_group_id(),
        epoch,
        members,
        destination_secret: *secret.as_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replication::bridge::tests::{
        fixture_family_founded, register_fixture_keys, seed_owner_binding, sign_family_fixture,
        sign_family_membership_revocation_fixture, sign_family_membership_widening_fixture,
    };
    use crate::self_room::{decide, HeldRoom, SelfRoomAction};
    use ciris_persist::federation::identity_type;
    use ciris_persist::federation::types::FamilyMember;
    use ciris_persist::federation::{
        FamilyMembershipRevocation, FamilyMembershipWidening, FederationDirectory,
    };
    use ciris_persist::store::MemoryBackend;

    const FAMILY: &str = "household";

    /// Family `household` founded by alice with bob; alice owns two nodes,
    /// bob one, carol one (not yet a member), a stranger's node owned by nobody.
    async fn backend() -> MemoryBackend {
        let b = MemoryBackend::new();
        register_fixture_keys(
            &b,
            &[
                ("person-alice", identity_type::USER),
                ("person-bob", identity_type::USER),
                ("person-carol", identity_type::USER),
                ("node-alice-a", identity_type::NODE),
                ("node-alice-b", identity_type::NODE),
                ("node-bob", identity_type::NODE),
                ("node-carol", identity_type::NODE),
                ("node-stranger", identity_type::NODE),
            ],
        )
        .await;
        for (owner, node) in [
            ("person-alice", "node-alice-a"),
            ("person-alice", "node-alice-b"),
            ("person-bob", "node-bob"),
            ("person-carol", "node-carol"),
        ] {
            seed_owner_binding(&b, owner, node).await;
        }
        b.put_family(sign_family_fixture(
            "person-alice",
            fixture_family_founded(FAMILY, "person-alice", "person-bob"),
        ))
        .await
        .expect("persist admits the family");
        b
    }

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("rfc3339")
    }

    #[tokio::test]
    async fn a_second_member_is_in_the_room_by_membership_not_by_principal() {
        let b = backend().await;
        let lens = crate::contact::PersistLens::new(&b);
        let r = roster(&b, FAMILY, &lens).await.expect("roster");
        assert_eq!(
            r.nodes,
            ["node-alice-a", "node-alice-b", "node-bob"],
            "every active member's nodes, sorted"
        );
        assert!(r.unresolved.is_empty(), "{:?}", r.unresolved);
        // Membership: bob's node is in the FAMILY room …
        assert_eq!(r.by_member.get("person-bob").unwrap(), &["node-bob"]);
        // … and NOT in alice's SELF room — principal equality is a different
        // predicate, asked of a different authority.
        let alice_self = crate::self_room::roster("person-alice", &lens).await;
        assert_eq!(alice_self, ["node-alice-a", "node-alice-b"]);
        assert!(!alice_self.iter().any(|n| n == "node-bob"));
        // Alice's second device is in the family room THROUGH alice, and in
        // her self room as her principal's device: both predicates hold, each
        // for its own reason.
        assert_eq!(
            r.by_member.get("person-alice").unwrap(),
            &["node-alice-a", "node-alice-b"]
        );
        assert!(alice_self.iter().any(|n| n == "node-alice-b"));
        // A stranger's node is in neither.
        assert!(!r.nodes.iter().any(|n| n == "node-stranger"));
        // Which family rooms a node owes follows its OWNER's membership.
        assert_eq!(families_of(&b, "node-bob", &lens).await.unwrap(), [FAMILY]);
        assert!(families_of(&b, "node-carol", &lens)
            .await
            .unwrap()
            .is_empty());
        assert!(families_of(&b, "node-stranger", &lens)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn a_widening_adds_the_new_members_nodes_and_decide_adds_them() {
        let b = backend().await;
        let lens = crate::contact::PersistLens::new(&b);
        let before = roster(&b, FAMILY, &lens).await.unwrap();
        b.put_family_membership_widening(sign_family_membership_widening_fixture(
            "person-alice",
            FamilyMembershipWidening {
                family_key_id: FAMILY.to_string(),
                member_key_id: "person-carol".to_string(),
                joined_at: at("2026-07-02T00:00:00Z"),
                effective_at: at("2026-07-02T00:00:00Z"),
                role: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .expect("a founder-signed widening has standing");
        let after = roster(&b, FAMILY, &lens).await.unwrap();
        assert!(after.nodes.iter().any(|n| n == "node-carol"));
        assert_eq!(
            families_of(&b, "node-carol", &lens).await.unwrap(),
            [FAMILY],
            "the member-side reader follows the same fold"
        );
        // The room held at the old roster is driven to add carol's node.
        let held = HeldRoom {
            claim: crate::mls::CommitClaim::new(at("2026-07-01T00:00:00Z"), "node-alice-a"),
            members: before.nodes.clone(),
        };
        assert_eq!(
            decide("node-alice-a", &after.nodes, Some(&held), None),
            SelfRoomAction::Add(vec!["node-carol".to_string()])
        );
    }

    #[tokio::test]
    async fn a_revoked_member_leaves_with_every_one_of_their_nodes() {
        let b = backend().await;
        let lens = crate::contact::PersistLens::new(&b);
        let before = roster(&b, FAMILY, &lens).await.unwrap();
        let now = chrono::Utc::now();
        b.put_family_membership_revocation(sign_family_membership_revocation_fixture(
            "person-alice",
            FamilyMembershipRevocation {
                family_key_id: FAMILY.to_string(),
                removed_identity_key_id: "person-bob".to_string(),
                removed_at: now,
                effective_at: now - chrono::Duration::seconds(1),
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
            },
        ))
        .await
        .expect("a founder-signed revocation has standing");
        let after = roster(&b, FAMILY, &lens).await.unwrap();
        assert_eq!(after.nodes, ["node-alice-a", "node-alice-b"]);
        assert!(!after.by_member.contains_key("person-bob"));
        assert!(families_of(&b, "node-bob", &lens).await.unwrap().is_empty());
        // Removal first: the room drops bob's node before anything else.
        let held = HeldRoom {
            claim: crate::mls::CommitClaim::new(at("2026-07-01T00:00:00Z"), "node-alice-a"),
            members: before.nodes.clone(),
        };
        assert_eq!(
            decide("node-alice-a", &after.nodes, Some(&held), None),
            SelfRoomAction::Remove(vec!["node-bob".to_string()])
        );
    }

    #[tokio::test]
    async fn a_member_with_no_node_yet_is_unresolved_not_guessed() {
        let b = backend().await;
        register_fixture_keys(&b, &[("person-dave", identity_type::USER)]).await;
        b.put_family_membership_widening(sign_family_membership_widening_fixture(
            "person-alice",
            FamilyMembershipWidening {
                family_key_id: FAMILY.to_string(),
                member_key_id: "person-dave".to_string(),
                joined_at: at("2026-07-02T00:00:00Z"),
                effective_at: at("2026-07-02T00:00:00Z"),
                role: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .expect("widening");
        let lens = crate::contact::PersistLens::new(&b);
        let r = roster(&b, FAMILY, &lens).await.unwrap();
        assert_eq!(r.unresolved, ["person-dave"]);
        assert!(!r.by_member.contains_key("person-dave"));
    }

    #[tokio::test]
    async fn an_unknown_family_is_refused_by_name_not_an_empty_roster() {
        let b = backend().await;
        let lens = crate::contact::PersistLens::new(&b);
        let err = roster(&b, "no-such-family", &lens)
            .await
            .expect_err("unknown family");
        assert!(err.contains("no-such-family"), "{err}");
        // FamilyMember is the persist type the fold returns; referenced so a
        // shape change in persist is noticed here.
        let _ = FamilyMember {
            key_id: String::new(),
            joined_at: chrono::Utc::now(),
            role: None,
        };
    }
}
