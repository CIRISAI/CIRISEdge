//! **The self room** — one identity's own devices, as an addressable group
//! (CIRISEdge#646, `FSD/CONTENT_TRANSFER.md` §6.3).
//!
//! A `self`-scoped blob's bytes move over derived destinations like every
//! other non-public cohort's (CC 5.4.6 lists `self` among the group-scoped
//! tiers whose destinations are *"resolved DETERMINISTICALLY from (cached
//! directory entry + per-group HKDF)"* — the MLS exporter). So the self
//! room is an ordinary [`CohortGroup`](crate::mls::CohortGroup) whose
//! members are the identity's nodes; nothing here is new machinery.
//!
//! What IS new is that nobody creates it. A community room is created by a
//! person inviting another; a self room must appear the moment an identity
//! has a second device, with no human act — and if two devices each create
//! one, they derive different secrets and address each other at
//! destinations nobody registered: correct by every local check and dark on
//! the wire, the CIRISEdge#646 shape this whole arc exists to remove.
//!
//! This module is therefore the RULE, and only the rule:
//!
//! - [`roster`] — who belongs (the directory's answer, not the MLS tree's);
//! - [`snapshot`] — what the lifecycle installs (the MLS tree's answer);
//! - [`decide`] — what this node should do about the difference.
//!
//! The host performs the IO the decision names, exactly as it does for
//! [`ScopeLifecycle`](crate::scope_lifecycle::ScopeLifecycle)'s verbs: edge
//! decides, the host drives. That split is what keeps two hosts from
//! disagreeing about who creates.
//!
//! # The bootstrap needs no room
//!
//! KeyPackage, Welcome and Commit travel as ordinary `self`-placed rows, so
//! they reach the identity's other nodes over the row plane — which since
//! v29.3.0 carries a `self` row to the owner's own nodes with no grant
//! between them (persist `send_set_for`, CC 3.2/3.3.6). Only the BYTES need
//! the room. There is no chicken-and-egg.

use crate::mls::CommitClaim;
use crate::scope_lifecycle::ScopeGroupSnapshot;
use crate::scope_room::ScopeRoom;

/// The self room of `identity_key_id`.
#[must_use]
pub fn room(identity_key_id: &str) -> ScopeRoom {
    ScopeRoom::self_collective(identity_key_id)
}

/// **Who belongs** — the identity's nodes, from the directory.
///
/// The authoritative roster is the directory's, not the MLS tree's: the
/// tree is the state this node has converged to, the directory is the state
/// it should converge toward, and [`decide`] is the difference. One
/// resolution — `nodes_owned_by`, the same walk the consent send set's node
/// half uses (CIRISEdge#524, persist `send_set_for`) — so the room's
/// membership and the row's recipients cannot disagree about who a person's
/// devices are.
///
/// Sorted and deduplicated, because the creator rule is an ordering over
/// this set and every node must compute the same one.
pub async fn roster(
    identity_key_id: &str,
    lens: &dyn crate::contact::DirectoryLens,
) -> Vec<String> {
    let mut nodes = lens.nodes_owned_by(identity_key_id).await;
    nodes.sort();
    nodes.dedup();
    nodes
}

/// **What the lifecycle installs** — the room's derived addresses at its
/// current epoch, keyed by [`ScopeRoom::table_group_id`].
///
/// The twin of [`cohort_addressing::snapshot`](crate::cohort_addressing::snapshot),
/// differing only in the key: a community's is namespaced, a self room's is
/// the bare identity (the table's key is `(scope, group_id)`, and the scope
/// already discriminates — see [`crate::scope_room`]).
///
/// Members are taken from the MLS tree, which for a self room already holds
/// NODES — so unlike a community there is no person-to-node walk here, and
/// no `unresolved` set.
///
/// # Errors
/// [`CohortAddressError`](crate::cohort_addressing::CohortAddressError) when
/// the group cannot export its destination secret.
pub async fn snapshot(
    group: &crate::mls::CohortGroup,
    identity_key_id: &str,
) -> Result<ScopeGroupSnapshot, crate::cohort_addressing::CohortAddressError> {
    let epoch = group.epoch().await;
    let members = group.member_key_ids().await;
    let secret = group.destination_secret().await?;
    Ok(ScopeGroupSnapshot {
        group_id: room(identity_key_id).table_group_id(),
        epoch,
        members,
        destination_secret: *secret.as_bytes(),
    })
}

/// What this node holds for a self room, as [`decide`] needs to see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldRoom {
    /// The claim the room was created under — whose room this is, and when.
    pub claim: CommitClaim,
    /// The MLS tree's current members (nodes), as this node has converged.
    pub members: Vec<String>,
}

/// **The action this node should take.** Each arm is a different fact about
/// the difference between the directory and the tree, because each has a
/// different remedy — and a node that can only say "something is off"
/// cannot be driven.
#[must_use = "a self-room decision is an instruction to the host — perform it or log it"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfRoomAction {
    /// Create the room: this node is the canonical-first of the identity's
    /// nodes and nobody's room is known. Stamp the commit with a
    /// [`CommitClaim`] so a concurrent creator can be resolved.
    Create,
    /// Someone else creates. Publish a KeyPackage row at `self` scope and
    /// wait to be added — the row reaches the creator over the row plane.
    PublishKeyPackage,
    /// This node holds the room and the directory names devices the tree
    /// does not: add them (each needs a published KeyPackage).
    Add(Vec<String>),
    /// This node holds the room and the tree names devices the directory no
    /// longer does (a revoked occurrence): remove them, which advances the
    /// epoch and forward-secures what follows.
    Remove(Vec<String>),
    /// Two rooms exist for one identity and this node's loses the claim
    /// contest. Abandon it and join the winner's — the same convergent
    /// rule concurrent COMMITS settle by (CIRISEdge#604), applied one level
    /// up to creation itself.
    Abandon {
        /// The claim that won.
        in_favour_of: CommitClaim,
    },
    /// The tree matches the directory. Nothing to do.
    Idle,
    /// The directory does not name this node among the identity's devices.
    /// Refused rather than acted on: a node that is not in the roster would
    /// derive addresses it may not listen on, and the remedy is an owner
    /// binding, not a room. The analogue of
    /// [`ScopeLifecycleError::SelfNotInRoster`](crate::scope_lifecycle::ScopeLifecycleError::SelfNotInRoster).
    NotInRoster,
    /// The identity has exactly one device — this one. A room of one
    /// derives addresses nobody else can reach, so it waits. Not an error:
    /// it is the ordinary state of a single-device identity, and it ends
    /// when a second device announces.
    SoleDevice,
}

/// **The rule**, pure and total (`FSD/CONTENT_TRANSFER.md` §6.3).
///
/// `own_key_id` — this node. `roster` — [`roster`]'s output. `held` — this
/// node's room, if it has one. `rival` — the claim of another room seen for
/// the same identity (from a Welcome or a Commit row), if any.
///
/// # The creator rule
///
/// The canonical-first node (lowest key id, CC 4.4.3.2.4.1(a)'s ordering)
/// creates; everyone else offers a KeyPackage. Every node computes it from
/// the same sorted set, so in a converged directory exactly one node
/// creates. In an UNconverged one — B cannot see A yet, so B believes it is
/// first — two rooms appear, and that is not a failure mode to prevent but
/// one to settle: the claims are totally ordered, the later room is
/// abandoned, and its member rejoins the winner. Preventing it would need a
/// coordination round the substrate has no way to run.
///
/// # Ordering is the whole of it
///
/// A rival claim is compared with [`CommitClaim::wins_over`] — earliest
/// `asserted_at`, ties broken on the lowest committer key id — so two nodes
/// looking at the same pair of claims always abandon the same room, from
/// either arrival order, with no round trip.
pub fn decide(
    own_key_id: &str,
    roster: &[String],
    held: Option<&HeldRoom>,
    rival: Option<&CommitClaim>,
) -> SelfRoomAction {
    if !roster.iter().any(|n| n == own_key_id) {
        return SelfRoomAction::NotInRoster;
    }
    if let Some(mine) = held {
        // A contest is settled before any membership work: adding members to
        // a room that is about to be abandoned wastes an epoch and, worse,
        // addresses peers at a group that is going away.
        if let Some(theirs) = rival {
            if theirs.wins_over(&mine.claim) {
                return SelfRoomAction::Abandon {
                    in_favour_of: theirs.clone(),
                };
            }
        }
        let missing: Vec<String> = roster
            .iter()
            .filter(|n| !mine.members.iter().any(|m| m == *n))
            .cloned()
            .collect();
        if !missing.is_empty() {
            return SelfRoomAction::Add(missing);
        }
        let departed: Vec<String> = mine
            .members
            .iter()
            .filter(|m| !roster.iter().any(|n| n == *m))
            .cloned()
            .collect();
        if !departed.is_empty() {
            return SelfRoomAction::Remove(departed);
        }
        return SelfRoomAction::Idle;
    }
    // No room held. A rival's room IS the room — wait for its Welcome
    // rather than creating a second one to be abandoned.
    if rival.is_some() {
        return SelfRoomAction::PublishKeyPackage;
    }
    if roster.len() == 1 {
        return SelfRoomAction::SoleDevice;
    }
    // `roster` is sorted, so the canonical-first node is its head.
    if roster.first().is_some_and(|first| first == own_key_id) {
        SelfRoomAction::Create
    } else {
        SelfRoomAction::PublishKeyPackage
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(ms: i64, who: &str) -> CommitClaim {
        CommitClaim::new(
            chrono::DateTime::from_timestamp_millis(ms).expect("ts"),
            who,
        )
    }

    fn held(members: &[&str], at: i64, who: &str) -> HeldRoom {
        HeldRoom {
            claim: claim(at, who),
            members: members.iter().map(|m| (*m).to_owned()).collect(),
        }
    }

    fn roster(nodes: &[&str]) -> Vec<String> {
        let mut v: Vec<String> = nodes.iter().map(|n| (*n).to_owned()).collect();
        v.sort();
        v
    }

    /// The whole point: in a converged directory exactly ONE node creates,
    /// and it is the same one on every device — so two devices never derive
    /// two secrets for one identity.
    #[test]
    fn exactly_one_node_creates_and_every_node_agrees_which() {
        let r = roster(&["node-a", "node-b", "node-c"]);
        let creators: Vec<&str> = ["node-a", "node-b", "node-c"]
            .into_iter()
            .filter(|n| decide(n, &r, None, None) == SelfRoomAction::Create)
            .collect();
        assert_eq!(creators, vec!["node-a"], "the canonical-first node, only");
        for n in ["node-b", "node-c"] {
            assert_eq!(decide(n, &r, None, None), SelfRoomAction::PublishKeyPackage);
        }
    }

    /// The unconverged case the rule must SETTLE rather than prevent: B
    /// could not see A, so both created. The claims are totally ordered, so
    /// both nodes abandon the same room — and the loser's next tick offers
    /// its KeyPackage to the winner.
    #[test]
    fn two_rooms_from_an_unconverged_directory_settle_on_one_claim() {
        let r = roster(&["node-a", "node-b"]);
        let a_claim = claim(1_000, "node-a");
        let b_claim = claim(2_000, "node-b");
        // A holds the earlier room: it keeps it (and adds B).
        assert_eq!(
            decide(
                "node-a",
                &r,
                Some(&held(&["node-a"], 1_000, "node-a")),
                Some(&b_claim)
            ),
            SelfRoomAction::Add(vec!["node-b".to_owned()])
        );
        // B holds the later one: it abandons, in favour of A's.
        assert_eq!(
            decide(
                "node-b",
                &r,
                Some(&held(&["node-b"], 2_000, "node-b")),
                Some(&a_claim)
            ),
            SelfRoomAction::Abandon {
                in_favour_of: a_claim.clone()
            }
        );
        // Having abandoned, B offers itself to the winner.
        assert_eq!(
            decide("node-b", &r, None, Some(&a_claim)),
            SelfRoomAction::PublishKeyPackage,
            "never a second Create beside a known room"
        );
    }

    /// Equal instants are broken on the key id, so the contest is total —
    /// no pair of claims leaves two rooms standing.
    #[test]
    fn a_tie_is_broken_on_the_key_id_not_left_ambiguous() {
        let r = roster(&["node-a", "node-b"]);
        let a = claim(5_000, "node-a");
        let b = claim(5_000, "node-b");
        assert_eq!(
            decide(
                "node-b",
                &r,
                Some(&held(&["node-b"], 5_000, "node-b")),
                Some(&a)
            ),
            SelfRoomAction::Abandon { in_favour_of: a }
        );
        assert!(matches!(
            decide(
                "node-a",
                &r,
                Some(&held(&["node-a"], 5_000, "node-a")),
                Some(&b)
            ),
            SelfRoomAction::Add(_)
        ));
    }

    /// Membership tracks the DIRECTORY: a new device is added, a revoked
    /// occurrence is removed (which advances the epoch and forward-secures
    /// what follows), and a converged tree is idle.
    #[test]
    fn the_tree_is_driven_toward_the_directory_in_both_directions() {
        let r = roster(&["node-a", "node-b"]);
        assert_eq!(
            decide("node-a", &r, Some(&held(&["node-a"], 1, "node-a")), None),
            SelfRoomAction::Add(vec!["node-b".to_owned()])
        );
        assert_eq!(
            decide(
                "node-a",
                &r,
                Some(&held(&["node-a", "node-b"], 1, "node-a")),
                None
            ),
            SelfRoomAction::Idle
        );
        assert_eq!(
            decide(
                "node-a",
                &roster(&["node-a"]),
                Some(&held(&["node-a", "node-gone"], 1, "node-a")),
                None
            ),
            SelfRoomAction::Remove(vec!["node-gone".to_owned()]),
            "a revoked occurrence leaves the tree, not just the directory"
        );
    }

    /// A contest outranks membership work: a room about to be abandoned
    /// must not spend an epoch adding members, nor address peers at a group
    /// that is going away.
    #[test]
    fn a_losing_room_is_abandoned_before_it_adds_anyone() {
        let r = roster(&["node-a", "node-b", "node-c"]);
        let winner = claim(1, "node-a");
        assert_eq!(
            decide(
                "node-b",
                &r,
                Some(&held(&["node-b"], 9, "node-b")),
                Some(&winner)
            ),
            SelfRoomAction::Abandon {
                in_favour_of: winner
            },
            "not Add(node-a, node-c)"
        );
    }

    /// The two states that are not work: an identity with one device has
    /// nothing to address, and a node the directory does not own is refused
    /// by name rather than deriving addresses it may not listen on.
    #[test]
    fn a_sole_device_waits_and_a_stranger_is_refused_by_name() {
        assert_eq!(
            decide("node-a", &roster(&["node-a"]), None, None),
            SelfRoomAction::SoleDevice
        );
        assert_eq!(
            decide("node-x", &roster(&["node-a", "node-b"]), None, None),
            SelfRoomAction::NotInRoster
        );
        assert_eq!(
            decide(
                "node-x",
                &roster(&["node-a"]),
                Some(&held(&["node-x"], 1, "node-x")),
                None
            ),
            SelfRoomAction::NotInRoster,
            "checked before any tree work, held room or not"
        );
    }
}
