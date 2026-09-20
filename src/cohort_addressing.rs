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
/// a community or a call inside one — for a community, through
/// [`snapshot_for_nodes`] (CIRISEdge#640: the MLS roster names persons,
/// the table's members are nodes):
///
/// ```ignore
/// let roster = cohort_addressing::snapshot_for_nodes(&community, &lens).await?;
/// lifecycle.install(&scope, &roster.snapshot)?;
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
/// **The room's key in the address table — one definition.**
///
/// A community's addresses are installed under `(scope_for(id),
/// group_id_for(id))`. The blob router (`blob_swarm::scope`) looks a
/// community blob's holders up under the SAME pair, so the two cannot
/// drift: CIRISEdge#616 found `BlobMeaning` naming the room by its bare
/// `community_key_id` while the lifecycle had installed it under the
/// `cohort:` namespace — every lookup missed and every community pull was
/// refused as `HolderNotInGroup`. The namespace exists so a community and a
/// call running inside it cannot collide in the table; it is not optional,
/// and it is spelled here and nowhere else.
#[must_use]
pub fn group_id_for(community_id: &str) -> String {
    format!("cohort:{community_id}")
}

/// The scope a community's addresses are installed under — the same
/// `CohortScope::Cohort` the meaning projection names a community blob by.
#[must_use]
pub fn scope_for(community_id: &str) -> crate::cohort_scope::CohortScope {
    crate::cohort_scope::CohortScope::Cohort {
        cohort_id: community_id.to_owned(),
    }
}

/// **The adapter, as the lifecycle needs it (CIRISEdge#640): members are
/// NODES.** A community's MLS roster names PERSONS — the owners' fed-IDs
/// that consent and converse — while everything the address table is for
/// is a node: the lifecycle requires this node's own key in the roster
/// (`SelfNotInRoster`), the blob router looks a holder up by the key that
/// signed its `holds_bytes` claim (persist §6.1 (4): the node), and a derived
/// destination is something a node listens on. Handing [`snapshot`]'s roster
/// to `install` therefore cannot work for a community; this is the variant
/// that can.
///
/// Every roster entry is walked to *the person, then their nodes* through
/// the ONE resolution the contact ladder uses ([`crate::contact::resolve`]),
/// so a roster that already names nodes and one that names persons produce
/// the same node set. Entries the directory cannot resolve yet are reported
/// in `unresolved`, not silently dropped: they become addressable on the
/// next [`crate::scope_lifecycle::ScopeLifecycle::advance`] after their
/// announce lands, and the host decides whether to wait or install now.
///
/// ```ignore
/// let members = cohort_addressing::snapshot_for_nodes(&community, &lens).await?;
/// lifecycle.install(&scope, &members.snapshot)?;
/// ```
///
/// # Errors
/// [`CohortAddressError::Exporter`] on corrupted group state.
pub async fn snapshot_for_nodes(
    group: &CohortGroup,
    lens: &dyn crate::contact::DirectoryLens,
) -> Result<NodeRoster, CohortAddressError> {
    let mut snap = snapshot(group).await?;
    let persons = std::mem::take(&mut snap.members);
    let mut nodes: Vec<String> = Vec::with_capacity(persons.len());
    let mut unresolved: Vec<(String, crate::contact::LadderStall)> = Vec::new();
    for member in persons {
        match crate::contact::resolve(lens, &member).await {
            Ok(subject) => nodes.extend(subject.nodes),
            Err(stall) => unresolved.push((member, stall)),
        }
    }
    nodes.sort();
    nodes.dedup();
    if !unresolved.is_empty() {
        tracing::warn!(
            group = %snap.group_id,
            epoch = snap.epoch,
            resolved_nodes = nodes.len(),
            unresolved = ?unresolved,
            "cohort roster: some members resolve to no node yet — they are NOT in this \
             epoch's address set and become addressable on the next advance after their \
             announce lands (CIRISEdge#640)"
        );
    }
    snap.members = nodes;
    Ok(NodeRoster {
        snapshot: snap,
        unresolved,
    })
}

/// [`snapshot_for_nodes`]'s answer: the node-membered snapshot the lifecycle
/// takes, plus the roster entries that resolved to no node yet.
#[derive(Debug)]
pub struct NodeRoster {
    pub snapshot: ScopeGroupSnapshot,
    /// Roster entries (persons) the directory could not walk to a node, with
    /// why. Empty on a converged directory.
    pub unresolved: Vec<(String, crate::contact::LadderStall)>,
}

/// **The raw adapter.** Reduce a group to the one shape the lifecycle takes,
/// with the members EXACTLY as the MLS roster names them. For a community
/// that is persons, which the lifecycle refuses (`SelfNotInRoster`) — use
/// [`snapshot_for_nodes`] for a community. This form is right when the
/// roster already names nodes (a test group keyed by node ids).
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
        group_id: group_id_for(group.community_id()),
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

    /// CIRISEdge#640 — a community's MLS roster names PERSONS; the table's
    /// members are NODES. `snapshot_for_nodes` walks each person to their
    /// nodes through the contact ladder's one resolution, so the lifecycle
    /// (which requires THIS NODE in the roster) installs, and the blob router
    /// (which looks a holder up by its node key) routes. A person the
    /// directory cannot resolve yet is reported, not dropped silently.
    #[tokio::test]
    async fn a_community_of_persons_installs_as_its_nodes() {
        struct Lens;
        #[async_trait::async_trait]
        impl crate::contact::DirectoryLens for Lens {
            async fn identity_type_of(&self, key_id: &str) -> Option<String> {
                match key_id {
                    "alice-fed" | "bob-fed" | "carol-fed" => Some("user".into()),
                    "node-a" | "node-b1" | "node-b2" => Some("node".into()),
                    _ => None,
                }
            }
            async fn owner_of(&self, key_id: &str) -> Option<String> {
                match key_id {
                    "node-a" => Some("alice-fed".into()),
                    "node-b1" | "node-b2" => Some("bob-fed".into()),
                    _ => None,
                }
            }
            async fn nodes_owned_by(&self, fed_id: &str) -> Vec<String> {
                match fed_id {
                    "alice-fed" => vec!["node-a".into()],
                    "bob-fed" => vec!["node-b1".into(), "node-b2".into()],
                    _ => Vec::new(), // carol has announced no node yet
                }
            }
        }
        // The MLS group is keyed by PERSONS, as a chat room's is.
        let group = CohortGroup::create(store(), "room-1", "alice-fed", 16)
            .await
            .unwrap();
        let raw = snapshot(&group).await.unwrap();
        assert_eq!(
            raw.members,
            vec!["alice-fed".to_owned()],
            "the raw roster is persons"
        );

        let roster = snapshot_for_nodes(&group, &Lens).await.unwrap();
        assert_eq!(roster.snapshot.members, vec!["node-a".to_owned()]);
        assert!(roster.unresolved.is_empty());
        assert_eq!(roster.snapshot.group_id, group_id_for("room-1"));

        // The lifecycle on node-a installs it: node-a IS in the roster.
        let (life, table) = node("node-a");
        life.install(&scope_for("room-1"), &roster.snapshot)
            .unwrap();
        assert!(table
            .send_address(&scope_for("room-1"), &group_id_for("room-1"), "node-a")
            .is_some());
        // The raw (person) snapshot is refused by the same lifecycle.
        let (life2, _) = node("node-a");
        assert!(matches!(
            life2.install(&scope_for("room-1"), &raw),
            Err(crate::scope_lifecycle::ScopeLifecycleError::SelfNotInRoster { .. })
        ));

        // A person with no announced node is reported, not silently dropped.
        let mut snap = snapshot(&group).await.unwrap();
        snap.members = vec!["bob-fed".into(), "carol-fed".into()];
        // Drive the walk over a hand-built roster through the same function
        // shape: resolve each member.
        let mut nodes = Vec::new();
        let mut unresolved = Vec::new();
        for m in &snap.members {
            match crate::contact::resolve(&Lens, m).await {
                Ok(s) => nodes.extend(s.nodes),
                Err(e) => unresolved.push((m.clone(), e)),
            }
        }
        assert_eq!(nodes, vec!["node-b1".to_owned(), "node-b2".to_owned()]);
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].0, "carol-fed");
    }

    /// CIRISEdge#616 — the router looks a community up under
    /// `(scope_for, group_id_for)`; the lifecycle installs a snapshot under
    /// `snapshot.group_id`. If these ever disagree every community pull is
    /// refused as `HolderNotInGroup`, silently. Pinned here, once.
    #[tokio::test]
    async fn the_router_key_and_the_installed_key_are_one_definition() {
        let a = CohortGroup::create(store(), "c-key", "node-a", 16)
            .await
            .unwrap();
        let snap = snapshot(&a).await.unwrap();
        assert_eq!(snap.group_id, group_id_for("c-key"));
        assert_eq!(
            scope_for("c-key"),
            CohortScope::Cohort {
                cohort_id: "c-key".to_owned()
            }
        );
        let (life, table) = node("node-a");
        life.install(&scope_for("c-key"), &snap).unwrap();
        assert!(
            table
                .send_address(&scope_for("c-key"), &group_id_for("c-key"), "node-a")
                .is_some(),
            "what the lifecycle installed is found under the router's key",
        );
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
