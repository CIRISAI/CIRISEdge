//! **The room a scope's addresses are installed under** (CIRISEdge#646).
//!
//! A cohort's bytes move over per-member derived destinations
//! ([`ScopeAddressTable`](crate::scope_addressing::ScopeAddressTable),
//! CC 5.4.6). Three facts have to agree for that to work, and before this
//! module they were spelled in three places:
//!
//! 1. the **cohort scope** a blob's content names (the projector's output);
//! 2. the **group id the content names** — what rides the row and the
//!    pointer;
//! 3. the **group id the lifecycle installs under** — the table's key.
//!
//! (2) and (3) are not always the same string. A community blob names its
//! room by the bare `community_key_id`, while the lifecycle installs it
//! under the `cohort:` namespace — and when the router spelled one and the
//! installer the other, every community holder read as not-in-group and
//! every arrival as a group mismatch, both silently (CIRISEdge#616/#619).
//! That bug is a naming disagreement, so the fix is a single name, not a
//! second careful caller: **every question about a room's identity is asked
//! of this type.**
//!
//! # Why the namespace is community-only
//!
//! The table's key is the PAIR `(CohortScope, group_id)`, so the scope
//! already discriminates: `(SelfOnly, "alice")` and `(Cohort, "alice")`
//! cannot collide. The `cohort:` prefix is a community-era spelling
//! (CIRISEdge#616) that stays because communities are installed under it
//! today; self and family rooms take the bare id, and adding a prefix would
//! buy nothing but a migration. What matters is that ONE function says so.
//!
//! # What this type is not
//!
//! It answers *naming* and nothing else — no IO, no roster, no MLS. Each
//! room kind's roster comes from a different authority (a community's from
//! its MLS tree, the self-collective's from the owner's nodes in the
//! directory, a family's from its roster record), so a roster lives with
//! its source rather than behind one signature that would have to take
//! every source's inputs.

use crate::blob_swarm::ContentScope;
use crate::cohort_scope::CohortScope;

/// The community namespace prefix (CIRISEdge#616). Communities are
/// installed under it; nothing else is.
const COHORT_NAMESPACE: &str = "cohort:";

/// **A room, by kind** — the one place a group's names are derived.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScopeRoom {
    /// A community or affiliations room, named by its `community_key_id`.
    Community {
        /// The bare id the row and the pointer carry.
        community_key_id: String,
    },
    /// The **self room**: one identity's own devices (CC 3.3.6), named by
    /// the identity whose collective it is (`FSD/CONTENT_TRANSFER.md` §6.3).
    SelfCollective {
        /// The identity (the person's federation key id), never a node's.
        identity_key_id: String,
    },
    /// A family's room, named by the `family_key_id` the row carries
    /// (CC 5.2, CIRISPersist#887).
    Family {
        /// The family record's key id.
        family_key_id: String,
    },
}

impl ScopeRoom {
    /// A community room.
    #[must_use]
    pub fn community(community_key_id: impl Into<String>) -> Self {
        Self::Community {
            community_key_id: community_key_id.into(),
        }
    }

    /// The self room of `identity_key_id` — the person's own devices.
    #[must_use]
    pub fn self_collective(identity_key_id: impl Into<String>) -> Self {
        Self::SelfCollective {
            identity_key_id: identity_key_id.into(),
        }
    }

    /// A family's room.
    #[must_use]
    pub fn family(family_key_id: impl Into<String>) -> Self {
        Self::Family {
            family_key_id: family_key_id.into(),
        }
    }

    /// The room a blob's projected [`ContentScope`] belongs to — the bridge
    /// from what the content SAYS to where its addresses LIVE.
    ///
    /// `None` for federation-scoped content, which has no room: commons
    /// bytes ride the federation address and no group is installed for
    /// them (`FSD/CONTENT_TRANSFER.md` §5.2 R5).
    #[must_use]
    pub fn from_content_scope(content: &ContentScope) -> Option<Self> {
        let ContentScope::Group { scope, group_id } = content else {
            return None;
        };
        Some(match scope {
            CohortScope::Cohort { .. } => Self::community(group_id),
            CohortScope::SelfOnly => Self::self_collective(group_id),
            CohortScope::Family => Self::family(group_id),
            // `Public` inside a `Group` is refused upstream
            // (`ScopeRouteRefusal::PublicIsNotScoped`); naming a room for it
            // would invent the group that refusal exists to deny.
            CohortScope::Public => return None,
        })
    }

    /// The cohort scope this room's addresses are installed under — the
    /// first half of the table's key.
    #[must_use]
    pub fn scope(&self) -> CohortScope {
        match self {
            Self::Community { community_key_id } => CohortScope::Cohort {
                cohort_id: community_key_id.clone(),
            },
            Self::SelfCollective { .. } => CohortScope::SelfOnly,
            Self::Family { .. } => CohortScope::Family,
        }
    }

    /// The id the CONTENT names: what a row's envelope and a
    /// [`BlobPointer`](crate::group_content::BlobPointer) carry, and what
    /// [`BlobMeaning::project`](crate::blob_swarm::BlobMeaning::project)
    /// yields.
    #[must_use]
    pub fn content_group_id(&self) -> &str {
        match self {
            Self::Community { community_key_id } => community_key_id,
            Self::SelfCollective { identity_key_id } => identity_key_id,
            Self::Family { family_key_id } => family_key_id,
        }
    }

    /// The id the LIFECYCLE installs under — the second half of the table's
    /// key, and what the send router and the serve gate look a group up by.
    ///
    /// Differs from [`Self::content_group_id`] for a community only (see
    /// the module docs). Every caller on both sides of the wire asks this
    /// function, so the installer and the lookups cannot drift.
    #[must_use]
    pub fn table_group_id(&self) -> String {
        match self {
            Self::Community { community_key_id } => {
                format!("{COHORT_NAMESPACE}{community_key_id}")
            }
            Self::SelfCollective { identity_key_id } => identity_key_id.clone(),
            Self::Family { family_key_id } => family_key_id.clone(),
        }
    }

    /// The envelope field a row places itself in this room with — the
    /// **cohort target** persist's write gate reads
    /// (`admission::envelope_cohort_target`, CIRISPersist#887). `None` for
    /// the self room: a `self` row names no target, because the owner IS
    /// the target and the row's author already names them.
    ///
    /// One spelling per kind, here, so a producer cannot write an alias the
    /// gate does not read (and `family_key_id` is the canonical member, not
    /// `community_key_id`).
    #[must_use]
    pub fn cohort_target_field(&self) -> Option<&'static str> {
        match self {
            Self::Community { .. } => Some("community_key_id"),
            Self::Family { .. } => Some("family_key_id"),
            Self::SelfCollective { .. } => None,
        }
    }

    /// The audience an authored row is WIDENED to in order to reach this
    /// room (CC 4.4.3.3.1, `attestation_bind::share`).
    ///
    /// Every content row is authored `self`/local-tier and crosses to its
    /// cohort as a second row — including a self row, which crosses to
    /// [`With::MyDevices`]: a local-tier row replicates nowhere, so the
    /// owner's other devices see nothing until it crosses. That the self
    /// case is a crossing like every other is what keeps one code path.
    #[must_use]
    pub fn widen_to(&self) -> crate::replication::attestation_bind::With {
        use crate::replication::attestation_bind::With;
        match self {
            Self::Community { community_key_id } => With::Community {
                community_key_id: community_key_id.clone(),
            },
            Self::SelfCollective { .. } => With::MyDevices,
            Self::Family { family_key_id } => With::MyFamily {
                family_key_id: family_key_id.clone(),
            },
        }
    }

    /// The `cohort_scope` column a row ABOUT this room carries — its
    /// KeyPackage, Welcome and Commit rows (`FSD/CONTENT_TRANSFER.md`
    /// §6.3), which ride the ordinary row plane and need no room of their
    /// own to cross.
    #[must_use]
    pub fn row_scope_token(&self) -> &'static str {
        use ciris_persist::federation::types::cohort_scope as ps;
        match self {
            Self::Community { .. } => ps::COMMUNITY,
            Self::SelfCollective { .. } => ps::SELF,
            Self::Family { .. } => ps::FAMILY,
        }
    }
}

impl std::fmt::Display for ScopeRoom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}",
            self.scope().kind_token(),
            self.content_group_id()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The round trip the router makes on every scoped pull: the projector
    /// names a scope and an id, and the room turns that into the table's
    /// key. A break here is the CIRISEdge#616 class — silent on both sides.
    #[test]
    fn a_projected_content_scope_names_exactly_one_room_and_one_table_key() {
        for (content, expect_table) in [
            (
                ContentScope::Group {
                    scope: CohortScope::Cohort {
                        cohort_id: "room-1".into(),
                    },
                    group_id: "room-1".into(),
                },
                "cohort:room-1",
            ),
            (
                ContentScope::Group {
                    scope: CohortScope::SelfOnly,
                    group_id: "alice-fed".into(),
                },
                "alice-fed",
            ),
            (
                ContentScope::Group {
                    scope: CohortScope::Family,
                    group_id: "fam-7".into(),
                },
                "fam-7",
            ),
        ] {
            let room = ScopeRoom::from_content_scope(&content).expect("a group names a room");
            assert_eq!(room.table_group_id(), expect_table);
            assert_eq!(room.scope(), *content.cohort_scope());
            assert_eq!(Some(room.content_group_id()), content.group_id());
        }
    }

    #[test]
    fn commons_content_has_no_room() {
        assert_eq!(
            ScopeRoom::from_content_scope(&ContentScope::Federation),
            None
        );
        // `Public` inside a Group is the refused shape, not a room.
        assert_eq!(
            ScopeRoom::from_content_scope(&ContentScope::Group {
                scope: CohortScope::Public,
                group_id: "anything".into(),
            }),
            None
        );
    }

    /// The scope is half the key, so two rooms named alike in different
    /// cohorts are different rooms — which is why only communities carry a
    /// namespace prefix.
    #[test]
    fn one_id_in_two_cohorts_is_two_rooms() {
        let c = ScopeRoom::community("alice-fed");
        let s = ScopeRoom::self_collective("alice-fed");
        assert_ne!(c, s);
        assert_ne!(c.table_group_id(), s.table_group_id());
        assert_ne!(c.scope(), s.scope());
        assert_eq!(c.content_group_id(), s.content_group_id());
    }

    /// The three facts a producer needs — the scope column, the target
    /// field, the crossing — agree per kind by construction, because one
    /// match arm answers all three.
    #[test]
    fn a_rooms_row_facts_agree_per_kind() {
        use crate::replication::attestation_bind::With;
        let c = ScopeRoom::community("room-1");
        assert_eq!(c.cohort_target_field(), Some("community_key_id"));
        assert_eq!(
            c.widen_to(),
            With::Community {
                community_key_id: "room-1".into()
            }
        );
        let s = ScopeRoom::self_collective("alice-fed");
        assert_eq!(s.cohort_target_field(), None, "a self row names no target");
        assert_eq!(s.widen_to(), With::MyDevices);
        let f = ScopeRoom::family("fam-7");
        assert_eq!(
            f.cohort_target_field(),
            Some("family_key_id"),
            "the canonical member persist's gate reads (CIRISPersist#887)"
        );
        assert_eq!(
            f.widen_to(),
            With::MyFamily {
                family_key_id: "fam-7".into()
            }
        );
    }

    #[test]
    fn a_rooms_own_rows_carry_its_cohort_scope() {
        use ciris_persist::federation::types::cohort_scope as ps;
        assert_eq!(ScopeRoom::community("c").row_scope_token(), ps::COMMUNITY);
        assert_eq!(ScopeRoom::self_collective("a").row_scope_token(), ps::SELF);
        assert_eq!(ScopeRoom::family("f").row_scope_token(), ps::FAMILY);
    }
}
