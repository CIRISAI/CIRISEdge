//! CIRISEdge#761 (persist v53 S1, CC 5.4.6) — **which group a membership-plane
//! row is about**, so the serve gate can ask persist's
//! [`may_receive_group_plane`](ciris_persist::federation::replication_audience::may_receive_group_plane)
//! about it.
//!
//! persist's `KindPolicy.audience` names seven kinds `MembershipPlane`: the two
//! group RECORDS (`Family`, `Community`) and the five membership planes
//! (family / community revocation, community / family widening, community
//! listing). A private group's rows reach its members' nodes, its live
//! invitees' nodes (with the group's full plane history) and the nodes of the
//! member a row names; a public group's reach every peer. Who is in which set
//! is persist's rule; this module only reads the row's `(scope, group, named)`
//! triple, from the typed signed row on the advertise and from the same typed
//! row decoded off the wire on the fetch twin, so the two read one spelling.
//!
//! This replaces the CIRISEdge#762 `public_group` stand-in: persist's resolver
//! answers the public-group question itself.

use ciris_persist::federation::types::{
    cohort_scope, SignedCommunity, SignedCommunityMembershipListing,
    SignedCommunityMembershipRevocation, SignedCommunityMembershipWidening, SignedFamily,
    SignedFamilyMembershipRevocation, SignedFamilyMembershipWidening,
};

use super::protocol::EnvelopeKind;

/// The group a membership-plane row is about, in the shape persist's
/// `may_receive_group_plane(recipient, scope, group, named)` takes it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupPlane {
    /// `family` or `community`.
    pub scope: &'static str,
    /// The group's key id.
    pub group: String,
    /// The member the row names (the removed, added or listed member); `None`
    /// for a group record.
    pub named: Option<String>,
}

impl GroupPlane {
    fn family(group: &str, named: Option<&str>) -> Self {
        Self {
            scope: cohort_scope::FAMILY,
            group: group.to_owned(),
            named: named.map(str::to_owned),
        }
    }

    fn community(group: &str, named: Option<&str>) -> Self {
        Self {
            scope: cohort_scope::COMMUNITY,
            group: group.to_owned(),
            named: named.map(str::to_owned),
        }
    }

    /// A family record.
    #[must_use]
    pub fn of_family(s: &SignedFamily) -> Self {
        Self::family(&s.family.family_key_id, None)
    }

    /// A community record.
    #[must_use]
    pub fn of_community(s: &SignedCommunity) -> Self {
        Self::community(&s.community.community_key_id, None)
    }

    /// A family membership revocation: names the removed member.
    #[must_use]
    pub fn of_family_revocation(s: &SignedFamilyMembershipRevocation) -> Self {
        let r = &s.family_membership_revocation;
        Self::family(&r.family_key_id, Some(&r.removed_identity_key_id))
    }

    /// A community membership revocation: names the removed member.
    #[must_use]
    pub fn of_community_revocation(s: &SignedCommunityMembershipRevocation) -> Self {
        let r = &s.community_membership_revocation;
        Self::community(&r.community_key_id, Some(&r.removed_identity_key_id))
    }

    /// A community widening: names the member it seats.
    #[must_use]
    pub fn of_community_widening(s: &SignedCommunityMembershipWidening) -> Self {
        let w = &s.community_membership_widening;
        Self::community(&w.community_key_id, Some(&w.member_key_id))
    }

    /// A family widening: names the member it seats.
    #[must_use]
    pub fn of_family_widening(s: &SignedFamilyMembershipWidening) -> Self {
        let w = &s.family_membership_widening;
        Self::family(&w.family_key_id, Some(&w.member_key_id))
    }

    /// A community listing: names the member whose disclosure it is.
    #[must_use]
    pub fn of_community_listing(s: &SignedCommunityMembershipListing) -> Self {
        let l = &s.community_membership_listing;
        Self::community(&l.community_key_id, Some(&l.member_key_id))
    }

    /// The fetch twin: decode `bytes` as `kind`'s signed row and read it with
    /// the advertise's own reader. `None` for a kind that is not a membership
    /// plane, or bytes that do not decode (the gate fails closed on both).
    #[must_use]
    pub fn of_wire(kind: EnvelopeKind, bytes: &[u8]) -> Option<Self> {
        fn de<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Option<T> {
            serde_json::from_slice(bytes).ok()
        }
        match kind {
            EnvelopeKind::Family => de(bytes).as_ref().map(Self::of_family),
            EnvelopeKind::Community => de(bytes).as_ref().map(Self::of_community),
            EnvelopeKind::FamilyMembershipRevocation => {
                de(bytes).as_ref().map(Self::of_family_revocation)
            }
            EnvelopeKind::CommunityMembershipRevocation => {
                de(bytes).as_ref().map(Self::of_community_revocation)
            }
            EnvelopeKind::CommunityMembershipWidening => {
                de(bytes).as_ref().map(Self::of_community_widening)
            }
            EnvelopeKind::FamilyMembershipWidening => {
                de(bytes).as_ref().map(Self::of_family_widening)
            }
            EnvelopeKind::CommunityMembershipListing => {
                de(bytes).as_ref().map(Self::of_community_listing)
            }
            _ => None,
        }
    }
}

/// Is `kind` one persist serves as a membership plane
/// (`ServeAudience::MembershipPlane`)? Read from persist's own policy, so a
/// kind persist moves in or out of the class moves here with it. The two
/// `ALL` arrays are the same names in the same order (both hashed:
/// `REPLICATION_POLICY_HASH`, `SERVE_ADVERTISE_POLICY_HASH`).
#[must_use]
pub fn is_membership_plane(kind: EnvelopeKind) -> bool {
    use ciris_persist::federation::replication_policy::{
        policy_for, EnvelopeKind as PersistKind, ServeAudience,
    };
    EnvelopeKind::ALL
        .iter()
        .position(|k| *k == kind)
        .and_then(|i| PersistKind::ALL.get(i).copied())
        .is_some_and(|k| policy_for(k).audience == ServeAudience::MembershipPlane)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kinds persist names `MembershipPlane` are exactly the seven
    /// [`GroupPlane::of_wire`] reads: a kind persist adds to the class without
    /// a reader here reds this test instead of being served ungated.
    #[test]
    fn every_membership_plane_kind_has_a_reader() {
        use ciris_persist::federation::replication_policy::EnvelopeKind as PersistKind;
        for (i, k) in EnvelopeKind::ALL.iter().enumerate() {
            assert_eq!(
                format!("{k:?}"),
                PersistKind::ALL[i].as_str(),
                "edge's and persist's kind lists diverged at {i}"
            );
        }
        let planes: std::collections::HashSet<EnvelopeKind> = EnvelopeKind::ALL
            .iter()
            .copied()
            .filter(|k| is_membership_plane(*k))
            .collect();
        let read: std::collections::HashSet<EnvelopeKind> = [
            EnvelopeKind::Family,
            EnvelopeKind::Community,
            EnvelopeKind::FamilyMembershipRevocation,
            EnvelopeKind::CommunityMembershipRevocation,
            EnvelopeKind::CommunityMembershipWidening,
            EnvelopeKind::FamilyMembershipWidening,
            EnvelopeKind::CommunityMembershipListing,
        ]
        .into_iter()
        .collect();
        assert_eq!(planes, read);
    }
}
