//! CIRISEdge#762 — **which groups are PUBLIC**: the groups whose record every
//! peer may be handed, because every node resolves its trust root (or its
//! reclaim authority) through them without being a member.
//!
//! CC 5.4.6 hides a group's existence and membership "from outsiders only";
//! CC 4.4.3.2.1 makes `infrastructure` communities Commons-tier and publicly
//! auditable. persist's ruling on CIRISEdge#761: public groups' records stay
//! visible to every peer, and only private groups are gated. So the #758
//! record gate (`group_record_not_member_or_invitee`) applies only where
//! [`is_public_group`] says `false` (`FSD/FIRST_CONTACT.md` §2.5, I23).
//!
//! The markers are persist's, read where persist's own readers read them:
//!
//! - **Community** — public iff its `policy_blob.cohort_subkind` is
//!   [`COHORT_SUBKIND_INFRASTRUCTURE`](ciris_persist::federation::admission::COHORT_SUBKIND_INFRASTRUCTURE),
//!   through persist's [`community_subkind`](ciris_persist::federation::community_subkind).
//!   The SUBKIND, never the id: `ciris-canonical` carries it (persist I190),
//!   and so does every other infrastructure community.
//! - **Family** — no field marks a family public; persist names them by
//!   configured id:
//!   - the accord / charter family: [`accord_family_key_id`](ciris_persist::federation::canonical_community::accord_family_key_id)
//!     (verify's `HUMANITY_ACCORD_FAMILY_KEY_ID`, the family
//!     `trust_root.rs` resolves the `ciris-canonical` arm through) and the
//!     baked genesis bundle's [`family_key_id`](ciris_persist::federation::genesis::canonical_genesis_bundle);
//!   - under `test-anchor`, the anchored accord family
//!     ([`accord_family_genesis_record`](ciris_persist::federation::genesis::accord_family_genesis_record),
//!     CIRISPersist#805) — at this pin the same id, read anyway so the two
//!     cannot drift;
//!   - the deployment's Wise-Authority reclaim body,
//!     [`ReclaimPolicy::from_deployment_pin`](ciris_persist::federation::ReclaimPolicy::from_deployment_pin)`.wa_family_key_id`
//!     — the SAME source persist's reclaim admission reads
//!     (`admission.rs` → `ownership_reclaim.rs` `wa_quorum_over_body`). Edge
//!     holds no reclaim policy of its own; persist publishes it only through
//!     `CIRIS_PERSIST_WA_ADJUDICATION_FAMILY_KEY_ID`, so this reads it through
//!     persist's own parser, per call, exactly as persist does (a node with no
//!     published WA body has no public WA family).
//!
//! TODO(v53): replace this stand-in with persist v53's
//! `ciris_persist::federation::replication_audience::is_public_group`, which
//! persist has committed to be exactly this predicate (CIRISEdge#761/#762),
//! so the two repos cannot answer differently.

use ciris_persist::federation::types::Community;

/// A group, as the serve gate sees it: a community record (its subkind is
/// the marker) or a family id (its configured id is the marker).
#[derive(Debug, Clone, Copy)]
pub enum GroupRef<'a> {
    /// A community record.
    Community(&'a Community),
    /// A family, by `family_key_id`.
    Family(&'a str),
}

/// CIRISEdge#762 — is `group` PUBLIC (its record served to every peer, the
/// pre-v38 `public` serve) rather than private (the #758 member-or-invitee
/// gate)? See the module doc for the markers and where each is read.
///
/// TODO(v53): `ciris_persist::federation::replication_audience::is_public_group`.
#[must_use]
pub fn is_public_group(group: GroupRef<'_>) -> bool {
    match group {
        GroupRef::Community(c) => {
            ciris_persist::federation::community_subkind(c)
                == Some(ciris_persist::federation::admission::COHORT_SUBKIND_INFRASTRUCTURE)
        }
        GroupRef::Family(id) => is_public_family(id),
    }
}

/// The family arm of [`is_public_group`].
fn is_public_family(family_key_id: &str) -> bool {
    if accord_family_ids().iter().any(|a| a == family_key_id) {
        return true;
    }
    ciris_persist::federation::ReclaimPolicy::from_deployment_pin()
        .is_some_and(|p| p.wa_family_key_id == family_key_id)
}

/// The accord / charter family ids: build-time constants of the pinned
/// persist/verify pair, so read once.
fn accord_family_ids() -> &'static [String] {
    static IDS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    IDS.get_or_init(|| {
        let mut ids = vec![
            ciris_persist::federation::canonical_community::accord_family_key_id().to_owned(),
            ciris_persist::federation::genesis::canonical_genesis_bundle()
                .family_key_id
                .clone(),
        ];
        #[cfg(feature = "test-anchor")]
        ids.push(ciris_persist::federation::genesis::accord_family_genesis_record().family_key_id);
        ids.sort();
        ids.dedup();
        ids
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn community(policy_blob: Option<serde_json::Value>, id: &str) -> Community {
        Community {
            community_key_id: id.to_owned(),
            community_name: "c".to_owned(),
            members: Vec::new(),
            founded_at: chrono::Utc::now(),
            consensus_protocol: "founder_only".to_owned(),
            policy_blob,
            persist_row_hash: String::new(),
        }
    }

    #[test]
    fn a_community_is_public_by_its_infrastructure_subkind_not_its_id() {
        let infra = community(
            Some(serde_json::json!({ "cohort_subkind": "infrastructure" })),
            "any-room",
        );
        assert!(is_public_group(GroupRef::Community(&infra)));
        let named_canonical_without_subkind = community(None, "ciris-canonical");
        assert!(
            !is_public_group(GroupRef::Community(&named_canonical_without_subkind)),
            "the id is not the marker"
        );
        let other_subkind = community(
            Some(serde_json::json!({ "cohort_subkind": "chat" })),
            "room",
        );
        assert!(!is_public_group(GroupRef::Community(&other_subkind)));
    }

    #[test]
    fn the_accord_family_is_public_and_an_ordinary_family_is_not() {
        assert!(is_public_group(GroupRef::Family(
            ciris_persist::federation::canonical_community::accord_family_key_id()
        )));
        assert!(is_public_group(GroupRef::Family(
            &ciris_persist::federation::genesis::canonical_genesis_bundle().family_key_id
        )));
        assert!(!is_public_group(GroupRef::Family("f-762-private")));
    }
}
