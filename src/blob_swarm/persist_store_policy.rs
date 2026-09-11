//! CIRISEdge#581 — the persist-backed [`BlobStorePolicy`], so the store gate
//! can actually be armed.
//!
//! The gate ([`super::store_gate::admit_blob_store`]) is the rule. This is
//! the reference resolver for the two axes that need the directory, built on
//! the **same three walks the row plane already uses** rather than a second
//! implementation:
//!
//! | axis | walk | why this one |
//! |---|---|---|
//! | 1 provenance (`self`) | `admission_identity_for_writer` | the ONE spelling of "the principal behind a key" — the same AV-45 uses for a writer |
//! | 1 provenance (group) | `list_{families,communities}_for_member` | persist's own rosters, so membership is unforgeable by the sender |
//! | 2 audience | the same two lists, asked about THIS node | inverting the serve question rather than re-deriving it |
//!
//! CIRISEdge#581 is explicit that a second "may I hold this" predicate would
//! drift from the first, and that a cross-plane risk wants the duplication
//! *removed* rather than guarded by a test. So nothing here re-derives
//! membership; it asks persist the same questions
//! `bridge::audience_withholds` asks, with this node as the subject.
//!
//! # The allowlist is data, and deliberately not derived
//!
//! Axis 1 for commons content is an **allowlist**, and this type takes it as
//! a set rather than computing it. That is the honest shape: which authority
//! blesses a CI key is a Registry/Server question, and edge consumes the
//! roster. A policy constructed with an empty allowlist refuses all commons
//! content — which is correct, not a bug, and is what an operator who has
//! not yet been given a roster should experience.
//!
//! # Fail-closed, every arm
//!
//! Any directory error resolves to [`SenderStanding::Undeterminable`] or
//! [`AudienceStanding::Undeterminable`], both of which the gate refuses. A
//! node that cannot answer "is this sender a member" does not get to guess,
//! and the guess it would otherwise make is the permissive one.

use std::collections::HashSet;
use std::sync::Arc;

use super::scope::ContentScope;
use super::store_gate::{AudienceStanding, BlobStorePolicy, OperatorStoreConsent, SenderStanding};
use crate::CohortScope;

/// Resolves the store gate's directory-backed axes against persist.
pub struct PersistBlobStorePolicy {
    directory: Arc<dyn ciris_persist::federation::FederationDirectory>,
    /// This node's own federation key id — the subject of every axis-2
    /// question ("am *I* in this audience").
    local_key_id: String,
    /// Axis 1, commons tier. Supplied, never derived — see the module docs.
    commons_allowlist: HashSet<String>,
    /// Axis 3, the operator's local policy.
    consent: OperatorStoreConsent,
}

impl std::fmt::Debug for PersistBlobStorePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistBlobStorePolicy")
            .field("local_key_id", &self.local_key_id)
            .field("commons_allowlist_len", &self.commons_allowlist.len())
            .field("consent", &self.consent)
            .finish_non_exhaustive()
    }
}

impl PersistBlobStorePolicy {
    /// Build a policy. `local_key_id` is this node's federation key id.
    ///
    /// The allowlist starts EMPTY, which refuses all commons content. Add
    /// the blessed roster with [`with_commons_allowlist`](Self::with_commons_allowlist).
    #[must_use]
    pub fn new(
        directory: Arc<dyn ciris_persist::federation::FederationDirectory>,
        local_key_id: impl Into<String>,
    ) -> Self {
        Self {
            directory,
            local_key_id: local_key_id.into(),
            commons_allowlist: HashSet::new(),
            consent: OperatorStoreConsent::default(),
        }
    }

    /// Install the blessed-sender roster for commons-tier content.
    #[must_use]
    pub fn with_commons_allowlist(mut self, keys: impl IntoIterator<Item = String>) -> Self {
        self.commons_allowlist = keys.into_iter().collect();
        self
    }

    /// Install the operator's store policy (axis 3).
    #[must_use]
    pub fn with_consent(mut self, consent: OperatorStoreConsent) -> Self {
        self.consent = consent;
        self
    }

    /// The cohorts a key's principal belongs to, or `None` if the directory
    /// could not answer. Fail-closed by returning `None` rather than empty:
    /// "unresolvable" and "member of nothing" are different facts and only
    /// one of them is a refusal we can explain.
    async fn cohorts_of(&self, key_id: &str) -> Option<(HashSet<String>, HashSet<String>)> {
        let dir = &*self.directory;
        // The **_active** views, not the plain ones.
        //
        // `list_{families,communities}_for_member` are persist's FULL-HISTORY
        // accessors — they carry no revocation filter. Reading them makes
        // membership permanent: a member ejected from a community keeps
        // standing on axis 1 forever, and a community THIS node has left
        // still reads as `In` on axis 2, which with the default
        // `community: Announce` means storing and advertising content for a
        // community we are no longer in.
        //
        // That directly contradicts this module's own rule — "'Current'
        // matters: membership is read now, not remembered" — which is the
        // kind of gap that only shows up when someone is removed and
        // nothing changes.
        match (
            dir.list_families_for_member_active(key_id).await,
            dir.list_communities_for_member_active(key_id).await,
        ) {
            (Ok(families), Ok(communities)) => Some((
                families.into_iter().map(|f| f.family_key_id).collect(),
                communities
                    .into_iter()
                    .map(|c| c.community_key_id)
                    .collect(),
            )),
            (Err(e), _) | (_, Err(e)) => {
                tracing::debug!(
                    key_id,
                    error = %e,
                    "store gate: cohort membership unresolved — axis fails closed \
                     (CIRISEdge#581)"
                );
                None
            }
        }
    }

    /// The principal behind a key, through the one spelling of that question.
    async fn principal_of(&self, key_id: &str) -> Option<String> {
        match ciris_persist::federation::admission::admission_identity_for_writer(
            &*self.directory as &dyn ciris_persist::federation::FederationDirectory,
            key_id,
        )
        .await
        {
            Ok(p) => Some(p),
            Err(e) => {
                tracing::debug!(
                    key_id,
                    error = %e,
                    "store gate: principal unresolved — axis fails closed (CIRISEdge#581)"
                );
                None
            }
        }
    }
}

#[async_trait::async_trait]
impl BlobStorePolicy for PersistBlobStorePolicy {
    async fn sender_standing(&self, holder_key_id: &str, content: &ContentScope) -> SenderStanding {
        match content.cohort_scope() {
            // Commons: the allowlist, and nothing else. A valid signature is
            // not authorization — `VerifiedOnly` is what a sender who merely
            // signed gets, and the gate refuses it.
            CohortScope::Public => {
                if self.commons_allowlist.contains(holder_key_id) {
                    SenderStanding::Allowlisted
                } else {
                    SenderStanding::VerifiedOnly
                }
            }
            // A community's content may be placed by a current member of a
            // community THIS NODE HAS JOINED. Both halves are checked: a
            // member of a community we are not in has no standing here, and
            // neither does a non-member of one we are in.
            CohortScope::Cohort { cohort_id } => {
                let (Some((_, theirs)), Some((_, ours))) = (
                    self.cohorts_of(holder_key_id).await,
                    self.cohorts_of(&self.local_key_id).await,
                ) else {
                    return SenderStanding::Undeterminable;
                };
                if theirs.contains(cohort_id) && ours.contains(cohort_id) {
                    SenderStanding::MemberOfJoinedGroup
                } else {
                    SenderStanding::VerifiedOnly
                }
            }
            CohortScope::Family => {
                let (Some((theirs, _)), Some((ours, _))) = (
                    self.cohorts_of(holder_key_id).await,
                    self.cohorts_of(&self.local_key_id).await,
                ) else {
                    return SenderStanding::Undeterminable;
                };
                // Family content carries no id on the wire scope, so the
                // test is "we share a family at all".
                if theirs.intersection(&ours).next().is_some() {
                    SenderStanding::MemberOfJoinedGroup
                } else {
                    SenderStanding::VerifiedOnly
                }
            }
            // Only the owner's own nodes may place the owner's own content.
            CohortScope::SelfOnly => {
                let (Some(theirs), Some(ours)) = (
                    self.principal_of(holder_key_id).await,
                    self.principal_of(&self.local_key_id).await,
                ) else {
                    return SenderStanding::Undeterminable;
                };
                if theirs == ours {
                    SenderStanding::OwnNode
                } else {
                    SenderStanding::VerifiedOnly
                }
            }
        }
    }

    async fn audience_standing(&self, content: &ContentScope) -> AudienceStanding {
        match content.cohort_scope() {
            // Commons content declares an audience of everyone. Being in it
            // is not the question that gates commons — axis 1's allowlist
            // and axis 3's consent are.
            CohortScope::Public => AudienceStanding::In,
            CohortScope::Cohort { cohort_id } => {
                let Some((_, ours)) = self.cohorts_of(&self.local_key_id).await else {
                    return AudienceStanding::Undeterminable;
                };
                if ours.contains(cohort_id) {
                    AudienceStanding::In
                } else {
                    AudienceStanding::Out
                }
            }
            CohortScope::Family => {
                let Some((ours, _)) = self.cohorts_of(&self.local_key_id).await else {
                    return AudienceStanding::Undeterminable;
                };
                if ours.is_empty() {
                    AudienceStanding::Out
                } else {
                    AudienceStanding::In
                }
            }
            // `self` content's audience is the owner's own node set, and we
            // are in it exactly when we can resolve ourselves at all. The
            // sender axis is what actually constrains this scope.
            CohortScope::SelfOnly => match self.principal_of(&self.local_key_id).await {
                Some(_) => AudienceStanding::In,
                None => AudienceStanding::Undeterminable,
            },
        }
    }

    fn consent(&self) -> OperatorStoreConsent {
        self.consent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob_swarm::store_gate::ConsentDisposition;

    fn commons() -> ContentScope {
        ContentScope::Federation
    }

    /// The allowlist is consulted by IDENTITY, and an empty one refuses
    /// everything — the state an operator who has no roster yet should be in.
    #[test]
    fn an_empty_allowlist_grants_no_commons_standing() {
        let p = PersistBlobStorePolicy {
            directory: empty_directory(),
            local_key_id: "me".into(),
            commons_allowlist: HashSet::new(),
            consent: OperatorStoreConsent::default(),
        };
        // `sender_standing` for Public never touches the directory, so this
        // is resolvable without one.
        let got = futures::executor::block_on(p.sender_standing("ci-runner", &commons()));
        assert_eq!(
            got,
            SenderStanding::VerifiedOnly,
            "no roster means no blessing — refusing is correct, not a bug",
        );
    }

    #[test]
    fn an_allowlisted_sender_gets_exactly_that_standing() {
        let p = PersistBlobStorePolicy {
            directory: empty_directory(),
            local_key_id: "me".into(),
            commons_allowlist: ["ci-runner".to_string()].into_iter().collect(),
            consent: OperatorStoreConsent::default(),
        };
        let got = futures::executor::block_on(p.sender_standing("ci-runner", &commons()));
        assert_eq!(got, SenderStanding::Allowlisted);
        // …and only that sender.
        let other = futures::executor::block_on(p.sender_standing("someone-else", &commons()));
        assert_eq!(other, SenderStanding::VerifiedOnly);
    }

    #[test]
    fn the_builders_carry_what_they_are_given() {
        let p = PersistBlobStorePolicy::new(empty_directory(), "me")
            .with_commons_allowlist(["a".to_string(), "b".to_string()])
            .with_consent(OperatorStoreConsent {
                commons: ConsentDisposition::Announce,
                ..OperatorStoreConsent::default()
            });
        assert_eq!(p.commons_allowlist.len(), 2);
        assert_eq!(p.consent().commons, ConsentDisposition::Announce);
        // The default the builder starts from is still the conservative one
        // for every axis it was not told about.
        assert_eq!(p.consent().family, ConsentDisposition::LocalOnly);
    }

    /// An empty in-memory directory.
    ///
    /// Named for what it is rather than what these tests use it for: the
    /// Public arm of `sender_standing` never consults it, and the tests
    /// above assert on that arm. An empty directory would ALSO answer
    /// "member of nothing" for the group arms, so do not reach for it to
    /// test those — it would pass for the wrong reason.
    fn empty_directory() -> Arc<dyn ciris_persist::federation::FederationDirectory> {
        futures::executor::block_on(async {
            ciris_persist::prelude::FederationDirectorySqlite::open(":memory:")
                .await
                .expect("in-memory directory")
        })
    }
}
