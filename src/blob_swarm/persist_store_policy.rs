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
//! | 1 provenance (group) | `list_{families,communities}_for_member_active`, asked about the key AND its principal | persist's own rosters, so membership is unforgeable by the sender; the principal hop because **the rosters name persons and the wire keys are nodes** (CIRISEdge#523's shape, one plane over) |
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

    /// The cohorts a key belongs to — **through its principal too**.
    ///
    /// # CIRISEdge#581 F4: the hop the rosters require
    ///
    /// persist's rosters name PERSONS. The key ids on this path are wire
    /// keys: a node key, or an identity OCCURRENCE. So asking
    /// `list_communities_for_member(<node key>)` returns nothing for a node
    /// whose owner is a full member — and the first cut asked exactly that.
    ///
    /// It fails CLOSED, which is why it produced no security finding and
    /// would have produced no bug report either: it simply refuses every
    /// real community blob, for every real member, forever. A gate that
    /// refuses everything is a gate an operator turns off, which is the
    /// worst outcome available.
    ///
    /// `bridge::peer_in_cohort` already carries this shape for the serve
    /// side (CIRISEdge#523, "the roster names persons, the peer is a node"),
    /// so this is the same question asked with the same hop, not a second
    /// membership rule.
    ///
    /// `None` means the directory could not answer — distinct from "member
    /// of nothing", because only one of those is a refusal we can explain.
    async fn cohorts_of(&self, key_id: &str) -> Option<(HashSet<String>, HashSet<String>)> {
        let mut ids = vec![key_id.to_owned()];
        if let Principal::Resolved(p) = self.principal_of(key_id).await {
            if p != key_id {
                ids.push(p);
            }
        }
        let mut families = HashSet::new();
        let mut communities = HashSet::new();
        for id in ids {
            let (f, c) = self.rosters_of(&id).await?;
            families.extend(f);
            communities.extend(c);
        }
        Some((families, communities))
    }

    /// The roster reads for ONE key id, with no principal hop.
    async fn rosters_of(&self, key_id: &str) -> Option<(HashSet<String>, HashSet<String>)> {
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

    /// The principal behind a key, through the one spelling of that
    /// question — with the ECHO case reported rather than hidden.
    ///
    /// # CIRISEdge#581 F7: what `Ok` actually means here
    ///
    /// `admission_identity_for_writer` is not a lookup that fails on an
    /// unknown key. Its last line is:
    ///
    /// ```text
    /// Ok(writer.to_owned())
    /// ```
    ///
    /// — a key that is neither an identity occurrence nor an owned node is
    /// its own principal. That is right for persist (a PERSON is their own
    /// principal, and the door cannot know which case it is in) and wrong
    /// to read as a resolution here.
    ///
    /// The first cut returned `Option<String>` and so could not tell the
    /// two apart. Its `SelfOnly` arm then compared two echoes and was safe
    /// only because two different key ids are two different strings —
    /// **not** because the undeterminable arm the module docs promise ever
    /// ran. A gate documented as fail-closed that is actually correct-by-
    /// string-inequality is one rename away from being neither.
    ///
    /// So the echo is separated from a real resolution, and an echo from a
    /// key the directory has never heard of is [`Principal::Unknown`] —
    /// which the `SelfOnly` arm refuses as `Undeterminable`, the posture
    /// that was always documented.
    async fn principal_of(&self, key_id: &str) -> Principal {
        let dir = &*self.directory as &dyn ciris_persist::federation::FederationDirectory;
        let resolved =
            match ciris_persist::federation::admission::admission_identity_for_writer(dir, key_id)
                .await
            {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(
                        key_id,
                        error = %e,
                        "store gate: principal unresolved — axis fails closed (CIRISEdge#581)"
                    );
                    return Principal::Unresolvable;
                }
            };
        if resolved != key_id {
            return Principal::Resolved(resolved);
        }
        // The echo. A key that IS in the directory and is its own principal
        // is a person (or an unowned node standing for itself) — a real
        // answer. A key the directory has never seen is not an answer at
        // all, and must not be compared as though it were.
        match dir.lookup_public_key(key_id).await {
            Ok(Some(_)) => Principal::Resolved(resolved),
            Ok(None) => {
                tracing::debug!(
                    key_id,
                    "store gate: principal echoed for a key the directory does not \
                     know — treated as unresolved, not as a principal of its own \
                     (CIRISEdge#581 F7)"
                );
                Principal::Unknown
            }
            Err(e) => {
                tracing::debug!(
                    key_id,
                    error = %e,
                    "store gate: key lookup failed — axis fails closed (CIRISEdge#581)"
                );
                Principal::Unresolvable
            }
        }
    }
}

/// What the principal walk established about a key.
///
/// Three states because persist's door has three outcomes and only one of
/// them is an answer — see [`PersistBlobStorePolicy::principal_of`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Principal {
    /// A principal was established: an occurrence's identity, a node's
    /// owner, or a key the directory knows that stands for itself.
    Resolved(String),
    /// The door echoed a key the directory has never seen. Not a principal.
    Unknown,
    /// The walk errored.
    Unresolvable,
}

impl Principal {
    /// The established principal, or `None` for the two non-answers.
    fn get(&self) -> Option<&str> {
        match self {
            Self::Resolved(p) => Some(p),
            Self::Unknown | Self::Unresolvable => None,
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
                let theirs = self.principal_of(holder_key_id).await;
                let ours = self.principal_of(&self.local_key_id).await;
                let (Some(theirs), Some(ours)) = (theirs.get(), ours.get()) else {
                    // F7 — an ECHO is not a principal, so this arm is
                    // reached by a key the directory does not know, and the
                    // refusal is the documented one rather than an accident
                    // of two strings differing.
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
            CohortScope::SelfOnly => match self.principal_of(&self.local_key_id).await.get() {
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

/// The group arms, against a REAL directory.
///
/// The arms above them were the only ones covered: `Public` never touches
/// the directory, so an empty in-memory one was enough and the group arms
/// had **no witness at all** — which is how the missing principal hop (F4)
/// survived. A gate that refuses every real community blob fails closed, so
/// nothing is red; the only signal is an operator turning the gate off.
#[cfg(test)]
mod directory_tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ciris_keyring::HardwareSigner as _;
    use ciris_persist::federation::types::identity_type;
    use ciris_persist::federation::types::{Community, CommunityMember, SignedCommunity};
    use ciris_persist::federation::{Attestation, FederationDirectory, SignedAttestation};
    use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
    use ciris_persist::store::backend::Backend as _;

    const PERSON: &str = "person-alice";
    const NODE: &str = "node-alice";
    const STRANGER: &str = "node-stranger";
    const ROOM: &str = "room-1";

    fn ts() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_767_225_296, 0).expect("ts")
    }

    fn signer(alias: &str, seed: u8) -> ciris_keyring::Ed25519SoftwareSigner {
        let mut ed = ciris_keyring::Ed25519SoftwareSigner::new(alias);
        ed.import_key(&[seed; 32]).expect("import");
        ed
    }

    /// The FULL hybrid signature over `bytes`, base64'd.
    ///
    /// persist verifies the federation tier under `HybridPolicy::Strict`, so
    /// a key registered with a PQC pubkey and a row carrying only the
    /// classical half is refused (`verify_hybrid_pqc_fields_mismatch`). The
    /// ML-DSA half signs `canonical ‖ ed25519_sig` — AV-33's binding, the
    /// same way `identity::sign_bound_hybrid` spells it.
    async fn hybrid_sign(key_id: &str, seed: u8, bytes: &[u8]) -> (String, String) {
        let ed = signer(key_id, seed).sign(bytes).await.expect("ed sign");
        let pqc = ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(
            &[seed ^ 0x55; 32],
            format!("{key_id}-pqc"),
        )
        .expect("pqc");
        let mut bound = bytes.to_vec();
        bound.extend_from_slice(&ed);
        let sig = ciris_keyring::PqcSigner::sign(&pqc, &bound)
            .await
            .expect("pqc sign");
        (B64.encode(&ed), B64.encode(&sig))
    }

    async fn register(dir: &dyn FederationDirectory, key_id: &str, kind: &str, seed: u8) {
        let ed = signer(key_id, seed);
        let pubkey = ed.public_key().await.expect("pubkey");
        let pqc = ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(
            &[seed ^ 0x55; 32],
            format!("{key_id}-pqc"),
        )
        .expect("pqc");
        let pqc_pub = ciris_keyring::PqcSigner::public_key(&pqc)
            .await
            .expect("pqc pubkey");
        let envelope = serde_json::json!({ "key_id": key_id });
        let canonical = serde_json::to_vec(&envelope).expect("serialize");
        let digest = <sha2::Sha256 as sha2::Digest>::digest(&canonical);
        let sig = ed.sign(digest.as_slice()).await.expect("sign");
        dir.put_public_key(SignedKeyRecord {
            record: KeyRecord {
                key_id: key_id.to_owned(),
                pubkey_ed25519_base64: B64.encode(&pubkey),
                pubkey_ml_dsa_65_base64: Some(B64.encode(&pqc_pub)),
                algorithm: "hybrid".to_owned(),
                identity_type: kind.to_owned(),
                identity_ref: key_id.to_owned(),
                valid_from: ts(),
                valid_until: None,
                registration_envelope: envelope,
                original_content_hash: hex::encode(digest),
                scrub_signature_classical: B64.encode(sig),
                scrub_signature_pqc: None,
                scrub_key_id: key_id.to_owned(),
                scrub_timestamp: ts(),
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .expect("register key");
    }

    /// The owner binding that makes `NODE` resolve to `PERSON` — the hop the
    /// rosters need, seeded through persist's own dimension and purpose
    /// constants rather than spelled here, so the fixture cannot go green
    /// against a predicate the field does not run.
    async fn bind_owner(dir: &dyn FederationDirectory) {
        use ciris_persist::federation::types::owner_binding;
        let id = "own-1";
        let mut envelope = serde_json::json!({
            "scope": ["infra:network_presence"],
            "dimension": owner_binding::DIMENSION,
            "delegation_purpose": owner_binding::PURPOSE,
        });
        crate::replication::attestation_bind::bind_attestation_envelope(
            &mut envelope,
            ts(),
            &crate::replication::attestation_bind::AttestationColumns {
                attestation_id: id,
                attesting_key_id: PERSON,
                attestation_type: "delegates_to",
                attested_key_id: NODE,
                subject_key_ids: &[NODE.to_owned()],
                cohort_scope: ciris_persist::federation::types::cohort_scope::FEDERATION,
                weight: None,
            },
        );
        let canonical =
            ciris_persist::prelude::ceg_produce_canonicalize(&envelope).expect("canonicalize");
        let digest = <sha2::Sha256 as sha2::Digest>::digest(&canonical);
        let (sig_b64, pqc_b64) = hybrid_sign(PERSON, 0x11, &canonical).await;
        let row = Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: PERSON.to_owned(),
            attested_key_id: NODE.to_owned(),
            attestation_type: "delegates_to".to_owned(),
            weight: None,
            asserted_at: ts(),
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: hex::encode(digest),
            scrub_signature_classical: sig_b64,
            scrub_signature_pqc: Some(pqc_b64),
            scrub_key_id: PERSON.to_owned(),
            scrub_timestamp: ts(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec![NODE.to_owned()],
            withdraws_admission_rule: None,
            cohort_scope: ciris_persist::federation::types::cohort_scope::FEDERATION.to_owned(),
            tier: ciris_persist::federation::types::attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        dir.put_attestation(SignedAttestation { attestation: row })
            .await
            .expect("seed the owner binding");
    }

    /// A directory where `PERSON` is a member of `ROOM` and runs `NODE`.
    async fn joined_directory() -> Arc<dyn FederationDirectory> {
        let dir = FederationDirectorySqlite::open(":memory:")
            .await
            .expect("open");
        dir.run_migrations().await.expect("migrate");
        register(&*dir, PERSON, identity_type::USER, 0x11).await;
        register(&*dir, NODE, identity_type::NODE, 0x22).await;
        register(&*dir, STRANGER, identity_type::NODE, 0x33).await;
        register(&*dir, ROOM, identity_type::AGENT, 0x44).await;
        bind_owner(&*dir).await;
        // `role: FOUNDER` is persist's own constant, never a local
        // `"founder"` literal — an invented spelling would make the fixture
        // green against a predicate the field does not run.
        let community = Community {
            community_key_id: ROOM.to_owned(),
            community_name: "The Room".to_owned(),
            members: vec![CommunityMember {
                key_id: PERSON.to_owned(),
                joined_at: ts(),
                role: Some(ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER.to_owned()),
            }],
            founded_at: ts(),
            consensus_protocol: "founder_only".to_owned(),
            policy_blob: None,
            persist_row_hash: String::new(),
        };
        let canonical =
            ciris_persist::prelude::ceg_produce_canonicalize(&community.signing_envelope())
                .expect("canonicalize the room");
        let (sig_b64, pqc_b64) = hybrid_sign(PERSON, 0x11, &canonical).await;
        dir.put_community(SignedCommunity {
            community,
            authority_key_id: PERSON.to_owned(),
            scrub_signature_classical: sig_b64,
            scrub_signature_pqc: Some(pqc_b64),
        })
        .await
        .expect("seed the room");
        dir
    }

    fn room_content() -> ContentScope {
        ContentScope::Group {
            scope: CohortScope::Cohort {
                cohort_id: ROOM.to_owned(),
            },
            group_id: ROOM.to_owned(),
        }
    }

    fn policy_at(dir: Arc<dyn FederationDirectory>, local: &str) -> PersistBlobStorePolicy {
        PersistBlobStorePolicy::new(dir, local)
    }

    /// **CIRISEdge#581 F4 — the principal hop, with its own witness.**
    ///
    /// The roster names `person-alice`. Both the sender and this node are
    /// `node-alice`, a NODE key that appears on no roster. Without the hop
    /// every one of these is `VerifiedOnly` / `Out` and the gate refuses
    /// every real community blob.
    #[tokio::test]
    async fn a_members_node_has_standing_and_is_in_the_audience() {
        let p = policy_at(joined_directory().await, NODE);
        assert_eq!(
            p.sender_standing(NODE, &room_content()).await,
            SenderStanding::MemberOfJoinedGroup,
            "the roster names the PERSON; the wire key is their NODE",
        );
        assert_eq!(
            p.audience_standing(&room_content()).await,
            AudienceStanding::In,
        );
    }

    /// The person's own key still works — the hop is added BESIDE the direct
    /// test, never in place of it.
    #[tokio::test]
    async fn the_person_themselves_still_has_standing() {
        let p = policy_at(joined_directory().await, PERSON);
        assert_eq!(
            p.sender_standing(PERSON, &room_content()).await,
            SenderStanding::MemberOfJoinedGroup,
        );
    }

    /// The negative control, and the reason the hop is not "trust anyone who
    /// has an owner": a node whose owner is on no roster gets nothing.
    #[tokio::test]
    async fn a_stranger_node_gets_no_standing_from_the_hop() {
        let p = policy_at(joined_directory().await, NODE);
        assert_eq!(
            p.sender_standing(STRANGER, &room_content()).await,
            SenderStanding::VerifiedOnly,
            "the widening must not become 'anyone with a principal'",
        );
    }

    /// Both halves of axis 1 are required: a member of a room THIS NODE has
    /// not joined has no standing to place content here.
    #[tokio::test]
    async fn a_member_of_a_room_we_have_not_joined_has_no_standing() {
        // This node is the stranger, so `ours` does not contain the room.
        let p = policy_at(joined_directory().await, STRANGER);
        assert_eq!(
            p.sender_standing(NODE, &room_content()).await,
            SenderStanding::VerifiedOnly,
        );
        assert_eq!(
            p.audience_standing(&room_content()).await,
            AudienceStanding::Out,
        );
    }

    /// **CIRISEdge#581 F7 — the undeterminable arm actually runs.**
    ///
    /// `admission_identity_for_writer` ECHOES a key it knows nothing about
    /// (`Ok(writer.to_owned())`), so the first cut compared two echoes and
    /// was safe only because two key ids are two different strings. Here the
    /// holder is a key the directory has never seen: the answer must be
    /// `Undeterminable` — the documented posture — and not `VerifiedOnly`,
    /// which would say edge resolved a principal and found it different.
    #[tokio::test]
    async fn a_self_scoped_placement_by_an_unknown_key_is_undeterminable() {
        let p = policy_at(joined_directory().await, NODE);
        let own = ContentScope::Group {
            scope: CohortScope::SelfOnly,
            group_id: NODE.to_owned(),
        };
        assert_eq!(
            p.sender_standing("who-even-is-this", &own).await,
            SenderStanding::Undeterminable,
            "an echoed principal is not a principal",
        );
        // …and the owner's own node is still recognised, so the refusal
        // above is the unknown-key arm and not a blanket refusal.
        assert_eq!(p.sender_standing(NODE, &own).await, SenderStanding::OwnNode,);
    }
}
