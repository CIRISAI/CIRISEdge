//! Scope-aware fountain **holdings publication** (CIRISEdge#499).
//!
//! # The defect this closes
//!
//! Before this module the swarm publisher
//! ([`run_publisher`](super::runtime::FountainSwarmRuntime)) walked every
//! held `content_id` returned by
//! [`FountainHoldingsSource::list_held_fountain_content`] and broadcast a
//! signed [`FountainHoldingClaim`] — the `content_id` **and its
//! `symbol_ids`** — to every peer a caller-supplied
//! `Fn() -> Vec<String>` returned. There was no entitlement filter of any
//! kind. A family-scoped or community-scoped holding was announced,
//! unprompted, to peers with no business knowing it exists.
//!
//! That is a wider disclosure than the fetch path
//! [`crate::blob_swarm::scope`] closes one plane over: a fetch discloses
//! to one asker who at least had to ask, a holdings broadcast discloses to
//! everyone on a timer. Per <https://ciris.ai/contextual-integrity/>,
//! *"I hold this content"* is itself a flow — publishing it to the wrong
//! cohort is a violation even though **no content bytes move**. The
//! `symbol_ids` make it worse, not better: they are a per-content
//! fingerprint that lets an observer correlate holdings across ticks.
//!
//! # Whose rule is whose
//!
//! This module invents **no** projection policy. It is a two-input join:
//!
//! - **persist owns the projection.** `Plane::FountainContent` is one of
//!   persist's five planes and
//!   [`projection_for`]`(Plane::FountainContent, cohort_scope, authority,
//!   is_tombstone)` answers exactly the question "who may learn this?"
//!   Edge's replication bridge already calls it on the advertise sweep
//!   (`FederationDirectoryReplicationBridge::attestation_projection`); the
//!   swarm publisher is performing an advertise by another name and was
//!   the one advertise path skipping it.
//! - **the host owns the content's scope.** Edge never infers what scope a
//!   fountain content lives in — that is the persist-backed consumer's
//!   classification, surfaced through
//!   [`FountainHoldingsSource::content_scope`], exactly as
//!   [`BlobChunkSource::chunk_scope`](crate::blob_swarm::BlobChunkSource::chunk_scope)
//!   surfaces a blob's. `None` means **UNKNOWN**, never *public*.
//! - **persist owns the AUTHORITY, and it is asked of the SIGNER.**
//!   v37.1.0 (CIRISPersist#744 item 2) — [`holdings_authority`] resolves
//!   [`AuthorityClass::AccordCoScrub`] for a trust-root publisher and
//!   [`AuthorityClass::ProducerSteward`] for everyone else, re-derived
//!   from persist's own verified state on every call. Edge used to pass
//!   a hard-coded `ProducerSteward`, which under-advertised a genuine
//!   canonical corpus.
//!
//!   **Note the shape of the fix, because a cheaper one was refused.**
//!   Authority could have ridden the fountain row's opaque signed
//!   `envelope` — mechanically preimage-safe, since a new JSON key moves
//!   no stored signature. It is substantively wrong: `AccordCoScrub` is
//!   precisely the class a producer must never self-declare, or a corpus
//!   confers trust-root reach on itself (CIRISPersist#543/#659 — a gate
//!   that reads the subject rather than the signer). So the authority is
//!   declared AT THE SEAM. `holdings_authority` takes only the publisher
//!   key: `corpus_kind` is **not a parameter**, so the inference edge was
//!   told not to make is not expressible, and this module must never add
//!   a path that derives authority from the record.
//!
//! - **persist owns the RECIPIENT SET on the commons tiers.**
//!   [`resolve_projection_recipients`] resolves the projection ITSELF
//!   from `(plane, scope, authority, is_tombstone)` — never from a
//!   caller-nominated [`Projection`] — and answers *"may this peer be
//!   told we hold this?"* as a [`RecipientVerdict`]. Edge used to map
//!   `Global | Cohort => announce` by hand, which is why the two halves
//!   had to land together: see [`HoldingsScopeGate::admits`].
//!
//! - **edge owns the per-recipient MECHANISM on its OWN groups.**
//!   For [`ContentScope::Group`] the audience is a roster edge holds in
//!   its address table and persist does not have a key for — see
//!   [`HoldingsScopeGate::admits`]'s "the seam edge cannot yet supply"
//!   note. Edge's resolver is [`ScopeAddressTable::send_address`] — a
//!   peer holds a derived address in a group iff it is a member at a
//!   live epoch. That is the same membership fact
//!   [`ScopeRouteRefusal::HolderNotInGroup`](crate::blob_swarm::ScopeRouteRefusal::HolderNotInGroup)
//!   already rides, reused rather than re-derived.
//!
//! # Fail-closed, and the exact shape of "closed"
//!
//! [`HoldingAnnounce`] is `#[must_use]` and its refusal arm carries a
//! named [`HoldingRefusal`] which maps to a
//! [`WithholdReason`] — the #433 ledger, the #425 choke-point pattern.
//! There is no arm that refuses silently and no arm a caller can drop on
//! the floor: [`HoldingsPublishGate::admit_and_book`] books the withhold
//! **before** it returns the refusal, so a caller that ignores the value
//! still leaves a counted, attributed event behind.
//!
//! **But fail-closed is armed, not unconditional.** The whole gate is
//! gated on whether a [`ScopeAddressTable`] is installed
//! ([`HoldingsScopeGate::is_scope_native`]) — the identical arming
//! condition [`BlobScopeRouter::is_scope_native`] uses, and for the
//! identical reason. A deployment with no table has no scope roster to
//! resolve anyone against, so a gate over it could only refuse
//! everything; it therefore behaves **byte-identically to pre-#499**:
//! every held content announced to every cohort peer. Refusing every
//! holding on a node that cannot resolve a roster would not be
//! fail-closed, it would be fail-broken.
//!
//! [`FountainHoldingsSource::list_held_fountain_content`]: super::FountainHoldingsSource::list_held_fountain_content
//! [`FountainHoldingsSource::content_scope`]: super::FountainHoldingsSource::content_scope
//! [`FountainHoldingClaim`]: crate::holonomic::swarm_rarity::FountainHoldingClaim
//! [`BlobScopeRouter::is_scope_native`]: crate::blob_swarm::BlobScopeRouter::is_scope_native

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ciris_persist::federation::namespace::{
    holdings_authority, projection_for, resolve_projection_recipients, AuthorityClass, Plane,
    Projection, RecipientBasis, RecipientVerdict,
};
use ciris_persist::federation::types::cohort_scope;
use ciris_persist::federation::FederationDirectory;

use crate::blob_swarm::ContentScope;
use crate::cohort_scope::CohortScope;
use crate::observability::{EdgeMetrics, WithholdReason};
use crate::scope_addressing::ScopeAddressTable;

/// Edge's [`CohortScope`] → persist's `cohort_scope` string token.
///
/// **Not a new mapping.** It is the exact mapping
/// [`CohortScope::crypto_tier`] already performs against persist's
/// 7-value lattice (`Public` → `federation`, `SelfOnly` → `self`,
/// `Family` → `family`, `Cohort{..}` → `community`), lifted so the
/// projection axis and the crypto-tier axis cannot drift to two answers
/// for one scope. The tokens come from persist's own consts, never a
/// string literal.
fn persist_scope_token(scope: &CohortScope) -> &'static str {
    match scope {
        CohortScope::Public => cohort_scope::FEDERATION,
        CohortScope::SelfOnly => cohort_scope::SELF,
        CohortScope::Family => cohort_scope::FAMILY,
        CohortScope::Cohort { .. } => cohort_scope::COMMUNITY,
    }
}

/// Stable low-cardinality tag for a [`Projection`] — for logs and the
/// bounded withhold record. Never carries a capability token's value.
fn projection_tag(projection: Projection) -> &'static str {
    match projection {
        Projection::Global => "global",
        Projection::Cohort => "cohort",
        Projection::SelfOwn => "self_own",
        Projection::Capability(_) => "capability",
        Projection::Subject => "subject",
    }
}

/// Stable low-cardinality tag for persist's [`RecipientBasis`] — WHY the
/// recipient set could not be resolved.
///
/// Persist keeps three distinct *"I cannot judge"* causes because "each is
/// a different thing for an operator to go fix". Edge books them under one
/// [`WithholdReason`] (they are ONE branch here — the verdict said it could
/// not judge) but carries the cause in the refusal's payload, its `Display`
/// and its log line, so persist's distinction survives into the ledger
/// instead of being flattened at edge's seam.
///
/// `RecipientBasis` is `#[non_exhaustive]`: persist adds a basis when a new
/// audience axis lands. The wildcard is therefore REQUIRED by the type and
/// is not a policy default — every arm below and the fallback alike are
/// only ever reached on a verdict that already refused.
fn basis_tag(basis: RecipientBasis) -> &'static str {
    match basis {
        RecipientBasis::OwnRoster => "own_roster",
        RecipientBasis::CohortRoster => "cohort_roster",
        RecipientBasis::Unbounded => "unbounded",
        RecipientBasis::NoRosterForScope => "no_roster_for_scope",
        RecipientBasis::GroupUnresolvable => "group_unresolvable",
        // persist v38.0.0 (CIRISPersist#746) — a scope-address-table id
        // (`cohort:*` / `av-stream:*`) in the federation-key parameter
        // is refused BY NAME, never answered as a confident
        // `GroupUnresolvable` about a group that was never asked about.
        // Edge never hands one over (the `ContentScope::Group` branch
        // resolves via the address table, and the Federation branch's
        // `group_key_id` is provably unread — see
        // `federation_branch_never_reads_the_group_key_id`), so this
        // arm firing means a caller wired the wrong id space; the tag
        // names that remedy instead of flattening it into
        // "membership list broken".
        RecipientBasis::GroupIdNotFederationKeyed => "group_id_not_federation_keyed",
        RecipientBasis::NotRosterKeyed => "not_roster_keyed",
        _ => "unknown_basis",
    }
}

/// Why a holdings claim was NOT announced to a peer.
///
/// Each variant is ONE code branch, per the CIRISEdge#433 rule that a
/// refusal reason is the BRANCH and never a disjunction — folding "I
/// cannot tell what this content is" into "you are not on its roster"
/// would send an operator to fix a membership list when the actual remedy
/// is to wire [`FountainHoldingsSource::content_scope`](super::FountainHoldingsSource::content_scope).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldingRefusal {
    /// The host could not determine the content's scope on a node that IS
    /// scope-native. Refused rather than defaulted: "unclassified means
    /// public" is the single most expensive default this stack could
    /// adopt, and it is not edge's to choose — `content_scope`'s `None`
    /// means *unknown*, not *public*.
    ScopeUndeterminable,
    /// The host declared [`ContentScope::Group`] at a `Public` cohort
    /// scope. Refused for the same reason
    /// [`ScopeRouteRefusal::PublicIsNotScoped`](crate::blob_swarm::ScopeRouteRefusal::PublicIsNotScoped)
    /// is: a private roster paired with "public" is a contradiction, not
    /// a configuration. Public content is [`ContentScope::Federation`].
    PublicIsNotScoped,
    /// The projection bounds this record to its OWN roster
    /// ([`Projection::Cohort`] over a named group, or the
    /// structurally-invisible [`Projection::SelfOwn`]) and this peer holds
    /// no derived address in that group — not a member at any live epoch,
    /// or excluded at a rotation seal. **This is the leak closing.**
    PeerNotInRoster {
        /// [`CohortScope::kind_token`] of the content's scope.
        content_kind: &'static str,
        /// Stable low-cardinality tag of the projection that bound the
        /// audience (`cohort` / `self_own`).
        projection: &'static str,
    },
    /// `projection_for` named an audience kind this gate has no mechanism
    /// to resolve to a peer set on this plane — today
    /// [`Projection::Capability`] / [`Projection::Subject`] (role-keyed
    /// and subject-keyed audiences that `Plane::FountainContent` has no
    /// cell for), or a `SelfOwn` record that names no roster to be
    /// invisible within.
    ///
    /// Structurally unreachable against persist v37's table; booked
    /// fail-closed anyway so a future persist widening surfaces as a NAMED
    /// withhold instead of as an allow.
    ProjectionUnsupported {
        /// Stable low-cardinality tag of the projection edge cannot
        /// resolve (`capability` / `subject`).
        projection: &'static str,
    },
    /// The gate is ARMED (a [`ScopeAddressTable`] is installed) but no
    /// [`FederationDirectory`] is wired, so neither
    /// [`holdings_authority`] nor [`resolve_projection_recipients`] can
    /// be asked. A wiring fault, not a policy decision — the same shape
    /// as [`WithholdReason::LocalIdentityMissing`] on the replication
    /// plane, and refused rather than silently falling back to the
    /// pre-#744 hard-coded authority: falling back would resurrect
    /// exactly the defect this cut removes, and would do it invisibly.
    DirectoryMissing,
    /// [`holdings_authority`] could not be resolved — the trust-root walk
    /// over the PUBLISHER's key errored.
    ///
    /// Never folded into a `ProducerSteward` default. A read that failed
    /// is not a statement that the publisher is a plain producer, and
    /// quietly demoting it would be the #425 Exhibit C shape: an
    /// infrastructure fault reported as a confident claim about the
    /// signer.
    AuthorityUnresolved,
    /// [`resolve_projection_recipients`] answered *"I cannot judge"*
    /// (`set_resolvable == false`).
    ///
    /// **Structurally distinct from [`PeerNotInRoster`](Self::PeerNotInRoster),
    /// which is the whole point.** Persist keeps `set_resolvable` and
    /// `peer_in_set` as two fields precisely so an admission of ignorance
    /// is never reported as an accusation about the peer, and collapsing
    /// them here would undo that one plane over (the CIRISPersist#731
    /// lesson, restated for #744). An operator seeing this must go fix a
    /// roster table or a group registration; an operator seeing
    /// `PeerNotInRoster` must go fix a membership list. Different places.
    RecipientSetUnresolved {
        /// [`basis_tag`] of persist's [`RecipientBasis`] — WHICH of the
        /// "cannot judge" causes fired (`no_roster_for_scope` /
        /// `group_unresolvable`), so the ledger keeps the distinction
        /// persist drew.
        basis: &'static str,
    },
    /// [`resolve_projection_recipients`] itself returned `Err`.
    ///
    /// Persist documents every resolution path as returning `Ok` today
    /// and retains the `Result` "because a future leg may need to
    /// distinguish an infrastructure fault from a refusal". Edge honours
    /// that split now rather than later: a transport/read fault is booked
    /// as one, never as
    /// [`RecipientSetUnresolved`](Self::RecipientSetUnresolved), which is
    /// a VERDICT persist reached deliberately.
    RecipientReadError,
}

impl HoldingRefusal {
    /// Stable, low-cardinality tag for log throttling and metric detail.
    /// Never contains a peer id, a content id or a group id — those ride
    /// the bounded record, not the label (unbounded label cardinality
    /// explodes downstream metric storage).
    #[must_use]
    pub const fn reason_tag(&self) -> &'static str {
        match self {
            Self::ScopeUndeterminable => "holding_scope_undeterminable",
            Self::PublicIsNotScoped => "holding_scope_public_group",
            Self::PeerNotInRoster { .. } => "holding_scope_peer_not_in_roster",
            Self::ProjectionUnsupported { .. } => "holding_scope_projection_unsupported",
            Self::DirectoryMissing => "holding_scope_directory_missing",
            Self::AuthorityUnresolved => "holding_scope_authority_unresolved",
            Self::RecipientSetUnresolved { .. } => "holding_scope_recipient_set_unresolved",
            Self::RecipientReadError => "holding_scope_recipient_read_error",
        }
    }

    /// The withhold-ledger reason for this branch (CIRISEdge#433).
    #[must_use]
    pub const fn withhold_reason(&self) -> WithholdReason {
        match self {
            Self::ScopeUndeterminable => WithholdReason::HoldingScopeUndeterminable,
            Self::PublicIsNotScoped => WithholdReason::HoldingScopePublicGroup,
            Self::PeerNotInRoster { .. } => WithholdReason::HoldingScopePeerNotInRoster,
            Self::ProjectionUnsupported { .. } => WithholdReason::HoldingScopeProjectionUnsupported,
            Self::DirectoryMissing => WithholdReason::HoldingScopeDirectoryMissing,
            Self::AuthorityUnresolved => WithholdReason::HoldingScopeAuthorityUnresolved,
            Self::RecipientSetUnresolved { .. } => {
                WithholdReason::HoldingScopeRecipientSetUnresolved
            }
            Self::RecipientReadError => WithholdReason::HoldingScopeRecipientReadError,
        }
    }
}

impl std::fmt::Display for HoldingRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ScopeUndeterminable => f.write_str(
                "fountain holding scope is UNDETERMINABLE and this node is scope-native \
                 — refusing to announce the holding (and its symbol_ids) to anyone. Wire \
                 FountainHoldingsSource::content_scope; a None answer is never read as \
                 Public (CIRISEdge#499)",
            ),
            Self::PublicIsNotScoped => f.write_str(
                "fountain holding declared a scope GROUP at Public scope — a private \
                 roster is not a public audience; public content must be declared \
                 ContentScope::Federation (CIRISEdge#499)",
            ),
            Self::PeerNotInRoster {
                content_kind,
                projection,
            } => write!(
                f,
                "fountain holding is scoped '{content_kind}' and projects '{projection}' \
                 (audience = the record's own roster); this peer holds no derived address \
                 in that group at any live epoch, so it is not told the holding exists \
                 (CIRISEdge#499)"
            ),
            Self::ProjectionUnsupported { projection } => write!(
                f,
                "fountain holding projects '{projection}', an audience kind this gate has \
                 no peer-set mechanism for on Plane::FountainContent — refusing \
                 fail-closed rather than guessing the audience (CIRISEdge#499)"
            ),
            Self::DirectoryMissing => f.write_str(
                "fountain holdings gate is ARMED (a scope-address table is installed) but no \
                 FederationDirectory is wired, so neither the publisher's authority class nor \
                 the recipient set can be resolved. Wire SwarmRuntimeOptions::directory; the \
                 gate will NOT fall back to a hard-coded authority (CIRISPersist#744)",
            ),
            Self::AuthorityUnresolved => f.write_str(
                "resolving the PUBLISHER's authority class (persist holdings_authority — the \
                 accord-co-scrub trust-root walk) FAILED. Withholding: a read that failed is \
                 not a statement that the publisher is a plain producer, and demoting it \
                 silently is how a trust-root corpus loses its reach (CIRISPersist#744)",
            ),
            Self::RecipientSetUnresolved { basis } => write!(
                f,
                "persist's resolve_projection_recipients returned set_resolvable=false \
                 (basis '{basis}') — it CANNOT JUDGE this record's recipient set, which is \
                 NOT a statement that the peer is outside it. Withholding fail-closed; an \
                 advertisement gate never fails open (CIRISPersist#744)"
            ),
            Self::RecipientReadError => f.write_str(
                "persist's resolve_projection_recipients returned an ERROR — an \
                 infrastructure fault, deliberately not booked as the 'cannot judge' verdict \
                 it would otherwise be mistaken for. Withholding (CIRISPersist#744)",
            ),
        }
    }
}

/// Whether a holdings claim may be announced to one peer.
///
/// `#[must_use]` with a payload-carrying refusal arm, mirroring
/// [`ServeAdmission`](crate::blob_swarm::ServeAdmission) and
/// [`ApplyOutcome`](crate::replication::summary::ApplyOutcome)
/// (CIRISEdge#425): the publisher cannot drop this on the floor, and a
/// refusal always arrives with a named reason to book and log. A bare
/// `bool` would have made "withheld" and "withheld for a reason nobody
/// can see" the same value — the exact silent-refusal class #423–#429
/// spent four cuts removing.
#[must_use = "a holding admission carries a refusal reason the publisher must book and log — do not drop it"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldingAnnounce {
    /// Announce the holding to this peer.
    Announce,
    /// Do not announce; book and log this reason.
    Withhold(HoldingRefusal),
}

impl HoldingAnnounce {
    /// `true` iff the holding may be announced to this peer.
    #[must_use]
    pub fn is_announced(&self) -> bool {
        matches!(self, Self::Announce)
    }
}

/// Resolves whether a held content's scope admits announcing it to a
/// given peer.
///
/// Holds only the address table (a pure lookup structure) — it cannot
/// send, so it cannot be the place a publish decision leaks into the
/// transport. Every method is synchronous and takes no lock across
/// anything: the table's own methods are synchronous by design
/// (CIRISEdge#217 — a guard held across an `.await` on a publish path is
/// what produced the real hangs), and this type adds no state of its own.
#[derive(Clone, Default)]
pub struct HoldingsScopeGate {
    table: Option<Arc<ScopeAddressTable>>,
    directory: Option<Arc<dyn FederationDirectory>>,
}

impl HoldingsScopeGate {
    /// A gate over an installed table and the federation directory the
    /// two persist verbs are asked of.
    ///
    /// `table: None` — the production state until the MLS exporter label
    /// is specified upstream — yields a gate that announces everything,
    /// i.e. exactly pre-#499 behaviour, **without touching the
    /// directory**. `table: Some` with `directory: None` is an armed but
    /// unwired node, which fails closed
    /// ([`HoldingRefusal::DirectoryMissing`]) rather than reverting to a
    /// hard-coded authority class.
    #[must_use]
    pub fn new(
        table: Option<Arc<ScopeAddressTable>>,
        directory: Option<Arc<dyn FederationDirectory>>,
    ) -> Self {
        Self { table, directory }
    }

    /// `true` iff a [`ScopeAddressTable`] is installed, i.e. iff this node
    /// can resolve a scope roster at all.
    ///
    /// THE arming condition. A deployment fact, not a policy knob: a node
    /// with no table has no roster to resolve any peer against, so a gate
    /// over it could only ever refuse everything.
    #[must_use]
    pub fn is_scope_native(&self) -> bool {
        self.table.is_some()
    }

    /// The projection persist resolves for `scope` under `authority` on
    /// [`Plane::FountainContent`]. Exposed so the pin test reads the real
    /// table rather than a copy of it — the #636 lesson that a gate must
    /// see the table itself.
    ///
    /// `authority` is a PARAMETER as of v37.1.0 (CIRISPersist#744): it
    /// used to be a hard-coded `ProducerSteward` const, and that const
    /// was the under-advertisement bug. It is resolved per publisher by
    /// [`holdings_authority`] and never inferred from the record.
    #[must_use]
    pub fn projection_of(scope: &CohortScope, authority: AuthorityClass) -> Projection {
        projection_for(
            Plane::FountainContent,
            persist_scope_token(scope),
            authority,
            // A holdings claim is a live claim about what this node
            // currently retains. It is never a tombstone: there is no
            // "un-holding" record on this plane — a dropped holding is
            // expressed by the claim ceasing to be republished, which the
            // runtime's TTL prune reads. Passing `true` here would raise
            // every scoped holding to the anti-rollback ceiling.
            false,
        )
    }

    /// May a holdings claim for content scoped `content` be announced to
    /// `peer_key_id`?
    ///
    /// `content` is the host's declaration
    /// ([`FountainHoldingsSource::content_scope`](super::FountainHoldingsSource::content_scope)),
    /// or `None` when it could not be determined.
    ///
    /// # Arming
    ///
    /// `is_scope_native() == false` ⇒ [`HoldingAnnounce::Announce`]
    /// unconditionally, with no table probe and **no directory call**. See
    /// the module docs: additive, not disruptive. The early return is
    /// byte-identical to pre-#499 and pre-#744 alike — an unarmed node
    /// performs no `.await` on this path at all.
    ///
    /// v18 — the UNARMED state is no longer silent: the FIRST consultation
    /// of an unarmed gate emits one process-lifetime WARN naming the
    /// staged state and what arming requires — installing the MLS
    /// [`ScopeAddressTable`], an OPERATOR OPT-IN via
    /// `EdgeBuilder::scope_native_addressing` (the deriver itself shipped
    /// with CIRISVerify#259's `ScopePrivacyDeriver`; nothing upstream is
    /// pending). One atomic flag, no throttle table, no behavior change —
    /// production deliberately rides unarmed until the operator opts in,
    /// and an operator reading logs must be able to tell "staged open"
    /// from "armed and passing".
    ///
    /// # The two halves of CIRISPersist#744, and why they are one change
    ///
    /// `authority` is read by `projection_for` on
    /// [`Plane::FountainContent`] at **exactly one scope** — `federation`
    /// — where a trust root projects `Global` and everyone else projects
    /// `Cohort`. Every other scope arm ignores it
    /// (`authority_is_read_only_at_federation_scope` pins this). So the
    /// authority seam and the recipient verb act on the SAME cell, and
    /// landing either alone is a defect:
    ///
    /// - **verb alone** (authority still hard-coded `ProducerSteward`): a
    ///   trust-root publisher's federation-scoped corpus resolves
    ///   `Cohort`, `Cohort::from_token("federation")` has no roster table,
    ///   and the verdict is `NoRosterForScope` — the canonical corpus
    ///   goes DARK.
    /// - **seam alone** (still hand-mapping `Global | Cohort => announce`):
    ///   a trust-root publisher now resolves `AccordCoScrub` and so
    ///   `Global`, which the hand-map admitted for free — because it
    ///   admitted `Cohort` too. `Global` is *unbounded*; the hand-map made
    ///   the widening invisible by treating "everyone" and "the cohort" as
    ///   one answer.
    ///
    /// `neither_half_alone_is_safe` is the guard.
    ///
    /// # The seam edge cannot yet supply — [`ContentScope::Group`]
    ///
    /// The verb's roster leg reads `active_members(cohort, group_key_id)`,
    /// a **federation group key id**. Edge's [`ContentScope::Group`]
    /// carries the ADDRESS TABLE's group id, a different namespace —
    /// `cohort_addressing::snapshot` mints it as `cohort:{community_id}`
    /// and the A/V plane mints session ids alongside, both namespaced so
    /// "a community and a call inside it cannot collide". The same field
    /// is what [`ScopeAddressTable::send_address`] is keyed on, so one
    /// string cannot be both.
    ///
    /// Passing it to persist anyway would not be fail-closed, it would be
    /// a **wrong answer that happens to point the safe way**: persist
    /// would resolve `GroupUnresolvable` for a group it was never asked
    /// about, and every family/community holding would go dark under a
    /// verdict that looks authoritative. That is the CIRISPersist#731
    /// shape the verb's own signature exists to prevent (which is why it
    /// takes `authority`/`is_tombstone` and resolves the projection
    /// itself, rather than accepting a caller-nominated `Projection`).
    ///
    /// So this branch keeps edge's address-table membership — the only
    /// registry edge holds a key for — and the group-key-id seam is
    /// reported upstream rather than faked here.
    pub async fn admits(
        &self,
        publisher_key_id: &str,
        content: Option<&ContentScope>,
        peer_key_id: &str,
    ) -> HoldingAnnounce {
        // ARMING — the byte-identical early return. No probe, no await.
        let Some(table) = self.table.as_ref() else {
            warn_holdings_scope_gate_unarmed();
            return HoldingAnnounce::Announce;
        };

        let Some(content) = content else {
            return HoldingAnnounce::Withhold(HoldingRefusal::ScopeUndeterminable);
        };

        // A private roster at Public scope is a contradiction, not a
        // configuration — refused before any lookup and before any
        // directory call, exactly as the blob router refuses it on the
        // send side. Hoisted above the awaits so a malformed declaration
        // never reads as a wiring fault.
        if let ContentScope::Group {
            scope: CohortScope::Public,
            ..
        } = content
        {
            return HoldingAnnounce::Withhold(HoldingRefusal::PublicIsNotScoped);
        }

        let Some(directory) = self.directory.as_deref() else {
            return HoldingAnnounce::Withhold(HoldingRefusal::DirectoryMissing);
        };

        // ── HALF 1: THE AUTHORITY SEAM ──────────────────────────────
        // Asked of the SIGNER, re-derived from persist's verified state
        // on every call. Never stored, never signed by the party it
        // benefits, never inferred from `corpus_kind` — which is not even
        // a parameter here, so the inference is not expressible.
        //
        // CIRISEdge#217: no guard is held here. `self.directory` is an
        // `Arc` deref, and the only lock in this function
        // (`send_address`'s, below) is taken AFTER every await and
        // released within its own statement.
        let authority = match holdings_authority(directory, publisher_key_id).await {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(
                    publisher = %publisher_key_id,
                    error = %e,
                    "holdings gate: holdings_authority FAILED — withholding",
                );
                return HoldingAnnounce::Withhold(HoldingRefusal::AuthorityUnresolved);
            }
        };

        // Resolve the projection PER RECORD from the record's real scope
        // — never from a cached assumption, the discipline `bridge.rs`
        // holds on the attestation plane.
        let content_scope = content.cohort_scope();

        match content {
            // ── HALF 2: THE RECIPIENT VERB ──────────────────────────
            // Federation/commons content. Persist resolves the projection
            // ITSELF and answers whether this peer may be told — replacing
            // edge's hand-rolled `Global | Cohort => announce`.
            //
            // `group_key_id` is provably UNREAD on this branch: `Global`
            // returns `Unbounded` and `Cohort` at a commons tier returns
            // `NoRosterForScope`, both before any roster leg. It is passed
            // empty rather than invented, and
            // `federation_branch_never_reads_the_group_key_id` pins that.
            ContentScope::Federation => {
                let verdict = match resolve_projection_recipients(
                    directory,
                    Plane::FountainContent,
                    persist_scope_token(content_scope),
                    authority,
                    // A holdings claim is a live claim about what this
                    // node currently retains — never a tombstone. See
                    // `projection_of`.
                    false,
                    "",
                    peer_key_id,
                )
                .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(
                            peer = %peer_key_id,
                            error = %e,
                            "holdings gate: resolve_projection_recipients ERRORED — withholding",
                        );
                        return HoldingAnnounce::Withhold(HoldingRefusal::RecipientReadError);
                    }
                };
                Self::read_verdict(verdict, content_scope, authority)
            }
            ContentScope::Group { scope, group_id } => {
                let projection = Self::projection_of(content_scope, authority);
                match projection {
                    // Commons gossip — the record reaches the whole
                    // federation regardless of roster.
                    Projection::Global => HoldingAnnounce::Announce,
                    // `Cohort` / `SelfOwn` — both bound the audience to
                    // the record's OWN roster. Edge's resolver for that
                    // roster is the address table's membership, one
                    // hash-map probe and no derivation. See the
                    // "seam edge cannot yet supply" note above for why
                    // persist's verb is NOT asked here.
                    //
                    // v18 audit note — `SelfOwn` announced-to-roster is a
                    // DELIBERATE reading, not the attestation plane's
                    // "structurally invisible" collapsed by accident. A
                    // holdings claim is publish-own BY CONSTRUCTION (the
                    // announcing node is the claim's producer), so the
                    // SelfOwn publisher restriction is trivially satisfied;
                    // what remains is the AUDIENCE, and persist bounds it
                    // to the record's OWN roster — the family's MLS group
                    // for family scope (the same set the blob serve gate
                    // admits on the family address), and the owner's own
                    // device set for `self` scope (the single-owner
                    // boundary, CIRISConstitution#23). The residual trust
                    // assumption is the TABLE INSTALLER's: a `self`-scope
                    // group's roster must be only the owner's nodes — this
                    // gate cannot verify that. Pinned by
                    // `family_holding_withheld_from_outsider_while_federation_still_flows`.
                    Projection::Cohort | Projection::SelfOwn => {
                        if table.send_address(scope, group_id, peer_key_id).is_some() {
                            if projection == Projection::SelfOwn {
                                tracing::debug!(
                                    peer = %peer_key_id,
                                    content_kind = scope.kind_token(),
                                    "SelfOwn-projected holding announced to its OWN \
                                     group roster (deliberate — see the v18 audit \
                                     note at this site)"
                                );
                            }
                            HoldingAnnounce::Announce
                        } else {
                            HoldingAnnounce::Withhold(HoldingRefusal::PeerNotInRoster {
                                content_kind: scope.kind_token(),
                                projection: projection_tag(projection),
                            })
                        }
                    }
                    other => HoldingAnnounce::Withhold(HoldingRefusal::ProjectionUnsupported {
                        projection: projection_tag(other),
                    }),
                }
            }
        }
    }

    /// Read persist's [`RecipientVerdict`] into an announce decision.
    ///
    /// **The order of these two reads is load-bearing.** `set_resolvable`
    /// is consulted FIRST and has its own refusal; only then is
    /// `peer_in_set` meaningful. Reversing them — or reading
    /// `peer_in_set` alone — reports *"I cannot judge"* as *"you are not
    /// seated"*: an admission of ignorance dressed as an accusation, and
    /// the exact collapse persist split the struct to prevent.
    ///
    /// `may_advertise()` is deliberately NOT used as the single test: it
    /// is the right conjunction but it erases which half failed, and #433
    /// requires the branch, not the disjunction.
    fn read_verdict(
        verdict: RecipientVerdict,
        content_scope: &CohortScope,
        authority: AuthorityClass,
    ) -> HoldingAnnounce {
        if !verdict.set_resolvable {
            // "I cannot judge" — NOT "the peer is not in the set".
            return match verdict.basis {
                // Role-keyed / subject-keyed audiences are not a
                // `(scope, group)` question at all. This is the exact
                // condition `ProjectionUnsupported` was minted for, so it
                // keeps that reason rather than minting a second name for
                // one fact. Structurally unreachable against persist
                // v37's FountainContent table (which yields only
                // Global/Cohort/SelfOwn); booked fail-closed anyway so a
                // future persist widening surfaces as a NAMED withhold
                // instead of as an allow.
                RecipientBasis::NotRosterKeyed => {
                    HoldingAnnounce::Withhold(HoldingRefusal::ProjectionUnsupported {
                        projection: projection_tag(Self::projection_of(content_scope, authority)),
                    })
                }
                other => HoldingAnnounce::Withhold(HoldingRefusal::RecipientSetUnresolved {
                    basis: basis_tag(other),
                }),
            };
        }
        if !verdict.peer_in_set {
            // Resolved, and the peer is genuinely outside it.
            return HoldingAnnounce::Withhold(HoldingRefusal::PeerNotInRoster {
                content_kind: content_scope.kind_token(),
                projection: projection_tag(Self::projection_of(content_scope, authority)),
            });
        }
        debug_assert!(
            verdict.may_advertise(),
            "both verdict legs passed, so persist must also admit"
        );
        HoldingAnnounce::Announce
    }
}

/// The publisher-side choke point: decide **and book**.
///
/// Pairs the pure [`HoldingsScopeGate`] with the CIRISEdge#433 withhold
/// ledger so the publisher has exactly one call to make and no way to
/// refuse silently — [`Self::admit_and_book`] increments the counter and
/// pushes the attribution record BEFORE it returns the refusal. A caller
/// that ignores the returned value still leaves a counted, attributed,
/// logged event behind, which is the property #433 exists to guarantee
/// (a withholding node must not report what an idle node reports).
#[derive(Clone, Default)]
pub struct HoldingsPublishGate {
    gate: HoldingsScopeGate,
    metrics: Option<EdgeMetrics>,
}

impl HoldingsPublishGate {
    /// Construct from the runtime's optional address table, the optional
    /// federation directory the persist verbs are asked of, and the
    /// optional metrics handle. All `None` is the pre-#499 deployment:
    /// the gate admits everything and books nothing.
    #[must_use]
    pub fn new(
        table: Option<Arc<ScopeAddressTable>>,
        directory: Option<Arc<dyn FederationDirectory>>,
        metrics: Option<EdgeMetrics>,
    ) -> Self {
        Self {
            gate: HoldingsScopeGate::new(table, directory),
            metrics,
        }
    }

    /// `true` iff the gate is armed (a [`ScopeAddressTable`] is installed).
    #[must_use]
    pub fn is_scope_native(&self) -> bool {
        self.gate.is_scope_native()
    }

    /// Decide whether `content_id` (scoped `content`) may be announced to
    /// `peer_key_id`, booking + logging any withhold before returning it.
    ///
    /// `publisher_key_id` is the key the holding claim is published
    /// under — the local node's. It is the ONLY input
    /// [`holdings_authority`] takes, and it is a parameter rather than
    /// gate state so the authority is resolved per publisher and never
    /// cached across one.
    ///
    /// **CIRISEdge#217.** `async` as of v37.1.0 (the two persist verbs
    /// are async), so the lock discipline is now load-bearing rather than
    /// incidental: no guard is held across any `.await` here or in
    /// [`HoldingsScopeGate::admits`]. The only lock taken is inside
    /// [`ScopeAddressTable::send_address`], which runs after every await
    /// and releases within its own statement; the metrics booking below
    /// happens after the gate has fully returned.
    pub async fn admit_and_book(
        &self,
        publisher_key_id: &str,
        content_id: &str,
        content: Option<&ContentScope>,
        peer_key_id: &str,
    ) -> HoldingAnnounce {
        let verdict = self
            .gate
            .admits(publisher_key_id, content, peer_key_id)
            .await;
        if let HoldingAnnounce::Withhold(refusal) = &verdict {
            if let Some(m) = self.metrics.as_ref() {
                m.inc_withhold(
                    refusal.withhold_reason(),
                    peer_key_id,
                    &withhold_detail(content_id),
                );
            }
            tracing::warn!(
                peer = %peer_key_id,
                content_id = %content_id,
                reason = refusal.reason_tag(),
                "swarm_runtime.publisher: holding WITHHELD — {refusal}",
            );
        }
        verdict
    }
}

/// The short, low-cardinality `detail` for a holdings withhold: the plane
/// tag plus a bounded content-id prefix. Mirrors the bridge's
/// `withhold_detail` (kind + 8-byte hash prefix) — the ring is an
/// attribution window, not a log sink, so its entries stay bounded in size
/// as well as in count.
fn withhold_detail(content_id: &str) -> String {
    let prefix: String = content_id.chars().take(16).collect();
    format!("fountain:{prefix}")
}

/// v18 — has the unarmed-gate staging WARN fired this process?
static HOLDINGS_SCOPE_GATE_UNARMED_WARNED: AtomicBool = AtomicBool::new(false);

/// v18 — say ONCE (per process) that the holdings scope gate is riding the
/// staged default-open state. The default itself is INTENTIONAL and must not
/// flip (production rides it; `unarmed_gate_announces_everything` pins it) —
/// this only makes the state legible, so "staged open" can never again be
/// mistaken for "armed and passing".
fn warn_holdings_scope_gate_unarmed() {
    if !HOLDINGS_SCOPE_GATE_UNARMED_WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            "fountain holdings scope gate UNARMED — scope-native addressing is not \
             installed, so this node rides the pre-#499 staged state: every held \
             content is announced to every cohort peer, with no scope filter. This \
             is the deliberate default; arming is an OPERATOR OPT-IN — install the \
             MLS ScopeAddressTable via EdgeBuilder::scope_native_addressing (the \
             CIRISVerify#259 ScopePrivacyDeriver is shipped). Warned once per process."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle_gate::test_support::{field_fixture, PIPELINE, PRESENTER};
    use crate::scope_addressing::StubDeriver;

    const ALICE: &str = "ed25519:alice";
    const BOB: &str = "ed25519:bob";
    const OUTSIDER: &str = "ed25519:mallory";

    /// The REAL trust root: `field_fixture` seeds `PIPELINE` with an
    /// accord-co-scrubbed `infra:attest` record admitted through persist's
    /// own role gate — no fixture backdoor — so
    /// `is_infra_attest_effective` (and therefore
    /// `holdings_authority`) resolves `AccordCoScrub` for it.
    /// `PRESENTER` is a plain node row and resolves `ProducerSteward`.
    /// Using persist's real predicate both ways is what makes the seam
    /// EXERCISED rather than asserted.
    async fn directory() -> Arc<dyn FederationDirectory> {
        let (backend, _bundle) = field_fixture().await;
        Arc::new(backend)
    }

    fn cohort(id: &str) -> CohortScope {
        CohortScope::Cohort {
            cohort_id: id.to_owned(),
        }
    }

    /// One family group `fam-1` and one community group `com-1`, each
    /// holding alice + bob. `mallory` is in NEITHER.
    fn table() -> Arc<ScopeAddressTable> {
        let t = ScopeAddressTable::new(Arc::new(StubDeriver));
        t.install_group(&CohortScope::Family, "fam-1", 1, &[0xA1; 32], &[ALICE, BOB])
            .expect("family install");
        t.install_group(
            &cohort("neighbourhood"),
            "com-1",
            1,
            &[0xB2; 32],
            &[ALICE, BOB],
        )
        .expect("community install");
        Arc::new(t)
    }

    /// Armed AND wired — a table plus the real directory.
    async fn armed() -> HoldingsScopeGate {
        HoldingsScopeGate::new(Some(table()), Some(directory().await))
    }

    fn family_content() -> ContentScope {
        ContentScope::Group {
            scope: CohortScope::Family,
            group_id: "fam-1".to_owned(),
        }
    }

    fn community_content() -> ContentScope {
        ContentScope::Group {
            scope: cohort("neighbourhood"),
            group_id: "com-1".to_owned(),
        }
    }

    // ─── The projection is persist's, and this reads the real table ───

    /// The load-bearing pin: what `Plane::FountainContent` projects for
    /// each scope token edge can produce. If persist re-decides a cell,
    /// this reds HERE rather than silently changing who learns what.
    #[test]
    fn persist_owns_the_fountain_content_projection() {
        use AuthorityClass::{AccordCoScrub, ProducerSteward};
        for authority in [ProducerSteward, AccordCoScrub] {
            assert_eq!(
                HoldingsScopeGate::projection_of(&CohortScope::SelfOnly, authority),
                Projection::SelfOwn,
                "self scope must be structurally invisible under {authority:?}",
            );
            assert_eq!(
                HoldingsScopeGate::projection_of(&CohortScope::Family, authority),
                Projection::SelfOwn,
                "family scope must be structurally invisible under {authority:?}",
            );
            assert_eq!(
                HoldingsScopeGate::projection_of(&cohort("neighbourhood"), authority),
                Projection::Cohort,
                "community scope relays over ITS OWN roster under {authority:?}",
            );
        }
        assert_eq!(
            HoldingsScopeGate::projection_of(&CohortScope::Public, ProducerSteward),
            Projection::Cohort,
            "federation scope under a PLAIN producer is the cohort relay",
        );
        assert_eq!(
            HoldingsScopeGate::projection_of(&CohortScope::Public, AccordCoScrub),
            Projection::Global,
            "federation scope under a TRUST ROOT reaches the whole federation — \
             the cell the #744 authority seam exists to reach",
        );
    }

    /// **Why the two halves are ONE change, as a checked fact.**
    ///
    /// On `Plane::FountainContent` the authority axis is read at exactly
    /// one scope — `federation`. Every other scope arm ignores it. That is
    /// what makes the seam and the recipient verb act on the SAME cell,
    /// and it is asserted here rather than claimed in a comment: if
    /// persist ever makes another scope authority-sensitive, this reds and
    /// the `admits` reasoning must be revisited.
    #[test]
    fn authority_is_read_only_at_federation_scope() {
        use AuthorityClass::{AccordCoScrub, ProducerSteward};
        for scope in [
            CohortScope::SelfOnly,
            CohortScope::Family,
            cohort("neighbourhood"),
        ] {
            assert_eq!(
                HoldingsScopeGate::projection_of(&scope, ProducerSteward),
                HoldingsScopeGate::projection_of(&scope, AccordCoScrub),
                "{scope:?} must be authority-INSENSITIVE on this plane",
            );
        }
        assert_ne!(
            HoldingsScopeGate::projection_of(&CohortScope::Public, ProducerSteward),
            HoldingsScopeGate::projection_of(&CohortScope::Public, AccordCoScrub),
            "federation scope is the ONE authority-sensitive cell — if this ever \
             stops being true, the seam has moved and `admits` must follow",
        );
    }

    /// The scope-token map is persist's lattice, not a literal table of
    /// edge's own — pinned against persist's consts.
    #[test]
    fn scope_tokens_come_from_persists_lattice() {
        assert_eq!(
            persist_scope_token(&CohortScope::Public),
            cohort_scope::FEDERATION
        );
        assert_eq!(
            persist_scope_token(&CohortScope::SelfOnly),
            cohort_scope::SELF
        );
        assert_eq!(
            persist_scope_token(&CohortScope::Family),
            cohort_scope::FAMILY
        );
        assert_eq!(persist_scope_token(&cohort("x")), cohort_scope::COMMUNITY);
    }

    // ─── Arming: the no-regression case ───────────────────────────────

    /// A node with NO address table announces everything, including
    /// content whose scope is unknown AND content that is family-scoped.
    /// This is the pre-#499 deployment and it must not change.
    ///
    /// v18 PIN — "no table ⇒ default-open" is INTENTIONAL, not an
    /// oversight: production rides this staged state, and arming is an
    /// operator OPT-IN (`EdgeBuilder::scope_native_addressing` installs the
    /// MLS table; the CIRISVerify#259 deriver is shipped). A future "fix"
    /// that flips this default fail-closed would dark every holding on
    /// every existing deployment. If you are here to flip it: that is the
    /// arming event, done by installing the table — not by editing the
    /// gate.
    #[tokio::test]
    async fn unarmed_gate_announces_everything() {
        let g = HoldingsScopeGate::new(None, None);
        assert!(!g.is_scope_native());
        for publisher in [PIPELINE, PRESENTER, "nobody-at-all"] {
            assert!(g.admits(publisher, None, OUTSIDER).await.is_announced());
            assert!(g
                .admits(publisher, Some(&ContentScope::Federation), OUTSIDER)
                .await
                .is_announced());
            assert!(g
                .admits(publisher, Some(&family_content()), OUTSIDER)
                .await
                .is_announced());
            assert!(g
                .admits(publisher, Some(&community_content()), OUTSIDER)
                .await
                .is_announced());
        }
    }

    /// The unarmed path must be byte-identical WITH a directory wired as
    /// without one: arming is table installation, and #744 must not have
    /// turned a directory into a second arming condition. If the early
    /// return were dropped, a directory-wired unarmed node would start
    /// consulting persist and a plain producer's federation content would
    /// go dark on a deployment that never opted in.
    #[tokio::test]
    async fn unarmed_path_is_identical_with_and_without_a_directory() {
        let dir = directory().await;
        let no_dir = HoldingsScopeGate::new(None, None);
        let with_dir = HoldingsScopeGate::new(None, Some(dir));
        for publisher in [PIPELINE, PRESENTER] {
            for content in [
                None,
                Some(ContentScope::Federation),
                Some(family_content()),
                Some(community_content()),
            ] {
                let a = no_dir.admits(publisher, content.as_ref(), OUTSIDER).await;
                let b = with_dir.admits(publisher, content.as_ref(), OUTSIDER).await;
                assert_eq!(a, HoldingAnnounce::Announce, "unarmed must announce");
                assert_eq!(a, b, "a directory must not arm the gate");
            }
        }
    }

    // ─── CIRISPersist#744: the two halves ─────────────────────────────

    /// **THE HALF-LANDING GUARD.** Both assertions live in ONE test on
    /// purpose: each catches a different half, so the test reds if either
    /// is reverted alone.
    ///
    /// - Revert the SEAM (hard-code `ProducerSteward` again) and the first
    ///   assertion reds: the trust root's federation corpus resolves
    ///   `Cohort`, which at a commons tier has no roster table, so the
    ///   verb answers `NoRosterForScope` and the canonical corpus goes
    ///   DARK.
    /// - Revert the VERB (restore `Global | Cohort => announce`) and the
    ///   second assertion reds: the plain producer's `Cohort` is admitted
    ///   as if it were `Global`, which is the widening the hand-map hid by
    ///   treating "everyone" and "the cohort" as one answer.
    ///
    /// A comment cannot catch either. This can.
    #[tokio::test]
    async fn neither_half_alone_is_safe() {
        let g = armed().await;

        // HALF 1 needs HALF 2 to be reached honestly.
        assert_eq!(
            g.admits(PIPELINE, Some(&ContentScope::Federation), OUTSIDER)
                .await,
            HoldingAnnounce::Announce,
            "a TRUST-ROOT publisher's federation corpus projects Global, which \
             persist resolves as Unbounded — every peer is in the set. If this \
             reds, the authority seam is gone and the verb is dark-failing the \
             canonical corpus it exists to carry",
        );

        // HALF 2 needs HALF 1 to be more than a widening.
        assert_eq!(
            g.admits(PRESENTER, Some(&ContentScope::Federation), OUTSIDER)
                .await,
            HoldingAnnounce::Withhold(HoldingRefusal::RecipientSetUnresolved {
                basis: "no_roster_for_scope",
            }),
            "a PLAIN producer's federation corpus projects Cohort, and persist \
             holds no roster table for a commons tier — 'I cannot judge', which \
             withholds. If this reds, the hand-rolled `Global | Cohort => \
             announce` is back and `Global`'s unboundedness is invisible again",
        );
    }

    /// The seam itself, exercised BOTH ways against persist's real
    /// predicate — a trust root and a non-trust root, resolved from rows
    /// admitted through persist's own gate.
    ///
    /// Distinct from the guard above: this pins the AUTHORITY resolution,
    /// so a mutation that resolves `AccordCoScrub` for everybody (the
    /// dangerous direction — a corpus conferring trust-root reach on
    /// itself) reds here even though it would leave the guard's first
    /// assertion green.
    #[tokio::test]
    async fn the_seam_resolves_both_classes_from_persists_own_state() {
        let dir = directory().await;
        assert_eq!(
            holdings_authority(dir.as_ref(), PIPELINE).await.unwrap(),
            AuthorityClass::AccordCoScrub,
            "an accord-co-scrubbed infra:attest pipeline IS a trust root",
        );
        assert_eq!(
            holdings_authority(dir.as_ref(), PRESENTER).await.unwrap(),
            AuthorityClass::ProducerSteward,
            "a plain node row must NOT resolve the class it could never \
             self-declare",
        );
        assert_eq!(
            holdings_authority(dir.as_ref(), "never-registered")
                .await
                .unwrap(),
            AuthorityClass::ProducerSteward,
            "an unknown publisher takes the negative default, which never \
             widens a cell",
        );
    }

    /// `set_resolvable == false` is *"I cannot judge"* and MUST book its
    /// own reason, never the peer-not-in-set one. Reading `peer_in_set`
    /// alone would report an admission of ignorance as an accusation.
    #[tokio::test]
    async fn cannot_judge_is_not_the_same_refusal_as_peer_not_in_set() {
        let g = armed().await;

        // Cannot judge: a commons tier has no roster table at all.
        let cannot_judge = g
            .admits(PRESENTER, Some(&ContentScope::Federation), OUTSIDER)
            .await;
        // Judged, and the peer is genuinely outside the resolved set.
        let not_seated = g.admits(PRESENTER, Some(&family_content()), OUTSIDER).await;

        assert!(!cannot_judge.is_announced() && !not_seated.is_announced());
        let (HoldingAnnounce::Withhold(a), HoldingAnnounce::Withhold(b)) =
            (&cannot_judge, &not_seated)
        else {
            unreachable!("both must be withholds")
        };
        assert_ne!(
            a.withhold_reason(),
            b.withhold_reason(),
            "collapsing set_resolvable into peer_in_set reports 'I cannot \
             judge' as 'you are not seated' — persist splits the struct \
             precisely to stop that",
        );
        assert_eq!(
            a.withhold_reason(),
            WithholdReason::HoldingScopeRecipientSetUnresolved
        );
        assert_eq!(
            b.withhold_reason(),
            WithholdReason::HoldingScopePeerNotInRoster
        );
    }

    /// The federation branch passes an EMPTY `group_key_id` because
    /// persist provably never reads it there — `Global` returns
    /// `Unbounded` and `Cohort` at a commons tier returns
    /// `NoRosterForScope`, both before any roster leg. Pinned against
    /// persist directly: if a future persist starts reading it, this reds
    /// rather than the gate silently asking about a group named "".
    #[tokio::test]
    async fn federation_branch_never_reads_the_group_key_id() {
        let dir = directory().await;
        for authority in [
            AuthorityClass::AccordCoScrub,
            AuthorityClass::ProducerSteward,
        ] {
            let mut seen = Vec::new();
            for group in ["", "fam-1", "cohort:neighbourhood", "utter-nonsense"] {
                seen.push(
                    resolve_projection_recipients(
                        dir.as_ref(),
                        Plane::FountainContent,
                        cohort_scope::FEDERATION,
                        authority,
                        false,
                        group,
                        OUTSIDER,
                    )
                    .await
                    .unwrap(),
                );
            }
            assert!(
                seen.windows(2).all(|w| w[0] == w[1]),
                "federation-scope verdicts must not vary with group_key_id \
                 under {authority:?}, got {seen:?}",
            );
        }
    }

    /// An ARMED node with no directory cannot ask either verb, and must
    /// say so — NOT fall back to the pre-#744 hard-coded authority, which
    /// would restore the defect invisibly.
    #[tokio::test]
    async fn armed_without_a_directory_fails_closed_and_names_the_wiring() {
        let g = HoldingsScopeGate::new(Some(table()), None);
        assert!(g.is_scope_native());
        assert_eq!(
            g.admits(PIPELINE, Some(&ContentScope::Federation), BOB)
                .await,
            HoldingAnnounce::Withhold(HoldingRefusal::DirectoryMissing),
            "a trust root's corpus must NOT be announced on an unwired node \
             just because the old const would have admitted it",
        );
        // …and a family member is refused for the WIRING, not for the roster.
        assert_eq!(
            g.admits(PIPELINE, Some(&family_content()), BOB).await,
            HoldingAnnounce::Withhold(HoldingRefusal::DirectoryMissing),
        );
    }

    // ─── Armed: the leak closes, and only where it should ─────────────

    /// THE test: a family-scoped holding is withheld from a peer outside
    /// the family, AND a federation-scoped one to the SAME peer still
    /// goes — so this cannot pass by announcing nothing.
    #[tokio::test]
    async fn family_holding_withheld_from_outsider_while_federation_still_flows() {
        let g = armed().await;
        assert_eq!(
            g.admits(PIPELINE, Some(&family_content()), OUTSIDER).await,
            HoldingAnnounce::Withhold(HoldingRefusal::PeerNotInRoster {
                content_kind: "family",
                projection: "self_own",
            }),
        );
        assert!(
            g.admits(PIPELINE, Some(&ContentScope::Federation), OUTSIDER)
                .await
                .is_announced(),
            "a federation-scoped holding must still reach the same peer — \
             otherwise this suite passes by broadcasting nothing. Note the \
             publisher must now be a TRUST ROOT for this to hold: under a \
             plain producer persist projects Cohort at a commons tier and \
             withholds (CIRISPersist#744)",
        );
        // …and the family member still learns of it.
        assert!(
            g.admits(PIPELINE, Some(&family_content()), BOB)
                .await
                .is_announced(),
            "a family MEMBER must still be told; withholding from everyone \
             is not the fix",
        );
    }

    /// The community half of the same leak: persist projects `Cohort`,
    /// which persist defines as "the members of ITS roster" — not every
    /// peer the publisher happens to hold.
    #[tokio::test]
    async fn community_holding_withheld_from_non_member() {
        let g = armed().await;
        assert_eq!(
            g.admits(PIPELINE, Some(&community_content()), OUTSIDER)
                .await,
            HoldingAnnounce::Withhold(HoldingRefusal::PeerNotInRoster {
                content_kind: "cohort",
                projection: "cohort",
            }),
        );
        assert!(g
            .admits(PIPELINE, Some(&community_content()), ALICE)
            .await
            .is_announced());
    }

    /// Possession of the FAMILY roster says nothing about the COMMUNITY
    /// one and vice versa: membership is resolved per (scope, group), so a
    /// member of one group is not admitted to another group's holdings.
    #[tokio::test]
    async fn membership_does_not_cross_groups() {
        let t = ScopeAddressTable::new(Arc::new(StubDeriver));
        t.install_group(&CohortScope::Family, "fam-1", 1, &[0xA1; 32], &[ALICE])
            .expect("family install");
        t.install_group(&cohort("neighbourhood"), "com-1", 1, &[0xB2; 32], &[BOB])
            .expect("community install");
        let g = HoldingsScopeGate::new(Some(Arc::new(t)), Some(directory().await));
        // alice is family-only, bob is community-only.
        assert!(g
            .admits(PIPELINE, Some(&family_content()), ALICE)
            .await
            .is_announced());
        assert!(!g
            .admits(PIPELINE, Some(&family_content()), BOB)
            .await
            .is_announced());
        assert!(g
            .admits(PIPELINE, Some(&community_content()), BOB)
            .await
            .is_announced());
        assert!(!g
            .admits(PIPELINE, Some(&community_content()), ALICE)
            .await
            .is_announced());
    }

    /// Unknown scope on a scope-native node is refused, with the branch's
    /// own named reason — never read as public.
    #[tokio::test]
    async fn unknown_scope_is_refused_not_defaulted_public() {
        let g = armed().await;
        assert_eq!(
            g.admits(PIPELINE, None, BOB).await,
            HoldingAnnounce::Withhold(HoldingRefusal::ScopeUndeterminable),
        );
        assert_eq!(
            HoldingRefusal::ScopeUndeterminable.withhold_reason(),
            WithholdReason::HoldingScopeUndeterminable,
        );
    }

    /// A group declared at Public scope is a contradiction, refused before
    /// any roster lookup — and NOT folded into `PeerNotInRoster`.
    #[tokio::test]
    async fn group_at_public_scope_is_its_own_refusal() {
        let g = armed().await;
        let bogus = ContentScope::Group {
            scope: CohortScope::Public,
            group_id: "fam-1".to_owned(),
        };
        assert_eq!(
            g.admits(PIPELINE, Some(&bogus), ALICE).await,
            HoldingAnnounce::Withhold(HoldingRefusal::PublicIsNotScoped),
        );
        // A contradiction is a contradiction regardless of wiring: it is
        // refused BEFORE the directory is consulted, so an unwired node
        // still names the declaration rather than the missing directory.
        let unwired = HoldingsScopeGate::new(Some(table()), None);
        assert_eq!(
            unwired.admits(PIPELINE, Some(&bogus), ALICE).await,
            HoldingAnnounce::Withhold(HoldingRefusal::PublicIsNotScoped),
        );
    }

    /// A member excluded at a rotation seal loses the holding announcement
    /// — the roster is read live, not cached.
    #[tokio::test]
    async fn removed_member_stops_being_announced_to() {
        let t = ScopeAddressTable::new(Arc::new(StubDeriver));
        t.install_group(&CohortScope::Family, "fam-1", 1, &[0xA1; 32], &[ALICE, BOB])
            .expect("family install");
        let t = Arc::new(t);
        let g = HoldingsScopeGate::new(Some(Arc::clone(&t)), Some(directory().await));
        assert!(g
            .admits(PIPELINE, Some(&family_content()), BOB)
            .await
            .is_announced());
        t.remove_member(&CohortScope::Family, "fam-1", BOB);
        assert!(
            !g.admits(PIPELINE, Some(&family_content()), BOB)
                .await
                .is_announced(),
            "the roster must be read per-decision, never cached",
        );
    }

    /// Content naming a group the table has never heard of is withheld —
    /// fail-closed, not "no group means everyone".
    #[tokio::test]
    async fn unknown_group_is_withheld() {
        let g = armed().await;
        let ghost = ContentScope::Group {
            scope: CohortScope::Family,
            group_id: "fam-does-not-exist".to_owned(),
        };
        assert!(!g.admits(PIPELINE, Some(&ghost), ALICE).await.is_announced());
    }

    // ─── The refusal taxonomy is a taxonomy ───────────────────────────

    /// #433: one reason per branch. Every branch a distinct
    /// `WithholdReason` and a distinct label — including the four
    /// CIRISPersist#744 arms, and in particular `RecipientSetUnresolved`
    /// ("I cannot judge") never colliding with `PeerNotInRoster`
    /// ("judged, not seated").
    #[test]
    fn every_refusal_branch_has_its_own_named_reason() {
        let all = [
            HoldingRefusal::ScopeUndeterminable,
            HoldingRefusal::PublicIsNotScoped,
            HoldingRefusal::PeerNotInRoster {
                content_kind: "family",
                projection: "self_own",
            },
            HoldingRefusal::ProjectionUnsupported {
                projection: "subject",
            },
            HoldingRefusal::DirectoryMissing,
            HoldingRefusal::AuthorityUnresolved,
            HoldingRefusal::RecipientSetUnresolved {
                basis: "no_roster_for_scope",
            },
            HoldingRefusal::RecipientReadError,
        ];
        let tags: std::collections::BTreeSet<&str> =
            all.iter().map(HoldingRefusal::reason_tag).collect();
        assert_eq!(tags.len(), all.len(), "reason tags must not collide");
        let reasons: std::collections::BTreeSet<WithholdReason> =
            all.iter().map(HoldingRefusal::withhold_reason).collect();
        assert_eq!(
            reasons.len(),
            all.len(),
            "withhold reasons must not collide"
        );
        for r in &all {
            assert!(!r.to_string().is_empty(), "every refusal must say why");
        }
    }

    /// Persist's three "cannot judge" causes stay distinguishable in the
    /// booked record even though they share one `WithholdReason` — the
    /// basis tag is the payload, so an operator is still sent to the right
    /// place. Also pins that no basis tag collides.
    #[test]
    fn the_cannot_judge_bases_stay_distinguishable() {
        let tags: std::collections::BTreeSet<&str> = [
            RecipientBasis::OwnRoster,
            RecipientBasis::CohortRoster,
            RecipientBasis::Unbounded,
            RecipientBasis::NoRosterForScope,
            RecipientBasis::GroupUnresolvable,
            RecipientBasis::NotRosterKeyed,
        ]
        .into_iter()
        .map(basis_tag)
        .collect();
        assert_eq!(tags.len(), 6, "basis tags must not collide");
        assert!(
            HoldingRefusal::RecipientSetUnresolved {
                basis: "group_unresolvable",
            }
            .to_string()
            .contains("group_unresolvable"),
            "the cause persist named must reach the operator",
        );
    }

    /// Every `WithholdReason` this module can book is attributed to a CI
    /// parameter, and the two publisher-side arms are attributed to
    /// SENDER — not defaulted to Recipient. The gate cannot establish its
    /// own publisher's standing in those branches, which is a sender
    /// question even though it reads like infrastructure.
    #[test]
    fn holdings_refusals_are_attributed_to_the_right_ci_parameter() {
        use crate::contextual_integrity::{parameter_of, CiParameter};
        assert_eq!(
            parameter_of(WithholdReason::HoldingScopeAuthorityUnresolved),
            CiParameter::Sender,
        );
        assert_eq!(
            parameter_of(WithholdReason::HoldingScopeDirectoryMissing),
            CiParameter::Sender,
        );
        assert_eq!(
            parameter_of(WithholdReason::HoldingScopeRecipientSetUnresolved),
            CiParameter::Recipient,
        );
        assert_eq!(
            parameter_of(WithholdReason::HoldingScopeRecipientReadError),
            CiParameter::Recipient,
        );
    }

    // ─── Booking: a withhold is an event, not a non-event ─────────────

    /// `admit_and_book` books BEFORE returning, so an ignored return value
    /// still leaves a counted, attributed event.
    #[tokio::test]
    async fn withholds_are_booked_on_the_ledger() {
        let metrics = EdgeMetrics::default();
        let pg = HoldingsPublishGate::new(
            Some(table()),
            Some(directory().await),
            Some(metrics.clone()),
        );
        let _ = pg
            .admit_and_book(PIPELINE, "c-secret", Some(&family_content()), OUTSIDER)
            .await;
        let _ = pg
            .admit_and_book(PIPELINE, "c-unknown", None, OUTSIDER)
            .await;
        assert_eq!(
            metrics.withholds(WithholdReason::HoldingScopePeerNotInRoster),
            1
        );
        assert_eq!(
            metrics.withholds(WithholdReason::HoldingScopeUndeterminable),
            1
        );
        let snap = metrics.snapshot();
        assert!(
            snap.recent_withholds
                .iter()
                .any(|w| w.peer_key_id == OUTSIDER && w.detail.starts_with("fountain:")),
            "the attribution ring must name the peer and the content",
        );
    }

    /// An ANNOUNCE books nothing — the ledger must distinguish a
    /// withholding node from a working one.
    #[tokio::test]
    async fn announces_book_nothing() {
        let metrics = EdgeMetrics::default();
        let pg = HoldingsPublishGate::new(
            Some(table()),
            Some(directory().await),
            Some(metrics.clone()),
        );
        // A TRUST-ROOT publisher: federation content reaches everyone,
        // family content reaches the family member.
        let _ = pg
            .admit_and_book(PIPELINE, "c-pub", Some(&ContentScope::Federation), OUTSIDER)
            .await;
        let _ = pg
            .admit_and_book(PIPELINE, "c-fam", Some(&family_content()), BOB)
            .await;
        assert!(metrics.snapshot().withholds_by_reason.is_empty());
    }

    /// The detail string stays bounded regardless of content-id length.
    #[test]
    fn withhold_detail_is_bounded() {
        let long = "c".repeat(4096);
        let d = withhold_detail(&long);
        assert_eq!(d, format!("fountain:{}", "c".repeat(16)));
    }
}
