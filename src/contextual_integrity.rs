//! What was delivered, and why — in the vocabulary of the commitment
//! (<https://ciris.ai/contextual-integrity>).
//!
//! # Why this module exists
//!
//! Edge's design thesis is that **"the strongest flow rule is one the
//! network cannot express breaking"**, and its serve path already
//! enforces that: a record reaches a peer only after passing the
//! projection filter, the consent gate, the capability restriction, the
//! quarantine check, the accord relay gate, and — since CIRISEdge#499 —
//! the scope-address admission.
//!
//! Every one of those gates enforces a *specific* commitment. But that
//! attribution lived only in prose. A [`WithholdReason`] said what
//! mechanism refused; nothing said **which promise to the data subject
//! that mechanism keeps**. So "why was this withheld" could be answered
//! in edge's vocabulary and not in the vocabulary the commitment is
//! written in — which is the one an operator, an auditor, or a data
//! subject actually asks in.
//!
//! This module is that attribution, and it is **total by compile
//! error**.
//!
//! # Nissenbaum's five parameters, as edge's wire fields
//!
//! Contextual integrity defines privacy as **appropriate flow**, and a
//! violation as a breach of context-relative norms across five
//! parameters. Edge maps each onto a signed wire field:
//!
//! | parameter | edge's field |
//! |---|---|
//! | data subject | `subject_key_ids` |
//! | sender | `attesting_key_id` |
//! | recipient | `cohort_scope` · `subject_key_ids` · `delivery_mode` |
//! | information type | `dimension` |
//! | transmission principle | `consent:scope` |
//!
//! [`CiParameter`] is those five. [`parameter_of`] says which one each
//! refusal defends.
//!
//! # The guard, and why it is a compile error
//!
//! [`parameter_of`] matches [`WithholdReason`] **exhaustively, with no
//! wildcard**. `WithholdReason` is edge's own enum and is not
//! `#[non_exhaustive]`, so adding a gate without saying which commitment
//! it serves **fails the build**.
//!
//! That is deliberate, and it is the strongest form available here.
//! Edge could not get this guard for persist's `AttestationFamily` —
//! that enum is `#[non_exhaustive]`, so a downstream match must carry a
//! wildcard and can never be exhaustive (see [`crate::family_gates`],
//! which falls back to a loud-and-restrictive wildcard instead). Here
//! the enum is edge's, so the compiler can hold the invariant directly:
//! **a new way to withhold cannot enter this codebase anonymously.**
//!
//! # Both directions of a flow, and the one gap that remains
//!
//! Edge refuses in three places, and they are not the same thing:
//!
//! - **Serve / emit** refusals go through [`WithholdReason`] and
//!   `EdgeMetrics::inc_withhold` — a counted, attributed ledger.
//!   [`parameter_of`] maps it.
//! - **Accept / store** refusals go through
//!   [`StoreRefusal`](crate::blob_swarm::StoreRefusal) and
//!   [`MeaningRefusal`](crate::blob_swarm::MeaningRefusal) — edge
//!   declining to take content IN. [`parameter_of_store_refusal`] and
//!   [`parameter_of_meaning_refusal`] map those, each exhaustive and
//!   wildcard-free over an enum that is edge's own, so the same compile
//!   error holds: **a new way to refuse content cannot enter this
//!   codebase anonymously either.**
//! - **Inbound / transport** drops go through
//!   `ReticulumTransport::drop_inbound` — a throttled WARN with a string
//!   reason tag (CIRISEdge#425). It is log-only, carries no typed
//!   reason, and is therefore **still not attributed here.**
//!
//! # Why the accept side is the same five parameters
//!
//! It reads at first like a different question — the serve side asks
//! *may I send this*, the accept side *may I hold this* — and the
//! temptation is a second vocabulary for it. There isn't one. Appropriate
//! flow is a property of the FLOW, and both ends evaluate the same five
//! parameters from their own position:
//!
//! | axis | the accept-side question | parameter |
//! |---|---|---|
//! | meaning | what IS this, and who says so | Information type · Sender |
//! | 1 provenance | may this sender place content of this kind here | Sender |
//! | 2 scope | are we in the audience it declares | Recipient |
//! | 3 consent | did this operator agree to hold this class at all | Transmission principle |
//!
//! Axis 3 is the one worth naming: an operator declining to hold a class
//! of content is not a statement about the sender or the audience, it is
//! this node's own **rule of carriage** — the retain-with-limits
//! parameter, the same one the LXMF propagation terms land on below. A
//! node that had no way to say "not on my disk" would be enforcing
//! everybody's norms except its own.
//!
//! # Where the darknet half lands
//!
//! The `self` and `family` scopes are the derived group plane (CC 5.4.6):
//! persist suppresses `holds_bytes` for them structurally, so holding
//! that content publishes nothing. That is why
//! [`StoreAdmission::StoreLocalOnly`](crate::blob_swarm::StoreAdmission)
//! exists as a distinct verdict rather than a flag — *accept* and
//! *announce* are two different flows, with two different recipients, and
//! collapsing them is exactly how "can hold" quietly becomes "does
//! advertise".
//!
//! # What this module is NOT
//!
//! It makes **no decisions**. Every verdict is still the gate's; this
//! only names, after the fact, which commitment a verdict served.
//! Re-deriving any gate's rule here would be a second implementation of
//! it — the precise defect class this repo has spent the last several
//! releases removing.

use crate::blob_swarm::{MeaningRefusal, StoreRefusal};
use crate::observability::WithholdReason;

/// One of the five parameters an information-flow norm is defined over
/// (Nissenbaum; <https://ciris.ai/contextual-integrity>).
///
/// A flow is *appropriate* when it conforms on all five. A refusal is
/// edge declining to participate in a flow that would not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CiParameter {
    /// **Data subject** — who the claim is about. Edge's
    /// `subject_key_ids`, which puts revocation at the wire level
    /// rather than the application layer.
    DataSubject,
    /// **Sender** — who originated the claim. Edge's
    /// `attesting_key_id`: every flow has a named, cryptographic
    /// source, and a frame edge cannot attribute is dropped before any
    /// handler sees it.
    Sender,
    /// **Recipient** — who may receive. Edge keeps three axes distinct
    /// on purpose: `cohort_scope` (visibility), `subject_key_ids`
    /// (revocation authority) and `delivery_mode` (active receipt).
    /// Collapsing them is how "can see" quietly becomes "will be sent".
    Recipient,
    /// **Information type** — what is being claimed. Edge's `dimension`
    /// namespace, whose prefixes carry objective, machine-checkable
    /// admission tests rather than a human category.
    InformationType,
    /// **Transmission principle** — the rule the flow must follow:
    /// retain, share, analyze, train, publish, with limits. Edge's
    /// `consent:scope`, as a signed and revocable wire commitment.
    /// CIRIS calls this the decisive differentiator, because it is the
    /// parameter most systems leave in prose.
    TransmissionPrinciple,
}

impl CiParameter {
    /// A stable token, for logs and metrics.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DataSubject => "data_subject",
            Self::Sender => "sender",
            Self::Recipient => "recipient",
            Self::InformationType => "information_type",
            Self::TransmissionPrinciple => "transmission_principle",
        }
    }

    /// The commitment, in the words an operator or data subject would
    /// use — not edge's mechanism vocabulary.
    #[must_use]
    pub fn commitment(self) -> &'static str {
        match self {
            Self::DataSubject => "a claim about you carries your revocation authority on the wire",
            Self::Sender => "every claim has a named cryptographic source",
            Self::Recipient => "a claim reaches only the context it was made in",
            Self::InformationType => "what is claimed is what the namespace admits",
            Self::TransmissionPrinciple => "the flow follows the rule its consent grant names",
        }
    }
}

/// Which commitment this refusal defends.
///
/// **Exhaustive, no wildcard, on purpose.** Adding a [`WithholdReason`]
/// without attributing it here does not compile. See the module docs.
#[must_use]
// The arms are grouped by REASONING, not by value: three separate groups
// map to `Recipient` because they defend it for three different reasons
// (the consent-resolved send set, CC 4.2.1 accord carriage, and #499
// scope-address admission), and each carries the comment that says which.
// Collapsing them into one arm would satisfy the lint by deleting exactly
// the attribution this module exists to record. The allow sits directly on
// the function so nothing can be inserted between it and its target
// (a displacement that has bitten this repo before).
#[allow(clippy::match_same_arms)]
pub fn parameter_of(reason: WithholdReason) -> CiParameter {
    match reason {
        // ── Recipient ───────────────────────────────────────────────
        // The scope/consent-resolved send set IS the recipient axis:
        // these are edge declining to move a claim outside the context
        // it was made in.
        WithholdReason::SendSetUnresolved
        | WithholdReason::RecipientNotInSendSet
        | WithholdReason::ConfigPaused => CiParameter::Recipient,

        // CC 4.2.1 — "a node that never trusted the accord is simply
        // not reached". Carriage narrowed to the accord's own roster is
        // a recipient bound, not an information-type one: the dimension
        // is admitted, the audience is not.
        WithholdReason::AccordRelayRosterUnresolvable
        | WithholdReason::AccordRelaySignerNotSeated
        | WithholdReason::AccordRelayNoTrustEdge
        | WithholdReason::AccordRelayUnresolved
        | WithholdReason::AccordRelayObjectRootUnnamed
        | WithholdReason::AccordRelayObjectRootDisagrees => CiParameter::Recipient,

        // CIRISEdge#499 — arrival on a scope-derived address is the
        // recipient's *demonstration* of context membership, replacing
        // a directory claim about it. A peer that cannot demonstrate it
        // is outside the context.
        WithholdReason::BlobScopeUndeterminable
        | WithholdReason::BlobArrivalScopeInsufficient
        | WithholdReason::BlobArrivalGroupMismatch => CiParameter::Recipient,

        // CIRISEdge#499 (holdings plane) — "I hold this" is itself a
        // flow, and before this cut a family-scoped holding's content id
        // AND symbol ids were announced on a timer to every peer the
        // cohort callback returned. All of these defend the same
        // commitment — a claim reaches only the context it was made in —
        // and are separate variants rather than one because each sends
        // the operator somewhere different: fix the declaration, fix the
        // roster, or await a persist widening. Different remedies, same
        // promise.
        //
        // CIRISPersist#744 adds the two verdict-side arms. Both are the
        // RECIPIENT axis because they are persist answering "who may be
        // told", not a claim about the publisher: `RecipientSetUnresolved`
        // is persist declining to name the audience ("I cannot judge"),
        // and `RecipientReadError` is that same question left unanswered
        // by a fault. Neither is a statement about the peer — which is
        // exactly why they are not folded into `PeerNotInRoster` — but
        // both are edge refusing to move a claim it cannot bound to a
        // context, which is the recipient commitment.
        WithholdReason::HoldingScopeUndeterminable
        | WithholdReason::HoldingScopePublicGroup
        | WithholdReason::HoldingScopePeerNotInRoster
        | WithholdReason::HoldingScopeProjectionUnsupported
        | WithholdReason::HoldingScopeRecipientSetUnresolved
        | WithholdReason::HoldingScopeRecipientReadError => CiParameter::Recipient,

        // CIRISEdge#169 (LXMF propagation host) — serving as a propagation
        // node means moving someone ELSE's claim on their behalf, so the
        // recipient axis is where its two identity gates land. The mailbox
        // is indexed BY destination, which makes "you may read only your
        // own mail" structural rather than a filter; these two are what
        // that structure says out loud when it refuses. Off-roster is a
        // context this node does not carry into at all; a scope mismatch
        // is a requester reaching for a context that is not theirs.
        WithholdReason::LxmfDestinationNotServed | WithholdReason::LxmfMailboxScopeMismatch => {
            CiParameter::Recipient
        }

        // ── Transmission principle ──────────────────────────────────
        // The serve capability and the per-record restriction are the
        // grant's own terms: not "who may see" but "under what rule
        // this may move". `infra:serve` is the capability the grant
        // requires of a carrier; the restriction is the limit written
        // into the grant itself.
        WithholdReason::ServeCapabilityMissing
        | WithholdReason::ServeCapabilityReadError
        | WithholdReason::ServeCapabilityNotRooted
        | WithholdReason::RecipientCapabilityRestriction => CiParameter::TransmissionPrinciple,

        // CIRISEdge#169 — a propagation node's TERMS OF CARRIAGE. Each of
        // these is the node's published rule about how a flow may pass
        // through it, refusing a flow that does not meet it:
        //   * `LxmfPropagationDisabled` — this node does not carry
        //     third-party mail at all (the default posture).
        //   * `LxmfStampBelowCost` — the proof-of-work cost the node
        //     ANNOUNCES is the price of carriage; an unpaid upload has not
        //     met the offered rule.
        //   * `LxmfFrameOversized` / `LxmfMailboxFull` — the size and
        //     capacity ceilings the node commits to, refusing rather than
        //     silently growing to accommodate a stranger.
        //   * `LxmfRetentionExpired` — the bounded-retention promise
        //     itself: "held, but only this long". This is the parameter
        //     Nissenbaum describes as retain-with-limits, and it is the
        //     whole reason edge will not quietly become a mailbox.
        // None of these is a claim about WHO may receive — an on-roster
        // recipient whose mail expires was refused by the clock, not by
        // the audience.
        WithholdReason::LxmfPropagationDisabled
        | WithholdReason::LxmfStampBelowCost
        | WithholdReason::LxmfFrameOversized
        | WithholdReason::LxmfMailboxFull
        | WithholdReason::LxmfRetentionExpired => CiParameter::TransmissionPrinciple,

        // ── Sender ──────────────────────────────────────────────────
        // Every flow must have a named, rooted, non-quarantined source.
        // A trust-root walk failure is "I cannot establish who this is
        // from", which is a sender question even though it reads like
        // infrastructure.
        WithholdReason::LocalIdentityMissing
        | WithholdReason::TrustRootWalkError
        | WithholdReason::QuarantinedAuthor
        | WithholdReason::QuarantineReadError => CiParameter::Sender,

        // CIRISPersist#744 (holdings plane) — the two PUBLISHER-side
        // arms, and they are Sender for the reason the group above
        // states rather than Recipient by default.
        //
        // `HoldingScopeAuthorityUnresolved` IS a trust-root walk failure:
        // `holdings_authority` is `is_canonical_effective ||
        // is_infra_attest_effective` over the publisher's key. It is the
        // same question as `TrustRootWalkError` asked on the holdings
        // plane — "I cannot establish who this is from" — so it takes the
        // same attribution. Filing it under Recipient would say edge
        // declined to reach a peer, when what actually happened is that
        // edge could not establish its own publisher's standing.
        //
        // `HoldingScopeDirectoryMissing` is the wiring twin, and it sits
        // here for the reason `LocalIdentityMissing` does: with no
        // directory there is no verified state in which the publisher's
        // authority class exists to be resolved. That call is also
        // strictly first — the recipient verb TAKES the authority as an
        // input — so the parameter that fails first is the sender's.
        WithholdReason::HoldingScopeAuthorityUnresolved
        | WithholdReason::HoldingScopeDirectoryMissing => CiParameter::Sender,

        // The row is not the type it claims, or its signed mirror does
        // not bind its columns — so the named source is not established
        // for the bytes on offer.
        WithholdReason::AccordRelayObjectUnreadable | WithholdReason::AccordRelayMirrorUnbound => {
            CiParameter::Sender
        }

        // CIRISEdge#169 — a `/get` on a link whose remote identity edge
        // could not resolve. Deliberately NOT `Recipient`, though it is a
        // request to receive: what actually failed is attribution, and
        // this is the same commitment the E3 unattributed-frame drop
        // keeps — a frame edge cannot attribute gets no service. Reading
        // it as a recipient gate would misfile the remedy (identify the
        // link, not amend the roster).
        WithholdReason::LxmfRequesterUnidentified => CiParameter::Sender,

        // ── Information type ────────────────────────────────────────
        // Persist's classifier says this row is not on the family the
        // gate exists for — a claim about WHAT this is, not who may
        // have it.
        WithholdReason::AccordRelayObjectNotAccord => CiParameter::InformationType,

        // CIRISEdge#169 — "these bytes are not what this endpoint
        // admits". `LxmfWireUnparseable` is malformed input;
        // `LxmfPeerSyncUnsupported` is the crate's own distinction —
        // a well-formed MULTI-message upload is the node-to-node
        // `/offer` sync form, i.e. a message for an endpoint edge does
        // not serve (leviculum#209), not a broken one. Two variants
        // because the operator goes somewhere different for each, one
        // parameter because both answer WHAT rather than WHO.
        WithholdReason::LxmfWireUnparseable | WithholdReason::LxmfPeerSyncUnsupported => {
            CiParameter::InformationType
        }

        // ── Data subject ────────────────────────────────────────────
        // A record edge cannot fetch, serialize or hash cannot have its
        // subject's revocation authority honoured on the wire, because
        // the fields that carry it are unreadable. Fail closed rather
        // than move bytes whose subject bindings we cannot read.
        WithholdReason::EnvelopeUnfetchable
        | WithholdReason::RowNotSerializable
        | WithholdReason::RowHashUndecodable => CiParameter::DataSubject,
    }
}

/// Which commitment a **meaning** refusal defends — the invariant that a
/// blob with no signed attestation saying what it is, is an invalid state.
///
/// **Exhaustive, no wildcard, on purpose.** [`MeaningRefusal`] is edge's own
/// enum and is not `#[non_exhaustive]`, so a new way to refuse meaning
/// without attributing it here does not compile.
#[must_use]
pub fn parameter_of_meaning_refusal(refusal: &MeaningRefusal) -> CiParameter {
    match refusal {
        // ── Sender ──────────────────────────────────────────────────
        // "Every claim has a named cryptographic source." A row with an
        // empty signature column, or a signature naming nobody, is a claim
        // with no source — the same commitment the E3 unattributed-frame
        // drop keeps, asked of a row instead of a frame.
        MeaningRefusal::Unsigned => CiParameter::Sender,

        // ── Information type ────────────────────────────────────────
        // Both of these are edge saying "nothing here tells me WHAT these
        // bytes are", which is the information-type parameter and not the
        // recipient one — and the distinction decides the remedy. A
        // `holds_bytes` row is a well-formed, signed, correctly-scoped
        // claim; what it claims is POSSESSION. Reading it as an
        // information type would classify every blob on the node as
        // commons content, because that is the cohort its column carries.
        //
        // `DoesNotReference` is the same gap from the other side: a row
        // that states an information type, for other bytes.
        MeaningRefusal::PossessionIsNotMeaning | MeaningRefusal::DoesNotReference { .. } => {
            CiParameter::InformationType
        }

        // ── Recipient ───────────────────────────────────────────────
        // `cohort_scope` IS the recipient axis. A scope token edge cannot
        // map, and a scoped row that names no group, are both audiences
        // edge cannot bound — and an unbounded audience is the one thing
        // a recipient gate must never default. Two variants because the
        // remedies differ (teach edge the scope vs. fix the producer),
        // one parameter because both leave the same question unanswered.
        MeaningRefusal::UnknownScope { .. } | MeaningRefusal::GroupWithoutId { .. } => {
            CiParameter::Recipient
        }
    }
}

/// Which commitment a **store** refusal defends — the accept side of the
/// same five parameters.
///
/// **Exhaustive, no wildcard, on purpose**, for the reason
/// [`parameter_of`] is: [`StoreRefusal`] is edge's own enum, so the
/// compiler holds the invariant that a new store-gate refusal cannot enter
/// anonymously.
#[must_use]
// Grouped by REASONING, not by value — see the note on `parameter_of`.
#[allow(clippy::match_same_arms)]
pub fn parameter_of_store_refusal(refusal: &StoreRefusal) -> CiParameter {
    match refusal {
        // ── Information type ────────────────────────────────────────
        // Pre-axis. The caller named no [`BlobMeaning`] at all, so edge
        // has no statement of what the bytes are — and every other axis
        // takes that as an input.
        //
        // Filed under information type rather than recipient, though the
        // variant is spelled "scope": the projection refuses in order, and
        // signed / not-possession / references-this-blob all fail BEFORE
        // the scope is read. What is missing here is the row, not the
        // cohort on it.
        //
        // [`BlobMeaning`]: crate::blob_swarm::BlobMeaning
        StoreRefusal::ScopeUndeterminable => CiParameter::InformationType,

        // ── Sender ──────────────────────────────────────────────────
        // Axis 1. Norms are sender-indexed: a community's content may be
        // placed by its current members, commons content by the blessed
        // allowlist. A VERIFIED sender who is not an appropriate sender
        // for this content in this context fails the sender parameter —
        // which is the whole point of the axis, and the CIRISEdge#564
        // lesson stated in CI's vocabulary: verification establishes the
        // source, it does not establish that the source is appropriate.
        StoreRefusal::SenderNotApprovedForTier { .. }
        | StoreRefusal::SenderUndeterminable { .. } => CiParameter::Sender,

        // ── Recipient ───────────────────────────────────────────────
        // Axis 2, evaluated from the receiving end: WE are the recipient,
        // and the content names an audience we are not in (or one we
        // cannot resolve ourselves into). Accepting anyway would place a
        // claim outside the context it was made in — the same commitment
        // the serve side keeps by not sending it.
        StoreRefusal::NotInAudience { .. } | StoreRefusal::AudienceUndeterminable { .. } => {
            CiParameter::Recipient
        }

        // ── Transmission principle ──────────────────────────────────
        // Axis 3, and the only one no peer and no roster can overrule in
        // either direction. This is the node's own rule of carriage —
        // retain-with-limits, the parameter CIRIS calls the decisive
        // differentiator — and it is deliberately NOT a claim about the
        // sender or the audience: #581's own example is a blessed runner
        // whose content clears axes 1 and 2 and is still refused because
        // the operator never agreed to host public blobs.
        StoreRefusal::OperatorDeclined { .. } => CiParameter::TransmissionPrinciple,
    }
}

/// An **acceptance** decision, in commitment terms — the accept-side twin
/// of [`Delivery`].
///
/// Two verdicts rather than a bool for the same reason the store gate
/// returns a trichotomy: *hold* and *hold and announce* are different
/// flows with different recipients, and a value that collapsed them would
/// make the `self` / `family` scopes' structural invisibility (CC 5.4.6)
/// invisible to the audit trail too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acceptance {
    /// The bytes were accepted and a holder attestation was published.
    StoredAndAnnounced,
    /// The bytes were accepted and NOTHING was published about holding
    /// them.
    StoredSilently,
    /// Edge declined to take the content in. Carries the axis that
    /// refused AND the commitment that refusal defends.
    Refused {
        /// The gate that refused — edge's mechanism vocabulary.
        refusal: StoreRefusal,
        /// The commitment it defends.
        parameter: CiParameter,
    },
}

impl Acceptance {
    /// Build a refusal, attributing it automatically. There is no way to
    /// construct a `Refused` whose parameter disagrees with its refusal.
    #[must_use]
    pub fn refused(refusal: StoreRefusal) -> Self {
        let parameter = parameter_of_store_refusal(&refusal);
        Self::Refused { refusal, parameter }
    }

    /// Whether the bytes were accepted at all.
    #[must_use]
    pub fn accepted(&self) -> bool {
        matches!(self, Self::StoredAndAnnounced | Self::StoredSilently)
    }

    /// One line, in the commitment's vocabulary.
    #[must_use]
    pub fn explain(&self) -> String {
        match self {
            Self::StoredAndAnnounced => {
                "accepted and announced: the flow conformed on every evaluated parameter, and \
                 this node published that it holds the content"
                    .into()
            }
            Self::StoredSilently => {
                "accepted, unannounced: the flow conformed, and holding it publishes nothing — \
                 the scope suppresses the holder claim, or the operator consented to hold but \
                 not to advertise"
                    .into()
            }
            Self::Refused { refusal, parameter } => format!(
                "refused [{}] to keep the commitment that {} (axis {})",
                parameter.as_str(),
                parameter.commitment(),
                refusal.axis(),
            ),
        }
    }
}

/// A delivery decision, in commitment terms.
///
/// The value a serve path can hand an operator, an audit log, or a
/// downstream that must explain itself: **what happened, and which
/// promise it kept**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// The flow conformed on every parameter edge evaluates, and the
    /// record was offered.
    Delivered,
    /// Edge declined to participate. Carries the mechanism that refused
    /// AND the commitment that refusal defends, so the answer is
    /// legible in both vocabularies at once.
    Withheld {
        /// The gate that refused — edge's mechanism vocabulary.
        reason: WithholdReason,
        /// The commitment it defends — the vocabulary the promise is
        /// written in.
        parameter: CiParameter,
    },
}

impl Delivery {
    /// Build a refusal, attributing it automatically. There is no way
    /// to construct a `Withheld` whose parameter disagrees with its
    /// reason.
    #[must_use]
    pub fn withheld(reason: WithholdReason) -> Self {
        Self::Withheld {
            reason,
            parameter: parameter_of(reason),
        }
    }

    /// Whether the record was offered.
    #[must_use]
    pub fn delivered(self) -> bool {
        matches!(self, Self::Delivered)
    }

    /// One line, in the commitment's vocabulary — for an operator log
    /// or a subject-facing explanation.
    #[must_use]
    pub fn explain(self) -> String {
        match self {
            Self::Delivered => "delivered: the flow conformed on every evaluated parameter".into(),
            Self::Withheld { reason, parameter } => format!(
                "withheld [{}] to keep the commitment that {} (gate: {})",
                parameter.as_str(),
                parameter.commitment(),
                reason.as_str(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The accept side is attributed on the same five parameters, and a
    /// refusal cannot disagree with its own attribution.
    ///
    /// Totality is the compiler's (both enums are edge's own and neither
    /// is `#[non_exhaustive]`, so the wildcard-free matches must stay
    /// exhaustive). What this pins is that every axis is REACHABLE and
    /// that the mapping is the intended one — a match can be exhaustive
    /// and still send every arm to one parameter.
    #[test]
    fn the_accept_side_maps_each_axis_to_its_own_parameter() {
        let kind = "cohort";
        let cases = [
            (
                StoreRefusal::ScopeUndeterminable,
                CiParameter::InformationType,
                0u8,
            ),
            (
                StoreRefusal::SenderNotApprovedForTier {
                    content_kind: kind,
                    sender: crate::blob_swarm::SenderStanding::VerifiedOnly,
                },
                CiParameter::Sender,
                1,
            ),
            (
                StoreRefusal::SenderUndeterminable { content_kind: kind },
                CiParameter::Sender,
                1,
            ),
            (
                StoreRefusal::NotInAudience { content_kind: kind },
                CiParameter::Recipient,
                2,
            ),
            (
                StoreRefusal::AudienceUndeterminable { content_kind: kind },
                CiParameter::Recipient,
                2,
            ),
            (
                StoreRefusal::OperatorDeclined { content_kind: kind },
                CiParameter::TransmissionPrinciple,
                3,
            ),
        ];
        for (refusal, want, axis) in cases {
            assert_eq!(
                parameter_of_store_refusal(&refusal),
                want,
                "{refusal:?} must defend {want:?}",
            );
            assert_eq!(refusal.axis(), axis, "{refusal:?}");
            // The constructor cannot produce a disagreeing pair.
            match Acceptance::refused(refusal.clone()) {
                Acceptance::Refused { parameter, .. } => assert_eq!(parameter, want),
                other => panic!("a refusal must not read as accepted: {other:?}"),
            }
            assert!(!Acceptance::refused(refusal).accepted());
        }
    }

    /// The three axes must not collapse onto one parameter — if they did,
    /// the attribution would be decoration. Four distinct parameters
    /// across the accept side, including the pre-axis arm.
    #[test]
    fn the_accept_side_is_not_one_parameter_wearing_four_names() {
        let kind = "cohort";
        let mut seen: Vec<CiParameter> = [
            StoreRefusal::ScopeUndeterminable,
            StoreRefusal::SenderUndeterminable { content_kind: kind },
            StoreRefusal::NotInAudience { content_kind: kind },
            StoreRefusal::OperatorDeclined { content_kind: kind },
        ]
        .iter()
        .map(parameter_of_store_refusal)
        .collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 4, "the axes collapsed: {seen:?}");
    }

    /// A meaning refusal is attributed too, and the possession/meaning
    /// distinction lands on INFORMATION TYPE rather than recipient — the
    /// attribution that decides where an operator is sent.
    #[test]
    fn a_possession_claim_fails_the_information_type_parameter() {
        assert_eq!(
            parameter_of_meaning_refusal(&MeaningRefusal::PossessionIsNotMeaning),
            CiParameter::InformationType,
            "a holds_bytes row is well-formed, signed and correctly scoped; what \
             it does not carry is an information TYPE",
        );
        assert_eq!(
            parameter_of_meaning_refusal(&MeaningRefusal::Unsigned),
            CiParameter::Sender,
        );
        assert_eq!(
            parameter_of_meaning_refusal(&MeaningRefusal::UnknownScope {
                scope: "galactic".into()
            }),
            CiParameter::Recipient,
        );
        assert_eq!(
            parameter_of_meaning_refusal(&MeaningRefusal::GroupWithoutId {
                scope: "community".into()
            }),
            CiParameter::Recipient,
        );
        assert_eq!(
            parameter_of_meaning_refusal(&MeaningRefusal::DoesNotReference {
                sha256_hex: String::new()
            }),
            CiParameter::InformationType,
        );
    }

    /// `StoreLocalOnly` is a distinct verdict from `StoreAndAnnounce` in
    /// the explanation too — CC 5.4.6's derived group plane is only
    /// invisible if the audit trail says so as well.
    #[test]
    fn holding_and_announcing_explain_as_different_flows() {
        let held = Acceptance::StoredSilently.explain();
        let announced = Acceptance::StoredAndAnnounced.explain();
        assert!(held.contains("publishes nothing"), "{held}");
        assert!(announced.contains("published"), "{announced}");
        assert_ne!(held, announced);
        assert!(Acceptance::StoredSilently.accepted());
        assert!(Acceptance::StoredAndAnnounced.accepted());
    }

    /// Every refusal edge can produce is attributed. The compiler
    /// already guarantees totality — this pins that the mapping is
    /// *reachable* and self-consistent, and that `withheld` cannot
    /// disagree with `parameter_of`.
    #[test]
    fn every_withhold_reason_is_attributed_consistently() {
        for reason in ALL_REASONS {
            let d = Delivery::withheld(reason);
            let Delivery::Withheld { parameter, .. } = d else {
                panic!("withheld() must produce Withheld");
            };
            assert_eq!(
                parameter,
                parameter_of(reason),
                "{} attributed inconsistently",
                reason.as_str(),
            );
            assert!(!d.delivered());
            assert!(
                d.explain().contains(parameter.as_str()),
                "the explanation must name the commitment it kept",
            );
        }
    }

    /// The five parameters are all live — not four with one aspirational.
    /// If a parameter has no gate defending it, that is a hole in the
    /// enforcement, and it should be visible here rather than implied by
    /// the module's prose.
    #[test]
    fn all_five_parameters_have_at_least_one_gate_defending_them() {
        use std::collections::BTreeSet;
        let covered: BTreeSet<CiParameter> =
            ALL_REASONS.iter().copied().map(parameter_of).collect();
        for p in [
            CiParameter::DataSubject,
            CiParameter::Sender,
            CiParameter::Recipient,
            CiParameter::InformationType,
            CiParameter::TransmissionPrinciple,
        ] {
            assert!(
                covered.contains(&p),
                "no gate defends the {} parameter — the commitment is prose, not enforcement",
                p.as_str(),
            );
        }
    }

    /// The recipient axis carries the most gates, and that is expected
    /// rather than accidental: it is the parameter edge's transport
    /// layer is uniquely positioned to enforce, and the one CIRISEdge#499
    /// spent this release closing. Pinned so a future refactor that
    /// silently moves gates off it is visible.
    #[test]
    fn the_recipient_axis_is_the_most_defended() {
        let counts = |p: CiParameter| {
            ALL_REASONS
                .iter()
                .filter(|r| parameter_of(**r) == p)
                .count()
        };
        let recipient = counts(CiParameter::Recipient);
        for p in [
            CiParameter::DataSubject,
            CiParameter::Sender,
            CiParameter::InformationType,
            CiParameter::TransmissionPrinciple,
        ] {
            assert!(
                recipient > counts(p),
                "recipient ({recipient}) should out-gate {} ({})",
                p.as_str(),
                counts(p),
            );
        }
    }

    /// Every reason edge defines. Hand-listed because there is no
    /// `strum`-style iteration on the enum — but `parameter_of`'s
    /// exhaustive match is what actually guarantees totality, so a
    /// reason missing from THIS list weakens the tests, never the
    /// invariant.
    ///
    /// **It has already drifted once, and the mechanism is worth knowing.**
    /// Two agents added variants concurrently; the merge auto-resolved
    /// `contextual_integrity.rs` by taking one side's array, which had been
    /// written against a base predating the other side's four reasons. The
    /// enum had 44, this had 40, and it compiled — because a shorter literal
    /// with a matching length annotation is perfectly valid. `parameter_of`
    /// stayed exhaustive, so nothing was misattributed; the tests simply
    /// stopped covering four reasons, silently.
    ///
    /// So: when adding a reason, add it here too, and on a merge that touches
    /// this file check the count against the enum rather than trusting a
    /// green suite.
    const ALL_REASONS: [WithholdReason; 44] = [
        WithholdReason::EnvelopeUnfetchable,
        WithholdReason::LocalIdentityMissing,
        WithholdReason::SendSetUnresolved,
        WithholdReason::RecipientNotInSendSet,
        WithholdReason::ServeCapabilityMissing,
        WithholdReason::ServeCapabilityReadError,
        WithholdReason::ServeCapabilityNotRooted,
        WithholdReason::TrustRootWalkError,
        WithholdReason::RecipientCapabilityRestriction,
        WithholdReason::RowNotSerializable,
        WithholdReason::RowHashUndecodable,
        WithholdReason::ConfigPaused,
        WithholdReason::QuarantinedAuthor,
        WithholdReason::QuarantineReadError,
        WithholdReason::AccordRelayRosterUnresolvable,
        WithholdReason::AccordRelaySignerNotSeated,
        WithholdReason::AccordRelayNoTrustEdge,
        WithholdReason::AccordRelayUnresolved,
        WithholdReason::AccordRelayObjectUnreadable,
        WithholdReason::AccordRelayMirrorUnbound,
        WithholdReason::AccordRelayObjectNotAccord,
        WithholdReason::AccordRelayObjectRootUnnamed,
        WithholdReason::AccordRelayObjectRootDisagrees,
        WithholdReason::BlobScopeUndeterminable,
        WithholdReason::BlobArrivalScopeInsufficient,
        WithholdReason::BlobArrivalGroupMismatch,
        WithholdReason::HoldingScopeUndeterminable,
        WithholdReason::HoldingScopePublicGroup,
        WithholdReason::HoldingScopePeerNotInRoster,
        WithholdReason::HoldingScopeProjectionUnsupported,
        WithholdReason::LxmfPropagationDisabled,
        WithholdReason::LxmfDestinationNotServed,
        WithholdReason::LxmfRequesterUnidentified,
        WithholdReason::LxmfMailboxScopeMismatch,
        WithholdReason::LxmfStampBelowCost,
        WithholdReason::LxmfWireUnparseable,
        WithholdReason::LxmfPeerSyncUnsupported,
        WithholdReason::LxmfFrameOversized,
        WithholdReason::LxmfMailboxFull,
        WithholdReason::LxmfRetentionExpired,
        WithholdReason::HoldingScopeAuthorityUnresolved,
        WithholdReason::HoldingScopeDirectoryMissing,
        WithholdReason::HoldingScopeRecipientSetUnresolved,
        WithholdReason::HoldingScopeRecipientReadError,
    ];
}
