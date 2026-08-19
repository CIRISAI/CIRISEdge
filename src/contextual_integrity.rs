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
//! # What this module is NOT
//!
//! It makes **no decisions**. Every verdict is still the gate's; this
//! only names, after the fact, which commitment a verdict served.
//! Re-deriving any gate's rule here would be a second implementation of
//! it — the precise defect class this repo has spent the last several
//! releases removing.

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
        // cohort callback returned. All four defend the same commitment
        // — a claim reaches only the context it was made in — and are
        // four variants rather than one because each sends the operator
        // somewhere different: fix the wiring, fix the declaration, fix
        // the roster, or await a persist widening. Different remedies,
        // same promise.
        WithholdReason::HoldingScopeUndeterminable
        | WithholdReason::HoldingScopePublicGroup
        | WithholdReason::HoldingScopePeerNotInRoster
        | WithholdReason::HoldingScopeProjectionUnsupported => CiParameter::Recipient,

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
    const ALL_REASONS: [WithholdReason; 40] = [
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
    ];
}
