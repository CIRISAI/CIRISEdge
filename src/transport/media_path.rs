//! Why a call's media path failed: the `MediaPathFailed` / `MediaPathRestored`
//! call events, the NAT report they carry, and the ONE place the cause is
//! decided.
//!
//! # The ruling
//!
//! When a call cannot connect to a member, the person sees the real reason:
//! this node's NAT, the peer's NAT (as the peer claims it), and what was tried.
//! The canonical never relays call media, so there is no fallback, and the
//! event says so ([`RelayStanding::RefusedByPolicy`], always, on the LTS).
//!
//! # Edge decides the cause once
//!
//! [`media_path_verdict`] reads one struct, [`DirectPathFacts`]: everything edge
//! knows when a path attempt concludes. The server and the client render the
//! token; neither re-derives it. [`path_attempts`] builds the `tried` list from
//! the same facts, and [`legacy_class`] the RFC 3489 display word from the
//! RFC 4787 behaviours, so every derived field has exactly one source.
//!
//! # What this pin knows
//!
//! leviculum v0.34.0+ciris.3 reports a direct-link OUTCOME only (established,
//! or a [`AttemptFailure`]). No NAT measurement, no per-technique detail. So
//! on this pin every NAT field is `unknown` / [`NatEvidence::None`], and the
//! facts that wait on leviculum's punch diagnostics (its
//! `diag/punch-telemetry` line: the probe summary's mapping and allocation
//! evidence, the punch summary's knocks, sockets, first-heard time and
//! heard-not-acked count) are `None`. Each such field names the diagnostic that
//! will fill it.
//!
//! # No addresses
//!
//! Nothing here carries an address, a port or a peer identifier: behaviours,
//! counts, durations and tokens only. The member is named by the call event's
//! own `member`, as every other call event names one.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Declares a closed token set: a snake_case serde form, `token()`, `parse()`
/// and `ALL`, so the three cannot drift.
macro_rules! token_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident => $token:literal, )+
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $( $(#[$vmeta])* $variant, )+
        }

        impl $name {
            /// Every value, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The stable token (the serde form).
            #[must_use]
            pub const fn token(self) -> &'static str {
                match self {
                    $(Self::$variant => $token,)+
                }
            }

            /// The value of a token.
            #[must_use]
            pub fn parse(token: &str) -> Option<Self> {
                match token {
                    $($token => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

token_enum! {
    /// Why a call's media path to a member failed: decided once, by
    /// [`media_path_verdict`].
    pub enum MediaPathCause {
        /// Both NATs allocate ports at random: no port can be predicted on
        /// either side, so a punch has nothing to aim at.
        BothNatsRandom => "both_nats_random",
        /// The punch ran and nothing came back.
        PunchNoAnswer => "punch_no_answer",
        /// The punch got through one way only: one side heard the other and
        /// was not heard back.
        PunchOneWay => "punch_one_way",
        /// The attempt ended before either NAT's behaviour was known.
        NatUndetermined => "nat_undetermined",
        /// No facilitator: this node has none configured or resolved, or its
        /// facilitator did not answer its probe.
        NoFacilitator => "no_facilitator",
        /// The peer's policy refused the direct path (its REJECT `POLICY`).
        RefusedByPeerPolicy => "refused_by_peer_policy",
        /// The peer cannot take part (its REJECT `UNSUPPORTED`: on leviculum,
        /// its own facilitator probe failed, or it has none).
        PeerUnsupported => "peer_unsupported",
        /// The escalation budget refused the techniques the NATs needed.
        BudgetRefused => "budget_refused",
        /// This node does not trust the peer enough to reveal its public
        /// address or escalate toward it.
        NotTrusted => "not_trusted",
        /// None of the above (a transient refusal, a path lost on the way, the
        /// operator's switch).
        Other => "other",
    }
}

token_enum! {
    /// The internal branch [`media_path_verdict`] took: a closed list, so a
    /// `cause = other` (and every other cause) names exactly why. Never free
    /// text.
    pub enum PathDetail {
        /// The operator switched proposing off.
        ProposingOff => "proposing_off",
        /// No facilitator is configured or resolved.
        FacilitatorUnresolved => "facilitator_unresolved",
        /// The peer is not one this node reveals its address to.
        PeerUntrusted => "peer_untrusted",
        /// The punch's trust gate refused to escalate.
        EscalationGated => "escalation_gated",
        /// This node's facilitator did not answer its probe.
        ProbeFailed => "probe_failed",
        /// The peer REJECTed `UNSUPPORTED`.
        PeerRejectUnsupported => "peer_reject_unsupported",
        /// The peer REJECTed `POLICY`.
        PeerRejectPolicy => "peer_reject_policy",
        /// The punch failed and both NATs allocate at random.
        BothRandom => "both_random",
        /// The punch failed and the escalation allowance refused.
        EscalationBudget => "escalation_budget",
        /// The peer REJECTed `PUNCH_FAILED`: its side heard nothing.
        PeerPunchFailed => "peer_punch_failed",
        /// This node heard the peer and was never acked.
        HeardNotAcked => "heard_not_acked",
        /// The punch window passed with nothing heard.
        PunchSilent => "punch_silent",
        /// The peer stopped answering partway.
        PeerTimeout => "peer_timeout",
        /// The proposal had no outcome within the dial's budget.
        ProposalUnanswered => "proposal_unanswered",
        /// The peer REJECTed `BUSY`.
        PeerBusy => "peer_busy",
        /// The peer's own proposal won the tie on the link.
        Glare => "glare",
        /// The peer REJECTed `HOLDING`.
        PeerHolding => "peer_holding",
        /// The peer REJECTed with a reason this build does not know.
        PeerRejectUnknown => "peer_reject_unknown",
        /// The punched interface went down before the link moved.
        InterfaceLost => "interface_lost",
        /// The link waited on a transfer past leviculum's deadline.
        HeldTooLong => "held_too_long",
        /// The peer left the direct path while this node waited.
        PeerFellBack => "peer_fell_back",
        /// No identity link to the member could be had.
        NoLink => "no_link",
        /// The last proposal's backoff runs, with no failure on record.
        BackingOff => "backing_off",
        /// The peer initiated the link, so it proposes.
        Yielded => "yielded",
        /// leviculum refused to start the proposal.
        ProposeRefused => "propose_refused",
        /// A path stands (not a failure).
        PathStands => "path_stands",
    }
}

token_enum! {
    /// A path technique.
    pub enum PathKind {
        /// The two ends' host addresses on one network (behind one NAT).
        DirectLan => "direct_lan",
        /// Global IPv6 host addresses: no NAT, a stateful firewall at most.
        DirectIpv6 => "direct_ipv6",
        /// Each end's reflexive (public) address, as the facilitator saw it:
        /// the ordinary hole punch.
        DirectReflexive => "direct_reflexive",
        /// The ports the peer predicts its NAT will map next.
        PredictedPorts => "predicted_ports",
        /// Many sockets toward a random NAT, for a birthday collision.
        Birthday => "birthday",
        /// A mapping the router holds on request (PCP, NAT-PMP, UPnP).
        MappedPort => "mapped_port",
    }
}

token_enum! {
    /// How one technique ended.
    pub enum PathOutcome {
        /// A leg came up on it.
        Established => "established",
        /// It ran and nothing came back.
        NoAnswer => "no_answer",
        /// One side heard the other and was not heard back.
        OneWay => "one_way",
        /// The peer refused it.
        RefusedByPeer => "refused_by_peer",
        /// No facilitator answered, so it could not start.
        NoFacilitator => "no_facilitator",
        /// Not tried: nothing measured says it would help.
        NotTriedNoEvidence => "not_tried_no_evidence",
        /// Not tried: the peer is not trusted enough for it.
        NotTriedUntrusted => "not_tried_untrusted",
        /// Not tried: the escalation budget refused it.
        BudgetRefused => "budget_refused",
    }
}

token_enum! {
    /// RFC 4787 §4.1 — how a NAT maps an internal endpoint to external ones.
    pub enum NatMapping {
        /// No translation: the host's own address is its public one.
        None => "none",
        /// Endpoint-Independent Mapping (RFC 4787 §4.1).
        EndpointIndependent => "endpoint_independent",
        /// Address-Dependent Mapping (RFC 4787 §4.1).
        AddressDependent => "address_dependent",
        /// Address and Port-Dependent Mapping (RFC 4787 §4.1).
        AddressAndPortDependent => "address_and_port_dependent",
        /// Not measured.
        Unknown => "unknown",
    }
}

token_enum! {
    /// RFC 4787 §4.2.1 — how a NAT picks the external port of a new mapping.
    pub enum NatAllocation {
        /// Port preservation: the external port is the internal one.
        Preserving => "preserving",
        /// The next mapping's port follows the last by a fixed step.
        Sequential => "sequential",
        /// No pattern: nothing can be predicted.
        Random => "random",
        /// Not measured.
        Unknown => "unknown",
    }
}

token_enum! {
    /// RFC 4787 §5 — which inbound packets a NAT lets through a mapping.
    pub enum NatFiltering {
        /// Endpoint-Independent Filtering (RFC 4787 §5).
        EndpointIndependent => "endpoint_independent",
        /// Address-Dependent Filtering (RFC 4787 §5).
        AddressDependent => "address_dependent",
        /// Address and Port-Dependent Filtering (RFC 4787 §5).
        AddressAndPortDependent => "address_and_port_dependent",
        /// Not measured.
        Unknown => "unknown",
    }
}

token_enum! {
    /// Whether the router holds a mapping for this node on request.
    pub enum RouterMapping {
        /// Port Control Protocol (RFC 6887) granted one.
        HeldPcp => "held_pcp",
        /// NAT-PMP (RFC 6886) granted one.
        HeldNatPmp => "held_nat_pmp",
        /// UPnP IGD granted one.
        HeldUpnp => "held_upnp",
        /// Asked, and nothing granted one.
        None => "none",
        /// Never asked.
        NotTried => "not_tried",
    }
}

token_enum! {
    /// The address family the report was measured on.
    pub enum AddressFamily {
        /// IPv4.
        V4 => "v4",
        /// IPv6.
        V6 => "v6",
    }
}

token_enum! {
    /// On what evidence the report stands.
    pub enum NatEvidence {
        /// Two observers saw this node's mapping (RFC 5780 §4.3 style).
        TwoObserver => "two_observer",
        /// This node's own allocation probes, with no second observer.
        OwnEvidence => "own_evidence",
        /// Nothing measured: every behaviour is `unknown`.
        None => "none",
    }
}

token_enum! {
    /// The RFC 3489 §5 display word, DERIVED from mapping and filtering by
    /// [`legacy_class`] and nowhere else. RFC 4787 §3 retired these terms as
    /// a classification; they are kept because people know them.
    pub enum LegacyClass {
        /// No NAT.
        Open => "open",
        /// RFC 3489 full cone: EIM with EIF.
        FullCone => "full_cone",
        /// RFC 3489 restricted cone: EIM with ADF.
        Restricted => "restricted",
        /// RFC 3489 port-restricted cone: EIM with APDF.
        PortRestricted => "port_restricted",
        /// RFC 3489 symmetric: the mapping depends on the destination.
        Symmetric => "symmetric",
        /// Not enough measured to name one.
        Unknown => "unknown",
    }
}

token_enum! {
    /// Where a peer's NAT report came from.
    pub enum NatReportSource {
        /// The peer's own claim, unverified by this node.
        SelfReported => "self_reported",
    }
}

token_enum! {
    /// Whether a relay could carry the call's media instead.
    pub enum RelayStanding {
        /// The canonical never relays call media: refused by policy. Always
        /// this on the LTS.
        RefusedByPolicy => "refused_by_policy",
        /// Relaying is allowed, and no relay was available.
        NoneAvailable => "none_available",
    }
}

/// **THE derivation** of the RFC 3489 §5 display word from the RFC 4787
/// behaviours (mapping §4.1, filtering §5). One function: the report's
/// `legacy_class` is never set any other way.
///
/// | mapping | filtering | word |
/// |---|---|---|
/// | `none` | `endpoint_independent` / `unknown` | `open` |
/// | `none` | `address_dependent` | `restricted` |
/// | `none` | `address_and_port_dependent` | `port_restricted` |
/// | `endpoint_independent` | `endpoint_independent` | `full_cone` |
/// | `endpoint_independent` | `address_dependent` | `restricted` |
/// | `endpoint_independent` | `address_and_port_dependent` | `port_restricted` |
/// | `endpoint_independent` | `unknown` | `unknown` |
/// | `address_dependent` / `address_and_port_dependent` | any | `symmetric` |
/// | `unknown` | any | `unknown` |
///
/// - RFC 3489 §5 defines its cones as one mapping per internal endpoint (EIM,
///   RFC 4787 §4.1) told apart by filtering (RFC 4787 §5): full cone = EIF,
///   restricted = ADF, port restricted = APDF.
/// - RFC 3489's symmetric NAT maps per destination; RFC 4787 §4.1 notes that
///   covers both ADM and APDM, so either is `symmetric` whatever the filter.
/// - No NAT with a filtering firewall is RFC 3489 §10.1's "symmetric UDP
///   firewall", which has no word here; for a punch it behaves as the cone
///   with the same filtering (the mapping is the host's own address), so it
///   takes that cone's word. No NAT and no known filter is `open`.
#[must_use]
pub const fn legacy_class(mapping: NatMapping, filtering: NatFiltering) -> LegacyClass {
    match (mapping, filtering) {
        (NatMapping::None, NatFiltering::EndpointIndependent | NatFiltering::Unknown) => {
            LegacyClass::Open
        }
        (NatMapping::None | NatMapping::EndpointIndependent, NatFiltering::AddressDependent) => {
            LegacyClass::Restricted
        }
        (
            NatMapping::None | NatMapping::EndpointIndependent,
            NatFiltering::AddressAndPortDependent,
        ) => LegacyClass::PortRestricted,
        (NatMapping::EndpointIndependent, NatFiltering::EndpointIndependent) => {
            LegacyClass::FullCone
        }
        (NatMapping::AddressDependent | NatMapping::AddressAndPortDependent, _) => {
            LegacyClass::Symmetric
        }
        (NatMapping::EndpointIndependent | NatMapping::Unknown, _) => LegacyClass::Unknown,
    }
}

/// What this node knows of one NAT: behaviours only, never an address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatReport {
    /// RFC 4787 §4.1 mapping behaviour.
    pub mapping: NatMapping,
    /// RFC 4787 §4.2.1 port allocation.
    pub allocation: NatAllocation,
    /// RFC 4787 §5 filtering behaviour.
    pub filtering: NatFiltering,
    /// Whether the external port equalled the internal one; `None` unmeasured.
    pub port_preserving: Option<bool>,
    /// Whether the router holds a mapping on request.
    pub router_mapping: RouterMapping,
    /// The family the measurement ran on.
    pub family: AddressFamily,
    /// On what evidence.
    pub evidence: NatEvidence,
    /// [`legacy_class`] of `mapping` and `filtering`; set by
    /// [`NatReport::new`], never by hand.
    pub legacy_class: LegacyClass,
    /// When it was measured (UTC, millisecond precision; serialised as
    /// milliseconds since the Unix epoch).
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub measured_at: DateTime<Utc>,
}

impl NatReport {
    /// A report, its `legacy_class` derived.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mapping: NatMapping,
        allocation: NatAllocation,
        filtering: NatFiltering,
        port_preserving: Option<bool>,
        router_mapping: RouterMapping,
        family: AddressFamily,
        evidence: NatEvidence,
        measured_at: DateTime<Utc>,
    ) -> Self {
        Self {
            mapping,
            allocation,
            filtering,
            port_preserving,
            router_mapping,
            family,
            evidence,
            legacy_class: legacy_class(mapping, filtering),
            measured_at: truncate_ms(measured_at),
        }
    }

    /// Nothing measured, as of `at`: every behaviour `unknown`, evidence
    /// `none`, the router never asked. `family` is `v4`, the family edge's
    /// facilitator probe runs on; with evidence `none` it states no
    /// measurement.
    #[must_use]
    pub fn unknown(at: DateTime<Utc>) -> Self {
        Self::new(
            NatMapping::Unknown,
            NatAllocation::Unknown,
            NatFiltering::Unknown,
            None,
            RouterMapping::NotTried,
            AddressFamily::V4,
            NatEvidence::None,
            at,
        )
    }

    /// Whether anything was measured.
    #[must_use]
    pub fn measured(&self) -> bool {
        self.evidence != NatEvidence::None
    }
}

fn truncate_ms(at: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(at.timestamp_millis()).unwrap_or(at)
}

/// The peer's NAT, as the peer claims it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerNatReport {
    /// What it claims.
    pub report: NatReport,
    /// `self_reported`, always: this node never measured it.
    pub source: NatReportSource,
}

/// One technique tried (or not) toward a member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathAttempt {
    /// Which technique.
    pub kind: PathKind,
    /// How it ended.
    pub outcome: PathOutcome,
    /// How many times it ran toward this member (saturating).
    pub attempts: u8,
    /// How long the last run took, in milliseconds (saturating).
    pub elapsed_ms: u32,
    /// Knocks sent (0 when not counted on this pin).
    pub knocks_sent: u16,
    /// Sockets it held open (0 when it did not run).
    pub sockets: u16,
}

/// What a direct-path attempt came to, in edge's terms (leviculum's
/// `direct_link::Failure`, mirrored so this module needs no transport).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptFailure {
    /// The peer sent REJECT with this reason byte (leviculum's `REJECT_*`).
    Rejected(u8),
    /// This node's facilitator did not answer its probe.
    ProbeFailed,
    /// The peer stopped answering partway.
    Timeout,
    /// No punch frame got through in the punch window.
    PunchFailed,
    /// The peer's proposal won the tie on the same link.
    Glare,
    /// The punched interface went down before the link moved.
    InterfaceLost,
    /// The link waited on a transfer past leviculum's deadline.
    HeldTooLong,
    /// The peer left the direct path while this node waited.
    PeerFellBack,
}

/// leviculum's REJECT reasons, as its `direct_link::wire` names them.
pub mod reject {
    /// The responder's policy refused.
    pub const POLICY: u8 = 0x01;
    /// The responder has an upgrade running on the link.
    pub const BUSY: u8 = 0x02;
    /// The responder cannot take part (its facilitator probe failed).
    pub const UNSUPPORTED: u8 = 0x03;
    /// The responder's side of the punch failed (two-sided commit).
    pub const PUNCH_FAILED: u8 = 0x10;
    /// The link's initiator's own proposal stands.
    pub const GLARE: u8 = 0x11;
    /// The responder holds its move for a transfer.
    pub const HOLDING: u8 = 0x12;
}

/// Why no proposal ran this time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotProposed {
    /// No identity link to the member could be had.
    NoLink,
    /// The last proposal failed and its backoff runs, with no failure on
    /// record (the record is used instead when there is one).
    BackingOff,
    /// The peer initiated the link, so it proposes (glare tie-break).
    Yielded,
    /// leviculum refused to start the proposal (cooldown, busy channel).
    ProposeRefused,
}

/// What the attempt came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectAttempt {
    /// A direct path stands.
    Established,
    /// The member is a one-hop neighbour: nothing to punch.
    AlreadyNeighbour,
    /// No proposal ran.
    NotProposed(NotProposed),
    /// A proposal ended without a direct path.
    Failed(AttemptFailure),
    /// A proposal ran past the dial's budget with no outcome.
    NoOutcome,
}

impl DirectAttempt {
    /// Whether this is an attempt's conclusion (a proposal's own outcome, or
    /// a reason none can run), as opposed to a pass that tried nothing new.
    #[must_use]
    pub const fn conclusive(&self) -> bool {
        matches!(
            self,
            Self::Failed(_) | Self::Established | Self::AlreadyNeighbour
        )
    }
}

/// **Everything edge knows when a path attempt to one member concludes.** The
/// one input of [`media_path_verdict`] and [`path_attempts`]. Filled by the
/// transport at the dial
/// ([`crate::transport::reticulum::ReticulumTransport::open_av_link`]'s
/// direct-path step); every field marked "waits on leviculum" is `None` on
/// the v0.34.0+ciris.3 pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectPathFacts {
    /// The operator's switch: this node proposes at all.
    pub proposing: bool,
    /// A facilitator is resolved for this node's probe.
    pub facilitator_resolved: bool,
    /// The member is one this node may reveal its address to (a room peer or
    /// a consented contact, `direct_standing`).
    pub peer_trusted: bool,
    /// What the attempt came to (a backoff pass carries the failure that set
    /// the backoff).
    pub attempt: DirectAttempt,
    /// Proposals to this member that ended without a path, in a row.
    pub attempts: u32,
    /// How long this attempt took, the identity link and the outcome together.
    pub elapsed: Duration,
    /// This node's NAT. Waits on leviculum: the probe summary
    /// (`direct_link_diag` `event = "probe"`: `mapping`, `edm_evidence`,
    /// `alloc_step1`/`alloc_step2`, `port_preserved`, `no_nat`,
    /// `public_family`). Filtering waits on a filtering test leviculum does
    /// not run yet.
    pub local_nat: Option<NatReport>,
    /// The peer's NAT, as it claims it. Waits on leviculum: its REQUEST/READY
    /// signals (the diag line carries the peer's `birthday` flag and predicted
    /// ports there; a NatReport would ride beside them).
    pub peer_nat: Option<PeerNatReport>,
    /// The punch's policy gate let it escalate. Waits on leviculum: the punch
    /// summary's `escalation_allowed`.
    pub escalation_allowed: Option<bool>,
    /// The pair's escalation allowance granted it (`Some(false)`: the budget
    /// refused). Waits on leviculum: the punch summary's `escalation`.
    pub escalation_granted: Option<bool>,
    /// Knocks sent to predicted ports and the spray. Waits on leviculum: the
    /// punch summary's `knocks`.
    pub knocks_sent: Option<u32>,
    /// Sockets the punch held toward the peer: the session socket plus the
    /// birthday sockets. Waits on leviculum: the punch summary's
    /// `birthday_open`.
    pub sockets: Option<u32>,
    /// Predicted ports punched. Waits on leviculum: the punch summary's
    /// `predicted`.
    pub predicted_ports: Option<u32>,
    /// How long until the peer was first heard. Waits on leviculum: the punch
    /// summary's `first_heard_ms`.
    pub first_heard_ms: Option<u64>,
    /// The peer's punches were heard and this node's were never acked (the
    /// one-way signature). Waits on leviculum: the punch summary's
    /// `punches_heard` / `acks_heard`.
    pub heard_not_acked: Option<bool>,
    /// Global IPv6 host candidates were punched. Waits on leviculum: the punch
    /// summary's `host_v6`.
    pub ipv6_candidates: Option<bool>,
    /// Same-NAT IPv4 host candidates were punched. Waits on leviculum: the
    /// punch summary's `host_v4`.
    pub lan_candidates: Option<bool>,
    /// Whether the router holds a mapping. Waits on leviculum (no PCP /
    /// NAT-PMP / UPnP client yet): always `not_tried`.
    pub router_mapping: RouterMapping,
    /// How long until edge proposes to this member again (its tracker's
    /// backoff), when one runs. Known on this pin.
    pub backoff_remaining: Option<Duration>,
    /// How long until the escalation allowance refills. Waits on leviculum:
    /// its per-pair escalation budget does not report a refill time.
    pub escalation_refill: Option<Duration>,
}

impl DirectPathFacts {
    /// Facts with nothing measured, for `attempt`.
    #[must_use]
    pub const fn bare(attempt: DirectAttempt) -> Self {
        Self {
            proposing: true,
            facilitator_resolved: true,
            peer_trusted: true,
            attempt,
            attempts: 0,
            elapsed: Duration::ZERO,
            local_nat: None,
            peer_nat: None,
            escalation_allowed: None,
            escalation_granted: None,
            knocks_sent: None,
            sockets: None,
            predicted_ports: None,
            first_heard_ms: None,
            heard_not_acked: None,
            ipv6_candidates: None,
            lan_candidates: None,
            router_mapping: RouterMapping::NotTried,
            backoff_remaining: None,
            escalation_refill: None,
        }
    }

    /// Whether a media leg can stand on this attempt (a direct path, or a
    /// neighbour): then no `MediaPathFailed` is due.
    #[must_use]
    pub const fn path_stands(&self) -> bool {
        matches!(
            self.attempt,
            DirectAttempt::Established | DirectAttempt::AlreadyNeighbour
        )
    }

    /// The technique a standing path rides.
    #[must_use]
    pub fn via(&self) -> Option<PathKind> {
        match self.attempt {
            DirectAttempt::Established => Some(PathKind::DirectReflexive),
            DirectAttempt::AlreadyNeighbour => Some(PathKind::DirectLan),
            _ => None,
        }
    }

    fn one_way(&self) -> bool {
        self.heard_not_acked == Some(true)
            || self.attempt == DirectAttempt::Failed(AttemptFailure::Rejected(reject::PUNCH_FAILED))
    }

    fn both_random(&self) -> bool {
        let local = self
            .local_nat
            .as_ref()
            .is_some_and(|r| r.allocation == NatAllocation::Random);
        let peer = self
            .peer_nat
            .as_ref()
            .is_some_and(|r| r.report.allocation == NatAllocation::Random);
        local && peer
    }

    fn nat_known(&self) -> bool {
        self.local_nat.as_ref().is_some_and(NatReport::measured)
            || self.peer_nat.as_ref().is_some_and(|p| p.report.measured())
    }
}

/// What [`media_path_verdict`] decides: the cause, whether a retry can help
/// and when, and the branch that decided it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaPathVerdict {
    /// Why.
    pub cause: MediaPathCause,
    /// Whether retrying (the same pair, the same networks) can succeed:
    /// [`MediaPathCause::retryable`].
    pub retryable: bool,
    /// When to retry, in seconds, if known: the escalation allowance's refill
    /// for `budget_refused` (waits on leviculum), else edge's own backoff to
    /// the member. `None` when not retryable.
    pub retry_after_s: Option<u32>,
    /// The branch, always `Some` (so always `Some` when the cause is `other`).
    pub detail: Option<PathDetail>,
}

impl MediaPathCause {
    /// Whether a retry can help. `false` for a fact a retry does not change:
    /// both NATs random, the peer untrusted, the peer's policy, the peer
    /// unable to take part. `true` for the rest.
    #[must_use]
    pub const fn retryable(self) -> bool {
        !matches!(
            self,
            Self::BothNatsRandom
                | Self::NotTrusted
                | Self::RefusedByPeerPolicy
                | Self::PeerUnsupported
        )
    }
}

/// The branch and its cause, before the retry fields.
fn decide(facts: &DirectPathFacts) -> (MediaPathCause, PathDetail) {
    use AttemptFailure as F;
    use MediaPathCause as C;
    use PathDetail as D;
    if !facts.proposing {
        return (C::Other, D::ProposingOff);
    }
    if !facts.facilitator_resolved {
        return (C::NoFacilitator, D::FacilitatorUnresolved);
    }
    if !facts.peer_trusted {
        return (C::NotTrusted, D::PeerUntrusted);
    }
    if facts.escalation_allowed == Some(false) {
        return (C::NotTrusted, D::EscalationGated);
    }
    match facts.attempt {
        DirectAttempt::Failed(F::ProbeFailed) => (C::NoFacilitator, D::ProbeFailed),
        DirectAttempt::Failed(F::Rejected(reject::UNSUPPORTED)) => {
            (C::PeerUnsupported, D::PeerRejectUnsupported)
        }
        DirectAttempt::Failed(F::Rejected(reject::POLICY)) => {
            (C::RefusedByPeerPolicy, D::PeerRejectPolicy)
        }
        DirectAttempt::Failed(f @ (F::PunchFailed | F::Rejected(reject::PUNCH_FAILED))) => {
            if facts.both_random() {
                (C::BothNatsRandom, D::BothRandom)
            } else if facts.escalation_granted == Some(false) {
                (C::BudgetRefused, D::EscalationBudget)
            } else if f == F::Rejected(reject::PUNCH_FAILED) {
                (C::PunchOneWay, D::PeerPunchFailed)
            } else if facts.heard_not_acked == Some(true) {
                (C::PunchOneWay, D::HeardNotAcked)
            } else {
                (C::PunchNoAnswer, D::PunchSilent)
            }
        }
        DirectAttempt::Failed(F::Timeout) => (
            if facts.nat_known() {
                C::Other
            } else {
                C::NatUndetermined
            },
            D::PeerTimeout,
        ),
        DirectAttempt::NoOutcome => (
            if facts.nat_known() {
                C::Other
            } else {
                C::NatUndetermined
            },
            D::ProposalUnanswered,
        ),
        DirectAttempt::Failed(F::Rejected(reject::BUSY)) => (C::Other, D::PeerBusy),
        DirectAttempt::Failed(F::Rejected(reject::GLARE) | F::Glare) => (C::Other, D::Glare),
        DirectAttempt::Failed(F::Rejected(reject::HOLDING)) => (C::Other, D::PeerHolding),
        DirectAttempt::Failed(F::Rejected(_)) => (C::Other, D::PeerRejectUnknown),
        DirectAttempt::Failed(F::InterfaceLost) => (C::Other, D::InterfaceLost),
        DirectAttempt::Failed(F::HeldTooLong) => (C::Other, D::HeldTooLong),
        DirectAttempt::Failed(F::PeerFellBack) => (C::Other, D::PeerFellBack),
        DirectAttempt::NotProposed(NotProposed::NoLink) => (C::Other, D::NoLink),
        DirectAttempt::NotProposed(NotProposed::BackingOff) => (C::Other, D::BackingOff),
        DirectAttempt::NotProposed(NotProposed::Yielded) => (C::Other, D::Yielded),
        DirectAttempt::NotProposed(NotProposed::ProposeRefused) => (C::Other, D::ProposeRefused),
        DirectAttempt::Established | DirectAttempt::AlreadyNeighbour => (C::Other, D::PathStands),
    }
}

fn whole_secs(d: Duration) -> u32 {
    // Rounded up: a retry at the stated second is never early.
    let s = d.as_secs() + u64::from(d.subsec_nanos() > 0);
    u32::try_from(s).unwrap_or(u32::MAX)
}

/// **THE verdict** on a failed media path, decided once from `facts`. Pure.
///
/// The cause, in order, the first that holds (the detail token in brackets):
///
/// 1. the operator's switch is off: `other` (`proposing_off`);
/// 2. no facilitator resolved: `no_facilitator` (`facilitator_unresolved`);
/// 3. the peer is not trusted (`peer_untrusted`), or the punch's trust gate
///    refused to escalate (`escalation_gated`): `not_trusted`;
/// 4. this node's probe failed: `no_facilitator` (`probe_failed`);
/// 5. the peer REJECTed `UNSUPPORTED`: `peer_unsupported`
///    (`peer_reject_unsupported`);
/// 6. the peer REJECTed `POLICY`: `refused_by_peer_policy`
///    (`peer_reject_policy`);
/// 7. the punch failed (`PunchFailed`, or REJECT `PUNCH_FAILED`):
///    `both_nats_random` when both NATs allocate at random (`both_random`);
///    else `budget_refused` when the allowance refused escalation
///    (`escalation_budget`); else `punch_one_way` when the peer's side failed
///    (`peer_punch_failed`) or this side heard it unanswered
///    (`heard_not_acked`); else `punch_no_answer` (`punch_silent`);
/// 8. the peer stopped answering (`peer_timeout`), or the dial's budget ran
///    out with no outcome (`proposal_unanswered`): `nat_undetermined` when
///    neither NAT was measured, else `other`;
/// 9. anything else is `other`, its detail naming the branch: `peer_busy`,
///    `glare`, `peer_holding`, `peer_reject_unknown`, `interface_lost`,
///    `held_too_long`, `peer_fell_back`, `no_link`, `backing_off`,
///    `yielded`, `propose_refused`, `path_stands`.
///
/// `retryable` is [`MediaPathCause::retryable`]. `retry_after_s`, when
/// retryable: for `budget_refused` the allowance's refill when known, else
/// edge's backoff to the member when one runs; `None` otherwise.
///
/// A standing path is not a failure (`other`, `path_stands`); callers ask
/// only when [`DirectPathFacts::path_stands`] is false.
#[must_use]
pub fn media_path_verdict(facts: &DirectPathFacts) -> MediaPathVerdict {
    let (cause, detail) = decide(facts);
    let retryable = cause.retryable();
    let retry_after = if !retryable {
        None
    } else if cause == MediaPathCause::BudgetRefused {
        facts.escalation_refill.or(facts.backoff_remaining)
    } else {
        facts.backoff_remaining
    };
    MediaPathVerdict {
        cause,
        retryable,
        retry_after_s: retry_after.map(whole_secs),
        detail: Some(detail),
    }
}

/// [`media_path_verdict`]'s cause alone.
#[must_use]
pub fn media_path_cause(facts: &DirectPathFacts) -> MediaPathCause {
    media_path_verdict(facts).cause
}

/// The primary punch's outcome, from the attempt.
fn reflexive_outcome(facts: &DirectPathFacts) -> Option<PathOutcome> {
    use AttemptFailure as F;
    Some(match facts.attempt {
        DirectAttempt::Established => PathOutcome::Established,
        DirectAttempt::Failed(F::ProbeFailed | F::Rejected(reject::UNSUPPORTED)) => {
            PathOutcome::NoFacilitator
        }
        DirectAttempt::Failed(F::Rejected(reject::PUNCH_FAILED)) => PathOutcome::OneWay,
        DirectAttempt::Failed(F::PunchFailed) if facts.one_way() => PathOutcome::OneWay,
        DirectAttempt::Failed(F::Rejected(_) | F::Glare) => PathOutcome::RefusedByPeer,
        DirectAttempt::Failed(
            F::PunchFailed | F::Timeout | F::InterfaceLost | F::HeldTooLong | F::PeerFellBack,
        )
        | DirectAttempt::NoOutcome => PathOutcome::NoAnswer,
        DirectAttempt::AlreadyNeighbour | DirectAttempt::NotProposed(_) => return None,
    })
}

fn sat_u8(n: u32) -> u8 {
    u8::try_from(n).unwrap_or(u8::MAX)
}

fn sat_u16(n: u32) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

/// **What was tried** toward the member, from the same facts as the cause.
/// Pure. Lists only techniques something says about: the primary punch when a
/// proposal ran or could not (no facilitator, untrusted), and the others only
/// when leviculum's diagnostics report them (never on this pin). A member
/// that is a one-hop neighbour lists `direct_lan` established.
#[must_use]
pub fn path_attempts(facts: &DirectPathFacts) -> Vec<PathAttempt> {
    let elapsed_ms = u32::try_from(facts.elapsed.as_millis()).unwrap_or(u32::MAX);
    let ran = |kind, outcome, knocks: u32, sockets: u32| PathAttempt {
        kind,
        outcome,
        attempts: sat_u8(facts.attempts.max(1)),
        elapsed_ms,
        knocks_sent: sat_u16(knocks),
        sockets: sat_u16(sockets),
    };
    let not_run = |kind, outcome| PathAttempt {
        kind,
        outcome,
        attempts: 0,
        elapsed_ms: 0,
        knocks_sent: 0,
        sockets: 0,
    };
    if facts.attempt == DirectAttempt::AlreadyNeighbour {
        return vec![ran(PathKind::DirectLan, PathOutcome::Established, 0, 1)];
    }
    if !facts.proposing {
        return Vec::new();
    }
    if !facts.facilitator_resolved {
        return vec![not_run(
            PathKind::DirectReflexive,
            PathOutcome::NoFacilitator,
        )];
    }
    if !facts.peer_trusted {
        return vec![not_run(
            PathKind::DirectReflexive,
            PathOutcome::NotTriedUntrusted,
        )];
    }
    let Some(primary) = reflexive_outcome(facts) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    // Host candidates are punched beside the reflexive address, in the same
    // session: they share its outcome.
    if facts.lan_candidates == Some(true) {
        out.push(ran(PathKind::DirectLan, primary, 0, 1));
    }
    if facts.ipv6_candidates == Some(true) {
        out.push(ran(PathKind::DirectIpv6, primary, 0, 1));
    }
    out.push(ran(PathKind::DirectReflexive, primary, 0, 1));
    // The escalated techniques, only as the diagnostics report them.
    let escalated_outcome = if facts.escalation_allowed == Some(false) {
        Some(PathOutcome::NotTriedUntrusted)
    } else if facts.escalation_granted == Some(false) {
        Some(PathOutcome::BudgetRefused)
    } else {
        None
    };
    let knocks = facts.knocks_sent.unwrap_or(0);
    match (facts.predicted_ports, escalated_outcome) {
        (Some(n), None) if n > 0 => out.push(ran(PathKind::PredictedPorts, primary, knocks, 1)),
        (Some(n), Some(o)) if n > 0 => out.push(not_run(PathKind::PredictedPorts, o)),
        _ => {}
    }
    match (facts.sockets, escalated_outcome) {
        (Some(s), None) if s > 1 => out.push(ran(PathKind::Birthday, primary, knocks, s)),
        (Some(s), Some(o)) if s > 1 => out.push(not_run(PathKind::Birthday, o)),
        _ => {}
    }
    match facts.router_mapping {
        RouterMapping::HeldPcp | RouterMapping::HeldNatPmp | RouterMapping::HeldUpnp => {
            out.push(ran(PathKind::MappedPort, primary, 0, 1));
        }
        RouterMapping::None | RouterMapping::NotTried => {}
    }
    out
}

/// The relay standing on the LTS: the canonical never relays call media.
pub const LTS_RELAY_STANDING: RelayStanding = RelayStanding::RefusedByPolicy;

/// Everything a `MediaPathFailed` carries but its member, from `facts`, as of
/// `now` (the instant an unmeasured local report reads).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaPathFailure {
    /// [`media_path_verdict`]'s cause.
    pub cause: MediaPathCause,
    /// [`media_path_verdict`]'s.
    pub retryable: bool,
    /// [`media_path_verdict`]'s.
    pub retry_after_s: Option<u32>,
    /// [`media_path_verdict`]'s.
    pub detail: Option<PathDetail>,
    /// [`path_attempts`].
    pub tried: Vec<PathAttempt>,
    /// This node's NAT ([`NatReport::unknown`] when unmeasured).
    pub local_nat: NatReport,
    /// The peer's claim, if it made one.
    pub peer_nat: Option<PeerNatReport>,
    /// [`LTS_RELAY_STANDING`].
    pub relay: RelayStanding,
}

impl MediaPathFailure {
    /// Derive it.
    #[must_use]
    pub fn from_facts(facts: &DirectPathFacts, now: DateTime<Utc>) -> Self {
        let v = media_path_verdict(facts);
        Self {
            cause: v.cause,
            retryable: v.retryable,
            retry_after_s: v.retry_after_s,
            detail: v.detail,
            tried: path_attempts(facts),
            local_nat: facts
                .local_nat
                .clone()
                .unwrap_or_else(|| NatReport::unknown(now)),
            peer_nat: facts.peer_nat.clone(),
            relay: LTS_RELAY_STANDING,
        }
    }
}

#[cfg(feature = "_reticulum-module")]
impl From<leviculum_core::direct_link::Failure> for AttemptFailure {
    fn from(f: leviculum_core::direct_link::Failure) -> Self {
        use leviculum_core::direct_link::Failure as L;
        match f {
            L::Rejected(code) => Self::Rejected(code),
            L::ProbeFailed => Self::ProbeFailed,
            L::Timeout => Self::Timeout,
            L::PunchFailed => Self::PunchFailed,
            L::Glare => Self::Glare,
            L::InterfaceLost => Self::InterfaceLost,
            L::HeldTooLong => Self::HeldTooLong,
            L::PeerFellBack => Self::PeerFellBack,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at() -> DateTime<Utc> {
        DateTime::from_timestamp_millis(1_790_000_000_123).expect("instant")
    }

    fn report(allocation: NatAllocation) -> NatReport {
        NatReport::new(
            NatMapping::AddressAndPortDependent,
            allocation,
            NatFiltering::AddressAndPortDependent,
            Some(false),
            RouterMapping::NotTried,
            AddressFamily::V4,
            NatEvidence::TwoObserver,
            at(),
        )
    }

    fn peer(allocation: NatAllocation) -> PeerNatReport {
        PeerNatReport {
            report: report(allocation),
            source: NatReportSource::SelfReported,
        }
    }

    fn failed(f: AttemptFailure) -> DirectPathFacts {
        DirectPathFacts::bare(DirectAttempt::Failed(f))
    }

    /// The full RFC 4787 → RFC 3489 table: every (mapping, filtering) pair.
    #[test]
    fn legacy_class_covers_every_pair() {
        use LegacyClass as L;
        use NatFiltering as Fi;
        use NatMapping as M;
        let table: &[(M, Fi, L)] = &[
            (M::None, Fi::EndpointIndependent, L::Open),
            (M::None, Fi::Unknown, L::Open),
            (M::None, Fi::AddressDependent, L::Restricted),
            (M::None, Fi::AddressAndPortDependent, L::PortRestricted),
            (M::EndpointIndependent, Fi::EndpointIndependent, L::FullCone),
            (M::EndpointIndependent, Fi::AddressDependent, L::Restricted),
            (
                M::EndpointIndependent,
                Fi::AddressAndPortDependent,
                L::PortRestricted,
            ),
            (M::EndpointIndependent, Fi::Unknown, L::Unknown),
            (M::AddressDependent, Fi::EndpointIndependent, L::Symmetric),
            (M::AddressDependent, Fi::AddressDependent, L::Symmetric),
            (
                M::AddressDependent,
                Fi::AddressAndPortDependent,
                L::Symmetric,
            ),
            (M::AddressDependent, Fi::Unknown, L::Symmetric),
            (
                M::AddressAndPortDependent,
                Fi::EndpointIndependent,
                L::Symmetric,
            ),
            (
                M::AddressAndPortDependent,
                Fi::AddressDependent,
                L::Symmetric,
            ),
            (
                M::AddressAndPortDependent,
                Fi::AddressAndPortDependent,
                L::Symmetric,
            ),
            (M::AddressAndPortDependent, Fi::Unknown, L::Symmetric),
            (M::Unknown, Fi::EndpointIndependent, L::Unknown),
            (M::Unknown, Fi::AddressDependent, L::Unknown),
            (M::Unknown, Fi::AddressAndPortDependent, L::Unknown),
            (M::Unknown, Fi::Unknown, L::Unknown),
        ];
        assert_eq!(table.len(), M::ALL.len() * Fi::ALL.len(), "every pair once");
        for (m, f, want) in table {
            assert_eq!(legacy_class(*m, *f), *want, "{m:?} × {f:?}");
        }
        // Every word is reachable.
        for w in L::ALL {
            assert!(table.iter().any(|(_, _, l)| l == w), "{w:?} unreachable");
        }
    }

    /// Every verdict row: each input, the cause, `retryable`, `retry_after_s`
    /// and the detail it decides. Every cause token and every detail token
    /// has a row.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn the_verdict_table() {
        use AttemptFailure as F;
        use MediaPathCause as C;
        use PathDetail as D;
        // (what, facts, cause, detail, retry_after_s)
        let mut rows: Vec<(&str, DirectPathFacts, C, D, Option<u32>)> = Vec::new();
        for a in [
            DirectAttempt::Failed(F::PunchFailed),
            DirectAttempt::Failed(F::Rejected(reject::POLICY)),
            DirectAttempt::NotProposed(NotProposed::NoLink),
        ] {
            rows.push((
                "proposing off",
                DirectPathFacts {
                    proposing: false,
                    ..DirectPathFacts::bare(a)
                },
                C::Other,
                D::ProposingOff,
                None,
            ));
        }
        rows.push((
            "no facilitator resolved",
            DirectPathFacts {
                facilitator_resolved: false,
                ..DirectPathFacts::bare(DirectAttempt::NotProposed(NotProposed::NoLink))
            },
            C::NoFacilitator,
            D::FacilitatorUnresolved,
            None,
        ));
        rows.push((
            "probe failed, backing off 59.2 s",
            DirectPathFacts {
                backoff_remaining: Some(Duration::from_millis(59_200)),
                ..failed(F::ProbeFailed)
            },
            C::NoFacilitator,
            D::ProbeFailed,
            Some(60),
        ));
        rows.push((
            "peer unsupported, backoff ignored",
            DirectPathFacts {
                backoff_remaining: Some(Duration::from_secs(60)),
                ..failed(F::Rejected(reject::UNSUPPORTED))
            },
            C::PeerUnsupported,
            D::PeerRejectUnsupported,
            None,
        ));
        rows.push((
            "peer not trusted",
            DirectPathFacts {
                peer_trusted: false,
                backoff_remaining: Some(Duration::from_secs(60)),
                ..failed(F::PunchFailed)
            },
            C::NotTrusted,
            D::PeerUntrusted,
            None,
        ));
        rows.push((
            "escalation gate refused",
            DirectPathFacts {
                escalation_allowed: Some(false),
                ..failed(F::PunchFailed)
            },
            C::NotTrusted,
            D::EscalationGated,
            None,
        ));
        rows.push((
            "peer policy",
            DirectPathFacts {
                backoff_remaining: Some(Duration::from_secs(120)),
                ..failed(F::Rejected(reject::POLICY))
            },
            C::RefusedByPeerPolicy,
            D::PeerRejectPolicy,
            None,
        ));
        for f in [F::PunchFailed, F::Rejected(reject::PUNCH_FAILED)] {
            rows.push((
                "both random wins over the budget and one-way",
                DirectPathFacts {
                    local_nat: Some(report(NatAllocation::Random)),
                    peer_nat: Some(peer(NatAllocation::Random)),
                    escalation_granted: Some(false),
                    heard_not_acked: Some(true),
                    backoff_remaining: Some(Duration::from_secs(3_600)),
                    ..failed(f)
                },
                C::BothNatsRandom,
                D::BothRandom,
                None,
            ));
        }
        rows.push((
            "budget refused, refill known",
            DirectPathFacts {
                local_nat: Some(report(NatAllocation::Random)),
                peer_nat: Some(peer(NatAllocation::Sequential)),
                escalation_granted: Some(false),
                escalation_refill: Some(Duration::from_secs(90)),
                backoff_remaining: Some(Duration::from_secs(3_600)),
                ..failed(F::PunchFailed)
            },
            C::BudgetRefused,
            D::EscalationBudget,
            Some(90),
        ));
        rows.push((
            "budget refused, refill unknown: the backoff",
            DirectPathFacts {
                escalation_granted: Some(false),
                backoff_remaining: Some(Duration::from_secs(3_600)),
                ..failed(F::PunchFailed)
            },
            C::BudgetRefused,
            D::EscalationBudget,
            Some(3_600),
        ));
        rows.push((
            "budget refused, nothing known",
            DirectPathFacts {
                escalation_granted: Some(false),
                ..failed(F::PunchFailed)
            },
            C::BudgetRefused,
            D::EscalationBudget,
            None,
        ));
        rows.push((
            "peer's side failed",
            failed(F::Rejected(reject::PUNCH_FAILED)),
            C::PunchOneWay,
            D::PeerPunchFailed,
            None,
        ));
        rows.push((
            "heard, never acked",
            DirectPathFacts {
                heard_not_acked: Some(true),
                backoff_remaining: Some(Duration::from_secs(3_600)),
                ..failed(F::PunchFailed)
            },
            C::PunchOneWay,
            D::HeardNotAcked,
            Some(3_600),
        ));
        rows.push((
            "punch failed",
            DirectPathFacts {
                backoff_remaining: Some(Duration::from_secs(3_600)),
                ..failed(F::PunchFailed)
            },
            C::PunchNoAnswer,
            D::PunchSilent,
            Some(3_600),
        ));
        rows.push((
            "punch failed, only this side random",
            DirectPathFacts {
                local_nat: Some(report(NatAllocation::Random)),
                heard_not_acked: Some(false),
                escalation_granted: Some(true),
                ..failed(F::PunchFailed)
            },
            C::PunchNoAnswer,
            D::PunchSilent,
            None,
        ));
        rows.push((
            "timeout",
            failed(F::Timeout),
            C::NatUndetermined,
            D::PeerTimeout,
            None,
        ));
        rows.push((
            "timeout, unmeasured report",
            DirectPathFacts {
                local_nat: Some(NatReport::unknown(at())),
                backoff_remaining: Some(Duration::from_secs(120)),
                ..failed(F::Timeout)
            },
            C::NatUndetermined,
            D::PeerTimeout,
            Some(120),
        ));
        rows.push((
            "no outcome in budget",
            DirectPathFacts::bare(DirectAttempt::NoOutcome),
            C::NatUndetermined,
            D::ProposalUnanswered,
            None,
        ));
        rows.push((
            "timeout, NAT measured",
            DirectPathFacts {
                local_nat: Some(report(NatAllocation::Sequential)),
                ..failed(F::Timeout)
            },
            C::Other,
            D::PeerTimeout,
            None,
        ));
        rows.push((
            "no outcome, peer NAT measured",
            DirectPathFacts {
                peer_nat: Some(peer(NatAllocation::Preserving)),
                backoff_remaining: Some(Duration::from_secs(1)),
                ..DirectPathFacts::bare(DirectAttempt::NoOutcome)
            },
            C::Other,
            D::ProposalUnanswered,
            Some(1),
        ));
        for (f, d) in [
            (F::Rejected(reject::BUSY), D::PeerBusy),
            (F::Rejected(reject::GLARE), D::Glare),
            (F::Glare, D::Glare),
            (F::Rejected(reject::HOLDING), D::PeerHolding),
            (F::Rejected(0x7f), D::PeerRejectUnknown),
            (F::InterfaceLost, D::InterfaceLost),
            (F::HeldTooLong, D::HeldTooLong),
            (F::PeerFellBack, D::PeerFellBack),
        ] {
            rows.push(("transient", failed(f), C::Other, d, None));
        }
        for (n, d) in [
            (NotProposed::NoLink, D::NoLink),
            (NotProposed::BackingOff, D::BackingOff),
            (NotProposed::Yielded, D::Yielded),
            (NotProposed::ProposeRefused, D::ProposeRefused),
        ] {
            rows.push((
                "not proposed",
                DirectPathFacts {
                    backoff_remaining: Some(Duration::from_secs(30)),
                    ..DirectPathFacts::bare(DirectAttempt::NotProposed(n))
                },
                C::Other,
                d,
                Some(30),
            ));
        }
        for a in [DirectAttempt::Established, DirectAttempt::AlreadyNeighbour] {
            rows.push((
                "standing",
                DirectPathFacts::bare(a),
                C::Other,
                D::PathStands,
                None,
            ));
        }
        for (what, facts, cause, detail, after) in &rows {
            let v = media_path_verdict(facts);
            assert_eq!(
                v,
                MediaPathVerdict {
                    cause: *cause,
                    retryable: cause.retryable(),
                    retry_after_s: *after,
                    detail: Some(*detail),
                },
                "{what}: {facts:?}"
            );
            assert_eq!(media_path_cause(facts), *cause);
        }
        for c in C::ALL {
            assert!(
                rows.iter().any(|r| r.2 == *c),
                "{c:?} has no row that maps to it"
            );
        }
        for d in D::ALL {
            assert!(
                rows.iter().any(|r| r.3 == *d),
                "{d:?} has no row that maps to it"
            );
        }
    }

    /// `retryable` per cause, as agreed with the server.
    #[test]
    fn retryable_per_cause() {
        use MediaPathCause as C;
        let table = [
            (C::BothNatsRandom, false),
            (C::PunchNoAnswer, true),
            (C::PunchOneWay, true),
            (C::NatUndetermined, true),
            (C::NoFacilitator, true),
            (C::RefusedByPeerPolicy, false),
            (C::PeerUnsupported, false),
            (C::BudgetRefused, true),
            (C::NotTrusted, false),
            (C::Other, true),
        ];
        assert_eq!(table.len(), C::ALL.len());
        for (c, r) in table {
            assert_eq!(c.retryable(), r, "{c:?}");
        }
    }

    #[test]
    fn the_tried_list_names_what_ran() {
        use AttemptFailure as F;
        let t = |f: DirectPathFacts| -> Vec<(PathKind, PathOutcome)> {
            path_attempts(&f)
                .into_iter()
                .map(|a| (a.kind, a.outcome))
                .collect()
        };
        assert_eq!(
            t(DirectPathFacts {
                proposing: false,
                ..failed(F::PunchFailed)
            }),
            Vec::<(PathKind, PathOutcome)>::new()
        );
        assert_eq!(
            t(DirectPathFacts {
                facilitator_resolved: false,
                ..DirectPathFacts::bare(DirectAttempt::NotProposed(NotProposed::NoLink))
            }),
            [(PathKind::DirectReflexive, PathOutcome::NoFacilitator)]
        );
        assert_eq!(
            t(DirectPathFacts {
                peer_trusted: false,
                ..failed(F::PunchFailed)
            }),
            [(PathKind::DirectReflexive, PathOutcome::NotTriedUntrusted)]
        );
        for (f, o) in [
            (F::PunchFailed, PathOutcome::NoAnswer),
            (F::Timeout, PathOutcome::NoAnswer),
            (F::InterfaceLost, PathOutcome::NoAnswer),
            (F::HeldTooLong, PathOutcome::NoAnswer),
            (F::PeerFellBack, PathOutcome::NoAnswer),
            (F::ProbeFailed, PathOutcome::NoFacilitator),
            (F::Rejected(reject::UNSUPPORTED), PathOutcome::NoFacilitator),
            (F::Rejected(reject::POLICY), PathOutcome::RefusedByPeer),
            (F::Rejected(reject::BUSY), PathOutcome::RefusedByPeer),
            (F::Glare, PathOutcome::RefusedByPeer),
            (F::Rejected(reject::PUNCH_FAILED), PathOutcome::OneWay),
        ] {
            assert_eq!(t(failed(f)), [(PathKind::DirectReflexive, o)], "{f:?}");
        }
        assert_eq!(
            t(DirectPathFacts {
                heard_not_acked: Some(true),
                ..failed(F::PunchFailed)
            }),
            [(PathKind::DirectReflexive, PathOutcome::OneWay)]
        );
        assert_eq!(
            t(DirectPathFacts::bare(DirectAttempt::NoOutcome)),
            [(PathKind::DirectReflexive, PathOutcome::NoAnswer)]
        );
        assert_eq!(
            t(DirectPathFacts::bare(DirectAttempt::Established)),
            [(PathKind::DirectReflexive, PathOutcome::Established)]
        );
        assert_eq!(
            t(DirectPathFacts::bare(DirectAttempt::AlreadyNeighbour)),
            [(PathKind::DirectLan, PathOutcome::Established)]
        );
        for n in [
            NotProposed::NoLink,
            NotProposed::BackingOff,
            NotProposed::Yielded,
            NotProposed::ProposeRefused,
        ] {
            assert!(t(DirectPathFacts::bare(DirectAttempt::NotProposed(n))).is_empty());
        }
        // The diagnostics' techniques, as they report them.
        let full = DirectPathFacts {
            lan_candidates: Some(true),
            ipv6_candidates: Some(true),
            predicted_ports: Some(4),
            sockets: Some(64),
            knocks_sent: Some(300),
            router_mapping: RouterMapping::HeldPcp,
            ..failed(F::PunchFailed)
        };
        assert_eq!(
            t(full.clone()),
            [
                (PathKind::DirectLan, PathOutcome::NoAnswer),
                (PathKind::DirectIpv6, PathOutcome::NoAnswer),
                (PathKind::DirectReflexive, PathOutcome::NoAnswer),
                (PathKind::PredictedPorts, PathOutcome::NoAnswer),
                (PathKind::Birthday, PathOutcome::NoAnswer),
                (PathKind::MappedPort, PathOutcome::NoAnswer),
            ]
        );
        let birthday = path_attempts(&full)
            .into_iter()
            .find(|a| a.kind == PathKind::Birthday)
            .expect("birthday");
        assert_eq!((birthday.knocks_sent, birthday.sockets), (300, 64));
        assert_eq!(
            t(DirectPathFacts {
                escalation_granted: Some(false),
                ..full.clone()
            })[3..5],
            [
                (PathKind::PredictedPorts, PathOutcome::BudgetRefused),
                (PathKind::Birthday, PathOutcome::BudgetRefused),
            ]
        );
        // The not-trusted gate is the cause before the list is built, but the
        // list says it too when trust holds and only the gate refused.
        let gated = DirectPathFacts {
            escalation_allowed: Some(false),
            ..full
        };
        assert_eq!(
            t(gated)[3..5],
            [
                (PathKind::PredictedPorts, PathOutcome::NotTriedUntrusted),
                (PathKind::Birthday, PathOutcome::NotTriedUntrusted),
            ]
        );
    }

    #[test]
    fn counts_saturate() {
        let f = DirectPathFacts {
            attempts: 1_000,
            elapsed: Duration::from_secs(u64::MAX / 4),
            knocks_sent: Some(u32::MAX),
            predicted_ports: Some(1),
            ..DirectPathFacts::bare(DirectAttempt::Failed(AttemptFailure::PunchFailed))
        };
        let tried = path_attempts(&f);
        assert!(tried.iter().all(|a| a.attempts == u8::MAX));
        assert!(tried.iter().all(|a| a.elapsed_ms == u32::MAX));
        assert!(tried
            .iter()
            .any(|a| a.kind == PathKind::PredictedPorts && a.knocks_sent == u16::MAX));
    }

    #[test]
    fn tokens_are_the_serde_form_and_parse_back() {
        fn check<T>(all: &[T], token: fn(T) -> &'static str, parse: fn(&str) -> Option<T>)
        where
            T: Copy + PartialEq + std::fmt::Debug + Serialize,
        {
            for v in all {
                let t = token(*v);
                assert_eq!(serde_json::to_value(v).expect("ser"), t, "{v:?}");
                assert_eq!(parse(t), Some(*v));
                assert!(t
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit()));
            }
            assert_eq!(parse("Nope"), None);
        }
        check(
            MediaPathCause::ALL,
            MediaPathCause::token,
            MediaPathCause::parse,
        );
        check(PathDetail::ALL, PathDetail::token, PathDetail::parse);
        check(PathKind::ALL, PathKind::token, PathKind::parse);
        check(PathOutcome::ALL, PathOutcome::token, PathOutcome::parse);
        check(NatMapping::ALL, NatMapping::token, NatMapping::parse);
        check(
            NatAllocation::ALL,
            NatAllocation::token,
            NatAllocation::parse,
        );
        check(NatFiltering::ALL, NatFiltering::token, NatFiltering::parse);
        check(
            RouterMapping::ALL,
            RouterMapping::token,
            RouterMapping::parse,
        );
        check(
            AddressFamily::ALL,
            AddressFamily::token,
            AddressFamily::parse,
        );
        check(NatEvidence::ALL, NatEvidence::token, NatEvidence::parse);
        check(LegacyClass::ALL, LegacyClass::token, LegacyClass::parse);
        check(
            NatReportSource::ALL,
            NatReportSource::token,
            NatReportSource::parse,
        );
        check(
            RelayStanding::ALL,
            RelayStanding::token,
            RelayStanding::parse,
        );
        assert_eq!(MediaPathCause::ALL.len(), 10);
        assert_eq!(PathKind::ALL.len(), 6);
        assert_eq!(PathOutcome::ALL.len(), 8);
    }

    #[test]
    fn a_report_round_trips_in_milliseconds() {
        let r = PeerNatReport {
            report: report(NatAllocation::Sequential),
            source: NatReportSource::SelfReported,
        };
        let v = serde_json::to_value(&r).expect("ser");
        assert_eq!(v["report"]["measured_at"], 1_790_000_000_123_i64);
        assert_eq!(v["report"]["legacy_class"], "symmetric");
        assert_eq!(v["report"]["port_preserving"], false);
        assert_eq!(v["source"], "self_reported");
        let back: PeerNatReport = serde_json::from_value(v).expect("de");
        assert_eq!(back, r);
        // Sub-millisecond precision is dropped at the constructor, so a
        // report equals its own round trip.
        let fine = DateTime::from_timestamp(1_790_000_000, 123_456_789).expect("instant");
        let u = NatReport::unknown(fine);
        let back: NatReport =
            serde_json::from_str(&serde_json::to_string(&u).expect("ser")).expect("de");
        assert_eq!(back, u);
        assert!(!u.measured());
        assert_eq!(u.legacy_class, LegacyClass::Unknown);
    }

    #[test]
    fn a_failure_from_unmeasured_facts_is_unknown_and_refused_by_policy() {
        let f = MediaPathFailure::from_facts(
            &DirectPathFacts::bare(DirectAttempt::Failed(AttemptFailure::PunchFailed)),
            at(),
        );
        assert_eq!(f.cause, MediaPathCause::PunchNoAnswer);
        assert!(f.retryable);
        assert_eq!(f.retry_after_s, None);
        assert_eq!(f.detail, Some(PathDetail::PunchSilent));
        assert_eq!(f.relay, RelayStanding::RefusedByPolicy);
        assert_eq!(f.local_nat, NatReport::unknown(at()));
        assert_eq!(f.peer_nat, None);
    }
}
