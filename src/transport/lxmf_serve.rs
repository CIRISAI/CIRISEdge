//! LXMF propagation **host serve path** — this node acting as a
//! propagation node for others (CIRISEdge#169).
//!
//! [`crate::transport::lxmf_propagation`] is the CLIENT half plus an
//! unscoped admission core. This module is the other half: the state
//! machine that answers a stranger's `/get` and admits a stranger's
//! upload. It is what "#169 host serve path" means, and it is the piece
//! that was blocked until **leviculum#38 landed** — at edge's pinned
//! `v0.20.0+ciris.1` the host-direction codecs are public
//! (`PropagationUpload::decode`, `MessageGetRequest::decode`,
//! `MessageListResponse::encode`, `MessageGetResponse::encode`,
//! `PropagationSignal::encode`) and, decisively,
//! [`PropagatedMessage::from_unstamped_bytes`] +
//! [`PropagatedMessage::destination_hash`] are public, which is what makes
//! **per-recipient mailbox scoping** possible at all.
//!
//! We INTEGRATE `leviculum-lxmf`; every wire byte, hash and proof-of-work
//! comes from it. This module contributes exactly three things the crate
//! deliberately leaves to a host: **who we serve**, **what we retain**,
//! and **for how long**.
//!
//! # Sans-I/O, and therefore CIRISEdge#217-safe by construction
//!
//! Nothing here is `async` and nothing here `.await`s, so a lock guard
//! *cannot* be held across an await on the transport path — the invariant
//! is structural rather than reviewed. Timing is
//! [`std::time::Instant`] (monotonic), never `tokio::time` and never the
//! wall clock: a retention window must not be shortened or extended by an
//! NTP step. `now` is a parameter, so every bound is testable at its exact
//! ceiling.
//!
//! # Retention posture — bounded, explicit, and refusing rather than evicting
//!
//! Edge's recorded position on LXMF propagation is that a propagation node
//! holds LXMF **end-to-end ciphertext** and has no key and no decrypt path,
//! so it is a *metadata observer* and an *availability lever*, not a
//! confidentiality break — and that third-party propagation is therefore a
//! deliberate operator choice for genuinely asleep peers, never the default
//! reply path (which is why store-and-forward stays OFF the #353/#373
//! live-link reply path). This module holds that line in four ways:
//!
//! 1. **Default OFF.** [`PropagationAudience::Disabled`] is
//!    [`Default`]. A node that has not been explicitly told whose mail to
//!    hold answers every propagation request with a named refusal. There
//!    is deliberately **no "open node" variant**: serving all comers is a
//!    policy choice about who may propagate what, and that rule is
//!    persist's or the constitution's, not edge's (see *Upstream*, below).
//! 2. **Explicit roster.** [`PropagationAudience::Roster`] is an operator-
//!    supplied set of destination hashes. Both legs check it: an upload is
//!    admitted only for a rostered *recipient*, and a `/get` is answered
//!    only for a rostered *requester*.
//! 3. **Bounded retention.** [`LxmfServeLimits::retention`] evicts
//!    uncollected mail, and every eviction is reported as a
//!    [`WithholdReason::LxmfRetentionExpired`] notice. A propagation node
//!    that dropped third-party mail silently would be indistinguishable
//!    from one that never received it.
//! 4. **Full means refuse, not evict.** Every other bounded store in edge
//!    (notably [`crate::transport::store_and_forward`]) evicts oldest-first
//!    to admit. This one **refuses**, and that difference is the security
//!    property: store-and-forward queues *this node's own* outbound
//!    envelopes, where there is no third party to harm, whereas evicting
//!    here would let an attacker flush a victim's pending mail with junk
//!    uploads — turning a capacity bound into a censorship lever.
//!
//! # Recipient scoping is structural
//!
//! The mailbox is `destination -> transient_id -> ciphertext`. "You may
//! read only your own mail" is therefore the shape of the data, not a
//! filter that a future edit can forget to apply: serving another
//! destination's message would require indexing a map this code never
//! indexes. A requester that names a transient ID parked for someone
//! *else* is reported as [`WithholdReason::LxmfMailboxScopeMismatch`] —
//! including on the acknowledge leg, where it would otherwise be a way to
//! **purge a stranger's mailbox**.
//!
//! # What this module refuses to decide (upstream)
//!
//! *Who may use this node as a propagation node* is not edge's rule to
//! write. Edge supplies the mechanism (a roster) and fails closed; the
//! roster's **source** — whether propagation carriage follows
//! `infra:transport` conferral, the accord roster, or something else — is
//! an upstream question. It is deliberately NOT wired to
//! `resolve_transit_eligibility` here, because choosing that would be edge
//! inventing the policy. See the module's report notes and CIRISEdge#169.
//!
//! Likewise the node-to-node `/offer` peer-sync direction is not
//! implemented, because `leviculum-lxmf` does not implement it
//! (leviculum#209); a well-formed multi-message upload is reported as
//! [`WithholdReason::LxmfPeerSyncUnsupported`] rather than mis-parsed.
//!
//! # Where this hooks into the event loop
//!
//! Edge has exactly one Reticulum event loop and this module does not add
//! a second. It is a pure decision function driven from
//! [`crate::transport::reticulum`]'s existing `handle_event`:
//!
//! * `NodeEvent::RequestReceived` with `path == `[`MESSAGE_GET_PATH`] →
//!   [`LxmfServeNode::serve_get`], whose `requester` argument is
//!   `Node::get_remote_identity(link_id)` reduced to that identity's
//!   destination hash. [`ServeOutcome::Respond`] carries the bytes for
//!   `send_response(request_id, ..)`.
//! * the inbound upload link-data / resource path →
//!   [`LxmfServeNode::serve_upload`].
//! * any existing periodic tick → [`LxmfServeNode::sweep`], so retention
//!   is enforced on an idle node too.
//!
//! In every case the caller must drain [`ServeResult::notices`] into
//! [`crate::observability::EdgeMetrics::inc_withhold`]; `ServeResult` is
//! `#[must_use]` so a refusal cannot be dropped on the floor
//! (CIRISEdge#425/#433).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use leviculum_lxmf::constants::{
    DESTINATION_LENGTH, PROPAGATION_LIMIT_KB, WORKBLOCK_EXPAND_ROUNDS_PN,
};
use leviculum_lxmf::stamp::{self, CooperativeStamper, ReadyYield};
use leviculum_lxmf::{
    MessageGetRequest, MessageGetResponse, MessageListResponse, PeerError, PropagatedMessage,
    PropagationError, PropagationSignal, PropagationUpload, TransientId,
};

use crate::contextual_integrity::{parameter_of, CiParameter, Delivery};
use crate::observability::WithholdReason;

/// Re-exported so the event loop's `register_request_handler` and this
/// module's dispatch agree by construction.
pub use leviculum_lxmf::MESSAGE_GET_PATH;

/// A Reticulum destination hash — the mailbox key, and the identity a
/// requester is scoped to.
pub type DestinationHash16 = [u8; DESTINATION_LENGTH];

/// Bytes each parked entry costs in addition to its ciphertext: the
/// destination hash plus the transient ID that key it.
///
/// Counted deliberately. `leviculum-lxmf`'s own `MemoryLxmfStorage` learned
/// this upstream — "counting values alone lets an attacker exhaust a
/// constrained target with many large keys carrying empty values" — and the
/// lesson is applied here rather than re-derived: a peer must not be able to
/// size an allocation we did not account for.
const ENTRY_OVERHEAD_BYTES: usize = DESTINATION_LENGTH + 32;

/// Every ceiling this node enforces while serving strangers.
///
/// A propagation node serves parties it has no relationship with, so every
/// buffer, queue and retention window has an explicit bound. Boundary
/// semantics follow `leviculum-lxmf`'s own convention (`DELIVERY_LIMIT_BYTES`:
/// "exactly at the limit is accepted; the comparison is `size > limit`"):
/// a value **equal to** a size ceiling is admitted, one **above** it is
/// refused; a count ceiling is full when reached; retention expires when
/// the window is reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LxmfServeLimits {
    /// Largest `/get` request body accepted, before any decode.
    pub max_request_bytes: usize,
    /// Largest upload envelope accepted, before any decode.
    pub max_upload_bytes: usize,
    /// Most transient IDs one request may name across `wants` + `haves`.
    /// Bounds the work a single request can buy.
    pub max_ids_per_request: usize,
    /// Total mailbox bytes retained, keys included.
    pub max_store_bytes: usize,
    /// Most messages parked for any one destination.
    pub max_messages_per_destination: usize,
    /// Most distinct destinations with a live mailbox. Without this an
    /// attacker mints unbounded mailbox keys under the byte cap.
    pub max_destinations: usize,
    /// Most messages returned in one `/get` download response.
    pub max_messages_per_response: usize,
    /// Most bytes returned in one `/get` download response.
    pub max_response_bytes: usize,
    /// How long an uncollected message is retained before it is evicted
    /// and reported. The retention posture, in one field.
    pub retention: Duration,
    /// Admission proof-of-work cost (leading-zero bits) this node
    /// advertises and enforces. `0` disables the spam bound, so the
    /// default is non-zero.
    pub stamp_cost: u8,
}

impl Default for LxmfServeLimits {
    /// Defaults chosen from upstream and from edge's existing #169 Scope-B
    /// budget rather than invented: the per-transfer sizes are
    /// `leviculum-lxmf`'s own [`PROPAGATION_LIMIT_KB`] (Python
    /// `LXMRouter.PROPAGATION_LIMIT`), and the store budget, per-destination
    /// depth and retention window match
    /// [`crate::transport::store_and_forward`]'s defaults so an operator
    /// running both planes reasons about one set of numbers.
    fn default() -> Self {
        let propagation_limit_bytes =
            usize::try_from(PROPAGATION_LIMIT_KB * 1000).unwrap_or(256 * 1000);
        Self {
            max_request_bytes: 64 * 1024,
            max_upload_bytes: propagation_limit_bytes,
            max_ids_per_request: 1024,
            max_store_bytes: 64 * 1024 * 1024,
            max_messages_per_destination: 256,
            max_destinations: 1024,
            max_messages_per_response: 64,
            max_response_bytes: propagation_limit_bytes,
            retention: Duration::from_secs(7 * 24 * 60 * 60),
            stamp_cost: 8,
        }
    }
}

/// Whose mail this node is willing to hold and serve.
///
/// There is no "serve everyone" variant, and that absence is the point:
/// *who may use this node as a propagation node* is a policy question, and
/// policy is persist's or the constitution's to state. Edge offers the
/// mechanism and fails closed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
/// # Why this is NOT `resolve_transit_eligibility` (CIRISPersist#561 / CIRISEdge#430)
///
/// The obvious move is to reuse the RNS transit rule — *directory-present,
/// `identity_type` contains `node`, self-offers `infra:transport`, shares a
/// trust root I trust* — since both planes carry only ciphertext. **That rule
/// is too wide here**, and persist's own rationale for why it is wide is what
/// rules it out:
///
/// > A relay carries only ciphertext — no `EpochDek` is reachable from a hop
/// > … and it is what keeps relaying DECENTRALIZED: any trust-anchored node
/// > offering transport can serve as a hop.
///
/// Three legs hold that up, and LXMF propagation satisfies only the first:
///
/// | | RNS transit | LXMF propagation |
/// |---|---|---|
/// | ciphertext-only | yes | **yes** |
/// | transient | the frame passes, the node forgets | **retains for days** |
/// | breadth is the point | yes, every hop matters | no, a mailbox needs no strangers |
///
/// The decisive difference is what the node **learns and holds over time**. A
/// transit hop sees `(prev, next, size, time)` and forgets. A propagation node
/// holds a mailbox **keyed by recipient**, and durably learns which
/// destinations have mail waiting, how much and from whom, and *when the
/// recipient came online to collect it* — a presence oracle. It can also
/// withhold or delete, which is an availability lever aimed at one named
/// person.
///
/// So the confidentiality property is identical and the metadata and
/// availability properties are categorically different. `infra:transport`'s
/// bar is proportionate to *"carries ciphertext and forgets"*. It is not
/// proportionate to *"holds your mailbox and knows when you check it"*.
///
/// # The rule that does apply
///
/// **Self, family, and the communities this node is a member of** — the
/// cohort-scope vocabulary CC already defines, resolved through machinery
/// CIRISEdge#499 already built (`CohortGroup`'s roster, `ScopeAddressTable`'s
/// membership). Edge POPULATES this roster from cohort membership; it does not
/// author a predicate, which is what kept this from being edge writing policy.
///
/// Both legs read the same set, and they are different questions:
/// - **upload** — someone hands this node mail *for* `R`: `R` must be served.
/// - **download** — a requester wants `R`'s mail: the requester must *be* `R`
///   (already structural, since the mailbox indexes by destination) *and* `R`
///   must be served.
pub enum PropagationAudience {
    /// This node does not carry third-party mail. The default posture.
    #[default]
    Disabled,
    /// The operator-supplied set of destinations this node holds mail for.
    Roster(BTreeSet<DestinationHash16>),
}

impl PropagationAudience {
    /// Build the roster from **cohort membership** — self, family, and the
    /// communities this node belongs to.
    ///
    /// This is the rule that applies to propagation (see the type docs for
    /// why it is not `resolve_transit_eligibility`), expressed as code so the
    /// next implementer inherits it rather than re-deriving it.
    ///
    /// `groups` is the set of `(scope, group_id)` pairs this node is a member
    /// of — exactly what a host already holds after driving
    /// [`ScopeLifecycle::install`] for each. For each, every member's derived
    /// address is added, because a propagation node holds mail *for the
    /// cohort*, not only for itself.
    ///
    /// Edge is POPULATING a set here, not authoring a predicate: membership is
    /// answered by [`ScopeAddressTable`], and the scope vocabulary is CC's.
    ///
    /// Returns [`Self::Disabled`] when the table admits nothing — an empty
    /// roster and "carry no third-party mail" are the same posture, and
    /// collapsing them means there is no way to be armed-but-empty and believe
    /// otherwise.
    ///
    /// [`ScopeLifecycle::install`]: crate::scope_lifecycle::ScopeLifecycle::install
    /// [`ScopeAddressTable`]: crate::scope_addressing::ScopeAddressTable
    #[must_use]
    pub fn from_cohort_membership(
        table: &crate::scope_addressing::ScopeAddressTable,
        groups: &[(crate::cohort_scope::CohortScope, String)],
        members_of: &dyn Fn(&crate::cohort_scope::CohortScope, &str) -> Vec<String>,
    ) -> Self {
        let mut roster = BTreeSet::new();
        for (scope, group_id) in groups {
            for member in members_of(scope, group_id) {
                if let Some(addr) = table.send_address(scope, group_id, &member) {
                    roster.insert(*addr.as_bytes());
                }
            }
        }
        if roster.is_empty() {
            Self::Disabled
        } else {
            Self::Roster(roster)
        }
    }

    /// Whether `destination` is one this node carries for.
    #[must_use]
    pub fn serves(&self, destination: &DestinationHash16) -> bool {
        match self {
            Self::Disabled => false,
            Self::Roster(set) => set.contains(destination),
        }
    }

    /// Whether the node is operating as a propagation node at all.
    #[must_use]
    pub fn enabled(&self) -> bool {
        matches!(self, Self::Roster(_))
    }
}

/// One thing this node declined to do, or undid, in commitment terms.
///
/// Emitted for refusals AND for retention evictions, so nothing leaves the
/// mailbox silently (CIRISEdge#425/#433). The caller pushes each into the
/// withhold ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    /// The gate that refused, or the clock that evicted.
    pub reason: WithholdReason,
    /// Short, static, low-cardinality leg descriptor — never peer-supplied
    /// bytes, matching `inc_withhold`'s contract that the ring stays
    /// bounded in entry size as well as in count.
    pub detail: &'static str,
    /// The destination this concerned, when one is known.
    pub destination: Option<DestinationHash16>,
}

impl Notice {
    fn new(
        reason: WithholdReason,
        detail: &'static str,
        destination: Option<DestinationHash16>,
    ) -> Self {
        Self {
            reason,
            detail,
            destination,
        }
    }

    /// The commitment this notice defends — the single source of truth is
    /// [`parameter_of`], never a second table here.
    #[must_use]
    pub fn parameter(&self) -> CiParameter {
        parameter_of(self.reason)
    }

    /// The decision in commitment vocabulary, for an operator log.
    #[must_use]
    pub fn delivery(&self) -> Delivery {
        Delivery::withheld(self.reason)
    }
}

/// What the event loop must do with this request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServeOutcome {
    /// Send these bytes back via `send_response(request_id, ..)`.
    Respond(Vec<u8>),
    /// An upload was admitted and is now parked. LXMF sends no
    /// acknowledgement for a successful upload, so there is nothing to
    /// write back.
    Admitted {
        /// The re-derived transient ID it was parked under — never the
        /// wire-supplied one.
        transient_id: TransientId,
        /// The recipient whose mailbox now holds it.
        destination: DestinationHash16,
    },
    /// Refused. `response`, when present, is the wire refusal the protocol
    /// defines for this leg (a `PeerError` code on `/get`, a
    /// [`PropagationSignal`] on upload); `None` means the protocol defines
    /// no reply and the caller should simply not answer.
    Refused {
        /// The gate that refused.
        reason: WithholdReason,
        /// Short static leg descriptor.
        detail: &'static str,
        /// Bytes to send back, if the protocol defines a refusal reply.
        response: Option<Vec<u8>>,
    },
}

/// The outcome plus every notice the call produced.
///
/// `#[must_use]`: a caller that dropped this would drop refusals and
/// retention evictions on the floor, which is exactly the silent-drop class
/// CIRISEdge#425/#433 exists to make impossible.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServeResult {
    /// What to do next.
    pub outcome: ServeOutcome,
    /// Refusals and evictions to push into the withhold ledger. Bounded by
    /// construction: never more than the number of messages the mailbox
    /// ceilings allow it to hold.
    pub notices: Vec<Notice>,
}

impl ServeResult {
    fn refused(
        notices: Vec<Notice>,
        reason: WithholdReason,
        detail: &'static str,
        response: Option<Vec<u8>>,
    ) -> Self {
        let mut notices = notices;
        notices.push(Notice::new(reason, detail, None));
        Self {
            outcome: ServeOutcome::Refused {
                reason,
                detail,
                response,
            },
            notices,
        }
    }

    /// Whether the outcome was a refusal.
    #[must_use]
    pub fn refused_reason(&self) -> Option<WithholdReason> {
        match self.outcome {
            ServeOutcome::Refused { reason, .. } => Some(reason),
            _ => None,
        }
    }
}

/// One message parked on behalf of a third party.
#[derive(Clone, Debug)]
struct Parked {
    /// LXMF end-to-end ciphertext, verbatim. This node holds no key for it
    /// and there is no decrypt path on this type.
    ciphertext: Vec<u8>,
    /// Monotonic admission instant — the retention clock.
    stored_at: Instant,
}

/// `destination -> transient_id -> parked`. The nesting IS the scoping.
#[derive(Debug, Default)]
struct MailboxState {
    boxes: BTreeMap<DestinationHash16, BTreeMap<TransientId, Parked>>,
    /// Running total of `ENTRY_OVERHEAD_BYTES + ciphertext.len()`.
    bytes: usize,
}

impl MailboxState {
    /// Evict everything past the retention window, reporting each.
    fn sweep(&mut self, now: Instant, retention: Duration) -> Vec<Notice> {
        let mut notices = Vec::new();
        let mut emptied: Vec<DestinationHash16> = Vec::new();
        for (dest, entries) in &mut self.boxes {
            let expired: Vec<TransientId> = entries
                .iter()
                .filter(|(_, p)| now.duration_since(p.stored_at) >= retention)
                .map(|(id, _)| *id)
                .collect();
            for id in expired {
                if let Some(p) = entries.remove(&id) {
                    self.bytes = self
                        .bytes
                        .saturating_sub(ENTRY_OVERHEAD_BYTES + p.ciphertext.len());
                    notices.push(Notice::new(
                        WithholdReason::LxmfRetentionExpired,
                        "retention_window",
                        Some(*dest),
                    ));
                }
            }
            if entries.is_empty() {
                emptied.push(*dest);
            }
        }
        // An emptied mailbox is removed so it stops counting against
        // `max_destinations`; leaving it would let expired traffic
        // permanently consume the destination budget.
        for dest in emptied {
            self.boxes.remove(&dest);
        }
        notices
    }

    /// Whether any destination OTHER than `owner` holds `id`. The
    /// cross-recipient probe detector.
    fn held_by_other(&self, owner: &DestinationHash16, id: &TransientId) -> bool {
        self.boxes
            .iter()
            .any(|(dest, entries)| dest != owner && entries.contains_key(id))
    }
}

/// The propagation-node host: bounded, rostered, recipient-scoped.
#[derive(Debug)]
pub struct LxmfServeNode {
    limits: LxmfServeLimits,
    audience: PropagationAudience,
    state: Mutex<MailboxState>,
}

impl LxmfServeNode {
    /// A node with an explicit audience and explicit ceilings.
    #[must_use]
    pub fn new(audience: PropagationAudience, limits: LxmfServeLimits) -> Self {
        Self {
            limits,
            audience,
            state: Mutex::new(MailboxState::default()),
        }
    }

    /// A node that serves `roster` under [`LxmfServeLimits::default`].
    #[must_use]
    pub fn serving(roster: BTreeSet<DestinationHash16>) -> Self {
        Self::new(
            PropagationAudience::Roster(roster),
            LxmfServeLimits::default(),
        )
    }

    /// A node in the default posture: carries nobody's mail.
    #[must_use]
    pub fn disabled() -> Self {
        Self::new(PropagationAudience::Disabled, LxmfServeLimits::default())
    }

    /// The ceilings in force.
    #[must_use]
    pub fn limits(&self) -> LxmfServeLimits {
        self.limits
    }

    /// The audience in force.
    #[must_use]
    pub fn audience(&self) -> &PropagationAudience {
        &self.audience
    }

    /// Run the mailbox state under the lock.
    ///
    /// A poisoned lock is recovered rather than propagated: a propagation
    /// node must not become permanently unserviceable because one request
    /// panicked, which would make a panic a remote availability kill.
    /// There is no `.await` inside any caller of this, so no guard can
    /// cross a suspension point (CIRISEdge#217).
    fn with_state<T>(&self, f: impl FnOnce(&mut MailboxState) -> T) -> T {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut guard)
    }

    /// Evict everything past the retention window. Drive this from the
    /// event loop's existing periodic tick so retention is enforced on an
    /// idle node, not only when traffic happens to arrive.
    pub fn sweep(&self, now: Instant) -> Vec<Notice> {
        let retention = self.limits.retention;
        self.with_state(|st| st.sweep(now, retention))
    }

    /// Total retained ciphertext + key bytes.
    #[must_use]
    pub fn stored_bytes(&self) -> usize {
        self.with_state(|st| st.bytes)
    }

    /// Number of destinations with a live mailbox.
    #[must_use]
    pub fn destination_count(&self) -> usize {
        self.with_state(|st| st.boxes.len())
    }

    /// Messages parked for one destination.
    #[must_use]
    pub fn pending_for(&self, destination: &DestinationHash16) -> usize {
        self.with_state(|st| st.boxes.get(destination).map_or(0, BTreeMap::len))
    }

    /// The announce parameters this node's advertised terms imply, for the
    /// caller to encode into a [`leviculum_lxmf::PropagationNodeAnnounce`].
    /// Advertising a `stamp_cost` other than the one enforced would be a
    /// node lying about its price of carriage, so both come from here.
    #[must_use]
    pub fn advertised_stamp_cost(&self) -> u64 {
        u64::from(self.limits.stamp_cost)
    }

    // ── The `/get` mailbox exchange ─────────────────────────────────────

    /// Answer a client's `/get`.
    ///
    /// `requester` is the destination hash the link's remote identity
    /// resolves to — the caller reads it from
    /// `Node::get_remote_identity(link_id)`. `None` means the link is
    /// unidentified, which is refused: there is no answer to "whose
    /// mailbox is this".
    pub fn serve_get(
        &self,
        requester: Option<DestinationHash16>,
        body: &[u8],
        now: Instant,
    ) -> ServeResult {
        let notices = self.sweep(now);

        if !self.audience.enabled() {
            return ServeResult::refused(
                notices,
                WithholdReason::LxmfPropagationDisabled,
                "get",
                Some(peer_error_list(PeerError::NoAccess)),
            );
        }
        if body.len() > self.limits.max_request_bytes {
            return ServeResult::refused(
                notices,
                WithholdReason::LxmfFrameOversized,
                "get_request_bytes",
                Some(peer_error_list(PeerError::InvalidData)),
            );
        }
        let Some(requester) = requester else {
            return ServeResult::refused(
                notices,
                WithholdReason::LxmfRequesterUnidentified,
                "get_link_unidentified",
                Some(peer_error_list(PeerError::NoIdentity)),
            );
        };
        if !self.audience.serves(&requester) {
            return ServeResult::refused(
                notices,
                WithholdReason::LxmfDestinationNotServed,
                "get_requester_off_roster",
                Some(peer_error_list(PeerError::NoAccess)),
            );
        }
        let Ok(request) = MessageGetRequest::decode(body) else {
            return ServeResult::refused(
                notices,
                WithholdReason::LxmfWireUnparseable,
                "get_request",
                Some(peer_error_list(PeerError::InvalidData)),
            );
        };
        let named =
            request.wants.as_ref().map_or(0, Vec::len) + request.haves.as_ref().map_or(0, Vec::len);
        if named > self.limits.max_ids_per_request {
            return ServeResult::refused(
                notices,
                WithholdReason::LxmfFrameOversized,
                "get_request_id_count",
                Some(peer_error_list(PeerError::InvalidData)),
            );
        }

        match (request.wants, request.haves) {
            (Some(wants), _) => self.download(requester, &wants, notices),
            (None, Some(haves)) => self.acknowledge(requester, &haves, notices),
            (None, None) => self.list(requester, notices),
        }
    }

    /// `wants: None, haves: None` — list this requester's own transient IDs.
    fn list(&self, requester: DestinationHash16, notices: Vec<Notice>) -> ServeResult {
        let ids = self.with_state(|st| {
            st.boxes
                .get(&requester)
                .map_or_else(Vec::new, |entries| entries.keys().copied().collect())
        });
        respond(MessageListResponse::TransientIds(ids).encode(), notices)
    }

    /// `wants: Some(..)` — serve only what is parked for this requester.
    fn download(
        &self,
        requester: DestinationHash16,
        wants: &[TransientId],
        notices: Vec<Notice>,
    ) -> ServeResult {
        let limits = self.limits;
        let (messages, mut extra) = self.with_state(|st| {
            let mut messages: Vec<Vec<u8>> = Vec::new();
            let mut extra: Vec<Notice> = Vec::new();
            let mut bytes = 0usize;
            for id in wants {
                let Some(parked) = st.boxes.get(&requester).and_then(|e| e.get(id)) else {
                    // Not ours to serve. Two very different misses:
                    if st.held_by_other(&requester, id) {
                        // Parked for SOMEONE ELSE — a cross-recipient probe.
                        // Reported, because this miss is evidence of an
                        // attack rather than of a race.
                        extra.push(Notice::new(
                            WithholdReason::LxmfMailboxScopeMismatch,
                            "download_foreign_transient_id",
                            Some(requester),
                        ));
                    }
                    // Held by nobody: an ordinary absence (already collected,
                    // expired, or never existed). NOT a withhold — we are not
                    // declining to serve something we hold — and ledgering it
                    // would drown the real signal above in routine misses.
                    continue;
                };
                if messages.len() >= limits.max_messages_per_response
                    || bytes + parked.ciphertext.len() > limits.max_response_bytes
                {
                    // We DO hold it and are declining to send it in this
                    // response: a withhold, not a miss.
                    extra.push(Notice::new(
                        WithholdReason::LxmfFrameOversized,
                        "download_response_cap",
                        Some(requester),
                    ));
                    continue;
                }
                bytes += parked.ciphertext.len();
                messages.push(parked.ciphertext.clone());
            }
            (messages, extra)
        });
        let mut notices = notices;
        notices.append(&mut extra);
        respond(MessageGetResponse::Messages(messages).encode(), notices)
    }

    /// `wants: None, haves: Some(..)` — purge, from this requester's box only.
    fn acknowledge(
        &self,
        requester: DestinationHash16,
        haves: &[TransientId],
        notices: Vec<Notice>,
    ) -> ServeResult {
        let mut extra = self.with_state(|st| {
            let mut extra: Vec<Notice> = Vec::new();
            for id in haves {
                let removed = st
                    .boxes
                    .get_mut(&requester)
                    .and_then(|entries| entries.remove(id));
                if let Some(p) = removed {
                    st.bytes = st
                        .bytes
                        .saturating_sub(ENTRY_OVERHEAD_BYTES + p.ciphertext.len());
                } else if st.held_by_other(&requester, id) {
                    // Acknowledging someone else's message would DELETE it.
                    // The scoping makes that impossible; this says so.
                    extra.push(Notice::new(
                        WithholdReason::LxmfMailboxScopeMismatch,
                        "acknowledge_foreign_transient_id",
                        Some(requester),
                    ));
                }
            }
            if st.boxes.get(&requester).is_some_and(BTreeMap::is_empty) {
                st.boxes.remove(&requester);
            }
            extra
        });
        let mut notices = notices;
        notices.append(&mut extra);
        // Python answers the purge exchange with the (now shorter) list.
        let ids = self.with_state(|st| {
            st.boxes
                .get(&requester)
                .map_or_else(Vec::new, |entries| entries.keys().copied().collect())
        });
        respond(MessageListResponse::TransientIds(ids).encode(), notices)
    }

    // ── Upload admission ────────────────────────────────────────────────

    /// Admit (or refuse) an inbound upload envelope from raw link data or a
    /// resource body.
    ///
    /// Ordering is deliberate: every cheap check runs *before* the
    /// proof-of-work validation, so junk never buys us a workblock hash;
    /// and the proof-of-work runs *outside* the mailbox lock, so the
    /// expensive step never blocks another request (CIRISEdge#217 in
    /// spirit as well as letter — there is no `.await` here at all).
    pub fn serve_upload(&self, body: &[u8], now: Instant) -> ServeResult {
        let notices = self.sweep(now);

        if !self.audience.enabled() {
            return ServeResult::refused(
                notices,
                WithholdReason::LxmfPropagationDisabled,
                "upload",
                None,
            );
        }
        if body.len() > self.limits.max_upload_bytes {
            return ServeResult::refused(
                notices,
                WithholdReason::LxmfFrameOversized,
                "upload_bytes",
                None,
            );
        }
        let upload = match PropagationUpload::decode(body) {
            Ok(u) => u,
            Err(PropagationError::MultipleMessages) => {
                return ServeResult::refused(
                    notices,
                    WithholdReason::LxmfPeerSyncUnsupported,
                    "upload_offer_form",
                    None,
                );
            }
            Err(_) => {
                return ServeResult::refused(
                    notices,
                    WithholdReason::LxmfWireUnparseable,
                    "upload_envelope",
                    None,
                );
            }
        };

        // The recipient is read from the ciphertext's own framing, never
        // from anything the uploader asserts separately. Structurally
        // infallible after a successful `decode` — which guarantees
        // `unstamped.len() > LXMF_OVERHEAD`, exactly this call's
        // precondition — and pinned as such by
        // `decode_success_implies_readable_destination`.
        let Ok(propagated) = PropagatedMessage::from_unstamped_bytes(upload.unstamped_lxmf())
        else {
            return ServeResult::refused(
                notices,
                WithholdReason::LxmfWireUnparseable,
                "upload_destination",
                None,
            );
        };
        let destination = *propagated.destination_hash();

        if !self.audience.serves(&destination) {
            return ServeResult::refused(
                notices,
                WithholdReason::LxmfDestinationNotServed,
                "upload_recipient_off_roster",
                None,
            );
        }

        // Spam bound. Outside the lock, on the re-derived transient ID.
        if !self.stamp_clears_cost(upload.transient_id(), upload.propagation_stamp()) {
            return ServeResult::refused(
                notices,
                WithholdReason::LxmfStampBelowCost,
                "upload_stamp",
                Some(PropagationSignal::InvalidStamp.encode()),
            );
        }

        self.park(destination, &upload, now, notices)
    }

    /// Validate the outer propagation-node proof-of-work stamp against the
    /// cost this node advertises. `leviculum-lxmf` does the work; a stamp
    /// that does not clear the cost yields `Ok(None)`, and an engine error
    /// is treated as "did not clear" (fail-closed).
    fn stamp_clears_cost(&self, transient_id: &TransientId, stamp_bytes: &[u8; 32]) -> bool {
        let mut engine = CooperativeStamper::new(rand::rngs::OsRng, ReadyYield);
        futures::executor::block_on(stamp::validate(
            &mut engine,
            transient_id,
            stamp_bytes,
            self.limits.stamp_cost,
            WORKBLOCK_EXPAND_ROUNDS_PN,
            &[],
        ))
        .ok()
        .flatten()
        .is_some()
    }

    /// Capacity check and insert, atomically under the lock.
    ///
    /// Full means **refuse**, never evict — see the module docs.
    fn park(
        &self,
        destination: DestinationHash16,
        upload: &PropagationUpload,
        now: Instant,
        notices: Vec<Notice>,
    ) -> ServeResult {
        let limits = self.limits;
        let transient_id = *upload.transient_id();
        let ciphertext = upload.unstamped_lxmf().to_vec();
        let cost = ENTRY_OVERHEAD_BYTES + ciphertext.len();

        // Every ceiling is evaluated BEFORE any mutation, so a refused
        // upload leaves the mailbox byte-identical — in particular it
        // cannot leave an empty mailbox behind that would occupy the
        // destination budget.
        let full = self.with_state(|st| {
            let existing = st.boxes.get(&destination);
            if existing.is_none() && st.boxes.len() >= limits.max_destinations {
                return Some("upload_destination_cap");
            }
            // A repeat upload of a message already parked is idempotent, so
            // it is not charged against the depth cap and its old bytes are
            // credited back against the byte cap.
            let replacing = existing
                .and_then(|entries| entries.get(&transient_id))
                .map(|p| p.ciphertext.len());
            let depth = existing.map_or(0, BTreeMap::len);
            if replacing.is_none() && depth >= limits.max_messages_per_destination {
                return Some("upload_destination_depth");
            }
            let projected = st
                .bytes
                .saturating_sub(replacing.map_or(0, |n| ENTRY_OVERHEAD_BYTES + n))
                + cost;
            if projected > limits.max_store_bytes {
                return Some("upload_store_bytes");
            }
            st.boxes.entry(destination).or_default().insert(
                transient_id,
                Parked {
                    ciphertext,
                    stored_at: now,
                },
            );
            st.bytes = projected;
            None
        });

        match full {
            Some(detail) => {
                ServeResult::refused(notices, WithholdReason::LxmfMailboxFull, detail, None)
            }
            None => ServeResult {
                outcome: ServeOutcome::Admitted {
                    transient_id,
                    destination,
                },
                notices,
            },
        }
    }
}

/// The node's `/get` refusal reply: a bare `PeerError` code, which both
/// [`MessageListResponse`] and [`MessageGetResponse`] decode identically.
fn peer_error_list(error: PeerError) -> Vec<u8> {
    MessageListResponse::Error(error)
        .encode()
        .unwrap_or_default()
}

/// Wrap an encoder result into a response, degrading an encode failure into
/// a named refusal rather than a panic or an empty answer.
fn respond(encoded: Result<Vec<u8>, PropagationError>, notices: Vec<Notice>) -> ServeResult {
    match encoded {
        Ok(bytes) => ServeResult {
            outcome: ServeOutcome::Respond(bytes),
            notices,
        },
        Err(_) => ServeResult::refused(
            notices,
            WithholdReason::LxmfWireUnparseable,
            "response_encode",
            None,
        ),
    }
}

#[cfg(test)]
mod tests;
