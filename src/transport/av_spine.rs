//! The A/V spine — the runtime that drives ONE call from join to media
//! to heal (CIRISEdge#499 / the A/V-mesh flagship).
//!
//! # What was missing
//!
//! Every piece of a call already existed and was unit-tested: the MLS
//! group ([`AvSession`]), the media roles ([`AvPublisher`], [`AvRelay`],
//! [`AvSubscriber`]), the SFU roster + address-rotation window
//! ([`RelayNode`]), the derived-address table
//! ([`ScopeAddressTable`]), and the lifecycle that keeps the table and
//! the transport in step ([`ScopeLifecycle`]). Nothing *sequenced* them,
//! and the gap had a specific shape:
//!
//! **An epoch advance moved the keys and left the addresses behind.**
//! Every roster change re-derives every member's scoped address, because
//! the address is a function of the MLS epoch secret. [`AvPublisher`]'s
//! `admit_joiner` / `advance_epoch` roll the epoch and rotate the DEK —
//! and that is all they do. The lifecycle was never advanced, so this
//! node kept listening on an address no peer derives any more; the
//! relay's answerable window was never advanced, so it kept answering on
//! an address the table would no longer attribute. Neither half errors.
//! An RNS destination nobody registered is simply never delivered to,
//! and the call goes quiet with a clean log.
//!
//! # The shape
//!
//! [`AvSpine`] owns the three objects that must move together — the
//! publisher (which owns the session), the relay, and a handle to the
//! lifecycle — and exposes the call's verbs. Because it owns them, the
//! *only* way to advance a call's epoch is through a verb that
//! re-addresses it:
//!
//! ```text
//!   open      install the session's addresses; the relay is BORN at the
//!             installed address (it is never constructible at another)
//!   join      admit → MLS epoch → re-address → move the relay window
//!   subscribe a roster member becomes a relay subscriber
//!   publish   inner-seal ONCE → RelayNode::forward + the publisher's links
//!   heal      a dropped subscriber is re-admitted, pruned, or evicted
//!             (an eviction re-addresses, like any other epoch move)
//!   seal      the convergence window closes BOTH make-before-break
//!             windows on one deadline
//! ```
//!
//! ## Where the epoch-advance hook lives, and why here
//!
//! Not inside [`AvPublisher::advance_epoch`]. That verb is the MLS +
//! DEK move and is legitimately used with no addressing plane at all — a
//! subscriber applying a Commit, a test, a caller whose transport is
//! HTTP. Wiring the lifecycle into it would make every such caller carry
//! a `ScopeLifecycle` it has no use for, and would still not move the
//! relay window (not every node running a session relays it).
//!
//! So the hook is here, at the one place that holds all three, and the
//! stranding is closed *structurally* rather than by discipline: the
//! spine takes `AvPublisher` **by value** and hands back only `&`. Once
//! a call is inside a spine, `advance_epoch` is unreachable, so an epoch
//! cannot move without its addresses.
//!
//! ## Atomic from the caller's point of view
//!
//! An MLS commit cannot be un-committed, so "atomic" here means: the
//! caller never observes a state where the two address planes disagree.
//! The relay's window moves **only after, and only if,** the lifecycle
//! advance succeeded. If the advance fails, the relay is left exactly
//! where it was, so its answerable set still equals the table's
//! accept-set — the call is *degraded* (it serves what is live and
//! refuses to grow), never *half-live* (answering at an address nothing
//! attributes). The degradation is a named, queryable state
//! ([`StrandedEpoch`]), not a log line.
//!
//! ## Make-before-break, and what a rotation must never do
//!
//! A [`DestinationHash`] is used to *dial* and to *listen*, never per
//! chunk, and an established link is keyed by `LinkId`. Live links
//! therefore survive a rotation by construction, and the spine does not
//! touch them: `publish` after a rotation fans to the same relay
//! subscribers, on the same transit keys, with the same `link_seq`
//! counters. Retirement stops NEW dials at the superseded address; it is
//! deliberately not a link sweep.
//!
//! ## The relay never holds plaintext
//!
//! [`RelayNode`] has no [`EpochDek`] field and nothing reachable from it
//! does. The spine preserves that: it hands the relay an
//! [`InnerSealed`] — ciphertext under the epoch DEK — and the DEK itself
//! stays inside [`AvPublisher`]. `seal_next` runs on the publisher;
//! `forward` runs on the relay; the boundary between them is the one
//! this module is careful never to blur.
//!
//! [`EpochDek`]: super::realtime_av::EpochDek
//!
//! ## Locks and time (CIRISEdge#217)
//!
//! The spine holds **no locks at all**. Every verb takes `&mut self`, so
//! its state is reached by exclusive ownership and there is no guard in
//! existence to hold across an `.await`. That is the structural form of
//! the invariant, not an audited absence of one.
//!
//! Timing is likewise structural: no verb reads a clock. Every verb that
//! can close a convergence window takes `now: std::time::Instant` from
//! the caller, so the spine's deadline arithmetic is monotonic,
//! deterministic under test, and cannot reach a runtime timer. The spine
//! owns *what* seals and *when it is due*; the caller owns only what
//! time it is.
//!
//! ## The seal cadence
//!
//! [`ScopeLifecycle::seal_due`] is timing-driven and, before this
//! module, nothing called it — a superseded address stayed routable
//! forever. The spine drives it two ways, and neither needs a timer for
//! a call that is carrying media:
//!
//! 1. **Every verb seals first.** `join`, `subscribe`, `publish` and
//!    `heal` open by closing any window that is due. A live call
//!    publishes continuously, so the cadence rides the traffic that
//!    makes it necessary.
//! 2. **[`AvSpine::seal_deadline`]** is the single value an idle call's
//!    host loop must wait on. It is `None` when nothing is pending.
//!
//! Both halves close on ONE deadline: [`AvSpine::seal_due`] drops the
//! relay's superseded address on exactly the signal that dropped the
//! table's superseded epoch ([`ScopeLifecycle::seal_group_due`]), so the
//! two windows cannot end at different moments.
//!
//! [`AvSession`]: super::realtime_av_session::AvSession
//! [`AvRelay`]: super::realtime_av_runtime::AvRelay
//! [`AvSubscriber`]: super::realtime_av_runtime::AvSubscriber
//! [`ScopeAddressTable`]: crate::scope_addressing::ScopeAddressTable

use std::sync::Arc;
use std::time::Instant;

use leviculum_core::DestinationHash;
use leviculum_std::driver::ReticulumNode;

use crate::av_addressing::{self, AvAddressError};
use crate::cohort_scope::CohortScope;
use crate::scope_addressing::MemberAddress;
use crate::scope_lifecycle::{ScopeLifecycle, ScopeLifecycleError};

use super::federation_session::PeerKexPubkeys;
use super::realtime_av::{
    ChunkLayer, ChunkSeq, Epoch, InnerSealed, ReceiverLayerPolicy, StreamId, CODEC_OPAQUE,
};
use super::realtime_av_dispatcher::AvSubscriberLink;
use super::realtime_av_relay::{PeerKeyId, RelayError, RelayForwardOut, RelayNode};
use super::realtime_av_runtime::{AvPublisher, AvRuntimeError};
use super::realtime_av_session::RosterDelta;
use ciris_crypto::MlDsa65Signer;

// ─── errors ─────────────────────────────────────────────────────────

/// An MLS epoch that moved without its scoped addresses.
///
/// The call is **degraded**: live links keep running (a link is keyed by
/// `LinkId`, so a rotation never cut them), and both address planes
/// still agree with each other — but this node is not listening at the
/// live epoch's address, so nothing NEW can reach it. Verbs that would
/// grow the call's reachability refuse while this is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrandedEpoch {
    /// The MLS epoch the session reached.
    pub epoch: u64,
    /// Why its addresses did not follow.
    pub reason: String,
}

/// Why a spine verb refused.
#[derive(Debug, thiserror::Error)]
pub enum AvSpineError {
    /// The media / MLS tier refused (seal, dispatch, rekey, ALM).
    #[error("A/V runtime: {0}")]
    Runtime(#[from] AvRuntimeError),
    /// The session's destination secret could not be derived.
    #[error("session addressing: {0}")]
    Addressing(#[from] AvAddressError),
    /// The scope lifecycle refused the install or the advance.
    #[error("scope lifecycle: {0}")]
    Lifecycle(#[from] ScopeLifecycleError),
    /// The relay refused a roster operation.
    #[error("relay: {0}")]
    Relay(#[from] RelayError),
    /// The MLS epoch advanced and its addresses did not. The relay
    /// window was deliberately NOT moved, so the two planes still agree;
    /// see [`StrandedEpoch`].
    #[error("epoch {} advanced without its scoped addresses ({}) — the call serves its live \
             links but cannot be reached at the new epoch", .0.epoch, .0.reason)]
    AddressStranded(StrandedEpoch),
    /// A verb that would grow the call's reachability, refused because
    /// the call is stranded. Growing a call nobody can dial into would
    /// hand out addresses that answer nowhere.
    #[error("{verb} refused: the call is stranded at epoch {} ({})", .stranded.epoch, .stranded.reason)]
    Stranded {
        /// The verb that refused.
        verb: &'static str,
        /// The state it refused in.
        stranded: StrandedEpoch,
    },
    /// A peer that is not in the MLS roster cannot be a subscriber: it
    /// holds no epoch DEK, so every chunk forwarded to it is a chunk it
    /// cannot open, and the relay would be spending fan-out on a peer
    /// the group never admitted.
    #[error("{0} is not a member of this call — admit it via join before subscribing it")]
    NotAMember(PeerKeyId),
    /// A relay verb on a node that does not relay this stream.
    #[error("this node does not relay stream {0:?} — open the spine with a relay node")]
    NoRelay(StreamId),
}

// ─── outcomes ───────────────────────────────────────────────────────

/// What an address move did. Returned inside every verb that advances an
/// epoch, so a caller can assert on the move rather than infer it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct Readdressed {
    /// The epoch now live for sending.
    pub epoch: u64,
    /// Addresses derived for this epoch (one per member).
    pub derived: usize,
    /// This node's address at `epoch` — registered, and the relay's new
    /// send address when this node relays.
    pub own_address: MemberAddress,
    /// Whether the relay's answerable window moved with it. `false` only
    /// when this node does not relay the stream.
    pub relay_window_moved: bool,
    /// An address pushed out of the relay's answerable window EARLY,
    /// because a second rotation landed inside one convergence window
    /// (three people joining a call in five minutes does it). The relay
    /// holds one superseded address, so the oldest leaves; a peer still
    /// dialling it re-dials at the live epoch. Reported rather than
    /// asserted away — the table reports the same eviction as
    /// `EpochTransition::evicted`.
    pub relay_evicted_early: Option<[u8; 16]>,
}

/// Everything a joiner needs to enter the call, plus the proof its
/// admission moved the addresses.
#[derive(Debug)]
#[must_use]
pub struct JoinTicket {
    /// The admitted member.
    pub joiner: PeerKeyId,
    /// The epoch its admission created.
    pub epoch: Epoch,
    /// MLS Commit — for the members already in the call.
    pub commit_bytes: Vec<u8>,
    /// MLS Welcome — for the joiner. Carries the inviter's ML-DSA-65
    /// signature (CIRISEdge#331), so the joiner verifies who admitted it
    /// directory-only, with no TOFU.
    pub welcome_bytes: Vec<u8>,
    /// Where the joiner dials to reach this node at the new epoch. When
    /// this node relays the stream, this is also the relay's send
    /// address — the two are the same value by construction, not by
    /// convention.
    pub dial_address: MemberAddress,
    /// The address the joiner will present at this epoch, derived here
    /// so this node can dial it. The joiner derives the same bytes from
    /// its own session (RFC 9420 §8.5 makes the exporter epoch-
    /// deterministic); nothing secret is disclosed by naming it.
    pub joiner_address: Option<MemberAddress>,
    /// The address move the admission performed.
    pub readdressed: Readdressed,
}

/// A member registered on the relay's roster for this stream.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct Subscribed {
    /// The subscriber.
    pub subscriber: PeerKeyId,
    /// The epoch it subscribed at.
    pub epoch: Epoch,
    /// The relay address it dials.
    pub dial_address: MemberAddress,
    /// Relay subscribers on this stream after the registration.
    pub roster: usize,
}

/// One fan-out leg's result. A leg's failure is reported, never allowed
/// to cancel the other leg's delivery (CIRISEdge#425 — no silent drop,
/// and no silent *un*-drop either).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegOutcome {
    /// Nothing to do on this leg — no relay, or no links.
    Idle,
    /// Fanned to `reached` destinations.
    Delivered {
        /// Destinations the chunk reached.
        reached: usize,
    },
    /// The leg failed. The chunk may have reached some destinations
    /// before it did.
    Failed {
        /// Destinations reached before the failure, where the leg can
        /// say. `RelayNode::forward` seals the whole roster or none of
        /// it, so it is exact there; the publisher's dispatcher stops at
        /// the first failing subscriber without reporting how many
        /// preceded it, so it is `0` there and means "unknown, at least
        /// one link did not get it" rather than "none did".
        reached: usize,
        /// The refusal, rendered.
        error: String,
    },
}

impl LegOutcome {
    /// Destinations this leg reached.
    #[must_use]
    pub fn reached(&self) -> usize {
        match self {
            Self::Idle => 0,
            Self::Delivered { reached } | Self::Failed { reached, .. } => *reached,
        }
    }

    /// Whether this leg failed.
    #[must_use]
    pub fn failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

/// The result of publishing one chunk through the spine.
///
/// Both legs are reported because a chunk is inner-sealed ONCE and
/// handed to both: returning `Err` on one leg's failure would silently
/// discard the other leg's already-sealed wire bytes.
#[derive(Debug)]
#[must_use]
pub struct Fanout {
    /// The sequence the chunk was stamped with.
    pub chunk_seq: ChunkSeq,
    /// The epoch it was sealed under.
    pub epoch: Epoch,
    /// Wire-ready sealed bytes, one per ADMITTED relay subscriber, for
    /// the caller's Layer-2 dispatch. Empty when this node does not
    /// relay the stream.
    pub relayed: Vec<RelayForwardOut>,
    /// Relay subscribers whose layer policy withheld this chunk. The
    /// relay skips them silently inside `forward`; the spine counts the
    /// difference so a withheld chunk is a number rather than a
    /// non-event (CIRISEdge#425).
    pub relay_withheld: usize,
    /// The relay leg.
    pub relay: LegOutcome,
    /// The publisher's own downstream links (the hop to a REMOTE relay,
    /// when this node is not the relay).
    pub direct: LegOutcome,
    /// Set when the call is serving live links at a superseded epoch.
    pub stranded: Option<StrandedEpoch>,
    /// Any convergence window this publish closed on its way in.
    pub sealed: SpineSeal,
}

/// Why a dropped subscriber was pruned rather than re-admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruneReason {
    /// It is no longer in the MLS roster, so there is nothing to
    /// re-admit it to — it holds no epoch DEK.
    NotAMember,
    /// The caller classified the drop as recoverable but offered no
    /// re-dial material, so the relay cannot re-key the hop.
    NoRedialOffered,
}

/// How the caller classified a subscriber's disappearance.
///
/// The spine does **not** infer this. Whether a dropped link is a
/// transient fault or a departure is a policy question — how many
/// consecutive failures, over what window, count as gone — and neither
/// CIRISPersist nor CIRISVerify supplies that rule, so edge must not
/// invent one. The caller classifies; the spine executes, and each
/// classification has exactly one correct convergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropCause {
    /// The hop failed but the peer is still on the call. Re-key the hop;
    /// do NOT move the epoch (a rekey per flaky link would churn every
    /// member's address for one peer's Wi-Fi).
    LinkFailure,
    /// The peer left. Forward secrecy requires it out of the MLS group,
    /// which moves the epoch and therefore the addresses.
    Departed,
}

/// Re-dial material for a [`DropCause::LinkFailure`] heal.
pub struct Redial {
    /// The freshly-KEX'd per-(subscriber, stream) transit key. A re-dial
    /// is a new link, so it is a new transit key; re-using the old one
    /// across a re-dial would restart a keystream under a used key.
    pub transit_key: [u8; 32],
    /// The subscriber's layer-admission cap on the new hop.
    pub layer_policy: ReceiverLayerPolicy,
}

impl std::fmt::Debug for Redial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redial")
            .field("transit_key", &"<redacted>")
            .field("layer_policy", &self.layer_policy)
            .finish()
    }
}

/// A subscriber that stopped receiving, and how the caller classified
/// it.
#[derive(Debug)]
pub struct SubscriberDrop {
    /// The subscriber that dropped.
    pub subscriber: PeerKeyId,
    /// The caller's classification.
    pub cause: DropCause,
    /// Re-dial material. Required to re-admit a
    /// [`DropCause::LinkFailure`]; ignored for a departure.
    pub redial: Option<Redial>,
}

/// How a drop converged. Every branch is named — a heal never ends in a
/// bare `continue` (CIRISEdge#425).
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum HealOutcome {
    /// Re-keyed onto a fresh hop. The roster and the addresses did not
    /// move: the peer never left, so nothing about the group changed.
    Readmitted {
        /// The re-admitted subscriber.
        subscriber: PeerKeyId,
        /// The epoch it rejoined at (unchanged).
        epoch: Epoch,
    },
    /// Removed from the relay roster only. The MLS group is untouched
    /// because the peer was already out of it (or never in it).
    RosterPruned {
        /// The pruned subscriber.
        subscriber: PeerKeyId,
        /// Why pruning was the right convergence.
        reason: PruneReason,
    },
    /// Removed from the MLS group: the epoch advanced, every member's
    /// address moved with it, and the seal is scheduled.
    Evicted {
        /// The evicted member.
        subscriber: PeerKeyId,
        /// Whether it was also on the relay roster.
        was_subscribed: bool,
        /// The address move the eviction performed.
        readdressed: Readdressed,
    },
}

/// What a seal pass closed. `Default` is "nothing was due".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[must_use]
pub struct SpineSeal {
    /// The table dropped this group's superseded epoch.
    pub sealed: bool,
    /// The superseded destination could NOT be retired from the
    /// transport — it stays routable despite being sealed. Zero in a
    /// healthy deployment since leviculum#54; a `true` here is the
    /// reachability-disclosure alarm.
    pub unretired: bool,
    /// The relay's superseded answerable address, dropped by this seal.
    pub relay_retired: Option<[u8; 16]>,
    /// The table refused the seal, so the relay's window was deliberately
    /// left open too — closing one plane without the other is the drift
    /// this whole module exists to prevent.
    pub table_refused: bool,
}

/// A call's live state, for a health endpoint or a test.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct SpineHealth {
    /// The stream.
    pub stream_id: StreamId,
    /// The live MLS epoch.
    pub epoch: Epoch,
    /// MLS roster size.
    pub members: usize,
    /// Relay subscribers on this stream.
    pub relay_subscribers: usize,
    /// This node's registered address at the live epoch.
    pub own_address: [u8; 16],
    /// Every address the relay currently answers on — one outside a
    /// rotation window, two inside one. Empty when this node does not
    /// relay.
    pub relay_answers: Vec<[u8; 16]>,
    /// Set when the call is serving live links at a superseded epoch.
    pub stranded: Option<StrandedEpoch>,
    /// When the pending convergence window closes, if one is open.
    pub seal_deadline: Option<Instant>,
}

/// A joiner's admission material.
pub struct Joiner<'a> {
    /// The joiner's federation key id.
    pub key_id: &'a str,
    /// The KeyPackage it published to the federation directory.
    pub key_package: openmls::prelude::KeyPackage,
    /// Its advertised hybrid KEX pubkeys — the Welcome is wrapped to
    /// these.
    pub kex: &'a PeerKexPubkeys,
    /// This node's long-term ML-DSA-65 federation signer. The Welcome
    /// carries its signature so the joiner can prove who invited it
    /// (CIRISEdge#331 / CC 5.4.4).
    pub inviter_signer: &'a MlDsa65Signer,
    /// This node's directory pk_id, so the joiner can resolve the key
    /// that signature verifies against.
    pub inviter_pk_id: &'a str,
}

// ─── the spine ──────────────────────────────────────────────────────

/// One call's lifecycle: the publisher, the relay, and the addresses,
/// driven together.
///
/// See the module head for the shape and the invariants. The type holds
/// no locks and reads no clock.
pub struct AvSpine {
    scope: CohortScope,
    group_id: String,
    lifecycle: Arc<ScopeLifecycle>,
    /// Owned by value: this is what makes `advance_epoch` unreachable
    /// from outside, and therefore what makes an un-addressed epoch move
    /// unrepresentable.
    publisher: AvPublisher,
    /// `None` when this node is on the call but does not relay it.
    relay: Option<RelayNode>,
    own_address: MemberAddress,
    stranded: Option<StrandedEpoch>,
}

impl AvSpine {
    /// Stand a call up: install the session's scoped addresses, and — if
    /// this node relays the stream — mint the relay AT the installed
    /// address.
    ///
    /// `relay_node` is the leviculum node the relay rides. The spine
    /// constructs the [`RelayNode`] itself rather than taking one,
    /// because a relay's address must be a derived, scope-native one
    /// from its first instant: a relay built at some other address would
    /// answer on a hash the table never installed, which is exactly the
    /// disagreement this module exists to make impossible. Pass `None`
    /// for a node that publishes or subscribes without relaying.
    ///
    /// # Errors
    ///
    /// [`AvSpineError::Addressing`] if the session's destination secret
    /// cannot be derived; [`AvSpineError::Lifecycle`] if the table
    /// refuses the install or the transport refuses to listen (in which
    /// case the install is rolled back — the call is not created
    /// half-live).
    pub fn open(
        scope: CohortScope,
        lifecycle: Arc<ScopeLifecycle>,
        publisher: AvPublisher,
        relay_node: Option<Arc<ReticulumNode>>,
    ) -> Result<Self, AvSpineError> {
        let group_id = av_addressing::session_group_id(publisher.session());
        let installed = {
            let snapshot = av_addressing::snapshot(publisher.session())?;
            lifecycle.install(&scope, &snapshot)?
        };
        let relay = relay_node.map(|node| {
            RelayNode::new(
                node,
                DestinationHash::new(*installed.own_address.as_bytes()),
            )
        });
        tracing::info!(
            stream = ?publisher.stream_id(),
            group = %group_id,
            epoch = installed.epoch,
            derived = installed.derived,
            relays = relay.is_some(),
            "AV spine: call opened — scoped addresses installed"
        );
        Ok(Self {
            scope,
            group_id,
            lifecycle,
            publisher,
            relay,
            own_address: installed.own_address,
            stranded: None,
        })
    }

    // ── reads ───────────────────────────────────────────────────────

    /// The stream this spine drives.
    #[must_use]
    pub fn stream_id(&self) -> StreamId {
        self.publisher.stream_id()
    }

    /// The live MLS epoch.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.publisher.epoch()
    }

    /// This node's registered address at the live epoch.
    #[must_use]
    pub fn own_address(&self) -> &MemberAddress {
        &self.own_address
    }

    /// The publisher, read-only. Deliberately no `&mut`: handing one out
    /// would re-open `advance_epoch` and with it the un-addressed epoch
    /// move this module closes.
    #[must_use]
    pub fn publisher(&self) -> &AvPublisher {
        &self.publisher
    }

    /// The relay, read-only, when this node relays the stream.
    #[must_use]
    pub fn relay(&self) -> Option<&RelayNode> {
        self.relay.as_ref()
    }

    /// The call's degraded state, if it has one.
    #[must_use]
    pub fn stranded(&self) -> Option<&StrandedEpoch> {
        self.stranded.as_ref()
    }

    /// Whether `key_id` is in the call's MLS roster.
    #[must_use]
    pub fn is_member(&self, key_id: &str) -> bool {
        self.publisher
            .session()
            .member_key_ids()
            .iter()
            .any(|m| m == key_id)
    }

    /// A snapshot of the call, for a health endpoint or an assertion.
    pub fn health(&self) -> SpineHealth {
        let stream_id = self.publisher.stream_id();
        let relay_answers = self.relay.as_ref().map_or_else(Vec::new, |r| {
            let mut answers = vec![*r.address().as_bytes()];
            if let Some(sup) = r.superseded_address() {
                answers.push(*sup.as_bytes());
            }
            answers
        });
        SpineHealth {
            stream_id,
            epoch: self.publisher.epoch(),
            members: self.publisher.session().member_key_ids().len(),
            relay_subscribers: self
                .relay
                .as_ref()
                .map_or(0, |r| r.subscriber_count(stream_id)),
            own_address: *self.own_address.as_bytes(),
            relay_answers,
            stranded: self.stranded.clone(),
            seal_deadline: self.seal_deadline(),
        }
    }

    // ── the seal cadence ────────────────────────────────────────────

    /// When this call's pending convergence window closes, or `None`
    /// when no rotation is pending.
    ///
    /// The one value an idle call's host loop needs to wait on. A call
    /// that is carrying media never needs it: every verb seals first.
    #[must_use]
    pub fn seal_deadline(&self) -> Option<Instant> {
        self.lifecycle.seal_deadline(&self.scope, &self.group_id)
    }

    /// Close this call's convergence window if it is due.
    ///
    /// Retires **exactly** the superseded address, on both planes, on one
    /// deadline: the table's superseded epoch and the relay's superseded
    /// answerable address are dropped together, because the relay's drop
    /// is conditioned on the table's. The live address is never touched
    /// — the relay's send address and the table's current epoch are not
    /// part of what a seal removes.
    ///
    /// Idempotent, and cheap when nothing is due. Called at the head of
    /// every other verb, so a caller normally never calls it directly.
    pub fn seal_due(&mut self, now: Instant) -> SpineSeal {
        let Some(table) = self
            .lifecycle
            .seal_group_due(&self.scope, &self.group_id, now)
        else {
            return SpineSeal::default();
        };
        if table.sealed == 0 {
            // The table refused. Dropping the relay's superseded address
            // now would leave the relay deaf at an epoch the table still
            // attributes — the exact drift the lifecycle exists to
            // prevent — so both windows stay open and say so.
            tracing::warn!(
                group = %self.group_id,
                "AV spine seal: the table refused this group's seal, so the relay's \
                 answerable window is deliberately left OPEN too — both planes stay at \
                 the superseded epoch rather than disagreeing (CIRISEdge#499)"
            );
            return SpineSeal {
                sealed: false,
                unretired: table.unretired > 0,
                relay_retired: None,
                table_refused: true,
            };
        }
        let relay_retired = self
            .relay
            .as_mut()
            .and_then(RelayNode::seal_address_rotation)
            .map(|d| *d.as_bytes());
        tracing::info!(
            group = %self.group_id,
            unretired = table.unretired,
            relay_retired = relay_retired.is_some(),
            "AV spine seal: convergence window closed on both planes"
        );
        SpineSeal {
            sealed: true,
            unretired: table.unretired > 0,
            relay_retired,
            table_refused: false,
        }
    }

    // ── join ────────────────────────────────────────────────────────

    /// Admit a joiner, advance the epoch, re-address the call, and hand
    /// back everything the joiner needs to dial in.
    ///
    /// The MLS add, the address move and the relay-window move are one
    /// step from the caller's point of view: either the ticket names a
    /// converged epoch, or the error names the degradation and the two
    /// address planes still agree with each other.
    ///
    /// # Errors
    ///
    /// [`AvSpineError::Stranded`] when the call cannot currently be
    /// reached at its live epoch — admitting a joiner would hand it an
    /// address that answers nowhere. [`AvSpineError::Runtime`] if the
    /// MLS add fails (it is refused before the epoch moves, e.g. a
    /// joiner without ML-KEM-768). [`AvSpineError::AddressStranded`] if
    /// the epoch moved but its addresses could not.
    pub fn join(&mut self, joiner: Joiner<'_>, now: Instant) -> Result<JoinTicket, AvSpineError> {
        let sealed = self.seal_due(now);
        self.refuse_if_stranded("join")?;

        let mut artifacts = self.publisher.admit_joiner(
            joiner.key_id,
            joiner.key_package,
            joiner.kex,
            joiner.inviter_signer,
            joiner.inviter_pk_id,
        )?;
        // From here the MLS epoch HAS moved. `readdress` either moves both
        // address planes with it or leaves both where they were.
        let readdressed = self.readdress(now)?;

        let welcome_bytes = if artifacts.welcome_bytes.is_empty() {
            // An Add always emits exactly one Welcome; an empty vec would
            // mean the joiner can never bootstrap, which is a refusal, not
            // a quiet zero.
            return Err(AvSpineError::AddressStranded(StrandedEpoch {
                epoch: readdressed.epoch,
                reason: format!("MLS emitted no Welcome for joiner {}", joiner.key_id),
            }));
        } else {
            std::mem::take(&mut artifacts.welcome_bytes[0])
        };

        tracing::info!(
            stream = ?self.publisher.stream_id(),
            peer = %joiner.key_id,
            epoch = readdressed.epoch,
            derived = readdressed.derived,
            relay_window_moved = readdressed.relay_window_moved,
            sealed = sealed.sealed,
            "AV spine JOIN: joiner admitted, epoch + addresses moved together"
        );
        Ok(JoinTicket {
            joiner: joiner.key_id.to_owned(),
            epoch: artifacts.new_epoch,
            commit_bytes: std::mem::take(&mut artifacts.commit_bytes),
            welcome_bytes,
            dial_address: readdressed.own_address,
            joiner_address: self.address_of(joiner.key_id, readdressed.epoch),
            readdressed,
        })
    }

    // ── subscribe ───────────────────────────────────────────────────

    /// Register a call member as a downstream subscriber on this node's
    /// relay.
    ///
    /// Narrowed to the MLS roster on purpose: a non-member holds no
    /// epoch DEK, so every chunk the relay would seal for it is a chunk
    /// it cannot open. Refusing here keeps fan-out spent only on peers
    /// the group admitted.
    ///
    /// Idempotent on `subscriber` — re-subscribing replaces the transit
    /// key and the layer policy, zeroizing the old key.
    ///
    /// # Errors
    ///
    /// [`AvSpineError::NoRelay`] if this node does not relay the stream;
    /// [`AvSpineError::NotAMember`] if the peer is not on the call;
    /// [`AvSpineError::Stranded`] if the call cannot be dialled at its
    /// live epoch.
    pub fn subscribe(
        &mut self,
        subscriber: &PeerKeyId,
        transit_key: [u8; 32],
        layer_policy: ReceiverLayerPolicy,
        now: Instant,
    ) -> Result<Subscribed, AvSpineError> {
        let _sealed = self.seal_due(now);
        self.refuse_if_stranded("subscribe")?;
        if !self.is_member(subscriber) {
            tracing::warn!(
                stream = ?self.publisher.stream_id(),
                peer = %subscriber,
                "AV spine SUBSCRIBE refused: not in the call's MLS roster — it holds no \
                 epoch DEK, so every forwarded chunk would be unopenable (CIRISEdge#425)"
            );
            return Err(AvSpineError::NotAMember(subscriber.clone()));
        }
        let stream_id = self.publisher.stream_id();
        let epoch = self.publisher.epoch();
        let dial_address = self.own_address;
        let relay = self
            .relay
            .as_mut()
            .ok_or(AvSpineError::NoRelay(stream_id))?;
        relay.subscribe(stream_id, subscriber.clone(), transit_key, layer_policy)?;
        let roster = relay.subscriber_count(stream_id);
        tracing::info!(
            stream = ?stream_id,
            peer = %subscriber,
            epoch = epoch.0,
            roster,
            "AV spine SUBSCRIBE: member registered on the relay roster"
        );
        Ok(Subscribed {
            subscriber: subscriber.clone(),
            epoch,
            dial_address,
            roster,
        })
    }

    /// Attach a downstream link to the PUBLISHER's own dispatcher — the
    /// hop toward a remote relay, for a node that publishes without
    /// relaying.
    ///
    /// # Errors
    ///
    /// [`AvSpineError::Runtime`] if the dispatcher refuses the link.
    pub fn attach_downstream(&mut self, link: AvSubscriberLink) -> Result<(), AvSpineError> {
        self.publisher.add_subscriber(link)?;
        Ok(())
    }

    /// Detach a downstream publisher link.
    pub fn detach_downstream(&mut self, subscriber: &PeerKeyId) {
        self.publisher.remove_subscriber(subscriber);
    }

    // ── relay / publish ─────────────────────────────────────────────

    /// Inner-seal one opaque chunk and fan it through both legs.
    ///
    /// # Errors
    ///
    /// [`AvSpineError::Runtime`] if the inner seal fails — the only
    /// failure that means nothing was emitted anywhere. A leg's failure
    /// is reported in [`Fanout`], not raised, so one leg's refusal never
    /// discards the other leg's already-sealed bytes.
    pub async fn publish(
        &mut self,
        plaintext: &[u8],
        now: Instant,
    ) -> Result<Fanout, AvSpineError> {
        self.publish_chunk(plaintext, CODEC_OPAQUE, ChunkLayer::BASE, now)
            .await
    }

    /// Inner-seal one chunk under the live epoch DEK and fan the SAME
    /// ciphertext through the relay roster ([`RelayNode::forward`]) and
    /// the publisher's own links.
    ///
    /// One inner seal, two fan-outs — the CIRISEdge#122 shape. The relay
    /// leg receives an [`InnerSealed`]: ciphertext under a DEK the relay
    /// does not have and cannot reach.
    ///
    /// A rotation does not interrupt this. Subscribers keep their
    /// transit keys and their `link_seq` counters across an epoch move,
    /// because a live link is keyed by `LinkId` and was never dialled
    /// again.
    ///
    /// # Errors
    ///
    /// [`AvSpineError::Runtime`] on inner-seal failure.
    pub async fn publish_chunk(
        &mut self,
        plaintext: &[u8],
        codec_id: u8,
        layer: ChunkLayer,
        now: Instant,
    ) -> Result<Fanout, AvSpineError> {
        let sealed = self.seal_due(now);
        let (chunk_seq, inner) = self.publisher.seal_next(plaintext, codec_id, layer)?;
        let stream_id = self.publisher.stream_id();

        let (relayed, relay_withheld, relay) =
            Self::forward_leg(self.relay.as_mut(), stream_id, &inner);

        // `inner` moves into the dispatcher here. Nothing borrowed from
        // `self.relay` is alive across this await — the relay leg is
        // fully resolved into owned values above (CIRISEdge#217).
        let direct = match self.publisher.dispatch_inner(inner).await {
            Ok(0) => LegOutcome::Idle,
            Ok(reached) => LegOutcome::Delivered { reached },
            Err(e) => {
                tracing::warn!(
                    stream = ?stream_id,
                    chunk_seq = chunk_seq.0,
                    error = %e,
                    "AV spine publish: the publisher's own links FAILED — the relay leg's \
                     result stands (CIRISEdge#425)"
                );
                LegOutcome::Failed {
                    reached: 0,
                    error: e.to_string(),
                }
            }
        };

        Ok(Fanout {
            chunk_seq,
            epoch: self.publisher.epoch(),
            relayed,
            relay_withheld,
            relay,
            direct,
            stranded: self.stranded.clone(),
            sealed,
        })
    }

    /// The relay fan-out leg, resolved to owned values so no borrow of
    /// the relay can outlive it into an `.await`.
    fn forward_leg(
        relay: Option<&mut RelayNode>,
        stream_id: StreamId,
        inner: &InnerSealed,
    ) -> (Vec<RelayForwardOut>, usize, LegOutcome) {
        let Some(relay) = relay else {
            return (Vec::new(), 0, LegOutcome::Idle);
        };
        let roster = relay.subscriber_count(stream_id);
        if roster == 0 {
            return (Vec::new(), 0, LegOutcome::Idle);
        }
        match relay.forward(stream_id, inner) {
            Ok(out) => {
                // `forward` skips a policy-refused subscriber with a bare
                // `continue`; the shortfall is the only evidence it
                // happened, so the spine counts it rather than let a
                // withheld chunk read as absence-of-work.
                let withheld = roster.saturating_sub(out.len());
                if withheld > 0 {
                    tracing::info!(
                        stream = ?stream_id,
                        chunk_seq = inner.chunk_seq().0,
                        withheld,
                        roster,
                        "AV spine relay: chunk WITHHELD from subscribers by their layer \
                         policy (not a loss — CIRISEdge#128 admission)"
                    );
                }
                let reached = out.len();
                (out, withheld, LegOutcome::Delivered { reached })
            }
            Err(e) => {
                tracing::warn!(
                    stream = ?stream_id,
                    chunk_seq = inner.chunk_seq().0,
                    error = %e,
                    "AV spine relay: fan-out FAILED — no downstream subscriber received this \
                     chunk (CIRISEdge#425)"
                );
                (
                    Vec::new(),
                    0,
                    LegOutcome::Failed {
                        reached: 0,
                        error: e.to_string(),
                    },
                )
            }
        }
    }

    // ── heal ────────────────────────────────────────────────────────

    /// Converge the call around a subscriber that stopped receiving.
    ///
    /// Three convergences, one per classification, all named:
    ///
    /// - a recoverable drop of a still-current member → **re-admitted**
    ///   on a fresh transit key, with the epoch untouched;
    /// - a drop of a peer that is no longer in the MLS roster, or a
    ///   recoverable drop with no re-dial material → **pruned** from the
    ///   relay roster;
    /// - a departure → **evicted** from MLS, which advances the epoch
    ///   and re-addresses the call exactly as a join does.
    ///
    /// A departure is executed even when the call is stranded: leaving a
    /// departed member keyed is a forward-secrecy failure, and the
    /// eviction's own re-address either lifts the degradation or leaves
    /// it named.
    ///
    /// # Errors
    ///
    /// [`AvSpineError::NoRelay`] for a heal on a non-relaying node;
    /// [`AvSpineError::Runtime`] if the MLS remove fails;
    /// [`AvSpineError::AddressStranded`] if an eviction's epoch moved but
    /// its addresses could not.
    pub fn heal(
        &mut self,
        drop: SubscriberDrop,
        now: Instant,
    ) -> Result<HealOutcome, AvSpineError> {
        let _sealed = self.seal_due(now);
        let stream_id = self.publisher.stream_id();
        if self.relay.is_none() {
            return Err(AvSpineError::NoRelay(stream_id));
        }
        let still_a_member = self.is_member(&drop.subscriber);

        match drop.cause {
            DropCause::LinkFailure => {
                let reason = if still_a_member {
                    match drop.redial {
                        Some(redial) => {
                            let relay = self
                                .relay
                                .as_mut()
                                .ok_or(AvSpineError::NoRelay(stream_id))?;
                            relay.subscribe(
                                stream_id,
                                drop.subscriber.clone(),
                                redial.transit_key,
                                redial.layer_policy,
                            )?;
                            tracing::info!(
                                stream = ?stream_id,
                                peer = %drop.subscriber,
                                epoch = self.publisher.epoch().0,
                                "AV spine HEAL: subscriber re-admitted on a fresh hop — the \
                                 epoch did NOT move (a rekey per flaky link would churn every \
                                 member's address for one peer's radio)"
                            );
                            return Ok(HealOutcome::Readmitted {
                                subscriber: drop.subscriber,
                                epoch: self.publisher.epoch(),
                            });
                        }
                        None => PruneReason::NoRedialOffered,
                    }
                } else {
                    PruneReason::NotAMember
                };
                self.prune_from_relay(&drop.subscriber, stream_id);
                tracing::warn!(
                    stream = ?stream_id,
                    peer = %drop.subscriber,
                    ?reason,
                    "AV spine HEAL: subscriber PRUNED from the relay roster (CIRISEdge#425)"
                );
                Ok(HealOutcome::RosterPruned {
                    subscriber: drop.subscriber,
                    reason,
                })
            }
            DropCause::Departed => {
                let was_subscribed = self.prune_from_relay(&drop.subscriber, stream_id);
                if !still_a_member {
                    tracing::warn!(
                        stream = ?stream_id,
                        peer = %drop.subscriber,
                        "AV spine HEAL: departure of a peer already out of the MLS roster — \
                         relay roster pruned, no epoch move (CIRISEdge#425)"
                    );
                    return Ok(HealOutcome::RosterPruned {
                        subscriber: drop.subscriber,
                        reason: PruneReason::NotAMember,
                    });
                }
                // Forward secrecy: the departed member must not hold the
                // DEK that seals the next chunk. This moves the epoch,
                // so it re-addresses exactly like a join.
                self.publisher
                    .advance_epoch(RosterDelta::Leave(drop.subscriber.clone()))?;
                let readdressed = self.readdress(now)?;
                tracing::info!(
                    stream = ?stream_id,
                    peer = %drop.subscriber,
                    epoch = readdressed.epoch,
                    was_subscribed,
                    relay_window_moved = readdressed.relay_window_moved,
                    "AV spine HEAL: member EVICTED — epoch + addresses moved together"
                );
                Ok(HealOutcome::Evicted {
                    subscriber: drop.subscriber,
                    was_subscribed,
                    readdressed,
                })
            }
        }
    }

    // ── internals ───────────────────────────────────────────────────

    /// **The hook.** Move both address planes onto the epoch the session
    /// just reached.
    ///
    /// Order is the whole point. The lifecycle goes first, because it is
    /// the one that can fail: it derives the new addresses, activates
    /// them for sending, registers this node's own with the transport,
    /// and schedules the seal. Only once it has succeeded does the
    /// relay's answerable window move — so the relay can never be
    /// answering on an address the table never installed, and a failure
    /// leaves the two planes agreeing with each other at the superseded
    /// epoch rather than disagreeing across it.
    fn readdress(&mut self, now: Instant) -> Result<Readdressed, AvSpineError> {
        let advanced = {
            let snapshot = av_addressing::snapshot(self.publisher.session())?;
            let epoch = snapshot.epoch;
            match self.lifecycle.advance(&self.scope, &snapshot, now) {
                Ok(outcome) => outcome,
                Err(e) => {
                    let stranded = StrandedEpoch {
                        epoch,
                        reason: e.to_string(),
                    };
                    tracing::error!(
                        stream = ?self.publisher.stream_id(),
                        group = %self.group_id,
                        epoch,
                        error = %e,
                        "AV spine: the MLS epoch advanced and its scoped addresses did NOT. \
                         The relay's answerable window is deliberately left where it is, so \
                         both planes still agree; live links keep running and the call \
                         refuses to grow until this is resolved (CIRISEdge#499/#425)"
                    );
                    self.stranded = Some(stranded.clone());
                    return Err(AvSpineError::AddressStranded(stranded));
                }
            }
        };

        let mut relay_evicted_early = None;
        let relay_window_moved = if let Some(relay) = self.relay.as_mut() {
            relay_evicted_early =
                av_addressing::advance_relay_window(relay, &advanced).map(|d| *d.as_bytes());
            true
        } else {
            false
        };
        if relay_evicted_early.is_some() {
            tracing::info!(
                stream = ?self.publisher.stream_id(),
                group = %self.group_id,
                epoch = advanced.epoch,
                "AV spine: a second rotation inside one convergence window pushed the                  oldest address out of the relay's answerable window early — a peer                  still dialling it re-dials at the live epoch (CIRISEdge#499)"
            );
        }

        self.own_address = advanced.own_address;
        self.stranded = None;
        Ok(Readdressed {
            epoch: advanced.epoch,
            derived: advanced.derived,
            own_address: advanced.own_address,
            relay_window_moved,
            relay_evicted_early,
        })
    }

    /// Refuse a verb that would grow the call's reachability while the
    /// call cannot be reached at its live epoch.
    fn refuse_if_stranded(&self, verb: &'static str) -> Result<(), AvSpineError> {
        if let Some(stranded) = self.stranded.clone() {
            tracing::warn!(
                stream = ?self.publisher.stream_id(),
                verb,
                epoch = stranded.epoch,
                "AV spine: verb REFUSED — the call is stranded at a superseded epoch, so \
                 anything it handed out would name an address that answers nowhere"
            );
            return Err(AvSpineError::Stranded { verb, stranded });
        }
        Ok(())
    }

    /// Drop a subscriber from the relay roster. Returns whether it was
    /// there. A `SubscriberNotFound` is the expected answer for a peer
    /// that never subscribed, so it is reported as `false` rather than
    /// raised.
    fn prune_from_relay(&mut self, subscriber: &PeerKeyId, stream_id: StreamId) -> bool {
        let Some(relay) = self.relay.as_mut() else {
            return false;
        };
        relay.unsubscribe(stream_id, subscriber).is_ok()
    }

    /// A member's derived address at `epoch`, if the table holds one.
    fn address_of(&self, key_id: &str, epoch: u64) -> Option<MemberAddress> {
        self.lifecycle
            .table()
            .address_at(&self.scope, &self.group_id, epoch, key_id)
    }
}

#[cfg(test)]
mod tests;
