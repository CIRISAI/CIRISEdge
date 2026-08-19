//! CIRISEdge workstream F — the fail-closed **accord relay gate**: may THIS
//! node carry a given `accord:*` object?
//!
//! ## Projection decides who may HOLD; relay decides who may CARRY
//!
//! `accord:*` resolves [`Projection::Global`](ciris_persist::federation::namespace::Projection)
//! at every commons tier (CIRISPersist v36.2.0 / #713) and that row is
//! **correct for carriage**: an accord act is not a single emission but m-of-n
//! over a live roster, assembled by partial-quorum objects replicating until
//! they meet. A partial is emitted PRE-AUTHORITY, and the roster's cohort span
//! is not knowable at emit time, so any narrower projection is a bootstrap
//! paradox — the object would need quorum to project widely and need to project
//! widely to reach quorum.
//!
//! Global would be wrong as **reach**. CC 4.2.1 ("Reach is consent-scoped") is
//! explicit that a node *"that never trusted the accord, or has already cut the
//! edge, is simply not reached."* The projection row alone therefore
//! over-delivers, and **this predicate is what narrows carriage back to exactly
//! that set.**
//!
//! ## WHICH accord? The OBJECT says — and PERSIST reads it (CIRISPersist#733)
//!
//! Until v17.10.0 this gate judged every `accord:*` row against ONE root the
//! host named at construction (`ReplicationRuntimeConfig::accord_relay_root`).
//! That is the defect CIRISPersist#731 reports, and it failed in the
//! **permissive** direction:
//!
//! > A caller that supplies the wrong `root_ref` gets a **confidently wrong**
//! > answer […] pass a root this node happens to trust and whose roster happens
//! > to seat the signer, and `may_relay()` returns `true` for an object that
//! > belongs to a **different** accord. The predicate cannot detect this,
//! > because it was never given the object.
//!
//! Edge's first answer to that (v17.10.0) was to read the root out of the row
//! ITSELF — a hand-rolled [`RowMirror`](ciris_persist::federation::envelope::RowMirror)
//! walk plus an `accord:lifecycle:v1` special case, which meant edge held a rule
//! about **which field of an `accord:*` row names its accord**. That rule was
//! never edge's, and persist v37.0.0 (CIRISPersist#733) took it:
//! [`accord_root_claim`] reads the claim off a row, a signed
//! [`accord_root`](ciris_persist::federation::envelope::paths::ACCORD_ROOT)
//! envelope key carries it on every dimension, and
//! [`may_relay_accord_attestation`] is the **taking verb** — hand it the row and
//! it answers, nominating nothing.
//!
//! **So the hand-parsing is gone.** What edge keeps is a CACHE KEY, which is a
//! local concern — and even that is derived through [`accord_root_claim`] rather
//! than by re-reading the row, so there is exactly one reading of *"which
//! root?"* in the process. The key is the PAIR `(root, signer)`: the same signer
//! under two different roots has two different correct verdicts, and a
//! signer-keyed cache would rebuild #731 *behind* the fixed verb, where it is
//! harder to see.
//!
//! ## Zero trust logic here
//!
//! The whole verdict is persist's — [`may_relay_accord_participation`] for an
//! [`AccordParticipation`], [`may_relay_accord_attestation`] for an `accord:*`
//! attestation. Seated signer AND a live `delegates_to(self → root)`. This
//! module resolves, caches, and enforces; it decides nothing. It does not
//! re-derive seating, roster membership, edge existence, **or which accord a row
//! belongs to**, and the family classification of a dimension is persist's
//! [`attestation_family`]
//! (the same fold `attestation_requires_serve` took in v17.7.0), never an
//! edge-side `"accord:"` prefix match.
//!
//! ## The two persist predicates edge calls for ATTRIBUTION, and why
//!
//! [`may_relay_accord_attestation`] returns a three-bool [`RelayVerdict`], and
//! it collapses FOUR distinct *"I cannot judge"* causes into
//! `roster_resolvable: false` — an absent/divergent row mirror, a not-`accord:*`
//! row, [`AccordRootClaim::Unnamed`] and [`AccordRootClaim::Disagrees`]. Persist
//! keeps those apart in its own table; edge must too, because each is a
//! different thing for an operator to go fix, and the #425 withhold-ledger
//! discipline is that a refusal names ONE branch.
//!
//! There is no way to recover them from the verdict, so edge asks persist's own
//! two pure functions —
//! [`check_row_column_binding`]
//! and [`accord_root_claim`], **the very two the verb runs internally**, in the
//! same order — and maps each to its own [`RelayRefusal`]. This is not a second
//! definition of anything: both callers call one body, which is the property
//! #733 was written to establish.
//!
//! It also protects the CACHE. The key's root half can come from an unsigned
//! column on the drill-dimension fallback, so keying before the binding gate has
//! run would let a forged row park an *unjudgeable* verdict on a LEGITIMATE
//! `(root, signer)` pair for a whole TTL — a fail-closed denial of the kill
//! switch plane, cheap to repeat. Running the binding gate FIRST, and refusing
//! without caching, means every key half is signature-covered by construction.
//!
//! ## The three-way verdict is kept three-way
//!
//! [`RelayVerdict`] is typed rather than a bool because `roster_resolvable` /
//! `signer_seated` / `edge_exists` are three different situations, and persist
//! wrote a mutation specifically to prove *"I cannot judge"* never collapses
//! into *"not seated"*. [`RelayRefusal`] preserves that split on edge's side:
//! the attribution order below reads `roster_resolvable` FIRST, because a
//! `None` roster also leaves `signer_seated == false`, so a seated-first reading
//! would report an unjudgeable root as an unseated signer — the exact collapse.
//!
//! ## Async resolver, sync gate (CIRISEdge#217)
//!
//! persist's predicates are `async`; the replication serve path
//! ([`crate::replication::session`]) is synchronous, and the per-record serve
//! gate it reaches through `fetch_envelope` runs once PER ENVELOPE inside a
//! round's reply assembly — the shape that produced CIRISEdge#400 (a per-
//! envelope directory read blew the round budget outright). So this follows the
//! established edge pattern, the same one CIRISEdge#430's
//! [`TransitGate`](crate::transport::realtime_av_alm::transit_gate::TransitGate)
//! uses: **resolve async ONCE, cache the verdict with a validity bound,
//! invalidate on the apply path, and gate on a PURE SYNC predicate**
//! ([`AccordRelayGate::decide`] — no I/O, no `.await`, no `tokio::time`; the
//! freshness bound is a monotonic [`std::time::Instant`], and no lock is ever
//! held across an await).
//!
//! ## Fail CLOSED, in every direction
//!
//! A cache miss, an expired entry, an invalidated entry, a resolver error, an
//! absent directory, an absent local identity, a row that will not deserialize,
//! a row whose signed mirror is absent or diverges, a row that names no root, a
//! row that names two, and `roster_resolvable == false` all refuse.
//! [`RelayRefusal::Unresolved`] is deliberately distinct from every decided
//! refusal, so a refusal *because we never ran the predicate* can never be read
//! as a refusal *because we decided* — the distinction a fail-safe default
//! otherwise hides.
//!
//! ## Deliberately NOT here: whether this node is BOUND by a halt
//!
//! CC 4.2.1 pins binding against the edge set at the invocation's `asserted_at`
//! (*"exit is prospective, never retroactive"*), while relay reads LIVE state:
//! cutting an edge stops carriage immediately and leaves you bound by a halt
//! already invoked. One name, two clocks — fusing them would be an axis fusion.
//! If a "bound by a halt" question ever lands in edge it needs its own resolver
//! and its own cache keyed at the invocation instant; it must not ride this one.
//!
//! ## Scope: `accord:*` only
//!
//! `objection:*` — the reserved-prefix sibling — deliberately stays on the
//! conservative projection row: the co-scrub-assembly argument covers `accord:`
//! only (CIRISPersist#713, the `provenance:build_manifest:` / `provenance:`
//! precedent). Do not extend this gate to it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ciris_persist::federation::admission::check_row_column_binding;
use ciris_persist::federation::trust_root::{
    accord_root_claim, may_relay_accord_attestation, may_relay_accord_participation,
    AccordRootClaim, RelayRefusal as PersistRelayRefusal, RelayVerdict,
};
use ciris_persist::federation::{Attestation, FederationDirectory};
use ciris_verify_core::accord_live_quorum::AccordParticipation;

/// How long one resolved [`RelayVerdict`] stays usable before the gate
/// re-resolves it.
///
/// Sized off the same reasoning as
/// [`CONSENT_SEND_SET_MEMO_TTL`](crate::replication::bridge) (10 s): long
/// enough that a round's advertise sweep plus its N per-envelope serve gates
/// share ONE resolution, short enough to sit well under the 30 s anti-entropy
/// cadence, so a change nobody sent us an invalidation event for still takes
/// effect by the next round.
///
/// Applied to grants AND refusals alike. A stale *grant* is the
/// security-relevant direction and is what bounds the window; a stale *refusal*
/// is fail-closed but must not be unbounded either — caching a refusal forever
/// would pin a node dark across the very event that fixes it (a seat landing,
/// our own trust edge being granted), which is CIRISEdge#430's
/// `NEGATIVE_VERDICT_TTL` lesson. One bound covers both, so there is no
/// asymmetry to justify or to drift.
pub const RELAY_VERDICT_TTL: Duration = Duration::from_secs(10);

/// Why a relay was refused. Every variant is ONE branch, never a disjunction —
/// the [`WithholdReason`](crate::observability::WithholdReason) discipline: an
/// operator must be able to tell "I cannot judge" from "the signer is not
/// seated" from "we never ran the check", because each is a different thing to
/// go fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayRefusal {
    /// persist could not resolve the root's roster at all
    /// ([`RelayVerdict::roster_resolvable`] `== false`) — this node holds no
    /// family under the root **the object named**. **"I cannot judge", NOT "the
    /// signer is not seated"**, and it refuses. Remedy: sync that root's family
    /// record.
    RosterUnresolvable,
    /// The roster resolved and the object's signer holds no live seat on it
    /// (revocation-folded). Trusting a root does not make every key naming it
    /// authoritative — and, post-#731, a signer seated on some OTHER accord
    /// lands here rather than being waved through against a nominated root.
    SignerNotSeated,
    /// No live `delegates_to(self → root)`: this node never granted the root
    /// the object named, or has cut the edge. CC 4.2.1 — *"simply not
    /// reached"*. This is the leg a bare `Global` projection runs straight over.
    NoTrustEdge,
    /// **We never ran the predicate**: no verdict is cached for this
    /// `(root, signer)` pair, or the cached one expired / was invalidated, and
    /// the sync gate cannot resolve. Deliberately distinct from every decided
    /// refusal above — a refusal that reports itself as unresolved is the one an
    /// operator can act on, and it keeps a green test from proving nothing when
    /// the surrounding default already refuses.
    Unresolved,
    /// The gate has no `self_key_id`, so there is no "I" whose
    /// `delegates_to(self → root)` could exist. A WIRING fault
    /// (`ReplicationRuntimeConfig::local_key_id`), not a policy decision.
    NoLocalIdentity,
    /// The wire value is not an [`Attestation`] at all — it does not
    /// deserialize into persist's row type, so there is no row to hand the verb
    /// and nothing to ask. Fail-closed and LOUD (CIRISEdge#425) — a malformed
    /// row, never a silent `continue`. Reachable only from the direct-fetch
    /// path, whose bytes come off the wire; the advertise and subject-Pull sites
    /// hold a typed row and serialize it themselves.
    ObjectUnreadable,
    /// CIRISPersist#733, persist's first *"cannot judge"* row — the row's signed
    /// [`RowMirror`](ciris_persist::federation::envelope::RowMirror) is ABSENT
    /// (a pre-#643 unstamped row) or DIVERGES from the typed columns, so the
    /// columns assert nothing and the row never passed a persist door. Distinct
    /// from [`Self::ObjectUnreadable`]: that row is not an attestation, this one
    /// is an attestation whose unsigned half has been edited. A divergence is a
    /// SECURITY event (a relay rewriting a signed row's identity, verb, signer
    /// or subject); a missing mirror is a producer-vintage problem. Different
    /// findings, different remedies, so never folded.
    MirrorUnbound,
    /// [`AccordRootClaim::NotAccord`] — persist says this row is not on the
    /// `accord:*` family at all, so it "is not this predicate's to judge" and
    /// the verb refuses it. Unreachable through
    /// `FederationDirectoryReplicationBridge::accord_relay_withholds` BY SHARED
    /// PREDICATE (CIRISEdge#505 / v37.1.0): its `attestation_is_accord`
    /// early-out is persist's `is_accord_family`, over both namespaces — and
    /// `accord_root_claim` calls that same function for its own family test, so
    /// a row the pre-filter admits cannot classify `NotAccord` here. Kept
    /// anyway so a DIRECT caller of the public entry point below fails CLOSED
    /// with a name, rather than falling through to an allow.
    ObjectNotAccord,
    /// [`AccordRootClaim::Unnamed`] — the row IS on the `accord:*` family and
    /// **nothing in it names the accord it acts under**: no signed
    /// [`accord_root`](ciris_persist::federation::envelope::paths::ACCORD_ROOT)
    /// key, and not the one dimension whose fallback rule persist defines. A
    /// pre-#733 row or an unadopted producer's. Answering "which root?" from
    /// construction state is the permissive failure #731 reports, so this
    /// refuses instead — the durable narrowing #733 accepted, not a local
    /// misconfiguration.
    ObjectRootUnnamed,
    /// [`AccordRootClaim::Disagrees`] — **ONE ARTIFACT ASSERTING TWO ACCORDS**:
    /// a drill row carrying both signals, whose signed `accord_root` key and
    /// drill-dimension rule name different roots. Neither signal is preferred
    /// (preferring the key lets an emitter relabel a heartbeat's accord;
    /// preferring the column makes the new field decorative), so it refuses.
    ///
    /// **This is NOT dead code behind persist's write door.** That door protects
    /// rows this node ADMITS; relaying is exactly when a node handles rows it
    /// never admitted, which is the entire premise of this plane. Its own
    /// variant, never folded into [`Self::ObjectRootUnnamed`] — "names no
    /// accord" and "names two" send an operator to different places.
    ObjectRootDisagrees,
}

impl RelayRefusal {
    /// Snake-case stable label — the `detail` string the withhold ledger
    /// carries, and what a log line joins on.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RosterUnresolvable => "roster_unresolvable",
            Self::SignerNotSeated => "signer_not_seated",
            Self::NoTrustEdge => "no_trust_edge",
            Self::Unresolved => "unresolved",
            Self::NoLocalIdentity => "no_local_identity",
            Self::ObjectUnreadable => "object_unreadable",
            Self::MirrorUnbound => "mirror_unbound",
            Self::ObjectNotAccord => "object_not_accord",
            Self::ObjectRootUnnamed => "object_root_unnamed",
            Self::ObjectRootDisagrees => "object_root_disagrees",
        }
    }
}

impl std::fmt::Display for RelayRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// **The CACHE KEY, and nothing else**: which accord an object acts under, and
/// who signed it.
///
/// # What this is NOT, post-#733
///
/// It is not edge's reading of the object. v17.10.0's version of this type
/// walked the [`RowMirror`](ciris_persist::federation::envelope::RowMirror) by
/// hand and carried an `accord:lifecycle:v1` special case, which made edge a
/// second owner of *"which field names the accord"*. Persist v37.0.0 took that
/// rule ([`accord_root_claim`]), so both constructors below now **consume**
/// persist's answer rather than compute one.
///
/// The pair still has to exist on edge's side because the verdict is CACHED and
/// a cache needs a key. Both of persist's legs are root-relative
/// (`active_roster_of(root)`, `delegates_to(self → root)`), so ONE signer has as
/// many correct verdicts as there are roots: keying on the signer alone would
/// serve accord A's answer for an accord B object — the cross-accord confusion
/// #731 is about, rebuilt *behind* the fixed verb where it is harder to see,
/// because the resolver would be reading the object correctly and the cache
/// would be answering for a different one.
///
/// # Every half is signature-covered
///
/// [`Self::of_row`] runs
/// [`check_row_column_binding`]
/// BEFORE it reads anything, so the typed columns are proven equal to the signed
/// mirror first. After that, `attesting_key_id` (which is the signer persist's
/// own verb reads) and the drill-dimension fallback's `attested_key_id` are
/// reading signed bytes. Keying without that proof would let a forged row park a
/// verdict on a legitimate pair — see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccordRelaySubject {
    /// The accord trust root the object acts under, as [`accord_root_claim`]
    /// read it off the object (or, for a participation, `family_key_id`).
    pub root_ref: String,
    /// The key that signed the object.
    pub signer_key_id: String,
}

impl AccordRelaySubject {
    /// The subject of an [`AccordParticipation`] — `family_key_id` (*"the accord
    /// family this decision is for"*) and `member_id` (the seat), both inside
    /// the bytes the holder's hybrid threshold signature covers
    /// (`AccordParticipation::canonical_bytes`).
    ///
    /// This is the shape persist's [`may_relay_accord_participation`] was
    /// written for, and [`AccordRelayGate::may_relay_participation`] calls that
    /// verb rather than re-deriving the pair — this constructor exists for the
    /// CACHE KEY, so a participation and an attestation under the same root
    /// share one entry.
    #[must_use]
    pub fn of_participation(participation: &AccordParticipation) -> Self {
        Self {
            root_ref: participation.family_key_id.clone(),
            signer_key_id: participation.member_id.clone(),
        }
    }

    /// The subject of an `accord:*` attestation ROW — persist's two pure gates,
    /// in persist's own order, and no edge parsing at all.
    ///
    /// 1. [`check_row_column_binding`]
    ///    — the same call [`may_relay_accord_attestation`] makes first, for the
    ///    same reason: `attesting_key_id` and `attested_key_id` are UNSIGNED
    ///    columns, and relaying is exactly when a node handles a row it never
    ///    admitted, so nothing may be read off them until they are proven equal
    ///    to the signed mirror.
    /// 2. [`accord_root_claim`] — persist's ONE reading of *"which accord does
    ///    this row claim?"*, shared with its write door.
    ///
    /// Each non-[`AccordRootClaim::Named`] outcome maps to its own
    /// [`RelayRefusal`], because the verb collapses all of them into
    /// `roster_resolvable: false` and an operator needs to know WHICH.
    ///
    /// # Errors
    ///
    /// [`RelayRefusal::MirrorUnbound`], [`RelayRefusal::ObjectNotAccord`],
    /// [`RelayRefusal::ObjectRootUnnamed`] or
    /// [`RelayRefusal::ObjectRootDisagrees`] — one per row of persist's own
    /// *"why this is 'I cannot judge'"* table.
    pub fn of_row(row: &Attestation) -> Result<Self, RelayRefusal> {
        if check_row_column_binding(row).is_err() {
            return Err(RelayRefusal::MirrorUnbound);
        }
        match accord_root_claim(row) {
            AccordRootClaim::Named { root_ref, .. } => Ok(Self {
                root_ref,
                // The signer persist's own verb passes to
                // `may_relay_accord_object` — read from the same column, now
                // proven equal to the signed mirror by step 1.
                signer_key_id: row.attesting_key_id.clone(),
            }),
            AccordRootClaim::NotAccord => Err(RelayRefusal::ObjectNotAccord),
            AccordRootClaim::Unnamed { .. } => Err(RelayRefusal::ObjectRootUnnamed),
            AccordRootClaim::Disagrees { .. } => Err(RelayRefusal::ObjectRootDisagrees),
        }
    }

    /// [`Self::of_row`] for a wire value — the shape the serve paths carry.
    ///
    /// # Errors
    ///
    /// [`RelayRefusal::ObjectUnreadable`] if the value is not an
    /// [`Attestation`]; otherwise [`Self::of_row`]'s.
    pub fn of_attestation(canonical_json: &serde_json::Value) -> Result<Self, RelayRefusal> {
        Self::of_row(&deserialize_row(canonical_json)?)
    }
}

/// The ONE place a wire value becomes persist's row type.
///
/// Borrows rather than cloning: `serde_json` implements `Deserializer` for
/// `&Value`, so this costs one walk and no copy of the envelope.
///
/// A failure is [`RelayRefusal::ObjectUnreadable`] — LOUD and withheld, never a
/// silent pass (CIRISEdge#425). It is only genuinely reachable from the
/// direct-fetch path, whose bytes come off the wire; the advertise and
/// subject-Pull sites serialize a typed row they already hold, so their
/// round-trip cannot fail.
fn deserialize_row(canonical_json: &serde_json::Value) -> Result<Attestation, RelayRefusal> {
    serde::Deserialize::deserialize(canonical_json).map_err(|_| RelayRefusal::ObjectUnreadable)
}

/// The gate's answer for one `accord:*` object. `#[must_use]` for the same
/// reason [`ApplyOutcome`](crate::replication::summary::ApplyOutcome) is: a
/// refusal carries a reason a caller must surface, and dropping it on the floor
/// is how a refusal becomes a silent drop (CIRISEdge#425).
#[must_use = "a relay decision carries a refusal reason the serve gate must book — do not drop it"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayDecision {
    /// persist's [`RelayVerdict::may_relay`] held: carry it.
    Relay,
    /// Refused, with the leg that refused.
    Refused(RelayRefusal),
}

impl RelayDecision {
    /// May the object be carried? Convenience for call sites that have already
    /// booked the refusal.
    #[must_use]
    pub fn may_relay(self) -> bool {
        matches!(self, Self::Relay)
    }

    /// The refusal leg, if this is a refusal.
    #[must_use]
    pub fn refusal(self) -> Option<RelayRefusal> {
        match self {
            Self::Relay => None,
            Self::Refused(r) => Some(r),
        }
    }
}

/// Map persist's typed verdict onto a decision.
///
/// **The ALLOW is persist's own [`RelayVerdict::may_relay`]**, never a
/// conjunction re-spelled here — a second spelling of the relay rule is exactly
/// the two-owners-for-one-fact error this whole module exists to avoid. The
/// legs below are pure ATTRIBUTION of a refusal persist already made, and their
/// order is load-bearing: `roster_resolvable` first, because an unresolvable
/// roster also leaves `signer_seated == false`, and reporting that as
/// "not seated" is the collapse CIRISPersist#713 wrote a mutation to forbid.
fn decision_of(verdict: RelayVerdict) -> RelayDecision {
    // v37.1.0 (CIRISPersist#743) — persist owns the ORDER now, via
    // `RelayVerdict::refusal_reason`. Edge maps its three-variant answer onto
    // its own richer refusal set and adds nothing.
    //
    // The order is load-bearing and was edge's to get wrong: `roster_resolvable`
    // must be read BEFORE `signer_seated`, or *"I cannot judge"* collapses into
    // *"the signer is not seated"* — an accusation substituted for an admission
    // of ignorance, on a relay gate. Persist's own mutation for this is the
    // cleanest demonstration in the substrate of why an equivalence test is not
    // coverage: reversing the two checks left their
    // `refusal_reason_is_none_exactly_when_may_relay_is_true` test GREEN,
    // because reordering changes WHY it refuses, not WHETHER. Only an ordering
    // test caught it.
    //
    // Edge held that ordering itself until now, which meant a second consumer
    // reading the three bools in the obvious order would have got a
    // confidently wrong attribution with nothing to catch it. It travels with
    // the type from here.
    match verdict.refusal_reason() {
        None => RelayDecision::Relay,
        Some(PersistRelayRefusal::RosterUnresolvable) => {
            RelayDecision::Refused(RelayRefusal::RosterUnresolvable)
        }
        Some(PersistRelayRefusal::SignerNotSeated) => {
            RelayDecision::Refused(RelayRefusal::SignerNotSeated)
        }
        Some(PersistRelayRefusal::NoEdgeToRoot) => {
            RelayDecision::Refused(RelayRefusal::NoTrustEdge)
        }
        // FORCED: persist's `RelayRefusal` is `#[non_exhaustive]`, so a
        // downstream match can never be exhaustive (the same constraint that
        // denies edge a compile-error guard on `AttestationFamily` — see
        // `crate::family_gates`).
        //
        // A refusal reason this build cannot name maps to `Unresolved` —
        // edge's own *"I cannot judge"* — and NOT to a seated/not-seated
        // answer. That is the whole point of the ordering this delegation
        // exists to inherit: when edge does not know why persist refused, the
        // honest report is ignorance, never an accusation about the signer.
        Some(_) => RelayDecision::Refused(RelayRefusal::Unresolved),
    }
}

/// One cached verdict for one `(root, signer)` pair.
#[derive(Debug, Clone, Copy)]
struct CachedVerdict {
    verdict: RelayVerdict,
    /// Monotonic instant of resolution ([`Instant`], never `tokio::time` —
    /// CIRISEdge#217: this rides a replication/transport path that can run on
    /// persist's runtime thread).
    fetched_at: Instant,
}

/// The cache key. **`(root, signer)`, never the signer alone** — the heart of
/// the CIRISPersist#731 fix.
///
/// Both of persist's legs are root-relative (`active_roster_of(root)` and
/// `delegates_to(self → root)`), so ONE signer has as many correct verdicts as
/// there are roots. A signer-keyed cache would let the verdict resolved for
/// accord A be served for an object belonging to accord B — the same
/// cross-accord confusion #731 is about, reintroduced *behind* the fixed verb,
/// where it is harder to see: the resolver would be reading the object
/// correctly and the cache would be answering for a different one.
type CacheKey = (String, String);

fn cache_key(subject: &AccordRelaySubject) -> CacheKey {
    (subject.root_ref.clone(), subject.signer_key_id.clone())
}

/// The pure, directory-free verdict cache. Split out from [`AccordRelayGate`]
/// so the freshness / invalidation / fail-closed rules are unit-testable
/// without a trust fixture (resolution correctness is persist's, tested there).
#[derive(Debug, Default)]
struct VerdictCache {
    /// Bumped by EVERY invalidation. An in-flight resolve snapshots it at the
    /// miss and commits only if it is unchanged — see [`Self::commit`].
    generation: u64,
    by_subject: HashMap<CacheKey, CachedVerdict>,
}

impl VerdictCache {
    /// The cached verdict for this `(root, signer)` pair iff a FRESH one exists.
    /// `None` means "no usable verdict", which the sync gate turns into
    /// [`RelayRefusal::Unresolved`] — never into an allow.
    fn get_fresh(&self, subject: &AccordRelaySubject, now: Instant) -> Option<RelayVerdict> {
        let entry = self.by_subject.get(&cache_key(subject))?;
        (now.saturating_duration_since(entry.fetched_at) < RELAY_VERDICT_TTL)
            .then_some(entry.verdict)
    }

    /// Commit a freshly-resolved verdict — but ONLY if no invalidation raced
    /// the resolve (`generation` unchanged since the miss snapshot).
    ///
    /// This is the CIRISEdge#482 review finding, hardened into this cache from
    /// the start: without the generation check, an invalidation landing DURING
    /// an in-flight `.await` is clobbered by the pre-mutation verdict re-armed
    /// with a fresh timestamp, and the "visible to the very next call"
    /// guarantee silently stops holding. Every invalidation bumps the
    /// generation (targeted removals included), so a dropped commit is the
    /// conservative outcome in every race: the next call re-resolves against
    /// live state. Two concurrent misses with NO interleaved invalidation still
    /// race benignly — they write the same answer.
    fn commit(
        &mut self,
        subject: &AccordRelaySubject,
        verdict: RelayVerdict,
        gen_at_miss: u64,
        now: Instant,
    ) {
        if self.generation != gen_at_miss {
            return;
        }
        // Bound memory: a departed signer must not accumulate. The live set is
        // naturally roster-sized, but BOTH halves of the key are peer-supplied
        // (the row's signed mirror), so an unbounded map would be a cheap DoS —
        // and post-#731 the key is a PAIR, so the product of forged roots and
        // forged signers is what an attacker would try to inflate.
        self.by_subject
            .retain(|_, v| now.saturating_duration_since(v.fetched_at) < RELAY_VERDICT_TTL);
        self.by_subject.insert(
            cache_key(subject),
            CachedVerdict {
                verdict,
                fetched_at: now,
            },
        );
    }

    /// Drop every entry a state change naming `key_id` could falsify: any entry
    /// whose ROOT is `key_id` (a roster change, a charter, our trust edge — both
    /// of persist's legs are root-relative, so every signer under it goes) and
    /// any entry whose SIGNER is `key_id` (a seat revocation), across every
    /// root that signer appears under.
    ///
    /// Post-#731 this replaces the old `key_id == self.root_ref ⇒ clear
    /// everything` special case, which only worked because there was exactly one
    /// root. With the root now coming from each object, "entries under this
    /// root" is a filter on the key's first half rather than the whole map.
    ///
    /// Bumps the generation unconditionally — including when nothing matched —
    /// so an in-flight resolve started before this call can never commit over
    /// it.
    fn invalidate(&mut self, key_id: &str) {
        self.generation = self.generation.wrapping_add(1);
        self.by_subject
            .retain(|(root, signer), _| root != key_id && signer != key_id);
    }

    /// Drop everything (a coarse "trust state moved and we cannot cheaply say
    /// whose" signal). Bumps the generation for the same reason.
    fn invalidate_all(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.by_subject.clear();
    }
}

/// The `accord:*` relay gate (workstream F). Wraps persist's relay predicates
/// with a TTL'd, apply-path-invalidated cache and a pure sync predicate; see the
/// module docs.
///
/// # There is no root here — that is the CIRISPersist#731 fix
///
/// This type used to hold a `root_ref` the host named at construction, and
/// judged every object against it. It holds none now: the root is read from each
/// object's signed bytes ([`AccordRelaySubject`]), so a host cannot nominate one
/// and an object belonging to a different accord cannot be waved through on a
/// roster that happens to seat its signer. Installing the gate is an on/off
/// wiring decision (`ReplicationRuntimeConfig::accord_relay_enforced`), not a
/// choice of which accord to believe in.
pub struct AccordRelayGate {
    directory: Arc<dyn FederationDirectory>,
    /// "I" — this node's federation `key_id`, the subject of leg 2's
    /// `delegates_to(self → root)`. `None` holds the gate fully closed
    /// ([`RelayRefusal::NoLocalIdentity`]): a wiring fault, and a gate with no
    /// "I" cannot evaluate consent-scoped reach at all.
    self_key_id: Option<String>,
    cache: Mutex<VerdictCache>,
}

impl AccordRelayGate {
    /// Build a gate over `directory`, anchored at `self_key_id` (our federation
    /// key). `None` for `self_key_id` holds the gate fully closed.
    ///
    /// No root parameter: see the type doc (CIRISPersist#731).
    #[must_use]
    pub fn new(directory: Arc<dyn FederationDirectory>, self_key_id: Option<String>) -> Self {
        Self {
            directory,
            self_key_id,
            cache: Mutex::new(VerdictCache::default()),
        }
    }

    /// The **DIMENSION HALF ONLY** of the `accord:*` family test — is this
    /// `dimension` string relay-gated per [`crate::family_gates::gates_for`]?
    ///
    /// **NEVER a carriage pre-filter.** The family rides BOTH namespaces —
    /// persist's admission comment (`check_reserved_prefix_admission`) is
    /// explicit: *"`accord:invoke:*` as a TYPE, `accord:human_dignity:v1` as a
    /// `scores` DIMENSION"* — and using this dimension-only half to decide
    /// whether a ROW reaches the gate is exactly the CIRISEdge#505
    /// under-gating hole: every `accord:invoke:*` row in the
    /// `attestation_type` namespace skipped the CC 4.2.1 relay gate and was
    /// carried unexamined. Row-level family classification has ONE owner,
    /// [`ciris_persist::federation::trust_root::is_accord_family`], consumed
    /// by the bridge's `attestation_is_accord` — and a source-assertion test
    /// there (`the_carriage_pre_filter_reads_is_accord_family_not_the_dimension_half`)
    /// pins that the pre-filter reads it and not this.
    ///
    /// What survives here is the WIRING PIN for [`crate::family_gates`]: the
    /// accord half of `gates_for`'s fold, exercised by that module's
    /// through-the-call-site test and the dimension matrix below, so the fold
    /// cannot silently drift from persist's registry (`objection:*` stays out
    /// of the family — CIRISPersist#713; an inline `matches!` would return
    /// `false` for a family this build predates). `#[cfg(test)]` plus the
    /// `dimension_half_` name are the fence: in a production build this fn
    /// does not exist, so a future caller reaching for it as a carriage
    /// pre-filter gets a compile error, not the #505 hole.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn dimension_half_is_gated(dimension: &str) -> bool {
        crate::family_gates::gates_for(dimension).accord_relay_gated
    }

    /// **The PURE SYNC predicate** — the gate itself. No I/O, no `.await`, no
    /// `tokio` primitive, one uncontended `std::sync::Mutex` acquisition that is
    /// released before returning. Safe to call from the synchronous replication
    /// serve path (CIRISEdge#217), once per envelope.
    ///
    /// Takes the OBJECT'S subject, so the verdict served is the one resolved for
    /// this object's root — not for whichever root the host had in mind.
    ///
    /// Fail-closed on every absence: no local identity, no cached verdict, an
    /// expired verdict, an invalidated verdict. It NEVER resolves — resolution
    /// is [`Self::prime`]'s job, so a per-envelope serve gate can never turn
    /// into a per-envelope trust walk (the CIRISEdge#400 regression).
    pub fn decide(&self, subject: &AccordRelaySubject, now: Instant) -> RelayDecision {
        if self.self_key_id.is_none() {
            return RelayDecision::Refused(RelayRefusal::NoLocalIdentity);
        }
        let cached = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_fresh(subject, now);
        match cached {
            Some(verdict) => decision_of(verdict),
            None => RelayDecision::Refused(RelayRefusal::Unresolved),
        }
    }

    /// **The ONE async step**: hand the ROW to persist's taking verb
    /// ([`may_relay_accord_attestation`]) and cache what it says, unless a fresh
    /// verdict is already held (cache-first — a hit costs one lock and no
    /// directory read). Returns the subject the verdict was filed under, so the
    /// caller can [`Self::decide`] on it.
    ///
    /// Nothing here nominates a root or a signer: the verb is given the object.
    /// [`AccordRelaySubject::of_row`] runs persist's own two pure gates purely to
    /// name a refusal and to key the cache, and it is the same pair of calls the
    /// verb makes internally — so a row this returns `Ok` for is exactly a row
    /// the verb will judge on its merits.
    ///
    /// The cache lock is taken twice, briefly, and **never held across the
    /// `.await`** (CIRISEdge#217). A resolver error does NOT cache: a transient
    /// directory fault must not pin a subject refused past the fault — the next
    /// call re-resolves, and [`Self::decide`] refuses meanwhile as
    /// [`RelayRefusal::Unresolved`], which says exactly what happened.
    ///
    /// # Errors
    ///
    /// [`AccordRelaySubject::of_row`]'s — a row persist cannot judge is refused
    /// here, before any directory read and without caching anything.
    pub async fn prime(
        &self,
        row: &Attestation,
        now: Instant,
    ) -> Result<AccordRelaySubject, RelayRefusal> {
        let subject = AccordRelaySubject::of_row(row)?;
        // No "I" ⇒ no `delegates_to(self → root)` to resolve. `decide` reports
        // that as `NoLocalIdentity`; resolving would be meaningless.
        let Some(us) = self.self_key_id.as_deref() else {
            return Ok(subject);
        };
        let gen_at_miss = {
            let guard = self
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if guard.get_fresh(&subject, now).is_some() {
                return Ok(subject);
            }
            // Snapshot the generation WITH the miss check, so an invalidation
            // during the `.await` below is detected at commit.
            guard.generation
        };

        let verdict = match may_relay_accord_attestation(&*self.directory, us, row).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    signer = %subject.signer_key_id,
                    root = %subject.root_ref,
                    error = %e,
                    "accord relay verdict resolve FAILED — carriage refused as `unresolved` \
                     until the next resolve (fail-closed, workstream F)"
                );
                return Ok(subject);
            }
        };
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .commit(&subject, verdict, gen_at_miss, now);
        Ok(subject)
    }

    /// [`Self::prime`] then [`Self::decide`], for a caller holding persist's row
    /// type. The async resolve / pure-sync predicate split is preserved: this is
    /// only the two in sequence.
    pub async fn may_relay_row(&self, row: &Attestation, now: Instant) -> RelayDecision {
        match self.prime(row, now).await {
            Ok(subject) => self.decide(&subject, now),
            Err(refusal) => RelayDecision::Refused(refusal),
        }
    }

    /// **The serve-path entry point for an `accord:*` attestation row**, from
    /// the wire value the three call sites carry.
    ///
    /// Deserializes ONCE into persist's row type and delegates to
    /// [`Self::may_relay_row`]; a value that is not an [`Attestation`] is
    /// REFUSED as [`RelayRefusal::ObjectUnreadable`], never carried.
    pub async fn may_relay_attestation(
        &self,
        canonical_json: &serde_json::Value,
        now: Instant,
    ) -> RelayDecision {
        match deserialize_row(canonical_json) {
            Ok(row) => self.may_relay_row(&row, now).await,
            Err(refusal) => RelayDecision::Refused(refusal),
        }
    }

    /// **The entry point for an [`AccordParticipation`]** — persist's
    /// [`may_relay_accord_participation`], which reads `family_key_id` and
    /// `member_id` out of the holder's signed canonical bytes itself.
    ///
    /// The verb is called directly rather than fed a pair edge derived, so the
    /// mapping object → `(root, signer)` has exactly one owner (persist).
    /// [`AccordRelaySubject::of_participation`] supplies only the CACHE KEY, and
    /// a test pins the two against each other.
    ///
    /// This is the plane CIRISPersist#731's verb was written for
    /// ([`AccordQuorumEvidence`](ciris_persist::federation::accord_carriage::AccordQuorumEvidence),
    /// the #474 cursor plane). Edge does not yet route that plane through this
    /// gate — see the module report — so this is the gate's readiness for it,
    /// not a live serve path.
    pub async fn may_relay_participation(
        &self,
        participation: &AccordParticipation,
        now: Instant,
    ) -> RelayDecision {
        let Some(us) = self.self_key_id.as_deref() else {
            return RelayDecision::Refused(RelayRefusal::NoLocalIdentity);
        };
        let subject = AccordRelaySubject::of_participation(participation);
        let gen_at_miss = {
            let guard = self
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match guard.get_fresh(&subject, now) {
                Some(verdict) => return decision_of(verdict),
                None => guard.generation,
            }
        };
        let verdict =
            match may_relay_accord_participation(&*self.directory, us, participation).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        member = %participation.member_id,
                        family = %participation.family_key_id,
                        error = %e,
                        "accord participation relay verdict resolve FAILED — carriage refused \
                         as `unresolved` until the next resolve (fail-closed, workstream F)"
                    );
                    return RelayDecision::Refused(RelayRefusal::Unresolved);
                }
            };
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .commit(&subject, verdict, gen_at_miss, now);
        decision_of(verdict)
    }

    /// Drop cached verdicts a state change naming `key_id` could falsify.
    /// Wired to the replication APPLY path so an in-band roster change,
    /// revocation, or trust-edge tombstone takes effect before the TTL would
    /// expire; [`RELAY_VERDICT_TTL`] is the backstop if an event is missed.
    ///
    /// Deliberately over-broad: `key_id` matching EITHER half of a cache key
    /// drops that entry — as a ROOT it drops every signer under that root (both
    /// of persist's legs are root-relative), as a SIGNER it drops that signer
    /// under every root. Choosing invalidation keys is a cache concern, not a
    /// trust rule — being too eager only costs a re-resolve, while being too
    /// narrow caches a verdict past the event that falsified it.
    pub fn invalidate(&self, key_id: &str) {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .invalidate(key_id);
    }

    /// Drop every cached verdict — the coarse "trust state moved and we cannot
    /// cheaply say whose" signal.
    pub fn invalidate_all(&self) {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .invalidate_all();
    }

    /// Test/diagnostic: how many verdicts are currently cached (fresh or not).
    #[cfg(test)]
    fn cached_len(&self) -> usize {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .by_subject
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_persist::federation::trust_root::{AccordRootSource, ACCORD_HEARTBEAT_DIMENSION};
    use ciris_persist::store::MemoryBackend;

    /// The three-bool verdict, spelled out at every call so a test's INPUT is
    /// legible next to its expectation.
    const fn verdict(
        roster_resolvable: bool,
        signer_seated: bool,
        edge_exists: bool,
    ) -> RelayVerdict {
        RelayVerdict {
            roster_resolvable,
            signer_seated,
            edge_exists,
        }
    }

    fn now() -> Instant {
        Instant::now()
    }

    /// A `(root, signer)` subject, for the cache tests.
    fn subject(root: &str, signer: &str) -> AccordRelaySubject {
        AccordRelaySubject {
            root_ref: root.to_owned(),
            signer_key_id: signer.to_owned(),
        }
    }

    /// A COMPLETE `accord:*` attestation row as a wire VALUE, in the shape
    /// persist v31.0.0 (#643) stamps: the `row` mirror lives inside
    /// `attestation_envelope` (what the scrub signature covers) and MIRRORS the
    /// typed columns, so `check_row_column_binding` passes. `accord_root` is the
    /// v37.0.0 (#733) signed key naming the row's own accord — `None` omits it,
    /// which is how a pre-#733 row looks.
    ///
    /// Every field persist's `Attestation` requires is present: these tests
    /// exercise the REAL deserialize the serve path performs, not a
    /// hand-selected subset (CIRISEdge's "test the field's own input" scar —
    /// a fixture the row type would reject proves nothing about a row type
    /// that must accept it).
    fn accord_row_value(
        dimension: &str,
        attesting: &str,
        attested: &str,
        accord_root: Option<&str>,
    ) -> serde_json::Value {
        typed_accord_row_value("scores", Some(dimension), attesting, attested, accord_root)
    }

    /// [`accord_row_value`] with the `attestation_type` namespace open too —
    /// CIRISEdge#505 / CIRISPersist#743: the family rides BOTH namespaces
    /// (*"`accord:invoke:*` as a TYPE, `accord:human_dignity:v1` as a `scores`
    /// DIMENSION"* — persist's own admission comment), and a fixture that can
    /// only spell the dimension shape can only ever test half of it.
    /// `dimension: None` omits the key entirely, which is the exact wire shape
    /// an `accord:invoke:*` row carries. The type is stamped into the signed
    /// `row` mirror as well as the column, else `check_row_column_binding`
    /// refuses the fixture for divergence rather than judging its family.
    fn typed_accord_row_value(
        attestation_type: &str,
        dimension: Option<&str>,
        attesting: &str,
        attested: &str,
        accord_root: Option<&str>,
    ) -> serde_json::Value {
        let mut envelope = serde_json::json!({
            "asserted_at": "2026-01-01T00:00:00Z",
            "row": {
                "attestation_id": "att-1",
                "attesting_key_id": attesting,
                "attestation_type": attestation_type,
                "attested_key_id": attested,
                "cohort_scope": "federation",
            },
        });
        if let Some(dim) = dimension {
            envelope["dimension"] = serde_json::json!(dim);
        }
        if let Some(root) = accord_root {
            envelope["accord_root"] = serde_json::json!(root);
        }
        serde_json::json!({
            "attestation_id": "att-1",
            "attesting_key_id": attesting,
            "attested_key_id": attested,
            "attestation_type": attestation_type,
            "asserted_at": "2026-01-01T00:00:00Z",
            "attestation_envelope": envelope,
            "original_content_hash": "0".repeat(64),
            "scrub_signature_classical": "x".repeat(88),
            "scrub_key_id": attesting,
            "scrub_timestamp": "2026-01-01T00:00:00Z",
            "persist_row_hash": "",
        })
    }

    /// [`accord_row_value`] as persist's row type — the argument the taking verb
    /// takes.
    fn accord_row(
        dimension: &str,
        attesting: &str,
        attested: &str,
        accord_root: Option<&str>,
    ) -> Attestation {
        serde_json::from_value(accord_row_value(
            dimension,
            attesting,
            attested,
            accord_root,
        ))
        .expect("the fixture is a well-formed persist Attestation")
    }

    /// A drill row: the one dimension whose fallback rule persist defines, so
    /// `attested_key_id` IS the accord and no signed key is needed.
    fn drill_row(attesting: &str, root: &str) -> Attestation {
        accord_row(ACCORD_HEARTBEAT_DIMENSION, attesting, root, None)
    }

    // ── decision_of: the verdict → decision mapping ──────────────────────

    /// Seated signer + live edge on a resolvable roster ⇒ relay. persist's own
    /// leg (A).
    #[test]
    fn seated_signer_with_a_live_edge_relays() {
        assert_eq!(decision_of(verdict(true, true, true)), RelayDecision::Relay);
    }

    /// persist's leg (C): the roster resolved and the signer is not on it.
    #[test]
    fn unseated_signer_is_refused_as_not_seated() {
        assert_eq!(
            decision_of(verdict(true, false, true)),
            RelayDecision::Refused(RelayRefusal::SignerNotSeated),
            "trusting a root does not make every key naming it authoritative"
        );
    }

    /// persist's leg (B) — the leg a bare `Global` projection runs over.
    #[test]
    fn seated_signer_without_our_edge_is_refused_as_no_trust_edge() {
        assert_eq!(
            decision_of(verdict(true, true, false)),
            RelayDecision::Refused(RelayRefusal::NoTrustEdge),
            "CC 4.2.1 — a node that never granted the root is simply not reached"
        );
    }

    /// persist's leg (D), and the invariant this whole type exists for:
    /// **"I cannot judge" must NOT collapse into "not seated"**.
    ///
    /// The input is field-shaped: an unresolvable roster ALWAYS carries
    /// `signer_seated: false` (persist computes seating from the roster
    /// `Option`), and `edge_exists: true` is the real situation of a node that
    /// granted a root whose family record it has not synced. A seated-first
    /// attribution order reports this as `SignerNotSeated` — a confident,
    /// wrong statement about the signer that sends an operator to the wrong
    /// place. MUTATION-VERIFIED (see the module report): reordering the legs
    /// reds exactly this assertion.
    #[test]
    fn unresolvable_roster_is_cannot_judge_not_not_seated() {
        assert_eq!(
            decision_of(verdict(false, false, true)),
            RelayDecision::Refused(RelayRefusal::RosterUnresolvable),
            "an unheld root is UNJUDGEABLE — reporting it as `signer_not_seated` is the \
             collapse CIRISPersist#713 wrote a mutation to forbid"
        );
        // …and it still refuses. Fail closed.
        assert!(!decision_of(verdict(false, false, true)).may_relay());
        assert!(!decision_of(verdict(false, false, false)).may_relay());
    }

    // ── AccordRelaySubject: persist reads the claim, edge keys on it ──────

    /// REWRITTEN for CIRISPersist#733. This used to assert that EDGE's mirror
    /// walk plus its `accord:lifecycle:v1` special case produced the pair. It
    /// now asserts the delegation: persist's [`accord_root_claim`] carries the
    /// drill-dimension fallback, edge consumes its answer, and the two agree by
    /// CONSTRUCTION rather than by edge re-deriving the rule.
    ///
    /// Asserted against persist's claim directly, so a change to persist's rule
    /// moves both sides of this test together — which is the point of having one
    /// owner.
    #[test]
    fn the_subject_is_exactly_what_persists_claim_says() {
        let row = drill_row("holder-a", "accord-x");
        assert_eq!(
            accord_root_claim(&row),
            AccordRootClaim::Named {
                root_ref: "accord-x".to_owned(),
                source: AccordRootSource::HeartbeatDimensionRule,
            },
            "the drill fallback is PERSIST's rule and it is the one that answers"
        );
        assert_eq!(
            AccordRelaySubject::of_row(&row),
            Ok(subject("accord-x", "holder-a")),
            "edge's key is persist's root plus the signer persist's own verb reads"
        );
    }

    /// REWRITTEN, and the property INVERTED — deliberately, because #733 moved
    /// it.
    ///
    /// The old test skewed the unsigned columns and asserted the subject was
    /// UNMOVED, because edge read the signed mirror and ignored the columns.
    /// That was edge working around a receive-path gate it did not run. Persist
    /// v37.0.0's verb runs
    /// [`check_row_column_binding`]
    /// ITSELF and treats its refusal as *"I cannot judge"*, so the correct
    /// serve-path answer to a skewed row is not "re-read it from the mirror" —
    /// it is **REFUSE**. Strictly stronger: the old behaviour would have carried
    /// a row whose signed and unsigned halves disagree, on the strength of the
    /// signed half alone.
    #[test]
    fn a_row_whose_columns_diverge_from_its_signed_mirror_is_refused() {
        let mut value = accord_row_value(ACCORD_HEARTBEAT_DIMENSION, "holder-a", "accord-x", None);
        value["attesting_key_id"] = serde_json::json!("attacker");
        value["attested_key_id"] = serde_json::json!("accord-the-attacker-prefers");
        assert_eq!(
            AccordRelaySubject::of_attestation(&value),
            Err(RelayRefusal::MirrorUnbound),
            "columns that diverge from the signed mirror make the row UNJUDGEABLE — persist's \
             own first `cannot judge` row, not a subject to be recovered from the mirror"
        );
        // …and the same row with its columns intact IS judgeable, so the
        // refusal above is about the divergence and not about the fixture.
        assert_eq!(
            AccordRelaySubject::of_attestation(&accord_row_value(
                ACCORD_HEARTBEAT_DIMENSION,
                "holder-a",
                "accord-x",
                None
            )),
            Ok(subject("accord-x", "holder-a")),
        );
    }

    /// REWRITTEN — this is the #733 WIDENING, and the old test asserted its
    /// opposite.
    ///
    /// Edge used to refuse every non-drill `accord:*` dimension outright
    /// (`ObjectRootUnnamed`), because nothing in such a row named its accord and
    /// edge would not invent a rule. v37.0.0 added the signed `accord_root`
    /// envelope key, so those rows CAN now name their accord — and the refusal
    /// survives only for the ones that still do not.
    #[test]
    fn a_non_drill_row_names_its_accord_with_the_signed_key_or_is_refused() {
        for dim in [
            "accord:human_dignity:v1",
            "accord:invoke:notify:halt",
            "accord:halt:v1",
        ] {
            assert_eq!(
                AccordRelaySubject::of_row(&accord_row(dim, "holder-a", "some-agent", None)),
                Err(RelayRefusal::ObjectRootUnnamed),
                "{dim} with no `accord_root`: a pre-#733 row names no accord — refuse, never \
                 fall back to a host-nominated root"
            );
            assert_eq!(
                AccordRelaySubject::of_row(&accord_row(
                    dim,
                    "holder-a",
                    "some-agent",
                    Some("accord-x")
                )),
                Ok(subject("accord-x", "holder-a")),
                "{dim} WITH the signed key: #733's general answer, on a dimension where \
                 `attested_key_id` is the scored agent and never the root"
            );
        }
    }

    /// **THE DUAL-SIGNAL DISAGREEMENT, and it is NOT dead code.** A drill row
    /// carrying BOTH signals that name different accords is refused — with its
    /// own leg, never folded into "names no root".
    ///
    /// Persist's write door refuses this shape too, which is exactly why the
    /// arm matters HERE: a write door protects rows this node ADMITS, and
    /// relaying is the case where a node handles a row it never admitted. That
    /// is the entire premise of the plane, and persist says so in
    /// `may_relay_accord_attestation`'s own doc.
    ///
    /// Neither signal is preferred: preferring the key lets an emitter relabel a
    /// heartbeat's accord, preferring the column makes the new field decorative.
    /// One artifact asserting two accords is malformed, whichever you believe.
    #[test]
    fn a_row_naming_two_accords_is_refused_as_disagrees_never_as_unnamed() {
        let row = accord_row(
            ACCORD_HEARTBEAT_DIMENSION,
            "holder-a",
            "accord-from-the-column",
            Some("accord-from-the-signed-key"),
        );
        assert_eq!(
            accord_root_claim(&row),
            AccordRootClaim::Disagrees {
                envelope_root: "accord-from-the-signed-key".to_owned(),
                attested_key_id: "accord-from-the-column".to_owned(),
            },
        );
        let got = AccordRelaySubject::of_row(&row);
        assert_eq!(
            got,
            Err(RelayRefusal::ObjectRootDisagrees),
            "one artifact asserting TWO accords is its own finding"
        );
        assert_ne!(
            got,
            Err(RelayRefusal::ObjectRootUnnamed),
            "`names two` is not `names none` — folding them sends an operator to add a key \
             the row already has"
        );
        // Agreement is NOT a disagreement: the same two signals naming the same
        // accord resolve, and the signed key is reported as the source.
        assert_eq!(
            AccordRelaySubject::of_row(&accord_row(
                ACCORD_HEARTBEAT_DIMENSION,
                "holder-a",
                "accord-x",
                Some("accord-x")
            )),
            Ok(subject("accord-x", "holder-a")),
            "both signals agreeing turns the drill rule into a CHECK, not a refusal"
        );
    }

    /// The two "we could not even get a row" legs, kept apart.
    ///
    /// REWRITTEN: all three inputs below used to land on `ObjectUnreadable`,
    /// because edge parsed the envelope by hand and every shape it could not
    /// walk looked the same. Now a value that is not an [`Attestation`] and a
    /// well-formed [`Attestation`] whose signed mirror is missing are DIFFERENT
    /// findings — fix the producer's serializer vs. re-mint a pre-#643 row — so
    /// they get different legs.
    #[test]
    fn an_unreadable_value_and_an_unbound_mirror_are_different_legs() {
        // Not an `Attestation` at all: no `attestation_id`, no signatures, no
        // `asserted_at`. persist's row type refuses it, and so do we.
        assert_eq!(
            AccordRelaySubject::of_attestation(&serde_json::json!({ "attesting_key_id": "a" })),
            Err(RelayRefusal::ObjectUnreadable),
        );
        // A row that is missing only the SIGNATURE fields is still not a row.
        assert_eq!(
            AccordRelaySubject::of_attestation(&serde_json::json!({
                "attestation_id": "att-1",
                "attesting_key_id": "a",
                "attested_key_id": "b",
                "attestation_type": "scores",
                "asserted_at": "2026-01-01T00:00:00Z",
                "attestation_envelope": { "dimension": ACCORD_HEARTBEAT_DIMENSION },
            })),
            Err(RelayRefusal::ObjectUnreadable),
        );
        // A COMPLETE row whose envelope carries no signed `row` mirror — a
        // pre-#643 unstamped row. Deserializes fine; persist's binding gate
        // refuses it.
        let mut value = accord_row_value(ACCORD_HEARTBEAT_DIMENSION, "holder-a", "accord-x", None);
        value["attestation_envelope"]
            .as_object_mut()
            .expect("envelope object")
            .remove("row");
        assert_eq!(
            AccordRelaySubject::of_attestation(&value),
            Err(RelayRefusal::MirrorUnbound),
            "an unstamped row is UNBOUND, not unreadable — the two send an operator to \
             different places"
        );
        // …and a `row` that is not persist's closed-member mirror lands there
        // too: the binding gate owns that judgement now, not an edge walk.
        let mut value = accord_row_value(ACCORD_HEARTBEAT_DIMENSION, "holder-a", "accord-x", None);
        value["attestation_envelope"]["row"] =
            serde_json::json!({ "attesting_key_id": "a", "not_a_mirror_member": 1 });
        assert_eq!(
            AccordRelaySubject::of_attestation(&value),
            Err(RelayRefusal::MirrorUnbound),
        );
    }

    /// [`AccordRootClaim::NotAccord`] fails CLOSED at the gate's public entry
    /// point. It is unreachable through the bridge by SHARED PREDICATE
    /// (CIRISEdge#505 / v37.1.0: the bridge's `attestation_is_accord` early-out
    /// is persist's `is_accord_family` over both namespaces, the exact family
    /// test `accord_root_claim` itself calls), but the arm must not be an
    /// allow: a direct caller of a `pub` predicate is a caller.
    #[test]
    fn a_row_that_is_not_accord_at_all_fails_closed_with_its_own_leg() {
        let row = accord_row("scores:reputation:v1", "holder-a", "someone", None);
        assert_eq!(accord_root_claim(&row), AccordRootClaim::NotAccord);
        assert_eq!(
            AccordRelaySubject::of_row(&row),
            Err(RelayRefusal::ObjectNotAccord),
            "persist refuses a non-accord row as unjudgeable; edge must not turn that into \
             a carriage grant"
        );
    }

    // ── VerdictCache: freshness, fail-closed miss, invalidation ──────────

    #[test]
    fn a_miss_is_none_never_a_default() {
        let c = VerdictCache::default();
        assert!(c.get_fresh(&subject("root", "never-seen"), now()).is_none());
    }

    #[test]
    fn a_committed_verdict_is_a_cache_hit_within_the_ttl() {
        let mut c = VerdictCache::default();
        let t0 = now();
        let s = subject("root", "holder-a");
        c.commit(&s, verdict(true, true, true), 0, t0);
        assert_eq!(
            c.get_fresh(
                &s,
                t0 + RELAY_VERDICT_TTL
                    .checked_sub(Duration::from_millis(1))
                    .expect("the TTL is longer than 1ms")
            ),
            Some(verdict(true, true, true)),
            "fresh just before the TTL"
        );
    }

    #[test]
    fn a_verdict_expires_at_the_ttl_and_the_gate_then_fails_closed() {
        let mut c = VerdictCache::default();
        let t0 = now();
        let s = subject("root", "holder-a");
        c.commit(&s, verdict(true, true, true), 0, t0);
        assert!(
            c.get_fresh(&s, t0 + RELAY_VERDICT_TTL).is_none(),
            "expired AT the TTL — an expired ALLOW must not keep relaying"
        );
    }

    /// **THE CACHE-KEY PROPERTY (CIRISPersist#731).** One signer, two roots,
    /// two OPPOSITE verdicts — and the cache must keep them apart. A
    /// signer-keyed cache serves accord A's allow for an accord B object, which
    /// is the cross-accord confusion #731 is about, reintroduced behind the
    /// fixed verb where it is harder to see.
    ///
    /// MUTATION-VERIFIED (see the module report): reverting `CacheKey` to the
    /// signer alone reds this test.
    #[test]
    fn one_signer_under_two_roots_holds_two_independent_verdicts() {
        let mut c = VerdictCache::default();
        let t0 = now();
        let on_a = subject("accord-a", "holder-a");
        let on_b = subject("accord-b", "holder-a");
        // Seated on A, NOT seated on B — the same key, two truths.
        c.commit(&on_a, verdict(true, true, true), c.generation, t0);
        c.commit(&on_b, verdict(true, false, true), c.generation, t0);
        assert_eq!(
            c.get_fresh(&on_a, t0),
            Some(verdict(true, true, true)),
            "accord A's verdict"
        );
        assert_eq!(
            c.get_fresh(&on_b, t0),
            Some(verdict(true, false, true)),
            "accord B's verdict is B's — NOT A's answer served under B's name"
        );
        assert!(
            !decision_of(c.get_fresh(&on_b, t0).expect("cached")).may_relay(),
            "and it still refuses for B"
        );
    }

    #[test]
    fn invalidate_drops_the_named_signer_and_leaves_the_others() {
        let mut c = VerdictCache::default();
        let t0 = now();
        let a = subject("root", "holder-a");
        let b = subject("root", "holder-b");
        c.commit(&a, verdict(true, true, true), c.generation, t0);
        c.commit(&b, verdict(true, true, true), c.generation, t0);
        c.invalidate("holder-a");
        assert!(c.get_fresh(&a, t0).is_none(), "holder-a dropped");
        assert_eq!(
            c.get_fresh(&b, t0),
            Some(verdict(true, true, true)),
            "an unrelated signer's verdict survives a targeted invalidation"
        );
    }

    /// The root half of the key is an invalidation handle too: a change naming
    /// a ROOT drops every signer under THAT root, and leaves other roots alone.
    /// (Pre-#731 this was `key_id == self.root_ref ⇒ clear the whole map`,
    /// which only worked because there was exactly one root.)
    #[test]
    fn invalidating_a_root_drops_its_signers_and_spares_other_roots() {
        let mut c = VerdictCache::default();
        let t0 = now();
        let a1 = subject("accord-a", "holder-1");
        let a2 = subject("accord-a", "holder-2");
        let b1 = subject("accord-b", "holder-1");
        for s in [&a1, &a2, &b1] {
            c.commit(s, verdict(true, true, true), c.generation, t0);
        }
        c.invalidate("accord-a");
        assert!(c.get_fresh(&a1, t0).is_none());
        assert!(c.get_fresh(&a2, t0).is_none());
        assert_eq!(
            c.get_fresh(&b1, t0),
            Some(verdict(true, true, true)),
            "accord B is untouched — both legs are root-relative, so only A's entries were \
             falsified"
        );
    }

    /// THE RACE (CIRISEdge#482 review finding, not reintroduced): an
    /// invalidation that lands while a resolve is in flight must not be
    /// clobbered by that resolve's pre-mutation answer re-armed with a fresh
    /// timestamp. Every invalidation bumps the generation; a commit whose
    /// snapshot is stale is DROPPED.
    #[test]
    fn a_commit_that_raced_an_invalidation_is_dropped_not_clobbering_it() {
        let mut c = VerdictCache::default();
        let t0 = now();
        let s = subject("root", "holder-a");
        // A resolve begins: snapshot the generation at the miss.
        let gen_at_miss = c.generation;
        // …an invalidation lands DURING the (awaited) resolve.
        c.invalidate("holder-a");
        // …and the in-flight resolve now tries to commit its stale answer.
        c.commit(&s, verdict(true, true, true), gen_at_miss, t0);
        assert!(
            c.get_fresh(&s, t0).is_none(),
            "the racing commit is DROPPED — the invalidation is not clobbered, and the \
             next call re-resolves against live state"
        );
        // A fresh resolve (snapshot taken after the invalidation) commits fine.
        let gen_now = c.generation;
        c.commit(&s, verdict(true, true, true), gen_now, t0);
        assert_eq!(c.get_fresh(&s, t0), Some(verdict(true, true, true)));
    }

    #[test]
    fn invalidate_all_clears_every_entry() {
        let mut c = VerdictCache::default();
        let t0 = now();
        let a = subject("root-a", "holder-a");
        let b = subject("root-b", "holder-b");
        c.commit(&a, verdict(true, true, true), c.generation, t0);
        c.commit(&b, verdict(true, true, true), c.generation, t0);
        c.invalidate_all();
        assert!(c.get_fresh(&a, t0).is_none());
        assert!(c.get_fresh(&b, t0).is_none());
    }

    // ── The gate: fail-closed, and the family classifier ─────────────────

    /// The DIMENSION-HALF matrix (CIRISEdge#505: the half-test, never the
    /// carriage pre-filter — see `dimension_half_is_gated`'s doc): it covers
    /// `accord:*` WITHOUT covering `objection:*` (which #713 deliberately left
    /// on the conservative row) — pinned here so an edge-side widening cannot
    /// happen by accident.
    #[test]
    fn only_accord_dimensions_are_gated() {
        assert!(AccordRelayGate::dimension_half_is_gated(
            "accord:lifecycle:v1"
        ));
        assert!(AccordRelayGate::dimension_half_is_gated("accord:halt:v1"));
        assert!(AccordRelayGate::dimension_half_is_gated(
            "accord:human_dignity:v1"
        ));
        for other in [
            "objection:conduct:v1",
            "trace:complete:v1",
            "scores:reputation:v1",
            "moderation:conduct:v1",
            "consent:replication:v1",
            "provenance:build_manifest:v1",
            "capacity:relay:v1",
            "transport:reachability:v1",
            // The bare stem is not "under" the stem — persist's prefix grammar.
            "accord:",
            "accord",
        ] {
            assert!(
                !AccordRelayGate::dimension_half_is_gated(other),
                "{other} must NOT be gated by the accord relay predicate"
            );
        }
    }

    #[test]
    fn no_local_identity_refuses_every_object() {
        let dir: Arc<dyn FederationDirectory> = Arc::new(MemoryBackend::new());
        let gate = AccordRelayGate::new(dir, None);
        assert_eq!(
            gate.decide(&subject("humanity-accord", "any-holder"), now()),
            RelayDecision::Refused(RelayRefusal::NoLocalIdentity),
            "no `I` ⇒ no consent-scoped reach to evaluate ⇒ closed"
        );
    }

    /// The trap this test set exists to avoid: a gate whose DEFAULT already
    /// refuses proves nothing by refusing. So assert the REASON — an
    /// un-primed gate refuses as `Unresolved` ("we never ran"), which is a
    /// different fact from any decided refusal.
    #[test]
    fn an_unprimed_gate_refuses_as_unresolved_not_as_a_decision() {
        let dir: Arc<dyn FederationDirectory> = Arc::new(MemoryBackend::new());
        let gate = AccordRelayGate::new(dir, Some("this-node".into()));
        assert_eq!(
            gate.decide(&subject("humanity-accord", "holder-a"), now()),
            RelayDecision::Refused(RelayRefusal::Unresolved),
            "a cache miss is `unresolved` — never an allow, and never mis-reported as a \
             verdict we did not reach"
        );
        assert_eq!(gate.cached_len(), 0, "deciding never populates the cache");
    }

    /// Priming against an EMPTY directory resolves through the real persist
    /// predicate and gets leg (D): no family under the root ⇒ cannot judge.
    /// The decision then flips from `Unresolved` to `RosterUnresolvable` —
    /// proving the resolve actually ran, which a bare "still refused" could
    /// not.
    #[tokio::test]
    async fn priming_an_unheld_root_caches_a_cannot_judge_verdict() {
        let dir: Arc<dyn FederationDirectory> = Arc::new(MemoryBackend::new());
        let gate = AccordRelayGate::new(dir, Some("this-node".into()));
        let t0 = now();
        let s = gate
            .prime(&drill_row("holder-a", "unheld-accord-root"), t0)
            .await
            .expect("a well-formed drill row is judgeable");
        assert_eq!(
            s,
            subject("unheld-accord-root", "holder-a"),
            "the verdict is filed under the pair persist read off the row"
        );
        assert_eq!(
            gate.decide(&s, t0),
            RelayDecision::Refused(RelayRefusal::RosterUnresolvable),
            "persist reports `roster_resolvable: false` for a root we hold no family for"
        );
        assert_eq!(gate.cached_len(), 1, "the verdict was cached");
        // …and expires into `Unresolved` — an expired cannot-judge is not a
        // standing cannot-judge, it is "we no longer know".
        assert_eq!(
            gate.decide(&s, t0 + RELAY_VERDICT_TTL),
            RelayDecision::Refused(RelayRefusal::Unresolved),
        );
    }

    /// A minimal registered key. persist requires every family member to be a
    /// registered `federation_keys` row (members MUST be registered keys), and
    /// `put_public_key` does not hybrid-verify the registration row, so
    /// placeholders are the honest fixture here — nothing in these tests
    /// verifies a signature.
    fn key(key_id: &str) -> ciris_persist::federation::SignedKeyRecord {
        use base64::Engine as _;
        use ciris_persist::federation::types::{algorithm, identity_type};
        use ciris_persist::federation::{KeyRecord, SignedKeyRecord};
        let b64 = base64::engine::general_purpose::STANDARD;
        let now = chrono::Utc::now();
        SignedKeyRecord {
            record: KeyRecord {
                key_id: key_id.to_owned(),
                pubkey_ed25519_base64: b64.encode([0u8; 32]),
                pubkey_ml_dsa_65_base64: Some(b64.encode([0u8; 1952])),
                algorithm: algorithm::HYBRID.to_owned(),
                identity_type: identity_type::NODE.to_owned(),
                identity_ref: format!("node-ref-{key_id}"),
                valid_from: now,
                valid_until: None,
                registration_envelope: serde_json::json!({ "key_id": key_id }),
                original_content_hash: "0".repeat(64),
                scrub_signature_classical: "x".repeat(88),
                scrub_signature_pqc: None,
                scrub_key_id: key_id.to_owned(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        }
    }

    /// Seed a keyless accord family (`put_family_local` — a family holds no key
    /// and cannot sign its own declaration), the way persist's own
    /// `seed_test_family` does.
    async fn seed_family(backend: &MemoryBackend, root: &str, members: &[&str]) {
        use ciris_persist::federation::types::{Family, FamilyMember};
        let founded: chrono::DateTime<chrono::Utc> = "2020-01-01T00:00:00Z"
            .parse()
            .expect("pinned founding instant");
        backend
            .put_family_local(Family {
                family_key_id: root.to_owned(),
                family_name: root.to_owned(),
                members: members
                    .iter()
                    .map(|m| FamilyMember {
                        key_id: (*m).to_owned(),
                        joined_at: founded,
                        role: Some("founder".to_owned()),
                    })
                    .collect(),
                founded_at: founded,
                consensus_protocol: "quorum:2/3".to_owned(),
                consensus_protocol_entrenched: true,
                persist_row_hash: String::new(),
            })
            .await
            .expect("seed the accord family (keyless, local door)");
    }

    /// persist's refusal legs (B), (C) and (D), end to end through the REAL
    /// resolver, over a keyless accord family.
    ///
    /// No trust edge is seeded here (that needs a hybrid-signed federation-tier
    /// attestation, whose fixture machinery lives in the bridge's test module),
    /// so this covers seated-but-un-granted, unseated, and unjudgeable. **The
    /// ALLOW path is proven end-to-end in
    /// `bridge::tests::accord_row_is_relayed_when_the_gate_allows_and_withheld_when_it_refuses`**
    /// — the #435 lesson holds: a gate only ever seen refusing is
    /// indistinguishable from a gate that is dead.
    #[tokio::test]
    async fn the_refusal_legs_through_the_real_resolver() {
        let root = "relay-accord-root";
        let seated = "relay-holder-a";
        let stranger = "relay-stranger";
        let us = "relay-this-node";

        let backend = Arc::new(MemoryBackend::new());
        for who in [root, seated, stranger, us] {
            backend
                .put_public_key(key(who))
                .await
                .expect("register key");
        }
        seed_family(&backend, root, &[seated]).await;

        let dir: Arc<dyn FederationDirectory> = backend;
        let gate = AccordRelayGate::new(Arc::clone(&dir), Some(us.to_owned()));
        let t0 = now();

        // (B) seated signer, but this node has NOT granted the root. The leg a
        // bare `Global` projection runs straight over.
        assert_eq!(
            gate.may_relay_attestation(
                &accord_row_value(ACCORD_HEARTBEAT_DIMENSION, seated, root, None),
                t0
            )
            .await,
            RelayDecision::Refused(RelayRefusal::NoTrustEdge),
            "seated but un-granted: CC 4.2.1 — simply not reached"
        );

        // (C) signer NOT on the roster. The roster IS resolvable here, so this
        // must read as `signer_not_seated` and never as `cannot judge`.
        assert_eq!(
            gate.may_relay_attestation(
                &accord_row_value(ACCORD_HEARTBEAT_DIMENSION, stranger, root, None),
                t0
            )
            .await,
            RelayDecision::Refused(RelayRefusal::SignerNotSeated),
        );

        // (D) an object naming a DIFFERENT root this node holds no family for —
        // cannot judge, and distinctly so. Same signer, same node: only the
        // root THE OBJECT NAMES changed, and the REASON changes with it.
        assert_eq!(
            gate.may_relay_attestation(
                &accord_row_value(
                    ACCORD_HEARTBEAT_DIMENSION,
                    seated,
                    "some-other-accord",
                    None
                ),
                t0
            )
            .await,
            RelayDecision::Refused(RelayRefusal::RosterUnresolvable),
        );

        // Cache expiry fails CLOSED, and reports that it no longer knows.
        assert_eq!(
            gate.decide(&subject(root, seated), t0 + RELAY_VERDICT_TTL),
            RelayDecision::Refused(RelayRefusal::Unresolved),
            "an expired verdict stops being a verdict until it is re-resolved"
        );
    }

    /// **THE #731 REGRESSION TEST, at the gate.** A node that trusts BOTH
    /// accords, a signer seated on A only, and an object belonging to B.
    ///
    /// The pre-#731 gate held `root_ref = "accord-a"` as construction state and
    /// judged *every* object against it, so this object — which says `accord-b`
    /// in its own signed bytes — resolved (seated on A ✓, edge to A ✓) and was
    /// CARRIED. That is persist's *"confidently wrong answer in the permissive
    /// direction"*.
    ///
    /// The trust edge (leg 2) is not seeded here — it needs a hybrid-signed
    /// federation attestation — so this asserts the leg that DIFFERS between
    /// the two roots: seating. Under B the signer is not seated, so the answer
    /// changes from the old code's allow to `signer_not_seated`. The full
    /// old-allows/new-refuses pair WITH a live edge, and the accompanying
    /// "a legitimately-seated signer IS still served" half, is
    /// `bridge::tests::an_object_belonging_to_another_accord_is_not_relayed_on_this_ones_roster`.
    #[tokio::test]
    async fn an_object_naming_another_root_is_judged_against_that_root() {
        let us = "x-node";
        let signer = "x-holder-on-a";
        let backend = Arc::new(MemoryBackend::new());
        for who in [us, signer, "some-other-holder", "accord-a", "accord-b"] {
            backend.put_public_key(key(who)).await.expect("register");
        }
        // The node holds a family for BOTH accords — so "cannot judge" is not
        // what is doing the work here; the roster resolves either way.
        seed_family(&backend, "accord-a", &[signer]).await;
        seed_family(&backend, "accord-b", &["some-other-holder"]).await;

        let dir: Arc<dyn FederationDirectory> = backend;
        let gate = AccordRelayGate::new(dir, Some(us.to_owned()));
        let t0 = now();

        // The object says `accord-b`. The signer is seated on `accord-a`.
        let decision = gate
            .may_relay_attestation(
                &accord_row_value(ACCORD_HEARTBEAT_DIMENSION, signer, "accord-b", None),
                t0,
            )
            .await;
        assert_eq!(
            decision,
            RelayDecision::Refused(RelayRefusal::SignerNotSeated),
            "the verdict is resolved against the root THE OBJECT NAMES (`accord-b`), where \
             this signer holds no seat — the pre-#731 gate judged it against the \
             host-nominated `accord-a`, found a seat, and carried it"
        );
        // And the SAME signer, on an object naming the root it IS seated on,
        // reaches the seating leg — so this is not a gate that refuses
        // everything. (It stops at `no_trust_edge`, leg 2, which is the next
        // leg after seating passes.)
        assert_eq!(
            gate.may_relay_attestation(
                &accord_row_value(ACCORD_HEARTBEAT_DIMENSION, signer, "accord-a", None),
                t0,
            )
            .await,
            RelayDecision::Refused(RelayRefusal::NoTrustEdge),
            "on its OWN accord the signer IS seated — seating passes and the refusal moves \
             to the trust-edge leg, so the refusal above is about the ROOT, not a blanket no"
        );
        assert_eq!(
            gate.cached_len(),
            2,
            "two roots, two entries — one signer does NOT collapse to one cached verdict"
        );
    }

    /// **ALL FIVE object refusals, carried through the serve-path ENTRY POINT.**
    ///
    /// [`AccordRelaySubject::of_row`] is unit-tested above, but that proves only
    /// that the DERIVATION refuses; it says nothing about what
    /// [`AccordRelayGate::may_relay_attestation`] does with an `Err`. Turning
    /// either `Err` arm into an allow is a one-token edit.
    ///
    /// # Every leg is asserted HERE, and that is the point
    ///
    /// This test originally covered two of the five, and a mutation run found
    /// the hole the user's rule predicts: flipping the `Disagrees` arm to
    /// `Named` left the entire suite green except the DERIVATION test, because
    /// nothing asserted what the GATE would then do with the row — and what it
    /// would do is resolve it against the envelope-named root and CARRY it if
    /// the signer happened to be seated there. So the roster below seats the
    /// signer on every root these rows name, which turns each refusal into a
    /// claim that survives the seating leg: a mutation that stops refusing gets
    /// `no_trust_edge` (or a relay), never the expected leg.
    ///
    /// The seated-signer half is asserted too, so this cannot pass by refusing
    /// everything.
    #[tokio::test]
    async fn the_serve_entry_point_refuses_every_row_it_cannot_judge() {
        let us = "e-node";
        let signer = "e-holder";
        let root = "e-accord";
        let other = "e-other-accord";
        let backend = Arc::new(MemoryBackend::new());
        for who in [us, signer, root, other] {
            backend.put_public_key(key(who)).await.expect("register");
        }
        // The signer is SEATED on both roots any row below names. So if a leg
        // stopped refusing, the gate would reach persist's seating leg and pass
        // it — the answer would change to `no_trust_edge`, and every assertion
        // here would red. A roster that seated nobody would let a broken arm
        // land on `signer_not_seated` and hide behind a fail-safe default.
        seed_family(&backend, root, &[signer]).await;
        seed_family(&backend, other, &[signer]).await;
        let dir: Arc<dyn FederationDirectory> = backend;
        let gate = AccordRelayGate::new(dir, Some(us.to_owned()));
        let t0 = now();

        // (1) Not an `Attestation` at all.
        assert_eq!(
            gate.may_relay_attestation(&serde_json::json!({ "attesting_key_id": signer }), t0)
                .await,
            RelayDecision::Refused(RelayRefusal::ObjectUnreadable),
            "an unreadable value is withheld, not carried"
        );

        // (2) A row whose columns diverge from its signed mirror.
        let mut skewed = accord_row_value(ACCORD_HEARTBEAT_DIMENSION, signer, root, None);
        skewed["attested_key_id"] = serde_json::json!(other);
        assert_eq!(
            gate.may_relay_attestation(&skewed, t0).await,
            RelayDecision::Refused(RelayRefusal::MirrorUnbound),
            "an unbound row is withheld — and the signer is seated on BOTH roots here, so \
             a gate that stopped refusing would have CARRIED it"
        );

        // (3) Not on the `accord:*` family at all.
        assert_eq!(
            gate.may_relay_attestation(
                &accord_row_value("scores:reputation:v1", signer, root, None),
                t0
            )
            .await,
            RelayDecision::Refused(RelayRefusal::ObjectNotAccord),
        );

        // (4) On the family, naming no accord.
        assert_eq!(
            gate.may_relay_attestation(
                &accord_row_value("accord:human_dignity:v1", signer, "some-agent", None),
                t0
            )
            .await,
            RelayDecision::Refused(RelayRefusal::ObjectRootUnnamed),
            "no root in the signed bytes ⇒ nothing to judge against ⇒ REFUSE, never carry"
        );

        // (5) On the family, naming TWO. Both named roots seat this signer, so
        // resolving either one instead of refusing reaches the trust-edge leg.
        assert_eq!(
            gate.may_relay_attestation(
                &accord_row_value(ACCORD_HEARTBEAT_DIMENSION, signer, root, Some(other)),
                t0
            )
            .await,
            RelayDecision::Refused(RelayRefusal::ObjectRootDisagrees),
            "one artifact asserting two accords is withheld at the GATE, not merely \
             classified as a disagreement by the derivation"
        );

        assert_eq!(
            gate.cached_len(),
            0,
            "not one of the five reached the resolver, so nothing was cached — a row we \
             cannot judge must not park a verdict on any (root, signer) pair"
        );

        // …and the gate is ALIVE: a well-formed drill by the seated signer gets
        // a real, resolved verdict (leg 2 — no trust edge is seeded here).
        assert_eq!(
            gate.may_relay_attestation(
                &accord_row_value(ACCORD_HEARTBEAT_DIMENSION, signer, root, None),
                t0
            )
            .await,
            RelayDecision::Refused(RelayRefusal::NoTrustEdge),
            "a judgeable row IS judged — the refusals above are about the object, not a \
             gate that refuses everything"
        );
        assert_eq!(gate.cached_len(), 1, "…and that one DID reach the resolver");
    }

    /// CIRISEdge#505 / CIRISPersist#743 — **a TYPE-namespace row is JUDGED,
    /// never skipped**, and a row on BOTH namespaces is gated ONCE.
    ///
    /// The pre-filter fix (bridge's `attestation_is_accord` → persist's
    /// `is_accord_family`) only puts `accord:invoke:*`-TYPED rows in front of
    /// this gate; this pins what the gate DOES with one, on the exact wire
    /// shape such a row produces: the namespace in `attestation_type` (column
    /// AND signed mirror) and no `dimension` key at all. The gate needs no
    /// type-namespace surface of its own — persist's `accord_root_claim`
    /// (which `may_relay_accord_attestation` and
    /// [`AccordRelaySubject::of_row`] both read) takes the TYPE arm of its own
    /// `is_accord_family` call and reads the signed `accord_root` envelope key,
    /// available on every namespace. Asserted here rather than assumed.
    #[tokio::test]
    async fn the_type_namespace_row_is_judged_not_skipped_and_both_namespaces_gate_once() {
        let us = "t-node";
        let signer = "t-holder";
        let second = "t-holder-second";
        let root = "t-accord";
        let backend = Arc::new(MemoryBackend::new());
        for who in [us, signer, second, root] {
            backend.put_public_key(key(who)).await.expect("register");
        }
        // Both signers SEATED, so a leg that stopped judging would surface as
        // a different answer (`no_trust_edge` / a relay), never hide behind a
        // fail-safe default (the five-refusal test's own discipline).
        seed_family(&backend, root, &[signer, second]).await;
        let dir: Arc<dyn FederationDirectory> = backend;
        let gate = AccordRelayGate::new(dir, Some(us.to_owned()));
        let t0 = now();

        // (a) The TYPE-namespace row: `accord:invoke:*` as the type, NO
        // dimension, naming its accord with the signed key. The subject is the
        // signed root + the bound signer — persist's type arm, not a skip.
        let invoke = typed_accord_row_value(
            "accord:invoke:notify:halt",
            None,
            signer,
            signer,
            Some(root),
        );
        assert_eq!(
            AccordRelaySubject::of_attestation(&invoke),
            Ok(subject(root, signer)),
            "the TYPE arm names the root from the signed `accord_root` key"
        );
        assert_eq!(
            gate.may_relay_attestation(&invoke, t0).await,
            RelayDecision::Refused(RelayRefusal::NoTrustEdge),
            "the row is EVALUATED on its merits (seated signer, no consent edge \
             seeded ⇒ leg 2) — before CIRISEdge#505 it never reached this gate"
        );
        assert_eq!(
            gate.cached_len(),
            1,
            "…and it DID reach the resolver: one (root, signer) verdict cached"
        );

        // (a′) The same shape naming NO accord is refused on ITS merits too —
        // fail-closed, with the object leg an operator can act on. The old
        // pre-filter would have CARRIED this row unexamined.
        assert_eq!(
            gate.may_relay_attestation(
                &typed_accord_row_value("accord:invoke:notify:halt", None, signer, signer, None),
                t0
            )
            .await,
            RelayDecision::Refused(RelayRefusal::ObjectRootUnnamed),
            "a type-namespace row naming no accord is REFUSED, never skipped or carried"
        );
        assert_eq!(gate.cached_len(), 1, "an unjudgeable row parks no verdict");

        // (d) BOTH namespaces accord-shaped: one row ⇒ ONE subject ⇒ ONE
        // cached verdict — gated once, no second evaluation for the second
        // namespace. (A second signer, so the single new entry is visible.)
        let both = typed_accord_row_value(
            "accord:invoke:notify:halt",
            Some("accord:human_dignity:v1"),
            second,
            second,
            Some(root),
        );
        assert_eq!(
            AccordRelaySubject::of_attestation(&both),
            Ok(subject(root, second)),
            "two namespaces, ONE subject — the signed root answers for both"
        );
        assert_eq!(
            gate.may_relay_attestation(&both, t0).await,
            RelayDecision::Refused(RelayRefusal::NoTrustEdge),
        );
        assert_eq!(
            gate.cached_len(),
            2,
            "one row on BOTH namespaces adds exactly ONE verdict — gated once"
        );
    }

    /// The ORDERING, not the equivalence.
    ///
    /// Persist showed why the distinction matters: reversing the two checks
    /// left their `refusal_reason_is_none_exactly_when_may_relay_is_true` test
    /// GREEN, because reordering changes WHY it refuses, not WHETHER. Shipping
    /// on equivalence alone yields a verdict saying "the signer is not seated"
    /// when the truth is "I cannot judge" — an accusation substituted for an
    /// admission of ignorance, on a relay gate.
    ///
    /// So this asserts the attribution where BOTH legs are false. No
    /// equivalence test can distinguish the two orderings on that input.
    #[test]
    fn cannot_judge_outranks_not_seated_when_both_legs_are_false() {
        let both_false = RelayVerdict {
            roster_resolvable: false,
            signer_seated: false,
            edge_exists: true,
        };
        assert_eq!(
            decision_of(both_false),
            RelayDecision::Refused(RelayRefusal::RosterUnresolvable),
            "an unresolvable roster is 'I cannot judge' and must NOT be \
             reported as 'the signer is not seated'",
        );
        // ...and the seated leg still reports itself when the roster DID
        // resolve, so this cannot pass by always answering RosterUnresolvable.
        assert_eq!(
            decision_of(RelayVerdict {
                roster_resolvable: true,
                signer_seated: false,
                edge_exists: true,
            }),
            RelayDecision::Refused(RelayRefusal::SignerNotSeated),
        );
    }

    /// persist's participation verb reads `family_key_id` / `member_id` out of
    /// the object, and edge's cache key must agree with what it read — else the
    /// verdict would be filed under a pair the resolver did not use.
    #[test]
    fn the_participation_cache_key_is_what_persists_verb_reads() {
        use ciris_verify_core::accord_live_quorum::{AccordParticipation, Vote};
        use ciris_verify_core::threshold::ThresholdSignature;
        let p = AccordParticipation {
            family_key_id: "accord-q".to_owned(),
            proposal_digest: "0".repeat(64),
            member_id: "holder-q".to_owned(),
            vote: Vote::Yes,
            window_until: "2026-01-01T00:00:00Z".to_owned(),
            signed_at: "2026-01-01T00:00:00Z".to_owned(),
            signature: ThresholdSignature {
                member_id: "holder-q".to_owned(),
                ed25519_signature_base64: String::new(),
                mldsa65_signature_base64: None,
            },
        };
        assert_eq!(
            AccordRelaySubject::of_participation(&p),
            subject("accord-q", "holder-q"),
            "the pair is (family_key_id, member_id) — the same two signature-covered fields \
             `may_relay_accord_participation` reads"
        );
    }

    /// The apply-path invalidation, at the gate's own surface: a cached verdict
    /// is dropped the moment a state change naming the signer (or the root)
    /// arrives, so the very next sync decision is `Unresolved` rather than the
    /// stale one.
    #[tokio::test]
    async fn invalidation_drops_a_cached_verdict_before_the_ttl() {
        let dir: Arc<dyn FederationDirectory> = Arc::new(MemoryBackend::new());
        let gate = AccordRelayGate::new(dir, Some("us".into()));
        let t0 = now();
        let s = subject("accord-root", "holder-a");
        let row = drill_row("holder-a", "accord-root");
        // Prime a verdict (an empty directory yields cannot-judge; what is
        // under test is the CACHE lifecycle, not the verdict's value).
        gate.prime(&row, t0).await.expect("judgeable");
        assert_eq!(gate.cached_len(), 1);
        assert_eq!(
            gate.decide(&s, t0),
            RelayDecision::Refused(RelayRefusal::RosterUnresolvable),
            "primed: the decision is the resolved verdict"
        );

        gate.invalidate("holder-a");
        assert_eq!(
            gate.decide(&s, t0),
            RelayDecision::Refused(RelayRefusal::Unresolved),
            "post-invalidation the gate reports `unresolved` — it no longer knows, and \
             says so instead of serving the dropped verdict"
        );

        // A root-naming invalidation drops every signer under THAT root.
        for r in [
            &row,
            &drill_row("holder-b", "accord-root"),
            &drill_row("holder-a", "other-root"),
        ] {
            gate.prime(r, t0).await.expect("judgeable");
        }
        assert_eq!(gate.cached_len(), 3);
        gate.invalidate("accord-root");
        assert_eq!(
            gate.cached_len(),
            1,
            "a change naming the ROOT falsifies every verdict under it — and only under it"
        );
    }

    /// **THE REQUIRED #733 PAIR, at the gate.** A row whose SIGNED `accord_root`
    /// key names accord B, signed by a holder seated only on accord A, on a node
    /// that holds a real family for BOTH — so `cannot judge` is doing none of
    /// the work here and the roster resolves either way.
    ///
    /// This is the shape #733 made possible and #731 made necessary: pre-#733
    /// the row could only be judged if its DIMENSION happened to be the drill
    /// one, and pre-#731 it was judged against whichever root the host had
    /// nominated — which, for a signer seated on A, was an ALLOW.
    ///
    /// Both halves are asserted. The refusal half alone would be satisfied by a
    /// gate that refuses everything; the twin — the same signer, the same
    /// dimension, the same node, with only the row's named root changed to the
    /// one it IS seated on — passes the seating leg and moves the refusal to the
    /// trust-edge leg, which is the next one along. (The full allow, with a live
    /// `delegates_to(self → root)` and a genuinely SERVED row, is
    /// `bridge::tests::a_signed_accord_root_decides_which_roster_judges_the_row`
    /// — a trust edge needs the bridge module's hybrid-signing fixtures.)
    #[tokio::test]
    async fn a_signed_accord_root_naming_another_accord_is_judged_against_that_one() {
        let us = "sk-node";
        let signer = "sk-holder-on-a";
        let backend = Arc::new(MemoryBackend::new());
        for who in [us, signer, "sk-other-holder", "accord-a", "accord-b"] {
            backend.put_public_key(key(who)).await.expect("register");
        }
        seed_family(&backend, "accord-a", &[signer]).await;
        seed_family(&backend, "accord-b", &["sk-other-holder"]).await;

        let dir: Arc<dyn FederationDirectory> = backend;
        let gate = AccordRelayGate::new(dir, Some(us.to_owned()));
        let t0 = now();

        // A NON-drill dimension, so the ONLY thing naming the accord is the
        // signed `accord_root` key — the drill fallback cannot answer here, and
        // `attested_key_id` is the scored agent.
        assert_eq!(
            gate.may_relay_attestation(
                &accord_row_value(
                    "accord:human_dignity:v1",
                    signer,
                    "some-scored-agent",
                    Some("accord-b")
                ),
                t0
            )
            .await,
            RelayDecision::Refused(RelayRefusal::SignerNotSeated),
            "the row NAMES accord-b, so accord-b's roster judges it — and this signer holds \
             no seat there. Judging it on accord-a's roster (where it IS seated) is the \
             confidently-wrong allow #731 reports"
        );

        // THE POSITIVE TWIN — only the named root changed.
        assert_eq!(
            gate.may_relay_attestation(
                &accord_row_value(
                    "accord:human_dignity:v1",
                    signer,
                    "some-scored-agent",
                    Some("accord-a")
                ),
                t0
            )
            .await,
            RelayDecision::Refused(RelayRefusal::NoTrustEdge),
            "on the accord it NAMES and IS seated on, seating passes and the refusal moves \
             to the trust-edge leg — so the refusal above is about the ROOT, not a gate \
             that refuses every row it is shown"
        );
        assert_eq!(
            gate.cached_len(),
            2,
            "two named roots, two cached verdicts for one signer"
        );
    }
}
