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
//! ## WHICH accord? The OBJECT says — never the host (CIRISPersist#731)
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
//! So the nominated root is **gone**. Both arguments to persist's predicate are
//! now read out of the object's own **signature-covered** bytes — see
//! [`AccordRelaySubject`] — and the cache is keyed by the PAIR, because the
//! same signer under two different roots has two different correct verdicts and
//! a signer-keyed cache would reintroduce exactly the confusion the verb fix
//! removed.
//!
//! ## Zero trust logic here
//!
//! The whole verdict is persist's — [`may_relay_accord_participation`] for an
//! [`AccordParticipation`], [`may_relay_accord_object`] for an `accord:*`
//! attestation whose signed bytes named its root. Seated signer AND a live
//! `delegates_to(self → root)`. This module resolves, caches, and enforces; it
//! decides nothing. It does not re-derive seating, roster membership, or edge
//! existence, and the family classification of a dimension is persist's
//! [`attestation_family`](ciris_persist::federation::namespace::attestation_family)
//! (the same fold `attestation_requires_serve` took in v17.7.0), never an
//! edge-side `"accord:"` prefix match.
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
//! absent directory, an absent local identity, an unreadable object, an object
//! that names no root, and `roster_resolvable == false` all refuse.
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

use ciris_persist::federation::admission::envelope_dimension;
use ciris_persist::federation::envelope::{paths, RowMirror};
use ciris_persist::federation::namespace::{attestation_family, AttestationFamily};
use ciris_persist::federation::trust_root::{
    may_relay_accord_object, may_relay_accord_participation, RelayVerdict,
    ACCORD_HEARTBEAT_DIMENSION,
};
use ciris_persist::federation::FederationDirectory;
use ciris_verify_core::accord_live_quorum::AccordParticipation;

/// The row column holding the SIGNED envelope. persist publishes the member
/// names INSIDE the envelope ([`paths`] / [`ciris_persist::federation::envelope::row_paths`])
/// but the column that holds it is a schema name on
/// [`Attestation`](ciris_persist::federation::Attestation), so it is spelled
/// here — the one string this module owns, and the same one
/// `attestation_requires_serve` and the quarantine consult already read.
const ATTESTATION_ENVELOPE: &str = "attestation_envelope";

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
    /// CIRISPersist#731 — the object's SIGNED bytes could not be read: no
    /// `attestation_envelope`, no `row` mirror, or a mirror that is not
    /// persist's [`RowMirror`]. Neither the signer nor the root is knowable, so
    /// there is no question to ask. Fail-closed and LOUD (CIRISEdge#425) — a
    /// malformed row, never a silent `continue`.
    ObjectUnreadable,
    /// CIRISPersist#731 — the object parsed, but **nothing in its signed bytes
    /// names the accord it acts under**. Answering "which root?" from
    /// construction state is the exact permissive failure #731 reports, so this
    /// refuses instead. See [`AccordRelaySubject::of_attestation`]: an UPSTREAM
    /// gap, not a local misconfiguration.
    ObjectRootUnnamed,
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
            Self::ObjectRootUnnamed => "object_root_unnamed",
        }
    }
}

impl std::fmt::Display for RelayRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// CIRISPersist#731 — **the two facts a relay decision needs, both read out of
/// the object's own signature-covered bytes**: which accord it acts under, and
/// who signed it.
///
/// # Why this type exists at all
///
/// It is the thing the pre-#731 gate did not have. `may_relay_accord_object`
/// takes `(signer, root)` as parameters, and edge was passing a root the HOST
/// named — so an object belonging to accord B, signed by a key seated on accord
/// A, was judged against A and carried. Making the pair a value derived
/// *from the object* is what removes the caller's ability to nominate.
///
/// # Signed bytes only
///
/// Persist's scrub signature covers `JCS(attestation_envelope)` **and nothing
/// else** — the top-level `attesting_key_id` / `attested_key_id` columns are
/// unsigned copies, bound to the envelope only by `check_row_column_binding` at
/// `put_attestation`. That binding is a receive-path admission gate; this is a
/// SERVE-path carriage gate, so it reads the signed mirror
/// ([`paths::ROW`] → [`RowMirror`], the seven members CIRISPersist#643 stamped
/// inside the signature precisely so a relay could not rewrite them) rather
/// than trusting a column a relay could have edited. Reading the unsigned copy
/// would hand an attacker the choice of root, which is #731 rebuilt one field
/// over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccordRelaySubject {
    /// The accord trust root the object acts under, from the object.
    pub root_ref: String,
    /// The key that signed the object, from the object.
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

    /// The subject of an `accord:*` ATTESTATION row, from its signed envelope.
    ///
    /// # Which field names the root, and why only one dimension qualifies
    ///
    /// The signer is unambiguous: [`RowMirror::attesting_key_id`], signed.
    ///
    /// The ROOT is not, and this is the honest part. `accord:*` is a whole
    /// dimension FAMILY whose only registry rule is `accord_holder-only`
    /// (CC 3.4.1 — it constrains the EMITTER's `identity_type`, and says nothing
    /// about which accord a row belongs to). Persist's own fixtures show
    /// `attested_key_id` carrying different things across the family: for
    /// `accord:human_dignity:v1` it is the AGENT being scored, and for
    /// `accord:invoke:notify:*` it is the self-attesting holder — neither is a
    /// root.
    ///
    /// **Exactly one dimension has an upstream answer.** For
    /// [`ACCORD_HEARTBEAT_DIMENSION`] persist's own trust-root fold resolves
    /// drills as `list_attestations_for(root_ref)` filtered to that dimension —
    /// i.e. persist *defines* an `accord:lifecycle:v1` row about X as a drill
    /// about accord X. Reading `attested_key_id` as the root there consumes
    /// persist's rule; asserting it for any other `accord:*` dimension would be
    /// edge inventing one.
    ///
    /// So every other dimension yields [`RelayRefusal::ObjectRootUnnamed`] and
    /// is REFUSED. That is a real narrowing of what this node will carry, and it
    /// is the correct direction: the alternative is answering "which root?" from
    /// construction state, which is the permissive failure #731 exists to close.
    /// The gap belongs to persist — a taking verb for `accord:*` attestations,
    /// the way [`may_relay_accord_participation`] is the one for participations.
    ///
    /// # Errors
    ///
    /// [`RelayRefusal::ObjectUnreadable`] if the signed envelope or its
    /// [`RowMirror`] cannot be read; [`RelayRefusal::ObjectRootUnnamed`] if it
    /// can, but names no root.
    pub fn of_attestation(canonical_json: &serde_json::Value) -> Result<Self, RelayRefusal> {
        let envelope = canonical_json
            .get(ATTESTATION_ENVELOPE)
            .ok_or(RelayRefusal::ObjectUnreadable)?;
        // The SIGNED mirror, through persist's own typed view of it. `RowMirror`
        // is `deny_unknown_fields`, so this is the exact seven-member object the
        // scrub signature covers — not a hand-spelled pointer walk that could
        // drift from the vocabulary.
        let mirror: RowMirror = envelope
            .get(paths::ROW)
            .and_then(|row| serde_json::from_value(row.clone()).ok())
            .ok_or(RelayRefusal::ObjectUnreadable)?;
        if envelope_dimension(envelope) != Some(ACCORD_HEARTBEAT_DIMENSION) {
            return Err(RelayRefusal::ObjectRootUnnamed);
        }
        Ok(Self {
            root_ref: mirror.attested_key_id,
            signer_key_id: mirror.attesting_key_id,
        })
    }
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
    if verdict.may_relay() {
        return RelayDecision::Relay;
    }
    if !verdict.roster_resolvable {
        return RelayDecision::Refused(RelayRefusal::RosterUnresolvable);
    }
    if !verdict.signer_seated {
        return RelayDecision::Refused(RelayRefusal::SignerNotSeated);
    }
    RelayDecision::Refused(RelayRefusal::NoTrustEdge)
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

    /// Is `dimension` in the `accord:*` family — i.e. is this gate the one that
    /// decides its carriage?
    ///
    /// persist's OWN classifier
    /// ([`attestation_family`], public since v36.1.0 for exactly this fold), never
    /// an edge-side `dimension.starts_with("accord:")`. The registry decides
    /// which family a dimension is in; a second spelling here is two owners for
    /// one wire fact. [`AttestationFamily`] is `#[non_exhaustive]`, so a future
    /// decided family is additive policy rather than a build break — and
    /// `objection:*`, the reserved-prefix sibling, is deliberately NOT in this
    /// family (CIRISPersist#713).
    #[must_use]
    pub fn dimension_is_gated(dimension: &str) -> bool {
        matches!(attestation_family(dimension), AttestationFamily::Accord)
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

    /// Resolve one already-derived subject through persist and cache it, unless
    /// a fresh verdict is already held (cache-first — a hit costs one lock and
    /// no directory read).
    ///
    /// The cache lock is taken twice, briefly, and **never held across the
    /// `.await`** (CIRISEdge#217). A resolver error does NOT cache: a transient
    /// directory fault must not pin a subject refused past the fault — the next
    /// call re-resolves, and [`Self::decide`] refuses meanwhile as
    /// [`RelayRefusal::Unresolved`], which says exactly what happened.
    pub async fn prime(&self, subject: &AccordRelaySubject, now: Instant) {
        let Some(us) = self.self_key_id.as_deref() else {
            return;
        };
        let gen_at_miss = {
            let guard = self
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if guard.get_fresh(subject, now).is_some() {
                return;
            }
            // Snapshot the generation WITH the miss check, so an invalidation
            // during the `.await` below is detected at commit.
            guard.generation
        };

        let verdict = match may_relay_accord_object(
            &*self.directory,
            us,
            &subject.signer_key_id,
            &subject.root_ref,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    signer = %subject.signer_key_id,
                    root = %subject.root_ref,
                    error = %e,
                    "accord relay verdict resolve FAILED — carriage refused as `unresolved` \
                     until the next resolve (fail-closed, workstream F)"
                );
                return;
            }
        };
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .commit(subject, verdict, gen_at_miss, now);
    }

    /// **The serve-path entry point for an `accord:*` attestation row**: derive
    /// the subject from the row's SIGNED bytes, resolve, and decide.
    ///
    /// The row is never trusted to tell the gate which root to use via anything
    /// but its signed mirror, and a row that cannot name one is REFUSED with a
    /// named leg rather than judged against a fallback (CIRISPersist#731).
    pub async fn may_relay_attestation(
        &self,
        canonical_json: &serde_json::Value,
        now: Instant,
    ) -> RelayDecision {
        match AccordRelaySubject::of_attestation(canonical_json) {
            Ok(subject) => {
                self.prime(&subject, now).await;
                self.decide(&subject, now)
            }
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

    /// An `accord:*` attestation row in the SIGNED shape persist v31.0.0
    /// (#643) stamps: the `row` mirror lives inside `attestation_envelope`,
    /// which is what the scrub signature covers. The top-level columns are
    /// written too — deliberately SKEWED in one test below, to prove the gate
    /// reads the signed half.
    fn accord_row(dimension: &str, attesting: &str, attested: &str) -> serde_json::Value {
        serde_json::json!({
            "attestation_id": "att-1",
            "attesting_key_id": attesting,
            "attested_key_id": attested,
            "attestation_type": "scores",
            "attestation_envelope": {
                "dimension": dimension,
                "asserted_at": "2026-01-01T00:00:00Z",
                "row": {
                    "attestation_id": "att-1",
                    "attesting_key_id": attesting,
                    "attestation_type": "scores",
                    "attested_key_id": attested,
                    "cohort_scope": "federation",
                },
            },
        })
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

    // ── AccordRelaySubject: the object names its own root (#731) ──────────

    /// The heartbeat/drill dimension is the ONE `accord:*` shape with an
    /// upstream root rule (persist's trust-root fold resolves drills as
    /// `list_attestations_for(root)` filtered to this dimension), so the signed
    /// `attested_key_id` IS the accord.
    #[test]
    fn a_heartbeat_row_names_its_root_and_its_signer() {
        let row = accord_row(ACCORD_HEARTBEAT_DIMENSION, "holder-a", "accord-x");
        assert_eq!(
            AccordRelaySubject::of_attestation(&row),
            Ok(subject("accord-x", "holder-a")),
            "both halves come from the SIGNED row mirror"
        );
    }

    /// **The signed half wins.** The unsigned top-level columns are bound to
    /// the envelope by persist's `check_row_column_binding` at
    /// `put_attestation` — a RECEIVE-path gate. This is a SERVE-path carriage
    /// gate, so it must not depend on that binding having run: skew the columns
    /// and the subject must be unmoved. Reading the unsigned copy would hand an
    /// attacker the choice of root — CIRISPersist#731 rebuilt one field over.
    #[test]
    fn the_unsigned_columns_cannot_move_the_subject() {
        let mut row = accord_row(ACCORD_HEARTBEAT_DIMENSION, "holder-a", "accord-x");
        row["attesting_key_id"] = serde_json::json!("attacker");
        row["attested_key_id"] = serde_json::json!("accord-the-attacker-prefers");
        assert_eq!(
            AccordRelaySubject::of_attestation(&row),
            Ok(subject("accord-x", "holder-a")),
            "the scrub signature covers JCS(attestation_envelope) and NOTHING else — the \
             top-level columns are unsigned and are not read here"
        );
    }

    /// Every other `accord:*` dimension names no root, so it is refused with
    /// its OWN leg rather than judged against a fallback. `accord_holder-only`
    /// (CC 3.4.1) constrains the emitter's identity type and says nothing about
    /// which accord a row belongs to; persist's own fixtures put a scored AGENT
    /// in `attested_key_id` for `accord:human_dignity:v1` and the self-attesting
    /// HOLDER for `accord:invoke:notify:*`.
    #[test]
    fn a_non_heartbeat_accord_row_names_no_root_and_is_refused_distinctly() {
        for dim in [
            "accord:human_dignity:v1",
            "accord:invoke:notify:halt",
            "accord:halt:v1",
        ] {
            assert_eq!(
                AccordRelaySubject::of_attestation(&accord_row(dim, "holder-a", "someone")),
                Err(RelayRefusal::ObjectRootUnnamed),
                "{dim}: no signed field names the accord — refuse, do NOT fall back to a \
                 host-nominated root (CIRISPersist#731)"
            );
        }
    }

    /// An unreadable object is its own leg, distinct from "names no root":
    /// one is a malformed row, the other a well-formed row with an upstream
    /// vocabulary gap, and they send an operator to different places.
    #[test]
    fn an_unreadable_row_is_its_own_refusal_leg() {
        // No envelope at all.
        assert_eq!(
            AccordRelaySubject::of_attestation(&serde_json::json!({ "attesting_key_id": "a" })),
            Err(RelayRefusal::ObjectUnreadable),
        );
        // Envelope, but no signed `row` mirror (a pre-#643 unstamped row).
        assert_eq!(
            AccordRelaySubject::of_attestation(&serde_json::json!({
                "attestation_envelope": { "dimension": ACCORD_HEARTBEAT_DIMENSION },
            })),
            Err(RelayRefusal::ObjectUnreadable),
        );
        // A `row` that is not persist's closed-member `RowMirror`.
        assert_eq!(
            AccordRelaySubject::of_attestation(&serde_json::json!({
                "attestation_envelope": {
                    "dimension": ACCORD_HEARTBEAT_DIMENSION,
                    "row": { "attesting_key_id": "a", "not_a_mirror_member": 1 },
                },
            })),
            Err(RelayRefusal::ObjectUnreadable),
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

    /// The dimension classifier is persist's, and it covers `accord:*` WITHOUT
    /// covering `objection:*` (which #713 deliberately left on the
    /// conservative row) — pinned here so an edge-side widening cannot happen
    /// by accident.
    #[test]
    fn only_accord_dimensions_are_gated() {
        assert!(AccordRelayGate::dimension_is_gated("accord:lifecycle:v1"));
        assert!(AccordRelayGate::dimension_is_gated("accord:halt:v1"));
        assert!(AccordRelayGate::dimension_is_gated(
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
                !AccordRelayGate::dimension_is_gated(other),
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
        let s = subject("unheld-accord-root", "holder-a");
        let t0 = now();
        gate.prime(&s, t0).await;
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
            gate.may_relay_attestation(&accord_row(ACCORD_HEARTBEAT_DIMENSION, seated, root), t0)
                .await,
            RelayDecision::Refused(RelayRefusal::NoTrustEdge),
            "seated but un-granted: CC 4.2.1 — simply not reached"
        );

        // (C) signer NOT on the roster. The roster IS resolvable here, so this
        // must read as `signer_not_seated` and never as `cannot judge`.
        assert_eq!(
            gate.may_relay_attestation(&accord_row(ACCORD_HEARTBEAT_DIMENSION, stranger, root), t0)
                .await,
            RelayDecision::Refused(RelayRefusal::SignerNotSeated),
        );

        // (D) an object naming a DIFFERENT root this node holds no family for —
        // cannot judge, and distinctly so. Same signer, same node: only the
        // root THE OBJECT NAMES changed, and the REASON changes with it.
        assert_eq!(
            gate.may_relay_attestation(
                &accord_row(ACCORD_HEARTBEAT_DIMENSION, seated, "some-other-accord"),
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
                &accord_row(ACCORD_HEARTBEAT_DIMENSION, signer, "accord-b"),
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
                &accord_row(ACCORD_HEARTBEAT_DIMENSION, signer, "accord-a"),
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

    /// **The serve-path entry point carries the object refusals through.**
    ///
    /// [`AccordRelaySubject::of_attestation`] is unit-tested above, but that
    /// proves only that the DERIVATION refuses; it says nothing about what
    /// [`AccordRelayGate::may_relay_attestation`] does with an `Err`. Turning
    /// that arm into an allow is a one-token edit, and without this test the
    /// whole gate module stays green while every unreadable and rootless
    /// `accord:*` row is carried. MUTATION-VERIFIED (see the module report):
    /// `Err(_) => RelayDecision::Relay` reds exactly this test.
    ///
    /// The seated-signer half is asserted too, so this cannot pass by refusing
    /// everything.
    #[tokio::test]
    async fn the_serve_entry_point_refuses_rows_it_cannot_judge() {
        let us = "e-node";
        let signer = "e-holder";
        let root = "e-accord";
        let backend = Arc::new(MemoryBackend::new());
        for who in [us, signer, root] {
            backend.put_public_key(key(who)).await.expect("register");
        }
        seed_family(&backend, root, &[signer]).await;
        let dir: Arc<dyn FederationDirectory> = backend;
        let gate = AccordRelayGate::new(dir, Some(us.to_owned()));
        let t0 = now();

        // A row whose signed bytes name no accord.
        assert_eq!(
            gate.may_relay_attestation(
                &accord_row("accord:human_dignity:v1", signer, "some-agent"),
                t0
            )
            .await,
            RelayDecision::Refused(RelayRefusal::ObjectRootUnnamed),
            "no root in the signed bytes ⇒ nothing to judge against ⇒ REFUSE, never carry"
        );
        // A row that does not parse at all.
        assert_eq!(
            gate.may_relay_attestation(&serde_json::json!({ "attesting_key_id": signer }), t0)
                .await,
            RelayDecision::Refused(RelayRefusal::ObjectUnreadable),
            "an unreadable row is withheld, not carried"
        );
        assert_eq!(
            gate.cached_len(),
            0,
            "a row we could not read never reached the resolver, so it cached nothing"
        );

        // …and the gate is ALIVE: a well-formed drill by the seated signer gets
        // a real, resolved verdict (leg 2 — no trust edge is seeded here).
        assert_eq!(
            gate.may_relay_attestation(&accord_row(ACCORD_HEARTBEAT_DIMENSION, signer, root), t0)
                .await,
            RelayDecision::Refused(RelayRefusal::NoTrustEdge),
            "a judgeable row IS judged — the refusals above are about the object, not a \
             gate that refuses everything"
        );
        assert_eq!(gate.cached_len(), 1, "…and that one DID reach the resolver");
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
        // Prime a verdict (an empty directory yields cannot-judge; what is
        // under test is the CACHE lifecycle, not the verdict's value).
        gate.prime(&s, t0).await;
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
        gate.prime(&s, t0).await;
        gate.prime(&subject("accord-root", "holder-b"), t0).await;
        gate.prime(&subject("other-root", "holder-a"), t0).await;
        assert_eq!(gate.cached_len(), 3);
        gate.invalidate("accord-root");
        assert_eq!(
            gate.cached_len(),
            1,
            "a change naming the ROOT falsifies every verdict under it — and only under it"
        );
    }
}
