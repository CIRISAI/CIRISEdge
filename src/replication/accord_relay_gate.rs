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
//! ## Zero trust logic here
//!
//! The whole verdict is persist's
//! [`may_relay_accord_object`] — seated signer AND a live
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
//! [`may_relay_accord_object`] is `async`; the replication serve path
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
//! absent directory, an absent local identity, and `roster_resolvable == false`
//! all refuse. [`RelayRefusal::Unresolved`] is deliberately distinct from every
//! decided refusal, so a refusal *because we never ran the predicate* can never
//! be read as a refusal *because we decided* — the distinction a fail-safe
//! default otherwise hides.
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

use ciris_persist::federation::namespace::{attestation_family, AttestationFamily};
use ciris_persist::federation::trust_root::{may_relay_accord_object, RelayVerdict};
use ciris_persist::federation::FederationDirectory;

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
    /// family under that root. **"I cannot judge", NOT "the signer is not
    /// seated"**, and it refuses. Remedy: sync the root's family record.
    RosterUnresolvable,
    /// The roster resolved and `signer_key_id` holds no live seat on it
    /// (revocation-folded). Trusting a root does not make every key naming it
    /// authoritative.
    SignerNotSeated,
    /// No live `delegates_to(self → root)`: this node never granted the root,
    /// or has cut the edge. CC 4.2.1 — *"simply not reached"*. This is the leg
    /// a bare `Global` projection runs straight over.
    NoTrustEdge,
    /// **We never ran the predicate**: no verdict is cached for this signer, or
    /// the cached one expired / was invalidated, and the sync gate cannot
    /// resolve. Deliberately distinct from every decided refusal above — a
    /// refusal that reports itself as unresolved is the one an operator can act
    /// on, and it keeps a green test from proving nothing when the surrounding
    /// default already refuses.
    Unresolved,
    /// The gate has no `self_key_id`, so there is no "I" whose
    /// `delegates_to(self → root)` could exist. A WIRING fault
    /// (`ReplicationRuntimeConfig::local_key_id`), not a policy decision.
    NoLocalIdentity,
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
        }
    }
}

impl std::fmt::Display for RelayRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
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

/// One cached verdict for one signer, under this gate's root.
#[derive(Debug, Clone, Copy)]
struct CachedVerdict {
    verdict: RelayVerdict,
    /// Monotonic instant of resolution ([`Instant`], never `tokio::time` —
    /// CIRISEdge#217: this rides a replication/transport path that can run on
    /// persist's runtime thread).
    fetched_at: Instant,
}

/// The pure, directory-free verdict cache. Split out from [`AccordRelayGate`]
/// so the freshness / invalidation / fail-closed rules are unit-testable
/// without a trust fixture (resolution correctness is persist's, tested there).
#[derive(Debug, Default)]
struct VerdictCache {
    /// Bumped by EVERY invalidation. An in-flight resolve snapshots it at the
    /// miss and commits only if it is unchanged — see [`Self::commit`].
    generation: u64,
    by_signer: HashMap<String, CachedVerdict>,
}

impl VerdictCache {
    /// The cached verdict for `signer` iff a FRESH one exists. `None` means
    /// "no usable verdict", which the sync gate turns into
    /// [`RelayRefusal::Unresolved`] — never into an allow.
    fn get_fresh(&self, signer: &str, now: Instant) -> Option<RelayVerdict> {
        let entry = self.by_signer.get(signer)?;
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
    fn commit(&mut self, signer: &str, verdict: RelayVerdict, gen_at_miss: u64, now: Instant) {
        if self.generation != gen_at_miss {
            return;
        }
        // Bound memory: a departed signer must not accumulate. The live set is
        // naturally roster-sized, but the key is peer-supplied (the row's
        // `attesting_key_id`), so an unbounded map would be a cheap DoS.
        self.by_signer
            .retain(|_, v| now.saturating_duration_since(v.fetched_at) < RELAY_VERDICT_TTL);
        self.by_signer.insert(
            signer.to_owned(),
            CachedVerdict {
                verdict,
                fetched_at: now,
            },
        );
    }

    /// Drop every entry a state change naming `key_id` could falsify: the
    /// signer whose verdict it is. A change naming the ROOT falsifies every
    /// entry (both legs are root-relative), so the caller widens that to
    /// [`Self::invalidate_all`].
    ///
    /// Bumps the generation unconditionally — including when nothing matched —
    /// so an in-flight resolve started before this call can never commit over
    /// it.
    fn invalidate(&mut self, key_id: &str) {
        self.generation = self.generation.wrapping_add(1);
        self.by_signer.remove(key_id);
    }

    /// Drop everything (a root-relative change, or a coarse "trust state moved"
    /// signal). Bumps the generation for the same reason.
    fn invalidate_all(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.by_signer.clear();
    }
}

/// The `accord:*` relay gate (workstream F). Wraps persist's
/// [`may_relay_accord_object`] with a TTL'd, apply-path-invalidated cache and a
/// pure sync predicate; see the module docs.
///
/// # The root is an INSTANCE parameter, supplied by the host
///
/// CC 4.2.3 is explicit that the accord roster belongs to a root — *"another
/// instantiation of this form names its own three"* — so `root_ref` is
/// construction state, not a baked constant, and every cache key is
/// `(this root, signer)`. An `accord:*` row carries NO field naming the root it
/// acts under, and persist exposes no `accord_root_of(row)` resolver, so the
/// value has to arrive from the wiring seam (for a single-instance fleet, the
/// genesis accord family id). Deriving it inside edge — from `attested_key_id`,
/// from a baked id, from anything — would be edge holding a rule about which
/// root an object belongs to, which is persist's to own. See the report note.
pub struct AccordRelayGate {
    directory: Arc<dyn FederationDirectory>,
    /// "I" — this node's federation `key_id`, the subject of leg 2's
    /// `delegates_to(self → root)`. `None` holds the gate fully closed
    /// ([`RelayRefusal::NoLocalIdentity`]): a wiring fault, and a gate with no
    /// "I" cannot evaluate consent-scoped reach at all.
    self_key_id: Option<String>,
    /// The accord trust root whose roster seats the signer and to which this
    /// node's edge must run.
    root_ref: String,
    cache: Mutex<VerdictCache>,
}

impl AccordRelayGate {
    /// Build a gate over `directory`, anchored at `self_key_id` (our federation
    /// key), for the accord root `root_ref`. `None` for `self_key_id` holds the
    /// gate fully closed.
    #[must_use]
    pub fn new(
        directory: Arc<dyn FederationDirectory>,
        self_key_id: Option<String>,
        root_ref: impl Into<String>,
    ) -> Self {
        Self {
            directory,
            self_key_id,
            root_ref: root_ref.into(),
            cache: Mutex::new(VerdictCache::default()),
        }
    }

    /// The accord root this gate judges against.
    #[must_use]
    pub fn root_ref(&self) -> &str {
        &self.root_ref
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
    /// Fail-closed on every absence: no local identity, no cached verdict, an
    /// expired verdict, an invalidated verdict. It NEVER resolves — resolution
    /// is [`Self::prime`]'s job, so a per-envelope serve gate can never turn
    /// into a per-envelope trust walk (the CIRISEdge#400 regression).
    pub fn decide(&self, signer_key_id: &str, now: Instant) -> RelayDecision {
        if self.self_key_id.is_none() {
            return RelayDecision::Refused(RelayRefusal::NoLocalIdentity);
        }
        let cached = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_fresh(signer_key_id, now);
        match cached {
            Some(verdict) => decision_of(verdict),
            None => RelayDecision::Refused(RelayRefusal::Unresolved),
        }
    }

    /// Resolve `signer_key_id`'s verdict through persist and cache it, unless a
    /// fresh one is already held (cache-first — a hit costs one lock and no
    /// directory read). The ONE async step, called from the async serve paths
    /// before their sync [`Self::decide`].
    ///
    /// The cache lock is taken twice, briefly, and **never held across the
    /// `.await`** (CIRISEdge#217). A resolver error does NOT cache: a transient
    /// directory fault must not pin a signer refused past the fault — the next
    /// call re-resolves, and [`Self::decide`] refuses meanwhile as
    /// [`RelayRefusal::Unresolved`], which says exactly what happened.
    pub async fn prime(&self, signer_key_id: &str, now: Instant) {
        let Some(us) = self.self_key_id.as_deref() else {
            return;
        };
        let gen_at_miss = {
            let guard = self
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if guard.get_fresh(signer_key_id, now).is_some() {
                return;
            }
            // Snapshot the generation WITH the miss check, so an invalidation
            // during the `.await` below is detected at commit.
            guard.generation
        };

        let verdict = match may_relay_accord_object(
            &*self.directory,
            us,
            signer_key_id,
            &self.root_ref,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    signer = signer_key_id,
                    root = %self.root_ref,
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
            .commit(signer_key_id, verdict, gen_at_miss, now);
    }

    /// [`Self::prime`] then [`Self::decide`] — the convenience an ASYNC gate
    /// site uses. The decision is still the pure sync predicate; this only
    /// guarantees a resolution attempt has happened first.
    pub async fn may_relay(&self, signer_key_id: &str, now: Instant) -> RelayDecision {
        self.prime(signer_key_id, now).await;
        self.decide(signer_key_id, now)
    }

    /// Drop cached verdicts a state change naming `key_id` could falsify.
    /// Wired to the replication APPLY path so an in-band roster change,
    /// revocation, or trust-edge tombstone takes effect before the TTL would
    /// expire; [`RELAY_VERDICT_TTL`] is the backstop if an event is missed.
    ///
    /// Deliberately over-broad: `key_id` naming the ROOT (or the root's family)
    /// drops EVERY entry, since both of persist's legs are root-relative.
    /// Choosing invalidation keys is a cache concern, not a trust rule — being
    /// too eager only costs a re-resolve, while being too narrow caches a
    /// verdict past the event that falsified it.
    pub fn invalidate(&self, key_id: &str) {
        let mut guard = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if key_id == self.root_ref {
            guard.invalidate_all();
        } else {
            guard.invalidate(key_id);
        }
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
            .by_signer
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

    // ── VerdictCache: freshness, fail-closed miss, invalidation ──────────

    #[test]
    fn a_miss_is_none_never_a_default() {
        let c = VerdictCache::default();
        assert!(c.get_fresh("never-seen", now()).is_none());
    }

    #[test]
    fn a_committed_verdict_is_a_cache_hit_within_the_ttl() {
        let mut c = VerdictCache::default();
        let t0 = now();
        c.commit("holder-a", verdict(true, true, true), 0, t0);
        assert_eq!(
            c.get_fresh(
                "holder-a",
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
        c.commit("holder-a", verdict(true, true, true), 0, t0);
        assert!(
            c.get_fresh("holder-a", t0 + RELAY_VERDICT_TTL).is_none(),
            "expired AT the TTL — an expired ALLOW must not keep relaying"
        );
    }

    #[test]
    fn invalidate_drops_the_named_signer_and_leaves_the_others() {
        let mut c = VerdictCache::default();
        let t0 = now();
        c.commit("holder-a", verdict(true, true, true), c.generation, t0);
        c.commit("holder-b", verdict(true, true, true), c.generation, t0);
        c.invalidate("holder-a");
        assert!(c.get_fresh("holder-a", t0).is_none(), "holder-a dropped");
        assert_eq!(
            c.get_fresh("holder-b", t0),
            Some(verdict(true, true, true)),
            "an unrelated signer's verdict survives a targeted invalidation"
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
        // A resolve begins: snapshot the generation at the miss.
        let gen_at_miss = c.generation;
        // …an invalidation lands DURING the (awaited) resolve.
        c.invalidate("holder-a");
        // …and the in-flight resolve now tries to commit its stale answer.
        c.commit("holder-a", verdict(true, true, true), gen_at_miss, t0);
        assert!(
            c.get_fresh("holder-a", t0).is_none(),
            "the racing commit is DROPPED — the invalidation is not clobbered, and the \
             next call re-resolves against live state"
        );
        // A fresh resolve (snapshot taken after the invalidation) commits fine.
        let gen_now = c.generation;
        c.commit("holder-a", verdict(true, true, true), gen_now, t0);
        assert_eq!(c.get_fresh("holder-a", t0), Some(verdict(true, true, true)));
    }

    #[test]
    fn invalidate_all_clears_every_entry() {
        let mut c = VerdictCache::default();
        let t0 = now();
        c.commit("holder-a", verdict(true, true, true), c.generation, t0);
        c.commit("holder-b", verdict(true, true, true), c.generation, t0);
        c.invalidate_all();
        assert!(c.get_fresh("holder-a", t0).is_none());
        assert!(c.get_fresh("holder-b", t0).is_none());
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
        let gate = AccordRelayGate::new(dir, None, "humanity-accord");
        assert_eq!(
            gate.decide("any-holder", now()),
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
        let gate = AccordRelayGate::new(dir, Some("this-node".into()), "humanity-accord");
        assert_eq!(
            gate.decide("holder-a", now()),
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
        let gate = AccordRelayGate::new(dir, Some("this-node".into()), "unheld-accord-root");
        let t0 = now();
        assert_eq!(
            gate.may_relay("holder-a", t0).await,
            RelayDecision::Refused(RelayRefusal::RosterUnresolvable),
            "persist reports `roster_resolvable: false` for a root we hold no family for"
        );
        assert_eq!(gate.cached_len(), 1, "the verdict was cached");
        // The cached verdict is served by the SYNC predicate, unchanged.
        assert_eq!(
            gate.decide("holder-a", t0),
            RelayDecision::Refused(RelayRefusal::RosterUnresolvable),
        );
        // …and expires into `Unresolved` — an expired cannot-judge is not a
        // standing cannot-judge, it is "we no longer know".
        assert_eq!(
            gate.decide("holder-a", t0 + RELAY_VERDICT_TTL),
            RelayDecision::Refused(RelayRefusal::Unresolved),
        );
    }

    /// persist's refusal legs (B), (C) and (D), end to end through the REAL
    /// resolver, over a keyless accord family seeded exactly the way persist's
    /// own `seed_test_family` seeds one (`put_family_local` — a family holds no
    /// key and cannot sign its own declaration).
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
        use ciris_persist::federation::types::{algorithm, identity_type, Family, FamilyMember};
        use ciris_persist::federation::{KeyRecord, SignedKeyRecord};

        /// A minimal registered key. persist requires every family member to be
        /// a registered `federation_keys` row (members MUST be registered
        /// keys), and `put_public_key` does not hybrid-verify the registration
        /// row, so placeholders are the honest fixture here — nothing in this
        /// test verifies a signature.
        fn key(key_id: &str) -> SignedKeyRecord {
            use base64::Engine as _;
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
        let founded: chrono::DateTime<chrono::Utc> = "2020-01-01T00:00:00Z"
            .parse()
            .expect("pinned founding instant");
        backend
            .put_family_local(Family {
                family_key_id: root.to_owned(),
                family_name: root.to_owned(),
                members: vec![FamilyMember {
                    key_id: seated.to_owned(),
                    joined_at: founded,
                    role: Some("founder".to_owned()),
                }],
                founded_at: founded,
                consensus_protocol: "quorum:2/3".to_owned(),
                consensus_protocol_entrenched: true,
                persist_row_hash: String::new(),
            })
            .await
            .expect("seed the accord family (keyless, local door)");

        let dir: Arc<dyn FederationDirectory> = backend;
        let gate = AccordRelayGate::new(Arc::clone(&dir), Some(us.to_owned()), root);
        let t0 = now();

        // (B) seated signer, but this node has NOT granted the root. The leg a
        // bare `Global` projection runs straight over.
        assert_eq!(
            gate.may_relay(seated, t0).await,
            RelayDecision::Refused(RelayRefusal::NoTrustEdge),
            "seated but un-granted: CC 4.2.1 — simply not reached"
        );

        // (C) signer NOT on the roster. The roster IS resolvable here, so this
        // must read as `signer_not_seated` and never as `cannot judge`.
        assert_eq!(
            gate.may_relay(stranger, t0).await,
            RelayDecision::Refused(RelayRefusal::SignerNotSeated),
        );

        // (D) a DIFFERENT root this node holds no family for — cannot judge,
        // and distinctly so. Same signer, same node: only the root changed,
        // and the REASON changes with it.
        let blind = AccordRelayGate::new(dir, Some(us.to_owned()), "some-other-accord");
        assert_eq!(
            blind.may_relay(seated, t0).await,
            RelayDecision::Refused(RelayRefusal::RosterUnresolvable),
        );

        // Cache expiry fails CLOSED, and reports that it no longer knows.
        assert_eq!(
            gate.decide(seated, t0 + RELAY_VERDICT_TTL),
            RelayDecision::Refused(RelayRefusal::Unresolved),
            "an expired verdict stops being a verdict until it is re-resolved"
        );
    }

    /// The apply-path invalidation, at the gate's own surface: a cached ALLOW
    /// is dropped the moment a state change naming the signer (or the root)
    /// arrives, so the very next sync decision is `Unresolved` rather than the
    /// stale grant.
    #[tokio::test]
    async fn invalidation_drops_a_cached_allow_before_the_ttl() {
        let dir: Arc<dyn FederationDirectory> = Arc::new(MemoryBackend::new());
        let gate = AccordRelayGate::new(dir, Some("us".into()), "accord-root");
        let t0 = now();
        // Prime a verdict (an empty directory yields cannot-judge; what is
        // under test is the CACHE lifecycle, not the verdict's value).
        let _ = gate.may_relay("holder-a", t0).await;
        assert_eq!(gate.cached_len(), 1);
        assert_eq!(
            gate.decide("holder-a", t0),
            RelayDecision::Refused(RelayRefusal::RosterUnresolvable),
            "primed: the decision is the resolved verdict"
        );

        gate.invalidate("holder-a");
        assert_eq!(
            gate.decide("holder-a", t0),
            RelayDecision::Refused(RelayRefusal::Unresolved),
            "post-invalidation the gate reports `unresolved` — it no longer knows, and \
             says so instead of serving the dropped verdict"
        );

        // A root-naming invalidation is the broad one: both legs are
        // root-relative, so every entry goes.
        let _ = gate.may_relay("holder-a", t0).await;
        let _ = gate.may_relay("holder-b", t0).await;
        assert_eq!(gate.cached_len(), 2);
        gate.invalidate("accord-root");
        assert_eq!(
            gate.cached_len(),
            0,
            "a change naming the ROOT falsifies every verdict under it"
        );
    }
}
