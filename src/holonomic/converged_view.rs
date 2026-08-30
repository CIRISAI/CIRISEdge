//! The READ side of the holonomic claim plane (CIRISEdge#545).
//!
//! Every node publishes signed
//! [`FountainHoldingClaim`](super::swarm_rarity::FountainHoldingClaim)
//! envelopes to its consent cohort, and every peer's converger
//! ([`crate::swarm::runtime`]) acts on the claims it receives. That is
//! already a federated, signed, consent-scoped assertion plane: nodes
//! saying what they hold, and peers converging on the assertions.
//!
//! Until this module it was **write-only from the embedder's side**.
//! `Edge::install_swarm_runtime` routes verified inbound claims into the
//! converger and there the information stopped — nothing could ask what
//! had been converged. A downstream mesh-status surface
//! (CIRISServer#498) could therefore only report *one observer's own
//! store* ("748 identities, 101,631 trace_events, as seen by this node"),
//! because that was the only thing it could honestly say. The
//! cross-node aggregate was sitting in the converger, unreachable.
//!
//! # What this is
//!
//! [`ConvergedClaimView`] is a **tap** on the same post-verify inbound
//! claim plane the converger reads, plus a reader that answers *"what
//! has this node converged about its cohort"* — [`ConvergedClaimView::read`].
//!
//! It is a tap and not a projection of
//! [`ObservedClaims`](crate::swarm::runtime::ObservedClaims) on purpose:
//! that map's shape is documented opaque and its only handle is a
//! `#[doc(hidden)]` test surface, so reading it would have meant widening
//! a private substrate type for a public status endpoint. Tapping the
//! dispatch arm instead gives the reader the identical input (post-AV-9,
//! same `(content_id, peer_id)` identity for "one claim"), keeps its
//! retention horizon its own, and — a real gain — keeps answering when
//! no converger is installed at all, where the old arm dropped the
//! envelope on the floor. [`fold_observations`] is factored out as the
//! pure arithmetic so a future `ObservedClaims → ConvergedView`
//! projection can produce byte-identical counts from the converger's own
//! map without reimplementing anything.
//!
//! # Two properties the consumer depends on
//!
//! ## Counts, not contents
//!
//! The downstream consumer is a **public endpoint**. A public surface
//! that enumerates the mesh's members is a reconnaissance surface, so
//! nothing that identifies a peer, a content_id, or a symbol ever leaves
//! this module. [`ConvergedView`] is numeric in every field — peer ids
//! and content ids exist only inside the accumulator, as the keys the
//! distinct-counts are computed over, and are never returned, logged,
//! or `Debug`-printed. (`converged_view_never_leaks_identifiers` pins
//! that.)
//!
//! ## Unknown is distinguishable from zero
//!
//! "No peers have claimed anything" and "the converged view could not be
//! read" MUST NOT arrive as the same value: reporting `0` on the
//! evidence of a failed read tells the world the mesh is empty when we
//! simply do not know. So the reader returns a two-state
//! [`ConvergenceReading`] — never a bare `Option<ConvergedView>`, which
//! reads as either — and the wire projection is exactly one method,
//! [`ConvergenceReading::converged`]: `None` ⇒ emit `null`, `Some(v)` ⇒
//! emit `v`'s counts **including `Some(0)`**, which is the real,
//! evidenced "converged to nothing".
//!
//! Three things are honestly *unknown* rather than zero, and each is a
//! distinct [`ConvergenceUnavailable`] variant:
//!
//! - the inbound plane was never armed on this node (`Edge::run` never
//!   started) — a zero count would be an artifact of a dead loop;
//! - the plane is armed but has not yet been listening for a full claim
//!   publication window and has heard nothing — a cold start is not
//!   evidence of an empty mesh;
//! - the state could not be read at all (a writer panicked and poisoned
//!   the lock).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::swarm_rarity::FountainHoldingClaim;

/// Default retention horizon for a converged claim. Matches the
/// converger's own `DEFAULT_OBSERVED_CLAIM_TTL` (600s) so the reader and
/// the converger agree on what "still held" means; realigned exactly by
/// [`ConvergedClaimView::align_to_converger`] when a runtime installs
/// with a non-default config.
///
/// Deliberately generous relative to the publish cadence: the consumer
/// judges liveness from [`ConvergedView::newest_claim_age_ms`], so
/// claims must survive long enough to *look* stale. Pruning aggressively
/// would hide a quiet mesh instead of reporting one.
pub const DEFAULT_CONVERGED_CLAIM_TTL: Duration = Duration::from_secs(600);

/// Default warm-up window — how long the plane must have been armed
/// before an *empty* set is reported as evidence rather than as unknown.
///
/// Two publish cadences (2 × 60s). One cadence would be the theoretical
/// minimum for "every cohort member should have spoken by now"; two
/// tolerates a single missed tick without the reader claiming an empty
/// mesh. A *non*-empty set is reported immediately — positive evidence
/// needs no warm-up.
pub const DEFAULT_CONVERGENCE_WARMUP: Duration = Duration::from_secs(120);

/// Cap on distinct `(content_id, peer_id)` claims tracked at once.
///
/// The claim plane is post-verify but not post-*quota*: a signed peer
/// can mint unlimited distinct `content_id`s, and the accumulator keys
/// on them. Same DoS shape the reassembler byte-budgets close. At the
/// cap the reader refuses NEW keys (existing keys still take freshness
/// updates, so liveness keeps flowing) and reports the refusal count, so
/// a saturated view is a declared FLOOR rather than a silent undercount.
///
/// ~20k entries × two short ids ≈ single-digit MB.
pub const DEFAULT_MAX_TRACKED_CLAIMS: usize = 20_000;

/// Why the converged view has no answer — *unknown*, never zero.
///
/// Each variant is a case where returning a count would assert something
/// about the mesh on the evidence of this node's own plumbing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvergenceUnavailable {
    /// The inbound claim plane has never been armed on this node — the
    /// dispatch loop that feeds the reader never started. Any count here
    /// would describe a dead loop, not the mesh.
    PlaneNotArmed,
    /// The plane is armed but has been listening for less than one
    /// warm-up window and has observed nothing. Cohort members publish
    /// on a cadence; before a window has elapsed, silence is a cold
    /// start, not an empty mesh.
    Warming {
        /// How long the plane has been armed.
        armed_for_ms: u64,
        /// The warm-up window that has not yet elapsed.
        window_ms: u64,
    },
    /// The converged state could not be read: a writer panicked while
    /// holding the lock. This is the case the issue names explicitly —
    /// a failed read must not be reported as an empty mesh.
    ReadFailed,
}

impl ConvergenceUnavailable {
    /// Stable snake_case discriminator for logs and FFI reason strings.
    /// Stable across cuts — downstream branches on it.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PlaneNotArmed => "plane_not_armed",
            Self::Warming { .. } => "warming",
            Self::ReadFailed => "read_failed",
        }
    }
}

/// What this node has converged about its cohort, in **counts only**.
///
/// Every field is numeric by construction — see the module docs on the
/// reconnaissance-surface rule. A consumer that wants "how big is the
/// mesh" reads [`Self::peers_converged`]; one that wants "is this
/// convergence live or stale" reads [`Self::newest_claim_age_ms`]
/// against its own knowledge of the publish cadence.
///
/// An all-zero view is a *real answer*: the plane was armed, has been
/// listening past its warm-up window, and no peer has claimed anything.
/// That is "converged to nothing", not "unknown" — which is why this
/// type is only reachable through [`ConvergenceReading::Converged`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergedView {
    /// Distinct peers this node has accepted at least one live claim
    /// from. The mesh-size answer.
    pub peers_converged: u32,
    /// Distinct `content_id`s claimed by at least one live claim.
    pub content_ids_converged: u32,
    /// Live `(content_id, peer_id)` claims — the converged claim count.
    /// One peer claiming three contents contributes three.
    pub claims_converged: u64,
    /// Aggregate holdings: total fountain symbols asserted across every
    /// live claim. Peers claiming overlapping symbol sets are counted
    /// once each — this is a *holdings* aggregate, not a distinct-symbol
    /// census (a census would require retaining symbol ids, which this
    /// reader deliberately does not).
    pub symbols_claimed: u64,
    /// Age of the freshest live claim, in milliseconds. **The liveness
    /// signal**: a value near the retention horizon means the cohort has
    /// gone quiet even though the counts are non-zero.
    ///
    /// `None` **iff** `claims_converged == 0` — an empty set has no
    /// newest member. Unambiguous here precisely because the
    /// absence-vs-empty question was already answered one level up by
    /// [`ConvergenceReading`].
    pub newest_claim_age_ms: Option<u64>,
    /// Age of the stalest live claim, in milliseconds. Bounded above by
    /// the retention horizon. `None` iff `claims_converged == 0`.
    pub oldest_claim_age_ms: Option<u64>,
    /// How long the inbound plane has been armed, in milliseconds. Lets
    /// a consumer weigh an empty answer: "nothing, after 4 seconds" and
    /// "nothing, after 4 hours" are very different claims about a mesh.
    pub observing_for_ms: u64,
    /// Distinct claims refused since arming because
    /// [`DEFAULT_MAX_TRACKED_CLAIMS`] was hit. **Non-zero ⇒ every count
    /// above is a floor, not an exact value.** Cumulative and monotonic
    /// by design: once we have undercounted, saying so stays true even
    /// after pruning drops the set back under the cap.
    pub claims_refused: u64,
}

impl ConvergedView {
    /// `true` when the node converged on nothing. Distinct from "we
    /// could not tell" — that is not representable in this type.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.claims_converged == 0
    }

    /// `true` when the tracked-claim cap was hit, so the counts are a
    /// lower bound.
    #[must_use]
    pub const fn is_floor(&self) -> bool {
        self.claims_refused > 0
    }
}

/// The result of reading the converged view.
///
/// A two-state enum rather than `Option<ConvergedView>` **on purpose**:
/// a bare `Option` reads as either "converged to nothing" or "nothing
/// computed yet" at every call site, and the downstream consumer is a
/// public endpoint that must report `null` for one and `0` for the
/// other. Making the distinction typed means a consumer cannot collapse
/// it by accident — it has to name which case it is handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a reading that is dropped reports nothing; match on it or call `converged()`"]
pub enum ConvergenceReading {
    /// No answer exists. Report as `null` — **never** as `0`.
    Unavailable(ConvergenceUnavailable),
    /// An answer exists, including a legitimately empty one. Report the
    /// counts verbatim, zeros included.
    Converged(ConvergedView),
}

impl ConvergenceReading {
    /// The wire projection CIRISServer#498 needs, and the ONLY place the
    /// two states are allowed to become an `Option`: `None` ⇒ serialize
    /// `null` (unknown), `Some(v)` ⇒ serialize `v`'s counts, **including
    /// all-zero**.
    #[must_use]
    pub const fn converged(&self) -> Option<&ConvergedView> {
        match self {
            Self::Converged(v) => Some(v),
            Self::Unavailable(_) => None,
        }
    }

    /// Why there is no answer, when there is none.
    #[must_use]
    pub const fn unavailable(&self) -> Option<&ConvergenceUnavailable> {
        match self {
            Self::Unavailable(r) => Some(r),
            Self::Converged(_) => None,
        }
    }

    /// `true` when an answer exists (empty or not).
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Converged(_))
    }
}

/// One observed claim reduced to the fields the counts need.
///
/// Borrowed so [`fold_observations`] allocates nothing per claim. The
/// symbol *ids* are already gone by this point — only their count
/// survives, because the reader has no use for contents and every reason
/// not to hold them.
#[derive(Debug, Clone, Copy)]
pub struct ClaimObservation<'a> {
    /// The claiming peer's federation `key_id`. Used only as a
    /// distinct-count key; never returned.
    pub peer_id: &'a str,
    /// The claimed content. Used only as a distinct-count key; never
    /// returned.
    pub content_id: &'a str,
    /// How many fountain symbols the claim asserted.
    pub symbol_count: u32,
    /// LOCAL monotonic instant the claim was observed at.
    ///
    /// Local, not the claim's own `observed_at_unix_ms`: the producer's
    /// timestamp is its own staleness window and is attacker-controlled
    /// (a peer can backdate or postdate at will, and would skew every
    /// freshness number here). The converger's TTL prune uses the same
    /// local-`Instant` discipline for the same reason.
    pub observed_at: Instant,
}

/// The pure fold: observations in, counts out.
///
/// Factored out of [`ConvergedClaimView`] so that (a) it is testable
/// against field-shaped claims with no clock plumbing, and (b) a future
/// projection from the converger's own
/// [`ObservedClaims`](crate::swarm::runtime::ObservedClaims) map can
/// produce byte-identical counts by feeding this the same observations —
/// there is exactly one implementation of the arithmetic.
///
/// Observations older than `ttl` are skipped rather than trusted: the
/// caller is expected to have pruned, and a fold that silently counted
/// expired claims would inflate `peers_converged` for a dead mesh.
#[must_use]
pub fn fold_observations<'a, I>(
    observations: I,
    now: Instant,
    ttl: Duration,
    observing_for: Duration,
    claims_refused: u64,
) -> ConvergedView
where
    I: IntoIterator<Item = ClaimObservation<'a>>,
{
    let mut peers: BTreeSet<&str> = BTreeSet::new();
    let mut contents: BTreeSet<&str> = BTreeSet::new();
    let mut claims_converged: u64 = 0;
    let mut symbols_claimed: u64 = 0;
    let mut newest: Option<Duration> = None;
    let mut oldest: Option<Duration> = None;

    for obs in observations {
        // `saturating_duration_since`, not `duration_since`: an
        // observation stamped fractionally in the future (two threads
        // racing `Instant::now()` around the lock) must read as age 0,
        // not panic a status endpoint.
        let age = now.saturating_duration_since(obs.observed_at);
        if age > ttl {
            continue;
        }
        peers.insert(obs.peer_id);
        contents.insert(obs.content_id);
        claims_converged = claims_converged.saturating_add(1);
        symbols_claimed = symbols_claimed.saturating_add(u64::from(obs.symbol_count));
        newest = Some(newest.map_or(age, |n| n.min(age)));
        oldest = Some(oldest.map_or(age, |o| o.max(age)));
    }

    ConvergedView {
        peers_converged: u32::try_from(peers.len()).unwrap_or(u32::MAX),
        content_ids_converged: u32::try_from(contents.len()).unwrap_or(u32::MAX),
        claims_converged,
        symbols_claimed,
        newest_claim_age_ms: newest.map(ms),
        oldest_claim_age_ms: oldest.map(ms),
        observing_for_ms: ms(observing_for),
        claims_refused,
    }
}

/// Milliseconds, saturating. A `Duration` longer than `u64::MAX` ms is
/// ~584 million years; clamping is strictly better than a panic in a
/// status path.
fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// One live claim as the accumulator keeps it: a symbol count and a
/// local observation instant. The claim itself — peer id, content id,
/// symbol ids, signatures — is NOT retained; the ids live in the map key
/// (needed for distinct counts) and nothing else survives.
#[derive(Debug, Clone, Copy)]
struct Observed {
    symbol_count: u32,
    observed_at: Instant,
}

#[derive(Debug, Default)]
struct ConvergedState {
    /// `(content_id, peer_id)` → live claim. Keyed exactly the way the
    /// converger's `ObservedClaims` keys — same nesting order, same
    /// last-wins-per-pair semantics — so "one claim" means the same
    /// thing to the reader and to the converger. `BTreeMap` for a
    /// deterministic walk.
    claims: BTreeMap<(String, String), Observed>,
    /// When the inbound plane was armed. `None` ⇒
    /// [`ConvergenceUnavailable::PlaneNotArmed`].
    armed_at: Option<Instant>,
    /// Cumulative distinct claims refused at the cap.
    refused: u64,
}

/// The converged view of the holonomic claim plane — the read API the
/// converger never had (CIRISEdge#545).
///
/// Lives on `Edge`, is armed when the inbound dispatch loop starts, is
/// fed by the post-verify `FountainHoldingClaim` dispatch arm, and is
/// read by [`Self::read`].
///
/// The reader is **synchronous**: a status endpoint must be callable
/// from a blocking FFI frame without a tokio runtime in scope, so the
/// state sits behind a `std::sync::RwLock` rather than tokio's. Every
/// critical section is a few map operations with no `.await` inside, so
/// it never blocks an executor meaningfully.
#[derive(Debug)]
pub struct ConvergedClaimView {
    state: RwLock<ConvergedState>,
    /// Retention horizon, milliseconds. Atomic so
    /// [`Self::align_to_converger`] can realign a live view at
    /// `install_swarm_runtime` time without touching the state lock.
    ttl_ms: AtomicU64,
    /// Warm-up window, milliseconds. Same rationale.
    warmup_ms: AtomicU64,
    max_tracked: usize,
}

impl Default for ConvergedClaimView {
    fn default() -> Self {
        Self::new()
    }
}

impl ConvergedClaimView {
    /// A view with the default horizons. Starts **unarmed**: until
    /// [`Self::arm`] runs, [`Self::read`] reports
    /// [`ConvergenceUnavailable::PlaneNotArmed`] rather than zero.
    #[must_use]
    pub fn new() -> Self {
        Self::with_horizons(DEFAULT_CONVERGED_CLAIM_TTL, DEFAULT_CONVERGENCE_WARMUP)
    }

    /// A view with explicit horizons. `max_tracked` stays at
    /// [`DEFAULT_MAX_TRACKED_CLAIMS`].
    #[must_use]
    pub fn with_horizons(ttl: Duration, warmup: Duration) -> Self {
        Self {
            state: RwLock::new(ConvergedState::default()),
            ttl_ms: AtomicU64::new(ms(ttl)),
            warmup_ms: AtomicU64::new(ms(warmup)),
            max_tracked: DEFAULT_MAX_TRACKED_CLAIMS,
        }
    }

    /// Realign the reader's horizons to a converger's actual config.
    ///
    /// Called from `Edge::install_swarm_runtime`. Without this, a
    /// deployment that runs a 5-second publish cadence would still be
    /// declared "warming" for two minutes, and one that runs an
    /// hour-long TTL would have the reader prune claims its own
    /// converger still holds — the two would disagree about what is
    /// live. `warmup` is two publish cadences, per
    /// [`DEFAULT_CONVERGENCE_WARMUP`].
    pub fn align_to_converger(&self, observed_claim_ttl: Duration, publish_cadence: Duration) {
        self.ttl_ms.store(ms(observed_claim_ttl), Ordering::Relaxed);
        self.warmup_ms
            .store(ms(publish_cadence.saturating_mul(2)), Ordering::Relaxed);
    }

    /// Arm the plane: record that this node's inbound dispatch loop is
    /// running and therefore that silence is now *evidence*.
    ///
    /// Idempotent — re-arming a running plane keeps the ORIGINAL instant
    /// rather than resetting the warm-up. `Edge::run` can be re-entered
    /// on a fold restart, and resetting would throw away a long, real
    /// observation window and re-report a known-empty mesh as unknown.
    pub fn arm(&self) {
        let Ok(mut st) = self.state.write() else {
            // Poisoned: `read` will report ReadFailed, which is the
            // honest answer. Arming into a poisoned lock cannot make it
            // less honest, so there is nothing to do here.
            return;
        };
        if st.armed_at.is_none() {
            st.armed_at = Some(Instant::now());
        }
    }

    /// Tap one post-verify claim into the converged view.
    ///
    /// Called from the same dispatch arm that feeds the converger, on
    /// the same envelopes, past the same AV-9 verify gate — and
    /// unconditionally, whether or not a `FountainSwarmRuntime` is
    /// installed, because "what has this node converged" is a question
    /// about the claim plane, not about whether an eviction policy
    /// happens to be running.
    ///
    /// Last-wins per `(content_id, peer_id)`, matching
    /// `register_observed_claim`.
    pub fn observe(&self, claim: &FountainHoldingClaim) {
        self.observe_at(claim, Instant::now());
    }

    /// [`Self::observe`] with an injected observation instant. Private:
    /// the clock is a test seam, not API.
    fn observe_at(&self, claim: &FountainHoldingClaim, at: Instant) {
        let Ok(mut st) = self.state.write() else {
            return;
        };
        let key = (claim.content_id.clone(), claim.peer_id.clone());
        let entry = Observed {
            // Saturating: a claim asserting more than 4 billion symbols
            // is not a number we need to be exact about.
            symbol_count: u32::try_from(claim.symbol_ids.len()).unwrap_or(u32::MAX),
            observed_at: at,
        };
        // Freshness updates to a pair we already track are ALWAYS accepted, cap
        // or no cap: refusing them would freeze `newest_claim_age_ms` and make a
        // live mesh look dead.
        if let Some(slot) = st.claims.get_mut(&key) {
            *slot = entry;
        } else {
            {
                if st.claims.len() >= self.max_tracked {
                    st.refused = st.refused.saturating_add(1);
                    return;
                }
                st.claims.insert(key, entry);
            }
        }
    }

    /// **The reader.** What has this node converged about its cohort.
    ///
    /// Prunes past the retention horizon, then folds. Returns
    /// [`ConvergenceReading::Unavailable`] — never a zero count — when
    /// the plane was never armed, when it is still warming with nothing
    /// observed, or when the state could not be read.
    pub fn read(&self) -> ConvergenceReading {
        self.read_at(Instant::now())
    }

    /// [`Self::read`] with an injected `now`. Private: test seam.
    fn read_at(&self, now: Instant) -> ConvergenceReading {
        let ttl = Duration::from_millis(self.ttl_ms.load(Ordering::Relaxed));
        let warmup = Duration::from_millis(self.warmup_ms.load(Ordering::Relaxed));

        // A poisoned lock is the issue's named "could not be read" case.
        // We deliberately do NOT recover via `PoisonError::into_inner`
        // here (the idiom used elsewhere in the crate for best-effort
        // caches): a panic inside a writer means the map may be
        // mid-update, and half a map is exactly the silent undercount
        // this API exists to avoid reporting.
        let Ok(mut st) = self.state.write() else {
            return ConvergenceReading::Unavailable(ConvergenceUnavailable::ReadFailed);
        };

        let Some(armed_at) = st.armed_at else {
            return ConvergenceReading::Unavailable(ConvergenceUnavailable::PlaneNotArmed);
        };

        st.claims
            .retain(|_, c| now.saturating_duration_since(c.observed_at) <= ttl);

        let observing_for = now.saturating_duration_since(armed_at);
        if st.claims.is_empty() && observing_for < warmup {
            return ConvergenceReading::Unavailable(ConvergenceUnavailable::Warming {
                armed_for_ms: ms(observing_for),
                window_ms: ms(warmup),
            });
        }

        let refused = st.refused;
        ConvergenceReading::Converged(fold_observations(
            st.claims
                .iter()
                .map(|((content_id, peer_id), c)| ClaimObservation {
                    peer_id: peer_id.as_str(),
                    content_id: content_id.as_str(),
                    symbol_count: c.symbol_count,
                    observed_at: c.observed_at,
                }),
            now,
            ttl,
            observing_for,
            refused,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Field-shaped input: the EXACT struct the dispatch arm parses out
    /// of a verified `MessageType::FountainHoldingClaim` envelope body,
    /// signature fields and all. Testing the fold on hand-rolled tuples
    /// would prove the arithmetic against inputs the field never
    /// produces.
    fn field_claim(peer: &str, content: &str, symbols: &[u32]) -> FountainHoldingClaim {
        let mut claim =
            FountainHoldingClaim::new(peer, content, symbols.to_vec(), 1_700_000_000_000);
        // The wire claims that reach the tap are signed — the dispatch
        // arm is past verify. Populate the hybrid pair so the tap is
        // exercised on the shape it actually sees, not on the
        // signature-free constructor output.
        claim.signature = "ZmFrZS1lZDI1NTE5".to_string();
        claim.signature_ml_dsa_65 = "ZmFrZS1tbC1kc2E=".to_string();
        claim.pqc_key_id = format!("{peer}-pqc");
        claim
    }

    /// A `now` far enough past the process epoch that subtracting test
    /// durations from it is always valid. `Instant - Duration` panics on
    /// underflow and `Instant`'s epoch is boot/process start, so a bare
    /// `Instant::now() - 10_000s` would flake on a freshly booted runner.
    fn far_future_now() -> Instant {
        Instant::now() + Duration::from_secs(86_400)
    }

    fn armed_view(ttl: Duration, warmup: Duration) -> ConvergedClaimView {
        let v = ConvergedClaimView::with_horizons(ttl, warmup);
        v.arm();
        v
    }

    // ---- absence vs empty ------------------------------------------

    #[test]
    fn unarmed_plane_is_unknown_not_zero() {
        let view = ConvergedClaimView::new();
        let reading = view.read();
        assert_eq!(
            reading,
            ConvergenceReading::Unavailable(ConvergenceUnavailable::PlaneNotArmed)
        );
        // The wire projection: null, not 0.
        assert!(reading.converged().is_none());
        assert!(!reading.is_available());
    }

    #[test]
    fn armed_but_warming_with_nothing_observed_is_unknown_not_zero() {
        let view = armed_view(DEFAULT_CONVERGED_CLAIM_TTL, Duration::from_secs(120));
        match view.read() {
            ConvergenceReading::Unavailable(ConvergenceUnavailable::Warming {
                window_ms, ..
            }) => assert_eq!(window_ms, 120_000),
            other => panic!("cold start must read as unknown, got {other:?}"),
        }
    }

    #[test]
    fn armed_past_warmup_with_nothing_observed_is_a_real_zero() {
        // Zero warm-up = the window has elapsed by construction.
        let view = armed_view(DEFAULT_CONVERGED_CLAIM_TTL, Duration::ZERO);
        let reading = view.read();
        let converged = reading
            .converged()
            .expect("past warm-up, an empty set is EVIDENCE and must be reported");
        assert_eq!(converged.peers_converged, 0);
        assert_eq!(converged.claims_converged, 0);
        assert!(converged.is_empty());
        // Empty set ⇒ no oldest/newest. Unambiguous: `claims_converged`
        // already said the set is empty.
        assert_eq!(converged.newest_claim_age_ms, None);
        assert_eq!(converged.oldest_claim_age_ms, None);
    }

    #[test]
    fn positive_evidence_is_reported_even_while_warming() {
        // A long warm-up window that has NOT elapsed...
        let view = armed_view(DEFAULT_CONVERGED_CLAIM_TTL, Duration::from_secs(3600));
        view.observe(&field_claim("peer-a", "content-1", &[1, 2, 3]));
        // ...must not suppress an answer we positively have.
        let reading = view.read();
        let converged = reading
            .converged()
            .expect("an observed claim is evidence regardless of warm-up");
        assert_eq!(converged.peers_converged, 1);
        assert_eq!(converged.claims_converged, 1);
    }

    #[test]
    fn read_failure_is_distinct_from_empty() {
        let view = armed_view(DEFAULT_CONVERGED_CLAIM_TTL, Duration::ZERO);
        // Poison the lock the way a panicking writer would.
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = view.state.write().expect("fresh lock");
            panic!("writer panic");
        }));
        assert!(poisoned.is_err());

        let reading = view.read();
        assert_eq!(
            reading,
            ConvergenceReading::Unavailable(ConvergenceUnavailable::ReadFailed)
        );
        // The whole point: a failed read must NOT tell the world the
        // mesh is empty.
        assert!(reading.converged().is_none());
    }

    // ---- counts ----------------------------------------------------

    #[test]
    fn distinct_peers_and_contents_are_counted_not_claims() {
        let view = armed_view(DEFAULT_CONVERGED_CLAIM_TTL, Duration::ZERO);
        // Two peers, two contents, four claims — the cross product a
        // real cohort produces.
        for peer in ["peer-a", "peer-b"] {
            for content in ["content-1", "content-2"] {
                view.observe(&field_claim(peer, content, &[7, 8]));
            }
        }
        let reading = view.read();
        let v = reading.converged().expect("armed past warm-up with claims");
        assert_eq!(v.peers_converged, 2);
        assert_eq!(v.content_ids_converged, 2);
        assert_eq!(v.claims_converged, 4);
        assert_eq!(v.symbols_claimed, 8, "2 symbols × 4 claims");
    }

    #[test]
    fn a_republished_claim_replaces_rather_than_double_counts() {
        let view = armed_view(DEFAULT_CONVERGED_CLAIM_TTL, Duration::ZERO);
        view.observe(&field_claim("peer-a", "content-1", &[1]));
        // Same (content, peer) republished at the next publish cadence
        // with a grown symbol set — the field's steady state.
        view.observe(&field_claim("peer-a", "content-1", &[1, 2, 3, 4]));
        let reading = view.read();
        let v = reading.converged().expect("claims present");
        assert_eq!(v.claims_converged, 1, "last-wins per (content, peer)");
        assert_eq!(v.symbols_claimed, 4, "the LATER claim's holdings");
    }

    // ---- freshness -------------------------------------------------

    #[test]
    fn ages_bracket_the_observed_set() {
        let view = armed_view(Duration::from_secs(600), Duration::ZERO);
        let now = far_future_now();
        // A cohort that has been publishing for a while: one peer heard
        // from 5 minutes ago, one 10 seconds ago.
        view.observe_at(
            &field_claim("peer-old", "content-1", &[1]),
            now.checked_sub(Duration::from_secs(300))
                .expect("test instant"),
        );
        view.observe_at(
            &field_claim("peer-new", "content-1", &[2]),
            now.checked_sub(Duration::from_secs(10))
                .expect("test instant"),
        );
        let reading = view.read_at(now);
        let v = reading.converged().expect("claims present");
        assert_eq!(v.newest_claim_age_ms, Some(10_000));
        assert_eq!(v.oldest_claim_age_ms, Some(300_000));
    }

    #[test]
    fn a_quiet_cohort_reads_as_stale_then_empties() {
        let view = armed_view(Duration::from_secs(600), Duration::ZERO);
        let now = far_future_now();
        view.observe_at(
            &field_claim("peer-a", "content-1", &[1]),
            now.checked_sub(Duration::from_secs(590))
                .expect("test instant"),
        );
        // Inside the horizon: still counted, but visibly stale — this is
        // the signal that distinguishes a live convergence from a dead
        // one, and is why the horizon is generous.
        let stale = view.read_at(now);
        let sv = stale.converged().expect("still inside the horizon");
        assert_eq!(sv.peers_converged, 1);
        assert_eq!(sv.newest_claim_age_ms, Some(590_000));

        // Past the horizon: pruned. Still an ANSWER (armed, past
        // warm-up) — a real, evidenced zero.
        let gone = view.read_at(now + Duration::from_secs(20));
        let gv = gone.converged().expect("armed and past warm-up");
        assert_eq!(gv.peers_converged, 0);
        assert!(gv.is_empty());
    }

    // ---- saturation ------------------------------------------------

    #[test]
    fn cap_saturation_is_declared_as_a_floor() {
        let mut view =
            ConvergedClaimView::with_horizons(DEFAULT_CONVERGED_CLAIM_TTL, Duration::ZERO);
        view.max_tracked = 2;
        view.arm();
        // A peer minting distinct content_ids — the flood shape.
        for i in 0..5 {
            view.observe(&field_claim("peer-flood", &format!("content-{i}"), &[1]));
        }
        let reading = view.read();
        let v = reading.converged().expect("claims present");
        assert_eq!(v.claims_converged, 2, "capped");
        assert_eq!(v.claims_refused, 3);
        assert!(v.is_floor(), "a saturated view must declare itself a floor");
    }

    #[test]
    fn saturation_still_accepts_freshness_for_tracked_pairs() {
        let mut view = ConvergedClaimView::with_horizons(Duration::from_secs(600), Duration::ZERO);
        view.max_tracked = 1;
        view.arm();
        let now = far_future_now();
        view.observe_at(
            &field_claim("peer-a", "content-1", &[1]),
            now.checked_sub(Duration::from_secs(300))
                .expect("test instant"),
        );
        view.observe(&field_claim("peer-b", "content-2", &[1])); // refused
        view.observe_at(&field_claim("peer-a", "content-1", &[1, 2]), now);
        let reading = view.read_at(now);
        let v = reading.converged().expect("claims present");
        assert_eq!(v.claims_refused, 1);
        assert_eq!(
            v.newest_claim_age_ms,
            Some(0),
            "a tracked pair must keep taking freshness updates at the cap"
        );
        assert_eq!(v.symbols_claimed, 2);
    }

    // ---- reconnaissance surface ------------------------------------

    #[test]
    fn converged_view_never_leaks_identifiers() {
        let view = armed_view(DEFAULT_CONVERGED_CLAIM_TTL, Duration::ZERO);
        view.observe(&field_claim(
            "SECRETPEERKEYID",
            "SECRETCONTENTID",
            &[404, 405],
        ));
        let reading = view.read();
        let v = reading.converged().expect("claims present");

        // `Debug` is the accidental-leak path: a status handler that logs
        // the view, or an FFI repr(), must not enumerate the mesh.
        let debug = format!("{v:?}");
        assert!(
            !debug.contains("SECRETPEERKEYID"),
            "peer id leaked: {debug}"
        );
        assert!(
            !debug.contains("SECRETCONTENTID"),
            "content id leaked: {debug}"
        );

        // Structural, not textual: pin the ENTIRE serialized field set.
        // A symbol id is numerically indistinguishable from a count in a
        // string search, so the guard that actually holds is "no field
        // beyond these eight ever appears on the wire" — a future field
        // carrying contents fails here at review time, not in
        // production.
        let json: serde_json::Value = serde_json::to_value(v).expect("view serializes");
        let mut keys: Vec<&str> = json
            .as_object()
            .expect("view is a JSON object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "claims_converged",
                "claims_refused",
                "content_ids_converged",
                "newest_claim_age_ms",
                "observing_for_ms",
                "oldest_claim_age_ms",
                "peers_converged",
                "symbols_claimed",
            ],
            "the converged view must stay COUNTS-ONLY: {json}"
        );
        assert!(
            json.as_object()
                .expect("object")
                .values()
                .all(|v| v.is_number() || v.is_null()),
            "every converged-view field must be numeric or absent: {json}"
        );
    }

    // ---- arming ----------------------------------------------------

    #[test]
    fn rearming_does_not_reset_the_observation_window() {
        let view = ConvergedClaimView::with_horizons(
            DEFAULT_CONVERGED_CLAIM_TTL,
            Duration::from_secs(120),
        );
        view.arm();
        let first = view
            .state
            .read()
            .expect("unpoisoned")
            .armed_at
            .expect("armed");
        // A fold restart re-enters `Edge::run` and re-arms.
        view.arm();
        let second = view
            .state
            .read()
            .expect("unpoisoned")
            .armed_at
            .expect("armed");
        assert_eq!(
            first, second,
            "re-arming must not throw away a real observation window"
        );
    }

    #[test]
    fn align_to_converger_moves_both_horizons() {
        let view = ConvergedClaimView::new();
        view.align_to_converger(Duration::from_secs(30), Duration::from_secs(5));
        assert_eq!(view.ttl_ms.load(Ordering::Relaxed), 30_000);
        assert_eq!(
            view.warmup_ms.load(Ordering::Relaxed),
            10_000,
            "warm-up is two publish cadences"
        );
    }

    // ---- the pure fold ---------------------------------------------

    #[test]
    fn fold_skips_observations_past_the_horizon() {
        let now = far_future_now();
        let obs = vec![
            ClaimObservation {
                peer_id: "peer-live",
                content_id: "content-1",
                symbol_count: 3,
                observed_at: now
                    .checked_sub(Duration::from_secs(10))
                    .expect("test instant"),
            },
            ClaimObservation {
                peer_id: "peer-expired",
                content_id: "content-2",
                symbol_count: 99,
                observed_at: now
                    .checked_sub(Duration::from_secs(10_000))
                    .expect("test instant"),
            },
        ];
        let v = fold_observations(obs, now, Duration::from_secs(600), Duration::ZERO, 0);
        assert_eq!(v.peers_converged, 1, "the expired peer must not be counted");
        assert_eq!(v.symbols_claimed, 3);
    }

    #[test]
    fn unavailable_reasons_have_stable_discriminators() {
        assert_eq!(
            ConvergenceUnavailable::PlaneNotArmed.as_str(),
            "plane_not_armed"
        );
        assert_eq!(
            ConvergenceUnavailable::Warming {
                armed_for_ms: 1,
                window_ms: 2
            }
            .as_str(),
            "warming"
        );
        assert_eq!(ConvergenceUnavailable::ReadFailed.as_str(), "read_failed");
    }
}
