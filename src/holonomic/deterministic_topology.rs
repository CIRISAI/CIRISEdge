//! Deterministic ALM topology — v3.10.0 holonomic Part 3.
//!
//! Pure function: same inputs => same tree. Composes with #135
//! `WholenessWitness` (inputs are witness leaves) so peers reconcile
//! against shared state, not against each other's planners.
//!
//! ## Why a NEW planner alongside the existing
//! [`crate::transport::realtime_av_alm::join`] module
//!
//! The v3.8.0 `AlmJoinPlanner` is local-only: it picks a parent for
//! the caller from the caller's view of candidates. Two peers that
//! receive a slightly different ordering of capacity advertisements
//! produce slightly different trees. That's fine for local subscribe,
//! but it's wrong for the holonomic substrate where the WHOLE topology
//! must reconcile across peers without a leader.
//!
//! The deterministic-mode planner here is the global counterpart:
//! given a snapshot bundle, it builds the entire tree as a pure
//! function. Two peers with byte-equal inputs MUST produce byte-equal
//! outputs — this is the load-bearing property and the reason the
//! existing planner is left untouched.
//!
//! ## Wire-determinism contract (LOCKED at `topology_version = 1`)
//!
//! - ALL sorts use canonical key ordering with explicit tie-break
//!   documentation; see each sort site for the key.
//! - The scoring formula uses INTEGER arithmetic ONLY (u64 weighted
//!   sums). NO `f32` / `f64` — floats are non-deterministic across
//!   architectures (`fma`, denormals, rounding mode, etc.).
//! - The `uplink_mbps` and `uplink_budget_mbps` `f32` fields coming
//!   in via [`SignedRelayCapacity`] are quantized to u64 millibits via
//!   [`f32_mbps_to_millibps_u64`] in a single, defined-rounding step
//!   BEFORE scoring; any non-finite or negative input is clamped to
//!   `0` so scoring never depends on the architecture's NaN bit
//!   pattern.
//! - Tie-break (parent score): if two parents score equally for the
//!   same child, choose by `parent_peer_id` lex-min.
//! - Greedy iteration order over children is by `child_peer_id`
//!   lex-min.
//! - Greedy iteration order over MDC sub-stream paths within a child
//!   is by `sub_stream_path` lex-min.
//! - Output `tree` is emitted in canonical order: sorted by
//!   `(child_peer_id, parent_peer_id, sub_stream_path)` all lex-min.
//! - Output `unrooted_peers` is sorted lex-min.
//!
//! Every ordering choice below is marked
//! `// wire-determinism critical`.

use serde::{Deserialize, Serialize};

// Re-export the v3.8.0 ALM-A advertisement primitive so this module's
// surface is self-contained for downstream callers — the topology
// function consumes this exact type by value via [`TopologyInputSnapshot`].
pub use crate::transport::realtime_av_alm::capacity::SignedRelayCapacity;

use crate::transport::realtime_av_alm::capacity::SubStreamPath;

/// Pinned topology wire version. Bump only when the determinism
/// contract changes (e.g. a new sort key, a new scoring weight, a new
/// filter step). v1 is the holonomic Part 3 cut.
pub const TOPOLOGY_VERSION: u16 = 1;

/// Reachability-observation max RTT in milliseconds beyond which a
/// peer-pair is treated as unreachable for scoring purposes. Picked
/// to match the v3.8.0 transport's pessimistic upper bound for an
/// over-the-mesh hop (Reticulum + ALM forwarding).
///
/// wire-determinism critical: this is part of the v1 scoring formula
/// and CANNOT be tuned without bumping [`TOPOLOGY_VERSION`].
pub const MAX_USEFUL_RTT_MS: u32 = 5_000;

/// Maximum trust-chain depth a topology v1 build will explore for
/// transitive trust grants. 4 hops = direct + 3 transitive — same
/// horizon CIRIS uses elsewhere for federation trust walks.
///
/// wire-determinism critical: v1 horizon; bump = topology version bump.
pub const MAX_TRUST_CHAIN_DEPTH: u8 = 4;

/// Weight (×) applied to the normalized capacity score in the
/// per-candidate-edge weighted sum. wire-determinism critical.
pub const WEIGHT_CAPACITY: u64 = 50;
/// Weight (×) applied to the normalized trust score. wire-determinism
/// critical.
pub const WEIGHT_TRUST: u64 = 30;
/// Weight (×) applied to the normalized reachability score.
/// wire-determinism critical.
pub const WEIGHT_REACHABILITY: u64 = 20;

/// Wire-determinism critical cap on per-identity self-asserted
/// capacity. Any `uplink_mbps` value advertised above this is
/// CLAMPED to this cap for scoring purposes. Locked at v1; appears
/// in CEG 1.0 §T conformance vectors.
///
/// 1 Gbps is the upper bound for any commodity-hardware sustained
/// outbound link in 2026. Production deployments with verified
/// throughput beyond this register through a separate trusted
/// throughput-challenge path (see RFC TBD).
pub const MAX_SELF_ASSERTED_UPLINK_MBPS: f32 = 1000.0;

/// Per-duplicate-subscriber penalty subtracted from a parent's
/// effective score, per existing subscriber the parent already
/// carries on the SAME `sub_stream_path` (MDC quadrant). Drives MDC
/// sub-stream distribution across multiple parents so a single
/// captured node cannot concentrate every sub-stream.
///
/// wire-determinism critical: part of the v1 scoring formula and
/// CANNOT be tuned without bumping [`TOPOLOGY_VERSION`].
pub const PENALTY_PER_SUB_PATH_DUP: u64 = 5;

/// One trust grant within a holonomic snapshot — a directed edge in
/// the federation's trust graph.
///
/// The shape is intentionally minimal — `chain_depth` lets a peer
/// publish a transitively-derived grant directly so the deterministic
/// planner doesn't have to walk the full trust graph at scoring time
/// (the walk happens upstream when the snapshot is assembled).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustGrant {
    /// Federation `key_id` of the peer that issued the grant.
    pub granter_peer_id: String,
    /// Federation `key_id` of the peer the grant flows to.
    pub grantee_peer_id: String,
    /// Unix milliseconds when the granter minted the grant.
    pub granted_at_unix_ms: u64,
    /// Trust-chain depth this grant represents (0 = direct;
    /// `n` = `n`-hop transitive). Grants with
    /// `chain_depth > MAX_TRUST_CHAIN_DEPTH` are dropped at filter
    /// time so v1 scoring stays within the documented horizon.
    pub chain_depth: u8,

    /// §13.3 per-grant trust weight (`0..=255`, max trust = 255).
    ///
    /// Additive wire field. Old grants minted before this field
    /// existed deserialize to [`TrustGrant::DEFAULT_WEIGHT`] (255,
    /// full trust) so back-compat is byte-faithful. The recursive
    /// trust bootstrap sums these along a witness chain and refuses
    /// admission when the sum exceeds the §13.3 aggregate-weight cap
    /// (`0.5 × root_trust`). The canonical clean-integer form is
    /// `weight = 255 - chain_depth * 50` (saturating at 0), so a
    /// direct grant is 255 and a depth-5 grant is 5 — see
    /// [`TrustGrant::canonical_weight_for_depth`].
    #[serde(default = "TrustGrant::default_weight")]
    pub weight: u32,
}

impl TrustGrant {
    /// Default weight for grants minted before the `weight` wire
    /// field existed: full trust (255). wire-determinism critical —
    /// changing this re-scores every legacy grant.
    pub const DEFAULT_WEIGHT: u32 = 255;

    /// Canonical clean-integer weight formula:
    /// `255 - chain_depth * 50`, saturating at 0. A direct grant
    /// (`chain_depth = 0`) is 255; a 5-hop grant is `255 - 250 = 5`;
    /// anything deeper saturates to 0. u8/u32 integer math only — no
    /// floats — so the value is byte-identical across every binding.
    /// wire-determinism critical.
    #[must_use]
    #[allow(clippy::cast_lossless)] // u32::from is not const-stable; u8->u32 lossless
    pub const fn canonical_weight_for_depth(chain_depth: u8) -> u32 {
        let decay = (chain_depth as u32).saturating_mul(50);
        Self::DEFAULT_WEIGHT.saturating_sub(decay)
    }

    /// serde default hook for the additive `weight` field.
    #[must_use]
    const fn default_weight() -> u32 {
        Self::DEFAULT_WEIGHT
    }
}

/// One peer-to-peer reachability observation within a holonomic
/// snapshot — a directed edge in the locality's reachability graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachabilityObservation {
    /// Federation `key_id` of the observing peer.
    pub from_peer_id: String,
    /// Federation `key_id` of the observed peer.
    pub to_peer_id: String,
    /// Observed round-trip time in milliseconds. Values above
    /// [`MAX_USEFUL_RTT_MS`] are treated as unreachable for scoring.
    pub observed_rtt_ms: u32,
    /// Unix milliseconds when the observation was taken.
    pub observed_at_unix_ms: u64,
}

/// The pure input bundle to [`compute_alm_topology`].
///
/// Two peers with byte-equal `TopologyInputSnapshot` instances MUST
/// produce byte-equal [`AlmTopology`] outputs — that's the holonomic
/// contract.
///
/// The bundle composes with #135 `WholenessWitness`: each field is a
/// witness leaf, so the snapshot is reconstructable from the witness
/// tree at any given `snapshot_epoch_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyInputSnapshot {
    /// Signed relay-capacity advertisements from peers in the
    /// federation. The function sorts these into canonical order
    /// before scoring so caller insertion order does NOT matter.
    pub capacity_ads: Vec<SignedRelayCapacity>,
    /// Trust grants composing the federation trust graph (already
    /// flattened to direct + transitive by the snapshot assembler).
    pub trust_grants: Vec<TrustGrant>,
    /// Reachability observations within `locality_id`. The function
    /// filters to observations whose endpoints both appear in the
    /// locality before scoring.
    pub reachability_observations: Vec<ReachabilityObservation>,
    /// Locality this topology snapshot is for — CIRIS federation
    /// localities partition the global mesh so trees are built within
    /// a locality, not across them.
    pub locality_id: String,
    /// Monotonically-increasing epoch id; matches `WholenessWitness`
    /// epoch ids. Copied verbatim into the output topology so peers
    /// can correlate computed trees to the witness state they came
    /// from.
    pub snapshot_epoch_id: u64,
}

/// Verification state of a capacity advertisement. Topology MUST
/// NOT score unverified ads.
///
/// wire-determinism critical: the verification state selects whether
/// an ad enters scoring (filter step) and whether its self-asserted
/// `uplink_mbps` is clamped to [`MAX_SELF_ASSERTED_UPLINK_MBPS`]
/// (clamp step). Both are part of the v1
/// [`compute_alm_topology_verified`] contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityVerification {
    /// Ad's hybrid PQC signature verified against signer's known
    /// federation key.
    HybridSignatureValid,
    /// Ad's signature was not validated, or validation failed.
    /// Topology MUST treat this peer as having zero capacity.
    Unverified,
    /// Ad's signature verified BUT a throughput challenge has
    /// confirmed sustained delivery at the advertised rate.
    /// Eligible for capacity above [`MAX_SELF_ASSERTED_UPLINK_MBPS`].
    ThroughputChallenged,
}

/// One signed capacity ad paired with its verification state. The
/// pair is the topology function's input unit — UNVERIFIED ads do
/// NOT enter scoring.
#[derive(Debug, Clone)]
pub struct VerifiedCapacityAd {
    /// The signed advertisement itself.
    pub ad: SignedRelayCapacity,
    /// Where verification of `ad` stands — drives the filter +
    /// clamp steps in [`compute_alm_topology_verified`].
    pub verification: CapacityVerification,
}

/// Hardened input bundle for [`compute_alm_topology_verified`].
///
/// Mirrors [`TopologyInputSnapshot`] but pairs every capacity ad
/// with its [`CapacityVerification`] state so the topology function
/// can drop unverified ads and clamp self-asserted capacity in a
/// single step BEFORE scoring.
#[derive(Debug, Clone)]
pub struct VerifiedTopologyInputSnapshot {
    /// Verification-paired capacity advertisements. Ads whose
    /// verification is [`CapacityVerification::Unverified`] are
    /// dropped before scoring.
    pub capacity_ads: Vec<VerifiedCapacityAd>,
    /// Trust grants — same semantics as
    /// [`TopologyInputSnapshot::trust_grants`].
    pub trust_grants: Vec<TrustGrant>,
    /// Reachability observations — same semantics as
    /// [`TopologyInputSnapshot::reachability_observations`].
    pub reachability_observations: Vec<ReachabilityObservation>,
    /// Locality this topology snapshot is for.
    pub locality_id: String,
    /// Monotonically-increasing epoch id; copied verbatim into the
    /// output topology.
    pub snapshot_epoch_id: u64,
}

/// One edge of the deterministically-computed ALM tree.
///
/// Each edge binds a child peer to a parent peer for a specific MDC
/// sub-stream path. An empty `sub_stream_path` means the whole stream
/// opaquely (same convention as
/// [`crate::transport::realtime_av_alm::capacity::SubStreamPath`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlmEdge {
    /// Parent peer's federation `key_id`.
    pub parent_peer_id: String,
    /// Child peer's federation `key_id`.
    pub child_peer_id: String,
    /// MDC sub-stream path (empty = whole-stream opaque).
    pub sub_stream_path: SubStreamPath,
}

/// The deterministic-mode topology output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlmTopology {
    /// Edges in the tree — canonical order:
    /// `(child_peer_id, parent_peer_id, sub_stream_path)` lex-min.
    pub tree: Vec<AlmEdge>,
    /// Peers seen in `capacity_ads` that could NOT be rooted in the
    /// tree (no eligible parent under the locality / trust /
    /// reachability filters). Canonical order: lex-min `peer_id`.
    pub unrooted_peers: Vec<String>,
    /// Copied verbatim from the input snapshot for correlation back
    /// to the witness tree.
    pub snapshot_epoch_id: u64,
    /// Pinned at [`TOPOLOGY_VERSION`]. Reserved for a future
    /// determinism-contract bump.
    pub topology_version: u16,
}

// ─────────────────────────────────────────────────────────────────────
// Integer-arithmetic helpers — float quantization + ratio math.
// ─────────────────────────────────────────────────────────────────────

/// Quantize an `f32` Mbps reading to u64 millibits-per-second.
///
/// Wire-determinism critical: the cross-architecture risk with floats
/// is non-finite values (NaN bit patterns), denormals, and rounding
/// modes. We constrain ALL three by:
///   - Mapping any non-finite or negative value to `0`.
///   - Multiplying by `1_000.0` and truncating with `as u64`, which
///     is a defined cast in Rust (saturating; NaN → 0).
///
/// Result range: 0 .. `u64::MAX`. Reasonable Mbps values
/// (<= 4e15 Mbps) round-trip exactly within `u64`.
#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn f32_mbps_to_millibps_u64(mbps: f32) -> u64 {
    if !mbps.is_finite() || mbps <= 0.0 {
        return 0;
    }
    // `as u64` on f32 is saturating + truncating in Rust — both
    // defined operations across architectures.
    (mbps * 1_000.0) as u64
}

/// [`MAX_SELF_ASSERTED_UPLINK_MBPS`] expressed in u64 millibits per
/// second via the same `* 1_000` quantization
/// [`f32_mbps_to_millibps_u64`] uses. The `1000.0 Mbps` f32 cap
/// converts to `1_000_000` millibps here once, at the clamp
/// boundary, so the clamp stays integer-only downstream.
///
/// wire-determinism critical: the float→int conversion happens
/// exactly here and nowhere else on the clamp path. The cast is
/// exact — `MAX_SELF_ASSERTED_UPLINK_MBPS` is a small positive whole
/// number — so truncation / sign-loss cannot occur.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
const MAX_SELF_ASSERTED_UPLINK_MILLIBPS: u64 =
    (MAX_SELF_ASSERTED_UPLINK_MBPS as u64).saturating_mul(1_000);

/// Apply the verification-state-dependent self-asserted-capacity cap
/// to an already-quantized uplink (millibps).
///
/// - [`CapacityVerification::HybridSignatureValid`]: clamp to
///   [`MAX_SELF_ASSERTED_UPLINK_MILLIBPS`] — a signed-but-unchallenged
///   ad cannot be the dominant unbounded term.
/// - [`CapacityVerification::ThroughputChallenged`]: NO clamp — the
///   advertised rate was confirmed by observed throughput.
/// - [`CapacityVerification::Unverified`]: never reaches this helper
///   (dropped at the filter step), but treated as `0` defensively.
///
/// wire-determinism critical: integer min only; no float on this path.
#[must_use]
fn clamp_self_asserted_millibps(uplink_millibps: u64, verification: CapacityVerification) -> u64 {
    match verification {
        CapacityVerification::ThroughputChallenged => uplink_millibps,
        CapacityVerification::HybridSignatureValid => {
            uplink_millibps.min(MAX_SELF_ASSERTED_UPLINK_MILLIBPS)
        }
        CapacityVerification::Unverified => 0,
    }
}

/// The maximum capacity-score input used to normalize each candidate
/// parent's `uplink_mbps`. Picked to comfortably exceed real-world
/// peer uplinks (1 Gbps = 1_000_000 millibps).
///
/// wire-determinism critical: part of the v1 normalization formula.
const CAPACITY_NORMALIZER_MILLIBPS: u64 = 10_000_000;

/// Normalize a capacity into a `[0 ..= 1000]` integer score where
/// `1000 = CAPACITY_NORMALIZER_MILLIBPS or higher`. Saturating math
/// throughout — no float, no panic, no architecture dependence.
#[must_use]
fn normalize_capacity_score(uplink_millibps: u64) -> u64 {
    let clamped = uplink_millibps.min(CAPACITY_NORMALIZER_MILLIBPS);
    // clamped <= 10_000_000 fits in u64 with room; safe.
    clamped.saturating_mul(1_000) / CAPACITY_NORMALIZER_MILLIBPS
}

/// Normalize a `chain_depth` u8 to a `[0 ..= 1000]` integer score
/// where direct grants (depth=0) score highest and depth =
/// [`MAX_TRUST_CHAIN_DEPTH`] scores lowest.
#[must_use]
fn normalize_trust_score(chain_depth: u8) -> u64 {
    if u64::from(chain_depth) > u64::from(MAX_TRUST_CHAIN_DEPTH) {
        return 0;
    }
    let remaining = u64::from(MAX_TRUST_CHAIN_DEPTH) - u64::from(chain_depth);
    // wire-determinism: linear inverse of depth.
    remaining.saturating_mul(1_000) / u64::from(MAX_TRUST_CHAIN_DEPTH)
}

/// Normalize an RTT into a `[0 ..= 1000]` integer score; faster
/// observations score higher.
#[must_use]
fn normalize_reachability_score(rtt_ms: u32) -> u64 {
    let rtt = u64::from(rtt_ms).min(u64::from(MAX_USEFUL_RTT_MS));
    let remaining = u64::from(MAX_USEFUL_RTT_MS) - rtt;
    remaining.saturating_mul(1_000) / u64::from(MAX_USEFUL_RTT_MS)
}

/// Canonical sub-stream paths for a child's advertised commitments.
///
/// wire-determinism critical: canonical lex-min sort + dedup over
/// `sub_stream_path` bytes; opaque-mode (empty commitments) yields a
/// single empty-path slot.
fn canonical_sub_paths(child_ad: &SignedRelayCapacity) -> Vec<SubStreamPath> {
    let mut sub_paths: Vec<SubStreamPath> = if child_ad.capacity.sub_stream_commitments.is_empty() {
        vec![Vec::new()]
    } else {
        child_ad
            .capacity
            .sub_stream_commitments
            .iter()
            .map(|c| c.sub_stream_path.clone())
            .collect()
    };
    sub_paths.sort();
    sub_paths.dedup();
    sub_paths
}

/// Pick the highest-scoring eligible parent for a given child on a
/// SPECIFIC `sub_stream_path`, or `None` if no candidate clears the
/// trust + reachability gates.
///
/// The capacity term reads from `parent_cap_millibps` — the
/// per-parent uplink that has ALREADY been verification-filtered and
/// self-assertion-clamped upstream (so this function never sees a
/// raw lying advertisement).
///
/// The score is reduced by [`PENALTY_PER_SUB_PATH_DUP`] per existing
/// subscriber the parent already carries on `candidate_sub_path`
/// (read from `sub_path_occupancy`). This penalty drives MDC
/// sub-streams to spread across multiple parents so a single node
/// cannot concentrate every quadrant.
///
/// wire-determinism critical: iteration is over the canonical-sorted
/// `candidate_peers` slice, so `>` (strict) keeps the first-seen
/// (= lex-min) parent on score ties; the penalty is integer
/// arithmetic saturating at 0.
fn best_parent_for_child(
    child_peer_id: &str,
    candidate_sub_path: &[u8],
    candidate_peers: &[String],
    parent_cap_millibps: &std::collections::BTreeMap<String, u64>,
    trust_min_depth: &std::collections::BTreeMap<(String, String), u8>,
    reach_min_rtt: &std::collections::BTreeMap<(String, String), u32>,
    sub_path_occupancy: &std::collections::BTreeMap<(String, SubStreamPath), u64>,
) -> Option<String> {
    let mut best_score: Option<u64> = None;
    let mut best_parent: Option<String> = None;

    for parent_peer_id in candidate_peers {
        if parent_peer_id == child_peer_id {
            continue;
        }

        // Trust gate: parent must hold a grant to the child within
        // the chain-depth horizon.
        let trust_depth =
            match trust_min_depth.get(&(parent_peer_id.clone(), child_peer_id.to_string())) {
                Some(d) => *d,
                None => continue,
            };

        // Reachability gate: parent → child observation must exist
        // AND be within MAX_USEFUL_RTT_MS.
        let rtt = match reach_min_rtt.get(&(parent_peer_id.clone(), child_peer_id.to_string())) {
            Some(r) => *r,
            None => continue,
        };
        if rtt > MAX_USEFUL_RTT_MS {
            continue;
        }

        // Score: integer weighted sum over the already-clamped
        // capacity, then the sub_path duplication penalty.
        let cap_millibps = parent_cap_millibps
            .get(parent_peer_id)
            .copied()
            .unwrap_or(0);
        let cap_s = normalize_capacity_score(cap_millibps);
        let trust_s = normalize_trust_score(trust_depth);
        let reach_s = normalize_reachability_score(rtt);

        let base = WEIGHT_CAPACITY
            .saturating_mul(cap_s)
            .saturating_add(WEIGHT_TRUST.saturating_mul(trust_s))
            .saturating_add(WEIGHT_REACHABILITY.saturating_mul(reach_s));

        // sub_path_penalty = PENALTY_PER_SUB_PATH_DUP × existing
        // subscribers at this parent on the same sub_stream_path.
        let existing = sub_path_occupancy
            .get(&(parent_peer_id.clone(), candidate_sub_path.to_vec()))
            .copied()
            .unwrap_or(0);
        let penalty = PENALTY_PER_SUB_PATH_DUP.saturating_mul(existing);
        let score = base.saturating_sub(penalty);

        match best_score {
            None => {
                best_score = Some(score);
                best_parent = Some(parent_peer_id.clone());
            }
            Some(prev) if score > prev => {
                best_score = Some(score);
                best_parent = Some(parent_peer_id.clone());
            }
            _ => {}
        }
    }

    best_parent
}

// ─────────────────────────────────────────────────────────────────────
// The deterministic topology function.
// ─────────────────────────────────────────────────────────────────────

/// Compute the ALM topology as a pure function of the snapshot.
///
/// **Two calls with byte-equal inputs MUST produce byte-equal
/// outputs.** This is the load-bearing property of the holonomic
/// substrate — it is what lets peers reconcile against shared state
/// (the witness) rather than against each other's planners.
///
/// ## Algorithm (v1)
///
/// 1. Sort `capacity_ads` by canonical key:
///    `(signed_at_unix_ms ASC, advertiser_key_id lex-min)`.
///    wire-determinism critical.
/// 2. Compute the locality peer set as the union of `from_peer_id`
///    AND `to_peer_id` over `reachability_observations`. A capacity
///    ad whose `advertiser_key_id` is NOT in the locality peer set is
///    excluded; its advertiser is unrooted.
/// 3. Build a `(granter, grantee) → min(chain_depth)` lookup from
///    `trust_grants`, dropping grants with
///    `chain_depth > MAX_TRUST_CHAIN_DEPTH`. wire-determinism: when
///    multiple grants share `(granter, grantee)` we keep the smallest
///    `chain_depth`; ties (same depth) collapse since `min` is
///    associative.
/// 4. Build a `(from, to) → min(observed_rtt_ms)` lookup from
///    `reachability_observations`. Same min-collapse rule.
/// 5. For each child peer (canonical-sorted), enumerate parent
///    candidates among the locality peers that hold a capacity ad,
///    with trust within `MAX_TRUST_CHAIN_DEPTH` of the child AND
///    reachability `<= MAX_USEFUL_RTT_MS`. Score each candidate as:
///    `score = WEIGHT_CAPACITY * cap_score + WEIGHT_TRUST *
///    trust_score + WEIGHT_REACHABILITY * reach_score`.
///    Pick the highest-scoring; tie-break by `parent_peer_id` lex-min.
///    wire-determinism critical.
/// 6. For peers with non-empty `sub_stream_commitments`, emit one
///    edge per sub-stream path (canonical-sorted by `sub_stream_path`
///    lex-min). For opaque-mode peers (empty commitments), emit one
///    edge with `sub_stream_path = vec![]`.
/// 7. Emit the tree in canonical output order, then the unrooted set.
#[must_use]
pub fn compute_alm_topology(snapshot: &TopologyInputSnapshot) -> AlmTopology {
    // Legacy entry: every ad is treated as Unverified, so it is
    // dropped at the filter step → no candidate peers → empty tree.
    // This is the safe (empty) default for v4.0.x callers that have
    // not yet migrated to `compute_alm_topology_verified` — see that
    // function for the migration path and the F-4 rationale.
    let verified: Vec<VerifiedCapacityAd> = snapshot
        .capacity_ads
        .iter()
        .cloned()
        .map(|ad| VerifiedCapacityAd {
            ad,
            verification: CapacityVerification::Unverified,
        })
        .collect();
    compute_core(
        &verified,
        &snapshot.trust_grants,
        &snapshot.reachability_observations,
        snapshot.snapshot_epoch_id,
    )
}

/// Hardened ALM topology computation — the v4.1.0
/// production-recommended entry point and the fix for the F-4
/// universal-eclipse gap (CIRISEdge#143).
///
/// Consumes verification-paired capacity ads and, BEFORE scoring:
///
/// 1. **Filter** — drops every ad whose verification is
///    [`CapacityVerification::Unverified`]. An unverified peer is
///    treated as zero capacity and NEVER enters scoring, so a liar
///    cannot win `best_parent_for_child` for anyone.
/// 2. **Clamp** — a [`CapacityVerification::HybridSignatureValid`]
///    ad's `uplink_mbps` is clamped to
///    [`MAX_SELF_ASSERTED_UPLINK_MBPS`], so self-asserted capacity
///    is no longer the dominant unbounded term. Capacity above the
///    cap requires [`CapacityVerification::ThroughputChallenged`]
///    (observed-throughput confirmation, not self-assertion).
/// 3. **Sub-path distribution** — `best_parent_for_child` scores
///    `sub_stream_path` occupancy via [`PENALTY_PER_SUB_PATH_DUP`],
///    so MDC sub-streams spread across multiple parents instead of
///    concentrating on one captured node.
///
/// Same byte-determinism contract as [`compute_alm_topology`]: two
/// peers with byte-equal `VerifiedTopologyInputSnapshot` inputs MUST
/// produce byte-equal [`AlmTopology`] outputs.
#[must_use]
pub fn compute_alm_topology_verified(snapshot: &VerifiedTopologyInputSnapshot) -> AlmTopology {
    compute_core(
        &snapshot.capacity_ads,
        &snapshot.trust_grants,
        &snapshot.reachability_observations,
        snapshot.snapshot_epoch_id,
    )
}

/// Shared deterministic build core for both topology entry points.
///
/// The verification-paired `capacity_ads` are filtered (unverified
/// dropped) and their scored capacity is the
/// [`clamp_self_asserted_millibps`] of the quantized `uplink_mbps`.
/// Everything else is the v1 algorithm verbatim.
#[allow(clippy::too_many_lines)]
fn compute_core(
    capacity_ads: &[VerifiedCapacityAd],
    trust_grants: &[TrustGrant],
    reachability_observations: &[ReachabilityObservation],
    snapshot_epoch_id: u64,
) -> AlmTopology {
    // Filter step: drop Unverified ads entirely so they never enter
    // scoring; keep the verification state alongside the surviving
    // ads for the clamp step below.
    let mut ads: Vec<VerifiedCapacityAd> = capacity_ads
        .iter()
        .filter(|v| v.verification != CapacityVerification::Unverified)
        .cloned()
        .collect();

    // Step 1: canonical-sort the capacity ads.
    // wire-determinism critical: (signed_at_unix_ms ASC,
    // advertiser_key_id lex-min). measured_at_unix_ms is the
    // publisher's mint timestamp — same key the v3.8.0 ALM-A path
    // uses for staleness, so it's the natural canonical position.
    ads.sort_by(|a, b| {
        a.ad.capacity
            .measured_at_unix_ms
            .cmp(&b.ad.capacity.measured_at_unix_ms)
            .then_with(|| a.ad.advertiser_key_id.cmp(&b.ad.advertiser_key_id))
    });

    // Step 2: locality peer set = union of reachability endpoints.
    // wire-determinism critical: BTreeSet keeps iteration in lex
    // order without an explicit sort step.
    let mut locality_peers: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for obs in reachability_observations {
        locality_peers.insert(obs.from_peer_id.clone());
        locality_peers.insert(obs.to_peer_id.clone());
    }

    // Step 3: trust lookup, min over chain_depth, dropping anything
    // beyond MAX_TRUST_CHAIN_DEPTH at insert time.
    let mut trust_min_depth: std::collections::BTreeMap<(String, String), u8> =
        std::collections::BTreeMap::new();
    for g in trust_grants {
        if g.chain_depth > MAX_TRUST_CHAIN_DEPTH {
            continue;
        }
        let key = (g.granter_peer_id.clone(), g.grantee_peer_id.clone());
        trust_min_depth
            .entry(key)
            .and_modify(|d| {
                if g.chain_depth < *d {
                    *d = g.chain_depth;
                }
            })
            .or_insert(g.chain_depth);
    }

    // Step 4: reachability lookup, min over observed_rtt_ms.
    let mut reach_min_rtt: std::collections::BTreeMap<(String, String), u32> =
        std::collections::BTreeMap::new();
    for o in reachability_observations {
        let key = (o.from_peer_id.clone(), o.to_peer_id.clone());
        reach_min_rtt
            .entry(key)
            .and_modify(|r| {
                if o.observed_rtt_ms < *r {
                    *r = o.observed_rtt_ms;
                }
            })
            .or_insert(o.observed_rtt_ms);
    }

    // Per-peer view of the canonical (latest) advertisement.
    // wire-determinism critical: ads are already sorted ASC by
    // (measured_at_unix_ms, advertiser_key_id), so inserting in order
    // and overwriting gives us the latest ad per peer; ties on
    // timestamp resolve by advertiser_key_id lex-min (same canonical
    // key everywhere).
    let mut latest_ad: std::collections::BTreeMap<String, VerifiedCapacityAd> =
        std::collections::BTreeMap::new();
    for ad in &ads {
        // Locality filter: peer must appear in locality_peers.
        if !locality_peers.contains(&ad.ad.advertiser_key_id) {
            continue;
        }
        latest_ad.insert(ad.ad.advertiser_key_id.clone(), ad.clone());
    }

    // Clamp step: quantize each surviving ad's self-asserted
    // uplink and apply the verification-state cap ONCE, here, so the
    // scored capacity feeding `best_parent_for_child` is already
    // bounded. wire-determinism critical: BTreeMap iteration is lex.
    let parent_cap_millibps: std::collections::BTreeMap<String, u64> = latest_ad
        .iter()
        .map(|(peer_id, v)| {
            let quantized = f32_mbps_to_millibps_u64(v.ad.capacity.uplink_mbps);
            (
                peer_id.clone(),
                clamp_self_asserted_millibps(quantized, v.verification),
            )
        })
        .collect();

    // The candidate peer set for THIS topology = peers that (a) appear
    // in the locality and (b) have at least one valid ad.
    let candidate_peers: Vec<String> = latest_ad.keys().cloned().collect();

    // Step 5 + 6: greedy assignment in canonical child order.
    // wire-determinism critical: BTreeMap iteration is lex order. As
    // edges are assigned we accrue `(parent, sub_path) → count` so
    // later assignments see the running MDC occupancy and diversify.
    let mut tree: Vec<AlmEdge> = Vec::new();
    let mut unrooted: Vec<String> = Vec::new();
    let mut sub_path_occupancy: std::collections::BTreeMap<(String, SubStreamPath), u64> =
        std::collections::BTreeMap::new();

    for child_peer_id in &candidate_peers {
        let child_ad = &latest_ad[child_peer_id].ad;
        let sub_paths = canonical_sub_paths(child_ad);

        let mut any_rooted_for_child = false;
        for sub_path in &sub_paths {
            if let Some(parent) = best_parent_for_child(
                child_peer_id,
                sub_path,
                &candidate_peers,
                &parent_cap_millibps,
                &trust_min_depth,
                &reach_min_rtt,
                &sub_path_occupancy,
            ) {
                *sub_path_occupancy
                    .entry((parent.clone(), sub_path.clone()))
                    .or_insert(0) += 1;
                tree.push(AlmEdge {
                    parent_peer_id: parent,
                    child_peer_id: child_peer_id.clone(),
                    sub_stream_path: sub_path.clone(),
                });
                any_rooted_for_child = true;
            }
        }

        if !any_rooted_for_child {
            unrooted.push(child_peer_id.clone());
        }
    }

    // Peers with surviving (verified) capacity ads that we excluded at
    // the locality filter step are also unrooted — they were never
    // candidates. Unverified-dropped peers are NOT listed here: they
    // never entered scoring, matching the "treat as zero capacity"
    // contract (the legacy entry therefore yields an empty topology).
    for ad in &ads {
        if !locality_peers.contains(&ad.ad.advertiser_key_id)
            && !unrooted.contains(&ad.ad.advertiser_key_id)
        {
            unrooted.push(ad.ad.advertiser_key_id.clone());
        }
    }

    // Step 7: canonical output order.
    // wire-determinism critical: (child_peer_id, parent_peer_id,
    // sub_stream_path) lex-min for `tree`; lex-min for `unrooted`.
    tree.sort_by(|a, b| {
        a.child_peer_id
            .cmp(&b.child_peer_id)
            .then_with(|| a.parent_peer_id.cmp(&b.parent_peer_id))
            .then_with(|| a.sub_stream_path.cmp(&b.sub_stream_path))
    });
    unrooted.sort();
    unrooted.dedup();

    AlmTopology {
        tree,
        unrooted_peers: unrooted,
        snapshot_epoch_id,
        topology_version: TOPOLOGY_VERSION,
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests.
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::realtime_av::{Epoch, ReceiverLayerPolicy, StreamId};
    use crate::transport::realtime_av_alm::capacity::{RelayCapacity, SubStreamCommitment};

    /// Build a fake `SignedRelayCapacity` directly — we don't need a
    /// real signature for topology tests because the deterministic
    /// planner is signature-blind by design (verification happens at
    /// the snapshot-assembly tier upstream).
    fn fake_signed_ad(
        peer_id: &str,
        uplink_mbps: f32,
        measured_at_unix_ms: u64,
        commitments: Vec<SubStreamCommitment>,
    ) -> SignedRelayCapacity {
        let cap = if commitments.is_empty() {
            RelayCapacity::new(
                uplink_mbps,
                4,
                16,
                ReceiverLayerPolicy::UNCAPPED,
                measured_at_unix_ms,
            )
        } else {
            RelayCapacity::with_substream_commitments(
                uplink_mbps,
                4,
                16,
                ReceiverLayerPolicy::UNCAPPED,
                measured_at_unix_ms,
                commitments,
            )
        };
        SignedRelayCapacity {
            advertiser_key_id: peer_id.to_string(),
            capacity: cap,
            stream_id: StreamId([0u8; 32]),
            epoch: Epoch(1),
            signature_ed25519_base64: String::new(),
            signature_ml_dsa_65_base64: String::new(),
        }
    }

    /// Wrap a legacy `TopologyInputSnapshot` into a verified one,
    /// stamping every ad with the SAME `verification`. Lets the
    /// migrated tests reuse the existing snapshot builders.
    fn verified(
        snap: &TopologyInputSnapshot,
        verification: CapacityVerification,
    ) -> VerifiedTopologyInputSnapshot {
        VerifiedTopologyInputSnapshot {
            capacity_ads: snap
                .capacity_ads
                .iter()
                .cloned()
                .map(|ad| VerifiedCapacityAd { ad, verification })
                .collect(),
            trust_grants: snap.trust_grants.clone(),
            reachability_observations: snap.reachability_observations.clone(),
            locality_id: snap.locality_id.clone(),
            snapshot_epoch_id: snap.snapshot_epoch_id,
        }
    }

    /// All-`HybridSignatureValid` verified snapshot — the common case
    /// for the migrated determinism / scoring tests.
    fn all_valid(snap: &TopologyInputSnapshot) -> VerifiedTopologyInputSnapshot {
        verified(snap, CapacityVerification::HybridSignatureValid)
    }

    fn three_peer_snapshot() -> TopologyInputSnapshot {
        // Three peers in a triangle, all observe each other, all
        // grant each other directly. peer-a has the highest uplink,
        // peer-c the lowest.
        let ads = vec![
            fake_signed_ad("peer-a", 100.0, 1_700_000_000_000, vec![]),
            fake_signed_ad("peer-b", 50.0, 1_700_000_000_500, vec![]),
            fake_signed_ad("peer-c", 10.0, 1_700_000_001_000, vec![]),
        ];

        let peers = ["peer-a", "peer-b", "peer-c"];
        let mut grants = Vec::new();
        let mut reach = Vec::new();
        for &g in &peers {
            for &t in &peers {
                if g == t {
                    continue;
                }
                grants.push(TrustGrant {
                    granter_peer_id: g.to_string(),
                    grantee_peer_id: t.to_string(),
                    granted_at_unix_ms: 1_700_000_000_000,
                    chain_depth: 0,
                    weight: TrustGrant::DEFAULT_WEIGHT,
                });
                reach.push(ReachabilityObservation {
                    from_peer_id: g.to_string(),
                    to_peer_id: t.to_string(),
                    observed_rtt_ms: 50,
                    observed_at_unix_ms: 1_700_000_000_000,
                });
            }
        }

        TopologyInputSnapshot {
            capacity_ads: ads,
            trust_grants: grants,
            reachability_observations: reach,
            locality_id: "loc-1".to_string(),
            snapshot_epoch_id: 42,
        }
    }

    #[test]
    fn same_input_same_output() {
        let snap = all_valid(&three_peer_snapshot());
        let a = compute_alm_topology_verified(&snap);
        let b = compute_alm_topology_verified(&snap);
        let a_bytes = serde_json::to_vec(&a).expect("serialize a");
        let b_bytes = serde_json::to_vec(&b).expect("serialize b");
        assert_eq!(a_bytes, b_bytes, "deterministic byte-equal output");
        // sanity: tree non-empty, version is v1.
        assert_eq!(a.topology_version, TOPOLOGY_VERSION);
        assert_eq!(a.snapshot_epoch_id, 42);
        assert!(!a.tree.is_empty(), "three rooted peers expected");
    }

    /// `wire_determinism_under_permutation` — the v3.10.0 property:
    /// input ads in any order MUST yield byte-equal output. Verified
    /// across ad reverse/rotate plus reachability + trust permutes.
    #[test]
    fn wire_determinism_under_permutation() {
        let base = three_peer_snapshot();
        let baseline = compute_alm_topology_verified(&all_valid(&base));

        // Reverse capacity ads.
        let mut p = base.clone();
        p.capacity_ads.reverse();
        assert_eq!(
            serde_json::to_vec(&baseline).unwrap(),
            serde_json::to_vec(&compute_alm_topology_verified(&all_valid(&p))).unwrap(),
            "ad permutation MUST NOT change output"
        );

        // Rotate capacity ads.
        let mut p2 = base.clone();
        p2.capacity_ads.rotate_left(1);
        assert_eq!(
            serde_json::to_vec(&baseline).unwrap(),
            serde_json::to_vec(&compute_alm_topology_verified(&all_valid(&p2))).unwrap(),
            "ad rotation MUST NOT change output"
        );

        // Permute reachability observations.
        let mut p3 = base.clone();
        p3.reachability_observations.reverse();
        assert_eq!(
            serde_json::to_vec(&baseline).unwrap(),
            serde_json::to_vec(&compute_alm_topology_verified(&all_valid(&p3))).unwrap(),
            "reachability permutation MUST NOT change output"
        );

        // Permute trust grants.
        let mut p4 = base.clone();
        p4.trust_grants.reverse();
        assert_eq!(
            serde_json::to_vec(&baseline).unwrap(),
            serde_json::to_vec(&compute_alm_topology_verified(&all_valid(&p4))).unwrap(),
            "trust permutation MUST NOT change output"
        );

        // Permute the verification-paired ad vector directly.
        let mut v = all_valid(&base);
        v.capacity_ads.reverse();
        assert_eq!(
            serde_json::to_vec(&baseline).unwrap(),
            serde_json::to_vec(&compute_alm_topology_verified(&v)).unwrap(),
            "verified-ad permutation MUST NOT change output"
        );
    }

    #[test]
    fn empty_snapshot_returns_empty_topology() {
        let snap = VerifiedTopologyInputSnapshot {
            capacity_ads: vec![],
            trust_grants: vec![],
            reachability_observations: vec![],
            locality_id: "loc-empty".to_string(),
            snapshot_epoch_id: 7,
        };
        let topo = compute_alm_topology_verified(&snap);
        assert!(topo.tree.is_empty());
        assert!(topo.unrooted_peers.is_empty());
        assert_eq!(topo.snapshot_epoch_id, 7);
        assert_eq!(topo.topology_version, TOPOLOGY_VERSION);
    }

    #[test]
    fn locality_filter_excludes_out_of_locality() {
        // Two peers in locality (have reachability observations);
        // peer-x has a capacity ad but NO reachability observations →
        // out of locality → unrooted.
        let ads = vec![
            fake_signed_ad("peer-a", 100.0, 1_700_000_000_000, vec![]),
            fake_signed_ad("peer-b", 50.0, 1_700_000_000_500, vec![]),
            fake_signed_ad("peer-x", 200.0, 1_700_000_000_750, vec![]),
        ];
        let grants = vec![
            TrustGrant {
                granter_peer_id: "peer-a".into(),
                grantee_peer_id: "peer-b".into(),
                granted_at_unix_ms: 1_700_000_000_000,
                chain_depth: 0,
                weight: TrustGrant::DEFAULT_WEIGHT,
            },
            TrustGrant {
                granter_peer_id: "peer-b".into(),
                grantee_peer_id: "peer-a".into(),
                granted_at_unix_ms: 1_700_000_000_000,
                chain_depth: 0,
                weight: TrustGrant::DEFAULT_WEIGHT,
            },
        ];
        let reach = vec![
            ReachabilityObservation {
                from_peer_id: "peer-a".into(),
                to_peer_id: "peer-b".into(),
                observed_rtt_ms: 30,
                observed_at_unix_ms: 1_700_000_000_000,
            },
            ReachabilityObservation {
                from_peer_id: "peer-b".into(),
                to_peer_id: "peer-a".into(),
                observed_rtt_ms: 30,
                observed_at_unix_ms: 1_700_000_000_000,
            },
        ];

        let snap = TopologyInputSnapshot {
            capacity_ads: ads,
            trust_grants: grants,
            reachability_observations: reach,
            locality_id: "loc-1".into(),
            snapshot_epoch_id: 99,
        };
        let topo = compute_alm_topology_verified(&all_valid(&snap));

        assert!(
            topo.unrooted_peers.contains(&"peer-x".to_string()),
            "peer-x not in locality must be unrooted: {topo:?}"
        );
        // Neither edge should reference peer-x.
        for edge in &topo.tree {
            assert_ne!(edge.parent_peer_id, "peer-x");
            assert_ne!(edge.child_peer_id, "peer-x");
        }
    }

    #[test]
    fn trust_chain_depth_respected() {
        // peer-a → peer-b grant at depth = MAX_TRUST_CHAIN_DEPTH + 1
        // → dropped → peer-b has no parent under trust horizon →
        // unrooted (if no other grants).
        let ads = vec![
            fake_signed_ad("peer-a", 100.0, 1_700_000_000_000, vec![]),
            fake_signed_ad("peer-b", 50.0, 1_700_000_000_500, vec![]),
        ];
        let grants = vec![TrustGrant {
            granter_peer_id: "peer-a".into(),
            grantee_peer_id: "peer-b".into(),
            granted_at_unix_ms: 1_700_000_000_000,
            chain_depth: MAX_TRUST_CHAIN_DEPTH + 1,
            weight: TrustGrant::DEFAULT_WEIGHT,
        }];
        let reach = vec![
            ReachabilityObservation {
                from_peer_id: "peer-a".into(),
                to_peer_id: "peer-b".into(),
                observed_rtt_ms: 30,
                observed_at_unix_ms: 1_700_000_000_000,
            },
            ReachabilityObservation {
                from_peer_id: "peer-b".into(),
                to_peer_id: "peer-a".into(),
                observed_rtt_ms: 30,
                observed_at_unix_ms: 1_700_000_000_000,
            },
        ];

        let snap = TopologyInputSnapshot {
            capacity_ads: ads,
            trust_grants: grants,
            reachability_observations: reach,
            locality_id: "loc-1".into(),
            snapshot_epoch_id: 1,
        };
        let topo = compute_alm_topology_verified(&all_valid(&snap));

        // No edges at all (no usable trust grants in either
        // direction).
        assert!(
            topo.tree.is_empty(),
            "no trust within horizon → no edges: {topo:?}"
        );
        assert!(topo.unrooted_peers.contains(&"peer-a".to_string()));
        assert!(topo.unrooted_peers.contains(&"peer-b".to_string()));
    }

    #[test]
    fn tie_break_by_peer_id_lex_min() {
        // Two parents (peer-aa and peer-zz) score equally for
        // peer-child: same uplink, same trust depth, same RTT. The
        // lex-min parent_peer_id ("peer-aa") wins.
        let ads = vec![
            fake_signed_ad("peer-aa", 100.0, 1_700_000_000_000, vec![]),
            fake_signed_ad("peer-zz", 100.0, 1_700_000_000_500, vec![]),
            fake_signed_ad("peer-child", 10.0, 1_700_000_001_000, vec![]),
        ];
        let mut grants = Vec::new();
        let mut reach = Vec::new();
        let peers = ["peer-aa", "peer-zz", "peer-child"];
        for &g in &peers {
            for &t in &peers {
                if g == t {
                    continue;
                }
                grants.push(TrustGrant {
                    granter_peer_id: g.into(),
                    grantee_peer_id: t.into(),
                    granted_at_unix_ms: 1_700_000_000_000,
                    chain_depth: 0,
                    weight: TrustGrant::DEFAULT_WEIGHT,
                });
                reach.push(ReachabilityObservation {
                    from_peer_id: g.into(),
                    to_peer_id: t.into(),
                    observed_rtt_ms: 50,
                    observed_at_unix_ms: 1_700_000_000_000,
                });
            }
        }

        let snap = TopologyInputSnapshot {
            capacity_ads: ads,
            trust_grants: grants,
            reachability_observations: reach,
            locality_id: "loc-tie".into(),
            snapshot_epoch_id: 8,
        };
        let topo = compute_alm_topology_verified(&all_valid(&snap));

        let child_edge = topo
            .tree
            .iter()
            .find(|e| e.child_peer_id == "peer-child")
            .expect("peer-child should be rooted");
        assert_eq!(
            child_edge.parent_peer_id, "peer-aa",
            "lex-min parent wins on tie: {topo:?}"
        );
    }

    #[test]
    fn mdc_sub_stream_emits_one_edge_per_path() {
        // peer-child commits to two sub-streams; expect two edges
        // (one per path) all to the lex-min eligible parent.
        let commitments = vec![
            SubStreamCommitment {
                sub_stream_path: vec![0],
                uplink_budget_mbps: 5.0,
                max_subscribers: 4,
            },
            SubStreamCommitment {
                sub_stream_path: vec![1],
                uplink_budget_mbps: 5.0,
                max_subscribers: 4,
            },
        ];
        let ads = vec![
            fake_signed_ad("peer-a", 100.0, 1_700_000_000_000, vec![]),
            fake_signed_ad("peer-child", 10.0, 1_700_000_001_000, commitments),
        ];
        let grants = vec![
            TrustGrant {
                granter_peer_id: "peer-a".into(),
                grantee_peer_id: "peer-child".into(),
                granted_at_unix_ms: 1_700_000_000_000,
                chain_depth: 0,
                weight: TrustGrant::DEFAULT_WEIGHT,
            },
            TrustGrant {
                granter_peer_id: "peer-child".into(),
                grantee_peer_id: "peer-a".into(),
                granted_at_unix_ms: 1_700_000_000_000,
                chain_depth: 0,
                weight: TrustGrant::DEFAULT_WEIGHT,
            },
        ];
        let reach = vec![
            ReachabilityObservation {
                from_peer_id: "peer-a".into(),
                to_peer_id: "peer-child".into(),
                observed_rtt_ms: 50,
                observed_at_unix_ms: 1_700_000_000_000,
            },
            ReachabilityObservation {
                from_peer_id: "peer-child".into(),
                to_peer_id: "peer-a".into(),
                observed_rtt_ms: 50,
                observed_at_unix_ms: 1_700_000_000_000,
            },
        ];

        let snap = TopologyInputSnapshot {
            capacity_ads: ads,
            trust_grants: grants,
            reachability_observations: reach,
            locality_id: "loc-mdc".into(),
            snapshot_epoch_id: 11,
        };
        let topo = compute_alm_topology_verified(&all_valid(&snap));

        // Two MDC edges for peer-child.
        let child_edges: Vec<&AlmEdge> = topo
            .tree
            .iter()
            .filter(|e| e.child_peer_id == "peer-child")
            .collect();
        assert_eq!(
            child_edges.len(),
            2,
            "MDC child should have one edge per sub-stream: {topo:?}"
        );
        // Canonical order: paths sorted lex-min.
        assert_eq!(child_edges[0].sub_stream_path, vec![0u8]);
        assert_eq!(child_edges[1].sub_stream_path, vec![1u8]);
        // All to peer-a.
        for e in &child_edges {
            assert_eq!(e.parent_peer_id, "peer-a");
        }
    }

    // ─────────────────────────────────────────────────────────────
    // F-4 hardening — verification filter, self-assertion clamp,
    // sub_path distribution (CIRISEdge#143).
    // ─────────────────────────────────────────────────────────────

    /// Snapshot with 5 ads, 2 unverified → topology built from only
    /// the 3 verified peers; the 2 unverified peers never enter
    /// scoring (zero capacity) and so never appear as parents.
    #[test]
    fn unverified_ads_dropped_before_scoring() {
        let peers = ["peer-a", "peer-b", "peer-c", "peer-d", "peer-e"];
        let ads: Vec<SignedRelayCapacity> = peers
            .iter()
            .enumerate()
            .map(|(i, p)| fake_signed_ad(p, 100.0, 1_700_000_000_000 + i as u64 * 100, vec![]))
            .collect();
        let mut grants = Vec::new();
        let mut reach = Vec::new();
        for &g in &peers {
            for &t in &peers {
                if g == t {
                    continue;
                }
                grants.push(TrustGrant {
                    granter_peer_id: g.into(),
                    grantee_peer_id: t.into(),
                    granted_at_unix_ms: 1_700_000_000_000,
                    chain_depth: 0,
                    weight: TrustGrant::DEFAULT_WEIGHT,
                });
                reach.push(ReachabilityObservation {
                    from_peer_id: g.into(),
                    to_peer_id: t.into(),
                    observed_rtt_ms: 50,
                    observed_at_unix_ms: 1_700_000_000_000,
                });
            }
        }

        // peer-d and peer-e are Unverified → dropped.
        let capacity_ads: Vec<VerifiedCapacityAd> = ads
            .into_iter()
            .map(|ad| {
                let verification =
                    if ad.advertiser_key_id == "peer-d" || ad.advertiser_key_id == "peer-e" {
                        CapacityVerification::Unverified
                    } else {
                        CapacityVerification::HybridSignatureValid
                    };
                VerifiedCapacityAd { ad, verification }
            })
            .collect();

        let snap = VerifiedTopologyInputSnapshot {
            capacity_ads,
            trust_grants: grants,
            reachability_observations: reach,
            locality_id: "loc-drop".into(),
            snapshot_epoch_id: 5,
        };
        let topo = compute_alm_topology_verified(&snap);

        // Only the 3 verified peers may appear as parent or child.
        for edge in &topo.tree {
            for id in [&edge.parent_peer_id, &edge.child_peer_id] {
                assert!(
                    ["peer-a", "peer-b", "peer-c"].contains(&id.as_str()),
                    "unverified peer {id} leaked into the tree: {topo:?}"
                );
            }
        }
        // Exactly the 3 verified peers are rooted.
        let rooted: std::collections::BTreeSet<&str> =
            topo.tree.iter().map(|e| e.child_peer_id.as_str()).collect();
        assert_eq!(rooted, ["peer-a", "peer-b", "peer-c"].into_iter().collect());
        // The dropped peers do NOT appear anywhere — not even unrooted
        // (they never entered scoring).
        assert!(!topo.unrooted_peers.contains(&"peer-d".to_string()));
        assert!(!topo.unrooted_peers.contains(&"peer-e".to_string()));
    }

    /// A peer advertising 10 Gbps with only a HybridSignatureValid ad
    /// is clamped to 1 Gbps for scoring — it does NOT out-score a
    /// peer advertising exactly the cap.
    #[test]
    fn clamped_capacity_at_max_self_asserted() {
        // 10 Gbps = 10_000 Mbps → 10_000_000 millibps quantized.
        let ten_gbps = f32_mbps_to_millibps_u64(10_000.0);
        assert_eq!(ten_gbps, 10_000_000);
        // HybridSignatureValid clamps to 1 Gbps = 1000 Mbps =
        // 1_000_000 millibps.
        let clamped =
            clamp_self_asserted_millibps(ten_gbps, CapacityVerification::HybridSignatureValid);
        assert_eq!(clamped, 1_000_000, "10 Gbps self-asserted clamps to 1 Gbps");
        // An honest 1 Gbps peer quantizes to the same value → after
        // clamp the liar gains nothing.
        let honest = f32_mbps_to_millibps_u64(1000.0);
        assert_eq!(
            clamp_self_asserted_millibps(honest, CapacityVerification::HybridSignatureValid),
            clamped,
            "clamped liar ties an honest 1 Gbps peer"
        );
    }

    /// A ThroughputChallenged ad advertising 10 Gbps is NOT clamped —
    /// observed-throughput confirmation lets it exceed the
    /// self-assertion cap.
    #[test]
    fn throughput_challenged_uncapped() {
        let ten_gbps = f32_mbps_to_millibps_u64(10_000.0);
        let challenged =
            clamp_self_asserted_millibps(ten_gbps, CapacityVerification::ThroughputChallenged);
        assert_eq!(challenged, 10_000_000, "throughput-challenged is uncapped");
        assert!(
            challenged
                > clamp_self_asserted_millibps(
                    ten_gbps,
                    CapacityVerification::HybridSignatureValid
                ),
            "challenged out-scores merely-signed for the same advertisement"
        );
    }

    /// Many children competing for the SAME MDC quadrant spread across
    /// distinct equally-good parents — the [`PENALTY_PER_SUB_PATH_DUP`]
    /// drives diversification instead of concentrating every sub-stream
    /// subscriber on the lex-min parent (the F-4 concentration vector).
    #[test]
    fn sub_path_penalty_distributes_mdc() {
        let parents = ["par-1", "par-2", "par-3", "par-4"];
        let children = ["kid-1", "kid-2", "kid-3", "kid-4"];

        let mut ads: Vec<SignedRelayCapacity> = parents
            .iter()
            .enumerate()
            .map(|(i, p)| fake_signed_ad(p, 100.0, 1_700_000_000_000 + i as u64, vec![]))
            .collect();
        for (i, c) in children.iter().enumerate() {
            ads.push(fake_signed_ad(
                c,
                10.0,
                1_700_000_010_000 + i as u64,
                vec![SubStreamCommitment {
                    sub_stream_path: vec![0],
                    uplink_budget_mbps: 5.0,
                    max_subscribers: 4,
                }],
            ));
        }

        // Every peer grants + reaches every other equally, so the only
        // differentiator is the sub_path duplication penalty.
        let mut grants = Vec::new();
        let mut reach = Vec::new();
        let all: Vec<&str> = parents.iter().chain(children.iter()).copied().collect();
        for &g in &all {
            for &t in &all {
                if g == t {
                    continue;
                }
                grants.push(TrustGrant {
                    granter_peer_id: g.into(),
                    grantee_peer_id: t.into(),
                    granted_at_unix_ms: 1_700_000_000_000,
                    chain_depth: 0,
                    weight: TrustGrant::DEFAULT_WEIGHT,
                });
                reach.push(ReachabilityObservation {
                    from_peer_id: g.into(),
                    to_peer_id: t.into(),
                    observed_rtt_ms: 50,
                    observed_at_unix_ms: 1_700_000_000_000,
                });
            }
        }

        let snap = TopologyInputSnapshot {
            capacity_ads: ads,
            trust_grants: grants,
            reachability_observations: reach,
            locality_id: "loc-mdc-dist".into(),
            snapshot_epoch_id: 77,
        };
        let topo = compute_alm_topology_verified(&all_valid(&snap));

        // Each child rooted on path [0]; collect the chosen parents.
        let chosen: Vec<&str> = children
            .iter()
            .map(|c| {
                topo.tree
                    .iter()
                    .find(|e| e.child_peer_id == *c && e.sub_stream_path == vec![0u8])
                    .unwrap_or_else(|| panic!("{c} should be rooted on path [0]: {topo:?}"))
                    .parent_peer_id
                    .as_str()
            })
            .collect();

        // Four children land on four DISTINCT parents — the penalty
        // fully diversified the quadrant's subscribers.
        let distinct: std::collections::BTreeSet<&str> = chosen.iter().copied().collect();
        assert_eq!(
            distinct.len(),
            4,
            "sub_path penalty must spread 4 same-quadrant subscribers across 4 parents: {chosen:?}"
        );
    }

    /// Legacy entry (`compute_alm_topology`) treats every ad as
    /// Unverified, so it returns an EMPTY topology — the safe default
    /// for v4.0.x callers that have not migrated to
    /// [`compute_alm_topology_verified`].
    #[test]
    fn existing_compute_alm_topology_treats_all_as_unverified() {
        let snap = three_peer_snapshot();
        let topo = compute_alm_topology(&snap);
        assert!(
            topo.tree.is_empty(),
            "legacy entry must yield an empty tree (all ads Unverified): {topo:?}"
        );
        // Unverified ads never enter scoring, so dropped peers are not
        // even listed as unrooted.
        assert!(
            topo.unrooted_peers.is_empty(),
            "legacy entry roots nobody and lists nobody: {topo:?}"
        );
        assert_eq!(topo.topology_version, TOPOLOGY_VERSION);
        assert_eq!(topo.snapshot_epoch_id, 42);
    }
}
