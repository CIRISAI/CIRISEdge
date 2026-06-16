//! ALM-B — parent finding / tree join (CIRISEdge#131 + CIRISEdge#128 MDC).
//!
//! Given a stream + my own [`ReceiverLayerPolicy`] + a candidate
//! pool of [`ParentCandidate`]s, [`AlmJoinPlanner::plan`] picks the
//! best primary parent (lowest RTT with room + adequate
//! reachability + layer-policy compatible) and up to
//! [`MAX_BACKUPS`] backups. The result is a [`JoinPlan`] the caller
//! uses to drive the existing relay subscribe primitive.
//!
//! ## What ALM-B IS
//!
//! - A pure, stateless function: candidates + reachability + stream
//!   bitrate → [`JoinPlan`] (or [`AlmJoinError`]).
//! - Deterministic in wall-clock time: the caller passes
//!   `wall_clock_unix_ms` so staleness is testable without mocking
//!   the system clock.
//!
//! ## What ALM-B is NOT
//!
//! - It does NOT subscribe to the parent. The actual subscribe call
//!   is [`crate::transport::realtime_av_relay::RelayNode::subscribe`]
//!   on the parent's [`crate::transport::realtime_av_relay::RelayNode`] —
//!   that already exists. ALM-B's job is to PICK the parent.
//! - It does NOT query federation_directory. The caller hands the
//!   candidate slice in; integrating with the directory is out of
//!   scope.
//! - It does NOT verify [`super::SignedRelayCapacity`]. That's
//!   federation_directory's responsibility — see HNDL discipline
//!   below.
//! - It does NOT manage multi-parent subscriptions. ALM-B returns
//!   the backup list; ALM-C consumes it.
//!
//! ## HNDL posture
//!
//! ALM-A's [`super::SignedRelayCapacity::verify`] is called by the
//! federation_directory read path **before** candidates reach this
//! module. A malicious peer cannot inject candidates because
//! federation_directory rejects unsigned / invalid advertisements
//! upstream. ALM-B's input shape ([`ParentCandidate`]) carries the
//! verified [`super::SignedRelayCapacity`] — the planner has no need
//! to re-verify, and the per-peer / per-stream binding is read
//! straight from the signed envelope's `advertiser_key_id` /
//! `stream_id` fields.
//!
//! ## Selection algorithm (the actual ranking)
//!
//! For a stream with bitrate `B` Mbps and my layer policy `P`,
//! given candidates `[c_0, c_1, ..., c_n]`:
//!
//! 1. **Staleness filter** — drop candidates whose
//!    `capacity.is_stale(wall_clock)` is true.
//! 2. **Layer-policy filter** — drop candidates whose
//!    `capacity.max_layer_supported` does NOT cover the receiver's
//!    layer policy `P`. The "covers" test:
//!    `max_layer_supported >= my_layer_policy.max_*` on every axis.
//! 3. **Room filter** — drop candidates without
//!    `capacity.has_room_for(B, 0)` (or `has_room_for_substream` in
//!    the MDC path).
//! 4. **Reachability filter** — drop candidates with
//!    `reachability_ratio < MIN_REACHABILITY_RATIO`. Unknown
//!    reachability (`None`) is treated as **worse than known-bad**.
//! 5. **RTT sort** — sort by `rtt_ms_estimate` ascending. `None`
//!    sorts to the end.
//! 6. **Primary = first; backups = next [`MAX_BACKUPS`]**.
//! 7. **Empty after filtering** — return the most-specific
//!    [`AlmJoinError`] variant.
//!
//! ## MDC mode — plan_for_substream (CIRISEdge#128)
//!
//! [`AlmJoinPlanner::plan_for_substream`] runs the same selection
//! algorithm but with the room filter swapped for
//! [`super::RelayCapacity::has_room_for_substream`], so only
//! candidates that commit to (or opaquely accept) the requested
//! sub-stream path are admitted.

use crate::transport::realtime_av::ReceiverLayerPolicy;

use super::capacity::{PeerKeyId, RelayCapacity, SignedRelayCapacity};

/// Minimum acceptable observed reachability ratio for a candidate
/// to be considered as a parent. `< MIN_REACHABILITY_RATIO` →
/// excluded. Unknown (no history) is treated as worse than this
/// and also excluded.
pub const MIN_REACHABILITY_RATIO: f64 = 0.5;

/// Maximum number of backup parents [`AlmJoinPlanner`] returns
/// alongside the primary. ALM-C consumes the list to set up
/// multi-parent subscription.
pub const MAX_BACKUPS: usize = 2;

/// One candidate parent relay's signed advertised capacity plus the
/// local reachability snapshot.
///
/// The caller (federation_directory integrator) shapes this from the
/// verified [`SignedRelayCapacity`] + a
/// [`crate::reachability::ReachabilityTracker`] snapshot for the
/// candidate's peer key id. ALM-B is signature-blind by design — the
/// `signed_capacity` is already verified upstream.
///
/// The per-peer (`advertiser_key_id`) and per-stream (`stream_id`)
/// bindings are read directly off `signed_capacity`; the planner
/// derives them on demand via [`Self::peer_key_id`] /
/// [`Self::stream_id`] rather than denormalizing them onto the outer
/// type.
#[derive(Debug, Clone)]
pub struct ParentCandidate {
    /// The candidate's signed capacity advertisement (already verified
    /// upstream by federation_directory). Carries the `advertiser_key_id`,
    /// `stream_id`, and `epoch` bindings on the signed envelope plus
    /// the inner [`RelayCapacity`] with its uplink / room / layer
    /// fields.
    pub signed_capacity: SignedRelayCapacity,
    /// Observed reachability ratio (`0.0..=1.0`). `None` if there is
    /// no history. We treat `None` as **worse than known-bad** for
    /// realtime: cold peers don't get a first shot.
    pub reachability_ratio: Option<f64>,
    /// Estimated RTT in milliseconds. `None` if no history.
    pub rtt_ms_estimate: Option<u32>,
}

impl ParentCandidate {
    /// Federation `key_id` of the candidate — read off the signed
    /// envelope's `advertiser_key_id`.
    #[must_use]
    pub fn peer_key_id(&self) -> &PeerKeyId {
        &self.signed_capacity.advertiser_key_id
    }

    /// The inner [`RelayCapacity`] — read off the signed envelope.
    /// Convenience for callers that want to inspect uplink / room /
    /// layer without walking into `signed_capacity.capacity`.
    #[must_use]
    pub fn capacity(&self) -> &RelayCapacity {
        &self.signed_capacity.capacity
    }
}

/// The output of [`AlmJoinPlanner::plan`] — the primary parent, the
/// backup list (ALM-C consumes), and the stream bitrate the plan was
/// sized for (so a receiver that downgrades their layer policy can
/// detect when a re-plan is needed).
#[derive(Debug, Clone, PartialEq)]
pub struct JoinPlan {
    /// The peer key id of the chosen primary parent.
    pub primary_parent: PeerKeyId,
    /// Up to [`MAX_BACKUPS`] backup parents in RTT-ascending order.
    /// Empty if only one feasible candidate exists in the pool.
    pub backup_parents: Vec<PeerKeyId>,
    /// The chunk-bitrate budget this plan is sized for, in Mbps.
    pub stream_bitrate_mbps: f32,
}

/// Errors [`AlmJoinPlanner::plan`] returns. The dispatch is the
/// **most-specific reason the candidate pool is empty after
/// filtering**:
///
/// - [`Self::NoFeasibleParent`] — the catch-all.
/// - [`Self::AllCandidatesStale`] — every candidate failed staleness.
/// - [`Self::NoCandidateSupportsLayerPolicy`] — every candidate
///   failed the layer-policy filter.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AlmJoinError {
    /// No candidate has room + acceptable reachability + a fresh
    /// advertisement + layer-policy compatibility.
    #[error("no feasible parent in the candidate pool")]
    NoFeasibleParent,
    /// Every candidate's advertisement is stale.
    #[error("all candidates' advertisements are stale")]
    AllCandidatesStale,
    /// Every candidate's `max_layer_supported` is below the
    /// receiver's layer policy.
    #[error("no candidate's max_layer_supported covers my layer policy")]
    NoCandidateSupportsLayerPolicy,
}

/// Stateless parent-finding planner.
pub struct AlmJoinPlanner;

impl AlmJoinPlanner {
    /// Pick the best parent (and backups) for a stream given the
    /// candidate pool. See the [module docs](self) §"Selection
    /// algorithm" for the full filtering + ranking rules.
    ///
    /// Uses the opaque-mode room check
    /// ([`RelayCapacity::has_room_for`]). For MDC sub-stream planning
    /// see [`Self::plan_for_substream`].
    ///
    /// # Errors
    ///
    /// Returns one of:
    /// - [`AlmJoinError::AllCandidatesStale`] when only the
    ///   staleness filter rejects.
    /// - [`AlmJoinError::NoCandidateSupportsLayerPolicy`] when
    ///   only the layer filter rejects.
    /// - [`AlmJoinError::NoFeasibleParent`] in every other empty
    ///   case (including an empty input pool).
    pub fn plan(
        candidates: &[ParentCandidate],
        stream_bitrate_mbps: f32,
        my_layer_policy: ReceiverLayerPolicy,
        wall_clock_unix_ms: u64,
    ) -> Result<JoinPlan, AlmJoinError> {
        Self::plan_inner(
            candidates,
            stream_bitrate_mbps,
            my_layer_policy,
            wall_clock_unix_ms,
            // No sub-stream path → opaque-mode room check.
            None,
        )
    }

    /// Plan a parent for a specific MDC sub-stream (CIRISEdge#128).
    ///
    /// Filters candidates to those whose [`RelayCapacity`] admits the
    /// sub-stream (via [`RelayCapacity::has_room_for_substream`]).
    /// Staleness, reachability, and layer-policy filters are unchanged
    /// from [`Self::plan`].
    ///
    /// A candidate with an opaque-mode capacity (empty
    /// `sub_stream_commitments`) admits any sub-stream up to the
    /// overall uplink budget; a candidate with declared commitments
    /// admits only sub-streams whose path is in their commitment list.
    ///
    /// # Errors
    ///
    /// Same dispatch as [`Self::plan`] — but `NoFeasibleParent` covers
    /// the case where every candidate lacks the sub-stream commitment
    /// too. The narrow `NoCandidateSupportsLayerPolicy` /
    /// `AllCandidatesStale` errors fire only when those filters are
    /// solely responsible.
    pub fn plan_for_substream(
        candidates: &[ParentCandidate],
        sub_stream_path: &[u8],
        stream_bitrate_mbps: f32,
        my_layer_policy: ReceiverLayerPolicy,
        wall_clock_unix_ms: u64,
    ) -> Result<JoinPlan, AlmJoinError> {
        Self::plan_inner(
            candidates,
            stream_bitrate_mbps,
            my_layer_policy,
            wall_clock_unix_ms,
            Some(sub_stream_path),
        )
    }

    fn plan_inner(
        candidates: &[ParentCandidate],
        stream_bitrate_mbps: f32,
        my_layer_policy: ReceiverLayerPolicy,
        wall_clock_unix_ms: u64,
        sub_stream_path: Option<&[u8]>,
    ) -> Result<JoinPlan, AlmJoinError> {
        if candidates.is_empty() {
            return Err(AlmJoinError::NoFeasibleParent);
        }

        // Step 1 — staleness filter.
        let fresh: Vec<&ParentCandidate> = candidates
            .iter()
            .filter(|c| !c.capacity().is_stale(wall_clock_unix_ms))
            .collect();
        if fresh.is_empty() {
            return Err(AlmJoinError::AllCandidatesStale);
        }

        // Step 2 — layer-policy filter.
        let layer_ok: Vec<&ParentCandidate> = fresh
            .iter()
            .copied()
            .filter(|c| supports_layer_policy(c.capacity(), my_layer_policy))
            .collect();
        if layer_ok.is_empty() {
            let any_layer_ok_in_pool = candidates
                .iter()
                .any(|c| supports_layer_policy(c.capacity(), my_layer_policy));
            if any_layer_ok_in_pool {
                return Err(AlmJoinError::NoFeasibleParent);
            }
            return Err(AlmJoinError::NoCandidateSupportsLayerPolicy);
        }

        // Step 3 — room filter. Switch on sub_stream_path: opaque vs MDC.
        let room_ok: Vec<&ParentCandidate> = layer_ok
            .iter()
            .copied()
            .filter(|c| match sub_stream_path {
                None => c.capacity().has_room_for(stream_bitrate_mbps, 0),
                Some(path) => c
                    .capacity()
                    .has_room_for_substream(path, stream_bitrate_mbps, 0),
            })
            .collect();

        // Step 4 — reachability filter.
        let reachable: Vec<&ParentCandidate> = room_ok
            .iter()
            .copied()
            .filter(|c| {
                c.reachability_ratio
                    .is_some_and(|r| r >= MIN_REACHABILITY_RATIO)
            })
            .collect();

        if reachable.is_empty() {
            return Err(AlmJoinError::NoFeasibleParent);
        }

        // Step 5 — RTT sort ascending. `None` sorts to the end.
        let mut ranked: Vec<&ParentCandidate> = reachable;
        ranked.sort_by_key(|c| c.rtt_ms_estimate.unwrap_or(u32::MAX));

        // Step 6 — primary + up to MAX_BACKUPS backups.
        let primary = ranked.remove(0).peer_key_id().clone();
        let backup_parents: Vec<PeerKeyId> = ranked
            .iter()
            .take(MAX_BACKUPS)
            .map(|c| c.peer_key_id().clone())
            .collect();

        Ok(JoinPlan {
            primary_parent: primary,
            backup_parents,
            stream_bitrate_mbps,
        })
    }
}

/// True iff `cap.max_layer_supported` covers every axis of `policy`.
fn supports_layer_policy(cap: &RelayCapacity, policy: ReceiverLayerPolicy) -> bool {
    cap.max_layer_supported.max_spatial >= policy.max_spatial
        && cap.max_layer_supported.max_temporal >= policy.max_temporal
        && cap.max_layer_supported.max_quality >= policy.max_quality
}

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;
    use crate::transport::realtime_av::{Epoch, StreamId};
    use crate::transport::realtime_av_alm::capacity::SubStreamCommitment;

    fn stream() -> StreamId {
        StreamId([0xA1; 32])
    }

    /// `UNCAPPED` policy as a ChunkLayer-equivalent — every axis at u8::MAX.
    const UNCAPPED_RX: ReceiverLayerPolicy = ReceiverLayerPolicy::UNCAPPED;
    /// Receive-side equivalent of a "blinking dot" cap — every axis 0.
    /// Matches what an honest "I can only forward base-layer" relay
    /// would advertise via `max_layer_supported`.
    const BASE_RX: ReceiverLayerPolicy = ReceiverLayerPolicy::BLINKING_DOT;

    /// Build a fresh `SignedRelayCapacity` shell for tests. The
    /// signature fields are placeholders — ALM-B is signature-blind.
    fn signed_capacity(
        peer: &str,
        max_layer_supported: ReceiverLayerPolicy,
        uplink_mbps: f32,
        measured_at_unix_ms: u64,
    ) -> SignedRelayCapacity {
        signed_capacity_with_subs(
            peer,
            max_layer_supported,
            uplink_mbps,
            measured_at_unix_ms,
            Vec::new(),
        )
    }

    fn signed_capacity_with_subs(
        peer: &str,
        max_layer_supported: ReceiverLayerPolicy,
        uplink_mbps: f32,
        measured_at_unix_ms: u64,
        subs: Vec<SubStreamCommitment>,
    ) -> SignedRelayCapacity {
        let capacity = RelayCapacity::with_substream_commitments(
            uplink_mbps,
            4,
            16,
            max_layer_supported,
            measured_at_unix_ms,
            subs,
        );
        SignedRelayCapacity {
            advertiser_key_id: peer.to_string(),
            capacity,
            stream_id: stream(),
            epoch: Epoch(1),
            signature_ed25519_base64: String::new(),
            signature_ml_dsa_65_base64: String::new(),
        }
    }

    /// Build a candidate. Uses the standard fresh `measured_at`
    /// (1_000) so a tested wall clock of FRESH_WALL_CLOCK (5_000)
    /// keeps it fresh (within the 30s STALE_AFTER_SECS window).
    fn candidate(
        peer: &str,
        max_layer: ReceiverLayerPolicy,
        uplink_mbps: f32,
        reachability_ratio: Option<f64>,
        rtt_ms_estimate: Option<u32>,
    ) -> ParentCandidate {
        ParentCandidate {
            signed_capacity: signed_capacity(peer, max_layer, uplink_mbps, 1_000),
            reachability_ratio,
            rtt_ms_estimate,
        }
    }

    fn candidate_with_subs(
        peer: &str,
        max_layer: ReceiverLayerPolicy,
        uplink_mbps: f32,
        reachability_ratio: Option<f64>,
        rtt_ms_estimate: Option<u32>,
        subs: Vec<SubStreamCommitment>,
    ) -> ParentCandidate {
        ParentCandidate {
            signed_capacity: signed_capacity_with_subs(peer, max_layer, uplink_mbps, 1_000, subs),
            reachability_ratio,
            rtt_ms_estimate,
        }
    }

    /// Build a candidate with a stale advertisement — measured 50s
    /// before STALE_WALL_CLOCK so the 30s STALE_AFTER_SECS gate fires.
    fn stale_candidate(peer: &str) -> ParentCandidate {
        ParentCandidate {
            // measured at t=1_000; STALE_AFTER_SECS = 30 → stale at
            // any wall clock >= 31_000.
            signed_capacity: signed_capacity(peer, UNCAPPED_RX, 100.0, 1_000),
            reachability_ratio: Some(0.95),
            rtt_ms_estimate: Some(20),
        }
    }

    /// Wall clock used in fresh-advertisement tests — within the 30s
    /// staleness window from `measured_at = 1_000`.
    const FRESH_WALL_CLOCK: u64 = 5_000;
    /// Wall clock past the 30s staleness window from `measured_at =
    /// 1_000` AND well past stale_candidate's TTL.
    const STALE_WALL_CLOCK: u64 = 60_000;

    fn substream_commitment(path: Vec<u8>, budget: f32, subs: u16) -> SubStreamCommitment {
        SubStreamCommitment {
            sub_stream_path: path,
            uplink_budget_mbps: budget,
            max_subscribers: subs,
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Happy paths.
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn plan_picks_lowest_rtt_among_feasible() {
        let candidates = vec![
            candidate("slow", UNCAPPED_RX, 100.0, Some(0.95), Some(200)),
            candidate("fast", UNCAPPED_RX, 100.0, Some(0.95), Some(50)),
            candidate("middle", UNCAPPED_RX, 100.0, Some(0.95), Some(100)),
        ];
        let plan = AlmJoinPlanner::plan(
            &candidates,
            2.5,
            ReceiverLayerPolicy::UNCAPPED,
            FRESH_WALL_CLOCK,
        )
        .expect("a feasible plan");
        assert_eq!(plan.primary_parent, "fast");
        assert_eq!(plan.backup_parents, vec!["middle", "slow"]);
        assert!((plan.stream_bitrate_mbps - 2.5).abs() < f32::EPSILON);
    }

    // ──────────────────────────────────────────────────────────────
    // Layer-policy filtering.
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn plan_respects_layer_policy() {
        let candidates = vec![
            candidate("blinking", BASE_RX, 100.0, Some(0.95), Some(50)),
            candidate("uncapped", UNCAPPED_RX, 100.0, Some(0.95), Some(200)),
        ];
        let plan = AlmJoinPlanner::plan(
            &candidates,
            2.5,
            ReceiverLayerPolicy::UNCAPPED,
            FRESH_WALL_CLOCK,
        )
        .expect("uncapped candidate must be feasible");
        assert_eq!(plan.primary_parent, "uncapped");
        assert!(plan.backup_parents.is_empty());
    }

    // ──────────────────────────────────────────────────────────────
    // Staleness filtering.
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn plan_filters_stale_advertisements() {
        // A candidate measured at t=0 is stale at any wall clock ≥
        // 30_000 (the 30s STALE_AFTER_SECS gate). A candidate
        // measured at t=1_000 is stale at wall clock ≥ 31_000.
        // Wall clock 30_500 puts the first stale, the second fresh.
        let mut stale = candidate("stale-but-fast", UNCAPPED_RX, 100.0, Some(0.95), Some(50));
        stale.signed_capacity.capacity.measured_at_unix_ms = 0;
        let fresh = candidate("fresh", UNCAPPED_RX, 100.0, Some(0.95), Some(200));
        let candidates = vec![stale, fresh];
        let plan = AlmJoinPlanner::plan(&candidates, 2.5, ReceiverLayerPolicy::UNCAPPED, 30_500)
            .expect("fresh candidate must be feasible");
        assert_eq!(plan.primary_parent, "fresh");
        assert!(plan.backup_parents.is_empty());
    }

    // ──────────────────────────────────────────────────────────────
    // Reachability filtering.
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn plan_filters_unreachable_candidates() {
        let candidates = vec![
            candidate("unreliable", UNCAPPED_RX, 100.0, Some(0.3), Some(20)),
            candidate("reliable", UNCAPPED_RX, 100.0, Some(0.95), Some(200)),
        ];
        let plan = AlmJoinPlanner::plan(
            &candidates,
            2.5,
            ReceiverLayerPolicy::UNCAPPED,
            FRESH_WALL_CLOCK,
        )
        .expect("reliable candidate must be feasible");
        assert_eq!(plan.primary_parent, "reliable");
        assert!(plan.backup_parents.is_empty());
    }

    #[test]
    fn plan_unknown_reachability_excluded() {
        let candidates = vec![
            candidate("unknown", UNCAPPED_RX, 100.0, None, Some(20)),
            candidate("known-good", UNCAPPED_RX, 100.0, Some(0.95), Some(200)),
        ];
        let plan = AlmJoinPlanner::plan(
            &candidates,
            2.5,
            ReceiverLayerPolicy::UNCAPPED,
            FRESH_WALL_CLOCK,
        )
        .expect("known-good candidate must be feasible");
        assert_eq!(plan.primary_parent, "known-good");
        assert!(plan.backup_parents.is_empty());
    }

    // ──────────────────────────────────────────────────────────────
    // Empty-pool / no-feasible-parent paths.
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn plan_returns_no_feasible_parent_when_pool_empty() {
        let candidates: Vec<ParentCandidate> = vec![];
        let r = AlmJoinPlanner::plan(
            &candidates,
            2.5,
            ReceiverLayerPolicy::UNCAPPED,
            FRESH_WALL_CLOCK,
        );
        assert_eq!(r, Err(AlmJoinError::NoFeasibleParent));
    }

    #[test]
    fn plan_returns_no_candidate_supports_layer_policy_correctly() {
        let candidates = vec![
            candidate("blink-1", BASE_RX, 100.0, Some(0.95), Some(50)),
            candidate("blink-2", BASE_RX, 100.0, Some(0.95), Some(100)),
        ];
        let r = AlmJoinPlanner::plan(
            &candidates,
            2.5,
            ReceiverLayerPolicy::UNCAPPED,
            FRESH_WALL_CLOCK,
        );
        assert_eq!(r, Err(AlmJoinError::NoCandidateSupportsLayerPolicy));
    }

    #[test]
    fn plan_returns_all_candidates_stale_correctly() {
        // Two stale candidates — both have measured_at = 1_000;
        // STALE_WALL_CLOCK = 60_000 puts them past the 30s gate.
        let candidates = vec![stale_candidate("a"), stale_candidate("b")];
        let r = AlmJoinPlanner::plan(
            &candidates,
            2.5,
            ReceiverLayerPolicy::UNCAPPED,
            STALE_WALL_CLOCK,
        );
        assert_eq!(r, Err(AlmJoinError::AllCandidatesStale));
    }

    #[test]
    fn plan_mixed_rejection_returns_generic_no_feasible_parent() {
        // a — uncapped but stale (measured at 0, stale at 30_500).
        // b — fresh but base-only.
        let a = ParentCandidate {
            signed_capacity: signed_capacity("a-stale-but-uncapped", UNCAPPED_RX, 100.0, 0),
            reachability_ratio: Some(0.95),
            rtt_ms_estimate: Some(20),
        };
        let b = candidate("b-fresh-but-blinking", BASE_RX, 100.0, Some(0.95), Some(50));
        let candidates = vec![a, b];
        // Wall clock 30_500 → a is stale (0 + 30_000 ≤ 30_500), b is
        // fresh (1_000 + 30_000 = 31_000 > 30_500).
        let r = AlmJoinPlanner::plan(&candidates, 2.5, ReceiverLayerPolicy::UNCAPPED, 30_500);
        assert_eq!(r, Err(AlmJoinError::NoFeasibleParent));
    }

    #[test]
    fn plan_filters_no_room_candidates() {
        // 2.5 Mbps stream; uplink 2.0 doesn't fit (1 × 2.5 > 2.0).
        let candidates = vec![
            candidate("no-room", UNCAPPED_RX, 2.0, Some(0.95), Some(20)),
            candidate("has-room", UNCAPPED_RX, 10.0, Some(0.95), Some(200)),
        ];
        let plan = AlmJoinPlanner::plan(
            &candidates,
            2.5,
            ReceiverLayerPolicy::UNCAPPED,
            FRESH_WALL_CLOCK,
        )
        .expect("has-room candidate must be feasible");
        assert_eq!(plan.primary_parent, "has-room");
        assert!(plan.backup_parents.is_empty());
    }

    // ──────────────────────────────────────────────────────────────
    // Backup selection.
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn plan_picks_backups_up_to_max_backups() {
        let candidates = vec![
            candidate("rtt-150", UNCAPPED_RX, 100.0, Some(0.95), Some(150)),
            candidate("rtt-50", UNCAPPED_RX, 100.0, Some(0.95), Some(50)),
            candidate("rtt-300", UNCAPPED_RX, 100.0, Some(0.95), Some(300)),
            candidate("rtt-200", UNCAPPED_RX, 100.0, Some(0.95), Some(200)),
            candidate("rtt-100", UNCAPPED_RX, 100.0, Some(0.95), Some(100)),
        ];
        let plan = AlmJoinPlanner::plan(
            &candidates,
            2.5,
            ReceiverLayerPolicy::UNCAPPED,
            FRESH_WALL_CLOCK,
        )
        .expect("feasible plan");
        assert_eq!(plan.primary_parent, "rtt-50");
        assert_eq!(plan.backup_parents.len(), MAX_BACKUPS);
        assert_eq!(plan.backup_parents[0], "rtt-100");
        assert_eq!(plan.backup_parents[1], "rtt-150");
    }

    #[test]
    fn plan_backups_empty_when_only_one_feasible() {
        // Build a feasible "lone", an explicitly-stale candidate, and
        // a fresh-but-unreliable candidate. Only "lone" survives all
        // filters → primary, no backups.
        let lone = candidate("lone", UNCAPPED_RX, 100.0, Some(0.95), Some(50));
        let mut stale_one = candidate("stale", UNCAPPED_RX, 100.0, Some(0.95), Some(40));
        // Stale at FRESH_WALL_CLOCK: measured at any t such that
        // FRESH_WALL_CLOCK - t >= 30_000. Set t to push past the gate.
        stale_one.signed_capacity.capacity.measured_at_unix_ms =
            FRESH_WALL_CLOCK.saturating_sub(31_000);
        // FRESH_WALL_CLOCK = 5_000; saturating to 0 means age = 5_000 < 30_000 → NOT stale.
        // Drive staleness explicitly: measure way before zero is impossible — use 0 + lift wall clock.
        // Simpler: tag the stale candidate as unreliable instead so the reachability filter
        // rejects it deterministically at FRESH_WALL_CLOCK.
        let mut filtered_out = stale_one;
        filtered_out.reachability_ratio = Some(0.2); // below MIN_REACHABILITY_RATIO
        let unreliable = candidate("unreliable", UNCAPPED_RX, 100.0, Some(0.2), Some(40));
        let candidates = vec![lone, filtered_out, unreliable];
        let plan = AlmJoinPlanner::plan(
            &candidates,
            2.5,
            ReceiverLayerPolicy::UNCAPPED,
            FRESH_WALL_CLOCK,
        )
        .expect("lone candidate must be feasible");
        assert_eq!(plan.primary_parent, "lone");
        assert!(plan.backup_parents.is_empty());
    }

    // ──────────────────────────────────────────────────────────────
    // RTT sort tiebreaks.
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn plan_unknown_rtt_sorts_as_worst() {
        let candidates = vec![
            candidate("no-rtt", UNCAPPED_RX, 100.0, Some(0.95), None),
            candidate("slow-rtt", UNCAPPED_RX, 100.0, Some(0.95), Some(1000)),
            candidate("fast-rtt", UNCAPPED_RX, 100.0, Some(0.95), Some(20)),
        ];
        let plan = AlmJoinPlanner::plan(
            &candidates,
            2.5,
            ReceiverLayerPolicy::UNCAPPED,
            FRESH_WALL_CLOCK,
        )
        .expect("feasible plan");
        assert_eq!(plan.primary_parent, "fast-rtt");
        assert_eq!(plan.backup_parents, vec!["slow-rtt", "no-rtt"]);
    }

    // ──────────────────────────────────────────────────────────────
    // MDC — plan_for_substream. CIRISEdge#128.
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn plan_for_substream_filters_candidates_by_substream_commitment() {
        // Two candidates: one commits to path [0], one commits to [1].
        let candidates = vec![
            candidate_with_subs(
                "first-half",
                UNCAPPED_RX,
                100.0,
                Some(0.95),
                Some(20),
                vec![substream_commitment(vec![0], 10.0, 4)],
            ),
            candidate_with_subs(
                "second-half",
                UNCAPPED_RX,
                100.0,
                Some(0.95),
                Some(10),
                vec![substream_commitment(vec![1], 10.0, 4)],
            ),
        ];
        // Plan for path [0] — second-half has no commitment for [0]
        // (commitments non-empty + no match → refuse), so only
        // first-half is feasible. RTT 20 → primary.
        let plan = AlmJoinPlanner::plan_for_substream(
            &candidates,
            &[0],
            2.5,
            ReceiverLayerPolicy::UNCAPPED,
            FRESH_WALL_CLOCK,
        )
        .expect("first-half must be feasible for [0]");
        assert_eq!(plan.primary_parent, "first-half");
        assert!(plan.backup_parents.is_empty());

        // Plan for path [1] — symmetric.
        let plan = AlmJoinPlanner::plan_for_substream(
            &candidates,
            &[1],
            2.5,
            ReceiverLayerPolicy::UNCAPPED,
            FRESH_WALL_CLOCK,
        )
        .expect("second-half must be feasible for [1]");
        assert_eq!(plan.primary_parent, "second-half");
    }

    #[test]
    fn plan_for_substream_with_opaque_candidates_admits_any_substream() {
        // Two opaque-mode candidates (empty commitments). They admit
        // any sub-stream up to the overall budget.
        let candidates = vec![
            candidate("opaque-a", UNCAPPED_RX, 100.0, Some(0.95), Some(50)),
            candidate("opaque-b", UNCAPPED_RX, 100.0, Some(0.95), Some(100)),
        ];
        let plan = AlmJoinPlanner::plan_for_substream(
            &candidates,
            &[0, 1, 0], // arbitrary deep MDC path
            2.5,
            ReceiverLayerPolicy::UNCAPPED,
            FRESH_WALL_CLOCK,
        )
        .expect("opaque candidates admit any path");
        assert_eq!(plan.primary_parent, "opaque-a");
        assert_eq!(plan.backup_parents, vec!["opaque-b"]);
    }

    #[test]
    fn plan_for_substream_refuses_when_no_candidate_serves_substream() {
        // Both candidates commit to path [0]; we ask for [1].
        let candidates = vec![
            candidate_with_subs(
                "a",
                UNCAPPED_RX,
                100.0,
                Some(0.95),
                Some(20),
                vec![substream_commitment(vec![0], 10.0, 4)],
            ),
            candidate_with_subs(
                "b",
                UNCAPPED_RX,
                100.0,
                Some(0.95),
                Some(40),
                vec![substream_commitment(vec![0], 10.0, 4)],
            ),
        ];
        let r = AlmJoinPlanner::plan_for_substream(
            &candidates,
            &[1],
            2.5,
            ReceiverLayerPolicy::UNCAPPED,
            FRESH_WALL_CLOCK,
        );
        assert_eq!(r, Err(AlmJoinError::NoFeasibleParent));
    }
}
