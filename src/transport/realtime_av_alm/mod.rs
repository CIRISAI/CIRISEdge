//! Application-Layer Multicast (ALM) — mesh-tree video for CIRISEdge
//! v3.8.0 (PR #131 follow-up + CIRISEdge#128 MDC).
//!
//! ## Why ALM
//!
//! The v3.8.0 substrate's [`super::realtime_av_relay::RelayNode`] IS the
//! per-peer relay primitive. The architectural decision: every peer is
//! potentially a relay; a publisher with uplink budget `X` (in copies of
//! the per-subscriber stream bitrate) sends to `X` peers directly; those
//! `X` peers advertise themselves and the remaining `N - X - 1`
//! participants proxy through them. Tree depth = `ceil(log_X(N))` —
//! Narada / Overcast / ZIGZAG family.
//!
//! L5-B's bench validates the approach: at 720p30 a peer's CPU can
//! sustain ~7 GiB/s aggregate AEAD throughput. CPU is NOT the bottleneck
//! — uplink IS. So per-peer branching factor `X = uplink_Mbps /
//! stream_bitrate_Mbps`.
//!
//! ## Module layout
//!
//! - **ALM-A** ([`capacity`]) — the signed [`capacity::RelayCapacity`]
//!   advertisement primitive — the data type peers publish to declare
//!   relay willingness + uplink budget + (new in v3.8.0) MDC
//!   sub-stream commitments. Signed for HNDL discipline, ready to be
//!   written to the federation directory.
//! - **ALM-A(cap)** ([`capacity_estimator`]) — the passive
//!   upload-capacity estimator (`docs/AV_ALM_DESIGN.md` §5.1 + §6;
//!   leviculum#35) that PRODUCES the `uplink_mbps` / servable-layers a
//!   relay is allowed to sign. Reads per-link delivery telemetry, filters
//!   it into a demonstrated-sustainable floor (over-claim impossible by
//!   construction), quantizes to whole servable layers, and coalesces a
//!   "capacity changed" signal so re-attestation fires only on a bucket
//!   crossing. Pure core; the leviculum read is one thin gated adapter.
//! - **ALM-A(delivered)** ([`delivered`]) — CIRISEdge#439: the delivered
//!   counterpart of the signed claim, keyed EXACTLY to the claim key
//!   `(advertiser_key_id, stream_id, epoch)`, plus the edge-named CEG
//!   dimension ([`delivered::CAPACITY_RELAY_DELIVERY_DIMENSION`]) a
//!   delivered-vs-claimed score is about, and the consent-gated
//!   (B5/CC#46, fail-closed) scores-plane emission shape LensCore reads.
//! - **ALM-B** ([`join`]) — parent-finding: given a stream and the set
//!   of fresh [`capacity::SignedRelayCapacity`] advertisements, select
//!   a parent for THIS peer that respects fan-out budgets, locality,
//!   and the tree-depth cap. Also offers [`join::AlmJoinPlanner::plan_for_substream`]
//!   for MDC parent selection.
//! - **ALM-C** ([`heal`]) — multi-parent heal + dedup: subscribe to
//!   one primary parent + N backups for the same (stream,
//!   sub_stream_path), dedup chunks by `(epoch, chunk_seq)`, and
//!   re-parent on parent silence.
//!
//! ## MDC ("holographic") extension — CIRISEdge#128
//!
//! v3.8.0 adds Multiple Description Coding semantics. The user
//! directive: "split each half equally, and make the advertisements
//! portion aware so people can re-assemble high bandwidth from
//! downstream." Each MDC sub-stream is independently decodable; any
//! subset reassembles at proportional fidelity. The substrate is
//! depth-agnostic (variable-depth, runtime-configurable); the codec
//! layer picks the split.
//!
//! Each ALM tier participates:
//!
//! - ALM-A carries [`capacity::SubStreamCommitment`]s on
//!   [`capacity::RelayCapacity`] — peers advertise which sub-streams
//!   they commit to forwarding.
//! - ALM-B exposes [`join::AlmJoinPlanner::plan_for_substream`] —
//!   plans a parent for a specific sub-stream path.
//! - ALM-C's [`heal::MultiParentSubscription`] carries a
//!   `sub_stream_path` field — one instance per sub-stream subscribed
//!   to. A receiver running 4 MDC sub-streams (full holographic 8K)
//!   spins up 4 instances; bandwidth overhead is K × the per-instance
//!   multi-parent cost.

pub mod capacity;
pub mod capacity_estimator;
pub mod delivered;
pub mod heal;
pub mod join;
pub mod transit_gate;

// CIRISEdge ALM A/V performance-testing suite (Track A / criteria foundation).
// Deterministic, clock-stepped, N-node A/V mesh simulator + 10-metric SOTA
// grader that drives the REAL ALM primitives (ALM-A/B/C + the holonomic
// deterministic topology) read-only. Test-only, mirroring the replication DST's
// `#[cfg(test)] mod sim;` — see the module docs for the fault model + metrics.
#[cfg(test)]
mod sim;

pub use capacity::{
    AlmCapacityError, PeerKeyId, PeerSigningPubkeys, RelayCapacity, SignedRelayCapacity,
    SubStreamCommitment, SubStreamPath, MEASUREMENT_WINDOW_SECS, STALE_AFTER_SECS,
};
pub use capacity_estimator::{
    aggregate, bucketize, diff_link, CapacityChange, CapacityEstimator, CapacitySample,
    DemonstratedCapacity, EstimatorArm, EstimatorConfig, LinkCounters, LinkInterval,
    CEILING_DECAY_SPAN_SECS, CEILING_STALE_SECS, FLOOR_PERCENTILE, FLOOR_WINDOW_SECS,
    SAFETY_MARGIN, UPGRADE_HOLD_WINDOWS,
};
pub use delivered::{
    delivery_envelope, emit_delivered_observation, observe_delivery, DeliveredAccumulator,
    DeliveredObservation, DeliveryEmitError, DeliveryEmitOutcome, DeliveryWithholdReason,
    ObservationKey, CAPACITY_RELAY_DELIVERY_DIMENSION,
};
pub use heal::{
    DedupRing, HealAction, HealApplyOutcome, MultiParentSubscription, ObserveOutcome,
    DEDUP_RING_CAPACITY, HEARTBEAT_INTERVAL_MS, PARENT_SILENCE_HEAL_MS, REPARENT_BACKOFF_MS,
};
pub use join::{
    AlmJoinError, AlmJoinPlanner, JoinPlan, ParentCandidate, MAX_BACKUPS, MIN_REACHABILITY_RATIO,
};
pub use transit_gate::{TransitGate, NEGATIVE_VERDICT_TTL};
