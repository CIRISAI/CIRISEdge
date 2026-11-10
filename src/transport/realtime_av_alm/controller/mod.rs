//! The ALM controller — closed-loop, herd-resistant parent selection and
//! admission for live A/V (stage 1: the pure core, proven in the sim).
//!
//! ## Why this exists
//!
//! The dormant [`super::join::AlmJoinPlanner`] is stateless and sorts by RTT
//! with `has_room_for(B, 0)`: every joiner picks the same parent (sim M9:
//! 500 of 500). That planner is **superseded** by this controller; it stays in
//! place until the controller is wired (stage 2) and is retired then.
//!
//! Production calls today (`Edge::join_call` → `Call::join`) are a full mesh
//! plus a flood by any `CallOptions::relay` node, with no subscribe, admission
//! or capacity check. This module is the replacement's decision core. It does
//! no I/O and is not yet called by `av_call.rs`.
//!
//! ## Discipline
//!
//! Every type here is a pure, synchronous state machine. Time is an injected
//! `now_ms`, randomness an injected [`JitterSource`], and every map is a
//! `BTreeMap`, so a seed reproduces a run bit-for-bit and the closed-loop sim
//! (`closed_loop_sim`) drives exactly these types.
//!
//! | Part | Module | Role |
//! |------|--------|------|
//! | C1 | [`path_meter`] | per-path meter (rate, loss, burst, latency, jitter, queue delay, stability) + the forwarder's egress meter |
//! | C2 | [`admission`] | `usable = min(advertised, measured) − committed − reserve`, ≤ 65 % of measured, one trial slot when unmeasured |
//! | C4 | [`selector`] | score, 20 % hysteresis, 10 s dwell, jittered backoff, make-before-break, warm (audio-only) standby |
//! | C6 | [`peer_state`] | available → degraded → suspected → down → recovering; suspicion is never a trust verdict |
//! | C7 | [`decision_log`] | deterministic, SHA-256-chained decision log + counters |
//!
//! C3 (stage 2) puts [`ControlMsg`] on the wire ([`wire`]): one `CALM`
//! frame per message on the existing A/V link, capability-gated per peer.
//! C5 (stale frames) lives in the call layer (`av_call.rs`) and leviculum's
//! timed Channel frames.
//!
//! ## Tiers
//!
//! Candidates carry a [`Tier`] (`FSD/CIRIS_MESH.md` R2): roster members
//! first (the publisher and member relays), the canonical last and never
//! scored against them; the canonical is audio-only (§6.4).
//!
//! ## Multi-hop
//!
//! A forwarder's parent may itself be a forwarder (depth > 1). Loops are kept
//! out three ways, cheapest first:
//!
//! 1. **Ancestry in every offer.** An [`Offer`] carries the forwarder's
//!    ancestry (root first). A selector never picks a candidate whose
//!    ancestry contains itself, and an admission refuses a subscriber that is
//!    in its own ancestry ([`RefuseReason::Loop`]).
//! 2. **Depth never rises voluntarily under children.** A selector that has
//!    admitted children may make a *voluntary* switch only to a candidate no
//!    deeper than its current parent. Two forwarders cannot then each move
//!    under the other on a consistent snapshot (each would need the other's
//!    depth strictly below its own).
//! 3. **Backstop.** A primary whose offer's ancestry contains the selector
//!    is a loop that slipped through stale offers: the primary is marked
//!    down and the selector fails over (BGP AS-path style).
//!
//! ## Membership
//!
//! Every tree node that fans out MUST be a room member (CC 5.4.6 forwarder
//! paragraph, E1 item 1, 6.1.6). Membership is an eligibility gate, like
//! trust and before any scoring, on both sides and fail-closed: a selector
//! never picks a candidate outside its roster ([`ParentSelector::set_members`]),
//! and an admission refuses ([`RefuseReason::NotMember`]) when either the
//! requester or the forwarder itself is outside its roster
//! ([`Admission::set_members`]). An empty roster admits and selects nobody.
//! A non-member may still carry one member-to-member link 1:1 at the
//! transport layer; that is below this controller and never a tree edge.
//!
//! Admission accounts for the upstream path: a relay with no healthy,
//! delivering upstream refuses ([`RefuseReason::UpstreamUnhealthy`]), a child
//! past `max_depth` is refused ([`RefuseReason::DepthLimit`]), and the offer
//! advertises the upstream latency so a subscriber scores end to end.

pub mod admission;
pub mod decision_log;
pub mod path_meter;
pub mod peer_state;
pub mod selector;
pub mod wire;

pub use admission::{Admission, ClassPolicy, Commitment, ForwarderKind};
pub use decision_log::{DecisionKind, DecisionLog};
pub use path_meter::{ChunkPos, EgressMeter, EgressWindow, PathMeter, PathSnapshot};
pub use peer_state::{PeerHealth, PeerState};
pub use selector::{ParentSelector, PathChunk, SelectorAction, UpstreamView};

use crate::transport::realtime_av::StreamId;

// ─── Peer identity seam ──────────────────────────────────────────────

/// A peer identity the controller can key maps by and hash into the decision
/// log. Production uses [`super::PeerKeyId`] (`String`); the sim uses `u32`
/// so a 1000-node run stays cheap.
pub trait PeerRef: Clone + Ord + Eq + std::hash::Hash + std::fmt::Debug {
    /// Append a canonical, unambiguous byte encoding (length-prefixed where
    /// the type is variable-length) for the decision-log hash.
    fn encode(&self, out: &mut Vec<u8>);
}

impl PeerRef for String {
    fn encode(&self, out: &mut Vec<u8>) {
        let len = u32::try_from(self.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(self.as_bytes());
    }
}

impl PeerRef for u32 {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }
}

// ─── Randomness seam ─────────────────────────────────────────────────

/// Injected randomness for jitter. Production seeds a [`SplitMix64`] from the
/// OS; the sim seeds it from the scenario seed.
pub trait JitterSource {
    /// The next 64 random bits.
    fn next_u64(&mut self) -> u64;

    /// A uniform draw in `[0, 1)`.
    #[allow(clippy::cast_precision_loss)]
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// A uniform draw in `[lo, hi)` (returns `lo` when `hi <= lo`).
    fn range_u64(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + self.next_u64() % (hi - lo)
    }
}

/// SplitMix64 — byte-identical to the replication DST's and `sim.rs`'s PRNG.
#[derive(Debug, Clone)]
pub struct SplitMix64(pub u64);

impl JitterSource for SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

// ─── Configuration (one stream class = one config) ───────────────────

/// Score weights for [`selector::ParentSelector`]. Trust is NOT a weight: it
/// gates eligibility only.
#[derive(Debug, Clone, Copy)]
pub struct ScoreWeights {
    /// Delivery (1 − loss, burst-penalised).
    pub delivery: f64,
    /// Admission headroom the candidate advertises.
    pub capacity: f64,
    /// End-to-end latency against the budget.
    pub latency: f64,
    /// Delivery stability over recent windows.
    pub stability: f64,
}

/// Every controller constant, so a stream class is a config and not a fork.
// Independent knobs (admission on/off, jitter, idle-aware silence, direct
// first), each a mutant or a deployment switch: not a mode enum in disguise.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct ControllerConfig {
    /// Full-quality stream rate a primary subscription costs (bits/s).
    pub stream_bps: u64,
    /// Audio-only rate a warm standby costs (bits/s).
    pub standby_bps: u64,
    /// Meter window length.
    pub meter_window_ms: u64,
    /// EWMA weight of the newest window.
    pub ewma_alpha: f64,
    /// Fraction of measured capacity that may be committed.
    pub commit_fraction: f64,
    /// Bits/s kept free of commitments.
    pub reserve_bps: u64,
    /// Fraction of the limit kept for forward-capable requesters while a
    /// child of this node could itself forward (`depth + 1 < max_depth`).
    pub forwarder_reserve_fraction: f64,
    /// Queue delay at or above which an egress window counts as congested.
    pub congestion_queue_ms: u64,
    /// Clean windows (no congestion) before the probe allowance grows.
    pub probe_clean_windows: u32,
    /// Advertised/measured ratio above which a forwarder is flagged as
    /// over-claiming (a signal only; admission already uses `min`).
    pub over_claim_ratio: f64,
    /// Admission on/off (off only in the T1 mutation).
    pub admission_enabled: bool,
    /// Voluntary-switch margin: switch only if `S_new > S_cur · (1 + h)`.
    pub hysteresis: f64,
    /// Windows the margin must hold before a voluntary switch.
    pub hysteresis_hold_windows: u32,
    /// Minimum time between voluntary switches.
    pub min_dwell_ms: u64,
    /// Minimum time between failure-driven switches.
    pub failover_min_interval_ms: u64,
    /// Randomised join delay and backoff jitter on/off.
    pub jitter: bool,
    /// Upper bound of the initial join delay.
    pub join_jitter_ms: u64,
    /// Backoff base after a refusal / failure.
    pub backoff_base_ms: u64,
    /// Backoff cap.
    pub backoff_max_ms: u64,
    /// Make-before-break: full chunks the new primary must deliver.
    pub mbb_confirm_chunks: u32,
    /// Make-before-break: least time since the new primary's first full chunk.
    pub mbb_confirm_ms: u64,
    /// Silence before a subscribed parent is suspected.
    pub suspect_silence_ms: u64,
    /// Silence before a subscribed parent is down.
    pub down_silence_ms: u64,
    /// Clean time a recovering peer needs to be available again.
    pub recover_clean_ms: u64,
    /// How long a Down/Suspected peer stays so before an offer (liveness,
    /// not delivery) may start its recovery.
    pub down_hold_ms: u64,
    /// Smoothed loss at or above which a path is degraded.
    pub degraded_loss: f64,
    /// End-to-end latency budget (ms).
    pub latency_budget_ms: u64,
    /// Deepest a subscriber may sit (publisher = 0).
    pub max_depth: u8,
    /// A subscribed parent's silence counts only while the stream is active
    /// on another path (a live call's stream is idle until its host
    /// publishes; an idle stream is not a dead parent). The link closing is
    /// then the hard down signal. Off in the sim, whose streams never idle.
    pub idle_aware_silence: bool,
    /// `FSD/CIRIS_MESH.md` R1: a viable direct path (the publisher itself,
    /// depth 0) is taken before any relay, and a relay gives way to it. Off
    /// in the stage-1 sim, whose worlds exercise publisher shedding by score;
    /// on for live calls (a publisher with no room still sheds to relays:
    /// it stops being viable).
    pub direct_first: bool,
    /// Score weights.
    pub weights: ScoreWeights,
}

impl ControllerConfig {
    /// The interactive-call class: 1 Mbit/s video, 64 kbit/s audio standby.
    #[must_use]
    pub fn interactive() -> Self {
        Self {
            stream_bps: 1_000_000,
            standby_bps: 64_000,
            meter_window_ms: 1_000,
            ewma_alpha: 0.3,
            commit_fraction: 0.65,
            reserve_bps: 0,
            forwarder_reserve_fraction: 0.0,
            congestion_queue_ms: 150,
            probe_clean_windows: 2,
            over_claim_ratio: 2.0,
            admission_enabled: true,
            hysteresis: 0.20,
            hysteresis_hold_windows: 3,
            min_dwell_ms: 10_000,
            failover_min_interval_ms: 2_000,
            jitter: true,
            join_jitter_ms: 1_000,
            backoff_base_ms: 500,
            backoff_max_ms: 8_000,
            mbb_confirm_chunks: 8,
            mbb_confirm_ms: 250,
            suspect_silence_ms: super::PARENT_SILENCE_HEAL_MS,
            down_silence_ms: 5_000,
            recover_clean_ms: 5_000,
            down_hold_ms: 15_000,
            degraded_loss: 0.05,
            latency_budget_ms: 400,
            max_depth: 3,
            idle_aware_silence: false,
            direct_first: false,
            weights: ScoreWeights {
                delivery: 0.45,
                capacity: 0.15,
                latency: 0.25,
                stability: 0.15,
            },
        }
    }

    /// The T1 mutation: hysteresis, dwell, jitter and admission all off. A
    /// herding test that passes with this config is not testing herding.
    #[must_use]
    pub fn herding_mutant(mut self) -> Self {
        self.hysteresis = 0.0;
        self.hysteresis_hold_windows = 1;
        self.min_dwell_ms = 0;
        self.failover_min_interval_ms = 0;
        self.jitter = false;
        self.join_jitter_ms = 0;
        self.backoff_base_ms = 0;
        self.backoff_max_ms = 0;
        self.admission_enabled = false;
        self
    }

    /// The transport-relay class (`FSD/CIRIS_MESH.md` §4.2): the same
    /// controller choosing a RELAYED TRANSPORT PATH (a relay reservation)
    /// instead of an A/V parent. Depth is 1 by rule (one relay, never two),
    /// the primary is the reservation's measured rate and the standby is a
    /// keepalive-only link (measured by real keepalive delivery).
    #[must_use]
    pub fn transport_relay() -> Self {
        Self {
            // The `server` shaping class' per-link rate (7000 B/s): the
            // default allowance an unreserved relayed link gets.
            stream_bps: 56_000,
            standby_bps: 1_000,
            max_depth: 1,
            ..Self::interactive()
        }
    }

    /// Cost of a subscription in `role`.
    #[must_use]
    pub fn role_bps(&self, role: Role) -> u64 {
        match role {
            Role::Primary => self.stream_bps,
            Role::Standby => self.standby_bps,
        }
    }

    /// `base · 2^k · U(0.5, 1.5)` (no jitter → `base · 2^k`), capped.
    pub fn backoff_ms(&self, base_ms: u64, k: u32, rng: &mut dyn JitterSource) -> u64 {
        let raw = base_ms.saturating_mul(1u64 << k.min(16));
        let capped = raw.min(self.backoff_max_ms.max(base_ms));
        if self.jitter && capped > 0 {
            let lo = capped / 2;
            rng.range_u64(lo, capped + lo + 1)
        } else {
            capped
        }
    }
}

// ─── Messages (the C3 frame's payloads, stage 2 puts them on the wire) ─

/// What a subscription asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// The full stream.
    Primary,
    /// The warm standby: audio only, measured by real delivery.
    Standby,
}

/// A forwarder's periodic advertisement to the subscribers that list it as a
/// candidate. Stage 2 sends it on the C3 control frame; it is NOT the signed
/// capacity ad (which is a slow-loop reputation input and stays separate).
#[derive(Debug, Clone, PartialEq)]
pub struct Offer<P> {
    /// The forwarder.
    pub from: P,
    /// Its depth (publisher = 0).
    pub depth: u8,
    /// Its ancestry, root first (empty for the publisher).
    pub ancestry: Vec<P>,
    /// Admission headroom for a new primary (bits/s); 0 = full.
    pub headroom_bps: u64,
    /// Headroom a FORWARD-CAPABLE primary could get, counting commitments it
    /// may preempt (non-forwarders) while this forwarder's children could
    /// still forward; equals `headroom_bps` otherwise. Without it a relay
    /// orphaned with a full root never asks the root, and a subtree whose
    /// relays only see each other stalemates.
    pub forwarder_headroom_bps: u64,
    /// Latency from the publisher to the forwarder (ms).
    pub upstream_latency_ms: u32,
    /// Whether the forwarder is itself receiving the stream (always true for
    /// the publisher). A non-forwarding candidate is ineligible.
    pub forwarding: bool,
}

/// A subscribe request (also an upgrade standby → primary, or a downgrade).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeRequest<P> {
    /// The requester.
    pub subscriber: P,
    /// The role asked for.
    pub role: Role,
    /// Whether the requester can itself forward (it may use the forwarder
    /// reserve).
    pub forward_capable: bool,
    /// v45 — the most of this stream the requester takes from this parent
    /// (CC 5.3.3.4: a relay forwards only the layers asked for, on the tree):
    /// `None` is everything. Carried only to a parent whose `CAPS` carry
    /// [`wire::CAP_LAYER_REQUEST`]; a re-SUBSCRIBE changes or withdraws it.
    pub layers: Option<crate::transport::realtime_av::ReceiverLayerPolicy>,
}

/// Why an admission refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefuseReason {
    /// No usable capacity.
    Capacity,
    /// The requester is in this forwarder's ancestry.
    Loop,
    /// The child would sit past `max_depth`.
    DepthLimit,
    /// This forwarder has no healthy, delivering upstream.
    UpstreamUnhealthy,
    /// The requester, or this forwarder itself, is not a room member. A tree
    /// node that fans out MUST be a member (CC 5.4.6 forwarder paragraph,
    /// E1 item 1, 6.1.6); a non-member may only be a transport-layer
    /// forwarder of ONE member-to-member link, never a tree node.
    NotMember,
    /// The flow's class is refused by this forwarder's class policy: a
    /// canonical never relays video (`FSD/CIRIS_MESH.md` §6.4 V1).
    ClassRefused,
    /// This node's service tier closed admission to new relay work
    /// (`FSD/CIRIS_MESH.md` §7.2 Admit-close).
    AdmitClosed,
}

impl RefuseReason {
    /// Every reason (for token tests).
    pub const ALL: [Self; 7] = [
        Self::Capacity,
        Self::Loop,
        Self::DepthLimit,
        Self::UpstreamUnhealthy,
        Self::NotMember,
        Self::ClassRefused,
        Self::AdmitClosed,
    ];

    /// The stable refusal token (counted by label, surfaced to the host).
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Capacity => "relay_capacity",
            Self::Loop => "relay_loop",
            Self::DepthLimit => "relay_depth_limit",
            Self::UpstreamUnhealthy => "relay_upstream_unhealthy",
            Self::NotMember => "relay_nonmember_fanout",
            Self::ClassRefused => "relay_class_refused:video",
            Self::AdmitClosed => "load_refuse:admit_closed",
        }
    }

    /// The wire code (C3 `REFUSE`).
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// From the wire code.
    #[must_use]
    pub const fn from_code(c: u8) -> Option<Self> {
        match c {
            0 => Some(Self::Capacity),
            1 => Some(Self::Loop),
            2 => Some(Self::DepthLimit),
            3 => Some(Self::UpstreamUnhealthy),
            4 => Some(Self::NotMember),
            5 => Some(Self::ClassRefused),
            6 => Some(Self::AdmitClosed),
            _ => None,
        }
    }
}

/// Which selection tier a candidate parent belongs to (`FSD/CIRIS_MESH.md`
/// §1, R2). Tiers are never compared by score: a lower tier with any viable
/// candidate wins outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Tier {
    /// A room member (the publisher itself, or a member relay): an ALM media
    /// parent. Roster members come before any canonical.
    #[default]
    Member,
    /// The canonical: a non-member TRANSPORT forwarder of one
    /// member-to-member link, the last resort. It never carries video
    /// (§6.4 V1): it is eligible only for the audio (standby) role, and a
    /// node on it keeps probing the member tier (R3).
    Canonical,
}

/// Admission's answer.
#[derive(Debug, Clone, PartialEq)]
pub enum AdmitDecision {
    /// Admitted in `role`.
    Admit {
        /// The role committed.
        role: Role,
    },
    /// Refused; do not ask this forwarder again before `retry_after_ms`.
    Refuse {
        /// Why.
        reason: RefuseReason,
        /// Jittered retry-after.
        retry_after_ms: u64,
    },
}

/// Why a forwarder shed a subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ShedReason {
    /// Measured capacity fell below commitments (most recent admittee first).
    OverCommitted,
    /// The forwarder lost its upstream.
    UpstreamLost,
    /// Displaced by a forward-capable subscriber (forwarder preemption).
    Preempted,
    /// Shed by this node's service tier (`FSD/CIRIS_MESH.md` §7.2 A-shed).
    LoadShed,
}

impl ShedReason {
    /// The stable token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::OverCommitted => "relay_shed:over_committed",
            Self::UpstreamLost => "relay_shed:upstream_lost",
            Self::Preempted => "relay_shed:preempted",
            Self::LoadShed => "load_shed:audio",
        }
    }

    /// The wire code (C3 `SHED`).
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// From the wire code.
    #[must_use]
    pub const fn from_code(c: u8) -> Option<Self> {
        match c {
            0 => Some(Self::OverCommitted),
            1 => Some(Self::UpstreamLost),
            2 => Some(Self::Preempted),
            3 => Some(Self::LoadShed),
            _ => None,
        }
    }
}

/// Whether a chunk of `codec_id` at `layer` passes a child's layer cap
/// (v45, carried on its SUBSCRIBE): codec-opaque chunks pass every cap, and
/// a layered chunk passes when every axis is within it.
#[must_use]
pub fn layer_cap_admits(
    cap: crate::transport::realtime_av::ReceiverLayerPolicy,
    codec_id: u8,
    layer: crate::transport::realtime_av::ChunkLayer,
) -> bool {
    codec_id == crate::transport::realtime_av::CODEC_OPAQUE || cap.admits(layer)
}

/// The control vocabulary C3 will frame. One frame = one stream + one
/// message, sent on the subscriber's existing link to the forwarder.
#[derive(Debug, Clone, PartialEq)]
pub enum ControlMsg<P> {
    /// Subscriber → forwarder.
    Subscribe(SubscribeRequest<P>),
    /// Subscriber → forwarder.
    Unsubscribe {
        /// The subscriber leaving.
        subscriber: P,
    },
    /// Forwarder → subscriber.
    Decision(AdmitDecision),
    /// Forwarder → subscriber.
    Shed {
        /// Why.
        reason: ShedReason,
    },
    /// Forwarder → candidates.
    Offer(Offer<P>),
}

/// A [`ControlMsg`] bound to its stream — the unit stage 2's C3 frame carries.
#[derive(Debug, Clone, PartialEq)]
pub struct ControlFrame<P> {
    /// The stream.
    pub stream: StreamId,
    /// The message.
    pub msg: ControlMsg<P>,
}
