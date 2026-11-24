//! ALM stage 2 — the call's controller state: the ALM mesh on a live call.
//!
//! One [`AlmState`] per call (per node), behind a std mutex in the call's
//! shared state. It is synchronous and does no I/O: every method returns the
//! C3 frames to send ([`Outgoing`]) and the async call layer sends them. The
//! clock is the call's own monotonic `now_ms`, randomness a seeded
//! [`SplitMix64`], so a field log replays.
//!
//! What it runs:
//!
//! - **This node's stream, as parent 0**: an [`Admission`] (C2) answering the
//!   other members' C3 `SUBSCRIBE`s. A publisher starts at
//!   [`PUBLISHER_INITIAL_PROBE`] direct children into an unmeasured uplink
//!   and widens one step a clean window while members wait (G8 slow
//!   start: the rest hear it through the first child meanwhile); measured
//!   congestion, or an uplink-stall verdict, sheds the most recent
//!   subscribers to member relays (T7) and holds the probe
//!   [`STALL_PROBE_HOLD_MS`].
//! - **Every other member's stream, as subscriber**: a [`ParentSelector`]
//!   (C4/C6) choosing among the publisher itself and the members that
//!   forward it, from their C3 `OFFER`s. Room membership gates candidacy
//!   (CC 5.4.6 / 6.1.6: tree nodes are members). When the publisher cannot
//!   reach this node directly (hard NAT, a failed punch, no direct path),
//!   it simply never offers here, and the roster members that hear it ARE
//!   the candidates: roster relays before any canonical, organically.
//! - **Streams this node forwards** (when it offers relay): an [`Admission`]
//!   per stream, with its upstream view refreshed after every selector
//!   decision, so a relay that just lost its parent refuses before a peer in
//!   the same failover wave lands on it.
//!
//! The selector's warm standby is the base/audio layer only; a forwarder
//! sends a standby child only base-layer and codec-opaque (audio) chunks.
//! A peer that does not speak C3 (no `CAPS`) is served exactly as before:
//! the full stream, and the legacy first-hand relay when this node relays.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant};

use crate::load_ladder::ServiceTier;
use crate::transport::realtime_av::StreamId;
use crate::transport::realtime_av_alm::controller::wire::{
    self, encode, encode_caps, CAPS_THIS_BUILD, CAP_BINDING_V2, CAP_C3_V1, CAP_LAYER_REQUEST,
    CAP_LINK_DATAGRAMS, CAP_RELAY, CAP_TIMED_FRAMES,
};
use crate::transport::realtime_av_alm::controller::{
    Admission, AdmitDecision, ChunkPos, ControlFrame, ControlMsg, ControllerConfig, DecisionKind,
    DecisionLog, EgressMeter, EgressWindow, ParentSelector, PathChunk, RefuseReason, Role,
    SelectorAction, ShedReason, SplitMix64, SubscribeRequest,
};

/// How often a forwarder offers each stream it can serve.
pub(super) const OFFER_EVERY_MS: u64 = 1_000;
/// The publisher's starting probe allowance, in streams (G8 slow start): an
/// unmeasured uplink takes two copies first (a three-person room is the full
/// mesh it was), and the probe widens while members wait for it. Full fan-out from the first
/// chunk overloaded a capped uplink at once (the 45.1.9 matrix: 250 kbit
/// against three copies of ~190).
pub(super) const PUBLISHER_INITIAL_PROBE: u64 = 2;
/// G8 — after an uplink-stall verdict, how long nothing widens this node's
/// rooms (`Admission::hold_probe`).
pub(super) const STALL_PROBE_HOLD_MS: u64 = 10_000;
/// Row B1b — under a latched stall verdict, how often a member that holds no
/// commitment here is sent this node's offers (the leg's liveness minimum).
pub(super) const STALL_NONCHILD_OFFER_MS: u64 = 2_000;
/// Row B2 — the longest a non-child's offer interval stretches under the
/// budget (the model accepts ~3.5 s of dead detection on such a leg).
pub(super) const STALL_NONCHILD_OFFER_MAX_MS: u64 = 3_500;
/// Row B2 — what one sealed offer costs on the wire beyond its plaintext
/// (E1 link seal, the Channel and RNS headers), for the budget's arithmetic.
const OFFER_WIRE_OVERHEAD: usize = 120;

/// Row B2, the transition: latched verdict → this node's periodic control
/// (its offers) stays within ¼ of what the uplink carries beyond one media
/// copy (`ceiling − one`, the admission's measured ceiling). Children and
/// parents keep 1 s (F14a); the non-children's interval stretches from
/// [`STALL_NONCHILD_OFFER_MS`] up to [`STALL_NONCHILD_OFFER_MAX_MS`] to fit
/// what is left. Unmeasured: the 2 s minimum.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub(super) fn stall_offer_interval_ms(
    ceiling_bps: Option<f64>,
    one_copy_bps: u64,
    offer_len: usize,
    keep: usize,
    rest: usize,
) -> u64 {
    let Some(c) = ceiling_bps else {
        return STALL_NONCHILD_OFFER_MS;
    };
    let budget = ((c - one_copy_bps as f64) / 4.0).max(0.0);
    let bits = ((offer_len + OFFER_WIRE_OVERHEAD) * 8) as f64;
    let left = budget - keep as f64 * bits;
    if rest == 0 {
        return STALL_NONCHILD_OFFER_MS;
    }
    if left <= 0.0 {
        return STALL_NONCHILD_OFFER_MAX_MS;
    }
    let ms = (rest as f64 * bits * 1000.0 / left).ceil() as u64;
    ms.clamp(STALL_NONCHILD_OFFER_MS, STALL_NONCHILD_OFFER_MAX_MS)
}
/// G8 slow start — how long a member refused for room still gets the
/// publisher's chunks: two offer periods, so a child's OFFER has reached it
/// and it has moved before the bridge ends.
pub(super) const SLOW_START_BRIDGE_MS: u64 = 2 * OFFER_EVERY_MS;
/// How long a C3 peer that has not yet chosen a parent for this node's
/// stream keeps receiving it (the join gap: join jitter + one offer + one
/// round trip). Past it, a peer that chose nothing gets nothing.
pub(super) const PROVISIONAL_MS: u64 = 10_000;
/// Time to live for codec-opaque (audio) media on a timed leg.
pub(super) const AUDIO_TTL: Duration = Duration::from_millis(300);
/// Time to live for layered video on a timed leg.
pub(super) const VIDEO_TTL: Duration = Duration::from_millis(400);
/// The floor a measured stream rate is never priced below (bits/s).
const MIN_STREAM_BPS: f64 = 16_000.0;
/// The floor a measured audio rate is never priced below (bits/s).
const MIN_AUDIO_BPS: f64 = 8_000.0;
/// Chunks remembered per stream for the forwarding dedupe.
const FORWARD_DEDUPE: usize = 512;

/// The forwarding dedupe of one stream: the `(epoch, seq)` set and its order.
type SeenRing = (BTreeSet<(u64, u64)>, VecDeque<(u64, u64)>);

/// One C3 frame to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Outgoing {
    /// The member it goes to.
    pub to: String,
    /// The encoded frame.
    pub frame: Vec<u8>,
}

/// A stream's measured rate: bits/s over 1 s windows, EWMA.
#[derive(Debug, Clone, Default)]
struct Rate {
    win_full: u64,
    win_audio: u64,
    since_ms: u64,
    full_bps: f64,
    audio_bps: f64,
    windows: u32,
}

impl Rate {
    fn add(&mut self, bytes: u64, audio: bool) {
        self.win_full += bytes;
        if audio {
            self.win_audio += bytes;
        }
    }

    #[allow(clippy::cast_precision_loss)]
    fn roll(&mut self, now_ms: u64) -> bool {
        let dt = now_ms.saturating_sub(self.since_ms);
        if dt < 1_000 {
            return false;
        }
        let secs = dt as f64 / 1_000.0;
        let full = self.win_full as f64 * 8.0 / secs;
        let audio = self.win_audio as f64 * 8.0 / secs;
        let a = if self.windows == 0 { 1.0 } else { 0.3 };
        self.full_bps = a * full + (1.0 - a) * self.full_bps;
        self.audio_bps = a * audio + (1.0 - a) * self.audio_bps;
        self.windows += 1;
        self.win_full = 0;
        self.win_audio = 0;
        self.since_ms = now_ms;
        true
    }

    /// `(stream_bps, standby_bps)` to price commitments at.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn costs(&self) -> (u64, u64) {
        let full = self.full_bps.max(MIN_STREAM_BPS);
        let audio = self.audio_bps.max(MIN_AUDIO_BPS).min(full);
        (full as u64, audio as u64)
    }
}

/// One stream's parents, as this node chose them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlmParents {
    /// The stream.
    pub stream: StreamId,
    /// Its publisher, once known.
    pub publisher: Option<String>,
    /// The primary parent (full stream).
    pub primary: Option<String>,
    /// The warm standby (base/audio).
    pub standby: Option<String>,
    /// Primary changes after the first join.
    pub parent_changes: u64,
}

/// Calls cut — what a relay forwarded to one child node
/// ([`super::Call::relayed_to`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayedTo {
    /// The child node.
    pub child: String,
    /// Bytes forwarded to it (each chunk's sealed size on the wire).
    pub bytes: u64,
    /// Chunks forwarded to it.
    pub chunks: u64,
    /// The streams forwarded to it.
    pub streams: Vec<StreamId>,
}

/// What the ALM counted on a call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AlmCounts {
    /// C3 frames sent / received / malformed.
    pub c3_sent: u64,
    /// C3 frames received and applied.
    pub c3_received: u64,
    /// Frames that read as C3 and did not decode.
    pub c3_malformed: u64,
    /// Subscribes this node admitted.
    pub admitted: u64,
    /// Subscribes this node refused, by token.
    pub refused: BTreeMap<&'static str, u64>,
    /// Subscribers this node shed.
    pub shed: u64,
    /// Chunks this node forwarded as an admitted media parent.
    pub forwarded: u64,
    /// Media frames dropped by age before they were opened (C5).
    pub stale_dropped: u64,
    /// Legs shed to the base layer under congestion (C5).
    pub legs_shed_to_base: u64,
    /// `OFFER`s claiming depth 0 from anyone but the stream's publisher, or
    /// before its binding arrived, or a serve seat's for a stream it does not
    /// publish, dropped.
    pub offers_refused: u64,
    /// Calls cut — bytes this node forwarded as a media parent (each chunk's
    /// sealed size), to every child.
    pub relayed_bytes: u64,
}

/// The call's ALM controller state (see the module docs).
#[allow(clippy::struct_excessive_bools)] // independent switches, each its own lever
pub(super) struct AlmState {
    me: String,
    cfg: ControllerConfig,
    t0: Instant,
    rng: SplitMix64,
    log: DecisionLog,
    own_stream: StreamId,
    own: Admission<String>,
    /// v45 — this node's other own streams (a screen share beside the
    /// camera, `Call::add_stream`): each its own parent-0 admission and
    /// measured rate, so a share's children and shedding are its own.
    shares: BTreeMap<StreamId, (Admission<String>, Rate)>,
    relay_capable: bool,
    relays: BTreeMap<StreamId, Admission<String>>,
    sels: BTreeMap<StreamId, ParentSelector<String>>,
    publisher_of: BTreeMap<StreamId, String>,
    /// The publisher each stream's verified binding names: the one signed
    /// source. `publisher_of` follows it, and a hello cannot override it.
    bound_publisher: BTreeMap<StreamId, String>,
    caps: BTreeMap<String, u32>,
    /// Test seam — bits this node leaves out of its own `CAPS` (an older
    /// build's, say). 0 in production.
    caps_withheld: u32,
    /// v45 — whether this node takes part in SUBSCRIBE layer caps
    /// (advertises `CAP_LAYER_REQUEST`, applies a child's cap, sends its
    /// own). The host's lever; off by default until CC's 5.3.3.2.4 correction.
    layer_requests: bool,
    /// C3 members not yet subscribed to one of this node's own streams,
    /// with since when: `(own stream, member)`.
    provisional: BTreeMap<(StreamId, String), u64>,
    told_publisher: BTreeSet<StreamId>,
    draining_parent: BTreeMap<StreamId, String>,
    last_primary: BTreeMap<StreamId, Option<String>>,
    egress: EgressMeter,
    leg_queue_ms: BTreeMap<String, f64>,
    members: Vec<String>,
    tier: ServiceTier,
    own_rate: Rate,
    rates: BTreeMap<StreamId, Rate>,
    forwarded_seen: BTreeMap<StreamId, SeenRing>,
    min_offset: BTreeMap<StreamId, (i64, u64)>,
    last_offer_ms: u64,
    pub(super) counts: AlmCounts,
    pub(super) labels: Vec<&'static str>,
    /// Failovers waiting on the new parent's first chunk: when the old primary
    /// was last heard, and why it failed.
    failing_over: BTreeMap<StreamId, (u64, crate::telemetry::FailoverCause)>,
    /// Finished failover gaps, for the call to book.
    pub(super) gaps: Vec<(crate::telemetry::FailoverCause, std::time::Duration)>,
    /// How many of each decision the `av_plane` ledger has heard of.
    booked: BTreeMap<DecisionKind, u64>,
    /// The newest room epoch seen on each stream.
    epochs: BTreeMap<StreamId, u64>,
    video_unavailable: BTreeSet<StreamId>,
    /// v45 — the layer cap each child's SUBSCRIBE asked this node, as its
    /// parent, for: `(stream, child)`. Absent: everything.
    layer_caps: BTreeMap<(StreamId, String), crate::transport::realtime_av::ReceiverLayerPolicy>,
    /// v45 — the cap this node asks its parents for, per stream: carried on
    /// every SUBSCRIBE it sends a parent that takes one.
    wanted_layers: BTreeMap<StreamId, crate::transport::realtime_av::ReceiverLayerPolicy>,
    pub(super) events: Vec<super::CallEvent>,
    /// Calls cut — this node is a serve seat (a canonical): it never relays
    /// call media, audio included, whatever the host asked
    /// ([`CANONICAL_AV_FALLBACK`] off).
    serve_seat: bool,
    /// Calls cut — the serve seats this node knows of: their OFFERs for a
    /// stream they do not publish are dropped (or, with the lever on, put on
    /// the canonical tier).
    seats: BTreeSet<String>,
    /// Calls cut — streams a serve seat offered and this node refused: the
    /// media-path event's `refused_by_policy` when no member offered.
    seat_offered: BTreeSet<StreamId>,
    /// Calls cut — the last `RelayStatus` emitted, and the one seen last tick
    /// (a value is emitted only after it holds for one tick).
    relay_status: Option<(bool, u16)>,
    relay_status_pending: Option<(bool, u16)>,
    /// Calls cut — primary-parent changes since the call last read them:
    /// `(stream, new primary)`, for the media-path event.
    pub(super) parent_moves: Vec<(StreamId, Option<String>)>,
    /// Calls cut — per child node: bytes, chunks and streams forwarded.
    relayed: BTreeMap<String, (u64, u64, BTreeSet<StreamId>)>,
    /// G8 — this node's uplink is stalled: its legs' Channels hold messages
    /// unproved far past the RTT floor ([`UPLINK_STALL_MS`] on at least
    /// [`UPLINK_STALL_LEGS`] legs). On a datagram uplink this is the only
    /// sender-side sign of a bottleneck past the process (a router, a
    /// bufferbloated cellular queue): the egress meter's refusals never
    /// come (`path_meter` "Limit: datagram legs").
    uplink_stall: bool,
    /// G8 — when the stall was last detected: the verdict holds
    /// [`UPLINK_STALL_LATCH_MS`] past it (the stalled legs' links can die,
    /// and their detection with them, before the queue has drained).
    uplink_stall_seen_ms: Option<u64>,
    /// G8 — frames made between ticks (the shed on a stall's rise), sent
    /// with the next tick's.
    pending_out: Vec<Outgoing>,
    /// Row B1b — when each peer was last sent this node's offers.
    offered_at: BTreeMap<String, u64>,
}

/// G8 — a leg whose oldest unproved Channel message has waited this long is
/// stalled: far above any propagation floor this mesh runs at, and under
/// leviculum's ~1.3 s retry budget (leviculum#113).
pub(super) const UPLINK_STALL_MS: u64 = 400;
/// G8 — how many stalled legs make it the UPLINK (not one slow peer). With
/// one leg (a two-person call) there is no verdict, and none is needed: a
/// publisher with one child has nothing to shed.
pub(super) const UPLINK_STALL_LEGS: usize = 2;
/// G8 — the earlier verdict: a leg's oldest unproved Channel message is
/// BACKLOGGED when it was already unproved at the previous watch tick (its
/// age is rising) and has waited this long past the leg's own RTT floor
/// (`min_rtt`, so a long but uncongested path is not a queue). The uplink is
/// stalled when EVERY leg with something unproved is backlogged and there
/// are at least [`UPLINK_STALL_LEGS`] of them: one slow peer is one leg, and
/// a leg that proves its messages in time vetoes the verdict.
pub(super) const UPLINK_BACKLOG_MS: u64 = 200;
/// G8 — how long a stall verdict holds after its last detection: about the
/// time a shed publisher's queue takes to drain the backlog its legs saw.
pub(super) const UPLINK_STALL_LATCH_MS: u64 = 2_000;

/// **The canonical audio fallback lever** (`FSD/CIRIS_MESH.md` §6.4; Eric
/// 2026-11-21: no traffic on the canonical, audio included, while the mesh
/// scales). Off: a serve seat never relays call media, and a receiver drops a
/// serve seat's `OFFER` for a stream the seat does not publish. On: the seat
/// may relay and receivers place it on the canonical tier (never video, an
/// audio standby only, [`ParentSelector::set_tier`]). Off for 45.x.
pub const CANONICAL_AV_FALLBACK: bool = false;

/// The `ShedReason` a relay that turned off sends its children. An older
/// peer refuses an unknown shed code as malformed and would then wait out
/// the silence, so the wire carries `UpstreamLost` (the child fails over at
/// once) and the precise reason is the local label
/// [`crate::observability::ALM_RELAY_OFF_SHED`].
const RELAY_OFF_WIRE_REASON: ShedReason = ShedReason::UpstreamLost;

impl AlmState {
    /// A fresh state for `me` publishing `own_stream` in a room of `members`.
    pub(super) fn new(
        me: &str,
        own_stream: StreamId,
        members: &[String],
        relay_capable: bool,
        seed: u64,
    ) -> Self {
        let mut cfg = ControllerConfig::interactive();
        cfg.idle_aware_silence = true;
        cfg.direct_first = true;
        let mut own = Admission::publisher(me.to_owned(), cfg.clone(), None);
        own.set_members(members.iter().cloned());
        own.set_slow_start(true);
        own.set_probe_streams(PUBLISHER_INITIAL_PROBE);
        Self {
            me: me.to_owned(),
            egress: EgressMeter::new(cfg.meter_window_ms, cfg.congestion_queue_ms),
            cfg,
            t0: Instant::now(),
            rng: SplitMix64(seed),
            log: DecisionLog::new(64),
            own_stream,
            own,
            shares: BTreeMap::new(),
            relay_capable,
            relays: BTreeMap::new(),
            sels: BTreeMap::new(),
            publisher_of: BTreeMap::new(),
            bound_publisher: BTreeMap::new(),
            caps: BTreeMap::new(),
            caps_withheld: 0,
            layer_requests: false,
            provisional: BTreeMap::new(),
            told_publisher: BTreeSet::new(),
            draining_parent: BTreeMap::new(),
            last_primary: BTreeMap::new(),
            leg_queue_ms: BTreeMap::new(),
            members: members.to_vec(),
            tier: ServiceTier::FullOps,
            own_rate: Rate::default(),
            rates: BTreeMap::new(),
            forwarded_seen: BTreeMap::new(),
            min_offset: BTreeMap::new(),
            last_offer_ms: 0,
            counts: AlmCounts::default(),
            labels: Vec::new(),
            failing_over: BTreeMap::new(),
            gaps: Vec::new(),
            booked: BTreeMap::new(),
            epochs: BTreeMap::new(),
            video_unavailable: BTreeSet::new(),
            layer_caps: BTreeMap::new(),
            wanted_layers: BTreeMap::new(),
            events: Vec::new(),
            serve_seat: false,
            seats: BTreeSet::new(),
            seat_offered: BTreeSet::new(),
            relay_status: None,
            relay_status_pending: None,
            parent_moves: Vec::new(),
            relayed: BTreeMap::new(),
            uplink_stall: false,
            uplink_stall_seen_ms: None,
            pending_out: Vec::new(),
            offered_at: BTreeMap::new(),
        }
    }

    /// G8 serial redial — whether this node's own stream carried media in
    /// its last measured window (a silent listener's legs carry no media).
    pub(super) fn publishing(&self) -> bool {
        self.own_rate.full_bps > 0.0 || self.own_rate.win_full > 0
    }

    /// G8 — whether the stall verdict holds now (detected, or latched).
    pub(super) fn uplink_stalled(&self) -> bool {
        self.uplink_stall
    }

    /// G8 — whether this watch tick DETECTED this node's uplink stalled (the
    /// call reads its legs' unproved Channel ages). The verdict holds
    /// [`UPLINK_STALL_LATCH_MS`] past the last detection. On its rise it is
    /// counted and this node sheds AT ONCE, not at the next egress window:
    /// at 2-3x overload the stalled legs' links die (Channel retry
    /// exhaustion, ~1.3 s) before a window closes, and their detection with
    /// them (CIRISEdge 45.2.0, the capped witness: verdict 1, shed 0). The
    /// shed keeps ONE direct child (LIFO) and lets the relay work go. While
    /// the verdict holds, every egress window reads congested at that room.
    /// Offers keep their cadence (row D1): only a BACKLOGGED leg's offer is
    /// held, at the send (`alm_offer_held:backlog`).
    pub(super) fn set_uplink_stall(&mut self, detected: bool) {
        let now = self.now_ms();
        if detected {
            self.uplink_stall_seen_ms = Some(now);
        }
        let stalled = self
            .uplink_stall_seen_ms
            .is_some_and(|t| now.saturating_sub(t) < UPLINK_STALL_LATCH_MS);
        let rose = stalled && !self.uplink_stall;
        self.uplink_stall = stalled;
        if detected {
            // No upward re-probe until a hold past the last detection.
            let until = now.saturating_add(STALL_PROBE_HOLD_MS);
            self.own.hold_probe(until);
            for (a, _) in self.shares.values_mut() {
                a.hold_probe(until);
            }
            for a in self.relays.values_mut() {
                a.hold_probe(until);
            }
        }
        if rose {
            self.label(crate::observability::ALM_UPLINK_STALL);
            // Nobody unsubscribed keeps this node's own chunks on a stalled
            // uplink (the provisional join window, the slow-start bridge).
            let own: Vec<StreamId> = self.own_admissions().map(|(s, _)| s).collect();
            self.provisional.retain(|(s, _), _| !own.contains(s));
            let w = EgressWindow {
                sent_bps: 0.0,
                delivered_bps: 0.0,
                dropped_bytes: 0,
                max_queue_ms: 0.0,
                congested: true,
                capacity_bps: None,
            };
            let out = self.fold_egress_window(now, w);
            self.pending_out.extend(out);
        }
    }

    /// Calls cut — one chunk of `stream` forwarded to `child`.
    pub(super) fn note_relayed(&mut self, child: &str, stream: StreamId, wire_bytes: u64) {
        self.counts.relayed_bytes = self.counts.relayed_bytes.saturating_add(wire_bytes);
        let e = self.relayed.entry(child.to_owned()).or_default();
        e.0 = e.0.saturating_add(wire_bytes);
        e.1 = e.1.saturating_add(1);
        e.2.insert(stream);
    }

    /// Calls cut — what this node forwarded, per child node.
    pub(super) fn relayed_to(&self) -> Vec<RelayedTo> {
        self.relayed
            .iter()
            .map(|(child, (bytes, chunks, streams))| RelayedTo {
                child: child.clone(),
                bytes: *bytes,
                chunks: *chunks,
                streams: streams.iter().copied().collect(),
            })
            .collect()
    }

    /// Calls cut — this node is a serve seat: with [`CANONICAL_AV_FALLBACK`]
    /// off it never relays, so relaying turns off at once (its children
    /// fail over make-before-break) and stays off.
    pub(super) fn set_serve_seat(&mut self, seat: bool) -> Vec<Outgoing> {
        self.serve_seat = seat && !CANONICAL_AV_FALLBACK;
        if self.serve_seat {
            self.set_relay(false)
        } else {
            Vec::new()
        }
    }

    /// Calls cut — the serve seats this node knows of (the canonical set).
    pub(super) fn set_seats(&mut self, seats: impl IntoIterator<Item = String>) {
        self.seats = seats.into_iter().collect();
        if CANONICAL_AV_FALLBACK {
            let seats: Vec<String> = self.seats.iter().cloned().collect();
            for sel in self.sels.values_mut() {
                for p in &seats {
                    sel.set_tier(
                        p,
                        crate::transport::realtime_av_alm::controller::Tier::Canonical,
                    );
                }
            }
        }
    }

    /// Whether this node offers relay now.
    pub(super) fn relay_capable(&self) -> bool {
        self.relay_capable
    }

    /// Calls cut — `Call::set_relay`: start or stop relaying, live.
    ///
    /// Off: every relay admission closes (its offer reads no room), every
    /// child is shed make-before-break (the commitment leaves the ledger now,
    /// but this node keeps forwarding to it until it unsubscribes or the
    /// drain passes, so its standby or another relay takes over first), each
    /// is told with a SHED ([`RELAY_OFF_WIRE_REASON`] on the wire, booked
    /// `relay_shed:relay_off`), offers stop, and an emptied relay is dropped
    /// on a later tick. On: admission reopens at the service tier and every
    /// received stream gets a relay admission on the next tick. A serve seat
    /// stays off. Returns the SHED frames to send.
    pub(super) fn set_relay(&mut self, on: bool) -> Vec<Outgoing> {
        let on = on && !self.serve_seat;
        if on == self.relay_capable {
            return Vec::new();
        }
        self.relay_capable = on;
        for sel in self.sels.values_mut() {
            sel.set_forward_capable(on);
        }
        let mut out = Vec::new();
        if on {
            let closed = !self.tier.admits_new_relay_work();
            for a in self.relays.values_mut() {
                a.set_admit_closed(closed);
            }
        } else {
            let now = self.now_ms();
            let mut shed = Vec::new();
            for (stream, a) in &mut self.relays {
                a.set_admit_closed(true);
                for p in a.shed_all_draining(now, RELAY_OFF_WIRE_REASON, &mut self.log) {
                    shed.push((*stream, p));
                }
            }
            for (stream, p) in shed {
                self.counts.shed += 1;
                self.label(crate::observability::ALM_SHED);
                self.label(crate::observability::ALM_RELAY_OFF_SHED);
                out.push(Outgoing {
                    to: p,
                    frame: encode(
                        stream,
                        &ControlMsg::Shed {
                            reason: RELAY_OFF_WIRE_REASON,
                        },
                    ),
                });
            }
        }
        let status = (self.relay_capable, self.relaying_for());
        self.relay_status = Some(status);
        self.relay_status_pending = None;
        self.events.push(super::CallEvent::RelayStatus {
            relaying: status.0,
            relaying_for: status.1,
        });
        out
    }

    /// Calls cut — how many distinct child NODES this node forwards others'
    /// streams to now (admitted, or draining after a make-before-break shed).
    /// Its own stream's children are not counted: that is publishing, not
    /// relaying. Nodes, not people: the host maps a node to its owner.
    pub(super) fn relaying_for(&self) -> u16 {
        let kids: BTreeSet<String> = self
            .relays
            .values()
            .flat_map(|a| a.forwarding_to().into_iter().map(|(p, _)| p))
            .collect();
        u16::try_from(kids.len()).unwrap_or(u16::MAX)
    }

    /// Calls cut — streams a serve seat offered here and was refused, and no
    /// member offered (the media-path event's `refused_by_policy`).
    pub(super) fn only_a_seat_offered(&self, stream: StreamId) -> bool {
        self.seat_offered.contains(&stream)
            && self.sels.get(&stream).is_none_or(|s| {
                s.candidates()
                    .iter()
                    .all(|(p, _, _)| self.seats.contains(p))
            })
    }

    /// Calls cut — whether any member other than the publisher offers
    /// `stream` here now (a relay could carry it).
    pub(super) fn member_offers(&self, stream: StreamId) -> bool {
        let publisher = self.publisher_of.get(&stream);
        self.sels.get(&stream).is_some_and(|s| {
            s.candidates().iter().any(|(p, st, _)| {
                Some(p) != publisher
                    && !self.seats.contains(p)
                    && !matches!(
                        st,
                        crate::transport::realtime_av_alm::controller::PeerState::Down
                    )
            })
        })
    }

    /// The streams this node receives, with the publisher each names.
    pub(super) fn streams_of(&self, publisher: &str) -> Vec<StreamId> {
        self.publisher_of
            .iter()
            .filter(|(_, p)| p.as_str() == publisher)
            .map(|(s, _)| *s)
            .collect()
    }

    /// The primary parent this node chose for `stream`, if any.
    pub(super) fn primary_of(&self, stream: StreamId) -> Option<String> {
        self.sels.get(&stream).and_then(|s| s.primary().cloned())
    }

    /// The publisher `stream` names.
    pub(super) fn publisher_of(&self, stream: StreamId) -> Option<&str> {
        self.publisher_of.get(&stream).map(String::as_str)
    }

    /// The call's monotonic clock (ms).
    pub(super) fn now_ms(&self) -> u64 {
        u64::try_from(self.t0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// This node's capability bits.
    pub(super) fn caps_bits(&self) -> u32 {
        let layers = if self.layer_requests {
            CAP_LAYER_REQUEST
        } else {
            0
        };
        (CAPS_THIS_BUILD | layers | if self.relay_capable { CAP_RELAY } else { 0 })
            & !self.caps_withheld
    }

    /// Test seam — leave `bits` out of this node's `CAPS`.
    pub(super) fn withhold_caps(&mut self, bits: u32) {
        self.caps_withheld = bits;
    }

    /// v45 — the host's layer-cap lever (off by default).
    pub(super) fn set_layer_requests(&mut self, on: bool) {
        self.layer_requests = on;
    }

    /// This node's `CAPS` frame. `offer_datagrams` false (the host's
    /// `set_av_datagrams_enabled(false)`) leaves `CAP_LINK_DATAGRAMS` out.
    pub(super) fn caps_frame(&self, offer_datagrams: bool) -> Vec<u8> {
        let off = if offer_datagrams {
            0
        } else {
            CAP_LINK_DATAGRAMS
        };
        encode_caps(self.caps_bits() & !off)
    }

    /// Whether `peer` said it speaks C3.
    pub(super) fn speaks_c3(&self, peer: &str) -> bool {
        self.caps.get(peer).is_some_and(|c| c & CAP_C3_V1 != 0)
    }

    /// Whether `peer`'s leviculum takes timed frames.
    pub(super) fn takes_timed(&self, peer: &str) -> bool {
        self.caps
            .get(peer)
            .is_some_and(|c| c & CAP_TIMED_FRAMES != 0)
    }

    /// Whether `peer` parses a v2 stream key binding (`CAP_BINDING_V2`).
    pub(super) fn takes_binding_v2(&self, peer: &str) -> bool {
        self.caps.get(peer).is_some_and(|c| c & CAP_BINDING_V2 != 0)
    }

    /// v45 — whether `peer`'s `CAPS` came and lack `CAP_BINDING_V2`: an
    /// older build that never signs a v2 binding (so none is in flight).
    pub(super) fn known_without_binding_v2(&self, peer: &str) -> bool {
        self.caps.get(peer).is_some_and(|c| c & CAP_BINDING_V2 == 0)
    }

    /// v45 — whether this node sends `peer` v2 bindings: `peer` takes them
    /// and this node advertises taking them too (a node that does not, a v44
    /// build or the test seam's, signs and sends v1 only).
    pub(super) fn sends_binding_v2_to(&self, peer: &str) -> bool {
        self.advertises_binding_v2() && self.takes_binding_v2(peer)
    }

    /// v45 — whether this node advertises `CAP_BINDING_V2` (it takes v2
    /// bindings, so a framed stream's v2 is sent to it).
    pub(super) fn advertises_binding_v2(&self) -> bool {
        self.caps_bits() & CAP_BINDING_V2 != 0
    }

    /// leviculum#102 — whether `peer` takes media as unordered link
    /// datagrams. Only a peer whose `CAPS` carried the bit: an older edge (or
    /// one whose `CAPS` has not arrived) reads as "no".
    pub(super) fn takes_datagrams(&self, peer: &str) -> bool {
        self.caps
            .get(peer)
            .is_some_and(|c| c & CAP_LINK_DATAGRAMS != 0)
    }

    /// The decision log's chained hash (hex).
    pub(super) fn log_hash(&self) -> String {
        self.log.hash_hex()
    }

    /// Records in the decision log.
    pub(super) fn log_len(&self) -> u64 {
        self.log.len()
    }

    /// Records of one kind.
    pub(super) fn log_count(&self, kind: DecisionKind) -> u64 {
        self.log.count(kind)
    }

    /// The decision log's rendered tail.
    pub(super) fn log_tail(&self) -> String {
        self.log.tail()
    }

    /// Tell the `av_plane` ledger of the decisions the log took since last
    /// asked. The log is the one record of them, so the counters cannot drift
    /// from what a field log replays.
    pub(super) fn book_decisions(&mut self) {
        use crate::observability as o;
        for (kind, label) in [
            (DecisionKind::Failover, o::ALM_FAILOVER),
            (DecisionKind::Switch, o::ALM_SWITCH),
            (DecisionKind::LoopDetected, o::ALM_LOOP_DETECTED),
            (DecisionKind::OverClaim, o::ALM_OVER_CLAIM),
        ] {
            let seen = self.log.count(kind);
            let booked = self.booked.entry(kind).or_insert(0);
            for _ in *booked..seen {
                self.labels.push(label);
            }
            *booked = seen;
        }
    }

    fn label(&mut self, l: &'static str) {
        self.labels.push(l);
    }

    /// The room's roster (both sides: selectors and admissions).
    pub(super) fn set_members(&mut self, members: &[String]) {
        self.members = members.to_vec();
        self.own.set_members(members.iter().cloned());
        for (a, _) in self.shares.values_mut() {
            a.set_members(members.iter().cloned());
        }
        for a in self.relays.values_mut() {
            a.set_members(members.iter().cloned());
        }
        for s in self.sels.values_mut() {
            s.set_members(members.iter().cloned());
        }
        self.caps.retain(|p, _| members.contains(p));
        self.provisional.retain(|(_, p), _| members.contains(p));
        self.relayed.retain(|p, _| members.contains(p));
    }

    /// The service tier (§7.2): Admit-close on relays at ≥ 1, A-shed (LIFO,
    /// make-before-break) at 2.
    pub(super) fn set_tier(&mut self, tier: ServiceTier) -> Vec<Outgoing> {
        if tier == self.tier {
            return Vec::new();
        }
        let now = self.now_ms();
        self.tier = tier;
        self.events
            .push(super::CallEvent::LoadTier { tier: tier.as_u8() });
        let mut out = Vec::new();
        let mut shed_frames = Vec::new();
        for (stream, a) in &mut self.relays {
            a.set_admit_closed(!tier.admits_new_relay_work());
            if tier.sheds_relayed_audio() {
                for p in a.shed_all_draining(now, ShedReason::LoadShed, &mut self.log) {
                    shed_frames.push((*stream, p));
                }
            }
        }
        for (stream, p) in shed_frames {
            self.counts.shed += 1;
            self.label(crate::observability::ALM_SHED);
            self.label(ShedReason::LoadShed.token());
            out.push(Outgoing {
                to: p,
                frame: encode(
                    stream,
                    &ControlMsg::Shed {
                        reason: ShedReason::LoadShed,
                    },
                ),
            });
        }
        out
    }

    /// Every link that carried `peer`'s frames to this node is gone: it is
    /// down as a parent (C6), now, not after its silence.
    pub(super) fn on_parent_link_down(&mut self, peer: &str) {
        let now = self.now_ms();
        let p = peer.to_owned();
        for s in self.sels.values_mut() {
            s.on_link_down(now, &p, &mut self.log);
        }
    }

    /// This node's leg to `peer` is gone: it can no longer send it anything,
    /// so `peer` holds no commitment here.
    pub(super) fn on_child_link_down(&mut self, peer: &str) {
        self.layer_caps.retain(|(_, c), _| c != peer);
        let p = peer.to_owned();
        self.own.release(&p);
        for (a, _) in self.shares.values_mut() {
            a.release(&p);
        }
        for a in self.relays.values_mut() {
            a.release(&p);
        }
        self.provisional.retain(|(_, c), _| c != peer);
        self.ensure_own_primaries();
    }

    /// An ADMIT this node made could not be delivered (its resend budget
    /// spent): the commitment it named is released, so no slot is held for
    /// a child that never heard it was admitted (it asks again). Row E2 then
    /// applies as for any other loss.
    pub(super) fn on_admit_undelivered(&mut self, peer: &str, frame: &[u8]) {
        let Ok(crate::transport::realtime_av_alm::controller::wire::WireFrame::Control(
            ControlFrame {
                stream,
                msg: ControlMsg::Decision(AdmitDecision::Admit { .. }),
            },
        )) = crate::transport::realtime_av_alm::controller::wire::decode(frame, &self.me)
        else {
            return;
        };
        let p = peer.to_owned();
        if let Some(a) = self.own_admission_mut(stream) {
            a.release(&p);
        } else if let Some(a) = self.relays.get_mut(&stream) {
            a.release(&p);
        }
        self.ensure_own_primaries();
    }

    /// Row E2 — every own stream with any subscriber keeps a PRIMARY: when
    /// its last primary is lost by any cause (a link close, an unsubscribe, a
    /// shed), the oldest standby is promoted at once and told with an ADMIT
    /// as primary (sent with the next tick's frames); its media resumes
    /// because it now holds a primary commitment. With no standby, the next
    /// SUBSCRIBE is admitted whatever the room reads (row S3).
    fn ensure_own_primaries(&mut self) {
        let streams: Vec<StreamId> = self.own_admissions().map(|(s, _)| s).collect();
        for s in streams {
            let promoted = self
                .own_admission_mut(s)
                .and_then(Admission::promote_standby_if_no_primary);
            if let Some(child) = promoted {
                self.label(crate::observability::ALM_ADMIT);
                self.pending_out.push(Outgoing {
                    to: child,
                    frame: encode(
                        s,
                        &ControlMsg::Decision(AdmitDecision::Admit {
                            role: Role::Primary,
                        }),
                    ),
                });
            }
        }
    }

    /// The service tier now.
    pub(super) fn tier(&self) -> ServiceTier {
        self.tier
    }

    /// A peer's `CAPS`. Returns whether this is the first one heard.
    pub(super) fn on_caps(&mut self, peer: &str, caps: u32) -> bool {
        let first = self.caps.insert(peer.to_owned(), caps).is_none();
        if first && caps & CAP_C3_V1 != 0 && self.members.iter().any(|m| m == peer) {
            let now = self.now_ms();
            let p = peer.to_owned();
            let unheld: Vec<StreamId> = self
                .own_admissions()
                .filter(|(_, a)| a.role_of(&p).is_none())
                .map(|(s, _)| s)
                .collect();
            for s in unheld {
                self.provisional.insert((s, p.clone()), now);
            }
            self.label(crate::observability::ALM_C3_PEER_CAPABLE);
        }
        first
    }

    /// `publisher` publishes `stream` (its own link's hello names it). The
    /// hello is unsigned, so this is a first guess: a binding overrides it
    /// and it never overrides a binding.
    pub(super) fn note_publisher(&mut self, stream: StreamId, publisher: &str) {
        if self.is_own(stream) || publisher == self.me {
            return;
        }
        if !self.bound_publisher.contains_key(&stream) {
            self.publisher_of.insert(stream, publisher.to_owned());
        }
        self.selector(stream);
    }

    /// A verified binding names `publisher` for `stream`. A stream id is
    /// derived from its publisher, so this cannot change once known.
    pub(super) fn note_bound_publisher(&mut self, stream: StreamId, publisher: &str) {
        if self.is_own(stream) {
            return;
        }
        self.bound_publisher.insert(stream, publisher.to_owned());
        self.publisher_of.insert(stream, publisher.to_owned());
    }

    /// Why an `OFFER` from `peer` claiming depth 0 on `stream` is dropped, or
    /// `None` when `peer` is the stream's publisher.
    ///
    /// Depth 0 is the publisher itself, and direct-first takes it over every
    /// relay. An `OFFER` is attributed by the link but not signed, so the
    /// claim is checked against the binding. A claim that fails is dropped
    /// whole, not clamped to a relay's depth: nothing honest sends one (a
    /// forwarder offers its own depth), and a clamped offer would still make
    /// a liar a candidate with a depth and an empty ancestry it made up,
    /// which blinds the loop check. With no binding held yet the claim cannot
    /// be checked, and it is dropped too: chunks cannot be verified without a
    /// binding either, and the publisher offers again within a second.
    fn depth_zero_refusal(&self, stream: StreamId, peer: &str) -> Option<&'static str> {
        match self.bound_publisher.get(&stream) {
            Some(publisher) if publisher == peer => None,
            Some(_) => Some(crate::observability::ALM_OFFER_REFUSED_NOT_PUBLISHER),
            None => Some(crate::observability::ALM_OFFER_REFUSED_UNBOUND),
        }
    }

    fn selector(&mut self, stream: StreamId) -> &mut ParentSelector<String> {
        let (me, cfg, fc, members) = (
            self.me.clone(),
            self.cfg.clone(),
            self.relay_capable,
            self.members.clone(),
        );
        let seats: Vec<String> = if CANONICAL_AV_FALLBACK {
            self.seats.iter().cloned().collect()
        } else {
            Vec::new()
        };
        self.sels.entry(stream).or_insert_with(|| {
            let mut s = ParentSelector::new(me, cfg, fc);
            s.set_members(members);
            for p in &seats {
                s.set_tier(
                    p,
                    crate::transport::realtime_av_alm::controller::Tier::Canonical,
                );
            }
            s
        })
    }

    /// The per-leg queueing delay above the propagation floor, from the
    /// leg's link stats (refreshed each watch tick).
    pub(super) fn set_leg_queue_ms(&mut self, peer: &str, ms: f64) {
        self.leg_queue_ms.insert(peer.to_owned(), ms);
    }

    /// C1, sender side: `bytes` left on `peer`'s leg.
    pub(super) fn on_sent(&mut self, peer: &str, bytes: u64) {
        let now = self.now_ms();
        let q = self.leg_queue_ms.get(peer).copied().unwrap_or(0.0);
        self.egress.on_sent(now, bytes, q);
    }

    /// C1, sender side: `bytes` refused (congested) or expired unconfirmed.
    pub(super) fn on_dropped(&mut self, bytes: u64) {
        let now = self.now_ms();
        self.egress.on_dropped(now, bytes);
    }

    /// C1, sender side: `bytes` the uplink's links proved delivered
    /// (`docs/AV_ALM_DESIGN.md` §5.1).
    pub(super) fn on_delivered(&mut self, bytes: u64) {
        let now = self.now_ms();
        self.egress.on_delivered(now, bytes);
    }

    /// This node published `bytes` of its own (primary) stream.
    #[cfg(test)]
    pub(super) fn on_own_published(&mut self, bytes: u64, base_or_audio: bool) {
        self.own_rate.add(bytes, base_or_audio);
    }

    /// v45 — this node published `bytes` of its own `stream` (the primary
    /// or a share).
    pub(super) fn on_own_published_on(
        &mut self,
        stream: StreamId,
        bytes: u64,
        base_or_audio: bool,
    ) {
        if stream == self.own_stream {
            self.own_rate.add(bytes, base_or_audio);
        } else if let Some((_, r)) = self.shares.get_mut(&stream) {
            r.add(bytes, base_or_audio);
        }
    }

    /// The members this node's own (primary) chunk must NOT go to, among
    /// `legs`: C3 peers that hold no commitment (and are past the
    /// provisional window), and standby children for a chunk above the base
    /// layer.
    #[cfg(test)]
    pub(super) fn own_exclude(&self, legs: &[String], base_or_audio: bool) -> Vec<String> {
        self.own_exclude_on(self.own_stream, legs, base_or_audio)
    }

    /// v45 — [`Self::own_exclude`] for one of this node's own streams, by
    /// that stream's own admission. A stream this node does not publish
    /// excludes every C3 leg.
    pub(super) fn own_exclude_on(
        &self,
        stream: StreamId,
        legs: &[String],
        base_or_audio: bool,
    ) -> Vec<String> {
        let now = self.now_ms();
        let adm = self.own_admission(stream);
        legs.iter()
            .filter(|p| {
                if !self.speaks_c3(p) {
                    return false;
                }
                let Some(adm) = adm else {
                    return true;
                };
                match adm.role_of(p) {
                    Some(Role::Primary) => false,
                    // Stall row S1: latched verdict → a standby gets nothing
                    // (an opaque/audio standby is a full second copy).
                    Some(Role::Standby) => self.uplink_stall || !base_or_audio,
                    None => {
                        let fresh = self
                            .provisional
                            .get(&(stream, (*p).clone()))
                            .is_some_and(|t| now.saturating_sub(*t) < PROVISIONAL_MS);
                        let draining = adm.is_draining(p);
                        !(fresh || draining)
                    }
                }
            })
            .cloned()
            .collect()
    }

    /// v45 — whether `stream` is one of this node's own (the primary or a
    /// share).
    pub(super) fn is_own(&self, stream: StreamId) -> bool {
        stream == self.own_stream || self.shares.contains_key(&stream)
    }

    /// The admission of this node's own `stream`, if it publishes it.
    fn own_admission(&self, stream: StreamId) -> Option<&Admission<String>> {
        if stream == self.own_stream {
            Some(&self.own)
        } else {
            self.shares.get(&stream).map(|(a, _)| a)
        }
    }

    fn own_admission_mut(&mut self, stream: StreamId) -> Option<&mut Admission<String>> {
        if stream == self.own_stream {
            Some(&mut self.own)
        } else {
            self.shares.get_mut(&stream).map(|(a, _)| a)
        }
    }

    /// Every own stream's admission, the primary first.
    fn own_admissions(&self) -> impl Iterator<Item = (StreamId, &Admission<String>)> {
        std::iter::once((self.own_stream, &self.own))
            .chain(self.shares.iter().map(|(s, (a, _))| (*s, a)))
    }

    /// v45 — `Call::add_stream`: this node now also publishes `stream`, a
    /// parent-0 admission of its own on the same uplink (its commitments
    /// count against every other admission's room, and theirs against its).
    /// Every C3 member is provisional on it, so its first chunks reach each
    /// while that member's selector learns of it.
    pub(super) fn add_own_stream(&mut self, stream: StreamId) {
        if self.is_own(stream) {
            return;
        }
        let mut a = Admission::publisher(self.me.clone(), self.cfg.clone(), None);
        a.set_members(self.members.iter().cloned());
        a.set_slow_start(true);
        a.set_probe_streams(PUBLISHER_INITIAL_PROBE);
        self.shares.insert(stream, (a, Rate::default()));
        let now = self.now_ms();
        let c3: Vec<String> = self
            .caps
            .iter()
            .filter(|(p, c)| *c & CAP_C3_V1 != 0 && self.members.contains(p))
            .map(|(p, _)| p.clone())
            .collect();
        for p in c3 {
            self.provisional.insert((stream, p), now);
        }
    }

    /// v45 — `Call::end_stream`: this node no longer publishes `stream` (a
    /// share). Its admission, children's layer caps and provisional marks
    /// go; the primary is untouched.
    pub(super) fn remove_own_stream(&mut self, stream: StreamId) {
        if self.shares.remove(&stream).is_some() {
            self.provisional.retain(|(s, _), _| *s != stream);
            self.layer_caps.retain(|(s, _), _| *s != stream);
        }
    }

    /// v45 — this node's own streams besides the primary.
    #[cfg(test)]
    pub(super) fn share_streams(&self) -> Vec<StreamId> {
        self.shares.keys().copied().collect()
    }

    /// Whether this node forwards `stream`'s chunk `(epoch, seq)` heard from
    /// `from` and, if so, the legs it must NOT go to. Only chunks from this
    /// node's primary (or promoting) parent are forwarded, once each, to the
    /// admitted children (standby children: base/audio only); never back to
    /// `from` or the publisher.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn forward_exclude(
        &mut self,
        stream: StreamId,
        epoch: u64,
        seq: u64,
        from: &str,
        publisher: &str,
        legs: &[String],
        base_or_audio: bool,
    ) -> Option<Vec<String>> {
        let adm = self.relays.get(&stream)?;
        let sel = self.sels.get(&stream)?;
        let from_parent =
            sel.primary().is_some_and(|p| p == from) || sel.promoting().is_some_and(|p| p == from);
        if !from_parent {
            return None;
        }
        let targets: BTreeSet<String> = adm
            .forwarding_to()
            .into_iter()
            .filter(|(p, role)| {
                p != from
                    && p != publisher
                    && (*role == Role::Primary || (base_or_audio && !self.uplink_stall))
            })
            .map(|(p, _)| p)
            .collect();
        if targets.is_empty() {
            return None;
        }
        let (set, order) = self.forwarded_seen.entry(stream).or_default();
        if !set.insert((epoch, seq)) {
            return None;
        }
        order.push_back((epoch, seq));
        if order.len() > FORWARD_DEDUPE {
            if let Some(old) = order.pop_front() {
                set.remove(&old);
            }
        }
        Some(
            legs.iter()
                .filter(|l| !targets.contains(*l))
                .cloned()
                .collect(),
        )
    }

    /// C1, receiver side: a verified chunk of `stream` from `from`.
    /// `source_ms` is the publisher's signed timestamp; latency is measured
    /// above the fastest delivery seen for the stream, so clock offset
    /// between the hosts cancels.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_wrap,
        clippy::too_many_arguments
    )]
    pub(super) fn on_chunk(
        &mut self,
        stream: StreamId,
        from: &str,
        epoch: u64,
        seq: u64,
        bytes: u64,
        source_ms: u64,
        base_or_audio: bool,
        hop_lost: u64,
    ) {
        if self.is_own(stream) {
            return;
        }
        let now = self.now_ms();
        let newest = self.epochs.entry(stream).or_insert(epoch);
        if epoch > *newest {
            *newest = epoch;
            self.labels.push(crate::observability::ALM_EPOCH_RESYNC);
        }
        let wall = crate::transport::av_chunk_auth::unix_ms_now();
        let offset = wall as i64 - source_ms as i64;
        let entry = self.min_offset.entry(stream).or_insert((offset, now));
        // The floor decays: a better floor wins at once, a stale one is
        // replaced after 30 s.
        if offset < entry.0 || now.saturating_sub(entry.1) > 30_000 {
            *entry = (offset, now);
        }
        let latency = (offset - entry.0).max(0) as f64;
        let Some(sel) = self.sels.get_mut(&stream) else {
            return;
        };
        let role = sel
            .subscriptions()
            .into_iter()
            .find(|(p, _)| p == from)
            .map(|(_, r)| r);
        let chunk = PathChunk {
            pos: ChunkPos { epoch, seq },
            full: !base_or_audio,
            base_or_audio,
            hop_lost,
            bytes,
            latency_ms: latency,
        };
        sel.on_chunk(now, &from.to_owned(), chunk);
        if role == Some(Role::Primary) {
            if let Some((heard, cause)) = self.failing_over.remove(&stream) {
                let gap = std::time::Duration::from_millis(now.saturating_sub(heard));
                self.gaps.push((cause, gap));
            }
        }
        if sel.primary().is_some_and(|p| p == from) {
            self.rates
                .entry(stream)
                .or_default()
                .add(bytes, base_or_audio);
        }
    }

    /// What every admission on this uplink but `stream`'s commits (bits/s):
    /// every own stream's (the primary and each share) and every relayed
    /// stream's.
    fn external_except(&self, stream: StreamId) -> u64 {
        self.own_admissions()
            .filter(|(s, _)| *s != stream)
            .map(|(_, a)| a.committed_bps())
            .sum::<u64>()
            + self
                .relays
                .iter()
                .filter(|(s, _)| **s != stream)
                .map(|(_, a)| a.committed_bps())
                .sum::<u64>()
    }

    /// The SUBSCRIBE this node sends `parent` for `stream` in `role`: with
    /// this node's layer cap for the stream when the parent takes one.
    fn subscribe_frame(&self, stream: StreamId, parent: &str, role: Role) -> Vec<u8> {
        let layers = if self.takes_layer_requests(parent) {
            self.wanted_layers.get(&stream).copied()
        } else {
            None
        };
        encode(
            stream,
            &ControlMsg::Subscribe(SubscribeRequest {
                subscriber: self.me.clone(),
                role,
                forward_capable: self.relay_capable,
                layers,
            }),
        )
    }

    fn action_frames(
        &mut self,
        stream: StreamId,
        acts: Vec<SelectorAction<String>>,
    ) -> Vec<Outgoing> {
        acts.into_iter()
            .map(|a| match a {
                SelectorAction::Subscribe { parent, role } => Outgoing {
                    frame: self.subscribe_frame(stream, &parent, role),
                    to: parent,
                },
                SelectorAction::Unsubscribe { parent } => Outgoing {
                    frame: encode(
                        stream,
                        &ControlMsg::Unsubscribe {
                            subscriber: self.me.clone(),
                        },
                    ),
                    to: parent,
                },
            })
            .collect()
    }

    /// A relay admission for a stream this node receives (it has chosen a
    /// parent for it), when it offers relay. Made on the tick after the
    /// parent is chosen, and by a SUBSCRIBE that lands before that tick, so
    /// the ledger answers the request and names its own refusal.
    fn ensure_relay(&mut self, s: StreamId) {
        if !self.relay_capable || self.relays.contains_key(&s) {
            return;
        }
        if self.sels.get(&s).is_none_or(|sel| sel.primary().is_none()) {
            return;
        }
        let mut a = Admission::relay(self.me.clone(), self.cfg.clone(), None);
        let (full, audio) = self.rates.get(&s).cloned().unwrap_or_default().costs();
        a.set_role_costs(full, audio);
        a.set_members(self.members.iter().cloned());
        a.set_admit_closed(!self.tier.admits_new_relay_work());
        self.relays.insert(s, a);
        self.sync_upstream(s);
    }

    fn sync_upstream(&mut self, stream: StreamId) {
        let view = self
            .sels
            .get(&stream)
            .and_then(ParentSelector::upstream_view);
        if let Some(a) = self.relays.get_mut(&stream) {
            match view {
                Some(u) => a.set_upstream(Some(u.depth), u.ancestry, u.healthy, u.latency_ms),
                None => a.set_upstream(None, Vec::new(), false, 0),
            }
        }
    }

    /// One C3 frame from `peer` (`rtt_ms`: the link's smoothed RTT).
    #[allow(clippy::too_many_lines)]
    pub(super) fn on_control(
        &mut self,
        peer: &str,
        f: ControlFrame<String>,
        rtt_ms: f64,
    ) -> Vec<Outgoing> {
        let now = self.now_ms();
        let stream = f.stream;
        self.counts.c3_received += 1;
        self.label(crate::observability::ALM_C3_RECEIVED);
        let mut out = Vec::new();
        match f.msg {
            ControlMsg::Subscribe(req) => {
                if !self.is_own(stream) {
                    self.ensure_relay(stream);
                }
                let (decision, preempted) = if self.serve_seat && !self.is_own(stream) {
                    // Calls cut — a serve seat never relays call media. The
                    // wire carries `ClassRefused` (a code every C3 peer
                    // reads); the local token names the rule.
                    self.label(crate::observability::ALM_REFUSE_SERVE_SEAT);
                    (
                        AdmitDecision::Refuse {
                            reason: RefuseReason::ClassRefused,
                            retry_after_ms: self.cfg.backoff_base_ms * 4,
                        },
                        Vec::new(),
                    )
                } else if self.is_own(stream)
                    && self.uplink_stall
                    && req.role == Role::Standby
                    && self
                        .own_admission(stream)
                        .is_some_and(|a| a.role_of(&req.subscriber).is_none())
                {
                    // Stall row S2: a latched verdict admits no new standby
                    // (a shed child is never left as one).
                    self.provisional.remove(&(stream, peer.to_owned()));
                    (
                        AdmitDecision::Refuse {
                            reason: RefuseReason::Capacity,
                            retry_after_ms: UPLINK_STALL_LATCH_MS,
                        },
                        Vec::new(),
                    )
                } else if self.is_own(stream) {
                    self.provisional.remove(&(stream, peer.to_owned()));
                    let ext = self.external_except(stream);
                    let (mut rng, mut log) = (self.rng.clone(), std::mem::take(&mut self.log));
                    let a = self.own_admission_mut(stream).expect("own");
                    a.set_external_committed(ext);
                    let d = a.request(now, &req, &mut rng, &mut log);
                    let pre = a.take_preempted();
                    let unmeasured = a.ceiling_bps().is_none();
                    self.rng = rng;
                    self.log = log;
                    // G8 slow start — a member the probe has no room for yet
                    // keeps this node's chunks for SLOW_START_BRIDGE_MS, while
                    // the first children start offering the stream, so the
                    // move to a relay costs it nothing. Only while the uplink
                    // is unmeasured, and not when it is stalled: there the
                    // bridge is the overload.
                    if unmeasured
                        && !self.uplink_stall
                        && matches!(
                            d,
                            AdmitDecision::Refuse {
                                reason: RefuseReason::Capacity,
                                ..
                            }
                        )
                    {
                        let since = now.saturating_sub(PROVISIONAL_MS - SLOW_START_BRIDGE_MS);
                        let e = self
                            .provisional
                            .entry((stream, peer.to_owned()))
                            .or_insert(since);
                        *e = (*e).max(since);
                    }
                    (d, pre)
                } else if self.relays.contains_key(&stream) {
                    let ext = self.external_except(stream);
                    let a = self.relays.get_mut(&stream).expect("present");
                    a.set_external_committed(ext);
                    let d = a.request(now, &req, &mut self.rng, &mut self.log);
                    (d, a.take_preempted())
                } else {
                    // Not forwarding this stream: say so by name.
                    (
                        AdmitDecision::Refuse {
                            reason: RefuseReason::UpstreamUnhealthy,
                            retry_after_ms: self.cfg.backoff_base_ms * 4,
                        },
                        Vec::new(),
                    )
                };
                // v45 — an admitted SUBSCRIBE carries the child's layer cap
                // (or, without one, withdraws it), for a stream this node
                // parents.
                if matches!(decision, AdmitDecision::Admit { .. })
                    && self.layer_requests
                    && (self.is_own(stream) || self.relays.contains_key(&stream))
                {
                    let key = (stream, peer.to_owned());
                    match req.layers {
                        Some(cap) => {
                            self.layer_caps.insert(key, cap);
                        }
                        None => {
                            self.layer_caps.remove(&key);
                        }
                    }
                }
                match &decision {
                    AdmitDecision::Admit { .. } => {
                        self.counts.admitted += 1;
                        self.label(crate::observability::ALM_ADMIT);
                    }
                    AdmitDecision::Refuse { reason, .. } => {
                        *self.counts.refused.entry(reason.token()).or_insert(0) += 1;
                        self.label(crate::observability::ALM_REFUSE);
                        self.label(reason.token());
                    }
                }
                out.push(Outgoing {
                    to: peer.to_owned(),
                    frame: encode(stream, &ControlMsg::Decision(decision)),
                });
                for v in preempted {
                    self.counts.shed += 1;
                    self.label(crate::observability::ALM_SHED);
                    out.push(Outgoing {
                        to: v,
                        frame: encode(
                            stream,
                            &ControlMsg::Shed {
                                reason: ShedReason::Preempted,
                            },
                        ),
                    });
                }
            }
            ControlMsg::Unsubscribe { .. } => {
                self.layer_caps.remove(&(stream, peer.to_owned()));
                let p = peer.to_owned();
                if self.is_own(stream) {
                    self.provisional.remove(&(stream, p.clone()));
                    if let Some(a) = self.own_admission_mut(stream) {
                        a.release(&p);
                    }
                    self.ensure_own_primaries();
                } else if let Some(a) = self.relays.get_mut(&stream) {
                    a.release(&p);
                }
            }
            ControlMsg::Decision(d) => {
                let acts = match self.sels.get_mut(&stream) {
                    Some(s) => {
                        s.on_decision(now, &peer.to_owned(), &d, &mut self.rng, &mut self.log)
                    }
                    None => Vec::new(),
                };
                out.extend(self.action_frames(stream, acts));
                self.sync_upstream(stream);
            }
            ControlMsg::Shed { reason } => {
                if let Some(s) = self.sels.get_mut(&stream) {
                    s.on_shed(now, &peer.to_owned(), &mut self.rng, &mut self.log);
                    self.draining_parent.insert(stream, peer.to_owned());
                    self.label(reason.token());
                }
                self.sync_upstream(stream);
            }
            ControlMsg::Offer(o) => {
                if self.is_own(stream) || !self.members.iter().any(|m| m == peer) {
                    return out;
                }
                // Calls cut — a serve seat's OFFER for a stream it does not
                // publish: dropped while the canonical fallback is off.
                if !CANONICAL_AV_FALLBACK
                    && self.seats.contains(peer)
                    && self.bound_publisher.get(&stream).is_none_or(|p| p != peer)
                {
                    self.counts.offers_refused += 1;
                    self.seat_offered.insert(stream);
                    self.label(crate::observability::ALM_OFFER_REFUSED);
                    self.label(crate::observability::ALM_OFFER_REFUSED_SERVE_SEAT);
                    return out;
                }
                if o.depth == 0 {
                    if let Some(reason) = self.depth_zero_refusal(stream, peer) {
                        self.counts.offers_refused += 1;
                        self.label(crate::observability::ALM_OFFER_REFUSED);
                        self.label(reason);
                        let subject = peer.to_owned();
                        self.log.record(
                            now,
                            &self.me,
                            DecisionKind::OfferRefused,
                            Some(&subject),
                            0,
                            reason,
                        );
                        return out;
                    }
                }
                let mut log = std::mem::take(&mut self.log);
                self.selector(stream).on_offer(now, o, rtt_ms, &mut log);
                self.log = log;
            }
        }
        out
    }

    /// v45 — of `legs`, the children whose SUBSCRIBE layer cap for `stream`
    /// does not admit a chunk of `codec_id` at `layer`: this node sends them
    /// nothing of it. Every other child is untouched.
    pub(super) fn layer_exclude(
        &self,
        stream: StreamId,
        legs: &[String],
        codec_id: u8,
        layer: crate::transport::realtime_av::ChunkLayer,
    ) -> Vec<String> {
        if self.layer_caps.is_empty() {
            return Vec::new();
        }
        legs.iter()
            .filter(|l| {
                self.layer_caps
                    .get(&(stream, (*l).clone()))
                    .is_some_and(|cap| {
                        !crate::transport::realtime_av_alm::controller::layer_cap_admits(
                            *cap, codec_id, layer,
                        )
                    })
            })
            .cloned()
            .collect()
    }

    /// The publisher a verified binding names for `stream`, if any.
    pub(super) fn bound_publisher_of(&self, stream: StreamId) -> Option<&str> {
        self.bound_publisher.get(&stream).map(String::as_str)
    }

    /// When `stream`'s chunks last arrived on any path (call ms), if ever.
    pub(super) fn stream_last_activity_ms(&self, stream: StreamId) -> Option<u64> {
        self.sels
            .get(&stream)
            .and_then(ParentSelector::last_activity_ms)
    }

    /// v45 — `Call::replace_stream`, publisher side: this node's stream is
    /// now `stream`. The children of the old stream hold the same commitment
    /// on the new one (one uplink, the same members), and every C3 member is
    /// provisional again, so the new stream reaches each at once while its
    /// selector learns the new stream id and asks.
    pub(super) fn replace_own_stream(&mut self, stream: StreamId) {
        self.own_stream = stream;
        let now = self.now_ms();
        let c3: Vec<String> = self
            .caps
            .iter()
            .filter(|(p, c)| *c & CAP_C3_V1 != 0 && self.members.contains(p))
            .map(|(p, _)| p.clone())
            .collect();
        self.provisional
            .retain(|(s, _), _| *s == stream || self.shares.contains_key(s));
        for p in c3 {
            self.provisional.insert((stream, p), now);
        }
        let moved: Vec<(String, crate::transport::realtime_av::ReceiverLayerPolicy)> = self
            .layer_caps
            .iter()
            .filter(|((s, _), _)| *s != stream)
            .map(|((_, c), cap)| (c.clone(), *cap))
            .collect();
        self.layer_caps.retain(|(s, _), _| *s == stream);
        for (child, cap) in moved {
            self.layer_caps.insert((stream, child), cap);
        }
    }

    /// v45 — a publisher's signed `replaces`: `old` is gone in favour of
    /// `new`. Forget `old` (its selector, relay admission and meters); a layer
    /// cap this node asked for `old` carries over to `new`.
    pub(super) fn forget_replaced_stream(&mut self, old: StreamId, new: StreamId) {
        self.sels.remove(&old);
        self.relays.remove(&old);
        self.rates.remove(&old);
        self.forwarded_seen.remove(&old);
        self.min_offset.remove(&old);
        self.last_primary.remove(&old);
        self.told_publisher.remove(&old);
        self.draining_parent.remove(&old);
        self.failing_over.remove(&old);
        self.epochs.remove(&old);
        self.video_unavailable.remove(&old);
        self.layer_caps.retain(|(s, _), _| *s != old);
        if let Some(cap) = self.wanted_layers.remove(&old) {
            self.wanted_layers.insert(new, cap);
        }
    }

    /// v45 — ask this node's parents for `stream` for at most `cap` (`None`:
    /// everything). Kept, and carried on every SUBSCRIBE this node sends a
    /// parent that takes a cap; the current primary gets a re-SUBSCRIBE now
    /// (CC 5.3.3.4: the ask rides the tree), when it takes one.
    pub(super) fn request_layers(
        &mut self,
        stream: StreamId,
        cap: Option<crate::transport::realtime_av::ReceiverLayerPolicy>,
    ) -> Vec<Outgoing> {
        match cap {
            Some(c) => {
                self.wanted_layers.insert(stream, c);
            }
            None => {
                self.wanted_layers.remove(&stream);
            }
        }
        let parent = self.sels.get(&stream).and_then(|s| s.primary().cloned());
        parent
            .filter(|p| self.takes_layer_requests(p))
            .map(|p| Outgoing {
                frame: self.subscribe_frame(stream, &p, Role::Primary),
                to: p,
            })
            .into_iter()
            .collect()
    }

    /// Whether `peer` said it takes a SUBSCRIBE layer cap (and this node's
    /// lever is on).
    pub(super) fn takes_layer_requests(&self, peer: &str) -> bool {
        self.layer_requests
            && self
                .caps
                .get(peer)
                .is_some_and(|c| c & CAP_LAYER_REQUEST != 0)
    }

    /// Scale an admission's headroom (measured bits/s of the stream it
    /// forwards) into the nominal units every selector reasons in.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn nominal(&self, bps: u64, rate: &Rate) -> u64 {
        let (measured, _) = rate.costs();
        let scale = self.cfg.stream_bps as f64 / measured.max(1) as f64;
        // Rounded: exactly one stream of room must read as one stream.
        (bps as f64 * scale).min(u64::MAX as f64 / 2.0).round() as u64
    }

    /// C2 — fold one egress window into every admission on this uplink and
    /// return the sheds it made. While the uplink is stalled (G8) the window
    /// reads congested whatever the (blind) meter said: every relayed stream
    /// and share at one stream's room (that work goes), and this node's own
    /// stream at one stream ABOVE the reserve and whatever the node still
    /// holds elsewhere, so exactly one direct child is kept, never zero.
    #[allow(clippy::cast_precision_loss)] // bits/s, far below 2^52
    fn fold_egress_window(&mut self, now: u64, mut w: EgressWindow) -> Vec<Outgoing> {
        let mut out = Vec::new();
        let one = self.own_rate.costs().0 as f64;
        if self.uplink_stall {
            w.congested = true;
            w.capacity_bps = Some(w.capacity_bps.map_or(one, |c| c.min(one)));
        }
        let streams: Vec<StreamId> = self.relays.keys().copied().collect();
        let mut shed: Vec<(StreamId, String)> = Vec::new();
        for s in streams {
            let ext = self.external_except(s);
            let a = self.relays.get_mut(&s).expect("present");
            a.set_external_committed(ext);
            for p in a.on_egress_window(now, &w, &mut self.log) {
                shed.push((s, p));
            }
        }
        let ext = self.external_except(self.own_stream);
        self.own.set_external_committed(ext);
        let mut own_w = w;
        if self.uplink_stall {
            own_w.capacity_bps = Some(one + self.cfg.reserve_bps as f64 + ext as f64);
        }
        for p in self.own.on_egress_window(now, &own_w, &mut self.log) {
            shed.push((self.own_stream, p));
        }
        // v45 — each share sheds by its own commitments.
        let shares: Vec<StreamId> = self.shares.keys().copied().collect();
        for s in shares {
            let ext = self.external_except(s);
            let (a, _) = self.shares.get_mut(&s).expect("present");
            a.set_external_committed(ext);
            for p in a.on_egress_window(now, &w, &mut self.log) {
                shed.push((s, p));
            }
        }
        for (s, p) in shed {
            self.counts.shed += 1;
            self.label(crate::observability::ALM_SHED);
            out.push(Outgoing {
                to: p,
                frame: encode(
                    s,
                    &ControlMsg::Shed {
                        reason: ShedReason::OverCommitted,
                    },
                ),
            });
        }
        out
    }

    /// One watch tick: egress windows (C2 measurement and over-commit
    /// shedding), selector ticks (C4/C6) with the upstream refresh after
    /// each decision, relay admissions for newly forwarded streams, offers to
    /// `c3_legs` (the C3 members this node can reach), and the publisher
    /// and draining-parent unsubscribes.
    #[allow(clippy::too_many_lines)]
    pub(super) fn tick(&mut self, c3_legs: &[String]) -> Vec<Outgoing> {
        let now = self.now_ms();
        let mut out = std::mem::take(&mut self.pending_out);

        // Measured rates price commitments (production streams are the
        // host's bitrate, not a nominal one).
        if self.own_rate.roll(now) {
            let (full, audio) = self.own_rate.costs();
            self.own.set_role_costs(full, audio);
        }
        for (a, r) in self.shares.values_mut() {
            if r.roll(now) {
                let (full, audio) = r.costs();
                a.set_role_costs(full, audio);
            }
        }
        // Every relayed stream is priced at its measured rate (the floor
        // until media flows), on the same footing as this node's own.
        for (s, a) in &mut self.relays {
            let r = self.rates.entry(*s).or_default();
            if r.roll(now) || r.windows == 0 {
                let (full, audio) = r.costs();
                a.set_role_costs(full, audio);
            }
        }

        // C2: one egress window feeds every admission on this uplink.
        if let Some(w) = self.egress.roll(now) {
            let shed = self.fold_egress_window(now, w);
            out.extend(shed);
        }

        // C4/C6 per stream; the relay's upstream view is refreshed after
        // every decision (the simultaneous-failover loop).
        let streams: Vec<StreamId> = self.sels.keys().copied().collect();
        for s in streams {
            let has_children = self
                .relays
                .get(&s)
                .is_some_and(|a| a.ledger().values().any(|c| c.role == Role::Primary));
            let mut log = std::mem::take(&mut self.log);
            let sel = self.sels.get_mut(&s).expect("present");
            sel.set_has_children(has_children);
            let acts = sel.tick(now, &mut self.rng, &mut log);
            if let Some(failed) = sel.take_failover() {
                self.failing_over.insert(s, failed);
            }
            self.log = log;
            out.extend(self.action_frames(s, acts));
            self.sync_upstream(s);

            let sel = &self.sels[&s];
            let primary = sel.primary().cloned();
            let standby = sel.standby().cloned();
            self.ensure_relay(s);
            if self.last_primary.get(&s) != Some(&primary) {
                if self.last_primary.get(&s).is_some_and(Option::is_some) {
                    self.label(crate::observability::ALM_PARENT_CHANGE);
                }
                self.last_primary.insert(s, primary.clone());
                self.parent_moves.push((s, primary.clone()));
            }
            // The publisher keeps sending a C3 member that has not chosen
            // (the join gap): tell it once this node chose another parent.
            if let (Some(p), Some(publisher)) = (&primary, self.publisher_of.get(&s).cloned()) {
                let uses_publisher = *p == publisher || standby.as_ref() == Some(&publisher);
                if uses_publisher {
                    self.told_publisher.remove(&s);
                } else if self.told_publisher.insert(s) {
                    out.push(Outgoing {
                        to: publisher,
                        frame: encode(
                            s,
                            &ControlMsg::Unsubscribe {
                                subscriber: self.me.clone(),
                            },
                        ),
                    });
                }
            }
            // A parent that shed this node make-before-break keeps sending
            // until told: tell it once the replacement primary is up.
            if let Some(d) = self.draining_parent.get(&s).cloned() {
                if primary.as_ref().is_some_and(|p| *p != d) {
                    self.draining_parent.remove(&s);
                    out.push(Outgoing {
                        to: d,
                        frame: encode(
                            s,
                            &ControlMsg::Unsubscribe {
                                subscriber: self.me.clone(),
                            },
                        ),
                    });
                }
            }
            // §6.5 — audio only on the canonical tier.
            let vu = self.sels[&s].video_unavailable();
            let publisher = self.publisher_of.get(&s).cloned().unwrap_or_default();
            if vu && self.video_unavailable.insert(s) {
                self.events.push(super::CallEvent::VideoUnavailable {
                    publisher,
                    reason: "relay_canonical_audio_only",
                });
            } else if !vu && self.video_unavailable.remove(&s) {
                self.events
                    .push(super::CallEvent::VideoRestored { publisher });
            }
        }

        // Offers (C3) to every C3 member this node can reach, every
        // OFFER_EVERY_MS, stalled or not. Row D1: latched verdict ∧ a leg
        // with nothing unproved → that leg keeps the normal cadence (its
        // Channel traffic is what a dead peer is noticed by: the gap between
        // messages plus the retry ladder); latched ∧ backlogged leg → its
        // offer is held at the send (av_call `send_alm`). Never a blanket
        // hold-back: 5 s on every leg made a dead listener noticed ~4 s late.
        if now.saturating_sub(self.last_offer_ms) >= OFFER_EVERY_MS || self.last_offer_ms == 0 {
            self.last_offer_ms = now.max(1);
            let mut own_offer = self.own.offer();
            // The publisher's upstream latency is its own uplink queue: what
            // a child admitted now waits for its first chunk (the child's
            // selector owes a new subscription that much before calling it
            // silent).
            let queued = self
                .leg_queue_ms
                .values()
                .copied()
                .fold(0.0_f64, f64::max)
                .clamp(0.0, f64::from(u32::MAX));
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                own_offer.upstream_latency_ms =
                    own_offer.upstream_latency_ms.max(queued.round() as u32);
            }
            own_offer.headroom_bps = self.nominal(own_offer.headroom_bps, &self.own_rate);
            own_offer.forwarder_headroom_bps =
                self.nominal(own_offer.forwarder_headroom_bps, &self.own_rate);
            let own_frame = encode(self.own_stream, &ControlMsg::Offer(own_offer));
            let share_frames: Vec<Vec<u8>> = self
                .shares
                .iter()
                .map(|(s, (a, r))| {
                    let mut o = a.offer();
                    o.headroom_bps = self.nominal(o.headroom_bps, r);
                    o.forwarder_headroom_bps = self.nominal(o.forwarder_headroom_bps, r);
                    encode(*s, &ControlMsg::Offer(o))
                })
                .collect();
            let relay_offers: Vec<(StreamId, Vec<String>, Vec<u8>)> = self
                .relays
                .iter()
                .filter(|(_, a)| self.relay_capable && a.forwarding())
                .map(|(s, a)| {
                    let mut o = a.offer();
                    let rate = self.rates.get(s).cloned().unwrap_or_default();
                    o.headroom_bps = self.nominal(o.headroom_bps, &rate);
                    o.forwarder_headroom_bps = self.nominal(o.forwarder_headroom_bps, &rate);
                    let mut skip = o.ancestry.clone();
                    if let Some(p) = self.publisher_of.get(s) {
                        skip.push(p.clone());
                    }
                    (*s, skip, encode(*s, &ControlMsg::Offer(o)))
                })
                .collect();
            // Row B1b: latched verdict ∧ the peer is neither a child here nor
            // a parent this node receives from → its offers go at
            // the liveness minimum, one per STALL_NONCHILD_OFFER_MS; a child
            // keeps the 1 s cadence. Answers are never delayed (they are not
            // offers). Dead detection on such a leg is then ~2 s + the cold
            // retry ladder.
            let children: BTreeSet<String> = if self.uplink_stall {
                self.own_admissions()
                    .flat_map(|(_, a)| a.forwarding_to().into_iter().map(|(p, _)| p))
                    .chain(
                        self.relays
                            .values()
                            .flat_map(|a| a.forwarding_to().into_iter().map(|(p, _)| p)),
                    )
                    // F14a: and every node this one receives a stream from
                    // keeps the 1 s cadence too (its leg's evidence).
                    .chain(self.sels.values().flat_map(|sel| {
                        sel.primary()
                            .cloned()
                            .into_iter()
                            .chain(sel.standby().cloned())
                    }))
                    .collect()
            } else {
                BTreeSet::new()
            };
            let nonchild_every = if self.uplink_stall {
                let keep = c3_legs.iter().filter(|p| children.contains(*p)).count();
                let rest = c3_legs.len().saturating_sub(keep);
                stall_offer_interval_ms(
                    self.own.ceiling_bps(),
                    self.own_rate.costs().0,
                    own_frame.len(),
                    keep,
                    rest,
                )
            } else {
                OFFER_EVERY_MS
            };
            for peer in c3_legs {
                if !self.members.iter().any(|m| m == peer) {
                    continue;
                }
                if self.uplink_stall && !children.contains(peer) {
                    let last = self.offered_at.get(peer).copied().unwrap_or(0);
                    if last != 0 && now.saturating_sub(last) < nonchild_every {
                        continue;
                    }
                }
                self.offered_at.insert(peer.clone(), now.max(1));
                out.push(Outgoing {
                    to: peer.clone(),
                    frame: own_frame.clone(),
                });
                for f in &share_frames {
                    out.push(Outgoing {
                        to: peer.clone(),
                        frame: f.clone(),
                    });
                }
                for (_, skip, f) in &relay_offers {
                    if !skip.contains(peer) {
                        out.push(Outgoing {
                            to: peer.clone(),
                            frame: f.clone(),
                        });
                    }
                }
            }
        }

        // Calls cut — a relay turned off keeps forwarding to its draining
        // children until each unsubscribes or its drain passes; then the
        // emptied admission goes.
        if !self.relay_capable {
            for a in self.relays.values_mut() {
                a.expire_drains(now);
            }
            self.relays.retain(|_, a| !a.forwarding_to().is_empty());
        }

        // Calls cut — `RelayStatus`, on change, once a value has held for a
        // tick (a make-before-break hand-off does not fire twice).
        let status = (self.relay_capable, self.relaying_for());
        if self.relay_status == Some(status) {
            self.relay_status_pending = None;
        } else if self.relay_status_pending == Some(status) {
            self.relay_status = Some(status);
            self.relay_status_pending = None;
            self.events.push(super::CallEvent::RelayStatus {
                relaying: status.0,
                relaying_for: status.1,
            });
        } else {
            self.relay_status_pending = Some(status);
        }
        out
    }

    /// Every stream this node receives, with its chosen parents.
    pub(super) fn parents(&self) -> Vec<AlmParents> {
        self.sels
            .iter()
            .map(|(s, sel)| AlmParents {
                stream: *s,
                publisher: self.publisher_of.get(s).cloned(),
                primary: sel.primary().cloned(),
                standby: sel.standby().cloned(),
                parent_changes: sel.parent_changes(),
            })
            .collect()
    }

    /// Who holds a commitment on this node's own stream, by role.
    pub(super) fn own_children(&self) -> Vec<(String, Role)> {
        self.own_children_of(self.own_stream)
    }

    /// v45 — who holds a commitment on this node's own `stream` (the
    /// primary or a share), by role.
    pub(super) fn own_children_of(&self, stream: StreamId) -> Vec<(String, Role)> {
        self.own_admission(stream)
            .map(|a| {
                a.ledger()
                    .iter()
                    .map(|(p, c)| (p.clone(), c.role))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Who this node forwards `stream` to, by role.
    pub(super) fn relay_children(&self, stream: StreamId) -> Vec<(String, Role)> {
        self.relays
            .get(&stream)
            .map(Admission::forwarding_to)
            .unwrap_or_default()
    }

    /// Commitments, own and relayed (bits/s): the `load_ledger`'s A/V rows.
    pub(super) fn committed(&self) -> (u64, u64) {
        (
            self.own_admissions().map(|(_, a)| a.committed_bps()).sum(),
            self.relays.values().map(Admission::committed_bps).sum(),
        )
    }

    /// The worst relay commitment ratio against the learned ceiling (the
    /// ladder's `edge:relay_commit` signal); 0 while unmeasured.
    #[allow(clippy::cast_precision_loss)]
    pub(super) fn relay_commit_ratio(&self) -> f64 {
        self.relays
            .values()
            .chain(self.own_admissions().map(|(_, a)| a))
            .filter_map(|a| {
                a.ceiling_bps()
                    .filter(|c| *c > 0.0)
                    .map(|c| a.committed_bps() as f64 / c)
            })
            .fold(0.0, f64::max)
    }

    /// Note a decoded frame that did not decode.
    pub(super) fn note_malformed(&mut self, e: wire::WireError) {
        self.counts.c3_malformed += 1;
        self.label(crate::observability::ALM_C3_MALFORMED);
        self.label(e.token());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::realtime_av::ReceiverLayerPolicy;
    use crate::transport::realtime_av_alm::controller::wire::{decode, WireFrame};
    use crate::transport::realtime_av_alm::controller::PeerState;

    fn s(b: u8) -> StreamId {
        StreamId([b; 32])
    }

    fn roster() -> Vec<String> {
        vec!["a".into(), "b".into(), "c".into()]
    }

    fn deliver(to: &mut AlmState, from: &str, frames: &[Outgoing]) -> Vec<Outgoing> {
        let mut out = Vec::new();
        let me = to.me.clone();
        for f in frames.iter().filter(|f| f.to == me) {
            match decode(&f.frame, from).expect("decodes") {
                WireFrame::Caps(c) => {
                    to.on_caps(from, c);
                }
                WireFrame::Control(cf) => out.extend(to.on_control(from, cf, 20.0)),
            }
        }
        out
    }

    /// leviculum#102 — datagrams only toward a peer whose `CAPS` said so: no
    /// `CAPS` yet and a pre-#102 build's `CAPS` (bits 0-2 only) both read as
    /// "no", and the bit changes nothing else a `CAPS` says.
    #[test]
    fn datagrams_only_toward_a_peer_whose_caps_say_so() {
        let mut a = AlmState::new("a", s(1), &roster(), false, 1);
        assert!(!a.takes_datagrams("b"), "no CAPS heard: no datagrams");
        a.on_caps("b", CAP_C3_V1 | CAP_TIMED_FRAMES | CAP_RELAY);
        assert!(
            !a.takes_datagrams("b"),
            "an older edge's CAPS: no datagrams"
        );
        assert!(a.takes_timed("b") && a.speaks_c3("b"));
        a.on_caps("c", CAPS_THIS_BUILD);
        assert!(a.takes_datagrams("c"), "this build's CAPS: datagrams");
        assert!(a.takes_timed("c") && a.speaks_c3("c"));
        assert_ne!(
            CAPS_THIS_BUILD & CAP_LINK_DATAGRAMS,
            0,
            "this build says it"
        );
        // An older decoder masks only the bits it knows: bit 3 reads as nothing.
        let old_known = CAP_C3_V1 | CAP_TIMED_FRAMES | CAP_RELAY;
        assert_eq!(CAP_LINK_DATAGRAMS & old_known, 0, "bit 3 is a fresh bit");
        assert_eq!(
            wire::decode(&encode_caps(CAPS_THIS_BUILD | CAP_RELAY), "c"),
            Ok(WireFrame::Caps(CAPS_THIS_BUILD | CAP_RELAY)),
            "the CAPS frame is still 10 bytes, one u32"
        );
    }

    /// The C3 admit path between two nodes: B learns A's stream from A's
    /// offer, subscribes, A admits, and A's own chunks then go to B (and to
    /// nobody that never subscribed, past the provisional window).
    #[test]
    fn subscribe_admit_and_send_set() {
        let (sa, sb) = (s(1), s(2));
        let mut a = AlmState::new("a", sa, &roster(), false, 1);
        let mut b = AlmState::new("b", sb, &roster(), false, 2);
        a.on_caps("b", CAPS_THIS_BUILD);
        a.on_caps("c", CAPS_THIS_BUILD);
        b.on_caps("a", CAPS_THIS_BUILD);
        b.note_publisher(sa, "a");
        b.note_bound_publisher(sa, "a");
        let legs = vec!["b".to_owned(), "c".to_owned()];
        // Both C3 peers are provisional at first: nobody excluded.
        assert!(a.own_exclude(&legs, false).is_empty());
        let offers = a.tick(&legs);
        let _ = deliver(&mut b, "a", &offers);
        let mut sub = Vec::new();
        for _ in 0..12 {
            std::thread::sleep(Duration::from_millis(100));
            sub.extend(b.tick(&["a".to_owned()]));
        }
        assert!(sub.iter().any(|o| o.to == "a"), "B subscribes to A");
        let decisions = deliver(&mut a, "b", &sub);
        assert!(a
            .own_children()
            .iter()
            .any(|(p, r)| p == "b" && *r == Role::Primary));
        let _ = deliver(&mut b, "a", &decisions);
        assert_eq!(b.parents()[0].primary.as_deref(), Some("a"));
        // C never chose: once the provisional window passes it is excluded.
        a.provisional.insert((a.own_stream, "c".into()), 0);
        a.t0 = Instant::now()
            .checked_sub(Duration::from_millis(PROVISIONAL_MS + 1))
            .expect("the clock is past the window");
        assert_eq!(a.own_exclude(&legs, false), vec!["c".to_owned()]);
    }

    /// v45 — a share is a parent-0 admission of its own: B subscribes to
    /// A's share alone and is A's share child, not its camera child; the
    /// camera's send set is untouched, each stream is offered, and ending
    /// the share leaves the camera's admission and children as they were.
    #[test]
    fn a_share_is_its_own_admission_beside_the_camera() {
        let (cam, share) = (s(1), s(7));
        let mut a = AlmState::new("a", cam, &roster(), false, 1);
        // A loaded box: the share's provisional stamps come some ms after
        // the call's clock started. The window below must be passed from
        // THEIR stamp, not from the clock's start (CIRISEdge 45.1.7: with
        // the reset at exactly PROVISIONAL_MS + 1, any lag of 2 ms or more
        // read C as still fresh).
        std::thread::sleep(Duration::from_millis(5));
        a.on_caps("b", CAPS_THIS_BUILD);
        a.on_caps("c", CAPS_THIS_BUILD);
        a.add_own_stream(share);
        assert!(a.is_own(share) && a.is_own(cam));
        assert_eq!(a.share_streams(), vec![share]);
        let legs = vec!["b".to_owned(), "c".to_owned()];
        assert!(
            a.own_exclude_on(share, &legs, false).is_empty(),
            "every C3 member is provisional on a new share"
        );
        let offers = a.tick(&legs);
        let offered: BTreeSet<StreamId> = offers
            .iter()
            .filter_map(|o| match decode(&o.frame, "a") {
                Ok(WireFrame::Control(cf)) if matches!(cf.msg, ControlMsg::Offer(_)) => {
                    Some(cf.stream)
                }
                _ => None,
            })
            .collect();
        assert_eq!(offered, [cam, share].into_iter().collect(), "both offered");
        let sub = ControlFrame {
            stream: share,
            msg: ControlMsg::Subscribe(SubscribeRequest {
                subscriber: "b".into(),
                role: Role::Primary,
                forward_capable: false,
                layers: None,
            }),
        };
        let out = a.on_control("b", sub, 10.0);
        let WireFrame::Control(cf) = decode(&out[0].frame, "a").unwrap() else {
            panic!()
        };
        assert!(matches!(
            cf.msg,
            ControlMsg::Decision(AdmitDecision::Admit { .. })
        ));
        assert!(a
            .own_children_of(share)
            .iter()
            .any(|(p, r)| p == "b" && *r == Role::Primary));
        assert!(
            a.own_children().is_empty(),
            "the camera's children are its own"
        );
        // Past the window: C never chose either stream, B only the share.
        // Every stamp so far is at or before `lag` on the call's clock.
        let lag = a.now_ms();
        a.t0 = Instant::now()
            .checked_sub(Duration::from_millis(PROVISIONAL_MS + lag + 1))
            .expect("the clock is past the window");
        assert_eq!(a.own_exclude_on(share, &legs, false), vec!["c".to_owned()]);
        assert_eq!(
            a.own_exclude_on(cam, &legs, false),
            legs,
            "nobody took the camera"
        );
        a.remove_own_stream(share);
        assert!(!a.is_own(share) && a.is_own(cam));
        assert!(a.own_children_of(share).is_empty());
        assert_eq!(
            a.own_exclude_on(share, &legs, false),
            legs,
            "an ended share goes to nobody C3"
        );
    }

    /// A refusal names its token; a subscribe to a stream this node does not
    /// forward is refused `relay_upstream_unhealthy`.
    #[test]
    fn refuse_is_named() {
        let mut a = AlmState::new("a", s(1), &roster(), true, 1);
        let f = ControlFrame {
            stream: s(9),
            msg: ControlMsg::Subscribe(SubscribeRequest {
                subscriber: "b".into(),
                role: Role::Primary,
                forward_capable: false,
                layers: None,
            }),
        };
        let out = a.on_control("b", f, 10.0);
        let WireFrame::Control(cf) = decode(&out[0].frame, "a").unwrap() else {
            panic!()
        };
        assert!(matches!(
            cf.msg,
            ControlMsg::Decision(AdmitDecision::Refuse {
                reason: RefuseReason::UpstreamUnhealthy,
                ..
            })
        ));
        assert_eq!(a.counts.refused.get("relay_upstream_unhealthy"), Some(&1));
    }

    /// A non-C3 (legacy) peer is never excluded: it gets the full stream.
    #[test]
    fn legacy_peers_keep_the_full_mesh() {
        let a = AlmState::new("a", s(1), &roster(), false, 1);
        assert!(a.own_exclude(&["b".into(), "c".into()], false).is_empty());
    }

    /// Tier 2 sheds every relayed child LIFO with a named Shed notice.
    #[test]
    fn tier_two_sheds_relayed_children() {
        let mut a = AlmState::new("a", s(1), &roster(), true, 1);
        let mut adm = Admission::relay("a".to_owned(), ControllerConfig::interactive(), None);
        adm.set_members(roster());
        adm.set_upstream(Some(1), vec!["x".into()], true, 10);
        let mut rng = SplitMix64(3);
        let mut log = DecisionLog::default();
        for p in ["b", "c"] {
            let _ = adm.request(
                0,
                &SubscribeRequest {
                    subscriber: p.into(),
                    role: Role::Standby,
                    forward_capable: false,
                    layers: None,
                },
                &mut rng,
                &mut log,
            );
        }
        a.relays.insert(s(7), adm);
        let out = a.set_tier(ServiceTier::ChatAndContacts);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|o| matches!(
            decode(&o.frame, "a"),
            Ok(WireFrame::Control(ControlFrame {
                msg: ControlMsg::Shed {
                    reason: ShedReason::LoadShed
                },
                ..
            }))
        )));
        assert!(a.relays[&s(7)].admit_closed());
    }

    /// A relay with two children (B primary, C standby) on stream 7.
    fn relaying_a() -> AlmState {
        let mut a = AlmState::new("a", s(1), &roster(), true, 1);
        let mut adm = Admission::relay("a".to_owned(), ControllerConfig::interactive(), None);
        adm.set_members(roster());
        adm.set_upstream(Some(1), vec!["x".into()], true, 10);
        let mut rng = SplitMix64(3);
        let mut log = DecisionLog::default();
        // Standbys: a cold relay's one trial slot holds one primary.
        for (p, role) in [("b", Role::Standby), ("c", Role::Standby)] {
            let _ = adm.request(
                0,
                &SubscribeRequest {
                    subscriber: p.into(),
                    role,
                    forward_capable: false,
                    layers: None,
                },
                &mut rng,
                &mut log,
            );
        }
        a.relays.insert(s(7), adm);
        a
    }

    fn sheds(out: &[Outgoing]) -> Vec<(String, ShedReason)> {
        out.iter()
            .filter_map(|o| match decode(&o.frame, "a") {
                Ok(WireFrame::Control(ControlFrame {
                    msg: ControlMsg::Shed { reason },
                    ..
                })) => Some((o.to.clone(), reason)),
                _ => None,
            })
            .collect()
    }

    /// Calls cut — `set_relay(false)` mid-call: every child is shed
    /// make-before-break (told with a code every C3 peer decodes, booked
    /// `relay_shed:relay_off`), forwarding continues to the draining children,
    /// offers stop, `RelayStatus` fires at once, and the emptied relay goes
    /// once the drains pass. `set_relay(true)` reopens.
    #[test]
    fn a_relay_turned_off_hands_its_children_off_and_stops_offering() {
        let mut a = relaying_a();
        assert_eq!(a.relaying_for(), 2);
        let out = a.set_relay(false);
        let mut shed = sheds(&out);
        shed.sort();
        assert_eq!(
            shed,
            vec![
                ("b".to_owned(), ShedReason::UpstreamLost),
                ("c".to_owned(), ShedReason::UpstreamLost)
            ],
            "every child told, on a code an older peer decodes"
        );
        assert!(a.labels.contains(&crate::observability::ALM_RELAY_OFF_SHED));
        assert_eq!(a.caps_bits() & CAP_RELAY, 0, "CAPS no longer names relay");
        assert!(matches!(
            a.events.last(),
            Some(super::super::CallEvent::RelayStatus {
                relaying: false,
                relaying_for: 2
            })
        ));
        // Make-before-break: still forwarding to both while they drain.
        let mut kids = a.relay_children(s(7));
        kids.sort();
        assert_eq!(kids.len(), 2, "{kids:?}");
        // No relay offer goes out while off.
        let out = a.tick(&["b".to_owned(), "c".to_owned()]);
        assert!(
            !out.iter().any(|o| matches!(
                decode(&o.frame, "a"),
                Ok(WireFrame::Control(ControlFrame { stream, msg: ControlMsg::Offer(_) })) if stream == s(7)
            )),
            "no offer of the relayed stream"
        );
        // The drains pass: the relay goes, and the status settles to 0.
        a.t0 = Instant::now()
            .checked_sub(Duration::from_millis(a.cfg.down_silence_ms + 1_000))
            .expect("past the drain");
        let _ = a.tick(&[]);
        let _ = a.tick(&[]);
        assert!(a.relays.is_empty(), "the emptied relay is dropped");
        assert_eq!(a.relaying_for(), 0);
        assert!(a.events.iter().any(|e| matches!(
            e,
            super::super::CallEvent::RelayStatus {
                relaying: false,
                relaying_for: 0
            }
        )));
        // On again: CAPS says so and RelayStatus fires.
        let out = a.set_relay(true);
        assert!(out.is_empty());
        assert_ne!(a.caps_bits() & CAP_RELAY, 0);
        assert!(matches!(
            a.events.last(),
            Some(super::super::CallEvent::RelayStatus {
                relaying: true,
                relaying_for: 0
            })
        ));
    }

    /// Calls cut — `RelayStatus` fires on change, only after a value held
    /// one tick, and never on a repeat.
    #[test]
    fn relay_status_fires_on_change_after_holding_a_tick() {
        let mut a = relaying_a();
        let count = |a: &AlmState| {
            a.events
                .iter()
                .filter(|e| matches!(e, super::super::CallEvent::RelayStatus { .. }))
                .count()
        };
        let _ = a.tick(&[]);
        assert_eq!(count(&a), 0, "a first value waits a tick");
        let _ = a.tick(&[]);
        assert_eq!(count(&a), 1);
        assert!(matches!(
            a.events.last(),
            Some(super::super::CallEvent::RelayStatus {
                relaying: true,
                relaying_for: 2
            })
        ));
        let _ = a.tick(&[]);
        let _ = a.tick(&[]);
        assert_eq!(count(&a), 1, "no repeat");
    }

    /// Calls cut — a serve seat never relays call media, audio included:
    /// turning seat on sheds what it relayed, it never offers relay again,
    /// `set_relay(true)` cannot reopen it, and a relay SUBSCRIBE is refused
    /// (`relay_class_refused` on the wire, `relay_serve_seat` here). Its own
    /// stream is still served.
    #[test]
    fn a_serve_seat_never_relays() {
        let mut a = relaying_a();
        let out = a.set_serve_seat(true);
        assert_eq!(sheds(&out).len(), 2, "what it relayed is handed off");
        assert!(!a.relay_capable());
        assert!(a.set_relay(true).is_empty());
        assert!(!a.relay_capable(), "a seat stays off");
        let sub = |stream| ControlFrame {
            stream,
            msg: ControlMsg::Subscribe(SubscribeRequest {
                subscriber: "b".into(),
                role: Role::Standby,
                forward_capable: false,
                layers: None,
            }),
        };
        let out = a.on_control("b", sub(s(9)), 10.0);
        assert!(matches!(
            decode(&out[0].frame, "a"),
            Ok(WireFrame::Control(ControlFrame {
                msg: ControlMsg::Decision(AdmitDecision::Refuse {
                    reason: RefuseReason::ClassRefused,
                    ..
                }),
                ..
            }))
        ));
        assert!(a
            .labels
            .contains(&crate::observability::ALM_REFUSE_SERVE_SEAT));
        assert!(!a.relays.contains_key(&s(9)), "no relay admission is made");
        // Its own stream is publishing, not relaying.
        a.on_caps("b", CAPS_THIS_BUILD);
        let out = a.on_control("b", sub(s(1)), 10.0);
        assert!(matches!(
            decode(&out[0].frame, "a"),
            Ok(WireFrame::Control(ControlFrame {
                msg: ControlMsg::Decision(AdmitDecision::Admit { .. }),
                ..
            }))
        ));
    }

    /// Calls cut — a receiver drops a serve seat's OFFER for a stream the seat
    /// does not publish: it is never a candidate, and the stream reads
    /// `only_a_seat_offered` (the media-path event's `refused_by_policy`).
    #[test]
    fn a_serve_seats_offer_is_dropped_by_its_receiver() {
        let mut b = AlmState::new("b", s(2), &roster(), true, 2);
        b.set_seats(["c".to_owned()]);
        b.note_publisher(s(1), "a");
        b.note_bound_publisher(s(1), "a");
        let offer = ControlFrame {
            stream: s(1),
            msg: ControlMsg::Offer(crate::transport::realtime_av_alm::controller::Offer {
                from: "c".to_owned(),
                depth: 1,
                ancestry: vec!["a".to_owned()],
                headroom_bps: 1_000_000,
                forwarder_headroom_bps: 1_000_000,
                upstream_latency_ms: 10,
                forwarding: true,
            }),
        };
        let _ = b.on_control("c", offer, 10.0);
        assert_eq!(b.counts.offers_refused, 1);
        assert!(b
            .labels
            .contains(&crate::observability::ALM_OFFER_REFUSED_SERVE_SEAT));
        assert!(!b.member_offers(s(1)));
        assert!(b.only_a_seat_offered(s(1)));
        assert!(b
            .sels
            .get(&s(1))
            .is_none_or(|sel| sel.candidates().iter().all(|(p, _, _)| p != "c")));
    }

    /// G8 — a stalled datagram uplink is congested at one stream's room: the
    /// publisher keeps ONE child and sheds the rest (most recent first), its
    /// offers pause, and the stall is counted once on the rise.
    #[test]
    fn a_stalled_uplink_sheds_the_publisher_to_one_child() {
        let mut a = publisher_with(&["b", "c", "d"]);
        a.set_uplink_stall(true);
        a.set_uplink_stall(true);
        assert_eq!(
            a.labels
                .iter()
                .filter(|l| **l == crate::observability::ALM_UPLINK_STALL)
                .count(),
            1,
            "counted once on the rise"
        );
        let mut out = Vec::new();
        for _ in 0..2 {
            for _ in 0..30 {
                a.on_own_published(600, true);
                a.on_sent("b", 700);
            }
            a.t0 = a.t0.checked_sub(Duration::from_secs(1)).expect("clock");
            out.extend(a.tick(&["b".into(), "c".into(), "d".into()]));
        }
        let kids = a.own_children();
        assert_eq!(kids.len(), 1, "one child kept: {kids:?}");
        assert_eq!(kids[0].0, "b", "the oldest commitment is kept (LIFO shed)");
        let shed: Vec<String> = sheds(&out).into_iter().map(|(p, _)| p).collect();
        assert!(
            shed.contains(&"c".to_owned()) && shed.contains(&"d".to_owned()),
            "{shed:?}"
        );
        // Row D1: the verdict holds back no offers here (a backlogged leg's
        // is held at the send); a leg with nothing outstanding keeps its
        // normal cadence, so a dead peer on it is still noticed in time.
        let offers = out
            .iter()
            .filter(|o| {
                matches!(
                    decode(&o.frame, "a"),
                    Ok(WireFrame::Control(ControlFrame {
                        msg: ControlMsg::Offer(_),
                        ..
                    }))
                )
            })
            .count();
        assert!(offers >= 2, "an offer each window while stalled: {offers}");
    }

    /// G8 — publisher `a` of a four-person room with `kids` children admitted
    /// in order and six seconds of media behind it (its stream has a
    /// measured rate, the last egress window just closed).
    fn publisher_with(kids: &[&str]) -> AlmState {
        let roster4: Vec<String> = vec!["a".into(), "b".into(), "c".into(), "d".into()];
        let mut a = AlmState::new("a", s(1), &roster4, true, 1);
        let mut rng = SplitMix64(5);
        let mut log = DecisionLog::default();
        // Slow start: each child after the probe's two is admitted once a
        // clean window has shown the uplink carrying the ones before it.
        for p in kids {
            let mut d = None;
            for _ in 0..4 {
                let now = a.now_ms();
                let r = a.own.request(
                    now,
                    &SubscribeRequest {
                        subscriber: (*p).into(),
                        role: Role::Primary,
                        forward_capable: true,
                        layers: None,
                    },
                    &mut rng,
                    &mut log,
                );
                if matches!(r, AdmitDecision::Admit { .. }) {
                    d = Some(r);
                    break;
                }
                for _ in 0..30 {
                    a.on_own_published(600, true);
                    a.on_sent("b", 700);
                }
                a.t0 = a.t0.checked_sub(Duration::from_secs(1)).expect("clock");
                let _ = a.tick(&[]);
            }
            assert!(d.is_some(), "{p} admitted within four clean windows");
        }
        for _ in 0..6 {
            for _ in 0..30 {
                a.on_own_published(600, true);
                a.on_sent("b", 700);
            }
            a.t0 = a.t0.checked_sub(Duration::from_secs(1)).expect("clock");
            let _ = a.tick(&[]);
        }
        assert_eq!(a.own_children().len(), kids.len(), "clean uplink: no shed");
        a
    }

    /// G8 — the race the capped matrix lost (CIRISEdge 45.1.9, the loopback
    /// witness on leviculum c75fdeb0): the stall verdict rises between two
    /// egress windows, the stalled legs' links die before the next window
    /// closes, and their detection with them. The shed must go out on the
    /// RISE (one child kept, the newest shed first), and the verdict must
    /// hold for [`UPLINK_STALL_LATCH_MS`] after its last detection, so the
    /// window that closes next still reads the uplink as congested.
    #[test]
    fn a_stall_whose_links_die_before_the_window_closes_still_sheds() {
        let mut a = publisher_with(&["b", "c", "d"]);
        let legs: Vec<String> = vec!["b".into(), "c".into(), "d".into()];
        a.set_uplink_stall(true);
        // The same watch tick: no egress window has closed yet.
        let mut out = a.tick(&legs);
        assert_eq!(
            a.own_children(),
            vec![("b".to_owned(), Role::Primary)],
            "shed at the rise, to the oldest child"
        );
        // The stalled legs are gone a tick later: nothing is detected.
        a.t0 = a.t0.checked_sub(Duration::from_millis(250)).expect("clock");
        a.set_uplink_stall(false);
        assert!(a.uplink_stalled(), "latched past the last detection");
        a.t0 = a.t0.checked_sub(Duration::from_millis(800)).expect("clock");
        a.set_uplink_stall(false);
        for _ in 0..30 {
            a.on_own_published(600, true);
            a.on_sent("b", 700);
        }
        out.extend(a.tick(&legs));
        let shed: Vec<String> = sheds(&out).into_iter().map(|(p, _)| p).collect();
        assert_eq!(
            shed,
            vec!["d".to_owned(), "c".to_owned()],
            "LIFO, once each"
        );
        assert_eq!(a.own_children().len(), 1, "the window keeps one child");
        // The latch ends UPLINK_STALL_LATCH_MS after the last detection.
        a.t0 =
            a.t0.checked_sub(Duration::from_millis(1_000))
                .expect("clock");
        a.set_uplink_stall(false);
        assert!(!a.uplink_stalled(), "released after the latch");
    }

    /// G8 — after a stall verdict nothing widens the publisher's room for
    /// [`STALL_PROBE_HOLD_MS`]: a member refused meanwhile (the demand that
    /// would step the ceiling up a clean window) waits the hold out, then one
    /// step admits it.
    #[test]
    fn no_upward_probe_for_a_hold_after_a_stall() {
        let mut a = publisher_with(&["b"]);
        let mut rng = SplitMix64(9);
        let mut log = DecisionLog::default();
        let c = SubscribeRequest {
            subscriber: "c".to_owned(),
            role: Role::Primary,
            forward_capable: true,
            layers: None,
        };
        let media = |a: &mut AlmState, ms: u64| {
            for _ in 0..30 {
                a.on_own_published(600, true);
                a.on_sent("b", 700);
            }
            a.t0 = a.t0.checked_sub(Duration::from_millis(ms)).expect("clock");
        };
        a.set_uplink_stall(true);
        let _ = a.tick(&[]);
        let mut waited = 0u64;
        while waited + 1_000 < STALL_PROBE_HOLD_MS {
            media(&mut a, 1_000);
            waited += 1_000;
            a.set_uplink_stall(false);
            let _ = a.tick(&[]);
            let now = a.now_ms();
            let d = a.own.request(now, &c, &mut rng, &mut log);
            assert!(
                !matches!(d, AdmitDecision::Admit { .. }),
                "admitted {waited} ms after the stall"
            );
        }
        let mut admitted = false;
        for _ in 0..4 {
            media(&mut a, 1_000);
            a.set_uplink_stall(false);
            let _ = a.tick(&[]);
            let now = a.now_ms();
            if matches!(
                a.own.request(now, &c, &mut rng, &mut log),
                AdmitDecision::Admit { .. }
            ) {
                admitted = true;
                break;
            }
        }
        assert!(admitted, "one step once the hold has passed");
        assert_eq!(a.own_children().len(), 2);
    }

    /// Admit `p` on `a`'s own stream in `role`, forward-capable.
    fn admit_as(a: &mut AlmState, p: &str, role: Role) {
        let mut rng = SplitMix64(7);
        let mut log = DecisionLog::default();
        let now = a.now_ms();
        let d = a.own.request(
            now,
            &SubscribeRequest {
                subscriber: p.into(),
                role,
                forward_capable: true,
                layers: None,
            },
            &mut rng,
            &mut log,
        );
        assert!(matches!(d, AdmitDecision::Admit { .. }), "{p}: {d:?}");
    }

    /// Stall row S1 / E1 — under a latched stall verdict P sends ONE copy of
    /// its stream: a standby child (for an opaque / audio stream a full second
    /// copy) gets nothing until the verdict clears.
    #[test]
    fn a_latched_stall_sends_one_copy_per_stream() {
        let mut a = publisher_with(&["b"]);
        admit_as(&mut a, "c", Role::Standby);
        // Both speak C3 (a pre-C3 peer is served the full mesh as before).
        a.on_caps("b", CAP_C3_V1);
        a.on_caps("c", CAP_C3_V1);
        let legs: Vec<String> = vec!["b".into(), "c".into()];
        a.uplink_stall = true;
        let excluded = a.own_exclude(&legs, true);
        let copies = legs.iter().filter(|l| !excluded.contains(l)).count();
        assert_eq!(copies, 1, "excluded {excluded:?}");
        a.uplink_stall = false;
        assert!(
            a.own_exclude(&legs, true).is_empty(),
            "fed again once it clears"
        );
    }

    /// Stall rows S2, S3 / E2 — a stall shed takes standbys first and never
    /// the last primary (here the standby is the OLDER commitment, so LIFO
    /// alone would shed the primary), and a shed child asking back as a
    /// standby while the verdict holds is refused.
    #[test]
    fn a_stall_shed_keeps_a_primary_and_admits_no_standby() {
        let roster4: Vec<String> = vec!["a".into(), "b".into(), "c".into(), "d".into()];
        let mut a = AlmState::new("a", s(1), &roster4, true, 1);
        admit_as(&mut a, "c", Role::Standby);
        admit_as(&mut a, "b", Role::Primary);
        for _ in 0..6 {
            for _ in 0..30 {
                a.on_own_published(600, true);
                a.on_sent("b", 700);
            }
            a.t0 = a.t0.checked_sub(Duration::from_secs(1)).expect("clock");
            let _ = a.tick(&[]);
        }
        a.set_uplink_stall(true);
        let _ = a.tick(&["b".into(), "c".into()]);
        assert_eq!(a.own_children(), vec![("b".to_owned(), Role::Primary)]);
        let _ = a.on_control(
            "c",
            ControlFrame {
                stream: s(1),
                msg: ControlMsg::Subscribe(SubscribeRequest {
                    subscriber: "c".into(),
                    role: Role::Standby,
                    forward_capable: true,
                    layers: None,
                }),
            },
            10.0,
        );
        assert_eq!(
            a.own_children(),
            vec![("b".to_owned(), Role::Primary)],
            "no standby re-admitted under the verdict"
        );
    }

    /// F14a — a SILENT listener (it publishes nothing) still sends one fresh
    /// Channel message a second on its own leg toward the node it receives a
    /// stream from: its own stream's OFFER, to every C3 leg,
    /// the publisher included. That keeps evidence flowing on both of the
    /// publisher's links to it (leviculum's same-key form).
    #[test]
    fn a_silent_listener_offers_on_its_leg_to_its_parent_each_second() {
        let roster: Vec<String> = vec!["a".into(), "b".into()];
        // Its own uplink is clear (a listener's is not the bottleneck); were
        // it stalled, row B1b keeps a parent at 1 s too.
        let mut b = AlmState::new("b", s(2), &roster, true, 1);
        let mut offers = 0;
        for _ in 0..3 {
            b.t0 = b.t0.checked_sub(Duration::from_secs(1)).expect("clock");
            for o in b.tick(&["a".into()]) {
                if o.to == "a"
                    && matches!(
                        decode(&o.frame, "b"),
                        Ok(WireFrame::Control(ControlFrame {
                            msg: ControlMsg::Offer(_),
                            ..
                        }))
                    )
                {
                    offers += 1;
                }
            }
        }
        assert!(offers >= 3, "one a second toward the parent: {offers}");
    }

    /// Row B1b — under a latched verdict a member that is not a child gets
    /// this node's offers once per STALL_NONCHILD_OFFER_MS; a child keeps the
    /// 1 s cadence.
    #[test]
    fn a_latched_stall_offers_non_children_every_two_seconds() {
        let mut a = publisher_with(&["b"]);
        let (mut to_b, mut to_c) = (0, 0);
        for _ in 0..4 {
            a.t0 = a.t0.checked_sub(Duration::from_secs(1)).expect("clock");
            a.uplink_stall = true;
            for o in a.tick(&["b".into(), "c".into()]) {
                if matches!(
                    decode(&o.frame, "a"),
                    Ok(WireFrame::Control(ControlFrame {
                        msg: ControlMsg::Offer(_),
                        ..
                    }))
                ) {
                    if o.to == "b" {
                        to_b += 1;
                    } else if o.to == "c" {
                        to_c += 1;
                    }
                }
            }
        }
        assert!(to_b >= 4, "the child keeps 1 s: {to_b}");
        assert!(to_c <= 2, "a non-child at 2 s: {to_c}");
    }

    /// Row B2 — the non-children's offer interval fits ¼ of the leftover
    /// capacity, between 2 s and 3.5 s.
    #[test]
    fn the_stall_offer_budget_stretches_non_children_within_bounds() {
        // A roomy leftover: the 2 s floor.
        assert_eq!(
            stall_offer_interval_ms(Some(2_000_000.0), 100_000, 100, 1, 2),
            2_000
        );
        // ~30 kbit/s leftover -> 7.5 kbit/s budget; one kept leg at 1 s
        // (~1.8 kbit/s) leaves ~5.7 for two others: ~0.6 s, so the floor.
        assert_eq!(
            stall_offer_interval_ms(Some(130_000.0), 100_000, 100, 1, 2),
            2_000
        );
        // Many non-children on a thin leftover stretch to the cap.
        assert_eq!(
            stall_offer_interval_ms(Some(104_000.0), 100_000, 100, 1, 10),
            3_500
        );
        assert_eq!(stall_offer_interval_ms(None, 100_000, 100, 1, 2), 2_000);
    }

    /// The ADMIT-as-primary frames in `out`, by recipient.
    fn primary_admits(out: &[Outgoing]) -> Vec<String> {
        out.iter()
            .filter(|o| {
                matches!(
                    decode(&o.frame, "a"),
                    Ok(WireFrame::Control(ControlFrame {
                        msg: ControlMsg::Decision(AdmitDecision::Admit {
                            role: Role::Primary
                        }),
                        ..
                    }))
                )
            })
            .map(|o| o.to.clone())
            .collect()
    }

    /// An ADMIT that could not be delivered leaves no commitment behind.
    #[test]
    fn an_undelivered_admit_releases_its_commitment() {
        let mut a = publisher_with(&["b", "c"]);
        let admit = encode(
            s(1),
            &ControlMsg::Decision(AdmitDecision::Admit {
                role: Role::Primary,
            }),
        );
        a.on_admit_undelivered("c", &admit);
        assert_eq!(a.own_children(), vec![("b".to_owned(), Role::Primary)]);
        // Anything that is not an ADMIT changes nothing.
        let offer_like = encode(
            s(1),
            &ControlMsg::Shed {
                reason: ShedReason::OverCommitted,
            },
        );
        a.on_admit_undelivered("b", &offer_like);
        assert_eq!(a.own_children(), vec![("b".to_owned(), Role::Primary)]);
    }

    /// Row E2, cause: a link close — the publisher's last primary's leg goes
    /// while a standby remains: the standby is promoted at once and told.
    #[test]
    fn a_lost_primary_link_promotes_the_standby() {
        let mut a = publisher_with(&["b"]);
        admit_as(&mut a, "c", Role::Standby);
        a.on_child_link_down("b");
        assert_eq!(a.own_children(), vec![("c".to_owned(), Role::Primary)]);
        assert_eq!(primary_admits(&a.tick(&[])), vec!["c".to_owned()]);
    }

    /// Row E2, cause: an unsubscribe — the same when the last primary leaves.
    #[test]
    fn an_unsubscribing_primary_promotes_the_standby() {
        let mut a = publisher_with(&["b"]);
        admit_as(&mut a, "c", Role::Standby);
        let _ = a.on_control(
            "b",
            ControlFrame {
                stream: s(1),
                msg: ControlMsg::Unsubscribe {
                    subscriber: "b".to_owned(),
                },
            },
            10.0,
        );
        assert_eq!(a.own_children(), vec![("c".to_owned(), Role::Primary)]);
        assert_eq!(primary_admits(&a.tick(&[])), vec!["c".to_owned()]);
    }

    /// G8 — a stalled uplink with ONE child has nothing to shed: the verdict
    /// keeps the last direct path whatever the reserve or the relay work.
    #[test]
    fn a_stall_never_sheds_the_last_child() {
        let mut a = publisher_with(&["b"]);
        a.set_uplink_stall(true);
        let mut out = a.tick(&["b".into()]);
        for _ in 0..3 {
            for _ in 0..30 {
                a.on_own_published(600, true);
                a.on_sent("b", 700);
            }
            a.t0 = a.t0.checked_sub(Duration::from_secs(1)).expect("clock");
            a.set_uplink_stall(true);
            out.extend(a.tick(&["b".into()]));
        }
        assert!(sheds(&out).is_empty(), "{:?}", sheds(&out));
        assert_eq!(a.own_children().len(), 1);
    }

    // ── #945: three real controllers, C3 through the real encoder ────────

    const A: usize = 0;
    const B: usize = 1;
    const C: usize = 2;
    const NAMES: [&str; 3] = ["a", "b", "c"];
    /// One chunk's size on the wire (bytes).
    const CHUNK: u64 = 300;
    /// One media step: a chunk period (ms).
    const STEP_MS: u64 = 20;

    /// A publishes, C relays, B subscribes. Every frame between them is
    /// encoded and decoded as on a link, and which chunk reaches which path
    /// is what `own_exclude` and `forward_exclude` say, so a standby skips
    /// exactly what production skips. Time moves by shifting each clock.
    #[allow(clippy::struct_excessive_bools)] // independent test switches
    struct Mesh {
        nodes: Vec<AlmState>,
        sa: StreamId,
        epoch: u64,
        seq: u64,
        ticks: u64,
        /// Whether C's offers reach B.
        c_offers_to_b: bool,
        /// Withhold every `n`th chunk of A's direct leg to B.
        withhold_b: Option<u64>,
        /// Withhold every `n`th chunk of the relay's leg to B.
        withhold_standby: Option<u64>,
        /// Whether A's leg to B is up.
        a_to_b_up: bool,
        /// A's leg to B is capped at the base layer (a host cap or a C5
        /// shed: the dispatcher filters above it, before the hop counter).
        a_caps_b: bool,
        /// The relay's leg to B is capped at the base layer.
        c_caps_b: bool,
        /// Never send every `n`th base-or-audio chunk on A's leg to B.
        withhold_base_b: Option<u64>,
        /// Base-or-audio chunks A's fan-out has reached B's leg with.
        base_to_b: u64,
        /// Lose every `n`th chunk A's leg to B really sent, on the wire.
        wire_lose_b: Option<u64>,
        /// A's hop counter on the leg to B.
        hop_to_b: u64,
        /// Hop counters B has not seen a chunk for yet.
        hop_gap_b: u64,
    }

    impl Mesh {
        fn new() -> Self {
            let sa = s(1);
            let roster = roster();
            let mut nodes = vec![
                AlmState::new("a", sa, &roster, false, 1),
                AlmState::new("b", s(2), &roster, false, 2),
                AlmState::new("c", s(3), &roster, true, 3),
            ];
            for (i, n) in nodes.iter_mut().enumerate() {
                for (j, peer) in NAMES.iter().enumerate() {
                    if i != j {
                        n.on_caps(peer, CAPS_THIS_BUILD);
                    }
                }
            }
            for n in [B, C] {
                nodes[n].note_publisher(sa, "a");
                nodes[n].note_bound_publisher(sa, "a");
            }
            Self {
                nodes,
                sa,
                epoch: 1,
                seq: 0,
                ticks: 0,
                c_offers_to_b: true,
                withhold_b: None,
                withhold_standby: None,
                a_to_b_up: true,
                a_caps_b: false,
                c_caps_b: false,
                withhold_base_b: None,
                base_to_b: 0,
                wire_lose_b: None,
                hop_to_b: 0,
                hop_gap_b: 0,
            }
        }

        fn advance(&mut self, ms: u64) {
            for n in &mut self.nodes {
                n.t0 =
                    n.t0.checked_sub(Duration::from_millis(ms))
                        .expect("the clock is past the shift");
            }
        }

        fn route(&mut self, mut q: VecDeque<(usize, Outgoing)>) {
            while let Some((from, o)) = q.pop_front() {
                let to = NAMES.iter().position(|n| *n == o.to).expect("a member");
                match decode(&o.frame, NAMES[from]).expect("decodes") {
                    WireFrame::Caps(c) => {
                        self.nodes[to].on_caps(NAMES[from], c);
                    }
                    WireFrame::Control(cf) => {
                        for r in self.nodes[to].on_control(NAMES[from], cf, 20.0) {
                            q.push_back((to, r));
                        }
                    }
                }
            }
        }

        fn tick(&mut self) {
            let mut q = VecDeque::new();
            for i in [A, B, C] {
                let legs: Vec<String> = NAMES
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i && (i != C || *j != B || self.c_offers_to_b))
                    .map(|(_, n)| (*n).to_owned())
                    .collect();
                for o in self.nodes[i].tick(&legs) {
                    q.push_back((i, o));
                }
            }
            self.route(q);
        }

        /// One chunk of A's stream, as the fan-out and the relay send it.
        fn chunk(&mut self, base_or_audio: bool) {
            let (sa, epoch, seq) = (self.sa, self.epoch, self.seq);
            self.seq += 1;
            let at = crate::transport::av_chunk_auth::unix_ms_now();
            // Tier 2: the chunk is sealed, its seq spent, and it goes nowhere.
            if self.nodes[A].tier().own_call_audio_only() && !base_or_audio {
                return;
            }
            let legs = vec!["b".to_owned(), "c".to_owned()];
            let excluded = self.nodes[A].own_exclude(&legs, base_or_audio);
            self.nodes[A].on_own_published(CHUNK, base_or_audio);
            let mut withheld = self.withhold_b.is_some_and(|n| seq % n == 0);
            if base_or_audio {
                self.base_to_b += 1;
                withheld |= self
                    .withhold_base_b
                    .is_some_and(|n| self.base_to_b.is_multiple_of(n));
            }
            let filtered = self.a_caps_b && !base_or_audio;
            if !excluded.contains(&legs[0]) && !withheld && !filtered && self.a_to_b_up {
                self.nodes[A].on_sent("b", CHUNK);
                self.hop_to_b += 1;
                if self
                    .wire_lose_b
                    .is_some_and(|n| self.hop_to_b.is_multiple_of(n))
                {
                    self.hop_gap_b += 1;
                } else {
                    let lost = std::mem::take(&mut self.hop_gap_b);
                    self.nodes[B].on_chunk(sa, "a", epoch, seq, CHUNK, at, base_or_audio, lost);
                }
            }
            if excluded.contains(&legs[1]) {
                return;
            }
            self.nodes[A].on_sent("c", CHUNK);
            self.nodes[C].on_chunk(sa, "a", epoch, seq, CHUNK, at, base_or_audio, 0);
            let c_legs = vec!["a".to_owned(), "b".to_owned()];
            let forward =
                self.nodes[C].forward_exclude(sa, epoch, seq, "a", "a", &c_legs, base_or_audio);
            let dropped = self.withhold_standby.is_some_and(|n| seq % n == 0)
                || (self.c_caps_b && !base_or_audio);
            if forward.is_some_and(|skip| !skip.contains(&c_legs[1])) && !dropped {
                self.nodes[C].on_sent("b", CHUNK);
                self.nodes[B].on_chunk(sa, "c", epoch, seq, CHUNK, at, base_or_audio, 0);
            }
        }

        /// `ms` of media: each period one base-or-audio chunk and
        /// `enhancement` chunks above it, ticking at 10 Hz.
        fn run(&mut self, ms: u64, enhancement: u64, mut each_tick: impl FnMut(&Self)) {
            for _ in 0..ms / STEP_MS {
                self.advance(STEP_MS);
                self.chunk(true);
                for _ in 0..enhancement {
                    self.chunk(false);
                }
                self.ticks += 1;
                if self.ticks.is_multiple_of(5) {
                    self.tick();
                    each_tick(self);
                }
            }
        }

        /// `ms` of A's host starved: it publishes, its links refuse nearly
        /// everything and nothing arrives anywhere (a window sends a trickle
        /// and drops the rest).
        fn starve(&mut self, ms: u64) {
            for _ in 0..ms / STEP_MS {
                self.advance(STEP_MS);
                self.nodes[A].on_own_published(CHUNK, true);
                self.nodes[A].on_sent("b", 1);
                self.nodes[A].on_dropped(CHUNK);
                self.ticks += 1;
                if self.ticks.is_multiple_of(5) {
                    self.tick();
                }
            }
        }

        /// A's stream rolls: a new epoch, `chunk_seq` back to 0.
        fn roll(&mut self) {
            self.epoch += 1;
            self.seq = 0;
        }

        fn b_sel(&self) -> &ParentSelector<String> {
            &self.nodes[B].sels[&self.sa]
        }

        fn b_parents(&self) -> AlmParents {
            self.nodes[B]
                .parents()
                .into_iter()
                .find(|p| p.stream == self.sa)
                .expect("B hears A's stream")
        }

        fn state_of(&self, p: &str) -> Option<PeerState> {
            self.b_sel().state_of(&p.to_owned())
        }
    }

    fn degraded_ticks(states: &[PeerState]) -> usize {
        states.iter().filter(|s| **s == PeerState::Degraded).count()
    }

    fn offer_frame(stream: StreamId, from: &str) -> Vec<u8> {
        wire::encode(
            stream,
            &ControlMsg::Offer(crate::transport::realtime_av_alm::controller::Offer {
                from: from.to_owned(),
                depth: 0,
                ancestry: Vec::new(),
                headroom_bps: 100_000_000,
                forwarder_headroom_bps: 100_000_000,
                upstream_latency_ms: 0,
                forwarding: true,
            }),
        )
    }

    fn is_candidate(sel: &ParentSelector<String>, p: &str) -> bool {
        sel.candidates().iter().any(|(c, _, _)| c == p)
    }

    /// #945 item 2: C claims depth 0 on A's stream and the binding names A.
    /// The claim changes nothing and is logged and counted.
    #[test]
    fn a_depth_zero_offer_from_another_member_is_dropped() {
        let mut m = Mesh::new();
        let frame = offer_frame(m.sa, "c");
        m.route(VecDeque::from([(
            C,
            Outgoing {
                to: "b".into(),
                frame,
            },
        )]));
        assert_eq!(m.nodes[B].parents()[0].publisher.as_deref(), Some("a"));
        assert!(!is_candidate(m.b_sel(), "c"), "never scored");
        assert_eq!(m.nodes[B].counts.offers_refused, 1);
        assert_eq!(m.nodes[B].log_count(DecisionKind::OfferRefused), 1);
        assert!(m.nodes[B].log_tail().contains("not_publisher"));
        assert!(m.nodes[B]
            .labels
            .contains(&crate::observability::ALM_OFFER_REFUSED_NOT_PUBLISHER));
    }

    /// The v44 CI stall, deterministically: a few seconds of a starved host
    /// must not silence a publisher for the rest of its call. The congestion
    /// sheds, as it should; then the stream comes back on the one stream a
    /// publisher always keeps, and the mesh regrows when the ceiling goes
    /// stale. Mutations: with no floor A keeps nobody and offers no room, so
    /// nobody hears it again; with no staleness the ceiling binds for good.
    #[test]
    fn a_starved_publisher_is_heard_again() {
        let mut m = Mesh::new();
        m.run(30_000, 1, |_| {});
        assert_eq!(m.b_parents().primary.as_deref(), Some("a"), "the premise");
        assert_eq!(m.b_parents().standby.as_deref(), Some("c"), "the premise");

        m.starve(8_000);
        assert!(
            m.nodes[A].counts.shed > 0,
            "the premise: A shed: {}",
            m.nodes[A].log_tail()
        );
        assert!(
            !m.nodes[A].own_children().is_empty(),
            "a publisher keeps one child: {}",
            m.nodes[A].log_tail()
        );

        // The stream is back well before the ceiling goes stale.
        m.run(10_000, 1, |_| {});
        let heard = |m: &Mesh, n: usize| {
            m.nodes[n]
                .parents()
                .iter()
                .find(|p| p.stream == m.sa)
                .is_some_and(|p| p.primary.is_some())
        };
        assert!(
            heard(&m, B) && heard(&m, C),
            "both hear A: B {:?}; A {}\nB {}\nC {}",
            m.b_parents(),
            m.nodes[A].log_tail(),
            m.nodes[B].log_tail(),
            m.nodes[C].log_tail()
        );

        // And the direct mesh regrows once the ceiling is stale.
        m.run(
            crate::transport::realtime_av_alm::controller::admission::CEILING_STALE_MS + 20_000,
            1,
            |_| {},
        );
        assert_eq!(
            m.b_parents().primary.as_deref(),
            Some("a"),
            "direct first, again: {}",
            m.nodes[B].log_tail()
        );
        assert_eq!(m.b_parents().standby.as_deref(), Some("c"));
        assert_eq!(m.nodes[A].own_children().len(), 2, "both direct");
    }

    /// #945 item 2: a depth-0 claim that cannot be checked yet is dropped,
    /// and the publisher's next offer, once its binding is in, gets through.
    #[test]
    fn a_depth_zero_offer_waits_for_the_binding() {
        let sa = s(1);
        let mut b = AlmState::new("b", s(2), &roster(), false, 2);
        let offer = |b: &mut AlmState| {
            let WireFrame::Control(cf) = decode(&offer_frame(sa, "a"), "a").unwrap() else {
                panic!()
            };
            b.on_control("a", cf, 20.0);
        };
        offer(&mut b);
        assert!(b.sels.is_empty(), "no selector from an unchecked claim");
        assert_eq!(b.counts.offers_refused, 1);
        assert!(b
            .labels
            .contains(&crate::observability::ALM_OFFER_REFUSED_UNBOUND));
        b.note_bound_publisher(sa, "a");
        offer(&mut b);
        assert!(is_candidate(&b.sels[&sa], "a"));
        assert_eq!(b.counts.offers_refused, 1, "the publisher passes");
    }

    /// #945 item 2: the hello is unsigned, so a member naming another's
    /// stream as its own cannot rename a bound publisher, and a binding
    /// corrects a hello that came first.
    #[test]
    fn a_hello_never_renames_a_bound_publisher() {
        let sa = s(1);
        let mut b = AlmState::new("b", s(2), &roster(), false, 2);
        b.note_publisher(sa, "c");
        assert_eq!(b.parents()[0].publisher.as_deref(), Some("c"));
        b.note_bound_publisher(sa, "a");
        assert_eq!(b.parents()[0].publisher.as_deref(), Some("a"));
        b.note_publisher(sa, "c");
        assert_eq!(b.parents()[0].publisher.as_deref(), Some("a"));
    }

    /// #945 item 1: `chunk_seq` restarts at every roll. Neither path lost
    /// anything, so neither goes Degraded. Mutation: back to one key across
    /// epochs and both read a loss of about 1.0 for the roll's window.
    #[test]
    fn an_epoch_roll_is_a_resync_on_every_path() {
        let mut m = Mesh::new();
        m.run(15_000, 0, |_| {});
        let p = m.b_parents();
        assert_eq!(p.primary.as_deref(), Some("a"), "{p:?}");
        assert_eq!(p.standby.as_deref(), Some("c"), "{p:?}");
        m.roll();
        let (mut primary, mut standby) = (Vec::new(), Vec::new());
        m.run(12_000, 0, |m| {
            primary.extend(m.state_of("a"));
            standby.extend(m.state_of("c"));
        });
        assert_eq!(
            (degraded_ticks(&primary), degraded_ticks(&standby)),
            (0, 0),
            "ticks Degraded after a loss-free roll: primary {primary:?} standby {standby:?}"
        );
    }

    /// #945 item 1, the failover: a roll on a healthy direct primary must not
    /// hand the stream to a relay. C's standby joins just after the roll, so
    /// its meter never saw it: reading the roll as loss leaves the primary
    /// scoring far below a clean standby.
    #[test]
    fn an_epoch_roll_does_not_move_a_direct_primary() {
        let mut m = Mesh::new();
        m.c_offers_to_b = false;
        m.run(15_000, 0, |_| {});
        assert_eq!(m.b_parents().primary.as_deref(), Some("a"));
        assert_eq!(m.b_parents().standby, None);
        m.roll();
        m.c_offers_to_b = true;
        m.run(20_000, 0, |_| {});
        let p = m.b_parents();
        assert_eq!(
            p.standby.as_deref(),
            Some("c"),
            "the standby came up: {p:?}"
        );
        assert_eq!(p.primary.as_deref(), Some("a"), "{p:?}");
        assert_eq!(
            p.parent_changes,
            0,
            "the direct primary stayed: {}",
            m.nodes[B].log_tail()
        );
    }

    /// #945 item 3: a standby gets base and audio only, in a `chunk_seq`
    /// shared with the layers above, so its path shows gaps it never owed.
    #[test]
    fn a_standby_skipping_layers_is_not_a_lossy_path() {
        let mut m = Mesh::new();
        m.run(15_000, 2, |_| {});
        let p = m.b_parents();
        assert_eq!(p.primary.as_deref(), Some("a"), "{p:?}");
        assert_eq!(p.standby.as_deref(), Some("c"), "{p:?}");
        let mut standby = Vec::new();
        m.run(10_000, 2, |m| standby.extend(m.state_of("c")));
        assert_eq!(
            degraded_ticks(&standby),
            0,
            "a clean standby read as Degraded: {standby:?}"
        );
    }

    /// #945 item 3: a standby that really drops base chunks still measures
    /// as lossy. Mutation: ignoring a standby's gaps with nothing in their
    /// place reads it as clean, and it would out-score an honest primary.
    #[test]
    fn a_standby_that_drops_base_chunks_is_lossy() {
        let mut m = Mesh::new();
        m.run(15_000, 2, |_| {});
        assert_eq!(m.b_parents().standby.as_deref(), Some("c"));
        m.withhold_standby = Some(4);
        let mut standby = Vec::new();
        m.run(6_000, 2, |m| standby.extend(m.state_of("c")));
        assert!(
            degraded_ticks(&standby) > 0,
            "a quarter of the base chunks lost on the standby: {standby:?}"
        );
    }

    /// #945 item 3, the takeover: A's direct leg to B really loses chunks and
    /// C's standby path loses none. The primary is Degraded, so direct-first
    /// no longer holds it, and the clean standby takes over by score. With a
    /// standby's skipped layers read as loss it can never win.
    /// v44 — the decision log is the record; the ledger is told from it, so
    /// the counter and a replayed log cannot disagree. A's direct path goes
    /// silent while the stream runs on through C.
    #[test]
    fn a_failover_reaches_the_ledger_with_its_gap_and_cause() {
        let mut m = Mesh::new();
        m.run(15_000, 2, |_| {});
        assert_eq!(m.b_parents().primary.as_deref(), Some("a"));
        m.withhold_b = Some(1);
        m.run(20_000, 2, |_| {});
        let b = &mut m.nodes[B];
        let failovers = b.log_count(DecisionKind::Failover);
        assert!(failovers >= 1, "{}", b.log_tail());
        b.labels.clear();
        b.book_decisions();
        let booked = |labels: &[&str]| {
            labels
                .iter()
                .filter(|l| **l == crate::observability::ALM_FAILOVER)
                .count() as u64
        };
        assert_eq!(booked(&b.labels), failovers);
        b.labels.clear();
        b.book_decisions();
        assert_eq!(booked(&b.labels), 0, "booked once, never twice");
        let (cause, gap) = b.gaps.pop().expect("the new parent's chunk closed the gap");
        assert_eq!(cause, crate::telemetry::FailoverCause::LinkDown);
        assert!(
            gap >= std::time::Duration::from_millis(100),
            "the gap runs from when the old primary was last heard: {gap:?}"
        );
        assert!(b.failing_over.is_empty());
    }

    #[test]
    fn every_decision_the_ledger_names_reaches_it() {
        use crate::observability as o;
        let mut a = AlmState::new("a", s(0), &roster(), false, 1);
        let me = "a".to_owned();
        for kind in [
            DecisionKind::Switch,
            DecisionKind::LoopDetected,
            DecisionKind::OverClaim,
            DecisionKind::Admit,
        ] {
            a.log.record(0, &me, kind, None, 0, "test");
        }
        a.book_decisions();
        assert_eq!(
            a.labels,
            vec![o::ALM_SWITCH, o::ALM_LOOP_DETECTED, o::ALM_OVER_CLAIM]
        );
    }

    #[test]
    fn a_newer_epoch_is_one_resync_per_stream() {
        let mut a = AlmState::new("a", s(0), &roster(), false, 1);
        a.on_chunk(s(1), "b", 1, 5, 100, 0, true, 0);
        assert!(a.labels.is_empty(), "the first epoch seen is no resync");
        a.on_chunk(s(1), "c", 2, 0, 100, 0, true, 0);
        a.on_chunk(s(1), "b", 2, 0, 100, 0, true, 0);
        a.on_chunk(s(1), "b", 1, 6, 100, 0, true, 0);
        let n = a
            .labels
            .iter()
            .filter(|l| **l == crate::observability::ALM_EPOCH_RESYNC)
            .count();
        assert_eq!(n, 1);
    }

    #[test]
    fn a_lossy_primary_gives_way_to_a_clean_layered_standby() {
        let mut m = Mesh::new();
        m.run(15_000, 2, |_| {});
        assert_eq!(m.b_parents().standby.as_deref(), Some("c"));
        m.withhold_b = Some(4);
        m.run(30_000, 2, |_| {});
        let p = m.b_parents();
        assert!(
            p.parent_changes > 0,
            "the clean standby took over: {p:?}\n{}",
            m.nodes[B].log_tail()
        );
    }

    /// #945 finding A: a closed link is a hard signal. B fails over on the
    /// next tick, with no time for silence to pass, to the standby that is
    /// still delivering. Mutation: `PeerHealth::update` reading "subscribed"
    /// as "heard" flips Down to Recovering and no failover comes.
    #[test]
    fn a_primary_link_close_fails_over_at_once() {
        let mut m = Mesh::new();
        m.run(15_000, 2, |_| {});
        let p = m.b_parents();
        assert_eq!(p.primary.as_deref(), Some("a"), "{p:?}");
        assert_eq!(p.standby.as_deref(), Some("c"), "{p:?}");

        m.a_to_b_up = false;
        m.nodes[B].on_parent_link_down("a");
        m.tick();
        let (p, log) = (m.b_parents(), m.nodes[B].log_tail());
        assert_eq!(
            m.nodes[B].log_count(DecisionKind::Failover),
            1,
            "one tick after the close, with no silence: {log}"
        );
        assert_eq!(p.primary.as_deref(), Some("c"), "{p:?}\n{log}");
        assert_eq!(p.parent_changes, 1, "{p:?}\n{log}");
    }

    /// #945 finding A: a link that comes back before the failover does not
    /// strand a parent in Down: a chunk that really arrives clears it.
    #[test]
    fn a_closed_link_that_delivers_again_recovers() {
        let mut m = Mesh::new();
        m.run(15_000, 2, |_| {});
        m.nodes[B].on_parent_link_down("a");
        assert_eq!(m.state_of("a"), Some(PeerState::Down));
        m.advance(STEP_MS);
        m.chunk(true);
        m.tick();
        assert_eq!(m.state_of("a"), Some(PeerState::Recovering));
        assert_eq!(m.nodes[B].log_count(DecisionKind::Failover), 0);
    }

    /// B's primary A and standby C, with A's leg carrying `enhancement`
    /// layers above the base.
    fn settled(enhancement: u64) -> Mesh {
        let mut m = Mesh::new();
        m.run(15_000, enhancement, |_| {});
        let p = m.b_parents();
        assert_eq!(p.primary.as_deref(), Some("a"), "{p:?}");
        assert_eq!(p.standby.as_deref(), Some("c"), "{p:?}");
        m
    }

    /// Run on and give A's health per tick, the parents staying put.
    fn primary_states(m: &mut Mesh, ms: u64, enhancement: u64) -> Vec<PeerState> {
        let mut states = Vec::new();
        m.run(ms, enhancement, |m| states.extend(m.state_of("a")));
        states
    }

    /// #945 finding B: a leg capped at the base layer, by a C5 shed or a host
    /// cap, skips the layers above it. The dispatcher filters them before the
    /// hop counter and the standby delivers nothing A did not, so it is no
    /// loss, the parents stay, and the cap's end changes nothing either.
    #[test]
    fn a_primary_capped_at_the_base_layer_reads_no_loss() {
        let mut m = settled(2);
        m.a_caps_b = true;
        let capped = primary_states(&mut m, 20_000, 2);
        m.a_caps_b = false;
        let restored = primary_states(&mut m, 10_000, 2);
        assert_eq!(degraded_ticks(&capped), 0, "capped: {capped:?}");
        assert_eq!(degraded_ticks(&restored), 0, "restored: {restored:?}");
        let p = m.b_parents();
        assert_eq!(p.primary.as_deref(), Some("a"), "{p:?}");
        assert_eq!(p.parent_changes, 0, "{}", m.nodes[B].log_tail());
    }

    /// #945 finding B: at tier 2 a publisher seals its layers and sends them
    /// to nobody. No path owed them.
    #[test]
    fn a_publisher_shedding_its_own_layers_reads_no_loss_anywhere() {
        let mut m = settled(2);
        let _ = m.nodes[A].set_tier(ServiceTier::ChatAndContacts);
        let (mut primary, mut standby) = (Vec::new(), Vec::new());
        m.run(20_000, 2, |m| {
            primary.extend(m.state_of("a"));
            standby.extend(m.state_of("c"));
        });
        assert_eq!(degraded_ticks(&primary), 0, "primary: {primary:?}");
        assert_eq!(degraded_ticks(&standby), 0, "standby: {standby:?}");
        assert_eq!(m.b_parents().parent_changes, 0);
    }

    /// #945 finding B: the other side of the two above. A capped leg that
    /// really drops base chunks reads lossy and gives way to the clean
    /// standby. The chunks are never sent, so no hop counter shows them: only
    /// the standby's delivery of what A went past does. Mutation: dropping
    /// that reading makes this path clean, and the call stays on it.
    #[test]
    fn a_capped_primary_that_drops_base_chunks_is_lossy() {
        let mut m = settled(2);
        m.a_caps_b = true;
        m.withhold_base_b = Some(4);
        let states = primary_states(&mut m, 30_000, 2);
        assert!(degraded_ticks(&states) > 0, "{states:?}");
        assert!(
            m.b_parents().parent_changes > 0,
            "{}",
            m.nodes[B].log_tail()
        );
    }

    /// #945 finding B: the same drop on an uncapped primary, one base chunk in
    /// four among two enhancement layers each. Reading it over every chunk
    /// that arrived would dilute it below the threshold: base and audio are
    /// measured against base and audio.
    #[test]
    fn dropped_base_chunks_are_not_diluted_by_the_layers_above() {
        let mut m = settled(8);
        m.withhold_base_b = Some(6);
        let states = primary_states(&mut m, 12_000, 8);
        assert!(degraded_ticks(&states) > 0, "{states:?}");
    }

    /// #945 finding B: with no second path, the hop counter is the reading: a
    /// sent chunk that never arrived is loss whatever its layer, here on a
    /// capped leg where every `chunk_seq` gap also means nothing. Mutation:
    /// ignoring `hop_lost` reads this path clean.
    #[test]
    fn a_sole_capped_path_reads_its_hop_gaps() {
        let mut m = Mesh::new();
        m.c_offers_to_b = false;
        m.run(15_000, 2, |_| {});
        assert_eq!(m.b_parents().primary.as_deref(), Some("a"));
        assert_eq!(m.b_parents().standby, None);
        m.a_caps_b = true;
        m.wire_lose_b = Some(5);
        let states = primary_states(&mut m, 8_000, 2);
        assert!(degraded_ticks(&states) > 0, "{states:?}");
    }

    /// #945 finding B: at the call layer `full` was the link's role, so a
    /// make-before-break confirmed on any chunk. C can only send B the base
    /// layer, so promoting it would lose the video: it must not confirm.
    #[test]
    fn a_make_before_break_does_not_confirm_on_base_chunks() {
        let mut m = settled(2);
        m.c_caps_b = true;
        m.withhold_b = Some(4);
        m.run(30_000, 2, |_| {});
        let log = m.nodes[B].log_tail();
        assert_eq!(m.nodes[B].log_count(DecisionKind::Switch), 0, "{log}");
        assert!(
            m.nodes[B].log_count(DecisionKind::PromoteStart) > 0,
            "{log}"
        );
        assert!(log.contains("promote failed"), "{log}");
        assert_eq!(m.b_parents().primary.as_deref(), Some("a"), "{log}");
    }

    /// #945 finding B: a stream with nothing above the base has no other
    /// chunk to confirm on. Mutation: requiring an enhancement chunk strands
    /// every audio-only call on a lossy parent.
    #[test]
    fn a_make_before_break_confirms_when_nothing_is_layered() {
        let mut m = settled(0);
        m.withhold_b = Some(4);
        m.run(30_000, 0, |_| {});
        let log = m.nodes[B].log_tail();
        assert!(m.nodes[B].log_count(DecisionKind::Switch) > 0, "{log}");
        assert!(m.b_parents().parent_changes > 0, "{log}");
    }

    /// A SUBSCRIBE for `stream` in `role` to `to`, carrying `cap`.
    fn subscribe_with(
        stream: StreamId,
        to: &str,
        role: Role,
        cap: Option<ReceiverLayerPolicy>,
    ) -> Outgoing {
        Outgoing {
            to: to.to_owned(),
            frame: encode(
                stream,
                &ControlMsg::Subscribe(SubscribeRequest {
                    subscriber: String::new(),
                    role,
                    forward_capable: false,
                    layers: cap,
                }),
            ),
        }
    }

    /// v45 — a receiver's layer cap rides its SUBSCRIBE to its parent and
    /// caps what the parent sends that child alone: A (the publisher) drops
    /// B's copies above (0, 0, 0) and sends C everything; a relay (C)
    /// applies a cap for a stream it forwards the same way; audio passes
    /// every cap; a node that does not parent the stream keeps nothing; and a
    /// re-SUBSCRIBE without a cap withdraws it.
    #[test]
    fn a_subscribe_layer_cap_caps_that_child_alone() {
        use crate::transport::realtime_av::{ChunkLayer, CODEC_AV1_SVC, CODEC_OPAQUE};
        let mut m = settled(1);
        let sa = m.sa;
        // The host turned the lever on everywhere (off by default).
        for (i, n) in m.nodes.iter_mut().enumerate() {
            n.set_layer_requests(true);
            for (j, peer) in NAMES.iter().enumerate() {
                if i != j {
                    let c = n.caps[*peer] | CAP_LAYER_REQUEST;
                    n.caps.insert((*peer).to_owned(), c);
                }
            }
        }
        let base = ChunkLayer::BASE;
        let upper = ChunkLayer {
            spatial: 1,
            temporal: 0,
            quality: 0,
        };
        let kids = vec!["b".to_owned(), "c".to_owned()];
        assert!(
            m.nodes[A]
                .layer_exclude(sa, &kids, CODEC_AV1_SVC, upper)
                .is_empty(),
            "the premise: nobody asked"
        );
        // B asks its parent (A) for the base layer only: a re-SUBSCRIBE.
        let out = m.nodes[B].request_layers(sa, Some(ReceiverLayerPolicy::BLINKING_DOT));
        assert_eq!(
            out.iter().map(|o| o.to.as_str()).collect::<Vec<_>>(),
            ["a"],
            "one hop, to the primary"
        );
        assert!(
            matches!(
                decode(&out[0].frame, "b"),
                Ok(WireFrame::Control(ControlFrame {
                    msg: ControlMsg::Subscribe(SubscribeRequest {
                        role: Role::Primary,
                        layers: Some(ReceiverLayerPolicy::BLINKING_DOT),
                        ..
                    }),
                    ..
                }))
            ),
            "the cap rides the tree's own SUBSCRIBE"
        );
        m.route(out.into_iter().map(|o| (B, o)).collect());
        assert_eq!(m.b_parents().primary.as_deref(), Some("a"), "B stays on A");
        let a = &m.nodes[A];
        assert_eq!(a.layer_exclude(sa, &kids, CODEC_AV1_SVC, upper), ["b"]);
        assert!(a.layer_exclude(sa, &kids, CODEC_AV1_SVC, base).is_empty());
        assert!(
            a.layer_exclude(sa, &kids, CODEC_OPAQUE, base).is_empty(),
            "audio passes"
        );
        // A relay applies it for a stream it forwards (B's standby there:
        // the re-SUBSCRIBE keeps B's role).
        assert!(
            m.nodes[C].relays.contains_key(&sa),
            "the premise: C forwards A"
        );
        let cap = ReceiverLayerPolicy {
            max_spatial: 0,
            max_temporal: 1,
            max_quality: 0,
        };
        let _ = deliver(
            &mut m.nodes[C],
            "b",
            &[subscribe_with(sa, "c", Role::Standby, Some(cap))],
        );
        let legs = vec!["a".to_owned(), "b".to_owned()];
        let t2 = ChunkLayer {
            spatial: 0,
            temporal: 2,
            quality: 0,
        };
        assert_eq!(
            m.nodes[C].layer_exclude(sa, &legs, CODEC_AV1_SVC, t2),
            ["b"]
        );
        assert!(m.nodes[C]
            .layer_exclude(sa, &legs, CODEC_AV1_SVC, base)
            .is_empty());
        // Not a parent of the stream: kept nowhere.
        let other = s(9);
        let _ = deliver(
            &mut m.nodes[A],
            "b",
            &[subscribe_with(other, "a", Role::Primary, Some(cap))],
        );
        assert!(m.nodes[A]
            .layer_exclude(other, &kids, CODEC_AV1_SVC, t2)
            .is_empty());
        // Withdrawn: everything again.
        let out = m.nodes[B].request_layers(sa, None);
        m.route(out.into_iter().map(|o| (B, o)).collect());
        assert!(m.nodes[A]
            .layer_exclude(sa, &kids, CODEC_AV1_SVC, upper)
            .is_empty());
    }

    /// v45 — off by default: no node advertises the bit, puts a cap on a
    /// SUBSCRIBE or applies one. On, a parent whose `CAPS` lack the bit never
    /// gets a cap; the cap waits, and rides the next SUBSCRIBE to a parent
    /// that takes it.
    #[test]
    fn a_layer_cap_waits_for_a_parent_that_takes_it() {
        use crate::transport::realtime_av::{ChunkLayer, CODEC_AV1_SVC};
        let mut m = settled(1);
        let sa = m.sa;
        assert_eq!(
            m.nodes[A].caps_bits() & CAP_LAYER_REQUEST,
            0,
            "off by default"
        );
        let cap = ReceiverLayerPolicy::BLINKING_DOT;
        assert!(
            m.nodes[B].request_layers(sa, Some(cap)).is_empty(),
            "the lever is off"
        );
        let _ = deliver(
            &mut m.nodes[A],
            "b",
            &[subscribe_with(sa, "a", Role::Primary, Some(cap))],
        );
        let b = vec!["b".to_owned()];
        let upper = ChunkLayer {
            spatial: 1,
            temporal: 0,
            quality: 0,
        };
        assert!(
            m.nodes[A]
                .layer_exclude(sa, &b, CODEC_AV1_SVC, upper)
                .is_empty(),
            "an off node applies nothing"
        );
        m.nodes[B].set_layer_requests(true);
        m.nodes[B]
            .caps
            .insert("a".into(), CAP_C3_V1 | CAP_TIMED_FRAMES);
        assert!(
            m.nodes[B].request_layers(sa, Some(cap)).is_empty(),
            "A did not say it takes them"
        );
        assert_eq!(m.nodes[B].wanted_layers.get(&sa), Some(&cap), "kept");
        // A parent that takes it gets it on the next SUBSCRIBE.
        m.nodes[B]
            .caps
            .insert("c".into(), CAPS_THIS_BUILD | CAP_LAYER_REQUEST);
        let f = m.nodes[B].subscribe_frame(sa, "c", Role::Standby);
        assert!(matches!(
            decode(&f, "b"),
            Ok(WireFrame::Control(ControlFrame {
                msg: ControlMsg::Subscribe(SubscribeRequest {
                    layers: Some(_),
                    ..
                }),
                ..
            }))
        ));
        let f = m.nodes[B].subscribe_frame(sa, "a", Role::Primary);
        assert!(matches!(
            decode(&f, "b"),
            Ok(WireFrame::Control(ControlFrame {
                msg: ControlMsg::Subscribe(SubscribeRequest { layers: None, .. }),
                ..
            }))
        ));
    }

    /// The relay-on N=4 room of the server's av_mesh runs, on the production
    /// [`AlmState`] with an injected clock: every member publishes 30 Hz of
    /// opaque (all-"audio") chunks and offers relay; C3 frames are routed at
    /// once; each node's uplink is a per-second byte budget (a rate cap), and
    /// a stalled receiver delays delivery without limiting any rate.
    mod mesh4 {
        use super::*;
        use std::collections::{BTreeMap, HashSet};

        const N: usize = 4;
        const NAMES: [&str; N] = ["a", "b", "c", "d"];
        const CHUNK: u64 = 300;
        const STEP_MS: u64 = 33;
        /// One stream, as a rate: 30 chunks/s of `CHUNK` bytes.
        const STREAM_BYTES_PER_S: u64 = 30 * CHUNK;

        /// A delivery held back by a stalled receiver: released at `at`.
        struct Held {
            at: u64,
            from: usize,
            to: usize,
            stream: usize,
            seq: u64,
            source_ms: u64,
        }

        pub(super) struct World {
            nodes: Vec<AlmState>,
            streams: [StreamId; N],
            now: u64,
            steps: u64,
            seq: [u64; N],
            /// Per node: bytes/s its uplink carries (`None`: unlimited).
            pub(super) cap: [Option<u64>; N],
            window_start: u64,
            window_bytes: [u64; N],
            /// A receiver whose deliveries (and acks) are held back until the
            /// end of each stall, `(node, from_ms, to_ms)`, repeating.
            pub(super) stall: Option<(usize, Vec<(u64, u64)>)>,
            held: Vec<Held>,
            /// What each member heard of each stream: `(rx, stream) -> seqs`.
            heard: BTreeMap<(usize, usize), HashSet<u64>>,
            /// Each stream's chunks by when they were published.
            published: Vec<Vec<(u64, u64)>>,
        }

        impl World {
            pub(super) fn new() -> Self {
                let roster: Vec<String> = NAMES.iter().map(|n| (*n).to_owned()).collect();
                let streams = [s(1), s(2), s(3), s(4)];
                let mut nodes: Vec<AlmState> = (0..N)
                    .map(|i| AlmState::new(NAMES[i], streams[i], &roster, true, i as u64 + 1))
                    .collect();
                for (i, n) in nodes.iter_mut().enumerate() {
                    for (j, peer) in NAMES.iter().enumerate() {
                        if i != j {
                            n.on_caps(peer, CAPS_THIS_BUILD | CAP_RELAY);
                            n.note_publisher(streams[j], peer);
                            n.note_bound_publisher(streams[j], peer);
                        }
                    }
                }
                Self {
                    nodes,
                    streams,
                    now: 0,
                    steps: 0,
                    seq: [0; N],
                    cap: [None; N],
                    window_start: 0,
                    window_bytes: [0; N],
                    stall: None,
                    held: Vec::new(),
                    heard: BTreeMap::new(),
                    published: vec![Vec::new(); N],
                }
            }

            fn legs(i: usize) -> Vec<String> {
                (0..N)
                    .filter(|j| *j != i)
                    .map(|j| NAMES[j].to_owned())
                    .collect()
            }

            fn idx(name: &str) -> usize {
                NAMES.iter().position(|n| *n == name).expect("a member")
            }

            fn stalled(&self, rx: usize) -> Option<u64> {
                let (node, spans) = self.stall.as_ref()?;
                if *node != rx {
                    return None;
                }
                spans
                    .iter()
                    .find(|(from, to)| self.now >= *from && self.now < *to)
                    .map(|(_, to)| *to)
            }

            /// `from` puts one chunk of stream `stream` on its leg to `to`:
            /// within its uplink's budget it is accepted, and delivered now or,
            /// to a stalled receiver, when the stall ends.
            fn send(&mut self, from: usize, to: usize, stream: usize, seq: u64, source_ms: u64) {
                if let Some(cap) = self.cap[from] {
                    if self.window_bytes[from] + CHUNK > cap {
                        self.nodes[from].on_dropped(CHUNK);
                        return;
                    }
                }
                self.window_bytes[from] += CHUNK;
                if let Some(until) = self.stalled(to) {
                    // The stalled peer acks late: the link backs up and, now
                    // and then, refuses a frame (one per stalled second).
                    self.nodes[from].set_leg_queue_ms(NAMES[to], 400.0);
                    if seq.is_multiple_of(30) {
                        self.nodes[from].on_dropped(CHUNK);
                        return;
                    }
                    self.nodes[from].on_sent(NAMES[to], CHUNK);
                    self.held.push(Held {
                        at: until,
                        from,
                        to,
                        stream,
                        seq,
                        source_ms,
                    });
                    return;
                }
                self.nodes[from].set_leg_queue_ms(NAMES[to], 0.0);
                self.nodes[from].on_sent(NAMES[to], CHUNK);
                self.nodes[from].on_delivered(CHUNK);
                self.arrive(from, to, stream, seq, source_ms);
            }

            fn arrive(&mut self, from: usize, to: usize, stream: usize, seq: u64, source_ms: u64) {
                let st = self.streams[stream];
                self.nodes[to].on_chunk(st, NAMES[from], 1, seq, CHUNK, source_ms, true, 0);
                if self.heard.entry((to, stream)).or_default().insert(seq) {
                    // First copy: forward it where this node is a parent.
                    let legs = Self::legs(to);
                    let skip = self.nodes[to].forward_exclude(
                        st,
                        1,
                        seq,
                        NAMES[from],
                        NAMES[stream],
                        &legs,
                        true,
                    );
                    if let Some(skip) = skip {
                        for l in legs.iter().filter(|l| !skip.contains(l)) {
                            let k = Self::idx(l);
                            self.send(to, k, stream, seq, source_ms);
                        }
                    }
                }
            }

            fn release_held(&mut self) {
                let now = self.now;
                let (due, rest): (Vec<Held>, Vec<Held>) = std::mem::take(&mut self.held)
                    .into_iter()
                    .partition(|h| h.at <= now);
                self.held = rest;
                for h in due {
                    self.nodes[h.from].on_delivered(CHUNK);
                    self.arrive(h.from, h.to, h.stream, h.seq, h.source_ms);
                }
            }

            fn route(&mut self, mut q: VecDeque<(usize, Outgoing)>) {
                while let Some((from, o)) = q.pop_front() {
                    let to = Self::idx(&o.to);
                    match decode(&o.frame, NAMES[from]).expect("decodes") {
                        WireFrame::Caps(c) => {
                            self.nodes[to].on_caps(NAMES[from], c);
                        }
                        WireFrame::Control(cf) => {
                            for r in self.nodes[to].on_control(NAMES[from], cf, 20.0) {
                                q.push_back((to, r));
                            }
                        }
                    }
                }
            }

            fn tick(&mut self) {
                let mut q = VecDeque::new();
                for i in 0..N {
                    let _ = self.nodes[i].set_tier(ServiceTier::FullOps);
                    for o in self.nodes[i].tick(&Self::legs(i)) {
                        q.push_back((i, o));
                    }
                }
                self.route(q);
            }

            fn step(&mut self) {
                self.now += STEP_MS;
                self.steps += 1;
                for n in &mut self.nodes {
                    n.t0 =
                        n.t0.checked_sub(Duration::from_millis(STEP_MS))
                            .expect("the clock is past the shift");
                }
                if self.now >= self.window_start + 1_000 {
                    self.window_start = self.now;
                    self.window_bytes = [0; N];
                }
                self.release_held();
                let at = crate::transport::av_chunk_auth::unix_ms_now();
                for i in 0..N {
                    let seq = self.seq[i];
                    self.seq[i] += 1;
                    self.published[i].push((self.now, seq));
                    let legs = Self::legs(i);
                    let excluded = self.nodes[i].own_exclude(&legs, true);
                    self.nodes[i].on_own_published(CHUNK, true);
                    for l in legs.iter().filter(|l| !excluded.contains(l)) {
                        let k = Self::idx(l);
                        self.send(i, k, i, seq, at);
                    }
                }
                if self.steps.is_multiple_of(5) {
                    self.tick();
                }
            }

            pub(super) fn run_until(&mut self, ms: u64) {
                while self.now < ms {
                    self.step();
                }
            }

            /// Share of `stream`'s chunks published in `[from, to)` that
            /// every other member heard (the worst member).
            #[allow(clippy::cast_precision_loss)]
            pub(super) fn worst_heard(&self, stream: usize, from: u64, to: u64) -> f64 {
                let owed: Vec<u64> = self.published[stream]
                    .iter()
                    .filter(|(t, _)| *t >= from && *t < to)
                    .map(|(_, s)| *s)
                    .collect();
                (0..N)
                    .filter(|rx| *rx != stream)
                    .map(|rx| {
                        let got = self.heard.get(&(rx, stream));
                        let n = owed
                            .iter()
                            .filter(|s| got.is_some_and(|g| g.contains(s)))
                            .count();
                        n as f64 / owed.len().max(1) as f64
                    })
                    .fold(1.0, f64::min)
            }

            pub(super) fn sheds(&self) -> u64 {
                self.nodes.iter().map(|n| n.counts.shed).sum()
            }

            pub(super) fn shed_by(&self, i: usize) -> u64 {
                self.nodes[i].counts.shed
            }

            pub(super) fn tail(&self) -> String {
                self.nodes
                    .iter()
                    .map(|n| format!("--- {} ---\n{}", n.me, n.log_tail()))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        }

        /// A stall is not a cap: one member's acks stop for 1.5 s every 10 s
        /// (a busy host), with its links backing up past the old 150 ms bar
        /// and refusing a frame a second while it lasts, and no uplink has
        /// any rate limit. Nobody sheds and everyone hears everything. The
        /// avmesh4n/avmesh4rel shape. Mutation (v45.0.0 meter): the backed-up
        /// legs made every sender's uplink "congested", each learned its send
        /// rate as a ceiling, and shed.
        #[test]
        fn n4_a_stall_sheds_nobody() {
            let mut w = World::new();
            let spans = (2..6u64)
                .map(|k| (k * 10_000, k * 10_000 + 1_500))
                .collect();
            w.stall = Some((3, spans));
            w.run_until(60_000);
            assert_eq!(w.sheds(), 0, "a stall shed someone\n{}", w.tail());
            for st in 0..N {
                // A refused frame is a lost frame: the stall costs its few.
                let h = w.worst_heard(st, 10_000, 58_000);
                assert!(h >= 0.99, "stream {st} heard {h}\n{}", w.tail());
            }
        }

        /// A real cap sheds, and recovers once lifted: `a`'s uplink carries
        /// two and a half streams from 20 s to 50 s (it owes three). `a`
        /// sheds; within the bound after the lift every member hears `a`'s
        /// stream whole again. Mutation (v45.0.0): the ceiling stood until
        /// stale (60-240 s), nobody asked, and the shed members stayed shed.
        #[test]
        fn n4_a_rate_cap_sheds_and_recovers_within_the_bound() {
            /// Lift to whole again, at most.
            const BOUND_MS: u64 = 20_000;
            let mut w = World::new();
            w.run_until(20_000);
            assert_eq!(w.shed_by(0), 0, "the premise: no shed before the cap");
            w.cap[0] = Some(STREAM_BYTES_PER_S * 5 / 2);
            w.run_until(50_000);
            assert!(w.shed_by(0) > 0, "a real cap sheds\n{}", w.tail());
            w.cap[0] = None;
            w.run_until(50_000 + BOUND_MS + 20_000);
            let h = w.worst_heard(0, 50_000 + BOUND_MS, 50_000 + BOUND_MS + 18_000);
            assert!(
                h >= 0.999,
                "a's stream heard {h} from {BOUND_MS} ms after the lift\n{}",
                w.tail()
            );
        }
    }
}
