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
//!   other members' C3 `SUBSCRIBE`s. A small room starts as the full mesh it
//!   always was (the publisher's probe allowance is the room, up to
//!   [`PUBLISHER_INITIAL_FANOUT`]); measured congestion then sheds the most
//!   recent subscribers to member relays (T7).
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
    self, encode, encode_caps, CAPS_THIS_BUILD, CAP_C3_V1, CAP_RELAY, CAP_TIMED_FRAMES,
};
use crate::transport::realtime_av_alm::controller::{
    Admission, AdmitDecision, ChunkPos, ControlFrame, ControlMsg, ControllerConfig, DecisionKind,
    DecisionLog, EgressMeter, ParentSelector, PathChunk, RefuseReason, Role, SelectorAction,
    ShedReason, SplitMix64, SubscribeRequest,
};

/// How often a forwarder offers each stream it can serve.
pub(super) const OFFER_EVERY_MS: u64 = 1_000;
/// The publisher's starting probe allowance, in streams: a small room is
/// served as the full mesh it was; measurement then rules.
pub(super) const PUBLISHER_INITIAL_FANOUT: u64 = 8;
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
    /// before its binding arrived, dropped.
    pub offers_refused: u64,
}

/// The call's ALM controller state (see the module docs).
pub(super) struct AlmState {
    me: String,
    cfg: ControllerConfig,
    t0: Instant,
    rng: SplitMix64,
    log: DecisionLog,
    own_stream: StreamId,
    own: Admission<String>,
    relay_capable: bool,
    relays: BTreeMap<StreamId, Admission<String>>,
    sels: BTreeMap<StreamId, ParentSelector<String>>,
    publisher_of: BTreeMap<StreamId, String>,
    /// The publisher each stream's verified binding names: the one signed
    /// source. `publisher_of` follows it, and a hello cannot override it.
    bound_publisher: BTreeMap<StreamId, String>,
    caps: BTreeMap<String, u32>,
    provisional: BTreeMap<String, u64>,
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
    pub(super) events: Vec<super::CallEvent>,
}

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
        let fanout = (members.len().saturating_sub(1) as u64).clamp(1, PUBLISHER_INITIAL_FANOUT);
        own.set_probe_streams(fanout);
        Self {
            me: me.to_owned(),
            egress: EgressMeter::new(cfg.meter_window_ms, cfg.congestion_queue_ms),
            cfg,
            t0: Instant::now(),
            rng: SplitMix64(seed),
            log: DecisionLog::new(64),
            own_stream,
            own,
            relay_capable,
            relays: BTreeMap::new(),
            sels: BTreeMap::new(),
            publisher_of: BTreeMap::new(),
            bound_publisher: BTreeMap::new(),
            caps: BTreeMap::new(),
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
            events: Vec::new(),
        }
    }

    /// The call's monotonic clock (ms).
    pub(super) fn now_ms(&self) -> u64 {
        u64::try_from(self.t0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// This node's capability bits.
    pub(super) fn caps_bits(&self) -> u32 {
        CAPS_THIS_BUILD | if self.relay_capable { CAP_RELAY } else { 0 }
    }

    /// This node's `CAPS` frame.
    pub(super) fn caps_frame(&self) -> Vec<u8> {
        encode_caps(self.caps_bits())
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
        for a in self.relays.values_mut() {
            a.set_members(members.iter().cloned());
        }
        for s in self.sels.values_mut() {
            s.set_members(members.iter().cloned());
        }
        self.caps.retain(|p, _| members.contains(p));
        self.provisional.retain(|p, _| members.contains(p));
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
        let p = peer.to_owned();
        self.own.release(&p);
        for a in self.relays.values_mut() {
            a.release(&p);
        }
        self.provisional.remove(peer);
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
            if self.own.role_of(&peer.to_owned()).is_none() {
                self.provisional.insert(peer.to_owned(), now);
            }
            self.label(crate::observability::ALM_C3_PEER_CAPABLE);
        }
        first
    }

    /// `publisher` publishes `stream` (its own link's hello names it). The
    /// hello is unsigned, so this is a first guess: a binding overrides it
    /// and it never overrides a binding.
    pub(super) fn note_publisher(&mut self, stream: StreamId, publisher: &str) {
        if stream == self.own_stream || publisher == self.me {
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
        if stream == self.own_stream {
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
        self.sels.entry(stream).or_insert_with(|| {
            let mut s = ParentSelector::new(me, cfg, fc);
            s.set_members(members);
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

    /// This node published `bytes` of its own stream.
    pub(super) fn on_own_published(&mut self, bytes: u64, base_or_audio: bool) {
        self.own_rate.add(bytes, base_or_audio);
    }

    /// The members this node's own chunk must NOT go to, among `legs`: C3
    /// peers that hold no commitment (and are past the provisional window),
    /// and standby children for a chunk above the base layer.
    pub(super) fn own_exclude(&self, legs: &[String], base_or_audio: bool) -> Vec<String> {
        let now = self.now_ms();
        legs.iter()
            .filter(|p| {
                if !self.speaks_c3(p) {
                    return false;
                }
                match self.own.role_of(p) {
                    Some(Role::Primary) => false,
                    Some(Role::Standby) => !base_or_audio,
                    None => {
                        let fresh = self
                            .provisional
                            .get(*p)
                            .is_some_and(|t| now.saturating_sub(*t) < PROVISIONAL_MS);
                        let draining = self.own.is_draining(p);
                        !(fresh || draining)
                    }
                }
            })
            .cloned()
            .collect()
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
                p != from && p != publisher && (*role == Role::Primary || base_or_audio)
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
        if stream == self.own_stream {
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

    fn external_for(&self, stream: Option<StreamId>) -> u64 {
        let own = if stream.is_none() {
            0
        } else {
            self.own.committed_bps()
        };
        own + self
            .relays
            .iter()
            .filter(|(s, _)| Some(**s) != stream)
            .map(|(_, a)| a.committed_bps())
            .sum::<u64>()
    }

    fn action_frames(
        &mut self,
        stream: StreamId,
        acts: Vec<SelectorAction<String>>,
    ) -> Vec<Outgoing> {
        let fc = self.relay_capable;
        acts.into_iter()
            .map(|a| match a {
                SelectorAction::Subscribe { parent, role } => Outgoing {
                    frame: encode(
                        stream,
                        &ControlMsg::Subscribe(SubscribeRequest {
                            subscriber: self.me.clone(),
                            role,
                            forward_capable: fc,
                        }),
                    ),
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
                let (decision, preempted) = if stream == self.own_stream {
                    self.provisional.remove(peer);
                    let ext = self.external_for(None);
                    self.own.set_external_committed(ext);
                    let d = self.own.request(now, &req, &mut self.rng, &mut self.log);
                    (d, self.own.take_preempted())
                } else if self.relays.contains_key(&stream) {
                    let ext = self.external_for(Some(stream));
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
                let p = peer.to_owned();
                if stream == self.own_stream {
                    self.provisional.remove(peer);
                    self.own.release(&p);
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
                if stream == self.own_stream || !self.members.iter().any(|m| m == peer) {
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
        (bps as f64 * scale).min(u64::MAX as f64 / 2.0) as u64
    }

    /// One watch tick: egress windows (C2 measurement and over-commit
    /// shedding), selector ticks (C4/C6) with the upstream refresh after
    /// each decision, relay admissions for newly forwarded streams, offers to
    /// `c3_legs` (the C3 members this node can reach), and the publisher
    /// and draining-parent unsubscribes.
    #[allow(clippy::too_many_lines)]
    pub(super) fn tick(&mut self, c3_legs: &[String]) -> Vec<Outgoing> {
        let now = self.now_ms();
        let mut out = Vec::new();

        // Measured rates price commitments (production streams are the
        // host's bitrate, not a nominal one).
        if self.own_rate.roll(now) {
            let (full, audio) = self.own_rate.costs();
            self.own.set_role_costs(full, audio);
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
            let streams: Vec<StreamId> = self.relays.keys().copied().collect();
            let mut shed: Vec<(StreamId, String)> = Vec::new();
            for s in streams {
                let ext = self.external_for(Some(s));
                let a = self.relays.get_mut(&s).expect("present");
                a.set_external_committed(ext);
                for p in a.on_egress_window(now, &w, &mut self.log) {
                    shed.push((s, p));
                }
            }
            let ext = self.external_for(None);
            self.own.set_external_committed(ext);
            for p in self.own.on_egress_window(now, &w, &mut self.log) {
                shed.push((self.own_stream, p));
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
            // A relay admission for every stream this node receives, when it
            // offers relay.
            if self.relay_capable && primary.is_some() && !self.relays.contains_key(&s) {
                let mut a = Admission::relay(self.me.clone(), self.cfg.clone(), None);
                let (full, audio) = self.rates.get(&s).cloned().unwrap_or_default().costs();
                a.set_role_costs(full, audio);
                a.set_members(self.members.iter().cloned());
                a.set_admit_closed(!self.tier.admits_new_relay_work());
                self.relays.insert(s, a);
                self.sync_upstream(s);
            }
            if self.last_primary.get(&s) != Some(&primary) {
                if self.last_primary.get(&s).is_some_and(Option::is_some) {
                    self.label(crate::observability::ALM_PARENT_CHANGE);
                }
                self.last_primary.insert(s, primary.clone());
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

        // Offers (C3) to every C3 member this node can reach.
        if now.saturating_sub(self.last_offer_ms) >= OFFER_EVERY_MS || self.last_offer_ms == 0 {
            self.last_offer_ms = now.max(1);
            let mut own_offer = self.own.offer();
            own_offer.headroom_bps = self.nominal(own_offer.headroom_bps, &self.own_rate);
            own_offer.forwarder_headroom_bps =
                self.nominal(own_offer.forwarder_headroom_bps, &self.own_rate);
            let own_frame = encode(self.own_stream, &ControlMsg::Offer(own_offer));
            let relay_offers: Vec<(StreamId, Vec<String>, Vec<u8>)> = self
                .relays
                .iter()
                .filter(|(_, a)| a.forwarding())
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
            for peer in c3_legs {
                if !self.members.iter().any(|m| m == peer) {
                    continue;
                }
                out.push(Outgoing {
                    to: peer.clone(),
                    frame: own_frame.clone(),
                });
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
        self.own
            .ledger()
            .iter()
            .map(|(p, c)| (p.clone(), c.role))
            .collect()
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
            self.own.committed_bps(),
            self.relays.values().map(Admission::committed_bps).sum(),
        )
    }

    /// The worst relay commitment ratio against the learned ceiling (the
    /// ladder's `edge:relay_commit` signal); 0 while unmeasured.
    #[allow(clippy::cast_precision_loss)]
    pub(super) fn relay_commit_ratio(&self) -> f64 {
        self.relays
            .values()
            .chain(std::iter::once(&self.own))
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
        a.provisional.insert("c".into(), 0);
        a.t0 = Instant::now()
            .checked_sub(Duration::from_millis(PROVISIONAL_MS + 1))
            .expect("the clock is past the window");
        assert_eq!(a.own_exclude(&legs, false), vec!["c".to_owned()]);
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
                    .is_some_and(|n| self.base_to_b % n == 0);
            }
            let filtered = self.a_caps_b && !base_or_audio;
            if !excluded.contains(&legs[0]) && !withheld && !filtered && self.a_to_b_up {
                self.nodes[A].on_sent("b", CHUNK);
                self.hop_to_b += 1;
                if self.wire_lose_b.is_some_and(|n| self.hop_to_b % n == 0) {
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
                if self.ticks % 5 == 0 {
                    self.tick();
                    each_tick(self);
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
        a.on_chunk(s(1), "b", 1, 5, 100, 0, true);
        assert!(a.labels.is_empty(), "the first epoch seen is no resync");
        a.on_chunk(s(1), "c", 2, 0, 100, 0, true);
        a.on_chunk(s(1), "b", 2, 0, 100, 0, true);
        a.on_chunk(s(1), "b", 1, 6, 100, 0, true);
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
}
