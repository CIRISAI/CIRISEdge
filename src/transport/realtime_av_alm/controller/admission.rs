//! C2 — admission, for the publisher ("parent 0") and every relay alike.
//!
//! ```text
//!   usable = min(commit_fraction · advertised, measured) − committed − reserve
//! ```
//!
//! - **advertised** is the forwarder's own claim (operator cap / signed ad);
//!   absent = unbounded.
//! - **measured** is the uplink's demonstrated capacity from the uplink
//!   meter's verdict ([`super::EgressMeter`], `docs/AV_ALM_DESIGN.md` §5.1):
//!   the p10 delivery rate of the backpressured windows of a 30 s span in
//!   which the uplink, not a leg or a moment, was the bottleneck, with a 0.75
//!   margin. Each verdict replaces it, up or down. Until the first verdict it
//!   is unknown, and growth is gated by a **probe allowance**
//!   instead: the demonstrated clean floor plus an allowance that starts at
//!   ONE stream (the cold-start trial slot, so an unmeasured relay is not
//!   zero) and doubles after each clean window in which it was used.
//! - **One margin per measurement** (§5.1): `commit_fraction` (0.65) applies
//!   to an advertised claim; a measurement already carries the meter's
//!   [`MEASURED_MARGIN`] (0.75 of the p10 it demonstrated), so the limit is
//!   `min(0.65 · advertised, measured)`.
//! - **committed** is a live ledger keyed by subscriber (primary = stream
//!   rate, standby = audio rate), not static config.
//!
//! A measured ceiling is an estimate of a moment, not a property of the
//! uplink: one that stands [`CEILING_STALE_MS`] with no congested verdict from
//! the uplink meter is
//! forgotten and growth goes back to the probe allowance
//! (`docs/AV_ALM_DESIGN.md` §5.1, "a ceiling gone stale"). Nothing else could
//! lift it: it rises only on a window that sent more than it, and a forwarder
//! that was shed down to its ceiling, and offers no room, sends less. A
//! forwarder flagged for over-claiming keeps its ceiling.
//!
//! A clean window in which someone is waiting (a capacity refusal since the
//! last step) raises a measured ceiling by one stream of committable room:
//! additive increase. The ask is the probe; the next verdict takes it back if
//! the uplink really is full.
//!
//! A publisher's ceiling is never read below one stream. Every relay can be
//! replaced by another path; the publisher cannot, so with no child its
//! stream reaches nobody and no relay has anything to offer. Only the
//! measurement gives way: an advertised cap and the uplink's other streams
//! still bind.
//!
//! A forwarder whose ceiling drops below its commitments sheds the most
//! recent admittee first (LIFO, deterministic) until it fits. One whose claim
//! exceeds its measurement by `over_claim_ratio` is flagged
//! ([`DecisionKind::OverClaim`]) — a signal for the slow reputation loop; the
//! fast loop is already safe because it commits against the min.
//!
//! Upstream path: a relay with no healthy, delivering upstream refuses, a
//! child past `max_depth` is refused, and the requester may not be in this
//! forwarder's ancestry. While a child could itself forward
//! (`depth + 1 < max_depth`), a forward-capable primary that does not fit
//! **preempts** the most recent non-forwarding commitments (standbys first,
//! then leaf primaries), so leaves that joined first cannot strand relays
//! below the depth where they can forward. A static reserve
//! (`forwarder_reserve_fraction`) also exists but is off by default: it idles
//! capacity once every relay is placed.
//!
//! ## Stage 2 (`FSD/CIRIS_MESH.md` §4, §6.4, §7)
//!
//! - **Class policy** ([`ClassPolicy`]): a canonical refuses video outright
//!   ([`RefuseReason::ClassRefused`], V1) and commits audio only up to 5 %
//!   of its measured (or advertised) capacity with no trial slot (V2).
//! - **Forwarder kind** ([`ForwarderKind`]): a non-member TRANSPORT forwarder
//!   (the canonical, a contact) is not a room member and never a tree node;
//!   it carries member-to-member links 1:1. With `max_children = 1` a second
//!   downstream leg of one stream is refused `relay_nonmember_fanout` (M2).
//! - **Admit-close** ([`Admission::set_admit_closed`]): the service tier
//!   refuses new relay work ([`RefuseReason::AdmitClosed`]).
//! - **One uplink, many streams** ([`Admission::set_external_committed`]):
//!   a node's other admissions' commitments count against this one's limit.
//! - **Measured role costs** ([`Admission::set_role_costs`]): production
//!   prices a commitment at the stream's measured rate, not a nominal one.
//! - **Make-before-break shed** ([`Admission::shed_all_draining`]): a load
//!   shed keeps forwarding to the shed subscriber until it unsubscribes or
//!   `down_silence_ms` passes, so the move loses no frames (LS4).

use std::collections::{BTreeMap, BTreeSet};

use super::decision_log::{DecisionKind, DecisionLog};
use super::path_meter::EgressWindow;
use super::{
    AdmitDecision, ControllerConfig, JitterSource, Offer, PeerRef, RefuseReason, Role,
    SubscribeRequest,
};

/// One ledger entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commitment {
    /// The role admitted.
    pub role: Role,
    /// Bits/s committed.
    pub bps: u64,
    /// Admission order (LIFO shed key).
    pub order: u64,
    /// Whether the subscriber said it can forward.
    pub forward_capable: bool,
}

const MAX_PROBE_STREAMS: u64 = 16;

/// What kind of forwarder an admission speaks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForwarderKind {
    /// A room member: the publisher or a member relay (an ALM tree node).
    #[default]
    Member,
    /// A non-member transport forwarder (the canonical, a contact): carries
    /// one member's link to another 1:1, never a tree node. It needs no
    /// upstream of its own (the link IS the path to the far end) and is not
    /// on the roster; its requesters must be.
    Transport,
}

/// A forwarder's per-class policy (`FSD/CIRIS_MESH.md` §6.4).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClassPolicy {
    /// Whether the full stream (video) may be committed. `false` refuses
    /// every primary with [`RefuseReason::ClassRefused`].
    pub video: bool,
    /// Commit fraction for this forwarder in place of `commit_fraction`
    /// (the canonical's audio ceiling, 5 %).
    pub fraction: Option<f64>,
    /// Whether an unmeasured forwarder gets the cold-start trial slot.
    pub trial_slot: bool,
    /// Most subscribers at once (`Some(1)`: a non-member forwards one link
    /// of a stream, never a fan-out, M2).
    pub max_children: Option<usize>,
}

impl Default for ClassPolicy {
    fn default() -> Self {
        Self {
            video: true,
            fraction: None,
            trial_slot: true,
            max_children: None,
        }
    }
}

impl ClassPolicy {
    /// The canonical (§6.4 V1/V2): never video, audio within 5 % of
    /// measured, no trial slot.
    #[must_use]
    pub fn canonical() -> Self {
        Self {
            video: false,
            fraction: Some(0.05),
            trial_slot: false,
            max_children: None,
        }
    }

    /// A non-member contact forwarding a room's call (§4.4 M2): one
    /// downstream leg per stream.
    #[must_use]
    pub fn nonmember_forwarder() -> Self {
        Self {
            max_children: Some(1),
            ..Self::default()
        }
    }
}

/// A shed subscriber still being forwarded to until it moves (LS4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Drain {
    role: Role,
    until_ms: u64,
}

/// The margin on a measured capacity (`docs/AV_ALM_DESIGN.md` §5.1, §6
/// "give grace, stay safe"): the uplink meter commits 0.75 of the p10 rate it
/// demonstrated, and admission adds no `commit_fraction` on top. An
/// advertised claim, which nothing demonstrated, still takes
/// `commit_fraction` (0.65).
pub const MEASURED_MARGIN: f64 = super::path_meter::UPLINK_SAFETY_MARGIN;

/// How long a measured ceiling stands with no congested window before it is
/// stale. Each ceiling learned again waits twice as long, up to
/// [`CEILING_STALE_MAX_MS`], so a really limited uplink costs its subscribers
/// a move rarely, not every half minute (react fast, recover slowly).
pub const CEILING_STALE_MS: u64 = 60_000;
/// The longest a ceiling stands before it is stale.
pub const CEILING_STALE_MAX_MS: u64 = 120_000;

/// C2 admission for one forwarder and one stream.
// Independent state flags (root, upstream health, probe demand, over-claim
// latch), not a mode enum in disguise.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct Admission<P: PeerRef> {
    me: P,
    cfg: ControllerConfig,
    is_root: bool,
    advertised_bps: Option<u64>,
    ceiling_bps: Option<f64>,
    ceiling_stale_ms: u64,
    last_congested_ms: u64,
    floor_bps: f64,
    probe_bps: f64,
    clean_streak: u32,
    demand: bool,
    preempted: Vec<P>,
    over_claim_flagged: bool,
    ledger: BTreeMap<P, Commitment>,
    order: u64,
    depth: Option<u8>,
    ancestry: Vec<P>,
    upstream_healthy: bool,
    upstream_latency_ms: u32,
    members: BTreeSet<P>,
    kind: ForwarderKind,
    class: ClassPolicy,
    admit_closed: bool,
    external_committed: u64,
    draining: BTreeMap<P, Drain>,
}

impl<P: PeerRef> Admission<P> {
    /// The room roster (membership gate). Fail-closed: until set, and for
    /// anyone outside it, every request is refused [`RefuseReason::NotMember`];
    /// a forwarder outside its own roster offers nothing. Leaving the room
    /// does not shed existing children here (the call layer closes their
    /// legs on epoch roll); it stops new admissions.
    pub fn set_members(&mut self, members: impl IntoIterator<Item = P>) {
        self.members = members.into_iter().collect();
    }

    /// Whether `p` is in the roster.
    #[must_use]
    pub fn is_member(&self, p: &P) -> bool {
        self.members.contains(p)
    }

    /// Admission for the publisher (depth 0, always has its stream).
    #[must_use]
    pub fn publisher(me: P, cfg: ControllerConfig, advertised_bps: Option<u64>) -> Self {
        let mut a = Self::relay(me, cfg, advertised_bps);
        a.is_root = true;
        a.depth = Some(0);
        a.upstream_healthy = true;
        a
    }

    /// Admission for a relay (no upstream until [`Self::set_upstream`]).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn relay(me: P, cfg: ControllerConfig, advertised_bps: Option<u64>) -> Self {
        let probe = cfg.stream_bps as f64;
        Self {
            me,
            cfg,
            is_root: false,
            advertised_bps,
            ceiling_bps: None,
            ceiling_stale_ms: CEILING_STALE_MS,
            last_congested_ms: 0,
            floor_bps: 0.0,
            probe_bps: probe,
            clean_streak: 0,
            demand: false,
            preempted: Vec::new(),
            over_claim_flagged: false,
            ledger: BTreeMap::new(),
            order: 0,
            depth: None,
            ancestry: Vec::new(),
            upstream_healthy: false,
            upstream_latency_ms: 0,
            members: BTreeSet::new(),
            kind: ForwarderKind::Member,
            class: ClassPolicy::default(),
            admit_closed: false,
            external_committed: 0,
            draining: BTreeMap::new(),
        }
    }

    /// Admission for a non-member TRANSPORT forwarder (the canonical, or a
    /// contact) under `class`. It is always "forwarding" (the far end of each
    /// link is its upstream) and sits at depth 0 of the path it carries.
    #[must_use]
    pub fn transport(
        me: P,
        cfg: ControllerConfig,
        advertised_bps: Option<u64>,
        class: ClassPolicy,
    ) -> Self {
        let mut a = Self::relay(me, cfg, advertised_bps);
        a.kind = ForwarderKind::Transport;
        a.class = class;
        a.depth = Some(0);
        a.upstream_healthy = true;
        a
    }

    /// Set this forwarder's class policy.
    pub fn set_class_policy(&mut self, class: ClassPolicy) {
        self.class = class;
    }

    /// The class policy.
    #[must_use]
    pub fn class_policy(&self) -> ClassPolicy {
        self.class
    }

    /// The forwarder kind.
    #[must_use]
    pub fn kind(&self) -> ForwarderKind {
        self.kind
    }

    /// Admit-close (`FSD/CIRIS_MESH.md` §7.2): while closed, every request
    /// that would grow a commitment is refused [`RefuseReason::AdmitClosed`].
    /// Existing commitments are untouched (shedding is a separate lever).
    pub fn set_admit_closed(&mut self, closed: bool) {
        self.admit_closed = closed;
    }

    /// Whether admission is closed.
    #[must_use]
    pub fn admit_closed(&self) -> bool {
        self.admit_closed
    }

    /// Bits/s the node's OTHER admissions (its other streams) have committed
    /// on the same uplink: subtracted from this one's limit.
    pub fn set_external_committed(&mut self, bps: u64) {
        self.external_committed = bps;
    }

    /// Price commitments at measured rates: a primary costs `stream_bps`, a
    /// standby `standby_bps`. Re-prices the ledger (production measures the
    /// stream it forwards; the sim keeps the nominal config).
    #[allow(clippy::cast_precision_loss)]
    pub fn set_role_costs(&mut self, stream_bps: u64, standby_bps: u64) {
        // The probe allowance is counted in streams: it keeps its count.
        let old = self.cfg.stream_bps.max(1) as f64;
        self.probe_bps *= stream_bps.max(1) as f64 / old;
        self.cfg.stream_bps = stream_bps.max(1);
        self.cfg.standby_bps = standby_bps.max(1).min(self.cfg.stream_bps);
        for c in self.ledger.values_mut() {
            c.bps = self.cfg.role_bps(c.role);
        }
    }

    /// Grow the unmeasured probe allowance to `streams` full streams (a
    /// publisher starts a small room as a full mesh; measurement then rules).
    #[allow(clippy::cast_precision_loss)]
    pub fn set_probe_streams(&mut self, streams: u64) {
        if self.ceiling_bps.is_none() {
            self.probe_bps = self
                .probe_bps
                .max((streams.min(MAX_PROBE_STREAMS) * self.cfg.stream_bps) as f64);
        }
    }

    /// Everyone this forwarder sends to: the ledger, plus subscribers shed
    /// make-before-break whose drain has not ended.
    #[must_use]
    pub fn forwarding_to(&self) -> Vec<(P, Role)> {
        let mut v: Vec<(P, Role)> = self
            .ledger
            .iter()
            .map(|(p, c)| (p.clone(), c.role))
            .collect();
        for (p, d) in &self.draining {
            if !self.ledger.contains_key(p) {
                v.push((p.clone(), d.role));
            }
        }
        v
    }

    /// Whether `p` is being drained.
    #[must_use]
    pub fn is_draining(&self, p: &P) -> bool {
        self.draining.contains_key(p)
    }

    /// End drains whose budget passed.
    pub fn expire_drains(&mut self, now_ms: u64) {
        self.draining.retain(|_, d| d.until_ms > now_ms);
    }

    /// **A-shed** (`FSD/CIRIS_MESH.md` §7.2): shed every commitment, most
    /// recent first (LIFO), each make-before-break: the commitment leaves
    /// the ledger now (capacity is accounted free) but this forwarder keeps
    /// sending to the subscriber until it unsubscribes or `down_silence_ms`
    /// passes. Returns the shed subscribers in shed order.
    pub fn shed_all_draining(
        &mut self,
        now_ms: u64,
        reason: super::ShedReason,
        log: &mut DecisionLog,
    ) -> Vec<P> {
        let mut order: Vec<(P, Commitment)> =
            self.ledger.iter().map(|(p, c)| (p.clone(), *c)).collect();
        order.sort_by_key(|(_, c)| std::cmp::Reverse(c.order));
        let mut shed = Vec::with_capacity(order.len());
        for (p, c) in order {
            self.ledger.remove(&p);
            self.draining.insert(
                p.clone(),
                Drain {
                    role: c.role,
                    until_ms: now_ms + self.cfg.down_silence_ms,
                },
            );
            log.record(
                now_ms,
                &self.me,
                DecisionKind::Shed,
                Some(&p),
                i64::from(reason.code()),
                reason.token(),
            );
            shed.push(p);
        }
        shed
    }

    /// Update this relay's view of its own upstream (from its selector).
    pub fn set_upstream(
        &mut self,
        depth: Option<u8>,
        ancestry: Vec<P>,
        healthy: bool,
        latency_ms: u32,
    ) {
        if self.is_root {
            return;
        }
        self.depth = depth;
        self.ancestry = ancestry;
        self.upstream_healthy = healthy && depth.is_some();
        self.upstream_latency_ms = latency_ms;
    }

    /// The measured ceiling, if learned.
    #[must_use]
    pub fn ceiling_bps(&self) -> Option<f64> {
        self.ceiling_bps
    }

    /// The hard limit: `min(commit_fraction · advertised, measured) − reserve`.
    /// Shedding is against this limit only (the probe gate limits growth,
    /// never takes back what was admitted).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn hard_limit_bps(&self) -> f64 {
        (self.committable_bps() - self.cfg.reserve_bps as f64 - self.external_committed as f64)
            .max(0.0)
    }

    /// What may be committed before the reserve and the node's other
    /// streams: `min(commit_fraction · advertised, measured)`. One margin per
    /// measurement (`docs/AV_ALM_DESIGN.md` §5.1): a claim takes
    /// `commit_fraction`, a measurement already carries
    /// [`MEASURED_MARGIN`] from the uplink meter, and stacking both would
    /// commit about 0.49 of what the uplink demonstrably carries.
    #[allow(clippy::cast_precision_loss)]
    fn committable_bps(&self) -> f64 {
        let adv = self
            .advertised_bps
            .map_or(f64::INFINITY, |a| self.fraction() * a as f64);
        adv.min(self.measured_bps())
    }

    /// What the uplink measured, as committable (the meter's margin is in
    /// it; a class policy's fraction, the canonical's 5 %, still applies). A
    /// publisher's is never read below one stream (see the module docs): it
    /// is the one path nothing can replace.
    #[allow(clippy::cast_precision_loss)]
    fn measured_bps(&self) -> f64 {
        let Some(c) = self.ceiling_bps else {
            return f64::INFINITY;
        };
        let m = self.class.fraction.map_or(c, |f| f * c);
        if self.is_root {
            m.max(self.cfg.stream_bps as f64)
        } else {
            m
        }
    }

    fn fraction(&self) -> f64 {
        self.class.fraction.unwrap_or(self.cfg.commit_fraction)
    }

    /// The admission limit (bits/s) before the forwarder reserve: the hard
    /// limit, further gated by the probe allowance while unmeasured.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn limit_bps(&self) -> f64 {
        let hard = self.committable_bps();
        let probe = match (self.ceiling_bps, self.class.trial_slot) {
            (Some(_), _) => f64::INFINITY,
            (None, true) => self.floor_bps + self.probe_bps,
            // No trial slot: an unmeasured forwarder commits only against
            // what it advertises (the canonical's configured capacity), or
            // what it has demonstrated.
            (None, false) if self.advertised_bps.is_some() => f64::INFINITY,
            (None, false) => self.floor_bps,
        };
        // The node's other streams share the uplink, so they come off the
        // hard limit. They come off a relay's probe gate too: `floor_bps` is
        // what the WHOLE uplink demonstrated (every admission folds the one
        // shared egress window), so "floor + one step" is the uplink's
        // allowance, not each admission's. Without this every relayed stream
        // took floor + a step of its own, and a relay-on N=4 room committed
        // its full mesh plus a full-rate standby per other stream, unmeasured,
        // the second media started (CIRISEdge avmesh4n, 2026-11-10). The
        // publisher's own stream keeps its allowance whole: it is the one
        // path nothing can replace, and relays yield to it.
        //
        // Only what the floor demonstrated comes off: the node's commitments
        // the uplink is not yet sending (a stream that has not started, priced
        // at the floor rate) are no measurement either way, and taking them
        // off would leave a relay no step at all. So the uplink's growth is
        // `max(floor, committed elsewhere) + one step`, shared by its relays.
        let ext = self.external_committed as f64;
        let hard = hard - ext;
        let probe = if self.is_root {
            probe
        } else {
            probe - self.floor_bps.min(ext)
        };
        (hard.min(probe) - self.cfg.reserve_bps as f64).max(0.0)
    }

    /// Bits/s committed.
    #[must_use]
    pub fn committed_bps(&self) -> u64 {
        self.ledger.values().map(|c| c.bps).sum()
    }

    /// The ledger.
    #[must_use]
    pub fn ledger(&self) -> &BTreeMap<P, Commitment> {
        &self.ledger
    }

    /// The role `sub` holds, if any.
    #[must_use]
    pub fn role_of(&self, sub: &P) -> Option<Role> {
        self.ledger.get(sub).map(|c| c.role)
    }

    /// Whether this forwarder currently has the stream to forward.
    #[must_use]
    pub fn forwarding(&self) -> bool {
        match self.kind {
            ForwarderKind::Member => {
                self.members.contains(&self.me) && (self.is_root || self.upstream_healthy)
            }
            ForwarderKind::Transport => true,
        }
    }

    /// The offer to advertise to candidates.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    pub fn offer(&self) -> Offer<P> {
        // Admit-close refuses every request that grows a commitment, so a
        // closed forwarder has no room to offer: advertising it only draws
        // `load_refuse:admit_closed` refusals, each backing its asker off
        // (47 of them on one node in a 90 s N=4 call, avmesh4n m0).
        let open = !self.admit_closed;
        let headroom = if open {
            (self.limit_bps() - self.committed_bps() as f64).max(0.0)
        } else {
            0.0
        };
        let can_preempt = self
            .depth
            .is_some_and(|d| d.saturating_add(2) <= self.cfg.max_depth);
        let forwarder_headroom = if open && can_preempt && self.cfg.admission_enabled {
            let held_by_forwarders: u64 = self
                .ledger
                .values()
                .filter(|c| c.forward_capable)
                .map(|c| c.bps)
                .sum();
            (self.hard_limit_bps() - held_by_forwarders as f64).max(headroom)
        } else {
            headroom
        };
        Offer {
            from: self.me.clone(),
            depth: self.depth.unwrap_or(u8::MAX),
            ancestry: self.ancestry.clone(),
            // Rounded: exactly one stream of room must read as one stream.
            headroom_bps: headroom.round() as u64,
            forwarder_headroom_bps: forwarder_headroom.round() as u64,
            upstream_latency_ms: self.upstream_latency_ms,
            forwarding: self.forwarding(),
        }
    }

    fn refuse(
        &self,
        now_ms: u64,
        req: &SubscribeRequest<P>,
        reason: RefuseReason,
        rng: &mut dyn JitterSource,
        log: &mut DecisionLog,
    ) -> AdmitDecision {
        let retry_after_ms = self.cfg.backoff_ms(self.cfg.backoff_base_ms * 2, 0, rng);
        log.record(
            now_ms,
            &self.me,
            DecisionKind::Refuse,
            Some(&req.subscriber),
            reason as i64,
            "refuse",
        );
        AdmitDecision::Refuse {
            reason,
            retry_after_ms,
        }
    }

    fn commit(&mut self, now_ms: u64, req: &SubscribeRequest<P>, log: &mut DecisionLog) {
        let bps = self.cfg.role_bps(req.role);
        self.order += 1;
        let order = match self.ledger.get(&req.subscriber) {
            // An upgrade keeps nothing of the old order: it is the most
            // recent commitment of that size.
            Some(c) if c.role == req.role => c.order,
            _ => self.order,
        };
        self.ledger.insert(
            req.subscriber.clone(),
            Commitment {
                role: req.role,
                bps,
                order,
                forward_capable: req.forward_capable,
            },
        );
        log.record(
            now_ms,
            &self.me,
            DecisionKind::Admit,
            Some(&req.subscriber),
            i64::from(req.role == Role::Primary),
            "admit",
        );
    }

    /// Decide a subscribe request (new, upgrade or downgrade).
    #[allow(clippy::cast_precision_loss, clippy::too_many_lines)]
    pub fn request(
        &mut self,
        now_ms: u64,
        req: &SubscribeRequest<P>,
        rng: &mut dyn JitterSource,
        log: &mut DecisionLog,
    ) -> AdmitDecision {
        // Membership is eligibility, not admission: checked even with
        // admission off, and before anything else. A transport forwarder is
        // not a member; the links it carries are members'.
        let me_ok = self.kind == ForwarderKind::Transport || self.members.contains(&self.me);
        if !me_ok || !self.members.contains(&req.subscriber) {
            return self.refuse(now_ms, req, RefuseReason::NotMember, rng, log);
        }
        // M2: a non-member forwards one link of a stream, never a fan-out.
        if let Some(max) = self.class.max_children {
            if !self.ledger.contains_key(&req.subscriber) && self.ledger.len() >= max {
                return self.refuse(now_ms, req, RefuseReason::NotMember, rng, log);
            }
        }
        // V1: a class this forwarder never carries is refused whatever the
        // capacity (a canonical never relays video).
        if req.role == Role::Primary && !self.class.video {
            return self.refuse(now_ms, req, RefuseReason::ClassRefused, rng, log);
        }
        if !self.cfg.admission_enabled {
            self.commit(now_ms, req, log);
            return AdmitDecision::Admit { role: req.role };
        }
        let existing_bps = self.ledger.get(&req.subscriber).map_or(0, |c| c.bps);
        if self.admit_closed && self.cfg.role_bps(req.role) > existing_bps {
            return self.refuse(now_ms, req, RefuseReason::AdmitClosed, rng, log);
        }
        if req.subscriber == self.me || self.ancestry.contains(&req.subscriber) {
            return self.refuse(now_ms, req, RefuseReason::Loop, rng, log);
        }
        let Some(depth) = self.depth.filter(|_| self.forwarding()) else {
            return self.refuse(now_ms, req, RefuseReason::UpstreamUnhealthy, rng, log);
        };
        if depth.saturating_add(1) > self.cfg.max_depth {
            return self.refuse(now_ms, req, RefuseReason::DepthLimit, rng, log);
        }
        let existing = self.ledger.get(&req.subscriber).map_or(0, |c| c.bps);
        let need = self.cfg.role_bps(req.role);
        if need <= existing {
            self.commit(now_ms, req, log);
            return AdmitDecision::Admit { role: req.role };
        }
        let mut limit = self.limit_bps();
        if req.role == Role::Primary
            && !req.forward_capable
            && depth.saturating_add(2) <= self.cfg.max_depth
            && self.cfg.forwarder_reserve_fraction > 0.0
        {
            // Optional static reserve, a share of the HARD limit; never eats
            // the cold-start trial slot. Off by default: preemption below
            // does the job without idling capacity.
            let trial = if self.ledger.is_empty() {
                need as f64
            } else {
                0.0
            };
            let leaf_cap = self.hard_limit_bps() * (1.0 - self.cfg.forwarder_reserve_fraction);
            limit = limit.min(leaf_cap).max(trial.min(limit));
        }
        let committed = self.committed_bps() - existing;
        if (committed + need) as f64 <= limit + 1.0 {
            self.commit(now_ms, req, log);
            return AdmitDecision::Admit { role: req.role };
        }
        let forwarder = req.role == Role::Primary
            && req.forward_capable
            && depth.saturating_add(2) <= self.cfg.max_depth;
        let hard = self.hard_limit_bps();
        // Blocked only by the probe gate (it fits the hard limit): a
        // forwarder is admitted, and that admission IS the next probe step.
        // Nobody is displaced to satisfy a growth gate.
        if forwarder && (committed + need) as f64 <= hard + 1.0 {
            self.probe_bps = self
                .probe_bps
                .max((committed + need) as f64 - self.floor_bps);
            self.commit(now_ms, req, log);
            return AdmitDecision::Admit { role: req.role };
        }
        // Forwarder preemption (Overcast-style), only when the HARD limit
        // binds: a forward-capable primary whose children could still
        // forward displaces the most recent NON-forwarding commitments,
        // standbys first, then leaf primaries. A forwarder brings capacity;
        // a leaf shed here re-parents under it.
        let limit = limit.min(hard);
        if forwarder {
            let mut victims: Vec<(P, Commitment)> = self
                .ledger
                .iter()
                .filter(|(p, c)| !c.forward_capable && **p != req.subscriber)
                .map(|(p, c)| (p.clone(), *c))
                .collect();
            victims.sort_by_key(|(_, c)| (c.role == Role::Primary, std::cmp::Reverse(c.order)));
            let mut freed = 0u64;
            let mut take = 0usize;
            for (_, c) in &victims {
                if (committed - freed + need) as f64 <= limit + 1.0 {
                    break;
                }
                freed += c.bps;
                take += 1;
            }
            if (committed - freed + need) as f64 <= limit + 1.0 {
                for (v, _) in victims.into_iter().take(take) {
                    self.ledger.remove(&v);
                    log.record(
                        now_ms,
                        &self.me,
                        DecisionKind::Shed,
                        Some(&v),
                        1,
                        "preempted by forwarder",
                    );
                    self.preempted.push(v);
                }
                self.commit(now_ms, req, log);
                return AdmitDecision::Admit { role: req.role };
            }
        }
        self.demand = true;
        self.refuse(now_ms, req, RefuseReason::Capacity, rng, log)
    }

    /// Subscribers displaced by forwarder preemption since the last call;
    /// the caller sends each a [`super::ShedReason::Preempted`].
    pub fn take_preempted(&mut self) -> Vec<P> {
        std::mem::take(&mut self.preempted)
    }

    /// A subscriber left (or its link is gone).
    pub fn release(&mut self, sub: &P) -> bool {
        let drained = self.draining.remove(sub).is_some();
        self.ledger.remove(sub).is_some() || drained
    }

    /// Fold one closed egress window. Returns the subscribers shed (most
    /// recent first) when the measured limit fell below commitments.
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    pub fn on_egress_window(
        &mut self,
        now_ms: u64,
        w: &EgressWindow,
        log: &mut DecisionLog,
    ) -> Vec<P> {
        self.expire_drains(now_ms);
        // §5.1: the uplink meter's verdict IS the measurement. A window it
        // calls congested carries the span's demonstrated capacity, which
        // replaces the ceiling whether it is higher or lower: nothing here
        // ratchets, and a lone refusal or one slow leg never makes a verdict
        // (`EgressMeter`). It also keeps the ceiling from going stale.
        if let Some(c) = w.capacity_bps.filter(|_| w.congested) {
            self.clean_streak = 0;
            self.last_congested_ms = now_ms;
            self.ceiling_bps = Some(c);
            log.record(
                now_ms,
                &self.me,
                DecisionKind::Ceiling,
                None,
                c as i64,
                "congested",
            );
            if let Some(adv) = self.advertised_bps {
                if !self.over_claim_flagged && adv as f64 > self.cfg.over_claim_ratio * c {
                    self.over_claim_flagged = true;
                    log.record(
                        now_ms,
                        &self.me,
                        DecisionKind::OverClaim,
                        None,
                        (adv as f64 / c * 100.0) as i64,
                        "advertised/measured %",
                    );
                }
            }
        } else {
            self.clean_streak += 1;
            if let Some(c) = self.ceiling_bps {
                if w.sent_bps > c {
                    self.ceiling_bps = Some(w.sent_bps);
                }
                // Additive increase (Eric, 2026-11-10): a clean window in
                // which someone is waiting (a capacity refusal since the
                // last step) raises a measured ceiling by one stream of
                // committable room. The ask is the probe; the next verdict,
                // if the uplink really is full, takes it back. Without it a
                // shed member waited out the staleness (60-120 s) with the
                // uplink clean the whole time (avmesh4, after the cap lifted).
                if self.demand && !self.over_claim_flagged {
                    self.demand = false;
                    // From what the hard limit reads now (a publisher's
                    // one-stream floor included), so a step is one stream.
                    let per = self.class.fraction.unwrap_or(1.0);
                    let c = (self.measured_bps() + self.cfg.stream_bps as f64) / per;
                    self.ceiling_bps = Some(c);
                    log.record(
                        now_ms,
                        &self.me,
                        DecisionKind::Ceiling,
                        None,
                        c as i64,
                        "demand",
                    );
                }
                // Not for a forwarder caught over-claiming: that measurement
                // is what disproved its word, and it stays disproved.
                if !self.over_claim_flagged
                    && now_ms.saturating_sub(self.last_congested_ms) >= self.ceiling_stale_ms
                {
                    self.ceiling_bps = None;
                    self.ceiling_stale_ms = (self.ceiling_stale_ms * 2).min(CEILING_STALE_MAX_MS);
                    log.record(now_ms, &self.me, DecisionKind::Ceiling, None, 0, "stale");
                }
            } else {
                self.floor_bps = self.floor_bps.max(w.sent_bps);
                // Grow on use OR on demand (a capacity refusal since the
                // last growth): the probe is the measurement, so it must be
                // spent when someone is waiting for it.
                let used = self.committed_bps() as f64 >= 0.8 * (self.floor_bps + self.probe_bps);
                if (used || self.demand) && self.clean_streak >= self.cfg.probe_clean_windows {
                    self.demand = false;
                    self.clean_streak = 0;
                    self.probe_bps = (self.probe_bps * 2.0)
                        .min((MAX_PROBE_STREAMS * self.cfg.stream_bps) as f64);
                }
            }
        }
        if !self.cfg.admission_enabled {
            return Vec::new();
        }
        let mut shed = Vec::new();
        let limit = self.hard_limit_bps();
        while self.committed_bps() as f64 > limit + 1.0 {
            let Some(victim) = self
                .ledger
                .iter()
                .max_by_key(|(_, c)| c.order)
                .map(|(p, _)| p.clone())
            else {
                break;
            };
            self.ledger.remove(&victim);
            log.record(
                now_ms,
                &self.me,
                DecisionKind::Shed,
                Some(&victim),
                0,
                "over-committed",
            );
            shed.push(victim);
        }
        shed
    }
}

#[cfg(test)]
mod tests {
    use super::super::SplitMix64;
    use super::*;

    fn roster(a: &mut Admission<u32>) {
        a.set_members(0..32u32);
    }

    fn req(s: u32, role: Role) -> SubscribeRequest<u32> {
        SubscribeRequest {
            subscriber: s,
            role,
            forward_capable: false,
        }
    }

    #[test]
    fn cold_start_has_exactly_one_trial_slot() {
        let cfg = ControllerConfig::interactive();
        let mut a = Admission::publisher(0u32, cfg, None);
        roster(&mut a);
        let mut rng = SplitMix64(1);
        let mut log = DecisionLog::default();
        assert!(matches!(
            a.request(0, &req(1, Role::Primary), &mut rng, &mut log),
            AdmitDecision::Admit { .. }
        ));
        assert!(matches!(
            a.request(0, &req(2, Role::Primary), &mut rng, &mut log),
            AdmitDecision::Refuse {
                reason: RefuseReason::Capacity,
                ..
            }
        ));
    }

    #[test]
    fn honest_advertised_caps_at_65_percent() {
        let mut cfg = ControllerConfig::interactive();
        cfg.forwarder_reserve_fraction = 0.0;
        let mut a = Admission::publisher(0u32, cfg.clone(), Some(10 * cfg.stream_bps));
        roster(&mut a);
        let mut rng = SplitMix64(1);
        let mut log = DecisionLog::default();
        let mut admitted = 0;
        for t in 0..40u64 {
            for s in 0..20u32 {
                if a.role_of(&s).is_none()
                    && matches!(
                        a.request(t * 1000, &req(s, Role::Primary), &mut rng, &mut log),
                        AdmitDecision::Admit { .. }
                    )
                {
                    admitted += 1;
                }
            }
            #[allow(clippy::cast_precision_loss)]
            let sent = a.committed_bps() as f64;
            a.on_egress_window(
                t * 1000,
                &EgressWindow {
                    sent_bps: sent,
                    delivered_bps: sent,
                    dropped_bytes: 0,
                    max_queue_ms: 0.0,
                    congested: false,
                    capacity_bps: None,
                },
                &mut log,
            );
        }
        assert_eq!(admitted, 6, "0.65 × 10 streams → 6 primaries");
    }

    #[test]
    fn over_claim_is_measured_and_shed() {
        let cfg = ControllerConfig::interactive();
        let mut a = Admission::publisher(0u32, cfg.clone(), Some(100 * cfg.stream_bps));
        roster(&mut a);
        let mut rng = SplitMix64(1);
        let mut log = DecisionLog::default();
        for s in 0..10u32 {
            a.ledger.insert(
                s,
                Commitment {
                    role: Role::Primary,
                    bps: cfg.stream_bps,
                    order: u64::from(s),
                    forward_capable: false,
                },
            );
        }
        #[allow(clippy::cast_precision_loss)]
        let real = (4 * cfg.stream_bps) as f64;
        // The meter's verdict carries the capacity (its span already holds
        // the evidence: one verdict is a ceiling).
        let w = EgressWindow {
            sent_bps: real,
            delivered_bps: real,
            dropped_bytes: 10,
            max_queue_ms: 500.0,
            congested: true,
            capacity_bps: Some(real),
        };
        let shed = a.on_egress_window(1000, &w, &mut log);
        assert_eq!(
            shed,
            vec![9, 8, 7, 6, 5, 4],
            "LIFO down to what was measured (4), not 0.65 of the claim"
        );
        assert_eq!(log.count(DecisionKind::OverClaim), 1);
        let _ = &mut rng;
    }

    /// A window as the uplink meter closes it: `congested` is its verdict,
    /// with `sent_bps` the capacity it demonstrated.
    fn window(sent_bps: f64, congested: bool) -> EgressWindow {
        EgressWindow {
            sent_bps,
            delivered_bps: sent_bps,
            dropped_bytes: u64::from(congested) * 1_000,
            max_queue_ms: if congested { 500.0 } else { 0.0 },
            congested,
            capacity_bps: congested.then_some(sent_bps),
        }
    }

    /// A publisher whose two children were admitted on the probe.
    fn publisher_of_two() -> (Admission<u32>, DecisionLog, ControllerConfig) {
        let cfg = ControllerConfig::interactive();
        let mut a = Admission::publisher(0u32, cfg.clone(), None);
        roster(&mut a);
        a.set_probe_streams(2);
        let mut rng = SplitMix64(1);
        let mut log = DecisionLog::new(64);
        for s in [1, 2] {
            assert!(matches!(
                a.request(0, &req(s, Role::Primary), &mut rng, &mut log),
                AdmitDecision::Admit { .. }
            ));
        }
        (a, log, cfg)
    }

    /// CIRISEdge#945, the v44 CI stall: a host starved for a few seconds drove
    /// the ceiling far under one stream. Mutation: without the floor the last
    /// child is shed, the offer shows no room, and nobody ever asks again.
    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn a_publisher_keeps_one_stream_under_any_ceiling() {
        let (mut a, mut log, cfg) = publisher_of_two();
        let tiny = cfg.stream_bps as f64 / 50.0;
        let shed = a.on_egress_window(1_000, &window(tiny, true), &mut log);
        assert_eq!(shed, vec![2], "LIFO, and only down to one");
        assert!(a
            .on_egress_window(2_000, &window(tiny, true), &mut log)
            .is_empty());
        assert_eq!(a.ledger().len(), 1, "the oldest child stays");

        let mut rng = SplitMix64(1);
        a.release(&1);
        let offer = a.offer();
        assert_eq!(
            offer.headroom_bps, cfg.stream_bps,
            "an empty publisher offers its one stream"
        );
        assert!(
            matches!(
                a.request(3_000, &req(2, Role::Primary), &mut rng, &mut log),
                AdmitDecision::Admit { .. }
            ),
            "and admits it"
        );
        assert!(
            matches!(
                a.request(3_000, &req(3, Role::Primary), &mut rng, &mut log),
                AdmitDecision::Refuse { .. }
            ),
            "one stream, not two: the ceiling still binds"
        );
    }

    /// A relay has no such floor: its child can go elsewhere.
    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn a_relay_has_no_one_stream_floor() {
        let cfg = ControllerConfig::interactive();
        let mut a = Admission::relay(9u32, cfg.clone(), None);
        roster(&mut a);
        a.set_upstream(Some(1), vec![0], true, 10);
        let mut rng = SplitMix64(1);
        let mut log = DecisionLog::new(64);
        assert!(matches!(
            a.request(0, &req(1, Role::Primary), &mut rng, &mut log),
            AdmitDecision::Admit { .. }
        ));
        let tiny = cfg.stream_bps as f64 / 50.0;
        assert_eq!(
            a.on_egress_window(1_000, &window(tiny, true), &mut log),
            vec![1]
        );
    }

    /// A ceiling learned in a bad moment does not bind for the rest of the
    /// call, even with nothing sent that could lift it. Mutation: without the
    /// staleness the second child's room never comes back.
    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn a_ceiling_goes_stale_after_a_clean_stretch() {
        let (mut a, mut log, cfg) = publisher_of_two();
        let tiny = cfg.stream_bps as f64 / 50.0;
        let _ = a.on_egress_window(1_000, &window(tiny, true), &mut log);
        let _ = a.on_egress_window(2_000, &window(tiny, true), &mut log);
        assert!(a.ceiling_bps().is_some());
        assert_eq!(a.offer().headroom_bps, 0, "the one stream is taken");

        let clean = window(0.0, false);
        let before = 2_000 + CEILING_STALE_MS - 1;
        let _ = a.on_egress_window(before, &clean, &mut log);
        assert!(a.ceiling_bps().is_some(), "not before it is stale");
        let _ = a.on_egress_window(2_000 + CEILING_STALE_MS, &clean, &mut log);
        assert_eq!(a.ceiling_bps(), None, "stale");
        assert_eq!(
            a.offer().headroom_bps,
            cfg.stream_bps,
            "the probe's second stream is back"
        );
    }

    /// The measurement that disproved a forwarder's word stands (T2 in the
    /// closed-loop sim is this on a live world).
    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn an_over_claimer_keeps_its_ceiling() {
        let cfg = ControllerConfig::interactive();
        let mut a = Admission::relay(9u32, cfg.clone(), Some(100 * cfg.stream_bps));
        roster(&mut a);
        a.set_upstream(Some(1), vec![0], true, 10);
        let mut log = DecisionLog::new(64);
        let bps = 4.0 * cfg.stream_bps as f64;
        let _ = a.on_egress_window(1_000, &window(bps, true), &mut log);
        let _ = a.on_egress_window(2_000, &window(bps, true), &mut log);
        assert_eq!(log.count(DecisionKind::OverClaim), 1, "the premise");
        let _ = a.on_egress_window(10 * CEILING_STALE_MAX_MS, &window(bps, false), &mut log);
        assert!(a.ceiling_bps().is_some());
    }

    /// A congested window keeps a ceiling current, and a really limited
    /// uplink is re-probed less and less often.
    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn a_ceiling_learned_again_stands_twice_as_long() {
        let (mut a, mut log, cfg) = publisher_of_two();
        let bps = cfg.stream_bps as f64;
        let clean = window(0.0, false);
        let mut at = 1_000;
        // §5.1: 60 s, then 120 s, and never longer.
        for stands in [CEILING_STALE_MS, 2 * CEILING_STALE_MS, CEILING_STALE_MAX_MS] {
            let _ = a.on_egress_window(at, &window(bps, true), &mut log);
            at += 1_000;
            let _ = a.on_egress_window(at, &window(bps, true), &mut log);
            assert!(a.ceiling_bps().is_some());
            let _ = a.on_egress_window(at + stands - 1, &clean, &mut log);
            assert!(a.ceiling_bps().is_some(), "stands {stands} ms");
            at += stands;
            let _ = a.on_egress_window(at, &clean, &mut log);
            assert_eq!(a.ceiling_bps(), None, "stale after {stands} ms");
            at += 1_000;
        }
        // Capped.
        for _ in 0..8 {
            let _ = a.on_egress_window(at, &window(bps, true), &mut log);
            at += 1_000;
            let _ = a.on_egress_window(at, &window(bps, true), &mut log);
            at += CEILING_STALE_MAX_MS;
            let _ = a.on_egress_window(at, &clean, &mut log);
            assert_eq!(a.ceiling_bps(), None, "never longer than the cap");
            at += 1_000;
        }
    }

    /// The relay-on N=4 field run (avmesh4n m0, 2026-11-10): one uplink,
    /// four admissions (its own stream and a relay per other stream). The
    /// full mesh ran clean; the relays then each took the uplink's whole
    /// demonstrated floor plus a probe step of their own, a standby at full
    /// rate per other member (opaque media is all "audio"), and two windows
    /// later the uplink was congested and shedding. The probe gate is the
    /// uplink's: floor + one step, less what the node already committed.
    /// Mutation (v44.1.1): the relay admits floor (3) + step (1) = 4 standbys.
    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn an_unmeasured_uplink_is_probed_once_not_per_admission() {
        let cfg = ControllerConfig::interactive();
        let s = cfg.stream_bps;
        let mut own = Admission::publisher(0u32, cfg.clone(), None);
        roster(&mut own);
        own.set_probe_streams(3);
        let mut relay = Admission::relay(0u32, cfg.clone(), None);
        roster(&mut relay);
        relay.set_upstream(Some(1), vec![9], true, 10);
        // Opaque media: a standby is sent everything, so it costs a stream.
        relay.set_role_costs(s, s);
        let mut rng = SplitMix64(1);
        let mut log = DecisionLog::new(64);
        for c in 1..=3u32 {
            assert!(
                matches!(
                    own.request(0, &req(c, Role::Primary), &mut rng, &mut log),
                    AdmitDecision::Admit { .. }
                ),
                "the premise: a room of four is a full mesh on the probe"
            );
        }
        // The full mesh runs clean; both admissions fold the same window.
        let sent = own.committed_bps() as f64;
        for t in 1..=2u64 {
            let _ = own.on_egress_window(t * 1_000, &window(sent, false), &mut log);
            relay.set_external_committed(own.committed_bps());
            let _ = relay.on_egress_window(t * 1_000, &window(sent, false), &mut log);
        }
        relay.set_external_committed(own.committed_bps());
        let admitted = (4..=8u32)
            .filter(|&c| {
                matches!(
                    relay.request(3_000, &req(c, Role::Standby), &mut rng, &mut log),
                    AdmitDecision::Admit { .. }
                )
            })
            .count();
        assert_eq!(
            admitted, 1,
            "floor 3 + one step − own 3 = one standby, not four"
        );
        assert!(own.committed_bps() + relay.committed_bps() <= 4 * s);
        assert_eq!(own.ledger().len(), 3, "the publisher's own children stand");
    }

    /// A closed forwarder (service tier ≥ 1) refuses every request that would
    /// grow a commitment, so its offer shows no room; it still forwards what
    /// it holds. Mutation (v44.1.1): the offer advertises the probe's room and
    /// every member that reads it is refused `load_refuse:admit_closed`.
    #[test]
    fn an_admit_closed_relay_offers_no_room() {
        let cfg = ControllerConfig::interactive();
        let mut a = Admission::relay(9u32, cfg.clone(), None);
        roster(&mut a);
        a.set_upstream(Some(1), vec![0], true, 10);
        assert!(
            a.offer().headroom_bps >= cfg.stream_bps,
            "the premise: an open relay offers its trial slot"
        );
        a.set_admit_closed(true);
        let o = a.offer();
        assert_eq!((o.headroom_bps, o.forwarder_headroom_bps), (0, 0));
        assert!(o.forwarding, "closed to growth, not to what it carries");
        a.set_admit_closed(false);
        assert!(a.offer().headroom_bps >= cfg.stream_bps, "reopened");
    }

    /// One congested window is not a ceiling (two running are), so a lone
    /// one does not keep a ceiling from going stale. avmesh4 (C): eleven
    /// congested sends in the 60 s after the cap lifted kept m0's cap
    /// ceiling standing, and m1 and m3 never got room back. Mutation
    /// (v44.1.1): every congested window re-arms the staleness, and a blip
    /// every 5 s keeps the ceiling forever.
    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn lone_congested_windows_do_not_keep_a_ceiling() {
        let (mut a, mut log, cfg) = publisher_of_two();
        let bps = cfg.stream_bps as f64;
        let _ = a.on_egress_window(1_000, &window(bps, true), &mut log);
        assert!(a.ceiling_bps().is_some(), "the premise: a ceiling learned");
        // The real pipeline: 90 frames/s, one refused every 5 s (a lone
        // `Busy`). The uplink meter never calls that a verdict, so the
        // ceiling goes stale on time.
        let mut meter = super::super::EgressMeter::new(1_000, 150);
        let mut at = 1_000;
        while at < 1_000 + CEILING_STALE_MS {
            for _ in 0..90 {
                meter.on_sent(at, 300, 400.0);
            }
            meter.on_delivered(at, 90 * 300);
            if (at / 1_000) % 5 == 0 {
                meter.on_dropped(at, 300);
            }
            at += 1_000;
            let w = meter.roll(at).expect("a window");
            let _ = a.on_egress_window(at, &w, &mut log);
        }
        assert_eq!(a.ceiling_bps(), None, "stale on time: no blip is a verdict");
        // A verdict still keeps it.
        let _ = a.on_egress_window(at + 1_000, &window(bps, true), &mut log);
        let half = at + 1_000 + CEILING_STALE_MS / 2;
        let _ = a.on_egress_window(half, &window(0.0, false), &mut log);
        assert!(a.ceiling_bps().is_some());
    }

    /// A measured ceiling rises one stream per clean window in which
    /// someone is waiting. Mutation (v45.0.0): the refused member waits for
    /// the ceiling to go stale (60 s here), clean windows and all.
    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn a_waiting_member_raises_a_clean_ceiling_one_stream_a_window() {
        let (mut a, mut log, cfg) = publisher_of_two();
        let mut rng = SplitMix64(1);
        let bps = cfg.stream_bps as f64;
        // A verdict at one stream sheds the second child.
        assert_eq!(
            a.on_egress_window(1_000, &window(bps, true), &mut log),
            vec![2]
        );
        assert!(
            matches!(
                a.request(1_500, &req(2, Role::Primary), &mut rng, &mut log),
                AdmitDecision::Refuse {
                    reason: RefuseReason::Capacity,
                    ..
                }
            ),
            "the premise: no room under the verdict"
        );
        let _ = a.on_egress_window(2_000, &window(bps, false), &mut log);
        assert!(
            matches!(
                a.request(2_500, &req(2, Role::Primary), &mut rng, &mut log),
                AdmitDecision::Admit { .. }
            ),
            "one clean window with a member waiting is one more stream"
        );
        assert!(
            matches!(
                a.request(2_600, &req(3, Role::Primary), &mut rng, &mut log),
                AdmitDecision::Refuse { .. }
            ),
            "one, not more: the next waits for the next clean window"
        );
        let _ = a.on_egress_window(3_000, &window(2.0 * bps, false), &mut log);
        assert!(matches!(
            a.request(3_500, &req(3, Role::Primary), &mut rng, &mut log),
            AdmitDecision::Admit { .. }
        ));
        // Nobody waiting: a clean window adds nothing.
        let c = a.ceiling_bps();
        let _ = a.on_egress_window(4_000, &window(bps, false), &mut log);
        assert_eq!(a.ceiling_bps(), c);
    }

    /// One margin per measurement (§5.1): an uplink whose backpressured
    /// windows delivered 4 streams commits 0.75 × 4 = 3, not a further
    /// 0.65 of that (about 1.95). The real pipeline: meter, then admission.
    /// Mutation: `commit_fraction` stacked on the meter's margin sheds the
    /// publisher to one child.
    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn a_measured_uplink_commits_three_quarters_of_its_p10() {
        let cfg = ControllerConfig::interactive();
        let mut a = Admission::publisher(0u32, cfg.clone(), None);
        roster(&mut a);
        a.set_probe_streams(6);
        let mut rng = SplitMix64(1);
        let mut log = DecisionLog::new(64);
        for c in 1..=6u32 {
            assert!(matches!(
                a.request(0, &req(c, Role::Primary), &mut rng, &mut log),
                AdmitDecision::Admit { .. }
            ));
        }
        // Offered 6 streams, 4 delivered and the rest refused, every second.
        let frame = 100u64;
        let per_stream_frames = cfg.stream_bps / 8 / frame;
        let mut meter = super::super::EgressMeter::new(1_000, 150);
        let mut verdict = None;
        for t in 0..super::super::path_meter::UPLINK_MIN_WINDOWS as u64 {
            for _ in 0..4 * per_stream_frames {
                meter.on_sent(t * 1_000, frame, 0.0);
            }
            for _ in 0..2 * per_stream_frames {
                meter.on_dropped(t * 1_000, frame);
            }
            meter.on_delivered(t * 1_000, 4 * per_stream_frames * frame);
            let w = meter.roll(t * 1_000 + 1_000).expect("a window");
            if w.congested {
                verdict = Some(w);
            }
        }
        let w = verdict.expect("a capped uplink reaches a verdict");
        let four = (4 * per_stream_frames * frame * 8) as f64;
        assert!((w.capacity_bps.expect("its capacity") - MEASURED_MARGIN * four).abs() < 1.0);
        let shed = a.on_egress_window(10_000, &w, &mut log);
        assert_eq!(shed, vec![6, 5, 4], "0.75 x 4 streams = 3 stay");
        assert_eq!(a.ledger().len(), 3);
    }

    #[test]
    fn forwarder_preempts_most_recent_leaf_standbys_first() {
        let cfg = ControllerConfig::interactive();
        let mut a = Admission::publisher(0u32, cfg.clone(), Some(2 * cfg.stream_bps));
        roster(&mut a);
        let mut rng = SplitMix64(1);
        let mut log = DecisionLog::default();
        assert!(matches!(
            a.request(0, &req(1, Role::Primary), &mut rng, &mut log),
            AdmitDecision::Admit { .. }
        ));
        let fwd = SubscribeRequest {
            subscriber: 9,
            role: Role::Primary,
            forward_capable: true,
        };
        assert!(matches!(
            a.request(1, &fwd, &mut rng, &mut log),
            AdmitDecision::Admit { .. }
        ));
        assert_eq!(a.take_preempted(), vec![1]);
        assert_eq!(a.role_of(&9), Some(Role::Primary));
        // A second forwarder cannot displace a forwarder.
        let fwd2 = SubscribeRequest {
            subscriber: 8,
            role: Role::Primary,
            forward_capable: true,
        };
        assert!(matches!(
            a.request(2, &fwd2, &mut rng, &mut log),
            AdmitDecision::Refuse { .. }
        ));
        assert!(a.take_preempted().is_empty());
    }

    #[test]
    fn non_members_are_never_admitted_or_admitting() {
        let cfg = ControllerConfig::interactive();
        let mut rng = SplitMix64(1);
        let mut log = DecisionLog::default();
        // Fail-closed: no roster, nobody.
        let mut a = Admission::publisher(0u32, cfg.clone(), None);
        assert!(matches!(
            a.request(0, &req(1, Role::Primary), &mut rng, &mut log),
            AdmitDecision::Refuse {
                reason: RefuseReason::NotMember,
                ..
            }
        ));
        // A non-member requester, even a forwarder, even with admission off.
        a.set_members([0u32, 1]);
        let fwd = SubscribeRequest {
            subscriber: 7,
            role: Role::Primary,
            forward_capable: true,
        };
        assert!(matches!(
            a.request(0, &fwd, &mut rng, &mut log),
            AdmitDecision::Refuse {
                reason: RefuseReason::NotMember,
                ..
            }
        ));
        let mut off = Admission::publisher(0u32, cfg.clone().herding_mutant(), None);
        off.set_members([0u32, 1]);
        assert!(matches!(
            off.request(0, &fwd, &mut rng, &mut log),
            AdmitDecision::Refuse {
                reason: RefuseReason::NotMember,
                ..
            }
        ));
        // A forwarder outside its own roster neither admits nor offers.
        let mut r = Admission::relay(9u32, cfg, None);
        r.set_members([0u32, 1]);
        r.set_upstream(Some(1), vec![0], true, 10);
        assert!(!r.offer().forwarding);
        assert!(matches!(
            r.request(0, &req(1, Role::Primary), &mut rng, &mut log),
            AdmitDecision::Refuse {
                reason: RefuseReason::NotMember,
                ..
            }
        ));
    }

    #[test]
    fn relay_without_upstream_and_loops_are_refused() {
        let cfg = ControllerConfig::interactive();
        let mut a = Admission::relay(5u32, cfg, None);
        roster(&mut a);
        let mut rng = SplitMix64(1);
        let mut log = DecisionLog::default();
        assert!(matches!(
            a.request(0, &req(1, Role::Primary), &mut rng, &mut log),
            AdmitDecision::Refuse {
                reason: RefuseReason::UpstreamUnhealthy,
                ..
            }
        ));
        a.set_upstream(Some(1), vec![0, 1], true, 20);
        assert!(matches!(
            a.request(0, &req(1, Role::Primary), &mut rng, &mut log),
            AdmitDecision::Refuse {
                reason: RefuseReason::Loop,
                ..
            }
        ));
        a.set_upstream(Some(3), vec![0, 7, 8], true, 20);
        assert!(matches!(
            a.request(0, &req(2, Role::Primary), &mut rng, &mut log),
            AdmitDecision::Refuse {
                reason: RefuseReason::DepthLimit,
                ..
            }
        ));
    }

    // ─── stage 2 ──────────────────────────────────────────────────────

    #[test]
    fn canonical_refuses_video_and_caps_audio_at_five_percent() {
        let cfg = ControllerConfig::interactive();
        // 10 streams of advertised capacity: 5 % is 0.5 Mbit/s of AUDIO,
        // 7 standbys at 64 kbit/s.
        let adv = 10 * cfg.stream_bps;
        let mut a = Admission::transport(9u32, cfg.clone(), Some(adv), ClassPolicy::canonical());
        roster(&mut a);
        let mut rng = SplitMix64(3);
        let mut log = DecisionLog::default();
        for s in 1..6u32 {
            assert!(
                matches!(
                    a.request(0, &req(s, Role::Primary), &mut rng, &mut log),
                    AdmitDecision::Refuse {
                        reason: RefuseReason::ClassRefused,
                        ..
                    }
                ),
                "a canonical never commits video"
            );
        }
        let mut admitted = 0u64;
        for s in 1..32u32 {
            if matches!(
                a.request(0, &req(s, Role::Standby), &mut rng, &mut log),
                AdmitDecision::Admit { .. }
            ) {
                admitted += 1;
            }
        }
        #[allow(clippy::cast_precision_loss)]
        let cap = 0.05 * adv as f64;
        #[allow(clippy::cast_precision_loss)]
        let committed = a.committed_bps() as f64;
        assert!(committed <= cap + 1.0, "{committed} > 5 % of {adv}");
        assert_eq!(admitted, 7);
        assert_eq!(
            RefuseReason::ClassRefused.token(),
            "relay_class_refused:video"
        );
    }

    #[test]
    fn a_nonmember_forwarder_never_fans_out_a_stream() {
        // W5(a): a second downstream leg of one stream through the same
        // non-member is refused `relay_nonmember_fanout`. Mutation: with
        // `max_children: None` the second leg is admitted, so the assertion
        // below fails (checked by `nonmember_fanout_mutant_admits`).
        let cfg = ControllerConfig::interactive();
        let mut a = Admission::transport(
            9u32,
            cfg.clone(),
            Some(10 * cfg.stream_bps),
            ClassPolicy::nonmember_forwarder(),
        );
        roster(&mut a);
        let mut rng = SplitMix64(4);
        let mut log = DecisionLog::default();
        assert!(matches!(
            a.request(0, &req(1, Role::Primary), &mut rng, &mut log),
            AdmitDecision::Admit { .. }
        ));
        let second = a.request(0, &req(2, Role::Primary), &mut rng, &mut log);
        assert!(
            matches!(
                second,
                AdmitDecision::Refuse {
                    reason: RefuseReason::NotMember,
                    ..
                }
            ),
            "{second:?}"
        );
        assert_eq!(RefuseReason::NotMember.token(), "relay_nonmember_fanout");
    }

    #[test]
    fn nonmember_fanout_mutant_admits() {
        let cfg = ControllerConfig::interactive();
        let mut a = Admission::transport(
            9u32,
            cfg.clone(),
            Some(10 * cfg.stream_bps),
            ClassPolicy::default(),
        );
        roster(&mut a);
        a.set_probe_streams(4);
        let mut rng = SplitMix64(4);
        let mut log = DecisionLog::default();
        let _ = a.request(0, &req(1, Role::Primary), &mut rng, &mut log);
        assert!(
            matches!(
                a.request(0, &req(2, Role::Primary), &mut rng, &mut log),
                AdmitDecision::Admit { .. }
            ),
            "without M2's one-leg rule the second leg is admitted: the W5(a) check is live"
        );
    }

    #[test]
    fn admit_closed_refuses_growth_but_keeps_commitments() {
        let cfg = ControllerConfig::interactive();
        let mut a = Admission::publisher(0u32, cfg.clone(), Some(10 * cfg.stream_bps));
        roster(&mut a);
        a.set_probe_streams(8);
        let mut rng = SplitMix64(5);
        let mut log = DecisionLog::default();
        assert!(matches!(
            a.request(0, &req(1, Role::Primary), &mut rng, &mut log),
            AdmitDecision::Admit { .. }
        ));
        a.set_admit_closed(true);
        assert!(matches!(
            a.request(0, &req(2, Role::Standby), &mut rng, &mut log),
            AdmitDecision::Refuse {
                reason: RefuseReason::AdmitClosed,
                ..
            }
        ));
        // A downgrade never grows a commitment: still admitted.
        assert!(matches!(
            a.request(0, &req(1, Role::Standby), &mut rng, &mut log),
            AdmitDecision::Admit { .. }
        ));
        assert_eq!(a.ledger().len(), 1);
    }

    #[test]
    fn a_load_shed_is_lifo_and_keeps_forwarding_until_the_drain_ends() {
        let cfg = ControllerConfig::interactive();
        let mut a = Admission::publisher(0u32, cfg.clone(), Some(20 * cfg.stream_bps));
        roster(&mut a);
        a.set_probe_streams(8);
        let mut rng = SplitMix64(6);
        let mut log = DecisionLog::default();
        for s in 1..=4u32 {
            let _ = a.request(u64::from(s), &req(s, Role::Standby), &mut rng, &mut log);
        }
        let shed = a.shed_all_draining(100, super::super::ShedReason::LoadShed, &mut log);
        assert_eq!(shed, vec![4, 3, 2, 1], "newest admission first");
        assert_eq!(a.committed_bps(), 0);
        assert_eq!(
            a.forwarding_to().len(),
            4,
            "still forwarded while they move"
        );
        assert!(a.release(&2));
        assert_eq!(a.forwarding_to().len(), 3);
        a.expire_drains(100 + cfg.down_silence_ms);
        assert!(a.forwarding_to().is_empty());
    }

    #[test]
    fn other_streams_commitments_share_the_uplink() {
        let cfg = ControllerConfig::interactive();
        let mut a = Admission::publisher(0u32, cfg.clone(), Some(4 * cfg.stream_bps));
        roster(&mut a);
        a.set_probe_streams(8);
        // 65 % of 4 streams = 2.6 streams; another stream holds 2.
        a.set_external_committed(2 * cfg.stream_bps);
        let mut rng = SplitMix64(7);
        let mut log = DecisionLog::default();
        let mut n = 0;
        for s in 1..8u32 {
            if matches!(
                a.request(0, &req(s, Role::Primary), &mut rng, &mut log),
                AdmitDecision::Admit { .. }
            ) {
                n += 1;
            }
        }
        assert_eq!(n, 0, "0.6 of a stream left: no primary fits");
    }

    #[test]
    fn refusal_and_shed_tokens_are_stable_and_round_trip() {
        let mut seen = std::collections::BTreeSet::new();
        for r in RefuseReason::ALL {
            assert!(seen.insert(r.token()), "duplicate token {}", r.token());
            assert_eq!(RefuseReason::from_code(r.code()), Some(r));
        }
        for r in [
            super::super::ShedReason::OverCommitted,
            super::super::ShedReason::UpstreamLost,
            super::super::ShedReason::Preempted,
            super::super::ShedReason::LoadShed,
        ] {
            assert_eq!(super::super::ShedReason::from_code(r.code()), Some(r));
        }
    }
}
