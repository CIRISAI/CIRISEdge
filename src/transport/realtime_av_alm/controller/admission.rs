//! C2 — admission, for the publisher ("parent 0") and every relay alike.
//!
//! ```text
//!   usable = commit_fraction · min(advertised, measured) − committed − reserve
//! ```
//!
//! - **advertised** is the forwarder's own claim (operator cap / signed ad);
//!   absent = unbounded.
//! - **measured** is the uplink ceiling learned from congested egress windows
//!   ([`super::EgressWindow`]): a window with drops or queue delay over the
//!   threshold measured what the uplink really carries. Until the first such
//!   window it is unknown, and growth is gated by a **probe allowance**
//!   instead: the demonstrated clean floor plus an allowance that starts at
//!   ONE stream (the cold-start trial slot, so an unmeasured relay is not
//!   zero) and doubles after each clean window in which it was used.
//! - **commit_fraction** (0.65) applies to the min, so neither an honest
//!   claim nor a measurement is ever committed past 65 %.
//! - **committed** is a live ledger keyed by subscriber (primary = stream
//!   rate, standby = audio rate), not static config.
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
    floor_bps: f64,
    probe_bps: f64,
    clean_streak: u32,
    congested_streak: u32,
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
            floor_bps: 0.0,
            probe_bps: probe,
            clean_streak: 0,
            congested_streak: 0,
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

    /// The hard limit: `commit_fraction · min(advertised, measured) − reserve`.
    /// Shedding is against this limit only (the probe gate limits growth,
    /// never takes back what was admitted).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn hard_limit_bps(&self) -> f64 {
        let adv = self.advertised_bps.map_or(f64::INFINITY, |a| a as f64);
        let measured = self.ceiling_bps.unwrap_or(f64::INFINITY);
        (self.fraction() * adv.min(measured)
            - self.cfg.reserve_bps as f64
            - self.external_committed as f64)
            .max(0.0)
    }

    fn fraction(&self) -> f64 {
        self.class.fraction.unwrap_or(self.cfg.commit_fraction)
    }

    /// The admission limit (bits/s) before the forwarder reserve: the hard
    /// limit, further gated by the probe allowance while unmeasured.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn limit_bps(&self) -> f64 {
        let adv = self.advertised_bps.map_or(f64::INFINITY, |a| a as f64);
        let measured = self.ceiling_bps.unwrap_or(f64::INFINITY);
        let hard = self.fraction() * adv.min(measured);
        let probe = match (self.ceiling_bps, self.class.trial_slot) {
            (Some(_), _) => f64::INFINITY,
            (None, true) => self.floor_bps + self.probe_bps,
            // No trial slot: an unmeasured forwarder commits only against
            // what it advertises (the canonical's configured capacity), or
            // what it has demonstrated.
            (None, false) if self.advertised_bps.is_some() => f64::INFINITY,
            (None, false) => self.floor_bps,
        };
        // The node's other streams share the MEASURED uplink, so they come
        // off the hard limit; the probe gate is this admission's own growth.
        let hard = hard - self.external_committed as f64;
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
        let headroom = (self.limit_bps() - self.committed_bps() as f64).max(0.0);
        let can_preempt = self
            .depth
            .is_some_and(|d| d.saturating_add(2) <= self.cfg.max_depth);
        let forwarder_headroom = if can_preempt && self.cfg.admission_enabled {
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
            headroom_bps: headroom as u64,
            forwarder_headroom_bps: forwarder_headroom as u64,
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
        if w.congested && w.sent_bps > 0.0 {
            self.clean_streak = 0;
            self.congested_streak += 1;
            if self.congested_streak >= 2 {
                let c = match self.ceiling_bps {
                    None => w.sent_bps,
                    Some(c) => 0.5f64.mul_add(w.sent_bps - c, c),
                };
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
            }
        } else if !w.congested {
            self.congested_streak = 0;
            self.clean_streak += 1;
            if let Some(c) = self.ceiling_bps {
                if w.sent_bps > c {
                    self.ceiling_bps = Some(w.sent_bps);
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
                    dropped_bytes: 0,
                    max_queue_ms: 0.0,
                    congested: false,
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
        let w = EgressWindow {
            sent_bps: real,
            dropped_bytes: 10,
            max_queue_ms: 500.0,
            congested: true,
        };
        assert!(
            a.on_egress_window(0, &w, &mut log).is_empty(),
            "one window is not a ceiling"
        );
        let shed = a.on_egress_window(1000, &w, &mut log);
        assert_eq!(
            shed,
            vec![9, 8, 7, 6, 5, 4, 3, 2],
            "LIFO down to 0.65 × 4 → 2"
        );
        assert_eq!(log.count(DecisionKind::OverClaim), 1);
        let _ = &mut rng;
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
