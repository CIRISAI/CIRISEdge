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
        }
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
        (self.cfg.commit_fraction * adv.min(measured) - self.cfg.reserve_bps as f64).max(0.0)
    }

    /// The admission limit (bits/s) before the forwarder reserve: the hard
    /// limit, further gated by the probe allowance while unmeasured.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn limit_bps(&self) -> f64 {
        let adv = self.advertised_bps.map_or(f64::INFINITY, |a| a as f64);
        let measured = self.ceiling_bps.unwrap_or(f64::INFINITY);
        let hard = self.cfg.commit_fraction * adv.min(measured);
        let probe = if self.ceiling_bps.is_none() {
            self.floor_bps + self.probe_bps
        } else {
            f64::INFINITY
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
        self.members.contains(&self.me) && (self.is_root || self.upstream_healthy)
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
    #[allow(clippy::cast_precision_loss)]
    pub fn request(
        &mut self,
        now_ms: u64,
        req: &SubscribeRequest<P>,
        rng: &mut dyn JitterSource,
        log: &mut DecisionLog,
    ) -> AdmitDecision {
        // Membership is eligibility, not admission: checked even with
        // admission off, and before anything else.
        if !self.members.contains(&self.me) || !self.members.contains(&req.subscriber) {
            return self.refuse(now_ms, req, RefuseReason::NotMember, rng, log);
        }
        if !self.cfg.admission_enabled {
            self.commit(now_ms, req, log);
            return AdmitDecision::Admit { role: req.role };
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
        self.ledger.remove(sub).is_some()
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
}
