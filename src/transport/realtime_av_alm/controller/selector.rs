//! C4 — the parent selector, one per (this node, remote stream).
//!
//! It holds one primary (full stream) and one warm standby (audio only,
//! measured by real delivery, not synthetic probes), and decides when to
//! join, fail over and switch. Herding is controlled by construction:
//!
//! - **randomised join**: a join waits `U(0, join_jitter_ms)`, and among
//!   candidates scoring within 10 % of the best one is drawn at random;
//! - **admission is asked, not assumed**: a refusal backs the candidate off
//!   for `max(retry_after, base · 2^k · U(0.5, 1.5))`;
//! - **hysteresis**: a voluntary switch needs `S_standby > S_primary · 1.2`
//!   for `hysteresis_hold_windows` closed windows;
//! - **minimum dwell**: no voluntary switch within `min_dwell_ms · 2^k` of
//!   the last switch or join, k = voluntary switches in the last 120 s
//!   (failure switches are exempt, but rate-limited to one per
//!   `failover_min_interval_ms`);
//! - **make-before-break**: a voluntary switch upgrades the standby; the old
//!   primary is demoted (to standby) only after the new one delivered
//!   `mbb_confirm_chunks` full chunks AND `mbb_confirm_ms` passed;
//! - **failover** promotes the warm standby first (audio was already
//!   flowing, so audio has no gap).
//!
//! Score: `S = w_d·delivery + w_c·headroom + w_l·latency + w_s·stability`,
//! times a health factor. Membership and trust are not weights: both gate
//! candidacy before any scoring ([`ParentSelector::set_members`],
//! [`ParentSelector::set_eligible`]), and a parent that loses either is
//! dropped. Nothing else touches them.
//!
//! Multi-hop: candidates carry ancestry and depth in their [`Offer`]. A
//! candidate whose ancestry contains this node, or whose child would exceed
//! `max_depth`, is never picked; a standby under the primary (shared failure
//! domain) or without room to take over is down-weighted; a node with children never voluntarily moves deeper; and a
//! primary whose offer shows this node in its ancestry is a loop and is
//! marked down. Suspicion of a deeper parent waits longer
//! (`suspect · (1 + depth/2)`) so a relay's own failover finishes before its
//! children give up on it.

use std::collections::{BTreeMap, BTreeSet};

use super::decision_log::{DecisionKind, DecisionLog};
use super::path_meter::PathMeter;
use super::peer_state::{PeerHealth, PeerState};
use super::{AdmitDecision, ControllerConfig, JitterSource, Offer, PeerRef, Role};

/// What the caller must do on the wire (stage 2: a C3 frame each).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectorAction<P> {
    /// Ask `parent` for `role` (new, upgrade or downgrade).
    Subscribe {
        /// The forwarder.
        parent: P,
        /// The role.
        role: Role,
    },
    /// Leave `parent`.
    Unsubscribe {
        /// The forwarder.
        parent: P,
    },
}

/// This node's upstream, for its own admission (multi-hop accounting).
#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamView<P> {
    /// The primary parent.
    pub parent: P,
    /// This node's depth (parent's + 1).
    pub depth: u8,
    /// This node's ancestry, root first (parent's ancestry + parent).
    pub ancestry: Vec<P>,
    /// Whether the primary is delivering (not suspected or down).
    pub healthy: bool,
    /// Publisher-to-here latency (ms).
    pub latency_ms: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Link {
    None,
    Requested {
        role: Role,
        at_ms: u64,
        was_standby: bool,
    },
    Standby,
    Primary,
    Promoting {
        since_ms: u64,
        first_full_ms: Option<u64>,
        full_chunks: u32,
    },
}

impl Link {
    fn subscribed(self) -> bool {
        matches!(self, Self::Standby | Self::Primary | Self::Promoting { .. })
    }
}

#[derive(Debug, Clone)]
struct Cand<P> {
    offer: Option<Offer<P>>,
    rtt_ms: f64,
    meter: PathMeter,
    health: PeerHealth,
    link: Link,
    subscribed_at: u64,
    backoff_until: u64,
    failures: u32,
    better_windows: u32,
    no_room_offers: u32,
    eligible: bool,
}

/// How long an unanswered subscribe waits before it counts as refused.
pub const REQUEST_TIMEOUT_MS: u64 = 3_000;

/// Consecutive offers without room to take over before a standby is replaced.
pub const STANDBY_NO_ROOM_OFFERS: u32 = 5;

/// A standby under the primary (shared failure domain) scores this much.
pub const STANDBY_SHARED_DOMAIN_FACTOR: f64 = 0.6;

/// A standby without room to take over scores this much.
pub const STANDBY_NO_ROOM_FACTOR: f64 = 0.7;

/// Window over which voluntary switches double the dwell.
pub const FLAP_WINDOW_MS: u64 = 120_000;

/// A voluntary switch also needs an absolute score gain of at least
/// `hysteresis · this` (a ratio alone is noise when both scores are small).
pub const VOLUNTARY_MIN_ABS_GAIN_FACTOR: f64 = 0.5;

/// Candidates within this fraction of the best score are drawn at random
/// (jitter on); otherwise the best wins.
pub const PICK_BAND: f64 = 0.10;

/// C4 + C6 for one stream at one node.
#[derive(Debug, Clone)]
pub struct ParentSelector<P: PeerRef> {
    me: P,
    cfg: ControllerConfig,
    forward_capable: bool,
    has_children: bool,
    cands: BTreeMap<P, Cand<P>>,
    primary: Option<P>,
    standby: Option<P>,
    last_primary: Option<P>,
    join_at: Option<u64>,
    last_switch_ms: u64,
    last_failover_ms: Option<u64>,
    recent_switches: Vec<u64>,
    last_standby_rotation_ms: Option<u64>,
    members: BTreeSet<P>,
    parent_changes: u64,
}

impl<P: PeerRef> ParentSelector<P> {
    /// A selector for `me`. `forward_capable` is told to forwarders so they
    /// may grant it the forwarder reserve.
    #[must_use]
    pub fn new(me: P, cfg: ControllerConfig, forward_capable: bool) -> Self {
        Self {
            me,
            cfg,
            forward_capable,
            has_children: false,
            cands: BTreeMap::new(),
            primary: None,
            standby: None,
            last_primary: None,
            join_at: None,
            last_switch_ms: 0,
            last_failover_ms: None,
            recent_switches: Vec::new(),
            last_standby_rotation_ms: None,
            members: BTreeSet::new(),
            parent_changes: 0,
        }
    }

    /// Whether this node can forward (sent with every subscribe).
    #[must_use]
    pub fn forward_capable(&self) -> bool {
        self.forward_capable
    }

    /// Tell the selector whether this node has admitted children.
    pub fn set_has_children(&mut self, has: bool) {
        self.has_children = has;
    }

    /// The room roster (membership gate, CC 5.4.6 / E1 item 1 / 6.1.6).
    /// Fail-closed: a candidate outside it is never a media parent (primary
    /// or standby), whatever it offers; a parent that leaves the roster is
    /// dropped. An empty roster selects nobody.
    pub fn set_members(&mut self, members: impl IntoIterator<Item = P>) {
        self.members = members.into_iter().collect();
    }

    /// The trust gate's verdict for `p`. Health never changes this.
    pub fn set_eligible(&mut self, p: &P, eligible: bool) {
        if let Some(c) = self.cands.get_mut(p) {
            c.eligible = eligible;
        }
    }

    /// The primary parent.
    #[must_use]
    pub fn primary(&self) -> Option<&P> {
        self.primary.as_ref()
    }

    /// The warm standby.
    #[must_use]
    pub fn standby(&self) -> Option<&P> {
        self.standby.as_ref()
    }

    /// Primary changes after the first join.
    #[must_use]
    pub fn parent_changes(&self) -> u64 {
        self.parent_changes
    }

    /// Whether a make-before-break overlap is in progress.
    #[must_use]
    pub fn promoting(&self) -> Option<&P> {
        self.cands
            .iter()
            .find(|(_, c)| matches!(c.link, Link::Promoting { .. }))
            .map(|(p, _)| p)
    }

    /// The health of candidate `p`.
    #[must_use]
    pub fn state_of(&self, p: &P) -> Option<PeerState> {
        self.cands.get(p).map(|c| c.health.state())
    }

    /// Every parent this node is currently subscribed to, with its role.
    #[must_use]
    pub fn subscriptions(&self) -> Vec<(P, Role)> {
        self.cands
            .iter()
            .filter_map(|(p, c)| match c.link {
                Link::Primary | Link::Promoting { .. } => Some((p.clone(), Role::Primary)),
                Link::Standby => Some((p.clone(), Role::Standby)),
                _ => None,
            })
            .collect()
    }

    /// This node's upstream, for its own admission.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn upstream_view(&self) -> Option<UpstreamView<P>> {
        let p = self.primary.as_ref()?;
        let c = self.cands.get(p)?;
        let o = c.offer.as_ref()?;
        let mut ancestry = o.ancestry.clone();
        ancestry.push(p.clone());
        Some(UpstreamView {
            parent: p.clone(),
            depth: o.depth.saturating_add(1),
            ancestry,
            healthy: matches!(
                c.health.state(),
                PeerState::Available | PeerState::Degraded | PeerState::Recovering
            ) && o.forwarding,
            latency_ms: Self::e2e_latency(c) as u32,
        })
    }

    fn cand(&mut self, p: &P, now_ms: u64) -> &mut Cand<P> {
        let cfg = &self.cfg;
        self.cands.entry(p.clone()).or_insert_with(|| Cand {
            offer: None,
            rtt_ms: 0.0,
            meter: PathMeter::new(cfg.meter_window_ms, cfg.ewma_alpha),
            health: PeerHealth::new(now_ms),
            link: Link::None,
            subscribed_at: now_ms,
            backoff_until: 0,
            failures: 0,
            better_windows: 0,
            no_room_offers: 0,
            eligible: true,
        })
    }

    /// An offer from candidate `offer.from`, seen with round-trip `rtt_ms`.
    pub fn on_offer(&mut self, now_ms: u64, offer: Offer<P>, rtt_ms: f64, log: &mut DecisionLog) {
        if offer.from == self.me {
            return;
        }
        let from = offer.from.clone();
        let me = self.me.clone();
        let is_primary = self.primary.as_ref() == Some(&from);
        let (stream_bps, standby_bps) = (self.cfg.stream_bps, self.cfg.standby_bps);
        let down_hold_ms = self.cfg.down_hold_ms;
        let c = self.cand(&from, now_ms);
        let looped = offer.ancestry.contains(&me);
        c.rtt_ms = rtt_ms;
        c.meter.on_rtt(rtt_ms);
        let upgrade = stream_bps.saturating_sub(standby_bps);
        c.no_room_offers = if offer.headroom_bps < upgrade {
            c.no_room_offers + 1
        } else {
            0
        };
        c.offer = Some(offer);
        if is_primary && looped {
            if c.health.mark_down(now_ms).is_some() {
                log.record(
                    now_ms,
                    &me,
                    DecisionKind::LoopDetected,
                    Some(&from),
                    0,
                    "ancestry contains self",
                );
            }
        } else if c.link == Link::None {
            if let Some((_, to)) = c.health.on_alive(now_ms, down_hold_ms) {
                log.record(
                    now_ms,
                    &me,
                    DecisionKind::PeerState,
                    Some(&from),
                    to as i64,
                    "offer",
                );
            }
        }
    }

    /// A media chunk from `from` (after the caller's dedupe or not — the
    /// meter is per path, so duplicates across paths are counted per path).
    pub fn on_chunk(
        &mut self,
        now_ms: u64,
        from: &P,
        seq: u64,
        full: bool,
        bytes: u64,
        latency_ms: f64,
    ) {
        let Some(c) = self.cands.get_mut(from) else {
            return;
        };
        if !c.link.subscribed() {
            return;
        }
        c.meter.on_chunk(now_ms, seq, bytes, latency_ms);
        if let Link::Promoting {
            first_full_ms,
            full_chunks,
            ..
        } = &mut c.link
        {
            if full {
                first_full_ms.get_or_insert(now_ms);
                *full_chunks += 1;
            }
        }
    }

    /// The link to `from` is gone.
    pub fn on_link_down(&mut self, now_ms: u64, from: &P, log: &mut DecisionLog) {
        let me = self.me.clone();
        let Some(c) = self.cands.get_mut(from) else {
            return;
        };
        if let Some((_, to)) = c.health.mark_down(now_ms) {
            log.record(
                now_ms,
                &me,
                DecisionKind::PeerState,
                Some(from),
                to as i64,
                "link down",
            );
        }
        if self.standby.as_ref() == Some(from) {
            self.standby = None;
            c.link = Link::None;
        } else if matches!(c.link, Link::Requested { .. } | Link::Promoting { .. }) {
            c.link = Link::None;
        }
        // A primary is handled by the next tick's failover (it is Down).
    }

    /// `from` shed this node.
    pub fn on_shed(
        &mut self,
        now_ms: u64,
        from: &P,
        rng: &mut dyn JitterSource,
        log: &mut DecisionLog,
    ) {
        let me = self.me.clone();
        let base = self.cfg.backoff_base_ms * 4;
        let Some(c) = self.cands.get_mut(from) else {
            return;
        };
        c.failures += 1;
        c.backoff_until = now_ms + self.cfg.backoff_ms(base, c.failures, rng);
        c.link = Link::None;
        log.record(
            now_ms,
            &me,
            DecisionKind::Unsubscribe,
            Some(from),
            0,
            "shed",
        );
        if self.primary.as_ref() == Some(from) {
            self.primary = None;
        }
        if self.standby.as_ref() == Some(from) {
            self.standby = None;
        }
    }

    /// The forwarder `from` answered a subscribe.
    pub fn on_decision(
        &mut self,
        now_ms: u64,
        from: &P,
        decision: &AdmitDecision,
        rng: &mut dyn JitterSource,
        log: &mut DecisionLog,
    ) -> Vec<SelectorAction<P>> {
        let me = self.me.clone();
        let mut out = Vec::new();
        let Some(link) = self.cands.get(from).map(|c| c.link) else {
            return out;
        };
        let Link::Requested {
            role, was_standby, ..
        } = link
        else {
            // Stale answer for something we no longer want.
            if matches!(decision, AdmitDecision::Admit { .. }) && !link.subscribed() {
                out.push(SelectorAction::Unsubscribe {
                    parent: from.clone(),
                });
            }
            return out;
        };
        match decision {
            AdmitDecision::Refuse { retry_after_ms, .. } => {
                let base = self.cfg.backoff_base_ms;
                let c = self.cands.get_mut(from).expect("present");
                c.failures += 1;
                let b = self.cfg.backoff_ms(base, c.failures, rng);
                c.backoff_until = now_ms + b.max(*retry_after_ms);
                c.link = if was_standby {
                    Link::Standby
                } else {
                    Link::None
                };
                if !was_standby && self.standby.as_ref() == Some(from) {
                    self.standby = None;
                }
            }
            AdmitDecision::Admit { .. } => match role {
                Role::Standby => {
                    let c = self.cands.get_mut(from).expect("present");
                    c.link = Link::Standby;
                    c.failures = 0;
                    c.subscribed_at = now_ms;
                    c.meter.restart();
                    self.standby = Some(from.clone());
                }
                Role::Primary => {
                    if self.primary.is_some() {
                        let c = self.cands.get_mut(from).expect("present");
                        c.link = Link::Promoting {
                            since_ms: now_ms,
                            first_full_ms: None,
                            full_chunks: 0,
                        };
                        log.record(
                            now_ms,
                            &me,
                            DecisionKind::PromoteStart,
                            Some(from),
                            0,
                            "mbb",
                        );
                    } else {
                        if was_standby {
                            self.standby = None;
                        }
                        let c = self.cands.get_mut(from).expect("present");
                        c.link = Link::Primary;
                        c.failures = 0;
                        if !was_standby {
                            c.subscribed_at = now_ms;
                            c.meter.restart();
                        }
                        self.set_primary(now_ms, from.clone(), log, "admitted");
                    }
                }
            },
        }
        out
    }

    fn set_primary(&mut self, now_ms: u64, p: P, log: &mut DecisionLog, why: &'static str) {
        if self.last_primary.as_ref().is_some_and(|lp| lp != &p) {
            self.parent_changes += 1;
        }
        log.record(now_ms, &self.me, DecisionKind::Subscribe, Some(&p), 1, why);
        self.last_primary = Some(p.clone());
        self.primary = Some(p);
        self.last_switch_ms = now_ms;
    }

    #[allow(clippy::cast_precision_loss)]
    fn e2e_latency(c: &Cand<P>) -> f64 {
        let s = c.meter.snapshot();
        if c.link.subscribed() && s.windows >= 1 && s.latency_ms > 0.0 {
            s.latency_ms
        } else {
            let up = c
                .offer
                .as_ref()
                .map_or(0.0, |o| f64::from(o.upstream_latency_ms));
            up + c.rtt_ms / 2.0
        }
    }

    #[allow(clippy::cast_precision_loss)]
    fn score(&self, c: &Cand<P>) -> f64 {
        let w = self.cfg.weights;
        let s = c.meter.snapshot();
        let measured = c.link.subscribed() && s.windows >= 2;
        let delivery = if measured {
            s.burst
                .mul_add(-0.1, (-5.0f64).mul_add(s.loss, 1.0))
                .clamp(0.0, 1.0)
        } else {
            0.8
        };
        let own = match c.link {
            Link::Primary | Link::Promoting { .. } => self.cfg.stream_bps,
            Link::Standby => self.cfg.standby_bps,
            _ => 0,
        };
        let headroom = c.offer.as_ref().map_or(0.0, |o| {
            ((o.headroom_bps + own) as f64 / self.cfg.stream_bps.max(1) as f64).min(4.0) / 4.0
        });
        let latency =
            (1.0 - Self::e2e_latency(c) / self.cfg.latency_budget_ms.max(1) as f64).clamp(0.0, 1.0);
        let stability = if measured { s.stability } else { 0.5 };
        let health = match c.health.state() {
            PeerState::Available => 1.0,
            PeerState::Recovering => 0.9,
            PeerState::Degraded => 0.8,
            PeerState::Suspected | PeerState::Down => 0.0,
        };
        health
            * w.stability.mul_add(
                stability,
                w.latency
                    .mul_add(latency, w.delivery.mul_add(delivery, w.capacity * headroom)),
            )
    }

    fn viable(&self, p: &P, c: &Cand<P>, role: Role, now_ms: u64) -> bool {
        let Some(o) = c.offer.as_ref() else {
            return false;
        };
        if !c.eligible
            || !self.members.contains(p)
            || !o.forwarding
            || o.ancestry.contains(&self.me)
            || o.depth.saturating_add(1) > self.cfg.max_depth
            || now_ms < c.backoff_until
            || matches!(c.health.state(), PeerState::Suspected | PeerState::Down)
        {
            return false;
        }
        if self.cfg.admission_enabled && self.headroom_for(o, role) < self.cfg.role_bps(role) {
            return false;
        }
        if role == Role::Standby && self.primary.as_ref() == Some(p) {
            return false;
        }
        true
    }

    /// Whether `c` sits under the current primary (a shared failure domain).
    /// The root is in every ancestry, so a root primary shares with nobody.
    fn under_primary(&self, c: &Cand<P>) -> bool {
        let Some(pp) = &self.primary else {
            return false;
        };
        let primary_is_root = self
            .cands
            .get(pp)
            .and_then(|c| c.offer.as_ref())
            .is_some_and(|o| o.depth == 0);
        !primary_is_root && c.offer.as_ref().is_some_and(|o| o.ancestry.contains(pp))
    }

    /// The headroom an offer gives THIS node for `role`: a forward-capable
    /// node asking for a primary may preempt non-forwarders.
    fn headroom_for(&self, o: &Offer<P>, role: Role) -> u64 {
        if self.forward_capable && role == Role::Primary {
            o.forwarder_headroom_bps.max(o.headroom_bps)
        } else {
            o.headroom_bps
        }
    }

    /// Whether `c` advertises room to become a primary.
    fn has_room(&self, c: &Cand<P>) -> bool {
        !self.cfg.admission_enabled
            || c.offer
                .as_ref()
                .is_some_and(|o| self.headroom_for(o, Role::Primary) >= self.cfg.stream_bps)
    }

    /// Standby preference: diversity (not under the primary) and room to
    /// take over are score factors, not exclusions, so a node in a tight or
    /// shallow world still keeps an audio standby.
    fn standby_score(&self, c: &Cand<P>) -> f64 {
        let mut s = self.score(c);
        if self.under_primary(c) {
            s *= STANDBY_SHARED_DOMAIN_FACTOR;
        }
        if !self.has_room(c) {
            s *= STANDBY_NO_ROOM_FACTOR;
        }
        s
    }

    fn pick(
        &self,
        role: Role,
        now_ms: u64,
        require_room: bool,
        rng: &mut dyn JitterSource,
    ) -> Option<P> {
        let mut scored: Vec<(P, f64)> = self
            .cands
            .iter()
            .filter(|(_, c)| c.link == Link::None)
            .filter(|(p, c)| self.viable(p, c, role, now_ms))
            .filter(|(_, c)| !require_room || self.has_room(c))
            .map(|(p, c)| {
                let s = match role {
                    Role::Primary => self.score(c),
                    Role::Standby => self.standby_score(c),
                };
                (p.clone(), s)
            })
            .collect();
        let best = scored.iter().map(|(_, s)| *s).fold(f64::MIN, f64::max);
        if scored.is_empty() {
            return None;
        }
        if self.cfg.jitter {
            scored.retain(|(_, s)| *s >= best * (1.0 - PICK_BAND));
            let i = usize::try_from(rng.range_u64(0, scored.len() as u64)).unwrap_or(0);
            scored.into_iter().nth(i).map(|(p, _)| p)
        } else {
            scored.into_iter().find(|(_, s)| *s >= best).map(|(p, _)| p)
        }
    }

    /// The voluntary-switch dwell: `min_dwell · 2^k`, k = voluntary switches
    /// in the last [`FLAP_WINDOW_MS`] (capped at 8×), so a noisy pair cannot
    /// flap at the base dwell.
    fn dwell_ms(&self, now_ms: u64) -> u64 {
        let k = self
            .recent_switches
            .iter()
            .filter(|&&t| now_ms.saturating_sub(t) < FLAP_WINDOW_MS)
            .count()
            .min(3);
        self.cfg.min_dwell_ms << k
    }

    fn request(
        &mut self,
        now_ms: u64,
        p: &P,
        role: Role,
        why: &'static str,
        log: &mut DecisionLog,
    ) -> SelectorAction<P> {
        let c = self.cands.get_mut(p).expect("candidate");
        c.link = Link::Requested {
            role,
            at_ms: now_ms,
            was_standby: c.link == Link::Standby,
        };
        log.record(
            now_ms,
            &self.me,
            DecisionKind::Subscribe,
            Some(p),
            i64::from(role == Role::Primary) * 2,
            why,
        );
        SelectorAction::Subscribe {
            parent: p.clone(),
            role,
        }
    }

    fn drop_parent(
        &mut self,
        now_ms: u64,
        p: &P,
        rng: &mut dyn JitterSource,
        log: &mut DecisionLog,
        why: &'static str,
    ) -> SelectorAction<P> {
        let base = self.cfg.backoff_base_ms;
        let c = self.cands.get_mut(p).expect("candidate");
        c.link = Link::None;
        c.failures += 1;
        c.backoff_until = now_ms + self.cfg.backoff_ms(base, c.failures, rng);
        log.record(now_ms, &self.me, DecisionKind::Unsubscribe, Some(p), 0, why);
        SelectorAction::Unsubscribe { parent: p.clone() }
    }

    /// Advance the controller.
    #[allow(
        clippy::too_many_lines,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn tick(
        &mut self,
        now_ms: u64,
        rng: &mut dyn JitterSource,
        log: &mut DecisionLog,
    ) -> Vec<SelectorAction<P>> {
        let mut out = Vec::new();
        if self.join_at.is_none() {
            let delay = if self.cfg.jitter {
                rng.range_u64(0, self.cfg.join_jitter_ms + 1)
            } else {
                0
            };
            self.join_at = Some(now_ms + delay);
        }
        let join_at = self.join_at.unwrap_or(now_ms);
        if now_ms < join_at {
            return out;
        }
        let me = self.me.clone();

        // 1. Meters + health (C1 → C6).
        let mut rolled_standby = false;
        let standby = self.standby.clone();
        for (p, c) in &mut self.cands {
            let rolled = c.meter.roll(now_ms);
            if rolled && standby.as_ref() == Some(p) {
                rolled_standby = true;
            }
            let silent = c.link.subscribed().then(|| {
                let last = c
                    .meter
                    .last_arrival_ms()
                    .unwrap_or(c.subscribed_at)
                    .max(c.subscribed_at);
                let depth = c.offer.as_ref().map_or(0, |o| u64::from(o.depth.min(4)));
                now_ms.saturating_sub(last) * 2 / (2 + depth)
            });
            let snap = c.meter.snapshot();
            // Degraded = loss over the threshold OR end-to-end latency over
            // the stream class's budget (an interactive call that arrives
            // late is as broken as one that arrives lossy).
            #[allow(clippy::cast_precision_loss)]
            let over_budget = snap.latency_ms > self.cfg.latency_budget_ms as f64;
            let degraded = c.link.subscribed()
                && snap.windows >= 1
                && (snap.loss >= self.cfg.degraded_loss || over_budget);
            if let Some((_, to)) = c.health.update(now_ms, silent, degraded, &self.cfg) {
                log.record(
                    now_ms,
                    &me,
                    DecisionKind::PeerState,
                    Some(p),
                    to as i64,
                    "health",
                );
            }
            if let Link::Requested {
                at_ms, was_standby, ..
            } = c.link
            {
                if now_ms.saturating_sub(at_ms) > REQUEST_TIMEOUT_MS {
                    c.failures += 1;
                    c.backoff_until = now_ms
                        + self
                            .cfg
                            .backoff_ms(self.cfg.backoff_base_ms, c.failures, rng);
                    c.link = if was_standby {
                        Link::Standby
                    } else {
                        Link::None
                    };
                }
            }
        }
        if let Some(s) = &self.standby {
            if self
                .cands
                .get(s)
                .is_some_and(|c| !c.link.subscribed() && !matches!(c.link, Link::Requested { .. }))
            {
                self.standby = None;
            }
        }

        // 2. Make-before-break completion.
        if let Some(newp) = self.promoting().cloned() {
            let c = &self.cands[&newp];
            let Link::Promoting {
                since_ms,
                first_full_ms,
                full_chunks,
            } = c.link
            else {
                unreachable!()
            };
            let confirmed = full_chunks >= self.cfg.mbb_confirm_chunks
                && first_full_ms.is_some_and(|f| now_ms >= f + self.cfg.mbb_confirm_ms);
            let dead = matches!(c.health.state(), PeerState::Suspected | PeerState::Down);
            if confirmed {
                let old = self.primary.clone();
                self.cands.get_mut(&newp).expect("present").link = Link::Primary;
                if self.standby.as_ref() == Some(&newp) {
                    self.standby = None;
                }
                self.set_primary(now_ms, newp.clone(), log, "mbb confirmed");
                log.record(now_ms, &me, DecisionKind::Switch, Some(&newp), 0, "mbb");
                if let Some(old) = old {
                    let healthy = self.cands.get(&old).is_some_and(|c| {
                        matches!(
                            c.health.state(),
                            PeerState::Available | PeerState::Degraded | PeerState::Recovering
                        )
                    });
                    if healthy && self.standby.is_none() {
                        out.push(self.request(now_ms, &old, Role::Standby, "demote", log));
                    } else {
                        out.push(self.drop_parent(now_ms, &old, rng, log, "replaced"));
                    }
                }
            } else if dead || now_ms.saturating_sub(since_ms) > 4 * REQUEST_TIMEOUT_MS {
                // The new parent never confirmed: back to standby.
                out.push(self.request(now_ms, &newp, Role::Standby, "promote failed", log));
            }
        }

        // 3. Primary failure (C6 → failover).
        if let Some(p) = self.primary.clone() {
            let c = &self.cands[&p];
            let depth_bad = c
                .offer
                .as_ref()
                .is_some_and(|o| o.depth.saturating_add(1) > self.cfg.max_depth);
            let bad = matches!(c.health.state(), PeerState::Suspected | PeerState::Down)
                || depth_bad
                || !self.members.contains(&p)
                || !c.eligible;
            let allowed = self
                .last_failover_ms
                .map_or(true, |t| now_ms >= t + self.cfg.failover_min_interval_ms);
            if bad && allowed {
                self.last_failover_ms = Some(now_ms);
                self.primary = None;
                log.record(
                    now_ms,
                    &me,
                    DecisionKind::Failover,
                    Some(&p),
                    c.health.state() as i64,
                    "primary lost",
                );
                out.push(self.drop_parent(now_ms, &p, rng, log, "primary lost"));
                if let Some(np) = self.promoting().cloned() {
                    // The overlap's new parent is already admitted at full rate.
                    self.cands.get_mut(&np).expect("present").link = Link::Primary;
                    if self.standby.as_ref() == Some(&np) {
                        self.standby = None;
                    }
                    self.set_primary(now_ms, np, log, "failover to promoting");
                }
            }
        }

        // 4. Acquire a primary: the warm standby first.
        let pending_primary = self.cands.values().any(|c| {
            matches!(
                c.link,
                Link::Requested {
                    role: Role::Primary,
                    ..
                }
            )
        });
        if self.primary.is_none() && !pending_primary {
            let standby_ok = self.standby.clone().filter(|s| {
                let c = &self.cands[s];
                c.link == Link::Standby
                    && c.eligible
                    && self.members.contains(s)
                    && now_ms >= c.backoff_until
                    && c.offer.as_ref().is_some_and(|o| o.forwarding)
                    && matches!(
                        c.health.state(),
                        PeerState::Available | PeerState::Degraded | PeerState::Recovering
                    )
            });
            if let Some(s) = standby_ok {
                out.push(self.request(now_ms, &s, Role::Primary, "promote standby", log));
            } else if let Some(p) = self.pick(Role::Primary, now_ms, false, rng) {
                out.push(self.request(now_ms, &p, Role::Primary, "join", log));
            }
        }

        // 5. Voluntary switch to the measured standby (hysteresis + dwell).
        if let (Some(p), Some(s)) = (self.primary.clone(), self.standby.clone()) {
            let pc = &self.cands[&p];
            let sc = &self.cands[&s];
            let calm = self.promoting().is_none() && !pending_primary && sc.link == Link::Standby;
            let depth_ok = !self.has_children
                || match (pc.offer.as_ref(), sc.offer.as_ref()) {
                    (Some(po), Some(so)) => so.depth <= po.depth,
                    _ => false,
                };
            let upgrade = self.cfg.stream_bps.saturating_sub(self.cfg.standby_bps);
            let room = !self.cfg.admission_enabled
                || sc.offer.as_ref().is_some_and(|o| o.headroom_bps >= upgrade);
            let (s_new, s_cur) = (self.score(sc), self.score(pc));
            let better = sc.meter.snapshot().windows >= 2
                && room
                && now_ms >= sc.backoff_until
                && s_new > s_cur * (1.0 + self.cfg.hysteresis)
                && s_new - s_cur >= self.cfg.hysteresis * VOLUNTARY_MIN_ABS_GAIN_FACTOR;
            if rolled_standby {
                let sc = self.cands.get_mut(&s).expect("present");
                sc.better_windows = if better { sc.better_windows + 1 } else { 0 };
            }
            let held = self.cands[&s].better_windows >= self.cfg.hysteresis_hold_windows;
            if calm && depth_ok && held && now_ms >= self.last_switch_ms + self.dwell_ms(now_ms) {
                self.cands.get_mut(&s).expect("present").better_windows = 0;
                self.recent_switches.push(now_ms);
                self.recent_switches
                    .retain(|&t| now_ms.saturating_sub(t) < FLAP_WINDOW_MS);
                out.push(self.request(now_ms, &s, Role::Primary, "voluntary", log));
            }
        }

        // 6. Keep a warm standby (diverse: not the primary, not under it).
        if let Some(s) = self.standby.clone() {
            let c = &self.cands[&s];
            let calm = c.link == Link::Standby && self.promoting().is_none();
            if c.health.state() == PeerState::Down || !self.members.contains(&s) || !c.eligible {
                self.standby = None;
                out.push(self.drop_parent(now_ms, &s, rng, log, "standby down or ineligible"));
            } else if calm
                && self.cfg.admission_enabled
                && c.no_room_offers >= STANDBY_NO_ROOM_OFFERS
                && self
                    .last_standby_rotation_ms
                    .map_or(true, |t| now_ms >= t + self.cfg.min_dwell_ms)
            {
                // It could no longer take over: rotate it, but only to a
                // candidate that has room (audio only, cheap to move).
                if let Some(n) = self.pick(Role::Standby, now_ms, true, rng) {
                    self.last_standby_rotation_ms = Some(now_ms);
                    self.standby = None;
                    out.push(self.drop_parent(now_ms, &s, rng, log, "standby has no room"));
                    out.push(self.request(now_ms, &n, Role::Standby, "standby with room", log));
                }
            }
        }
        let pending_standby = self.cands.values().any(|c| {
            matches!(
                c.link,
                Link::Requested {
                    role: Role::Standby,
                    ..
                }
            )
        });
        if self.primary.is_some()
            && self.standby.is_none()
            && !pending_standby
            && self.promoting().is_none()
        {
            if let Some(s) = self.pick(Role::Standby, now_ms, false, rng) {
                out.push(self.request(now_ms, &s, Role::Standby, "standby", log));
            }
        }
        out
    }
}
