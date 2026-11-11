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
//!
//! **Tiers** (`FSD/CIRIS_MESH.md` R2/R3, §6.4–6.5): every candidate has a
//! [`Tier`]. The lowest tier with a viable candidate wins outright; scores
//! are compared only WITHIN a tier, so the canonical (usually the
//! best-provisioned, lowest-RTT candidate) can never out-score a roster
//! member. The canonical never carries video: it is never a primary, only an
//! audio (standby-role) path, taken when no member can serve the primary.
//! A node on it keeps probing the member tier with its jittered backoff and
//! moves back make-before-break ([`ParentSelector::video_unavailable`]).

use std::collections::{BTreeMap, BTreeSet};

use super::decision_log::{DecisionKind, DecisionLog};
use super::path_meter::{ChunkPos, PathMeter};
use super::peer_state::{PeerHealth, PeerState};
use super::{AdmitDecision, ControllerConfig, JitterSource, Offer, PeerRef, Role, Tier};

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
    tier: Tier,
    offer_at_ms: u64,
}

/// One chunk as a path delivered it.
#[derive(Debug, Clone, Copy)]
pub struct PathChunk {
    /// Where it sits in the stream.
    pub pos: ChunkPos,
    /// Whether it is more than a standby receives, so it shows a path
    /// delivering the full stream (a make-before-break confirms on these).
    /// A property of the chunk: a link's role says what was asked for, not
    /// what arrives.
    pub full: bool,
    /// Whether it is base-layer or audio: what a standby also receives.
    pub base_or_audio: bool,
    /// Chunks the sender put on this link ahead of it that never arrived
    /// (the link's hop counter): loss within the sender's policy.
    pub hop_lost: u64,
    /// Its size.
    pub bytes: u64,
    /// Its source-to-here latency (ms).
    pub latency_ms: f64,
}

/// How long an unanswered subscribe waits before it counts as refused.
pub const REQUEST_TIMEOUT_MS: u64 = 3_000;

/// Consecutive offers without room to take over before a standby is replaced.
pub const STANDBY_NO_ROOM_OFFERS: u32 = 5;

/// A standby under the primary (shared failure domain) scores this much.
pub const STANDBY_SHARED_DOMAIN_FACTOR: f64 = 0.6;

/// A standby without room to take over scores this much.
pub const STANDBY_NO_ROOM_FACTOR: f64 = 0.7;

/// How long after the last [`PathChunk::full`] chunk on any path the stream
/// still counts as layered. Past it nothing above the base is flowing (an
/// audio-only stream, a publisher at tier 2, a shed primary), so no other
/// chunk exists to confirm a make-before-break on.
pub const LAYERED_RECENT_MS: u64 = 2_000;

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
    /// The latest failover, until the controller takes it: when the old
    /// primary was last heard, and why it failed.
    failed_over: Option<(u64, crate::telemetry::FailoverCause)>,
    recent_switches: Vec<u64>,
    last_standby_rotation_ms: Option<u64>,
    members: BTreeSet<P>,
    parent_changes: u64,
    tiers: BTreeMap<P, Tier>,
    next_r3_probe_ms: u64,
    /// Since when this node has had no primary (member-tier R3).
    parentless_since_ms: Option<u64>,
    last_activity_ms: Option<u64>,
    /// When the stream last went from idle to active: silence on a path is
    /// never counted from before it (see `idle_aware_silence`).
    activity_since_ms: u64,
    /// When a [`PathChunk::full`] chunk last arrived on any path.
    last_full_ms: Option<u64>,
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
            failed_over: None,
            recent_switches: Vec::new(),
            last_standby_rotation_ms: None,
            members: BTreeSet::new(),
            parent_changes: 0,
            tiers: BTreeMap::new(),
            next_r3_probe_ms: 0,
            parentless_since_ms: None,
            last_activity_ms: None,
            activity_since_ms: 0,
            last_full_ms: None,
        }
    }

    /// Put candidate `p` in `tier` (default [`Tier::Member`]). A canonical
    /// candidate is exempt from the roster gate (it is a non-member
    /// transport forwarder, never a tree node) and is eligible for the audio
    /// role only.
    pub fn set_tier(&mut self, p: &P, tier: Tier) {
        self.tiers.insert(p.clone(), tier);
        if let Some(c) = self.cands.get_mut(p) {
            c.tier = tier;
        }
    }

    /// The tier of `p`.
    #[must_use]
    pub fn tier_of(&self, p: &P) -> Tier {
        self.tiers.get(p).copied().unwrap_or_default()
    }

    /// `FSD/CIRIS_MESH.md` §6.5: this node hears the stream on the canonical
    /// tier, audio only, with no member serving it the full stream.
    #[must_use]
    pub fn video_unavailable(&self) -> bool {
        self.primary.is_none()
            && self
                .standby
                .as_ref()
                .is_some_and(|s| self.tier_of(s) == Tier::Canonical)
    }

    /// Every candidate with its health, tier and whether it offered.
    #[must_use]
    pub fn candidates(&self) -> Vec<(P, PeerState, Tier)> {
        self.cands
            .iter()
            .map(|(p, c)| (p.clone(), c.health.state(), c.tier))
            .collect()
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

    /// When a chunk of the stream last arrived on any path (call ms), if
    /// ever: what `AttendeeLeft { Lost }` reads as the stream's silence.
    #[must_use]
    pub fn last_activity_ms(&self) -> Option<u64> {
        self.last_activity_ms
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
        let tier = self.tiers.get(p).copied().unwrap_or_default();
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
            tier,
            offer_at_ms: now_ms,
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
        c.offer_at_ms = now_ms;
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
    pub fn on_chunk(&mut self, now_ms: u64, from: &P, chunk: PathChunk) {
        // The stream is active (on some path), whoever delivered it.
        let resumed = self
            .last_activity_ms
            .is_none_or(|a| now_ms.saturating_sub(a) > self.cfg.suspect_silence_ms);
        if resumed {
            self.activity_since_ms = now_ms;
        }
        self.last_activity_ms = Some(now_ms);
        if chunk.full {
            self.last_full_ms = Some(now_ms);
        }
        let layered = self
            .last_full_ms
            .is_some_and(|t| now_ms.saturating_sub(t) <= LAYERED_RECENT_MS);
        let Some(c) = self.cands.get_mut(from) else {
            return;
        };
        if !c.link.subscribed() {
            return;
        }
        let fresh = c.meter.on_chunk(
            now_ms,
            chunk.pos,
            chunk.base_or_audio,
            chunk.hop_lost,
            chunk.bytes,
            chunk.latency_ms,
        );
        if let Link::Promoting {
            first_full_ms,
            full_chunks,
            ..
        } = &mut c.link
        {
            if chunk.full || !layered {
                first_full_ms.get_or_insert(now_ms);
                *full_chunks += 1;
            }
        }
        // Each parent owes the base and audio the other delivered.
        let (owing, link) = match c.link {
            Link::Primary => (self.standby.as_ref(), Link::Standby),
            Link::Standby => (self.primary.as_ref(), Link::Primary),
            _ => (None, Link::None),
        };
        if fresh && chunk.base_or_audio {
            if let Some(other) = owing.and_then(|p| self.cands.get_mut(p)) {
                if other.link == link {
                    other.meter.expect_base(chunk.pos);
                }
            }
        }
    }

    /// The latest failover, once: when the old primary was last heard, and
    /// why it failed.
    pub fn take_failover(&mut self) -> Option<(u64, crate::telemetry::FailoverCause)> {
        self.failed_over.take()
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
                    // A new standby replaces the old one: release it, or its
                    // reservation would be held for nothing.
                    if let Some(old) = self.standby.clone().filter(|o| o != from) {
                        if self
                            .cands
                            .get(&old)
                            .is_some_and(|c| c.link == Link::Standby)
                        {
                            self.cands.get_mut(&old).expect("present").link = Link::None;
                            log.record(
                                now_ms,
                                &me,
                                DecisionKind::Unsubscribe,
                                Some(&old),
                                0,
                                "standby replaced",
                            );
                            out.push(SelectorAction::Unsubscribe { parent: old });
                        }
                    }
                    let c = self.cands.get_mut(from).expect("present");
                    c.link = Link::Standby;
                    c.failures = 0;
                    c.subscribed_at = now_ms;
                    c.meter.restart();
                    self.standby = Some(from.clone());
                }
                Role::Primary => {
                    // The path was unmetered while the ask was out, and a
                    // standby's sequence skipped layers: the first full
                    // chunk continues from nothing.
                    self.cands.get_mut(from).expect("present").meter.restart();
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
        let canonical = c.tier == Tier::Canonical;
        if canonical && role == Role::Primary {
            // V1: the canonical never carries video.
            return false;
        }
        if !c.eligible
            || (!canonical && !self.members.contains(p))
            || !o.forwarding
            || o.ancestry.contains(&self.me)
            || o.depth.saturating_add(1) > self.cfg.max_depth
            || now_ms < c.backoff_until
            || matches!(c.health.state(), PeerState::Suspected | PeerState::Down)
            || now_ms.saturating_sub(c.offer_at_ms) > self.cfg.down_silence_ms
        {
            // A candidate that stopped offering (gone, or no longer
            // forwarding) is not a candidate: its last offer is stale.
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
        // R2: the lowest tier with a viable candidate wins outright; scores
        // are compared only within it.
        let low = scored.iter().map(|(p, _)| self.cands[p].tier).min()?;
        scored.retain(|(p, _)| self.cands[p].tier == low);
        // R1: direct first, whatever the relays score.
        let is_direct = |p: &P| {
            self.cands[p]
                .offer
                .as_ref()
                .is_some_and(|o| o.depth == 0 && o.ancestry.is_empty())
        };
        if self.cfg.direct_first && scored.iter().any(|(p, _)| is_direct(p)) {
            scored.retain(|(p, _)| is_direct(p));
        }
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
    /// R3's probe target: the best-scoring member-tier candidate that is
    /// viable in every way but advertised room.
    /// `direct_only`: the stream's publisher alone (a depth-0 offer).
    fn best_member_ignoring_room(&self, now_ms: u64, direct_only: bool) -> Option<P> {
        self.cands
            .iter()
            .filter(|(p, c)| {
                c.tier == Tier::Member
                    && c.link == Link::None
                    && c.eligible
                    && self.members.contains(p)
                    && self.primary.as_ref() != Some(p)
                    && now_ms >= c.backoff_until
                    && now_ms.saturating_sub(c.offer_at_ms) <= self.cfg.down_silence_ms
                    && c.offer.as_ref().is_some_and(|o| {
                        o.forwarding
                            && !o.ancestry.contains(&self.me)
                            && o.depth.saturating_add(1) <= self.cfg.max_depth
                    })
                    && !matches!(c.health.state(), PeerState::Suspected | PeerState::Down)
                    && (!direct_only
                        || c.offer
                            .as_ref()
                            .is_some_and(|o| o.depth == 0 && o.ancestry.is_empty()))
            })
            .map(|(p, c)| (p.clone(), self.score(c)))
            .max_by(|a, b| a.1.total_cmp(&b.1))
            .map(|(p, _)| p)
    }

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
        let (idle_aware, activity, resumed_at) = (
            self.cfg.idle_aware_silence,
            self.last_activity_ms,
            self.activity_since_ms,
        );
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
                if idle_aware && activity.is_none_or(|a| a <= last) {
                    // Nothing newer arrived on any path: the stream is idle,
                    // not this parent dead.
                    return 0;
                }
                // The stream's idle gap is nobody's silence: a path owes
                // chunks only since the stream resumed.
                let last = if idle_aware {
                    last.max(resumed_at)
                } else {
                    last
                };
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
            let last_arrival = c.meter.last_arrival_ms();
            if let Some((_, to)) =
                c.health
                    .update(now_ms, silent, last_arrival, degraded, &self.cfg)
            {
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
                    // The answer never came, which does not mean the
                    // forwarder never committed: say so, or a lost ADMIT
                    // leaves a commitment this node does not know it holds,
                    // whose offers then show no room to this node either.
                    out.push(if was_standby {
                        SelectorAction::Subscribe {
                            parent: p.clone(),
                            role: Role::Standby,
                        }
                    } else {
                        SelectorAction::Unsubscribe { parent: p.clone() }
                    });
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
                .is_none_or(|t| now_ms >= t + self.cfg.failover_min_interval_ms);
            if bad && allowed {
                use crate::telemetry::FailoverCause;
                let cause = if depth_bad {
                    FailoverCause::Depth
                } else if matches!(c.health.state(), PeerState::Suspected | PeerState::Down) {
                    FailoverCause::LinkDown
                } else {
                    FailoverCause::Health
                };
                let heard = c.meter.last_arrival_ms().unwrap_or(now_ms).min(now_ms);
                self.failed_over = Some((heard, cause));
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
        if self.primary.is_some() {
            self.parentless_since_ms = None;
        } else {
            self.parentless_since_ms.get_or_insert(now_ms);
        }
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
                c.tier != Tier::Canonical
                    && c.link == Link::Standby
                    && c.eligible
                    && self.members.contains(s)
                    && now_ms >= c.backoff_until
                    && c.offer.as_ref().is_some_and(|o| o.forwarding)
                    && matches!(
                        c.health.state(),
                        PeerState::Available | PeerState::Degraded | PeerState::Recovering
                    )
            });
            let standby_pending = self.cands.values().any(|c| {
                matches!(
                    c.link,
                    Link::Requested {
                        role: Role::Standby,
                        ..
                    }
                )
            });
            if let Some(s) = standby_ok {
                out.push(self.request(now_ms, &s, Role::Primary, "promote standby", log));
            } else if let Some(p) = self.pick(Role::Primary, now_ms, false, rng) {
                out.push(self.request(now_ms, &p, Role::Primary, "join", log));
            } else if self.video_unavailable() && now_ms >= self.next_r3_probe_ms {
                // R3: on the canonical tier, keep ASKING the member tier on a
                // jittered backoff, even when no member advertises room: a
                // forwarder grows its probe only on demand, and a request it
                // refuses is that demand.
                let base = self.cfg.backoff_base_ms * 4;
                self.next_r3_probe_ms = now_ms + self.cfg.backoff_ms(base, 2, rng);
                if let Some(p) = self.best_member_ignoring_room(now_ms, false) {
                    out.push(self.request(now_ms, &p, Role::Primary, "R3 probe", log));
                }
            } else if self.standby.is_none()
                && !standby_pending
                && self.cands.values().any(|c| c.tier == Tier::Canonical)
            {
                // §6.5: no member can serve the full stream. Take audio on the
                // canonical tier, and keep probing the member tier for the
                // primary (R3). Without a canonical candidate, see below.
                if let Some(s) = self
                    .pick(Role::Standby, now_ms, false, rng)
                    .filter(|s| self.cands[s].tier == Tier::Canonical)
                {
                    out.push(self.request(now_ms, &s, Role::Standby, "audio fallback", log));
                }
            } else if !self.cands.values().any(|c| c.tier == Tier::Canonical)
                && self
                    .parentless_since_ms
                    .is_some_and(|t| now_ms.saturating_sub(t) >= self.cfg.down_silence_ms)
                && now_ms >= self.next_r3_probe_ms
            {
                // R3 in a member-only world: a node that has had no parent for
                // `down_silence_ms`, with nobody advertising room, ASKS the
                // stream's publisher anyway, on the same jittered backoff.
                // The publisher is the one node that always holds the stream,
                // and its refusal is the demand its admission grows on. It
                // used to wait for room in silence: shed by its publisher
                // under a cap, nobody asked, the publisher's offer showed no
                // room until its ceiling went stale, and nothing grew (avmesh4,
                // m1 and m3 for the 60 s after the cap lifted). Only the
                // publisher, and only after the wait, so an ordinary failover
                // (which finds room) and the relays never see these asks.
                let base = self.cfg.backoff_base_ms * 4;
                self.next_r3_probe_ms = now_ms + self.cfg.backoff_ms(base, 2, rng);
                if let Some(p) = self.best_member_ignoring_room(now_ms, true) {
                    out.push(self.request(now_ms, &p, Role::Primary, "R3 probe", log));
                }
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
            // R1 / M1: a healthy direct primary is never left for a relay by
            // score, and a relay gives way to a direct standby by rule.
            let direct = |c: &Cand<P>| c.offer.as_ref().is_some_and(|o| o.depth == 0);
            let (to_direct, off_direct) = (
                self.cfg.direct_first
                    && direct(&self.cands[&s])
                    && !direct(&self.cands[&p])
                    && room,
                self.cfg.direct_first
                    && direct(&self.cands[&p])
                    && !direct(&self.cands[&s])
                    && self.cands[&p].health.state() == PeerState::Available,
            );
            if calm
                && depth_ok
                && (held || to_direct)
                && !off_direct
                && now_ms >= self.last_switch_ms + self.dwell_ms(now_ms)
            {
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
            let canonical = c.tier == Tier::Canonical;
            if c.health.state() == PeerState::Down
                || (!canonical && !self.members.contains(&s))
                || !c.eligible
            {
                self.standby = None;
                out.push(self.drop_parent(now_ms, &s, rng, log, "standby down or ineligible"));
            } else if calm && canonical && self.primary.is_some() {
                // R3: off the canonical as soon as a member can take the
                // standby (the primary already carries the audio).
                if let Some(n) = self
                    .pick(Role::Standby, now_ms, false, rng)
                    .filter(|n| self.cands[n].tier == Tier::Member)
                {
                    self.standby = None;
                    out.push(self.drop_parent(now_ms, &s, rng, log, "leave the canonical tier"));
                    out.push(self.request(now_ms, &n, Role::Standby, "member standby", log));
                } else if now_ms >= self.next_r3_probe_ms {
                    // No member advertises standby room: ask one anyway (R3);
                    // the canonical standby stays until a member admits, and
                    // is released then (`on_decision`).
                    let base = self.cfg.backoff_base_ms * 4;
                    self.next_r3_probe_ms = now_ms + self.cfg.backoff_ms(base, 2, rng);
                    if let Some(n) = self.best_member_ignoring_room(now_ms, false) {
                        out.push(self.request(now_ms, &n, Role::Standby, "R3 probe", log));
                    }
                }
            } else if calm
                && self.cfg.admission_enabled
                && c.no_room_offers >= STANDBY_NO_ROOM_OFFERS
                && self
                    .last_standby_rotation_ms
                    .is_none_or(|t| now_ms >= t + self.cfg.min_dwell_ms)
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

#[cfg(test)]
mod tests {
    use super::super::{AdmitDecision, SplitMix64};
    use super::*;

    /// A chunk at `seq` that every role receives.
    fn at(seq: u64, full: bool, bytes: u64, latency_ms: f64) -> PathChunk {
        PathChunk {
            pos: ChunkPos { epoch: 0, seq },
            full,
            base_or_audio: true,
            hop_lost: 0,
            bytes,
            latency_ms,
        }
    }

    fn offer(from: u32, headroom_streams: u64, cfg: &ControllerConfig) -> Offer<u32> {
        Offer {
            from,
            depth: 0,
            ancestry: Vec::new(),
            headroom_bps: headroom_streams * cfg.stream_bps,
            forwarder_headroom_bps: headroom_streams * cfg.stream_bps,
            upstream_latency_ms: 0,
            forwarding: true,
        }
    }

    /// Run `s` for `ms`, answering every subscribe with Admit and feeding
    /// fresh offers; returns the requests it made.
    fn drive(
        s: &mut ParentSelector<u32>,
        cfg: &ControllerConfig,
        from_ms: u64,
        to_ms: u64,
        offers: &[(u32, u64, f64)],
    ) -> Vec<SelectorAction<u32>> {
        let mut rng = SplitMix64(11);
        let mut log = DecisionLog::default();
        let mut all = Vec::new();
        let mut t = from_ms;
        let mut seq = from_ms / 50;
        while t < to_ms {
            // Every subscribed parent delivers (the primary the full chunk,
            // a standby its audio), at half its offer RTT.
            for (p, role) in s.subscriptions() {
                let rtt = offers.iter().find(|o| o.0 == p).map_or(50.0, |o| o.2);
                for k in 0..5 {
                    s.on_chunk(t, &p, at(seq + k, role == Role::Primary, 6_000, rtt / 2.0));
                }
            }
            seq += 5;
            if t.is_multiple_of(1_000) {
                for &(p, room, rtt) in offers {
                    s.on_offer(t, offer(p, room, cfg), rtt, &mut log);
                }
            }
            let acts = s.tick(t, &mut rng, &mut log);
            for a in &acts {
                if let SelectorAction::Subscribe { parent, role } = a {
                    let d = AdmitDecision::Admit { role: *role };
                    let more = s.on_decision(t, parent, &d, &mut rng, &mut log);
                    all.extend(more);
                }
            }
            all.extend(acts);
            t += 250;
        }
        all
    }

    /// #945 finding A, at the selector: Down from a closed link, or from a
    /// loop in the primary's own offer, is a verdict the same tick's failover
    /// acts on. Being subscribed is not being heard.
    #[test]
    fn a_verdict_on_a_primary_reaches_the_tick_that_follows_it() {
        for looped in [false, true] {
            let mut cfg = ControllerConfig::interactive();
            cfg.jitter = false;
            let mut s = ParentSelector::new(1u32, cfg.clone(), false);
            s.set_members([1u32, 2, 3]);
            let offers = [(2, 4, 20.0), (3, 4, 30.0)];
            let _ = drive(&mut s, &cfg, 0, 12_000, &offers);
            let (p, standby) = (*s.primary().expect("joined"), s.standby().copied());
            assert!(standby.is_some());
            let (mut rng, mut log) = (SplitMix64(1), DecisionLog::default());
            let t = 12_000;
            if looped {
                let o = Offer {
                    ancestry: vec![1],
                    ..offer(p, 4, &cfg)
                };
                s.on_offer(t, o, 20.0, &mut log);
            } else {
                s.on_link_down(t, &p, &mut log);
            }
            assert_eq!(s.state_of(&p), Some(PeerState::Down));
            let acts = s.tick(t, &mut rng, &mut log);
            assert_eq!(s.primary(), None, "looped={looped}: {}", log.tail());
            assert_eq!(log.count(DecisionKind::Failover), 1);
            assert!(
                acts.contains(&SelectorAction::Subscribe {
                    parent: standby.expect("present"),
                    role: Role::Primary,
                }),
                "looped={looped}: {acts:?}"
            );
        }
    }

    /// W1 (`FSD/CIRIS_MESH.md` §9): with any eligible member Available, the
    /// canonical is never chosen, however much better it scores.
    #[test]
    fn w1_members_before_the_canonical() {
        let cfg = ControllerConfig::interactive();
        let mut s = ParentSelector::new(1u32, cfg.clone(), false);
        s.set_members([1u32, 2, 3]);
        s.set_tier(&9, Tier::Canonical);
        // The canonical: lowest RTT, most headroom. The members: slow, tight.
        let acts = drive(
            &mut s,
            &cfg,
            0,
            20_000,
            &[(9, 50, 2.0), (2, 2, 300.0), (3, 2, 320.0)],
        );
        assert!(matches!(s.primary(), Some(&2 | &3)));
        assert!(matches!(s.standby(), Some(&2 | &3)));
        assert!(
            !acts
                .iter()
                .any(|a| matches!(a, SelectorAction::Subscribe { parent: 9, .. })),
            "the canonical was asked while a member was viable: {acts:?}"
        );
        assert!(!s.video_unavailable());
    }

    /// W1's mutation: scoring the canonical WITH the members (the same node
    /// put in the member tier) picks it. If this ever stops picking 9, W1
    /// no longer proves anything.
    #[test]
    fn w1_mutant_scoring_the_canonical_with_members_picks_it() {
        let cfg = ControllerConfig::interactive();
        let mut s = ParentSelector::new(1u32, cfg.clone(), false);
        s.set_members([1u32, 2, 3, 9]);
        let _ = drive(
            &mut s,
            &cfg,
            0,
            20_000,
            &[(9, 50, 2.0), (2, 2, 300.0), (3, 2, 320.0)],
        );
        assert_eq!(s.primary(), Some(&9));
    }

    fn relay_offer(from: u32, cfg: &ControllerConfig) -> Offer<u32> {
        Offer {
            depth: 1,
            ancestry: vec![2],
            ..offer(from, 4, cfg)
        }
    }

    /// R1: a viable publisher is taken before a better-scoring relay, on every
    /// seed (the pick band's draw must not decide it), and stays the primary.
    #[test]
    fn r1_a_direct_path_comes_before_a_better_scoring_relay() {
        for seed in 0..32u64 {
            let mut cfg = ControllerConfig::interactive();
            cfg.direct_first = true;
            let mut s = ParentSelector::new(1u32, cfg.clone(), true);
            s.set_members([1u32, 2, 3]);
            let mut rng = SplitMix64(seed);
            let mut log = DecisionLog::default();
            let mut t = 0;
            while t < 40_000 {
                if t % 1_000 == 0 {
                    // The publisher is far; the relay is near, with more room.
                    s.on_offer(t, offer(2, 1, &cfg), 300.0, &mut log);
                    s.on_offer(t, relay_offer(3, &cfg), 2.0, &mut log);
                }
                for a in s.tick(t, &mut rng, &mut log) {
                    if let SelectorAction::Subscribe { parent, role } = a {
                        let d = AdmitDecision::Admit { role };
                        let _ = s.on_decision(t, &parent, &d, &mut rng, &mut log);
                    }
                }
                for (p, role) in s.subscriptions() {
                    s.on_chunk(t, &p, at(t / 250, role == Role::Primary, 6_000, 5.0));
                }
                t += 250;
            }
            assert_eq!(s.primary(), Some(&2), "seed {seed}");
            assert_eq!(s.parent_changes(), 0, "seed {seed}");
        }
    }

    /// M1: a member on a relay moves to the publisher when a direct path
    /// appears, make-before-break.
    #[test]
    fn r1_a_relay_gives_way_to_a_direct_path_that_appears() {
        let mut cfg = ControllerConfig::interactive();
        cfg.direct_first = true;
        let mut s = ParentSelector::new(1u32, cfg.clone(), true);
        s.set_members([1u32, 2, 3]);
        let mut rng = SplitMix64(3);
        let mut log = DecisionLog::default();
        let mut t = 0;
        while t < 60_000 {
            if t % 1_000 == 0 {
                s.on_offer(t, relay_offer(3, &cfg), 2.0, &mut log);
                if t >= 20_000 {
                    s.on_offer(t, offer(2, 4, &cfg), 40.0, &mut log);
                }
            }
            if t == 19_750 {
                assert_eq!(s.primary(), Some(&3), "only the relay so far");
            }
            for a in s.tick(t, &mut rng, &mut log) {
                if let SelectorAction::Subscribe { parent, role } = a {
                    let d = AdmitDecision::Admit { role };
                    let _ = s.on_decision(t, &parent, &d, &mut rng, &mut log);
                }
            }
            for (p, role) in s.subscriptions() {
                for k in 0..10 {
                    s.on_chunk(t, &p, at(t / 25 + k, role == Role::Primary, 6_000, 5.0));
                }
            }
            t += 250;
        }
        assert_eq!(s.primary(), Some(&2));
    }

    /// A subscribe whose answer never came (a lost ADMIT) is withdrawn, so
    /// the forwarder's commitment cannot outlive this node's knowledge of it.
    #[test]
    fn an_unanswered_subscribe_is_withdrawn() {
        let cfg = ControllerConfig::interactive();
        let mut s = ParentSelector::new(1u32, cfg.clone(), false);
        s.set_members([1u32, 2]);
        let mut rng = SplitMix64(9);
        let mut log = DecisionLog::default();
        let mut asked_at = None;
        let mut withdrawn = false;
        let mut t = 0;
        while t < 12_000 && !withdrawn {
            if t % 1_000 == 0 {
                s.on_offer(t, offer(2, 4, &cfg), 20.0, &mut log);
            }
            for a in s.tick(t, &mut rng, &mut log) {
                match a {
                    SelectorAction::Subscribe { .. } => asked_at = asked_at.or(Some(t)),
                    SelectorAction::Unsubscribe { parent: 2 } => withdrawn = true,
                    SelectorAction::Unsubscribe { .. } => {}
                }
            }
            t += 250;
        }
        let at = asked_at.expect("it asked");
        assert!(withdrawn, "the unanswered subscribe is withdrawn");
        assert!(t > at + REQUEST_TIMEOUT_MS, "only after the timeout");
        assert!(s.primary().is_none());
    }

    /// A live call's stream idles until its host publishes. When it resumes,
    /// the first chunk lands on ONE path: the other parent must not be charged
    /// the idle gap as silence (it would fail over at once, and the publisher
    /// would stop sending to this member). It owes chunks only from then on.
    #[test]
    fn a_resuming_stream_does_not_charge_the_idle_gap_to_the_slower_path() {
        let mut cfg = ControllerConfig::interactive();
        cfg.idle_aware_silence = true;
        let mut s = ParentSelector::new(1u32, cfg.clone(), false);
        s.set_members([1u32, 2, 3]);
        let mut rng = SplitMix64(5);
        let mut log = DecisionLog::default();
        let mut t = 0;
        // Both parents up, nobody publishing, for 30 s: neither is suspected.
        while t < 30_000 {
            if t % 1_000 == 0 {
                s.on_offer(t, offer(2, 4, &cfg), 20.0, &mut log);
                s.on_offer(t, offer(3, 4, &cfg), 20.0, &mut log);
            }
            for a in s.tick(t, &mut rng, &mut log) {
                if let SelectorAction::Subscribe { parent, role } = a {
                    let d = AdmitDecision::Admit { role };
                    let _ = s.on_decision(t, &parent, &d, &mut rng, &mut log);
                }
            }
            t += 250;
        }
        let (p, st) = (
            *s.primary().expect("primary"),
            *s.standby().expect("standby"),
        );
        // The host starts publishing: the standby's copy lands first.
        s.on_chunk(t, &st, at(1, false, 100, 5.0));
        let _ = s.tick(t + 250, &mut rng, &mut log);
        assert_eq!(
            s.primary(),
            Some(&p),
            "the idle gap is not the primary's silence"
        );
        assert_eq!(s.state_of(&p), Some(PeerState::Available));
        // The primary really is silent while the stream runs: that counts.
        let mut now = t + 250;
        for k in 2..12 {
            now += 250;
            s.on_chunk(now, &st, at(k, false, 100, 5.0));
            let _ = s.tick(now, &mut rng, &mut log);
        }
        assert_ne!(
            s.state_of(&p),
            Some(PeerState::Available),
            "real silence is seen"
        );
    }

    /// #945 item 3: a standby promoted to primary owes nothing from before
    /// its admit. Mutation: keeping the standby's sequence across the
    /// promotion reads the interval as a burst of loss on the new primary.
    #[test]
    fn a_promoted_standby_starts_a_fresh_sequence() {
        let cfg = ControllerConfig::interactive();
        let mut s = ParentSelector::new(1u32, cfg.clone(), false);
        s.set_members([1u32, 2, 3]);
        let t = 20_000;
        let _ = drive(&mut s, &cfg, 0, t, &[(2, 4, 40.0), (3, 4, 60.0)]);
        let (p, st) = (
            *s.primary().expect("a primary"),
            *s.standby().expect("a standby"),
        );
        let mut rng = SplitMix64(11);
        let mut log = DecisionLog::default();
        s.on_shed(t, &p, &mut rng, &mut log);
        let acts = s.tick(t, &mut rng, &mut log);
        assert!(
            acts.contains(&SelectorAction::Subscribe {
                parent: st,
                role: Role::Primary
            }),
            "{acts:?}"
        );
        let admit = AdmitDecision::Admit {
            role: Role::Primary,
        };
        let _ = s.on_decision(t, &st, &admit, &mut rng, &mut log);
        assert_eq!(s.primary(), Some(&st));
        let first = 1_000_000;
        for k in 0..100 {
            let now = t + 25 * k;
            s.on_chunk(now, &st, at(first + k, true, 6_000, 5.0));
            s.on_offer(now, offer(st, 4, &cfg), 60.0, &mut log);
            let _ = s.tick(now, &mut rng, &mut log);
        }
        assert_eq!(s.state_of(&st), Some(PeerState::Available));
    }

    /// §6.5 / V1: with no member, the canonical carries audio only (never a
    /// primary) and the node keeps probing; a member that appears takes the
    /// primary and the canonical standby is released (R3).
    #[test]
    fn canonical_is_audio_only_and_the_member_tier_is_reprobed() {
        let cfg = ControllerConfig::interactive();
        let mut s = ParentSelector::new(1u32, cfg.clone(), false);
        s.set_members([1u32, 2, 3]);
        s.set_tier(&9, Tier::Canonical);
        let acts = drive(&mut s, &cfg, 0, 10_000, &[(9, 50, 2.0)]);
        assert!(s.primary().is_none());
        assert_eq!(s.standby(), Some(&9));
        assert!(s.video_unavailable());
        assert!(!acts.iter().any(|a| matches!(
            a,
            SelectorAction::Subscribe {
                parent: 9,
                role: Role::Primary
            }
        )));
        let acts = drive(
            &mut s,
            &cfg,
            10_000,
            30_000,
            &[(9, 50, 2.0), (2, 4, 40.0), (3, 4, 60.0)],
        );
        assert!(matches!(s.primary(), Some(&2 | &3)));
        assert_ne!(s.standby(), Some(&9), "{acts:?}");
        assert!(!s.video_unavailable());
    }

    /// A member with no parent and no candidate advertising room still asks
    /// (R3 on the member tier), on its jittered backoff. avmesh4 (C): shed by
    /// m0 under a cap, m1 and m3 never asked m0 again in the 60 s after the
    /// cap lifted (m0 refused nothing on its own stream), because m0's offer
    /// showed no room. Mutation (v44.1.1): a member-only world waits for
    /// room in silence, and no subscribe to the publisher is ever sent.
    #[test]
    fn a_member_with_no_parent_asks_the_publisher_without_room() {
        let cfg = ControllerConfig::interactive();
        let mut s = ParentSelector::new(1u32, cfg.clone(), false);
        s.set_members([1u32, 2, 3]);
        // The publisher (2) offers no room, and no relay offers at all.
        let acts = drive(&mut s, &cfg, 0, 20_000, &[(2, 0, 20.0)]);
        assert!(
            acts.iter().any(|a| matches!(
                a,
                SelectorAction::Subscribe {
                    parent: 2,
                    role: Role::Primary
                }
            )),
            "{acts:?}"
        );
        assert_eq!(s.primary(), Some(&2), "admitted: the ask was the demand");
    }
}
