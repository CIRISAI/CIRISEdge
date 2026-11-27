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
        /// RM2 — a late move ([`ParentSelector::late_move`]): its admit
        /// switches at once and leaves the old primary (RM3).
        late: bool,
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
    /// When this node last gave up waiting on a request to this candidate
    /// (the request timed out and the selector told the forwarder its
    /// current wish: an UNSUBSCRIBE, or the standby restated).
    abandoned_at_ms: Option<u64>,
    /// 45.3 — the last tick this candidate's silence was excused by its
    /// offer (offer-as-life): a path owes chunks only from then on, as it
    /// owes them only from a stream's resume.
    excused_at_ms: Option<u64>,
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
/// How long after this node abandoned a request an answer to it can still
/// arrive: the forwarder retries an answer its link refuses for up to 30 s
/// (edge's `C3_RESEND_BUDGET`).
pub const LATE_ANSWER_MS: u64 = 30_000;
/// Row S3 — a parentless node asks the publisher itself at most this often
/// (about a stall verdict's latch: a refusal under it is not a reason to
/// wait longer).
pub const PUBLISHER_ASK_EVERY_MS: u64 = 2_000;
/// Row S3 — how many times a node that lost the publisher as its primary
/// asks it directly before leaving it to the ordinary failover: a bounded
/// ask (a publisher with primaries refuses; asking forever crowded a
/// capacity-tight room, the stage-1 sim's t2).
pub const PUBLISHER_ASKS: u32 = 3;

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
    /// Row S3 — when the publisher may next be asked by
    /// [`Self::publisher_fallback`].
    next_publisher_ask_ms: u64,
    /// Row S3 — publisher asks left for this loss ([`PUBLISHER_ASKS`]); a
    /// primary resets it.
    publisher_asks_left: u32,
    /// Row S3 — when the last primary SHED this node (a decision its
    /// forwarder made, under its own load), rather than being lost: no ask
    /// back. Cleared by the next primary.
    primary_shed_at: Option<u64>,
    /// Since when this node has had no primary (member-tier R3).
    parentless_since_ms: Option<u64>,
    last_activity_ms: Option<u64>,
    /// When the stream last went from idle to active: silence on a path is
    /// never counted from before it (see `idle_aware_silence`).
    activity_since_ms: u64,
    /// When a [`PathChunk::full`] chunk last arrived on any path.
    last_full_ms: Option<u64>,
    /// RM3 — a publisher left by a late move is not asked for a standby
    /// before this instant (a standby of an opaque or audio stream is fed
    /// every chunk: the load it was shedding would stay, F12).
    standby_hold: BTreeMap<P, u64>,
    /// RM3 — a late move completed since the controller last asked.
    late_moved: bool,
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
            next_publisher_ask_ms: 0,
            publisher_asks_left: PUBLISHER_ASKS,
            primary_shed_at: None,
            parentless_since_ms: None,
            last_activity_ms: None,
            activity_since_ms: 0,
            last_full_ms: None,
            standby_hold: BTreeMap::new(),
            late_moved: false,
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

    /// Calls cut — this node started or stopped offering relay mid-call
    /// (`Call::set_relay`): told with every later subscribe, and no longer
    /// read as a forwarder that must not move deeper.
    pub fn set_forward_capable(&mut self, on: bool) {
        self.forward_capable = on;
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
            // 45.3 — never less late than the parent says its own upstream
            // is: a relay's meter is a smoothed reading that lags a queue
            // building at the publisher, and a child judging this node's
            // silence (offer-as-life) reads its offer.
            latency_ms: Self::e2e_latency(c).max(f64::from(o.upstream_latency_ms) + c.rtt_ms / 2.0)
                as u32,
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
            abandoned_at_ms: None,
            excused_at_ms: None,
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
            self.primary_shed_at = Some(now_ms);
        }
        if self.standby.as_ref() == Some(from) {
            self.standby = None;
        }
    }

    /// The forwarder `from` answered a subscribe.
    #[allow(clippy::too_many_lines)]
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
        let Some((link, abandoned_at)) = self.cands.get(from).map(|c| (c.link, c.abandoned_at_ms))
        else {
            return out;
        };
        // An ADMIT names the role it answers (admission echoes the request's
        // role). One for another role than the request now out answers an
        // older request: the answer to the current one is still to come (or
        // the timeout cleans up), so it is not applied.
        if let (Link::Requested { role: asked, .. }, AdmitDecision::Admit { role: got }) =
            (link, decision)
        {
            if asked != *got {
                log.record(
                    now_ms,
                    &me,
                    DecisionKind::Unsubscribe,
                    Some(from),
                    0,
                    "late answer to another request: not applied",
                );
                return out;
            }
        }
        let Link::Requested {
            role,
            was_standby,
            late,
            ..
        } = link
        else {
            // A late answer to a request this node abandoned: it has told the
            // forwarder its current wish since (an UNSUBSCRIBE, or the standby
            // restated), which the forwarder reads after this answer, so the
            // answer is not applied.
            let late = abandoned_at.is_some_and(|t| now_ms.saturating_sub(t) <= LATE_ANSWER_MS);
            if late && link.subscribed() && matches!(decision, AdmitDecision::Admit { .. }) {
                log.record(
                    now_ms,
                    &me,
                    DecisionKind::Unsubscribe,
                    Some(from),
                    0,
                    "late answer to an abandoned request: not applied",
                );
                return out;
            }
            // Row E2, the child's side: the publisher promoted this node's
            // STANDBY subscription to primary (its last primary was lost).
            // With no primary of its own, take it as the primary now.
            if matches!(
                decision,
                AdmitDecision::Admit {
                    role: Role::Primary
                }
            ) && link == Link::Standby
                && self.primary.is_none()
            {
                if self.standby.as_ref() == Some(from) {
                    self.standby = None;
                }
                let c = self.cands.get_mut(from).expect("present");
                c.link = Link::Primary;
                c.failures = 0;
                c.meter.restart();
                self.set_primary(now_ms, from.clone(), log, "promoted by parent");
                return out;
            }
            // A primary this node did not ask for, from its standby parent,
            // while it has a primary elsewhere: the forwarder would hold a
            // primary slot (and feed the full stream) for a node that counts
            // it a standby. Release it: an UNSUBSCRIBE frees the slot, and
            // the next tick takes a standby again.
            if matches!(
                decision,
                AdmitDecision::Admit {
                    role: Role::Primary
                }
            ) && link == Link::Standby
            {
                if self.standby.as_ref() == Some(from) {
                    self.standby = None;
                }
                self.cands.get_mut(from).expect("present").link = Link::None;
                log.record(
                    now_ms,
                    &me,
                    DecisionKind::Unsubscribe,
                    Some(from),
                    0,
                    "unasked primary while holding one",
                );
                out.push(SelectorAction::Unsubscribe {
                    parent: from.clone(),
                });
                return out;
            }
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
            AdmitDecision::Admit { .. } => {
                // The forwarder just committed to this node: fresh evidence it
                // is alive, so a Down left by an old link-down (the row S3 ask
                // bypasses health) is not held against the new subscription.
                // It was: the asked publisher's ADMIT was failed over one tick
                // later, at every ask (the kill witness, kill 2).
                let c = self.cands.get_mut(from).expect("present");
                if let Some((_, to)) = c.health.on_admitted(now_ms) {
                    log.record(
                        now_ms,
                        &me,
                        DecisionKind::PeerState,
                        Some(from),
                        to as i64,
                        "admitted",
                    );
                }
                match role {
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
                        if let Some(old) = self.primary.clone().filter(|o| late && o != from) {
                            // RM3: a late move switches on the admit, and only
                            // then leaves the old primary, fully: no demotion
                            // to a (fed) standby.
                            if was_standby {
                                self.standby = None;
                            }
                            let c = self.cands.get_mut(from).expect("present");
                            c.link = Link::Primary;
                            c.failures = 0;
                            if !was_standby {
                                c.subscribed_at = now_ms;
                            }
                            self.set_primary(now_ms, from.clone(), log, "late move");
                            log.record(now_ms, &me, DecisionKind::Switch, Some(from), 0, "late");
                            out.push(self.drop_parent(now_ms, &old, rng, log, "late"));
                            self.standby_hold
                                .insert(old, now_ms + self.cfg.min_dwell_ms);
                            self.late_moved = true;
                        } else if self.primary.is_some() {
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
                }
            }
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
        self.publisher_asks_left = PUBLISHER_ASKS;
        self.primary_shed_at = None;
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
        if role == Role::Standby && self.standby_hold.get(p).is_some_and(|t| now_ms < *t) {
            return false;
        }
        true
    }

    /// RM2 — whether a primary subscription is pending (asked, or a
    /// make-before-break in progress).
    #[must_use]
    pub fn primary_pending(&self) -> bool {
        self.cands.values().any(|c| {
            matches!(
                c.link,
                Link::Requested {
                    role: Role::Primary,
                    ..
                } | Link::Promoting { .. }
            )
        })
    }

    /// RM4 — the members this node believes are `publisher`'s direct
    /// children: every roster member whose latest offer, fresher than
    /// `down_silence_ms`, shows `publisher` as its parent (depth 1, ancestry
    /// `[publisher]`). This node is not among them (it hears no offer of its
    /// own); the caller adds itself.
    #[must_use]
    pub fn direct_children_by_offer(&self, now_ms: u64, publisher: &P) -> Vec<P> {
        self.cands
            .iter()
            .filter(|(p, c)| {
                *p != publisher
                    && self.members.contains(*p)
                    && now_ms.saturating_sub(c.offer_at_ms) <= self.cfg.down_silence_ms
                    && c.offer.as_ref().is_some_and(|o| {
                        o.depth == 1 && o.ancestry.len() == 1 && o.ancestry[0] == *publisher
                    })
            })
            .map(|(p, _)| p.clone())
            .collect()
    }

    /// RM2 — ask a member other than `publisher` to become the primary,
    /// keeping `publisher` until it admits (RM3, [`Self::on_decision`]).
    ///
    /// Transition: observable, the caller's sustained late reading of the
    /// publisher's own delivery (the caller also checks RM4 and RM6); state,
    /// the primary is `publisher` and nothing is pending; action, the
    /// best-scoring member-tier candidate that is viable for the primary
    /// (an offer within `down_silence_ms`, forwarding, not this node's
    /// descendant, not backed off, healthy) with room, and that `allowed`
    /// takes, is asked for the primary (an upgrade if it is the standby);
    /// must never, ask while something is pending, ask the publisher, or ask
    /// a stale offer or one without room. Returns the SUBSCRIBE, if any.
    pub fn late_move(
        &mut self,
        now_ms: u64,
        publisher: &P,
        allowed: &dyn Fn(&P) -> bool,
        log: &mut DecisionLog,
    ) -> Option<SelectorAction<P>> {
        if self.primary.as_ref() != Some(publisher) || self.primary_pending() {
            return None;
        }
        let pick = self
            .cands
            .iter()
            .filter(|(p, c)| {
                *p != publisher
                    && c.tier == Tier::Member
                    && matches!(c.link, Link::None | Link::Standby)
                    && self.viable(p, c, Role::Primary, now_ms)
                    && self.has_room(c)
                    && allowed(p)
            })
            .map(|(p, c)| (p.clone(), self.score(c)))
            .max_by(|a, b| a.1.total_cmp(&b.1))
            .map(|(p, _)| p)?;
        let c = self.cands.get_mut(&pick).expect("candidate");
        c.link = Link::Requested {
            role: Role::Primary,
            at_ms: now_ms,
            was_standby: c.link == Link::Standby,
            late: true,
        };
        log.record(
            now_ms,
            &self.me,
            DecisionKind::Subscribe,
            Some(&pick),
            2,
            "late",
        );
        Some(SelectorAction::Subscribe {
            parent: pick,
            role: Role::Primary,
        })
    }

    /// RM3 — whether a late move completed since last asked (once).
    pub fn take_late_moved(&mut self) -> bool {
        std::mem::take(&mut self.late_moved)
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

    /// Row S3, the child's side — only for a primary LOST (its link closed,
    /// or it fell silent), never for one that SHED this node: the publisher
    /// shed it under its own load, and asking back at once contradicted
    /// that, its refusal feeding the publisher's demand (the mesh4 n4
    /// witness: a re-overcommitted publisher shed its children again after
    /// the cap had lifted). The stream's publisher, known from any
    /// depth-0 offer it ever made, as a primary candidate whatever its health
    /// (a link down left it Down), its offer's age or a backoff (a refusal
    /// under a stall verdict is retried after the verdict's latch, not a
    /// doubling backoff): at most one ask per [`PUBLISHER_ASK_EVERY_MS`].
    fn publisher_fallback(&self, now_ms: u64) -> Option<P> {
        // Only for a node whose LOST primary was the publisher itself: at
        // join the ordinary pick and the publisher's offers do the work, and
        // a node that lost a relay re-parents in the relays' tree (asking the
        // publisher for everyone herds onto it).
        // At once: no wait for the ordinary failover first. A wait of a
        // request's time (3 s) held every kill witness's re-parenting back
        // by that much and failed it once by 0.36 s; the t2 herd it was
        // added against is kept off by `direct_first` alone.
        // Live calls only (`direct_first`, like R1): the stage-1 sim's
        // capacity-tight worlds (t2) are tuned without it.
        if !self.cfg.direct_first
            || now_ms < self.next_publisher_ask_ms
            || self.last_primary.is_none()
            || self.publisher_asks_left == 0
            || self.primary_shed_at.is_some()
        {
            return None;
        }
        // The publisher this node was taking the stream from directly (it
        // lost that link): a node on a relay asks its relays' tree first.
        let lost = self.last_primary.as_ref()?;
        self.cands
            .iter()
            .find(|(p, c)| {
                *p == lost
                    && c.tier == Tier::Member
                    && c.link == Link::None
                    && c.eligible
                    && self.members.contains(p)
                    && c.offer
                        .as_ref()
                        .is_some_and(|o| o.depth == 0 && o.ancestry.is_empty())
            })
            .map(|(p, _)| p.clone())
    }

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
        // A new request: the answer to it is the one now awaited, so the
        // late-answer window of an earlier, abandoned one ends here.
        c.abandoned_at_ms = None;
        c.link = Link::Requested {
            role,
            at_ms: now_ms,
            was_standby: c.link == Link::Standby,
            late: false,
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
        let down_silence_ms = self.cfg.down_silence_ms;
        for (p, c) in &mut self.cands {
            let rolled = c.meter.roll(now_ms);
            if rolled && standby.as_ref() == Some(p) {
                rolled_standby = true;
            }
            // 45.3 — a parent still OFFERING this stream, whose offer says
            // its own upstream is past the stale budget, is alive: it offers
            // only while it forwards the stream (its upstream healthy), and
            // what it receives is too late to pass on (a relay never
            // forwards stale media; a capped publisher sends none), so its
            // media silence is staleness being dropped, not death. No
            // silence failover for it; the lateness rules may still move
            // this node. Once its offers stop or its upstream reads on time
            // again it owes chunks from then on, not for the excused span
            // (charged at once, the span read as a Down the moment the
            // publisher's backlog dipped under the budget). A parent that
            // offers a fresh stream and sends nothing is a black hole, and
            // is failed over as before.
            let excused = c.offer.as_ref().is_some_and(|o| {
                o.forwarding && u64::from(o.upstream_latency_ms) > STALE_UPSTREAM_MS
            }) && now_ms.saturating_sub(c.offer_at_ms) <= OFFER_IS_LIFE_MS;
            if excused && c.link.subscribed() {
                c.excused_at_ms = Some(now_ms);
            }
            let excused_at = c.excused_at_ms;
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
                if excused {
                    return 0;
                }
                let last = last.max(excused_at.unwrap_or(0));
                // The stream's idle gap is nobody's silence: a path owes
                // chunks only since the stream resumed.
                let last = if idle_aware {
                    last.max(resumed_at)
                } else {
                    last
                };
                // Before a new subscription's first chunk, the parent's
                // advertised upstream latency (a publisher's uplink queue
                // included) is owed too: the stream it admits into is that
                // late at its own end. A publisher with a 2.2 s queue,
                // admitted, went Suspected at 1.5 s and was dropped before
                // its first chunk could arrive (the kill witness, kill 2).
                let first_owed = c
                    .meter
                    .last_arrival_ms()
                    .is_none_or(|a| a < c.subscribed_at);
                let grace = if first_owed {
                    c.offer
                        .as_ref()
                        .map_or(0, |o| u64::from(o.upstream_latency_ms))
                        .min(down_silence_ms)
                } else {
                    0
                };
                now_ms.saturating_sub(last).saturating_sub(grace) * 2 / (2 + depth)
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
                    c.abandoned_at_ms = Some(now_ms);
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
                    // The loop guard: never a standby that now hears the
                    // stream through this node.
                    && c.offer
                        .as_ref()
                        .is_some_and(|o| o.forwarding && !o.ancestry.contains(&me))
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
            } else if let Some(p) = self.publisher_fallback(now_ms) {
                // Row S3, the child's side: no primary and no viable
                // candidate → ask the publisher itself, without waiting for
                // its next offer or for its candidate to revive (it holds the
                // stream; its admission takes a primary when it has none).
                self.next_publisher_ask_ms = now_ms + PUBLISHER_ASK_EVERY_MS;
                self.publisher_asks_left = self.publisher_asks_left.saturating_sub(1);
                out.push(self.request(now_ms, &p, Role::Primary, "ask publisher", log));
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
            let calm = self.promoting().is_none()
                && !pending_primary
                && sc.link == Link::Standby
                && sc.offer.as_ref().is_some_and(|o| !o.ancestry.contains(&me));
            // Never promote a standby that is now this node's descendant.
            let looped = sc
                .offer
                .as_ref()
                .is_some_and(|o| o.ancestry.contains(&self.me));
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
                && !looped
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
            // A standby under this node (its offer's ancestry holds it)
            // could never take over: drop it like a down one.
            let looped = c.offer.as_ref().is_some_and(|o| o.ancestry.contains(&me));
            if c.health.state() == PeerState::Down
                || (!canonical && !self.members.contains(&s))
                || !c.eligible
                || looped
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
            } else if calm
                && self.cfg.direct_first
                && self.cfg.admission_enabled
                && self
                    .last_standby_rotation_ms
                    .is_none_or(|t| now_ms >= t + self.cfg.min_dwell_ms)
            {
                // Row RD — the way back to the publisher. A node that left
                // its publisher for a relay (a late move, a shed) keeps a
                // member as its standby, and nothing ever re-picked the
                // publisher while that relay stayed healthy: the publisher
                // re-opened room seconds after its cap lifted and its
                // children stayed relayed until something else moved them
                // (the come-back witness). So when this node hears the stream
                // through a relay, its standby is a relay too, and the
                // stream's publisher offers room for a whole stream, the
                // standby moves to the publisher (audio only, cheap); the
                // direct-first switch above then upgrades it.
                let direct = |c: &Cand<P>| {
                    c.offer
                        .as_ref()
                        .is_some_and(|o| o.depth == 0 && o.ancestry.is_empty())
                };
                let relayed = self
                    .primary
                    .as_ref()
                    .is_some_and(|p| !direct(&self.cands[p]));
                let to = self
                    .cands
                    .iter()
                    .filter(|(_, d)| d.link == Link::None && direct(d))
                    .filter(|(k, d)| self.viable(k, d, Role::Standby, now_ms))
                    .find(|(_, d)| {
                        d.offer
                            .as_ref()
                            .is_some_and(|o| o.headroom_bps >= self.cfg.stream_bps)
                    })
                    .map(|(k, _)| k.clone());
                if let (true, false, Some(n)) = (relayed, direct(c), to) {
                    self.last_standby_rotation_ms = Some(now_ms);
                    self.standby = None;
                    out.push(self.drop_parent(now_ms, &s, rng, log, "standby to the publisher"));
                    out.push(self.request(now_ms, &n, Role::Standby, "publisher has room", log));
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

/// 45.3 — how recent a parent's offer for a stream must be to count as its
/// life (its media silence then reads as stale media dropped, not death):
/// two and a half offer periods, so one lost or late offer is not death
/// either, and a parent whose offers stop is silent again within it.
pub const OFFER_IS_LIFE_MS: u64 = 2_500;
/// 45.3 — an upstream this late (ms) has nothing a receiver keeps: the
/// receivers' media budget (`av_call::MEDIA_STALE_BUDGET`).
pub const STALE_UPSTREAM_MS: u64 = 800;

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

    /// RM2 + RM3 at the selector: a late move asks a relay and keeps the
    /// publisher until the relay admits; a refusal leaves the publisher the
    /// primary with nothing sent to it; an admit switches at once and leaves
    /// the publisher fully, never as a (fed) standby.
    #[test]
    fn a_late_move_keeps_the_publisher_until_the_admit_and_then_leaves_it() {
        let mut cfg = ControllerConfig::interactive();
        cfg.direct_first = true;
        cfg.jitter = false;
        let mut s = ParentSelector::new(1u32, cfg.clone(), true);
        s.set_members([1u32, 2, 3]);
        let (mut rng, mut log) = (SplitMix64(5), DecisionLog::default());
        let offers = [(2, 4, 20.0)];
        let _ = drive(&mut s, &cfg, 0, 6_000, &offers);
        assert_eq!(s.primary(), Some(&2), "the premise: on the publisher");
        let t = 6_000;
        s.on_offer(t, relay_offer(3, &cfg), 5.0, &mut log);
        let allow = |_: &u32| true;
        assert_eq!(
            s.late_move(t, &2, &allow, &mut log),
            Some(SelectorAction::Subscribe {
                parent: 3,
                role: Role::Primary
            })
        );
        assert!(s.primary_pending());
        assert_eq!(s.late_move(t, &2, &allow, &mut log), None, "one at a time");
        let refused = AdmitDecision::Refuse {
            reason: super::super::RefuseReason::Capacity,
            retry_after_ms: 0,
        };
        let acts = s.on_decision(t, &3, &refused, &mut rng, &mut log);
        assert!(acts.is_empty(), "{acts:?}");
        assert_eq!(s.primary(), Some(&2), "refused: still on the publisher");
        let t = t + 10_000;
        s.on_offer(t, offer(2, 4, &cfg), 20.0, &mut log);
        s.on_offer(t, relay_offer(3, &cfg), 5.0, &mut log);
        assert!(s.late_move(t, &2, &allow, &mut log).is_some());
        let admit = AdmitDecision::Admit {
            role: Role::Primary,
        };
        let acts = s.on_decision(t, &3, &admit, &mut rng, &mut log);
        assert_eq!(s.primary(), Some(&3), "switched on the admit");
        assert_eq!(acts, vec![SelectorAction::Unsubscribe { parent: 2 }]);
        assert!(s.take_late_moved() && !s.take_late_moved());
        for a in s.tick(t + 250, &mut rng, &mut log) {
            assert_ne!(
                a,
                SelectorAction::Subscribe {
                    parent: 2,
                    role: Role::Standby
                },
                "the publisher is not taken back as a fed standby"
            );
        }
    }

    /// The loop guard on a standby: a standby whose latest offer shows this
    /// node in its ancestry (it now hears the stream THROUGH this node) is
    /// never promoted, neither as a failover nor as a voluntary switch.
    /// Mutation (45.2.0 before): the promotion checked only the standby's
    /// health and forwarding, so a node with no primary asked its own
    /// descendant (the kill witness, 734a272).
    #[test]
    fn a_standby_that_became_a_descendant_is_never_promoted() {
        let mut cfg = ControllerConfig::interactive();
        cfg.direct_first = true;
        cfg.jitter = false;
        let mut s = ParentSelector::new(1u32, cfg.clone(), true);
        s.set_members([1u32, 2, 3]);
        let (mut rng, mut log) = (SplitMix64(5), DecisionLog::default());
        let offers = [(2, 4, 20.0)];
        let _ = drive(&mut s, &cfg, 0, 4_000, &offers);
        assert_eq!(s.primary(), Some(&2), "the premise: on the publisher");
        // 3 offers as a relay under 2 and becomes this node's standby.
        let mut t = 4_000;
        let mut standby = false;
        while t < 12_000 && !standby {
            s.on_offer(t, offer(2, 4, &cfg), 20.0, &mut log);
            s.on_offer(t, relay_offer(3, &cfg), 5.0, &mut log);
            for a in s.tick(t, &mut rng, &mut log) {
                if let SelectorAction::Subscribe { parent, role } = a {
                    let _ = s.on_decision(
                        t,
                        &parent,
                        &AdmitDecision::Admit { role },
                        &mut rng,
                        &mut log,
                    );
                }
            }
            standby = s.standby() == Some(&3);
            t += 250;
        }
        assert!(standby, "the premise: 3 is the standby");
        // 3 now hears the stream through this node, and the publisher's link
        // is gone.
        let looped = Offer {
            depth: 2,
            ancestry: vec![2, 1],
            ..offer(3, 4, &cfg)
        };
        s.on_offer(t, looped, 5.0, &mut log);
        s.on_link_down(t, &2, &mut log);
        for k in 0..8u64 {
            let acts = s.tick(t + k * 250, &mut rng, &mut log);
            assert!(
                !acts.contains(&SelectorAction::Subscribe {
                    parent: 3,
                    role: Role::Primary
                }),
                "promoted its own descendant: {acts:?}"
            );
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

    /// 45.3 — a parent that keeps OFFERING a stream whose upstream it reports
    /// past the stale budget, while its media for it is silent (a relay
    /// dropping its upstream's stale media), is not failed over; once its
    /// offers stop, the silence counts and it is failed over within the
    /// existing bound (`down_silence_ms` past the offer's life). When the
    /// excuse ends with the offers still coming, the excused span is not
    /// charged at once: the parent owes chunks from then. A parent offering
    /// an on-time upstream and sending nothing is a black hole: failed over.
    #[test]
    #[allow(clippy::too_many_lines, clippy::many_single_char_names)]
    fn a_parent_that_still_offers_is_alive_and_one_that_stops_is_not() {
        let cfg = ControllerConfig::interactive();
        let mut s = ParentSelector::new(1u32, cfg.clone(), false);
        s.set_members([1u32, 2]);
        let mut rng = SplitMix64(9);
        let mut log = DecisionLog::default();
        let mut t = 0;
        while s.primary().is_none() && t < 10_000 {
            if t % 1_000 == 0 {
                s.on_offer(t, offer(2, 4, &cfg), 20.0, &mut log);
            }
            for a in s.tick(t, &mut rng, &mut log) {
                if let SelectorAction::Subscribe { parent, role } = a {
                    let d = AdmitDecision::Admit { role };
                    let _ = s.on_decision(t, &parent, &d, &mut rng, &mut log);
                }
            }
            t += 250;
        }
        assert_eq!(s.primary(), Some(&2));
        s.on_chunk(t, &2, at(1, false, 100, 5.0));
        // 20 s of media silence, offers each second that say the parent's
        // upstream is seconds late: never failed over.
        let late = |cfg: &ControllerConfig| {
            let mut o = offer(2, 4, cfg);
            o.upstream_latency_ms = 3_000;
            o
        };
        let quiet_from = t;
        while t < quiet_from + 20_000 {
            t += 250;
            if t % 1_000 == 0 {
                s.on_offer(t, late(&cfg), 20.0, &mut log);
            }
            let _ = s.tick(t, &mut rng, &mut log);
            assert_eq!(s.state_of(&2), Some(PeerState::Available), "at {t}");
        }
        assert_eq!(s.primary(), Some(&2));
        // A black hole: on-time offers and no media. Failed over as before.
        let mut b = ParentSelector::new(1u32, cfg.clone(), false);
        b.set_members([1u32, 2]);
        let mut bt = 0;
        while b.primary().is_none() && bt < 10_000 {
            if bt % 1_000 == 0 {
                b.on_offer(bt, offer(2, 4, &cfg), 20.0, &mut log);
            }
            for a in b.tick(bt, &mut rng, &mut log) {
                if let SelectorAction::Subscribe { parent, role } = a {
                    let d = AdmitDecision::Admit { role };
                    let _ = b.on_decision(bt, &parent, &d, &mut rng, &mut log);
                }
            }
            bt += 250;
        }
        b.on_chunk(bt, &2, at(1, false, 100, 5.0));
        let hole_from = bt;
        while b.state_of(&2) == Some(PeerState::Available) {
            bt += 250;
            if bt % 1_000 == 0 {
                b.on_offer(bt, offer(2, 4, &cfg), 20.0, &mut log);
            }
            let _ = b.tick(bt, &mut rng, &mut log);
            assert!(
                bt <= hole_from + cfg.down_silence_ms + 250,
                "a black hole is seen"
            );
        }
        // The excuse ends with the offers still coming (the publisher's
        // backlog dips under the budget): the excused span is not charged at
        // once; the parent owes chunks from then, within down_silence_ms.
        let mut e = ParentSelector::new(1u32, cfg.clone(), false);
        e.set_members([1u32, 2]);
        let mut et = 0;
        while e.primary().is_none() && et < 10_000 {
            if et % 1_000 == 0 {
                e.on_offer(et, late(&cfg), 20.0, &mut log);
            }
            for a in e.tick(et, &mut rng, &mut log) {
                if let SelectorAction::Subscribe { parent, role } = a {
                    let d = AdmitDecision::Admit { role };
                    let _ = e.on_decision(et, &parent, &d, &mut rng, &mut log);
                }
            }
            et += 250;
        }
        e.on_chunk(et, &2, at(1, false, 100, 5.0));
        let excused_from = et;
        while et < excused_from + 20_000 {
            et += 250;
            if et % 1_000 == 0 {
                e.on_offer(et, late(&cfg), 20.0, &mut log);
            }
            let _ = e.tick(et, &mut rng, &mut log);
        }
        assert_eq!(e.state_of(&2), Some(PeerState::Available));
        et += 250;
        e.on_offer(et, offer(2, 4, &cfg), 20.0, &mut log);
        let ended = et;
        let _ = e.tick(et, &mut rng, &mut log);
        assert_eq!(
            e.state_of(&2),
            Some(PeerState::Available),
            "the excused span is not charged at once"
        );
        while e.primary() == Some(&2) {
            et += 250;
            if et % 1_000 == 0 {
                e.on_offer(et, offer(2, 4, &cfg), 20.0, &mut log);
            }
            let _ = e.tick(et, &mut rng, &mut log);
            assert!(
                et <= ended + cfg.down_silence_ms + 250,
                "silence after the excuse is seen: failed over (at {et})"
            );
        }
        assert_ne!(e.state_of(&2), Some(PeerState::Available));
        // The offers stop: failed over within the offer's life plus the
        // silence bound (Suspected drops a primary with no standby to wait
        // on; it never reaches Down unsubscribed).
        let stopped = t;
        while s.primary() == Some(&2) {
            t += 250;
            let _ = s.tick(t, &mut rng, &mut log);
            assert!(
                t <= stopped + OFFER_IS_LIFE_MS + cfg.down_silence_ms + 250,
                "failed over within the bound (at {t})"
            );
        }
        assert_ne!(s.state_of(&2), Some(PeerState::Available));
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

    /// Row S3 and the loop guard — a node that lost its primary never takes
    /// a standby or candidate from its own subtree (an offer whose ancestry
    /// names it), and asks the publisher at once though its candidate is Down.
    #[test]
    fn a_parentless_node_never_takes_its_own_descendant_and_asks_the_publisher() {
        let mut cfg = ControllerConfig::interactive();
        cfg.direct_first = true;
        let mut s = ParentSelector::new(1u32, cfg.clone(), true);
        s.set_members([1u32, 2, 3]);
        // 2 publishes; 3 relays it (depth 1 under 2).
        let relay = |anc: Vec<u32>| Offer {
            from: 3,
            depth: u8::try_from(anc.len()).unwrap_or(1),
            ancestry: anc,
            headroom_bps: 4 * cfg.stream_bps,
            forwarder_headroom_bps: 4 * cfg.stream_bps,
            upstream_latency_ms: 0,
            forwarding: true,
        };
        let mut rng = SplitMix64(3);
        let mut log = DecisionLog::default();
        let _ = drive(&mut s, &cfg, 0, 10_000, &[(2, 4, 20.0)]);
        s.on_offer(10_000, relay(vec![2]), 20.0, &mut log);
        let _ = drive(&mut s, &cfg, 10_000, 20_000, &[(2, 4, 20.0)]);
        assert_eq!(s.primary(), Some(&2));
        // The tree moved: 3 is now UNDER this node (its ancestry names 1).
        s.on_offer(20_000, relay(vec![2, 1]), 20.0, &mut log);
        s.on_link_down(20_100, &2, &mut log);
        let mut asked: Vec<(u32, Role)> = Vec::new();
        let mut first_ask: Option<u64> = None;
        for k in 0..24u64 {
            let t = 20_250 + k * 250;
            for a in s.tick(t, &mut rng, &mut log) {
                if let SelectorAction::Subscribe { parent, role } = a {
                    if parent == 2 && role == Role::Primary {
                        first_ask.get_or_insert(t);
                    }
                    asked.push((parent, role));
                }
            }
        }
        assert!(
            !asked.iter().any(|(p, r)| *p == 3 && *r == Role::Primary),
            "never a primary from its own subtree: {asked:?}"
        );
        assert!(
            asked.iter().any(|(p, r)| *p == 2 && *r == Role::Primary),
            "the publisher is asked at once, Down or not: {asked:?}"
        );
        assert!(
            first_ask.is_some_and(|t| t <= 20_500),
            "asked on the tick after the loss (20_100), not after a wait: {first_ask:?}"
        );
    }

    /// A member with no parent and no candidate advertising room still asks
    /// (R3 on the member tier), on its jittered backoff. avmesh4 (C): shed by
    /// m0 under a cap, m1 and m3 never asked m0 again in the 60 s after the
    /// cap lifted (m0 refused nothing on its own stream), because m0's offer
    /// showed no room. Mutation (v44.1.1): a member-only world waits for
    /// room in silence, and no subscribe to the publisher is ever sent.
    /// A late ADMIT (the forwarder retries a refused answer for up to 30 s)
    /// is applied only when it answers the request now out: one for another
    /// role, or for a request this node abandoned, changes nothing; an
    /// unasked primary while this node holds one is released with an
    /// UNSUBSCRIBE. Mutation: each installed a parent or kept the slot.
    #[test]
    fn a_late_admit_is_applied_only_to_the_request_now_out() {
        let cfg = ControllerConfig::interactive();
        let mut rng = SplitMix64(5);
        let mut log = DecisionLog::default();
        let admit = |role| AdmitDecision::Admit { role };
        // (a) Another role than the request now out: not applied.
        let mut s = ParentSelector::new(1u32, cfg.clone(), false);
        s.set_members([1u32, 2, 3]);
        let _ = drive(&mut s, &cfg, 0, 10_000, &[(2, 4, 20.0), (3, 4, 30.0)]);
        let primary = *s.primary().expect("a primary");
        let other = if primary == 2 { 3 } else { 2 };
        let standby = s.standby;
        if standby == Some(other) {
            s.cands.get_mut(&other).expect("cand").link = Link::None;
            s.standby = None;
        }
        s.cands.get_mut(&other).expect("cand").link = Link::Requested {
            role: Role::Standby,
            at_ms: 10_000,
            was_standby: false,
            late: false,
        };
        let out = s.on_decision(10_100, &other, &admit(Role::Primary), &mut rng, &mut log);
        assert!(out.is_empty(), "{out:?}");
        assert_eq!(s.primary(), Some(&primary));
        assert!(matches!(s.cands[&other].link, Link::Requested { .. }));
        // (b) An unasked primary from the standby parent while holding one.
        s.cands.get_mut(&other).expect("cand").link = Link::Standby;
        s.standby = Some(other);
        let out = s.on_decision(10_200, &other, &admit(Role::Primary), &mut rng, &mut log);
        assert!(
            out.iter()
                .any(|a| matches!(a, SelectorAction::Unsubscribe { parent } if *parent == other)),
            "the slot is released: {out:?}"
        );
        assert_eq!(s.primary(), Some(&primary));
        assert_eq!(s.cands[&other].link, Link::None);
        // (c) A late answer to an abandoned request: not applied, even when
        // the node is parentless (its later message to the forwarder wins).
        let mut s = ParentSelector::new(1u32, cfg.clone(), false);
        s.set_members([1u32, 2]);
        s.on_offer(0, offer(2, 4, &cfg), 20.0, &mut log);
        {
            let c = s.cands.get_mut(&2).expect("cand");
            c.link = Link::Standby;
            c.abandoned_at_ms = Some(5_000);
        }
        s.standby = Some(2);
        let out = s.on_decision(20_000, &2, &admit(Role::Primary), &mut rng, &mut log);
        assert!(out.is_empty(), "{out:?}");
        assert_eq!(s.primary(), None, "no parent installed by a late answer");
        // Past LATE_ANSWER_MS it is the forwarder's own promotion (row E2).
        let _ = s.on_decision(40_000, &2, &admit(Role::Primary), &mut rng, &mut log);
        assert_eq!(s.primary(), Some(&2));
        // (d) Abandoned, then asked again within the window: the new
        // request's answer is applied.
        let mut s = ParentSelector::new(1u32, cfg.clone(), false);
        s.set_members([1u32, 2]);
        s.on_offer(0, offer(2, 4, &cfg), 20.0, &mut log);
        s.cands.get_mut(&2).expect("cand").abandoned_at_ms = Some(5_000);
        let _ = s.request(6_000, &2, Role::Primary, "again", &mut log);
        let _ = s.on_decision(6_100, &2, &admit(Role::Primary), &mut rng, &mut log);
        assert_eq!(
            s.primary(),
            Some(&2),
            "the current request's answer is applied"
        );
        assert_eq!(s.cands[&2].abandoned_at_ms, None);
    }

    /// Row S3 held — the asked publisher's ADMIT keeps: the Down its old
    /// link-down left is cleared by the ADMIT, and before the first chunk
    /// the publisher's advertised upstream latency (its uplink queue) is
    /// owed as well as the silence threshold. Mutation (kill 2): failed over
    /// one tick after every ADMIT, and the whole tree ended parentless.
    #[test]
    fn an_asked_publishers_admit_keeps_through_its_queue() {
        let mut cfg = ControllerConfig::interactive();
        cfg.direct_first = true;
        let mut s = ParentSelector::new(1u32, cfg.clone(), false);
        s.set_members([1u32, 2]);
        let mut rng = SplitMix64(9);
        let mut log = DecisionLog::default();
        let _ = drive(&mut s, &cfg, 0, 10_000, &[(2, 4, 20.0)]);
        assert_eq!(s.primary(), Some(&2));
        s.on_link_down(10_100, &2, &mut log);
        let queued = |t| {
            let mut o = offer(2, 4, &cfg);
            o.upstream_latency_ms = 2_200;
            let _ = t;
            o
        };
        let mut admitted_at = None;
        let mut t = 10_250;
        while t < 30_000 {
            if t % 1_000 == 0 {
                s.on_offer(t, queued(t), 20.0, &mut log);
            }
            for a in s.tick(t, &mut rng, &mut log) {
                if let SelectorAction::Subscribe { parent: 2, role } = a {
                    let d = AdmitDecision::Admit { role };
                    let _ = s.on_decision(t, &2, &d, &mut rng, &mut log);
                    if role == Role::Primary && admitted_at.is_none() {
                        admitted_at = Some(t);
                    }
                }
            }
            if let Some(at) = admitted_at {
                // No chunk yet: the queue is 2.2 s deep.
                if t < at + 2_000 {
                    assert_eq!(
                        s.primary(),
                        Some(&2),
                        "kept through its queue at t={t} (admitted {at})"
                    );
                } else {
                    break;
                }
            }
            t += 250;
        }
        assert!(
            admitted_at.is_some(),
            "the publisher was asked and admitted"
        );
    }

    /// Row S3 is for a LOST primary only: a node its publisher SHED does
    /// not ask it back (the publisher decided, under its own load). Mutation
    /// (5f8aa9b): it asked on the next tick, the refusal fed the publisher's
    /// demand, and mesh4's n4 re-overcommitted after the lift.
    #[test]
    fn a_node_its_publisher_shed_does_not_ask_it_back() {
        let mut cfg = ControllerConfig::interactive();
        cfg.direct_first = true;
        let mut s = ParentSelector::new(1u32, cfg.clone(), false);
        s.set_members([1u32, 2]);
        let mut rng = SplitMix64(4);
        let mut log = DecisionLog::default();
        let _ = drive(&mut s, &cfg, 0, 10_000, &[(2, 4, 20.0)]);
        assert_eq!(s.primary(), Some(&2));
        s.on_shed(10_100, &2, &mut rng, &mut log);
        for k in 0..24u64 {
            let _ = s.tick(10_250 + k * 250, &mut rng, &mut log);
        }
        assert!(
            !log.tail().contains("ask publisher"),
            "no ask back after a shed: {}",
            log.tail()
        );
    }

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
