//! The service ladder (`FSD/CIRIS_MESH.md` §7; Eric 2026-11-01): how a node
//! degrades under load, "from full ops, to audio and files, to supporting
//! basic chat/contacts".
//!
//! # The signal path (§7.3)
//!
//! - **The host** (the server, which owns the host budget the way the agent's
//!   resource monitor does) samples CPU, RSS and read time and calls
//!   `Edge::set_load_pressure(Normal | Warning | Critical)` (L-S1). That maps
//!   to tier 0, 1 or 2.
//! - **Edge's own signals** (L-S2) may raise the tier and never lower it below
//!   the host's: relay commitments at 65 % of measured for three windows, the
//!   A/V inbound queue older than 800 ms for three windows, and forwarded
//!   packets/s at 65 % (tier 1) or 90 % (tier 2) of measured forward capacity.
//! - **Asymmetric hysteresis** (L-S3): raising takes effect at once; lowering
//!   is one step at a time, and only after every input stayed below 0.8 × its
//!   raise threshold for the step's cooldown (60 s from tier 2 to 1, 120 s
//!   from 1 to 0). React fast, recover slowly: a shed costs requesters a
//!   make-before-break move, so a flapping tier would herd them.
//! - **Every change is logged and counted** (L-S4) under a stable token.
//!
//! # What each tier sheds (§7.2)
//!
//! [`ServiceTier`] answers the lever questions as O(1) reads (L-R3): the
//! ladder's own decisions must never be load. The never-shed set (L-A3: own
//! devices and owner, federation duty, `control`, revocations) is never named
//! by any lever: [`FlowClass::never_shed`] is checked before every shed.
//!
//! Shaped slots follow the same tiers (`FSD/PRIVACY_MODES.md` §6.12): what a
//! lever owes a peer is [`PeerObligation`], read when it acts. Cover is not
//! shed, and no lever touches a shaper.
//!
//! The state machine is pure and clock-injected (`now_ms`), so the sim drives
//! the production type (LS1–LS5 in `closed_loop_sim`).

use std::collections::BTreeMap;

/// The host's load verdict (L-S1). Promised to the server as
/// `Edge::set_load_pressure(LoadPressure)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum LoadPressure {
    /// Within budget.
    #[default]
    Normal,
    /// Over the warning threshold.
    Warning,
    /// Over the critical threshold.
    Critical,
}

impl LoadPressure {
    /// The tier this pressure asks for.
    #[must_use]
    pub const fn tier(self) -> ServiceTier {
        match self {
            Self::Normal => ServiceTier::FullOps,
            Self::Warning => ServiceTier::AudioAndFiles,
            Self::Critical => ServiceTier::ChatAndContacts,
        }
    }

    /// Parse a host's spelling (`normal` / `warning` / `critical`).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "normal" => Some(Self::Normal),
            "warning" => Some(Self::Warning),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

/// The service tier a node runs at (§7.2). Promised to the server as
/// `Edge::service_tier() -> ServiceTier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(u8)]
pub enum ServiceTier {
    /// Tier 0: everything.
    #[default]
    FullOps = 0,
    /// Tier 1: audio and files. Video on relayed legs is shed to the base
    /// layer, new relay work is refused, non-obligation rounds stretch.
    AudioAndFiles = 1,
    /// Tier 2: chat and contacts. Relayed audio is shed (LIFO,
    /// make-before-break), bulk transfer pauses, this node's own call is
    /// audio only.
    ChatAndContacts = 2,
}

impl ServiceTier {
    /// `0`, `1` or `2`.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// From `0`, `1` or `2` (anything higher is tier 2).
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::FullOps,
            1 => Self::AudioAndFiles,
            _ => Self::ChatAndContacts,
        }
    }

    /// The stable token `load_tier:{0,1,2}`.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::FullOps => "load_tier:0",
            Self::AudioAndFiles => "load_tier:1",
            Self::ChatAndContacts => "load_tier:2",
        }
    }

    const fn down(self) -> Self {
        match self {
            Self::FullOps | Self::AudioAndFiles => Self::FullOps,
            Self::ChatAndContacts => Self::AudioAndFiles,
        }
    }

    /// **Admit-close** (tier ≥ 1): no new relayed links, relay reservations
    /// or A/V relay legs; C2 answers `Refuse { retry_after }` with
    /// `load_refuse:admit_closed`.
    #[must_use]
    pub const fn admits_new_relay_work(self) -> bool {
        matches!(self, Self::FullOps)
    }

    /// **Admit-close on shaped slots** (tier ≥ 1, `FSD/PRIVACY_MODES.md`
    /// §6.12): a peer that is no obligation of this node gets no new shaped
    /// link. It is refused with referrals, and the node reports zero slots.
    #[must_use]
    pub const fn admits_new_shaped_links(self) -> bool {
        self.admits_new_relay_work()
    }

    /// **A shaped link sheds whole** (tier 2, §6.12): links to non-obligation
    /// peers may close, newest first. Never below the class: cover is not
    /// shed, and no lever here touches a shaper.
    #[must_use]
    pub const fn closes_shaped_links(self) -> bool {
        matches!(self, Self::ChatAndContacts)
    }

    /// **V-shed** (tier ≥ 1): video on legs this node RELAYS goes to the base
    /// layer (`BLINKING_DOT`), standbys keepalive-only.
    #[must_use]
    pub const fn sheds_relayed_video(self) -> bool {
        !matches!(self, Self::FullOps)
    }

    /// **A-shed** (tier 2): relayed audio legs are shed newest-first, each
    /// with a `Shed` notice so the requester moves make-before-break.
    #[must_use]
    pub const fn sheds_relayed_audio(self) -> bool {
        matches!(self, Self::ChatAndContacts)
    }

    /// **B-pause** (tier 2): bulk transfer for non-owner peers pauses (not
    /// cancelled; it resumes from its cursor at tier ≤ 1).
    #[must_use]
    pub const fn pauses_bulk(self) -> bool {
        matches!(self, Self::ChatAndContacts)
    }

    /// This node's OWN call: full at tiers 0 and 1 (video host-degraded at
    /// 1), audio only at tier 2.
    #[must_use]
    pub const fn own_call_audio_only(self) -> bool {
        matches!(self, Self::ChatAndContacts)
    }

    /// **Stretch** factor for expensive non-obligation rounds: ×1, ×4, ×8.
    #[must_use]
    pub const fn stretch(self) -> u32 {
        match self {
            Self::FullOps => 1,
            Self::AudioAndFiles => 4,
            Self::ChatAndContacts => 8,
        }
    }

    /// What tier `self` does to a flow of `class` ([`Lever`]). Never-shed
    /// classes are `Full` at every tier (L-A3).
    #[must_use]
    #[allow(clippy::match_same_arms)] // one arm per (class, tier) cell of §7.2's table
    pub const fn lever(self, class: FlowClass) -> Lever {
        if class.never_shed() {
            return Lever::Full;
        }
        match (class, self) {
            (_, Self::FullOps) => Lever::Full,
            (FlowClass::RelayedVideo, _) => Lever::BaseLayer,
            (FlowClass::RelayedAudio | FlowClass::Bulk, Self::AudioAndFiles) => Lever::Full,
            (FlowClass::RelayedAudio, Self::ChatAndContacts) => Lever::Shed,
            (FlowClass::Bulk, Self::ChatAndContacts) => Lever::Pause,
            (FlowClass::OrdinaryRound, t) => Lever::Stretch(t.stretch()),
            (FlowClass::OwnCallVideo, Self::AudioAndFiles) => Lever::BaseLayer,
            (FlowClass::OwnCallVideo, Self::ChatAndContacts) => Lever::Shed,
            (FlowClass::NewRelayWork, _) => Lever::Refuse,
            // Chat, contacts, own-device rounds and the rest: full (they are
            // never_shed above or kept by every tier of §7.2).
            _ => Lever::Full,
        }
    }
}

/// A flow's class for the ladder (§7.2's lever-to-plane mapping). Classified
/// from fields the flow is already routed on (L-R2), never from a body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FlowClass {
    /// KEX, route fetch, path requests, first contact, push-to-wake, C3.
    Control,
    /// Revocations of every kind.
    Revocation,
    /// This node's own devices and owner.
    OwnDevice,
    /// Serving replication as a seated canonical, rounds owed to the send
    /// set, acked custody (report-then-relief, L-A2).
    FederationDuty,
    /// Chat rows, contacts and consent rows, rooms, key grants.
    ChatAndContacts,
    /// Every other replication round to a non-obligation peer.
    OrdinaryRound,
    /// Blob and file transfer for non-owner peers; the durability pass.
    Bulk,
    /// Audio on a leg this node relays (member relay or forwarder).
    RelayedAudio,
    /// Video on a leg this node relays.
    RelayedVideo,
    /// This node's own call's video.
    OwnCallVideo,
    /// A NEW relayed link, reservation or A/V relay leg.
    NewRelayWork,
}

impl FlowClass {
    /// L-A3: served at full rate under every tier.
    #[must_use]
    pub const fn never_shed(self) -> bool {
        matches!(
            self,
            Self::Control | Self::Revocation | Self::OwnDevice | Self::FederationDuty
        )
    }
}

/// What this node owes a peer, read when a shed lever is about to act on it
/// (`FSD/CIRIS_MESH.md` §7.1, §7.2; `FSD/PRIVACY_MODES.md` §6.12). The peers a
/// tier leaves alone are the ones its Stretch row names, "the owner, own
/// devices or the send set", and the serve seats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerObligation {
    /// The owner or one of the owner's devices (L-A3).
    OwnDevice,
    /// A seat on the active canonical roster (L-A2).
    Seat,
    /// In the resolved send set: rounds are owed to it (L-A2).
    SendSet,
    /// None of these, on a complete read.
    Ordinary,
    /// The read failed or was narrower than the truth. A wrong refusal hurts
    /// quietly and a missed shed costs a little load, so nothing is shed.
    Unresolved,
}

impl PeerObligation {
    /// The ladder's class of this peer's flows; `None` when not known.
    #[must_use]
    pub const fn flow_class(self) -> Option<FlowClass> {
        match self {
            Self::OwnDevice => Some(FlowClass::OwnDevice),
            Self::Seat | Self::SendSet => Some(FlowClass::FederationDuty),
            Self::Ordinary => Some(FlowClass::OrdinaryRound),
            Self::Unresolved => None,
        }
    }

    /// Whether this peer keeps its shaped slot under every tier: Admit-close
    /// admits it and tier 2 never closes its link.
    #[must_use]
    pub const fn keeps_shaped_link(self) -> bool {
        match self.flow_class() {
            Some(class) => class.never_shed(),
            None => true,
        }
    }

    /// Whether this peer's slow path keeps running at tier 2: B-pause exempts
    /// the owner's devices alone ("for non-owner peers", §7.2).
    #[must_use]
    pub const fn keeps_slow_path(self) -> bool {
        matches!(self, Self::OwnDevice | Self::Unresolved)
    }
}

/// The read a shed lever makes at decision time. Installed on the transport
/// (`ReticulumTransport::install_peer_obligations`); production is
/// [`crate::peer_obligation::LivePeerObligations`].
#[async_trait::async_trait]
pub trait PeerObligations: Send + Sync + std::fmt::Debug {
    /// What this node owes `peer` now.
    async fn obligation_of(&self, peer: &str) -> PeerObligation;
}

/// What a tier does to one flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lever {
    /// Untouched.
    Full,
    /// Lengthen its interval by this factor; serve it after obligations.
    Stretch(u32),
    /// Video degraded to the base layer.
    BaseLayer,
    /// Paused, resumable from its cursor.
    Pause,
    /// Shed (LIFO, with a notice).
    Shed,
    /// Refused (`load_refuse:admit_closed`).
    Refuse,
}

/// Edge's own load signals for one window (L-S2). Ratios are against the
/// node's measured capacity; absent measures are 0.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct EdgeLoadSignals {
    /// Relay commitments ÷ measured relay capacity (worst resource).
    pub relay_commit_ratio: f64,
    /// Age of the oldest frame in the A/V inbound queues (ms).
    pub av_queue_age_ms: u64,
    /// Forwarded packets/s ÷ measured forward capacity.
    pub transit_pps_ratio: f64,
}

/// The ladder's knobs (§7.3 defaults).
#[derive(Debug, Clone, PartialEq)]
pub struct LadderConfig {
    /// Relay commitment ratio that raises to tier 1 (sustained).
    pub relay_commit_raise: f64,
    /// A/V queue age that raises to tier 1 (sustained), ms.
    pub av_queue_age_raise_ms: u64,
    /// Forwarded pps ratio that raises to tier 1.
    pub transit_tier1_raise: f64,
    /// Forwarded pps ratio that raises to tier 2.
    pub transit_tier2_raise: f64,
    /// Windows a sustained signal must hold.
    pub sustain_windows: u32,
    /// Lower thresholds are the raise thresholds × this.
    pub lower_factor: f64,
    /// Calm time before tier 2 → 1, ms.
    pub cooldown_2_to_1_ms: u64,
    /// Calm time before tier 1 → 0, ms.
    pub cooldown_1_to_0_ms: u64,
}

impl Default for LadderConfig {
    fn default() -> Self {
        Self {
            relay_commit_raise: 0.65,
            // 2 × REORDER_WINDOW_MAX (av_call.rs).
            av_queue_age_raise_ms: 800,
            transit_tier1_raise: 0.65,
            transit_tier2_raise: 0.90,
            sustain_windows: 3,
            lower_factor: 0.8,
            cooldown_2_to_1_ms: 60_000,
            cooldown_1_to_0_ms: 120_000,
        }
    }
}

impl LadderConfig {
    /// LS5-mut: every hysteresis and cooldown at zero. LS3 MUST fail with it.
    #[must_use]
    pub fn no_hysteresis(mut self) -> Self {
        self.sustain_windows = 1;
        self.lower_factor = 1.0;
        self.cooldown_2_to_1_ms = 0;
        self.cooldown_1_to_0_ms = 0;
        self
    }
}

/// One tier change, as logged (L-S4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierChange {
    /// When.
    pub at_ms: u64,
    /// From.
    pub from: ServiceTier,
    /// To.
    pub to: ServiceTier,
    /// Why: `host:warning`, `host:critical`, `host:normal`,
    /// `edge:relay_commit`, `edge:av_queue_age`, `edge:transit_pps`,
    /// `cooldown`.
    pub cause: &'static str,
}

/// Bound on remembered tier changes.
const CHANGE_LOG: usize = 64;

/// The ladder: host pressure + edge signals → the effective tier.
#[derive(Debug, Clone)]
pub struct LoadLadder {
    cfg: LadderConfig,
    host: LoadPressure,
    tier: ServiceTier,
    relay_streak: u32,
    queue_streak: u32,
    edge_tier: ServiceTier,
    edge_cause: &'static str,
    calm_since: Option<u64>,
    changes: Vec<TierChange>,
    counters: BTreeMap<&'static str, u64>,
}

impl Default for LoadLadder {
    fn default() -> Self {
        Self::new(LadderConfig::default())
    }
}

impl LoadLadder {
    /// A ladder at tier 0.
    #[must_use]
    pub fn new(cfg: LadderConfig) -> Self {
        Self {
            cfg,
            host: LoadPressure::Normal,
            tier: ServiceTier::FullOps,
            relay_streak: 0,
            queue_streak: 0,
            edge_tier: ServiceTier::FullOps,
            edge_cause: "",
            calm_since: None,
            changes: Vec::new(),
            counters: BTreeMap::new(),
        }
    }

    /// The effective tier.
    #[must_use]
    pub fn tier(&self) -> ServiceTier {
        self.tier
    }

    /// The host's last pressure.
    #[must_use]
    pub fn host_pressure(&self) -> LoadPressure {
        self.host
    }

    /// Recent tier changes, oldest first.
    #[must_use]
    pub fn changes(&self) -> &[TierChange] {
        &self.changes
    }

    /// Per-token counters (`load_tier:*`, causes).
    #[must_use]
    pub fn counters(&self) -> &BTreeMap<&'static str, u64> {
        &self.counters
    }

    /// The host's verdict (L-S1). Raising takes effect at once.
    pub fn set_host_pressure(&mut self, now_ms: u64, p: LoadPressure) -> ServiceTier {
        self.host = p;
        self.settle(now_ms)
    }

    /// One window of edge's own signals (L-S2).
    pub fn observe(&mut self, now_ms: u64, s: EdgeLoadSignals) -> ServiceTier {
        let c = &self.cfg;
        self.relay_streak = if s.relay_commit_ratio >= c.relay_commit_raise {
            self.relay_streak + 1
        } else {
            0
        };
        #[allow(clippy::cast_precision_loss)]
        let queue_hot = s.av_queue_age_ms > c.av_queue_age_raise_ms;
        self.queue_streak = if queue_hot { self.queue_streak + 1 } else { 0 };
        let (mut t, mut cause) = (ServiceTier::FullOps, "");
        if s.transit_pps_ratio >= c.transit_tier2_raise {
            (t, cause) = (ServiceTier::ChatAndContacts, "edge:transit_pps");
        } else if s.transit_pps_ratio >= c.transit_tier1_raise {
            (t, cause) = (ServiceTier::AudioAndFiles, "edge:transit_pps");
        } else if self.relay_streak >= c.sustain_windows {
            (t, cause) = (ServiceTier::AudioAndFiles, "edge:relay_commit");
        } else if self.queue_streak >= c.sustain_windows {
            (t, cause) = (ServiceTier::AudioAndFiles, "edge:av_queue_age");
        }
        // Calm is judged against the LOWER thresholds (raise × 0.8).
        let lf = c.lower_factor;
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let calm_for = |tier: ServiceTier| -> bool {
            match tier {
                ServiceTier::FullOps => true,
                ServiceTier::AudioAndFiles => {
                    s.transit_pps_ratio < c.transit_tier1_raise * lf
                        && s.relay_commit_ratio < c.relay_commit_raise * lf
                        && (s.av_queue_age_ms as f64) < c.av_queue_age_raise_ms as f64 * lf
                }
                ServiceTier::ChatAndContacts => s.transit_pps_ratio < c.transit_tier2_raise * lf,
            }
        };
        // `edge_tier` is what edge's signals still hold up: the raise level,
        // or the current level until the signals are calm below it.
        self.edge_tier = if t > ServiceTier::FullOps {
            t
        } else if self.edge_tier > ServiceTier::FullOps && !calm_for(self.edge_tier) {
            self.edge_tier
        } else {
            ServiceTier::FullOps
        };
        if !cause.is_empty() {
            self.edge_cause = cause;
        }
        self.settle(now_ms)
    }

    fn settle(&mut self, now_ms: u64) -> ServiceTier {
        let host_t = self.host.tier();
        let target = host_t.max(self.edge_tier);
        if target > self.tier {
            let cause = if host_t >= self.edge_tier {
                match self.host {
                    LoadPressure::Warning => "host:warning",
                    LoadPressure::Critical => "host:critical",
                    LoadPressure::Normal => "host:normal",
                }
            } else {
                self.edge_cause
            };
            self.change(now_ms, target, cause);
            self.calm_since = None;
            return self.tier;
        }
        if target == self.tier {
            self.calm_since = None;
            return self.tier;
        }
        // target < tier: lower one step after the step's cooldown of calm.
        let since = *self.calm_since.get_or_insert(now_ms);
        let cooldown = match self.tier {
            ServiceTier::ChatAndContacts => self.cfg.cooldown_2_to_1_ms,
            _ => self.cfg.cooldown_1_to_0_ms,
        };
        if now_ms.saturating_sub(since) >= cooldown {
            let to = self.tier.down().max(target);
            self.change(now_ms, to, "cooldown");
            // The next step needs its own full cooldown.
            self.calm_since = (to > target).then_some(now_ms);
        }
        self.tier
    }

    fn change(&mut self, now_ms: u64, to: ServiceTier, cause: &'static str) {
        let from = self.tier;
        self.tier = to;
        *self.counters.entry(to.token()).or_insert(0) += 1;
        if !cause.is_empty() {
            *self.counters.entry(cause).or_insert(0) += 1;
        }
        if self.changes.len() == CHANGE_LOG {
            self.changes.remove(0);
        }
        self.changes.push(TierChange {
            at_ms: now_ms,
            from,
            to,
            cause,
        });
        tracing::info!(
            from = from.as_u8(),
            to = to.as_u8(),
            cause,
            token = to.token(),
            "SERVICE TIER changed (FSD CIRIS_MESH §7)"
        );
    }
}

/// A [`LoadLadder`] shared by a node's parts (the `Edge` API, every live
/// call, the transport's forwarding meter), on one monotonic clock. Each
/// source reports its signal; once a second the worst of each is folded in
/// as one window (L-S2).
#[derive(Debug)]
pub struct SharedLadder {
    t0: std::time::Instant,
    inner: std::sync::Mutex<(LoadLadder, EdgeLoadSignals, u64)>,
}

impl Default for SharedLadder {
    fn default() -> Self {
        Self::new(LadderConfig::default())
    }
}

impl SharedLadder {
    /// A shared ladder at tier 0.
    #[must_use]
    pub fn new(cfg: LadderConfig) -> Self {
        Self {
            t0: std::time::Instant::now(),
            inner: std::sync::Mutex::new((LoadLadder::new(cfg), EdgeLoadSignals::default(), 0)),
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.t0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, (LoadLadder, EdgeLoadSignals, u64)> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The host's verdict (L-S1).
    pub fn set_host_pressure(&self, p: LoadPressure) -> ServiceTier {
        let now = self.now_ms();
        self.lock().0.set_host_pressure(now, p)
    }

    /// One source's signals for the current window: the worst of each
    /// across sources is folded in at the window's end.
    pub fn report(&self, s: EdgeLoadSignals) -> ServiceTier {
        let now = self.now_ms();
        let mut g = self.lock();
        g.1.relay_commit_ratio = g.1.relay_commit_ratio.max(s.relay_commit_ratio);
        g.1.av_queue_age_ms = g.1.av_queue_age_ms.max(s.av_queue_age_ms);
        g.1.transit_pps_ratio = g.1.transit_pps_ratio.max(s.transit_pps_ratio);
        if now.saturating_sub(g.2) >= 1_000 {
            let sig = std::mem::take(&mut g.1);
            g.2 = now;
            g.0.observe(now, sig);
        }
        g.0.tier()
    }

    /// The effective tier.
    #[must_use]
    pub fn tier(&self) -> ServiceTier {
        self.lock().0.tier()
    }

    /// The host's last pressure.
    #[must_use]
    pub fn host_pressure(&self) -> LoadPressure {
        self.lock().0.host_pressure()
    }

    /// Recent tier changes.
    #[must_use]
    pub fn changes(&self) -> Vec<TierChange> {
        self.lock().0.changes().to_vec()
    }

    /// Token counters (`load_tier:*` and causes).
    #[must_use]
    pub fn counters(&self) -> BTreeMap<&'static str, u64> {
        self.lock().0.counters().clone()
    }
}

/// **The ladder's ready set** (L-R1 / L-R3, the ladder's half): each peer's
/// obligation class, computed once per consent or membership CHANGE and
/// looked up in O(1) by the shed decision, never recomputed per flow.
#[derive(Debug, Clone, Default)]
pub struct ObligationSet {
    classes: std::collections::HashMap<String, FlowClass>,
    recomputes: u64,
}

impl ObligationSet {
    /// Replace the set (one consent or membership change).
    pub fn recompute(&mut self, peers: impl IntoIterator<Item = (String, FlowClass)>) {
        self.classes = peers.into_iter().collect();
        self.recomputes += 1;
    }

    /// Update one peer (an event naming it), counting one recompute.
    pub fn update(&mut self, peer: &str, class: Option<FlowClass>) {
        match class {
            Some(c) => {
                self.classes.insert(peer.to_owned(), c);
            }
            None => {
                self.classes.remove(peer);
            }
        }
        self.recomputes += 1;
    }

    /// A peer's class (O(1)); unknown peers are ordinary.
    #[must_use]
    pub fn class_of(&self, peer: &str) -> FlowClass {
        self.classes
            .get(peer)
            .copied()
            .unwrap_or(FlowClass::OrdinaryRound)
    }

    /// Recomputes so far.
    #[must_use]
    pub fn recomputes(&self) -> u64 {
        self.recomputes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_pressure_raises_at_once_and_lowers_one_step_per_cooldown() {
        let mut l = LoadLadder::default();
        assert_eq!(
            l.set_host_pressure(0, LoadPressure::Critical),
            ServiceTier::ChatAndContacts
        );
        assert_eq!(
            l.set_host_pressure(1_000, LoadPressure::Normal),
            ServiceTier::ChatAndContacts
        );
        assert_eq!(
            l.observe(60_000, EdgeLoadSignals::default()),
            ServiceTier::ChatAndContacts
        );
        assert_eq!(
            l.observe(61_000, EdgeLoadSignals::default()),
            ServiceTier::AudioAndFiles
        );
        assert_eq!(
            l.observe(180_000, EdgeLoadSignals::default()),
            ServiceTier::AudioAndFiles
        );
        assert_eq!(
            l.observe(181_000, EdgeLoadSignals::default()),
            ServiceTier::FullOps
        );
        let toks: Vec<_> = l
            .changes()
            .iter()
            .map(|c| (c.to.as_u8(), c.cause))
            .collect();
        assert_eq!(
            toks,
            vec![(2, "host:critical"), (1, "cooldown"), (0, "cooldown")]
        );
    }

    #[test]
    fn edge_never_lowers_below_the_host() {
        let mut l = LoadLadder::default();
        l.set_host_pressure(0, LoadPressure::Warning);
        for t in 0..400 {
            l.observe(t * 1_000, EdgeLoadSignals::default());
        }
        assert_eq!(l.tier(), ServiceTier::AudioAndFiles);
    }

    #[test]
    fn never_shed_classes_are_full_at_every_tier() {
        for t in [
            ServiceTier::FullOps,
            ServiceTier::AudioAndFiles,
            ServiceTier::ChatAndContacts,
        ] {
            for c in [
                FlowClass::Control,
                FlowClass::Revocation,
                FlowClass::OwnDevice,
                FlowClass::FederationDuty,
                FlowClass::ChatAndContacts,
            ] {
                assert_eq!(t.lever(c), Lever::Full, "{t:?} {c:?}");
            }
        }
        assert_eq!(
            ServiceTier::AudioAndFiles.lever(FlowClass::RelayedVideo),
            Lever::BaseLayer
        );
        assert_eq!(
            ServiceTier::AudioAndFiles.lever(FlowClass::RelayedAudio),
            Lever::Full
        );
        assert_eq!(
            ServiceTier::ChatAndContacts.lever(FlowClass::RelayedAudio),
            Lever::Shed
        );
        assert_eq!(
            ServiceTier::ChatAndContacts.lever(FlowClass::Bulk),
            Lever::Pause
        );
    }

    // ─── FSD CIRIS_MESH §7.6 — LS1–LS6 on the production ladder ────────

    /// LS1/LS2 flows: a relay carrying 4 video legs, 4 audio legs, 2 bulk
    /// transfers, chat, own-device rounds and a revocation burst.
    fn ls_flows() -> Vec<(&'static str, FlowClass)> {
        let mut v = Vec::new();
        for _ in 0..4 {
            v.push(("video", FlowClass::RelayedVideo));
        }
        for _ in 0..4 {
            v.push(("audio", FlowClass::RelayedAudio));
        }
        v.push(("bulk", FlowClass::Bulk));
        v.push(("bulk", FlowClass::Bulk));
        v.push(("chat", FlowClass::ChatAndContacts));
        v.push(("own", FlowClass::OwnDevice));
        v.push(("revocation", FlowClass::Revocation));
        v.push(("control", FlowClass::Control));
        v
    }

    /// The `load_shed:*` records a tier change produces, in order.
    fn shed_records(tier: ServiceTier, flows: &[(&'static str, FlowClass)]) -> Vec<&'static str> {
        flows
            .iter()
            .filter_map(|(name, c)| match tier.lever(*c) {
                Lever::Full | Lever::Stretch(_) => None,
                _ => Some(*name),
            })
            .collect()
    }

    /// **LS1 Ordering**: pressure ramps Normal → Warning → Critical. Video is
    /// shed before audio, audio before any chat effect (there is none).
    #[test]
    fn ls1_video_before_audio_before_chat() {
        let flows = ls_flows();
        let mut l = LoadLadder::default();
        let mut records: Vec<&'static str> = Vec::new();
        let mut last = l.tier();
        for (t, p) in [
            (0, LoadPressure::Normal),
            (30_000, LoadPressure::Warning),
            (90_000, LoadPressure::Critical),
        ] {
            let now = l.set_host_pressure(t, p);
            if now != last {
                for r in shed_records(now, &flows) {
                    if !records.contains(&r) || r == "audio" {
                        records.push(r);
                    }
                }
                last = now;
            }
        }
        let first_audio = records
            .iter()
            .position(|r| *r == "audio")
            .expect("audio shed at Critical");
        let last_video = records
            .iter()
            .rposition(|r| *r == "video")
            .expect("video shed");
        assert!(last_video < first_audio, "{records:?}");
        for never in ["chat", "own", "revocation", "control"] {
            assert!(!records.contains(&never), "{never} shed: {records:?}");
        }
    }

    /// **LS2 Never-shed**: 600 s at Critical; every never-shed class is at
    /// full rate every second, and no shed names one.
    #[test]
    fn ls2_never_shed_holds_for_ten_minutes_at_critical() {
        let mut l = LoadLadder::default();
        l.set_host_pressure(0, LoadPressure::Critical);
        for t in 0..600u64 {
            let tier = l.observe(t * 1_000, EdgeLoadSignals::default());
            for c in [
                FlowClass::Control,
                FlowClass::Revocation,
                FlowClass::OwnDevice,
                FlowClass::FederationDuty,
                FlowClass::ChatAndContacts,
            ] {
                assert_eq!(tier.lever(c), Lever::Full, "t={t} {c:?}");
            }
        }
        assert_eq!(l.tier(), ServiceTier::ChatAndContacts);
    }

    /// LS3's input: pressure around the Warning threshold at 0.2 Hz with
    /// ±10 % noise for 900 s (a noisy sample that lands below the threshold
    /// reads Normal), sampled every second.
    fn ls3_run(cfg: LadderConfig) -> Vec<TierChange> {
        let mut l = LoadLadder::new(cfg);
        let mut rng = crate::transport::realtime_av_alm::controller::SplitMix64(42);
        for t in 0..900u64 {
            use crate::transport::realtime_av_alm::controller::JitterSource;
            #[allow(clippy::cast_precision_loss)]
            let phase = (t as f64 * 0.2 * std::f64::consts::TAU).sin();
            let level = 1.0 + 0.05 * phase + 0.1 * (rng.unit() - 0.5);
            let p = if level >= 1.0 {
                LoadPressure::Warning
            } else {
                LoadPressure::Normal
            };
            l.set_host_pressure(t * 1_000, p);
            l.observe(t * 1_000, EdgeLoadSignals::default());
        }
        l.changes().to_vec()
    }

    /// LS3's pass criteria: ≤ 1 tier change per 120 s cooldown period, and
    /// no 1 → 0 → 1 cycle shorter than 120 s.
    fn ls3_verdict(changes: &[TierChange]) -> Result<(), String> {
        let periods = 900 / 120 + 1;
        if changes.len() > periods {
            return Err(format!("{} tier changes in 900 s", changes.len()));
        }
        for w in changes.windows(2) {
            if w[0].to == ServiceTier::FullOps
                && w[1].to == ServiceTier::AudioAndFiles
                && w[1].at_ms - w[0].at_ms < 120_000
            {
                return Err(format!("1→0→1 in {} ms", w[1].at_ms - w[0].at_ms));
            }
        }
        Ok(())
    }

    /// **LS3 No flapping.**
    #[test]
    fn ls3_no_flapping() {
        let changes = ls3_run(LadderConfig::default());
        assert!(ls3_verdict(&changes).is_ok(), "{changes:?}");
        assert_eq!(changes.len(), 1, "raised once, never lowered: {changes:?}");
    }

    /// **LS5-mut**: LS3 with every hysteresis and cooldown at zero MUST fail
    /// LS3. If it passes, LS3 does not test flapping.
    #[test]
    fn ls5_mut_no_hysteresis_must_fail_ls3() {
        let changes = ls3_run(LadderConfig::default().no_hysteresis());
        assert!(
            ls3_verdict(&changes).is_err(),
            "the mutant passed LS3 ({} changes)",
            changes.len()
        );
    }

    /// **LS5 Edge self-raise**: no host pressure; forwarded pps climbs to 95 %
    /// of measured. Tier 1 at 65 %, tier 2 at 90 %, cause `edge:transit_pps`;
    /// back to 0 only after both cooldowns.
    #[test]
    fn ls5_edge_self_raise_on_transit_pps() {
        let mut l = LoadLadder::default();
        let mut raised1 = None;
        let mut raised2 = None;
        for t in 0..=95u64 {
            #[allow(clippy::cast_precision_loss)]
            let ratio = t as f64 / 100.0;
            let tier = l.observe(
                t * 1_000,
                EdgeLoadSignals {
                    transit_pps_ratio: ratio,
                    ..EdgeLoadSignals::default()
                },
            );
            if tier >= ServiceTier::AudioAndFiles && raised1.is_none() {
                raised1 = Some(t);
            }
            if tier == ServiceTier::ChatAndContacts && raised2.is_none() {
                raised2 = Some(t);
            }
        }
        assert_eq!((raised1, raised2), (Some(65), Some(90)));
        assert!(l.changes().iter().all(|c| c.cause == "edge:transit_pps"));
        // Calm from t = 96 s: tier 2 → 1 after 60 s, 1 → 0 after 120 s more.
        let mut dropped = Vec::new();
        let mut last = l.tier();
        for t in 96..=400u64 {
            let tier = l.observe(t * 1_000, EdgeLoadSignals::default());
            if tier != last {
                dropped.push((t, tier));
                last = tier;
            }
        }
        assert_eq!(
            dropped,
            vec![
                (156, ServiceTier::AudioAndFiles),
                (276, ServiceTier::FullOps)
            ]
        );
    }

    /// **LS6 (the ladder's half)**: the shed decision reads a peer's class
    /// from the ready set in O(1) (L-R3), whatever the subject count, and one
    /// consent grant is exactly one recompute (L-R1). The replication half
    /// (round reads flat as subjects grow) is the #930 ready set, not here.
    #[test]
    fn ls6_ladder_reads_the_ready_set_and_one_grant_is_one_recompute() {
        for subjects in [5_000usize, 50_000] {
            let mut set = ObligationSet::default();
            set.recompute((0..subjects).map(|i| {
                (
                    format!("peer-{i}"),
                    if i % 10 == 0 {
                        FlowClass::OwnDevice
                    } else {
                        FlowClass::OrdinaryRound
                    },
                )
            }));
            assert_eq!(set.recomputes(), 1);
            let tier = ServiceTier::ChatAndContacts;
            let mut full = 0;
            for i in 0..1_000 {
                if tier.lever(set.class_of(&format!("peer-{i}"))) == Lever::Full {
                    full += 1;
                }
            }
            assert_eq!(full, 100, "own devices full, ordinary stretched");
            assert_eq!(set.recomputes(), 1, "lookups recompute nothing");
            set.update("peer-1", Some(FlowClass::ChatAndContacts));
            assert_eq!(set.recomputes(), 2, "one grant, one recompute");
        }
    }
}
