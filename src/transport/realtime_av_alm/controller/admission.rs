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

use sha2::{Digest, Sha256};

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
    /// G8 — no upward probe (no demand step, no doubling, no stale reset)
    /// before this instant: set by an uplink-stall verdict.
    probe_hold_until_ms: u64,
    /// G8 slow start ([`Self::set_slow_start`]).
    slow_start: bool,
    /// N4 — the probe backoff ([`Self::set_probe_backoff`]).
    probe_backoff: bool,
    /// N4 — failed probes, at most [`PROBE_FAILS_MAX`]: each doubles the wait
    /// before the next widening.
    probe_fails: u32,
    /// N4 — the last congestion or widening, and whether it was a widening.
    probe_event: Option<(u64, bool)>,
    /// Row FR — the longest a widening took to meet congestion since the
    /// last reset: a later widening is not counted as held before twice
    /// that has passed.
    probe_ttf_ms: u64,
    /// Row NV ([`Self::set_shed_on_verdict_only`]).
    shed_on_verdict_only: bool,
    /// Row RO — when `demand` was last set; it lapses a dwell later at a
    /// live call's publisher.
    demand_at_ms: u64,
    /// RM4 — the stream id a shed ranks by ([`Self::set_shed_rank`]).
    shed_rank: Option<[u8; 32]>,
    /// Row RO — when this forwarder last shed each member: that member's
    /// refusal within a dwell is not demand (it asks back what was just
    /// taken from it).
    shed_at: BTreeMap<P, u64>,
    /// Row ProbeAfterDrain — since when the uplink has measured drained
    /// ([`Self::set_uplink_drained`]), `None` while it is not.
    drained_since_ms: Option<u64>,
    /// Row ProbeAfterDrain — the last step it took.
    last_drain_step_ms: Option<u64>,
    /// Row ProbeAfterDrain — re-open steps taken (demand or drained), for
    /// the witnesses.
    reopen_steps: u64,
}

/// RM4 — a member's rank on a stream: the first eight bytes (big-endian) of
/// sha256(stream id ‖ the member's canonical encoding, [`PeerRef::encode`]).
/// Every member computes the same order from what it already holds, so the
/// child a publisher's stall shed keeps ([`Admission::set_shed_rank`]) is
/// the child the receivers spare, with nothing on the wire. Deliberately
/// unlike the join order.
#[must_use]
pub fn hash_rank<P: PeerRef>(stream: &[u8; 32], member: &P) -> u64 {
    let mut enc = Vec::new();
    member.encode(&mut enc);
    let d = Sha256::new()
        .chain_update(stream)
        .chain_update(&enc)
        .finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    u64::from_be_bytes(b)
}

/// N4 — the most failed probes the backoff counts (the wait tops out at
/// 2 windows × 2^2).
pub const PROBE_FAILS_MAX: u32 = 4;

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
            probe_hold_until_ms: 0,
            slow_start: false,
            probe_backoff: false,
            probe_fails: 0,
            probe_event: None,
            probe_ttf_ms: 0,
            shed_on_verdict_only: false,
            demand_at_ms: 0,
            shed_rank: None,
            shed_at: BTreeMap::new(),
            drained_since_ms: None,
            last_drain_step_ms: None,
            reopen_steps: 0,
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

    /// G8 slow start, for a publisher: while its uplink is unmeasured the
    /// probe allowance binds forwarders too (off: a forward-capable
    /// subscriber that fits the hard limit is admitted past the probe, and an
    /// unmeasured publisher's hard limit is unbounded, so every relaying
    /// member is a direct child at once). Off by default; the live call's
    /// publisher turns it on. The stage-1 sim's large worlds are tuned on the
    /// unbounded start (t2/t3/l3 fail with it on).
    pub fn set_slow_start(&mut self, on: bool) {
        self.slow_start = on && self.is_root;
    }

    /// G8 — an uplink-stall verdict: the probe restarts at one stream and
    /// nothing widens the room (no demand step, no doubling, no stale
    /// ceiling reset) until `until_ms`. The verdict IS the measurement; an
    /// upward probe straight after it re-overloads the queue it just left.
    #[allow(clippy::cast_precision_loss)]
    pub fn hold_probe(&mut self, until_ms: u64) {
        self.probe_hold_until_ms = self.probe_hold_until_ms.max(until_ms);
        self.probe_bps = self.probe_bps.min(self.cfg.stream_bps as f64);
    }

    /// N4 — the probe backoff (`docs/design/call_congestion`, rows N4 and
    /// ProbeBackoff). Off by default (the stage-1 sim's worlds are tuned
    /// without it); the live call's publisher turns it on.
    ///
    /// Transition: observable, an egress window closing clean; state, a
    /// widening is due (the demand step, or the slow-start probe doubling);
    /// action, widen only once 2 windows × 2^fails have passed since the last
    /// congestion or widening, fails ≤ [`PROBE_FAILS_MAX`]: a congestion that
    /// follows a widening before the next one (the probe failed) and a direct
    /// child's departure ([`Self::on_departure`]) step fails up, a widening
    /// that comes after one that held steps it down; must never, widen sooner.
    /// Without it a publisher under a permanent cap re-parents its children
    /// for ever (probe, late, leave, repeat).
    pub fn set_probe_backoff(&mut self, on: bool) {
        self.probe_backoff = on;
    }

    /// Row NV — a live call's forwarder sheds an existing child only on a
    /// congestion verdict (the meter's, or the stall's), never in a clean
    /// window. The clean-window shed fired when the ledger got ahead of the
    /// limit by accounting alone: another stream this node relays admitted
    /// someone, the limit left for this stream fell below what it had
    /// already committed, and a child admitted a second earlier was shed
    /// with the uplink carrying everything (the come-back witness: admit at
    /// 55.78 s, shed "over-committed" at 56.50 s, no cap; four primary
    /// changes for one listener). If the uplink really cannot carry what is
    /// committed, the verdict says so and that window sheds.
    pub fn set_shed_on_verdict_only(&mut self, on: bool) {
        self.shed_on_verdict_only = on;
    }

    /// RM4 — shed by rank on `stream` instead of LIFO by admission.
    ///
    /// Transition: observable, a window whose limit is below the
    /// commitments (an uplink-stall verdict, a measured ceiling); state, the
    /// ledger; action, shed standbys first, then primaries, each highest
    /// [`hash_rank`] first, so the LOWEST-ranked direct child is the one
    /// kept; must never, keep a different child than the receivers spare
    /// (they rank the same way), or take the last primary for a standby.
    /// `None`: LIFO (the default, and every relay's).
    pub fn set_shed_rank(&mut self, stream: Option<[u8; 32]>) {
        self.shed_rank = stream;
    }

    /// RM5 — a direct child left while this node's stream is live: read it
    /// as congestion (the model's late departure, `DepartureHolds`).
    ///
    /// Transition: observable, a primary child's UNSUBSCRIBE (the caller
    /// checks it was a primary in the ledger, not one being shed, and that
    /// the stream is live, and has released it); state, the children left;
    /// action, room = those children (the ceiling is set so the hard limit
    /// is what they commit), congested now, and the probe backoff steps up
    /// one; must never, widen sooner than 2 windows × 2^fails after it.
    #[allow(clippy::cast_precision_loss)]
    pub fn on_departure(&mut self, now_ms: u64, log: &mut DecisionLog) {
        let per = self.class.fraction.unwrap_or(1.0);
        let room = self.committed_bps() as f64
            + self.cfg.reserve_bps as f64
            + self.external_committed as f64;
        let c = room / per;
        self.ceiling_bps = Some(c);
        self.clean_streak = 0;
        self.last_congested_ms = now_ms;
        self.note_congestion(now_ms, true);
        #[allow(clippy::cast_possible_truncation)]
        log.record(
            now_ms,
            &self.me,
            DecisionKind::Ceiling,
            None,
            c as i64,
            "departure",
        );
    }

    /// Row ProbeAfterDrain — re-open steps taken so far.
    #[must_use]
    pub fn reopen_steps(&self) -> u64 {
        self.reopen_steps
    }

    /// N4 — failed probes counted now.
    #[must_use]
    pub fn probe_fails(&self) -> u32 {
        self.probe_fails
    }

    /// Row ProbeAfterDrain — the uplink measures drained now (every out
    /// leg's queue gauge known and under `congestion_queue_ms`, nothing
    /// outstanding), or not. The caller reports it each window.
    pub fn set_uplink_drained(&mut self, now_ms: u64, drained: bool) {
        if drained {
            self.drained_since_ms.get_or_insert(now_ms);
        } else {
            self.drained_since_ms = None;
        }
    }

    /// Row ProbeAfterDrain — drained for the hold: two clean meter windows
    /// (`probe_clean_windows × meter_window_ms`, 2 s), the same settling a
    /// slow-start doubling waits for.
    fn drained_for_hold(&self, now_ms: u64) -> bool {
        let hold = u64::from(self.cfg.probe_clean_windows) * self.cfg.meter_window_ms;
        self.drained_since_ms
            .is_some_and(|t| now_ms.saturating_sub(t) >= hold)
    }

    /// Row RO — whether a Capacity refusal of `who` is demand that widens
    /// the room: not while a stall verdict is latched, not from a member
    /// this forwarder shed within the dwell (it asks back what was just
    /// taken), and, after congestion taught a ceiling, only once the uplink
    /// has drained for the hold. A refusal under the cap, or to a node just
    /// shed, was spent as a step long after (the mesh4 n4 witness: a step 33
    /// s later, after the lift, and a shed-refuse-step cycle with no cap).
    /// A never-congested publisher is unchanged: every refusal is demand.
    fn refusal_is_demand(&self, now_ms: u64, who: &P) -> bool {
        let latched = self.probe_held(now_ms);
        let just_shed = self
            .shed_at
            .get(who)
            .is_some_and(|t| now_ms.saturating_sub(*t) < self.cfg.min_dwell_ms);
        let reopened = self.ceiling_bps.is_none() || self.drained_for_hold(now_ms);
        !latched && !just_shed && reopened
    }

    /// N4 — whether the backoff lets the room widen at `now_ms`.
    fn widen_allowed(&self, now_ms: u64) -> bool {
        !self.probe_backoff
            || self
                .probe_event
                .is_none_or(|(t, _)| now_ms >= t + self.backoff_wait_ms())
    }

    /// N4 — the wait the backoff imposes at the current fail count.
    fn backoff_wait_ms(&self) -> u64 {
        (2 * self.cfg.meter_window_ms) << self.probe_fails
    }

    /// N4, row FR — the room widened at `now_ms`. The previous widening
    /// counts as held, and the fails forgotten, only if it has stood with no
    /// congestion for its own backoff wait AND twice the longest any widening
    /// took to fail since the last reset. "Until the next widening" forgave a
    /// step that fails slowly (half a stream over a cap builds its queue over
    /// tens of seconds) a dwell after it was taken, so a held cap was probed
    /// at the dwell's rhythm for the life of the call.
    fn note_widen(&mut self, now_ms: u64) {
        if let Some((t, true)) = self.probe_event {
            let need = self.backoff_wait_ms().max(2 * self.probe_ttf_ms);
            if now_ms.saturating_sub(t) >= need {
                // A widening that stood that long shows the uplink carries
                // it: what the probe learned below it is forgotten, and the
                // room re-opens at the dwell's pace.
                self.reset_probe_memory();
            }
        }
        self.probe_event = Some((now_ms, true));
    }

    /// N4, row FR — congestion at `now_ms`; `failed`: count it as a failed
    /// probe whatever came before (a departure, RM5). A widening that meets
    /// congestion failed however long it took, and how long it took is kept.
    fn note_congestion(&mut self, now_ms: u64, failed: bool) {
        let widened = match self.probe_event {
            Some((t, true)) => Some(t),
            _ => None,
        };
        if let Some(t) = widened {
            self.probe_ttf_ms = self.probe_ttf_ms.max(now_ms.saturating_sub(t));
        }
        if failed || widened.is_some() {
            self.probe_fails = (self.probe_fails + 1).min(PROBE_FAILS_MAX);
        }
        self.probe_event = Some((now_ms, false));
    }

    /// Row FR — evidence that the uplink's capacity changed (a widening that
    /// stood, or the ceiling going stale): what the probe learned under the
    /// old capacity is forgotten.
    fn reset_probe_memory(&mut self) {
        self.probe_fails = 0;
        self.probe_ttf_ms = 0;
    }

    /// Whether an upward probe is held now ([`Self::hold_probe`]).
    #[must_use]
    pub fn probe_held(&self, now_ms: u64) -> bool {
        now_ms < self.probe_hold_until_ms
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
            self.shed_at.insert(p.clone(), now_ms);
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
        // Row S3 (the plain no-parent path): a publisher with NO primary
        // child admits a primary whatever its probe, ceiling or last offer
        // said. Its uplink is the one path nothing replaces, and the root's
        // floor is one stream; refusing it here left a capped publisher with
        // no children for the rest of a cap (the kept child's link had died).
        // Only for a publisher whose uplink carries nothing else of its own
        // (no share or relay commitments): those keep their room.
        if self.is_root
            && req.role == Role::Primary
            && self.external_committed == 0
            && !self.ledger.values().any(|c| c.role == Role::Primary)
        {
            self.commit(now_ms, req, log);
            return AdmitDecision::Admit { role: req.role };
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
        //
        // Not at a slow-starting publisher (G8): its uplink is the one path
        // nothing replaces, and while it is unmeasured every member that
        // relays would be admitted at once, the full fan-out the probe
        // exists to avoid. A refused forwarder hears the stream through a
        // child (that child relays) and its refusal is the demand that
        // widens the probe.
        if forwarder && !self.slow_start && (committed + need) as f64 <= hard + 1.0 {
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
                    self.shed_at.insert(v.clone(), now_ms);
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
        if self.refusal_is_demand(now_ms, &req.subscriber) {
            self.demand = true;
            self.demand_at_ms = now_ms;
        }
        self.refuse(now_ms, req, RefuseReason::Capacity, rng, log)
    }

    /// Subscribers displaced by forwarder preemption since the last call;
    /// the caller sends each a [`super::ShedReason::Preempted`].
    pub fn take_preempted(&mut self) -> Vec<P> {
        std::mem::take(&mut self.preempted)
    }

    /// Row E2 — a publisher left with no PRIMARY but holding a standby:
    /// promote the oldest standby to primary (priced as one) and return it;
    /// the caller tells it with an ADMIT as primary. `None` when a primary
    /// stands, there is no standby, or this is not a publisher.
    pub fn promote_standby_if_no_primary(&mut self) -> Option<P> {
        if !self.is_root || self.ledger.values().any(|c| c.role == Role::Primary) {
            return None;
        }
        let p = self
            .ledger
            .iter()
            .filter(|(_, c)| c.role == Role::Standby)
            .min_by_key(|(_, c)| c.order)
            .map(|(p, _)| p.clone())?;
        let bps = self.cfg.role_bps(Role::Primary);
        let c = self.ledger.get_mut(&p).expect("present");
        c.role = Role::Primary;
        c.bps = bps;
        Some(p)
    }

    /// A subscriber left (or its link is gone).
    pub fn release(&mut self, sub: &P) -> bool {
        let drained = self.draining.remove(sub).is_some();
        self.ledger.remove(sub).is_some() || drained
    }

    /// Fold one closed egress window. Returns the subscribers shed (most
    /// recent first) when the measured limit fell below commitments.
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    #[allow(clippy::too_many_lines)]
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
            self.note_congestion(now_ms, false);
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
            let held = self.probe_held(now_ms);
            // N4: a widening (the demand step, the probe doubling) also waits
            // out the probe backoff; a ceiling going stale is not one.
            let backoff = !self.widen_allowed(now_ms);
            if let Some(c) = self.ceiling_bps {
                // A clean window that carried more than the ceiling shows the
                // uplink carries at least that: committable at the meter's
                // margin, like a verdict (one margin per measurement, §5.1),
                // never the raw rate.
                let carried = w.sent_bps * MEASURED_MARGIN;
                if carried > c {
                    // A live call's publisher raises a congestion-taught
                    // ceiling one stream per dwell (below), never to what one
                    // window carried: a drain burst is not a sustained rate,
                    // one jump re-opens the whole room in one tick, and under
                    // a held cap a step's first windows carry it cleanly for
                    // seconds before its queue shows.
                    if !(self.is_root && self.probe_backoff) {
                        self.ceiling_bps = Some(carried);
                    }
                }
                // Additive increase (Eric, 2026-11-10): a clean window in
                // which someone is waiting (a capacity refusal since the
                // last step) raises a measured ceiling by one stream of
                // committable room. The ask is the probe; the next verdict,
                // if the uplink really is full, takes it back. Without it a
                // shed member waited out the staleness (60-120 s) with the
                // uplink clean the whole time (avmesh4, after the cap lifted).
                // Row ProbeAfterDrain + RO: a live call's publisher (root, N4
                // on) re-opens a congestion-taught ceiling one stream at a
                // time, for a waiting member (demand, RO-guarded at the
                // refusal) or because its uplink has drained for the hold,
                // at most once per dwell and under the N4 backoff, and only
                // while the room is short of one more stream. Each step is
                // one stream above what is committed now (not above the
                // last step's unused room), so steps never compound past
                // what the uplink was shown to carry. Its offers then show
                // room in seconds after a cap lifts, not after the 60 s
                // staleness, and its children move back one per dwell.
                let reopening = self.is_root && self.probe_backoff;
                // Row RO: demand nobody has waited on for a dwell lapses.
                if reopening
                    && self.demand
                    && now_ms.saturating_sub(self.demand_at_ms) >= self.cfg.min_dwell_ms
                {
                    self.demand = false;
                }
                let dwell_ok = self
                    .last_drain_step_ms
                    .is_none_or(|t| now_ms.saturating_sub(t) >= self.cfg.min_dwell_ms);
                let short =
                    self.committed_bps() + self.cfg.stream_bps > self.hard_limit_bps() as u64;
                if reopening {
                    if (self.demand || self.drained_for_hold(now_ms))
                        && !self.over_claim_flagged
                        && !held
                        && !backoff
                        && dwell_ok
                        && short
                    {
                        let why = if self.demand { "demand" } else { "drained" };
                        self.demand = false;
                        self.last_drain_step_ms = Some(now_ms);
                        self.reopen_steps += 1;
                        self.note_widen(now_ms);
                        let per = self.class.fraction.unwrap_or(1.0);
                        let used = self.committed_bps() as f64
                            + self.cfg.reserve_bps as f64
                            + self.external_committed as f64;
                        let c = (used + self.cfg.stream_bps as f64) / per;
                        self.ceiling_bps = Some(c);
                        log.record(now_ms, &self.me, DecisionKind::Ceiling, None, c as i64, why);
                    }
                } else if self.demand && !self.over_claim_flagged && !held && !backoff {
                    self.demand = false;
                    self.note_widen(now_ms);
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
                    && !held
                    && now_ms.saturating_sub(self.last_congested_ms) >= self.ceiling_stale_ms
                {
                    self.ceiling_bps = None;
                    self.reset_probe_memory();
                    self.ceiling_stale_ms = (self.ceiling_stale_ms * 2).min(CEILING_STALE_MAX_MS);
                    log.record(now_ms, &self.me, DecisionKind::Ceiling, None, 0, "stale");
                }
            } else {
                self.floor_bps = self.floor_bps.max(w.sent_bps);
                // Grow on use OR on demand (a capacity refusal since the
                // last growth): the probe is the measurement, so it must be
                // spent when someone is waiting for it.
                let used = self.committed_bps() as f64 >= 0.8 * (self.floor_bps + self.probe_bps);
                if (used || self.demand)
                    && !held
                    && !backoff
                    && self.clean_streak >= self.cfg.probe_clean_windows
                {
                    self.demand = false;
                    self.clean_streak = 0;
                    self.note_widen(now_ms);
                    self.probe_bps = (self.probe_bps * 2.0)
                        .min((MAX_PROBE_STREAMS * self.cfg.stream_bps) as f64);
                }
            }
        }
        if !self.cfg.admission_enabled {
            return Vec::new();
        }
        if self.shed_on_verdict_only && !(w.congested && w.capacity_bps.is_some()) {
            return Vec::new();
        }
        let mut shed = Vec::new();
        let limit = self.hard_limit_bps();
        while self.committed_bps() as f64 > limit + 1.0 {
            // Stall row S3: standbys go first (most recent first); a
            // publisher never sheds its LAST primary (it is the one path
            // nothing replaces), so it is never left with only standbys.
            // Among primaries, RM4's hash rank (the highest-ranked goes)
            // when set, else LIFO.
            let primaries = self
                .ledger
                .values()
                .filter(|c| c.role == Role::Primary)
                .count();
            let standby = self
                .ledger
                .iter()
                .filter(|(_, c)| c.role == Role::Standby)
                .max_by_key(|(_, c)| c.order)
                .map(|(p, _)| p.clone());
            let victim = standby.or_else(|| {
                if self.is_root && primaries <= 1 {
                    return None;
                }
                match &self.shed_rank {
                    None => self
                        .ledger
                        .iter()
                        .max_by_key(|(_, c)| c.order)
                        .map(|(p, _)| p.clone()),
                    Some(key) => self
                        .ledger
                        .iter()
                        .max_by_key(|(p, _)| hash_rank(key, *p))
                        .map(|(p, _)| p.clone()),
                }
            });
            let Some(victim) = victim else {
                break;
            };
            self.ledger.remove(&victim);
            self.shed_at.insert(victim.clone(), now_ms);
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
        // N4: a shed is the room not holding, like a congested verdict: if
        // the last event was a re-open step, that probe failed and the next
        // waits twice as long. Without it a held cap was probed on a fixed
        // dwell rhythm for the life of the call (the over-commit sheds that
        // followed each step were not congestion), each probe moving
        // listeners twice.
        if !shed.is_empty() && self.is_root && self.probe_backoff {
            self.note_congestion(now_ms, false);
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
            layers: None,
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

    /// G8 slow start — an unmeasured publisher's probe binds forwarders too:
    /// three relay-capable members asking at once get ONE direct slot, and
    /// the refusals are the demand that widens it.
    #[test]
    fn an_unmeasured_publisher_admits_one_forwarder_first() {
        let cfg = ControllerConfig::interactive();
        let mut a = Admission::publisher(0u32, cfg, None);
        a.set_slow_start(true);
        roster(&mut a);
        let mut rng = SplitMix64(1);
        let mut log = DecisionLog::default();
        let mut admitted = 0;
        for s in 1..=3u32 {
            let mut r = req(s, Role::Primary);
            r.forward_capable = true;
            if matches!(
                a.request(0, &r, &mut rng, &mut log),
                AdmitDecision::Admit { .. }
            ) {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 1, "one direct child into an unmeasured uplink");
    }

    /// Row S3 — a publisher with no primary child admits one whatever its
    /// room reads (here it advertises half a stream), so a capped call never
    /// sits with no direct child; a second primary still meets the limit.
    #[test]
    fn a_publisher_with_no_primary_admits_one() {
        let cfg = ControllerConfig::interactive();
        let mut a = Admission::publisher(0u32, cfg.clone(), Some(cfg.stream_bps / 2));
        roster(&mut a);
        let mut rng = SplitMix64(3);
        let mut log = DecisionLog::default();
        assert!(matches!(
            a.request(0, &req(1, Role::Primary), &mut rng, &mut log),
            AdmitDecision::Admit { .. }
        ));
        assert!(!matches!(
            a.request(0, &req(2, Role::Primary), &mut rng, &mut log),
            AdmitDecision::Admit { .. }
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

    /// Row ProbeAfterDrain — a congestion-taught ceiling re-opens by probing
    /// once the uplink has drained for the hold, long before
    /// `CEILING_STALE_MS`, and not while a queue remains; a step that meets
    /// congestion is a failed probe and the next waits longer (N4).
    /// Mutation (2ba6adb): the ceiling capped the publisher until it went
    /// stale 60 s after its last congested sample, so every recovery after
    /// a lifted cap cost a minute (the come-back witness).
    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn a_drained_uplink_reopens_a_congested_ceiling_by_probing() {
        let (mut a, mut log, cfg) = publisher_of_two();
        a.set_probe_backoff(true);
        let bps = cfg.stream_bps as f64;
        // A verdict at one stream: the second child goes.
        assert_eq!(
            a.on_egress_window(1_000, &window(bps, true), &mut log),
            vec![2]
        );
        let c0 = a.ceiling_bps().expect("a ceiling");
        // Not while a queue remains: clean windows, uplink not drained.
        let mut t = 2_000;
        while t <= 12_000 {
            a.set_uplink_drained(t, false);
            let _ = a.on_egress_window(t, &window(bps, false), &mut log);
            t += 1_000;
        }
        assert_eq!(
            a.ceiling_bps(),
            Some(c0),
            "no probe while the uplink still queues"
        );
        // Drained for the hold: one more stream, long before staleness.
        let mut stepped_at = None;
        while t <= 20_000 {
            a.set_uplink_drained(t, true);
            let _ = a.on_egress_window(t, &window(bps, false), &mut log);
            if a.ceiling_bps().is_some_and(|c| c > c0) {
                stepped_at = Some(t);
                break;
            }
            t += 1_000;
        }
        let at = stepped_at.expect("the drained uplink probes up");
        assert!(at < 1_000 + CEILING_STALE_MS, "re-opened at {at}");
        assert!(
            at >= 12_000 + u64::from(cfg.probe_clean_windows) * cfg.meter_window_ms,
            "only after the hold ({at})"
        );
        // The step meets congestion: a failed probe, so the next step waits
        // at least twice the base backoff past the dwell.
        let fails = a.probe_fails();
        let _ = a.on_egress_window(at + 1_000, &window(bps, true), &mut log);
        assert!(
            a.probe_fails() > fails,
            "a probe that met congestion failed"
        );
        let c1 = a.ceiling_bps().expect("re-measured");
        let mut next = None;
        let mut u = at + 2_000;
        while u <= at + 200_000 {
            a.set_uplink_drained(u, true);
            let _ = a.on_egress_window(u, &window(bps, false), &mut log);
            if a.ceiling_bps().is_some_and(|c| c > c1) {
                next = Some(u);
                break;
            }
            u += 1_000;
        }
        let next = next.expect("it probes again");
        // No sooner than a dwell after the last step, nor than the doubled
        // backoff after the congestion that failed it.
        let base = 2 * cfg.meter_window_ms;
        let backoff_end = at + 1_000 + (base << a.probe_fails());
        let dwell_end = at + cfg.min_dwell_ms;
        assert!(
            next >= backoff_end.max(dwell_end),
            "probed again at {next}: the backoff ends {backoff_end}, the dwell {dwell_end}"
        );
    }

    /// Row RO — a refusal of a member this publisher just shed, or one made
    /// under a latched verdict, is not demand: it is not spent later as a
    /// step. A member never shed, once the uplink has drained, is. Mutation
    /// (2ba6adb): every Capacity refusal set `demand`; one refused under the
    /// cap was spent 33 s later, after the lift (mesh4 n4).
    #[test]
    fn a_refusal_of_a_just_shed_member_is_not_demand() {
        let cfg = ControllerConfig::interactive();
        let bps = f64::from(u32::try_from(cfg.stream_bps).unwrap_or(u32::MAX));
        // A member this publisher just shed: its refusal is no demand.
        let (mut a, mut log, _) = publisher_of_two();
        let mut rng = SplitMix64(3);
        assert_eq!(
            a.on_egress_window(1_000, &window(bps, true), &mut log),
            vec![2]
        );
        a.set_uplink_drained(1_000, true);
        assert!(matches!(
            a.request(1_500, &req(2, Role::Primary), &mut rng, &mut log),
            AdmitDecision::Refuse { .. }
        ));
        let _ = a.on_egress_window(3_000, &window(bps, false), &mut log);
        assert!(
            !log.tail().contains("(demand)"),
            "a just-shed member's refusal took no demand step: {}",
            log.tail()
        );
        // Under a latched verdict: no refusal is demand; past it, with the
        // uplink drained for the hold, a member never shed is.
        let (mut a, mut log, _) = publisher_of_two();
        assert_eq!(
            a.on_egress_window(1_000, &window(bps, true), &mut log),
            vec![2]
        );
        a.hold_probe(20_000);
        a.set_uplink_drained(1_000, true);
        assert!(matches!(
            a.request(4_000, &req(4, Role::Primary), &mut rng, &mut log),
            AdmitDecision::Refuse { .. }
        ));
        let _ = a.on_egress_window(5_000, &window(bps, false), &mut log);
        assert!(
            !log.tail().contains("(demand)"),
            "none under a latched verdict"
        );
        assert!(matches!(
            a.request(21_000, &req(4, Role::Primary), &mut rng, &mut log),
            AdmitDecision::Refuse { .. }
        ));
        let _ = a.on_egress_window(22_000, &window(bps, false), &mut log);
        assert!(
            log.tail().contains("(demand)"),
            "a member never shed asked: {}",
            log.tail()
        );
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
        // Row RO: a congestion-taught ceiling re-opens only on a drained
        // uplink, and the member it shed is not the one whose ask counts:
        // a member that was never shed (4) waits here, the uplink drained.
        a.set_uplink_drained(1_000, true);
        assert!(
            matches!(
                a.request(3_000, &req(4, Role::Primary), &mut rng, &mut log),
                AdmitDecision::Refuse {
                    reason: RefuseReason::Capacity,
                    ..
                }
            ),
            "the premise: no room under the verdict"
        );
        let _ = a.on_egress_window(4_000, &window(bps, false), &mut log);
        assert!(
            matches!(
                a.request(4_100, &req(4, Role::Primary), &mut rng, &mut log),
                AdmitDecision::Admit { .. }
            ),
            "one clean window with a member waiting is one more stream"
        );
        assert!(
            matches!(
                a.request(4_200, &req(3, Role::Primary), &mut rng, &mut log),
                AdmitDecision::Refuse { .. }
            ),
            "one, not more: the next waits for the next clean window"
        );
        let _ = a.on_egress_window(5_000, &window(2.0 * bps, false), &mut log);
        assert!(matches!(
            a.request(5_500, &req(3, Role::Primary), &mut rng, &mut log),
            AdmitDecision::Admit { .. }
        ));
        // Nobody waiting: a clean window adds nothing.
        let c = a.ceiling_bps();
        let _ = a.on_egress_window(6_000, &window(bps, false), &mut log);
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

    /// RM4 — a ranked shed takes standbys first, then the highest-ranked
    /// primaries, and keeps the lowest-ranked primary, whatever the
    /// admission order.
    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn a_ranked_shed_keeps_the_lowest_ranked_primary() {
        let cfg = ControllerConfig::interactive();
        let key = [7u8; 32];
        let mut a = Admission::publisher(0u32, cfg.clone(), None);
        roster(&mut a);
        a.set_probe_streams(8);
        a.set_shed_rank(Some(key));
        let mut rng = SplitMix64(1);
        let mut log = DecisionLog::default();
        for s in 1..=4u32 {
            assert!(matches!(
                a.request(0, &req(s, Role::Primary), &mut rng, &mut log),
                AdmitDecision::Admit { .. }
            ));
        }
        assert!(matches!(
            a.request(0, &req(5, Role::Standby), &mut rng, &mut log),
            AdmitDecision::Admit { .. }
        ));
        let lowest = (1..=4u32).min_by_key(|s| hash_rank(&key, s)).expect("four");
        let w = window(cfg.stream_bps as f64, true);
        let shed = a.on_egress_window(1_000, &w, &mut log);
        assert_eq!(shed.first(), Some(&5), "the standby goes first: {shed:?}");
        assert_eq!(shed.len(), 4);
        assert_eq!(a.ledger().keys().copied().collect::<Vec<_>>(), vec![lowest]);
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
            layers: None,
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
            layers: None,
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
            layers: None,
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
