//! v44 — the operator's telemetry: what a loaded node can say about itself
//! without off-node export (`docs/TELEMETRY_CATALOGUE.md`).
//!
//! # The bundle's rules
//!
//! [`TELEMETRY_CATALOGUE`] holds one row for every
//! [`EdgeMetricsBundle`](crate::observability::EdgeMetricsBundle) field: its
//! `ciris.edge.*` name, kind, unit, bounded labels and exposure. A host renders
//! these names however it likes; edge has no `metrics` facade, no recorder and
//! no exporter, and the catalogue is what a recorder would `describe`.
//!
//! - **A hot path gets an atomic.** [`AtomicHistogram`] and the gauges here are
//!   lock-free and allocate nothing, so the event path can afford them.
//! - **A missing series is not 0.** Every closed label is present at zero from
//!   the first snapshot, so a series that is absent is a build that does not
//!   have it, and 0 is a thing that did not happen.
//! - **A liveness signal shares no lock with I/O.** [`LoopName`] stamps are one
//!   atomic store, on the loop's own cadence and never per event, so an age
//!   says the loop turned and says nothing of the traffic through it.
//! - **Shaping's secret stays secret.** Real frames and row wait are not a live
//!   counter here: they go through [`ShapingWindows`], flushed once per window
//!   W, per class, rounded, and only for a class holding at least
//!   [`SHAPING_CLASS_FLOOR`] links. With fewer an aggregate is a per-peer
//!   series, so the window is dropped and counted as withheld.
//! - **No peer in a label.** No field names a peer, a link or a room, with the
//!   two old exceptions the catalogue marks [`LabelValues::PeerKeyed`], and both
//!   are operator-only.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use crate::observability::{self as obs, HistogramSnapshot};
use crate::replication::EnvelopeKind;

/// A closed label set: an enum whose tokens are the only values a label takes.
macro_rules! closed_set {
    ($(#[$m:meta])* $name:ident { $($(#[$vm:meta])* $variant:ident = $token:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name { $($(#[$vm])* $variant),+ }

        impl $name {
            /// Every value, in order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
            /// Every token, in order.
            pub const TOKENS: &'static [&'static str] = &[$($token),+];
            /// How many values.
            pub const COUNT: usize = Self::TOKENS.len();

            /// The stable label token.
            #[must_use]
            pub const fn token(self) -> &'static str {
                Self::TOKENS[self as usize]
            }
        }
    };
}

closed_set!(
    /// What the Reticulum event loop was doing. Timer arms are here because
    /// they run on the same task: a slow announce tick holds every frame
    /// behind it, the same as a slow frame.
    EventLabel {
        /// An announce received.
        Announce = "announce",
        /// A link came up.
        LinkEstablished = "link_established",
        /// A link proved its identity.
        LinkIdentified = "link_identified",
        /// A message or link data frame.
        Frame = "frame",
        /// A request frame.
        Request = "request",
        /// An inbound or outbound Resource finished.
        ResourceCompleted = "resource_completed",
        /// A Resource's progress or start.
        ResourceProgress = "resource_progress",
        /// A Resource advertised.
        ResourceAdvertised = "resource_advertised",
        /// A Resource failed.
        ResourceFailed = "resource_failed",
        /// A link closed.
        LinkClosed = "link_closed",
        /// A link went stale.
        LinkStale = "link_stale",
        /// A direct-link event.
        DirectLink = "direct_link",
        /// A peer's congestion report.
        PeerCongested = "peer_congested",
        /// Any other node event.
        Other = "other",
        /// A keying outcome applied, with the frames that waited on it.
        KeyingApplied = "keying_applied",
        /// The attribution and deferred-handshake tick.
        AttributionTick = "attribution_tick",
        /// The link-pool and inbound reapers.
        PoolTick = "pool_tick",
        /// The periodic announce and the self-route re-arm.
        AnnounceTick = "announce_tick",
        /// The announce a new link triggers.
        LinkUpAnnounce = "link_up_announce",
    }
);

closed_set!(
    /// Whether a handshake's sender has standing here
    /// ([`crate::transport::link_keying`]).
    StandingLabel {
        /// A sender bound to a key this node answers for.
        Standing = "standing",
        /// Anyone else.
        Stranger = "stranger",
    }
);

closed_set!(
    /// One of leviculum's two node-event planes.
    PlaneLabel {
        /// The control plane.
        Control = "control",
        /// The data plane.
        Data = "data",
    }
);

closed_set!(
    /// Why a primary parent failed over.
    FailoverCause {
        /// Its link went down, or it went silent.
        LinkDown = "link_down",
        /// It was degraded, or left the members or eligibility.
        Health = "health",
        /// Its offered depth passed the bound.
        Depth = "depth",
    }
);

closed_set!(
    /// How a call's setup ended.
    CallSetupOutcome {
        /// A first frame arrived.
        FirstFrame = "first_frame",
        /// The call ended before one did.
        Ended = "ended",
    }
);

closed_set!(
    /// How a first-contact request ended.
    FirstContactOutcome {
        /// The peer answered.
        Answered = "answered",
        /// The wait ran out.
        Timeout = "timeout",
        /// It could not be sent, or the answer was refused.
        Failed = "failed",
    }
);

closed_set!(
    /// A refused row's retry disposition when it finally landed.
    DispositionLabel {
        /// It was on the transient schedule.
        Transient = "transient",
        /// It was on the terminal schedule.
        Terminal = "terminal",
    }
);

closed_set!(
    /// The loops `loop.last_progress_age` watches. Each stamps on its own
    /// cadence, never per event, so the age carries no traffic.
    LoopName {
        /// The Reticulum event loop's heartbeat.
        Event = "event",
        /// The outbound queue's sweeps.
        Sweep = "sweep",
        /// The seat-roster tick.
        Seat = "seat",
        /// The load-ladder tick.
        Ladder = "ladder",
        /// The outbound dispatcher.
        Dispatcher = "dispatcher",
    }
);

closed_set!(
    /// The shaping classes a link can run at.
    ShapingClass {
        /// Both ends hold a serve seat.
        Seat = "seat",
        /// A server.
        Server = "server",
        /// A home uplink.
        Home = "home",
        /// A phone on Wi-Fi.
        PhoneWifi = "phone-wifi",
        /// A phone on cellular.
        PhoneCellular = "phone-cellular",
    }
);

type DecisionRowSender = tokio::sync::broadcast::Sender<crate::decision_rows::DecisionRowRef>;

/// `ciris.edge.shaping.links` — whether a shaped link counts toward the bound.
pub const SHAPING_LINK_KINDS: &[&str] = &["counted", "seat"];
/// `ciris.edge.seal.keyer.workers` — the pool's size and how many run now.
pub const KEYER_WORKER_STATES: &[&str] = &["configured", "busy"];
/// `ciris.edge.replication.reply.queued` — the node's sum, and the fullest lane.
pub const REPLY_QUEUED_STATS: &[&str] = &["sum", "max"];

/// `ciris.edge.event.handler.duration` buckets, seconds. The 100 µs bound is
/// what tells the model's handler time from "under a millisecond"
/// (`FSD/EVENT_PATH_MODEL.md` §2.5).
pub const EVENT_HANDLER_BUCKETS: &[f64] = &[0.0001, 0.001, 0.01, 0.05, 0.25, 1.0, 5.0, 30.0];
/// `ciris.edge.seal.keying.duration` buckets, seconds.
pub const SEAL_KEYING_BUCKETS: &[f64] = &[0.005, 0.02, 0.05, 0.2, 1.0, 5.0, 10.0];
/// `ciris.edge.replication.{inbound,reply}.wait` buckets, seconds.
pub const REPLICATION_WAIT_BUCKETS: &[f64] = &[0.01, 0.1, 1.0, 5.0, 15.0, 60.0, 300.0];
/// `ciris.edge.shaping.row.wait` buckets, seconds: coarse on purpose.
pub const SHAPING_ROW_WAIT_BUCKETS: &[f64] = &[1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0];
/// `ciris.edge.alm.failover.gap` buckets, seconds.
pub const ALM_FAILOVER_GAP_BUCKETS: &[f64] = &[0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 15.0];
/// `ciris.edge.call.setup.duration` buckets, seconds.
pub const CALL_SETUP_BUCKETS: &[f64] = &[0.25, 0.5, 1.0, 2.0, 5.0, 15.0, 60.0];
/// `ciris.edge.first_contact.duration` buckets, seconds.
pub const FIRST_CONTACT_BUCKETS: &[f64] = &[0.1, 1.0, 5.0, 30.0, 120.0, 600.0];
/// `ciris.edge.refusal.attempts` buckets: refusals, not seconds.
pub const REFUSAL_ATTEMPT_BUCKETS: &[f64] = &[1.0, 2.0, 4.0, 8.0, 16.0, 32.0];
/// `ciris.edge.wake.first_round.duration` buckets, seconds.
pub const WAKE_FIRST_ROUND_BUCKETS: &[f64] = &[1.0, 5.0, 15.0, 60.0, 300.0, 1800.0];

/// A handler past this is logged as `edge.event_loop.slow`.
pub const EVENT_LOOP_SLOW: Duration = Duration::from_millis(250);

/// `ciris.edge.node.alive` — the event loop and the ladder turned this
/// recently. Well past a slow handler, so traffic cannot move it.
pub const NODE_ALIVE_BOUND: Duration = Duration::from_secs(60);

/// Fewest links a shaping class holds before its window is published.
pub const SHAPING_CLASS_FLOOR: usize = 3;
/// Published real frames are rounded down to a multiple of this.
pub const SHAPING_REAL_ROUNDING: u64 = 16;

const HIST_SLOTS: usize = 9;

/// A fixed-bucket histogram a hot path can record into: one relaxed add per
/// bucket and per sum, no lock and no allocation. The bounds stay with the
/// caller, as for [`FixedHistogram`](crate::observability::FixedHistogram);
/// at most eight of them, the last slot being `+Inf`.
#[derive(Debug, Default)]
pub struct AtomicHistogram {
    counts: [AtomicU64; HIST_SLOTS],
    sum: AtomicU64,
}

impl AtomicHistogram {
    fn slot(bounds: &[f64], v: f64) -> usize {
        bounds
            .iter()
            .position(|b| v <= *b)
            .unwrap_or(bounds.len())
            .min(HIST_SLOTS - 1)
    }

    /// Record one duration against `bounds`.
    pub fn observe(&self, bounds: &[f64], d: Duration) {
        self.counts[Self::slot(bounds, d.as_secs_f64())].fetch_add(1, Ordering::Relaxed);
        let ns = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
        self.sum.fetch_add(ns, Ordering::Relaxed);
    }

    /// Record one count against `bounds`. The snapshot's `sum_seconds` is then
    /// the sum of the counts.
    pub fn observe_count(&self, bounds: &[f64], n: u64) {
        #[allow(clippy::cast_precision_loss)]
        self.counts[Self::slot(bounds, n as f64)].fetch_add(1, Ordering::Relaxed);
        self.sum
            .fetch_add(n.saturating_mul(1_000_000_000), Ordering::Relaxed);
    }

    /// The point-in-time projection, cumulative, as
    /// [`FixedHistogram::snapshot`](crate::observability::FixedHistogram::snapshot).
    #[must_use]
    pub fn snapshot(&self, bounds: &'static [f64]) -> HistogramSnapshot {
        let mut cumulative = Vec::with_capacity(bounds.len() + 1);
        let mut running = 0u64;
        for slot in self.counts.iter().take(bounds.len() + 1) {
            running = running.saturating_add(slot.load(Ordering::Relaxed));
            cumulative.push(running);
        }
        #[allow(clippy::cast_precision_loss)]
        let sum_seconds = self.sum.load(Ordering::Relaxed) as f64 / 1e9;
        HistogramSnapshot {
            bounds,
            cumulative,
            count: running,
            sum_seconds,
        }
    }

    /// Move every observation out of `self` and into `to`.
    fn drain_into(&self, to: &Self) {
        for (from, into) in self.counts.iter().zip(&to.counts) {
            into.fetch_add(from.swap(0, Ordering::Relaxed), Ordering::Relaxed);
        }
        to.sum
            .fetch_add(self.sum.swap(0, Ordering::Relaxed), Ordering::Relaxed);
    }

    /// Drop every observation; returns how many there were.
    fn discard(&self) -> u64 {
        self.sum.store(0, Ordering::Relaxed);
        self.counts
            .iter()
            .map(|c| c.swap(0, Ordering::Relaxed))
            .sum()
    }
}

fn hist_family<const N: usize>(
    tokens: &[&'static str],
    hists: &[AtomicHistogram; N],
    bounds: &'static [f64],
) -> HashMap<String, HistogramSnapshot> {
    tokens
        .iter()
        .zip(hists)
        .map(|(t, h)| ((*t).to_string(), h.snapshot(bounds)))
        .collect()
}

fn counter_family<const N: usize>(
    tokens: &[&'static str],
    counters: &[AtomicU64; N],
) -> HashMap<String, u64> {
    tokens
        .iter()
        .zip(counters)
        .map(|(t, c)| ((*t).to_string(), c.load(Ordering::Relaxed)))
        .collect()
}

fn arr<T: Default, const N: usize>() -> [T; N] {
    std::array::from_fn(|_| T::default())
}

/// One class's window: what is pending, and what has been published.
#[derive(Debug, Default)]
struct ClassWindow {
    pending_real: AtomicU64,
    pending_wait: AtomicHistogram,
    published_real: AtomicU64,
    published_wait: AtomicHistogram,
    withheld: AtomicU64,
    closes_at_ms: AtomicU64,
}

/// Real frames and row wait, held back per class until a window closes.
///
/// `frames_real` on a live counter is a clock of the node's real traffic, which
/// is what rung 2 hides (`FSD/PRIVACY_MODES.md` §5). So nothing here is
/// readable until [`Self::tick`] publishes a whole window, and a window from a
/// class under [`SHAPING_CLASS_FLOOR`] links is dropped, not carried: carried,
/// it would reach the bundle later as the same per-peer figure.
#[derive(Debug, Default)]
pub struct ShapingWindows {
    classes: [ClassWindow; ShapingClass::COUNT],
}

impl ShapingWindows {
    /// One real frame left on a link of `class`.
    pub fn note_real(&self, class: ShapingClass) {
        self.classes[class as usize]
            .pending_real
            .fetch_add(1, Ordering::Relaxed);
    }

    /// One row left a link of `class` after waiting `d`.
    pub fn note_row_wait(&self, class: ShapingClass, d: Duration) {
        self.classes[class as usize]
            .pending_wait
            .observe(SHAPING_ROW_WAIT_BUCKETS, d);
    }

    /// Close every class's window that is due at `now_ms`. `links` says how
    /// many links a class holds now, `window_of` how long its window runs.
    pub fn tick(
        &self,
        now_ms: u64,
        links: impl Fn(ShapingClass) -> usize,
        window_of: impl Fn(ShapingClass) -> Duration,
    ) {
        for class in ShapingClass::ALL {
            let c = &self.classes[*class as usize];
            let closes = c.closes_at_ms.load(Ordering::Relaxed);
            let window_ms = u64::try_from(window_of(*class).as_millis()).unwrap_or(u64::MAX);
            if closes == 0 {
                c.closes_at_ms
                    .store(now_ms.saturating_add(window_ms), Ordering::Relaxed);
                continue;
            }
            if now_ms < closes {
                continue;
            }
            c.closes_at_ms
                .store(now_ms.saturating_add(window_ms), Ordering::Relaxed);
            let real = c.pending_real.swap(0, Ordering::Relaxed);
            if links(*class) >= SHAPING_CLASS_FLOOR {
                c.published_real
                    .fetch_add(real - real % SHAPING_REAL_ROUNDING, Ordering::Relaxed);
                c.pending_wait.drain_into(&c.published_wait);
            } else if real + c.pending_wait.discard() > 0 {
                c.withheld.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn published_real(&self) -> HashMap<String, u64> {
        ShapingClass::ALL
            .iter()
            .map(|c| {
                let v = self.classes[*c as usize]
                    .published_real
                    .load(Ordering::Relaxed);
                (c.token().to_string(), v)
            })
            .collect()
    }

    fn withheld(&self) -> HashMap<String, u64> {
        ShapingClass::ALL
            .iter()
            .map(|c| {
                let v = self.classes[*c as usize].withheld.load(Ordering::Relaxed);
                (c.token().to_string(), v)
            })
            .collect()
    }

    fn published_wait(&self) -> HashMap<String, HistogramSnapshot> {
        ShapingClass::ALL
            .iter()
            .map(|c| {
                let h = &self.classes[*c as usize].published_wait;
                (c.token().to_string(), h.snapshot(SHAPING_ROW_WAIT_BUCKETS))
            })
            .collect()
    }
}

/// A snapshot of every family this module owns. The bundle takes these field
/// by field; see the catalogue for what each means.
#[derive(Debug, Clone)]
pub struct TelemetrySnapshot {
    pub event_handler_duration_seconds: HashMap<String, HistogramSnapshot>,
    pub seal_keying_duration_seconds: HashMap<String, HistogramSnapshot>,
    pub replication_inbound_wait_seconds: HashMap<String, HistogramSnapshot>,
    pub replication_reply_wait_seconds: HashMap<String, HistogramSnapshot>,
    pub shaping_row_wait_seconds: HashMap<String, HistogramSnapshot>,
    pub alm_failover_gap_seconds: HashMap<String, HistogramSnapshot>,
    pub call_setup_duration_seconds: HashMap<String, HistogramSnapshot>,
    pub first_contact_duration_seconds: HashMap<String, HistogramSnapshot>,
    pub refusal_attempts: HashMap<String, HistogramSnapshot>,
    pub wake_first_round_duration_seconds: HistogramSnapshot,
    pub seal_keyer_queued: HashMap<String, u64>,
    pub seal_keyer_workers: HashMap<String, u64>,
    pub seal_awaiting_links: u64,
    pub seal_awaiting_bytes: u64,
    pub seal_held_bytes: u64,
    pub replication_reply_queued: HashMap<String, u64>,
    pub load_tier: u64,
    pub load_host_pressure: u64,
    pub load_pressure_report_age_seconds: f64,
    pub load_tier_changes_total: HashMap<String, u64>,
    pub shaping_enabled: u64,
    pub shaping_links: HashMap<String, u64>,
    pub shaping_free_slots: u64,
    pub shaping_seat_roster_age_seconds: f64,
    pub shaping_frames_real_windowed: HashMap<String, u64>,
    pub shaping_windows_withheld: HashMap<String, u64>,
    pub leviculum_events_queued: HashMap<String, u64>,
    pub leviculum_events_capacity: HashMap<String, u64>,
    pub leviculum_events_dropped: HashMap<String, u64>,
    pub leviculum_shed_packets: u64,
    pub direct_link_proposing: u64,
    pub alm_active_calls: u64,
    pub alm_c3_peers: u64,
    pub decision_row_unheard_total: HashMap<String, u64>,
    pub decision_row_subscribers: u64,
    pub apply_refusals: HashMap<String, u64>,
    pub loop_last_progress_age_seconds: HashMap<String, f64>,
    pub node_alive: u64,
}

/// The token of `apply_refusals` for a row moved from the transient schedule
/// to the terminal one.
pub const APPLY_REFUSAL_MOVED_TO_TERMINAL: &str = "moved_to_terminal";
/// The token prefix of `apply_refusals` for a row refused and later admitted.
pub const APPLY_REFUSAL_REFUSED_THEN_ADMITTED: &str = "refused_then_admitted";

/// The `to:cause` keys of `load_tier_changes_total`.
#[must_use]
pub fn load_tier_change_keys() -> Vec<String> {
    let mut out = Vec::with_capacity(LOAD_TIER_TOS.len() * LOAD_TIER_CAUSES.len());
    for to in LOAD_TIER_TOS {
        for cause in LOAD_TIER_CAUSES {
            out.push(format!("{to}:{cause}"));
        }
    }
    out
}

/// The tiers a change can land on.
pub const LOAD_TIER_TOS: &[&str] = &["load_tier:0", "load_tier:1", "load_tier:2"];
/// Why a tier changed.
pub const LOAD_TIER_CAUSES: &[&str] = &[
    "host:warning",
    "host:critical",
    "host:normal",
    "edge:transit_pps",
    "edge:relay_commit",
    "edge:av_queue_age",
    "cooldown",
];

/// The telemetry the event path and the loops record into. One per
/// [`EdgeMetrics`](crate::observability::EdgeMetrics) bag, shared by every
/// clone of it.
#[derive(Debug)]
pub struct EdgeTelemetry {
    epoch: Instant,
    event_handler: [AtomicHistogram; EventLabel::COUNT],
    seal_keying: [AtomicHistogram; StandingLabel::COUNT],
    inbound_wait: [AtomicHistogram; EnvelopeKind::ALL.len()],
    reply_wait: [AtomicHistogram; EnvelopeKind::ALL.len()],
    alm_failover_gap: [AtomicHistogram; FailoverCause::COUNT],
    call_setup: [AtomicHistogram; CallSetupOutcome::COUNT],
    first_contact: [AtomicHistogram; FirstContactOutcome::COUNT],
    refusal_attempts: [AtomicHistogram; DispositionLabel::COUNT],
    wake_first_round: AtomicHistogram,
    /// When a resume waits on its first completed round, ms past `epoch` + 1.
    woken_at_ms: AtomicU64,
    keyer_queued: [AtomicU64; StandingLabel::COUNT],
    keyer_workers: AtomicU64,
    keyer_busy: AtomicU64,
    seal_awaiting_links: AtomicU64,
    seal_awaiting_bytes: AtomicU64,
    seal_held_bytes: AtomicU64,
    reply_lanes: Mutex<Vec<Weak<AtomicUsize>>>,
    load_tier: AtomicU64,
    load_host_pressure: AtomicU64,
    pressure_reported_at_ms: AtomicU64,
    load_tier_changes: Mutex<HashMap<String, u64>>,
    shaping_enabled: AtomicU64,
    shaping_links_counted: AtomicU64,
    shaping_links_seat: AtomicU64,
    shaping_free_slots: AtomicU64,
    seat_roster_read_at_ms: AtomicU64,
    /// Real frames and row wait, per class and per window.
    pub shaping_windows: ShapingWindows,
    leviculum_events_queued: [AtomicU64; PlaneLabel::COUNT],
    leviculum_events_capacity: [AtomicU64; PlaneLabel::COUNT],
    leviculum_events_dropped: [AtomicU64; PlaneLabel::COUNT],
    leviculum_shed_packets: AtomicU64,
    direct_link_proposing: AtomicU64,
    alm_active_calls: AtomicU64,
    alm_c3_peers: AtomicU64,
    decision_row_unheard: [AtomicU64; DECISION_ROW_KINDS.len()],
    decision_rows: RwLock<Option<DecisionRowSender>>,
    moved_to_terminal: AtomicU64,
    refused_then_admitted: Mutex<HashMap<&'static str, u64>>,
    loop_stamps: [AtomicU64; LoopName::COUNT],
}

impl Default for EdgeTelemetry {
    fn default() -> Self {
        Self {
            epoch: Instant::now(),
            event_handler: arr(),
            seal_keying: arr(),
            inbound_wait: arr(),
            reply_wait: arr(),
            alm_failover_gap: arr(),
            call_setup: arr(),
            first_contact: arr(),
            refusal_attempts: arr(),
            wake_first_round: AtomicHistogram::default(),
            woken_at_ms: AtomicU64::new(0),
            keyer_queued: arr(),
            keyer_workers: AtomicU64::new(0),
            keyer_busy: AtomicU64::new(0),
            seal_awaiting_links: AtomicU64::new(0),
            seal_awaiting_bytes: AtomicU64::new(0),
            seal_held_bytes: AtomicU64::new(0),
            reply_lanes: Mutex::new(Vec::new()),
            load_tier: AtomicU64::new(0),
            load_host_pressure: AtomicU64::new(0),
            pressure_reported_at_ms: AtomicU64::new(0),
            load_tier_changes: Mutex::new(HashMap::new()),
            shaping_enabled: AtomicU64::new(0),
            shaping_links_counted: AtomicU64::new(0),
            shaping_links_seat: AtomicU64::new(0),
            shaping_free_slots: AtomicU64::new(0),
            seat_roster_read_at_ms: AtomicU64::new(0),
            shaping_windows: ShapingWindows::default(),
            leviculum_events_queued: arr(),
            leviculum_events_capacity: arr(),
            leviculum_events_dropped: arr(),
            leviculum_shed_packets: AtomicU64::new(0),
            direct_link_proposing: AtomicU64::new(0),
            alm_active_calls: AtomicU64::new(0),
            alm_c3_peers: AtomicU64::new(0),
            decision_row_unheard: arr(),
            decision_rows: RwLock::new(None),
            moved_to_terminal: AtomicU64::new(0),
            refused_then_admitted: Mutex::new(HashMap::new()),
            loop_stamps: arr(),
        }
    }
}

/// The `kind` tokens of `ciris.edge.decision_row.unheard`, in
/// [`DecisionRowKind`](crate::decision_rows::DecisionRowKind)'s order.
pub const DECISION_ROW_KINDS: [&str; 7] = [
    "membership_proposal",
    "membership_reply",
    "objection",
    "roster_landed",
    "moderation_action",
    "accord_halt",
    "contact_request",
];

fn kind_slot(kind: EnvelopeKind) -> usize {
    EnvelopeKind::ALL
        .iter()
        .position(|k| *k == kind)
        .unwrap_or(0)
}

fn envelope_kind_tokens() -> Vec<&'static str> {
    EnvelopeKind::ALL.iter().map(|k| k.as_wire_str()).collect()
}

impl EdgeTelemetry {
    /// Milliseconds past this bag's epoch, plus one: 0 stays "never".
    fn stamp(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis())
            .unwrap_or(u64::MAX - 1)
            .saturating_add(1)
    }

    /// Milliseconds past this bag's epoch.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.stamp()
    }

    /// Whole seconds since `stamp`, or `-1.0` for "never".
    fn age_seconds(&self, stamp: &AtomicU64) -> f64 {
        match stamp.load(Ordering::Relaxed) {
            0 => -1.0,
            at => {
                #[allow(clippy::cast_precision_loss)]
                let s = (self.stamp().saturating_sub(at) / 1000) as f64;
                s
            }
        }
    }

    /// One turn of the event loop took `d`. Past [`EVENT_LOOP_SLOW`] it says
    /// so, throttled per label.
    pub fn observe_event(&self, label: EventLabel, d: Duration) {
        self.event_handler[label as usize].observe(EVENT_HANDLER_BUCKETS, d);
        if d >= EVENT_LOOP_SLOW {
            use crate::log_throttle::ThrottleDecision;
            if let ThrottleDecision::Emit { suppressed_prev } = slow_log().check(label.token()) {
                tracing::warn!(
                    target: "edge.event_loop.slow",
                    event = label.token(),
                    ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX),
                    suppressed_prev,
                    "one event held the Reticulum event loop: everything queued waited behind it"
                );
            }
        }
    }

    /// One keying took `d` from its admission to its outcome.
    pub fn observe_keying(&self, standing: bool, d: Duration) {
        self.seal_keying[usize::from(!standing)].observe(SEAL_KEYING_BUCKETS, d);
    }

    /// A responder frame of `kind` sat `d` in the inbox.
    pub fn observe_inbound_wait(&self, kind: EnvelopeKind, d: Duration) {
        self.inbound_wait[kind_slot(kind)].observe(REPLICATION_WAIT_BUCKETS, d);
    }

    /// A reply of `kind` sat `d` in its lane.
    pub fn observe_reply_wait(&self, kind: EnvelopeKind, d: Duration) {
        self.reply_wait[kind_slot(kind)].observe(REPLICATION_WAIT_BUCKETS, d);
    }

    /// A failover left this node with no primary for `d`.
    pub fn observe_failover_gap(&self, cause: FailoverCause, d: Duration) {
        self.alm_failover_gap[cause as usize].observe(ALM_FAILOVER_GAP_BUCKETS, d);
    }

    /// A call's setup ended.
    pub fn observe_call_setup(&self, outcome: CallSetupOutcome, d: Duration) {
        self.call_setup[outcome as usize].observe(CALL_SETUP_BUCKETS, d);
    }

    /// A first-contact request ended.
    pub fn observe_first_contact(&self, outcome: FirstContactOutcome, d: Duration) {
        self.first_contact[outcome as usize].observe(FIRST_CONTACT_BUCKETS, d);
    }

    /// A row landed after `attempts` refusals on `disposition`'s schedule.
    pub fn observe_refusal_attempts(&self, disposition: DispositionLabel, attempts: u64) {
        self.refusal_attempts[disposition as usize]
            .observe_count(REFUSAL_ATTEMPT_BUCKETS, attempts);
    }

    /// The node resumed: the next completed round closes the clock.
    pub fn note_woken(&self) {
        self.woken_at_ms.store(self.stamp(), Ordering::Relaxed);
    }

    /// A round completed.
    pub fn note_round_completed(&self) {
        let woken = self.woken_at_ms.swap(0, Ordering::Relaxed);
        if woken != 0 {
            let ms = self.stamp().saturating_sub(woken);
            self.wake_first_round
                .observe(WAKE_FIRST_ROUND_BUCKETS, Duration::from_millis(ms));
        }
    }

    /// The keyer's queues now.
    pub fn set_keyer_queued(&self, standing: usize, strangers: usize) {
        self.keyer_queued[StandingLabel::Standing as usize]
            .store(standing as u64, Ordering::Relaxed);
        self.keyer_queued[StandingLabel::Stranger as usize]
            .store(strangers as u64, Ordering::Relaxed);
    }

    /// The keyer's workers now.
    pub fn set_keyer_workers(&self, configured: usize, busy: usize) {
        self.keyer_workers
            .store(configured as u64, Ordering::Relaxed);
        self.keyer_busy.store(busy as u64, Ordering::Relaxed);
    }

    /// The `Awaiting` ledger now.
    pub fn set_seal_awaiting(&self, links: usize, bytes: usize) {
        self.seal_awaiting_links
            .store(links as u64, Ordering::Relaxed);
        self.seal_awaiting_bytes
            .store(bytes as u64, Ordering::Relaxed);
    }

    /// Frames held during keying now, bytes.
    pub fn set_seal_held(&self, bytes: usize) {
        self.seal_held_bytes.store(bytes as u64, Ordering::Relaxed);
    }

    /// A new reply lane; `queued` is its depth, kept by the lane.
    pub fn register_reply_lane(&self, queued: &Arc<AtomicUsize>) {
        self.reply_lanes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Arc::downgrade(queued));
    }

    fn reply_queued(&self) -> HashMap<String, u64> {
        let (mut sum, mut max) = (0u64, 0u64);
        self.reply_lanes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|l| {
                let Some(lane) = l.upgrade() else {
                    return false;
                };
                let n = lane.load(Ordering::Relaxed) as u64;
                sum += n;
                max = max.max(n);
                true
            });
        HashMap::from([("sum".to_string(), sum), ("max".to_string(), max)])
    }

    /// The ladder's tier and the host's pressure now.
    pub fn set_load(&self, tier: u8, host_pressure: u8) {
        self.load_tier.store(u64::from(tier), Ordering::Relaxed);
        self.load_host_pressure
            .store(u64::from(host_pressure), Ordering::Relaxed);
    }

    /// The host reported its pressure just now.
    pub fn note_pressure_report(&self) {
        self.pressure_reported_at_ms
            .store(self.stamp(), Ordering::Relaxed);
    }

    /// The tier changed.
    pub fn note_tier_change(&self, to: &str, cause: &str) {
        *self
            .load_tier_changes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(format!("{to}:{cause}"))
            .or_insert(0) += 1;
    }

    /// What the shaped links look like now.
    pub fn set_shaping(&self, enabled: bool, counted: usize, seat: usize, free_slots: u8) {
        self.shaping_enabled
            .store(u64::from(enabled), Ordering::Relaxed);
        self.shaping_links_counted
            .store(counted as u64, Ordering::Relaxed);
        self.shaping_links_seat
            .store(seat as u64, Ordering::Relaxed);
        self.shaping_free_slots
            .store(u64::from(free_slots), Ordering::Relaxed);
    }

    /// The seat roster was read just now.
    pub fn note_seat_roster_read(&self) {
        self.seat_roster_read_at_ms
            .store(self.stamp(), Ordering::Relaxed);
    }

    /// Mirror leviculum's plane counters.
    pub fn set_leviculum_planes(
        &self,
        queued: [usize; 2],
        capacity: [usize; 2],
        dropped: [u64; 2],
        shed_packets: u64,
    ) {
        for i in 0..PlaneLabel::COUNT {
            self.leviculum_events_queued[i].store(queued[i] as u64, Ordering::Relaxed);
            self.leviculum_events_capacity[i].store(capacity[i] as u64, Ordering::Relaxed);
            self.leviculum_events_dropped[i].store(dropped[i], Ordering::Relaxed);
        }
        self.leviculum_shed_packets
            .store(shed_packets, Ordering::Relaxed);
    }

    /// Whether this node proposes direct links now.
    pub fn set_direct_link_proposing(&self, on: bool) {
        self.direct_link_proposing
            .store(u64::from(on), Ordering::Relaxed);
    }

    /// A call began.
    pub fn call_began(&self) {
        self.alm_active_calls.fetch_add(1, Ordering::Relaxed);
    }

    /// A call ended, taking its `c3_peers` with it.
    pub fn call_ended(&self, c3_peers: u64) {
        let dec = |a: &AtomicU64, by: u64| {
            let _ = a.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(by))
            });
        };
        dec(&self.alm_active_calls, 1);
        dec(&self.alm_c3_peers, c3_peers);
    }

    /// A call's C3-speaking members went from `before` to `after`.
    pub fn move_c3_peers(&self, before: u64, after: u64) {
        self.alm_c3_peers.fetch_add(after, Ordering::Relaxed);
        let _ = self
            .alm_c3_peers
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(before))
            });
    }

    /// A decision row found nobody listening.
    pub fn note_decision_row_unheard(&self, kind: crate::decision_rows::DecisionRowKind) {
        let slot = DECISION_ROW_KINDS
            .iter()
            .position(|k| *k == kind.as_str())
            .unwrap_or(0);
        self.decision_row_unheard[slot].fetch_add(1, Ordering::Relaxed);
    }

    /// The signal whose receivers `decision_row_subscribers` counts.
    pub fn watch_decision_rows(&self, sender: DecisionRowSender) {
        *self
            .decision_rows
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(sender);
    }

    /// A refused row moved to the terminal schedule.
    pub fn note_moved_to_terminal(&self) {
        self.moved_to_terminal.fetch_add(1, Ordering::Relaxed);
    }

    /// A refused row was admitted; `class` is the last refusal's class, if it
    /// had one.
    pub fn note_refused_then_admitted(&self, class: Option<&'static str>) {
        *self
            .refused_then_admitted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(class.unwrap_or(REFUSAL_CLASS_OTHER))
            .or_insert(0) += 1;
    }

    /// `name` turned just now.
    pub fn beat(&self, name: LoopName) {
        self.loop_stamps[name as usize].store(self.stamp(), Ordering::Relaxed);
    }

    /// `name` has stopped on purpose: its age reads `-1` ("not running"), so a
    /// parked node is not read as a wedged one.
    pub fn beat_off(&self, name: LoopName) {
        self.loop_stamps[name as usize].store(0, Ordering::Relaxed);
    }

    /// The two loops [`NODE_ALIVE_BOUND`] watches both turned within it.
    fn alive(&self) -> bool {
        [LoopName::Event, LoopName::Ladder].iter().all(|l| {
            let age = self.age_seconds(&self.loop_stamps[*l as usize]);
            (0.0..NODE_ALIVE_BOUND.as_secs_f64()).contains(&age)
        })
    }

    /// Project everything.
    // Straight-line field projection; its length grows with the bundle.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn snapshot(&self) -> TelemetrySnapshot {
        let kinds = envelope_kind_tokens();
        let mut changes: HashMap<String, u64> = load_tier_change_keys()
            .into_iter()
            .map(|k| (k, 0))
            .collect();
        for (k, v) in self
            .load_tier_changes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
        {
            changes.insert(k.clone(), *v);
        }
        let mut apply_refusals: HashMap<String, u64> = REFUSAL_CLASSES
            .iter()
            .map(|c| (format!("{APPLY_REFUSAL_REFUSED_THEN_ADMITTED}:{c}"), 0))
            .collect();
        for (c, n) in self
            .refused_then_admitted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
        {
            apply_refusals.insert(format!("{APPLY_REFUSAL_REFUSED_THEN_ADMITTED}:{c}"), *n);
        }
        apply_refusals.insert(
            APPLY_REFUSAL_MOVED_TO_TERMINAL.to_string(),
            self.moved_to_terminal.load(Ordering::Relaxed),
        );
        let subscribers = self
            .decision_rows
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map_or(0, DecisionRowSender::receiver_count);
        TelemetrySnapshot {
            event_handler_duration_seconds: hist_family(
                EventLabel::TOKENS,
                &self.event_handler,
                EVENT_HANDLER_BUCKETS,
            ),
            seal_keying_duration_seconds: hist_family(
                StandingLabel::TOKENS,
                &self.seal_keying,
                SEAL_KEYING_BUCKETS,
            ),
            replication_inbound_wait_seconds: hist_family(
                &kinds,
                &self.inbound_wait,
                REPLICATION_WAIT_BUCKETS,
            ),
            replication_reply_wait_seconds: hist_family(
                &kinds,
                &self.reply_wait,
                REPLICATION_WAIT_BUCKETS,
            ),
            shaping_row_wait_seconds: self.shaping_windows.published_wait(),
            alm_failover_gap_seconds: hist_family(
                FailoverCause::TOKENS,
                &self.alm_failover_gap,
                ALM_FAILOVER_GAP_BUCKETS,
            ),
            call_setup_duration_seconds: hist_family(
                CallSetupOutcome::TOKENS,
                &self.call_setup,
                CALL_SETUP_BUCKETS,
            ),
            first_contact_duration_seconds: hist_family(
                FirstContactOutcome::TOKENS,
                &self.first_contact,
                FIRST_CONTACT_BUCKETS,
            ),
            refusal_attempts: hist_family(
                DispositionLabel::TOKENS,
                &self.refusal_attempts,
                REFUSAL_ATTEMPT_BUCKETS,
            ),
            wake_first_round_duration_seconds: self
                .wake_first_round
                .snapshot(WAKE_FIRST_ROUND_BUCKETS),
            seal_keyer_queued: counter_family(StandingLabel::TOKENS, &self.keyer_queued),
            seal_keyer_workers: HashMap::from([
                (
                    "configured".to_string(),
                    self.keyer_workers.load(Ordering::Relaxed),
                ),
                ("busy".to_string(), self.keyer_busy.load(Ordering::Relaxed)),
            ]),
            seal_awaiting_links: self.seal_awaiting_links.load(Ordering::Relaxed),
            seal_awaiting_bytes: self.seal_awaiting_bytes.load(Ordering::Relaxed),
            seal_held_bytes: self.seal_held_bytes.load(Ordering::Relaxed),
            replication_reply_queued: self.reply_queued(),
            load_tier: self.load_tier.load(Ordering::Relaxed),
            load_host_pressure: self.load_host_pressure.load(Ordering::Relaxed),
            load_pressure_report_age_seconds: self.age_seconds(&self.pressure_reported_at_ms),
            load_tier_changes_total: changes,
            shaping_enabled: self.shaping_enabled.load(Ordering::Relaxed),
            shaping_links: HashMap::from([
                (
                    "counted".to_string(),
                    self.shaping_links_counted.load(Ordering::Relaxed),
                ),
                (
                    "seat".to_string(),
                    self.shaping_links_seat.load(Ordering::Relaxed),
                ),
            ]),
            shaping_free_slots: self.shaping_free_slots.load(Ordering::Relaxed),
            shaping_seat_roster_age_seconds: self.age_seconds(&self.seat_roster_read_at_ms),
            shaping_frames_real_windowed: self.shaping_windows.published_real(),
            shaping_windows_withheld: self.shaping_windows.withheld(),
            leviculum_events_queued: counter_family(
                PlaneLabel::TOKENS,
                &self.leviculum_events_queued,
            ),
            leviculum_events_capacity: counter_family(
                PlaneLabel::TOKENS,
                &self.leviculum_events_capacity,
            ),
            leviculum_events_dropped: counter_family(
                PlaneLabel::TOKENS,
                &self.leviculum_events_dropped,
            ),
            leviculum_shed_packets: self.leviculum_shed_packets.load(Ordering::Relaxed),
            direct_link_proposing: self.direct_link_proposing.load(Ordering::Relaxed),
            alm_active_calls: self.alm_active_calls.load(Ordering::Relaxed),
            alm_c3_peers: self.alm_c3_peers.load(Ordering::Relaxed),
            decision_row_unheard_total: counter_family(
                &DECISION_ROW_KINDS,
                &self.decision_row_unheard,
            ),
            decision_row_subscribers: subscribers as u64,
            apply_refusals,
            node_alive: u64::from(self.alive()),
            loop_last_progress_age_seconds: LoopName::ALL
                .iter()
                .map(|l| {
                    (
                        l.token().to_string(),
                        self.age_seconds(&self.loop_stamps[*l as usize]),
                    )
                })
                .collect(),
        }
    }
}

fn slow_log() -> &'static crate::log_throttle::LogThrottle {
    static LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> = std::sync::OnceLock::new();
    LOG.get_or_init(|| crate::log_throttle::LogThrottle::new(4, Duration::from_secs(60), 64))
}

/// The class token of a refusal edge could not classify.
pub const REFUSAL_CLASS_OTHER: &str = "other";
/// The classes `refused_then_admitted` carries: every
/// [`ApplyRefusalClass`](crate::replication::bridge::ApplyRefusalClass) token
/// and [`REFUSAL_CLASS_OTHER`].
pub const REFUSAL_CLASSES: &[&str] = &[
    "community_roster_fork",
    "retry_after_roster",
    "roster_authority_unauthorized",
    "retry_after_standing",
    "not_a_community_member",
    "not_a_family_member",
    "third_party_row",
    "retry_after_consent",
    "membership_consent_refused",
    REFUSAL_CLASS_OTHER,
];

/// What a catalogue row measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Monotonic since the node started.
    Counter,
    /// A level read now.
    Gauge,
    /// Cumulative `le` buckets, a count and a sum.
    Histogram,
}

/// A catalogue row's unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    /// Things.
    Count,
    /// Seconds. An age of `-1` means "never" or "not running".
    Seconds,
    /// Milliseconds.
    Milliseconds,
    /// Nanoseconds and samples, in pairs.
    Nanoseconds,
    /// Bytes.
    Bytes,
    /// A ratio in `[0, 1]`.
    Ratio,
}

/// Who may read a field. The server enforces this: `PublicSafe` may stay on
/// the unauthenticated route, `OperatorOnly` needs the owner or loopback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exposure {
    /// Liveness only; carries no traffic, peer or load.
    PublicSafe,
    /// Everything else.
    OperatorOnly,
}

/// The values a label takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelValues {
    /// Exactly these, each present at zero from the first snapshot.
    Closed(&'static [&'static str]),
    /// One of the `kind` tokens of [`EnvelopeKind`], each present at zero.
    EnvelopeKinds,
    /// A compile-time token at each increment site, or persist's refusal
    /// token: bounded by the source, not listed here, and absent until first
    /// seen.
    Tokens,
    /// Keyed by a peer. Only `peer_reachability_ratio` and `recent_withholds`,
    /// both operator-only, and neither may be joined by a new field.
    PeerKeyed,
}

/// One bundle field.
#[derive(Debug, Clone, Copy)]
pub struct TelemetrySpec {
    /// The [`EdgeMetricsBundle`](crate::observability::EdgeMetricsBundle) field.
    pub field: &'static str,
    /// Its name: `ciris.edge.*`, dotted.
    pub name: &'static str,
    /// What it measures.
    pub kind: Kind,
    /// In what.
    pub unit: Unit,
    /// Its label key and values, when labelled.
    pub label: Option<(&'static str, LabelValues)>,
    /// Who may read it.
    pub exposure: Exposure,
    /// One line for an operator.
    pub description: &'static str,
}

const fn spec(
    field: &'static str,
    name: &'static str,
    kind: Kind,
    unit: Unit,
    label: Option<(&'static str, LabelValues)>,
    description: &'static str,
) -> TelemetrySpec {
    TelemetrySpec {
        field,
        name,
        kind,
        unit,
        label,
        exposure: Exposure::OperatorOnly,
        description,
    }
}

const REASON: Option<(&str, LabelValues)> = Some(("reason", LabelValues::Tokens));
const KINDS: Option<(&str, LabelValues)> = Some(("kind", LabelValues::EnvelopeKinds));

// A catalogue row's label is an `Option`; this is its closed spelling.
#[allow(clippy::unnecessary_wraps)]
const fn closed(
    key: &'static str,
    v: &'static [&'static str],
) -> Option<(&'static str, LabelValues)> {
    Some((key, LabelValues::Closed(v)))
}

use Kind::{Counter, Gauge, Histogram};
use Unit::{Bytes, Count, Milliseconds, Nanoseconds, Ratio, Seconds};

/// Every bundle field, one row each. See the module docs.
pub const TELEMETRY_CATALOGUE: &[TelemetrySpec] = &[
    spec("envelopes_sent_total", "ciris.edge.envelopes.sent", Counter, Count, Some(("message_type", LabelValues::Tokens)), "Envelopes signed and offered, by message type."),
    spec("envelopes_received_total", "ciris.edge.envelopes.received", Counter, Count, Some(("message_type", LabelValues::Tokens)), "Envelopes verified inbound, by message type."),
    spec("send_failures_total", "ciris.edge.send.failures", Counter, Count, REASON, "Failed sends, by transport and error class."),
    spec("verify_failures_total", "ciris.edge.verify.failures", Counter, Count, REASON, "Inbound verifications refused, by class."),
    spec("durable_enqueued_total", "ciris.edge.durable.enqueued", Counter, Count, Some(("class", LabelValues::Tokens)), "Durable sends enqueued, by delivery class."),
    spec("transport_bytes_in_total", "ciris.edge.transport.bytes.in", Counter, Bytes, Some(("transport", LabelValues::Tokens)), "Bytes received, by transport."),
    spec("transport_bytes_out_total", "ciris.edge.transport.bytes.out", Counter, Bytes, Some(("transport", LabelValues::Tokens)), "Bytes sent, by transport."),
    spec("peer_reachability_ratio", "ciris.edge.peer.reachability", Gauge, Ratio, Some(("peer", LabelValues::PeerKeyed)), "Per-peer send success. Names peers: never public."),
    spec("inbound_dropped_low_trust", "ciris.edge.inbound.dropped_low_trust", Counter, Count, None, "Envelopes dropped by the trust short-circuit."),
    spec("replication_round_outcomes_total", "ciris.edge.round.outcomes", Counter, Count, closed("outcome", &["completed", "refused", "timed_out", "error"]), "Anti-entropy rounds, by outcome."),
    spec("replication_inbound_backpressure_drops", "ciris.edge.replication.inbound.backpressure_drops", Counter, Count, None, "Frames dropped at a full coordinator inbox."),
    spec("replication_inbound_backpressure_drops_by_role", "ciris.edge.replication.inbound.backpressure_drops_by_role", Counter, Count, Some(("role", LabelValues::Tokens)), "The same, by role."),
    spec("blob_route_refusals", "ciris.edge.blob.route_refusals", Counter, Count, REASON, "Blob holders dropped from a pull, by refusal."),
    spec("blob_serve_refusals", "ciris.edge.blob.serve_refusals", Counter, Count, REASON, "Blob serves refused, by reason."),
    spec("blob_serve_legacy_dag_walks", "ciris.edge.blob.serve_legacy_dag_walks", Counter, Count, None, "Chunk serves that fell back to the legacy DAG walk."),
    spec("blob_scoped_carriers", "ciris.edge.blob.scoped_carriers", Counter, Count, Some(("carrier", LabelValues::Tokens)), "Scoped blob carriage, by carrier."),
    spec("blob_pull_sources", "ciris.edge.blob.pull_sources", Counter, Count, Some(("source", LabelValues::Tokens)), "Blob pulls, by source."),
    spec("blob_pull_refusals", "ciris.edge.blob.pull_refusals", Counter, Count, REASON, "Blob pulls refused, by reason."),
    spec("blob_dag_phases", "ciris.edge.blob.dag.phases", Counter, Nanoseconds, Some(("phase", LabelValues::Tokens)), "Chunk-DAG time by phase: total nanoseconds and samples."),
    spec("blob_dag_chunks", "ciris.edge.blob.dag.chunks", Counter, Count, Some(("outcome", LabelValues::Tokens)), "Chunks by outcome."),
    spec("durability_custody", "ciris.edge.durability.custody", Counter, Count, Some(("outcome", LabelValues::Tokens)), "Custody claims by outcome."),
    spec("delivery_receipts", "ciris.edge.delivery.receipts", Counter, Count, Some(("outcome", LabelValues::Tokens)), "Delivery receipts by outcome."),
    spec("bootstrap_door_outcomes", "ciris.edge.bootstrap_door.outcomes", Counter, Count, Some(("decision", LabelValues::Tokens)), "Bootstrap door decisions."),
    spec("transport_inbound_drops", "ciris.edge.transport.inbound_drops", Counter, Count, REASON, "Frames dropped at the transport's inbound, by reason."),
    spec("first_contact_outcomes", "ciris.edge.first_contact.outcomes", Counter, Count, REASON, "First-contact outcomes on this node's opaque plane."),
    spec("av_plane", "ciris.edge.av.plane", Counter, Count, closed("reason", obs::AV_PLANE_LABELS), "A/V and ALM events; `alm_failover`, `alm_switch`, `alm_epoch_resync`, `alm_loop_detected`, `alm_over_claim` among them."),
    spec("link_seal", "ciris.edge.link_seal", Counter, Count, closed("reason", obs::LINK_SEAL_LABELS), "Link seal outcomes. A key with a `:` refines the key before it."),
    spec("link_shaping", "ciris.edge.link_shaping", Counter, Count, closed("reason", obs::LINK_SHAPING_LABELS), "Shaping outcomes. Raw real frames are not here: see `shaping_frames_real_windowed`."),
    spec("direct_link", "ciris.edge.direct_link", Counter, Count, closed("reason", obs::DIRECT_LINK_LABELS), "Direct-link attempts and outcomes."),
    spec("peer_binding", "ciris.edge.peer_binding", Counter, Count, closed("reason", obs::PEER_BINDING_LABELS), "Peer binding outcomes."),
    spec("key_plane_sweep", "ciris.edge.key_plane.sweep", Counter, Count, REASON, "Key-plane sweep counts."),
    spec("link_stall", "ciris.edge.link_stall", Counter, Count, closed("reason", obs::LINK_STALL_LABELS), "Stalled-link guard outcomes."),
    spec("advertise", "ciris.edge.advertise", Counter, Count, closed("reason", obs::ADVERTISE_LABELS), "The advertise sweep. `advertise_watermark_evicted` growing steadily means the cursor map is thrashing; `advertise_read_failed` is a page whose read failed, with its cursor held."),
    spec("direct_links_active", "ciris.edge.direct_links.active", Gauge, Count, None, "Links on a punched interface now."),
    spec("replication_routed_to_responder_total", "ciris.edge.replication.routed.responder", Counter, Count, None, "Frames routed to a responder."),
    spec("replication_routed_to_initiator_total", "ciris.edge.replication.routed.initiator", Counter, Count, None, "Frames routed to an initiator."),
    spec("replication_reply_dropped_total", "ciris.edge.replication.reply_dropped", Counter, Count, None, "Replies with no round to land in."),
    spec("announce_intake_evictions", "ciris.edge.announce.intake_evictions", Counter, Count, None, "Announce intake entries evicted at capacity."),
    spec("transport_packets_dropped", "ciris.edge.transport.packets_dropped", Counter, Count, None, "Packets the transport reported dropped."),
    spec("known_destination_evictions", "ciris.edge.known_destination.evictions", Gauge, Count, None, "leviculum's known-destination evictions, mirrored."),
    spec("transport_signer_id_mismatch", "ciris.edge.transport.signer_id_mismatch", Gauge, Count, None, "1 when the transport's signer is not the identity the node announces. This node's own wiring: the harm lands on peers as `link_seal_refused_no_pair`, so 0 here says nothing of peers failing to key to it."),
    spec("link_pool_links", "ciris.edge.link_pool.links", Gauge, Count, None, "Pooled links now."),
    spec("link_pool_max_per_destination", "ciris.edge.link_pool.max_per_destination", Gauge, Count, None, "The busiest destination's pooled links."),
    spec("link_pool_closed_by_reason", "ciris.edge.link_pool.closed", Counter, Count, REASON, "Pooled links closed, by reason."),
    spec("inbound_links", "ciris.edge.links.inbound", Gauge, Count, None, "Links peers dialled here."),
    spec("outbound_links", "ciris.edge.links.outbound", Gauge, Count, None, "Links this node dialled."),
    spec("inbound_link_closed_by_reason", "ciris.edge.links.inbound.closed", Counter, Count, REASON, "Inbound links closed, by cause."),
    spec("outbound_link_closed_by_reason", "ciris.edge.links.outbound.closed", Counter, Count, REASON, "Outbound links closed, by cause."),
    spec("link_before_binding", "ciris.edge.link.before_binding", Counter, Count, None, "Links identified before their announcer's binding."),
    spec("announce_queue_drop_first_seen", "ciris.edge.announce.queue_drop_first_seen", Counter, Count, None, "First-seen announces dropped at a full lane."),
    spec("channel_first_skipped_over_cap", "ciris.edge.channel_first.skipped_over_cap", Counter, Count, None, "Reverse-path frames too big for Channel-first."),
    spec("announce_to_binding_ms_last", "ciris.edge.announce.to_binding_last", Gauge, Milliseconds, None, "The latest first-seen bind's latency."),
    spec("withholds_by_reason", "ciris.edge.withholds", Counter, Count, REASON, "Rows withheld from a peer, by reason."),
    spec("recent_withholds", "ciris.edge.withholds.recent", Gauge, Count, Some(("peer", LabelValues::PeerKeyed)), "The latest withholds with their peer. Names peers: never public."),
    spec("replication_envelopes_served_total", "ciris.edge.replication.envelopes_served", Counter, Count, KINDS, "Envelopes served, by kind."),
    spec("apply_refusals_by_kind", "ciris.edge.apply_refusals.by_kind", Counter, Count, KINDS, "Apply refusals, by kind."),
    spec("key_apply_refusals_by_reason", "ciris.edge.apply_refusals.key", Counter, Count, REASON, "Key-plane refusals, by persist token."),
    spec("attestation_apply_refusals_by_reason", "ciris.edge.apply_refusals.attestation", Counter, Count, REASON, "Attestation refusals, by persist token."),
    spec("apply_refusals_by_class", "ciris.edge.apply_refusals.by_class", Counter, Count, REASON, "Apply refusals, by edge's class."),
    spec("envelope_kind_retired_refusals", "ciris.edge.apply_refusals.kind_retired", Counter, Count, REASON, "Rows of a retired kind refused."),
    spec("rows_parked_on_signer", "ciris.edge.rows.parked_on_signer", Counter, Count, KINDS, "Rows parked on an absent signer, by kind."),
    spec("signer_releases", "ciris.edge.rows.signer_releases", Counter, Count, None, "Rows released when their signer landed."),
    spec("retry_suppressions", "ciris.edge.retry.suppressions", Counter, Count, None, "Asks the refusal memory suppressed."),
    spec("signer_park_evictions", "ciris.edge.rows.signer_park_evictions", Counter, Count, None, "Parked rows evicted at the cap."),
    spec("refusal_memory_len", "ciris.edge.refusal_memory.len", Gauge, Count, None, "Rows remembered as refused."),
    spec("refusal_memory_capacity", "ciris.edge.refusal_memory.capacity", Gauge, Count, None, "The bound on that."),
    spec("parked_on_signer_len", "ciris.edge.rows.parked_on_signer.len", Gauge, Count, None, "Rows parked on a signer now."),
    spec("parked_on_signer_capacity", "ciris.edge.rows.parked_on_signer.capacity", Gauge, Count, None, "The bound on that."),
    spec("replication_applied_total", "ciris.edge.replication.applied", Counter, Count, KINDS, "Rows applied, by kind."),
    spec("replication_duplicate_total", "ciris.edge.replication.duplicate", Counter, Count, KINDS, "Rows already held, by kind."),
    spec("removal_delivery", "ciris.edge.removal.delivery", Gauge, Count, Some(("state", LabelValues::Tokens)), "Tracked removals: offered, acked, unacked. Rows, not peers."),
    spec("replication_round_duration_seconds", "ciris.edge.round.duration", Histogram, Seconds, KINDS, "Anti-entropy round time, by kind."),
    spec("sweep_permit_wait_seconds", "ciris.edge.sweep.permit_wait", Histogram, Seconds, None, "Time an advertise sweep waited for its permit."),
    spec("responder_rounds_total", "ciris.edge.responder.rounds", Counter, Count, Some(("outcome", LabelValues::Tokens)), "Responder rounds by `kind:outcome`, including `reply_shed`, `reply_shed_node` and `reply_expired`."),
    spec("responder_link_up_seconds", "ciris.edge.responder.link_up", Histogram, Seconds, Some(("stage", LabelValues::Tokens)), "Responder link-up time, by stage."),
    spec("responder_link_up_total", "ciris.edge.responder.link_up.outcomes", Counter, Count, Some(("outcome", LabelValues::Closed(&obs::LINK_UP_OUTCOMES))), "Responder link-ups, by outcome."),
    spec("recovered_links_total", "ciris.edge.links.recovered", Counter, Count, None, "Links rebuilt after a lost `LinkEstablished`."),
    spec("unclaimed_ship_refused_total", "ciris.edge.links.unclaimed_ship_refused", Counter, Count, None, "Ships refused on a claimed lane. Non-zero is a regression."),
    // v44
    spec("event_handler_duration_seconds", "ciris.edge.event.handler.duration", Histogram, Seconds, closed("event", EventLabel::TOKENS), "Time one event held the Reticulum event loop, timer arms included. Spans the frames a keying replays."),
    spec("seal_keying_duration_seconds", "ciris.edge.seal.keying.duration", Histogram, Seconds, closed("standing", StandingLabel::TOKENS), "A handshake's time from the keyer's queue to its outcome, decapsulation included."),
    spec("replication_inbound_wait_seconds", "ciris.edge.replication.inbound.wait", Histogram, Seconds, KINDS, "A frame's time in a responder's inbox, before its step."),
    spec("replication_reply_wait_seconds", "ciris.edge.replication.reply.wait", Histogram, Seconds, KINDS, "A reply's time in its lane, before its send. Every job, expired ones too; the count is the lane's jobs done."),
    spec("shaping_row_wait_seconds", "ciris.edge.shaping.row.wait", Histogram, Seconds, closed("class", ShapingClass::TOKENS), "Time a row took to leave a shaped link. Published per class per window W, only at 3 or more links."),
    spec("alm_failover_gap_seconds", "ciris.edge.alm.failover.gap", Histogram, Seconds, closed("cause", FailoverCause::TOKENS), "Time this node held a stream with no primary after a failover."),
    spec("call_setup_duration_seconds", "ciris.edge.call.setup.duration", Histogram, Seconds, closed("outcome", CallSetupOutcome::TOKENS), "Join to first frame heard, or to the call's end."),
    spec("first_contact_duration_seconds", "ciris.edge.first_contact.duration", Histogram, Seconds, closed("outcome", FirstContactOutcome::TOKENS), "A first-contact request's time to its end, as the requester saw it."),
    spec("refusal_attempts", "ciris.edge.refusal.attempts", Histogram, Count, closed("disposition", DispositionLabel::TOKENS), "Refusals a row took before it landed. Sum is in refusals, not seconds."),
    spec("wake_first_round_duration_seconds", "ciris.edge.wake.first_round.duration", Histogram, Seconds, None, "A resume's time to its first completed round."),
    spec("seal_keyer_queued", "ciris.edge.seal.keyer.queued", Gauge, Count, closed("standing", StandingLabel::TOKENS), "Handshakes waiting for a worker."),
    spec("seal_keyer_workers", "ciris.edge.seal.keyer.workers", Gauge, Count, closed("state", KEYER_WORKER_STATES), "The keyer's pool: its size, and how many run. A pool of 0 is a keyer never reached."),
    spec("seal_awaiting_links", "ciris.edge.seal.awaiting.links", Gauge, Count, None, "Links awaiting a handshake."),
    spec("seal_awaiting_bytes", "ciris.edge.seal.awaiting.bytes", Gauge, Bytes, None, "Handshake bytes held for them."),
    spec("seal_held_bytes", "ciris.edge.seal.held.bytes", Gauge, Bytes, None, "Frame bytes held during keying, against 8 × `HELD_BYTES_MAX`."),
    spec("replication_reply_queued", "ciris.edge.replication.reply.queued", Gauge, Count, closed("stat", REPLY_QUEUED_STATS), "Replies in every lane, and in the fullest."),
    spec("load_tier", "ciris.edge.load.tier", Gauge, Count, None, "The service tier: 0, 1 or 2."),
    spec("load_host_pressure", "ciris.edge.load.host_pressure", Gauge, Count, None, "The host's last verdict: 0, 1 or 2."),
    spec("load_pressure_report_age_seconds", "ciris.edge.load.pressure_report_age", Gauge, Seconds, None, "Age of the host's last verdict. -1: it never spoke, and tier 0 is not a calm reading."),
    spec("load_tier_changes_total", "ciris.edge.load.tier_changes", Counter, Count, Some(("to:cause", LabelValues::Tokens)), "Tier changes, by where to and who put it there. Every key present at zero."),
    spec("shaping_enabled", "ciris.edge.shaping.enabled", Gauge, Count, None, "1 when this node offers shaping. 0 explains a silent `link_shaping` family."),
    spec("shaping_links", "ciris.edge.shaping.links", Gauge, Count, closed("kind", SHAPING_LINK_KINDS), "Shaped links: those that count toward the bound, and seat links."),
    spec("shaping_free_slots", "ciris.edge.shaping.free_slots", Gauge, Count, None, "Slots a new peer could take here."),
    spec("shaping_seat_roster_age_seconds", "ciris.edge.shaping.seat_roster.age", Gauge, Seconds, None, "Age of the last roster read that worked. -1: none has."),
    spec("shaping_frames_real_windowed", "ciris.edge.shaping.frames_real", Counter, Count, closed("class", ShapingClass::TOKENS), "Real frames, per class, per window W, rounded down to 16, only at 3 or more links."),
    spec("shaping_windows_withheld", "ciris.edge.shaping.windows_withheld", Counter, Count, closed("class", ShapingClass::TOKENS), "Windows with data that a class under 3 links did not publish."),
    spec("leviculum_events_queued", "ciris.edge.leviculum.events.queued", Gauge, Count, closed("plane", PlaneLabel::TOKENS), "Bridges `leviculum.events.queued`: events waiting for this loop."),
    spec("leviculum_events_capacity", "ciris.edge.leviculum.events.capacity", Gauge, Count, closed("plane", PlaneLabel::TOKENS), "Bridges `leviculum.events.capacity`."),
    spec("leviculum_events_dropped", "ciris.edge.leviculum.events.dropped", Counter, Count, closed("plane", PlaneLabel::TOKENS), "Bridges `leviculum.events.dropped`: events this loop did not drain in time."),
    spec("leviculum_shed_packets", "ciris.edge.leviculum.shed.packets", Counter, Count, None, "Bridges `leviculum.shed.packets`: packets shed by a per-peer breaker."),
    spec("direct_link_proposing", "ciris.edge.direct_link.proposing", Gauge, Count, None, "1 when this node proposes direct links. 0 explains a silent `direct_link` family."),
    spec("alm_active_calls", "ciris.edge.alm.active_calls", Gauge, Count, None, "Calls live on this node. 0 explains a silent ALM."),
    spec("alm_c3_peers", "ciris.edge.alm.c3_peers", Gauge, Count, None, "Call members that speak C3, across live calls."),
    spec("decision_row_unheard_total", "ciris.edge.decision_row.unheard", Counter, Count, closed("kind", &DECISION_ROW_KINDS), "Decision-row events with no receiver."),
    spec("decision_row_subscribers", "ciris.edge.decision_row.subscribers", Gauge, Count, None, "Receivers of decision-row events now. 0 explains a silent decision-row family."),
    spec("apply_refusals", "ciris.edge.apply_refusals", Counter, Count, Some(("state", LabelValues::Tokens)), "`moved_to_terminal` and `refused_then_admitted:<class>`: a refusal's life, not its reason. Every key present at zero."),
    spec("loop_last_progress_age_seconds", "ciris.edge.loop.last_progress_age", Gauge, Seconds, closed("loop", LoopName::TOKENS), "Whole seconds since each loop turned. -1: not running, a parked node included. Stamped on each loop's own cadence, not per event. Not public: a dispatcher busy with a batch turns late."),
    TelemetrySpec { exposure: Exposure::PublicSafe, ..spec("node_alive", "ciris.edge.node.alive", Gauge, Count, None, "1 when the event loop and the ladder both turned within 60 s. A bound this coarse says the node runs and nothing of its traffic: the one field for an unauthenticated route.") },
];

/// The row for a field, or `None` when it has none.
#[must_use]
pub fn spec_of(field: &str) -> Option<&'static TelemetrySpec> {
    TELEMETRY_CATALOGUE.iter().find(|s| s.field == field)
}

#[cfg(test)]
#[path = "telemetry/tests.rs"]
mod tests;
