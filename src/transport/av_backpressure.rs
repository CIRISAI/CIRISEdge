//! CIRISEdge#591 / leviculum#66 — the producer half of the backpressure
//! contract.
//!
//! # The failure this exists for
//!
//! On the canonical, one peer of 130 took every one of 34,390 dropped
//! packets in 24 h — ~24/s sustained, with no idle hour — while the other
//! 129 dropped none. A legitimate agent producer, generating into a peer
//! that was discarding everything it sent, for a day, without ever finding
//! out.
//!
//! It could not find out, and that is the design defect leviculum v0.26.0
//! and this module together close. `LinkHandle` has two send methods:
//! `try_send()` surfaces `Busy` / `PacingDelay` — which *is* Reticulum's
//! `Channel.is_ready_to_send()` as an error — and `send()` **absorbs
//! exactly those conditions**, looping with sleeps until they clear. A
//! caller on `send()` can never learn it is being throttled, because the
//! backpressure is swallowed one layer below the agent.
//!
//! leviculum now sheds before masking, keeps proofs flowing so a congested
//! peer still gets its delivery confirmations, and pushes
//! `NodeEvent::PeerCongested`. None of that helps if edge keeps generating.
//! This is the half that stops.
//!
//! # The shape is Reticulum's, deliberately
//!
//! Copied rather than invented, from `RNS/Channel.py`: an AIMD window that
//! grows by one per delivery and shrinks by one per refusal, and a backoff
//! of `1.5^(tries-1) * max(rtt*2.5, 25ms) * (queue_len + 1.5)`. Inventing a
//! different curve here would mean two independently-tuned control loops on
//! the same wire.
//!
//! # Two floors that are really the same floor
//!
//! [`TRICKLE_INTERVAL`] caps the backoff at five minutes, which is
//! deliberately leviculum's circuit-breaker cooldown ceiling. The producer's
//! trickle and the acceptor's half-open probe then meet at roughly the same
//! cadence instead of beating against each other — a producer trickling
//! faster than the acceptor probes is just generating shed packets more
//! politely.
//!
//! And the trickle is an **idle floor, not a rate limit**: real agent
//! activity calls [`PeerBackoff::on_activity`] and may attempt immediately.
//! The goal is to stop *speculative retransmission of traffic that is being
//! discarded*, never to delay work someone is actually waiting on.

use std::time::{Duration, Instant};

/// Backoff ceiling, matching leviculum's circuit-breaker cooldown ceiling
/// so producer trickle and acceptor probe land at the same cadence.
pub const TRICKLE_INTERVAL: Duration = Duration::from_secs(300);

/// Reticulum's `max(rtt*2.5, 0.025)` floor — the smallest unit of backoff
/// regardless of how fast the link looks.
pub const MIN_BACKOFF: Duration = Duration::from_millis(25);

/// Reticulum's per-try growth base.
const BACKOFF_BASE: f64 = 1.5;

/// Reticulum's RTT multiplier.
const RTT_MULTIPLIER: f64 = 2.5;

/// Reticulum's `queue_len + 1.5` term keeps a backed-up queue from being
/// retried at the same cadence as an empty one.
const QUEUE_TERM_BIAS: f64 = 1.5;

/// AIMD window bounds. One is the floor because a window of zero would
/// stop the trickle, and the trickle is what discovers recovery.
const MIN_WINDOW: u32 = 1;
const MAX_WINDOW: u32 = 16;

/// How many consecutive refusals before a frame is abandoned rather than
/// carried forever. Reticulum's `_max_tries`.
pub const MAX_TRIES: u32 = 8;

/// What a send attempt was told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// The link took the bytes.
    Delivered,
    /// The link refused: `Busy`, `PacingDelay`, or a `PeerCongested` notice
    /// for this peer. The bytes were NOT handed to the transport.
    Refused,
}

/// What the caller should do with a frame it is holding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    /// Send it now.
    Send,
    /// Hold it; the earliest sensible retry is this far away.
    Wait(Duration),
    /// Stop carrying it — [`MAX_TRIES`] consecutive refusals. Reticulum
    /// gives up on the packet rather than retrying forever, and so do we:
    /// a frame that has been refused eight times running is not one more
    /// attempt away from delivery, and holding it costs memory on the node
    /// least able to spare it.
    Abandon,
}

/// Per-peer send pacing. One of these per link the A/V dispatcher fans out
/// onto.
///
/// Deliberately free of I/O and of any clock but the one passed in, so the
/// curve can be tested at the exact points the field produces rather than
/// by sleeping.
#[derive(Debug, Clone)]
pub struct PeerBackoff {
    /// AIMD window: +1 per delivery, -1 per refusal.
    window: u32,
    /// Consecutive refusals since the last delivery.
    tries: u32,
    /// Smoothed round-trip estimate, if the caller has one.
    rtt: Option<Duration>,
    /// Earliest instant a speculative send should be attempted.
    next_attempt_at: Option<Instant>,
    /// Latched from `NodeEvent::PeerCongested` — the peer is shedding and
    /// has said so, rather than us inferring it from refusals.
    congested: bool,
}

impl Default for PeerBackoff {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerBackoff {
    /// A peer we have no reason to distrust yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            window: MAX_WINDOW,
            tries: 0,
            rtt: None,
            next_attempt_at: None,
            congested: false,
        }
    }

    /// Feed a round-trip estimate, if the transport has one. Absent this,
    /// the backoff uses [`MIN_BACKOFF`] as Reticulum does.
    pub fn observe_rtt(&mut self, rtt: Duration) {
        self.rtt = Some(rtt);
    }

    /// The current AIMD window.
    #[must_use]
    pub const fn window(&self) -> u32 {
        self.window
    }

    /// Whether leviculum has told us this peer is shedding.
    #[must_use]
    pub const fn is_congested(&self) -> bool {
        self.congested
    }

    /// Consecutive refusals since the last delivery.
    #[must_use]
    pub const fn tries(&self) -> u32 {
        self.tries
    }

    /// CIRISEdge#591 item 4 — the pushed congestion signal.
    ///
    /// Taken as authoritative rather than as a hint: `PeerCongested` is
    /// Control class precisely so it survives the load that produced it, so
    /// a `true` here is better evidence than the refusals we would
    /// otherwise have to infer from. `false` clears the latch but does NOT
    /// reset the backoff — the circuit closing means leviculum will carry
    /// traffic again, not that the peer downstream got faster.
    pub fn on_congestion_signal(&mut self, congested: bool, now: Instant) {
        self.congested = congested;
        if congested {
            // Treat it exactly as a refusal: we know we would be shed.
            self.record(SendOutcome::Refused, now);
        }
    }

    /// Record what an attempt was told, and schedule the next one.
    pub fn record(&mut self, outcome: SendOutcome, now: Instant) {
        match outcome {
            SendOutcome::Delivered => {
                self.window = (self.window + 1).min(MAX_WINDOW);
                self.tries = 0;
                self.congested = false;
                self.next_attempt_at = None;
            }
            SendOutcome::Refused => {
                self.window = self.window.saturating_sub(1).max(MIN_WINDOW);
                self.tries = self.tries.saturating_add(1);
                self.next_attempt_at = Some(now + self.backoff());
            }
        }
    }

    /// CIRISEdge#591 item 3 — real agent activity resumes immediately.
    ///
    /// The trickle paces *speculative* traffic. Someone actually waiting on
    /// a send should not be made to wait out a cooldown earned by
    /// retransmissions. This clears the schedule without touching the
    /// window or the try count, so if the attempt is refused again the
    /// backoff resumes from where it was rather than from zero — activity
    /// buys an attempt, not an amnesty.
    pub fn on_activity(&mut self) {
        self.next_attempt_at = None;
    }

    /// What to do with a frame right now.
    #[must_use]
    pub fn attempt(&self, now: Instant, queue_len: usize) -> Attempt {
        if self.tries >= MAX_TRIES {
            return Attempt::Abandon;
        }
        match self.next_attempt_at {
            Some(at) if at > now => Attempt::Wait(Self::pace(at - now, queue_len)),
            _ => Attempt::Send,
        }
    }

    /// Reticulum's curve: `1.5^(tries-1) * max(rtt*2.5, 25ms)`, capped at
    /// the trickle interval. The queue term is applied in [`Self::pace`],
    /// where the caller's queue depth is known.
    fn backoff(&self) -> Duration {
        if self.tries == 0 {
            return Duration::ZERO;
        }
        let unit = self.rtt.map_or(MIN_BACKOFF, |rtt| {
            rtt.mul_f64(RTT_MULTIPLIER).max(MIN_BACKOFF)
        });
        // `tries - 1` per Reticulum: the first retry waits one unit, not
        // 1.5 units.
        let growth = BACKOFF_BASE.powi(i32::try_from(self.tries - 1).unwrap_or(i32::MAX));
        // `mul_f64` panics on overflow/NaN; the cap has to be applied to a
        // finite number, so clamp the multiplier rather than the product.
        let bounded = growth.min(f64::from(u32::MAX));
        unit.mul_f64(bounded).min(TRICKLE_INTERVAL)
    }

    /// Apply Reticulum's `(queue_len + 1.5)` term and re-cap. A backed-up
    /// queue is retried more slowly than an empty one — retrying a deep
    /// queue at the same cadence is how a producer converts congestion into
    /// more congestion.
    fn pace(base: Duration, queue_len: usize) -> Duration {
        #[allow(clippy::cast_precision_loss)] // queue depth; precision past 2^53 is meaningless
        let term = (queue_len as f64) + QUEUE_TERM_BIAS;
        base.mul_f64(term).min(TRICKLE_INTERVAL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn a_healthy_peer_is_never_paced() {
        let mut b = PeerBackoff::new();
        let now = t0();
        for _ in 0..5 {
            b.record(SendOutcome::Delivered, now);
            assert_eq!(b.attempt(now, 0), Attempt::Send);
        }
        assert_eq!(
            b.window(),
            MAX_WINDOW,
            "delivery must not shrink the window"
        );
        assert_eq!(b.tries(), 0);
    }

    #[test]
    fn the_window_is_additive_up_and_subtractive_down() {
        let mut b = PeerBackoff::new();
        let now = t0();
        for _ in 0..4 {
            b.record(SendOutcome::Refused, now);
        }
        assert_eq!(b.window(), MAX_WINDOW - 4);
        b.record(SendOutcome::Delivered, now);
        assert_eq!(b.window(), MAX_WINDOW - 3, "+1 per delivery, not a reset");
    }

    #[test]
    fn the_window_floors_at_one_so_the_trickle_survives() {
        let mut b = PeerBackoff::new();
        let now = t0();
        for _ in 0..100 {
            b.record(SendOutcome::Refused, now);
        }
        assert_eq!(
            b.window(),
            MIN_WINDOW,
            "a zero window would stop the trickle, and the trickle is what \
             discovers recovery",
        );
    }

    #[test]
    fn backoff_grows_geometrically_and_stops_at_the_trickle() {
        let mut b = PeerBackoff::new();
        let now = t0();
        let mut last = Duration::ZERO;
        for i in 1..MAX_TRIES {
            b.record(SendOutcome::Refused, now);
            let Attempt::Wait(d) = b.attempt(now, 0) else {
                panic!("a refused peer must be paced (try {i})");
            };
            assert!(d > last, "backoff must grow: {d:?} after {last:?}");
            assert!(d <= TRICKLE_INTERVAL, "never past the trickle: {d:?}");
            last = d;
        }
    }

    #[test]
    fn a_frame_refused_max_tries_times_is_abandoned_not_carried() {
        let mut b = PeerBackoff::new();
        let now = t0();
        for _ in 0..MAX_TRIES {
            b.record(SendOutcome::Refused, now);
        }
        assert_eq!(
            b.attempt(now, 0),
            Attempt::Abandon,
            "holding a frame refused {MAX_TRIES} times running costs memory on \
             the node least able to spare it",
        );
    }

    #[test]
    fn a_deep_queue_is_retried_more_slowly_than_an_empty_one() {
        let mut b = PeerBackoff::new();
        let now = t0();
        b.record(SendOutcome::Refused, now);
        let (Attempt::Wait(shallow), Attempt::Wait(deep)) = (b.attempt(now, 0), b.attempt(now, 20))
        else {
            panic!("both must be paced");
        };
        assert!(
            deep > shallow,
            "retrying a deep queue at the same cadence converts congestion \
             into more congestion",
        );
    }

    #[test]
    fn real_activity_buys_an_attempt_but_not_an_amnesty() {
        let mut b = PeerBackoff::new();
        let now = t0();
        for _ in 0..3 {
            b.record(SendOutcome::Refused, now);
        }
        assert!(matches!(b.attempt(now, 0), Attempt::Wait(_)));

        b.on_activity();
        assert_eq!(
            b.attempt(now, 0),
            Attempt::Send,
            "the trickle is an idle floor, not a rate limit on real work",
        );
        assert_eq!(
            b.tries(),
            3,
            "the earned backoff state survives the attempt"
        );

        // Refused again → paced from where it was, not from zero.
        b.record(SendOutcome::Refused, now);
        assert_eq!(b.tries(), 4);
    }

    #[test]
    fn a_pushed_congestion_signal_paces_without_waiting_for_a_refusal() {
        let mut b = PeerBackoff::new();
        let now = t0();
        assert_eq!(b.attempt(now, 0), Attempt::Send);

        b.on_congestion_signal(true, now);
        assert!(b.is_congested());
        assert!(
            matches!(b.attempt(now, 0), Attempt::Wait(_)),
            "PeerCongested is Control class so it survives the load that \
             produced it — it is better evidence than an inferred refusal",
        );
    }

    #[test]
    fn the_circuit_closing_clears_the_latch_but_not_the_backoff() {
        let mut b = PeerBackoff::new();
        let now = t0();
        b.on_congestion_signal(true, now);
        let tries_while_congested = b.tries();

        b.on_congestion_signal(false, now);
        assert!(!b.is_congested());
        assert_eq!(
            b.tries(),
            tries_while_congested,
            "the circuit closing means leviculum will carry traffic again, \
             not that the peer downstream got faster",
        );
    }

    #[test]
    fn a_delivery_clears_everything_including_the_latch() {
        let mut b = PeerBackoff::new();
        let now = t0();
        b.on_congestion_signal(true, now);
        b.record(SendOutcome::Delivered, now);
        assert!(!b.is_congested());
        assert_eq!(b.tries(), 0);
        assert_eq!(b.attempt(now, 0), Attempt::Send);
    }

    #[test]
    fn a_fast_link_still_backs_off_at_least_the_minimum() {
        let mut b = PeerBackoff::new();
        let now = t0();
        b.observe_rtt(Duration::from_micros(200)); // rtt*2.5 = 500us < 25ms
        b.record(SendOutcome::Refused, now);
        let Attempt::Wait(d) = b.attempt(now, 0) else {
            panic!("must pace");
        };
        assert!(
            d >= MIN_BACKOFF,
            "Reticulum's max(rtt*2.5, 25ms) floor: {d:?}"
        );
    }

    #[test]
    fn a_slow_link_paces_off_its_own_rtt_not_the_floor() {
        let mut fast = PeerBackoff::new();
        let mut slow = PeerBackoff::new();
        let now = t0();
        slow.observe_rtt(Duration::from_millis(400));
        fast.record(SendOutcome::Refused, now);
        slow.record(SendOutcome::Refused, now);
        let (Attempt::Wait(f), Attempt::Wait(s)) = (fast.attempt(now, 0), slow.attempt(now, 0))
        else {
            panic!("both must pace");
        };
        assert!(s > f, "rtt*2.5 dominates once it clears the floor");
    }

    #[test]
    fn the_backoff_never_overflows_however_long_it_is_refused() {
        let mut b = PeerBackoff::new();
        let now = t0();
        // Past MAX_TRIES the verdict is Abandon, but `record` keeps
        // counting and must not panic in `mul_f64` on the way.
        for _ in 0..1_000 {
            b.record(SendOutcome::Refused, now);
        }
        assert_eq!(b.attempt(now, 0), Attempt::Abandon);
    }
}

/// CIRISEdge#591 item 4 + telemetry — node-level record of which
/// interfaces leviculum is shedding on, and how much.
///
/// #591 asks for per-peer `circuit_open` and `shed_packets` to be tracked,
/// and names the question leviculum cannot answer from its own side:
/// **does the circuit sit open continuously, or oscillate?** That decides
/// whether the cooldown ladder is tuned right, and only a consumer holding
/// the series can say. So this counts TRANSITIONS, not just current state —
/// a snapshot of `congested: true` cannot distinguish one long outage from
/// a hundred short ones, and those call for opposite fixes.
#[derive(Debug, Default)]
pub struct CongestionRegistry {
    inner: std::sync::Mutex<std::collections::BTreeMap<usize, InterfaceCongestion>>,
}

/// Per-interface congestion series.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InterfaceCongestion {
    /// Is the circuit open (shedding) right now?
    pub circuit_open: bool,
    /// Packets shed on this interface since the node started, as last
    /// reported by leviculum.
    pub shed_packets: u64,
    /// How many times the circuit has OPENED. Distinguishes one sustained
    /// outage from flapping.
    pub open_transitions: u64,
}

impl CongestionRegistry {
    /// Record a `NodeEvent::PeerCongested`.
    pub fn record(&self, interface_id: usize, congested: bool, shed_packets: u64) {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            // A poisoned lock here must not take down the event loop: this
            // is telemetry, and losing a sample is strictly better than
            // losing the reader that would have seen the rest.
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry = guard.entry(interface_id).or_default();
        if congested && !entry.circuit_open {
            entry.open_transitions = entry.open_transitions.saturating_add(1);
        }
        entry.circuit_open = congested;
        entry.shed_packets = shed_packets;
    }

    /// Snapshot every interface's series.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(usize, InterfaceCongestion)> {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.iter().map(|(k, v)| (*k, *v)).collect()
    }

    /// Is ANY interface currently shedding? The cheap question a producer
    /// asks before generating speculative traffic.
    #[must_use]
    pub fn any_congested(&self) -> bool {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.values().any(|c| c.circuit_open)
    }
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    #[test]
    fn the_registry_counts_transitions_not_just_state() {
        let r = CongestionRegistry::default();
        // One sustained outage: repeated `true` is still one opening.
        for n in 1..=5 {
            r.record(0, true, n);
        }
        let [(0, c)] = r.snapshot()[..] else {
            panic!("one interface expected")
        };
        assert_eq!(c.open_transitions, 1, "a sustained outage is ONE opening");
        assert!(c.circuit_open);
        assert_eq!(c.shed_packets, 5);

        // Flapping: three separate openings, same current state.
        let f = CongestionRegistry::default();
        for _ in 0..3 {
            f.record(1, true, 1);
            f.record(1, false, 1);
        }
        f.record(1, true, 1);
        let [(1, c)] = f.snapshot()[..] else {
            panic!("one interface expected")
        };
        assert_eq!(
            c.open_transitions, 4,
            "flapping and a sustained outage look identical in a snapshot of \
             `circuit_open` alone, and they call for opposite fixes",
        );
    }

    #[test]
    fn any_congested_answers_across_interfaces() {
        let r = CongestionRegistry::default();
        r.record(0, false, 0);
        r.record(1, false, 0);
        assert!(!r.any_congested());
        r.record(1, true, 7);
        assert!(r.any_congested());
        r.record(1, false, 9);
        assert!(!r.any_congested());
    }
}
