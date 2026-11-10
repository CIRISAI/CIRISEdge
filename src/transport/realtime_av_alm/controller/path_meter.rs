//! C1 — per-path meters.
//!
//! [`PathMeter`] sits on the RECEIVING side of one (forwarder → subscriber)
//! path and measures what that path actually delivers: rate, loss and burst
//! loss, source-to-here latency, RFC 3550
//! interarrival jitter, queue delay (latency above the path's own floor),
//! RTT, and stability. Raw counts accumulate in a window of
//! `meter_window_ms`; a closed window folds into EWMAs.
//!
//! [`EgressMeter`] sits on the SENDING side of a forwarder's uplink and turns
//! the whole uplink's accepted, refused and delivered traffic into
//! [`EgressWindow`]s carrying the uplink-level verdict of
//! `docs/AV_ALM_DESIGN.md` §5.1, the input admission ([`super::admission`])
//! learns its capacity ceiling from. In production its inputs are every
//! leg's sends and `Busy`/`PacingDelay`/expiry refusals, and each link's
//! `bytes_delivered` deltas (leviculum#35).
//!
//! Silence is NOT loss here: a path that delivers nothing has no gaps.
//! Silence is the peer-state machine's input ([`super::peer_state`]).
//!
//! **Loss is never read from `chunk_seq`.** Every layer of a stream spends the
//! one sequence, so a gap says only that some chunk existed. A standby never
//! gets the layers above the base, a leg shed or capped at the base layer
//! does not either, and a publisher at service tier 2 seals its layers and
//! sends them to nobody: on the receiver those gaps look exactly like loss.
//! The filter sits on the sender and no frame names it. Loss comes from two
//! things the receiver does hold instead, both within what the path owed:
//!
//! 1. **The hop counter.** A link's counter is dense over what its sender put
//!    on it: it advances past nothing the policy in force filtered and nothing
//!    the link refused. A gap in it is a chunk that policy admitted and that
//!    never arrived, whatever its layer.
//! 2. **The other path.** A base-or-audio chunk one subscribed parent delivered
//!    that this one, in order, went past ([`PathMeter::expect_base`]). Every
//!    policy admits the base and audio, so every path owes them. This sees what
//!    the hop counter cannot: a chunk the sender never sent, because it was
//!    refused by its own link or lost upstream of a relay.
//!
//! The two read different populations, so each is measured against its own
//! (hops against chunks, base and audio against base and audio), and a window's
//! loss is the worse of them: one lost chunk may show in both.
//!
//! What this leaves unseen: a chunk never sent, on a path with no second path
//! to compare, and one every path lost. With no second path there is nothing
//! to move to either, so no selector decision rests on that reading.

use std::collections::VecDeque;

/// A smoothed view of one path, as of the last closed window.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PathSnapshot {
    /// Closed windows folded so far.
    pub windows: u32,
    /// Smoothed delivered rate (bits/s).
    pub delivered_bps: f64,
    /// Smoothed loss fraction.
    pub loss: f64,
    /// Smoothed fraction of windows that saw a burst (≥ 3 consecutive lost).
    pub burst: f64,
    /// Smoothed source-to-here latency (ms).
    pub latency_ms: f64,
    /// RFC 3550 interarrival jitter (ms).
    pub jitter_ms: f64,
    /// Smoothed queue delay: latency above this path's floor (ms).
    pub queue_delay_ms: f64,
    /// Smoothed RTT (ms), 0 if never sampled.
    pub rtt_ms: f64,
    /// 1 − normalised spread of the last windows' loss (1 = steady).
    pub stability: f64,
}

/// Where a chunk sits in its stream, ordered by epoch, then sequence.
///
/// `chunk_seq` is epoch-local: it restarts at every epoch roll (#846), so
/// sequence numbers compare only within one epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChunkPos {
    /// The room epoch it was sealed in.
    pub epoch: u64,
    /// Its epoch-local sequence number.
    pub seq: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct Acc {
    bytes: u64,
    chunks: u64,
    /// Chunks this path was sent and never delivered.
    hop_lost: u64,
    /// Base-or-audio chunks this path delivered.
    base: u64,
    /// Base-or-audio chunks the other path delivered and this one went past.
    base_lost: u64,
    burst: bool,
    latency_sum: f64,
}

/// Burst threshold: this many consecutive lost chunks is a burst.
pub const BURST_RUN: u64 = 3;

const STABILITY_WINDOWS: usize = 4;

/// Base chunks a path remembers, each way: more than any lag between two
/// parents, so a chunk falling out of either list is old.
const BASE_TRACKED: usize = 256;

/// C1 receive-side meter for one path.
#[derive(Debug, Clone)]
pub struct PathMeter {
    window_ms: u64,
    alpha: f64,
    window_start: Option<u64>,
    acc: Acc,
    highest: Option<ChunkPos>,
    last_arrival_ms: Option<u64>,
    last_latency: Option<f64>,
    min_latency: Option<f64>,
    recent_loss: [f64; STABILITY_WINDOWS],
    /// Base chunks the other path delivered, ahead of this path, in order.
    base_owed: VecDeque<ChunkPos>,
    /// Base chunks this path delivered, in order.
    base_delivered: VecDeque<ChunkPos>,
    snap: PathSnapshot,
}

fn ewma(old: f64, new: f64, alpha: f64, first: bool) -> f64 {
    if first {
        new
    } else {
        alpha.mul_add(new - old, old)
    }
}

impl PathMeter {
    /// A meter with the given window and EWMA weight.
    #[must_use]
    pub fn new(window_ms: u64, alpha: f64) -> Self {
        Self {
            window_ms: window_ms.max(1),
            alpha,
            window_start: None,
            acc: Acc::default(),
            highest: None,
            last_arrival_ms: None,
            last_latency: None,
            min_latency: None,
            recent_loss: [0.0; STABILITY_WINDOWS],
            base_owed: VecDeque::new(),
            base_delivered: VecDeque::new(),
            snap: PathSnapshot {
                windows: 0,
                delivered_bps: 0.0,
                loss: 0.0,
                burst: 0.0,
                latency_ms: 0.0,
                jitter_ms: 0.0,
                queue_delay_ms: 0.0,
                rtt_ms: 0.0,
                stability: 1.0,
            },
        }
    }

    /// One chunk arrived on this path. `base_or_audio` is its own class, from
    /// its layer and codec; `hop_lost` is how many chunks its sender put on
    /// this link ahead of it that never arrived. `latency_ms` is
    /// source-to-here (the sim knows it; production uses the arrival lag
    /// behind the earliest copy plus the forwarder's advertised upstream
    /// latency).
    ///
    /// A chunk at or behind this path's position reads as reordered, across
    /// an epoch roll too. Returns whether the chunk was new on this path.
    pub fn on_chunk(
        &mut self,
        now_ms: u64,
        pos: ChunkPos,
        base_or_audio: bool,
        hop_lost: u64,
        bytes: u64,
        latency_ms: f64,
    ) -> bool {
        self.window_start.get_or_insert(now_ms);
        self.acc.hop_lost += hop_lost;
        if hop_lost >= BURST_RUN {
            self.acc.burst = true;
        }
        if self.highest.is_some_and(|h| pos <= h) {
            return false;
        }
        self.highest = Some(pos);
        self.acc.bytes += bytes;
        self.acc.chunks += 1;
        self.settle_base(pos, base_or_audio);
        self.acc.latency_sum += latency_ms;
        if let Some(prev) = self.last_latency {
            let d = (latency_ms - prev).abs();
            self.snap.jitter_ms += (d - self.snap.jitter_ms) / 16.0;
        }
        self.last_latency = Some(latency_ms);
        self.min_latency = Some(self.min_latency.map_or(latency_ms, |m| m.min(latency_ms)));
        self.last_arrival_ms = Some(now_ms);
        true
    }

    /// This path delivered `pos`, in order: whatever it still owed before
    /// `pos` it went past, and that is loss.
    fn settle_base(&mut self, pos: ChunkPos, base_or_audio: bool) {
        let mut run = 0;
        while let Some(owed) = self.base_owed.front().copied().filter(|o| *o <= pos) {
            self.base_owed.pop_front();
            if owed < pos {
                self.acc.base_lost += 1;
                run += 1;
            }
        }
        if run >= BURST_RUN {
            self.acc.burst = true;
        }
        if base_or_audio {
            self.acc.base += 1;
            self.base_delivered.push_back(pos);
            if self.base_delivered.len() > BASE_TRACKED {
                self.base_delivered.pop_front();
            }
        }
    }

    /// The other subscribed path delivered the base-or-audio chunk `pos`: this
    /// path owes it too. What matters is order, not timing, so no lag between
    /// the two parents reads as loss, either way round. A path owes nothing
    /// from before its first chunk since it (re)started.
    pub fn expect_base(&mut self, pos: ChunkPos) {
        let Some(highest) = self.highest else {
            return;
        };
        if pos > highest {
            self.base_owed.push_back(pos);
            if self.base_owed.len() > BASE_TRACKED {
                self.base_owed.pop_front();
                self.acc.base_lost += 1;
            }
        } else if self.base_delivered.front().is_some_and(|f| pos > *f)
            && self.base_delivered.binary_search(&pos).is_err()
        {
            // This path is ahead of the other, and went past it.
            self.acc.base_lost += 1;
        }
    }

    /// An RTT sample (heartbeat / link stats).
    pub fn on_rtt(&mut self, rtt_ms: f64) {
        self.snap.rtt_ms = if self.snap.rtt_ms <= 0.0 {
            rtt_ms
        } else {
            0.125f64.mul_add(rtt_ms - self.snap.rtt_ms, self.snap.rtt_ms)
        };
    }

    /// Forget sequence continuity (the subscription restarted: a gap across
    /// an unsubscribed interval is not loss).
    pub fn restart(&mut self) {
        self.highest = None;
        self.last_latency = None;
        self.base_owed.clear();
        self.base_delivered.clear();
    }

    /// Close every window that ended at or before `now_ms`. Returns `true`
    /// if at least one window closed.
    #[allow(clippy::cast_precision_loss)]
    pub fn roll(&mut self, now_ms: u64) -> bool {
        let Some(start) = self.window_start else {
            return false;
        };
        if now_ms < start + self.window_ms {
            return false;
        }
        let a = std::mem::take(&mut self.acc);
        let first = self.snap.windows == 0;
        let bps = a.bytes as f64 * 8.0 * 1000.0 / self.window_ms as f64;
        let share = |lost: u64, delivered: u64| {
            let total = lost + delivered;
            if total == 0 {
                0.0
            } else {
                lost as f64 / total as f64
            }
        };
        let loss = share(a.hop_lost, a.chunks).max(share(a.base_lost, a.base));
        let s = &mut self.snap;
        s.delivered_bps = ewma(s.delivered_bps, bps, self.alpha, first);
        s.loss = ewma(s.loss, loss, self.alpha, first);
        s.burst = ewma(s.burst, if a.burst { 1.0 } else { 0.0 }, self.alpha, first);
        if a.chunks > 0 {
            let lat = a.latency_sum / a.chunks as f64;
            let had_latency = s.latency_ms > 0.0;
            s.latency_ms = ewma(s.latency_ms, lat, self.alpha, !had_latency);
            let q = (lat - self.min_latency.unwrap_or(lat)).max(0.0);
            s.queue_delay_ms = ewma(s.queue_delay_ms, q, self.alpha, !had_latency);
        }
        self.recent_loss.rotate_right(1);
        self.recent_loss[0] = loss;
        let n = (s.windows as usize + 1).min(STABILITY_WINDOWS);
        let w = &self.recent_loss[..n];
        let mean = w.iter().sum::<f64>() / n as f64;
        let spread = w.iter().map(|x| (x - mean).abs()).sum::<f64>() / n as f64;
        s.stability = (1.0 - spread * 10.0).clamp(0.0, 1.0);
        s.windows += 1;
        // Skip whole empty windows rather than closing them one by one.
        let elapsed = now_ms - start;
        self.window_start = Some(start + (elapsed / self.window_ms) * self.window_ms);
        true
    }

    /// The smoothed view as of the last closed window.
    #[must_use]
    pub fn snapshot(&self) -> PathSnapshot {
        self.snap
    }

    /// When this path last delivered anything.
    #[must_use]
    pub fn last_arrival_ms(&self) -> Option<u64> {
        self.last_arrival_ms
    }
}

/// One closed egress window of a forwarder's uplink.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EgressWindow {
    /// Bits/s the uplink accepted.
    pub sent_bps: f64,
    /// Bits/s the uplink's links confirmed delivered (leviculum#35
    /// `bytes_delivered` deltas; a leg with no delivery proof, a datagram
    /// leg, counts what it accepted).
    pub delivered_bps: f64,
    /// Bytes refused by the uplink (queue full / Busy / expired unconfirmed).
    pub dropped_bytes: u64,
    /// Worst queue delay sampled (ms). Telemetry only: a slow leg's queue is
    /// that leg's, not the uplink's.
    pub max_queue_ms: f64,
    /// The meter's verdict over its trailing span: the UPLINK is the
    /// bottleneck (`docs/AV_ALM_DESIGN.md` §5.1). See [`EgressMeter`].
    pub congested: bool,
    /// What the uplink demonstrably carries when [`Self::congested`]: the p10
    /// delivery rate of the span's backpressured windows, in the units
    /// commitments are priced in, times [`UPLINK_SAFETY_MARGIN`]. `None` when
    /// not congested.
    pub capacity_bps: Option<f64>,
}

/// The span (ms) the uplink verdict and its p10 are taken over (§5.1).
pub const UPLINK_SPAN_MS: u64 = 30_000;
/// Windows the span must hold before any verdict: a call's first seconds
/// (KEX, binding parts, a join burst) are no measurement.
pub const UPLINK_MIN_WINDOWS: usize = 5;
/// Share of the span's offered frames the uplink refused, at or above which
/// the uplink (not a moment, not one leg) is the bottleneck. A stalled
/// receiver or a busy host refuses a frame or two while it catches up; a
/// rate cap refuses its excess every window.
pub const UPLINK_REFUSED_SHARE: f64 = 0.05;
/// Distinct windows of the span with a refusal: one burst is not a cap.
pub const UPLINK_REFUSAL_WINDOWS: usize = 3;
/// The percentile of the backpressured windows' delivery rate (§5.1: "sign
/// the rate I virtually always meet").
pub const UPLINK_PERCENTILE: f64 = 10.0;
/// The margin on the demonstrated rate (§5.1, §6 "give grace, stay safe").
pub const UPLINK_SAFETY_MARGIN: f64 = 0.75;

/// One closed window as the span keeps it.
#[derive(Debug, Clone, Copy, Default)]
struct SpanWindow {
    sent_bytes: u64,
    delivered_bytes: u64,
    sent_frames: u64,
    refused_frames: u64,
}

/// C1 send-side meter for a forwarder's uplink: the aggregate across every
/// leg, the uplink-level verdict of `docs/AV_ALM_DESIGN.md` §5.1.
///
/// - **Inputs** per window: bytes and frames accepted ([`Self::on_sent`]),
///   frames refused or expired ([`Self::on_dropped`]), and bytes the links
///   confirmed delivered ([`Self::on_delivered`]).
/// - **App-limited windows are excluded**: a window in which nothing was
///   refused sent everything the app had, so its rate is a floor, never a
///   ceiling sample.
/// - **The verdict is the span's**, not a window's or a leg's: over the
///   trailing [`UPLINK_SPAN_MS`], at least [`UPLINK_REFUSED_SHARE`] of the
///   offered frames refused, in at least [`UPLINK_REFUSAL_WINDOWS`] windows,
///   with [`UPLINK_MIN_WINDOWS`] in the span. A stall (a busy host, a peer
///   slow to ack) delays delivery and refuses little; a cap refuses its
///   excess every window.
/// - **The capacity is the p10** of the backpressured windows' delivery rate,
///   rescaled to accepted (plaintext) units by the span's accepted/delivered
///   ratio, times [`UPLINK_SAFETY_MARGIN`]. It is recomputed every window,
///   so it rises with the uplink as well as falls.
///
/// No queue-delay threshold and no per-leg bit enters the verdict: a slow
/// leg is C5's (that leg sheds to its base layer) and its child's own C1's.
#[derive(Debug, Clone)]
pub struct EgressMeter {
    window_ms: u64,
    window_start: Option<u64>,
    cur: SpanWindow,
    max_queue: f64,
    dropped_bytes: u64,
    span: std::collections::VecDeque<SpanWindow>,
}

impl EgressMeter {
    /// A meter with the given window. `_congestion_queue_ms` is kept for the
    /// config's shape; queue delay no longer decides a verdict.
    #[must_use]
    pub fn new(window_ms: u64, _congestion_queue_ms: u64) -> Self {
        Self {
            window_ms: window_ms.max(1),
            window_start: None,
            cur: SpanWindow::default(),
            max_queue: 0.0,
            dropped_bytes: 0,
            span: std::collections::VecDeque::new(),
        }
    }

    fn span_windows(&self) -> usize {
        usize::try_from(UPLINK_SPAN_MS / self.window_ms)
            .unwrap_or(usize::MAX)
            .max(1)
    }

    /// Bytes accepted onto the uplink; `queue_ms` is the queue delay they saw.
    pub fn on_sent(&mut self, now_ms: u64, bytes: u64, queue_ms: f64) {
        self.window_start.get_or_insert(now_ms);
        self.cur.sent_bytes += bytes;
        self.cur.sent_frames += 1;
        self.max_queue = self.max_queue.max(queue_ms);
    }

    /// A frame of `bytes` the uplink refused (or that expired unconfirmed).
    pub fn on_dropped(&mut self, now_ms: u64, bytes: u64) {
        self.window_start.get_or_insert(now_ms);
        self.dropped_bytes += bytes;
        self.cur.refused_frames += 1;
    }

    /// Bytes the uplink's links confirmed delivered since the last call.
    pub fn on_delivered(&mut self, now_ms: u64, bytes: u64) {
        self.window_start.get_or_insert(now_ms);
        self.cur.delivered_bytes += bytes;
    }

    /// Close the current window if it ended. Empty-window gaps are skipped.
    #[allow(clippy::cast_precision_loss)]
    pub fn roll(&mut self, now_ms: u64) -> Option<EgressWindow> {
        let start = self.window_start?;
        if now_ms < start + self.window_ms {
            return None;
        }
        let secs = self.window_ms as f64 / 1_000.0;
        let closed = std::mem::take(&mut self.cur);
        self.span.push_back(closed);
        while self.span.len() > self.span_windows() {
            self.span.pop_front();
        }
        let capacity_bps = self.verdict();
        let w = EgressWindow {
            sent_bps: closed.sent_bytes as f64 * 8.0 / secs,
            delivered_bps: closed.delivered_bytes as f64 * 8.0 / secs,
            dropped_bytes: self.dropped_bytes,
            max_queue_ms: self.max_queue,
            congested: capacity_bps.is_some(),
            capacity_bps,
        };
        self.dropped_bytes = 0;
        self.max_queue = 0.0;
        let elapsed = now_ms - start;
        self.window_start = Some(start + (elapsed / self.window_ms) * self.window_ms);
        Some(w)
    }

    /// The span's verdict: the uplink's demonstrated capacity when it is the
    /// bottleneck, `None` otherwise.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn verdict(&self) -> Option<f64> {
        if self.span.len() < UPLINK_MIN_WINDOWS {
            return None;
        }
        let (mut sent_f, mut refused_f, mut sent_b, mut deliv_b) = (0u64, 0u64, 0u64, 0u64);
        for w in &self.span {
            sent_f += w.sent_frames;
            refused_f += w.refused_frames;
            sent_b += w.sent_bytes;
            deliv_b += w.delivered_bytes;
        }
        let offered = sent_f + refused_f;
        let refusal_windows = self.span.iter().filter(|w| w.refused_frames > 0).count();
        if offered == 0
            || (refused_f as f64) < UPLINK_REFUSED_SHARE * offered as f64
            || refusal_windows < UPLINK_REFUSAL_WINDOWS
        {
            return None;
        }
        // Delivered bytes carry the link's own framing; commitments are
        // priced in what the call layer sends. One ratio per span converts.
        let to_sent_units = if deliv_b > 0 {
            sent_b as f64 / deliv_b as f64
        } else {
            1.0
        };
        let secs = self.window_ms as f64 / 1_000.0;
        let mut rates: Vec<f64> = self
            .span
            .iter()
            .filter(|w| w.refused_frames > 0)
            .map(|w| w.delivered_bytes as f64 * 8.0 / secs * to_sent_units)
            .collect();
        rates.sort_by(f64::total_cmp);
        // Nearest rank: at small n the p10 is the minimum (claims less, never
        // more, as observability drops).
        let rank = ((UPLINK_PERCENTILE / 100.0) * rates.len() as f64).ceil() as usize;
        let p10 = rates[rank.clamp(1, rates.len()) - 1];
        Some(UPLINK_SAFETY_MARGIN * p10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(epoch: u64, seq: u64) -> ChunkPos {
        ChunkPos { epoch, seq }
    }

    #[test]
    fn meter_counts_hop_gaps_bursts_and_rate() {
        let mut m = PathMeter::new(1_000, 1.0);
        for seq in 0..10 {
            m.on_chunk(seq * 50, at(1, seq), true, 0, 1_000, 40.0);
        }
        // seq 10..=13 lost (burst of 4), then 14..19 arrive.
        for seq in 14..20 {
            let lost = if seq == 14 { 4 } else { 0 };
            m.on_chunk(seq * 50, at(1, seq), true, lost, 1_000, 40.0);
        }
        assert!(m.roll(1_000));
        let s = m.snapshot();
        assert_eq!(s.windows, 1);
        assert!((s.loss - 4.0 / 20.0).abs() < 1e-9, "loss {}", s.loss);
        assert!((s.burst - 1.0).abs() < 1e-9);
        assert!((s.delivered_bps - 16.0 * 8_000.0).abs() < 1e-6);
        assert!((s.latency_ms - 40.0).abs() < 1e-9);
    }

    #[test]
    fn silence_is_not_loss_and_restart_forgets_continuity() {
        let mut m = PathMeter::new(1_000, 1.0);
        m.on_chunk(0, at(1, 5), true, 0, 100, 10.0);
        m.restart();
        m.on_chunk(10, at(1, 50), true, 0, 100, 10.0);
        assert!(m.roll(5_000));
        assert!(m.snapshot().loss.abs() < 1e-12);
    }

    /// #945 item 1: `chunk_seq` restarts at a roll, so the jump is no gap. A
    /// gap inside the new epoch still is, and an old epoch's straggler is
    /// reordered, not a rewind that would forgive the next gap.
    #[test]
    fn an_epoch_change_resyncs_and_a_straggler_changes_nothing() {
        let mut m = PathMeter::new(1_000, 1.0);
        for seq in 900..950 {
            m.on_chunk(seq - 900, at(1, seq), true, 0, 100, 10.0);
        }
        for seq in 0..50 {
            m.on_chunk(50 + seq, at(2, seq), true, 0, 100, 10.0);
        }
        assert!(m.roll(1_000));
        let s = m.snapshot();
        assert!(s.loss.abs() < 1e-12, "a roll is no loss: {}", s.loss);
        assert!(s.burst.abs() < 1e-12, "a roll is no burst: {}", s.burst);

        m.on_chunk(1_000, at(1, 950), true, 0, 100, 10.0);
        m.on_chunk(1_001, at(2, 50), true, 0, 100, 10.0);
        m.on_chunk(1_002, at(2, 52), true, 1, 100, 10.0);
        assert!(m.roll(2_000));
        assert!(
            (m.snapshot().loss - 1.0 / 3.0).abs() < 1e-9,
            "one gap in the new epoch, the straggler uncounted: {}",
            m.snapshot().loss
        );
    }

    /// #945 item 3: a standby's gaps are layers it never owed, and what it
    /// really lost is what the primary delivered and it went past. The
    /// primary here leads, so `expect_base` comes first.
    #[test]
    fn a_base_only_path_reads_no_gaps_and_real_shortfalls() {
        let mut m = PathMeter::new(1_000, 1.0);
        m.on_chunk(0, at(1, 0), true, 0, 100, 10.0);
        // One base chunk in three: every gap here is two skipped layers.
        for k in 1..30 {
            m.expect_base(at(1, k * 3));
            m.on_chunk(k * 30, at(1, k * 3), true, 0, 100, 10.0);
        }
        assert!(m.roll(1_000));
        let s = m.snapshot();
        assert!(s.loss.abs() < 1e-12, "skipped layers: {}", s.loss);
        assert!(s.burst.abs() < 1e-12, "no burst: {}", s.burst);
        // Now it misses one in three of what the primary delivered.
        for k in 30..60 {
            m.expect_base(at(1, k * 3));
            if k % 3 != 0 {
                m.on_chunk(k * 30, at(1, k * 3), true, 0, 100, 10.0);
            }
        }
        assert!(m.roll(2_000));
        assert!(
            (m.snapshot().loss - 1.0 / 3.0).abs() < 0.05,
            "the shortfall is the loss: {}",
            m.snapshot().loss
        );
    }

    /// #945 item 3: a lag behind the primary is no loss whatever it does,
    /// nor is being ahead of it, and each way a chunk really skipped is.
    #[test]
    fn a_base_only_path_reads_order_not_timing() {
        // Behind, by a lag that swings from 8 chunks to 1 across a window
        // edge: 8 owed at the close are delivered in the next window.
        let mut m = PathMeter::new(1_000, 1.0);
        m.on_chunk(0, at(1, 0), true, 0, 100, 10.0);
        for k in 1..=8 {
            m.expect_base(at(1, k));
        }
        assert!(m.roll(1_000));
        for k in 1..=8 {
            m.on_chunk(1_000 + k, at(1, k), true, 0, 100, 10.0);
        }
        assert!(m.roll(2_000));
        assert!(m.snapshot().loss.abs() < 1e-12, "{}", m.snapshot().loss);

        // Ahead: 20 delivered, the primary follows, one was skipped here.
        let mut m = PathMeter::new(1_000, 1.0);
        for k in (0..20).filter(|k| *k != 7) {
            m.on_chunk(k, at(1, k), true, 0, 100, 10.0);
        }
        for k in 0..20 {
            m.expect_base(at(1, k));
        }
        assert!(m.roll(1_000));
        assert!((m.snapshot().loss - 1.0 / 20.0).abs() < 1e-9);
    }

    /// #945 item 3: a path owes nothing from before its first chunk: the
    /// primary's lead at a join, and whatever it delivers from behind it.
    #[test]
    fn a_base_only_path_owes_nothing_from_before_it_started() {
        let mut m = PathMeter::new(1_000, 1.0);
        for k in 0..8 {
            m.expect_base(at(1, k));
        }
        m.on_chunk(0, at(1, 20), true, 0, 100, 10.0);
        m.expect_base(at(1, 15));
        for k in 21..40 {
            m.on_chunk(k, at(1, k), true, 0, 100, 10.0);
        }
        assert!(m.roll(1_000));
        assert!(m.snapshot().loss.abs() < 1e-12);
    }

    /// #945: a `chunk_seq` gap alone proves nothing on any path, however
    /// long and whatever layers arrive around it.
    #[test]
    fn a_sequence_gap_is_not_loss() {
        let mut m = PathMeter::new(1_000, 1.0);
        for k in 0..30 {
            m.on_chunk(k * 30, at(1, k * 10), k % 2 == 0, 0, 100, 10.0);
        }
        assert!(m.roll(1_000));
        assert!(m.snapshot().loss.abs() < 1e-12, "{}", m.snapshot().loss);
        assert!(m.snapshot().burst.abs() < 1e-12);
    }

    /// #945: base chunks are measured against base chunks. One in four lost
    /// among nine layers each is a quarter of what every policy admits, not
    /// the 2 % of everything that arrived.
    #[test]
    fn base_loss_is_not_diluted_by_the_layers_above() {
        let mut m = PathMeter::new(1_000, 1.0);
        let mut seq = 0;
        for k in 0..40 {
            m.expect_base(at(1, seq));
            if k % 4 != 3 {
                m.on_chunk(seq, at(1, seq), true, 0, 100, 10.0);
            }
            for layer in 1..10 {
                m.on_chunk(seq + layer, at(1, seq + layer), false, 0, 100, 10.0);
            }
            seq += 10;
        }
        assert!(m.roll(1_000));
        let loss = m.snapshot().loss;
        assert!((loss - 0.25).abs() < 0.03, "{loss}");
    }

    /// #945: three base chunks gone in a row is a burst, read either way.
    #[test]
    fn a_run_of_base_chunks_or_hops_is_a_burst() {
        let mut m = PathMeter::new(1_000, 1.0);
        m.on_chunk(0, at(1, 0), true, 0, 100, 10.0);
        for k in 1..=3 {
            m.expect_base(at(1, k));
        }
        m.on_chunk(1, at(1, 4), true, 0, 100, 10.0);
        assert!(m.roll(1_000));
        assert!((m.snapshot().burst - 1.0).abs() < 1e-9);

        let mut m = PathMeter::new(1_000, 1.0);
        m.on_chunk(0, at(1, 0), false, BURST_RUN, 100, 10.0);
        assert!(m.roll(1_000));
        assert!((m.snapshot().burst - 1.0).abs() < 1e-9);
    }

    /// One uplink second: `frames` sent of `bytes` each, `refused` of them
    /// refused, and `delivered` bytes confirmed.
    fn second(
        e: &mut EgressMeter,
        t: u64,
        frames: u64,
        bytes: u64,
        refused: u64,
        delivered: u64,
    ) -> EgressWindow {
        for _ in 0..frames {
            e.on_sent(t, bytes, 0.0);
        }
        for _ in 0..refused {
            e.on_dropped(t, bytes);
        }
        e.on_delivered(t, delivered);
        e.roll(t + 1_000).expect("a window")
    }

    #[test]
    fn egress_reports_its_rates() {
        let mut e = EgressMeter::new(1_000, 100);
        let w = second(&mut e, 0, 100, 1_250, 0, 1_250 * 100);
        assert!(!w.congested);
        assert!((w.sent_bps - 1_000_000.0).abs() < 1e-6);
        assert!((w.delivered_bps - 1_000_000.0).abs() < 1e-6);
        assert_eq!(w.capacity_bps, None);
    }

    /// The avmesh4rel shape, at the meter (release build, quiet box, no rate
    /// limit anywhere): every window's queue delay over the old 150 ms bar
    /// and a frame refused now and then while a slow peer catches up. Only
    /// the inputs the v45.0.0 meter had, so this reads red on it. Mutation
    /// (v45.0.0): a refusal or a 150 ms queue made the window congested, and
    /// two such made a ceiling: m0 learned 647808 → 464440 bps in 5 s.
    #[test]
    fn a_stall_is_not_a_ceiling() {
        let mut e = EgressMeter::new(1_000, 150);
        for t in 0..60u64 {
            // 90 frames/s; seconds 10-12 of every 20 one refusal each.
            for _ in 0..90 {
                e.on_sent(t * 1_000, 300, 400.0);
            }
            if (10..=12).contains(&(t % 20)) {
                e.on_dropped(t * 1_000, 300);
            }
            let w = e.roll(t * 1_000 + 1_000).expect("a window");
            assert!(!w.congested, "second {t}: a stall is no capacity verdict");
        }
    }

    /// The avmesh4rel regression (release build, quiet box, every ALM
    /// decision kept): v45.0.0's m0 learned ceilings 647808, 601024, 611040,
    /// 547696, 464440 bps one second apart (07:25:27-31), went stale at
    /// 07:26:01 and learned 451200 at 07:26:04. Its rule was c1 = s1, then
    /// c(n) = c(n-1) + (s(n) - c(n-1))/2, so the windows sent 647808, 554240,
    /// 621056, 484352, 381184 and 451200 bps. Every one was flagged by queue
    /// delay (m0 refused 6 frames in the whole run). Fed here with the WORST
    /// member's whole-run refusals (m3, 43) all inside those six seconds and
    /// the backed-up queue in every window, the meter learns no ceiling.
    #[test]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn the_avmesh4rel_trace_learns_no_ceiling() {
        const FRAME: u64 = 300;
        let trace = [647_808u64, 554_240, 621_056, 484_352, 381_184, 451_200];
        let mut e = EgressMeter::new(1_000, 150);
        let mut refusals = 43u64;
        let mut t = 0u64;
        // The 30 s span holds the run's first seconds too, clean.
        for _ in 0..20 {
            let w = second(&mut e, t, 270, FRAME, 0, 270 * FRAME);
            assert!(!w.congested);
            t += 1_000;
        }
        for (i, bps) in trace.iter().enumerate() {
            let frames = bps / 8 / FRAME;
            let refused = if i + 1 == trace.len() { refusals } else { 8 };
            refusals -= refused;
            for _ in 0..frames {
                e.on_sent(t, FRAME, 400.0);
            }
            for _ in 0..refused {
                e.on_dropped(t, FRAME);
            }
            e.on_delivered(t, frames * FRAME);
            let w = e.roll(t + 1_000).expect("a window");
            assert!(!w.congested, "trace second {i} ({bps} bps): no ceiling");
            assert_eq!(w.capacity_bps, None);
            t += 1_000;
        }
        assert_eq!(refusals, 0, "all 43 were fed");
    }

    /// A real cap: 9 streams offered into 5, every window refusing the excess.
    /// The verdict comes once the span holds its windows, at what the uplink
    /// delivered, with the margin.
    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn a_rate_cap_is_a_ceiling_at_its_delivered_rate() {
        let mut e = EgressMeter::new(1_000, 150);
        let mut first = None;
        for t in 0..10u64 {
            let w = second(&mut e, t * 1_000, 50, 300, 40, 50 * 300);
            if w.congested && first.is_none() {
                first = Some(t);
                let cap = w
                    .capacity_bps
                    .expect("a congested window carries its capacity");
                let delivered = 50.0 * 300.0 * 8.0;
                assert!(
                    (cap - UPLINK_SAFETY_MARGIN * delivered).abs() < 1e-6,
                    "{cap}"
                );
            }
        }
        assert_eq!(
            first,
            Some(UPLINK_MIN_WINDOWS as u64 - 1),
            "after the span's minimum"
        );
    }

    /// The ceiling follows the uplink up as well as down: once the cap
    /// loosens, the backpressured windows deliver more and the p10 rises as
    /// the tighter windows leave the span.
    #[test]
    fn the_capacity_rises_with_the_uplink() {
        let mut e = EgressMeter::new(1_000, 150);
        let mut last = 0.0;
        for t in 0..10u64 {
            last = second(&mut e, t * 1_000, 50, 300, 40, 50 * 300)
                .capacity_bps
                .unwrap_or(last);
        }
        let tight = last;
        for t in 10..45u64 {
            last = second(&mut e, t * 1_000, 70, 300, 20, 70 * 300)
                .capacity_bps
                .unwrap_or(last);
        }
        assert!(last > tight * 1.3, "{tight} -> {last}");
    }

    /// Delivered bytes carry the link's framing: the capacity is reported in
    /// the units the call layer sends (and prices commitments) in.
    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn the_capacity_is_in_sent_units() {
        let mut e = EgressMeter::new(1_000, 150);
        let mut w = None;
        for t in 0..UPLINK_MIN_WINDOWS as u64 {
            // Every delivered byte reads 1.25 on the link.
            w = Some(second(&mut e, t * 1_000, 50, 300, 40, 50 * 375));
        }
        let cap = w.and_then(|w| w.capacity_bps).expect("a verdict");
        assert!(
            (cap - UPLINK_SAFETY_MARGIN * 50.0 * 300.0 * 8.0).abs() < 1e-6,
            "{cap}"
        );
    }
}
