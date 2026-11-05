//! C1 — per-path meters.
//!
//! [`PathMeter`] sits on the RECEIVING side of one (forwarder → subscriber)
//! path and measures what that path actually delivers: rate, loss and burst
//! loss (from per-path sequence gaps), source-to-here latency, RFC 3550
//! interarrival jitter, queue delay (latency above the path's own floor),
//! RTT, and stability. Raw counts accumulate in a window of
//! `meter_window_ms`; a closed window folds into EWMAs.
//!
//! [`EgressMeter`] sits on the SENDING side of a forwarder's uplink and turns
//! sent/dropped bytes and queue-delay samples into [`EgressWindow`]s, the
//! input admission ([`super::admission`]) learns its capacity ceiling from.
//! In production its inputs are `LinkCounters` diffs per link (sent bytes,
//! Busy/PacingDelay rejections) and `LegOutcome::Congested` streaks.
//!
//! Silence is NOT loss here: a path that delivers nothing has no gaps.
//! Silence is the peer-state machine's input ([`super::peer_state`]).

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
    lost: u64,
    burst: bool,
    latency_sum: f64,
}

/// Burst threshold: this many consecutive lost chunks is a burst.
pub const BURST_RUN: u64 = 3;

const STABILITY_WINDOWS: usize = 4;

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

    /// One chunk arrived on this path. `latency_ms` is source-to-here (the
    /// sim knows it; production uses the arrival lag behind the earliest copy
    /// plus the forwarder's advertised upstream latency).
    ///
    /// A chunk of a newer epoch is a resync, not a gap: its sequence number
    /// restarted and says nothing about the old epoch's tail. A straggler
    /// from an older epoch reads as reordered.
    #[allow(clippy::cast_precision_loss)]
    pub fn on_chunk(&mut self, now_ms: u64, pos: ChunkPos, bytes: u64, latency_ms: f64) {
        self.window_start.get_or_insert(now_ms);
        match self.highest {
            Some(h) if pos <= h => return, // reordered / duplicate on this path
            Some(h) if pos.epoch == h.epoch => {
                let gap = pos.seq - h.seq - 1;
                self.acc.lost += gap;
                if gap >= BURST_RUN {
                    self.acc.burst = true;
                }
            }
            Some(_) | None => {}
        }
        self.highest = Some(pos);
        self.acc.bytes += bytes;
        self.acc.chunks += 1;
        self.acc.latency_sum += latency_ms;
        if let Some(prev) = self.last_latency {
            let d = (latency_ms - prev).abs();
            self.snap.jitter_ms += (d - self.snap.jitter_ms) / 16.0;
        }
        self.last_latency = Some(latency_ms);
        self.min_latency = Some(self.min_latency.map_or(latency_ms, |m| m.min(latency_ms)));
        self.last_arrival_ms = Some(now_ms);
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
        let total = a.chunks + a.lost;
        let loss = if total == 0 {
            0.0
        } else {
            a.lost as f64 / total as f64
        };
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
    /// Bits/s actually sent.
    pub sent_bps: f64,
    /// Bytes refused by the uplink (queue full / Busy).
    pub dropped_bytes: u64,
    /// Worst queue delay sampled (ms).
    pub max_queue_ms: f64,
    /// Whether the window counts as congested (drops, or queue delay at or
    /// above the congestion threshold). A congested window's `sent_bps` is a
    /// measurement of the uplink's real capacity.
    pub congested: bool,
}

/// C1 send-side meter for a forwarder's uplink.
#[derive(Debug, Clone)]
pub struct EgressMeter {
    window_ms: u64,
    congestion_queue_ms: f64,
    window_start: Option<u64>,
    sent: u64,
    dropped: u64,
    max_queue: f64,
}

impl EgressMeter {
    /// A meter with the given window and congestion threshold.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn new(window_ms: u64, congestion_queue_ms: u64) -> Self {
        Self {
            window_ms: window_ms.max(1),
            congestion_queue_ms: congestion_queue_ms as f64,
            window_start: None,
            sent: 0,
            dropped: 0,
            max_queue: 0.0,
        }
    }

    /// Bytes accepted onto the uplink; `queue_ms` is the queue delay they saw.
    pub fn on_sent(&mut self, now_ms: u64, bytes: u64, queue_ms: f64) {
        self.window_start.get_or_insert(now_ms);
        self.sent += bytes;
        self.max_queue = self.max_queue.max(queue_ms);
    }

    /// Bytes the uplink refused.
    pub fn on_dropped(&mut self, now_ms: u64, bytes: u64) {
        self.window_start.get_or_insert(now_ms);
        self.dropped += bytes;
    }

    /// Close the current window if it ended. Empty-window gaps are skipped.
    #[allow(clippy::cast_precision_loss)]
    pub fn roll(&mut self, now_ms: u64) -> Option<EgressWindow> {
        let start = self.window_start?;
        if now_ms < start + self.window_ms {
            return None;
        }
        let w = EgressWindow {
            sent_bps: self.sent as f64 * 8.0 * 1000.0 / self.window_ms as f64,
            dropped_bytes: self.dropped,
            max_queue_ms: self.max_queue,
            congested: self.dropped > 0 || self.max_queue >= self.congestion_queue_ms,
        };
        self.sent = 0;
        self.dropped = 0;
        self.max_queue = 0.0;
        let elapsed = now_ms - start;
        self.window_start = Some(start + (elapsed / self.window_ms) * self.window_ms);
        Some(w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(epoch: u64, seq: u64) -> ChunkPos {
        ChunkPos { epoch, seq }
    }

    #[test]
    fn meter_counts_gaps_bursts_and_rate() {
        let mut m = PathMeter::new(1_000, 1.0);
        for seq in 0..10 {
            m.on_chunk(seq * 50, at(1, seq), 1_000, 40.0);
        }
        // seq 10..=13 lost (burst of 4), then 14..19 arrive.
        for seq in 14..20 {
            m.on_chunk(seq * 50, at(1, seq), 1_000, 40.0);
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
        m.on_chunk(0, at(1, 5), 100, 10.0);
        m.restart();
        m.on_chunk(10, at(1, 50), 100, 10.0);
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
            m.on_chunk(seq - 900, at(1, seq), 100, 10.0);
        }
        for seq in 0..50 {
            m.on_chunk(50 + seq, at(2, seq), 100, 10.0);
        }
        assert!(m.roll(1_000));
        let s = m.snapshot();
        assert!(s.loss.abs() < 1e-12, "a roll is no loss: {}", s.loss);
        assert!(s.burst.abs() < 1e-12, "a roll is no burst: {}", s.burst);

        m.on_chunk(1_000, at(1, 950), 100, 10.0);
        m.on_chunk(1_001, at(2, 50), 100, 10.0);
        m.on_chunk(1_002, at(2, 52), 100, 10.0);
        assert!(m.roll(2_000));
        assert!(
            (m.snapshot().loss - 1.0 / 3.0).abs() < 1e-9,
            "one gap in the new epoch, the straggler uncounted: {}",
            m.snapshot().loss
        );
    }

    #[test]
    fn egress_flags_congestion() {
        let mut e = EgressMeter::new(1_000, 100);
        e.on_sent(0, 125_000, 20.0);
        let w = e.roll(1_000).expect("window");
        assert!(!w.congested);
        assert!((w.sent_bps - 1_000_000.0).abs() < 1e-6);
        e.on_sent(1_000, 10, 150.0);
        assert!(e.roll(2_000).expect("window").congested);
        e.on_dropped(2_000, 10);
        assert!(e.roll(3_000).expect("window").congested);
    }
}
