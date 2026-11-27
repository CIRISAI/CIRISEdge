//! 45.3 — **the node's egress budget**: one sending rate `R` for everything
//! edge itself hands the uplink, set from the uplink's own delay, and served
//! in priority order (control > audio > video > bulk).
//!
//! Why one budget: under a whole-uplink cap every class edge holds back and
//! later releases comes back as a burst when its gate opens (video after a
//! drain, bulk after a yield), refilling the kernel's FIFO within seconds. A
//! single rate that every send draws from, with the lower classes yielding
//! first, keeps the queue short without gates.
//!
//! The signal is the call's uplink backlog (`av_call::uplink_backlog`: the
//! oldest unproved Channel message's age from its send, past the RTT floor,
//! least over every leg). Rate control is delay-based AIMD:
//! - over [`MD_ABOVE_MS`]: `R ← R × MD_FACTOR`, at most once per
//!   the backlog's depth, clamped to `[MD_EVERY_MS, MD_SPACING_MAX_MS]`: a cut shows in the reading only once the
//!   queue ahead of it has drained, so a second cut sooner than that cuts
//!   for the same queue twice (the bench: cutting every 500 ms swung the
//!   FIFO 0 → 3.4 s → 0 every ~12 s);
//! - under [`AI_BELOW_MS`]: `R ← R + max(AI_FLOOR_BPS, R / AI_DIVISOR)` per
//!   reading, about 13 % a second: slow, because the reading lags the queue
//!   by a second or more and a fast climb overshoots before it shows; and
//!   once the backlog has read clear for [`FAST_AFTER_MS`], `R / 8` per
//!   reading (a doubling in ~1.5 s), so a lifted cap is found in seconds;
//! - between: hold.
//!
//! No budget is in force until the first reading over [`MD_ABOVE_MS`]
//! (`rate_bps` is `None`: nothing is held); it starts at what edge was
//! handing the uplink then, decreased once. It is lifted again once the
//! backlog has read under [`AI_BELOW_MS`] for [`LIFT_AFTER_MS`] while edge
//! used less than [`LIFT_USE_RATIO`] of it.
//!
//! Serving: a token bucket at `R`, [`DEPTH_MS`] deep. Control is always taken
//! (it may drive the bucket negative: it is never held, but its bytes
//! count). Audio needs the bucket at or above 0, video above
//! [`VIDEO_RESERVE_MS`] of `R` (room kept for audio), bulk above
//! [`BULK_RESERVE_MS`] (room kept for both): so under a short budget bulk
//! waits first, then video, and audio last.
//!
//! **The floor** (CC review): strict priority starved bulk (it waited up to
//! a minute, then went as a burst). Bulk now has its own share of `R`:
//! [`FLOOR_SHARE`] of it, at least [`FLOOR_MIN_BPS`], paced by a second
//! bucket ([`FLOOR_DEPTH_MS`] deep). A bulk send goes when the main bucket
//! has room above the bulk reserve OR the floor bucket is not in debt; either
//! way its bits come out of the main bucket too, so the media classes yield
//! that share. Bulk waiters are served in order, and a bulk send never
//! waits past the floor's pace, so nothing is held to be released at once.
//!
//! **The send class** (CC review): an identity-plane send is FIRST class
//! (charged like control, never held) unless the code that built it knows
//! it is bulk and says so ([`sending_as`]); a send with no class is FIRST.
//!
//! Pure state with the clock passed in ([`BudgetCore`]); [`EgressBudget`] is
//! its shared, wall-clocked wrapper.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Decrease while the backlog reads over this (ms): the stall bound.
pub const MD_ABOVE_MS: u64 = 400;
/// Increase while the backlog reads under this (ms).
pub const AI_BELOW_MS: u64 = 100;
/// The multiplicative decrease.
pub const MD_FACTOR: f64 = 0.7;
/// At most one decrease this often (ms).
pub const MD_EVERY_MS: u64 = 500;
/// The longest wait between two cuts, however deep the reading: a deep
/// first burst (12 s on the bench) must still be cut down in seconds.
pub const MD_SPACING_MAX_MS: u64 = 1_000;
/// The additive increase per reading: the larger of this...
pub const AI_FLOOR_BPS: f64 = 8_000.0;
/// ...and `R` over this.
pub const AI_DIVISOR: f64 = 32.0;
/// Clear this long, the increase is `R / FAST_DIVISOR` a reading.
pub const FAST_AFTER_MS: u64 = 5_000;
/// The fast increase's divisor.
pub const FAST_DIVISOR: f64 = 8.0;
/// `R` never goes under this: control and one 60 ms audio copy.
pub const MIN_BPS: f64 = 64_000.0;
/// The bucket's depth, as time at `R`.
pub const DEPTH_MS: f64 = 250.0;
/// Video needs this much of `R` (ms) left in the bucket: audio's room.
pub const VIDEO_RESERVE_MS: f64 = 40.0;
/// Bulk needs this much: audio's and video's room.
pub const BULK_RESERVE_MS: f64 = 120.0;
/// The bulk floor: this share of `R`...
pub const FLOOR_SHARE: f64 = 0.10;
/// ...and never under this (bits/s).
pub const FLOOR_MIN_BPS: f64 = 8_000.0;
/// The floor bucket's depth, as time at the floor's rate.
pub const FLOOR_DEPTH_MS: f64 = 100.0;
/// The budget is lifted after the backlog reads clear this long...
pub const LIFT_AFTER_MS: u64 = 3_000;
/// ...while edge used less than this share of it.
pub const LIFT_USE_RATIO: f64 = 0.6;

/// What a send is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Call control (C3), never held.
    Control,
    /// Codec-opaque media.
    Audio,
    /// Every other media chunk.
    Video,
    /// Identity-plane envelopes positively known to be bulk (replication
    /// rows outside the FIRST families, chat, file transfer).
    Bulk,
}

/// 45.3 (CC review) — an identity-plane send's class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendClass {
    /// Never held: charged and counted like call control. The default.
    First,
    /// Waits on the budget, within the floor.
    Bulk,
}

tokio::task_local! {
    static SEND_CLASS: SendClass;
}

/// Run `send` as a `class` send: the transport reads it at the send.
pub async fn sending_as<F: std::future::Future>(class: SendClass, send: F) -> F::Output {
    SEND_CLASS.scope(class, send).await
}

/// The class of the send in progress: what [`sending_as`] said, else FIRST
/// (a send nobody classed is never filed as bulk).
#[must_use]
pub fn current_send_class() -> SendClass {
    SEND_CLASS.try_with(|c| *c).unwrap_or(SendClass::First)
}

/// The budget's pure state.
#[derive(Debug, Clone, Default)]
pub struct BudgetCore {
    rate: Option<f64>,
    tokens: f64,
    at_ms: u64,
    last_md_ms: Option<u64>,
    clear_since: Option<u64>,
    /// Bits taken (all classes) and control bits taken, over the current
    /// one-second window, and the last window's rates.
    win_start_ms: u64,
    win_bits: f64,
    win_control: f64,
    used_bps: f64,
    control_bps: f64,
    /// The rate when the current window opened, and when the last closed
    /// window opened (what its use is compared against: `R` climbs within a
    /// window, and the window's use lags it).
    win_rate: Option<f64>,
    used_against: Option<f64>,
    /// The floor bucket (bits); refilled at the floor's rate.
    floor_tokens: f64,
}

#[allow(clippy::cast_precision_loss)] // ms spans and bits, far under 2^52
impl BudgetCore {
    fn refill(&mut self, now_ms: u64) {
        if now_ms.saturating_sub(self.win_start_ms) >= 1_000 {
            let span = now_ms.saturating_sub(self.win_start_ms) as f64 / 1_000.0;
            self.used_bps = self.win_bits / span;
            self.control_bps = self.win_control / span;
            self.used_against = self.win_rate;
            self.win_rate = self.rate;
            self.win_start_ms = now_ms;
            self.win_bits = 0.0;
            self.win_control = 0.0;
        }
        if let Some(r) = self.rate {
            let dt = now_ms.saturating_sub(self.at_ms) as f64 / 1_000.0;
            self.tokens = (self.tokens + r * dt).min(r * DEPTH_MS / 1_000.0);
            let f = Self::floor_of(r);
            self.floor_tokens = (self.floor_tokens + f * dt).min(f * FLOOR_DEPTH_MS / 1_000.0);
        }
        self.at_ms = now_ms;
    }

    /// Fold one backlog reading (ms past the RTT floor; `None`: nothing
    /// outstanding, which reads as clear).
    pub fn observe(&mut self, now_ms: u64, backlog_ms: Option<u64>) {
        self.refill(now_ms);
        let b = backlog_ms.unwrap_or(0);
        if b > MD_ABOVE_MS {
            self.clear_since = None;
            let due = self.last_md_ms.is_none_or(|t| {
                now_ms.saturating_sub(t) >= b.clamp(MD_EVERY_MS, MD_SPACING_MAX_MS)
            });
            if due {
                let from = self.rate.unwrap_or_else(|| self.used_bps.max(MIN_BPS));
                self.rate = Some((from * MD_FACTOR).max(MIN_BPS));
                self.last_md_ms = Some(now_ms);
                self.tokens = self.tokens.min(0.0);
            }
        } else if b < AI_BELOW_MS {
            let since = *self.clear_since.get_or_insert(now_ms);
            if let Some(r) = self.rate {
                if now_ms.saturating_sub(since) >= LIFT_AFTER_MS
                    && self
                        .used_against
                        .is_some_and(|was| self.used_bps < was * LIFT_USE_RATIO)
                {
                    self.rate = None;
                    self.tokens = 0.0;
                } else if now_ms.saturating_sub(since) >= FAST_AFTER_MS {
                    self.rate = Some(r + r / FAST_DIVISOR);
                } else {
                    self.rate = Some(r + (r / AI_DIVISOR).max(AI_FLOOR_BPS));
                }
            }
        } else {
            self.clear_since = None;
        }
    }

    /// Take `bits` for a send of `class` now, if the budget serves it.
    /// Control is always taken.
    pub fn take(&mut self, now_ms: u64, class: Class, bits: f64) -> bool {
        self.refill(now_ms);
        let ok = match (self.rate, class) {
            (None, _) | (_, Class::Control) => true,
            (Some(r), Class::Audio) => self.tokens >= 0.0 || self.tokens + r * 0.02 >= bits,
            (Some(r), Class::Video) => self.tokens - bits >= r * VIDEO_RESERVE_MS / 1_000.0,
            (Some(r), Class::Bulk) => {
                self.tokens - bits >= r * BULK_RESERVE_MS / 1_000.0 || self.floor_tokens >= 0.0
            }
        };
        if ok {
            if self.rate.is_some() {
                self.tokens -= bits;
                if class == Class::Bulk {
                    self.floor_tokens -= bits;
                }
            }
            self.win_bits += bits;
            if class == Class::Control {
                self.win_control += bits;
            }
        }
        ok
    }

    /// The rate in force, `None` when no budget is.
    #[must_use]
    pub fn rate_bps(&self) -> Option<f64> {
        self.rate
    }

    /// The bulk floor under a rate `r` (bits/s).
    #[must_use]
    pub fn floor_of(r: f64) -> f64 {
        (r * FLOOR_SHARE).max(FLOOR_MIN_BPS)
    }

    /// What the rate leaves media after control (bits/s), `None` when no
    /// budget is in force.
    #[must_use]
    pub fn media_bps(&self) -> Option<f64> {
        self.rate.map(|r| (r - self.control_bps).max(0.0))
    }
}

/// The node's egress budget, shared by its calls and its transport.
#[derive(Debug)]
pub struct EgressBudget {
    t0: Instant,
    core: Mutex<BudgetCore>,
    /// Bulk waiters, served in arrival order (tokio's mutex is FIFO).
    bulk_queue: tokio::sync::Mutex<()>,
}

impl Default for EgressBudget {
    fn default() -> Self {
        Self {
            t0: Instant::now(),
            core: Mutex::new(BudgetCore::default()),
            bulk_queue: tokio::sync::Mutex::new(()),
        }
    }
}

impl EgressBudget {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.t0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn core(&self) -> std::sync::MutexGuard<'_, BudgetCore> {
        self.core
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Fold a backlog reading (a call's watch tick).
    pub fn observe(&self, backlog_ms: Option<u64>) {
        let now = self.now_ms();
        self.core().observe(now, backlog_ms);
    }

    /// Take `bytes` on the wire for `class` now (see [`BudgetCore::take`]).
    pub fn take(&self, class: Class, bytes: usize) -> bool {
        let now = self.now_ms();
        #[allow(clippy::cast_precision_loss)]
        let bits = bytes as f64 * 8.0;
        self.core().take(now, class, bits)
    }

    /// A bulk send of `bytes`: waits, in arrival order, until the budget
    /// serves it. The floor always serves it within its pace, so there is no
    /// give-up and nothing goes as a burst. Returns whether it waited.
    pub async fn wait_bulk(&self, bytes: usize) -> bool {
        let _turn = self.bulk_queue.lock().await;
        let mut waited = false;
        while !self.take(Class::Bulk, bytes) {
            waited = true;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        waited
    }

    /// The rate in force (bits/s), `None` when no budget is.
    #[must_use]
    pub fn rate_bps(&self) -> Option<f64> {
        self.core().rate_bps()
    }

    /// What the rate leaves media after control (bits/s), `None` when no
    /// budget is in force.
    #[must_use]
    pub fn media_bps(&self) -> Option<f64> {
        self.core().media_bps()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Uncapped there is no budget and nothing is held; the first reading
    /// over the bound starts one from what edge was sending, decreased.
    #[test]
    fn no_budget_until_the_backlog_reads_over_400_ms() {
        let mut b = BudgetCore::default();
        for t in (0..2_000).step_by(10) {
            assert!(b.take(t, Class::Bulk, 8_000.0));
        }
        b.observe(2_000, Some(50));
        assert_eq!(b.rate_bps(), None);
        b.observe(2_250, Some(401));
        let r = b.rate_bps().expect("a budget");
        assert!((r - 800_000.0 * MD_FACTOR).abs() < 1.0, "{r}");
    }

    /// While the backlog reads high the rate falls, once per MD_EVERY_MS,
    /// never under the floor; clear, it climbs; lifted once clear and unused.
    #[test]
    fn the_rate_falls_while_backlogged_climbs_when_clear_and_lifts_when_unused() {
        let mut b = BudgetCore::default();
        // A second of 1 Mbit/s handed to the uplink, then the backlog.
        for t in (0..1_100).step_by(10) {
            assert!(b.take(t, Class::Video, 10_000.0));
        }
        b.observe(1_100, Some(1_000));
        let r0 = b.rate_bps().unwrap();
        assert!(r0 > 500_000.0, "{r0}");
        b.observe(1_600, Some(1_000));
        assert_eq!(
            b.rate_bps(),
            Some(r0),
            "one decrease per queue's depth (1 s)"
        );
        b.observe(2_100, Some(1_000));
        assert!(b.rate_bps().unwrap() < r0);
        for t in (2_350..20_000).step_by(250) {
            b.observe(t, Some(1_000));
        }
        assert_eq!(b.rate_bps(), Some(MIN_BPS));
        b.observe(20_000, Some(200));
        assert_eq!(b.rate_bps(), Some(MIN_BPS), "between the bounds: hold");
        let mut t = 20_250;
        while let Some(r) = b.rate_bps().filter(|r| *r < 600_000.0) {
            // In use (control at the full rate), so it is not lifted early.
            assert!(b.take(t, Class::Control, r * 0.25));
            b.observe(t, Some(10));
            t += 250;
            assert!(t < 40_000);
        }
        assert!(b.rate_bps().is_some(), "climbed, not lifted");
        assert!(
            t - 20_250 <= 10_000,
            "found 600 kbit/s again in {} ms",
            t - 20_250
        );
        // Clear and unused for LIFT_AFTER_MS: lifted.
        for t in (t..t + 5_000).step_by(250) {
            b.observe(t, None);
        }
        assert_eq!(b.rate_bps(), None);
    }

    /// Under a short budget control is always taken, audio before video,
    /// video before bulk.
    #[test]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn control_always_then_audio_then_video_then_bulk() {
        let mut b = BudgetCore::default();
        b.observe(0, Some(1_000));
        // Force the floor and an empty bucket.
        for t in (500..10_000).step_by(500) {
            b.observe(t, Some(1_000));
        }
        let r = b.rate_bps().unwrap();
        assert!(
            b.take(10_000, Class::Control, 100_000.0),
            "control is never held"
        );
        assert!(!b.take(10_000, Class::Audio, 2_000.0));
        assert!(!b.take(10_000, Class::Video, 4_000.0));
        // Bulk's floor serves one send (it is not in debt), then holds it.
        assert!(b.take(10_000, Class::Bulk, 4_000.0), "the floor");
        assert!(!b.take(10_000, Class::Bulk, 4_000.0), "the floor in debt");
        // Refill to a full bucket: audio and video fit, bulk past both is
        // held while the floor is still repaying (one more floor send first).
        let full_after = 10_000 + 2_000 + (104_000.0 / r * 1_000.0) as u64;
        assert!(b.take(full_after, Class::Audio, 2_000.0));
        assert!(b.take(full_after, Class::Video, 4_000.0));
        let _ = b.take(full_after, Class::Bulk, 40_000.0);
        let left = r * DEPTH_MS / 1_000.0 - 6_000.0 - 40_000.0;
        assert!(!b.take(
            full_after,
            Class::Bulk,
            left - r * BULK_RESERVE_MS / 1_000.0 + 1.0
        ));
    }

    /// CC review — the floor: under a budget media fills, bulk still gets
    /// its share (FLOOR_SHARE of R, at least FLOOR_MIN_BPS), paced, never
    /// more than the floor's depth at once, and media yields that share.
    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn bulk_gets_its_floor_under_full_media_and_never_bursts() {
        let mut b = BudgetCore::default();
        b.observe(0, Some(1_000));
        for t in (500..10_000).step_by(500) {
            b.observe(t, Some(1_000));
        }
        let r = b.rate_bps().unwrap();
        let floor = BudgetCore::floor_of(r);
        // 20 s: video offered at twice R, bulk offered 1 kB every 5 ms.
        let (mut bulk_bits, mut video_bits) = (0.0, 0.0);
        let mut most_in_100ms: f64 = 0.0;
        let mut window: std::collections::VecDeque<(u64, f64)> = std::collections::VecDeque::new();
        for t in (10_000..30_000u64).step_by(5) {
            if t % 10 == 0 && b.take(t, Class::Video, r * 2.0 / 100.0) {
                video_bits += r * 2.0 / 100.0;
            }
            if b.take(t, Class::Bulk, 8_000.0) {
                bulk_bits += 8_000.0;
                window.push_back((t, 8_000.0));
            }
            while window.front().is_some_and(|(w, _)| t - w >= 100) {
                window.pop_front();
            }
            most_in_100ms = most_in_100ms.max(window.iter().map(|(_, x)| x).sum());
        }
        let bulk_bps = bulk_bits / 20.0;
        let video_bps = video_bits / 20.0;
        assert!(
            bulk_bps >= floor * 0.9,
            "bulk {bulk_bps} under its floor {floor}"
        );
        assert!(
            bulk_bps + video_bps <= r * 1.05,
            "together within R: {bulk_bps} + {video_bps} vs {r}"
        );
        // Never a burst: at most the floor's depth plus one send in any
        // 100 ms beyond its pace.
        assert!(
            most_in_100ms <= floor * 0.1 + floor * FLOOR_DEPTH_MS / 1_000.0 + 8_000.0,
            "{most_in_100ms} in 100 ms at a floor of {floor}"
        );
    }
}
