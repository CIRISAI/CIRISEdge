//! ALM-A(cap) — passive upload-capacity estimator
//! (CIRISEdge, `docs/AV_ALM_DESIGN.md` §5.1 + §6; leviculum#35).
//!
//! ## What this module is
//!
//! The producer that computes the *demonstrated-sustainable* uplink a
//! relay is allowed to sign into a [`super::capacity::SignedRelayCapacity`].
//! It does NOT sign — signing is [`super::capacity::SignedRelayCapacity::sign`],
//! a separate async hybrid-signer call (the seam is [`DemonstratedCapacity`]
//! + [`DemonstratedCapacity::to_relay_capacity`] at the bottom of this file).
//!
//! ## The physical fact the design rests on (§5.1)
//!
//! A relay actively forwarding a stream is **application-limited**: it
//! sends exactly the stream bitrate, never saturating the pipe. So a
//! passive per-link delivery-rate reading is a rock-solid **floor** ("I
//! am demonstrably sustaining X Mb/s with no congestion"), NOT the
//! headroom above it. That is *exactly* what a self-scored,
//! adversarially-verified claim wants: **you can only sign capacity you
//! have actually demonstrated**, so over-claiming is near-impossible by
//! construction (the [`overclaim_is_impossible`](tests) invariant proves
//! `signed ≤ demonstrated × SAFETY_MARGIN`). The BBR delivery-rate lesson:
//! the app-limited bit is what distinguishes a floor from a real ceiling
//! ([draft-cheng-iccrg-delivery-rate-estimation]).
//!
//! ## Where the numbers come from (leviculum v0.12.0 `LinkStats`, #35)
//!
//! leviculum exposes per-link, read-only, cumulative counters we sample
//! ~1 Hz and *difference*:
//!   - `bytes_delivered()` — proof-confirmed channel envelopes + completed
//!     outgoing resource transfers: the BBR-style delivery-rate numerator.
//!   - `busy_rejections()` / `pacing_rejections()` / `iface_pacing_rejections()`
//!     — the app-limited-vs-congestion-limited bit, *by source*
//!     (channel-window-full / link-pacer / interface-airtime-gate). Any of
//!     these moving over an interval means the link was backpressured while
//!     the app had more to send → that interval's rate is a *ceiling* sample.
//!     None moving → app-limited → *floor* only.
//!   - `min_rtt_ms()` — the conservative propagation-delay floor, carried
//!     through as the latency a relay can honestly advertise (§1 selection
//!     is latency×quality).
//!
//! The impure leviculum read is one gated `From<&LinkStats>` (see
//! [`LinkCounters`]); *everything* below the counter snapshot is pure and
//! deterministically unit-tested.
//!
//! ## The pipeline (§5.1 + §6)
//!
//! 1. **Per-link sampler** — difference cumulative counters over the
//!    interval → per-interval delivered bytes + a backpressure-moved bit
//!    ([`diff_link`]).
//! 2. **Node aggregate** — sum active links' delivered bytes; the node is
//!    congestion-limited iff *any* link backpressured; node `min_rtt` is
//!    the min across links ([`aggregate`]).
//! 3. **Conservative filter** (the "stay safe" half) — p10 of the
//!    demonstrated rate over a trailing [`FLOOR_WINDOW_SECS`] window (the
//!    floor); a ceiling refreshed *only* from congestion-limited samples
//!    that exceed the floor, decayed toward the floor once stale
//!    ([`CEILING_STALE_SECS`]‥+[`CEILING_DECAY_SPAN_SECS`]); safety margin
//!    `claimable = SAFETY_MARGIN × (filtered − committed)`; clamped to any
//!    OS/interface max.
//! 4. **Quantize DOWN** to whole servable stream-layers (buckets). A
//!    bucket **downgrades immediately** (safety); it **upgrades only after
//!    the higher bucket holds K=[`UPGRADE_HOLD_WINDOWS`] consecutive
//!    windows** (anti-flap — GCC's asymmetric `K_u ≫ K_d`).
//! 5. **Coalesce** — [`CapacityEstimator::observe`] returns `Some` **only
//!    when the signed bucket crosses**. That `Some` is what gates a
//!    re-attestation; we never re-sign per sample (§5 "coalesced +
//!    quantized", DoS-via-attestation-churn defense §8).
//!
//! ## Portability invariant (§5.1)
//!
//! As observability drops (Linux → mac/Win → Android → iOS → cellular) the
//! node claims **less, never more**: fewer samples ⇒ the p10 nearest-rank
//! collapses to the window minimum ⇒ a smaller demonstrated set ⇒ a more
//! conservative bucket. The self-scoring safety guarantee holds on every
//! platform.

use std::collections::VecDeque;

use super::capacity::RelayCapacity;
use crate::transport::realtime_av::ReceiverLayerPolicy;

// ─────────────────────────────────────────────────────────────────────
// Conservative-filter defaults (§5.1 / §6 — "the research transcript").
// ─────────────────────────────────────────────────────────────────────

/// Trailing window (seconds) the demonstrated **floor** is taken over.
/// Long enough to absorb TCP slow-start / RNS congestion bursts, short
/// enough that a node that just lost its uplink stops advertising the
/// stale rate promptly. Matches [`super::capacity::MEASUREMENT_WINDOW_SECS`]'s
/// intent at a finer granularity (this is the *sub*-window the filter
/// summarizes; the outer 60 s is the re-mint cadence).
pub const FLOOR_WINDOW_SECS: f64 = 30.0;

/// The floor is the **p10** (10th-percentile, worst-decile) of the
/// demonstrated rate over the window — "sign the rate I virtually always
/// meet", not the mean. Harmonic mean is the documented alternative; p10
/// is chosen because it is trivially conservative and, at small `n`,
/// nearest-rank collapses to the window minimum (the portability
/// invariant falls out for free).
pub const FLOOR_PERCENTILE: f64 = 10.0;

/// Safety margin (§6 "give grace, stay safe"): a relay signs only
/// `SAFETY_MARGIN × (filtered − committed)`. Under-promise so the
/// honesty-score risk is a non-issue. This factor is *the* reason
/// over-claiming is structurally impossible: `signed ≤ 0.75 ×
/// demonstrated < demonstrated`.
pub const SAFETY_MARGIN: f32 = 0.75;

/// Seconds a congestion-limited **ceiling** sample stays fully trusted
/// before it starts decaying toward the floor. Below this age the last
/// real ceiling is used verbatim.
pub const CEILING_STALE_SECS: f64 = 60.0;

/// Seconds over which a stale ceiling linearly decays from full trust to
/// the floor. Full decay lands at `CEILING_STALE_SECS +
/// CEILING_DECAY_SPAN_SECS` = 120 s (the §5.1 "staleness 60–120 s"
/// band). Past that a relay claims only its passively-demonstrated floor.
pub const CEILING_DECAY_SPAN_SECS: f64 = 60.0;

/// Anti-flap hold (`K`): a *higher* bucket must be supported for this many
/// consecutive windows before the signed bucket rises. A downgrade needs
/// no hold (immediate, for safety). Asymmetric adaptation — react fast to
/// degradation, promote slowly (GCC `K_u ≫ K_d`, §4).
pub const UPGRADE_HOLD_WINDOWS: u32 = 3;

// ─────────────────────────────────────────────────────────────────────
// The impure edge: a per-link cumulative-counter snapshot.
//
// `LinkCounters` is pure (no leviculum types), so the whole pipeline
// unit-tests without the transport feature. The ONLY leviculum-coupled
// code is the gated `From<&LinkStats>` — the "thin around the pure core"
// the design mandates. Edge reads it via `ReticulumNode::link_stats`
// (`ReticulumTransport::capacity_link_counters`, `reticulum.rs`).
// ─────────────────────────────────────────────────────────────────────

/// A snapshot of the leviculum v0.12.0 `LinkStats` counters this estimator
/// consumes. Cumulative and monotonic per link (reset only with the link),
/// so the sampler differences consecutive readings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkCounters {
    /// `LinkStats::bytes_delivered` — proof-confirmed channel envelopes +
    /// completed outgoing resource transfers. The delivery-rate numerator.
    pub bytes_delivered: u64,
    /// `LinkStats::busy_rejections` — sends refused because the channel
    /// window was full (the classic congestion-limited signal).
    pub busy_rejections: u64,
    /// `LinkStats::pacing_rejections` — sends refused by the link pacer.
    pub pacing_rejections: u64,
    /// `LinkStats::iface_pacing_rejections` — sends refused by the
    /// interface's airtime / next-slot gate before reaching the channel.
    pub iface_pacing_rejections: u64,
    /// `LinkStats::min_rtt_ms` — minimum Karn-valid delivery RTT observed;
    /// the conservative propagation-delay floor. `None` until a valid
    /// sample exists.
    pub min_rtt_ms: Option<u64>,
}

#[cfg(feature = "_reticulum-module")]
impl From<&leviculum_core::node::LinkStats> for LinkCounters {
    /// The one impure read (leviculum#35). All three backpressure counters
    /// are folded into the app-limited bit downstream; we keep them
    /// separate here so a future consumer can attribute *why* a link is
    /// congestion-limited (window vs pacer vs airtime).
    fn from(s: &leviculum_core::node::LinkStats) -> Self {
        Self {
            bytes_delivered: s.bytes_delivered(),
            busy_rejections: s.busy_rejections(),
            pacing_rejections: s.pacing_rejections(),
            iface_pacing_rejections: s.iface_pacing_rejections(),
            min_rtt_ms: s.min_rtt_ms(),
        }
    }
}

/// One link's differenced interval — the output of [`diff_link`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkInterval {
    /// Bytes delivered on this link during the interval.
    pub bytes_delivered: u64,
    /// Total backpressure rejections (all three counters) during the
    /// interval. Non-zero ⇒ the link was congestion-limited this interval.
    pub backpressure_events: u64,
    /// The link's current `min_rtt_ms` (propagation floor).
    pub min_rtt_ms: Option<u64>,
}

/// Difference two consecutive per-link counter snapshots. Saturating so a
/// link reset (counters drop to a fresh link's zero) yields a 0 delta, not
/// a wraparound — a reset link simply contributes nothing until it
/// re-accumulates, which is the conservative reading.
#[must_use]
pub fn diff_link(prev: &LinkCounters, now: &LinkCounters) -> LinkInterval {
    let backpressure = now
        .busy_rejections
        .saturating_sub(prev.busy_rejections)
        .saturating_add(now.pacing_rejections.saturating_sub(prev.pacing_rejections))
        .saturating_add(
            now.iface_pacing_rejections
                .saturating_sub(prev.iface_pacing_rejections),
        );
    LinkInterval {
        bytes_delivered: now.bytes_delivered.saturating_sub(prev.bytes_delivered),
        backpressure_events: backpressure,
        min_rtt_ms: now.min_rtt_ms,
    }
}

/// A node-level per-interval observation — the pure core's input. This is
/// the `(interval, bytes_delivered, min_rtt, app_limited)` tuple §5.1
/// names, aggregated across the node's active links.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CapacitySample {
    /// The interval this sample covers, in seconds (the ~1 Hz sampler tick
    /// spacing). Guarded: a non-positive interval is ignored by `observe`.
    pub interval_secs: f64,
    /// Bytes delivered across ALL active links during the interval (the
    /// node-aggregate demonstrated throughput). Capacity is a self-count,
    /// NOT a latch-sum (§5) — this is the relay's own delivered bytes.
    pub bytes_delivered: u64,
    /// Min `min_rtt_ms` across active links — the node's best propagation
    /// floor. `None` until some link has a valid RTT.
    pub min_rtt_ms: Option<u64>,
    /// `true` ⇒ NO link backpressured this interval ⇒ application-limited
    /// ⇒ the rate is a **floor** only. `false` ⇒ at least one link was
    /// backpressured ⇒ congestion-limited ⇒ a real **ceiling** sample.
    pub app_limited: bool,
}

/// Aggregate a node's differenced links into one [`CapacitySample`]. The
/// node is congestion-limited iff *any* link backpressured (one saturated
/// uplink is a real ceiling even if others idle); node `min_rtt` is the
/// min across links (best-case propagation).
#[must_use]
pub fn aggregate(intervals: &[LinkInterval], interval_secs: f64) -> CapacitySample {
    let bytes = intervals
        .iter()
        .map(|i| i.bytes_delivered)
        .fold(0u64, u64::saturating_add);
    let backpressure = intervals
        .iter()
        .map(|i| i.backpressure_events)
        .fold(0u64, u64::saturating_add);
    let min_rtt = intervals.iter().filter_map(|i| i.min_rtt_ms).min();
    CapacitySample {
        interval_secs,
        bytes_delivered: bytes,
        min_rtt_ms: min_rtt,
        app_limited: backpressure == 0,
    }
}

// ─────────────────────────────────────────────────────────────────────
// The pure core: filter → quantize → hysteresis → coalesce.
// ─────────────────────────────────────────────────────────────────────

/// Which arm set the demonstrated value — logged on every crossing so an
/// operator can tell a passively-measured floor from a congestion-probed
/// ceiling at a glance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstimatorArm {
    /// The demonstrated value is the passive p10 floor (application-limited;
    /// no congestion sample raised it). The common, ~free case.
    Floor,
    /// A (still-fresh) congestion-limited sample raised the demonstrated
    /// value above the floor.
    CeilingSample,
}

/// Tunables for [`CapacityEstimator`]. Construct with [`EstimatorConfig::new`]
/// for the §5.1 defaults; override fields for tests / per-platform policy.
#[derive(Debug, Clone, Copy)]
pub struct EstimatorConfig {
    /// Megabits/sec of ONE whole servable stream-layer — the quantization
    /// bucket unit. `bucket = floor(claimable / layer_bitrate_mbps)`.
    pub layer_bitrate_mbps: f32,
    /// Uplink already committed to current subscribers (the relay's own
    /// self-count, §5). Subtracted before the safety margin. A node-level
    /// policy quantity, not a per-sample measurement — hence config, so the
    /// per-sample input stays the pure `(interval, bytes, rtt, app_limited)`
    /// tuple.
    pub committed_mbps: f32,
    /// Optional OS/interface hard ceiling (Android `getLinkUpstreamBandwidthKbps`,
    /// a known interface cap). Used ONLY as an upper clamp — never trusted
    /// as capacity (§5.1 "never trusted: self-reported OS link capacity").
    pub os_max_mbps: Option<f32>,
    /// See [`FLOOR_WINDOW_SECS`].
    pub floor_window_secs: f64,
    /// See [`FLOOR_PERCENTILE`].
    pub floor_percentile: f64,
    /// See [`SAFETY_MARGIN`].
    pub safety_margin: f32,
    /// See [`CEILING_STALE_SECS`].
    pub ceiling_stale_secs: f64,
    /// See [`CEILING_DECAY_SPAN_SECS`].
    pub ceiling_decay_span_secs: f64,
    /// See [`UPGRADE_HOLD_WINDOWS`].
    pub upgrade_hold_windows: u32,
}

impl EstimatorConfig {
    /// The §5.1 defaults for a given per-layer bitrate. `committed_mbps = 0`,
    /// no OS clamp.
    #[must_use]
    pub fn new(layer_bitrate_mbps: f32) -> Self {
        Self {
            layer_bitrate_mbps,
            committed_mbps: 0.0,
            os_max_mbps: None,
            floor_window_secs: FLOOR_WINDOW_SECS,
            floor_percentile: FLOOR_PERCENTILE,
            safety_margin: SAFETY_MARGIN,
            ceiling_stale_secs: CEILING_STALE_SECS,
            ceiling_decay_span_secs: CEILING_DECAY_SPAN_SECS,
            upgrade_hold_windows: UPGRADE_HOLD_WINDOWS,
        }
    }
}

/// The estimator's demonstrated output — the seam to signing. Carries the
/// quantized, safety-margined remaining uplink ready to drop into a
/// [`RelayCapacity`], plus the raw floor + arm for the log line. SIGNING
/// itself ([`super::capacity::SignedRelayCapacity::sign`]) is out of scope.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DemonstratedCapacity {
    /// Conservative remaining uplink, Mbps, **quantized DOWN** to whole
    /// servable layers: `servable_layers × layer_bitrate_mbps`. This is
    /// what feeds [`RelayCapacity::uplink_mbps`].
    pub uplink_mbps: f32,
    /// Whole servable stream-layers — the signed bucket (§5.1 "denominate
    /// spare in whole servable stream-layers").
    pub servable_layers: u32,
    /// The p10 demonstrated floor before ceiling/margin (Mbps) — logged so
    /// the passively-measured floor is always visible.
    pub demonstrated_floor_mbps: f32,
    /// `max(floor, fresh-ceiling)` before the safety margin (Mbps).
    pub demonstrated_mbps: f32,
    /// Best propagation floor across active links (ms), for the latency the
    /// relay advertises (§1 selection is latency×quality).
    pub min_rtt_ms: Option<u64>,
    /// Which arm set [`Self::demonstrated_mbps`].
    pub arm: EstimatorArm,
}

impl DemonstratedCapacity {
    /// **The signing seam.** Build the *unsigned* [`RelayCapacity`] carrying
    /// this demonstrated uplink; the caller then threads it into the async
    /// hybrid signer:
    ///
    /// ```ignore
    /// let cap = demonstrated.to_relay_capacity(max_streams, subs, policy, now_ms);
    /// let signed = SignedRelayCapacity::sign(cap, stream_id, epoch, key_id, &signer).await?;
    /// ```
    ///
    /// The estimator owns *what* is safe to claim; the signer owns *binding
    /// it to an identity*. Re-sign ONLY when [`CapacityEstimator::observe`]
    /// returned `Some` (a bucket crossing) — never per sample.
    #[must_use]
    pub fn to_relay_capacity(
        &self,
        max_streams: u16,
        max_subscribers_per_stream: u16,
        max_layer_supported: ReceiverLayerPolicy,
        wall_clock_unix_ms: u64,
    ) -> RelayCapacity {
        RelayCapacity::new(
            self.uplink_mbps,
            max_streams,
            max_subscribers_per_stream,
            max_layer_supported,
            wall_clock_unix_ms,
        )
    }
}

/// A signed-bucket crossing — the coalesced "capacity changed" signal that
/// gates a single re-attestation. Emitted by [`CapacityEstimator::observe`]
/// ONLY when the bucket actually moves.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CapacityChange {
    /// The bucket before this crossing.
    pub old_bucket: u32,
    /// The bucket after (the new signed servable-layer count).
    pub new_bucket: u32,
    /// The full demonstrated output to sign.
    pub demonstrated: DemonstratedCapacity,
}

/// One rate observation retained in the trailing floor window.
#[derive(Debug, Clone, Copy)]
struct WindowEntry {
    /// Cumulative estimator time (seconds) at which this rate was observed.
    at: f64,
    /// Demonstrated rate for the interval (Mbps).
    rate_mbps: f32,
}

/// The passive upload-capacity estimator — the pure state machine.
///
/// Feed it [`CapacitySample`]s (one per ~1 Hz sampler tick) via
/// [`observe`](Self::observe); act on the returned `Some(CapacityChange)`
/// by re-signing, ignore `None`. Deterministic: identical sample sequences
/// yield identical crossings, which is what makes the whole filter/
/// quantize/hysteresis/coalesce path unit-testable without a clock.
#[derive(Debug, Clone)]
pub struct CapacityEstimator {
    cfg: EstimatorConfig,
    /// Cumulative virtual clock (seconds), advanced by each sample's
    /// `interval_secs`. The estimator never reads a real clock.
    now_secs: f64,
    /// Trailing-window rates for the p10 floor.
    window: VecDeque<WindowEntry>,
    /// Last congestion-demonstrated ceiling (Mbps), if any.
    ceiling_mbps: Option<f32>,
    /// Cumulative time the ceiling was last refreshed (for staleness decay).
    ceiling_at: f64,
    /// The currently-signed bucket (whole servable layers).
    signed_bucket: u32,
    /// Upgrade candidate + consecutive-window streak toward it.
    pending_bucket: Option<u32>,
    upgrade_streak: u32,
    /// Last known node `min_rtt` (carried when a sample lacks one).
    last_min_rtt: Option<u64>,
}

impl CapacityEstimator {
    /// A fresh estimator at bucket 0 (nothing demonstrated yet).
    #[must_use]
    pub fn new(cfg: EstimatorConfig) -> Self {
        Self {
            cfg,
            now_secs: 0.0,
            window: VecDeque::new(),
            ceiling_mbps: None,
            ceiling_at: 0.0,
            signed_bucket: 0,
            pending_bucket: None,
            upgrade_streak: 0,
            last_min_rtt: None,
        }
    }

    /// The current signed bucket (whole servable layers).
    #[must_use]
    pub fn signed_bucket(&self) -> u32 {
        self.signed_bucket
    }

    /// The current p10 demonstrated floor (Mbps) — inspection / tests.
    #[must_use]
    pub fn floor_mbps(&self) -> f32 {
        self.percentile_floor()
    }

    /// The current effective (staleness-decayed) ceiling (Mbps) if a fresh
    /// congestion sample is still in force above the floor — inspection /
    /// tests. `None` before any congestion-limited sample.
    #[must_use]
    pub fn ceiling_mbps(&self) -> Option<f32> {
        self.ceiling_mbps
            .map(|_| self.effective_ceiling(self.percentile_floor()))
    }

    /// Ingest one node-level interval sample. Returns `Some(CapacityChange)`
    /// **iff the signed bucket crossed** (the coalesced re-attestation
    /// gate); `None` otherwise. Every crossing is also logged (structured
    /// `tracing`, loud — never silent).
    pub fn observe(&mut self, sample: CapacitySample) -> Option<CapacityChange> {
        // Guard a non-positive / non-finite interval — it would
        // divide-by-zero the rate and corrupt the virtual clock. A
        // degenerate tick is a no-op.
        if !sample.interval_secs.is_finite() || sample.interval_secs <= 0.0 {
            return None;
        }
        self.now_secs += sample.interval_secs;
        if let Some(rtt) = sample.min_rtt_ms {
            self.last_min_rtt = Some(rtt);
        }

        let rate = rate_mbps(sample.bytes_delivered, sample.interval_secs);
        self.window.push_back(WindowEntry {
            at: self.now_secs,
            rate_mbps: rate,
        });
        // Evict rates older than the trailing window.
        while let Some(front) = self.window.front() {
            if self.now_secs - front.at > self.cfg.floor_window_secs {
                self.window.pop_front();
            } else {
                break;
            }
        }

        let floor = self.percentile_floor();

        // Ceiling refresh — ONLY from congestion-limited samples, and only
        // when the sample rate exceeds the current floor (a congestion event
        // at or below the floor is already captured by the floor dropping as
        // its low deliveries enter the window; the ceiling only ever ADDS
        // demonstrated headroom ABOVE the floor, never drags below it — an
        // app-limited sample can therefore never raise the ceiling).
        if !sample.app_limited {
            let candidate = self.effective_ceiling(floor).max(rate);
            if candidate > floor {
                self.ceiling_mbps = Some(candidate);
                self.ceiling_at = self.now_secs;
            }
        }

        let eff_ceiling = self.effective_ceiling(floor);
        let (demonstrated, arm) = if eff_ceiling > floor {
            (eff_ceiling, EstimatorArm::CeilingSample)
        } else {
            (floor, EstimatorArm::Floor)
        };

        // Clamp to any OS/interface max (never a source of capacity — only a
        // ceiling on what we'd otherwise claim), apply the safety margin, and
        // subtract the already-committed uplink.
        let filtered = match self.cfg.os_max_mbps {
            Some(m) => demonstrated.min(m),
            None => demonstrated,
        };
        let claimable = (self.cfg.safety_margin * (filtered - self.cfg.committed_mbps)).max(0.0);
        let target = bucketize(claimable, self.cfg.layer_bitrate_mbps);

        let old_bucket = self.signed_bucket;
        let changed = self.apply_hysteresis(target);
        if !changed {
            return None;
        }

        let demonstrated_out = DemonstratedCapacity {
            #[allow(clippy::cast_precision_loss)]
            uplink_mbps: (self.signed_bucket as f32) * self.cfg.layer_bitrate_mbps,
            servable_layers: self.signed_bucket,
            demonstrated_floor_mbps: floor,
            demonstrated_mbps: demonstrated,
            min_rtt_ms: self.last_min_rtt,
            arm,
        };

        // Instrumentation (HARD REQUIREMENT): every bucket crossing is loud.
        if self.signed_bucket > old_bucket {
            tracing::info!(
                old_bucket,
                new_bucket = self.signed_bucket,
                demonstrated_floor_mbps = floor,
                demonstrated_mbps = demonstrated,
                claimable_mbps = claimable,
                arm = ?arm,
                min_rtt_ms = ?self.last_min_rtt,
                "ALM capacity bucket UP — re-attest (held K windows)"
            );
        } else {
            tracing::info!(
                old_bucket,
                new_bucket = self.signed_bucket,
                demonstrated_floor_mbps = floor,
                demonstrated_mbps = demonstrated,
                claimable_mbps = claimable,
                arm = ?arm,
                min_rtt_ms = ?self.last_min_rtt,
                "ALM capacity bucket DOWN — re-attest immediately (safety)"
            );
        }

        Some(CapacityChange {
            old_bucket,
            new_bucket: self.signed_bucket,
            demonstrated: demonstrated_out,
        })
    }

    /// Hysteresis: downgrade immediately, upgrade only after the higher
    /// bucket holds `K` consecutive windows. Returns whether the signed
    /// bucket moved.
    fn apply_hysteresis(&mut self, target: u32) -> bool {
        use std::cmp::Ordering;
        match target.cmp(&self.signed_bucket) {
            Ordering::Less => {
                // Immediate downgrade — safety trumps anti-flap.
                self.signed_bucket = target;
                self.pending_bucket = None;
                self.upgrade_streak = 0;
                true
            }
            Ordering::Greater => {
                // Upgrade candidate. Track the *lowest* target seen across
                // the streak (the level that has actually held) so a spike
                // that recedes promotes only to the sustained level, never
                // the spike. `pending_bucket == None ⟺ upgrade_streak == 0`
                // is an invariant, so `+= 1` counts the fresh window as 1.
                let candidate = self.pending_bucket.map_or(target, |p| p.min(target));
                self.pending_bucket = Some(candidate);
                self.upgrade_streak += 1;
                if candidate > self.signed_bucket
                    && self.upgrade_streak >= self.cfg.upgrade_hold_windows
                {
                    self.signed_bucket = candidate;
                    self.pending_bucket = None;
                    self.upgrade_streak = 0;
                    return true;
                }
                false
            }
            Ordering::Equal => {
                // The upgrade candidate evaporated (we're back at the signed
                // level) — reset the streak so a later upgrade must earn its
                // K windows afresh. This is what makes boundary jitter (target
                // oscillating signed↔signed+1) never thrash the signed bucket.
                self.pending_bucket = None;
                self.upgrade_streak = 0;
                false
            }
        }
    }

    /// p10 (nearest-rank) of the windowed rates — the conservative floor.
    /// Empty window ⇒ 0. Small `n` ⇒ index 0 ⇒ the window minimum (the
    /// portability invariant: fewer signals ⇒ claim less).
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn percentile_floor(&self) -> f32 {
        if self.window.is_empty() {
            return 0.0;
        }
        let mut rates: Vec<f32> = self.window.iter().map(|e| e.rate_mbps).collect();
        rates.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = rates.len();
        let rank = ((self.cfg.floor_percentile / 100.0) * ((n as f64) - 1.0)).floor() as usize;
        rates[rank.min(n - 1)]
    }

    /// The ceiling decayed for staleness: full trust below
    /// `ceiling_stale_secs`, linearly toward the floor across the decay
    /// span, then the floor. Never below the floor (the floor is
    /// independently demonstrated).
    #[allow(clippy::cast_possible_truncation)]
    fn effective_ceiling(&self, floor: f32) -> f32 {
        let Some(c) = self.ceiling_mbps else {
            return floor;
        };
        let age = self.now_secs - self.ceiling_at;
        let factor = if age <= self.cfg.ceiling_stale_secs {
            1.0
        } else if age >= self.cfg.ceiling_stale_secs + self.cfg.ceiling_decay_span_secs {
            0.0
        } else {
            1.0 - (age - self.cfg.ceiling_stale_secs) / self.cfg.ceiling_decay_span_secs
        };
        floor + (c - floor).max(0.0) * (factor as f32)
    }
}

/// Delivered bytes over an interval → megabits/sec. `f64` internally
/// (byte counts overflow `f32` precision), cast to the `f32` the
/// [`RelayCapacity`] surface uses at the boundary.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
#[must_use]
fn rate_mbps(bytes: u64, secs: f64) -> f32 {
    (((bytes as f64) * 8.0 / 1_000_000.0) / secs) as f32
}

/// Quantize a claimable rate DOWN to whole servable stream-layers.
/// `floor(claimable / layer_bitrate)`; a non-positive rate or bitrate is 0
/// layers. Downward rounding is load-bearing: it guarantees
/// `bucket × bitrate ≤ claimable`, the last step of the over-claim proof.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[must_use]
pub fn bucketize(claimable_mbps: f32, layer_bitrate_mbps: f32) -> u32 {
    if !(claimable_mbps.is_finite() && layer_bitrate_mbps.is_finite())
        || claimable_mbps <= 0.0
        || layer_bitrate_mbps <= 0.0
    {
        return 0;
    }
    (claimable_mbps / layer_bitrate_mbps).floor() as u32
}

#[cfg(test)]
#[allow(clippy::float_cmp, clippy::similar_names)]
mod tests {
    use super::*;

    /// Bytes to deliver in `secs` to demonstrate exactly `mbps`.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    fn bytes_for(mbps: f32, secs: f64) -> u64 {
        ((f64::from(mbps) * 1_000_000.0 / 8.0) * secs) as u64
    }

    /// An app-limited (floor-only) 1 s sample sustaining `mbps`.
    fn floor_sample(mbps: f32) -> CapacitySample {
        CapacitySample {
            interval_secs: 1.0,
            bytes_delivered: bytes_for(mbps, 1.0),
            min_rtt_ms: Some(40),
            app_limited: true,
        }
    }

    /// A congestion-limited (ceiling) 1 s sample delivering `mbps` while
    /// backpressured.
    fn ceiling_sample(mbps: f32) -> CapacitySample {
        CapacitySample {
            interval_secs: 1.0,
            bytes_delivered: bytes_for(mbps, 1.0),
            min_rtt_ms: Some(40),
            app_limited: false,
        }
    }

    /// Drive N identical samples, returning the last emitted change (if any).
    fn drive(est: &mut CapacityEstimator, s: CapacitySample, n: usize) -> Option<CapacityChange> {
        let mut last = None;
        for _ in 0..n {
            if let Some(c) = est.observe(s) {
                last = Some(c);
            }
        }
        last
    }

    // ── diff / aggregate (the thin impure edge, tested purely) ──────────

    #[test]
    fn diff_link_saturating_and_backpressure_fold() {
        let prev = LinkCounters {
            bytes_delivered: 1_000,
            busy_rejections: 2,
            pacing_rejections: 1,
            iface_pacing_rejections: 0,
            min_rtt_ms: Some(30),
        };
        let now = LinkCounters {
            bytes_delivered: 6_000,
            busy_rejections: 5,
            pacing_rejections: 1,
            iface_pacing_rejections: 3,
            min_rtt_ms: Some(28),
        };
        let d = diff_link(&prev, &now);
        assert_eq!(d.bytes_delivered, 5_000);
        // (5-2) + (1-1) + (3-0) = 6 backpressure events.
        assert_eq!(d.backpressure_events, 6);
        assert_eq!(d.min_rtt_ms, Some(28));

        // A link reset (counters below prev) saturates to 0, never wraps.
        let reset = LinkCounters::default();
        let d2 = diff_link(&now, &reset);
        assert_eq!(d2.bytes_delivered, 0);
        assert_eq!(d2.backpressure_events, 0);
    }

    #[test]
    fn aggregate_sums_bytes_min_rtt_and_any_backpressure() {
        let a = LinkInterval {
            bytes_delivered: 4_000,
            backpressure_events: 0,
            min_rtt_ms: Some(50),
        };
        let b = LinkInterval {
            bytes_delivered: 6_000,
            backpressure_events: 2, // one link backpressured ⇒ node congestion-limited
            min_rtt_ms: Some(20),
        };
        let s = aggregate(&[a, b], 1.0);
        assert_eq!(s.bytes_delivered, 10_000);
        assert_eq!(s.min_rtt_ms, Some(20));
        assert!(
            !s.app_limited,
            "any link backpressured ⇒ node congestion-limited"
        );

        let idle = aggregate(&[], 1.0);
        assert!(idle.app_limited);
        assert_eq!(idle.bytes_delivered, 0);
        assert_eq!(idle.min_rtt_ms, None);
    }

    // ── the pure core: filter / quantize / hysteresis / coalesce ────────

    /// Demonstrated floor tracks the sustained rate; the first crossing
    /// upgrades to it (through the K-window hold), and the output shape is
    /// the safety-margined, quantized-down servable-layer count.
    #[test]
    fn demonstrated_floor_tracks_sustained_rate() {
        // 5 Mbps/layer. Sustain 25 Mbps app-limited.
        let mut est = CapacityEstimator::new(EstimatorConfig::new(5.0));
        // floor→25, claimable = 0.75*25 = 18.75, bucket = floor(18.75/5) = 3.
        let change = drive(&mut est, floor_sample(25.0), 20).expect("bucket rose");
        assert_eq!(est.signed_bucket(), 3);
        assert_eq!(change.demonstrated.servable_layers, 3);
        assert_eq!(change.demonstrated.uplink_mbps, 15.0); // 3 layers × 5
        assert_eq!(change.demonstrated.arm, EstimatorArm::Floor);
        assert!((est.floor_mbps() - 25.0).abs() < 0.01);
        // Floor-only: no ceiling ever recorded.
        assert_eq!(est.ceiling_mbps(), None);
    }

    /// A congestion-limited burst raises the ceiling ABOVE the floor and the
    /// bucket climbs to it after the K-window hold; app-limited samples at
    /// the same rate would not.
    #[test]
    fn congestion_burst_raises_ceiling_and_upgrades() {
        let mut est = CapacityEstimator::new(EstimatorConfig::new(5.0));
        // Establish a 25 Mbps floor (bucket 3).
        drive(&mut est, floor_sample(25.0), 20);
        assert_eq!(est.signed_bucket(), 3);

        // One congestion-limited 60 Mbps sample sets the ceiling; it then
        // PERSISTS (below staleness) across app-limited follow-ups, so the
        // higher target holds its K windows and the bucket climbs.
        // ceiling→60, claimable = 0.75*60 = 45, target = floor(45/5) = 9.
        let c1 = est.observe(ceiling_sample(60.0));
        assert!(
            c1.is_none(),
            "no jump on the first higher window (K=3 hold)"
        );
        assert!(est.ceiling_mbps().unwrap() >= 60.0 - 0.5);
        assert!(
            est.observe(floor_sample(25.0)).is_none(),
            "2nd window: still held"
        );
        let up = est
            .observe(floor_sample(25.0))
            .expect("3rd consecutive higher window upgrades");
        assert_eq!(up.new_bucket, 9);
        assert_eq!(up.demonstrated.arm, EstimatorArm::CeilingSample);
    }

    /// App-limited samples NEVER raise the ceiling — even delivering far
    /// above the established floor. (They legitimately raise the passive
    /// FLOOR, which is the point of passive measurement; but the ceiling
    /// mechanism stays untouched, so `arm` never becomes `CeilingSample`.)
    #[test]
    fn app_limited_never_raises_ceiling() {
        let mut est = CapacityEstimator::new(EstimatorConfig::new(5.0));
        drive(&mut est, floor_sample(20.0), 20);
        assert_eq!(est.ceiling_mbps(), None);

        // High-rate but app-limited: the ceiling stays None; the floor
        // simply rises as the window refills with the higher deliveries.
        drive(&mut est, floor_sample(50.0), 40);
        assert_eq!(
            est.ceiling_mbps(),
            None,
            "app-limited must not set a ceiling"
        );
        assert!(
            est.floor_mbps() >= 50.0 - 0.5,
            "floor legitimately follows sustained rate"
        );
    }

    /// A bucket DOWNGRADES on the very next observe (no hold) — safety.
    #[test]
    fn bucket_downgrades_immediately() {
        let mut est = CapacityEstimator::new(EstimatorConfig::new(5.0));
        drive(&mut est, floor_sample(60.0), 40); // high floor
        let high = est.signed_bucket();
        assert!(high >= 6, "established a high bucket first");

        // Uplink collapses to 5 Mbps. The p10 floor drops fast as the low
        // deliveries dominate the window; the bucket must fall immediately
        // once the target drops below it — no K-window wait.
        let mut downgraded_at = None;
        for i in 0..40 {
            if let Some(c) = est.observe(floor_sample(5.0)) {
                if c.new_bucket < c.old_bucket && downgraded_at.is_none() {
                    downgraded_at = Some(i);
                }
            }
        }
        assert!(downgraded_at.is_some(), "a downgrade must have fired");
        // Settles to floor(0.75*5/5) = 0.
        assert_eq!(est.signed_bucket(), 0);
    }

    /// The higher bucket must hold K=3 consecutive windows before the signed
    /// bucket rises — no upgrade on windows 1 or 2.
    #[test]
    fn bucket_upgrades_only_after_k3() {
        let cfg = EstimatorConfig::new(5.0);
        assert_eq!(cfg.upgrade_hold_windows, 3);
        let mut est = CapacityEstimator::new(cfg);

        // From bucket 0, three congestion-limited 60 Mbps windows.
        assert!(
            est.observe(ceiling_sample(60.0)).is_none(),
            "window 1: no upgrade"
        );
        assert!(
            est.observe(ceiling_sample(60.0)).is_none(),
            "window 2: no upgrade"
        );
        let up = est
            .observe(ceiling_sample(60.0))
            .expect("window 3: upgrade");
        assert_eq!(up.old_bucket, 0);
        assert!(up.new_bucket > 0);
    }

    /// A jittery input whose conservatively-filtered floor stays inside ONE
    /// bucket band does NOT thrash the signed bucket — after it settles,
    /// zero further crossings are emitted despite per-sample rate jitter.
    #[test]
    fn jitter_does_not_thrash_signed_bucket() {
        let mut est = CapacityEstimator::new(EstimatorConfig::new(5.0));
        // Rates jitter 22↔28 Mbps. p10 tracks the low envelope (~22), well
        // inside bucket 3's band: claimable 0.75*22=16.5 → 3, and even the
        // high 28 → 0.75*28=21 → 4? No: we assert on the p10 floor which is
        // pinned low by the 22s, keeping the target at 3 every window.
        // Warm up to steady state first.
        for i in 0..30 {
            let mbps = if i % 2 == 0 { 22.0 } else { 28.0 };
            est.observe(floor_sample(mbps));
        }
        let settled = est.signed_bucket();
        // Now count crossings over a long jittery run — must be zero.
        let mut crossings = 0;
        for i in 0..200 {
            let mbps = if i % 2 == 0 { 22.0 } else { 28.0 };
            if est.observe(floor_sample(mbps)).is_some() {
                crossings += 1;
            }
        }
        assert_eq!(
            crossings, 0,
            "steady jitter must not move the signed bucket"
        );
        assert_eq!(est.signed_bucket(), settled);
    }

    /// Over-claim is impossible BY CONSTRUCTION: after every observe, the
    /// signed uplink never exceeds `demonstrated × SAFETY_MARGIN`. Driven by
    /// a deterministic pseudo-random mix of floor/ceiling samples so the
    /// invariant is checked across upgrades, downgrades, and decay.
    #[test]
    fn overclaim_is_impossible() {
        let mut est = CapacityEstimator::new(EstimatorConfig::new(5.0));
        // Deterministic LCG — reproducible, no rand dep.
        let mut state: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            (state >> 33) as u32
        };
        for _ in 0..5_000 {
            // `next() % 100` is ≤ 99, exact in an f32 mantissa — the
            // cast_precision_loss lint is about large u32, not this bounded value.
            #[allow(clippy::cast_precision_loss)]
            let mbps = 1.0 + (next() % 100) as f32; // 1..=100 Mbps
            let app_limited = next() % 4 != 0; // ~25% congestion-limited
            let sample = CapacitySample {
                interval_secs: 1.0,
                bytes_delivered: bytes_for(mbps, 1.0),
                min_rtt_ms: Some(u64::from(20 + next() % 60)),
                app_limited,
            };
            est.observe(sample);

            // The signed uplink the relay would attest right now.
            #[allow(clippy::cast_precision_loss)]
            let signed_uplink = (est.signed_bucket() as f32) * 5.0;
            // The most it could honestly claim = demonstrated × margin. The
            // demonstrated value is at least the floor; a fresh ceiling only
            // raises it, so `floor × margin` is a valid lower bound to test
            // against — but we test against the true demonstrated ceiling.
            let demonstrated = est
                .ceiling_mbps()
                .map_or(est.floor_mbps(), |c| c.max(est.floor_mbps()));
            let max_honest = SAFETY_MARGIN * demonstrated + 1e-3;
            assert!(
                signed_uplink <= max_honest,
                "OVER-CLAIM: signed {signed_uplink} > {max_honest} (demonstrated {demonstrated})"
            );
        }
    }

    /// The signing seam produces an unsigned `RelayCapacity` carrying the
    /// demonstrated uplink verbatim — ready for `SignedRelayCapacity::sign`.
    #[test]
    fn seam_to_relay_capacity_carries_uplink() {
        let mut est = CapacityEstimator::new(EstimatorConfig::new(5.0));
        let change = drive(&mut est, floor_sample(25.0), 20).expect("rose");
        let cap = change.demonstrated.to_relay_capacity(
            4,
            16,
            ReceiverLayerPolicy::UNCAPPED,
            1_700_000_000_000,
        );
        assert_eq!(cap.uplink_mbps, change.demonstrated.uplink_mbps);
        assert_eq!(cap.uplink_mbps, 15.0);
    }

    /// The OS/interface max is an upper CLAMP only — it caps the claim but
    /// is never itself a source of capacity.
    #[test]
    fn os_max_clamps_the_claim() {
        let mut cfg = EstimatorConfig::new(5.0);
        cfg.os_max_mbps = Some(10.0); // interface caps at 10 Mbps
        let mut est = CapacityEstimator::new(cfg);
        // Demonstrate 60 Mbps, but the clamp holds filtered at 10 →
        // claimable 0.75*10 = 7.5 → bucket 1.
        drive(&mut est, floor_sample(60.0), 40);
        assert_eq!(est.signed_bucket(), 1);
    }

    /// A committed uplink is subtracted before the margin — a busy relay
    /// signs less remaining capacity.
    #[test]
    fn committed_uplink_reduces_claim() {
        let mut cfg = EstimatorConfig::new(5.0);
        cfg.committed_mbps = 20.0; // already serving 20 Mbps
        let mut est = CapacityEstimator::new(cfg);
        // Demonstrate 40 Mbps: claimable = 0.75*(40-20) = 15 → bucket 3.
        drive(&mut est, floor_sample(40.0), 40);
        assert_eq!(est.signed_bucket(), 3);
    }
}
