//! Per-content_id consent-decay scheduler.
//!
//! CIRISPersist v8.0.0 ships **two orthogonal triggers** for
//! fountain-content eviction:
//!
//! 1. **DiskPressure** — capacity-driven. Persist evicts symbols by
//!    [`ChunkLayer.quality`] when its disk-pressure controller crosses
//!    a tier threshold. Already wired in v8.0.0; edge has no role.
//! 2. **Consent decay** — wall-clock-driven, per-`content_id`.
//!    Consensual Evolution Protocol attaches an `admitted_at` +
//!    `consent_class` envelope to every published content; the
//!    decay clock walks the tier down independent of disk pressure.
//!    TEMPORARY content has a 14-day envelope, STANDARD a 90-day
//!    envelope, PERSISTENT a longer envelope. Revocation overrides
//!    everything → immediate hard delete (GDPR Art.17).
//!
//! **Edge owns Trigger 2.** Persist exposes the eviction surface;
//! edge schedules the priority recomputation per content_id from the
//! consent envelope. This module is that scheduler.
//!
//! ## Design notes
//!
//! - **Pure compute is separated from I/O.** [`compute_decay_tier`]
//!   is a stateless function over `(schedule, now_unix_ms)` — every
//!   acceptance test in this module exercises it directly without
//!   spinning up tokio.
//! - **The runtime loop walks all content_ids on every tick.**
//!   No incremental / delta-driven scheduling at L1 — persist's
//!   own pressure controller already coalesces tier flips, so we
//!   keep the edge-side logic simple. The bench at v3.9.x will
//!   measure whether the linear walk needs amortizing; v3.9.0
//!   ships the straight-line implementation.
//! - **Per-content_id failures are non-fatal.** If `set_decay_tier`
//!   returns `Err` for one content_id, the scheduler logs (via
//!   `tracing`) and continues with the rest. The next tick retries.
//! - **The persist FFI is a trait.** Persist v8.x will land the
//!   concrete listing + tier-set + consent-schedule accessors; until
//!   then, the stub [`RealPersistHandle`] returns
//!   [`ConsentDecayError::PersistUnavailable`] and the scheduler is
//!   exercised in tests via [`MockPersistHandle`]. The trait is
//!   `Send + Sync` and every method is `async` — no specific tokio
//!   runtime config is required.
//!
//! ## Cross-repo handoff (CIRISPersist v8.x)
//!
//! The three methods on [`PersistHandle`] are the exact surface
//! edge needs from persist. Concrete API names on the persist side
//! TBD:
//!
//! - `list_fountain_content` → enumerate content_ids + current tier
//! - `set_decay_tier(content_id, tier)` → apply tier change
//! - `get_consent_schedule(content_id)` → fetch admitted_at +
//!   consent_class + revoked_at from the content's envelope
//!
//! Persist's eviction surface applies the tier on its next
//! maintenance pass — edge never blocks on the eviction itself.
//!
//! [`ChunkLayer.quality`]: ../../../docs/V3_8_0_RECOMMENDED_STACK.md

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::watch;

// ─── Types ──────────────────────────────────────────────────────────

/// Consent class metadata. Opaque to the scheduler — the scheduler
/// only consumes the day thresholds.
///
/// The three canonical class names come from CIRISPersist's Consensual
/// Evolution Protocol vocabulary (`consent_role` / `consent_record`):
/// `"TEMPORARY"`, `"STANDARD"`, `"PERSISTENT"`. Storing the name as a
/// `String` (not an enum) keeps the type extensible — a deployment can
/// define a new class via the persist-side envelope without an edge
/// release.
///
/// The five `default_*_days` fields define the decay band edges:
///
/// | Days since admission | Resulting tier |
/// |---|---|
/// | `[0, default_full_tier_days)` | [`DecayTier::Full`] |
/// | `[default_full_tier_days, default_t2_days)` | [`DecayTier::T2DropRepair`] |
/// | `[default_t2_days, default_t3_days)` | [`DecayTier::T3DropHighQuality`] |
/// | `[default_t3_days, default_t4_days)` | [`DecayTier::T4MinViableOnly`] |
/// | `[default_t4_days, default_envelope_only_days)` | [`DecayTier::T4MinViableOnly`] (final hold) |
/// | `[default_envelope_only_days, ∞)` | [`DecayTier::EnvelopeOnly`] |
///
/// (`default_t4_days == default_envelope_only_days` is the canonical
/// shape for the TEMPORARY 14-day pattern.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentClass {
    /// `"TEMPORARY"` | `"STANDARD"` | `"PERSISTENT"` — opaque to the
    /// scheduler; surfaced for logging / metrics.
    pub name: String,
    /// How long the content stays at Tier 1 (full FEC) by default.
    pub default_full_tier_days: u32,
    /// After this many days, drop K repair symbols → enters T2.
    pub default_t2_days: u32,
    /// After this many days, drop high-quality source symbols → enters T3.
    pub default_t3_days: u32,
    /// After this many days, keep only `min_viable_symbols` → enters T4.
    pub default_t4_days: u32,
    /// After this many days, drop content entirely (T5) → enters
    /// [`DecayTier::EnvelopeOnly`].
    pub default_envelope_only_days: u32,
}

impl ConsentClass {
    /// The CEP-canonical TEMPORARY 14-day decay schedule.
    ///
    /// - 0–3 days: Full
    /// - 4–7 days: T2DropRepair
    /// - 8–10 days: T3DropHighQuality
    /// - 11–13 days: T4MinViableOnly
    /// - 14+ days: EnvelopeOnly
    #[must_use]
    pub fn temporary_14_day() -> Self {
        Self {
            name: "TEMPORARY".to_string(),
            default_full_tier_days: 4,
            default_t2_days: 8,
            default_t3_days: 11,
            default_t4_days: 14,
            default_envelope_only_days: 14,
        }
    }

    /// The CEP-canonical STANDARD 90-day decay schedule. Same shape as
    /// [`ConsentClass::temporary_14_day`], longer thresholds.
    ///
    /// - 0–25 days: Full
    /// - 26–50 days: T2DropRepair
    /// - 51–69 days: T3DropHighQuality
    /// - 70–89 days: T4MinViableOnly
    /// - 90+ days: EnvelopeOnly
    #[must_use]
    pub fn standard_90_day() -> Self {
        Self {
            name: "STANDARD".to_string(),
            default_full_tier_days: 26,
            default_t2_days: 51,
            default_t3_days: 70,
            default_t4_days: 90,
            default_envelope_only_days: 90,
        }
    }
}

/// Per-content_id decay schedule snapshot, as fetched from the
/// content's CEP envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentDecaySchedule {
    pub content_id: String,
    pub consent_class: ConsentClass,
    /// Unix millis when the content was admitted (envelope field).
    pub admitted_at_unix_ms: u64,
    /// Unix millis when consent was revoked. `Some` → immediate
    /// [`DecayTier::HardDelete`] regardless of age.
    pub revoked_at_unix_ms: Option<u64>,
}

/// Computed target eviction tier for a single content_id.
///
/// The tiers correspond 1:1 with the persist-side eviction surface
/// (`docs/V3_8_0_RECOMMENDED_STACK.md` §Disk-pressure eviction policy).
/// They are also driven independently by the consent-decay scheduler
/// in this module — `set_decay_tier` is the orthogonal trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecayTier {
    /// Tier 1: all N+K symbols retained. Lossless reconstruction.
    Full,
    /// Tier 2: K repair symbols evicted. Source set still reconstructs.
    T2DropRepair,
    /// Tier 3: highest-quality source symbols evicted past ~N/2.
    /// Partial reconstruction with documented probability.
    T3DropHighQuality,
    /// Tier 4: only `min_viable_symbols` retained. Summary-shaped
    /// fragments.
    T4MinViableOnly,
    /// Tier 5: content bytes dropped; manifest envelope retained.
    /// "Trace existed with signature X."
    EnvelopeOnly,
    /// Tier 6: manifest itself dropped. Reserved for revoked consent
    /// (GDPR Art.17). Never produced by age-based decay.
    HardDelete,
}

// ─── Errors ─────────────────────────────────────────────────────────

/// Errors surfaced by the consent-decay scheduler.
#[derive(Error, Debug)]
pub enum ConsentDecayError {
    /// Persist v8.x has not yet exposed the consent-decay FFI. The
    /// stub [`RealPersistHandle`] returns this until the cross-repo
    /// handoff is wired in v3.9.x.
    #[error("persist FFI not available")]
    PersistUnavailable,

    /// Encountered a consent class the scheduler cannot interpret.
    /// Reserved for future class-vocabulary expansion; the current
    /// scheduler treats every class as opaque day-band metadata so
    /// this is not raised by the v3.9.0 logic.
    #[error("invalid consent class: {0}")]
    InvalidConsentClass(String),

    /// The scheduler fell behind its target cadence to the point that
    /// more than the configured threshold of content_ids are due for
    /// reevaluation. Reserved for runtime telemetry / future
    /// backpressure handling.
    #[error("scheduling overdue: {0} content_ids late")]
    OverdueBacklog(usize),
}

// ─── PersistHandle trait + stubs ────────────────────────────────────

/// FFI surface the scheduler needs from persist v8.x.
///
/// Every method is `async` + `Send + Sync` so the scheduler can be
/// driven from any tokio runtime config (multi-thread or current-
/// thread). Implementations are expected to be cheap-to-clone via
/// `Arc<dyn PersistHandle>`; the scheduler clones the trait object,
/// not the concrete state.
///
/// **Stub status**: at v3.9.0 L1 the concrete [`RealPersistHandle`]
/// returns [`ConsentDecayError::PersistUnavailable`] for every call.
/// Persist v8.x will land the matching surface in a follow-on cut.
#[async_trait]
pub trait PersistHandle: Send + Sync {
    /// List all fountain content_ids and their current decay tier.
    ///
    /// Returns one entry per content_id under persist's fountain-content
    /// table. Order is implementation-defined.
    async fn list_fountain_content(&self) -> Result<Vec<(String, DecayTier)>, ConsentDecayError>;

    /// Set the decay tier for `content_id`. Persist's eviction surface
    /// applies the tier on its next maintenance pass — this call does
    /// NOT block on the eviction itself.
    ///
    /// Idempotent: setting the tier to the value persist already has
    /// is a no-op on the persist side. The scheduler avoids the call
    /// when it can (see [`ConsentDecayScheduler::tick`]) but does not
    /// rely on the no-op behavior for correctness.
    async fn set_decay_tier(
        &self,
        content_id: &str,
        tier: DecayTier,
    ) -> Result<(), ConsentDecayError>;

    /// Fetch the consent schedule for `content_id` from its CEP
    /// envelope. Persist materializes the schedule from the content's
    /// `admitted_at` / `consent_class` / `revoked_at` envelope fields.
    async fn get_consent_schedule(
        &self,
        content_id: &str,
    ) -> Result<ConsentDecaySchedule, ConsentDecayError>;
}

/// Stub `PersistHandle` for the v3.9.0 L1 cut. Returns
/// [`ConsentDecayError::PersistUnavailable`] for every call. Replaced
/// by a real implementation in v3.9.x once persist exposes the
/// matching FFI.
///
/// Construct via [`RealPersistHandle::new`]; the type is
/// always-available (not `#[cfg(test)]`) so downstream consumers can
/// wire it as a placeholder while the real surface is pending.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealPersistHandle;

impl RealPersistHandle {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PersistHandle for RealPersistHandle {
    async fn list_fountain_content(&self) -> Result<Vec<(String, DecayTier)>, ConsentDecayError> {
        Err(ConsentDecayError::PersistUnavailable)
    }

    async fn set_decay_tier(
        &self,
        _content_id: &str,
        _tier: DecayTier,
    ) -> Result<(), ConsentDecayError> {
        Err(ConsentDecayError::PersistUnavailable)
    }

    async fn get_consent_schedule(
        &self,
        _content_id: &str,
    ) -> Result<ConsentDecaySchedule, ConsentDecayError> {
        Err(ConsentDecayError::PersistUnavailable)
    }
}

// ─── Scheduler ──────────────────────────────────────────────────────

const MS_PER_DAY: u64 = 24 * 60 * 60 * 1000;

/// Background scheduler that walks persist's fountain content periodically,
/// recomputes the target decay tier per content_id, and pushes tier changes
/// through the [`PersistHandle`] FFI.
///
/// Construct via [`ConsentDecayScheduler::new`]; drive with
/// [`ConsentDecayScheduler::run`].
pub struct ConsentDecayScheduler {
    cadence_secs: u64,
    persist_handle: Arc<dyn PersistHandle>,
}

impl ConsentDecayScheduler {
    /// Construct a scheduler over a persist handle.
    ///
    /// `cadence_secs` is the wall-clock interval between scheduler
    /// walks. A reasonable production default is 60 seconds — the
    /// per-content_id decay clock runs in days, so per-minute walks
    /// keep tier-flip latency bounded without overloading persist.
    /// Tests pin to short cadences to exercise the loop.
    #[must_use]
    pub fn new(persist_handle: Arc<dyn PersistHandle>, cadence_secs: u64) -> Self {
        Self {
            cadence_secs,
            persist_handle,
        }
    }

    /// Compute the target decay tier for a single content_id given its
    /// schedule and the current wall clock.
    ///
    /// Pure function — no I/O. Every acceptance test in this module
    /// exercises this directly.
    ///
    /// Decision order:
    /// 1. If `revoked_at_unix_ms` is `Some` → [`DecayTier::HardDelete`].
    /// 2. If `now < admitted_at` (clock skew) → [`DecayTier::Full`].
    /// 3. Otherwise map `(now - admitted_at) / MS_PER_DAY` against the
    ///    consent class day bands.
    #[must_use]
    pub fn compute_decay_tier(schedule: &ConsentDecaySchedule, now_unix_ms: u64) -> DecayTier {
        // Revocation overrides everything (GDPR Art.17). The manifest
        // also goes — persist's eviction surface applies HardDelete by
        // dropping the envelope row, not just the content bytes.
        if schedule.revoked_at_unix_ms.is_some() {
            return DecayTier::HardDelete;
        }

        // Clock skew tolerance: if the admitted_at timestamp is in the
        // future (the operator clock drifted, or the envelope was
        // pre-dated), don't penalize the content — hold at Full.
        if now_unix_ms < schedule.admitted_at_unix_ms {
            return DecayTier::Full;
        }

        let age_ms = now_unix_ms - schedule.admitted_at_unix_ms;
        // Saturate to u32::MAX; the boundary checks below all clamp at
        // u32 day-band edges, so saturation is equivalent to "past every
        // band" — which would have been the result anyway for a 130k+
        // year-old schedule.
        let age_days = u32::try_from(age_ms / MS_PER_DAY).unwrap_or(u32::MAX);
        let cls = &schedule.consent_class;

        if age_days < cls.default_full_tier_days {
            DecayTier::Full
        } else if age_days < cls.default_t2_days {
            DecayTier::T2DropRepair
        } else if age_days < cls.default_t3_days {
            DecayTier::T3DropHighQuality
        } else if age_days < cls.default_envelope_only_days {
            // T4 covers the window from `default_t3_days` up to
            // `default_envelope_only_days`. `default_t4_days` is the
            // *display* boundary inside this window (used by humans
            // reading the class definition); the actual T4 → T5
            // transition is at `default_envelope_only_days`.
            DecayTier::T4MinViableOnly
        } else {
            DecayTier::EnvelopeOnly
        }
    }

    /// Run a single scheduler walk over all fountain content_ids.
    ///
    /// Returns the number of tier changes pushed to persist. Per-
    /// content_id errors are logged via `tracing` and counted but do
    /// not abort the walk — the next tick retries.
    ///
    /// Exposed `pub` for testability; production drives it via
    /// [`Self::run`].
    pub async fn tick(&self, now_unix_ms: u64) -> Result<usize, ConsentDecayError> {
        let content = self.persist_handle.list_fountain_content().await?;
        let mut changed = 0usize;
        for (content_id, current_tier) in content {
            let schedule = match self.persist_handle.get_consent_schedule(&content_id).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        content_id = %content_id,
                        error = %e,
                        "consent_decay: get_consent_schedule failed; skipping content_id",
                    );
                    continue;
                }
            };
            let target = Self::compute_decay_tier(&schedule, now_unix_ms);
            if target == current_tier {
                continue;
            }
            match self
                .persist_handle
                .set_decay_tier(&content_id, target)
                .await
            {
                Ok(()) => {
                    changed += 1;
                    tracing::debug!(
                        content_id = %content_id,
                        from = ?current_tier,
                        to = ?target,
                        "consent_decay: tier changed",
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        content_id = %content_id,
                        target = ?target,
                        error = %e,
                        "consent_decay: set_decay_tier failed; will retry next tick",
                    );
                }
            }
        }
        Ok(changed)
    }

    /// Run the scheduler in a tokio task until `shutdown` is signalled.
    ///
    /// Each cadence tick walks all fountain content_ids via the
    /// `PersistHandle` and pushes tier changes. The shutdown signal is
    /// observed cooperatively — `run` returns within at most ~2×
    /// `cadence_secs` of the signal flipping.
    ///
    /// Returns `Ok(())` on clean shutdown. Returns the first
    /// scheduler-level error (i.e., from `list_fountain_content`) only
    /// if it is fatal at the trait level — per-content_id failures
    /// are non-fatal (see [`Self::tick`]).
    pub async fn run(&self, mut shutdown: watch::Receiver<()>) -> Result<(), ConsentDecayError> {
        let cadence = Duration::from_secs(self.cadence_secs.max(1));
        let mut ticker = tokio::time::interval(cadence);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!("consent_decay: shutdown received");
                    return Ok(());
                }
                _ = ticker.tick() => {
                    let now_unix_ms = current_unix_ms();
                    match self.tick(now_unix_ms).await {
                        Ok(n) => {
                            if n > 0 {
                                tracing::info!(changed = n, "consent_decay: tick complete");
                            }
                        }
                        Err(e) => {
                            // A `list_fountain_content` failure is
                            // recoverable across ticks — log and keep
                            // running. Returning early here would let
                            // a transient persist error tear down the
                            // scheduler.
                            tracing::warn!(error = %e, "consent_decay: tick failed");
                        }
                    }
                }
            }
        }
    }
}

fn current_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory `PersistHandle` for tests. Tracks call counts so the
    /// `_only_sets_tier_when_it_differs` test can assert on
    /// `set_decay_tier` not firing for matching tiers.
    #[derive(Debug, Default)]
    struct MockPersistHandle {
        content: Mutex<Vec<(String, DecayTier)>>,
        schedules: Mutex<HashMap<String, ConsentDecaySchedule>>,
        set_calls: Mutex<Vec<(String, DecayTier)>>,
        list_calls: Mutex<usize>,
        get_calls: Mutex<HashMap<String, usize>>,
        fail_set_for: Mutex<Option<String>>,
    }

    impl MockPersistHandle {
        fn insert(
            &self,
            content_id: &str,
            current_tier: DecayTier,
            schedule: ConsentDecaySchedule,
        ) {
            self.content
                .lock()
                .unwrap()
                .push((content_id.to_string(), current_tier));
            self.schedules
                .lock()
                .unwrap()
                .insert(content_id.to_string(), schedule);
        }

        fn fail_set_for(&self, content_id: &str) {
            *self.fail_set_for.lock().unwrap() = Some(content_id.to_string());
        }

        fn set_calls(&self) -> Vec<(String, DecayTier)> {
            self.set_calls.lock().unwrap().clone()
        }

        fn list_call_count(&self) -> usize {
            *self.list_calls.lock().unwrap()
        }

        fn get_call_count(&self, content_id: &str) -> usize {
            *self.get_calls.lock().unwrap().get(content_id).unwrap_or(&0)
        }
    }

    #[async_trait]
    impl PersistHandle for MockPersistHandle {
        async fn list_fountain_content(
            &self,
        ) -> Result<Vec<(String, DecayTier)>, ConsentDecayError> {
            *self.list_calls.lock().unwrap() += 1;
            Ok(self.content.lock().unwrap().clone())
        }

        async fn set_decay_tier(
            &self,
            content_id: &str,
            tier: DecayTier,
        ) -> Result<(), ConsentDecayError> {
            if let Some(ref target) = *self.fail_set_for.lock().unwrap() {
                if target == content_id {
                    return Err(ConsentDecayError::PersistUnavailable);
                }
            }
            self.set_calls
                .lock()
                .unwrap()
                .push((content_id.to_string(), tier));
            // Update the stored current_tier too so a follow-up tick
            // sees the new state.
            let mut content = self.content.lock().unwrap();
            for (cid, t) in content.iter_mut() {
                if cid == content_id {
                    *t = tier;
                }
            }
            Ok(())
        }

        async fn get_consent_schedule(
            &self,
            content_id: &str,
        ) -> Result<ConsentDecaySchedule, ConsentDecayError> {
            *self
                .get_calls
                .lock()
                .unwrap()
                .entry(content_id.to_string())
                .or_insert(0) += 1;
            self.schedules
                .lock()
                .unwrap()
                .get(content_id)
                .cloned()
                .ok_or_else(|| {
                    ConsentDecayError::InvalidConsentClass(format!("no schedule for {content_id}"))
                })
        }
    }

    fn sched(class: ConsentClass, admitted_at_unix_ms: u64) -> ConsentDecaySchedule {
        ConsentDecaySchedule {
            content_id: "test".to_string(),
            consent_class: class,
            admitted_at_unix_ms,
            revoked_at_unix_ms: None,
        }
    }

    #[test]
    fn compute_decay_tier_temporary_14_day_schedule() {
        let s = sched(ConsentClass::temporary_14_day(), 0);
        // 0..=3 days: Full
        for d in 0u64..=3 {
            assert_eq!(
                ConsentDecayScheduler::compute_decay_tier(&s, d * MS_PER_DAY),
                DecayTier::Full,
                "day {d} should be Full"
            );
        }
        // 4..=7 days: T2DropRepair
        for d in 4u64..=7 {
            assert_eq!(
                ConsentDecayScheduler::compute_decay_tier(&s, d * MS_PER_DAY),
                DecayTier::T2DropRepair,
                "day {d} should be T2DropRepair"
            );
        }
        // 8..=10 days: T3DropHighQuality
        for d in 8u64..=10 {
            assert_eq!(
                ConsentDecayScheduler::compute_decay_tier(&s, d * MS_PER_DAY),
                DecayTier::T3DropHighQuality,
                "day {d} should be T3DropHighQuality"
            );
        }
        // 11..=13 days: T4MinViableOnly
        for d in 11u64..=13 {
            assert_eq!(
                ConsentDecayScheduler::compute_decay_tier(&s, d * MS_PER_DAY),
                DecayTier::T4MinViableOnly,
                "day {d} should be T4MinViableOnly"
            );
        }
        // 14+ days: EnvelopeOnly
        for d in [14u64, 15, 30, 365] {
            assert_eq!(
                ConsentDecayScheduler::compute_decay_tier(&s, d * MS_PER_DAY),
                DecayTier::EnvelopeOnly,
                "day {d} should be EnvelopeOnly"
            );
        }
    }

    #[test]
    fn compute_decay_tier_standard_90_day_schedule() {
        let s = sched(ConsentClass::standard_90_day(), 0);
        // Same shape, longer thresholds. Spot-check each band edge.
        // 0..=25 days: Full
        for d in [0u64, 10, 25] {
            assert_eq!(
                ConsentDecayScheduler::compute_decay_tier(&s, d * MS_PER_DAY),
                DecayTier::Full,
                "day {d} should be Full"
            );
        }
        // 26..=50 days: T2DropRepair
        for d in [26u64, 40, 50] {
            assert_eq!(
                ConsentDecayScheduler::compute_decay_tier(&s, d * MS_PER_DAY),
                DecayTier::T2DropRepair,
                "day {d} should be T2DropRepair"
            );
        }
        // 51..=69 days: T3DropHighQuality
        for d in [51u64, 60, 69] {
            assert_eq!(
                ConsentDecayScheduler::compute_decay_tier(&s, d * MS_PER_DAY),
                DecayTier::T3DropHighQuality,
                "day {d} should be T3DropHighQuality"
            );
        }
        // 70..=89 days: T4MinViableOnly
        for d in [70u64, 80, 89] {
            assert_eq!(
                ConsentDecayScheduler::compute_decay_tier(&s, d * MS_PER_DAY),
                DecayTier::T4MinViableOnly,
                "day {d} should be T4MinViableOnly"
            );
        }
        // 90+ days: EnvelopeOnly
        for d in [90u64, 91, 365, 730] {
            assert_eq!(
                ConsentDecayScheduler::compute_decay_tier(&s, d * MS_PER_DAY),
                DecayTier::EnvelopeOnly,
                "day {d} should be EnvelopeOnly"
            );
        }
    }

    #[test]
    fn compute_decay_tier_revoked_immediate_hard_delete() {
        // Revoked overrides the age-based tier — even at day 0 with a
        // freshly admitted TEMPORARY schedule.
        let mut s = sched(ConsentClass::temporary_14_day(), 0);
        s.revoked_at_unix_ms = Some(1);
        assert_eq!(
            ConsentDecayScheduler::compute_decay_tier(&s, 0),
            DecayTier::HardDelete
        );
        assert_eq!(
            ConsentDecayScheduler::compute_decay_tier(&s, 100 * MS_PER_DAY),
            DecayTier::HardDelete,
            "revoked content stays HardDelete regardless of age"
        );

        // Same for STANDARD.
        let mut s = sched(ConsentClass::standard_90_day(), 0);
        s.revoked_at_unix_ms = Some(123_456_789);
        assert_eq!(
            ConsentDecayScheduler::compute_decay_tier(&s, 1_000_000_000),
            DecayTier::HardDelete
        );
    }

    #[test]
    fn compute_decay_tier_pre_admission_clock_skew_returns_full() {
        // Admitted in the future relative to `now` — operator clock
        // drifted, or envelope was pre-dated. Hold at Full rather than
        // penalize content for a clock error.
        let s = sched(ConsentClass::temporary_14_day(), 1_000_000_000_000);
        assert_eq!(
            ConsentDecayScheduler::compute_decay_tier(&s, 999_999_999_999),
            DecayTier::Full,
            "now < admitted_at should yield Full (clock skew tolerance)"
        );
        // At the exact boundary it's still Full (age == 0).
        assert_eq!(
            ConsentDecayScheduler::compute_decay_tier(&s, 1_000_000_000_000),
            DecayTier::Full
        );
    }

    #[tokio::test]
    async fn scheduler_walks_all_content_ids() {
        let handle = Arc::new(MockPersistHandle::default());
        for i in 0..10 {
            let cid = format!("c{i}");
            handle.insert(
                &cid,
                DecayTier::Full,
                ConsentDecaySchedule {
                    content_id: cid.clone(),
                    consent_class: ConsentClass::temporary_14_day(),
                    admitted_at_unix_ms: 0,
                    revoked_at_unix_ms: None,
                },
            );
        }
        let sched_h: Arc<dyn PersistHandle> = handle.clone();
        let scheduler = ConsentDecayScheduler::new(sched_h, 60);
        // Now is "day 5" → all 10 content_ids should transition from
        // Full to T2DropRepair.
        let now = 5 * MS_PER_DAY;
        let changed = scheduler.tick(now).await.unwrap();
        assert_eq!(changed, 10, "all 10 content_ids should have changed tier");
        // All 10 schedules were fetched.
        for i in 0..10 {
            let cid = format!("c{i}");
            assert_eq!(handle.get_call_count(&cid), 1, "{cid} get_call_count");
        }
        // All 10 set_decay_tier calls happened, each with T2DropRepair.
        let calls = handle.set_calls();
        assert_eq!(calls.len(), 10);
        for (_, tier) in &calls {
            assert_eq!(*tier, DecayTier::T2DropRepair);
        }
        // One list call per tick.
        assert_eq!(handle.list_call_count(), 1);
    }

    #[tokio::test]
    async fn scheduler_only_sets_tier_when_it_differs() {
        let handle = Arc::new(MockPersistHandle::default());
        // c_at_target is already at the tier the decay function will
        // pick for "day 5". c_will_change is currently at Full and
        // needs to move to T2DropRepair.
        handle.insert(
            "c_at_target",
            DecayTier::T2DropRepair,
            ConsentDecaySchedule {
                content_id: "c_at_target".to_string(),
                consent_class: ConsentClass::temporary_14_day(),
                admitted_at_unix_ms: 0,
                revoked_at_unix_ms: None,
            },
        );
        handle.insert(
            "c_will_change",
            DecayTier::Full,
            ConsentDecaySchedule {
                content_id: "c_will_change".to_string(),
                consent_class: ConsentClass::temporary_14_day(),
                admitted_at_unix_ms: 0,
                revoked_at_unix_ms: None,
            },
        );
        let sched_h: Arc<dyn PersistHandle> = handle.clone();
        let scheduler = ConsentDecayScheduler::new(sched_h, 60);
        let now = 5 * MS_PER_DAY;
        let changed = scheduler.tick(now).await.unwrap();
        assert_eq!(changed, 1);
        let calls = handle.set_calls();
        assert_eq!(
            calls.len(),
            1,
            "only the content_id whose tier differs should be set"
        );
        assert_eq!(calls[0].0, "c_will_change");
        assert_eq!(calls[0].1, DecayTier::T2DropRepair);
    }

    #[tokio::test]
    async fn scheduler_continues_after_individual_failure() {
        let handle = Arc::new(MockPersistHandle::default());
        for i in 0..5 {
            let cid = format!("c{i}");
            handle.insert(
                &cid,
                DecayTier::Full,
                ConsentDecaySchedule {
                    content_id: cid.clone(),
                    consent_class: ConsentClass::temporary_14_day(),
                    admitted_at_unix_ms: 0,
                    revoked_at_unix_ms: None,
                },
            );
        }
        // c2's set_decay_tier will fail; the other 4 must still
        // succeed.
        handle.fail_set_for("c2");

        let sched_h: Arc<dyn PersistHandle> = handle.clone();
        let scheduler = ConsentDecayScheduler::new(sched_h, 60);
        let now = 5 * MS_PER_DAY;
        let changed = scheduler.tick(now).await.unwrap();
        assert_eq!(changed, 4, "4 of 5 should have changed; c2 failed");

        let calls = handle.set_calls();
        // Only the 4 successful calls were recorded.
        assert_eq!(calls.len(), 4);
        for (cid, _) in &calls {
            assert_ne!(cid, "c2", "c2 should not be in the success list");
        }
    }

    #[tokio::test]
    async fn scheduler_respects_shutdown() {
        // Cadence = 1 second; shutdown signal flipped immediately;
        // scheduler must exit within ~2× cadence = 2 seconds.
        let handle: Arc<dyn PersistHandle> = Arc::new(MockPersistHandle::default());
        let scheduler = ConsentDecayScheduler::new(handle, 1);
        let (tx, rx) = watch::channel(());
        let join = tokio::spawn(async move { scheduler.run(rx).await });
        // Flip immediately.
        tx.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), join)
            .await
            .expect("scheduler did not exit within 2× cadence")
            .expect("scheduler task panicked");
        assert!(result.is_ok(), "scheduler.run returned Err: {result:?}");
    }

    #[tokio::test]
    async fn real_persist_handle_stub_returns_unavailable() {
        let h = RealPersistHandle::new();
        assert!(matches!(
            h.list_fountain_content().await,
            Err(ConsentDecayError::PersistUnavailable)
        ));
        assert!(matches!(
            h.set_decay_tier("c", DecayTier::Full).await,
            Err(ConsentDecayError::PersistUnavailable)
        ));
        assert!(matches!(
            h.get_consent_schedule("c").await,
            Err(ConsentDecayError::PersistUnavailable)
        ));
    }
}
