//! Edge-side Counter-RII detector — `ProbePatternObserver`.
//!
//! Per RATCHET's `Counter-RII detection / Per-layer signal spec / Edge
//! layer` and CIRISEdge#39:
//!
//! Observes inbound probe-pattern signatures at the transport layer
//! (message-shape clustering, rate anomalies, timing distributions),
//! emits typed `EdgeDetectionEvent` rows tagged with `signing_key_id`
//! plus observation window for downstream joint correlation with
//! CIRISLensCore#21's 16-feature per-trace projection.
//!
//! # Joint-correlation contract (CIRISLensCore#21)
//!
//! Both layers compute a 16-feature projection over their respective
//! observation surface; lens-core's projection comes from per-trace
//! `idma_*` features (idma_correlation_risk, idma_k_eff, idma_phase,
//! entropy/coherence displacement, processing_time, llm_calls); edge's
//! projection comes from this module's rolling-window counters. A
//! joint detection requires both signals to agree for the same
//! `signing_key_id` over the same window.
//!
//! # Consent-role gating (load-bearing, F-CR-3)
//!
//! Per RATCHET's `formal/RATCHET/Core/ConsentGate.lean` F-CR-3, the
//! observer **never** records observations or emits detections for any
//! of:
//!
//! - [`ConsentRole::SelfConscience`]
//! - [`ConsentRole::AuthorizedReview`]
//! - [`ConsentRole::AuthorizedResearch`]
//! - [`ConsentRole::Peer`]
//!
//! Only [`ConsentRole::UnconsentedExternal`] passes the gate. The
//! envelope wire format does not (yet) carry a `consent_role` field;
//! until the field lands, the role is derived from the federation key
//! directory: any peer NOT in the federation_keys directory is treated
//! as `UnconsentedExternal` (fail-closed for the federation; an
//! ordinary peer-tier sender remains in the `Peer` role and is
//! suppressed). The resolver hook is
//! [`ProbePatternObserver::classify_consent_role`].
//!
//! # Configuration discipline
//!
//! [`ProbePatternConfig::enabled`] defaults to `false` — observation
//! is opt-in per deployment per the privacy posture. The
//! [`crate::EdgeConfig::probe_pattern_observer_enabled`] flag is the
//! Edge-level switch; when `false`, [`crate::Edge::detector`] is
//! `None` and the `dispatch_inbound` hook is a no-op.
//!
//! # Persistence stub
//!
//! Verdicts are computed end-to-end and emit via
//! `tracing::warn!(target = "edge::detector::verdict", ...)` —
//! persist's `DerivedSchema` trait exposes `get_edge_detection_events`
//! (read) but no `put_edge_detection_event` (write) admission as of
//! ciris-persist v3.0.0. Once the persist follow-up
//! `put_edge_detection_event` admission API lands, this module's
//! `emit_verdict` will call it with a fully-shaped
//! `EdgeDetectionEvent` row; the verdict struct already mirrors that
//! row shape 1:1.

// Statistics math (Shannon entropy, KS p-value, EWMA z-score) is
// inherently f64; the conversions from window-bounded usize / u32 / u64
// counters and chrono millisecond deltas are at most O(10^4) in
// realistic deployments — well within f64 mantissa range. The
// `cast_precision_loss` and `cast_possible_truncation` lints would
// require manual `f64::from(u32)` / `as_f64()` boilerplate that
// obscures the math; we opt out at module scope.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_lossless
)]

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::Mutex;

use crate::messages::{EdgeEnvelope, MessageType};
use crate::transport::TransportId;
use crate::verify::VerifyDirectory;

/// v0.17.0 (CIRISEdge#39) — object-safe admission shim for
/// `cirislens.edge_detection_events`. Persist's `DerivedSchema` trait
/// uses return-position `impl Future`, which is not `dyn`-compatible.
/// This thin trait wraps the single method
/// [`Self::put_edge_detection_event`] in `async_trait` so the detector
/// can hold an `Arc<dyn EdgeDetectionAdmission>` and call into either
/// `SqliteBackend` or `PostgresBackend` uniformly.
///
/// Both backends impl this via the blanket impl below (any
/// `DerivedSchema`-impler is also an admission shim).
#[async_trait::async_trait]
pub trait EdgeDetectionAdmission: Send + Sync + 'static {
    /// Admit one `EdgeDetectionEvent` row. Delegates to persist's
    /// `DerivedSchema::put_edge_detection_event` (#118).
    async fn put_edge_detection_event(
        &self,
        event: ciris_persist::derived::types::EdgeDetectionEvent,
    ) -> Result<(), ciris_persist::derived::Error>;
}

#[async_trait::async_trait]
impl<T> EdgeDetectionAdmission for T
where
    T: ciris_persist::derived::DerivedSchema + Send + Sync + 'static,
{
    async fn put_edge_detection_event(
        &self,
        event: ciris_persist::derived::types::EdgeDetectionEvent,
    ) -> Result<(), ciris_persist::derived::Error> {
        <T as ciris_persist::derived::DerivedSchema>::put_edge_detection_event(self, event).await
    }
}

/// RATCHET ConsentGate consent role (F-CR-3 vocabulary).
///
/// Mirrors RATCHET's `formal/RATCHET/Core/ConsentGate.lean` taxonomy.
/// Only [`Self::UnconsentedExternal`] permits detection emission; all
/// other roles are F-CR-3 suppressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConsentRole {
    /// Agent's own internal probes (e.g. SelfConscience-tagged
    /// self-checks). F-CR-3 suppressed.
    SelfConscience,
    /// Review-mode traffic with explicit authorization. F-CR-3
    /// suppressed.
    AuthorizedReview,
    /// Research-mode traffic with explicit authorization. F-CR-3
    /// suppressed.
    AuthorizedResearch,
    /// Ordinary peer-to-peer federation traffic. F-CR-3 suppressed
    /// — the federation IS this case.
    Peer,
    /// External, unconsented sender. The ONLY role that passes the
    /// F-CR-3 gate.
    UnconsentedExternal,
}

impl ConsentRole {
    /// Returns `true` iff a detector may record / emit for this role.
    /// Single source of truth for the F-CR-3 gate.
    #[must_use]
    pub fn permits_detection_emission(self) -> bool {
        matches!(self, Self::UnconsentedExternal)
    }
}

/// One cohort centroid from the RATCHET calibration channel.
///
/// Mirrors `ciris_persist::derived::types::CohortCentroid` in shape
/// but lives in this module (and not as a re-export) because the
/// detector consumes a *subset* of the cohort centroid surface (just
/// the per-feature centroid + variance for shape-distance scoring;
/// the cohort key + sample_count aren't load-bearing at the edge
/// detector tier — those are lens-core's territory).
#[derive(Debug, Clone)]
pub struct CohortCentroid {
    /// Per-feature centroid; length up to 16.
    pub centroid: Vec<f64>,
    /// Per-feature variance; length matches `centroid`.
    pub variance: Vec<f64>,
}

/// Configuration for [`ProbePatternObserver`].
///
/// All thresholds are calibration-channel parameters per RATCHET's
/// `formal/RATCHET/Core` spec. The defaults are conservative
/// (favouring false-negatives over false-positives) — production
/// calibration replaces them via [`Self::cohort_centroids`] and the
/// per-deployment thresholds reach the observer at runtime through the
/// `CalibrationBundle` channel (persist's
/// `get_current_calibration_bundle` accessor; lens-core's startup load
/// shapes the bundle into a `ProbePatternConfig` instance).
#[derive(Debug, Clone)]
pub struct ProbePatternConfig {
    /// Whether to observe inbound traffic at all. Default `false` —
    /// opt-in per deployment per the privacy posture (CIRISEdge#39
    /// "Configurable on/off"). When `false`, the observer is a no-op
    /// at every entry point (no allocation, no clock reads).
    pub enabled: bool,
    /// Observation window in seconds. Default `60`. Per-signing-key-id
    /// counters age out observations older than this window before
    /// computing detection statistics.
    pub window_seconds: u64,
    /// Minimum messages-per-window before a detection can fire.
    /// Default `10`. Below this floor, the signal is too sparse for
    /// statistical confidence (a single misbehaving peer with 2
    /// messages would otherwise dominate a 60-second window).
    pub min_messages_per_window: u32,
    /// Message-shape entropy threshold. Default `0.3` (nats). When
    /// the per-(signing-key-id, window) Shannon entropy over the
    /// `MessageType` discriminator distribution falls **below** this
    /// threshold, the sender is sending an unusually-clustered set of
    /// message types (the probe-shape clustering signal).
    pub message_shape_entropy_threshold: f64,
    /// Rate-anomaly z-score threshold. Default `3.0` standard
    /// deviations from baseline. The per-window rate is compared to a
    /// running baseline; a z-score **above** this threshold trips the
    /// rate-anomaly signal.
    pub rate_anomaly_zscore: f64,
    /// Timing-distribution Kolmogorov-Smirnov p-value threshold.
    /// Default `0.01`. A KS p-value **below** this threshold rejects
    /// the null hypothesis that the inter-arrival distribution
    /// matches the federation baseline (uniform exponential), tripping
    /// the timing-distribution signal.
    pub timing_distribution_kolmogorov_smirnov_pvalue: f64,
    /// RATCHET cohort centroids keyed by cohort identifier. The
    /// detector compares the per-window 16-feature projection against
    /// the cohort centroid for the sender's federation role; an
    /// out-of-cohort projection (distance beyond the variance band)
    /// contributes to the verdict's `features_16` payload that
    /// lens-core joins on. Empty map → centroid comparison skipped
    /// (the rate / shape / timing thresholds still fire).
    pub cohort_centroids: HashMap<String, CohortCentroid>,
}

impl Default for ProbePatternConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window_seconds: 60,
            min_messages_per_window: 10,
            message_shape_entropy_threshold: 0.3,
            rate_anomaly_zscore: 3.0,
            timing_distribution_kolmogorov_smirnov_pvalue: 0.01,
            cohort_centroids: HashMap::new(),
        }
    }
}

/// Per-signing-key-id rolling-window observation record.
///
/// One inbound envelope = one observation. Aged out by
/// [`ProbePatternState::prune_window`] before every
/// statistic-computation pass.
#[derive(Debug, Clone)]
struct Observation {
    /// Wall-clock when the envelope was observed.
    observed_at: DateTime<Utc>,
    /// The envelope's `MessageType` discriminator (the shape-clustering
    /// signal).
    message_type: MessageType,
    /// Transport medium the envelope arrived on (informational; not
    /// load-bearing in detection math at v0.17.0).
    #[allow(dead_code)]
    transport: TransportId,
}

/// Per-signing-key-id observation state.
///
/// All fields are guarded by a single [`tokio::sync::Mutex`] at the
/// [`ProbePatternObserver`] level — observations are inserted via
/// short critical sections; statistic computation reads the same
/// state inside the same critical section. No nested locks.
#[derive(Debug, Default)]
pub struct ProbePatternState {
    /// Per-signing-key-id rolling observation deque (window-bounded).
    per_key: HashMap<String, VecDeque<Observation>>,
    /// Per-signing-key-id consent-role cache. Populated lazily on
    /// first observation; refreshed when the role becomes stale (a
    /// federation join/leave invalidates the cache out-of-band — the
    /// detector falls back to fail-closed on cache miss).
    role_cache: HashMap<String, ConsentRole>,
    /// Per-signing-key-id rate baseline (messages-per-window). One
    /// EWMA channel per peer; the rate-anomaly z-score is computed
    /// against this. Stored as `(ewma_mean, ewma_var)`.
    rate_baseline: HashMap<String, (f64, f64)>,
}

impl ProbePatternState {
    /// Drop observations older than `cutoff` from the per-key deque.
    /// Called from every public entry point before any statistic
    /// computation.
    fn prune_window(&mut self, signing_key_id: &str, cutoff: DateTime<Utc>) {
        if let Some(deque) = self.per_key.get_mut(signing_key_id) {
            while let Some(front) = deque.front() {
                if front.observed_at < cutoff {
                    deque.pop_front();
                } else {
                    break;
                }
            }
            if deque.is_empty() {
                self.per_key.remove(signing_key_id);
            }
        }
    }
}

/// Detection verdict — mirrors persist's `EdgeDetectionEvent` row shape
/// (CIRISPersist V020 / `cirislens.edge_detection_events`).
///
/// One verdict = one prospective row. The detector hands the verdict
/// to the persistence stub; the stub will become a
/// `Engine::put_edge_detection_event` call once persist exposes the
/// write-side admission API.
#[derive(Debug, Clone)]
pub struct DetectionVerdict {
    /// Sender being flagged. Maps to `EdgeDetectionEvent.subject_key_id`.
    pub signing_key_id: String,
    /// Start of the observation window.
    pub window_start: DateTime<Utc>,
    /// End of the observation window.
    pub window_end: DateTime<Utc>,
    /// Total envelopes observed for this `signing_key_id` in window.
    pub message_count: u32,
    /// Shannon entropy over the `MessageType` distribution in window.
    /// Lower = more clustered (more probe-shaped).
    pub shape_entropy: f64,
    /// Rate z-score against the per-key baseline.
    pub rate_zscore: f64,
    /// KS p-value for inter-arrival distribution.
    pub ks_pvalue: f64,
    /// 16-feature projection that joins with lens-core's per-trace
    /// projection (CIRISLensCore#21). Order is pinned by RATCHET's
    /// `projection_version` field; v0.17.0 ships the v1 ordering:
    ///
    /// - `[0]` message_count (normalized to window)
    /// - `[1]` shape_entropy
    /// - `[2]` rate_zscore
    /// - `[3]` ks_pvalue
    /// - `[4..16]` per-MessageType-bucket counts (12 buckets, one per
    ///   MessageType variant most common in probe traffic)
    pub features_16: [f64; 16],
}

/// Edge-side probe-pattern detector. Construct via [`Self::new`].
///
/// Cheap to clone (single `Arc<Mutex>` interior). The expected
/// ownership pattern is `Arc<ProbePatternObserver>` on
/// [`crate::Edge::detector`].
pub struct ProbePatternObserver {
    /// Federation-key directory used to classify a signing key into
    /// the [`ConsentRole`] taxonomy. Cheap clone; consulted on
    /// every first-observation per signing key.
    directory: Arc<dyn VerifyDirectory>,
    /// Detector configuration. Cloned out of [`crate::EdgeConfig`] at
    /// builder time; immutable for the lifetime of the observer.
    config: ProbePatternConfig,
    /// Mutable per-signing-key-id state. Single mutex; observations
    /// are short critical sections (a deque push + a HashMap insert).
    state: Mutex<ProbePatternState>,
    /// v0.17.0 — persist `DerivedSchema` admission handle. When
    /// `Some`, [`Self::emit_verdict`] calls
    /// `put_edge_detection_event` to admit the verdict into the
    /// `cirislens.edge_detection_events` V020 table (persist#118,
    /// shipped at v3.1.1). When `None` (e.g. unit tests that don't
    /// stand up a backend), `emit_verdict` falls back to the
    /// `tracing::warn!` path documented at module scope. The
    /// production cohabitation init path (`init_edge_runtime`) wires
    /// this from the same `BackendDispatch` arm that produced the
    /// `outbound_queue_capsule` — both `SqliteBackend` and
    /// `PostgresBackend` impl `DerivedSchema` (and therefore the
    /// blanket [`EdgeDetectionAdmission`] above).
    derived_schema: Option<Arc<dyn EdgeDetectionAdmission>>,
    /// v0.17.0 — tenant scope for emitted `EdgeDetectionEvent` rows.
    /// Persist's V020 row requires a `tenant_id` (AV-51 audit-log
    /// alignment). Defaults to `"default"` when not configured; the
    /// production cohabitation init path may override via
    /// [`Self::with_tenant_id`].
    tenant_id: String,
    /// v0.17.0 — the local edge's signing key_id, recorded on every
    /// emitted `EdgeDetectionEvent` as `signing_key_id` (the detector
    /// identity, distinct from `subject_key_id` which is the suspect).
    /// Defaults to `"ciris-edge::probe-pattern-observer"` when not
    /// configured; production wiring sets the local signer's key_id.
    signing_key_id: String,
}

impl ProbePatternObserver {
    /// Construct an observer. `directory` is the same federation-key
    /// directory the verify pipeline uses; the observer consults it
    /// for consent-role classification.
    ///
    /// The observer starts WITHOUT a persist admission handle —
    /// `emit_verdict` falls back to `tracing::warn!`. Production
    /// deployments call [`Self::with_derived_schema`] to wire the
    /// `put_edge_detection_event` admission path.
    #[must_use]
    pub fn new(directory: Arc<dyn VerifyDirectory>, config: ProbePatternConfig) -> Self {
        Self {
            directory,
            config,
            state: Mutex::new(ProbePatternState::default()),
            derived_schema: None,
            tenant_id: "default".to_string(),
            signing_key_id: "ciris-edge::probe-pattern-observer".to_string(),
        }
    }

    /// v0.17.0 — attach a persist `DerivedSchema` admission handle.
    /// When set, [`Self::emit_verdict`] writes the verdict into
    /// `cirislens.edge_detection_events` via
    /// `put_edge_detection_event` (persist v3.1.1 / #118). Without
    /// this, `emit_verdict` falls back to a `tracing::warn!` log
    /// (the v0.13.0 STUB behavior).
    #[must_use]
    pub fn with_derived_schema(mut self, schema: Arc<dyn EdgeDetectionAdmission>) -> Self {
        self.derived_schema = Some(schema);
        self
    }

    /// v0.17.0 — set the `tenant_id` recorded on emitted
    /// `EdgeDetectionEvent` rows (matches `cirislens.audit_log.tenant_id`
    /// per AV-51).
    #[must_use]
    pub fn with_tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = tenant_id.into();
        self
    }

    /// v0.17.0 — set the detector's own `signing_key_id` recorded on
    /// emitted `EdgeDetectionEvent` rows. Production wiring passes the
    /// local edge's federation `key_id`; the row's `subject_key_id`
    /// remains the suspect peer's id (the field on `DetectionVerdict`).
    #[must_use]
    pub fn with_signing_key_id(mut self, signing_key_id: impl Into<String>) -> Self {
        self.signing_key_id = signing_key_id.into();
        self
    }

    /// Returns `true` iff the observer is configured-on. The
    /// `dispatch_inbound` hook checks this before any other work —
    /// a disabled observer is a single Option-is-Some + an
    /// `enabled` field read.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Classify `signing_key_id` into a [`ConsentRole`].
    ///
    /// v0.17.0 derives the role from the federation key directory:
    ///
    /// - Key found in `federation_keys` → [`ConsentRole::Peer`]
    ///   (suppressed; the federation IS the peer case).
    /// - Key NOT found in `federation_keys` → [`ConsentRole::UnconsentedExternal`]
    ///   (the F-CR-3 gate opens).
    ///
    /// Once the envelope wire format carries an explicit
    /// `consent_role` field (planned for a future schema-version
    /// bump), this method will prefer the envelope-tagged role over
    /// the directory lookup. The directory-lookup fallback remains
    /// for envelope shapes that don't carry the tag (back-compat with
    /// SchemaVersion::V1_0_0).
    ///
    /// Cache miss is the slow path (a directory `lookup_public_key`);
    /// repeat lookups hit the in-process role cache.
    pub async fn classify_consent_role(&self, signing_key_id: &str) -> ConsentRole {
        {
            let state = self.state.lock().await;
            if let Some(role) = state.role_cache.get(signing_key_id) {
                return *role;
            }
        }

        let role = match self.directory.lookup_public_key(signing_key_id).await {
            // Found in federation_keys → Peer (F-CR-3 suppresses).
            Ok(Some(_pubkey)) => ConsentRole::Peer,
            // Not found OR directory error → UnconsentedExternal
            // (fail-closed for the federation; the only role the
            // gate opens for).
            Ok(None) | Err(_) => ConsentRole::UnconsentedExternal,
        };

        {
            let mut state = self.state.lock().await;
            state.role_cache.insert(signing_key_id.to_string(), role);
        }
        role
    }

    /// Record an inbound observation.
    ///
    /// No-op when the observer is disabled OR the sender's consent
    /// role suppresses emission. Otherwise the observation is recorded
    /// into the per-key rolling deque; aging happens lazily on the
    /// next observation for the same key (and at every
    /// `check_for_detection` call).
    pub async fn observe_inbound(&self, envelope: &EdgeEnvelope, transport: TransportId) {
        if !self.config.enabled {
            return;
        }

        let role = self.classify_consent_role(&envelope.signing_key_id).await;
        if !role.permits_detection_emission() {
            return;
        }

        let now = Utc::now();
        let cutoff = now
            - chrono::Duration::seconds(
                i64::try_from(self.config.window_seconds).unwrap_or(i64::MAX),
            );

        let mut state = self.state.lock().await;
        state.prune_window(&envelope.signing_key_id, cutoff);
        let deque = state
            .per_key
            .entry(envelope.signing_key_id.clone())
            .or_default();
        deque.push_back(Observation {
            observed_at: now,
            message_type: envelope.message_type.clone(),
            transport,
        });
    }

    /// Compute statistics over the current window for `signing_key_id`
    /// and return a [`DetectionVerdict`] iff the configured thresholds
    /// are tripped.
    ///
    /// Returns `None` when:
    /// - Observer disabled
    /// - Consent role suppresses (Peer / SelfConscience /
    ///   AuthorizedReview / AuthorizedResearch)
    /// - Fewer than [`ProbePatternConfig::min_messages_per_window`]
    ///   observations in window
    /// - None of the threshold gates trip
    pub async fn check_for_detection(&self, signing_key_id: &str) -> Option<DetectionVerdict> {
        if !self.config.enabled {
            return None;
        }
        let role = self.classify_consent_role(signing_key_id).await;
        if !role.permits_detection_emission() {
            return None;
        }

        let now = Utc::now();
        let cutoff = now
            - chrono::Duration::seconds(
                i64::try_from(self.config.window_seconds).unwrap_or(i64::MAX),
            );

        let mut state = self.state.lock().await;
        state.prune_window(signing_key_id, cutoff);

        // Compute every statistic that depends on the deque first
        // (immutable borrow of `state.per_key`), THEN take the mutable
        // borrow of `state.rate_baseline` for the EWMA update — split
        // the borrows so the borrow checker accepts the back-to-back
        // accesses on the same mutex guard.
        let (message_count, window_start, window_end, shape_entropy, ks_pvalue, mut features_16) = {
            let deque = state.per_key.get(signing_key_id)?;
            let message_count_u = deque.len();
            if message_count_u < self.config.min_messages_per_window as usize {
                return None;
            }
            let message_count = u32::try_from(message_count_u).unwrap_or(u32::MAX);

            let window_start = deque.front().map_or(now, |o| o.observed_at);
            let window_end = deque.back().map_or(now, |o| o.observed_at);

            let shape_entropy = shannon_entropy_over_message_types(deque);
            let ks_pvalue =
                ks_pvalue_against_uniform_exponential(deque, self.config.window_seconds);

            let mut features_16 = [0.0f64; 16];
            features_16[0] = message_count as f64 / self.config.window_seconds.max(1) as f64;
            features_16[1] = shape_entropy;
            features_16[3] = ks_pvalue;
            // Buckets 4..16 — per-MessageType bucket counts for the 12
            // wire types most likely to appear in probe traffic.
            // Iterating the deque once is cheap (window is bounded;
            // default 60s ≥ 10 messages ≪ thousands).
            per_message_type_buckets(deque, &mut features_16[4..16]);

            (
                message_count,
                window_start,
                window_end,
                shape_entropy,
                ks_pvalue,
                features_16,
            )
        };

        let rate_zscore = update_and_compute_rate_zscore(
            &mut state.rate_baseline,
            signing_key_id,
            message_count as f64,
        );
        features_16[2] = rate_zscore;

        let entropy_trip = shape_entropy < self.config.message_shape_entropy_threshold;
        let rate_trip = rate_zscore > self.config.rate_anomaly_zscore;
        let timing_trip = ks_pvalue < self.config.timing_distribution_kolmogorov_smirnov_pvalue;

        if !(entropy_trip || rate_trip || timing_trip) {
            return None;
        }

        Some(DetectionVerdict {
            signing_key_id: signing_key_id.to_string(),
            window_start,
            window_end,
            message_count,
            shape_entropy,
            rate_zscore,
            ks_pvalue,
            features_16,
        })
    }

    /// Emit a verdict to the persistence substrate.
    ///
    /// v0.17.0 — flipped from the v0.13.0 STUB (`tracing::warn!` only)
    /// to a real persist `put_edge_detection_event` admission call now
    /// that CIRISPersist v3.1.1 (#118) ships the write-side API on
    /// `DerivedSchema`. When a derived-schema handle is wired via
    /// [`Self::with_derived_schema`], the verdict is shaped into an
    /// `EdgeDetectionEvent` row and admitted via
    /// `put_edge_detection_event`; downstream `LensCore` joint
    /// correlation reads via `get_edge_detection_events`.
    ///
    /// Row shape (matches `ciris_persist::derived::types::EdgeDetectionEvent`
    /// V020):
    ///
    /// - `detection_id` — fresh UUID per verdict
    /// - `tenant_id` — configured via [`Self::with_tenant_id`]
    /// - `subject_key_id` — `verdict.signing_key_id` (the suspect)
    /// - `observed_at` — `verdict.window_end`
    /// - `evidence` — JSON object with the four statistic fields +
    ///   the 16-feature projection (lens-core joins on this)
    /// - `detector_kind` — `"unconsented_external_probe"` (V020 vocab)
    /// - `severity` — `"warn"` (V020 vocab; verdicts that fire the
    ///   thresholds are warn-class, not block-class)
    /// - `signing_key_id` — the detector's own key_id (configured via
    ///   [`Self::with_signing_key_id`])
    /// - `signature` — empty string at v0.17.0; future cuts will sign
    ///   the canonical row via the local signer (persist treats this
    ///   field opaquely per the trait docblock)
    /// - `signature_verified` — `false` (no signature emitted yet)
    /// - `persist_row_hash` — empty string (persist fills on write)
    ///
    /// When no derived-schema handle is wired (e.g. unit tests that
    /// don't stand up a backend), the method falls back to the v0.13.0
    /// `tracing::warn!` log so the verdict is still observable.
    /// Persist errors are logged at warn level — `emit_verdict` is
    /// fire-and-forget at the dispatch site; a failed admission must
    /// not stall the inbound dispatch pipeline.
    pub async fn emit_verdict(&self, verdict: &DetectionVerdict) {
        if let Some(schema) = self.derived_schema.as_ref() {
            let event = ciris_persist::derived::types::EdgeDetectionEvent {
                detection_id: uuid::Uuid::new_v4().to_string(),
                tenant_id: self.tenant_id.clone(),
                detector_kind: "unconsented_external_probe".to_string(),
                subject_key_id: verdict.signing_key_id.clone(),
                observed_at: verdict.window_end,
                evidence: serde_json::json!({
                    "window_start": verdict.window_start,
                    "window_end": verdict.window_end,
                    "message_count": verdict.message_count,
                    "shape_entropy": verdict.shape_entropy,
                    "rate_zscore": verdict.rate_zscore,
                    "ks_pvalue": verdict.ks_pvalue,
                    "features_16": verdict.features_16,
                }),
                severity: "warn".to_string(),
                signature: String::new(),
                signing_key_id: self.signing_key_id.clone(),
                signature_verified: false,
                persist_row_hash: String::new(),
            };
            if let Err(e) = schema.put_edge_detection_event(event).await {
                tracing::warn!(
                    target: "edge::detector::verdict",
                    error = %e,
                    subject_key_id = %verdict.signing_key_id,
                    "put_edge_detection_event failed; verdict dropped",
                );
            }
        } else {
            tracing::warn!(
                target: "edge::detector::verdict",
                detector_kind = "unconsented_external_probe",
                subject_key_id = %verdict.signing_key_id,
                observed_at = %verdict.window_end,
                message_count = verdict.message_count,
                shape_entropy = verdict.shape_entropy,
                rate_zscore = verdict.rate_zscore,
                ks_pvalue = verdict.ks_pvalue,
                "ProbePatternObserver detection verdict (CIRISEdge#39); no derived-schema handle wired — verdict logged only",
            );
        }
    }

    /// Test-only accessor for the per-key observation deque length.
    #[doc(hidden)]
    pub async fn observation_count_for(&self, signing_key_id: &str) -> usize {
        let state = self.state.lock().await;
        state.per_key.get(signing_key_id).map_or(0, VecDeque::len)
    }

    /// Test-only accessor to inject a consent role into the role cache,
    /// bypassing directory lookup. Production code never uses this.
    #[doc(hidden)]
    pub async fn inject_role_for_test(&self, signing_key_id: &str, role: ConsentRole) {
        let mut state = self.state.lock().await;
        state.role_cache.insert(signing_key_id.to_string(), role);
    }
}

// ─── statistic helpers ──────────────────────────────────────────────

/// Shannon entropy in nats over the [`MessageType`] distribution.
/// Clustered traffic (a single message type dominates) → low entropy.
fn shannon_entropy_over_message_types(deque: &VecDeque<Observation>) -> f64 {
    if deque.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<MessageType, u32> = HashMap::new();
    for o in deque {
        *counts.entry(o.message_type.clone()).or_insert(0) += 1;
    }
    let total = deque.len() as f64;
    let mut h = 0.0;
    for c in counts.values() {
        let p = *c as f64 / total;
        if p > 0.0 {
            h -= p * p.ln();
        }
    }
    h
}

/// Update the per-key EWMA rate baseline and return the current
/// window's z-score against it.
///
/// First observation seeds the baseline with `(rate, 1.0)` (small
/// variance to bootstrap); subsequent observations EWMA at α = 0.2.
fn update_and_compute_rate_zscore(
    baseline: &mut HashMap<String, (f64, f64)>,
    signing_key_id: &str,
    rate: f64,
) -> f64 {
    const ALPHA: f64 = 0.2;
    let entry = baseline
        .entry(signing_key_id.to_string())
        .or_insert((0.0, 1.0));
    let (mean, var) = *entry;
    let z = if var > 0.0 {
        (rate - mean) / var.sqrt()
    } else {
        0.0
    };
    let new_mean = (1.0 - ALPHA) * mean + ALPHA * rate;
    let delta = rate - new_mean;
    let new_var = (1.0 - ALPHA) * var + ALPHA * delta * delta;
    *entry = (new_mean, new_var.max(1e-9));
    z
}

/// One-sample Kolmogorov-Smirnov p-value against a uniform exponential
/// inter-arrival distribution.
///
/// Federation baseline assumption: inter-arrival times for an ordinary
/// peer are roughly exponential (Poisson arrivals). A probe-shaped
/// sender clusters bursts → KS rejects → p-value ≪ baseline.
///
/// v0.17.0 ships a *bounded-precision* KS approximation suitable for
/// the small windows (10..few-thousand observations) the detector
/// works on. Full asymptotic KS lives in lens-core's joint correlation
/// stage. The approximation:
///
/// - empirical CDF over the inter-arrival samples
/// - reference CDF = `1 - exp(-x / mean(samples))`
/// - D = sup |F_emp - F_ref|
/// - p ≈ 2 * exp(-2 * n * D²)  (Birnbaum-Tippett bound)
fn ks_pvalue_against_uniform_exponential(
    deque: &VecDeque<Observation>,
    _window_seconds: u64,
) -> f64 {
    if deque.len() < 2 {
        return 1.0;
    }
    let mut intervals: Vec<f64> = Vec::with_capacity(deque.len() - 1);
    let mut prev = None;
    for o in deque {
        if let Some(p) = prev {
            let dt_ms = o.observed_at.signed_duration_since(p).num_milliseconds();
            intervals.push((dt_ms as f64 / 1000.0).max(0.0));
        }
        prev = Some(o.observed_at);
    }
    if intervals.is_empty() {
        return 1.0;
    }
    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if mean <= 0.0 {
        // Identical timestamps → highly-clustered → reject the null.
        return 0.0;
    }
    let mut sorted = intervals.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = sorted.len() as f64;
    let mut d_max: f64 = 0.0;
    for (i, x) in sorted.iter().enumerate() {
        let f_emp = (i + 1) as f64 / n;
        let f_ref = 1.0 - (-x / mean).exp();
        let d = (f_emp - f_ref).abs();
        if d > d_max {
            d_max = d;
        }
    }
    let p = 2.0 * (-2.0 * n * d_max * d_max).exp();
    p.clamp(0.0, 1.0)
}

/// Fill 12 per-`MessageType` count buckets into `out` (length 12).
/// Bucket order is pinned in this function — RATCHET's
/// `projection_version` v1 contract.
fn per_message_type_buckets(deque: &VecDeque<Observation>, out: &mut [f64]) {
    debug_assert_eq!(out.len(), 12);
    for o in deque {
        let idx = match o.message_type {
            MessageType::OpaqueRequest => 0,
            MessageType::OpaqueResponse => 1,
            MessageType::AttestationGossip => 2,
            MessageType::PublicKeyRegistration => 3,
            MessageType::ContentFetch => 4,
            MessageType::ContentBody => 5,
            MessageType::ContentMiss => 6,
            MessageType::OpaqueEvent => 7,
            MessageType::FederationAnnouncement => 8,
            MessageType::DeliveryAttestation => 9,
            MessageType::DeliveryRefusalAttestation => 10,
            // All other MessageType variants fall into the "other" bucket.
            _ => 11,
        };
        out[idx] += 1.0;
    }
}

// ─── tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{MessageType, OpaqueEvent, SchemaVersion};
    use crate::verify::{AccordHolderKey, HybridPolicy, VerifyError, VerifyOutcome};
    use ciris_persist::prelude::HybridVerifyError;
    use serde_json::value::RawValue;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration as StdDuration;

    /// Test-only `VerifyDirectory` impl that returns `Ok(None)` for
    /// every key (every sender is UnconsentedExternal by default) and
    /// `Ok(Some(_))` for keys that have been explicitly registered as
    /// peers via [`Self::register_peer`].
    struct TestDirectory {
        peers: parking_lot::RwLock<std::collections::HashSet<String>>,
        called: AtomicBool,
    }

    impl TestDirectory {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                peers: parking_lot::RwLock::new(std::collections::HashSet::new()),
                called: AtomicBool::new(false),
            })
        }

        fn register_peer(&self, key_id: &str) {
            self.peers.write().insert(key_id.to_string());
        }
    }

    #[async_trait::async_trait]
    impl VerifyDirectory for TestDirectory {
        async fn verify_hybrid_via_directory(
            &self,
            _canonical_bytes: &[u8],
            _signing_key_id: &str,
            _ed25519_sig_b64: &str,
            _ml_dsa_65_sig_b64: Option<&str>,
            _policy: HybridPolicy,
            _row_age: Option<StdDuration>,
        ) -> Result<VerifyOutcome, HybridVerifyError> {
            // Unused in detector tests; verify pipeline is never invoked.
            unreachable!("detector tests do not invoke verify_hybrid_via_directory")
        }

        async fn list_accord_holders(&self) -> Result<Vec<AccordHolderKey>, VerifyError> {
            Ok(Vec::new())
        }

        async fn lookup_public_key(&self, key_id: &str) -> Result<Option<[u8; 32]>, VerifyError> {
            self.called.store(true, Ordering::SeqCst);
            if self.peers.read().contains(key_id) {
                // Synthetic non-empty pubkey — the observer only checks
                // `Some` vs `None`; the bytes never reach a verify path
                // in these unit tests.
                Ok(Some([0u8; 32]))
            } else {
                Ok(None)
            }
        }
    }

    fn envelope(signing_key_id: &str, message_type: MessageType) -> EdgeEnvelope {
        let body = serde_json::to_string(&OpaqueEvent {
            kind: 1,
            payload: b"hi".to_vec(),
        })
        .unwrap();
        EdgeEnvelope {
            edge_schema_version: SchemaVersion::V2_0_0,
            signing_key_id: signing_key_id.to_string(),
            destination_key_id: "destination".into(),
            message_type,
            sent_at: Utc::now(),
            nonce: [0u8; 16],
            body: RawValue::from_string(body).unwrap(),
            signature: "AAAA".into(),
            signature_pqc: None,
            in_reply_to: None,
            // CIRIS 3.0 wire types (v0.16.0+) — fields are Option,
            // None for unit-test traffic.
            testimonial_witness: None,
            key_boundary_scope: None,
            // v0.19.1 (CIRISEdge#48-A) — cohort_scope absent on
            // detector unit-test fixtures.
            cohort_scope: None,
        }
    }

    fn enabled_config() -> ProbePatternConfig {
        ProbePatternConfig {
            enabled: true,
            window_seconds: 60,
            min_messages_per_window: 5,
            message_shape_entropy_threshold: 0.3,
            rate_anomaly_zscore: 3.0,
            timing_distribution_kolmogorov_smirnov_pvalue: 0.01,
            cohort_centroids: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn disabled_observer_is_noop() {
        let dir = TestDirectory::new();
        let mut cfg = enabled_config();
        cfg.enabled = false;
        let observer = ProbePatternObserver::new(dir.clone(), cfg);

        for _ in 0..100 {
            observer
                .observe_inbound(
                    &envelope("attacker", MessageType::OpaqueEvent),
                    TransportId::HTTP,
                )
                .await;
        }
        assert_eq!(observer.observation_count_for("attacker").await, 0);
        let verdict = observer.check_for_detection("attacker").await;
        assert!(verdict.is_none(), "disabled observer must never emit");
    }

    #[tokio::test]
    async fn consent_role_peer_never_emits() {
        let dir = TestDirectory::new();
        let observer = ProbePatternObserver::new(dir.clone(), enabled_config());
        observer
            .inject_role_for_test("peer-A", ConsentRole::Peer)
            .await;

        // 100 inbound observations from a Peer-role sender (the
        // federation case) — F-CR-3 suppresses unconditionally.
        for _ in 0..100 {
            observer
                .observe_inbound(
                    &envelope("peer-A", MessageType::OpaqueEvent),
                    TransportId::HTTP,
                )
                .await;
        }
        assert_eq!(observer.observation_count_for("peer-A").await, 0);
        assert!(observer.check_for_detection("peer-A").await.is_none());
    }

    #[tokio::test]
    async fn consent_role_self_conscience_never_emits() {
        let dir = TestDirectory::new();
        let observer = ProbePatternObserver::new(dir.clone(), enabled_config());
        observer
            .inject_role_for_test("self", ConsentRole::SelfConscience)
            .await;

        for _ in 0..100 {
            observer
                .observe_inbound(
                    &envelope("self", MessageType::OpaqueEvent),
                    TransportId::HTTP,
                )
                .await;
        }
        assert_eq!(observer.observation_count_for("self").await, 0);
        assert!(observer.check_for_detection("self").await.is_none());
    }

    #[tokio::test]
    async fn consent_role_authorized_review_never_emits() {
        let dir = TestDirectory::new();
        let observer = ProbePatternObserver::new(dir.clone(), enabled_config());
        observer
            .inject_role_for_test("reviewer", ConsentRole::AuthorizedReview)
            .await;

        for _ in 0..100 {
            observer
                .observe_inbound(
                    &envelope("reviewer", MessageType::OpaqueEvent),
                    TransportId::HTTP,
                )
                .await;
        }
        assert_eq!(observer.observation_count_for("reviewer").await, 0);
        assert!(observer.check_for_detection("reviewer").await.is_none());
    }

    #[tokio::test]
    async fn consent_role_authorized_research_never_emits() {
        let dir = TestDirectory::new();
        let observer = ProbePatternObserver::new(dir.clone(), enabled_config());
        observer
            .inject_role_for_test("researcher", ConsentRole::AuthorizedResearch)
            .await;

        for _ in 0..100 {
            observer
                .observe_inbound(
                    &envelope("researcher", MessageType::OpaqueEvent),
                    TransportId::HTTP,
                )
                .await;
        }
        assert_eq!(observer.observation_count_for("researcher").await, 0);
        assert!(observer.check_for_detection("researcher").await.is_none());
    }

    #[tokio::test]
    async fn unconsented_external_above_thresholds_emits() {
        let dir = TestDirectory::new();
        // Don't register the peer → directory lookup returns None →
        // UnconsentedExternal.
        let observer = ProbePatternObserver::new(dir.clone(), enabled_config());

        // 50 identical-MessageType observations → shape_entropy = 0.0
        // (perfectly clustered) < threshold 0.3 → trips entropy gate.
        for _ in 0..50 {
            observer
                .observe_inbound(
                    &envelope("attacker", MessageType::OpaqueEvent),
                    TransportId::HTTP,
                )
                .await;
        }
        let v = observer
            .check_for_detection("attacker")
            .await
            .expect("must emit verdict for clear probe pattern");
        assert_eq!(v.signing_key_id, "attacker");
        assert_eq!(v.message_count, 50);
        assert!(
            v.shape_entropy < 0.3,
            "shape_entropy = {} should be below threshold",
            v.shape_entropy
        );
        assert!(v.features_16[0] > 0.0, "feature[0] = rate must be non-zero");
    }

    #[tokio::test]
    async fn unconsented_external_below_thresholds_silent() {
        let dir = TestDirectory::new();
        // Loosen the config to "all thresholds quiet for varied
        // traffic" — we want to assert that an UnconsentedExternal
        // sender whose stats don't reach any threshold gets None back.
        let cfg = ProbePatternConfig {
            enabled: true,
            window_seconds: 60,
            min_messages_per_window: 100, // raise the floor — 6 obs < 100, no detection possible
            message_shape_entropy_threshold: 0.3,
            rate_anomaly_zscore: 3.0,
            timing_distribution_kolmogorov_smirnov_pvalue: 0.01,
            cohort_centroids: HashMap::new(),
        };
        let observer = ProbePatternObserver::new(dir.clone(), cfg);

        // 6 observations spread across distinct MessageTypes — well
        // below the min_messages_per_window=100 floor; even though
        // this would otherwise be a "sparse, varied" traffic profile,
        // the floor guarantees no detection without needing to
        // calibrate the rate-baseline EWMA against a specific
        // distribution.
        let types = [
            MessageType::OpaqueEvent,
            MessageType::OpaqueRequest,
            MessageType::ContentFetch,
            MessageType::ContentBody,
            MessageType::OpaqueResponse,
            MessageType::AttestationGossip,
        ];
        for t in types {
            observer
                .observe_inbound(&envelope("varied", t), TransportId::HTTP)
                .await;
        }
        let v = observer.check_for_detection("varied").await;
        assert!(
            v.is_none(),
            "sparse traffic below min_messages_per_window must not trip detector; got {v:?}"
        );
    }

    #[tokio::test]
    async fn sliding_window_eviction() {
        let dir = TestDirectory::new();
        let mut cfg = enabled_config();
        // 1-second window so the test runs in real-time.
        cfg.window_seconds = 1;
        cfg.min_messages_per_window = 1;
        let observer = ProbePatternObserver::new(dir.clone(), cfg);

        observer
            .observe_inbound(
                &envelope("transient", MessageType::OpaqueEvent),
                TransportId::HTTP,
            )
            .await;
        assert_eq!(observer.observation_count_for("transient").await, 1);

        // Sleep > window_seconds, then observe again. The first
        // observation should age out on the second `observe_inbound`'s
        // `prune_window` pass.
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        observer
            .observe_inbound(
                &envelope("transient", MessageType::OpaqueEvent),
                TransportId::HTTP,
            )
            .await;
        assert_eq!(
            observer.observation_count_for("transient").await,
            1,
            "the earlier observation must have aged out"
        );
    }

    #[tokio::test]
    async fn directory_lookup_drives_consent_role_classification() {
        let dir = TestDirectory::new();
        dir.register_peer("registered-peer");
        let observer = ProbePatternObserver::new(dir.clone(), enabled_config());

        let role_a = observer.classify_consent_role("registered-peer").await;
        assert_eq!(role_a, ConsentRole::Peer);

        let role_b = observer.classify_consent_role("not-in-directory").await;
        assert_eq!(role_b, ConsentRole::UnconsentedExternal);

        // Cache hit on second call — directory not re-consulted.
        dir.called.store(false, Ordering::SeqCst);
        let role_a_again = observer.classify_consent_role("registered-peer").await;
        assert_eq!(role_a_again, ConsentRole::Peer);
        assert!(
            !dir.called.load(Ordering::SeqCst),
            "second classification must hit the role cache, not re-consult the directory"
        );
    }
}
