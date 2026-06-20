//! §3.1 emission scheduler runtime (CIRISEdge#175, v6.1.0).
//!
//! Wires together the [`super::poisson::PoissonScheduler`] timer
//! source, the [`super::budget::BudgetMeter`] lifetime-average
//! inequality, the [`super::envelope`] AEAD framing, and the
//! [`super::fragment`] chunker into a single runtime the
//! enumerated emission paths (FSD §6.1) feed real publications
//! through.
//!
//! # Surface
//!
//! Consumers construct a [`Scheduler`] with [`SchedulerConfig`],
//! [`Scheduler::start`] it on a tokio task, and then `submit`
//! real publications. The scheduler:
//!
//! 1. fragments the payload into 1.4 KB envelopes,
//! 2. enqueues fragments at the matching scope's queue,
//! 3. wakes the per-scope Poisson loop, which fires on
//!    `Exp(λ_scope)` intervals,
//! 4. on each fire, queries the [`BudgetMeter`] — if real budget
//!    is available AND the queue is non-empty, emits the next
//!    real envelope; if real queue empty OR budget exhausted,
//!    emits a synthetic cover envelope,
//! 5. invokes the wire-side `EmitFn` (`async dyn Fn(EmissionEnvelope)`).
//!
//! The wire-side emit fn is plugged in by the caller — typically a
//! `Transport::send`-style closure. The scheduler is transport-
//! agnostic (FSD §3.1 maintenance-cover-budget is independent of
//! the transport choice).

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use tokio::sync::Notify;

use super::budget::{BudgetMeter, BudgetState};
use super::envelope::{seal_envelope, EmissionEnvelope, EmissionHeader, MAX_PAYLOAD_BYTES};
use super::fragment::{fragment_payload, FragmentError};
use super::poisson::{PoissonScheduler, ScopeKey};

/// Wire-side emit closure type. The scheduler hands the closure one
/// sealed [`EmissionEnvelope`] per timer fire.
pub type EmitFn =
    Arc<dyn Fn(EmissionEnvelope) -> futures::future::BoxFuture<'static, ()> + Send + Sync>;

/// Per-scope configuration.
#[derive(Debug, Clone)]
pub struct ScopeConfig {
    /// Poisson rate λ_scope (emissions/second).
    pub lambda: f64,
    /// `target_real_per_window` for the budget meter.
    pub target_real_per_window: u32,
    /// Window duration for the budget meter.
    pub window: Duration,
    /// Per-scope AEAD key (the FSD §2.2 `K_record_id`/`K_symbol`
    /// for community/family/self scope, or a federation-public key
    /// for federation scope). The scope key is the AEAD key the
    /// envelope is sealed under.
    pub scope_key: [u8; 32],
}

/// Top-level scheduler configuration.
#[derive(Default, Clone)]
pub struct SchedulerConfig {
    /// Per-scope configuration map.
    pub scopes: HashMap<ScopeKey, ScopeConfig>,
}

impl fmt::Debug for SchedulerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SchedulerConfig")
            .field("num_scopes", &self.scopes.len())
            .finish()
    }
}

/// One real publication queued at a specific scope.
#[derive(Debug, Clone)]
struct QueuedFragment {
    header: EmissionHeader,
    payload: Vec<u8>,
}

/// Per-scope queue state. Shared across the submit path and the
/// per-scope timer loop.
struct ScopeQueue {
    config: ScopeConfig,
    queue: Mutex<VecDeque<QueuedFragment>>,
    notify: Notify,
}

/// Errors from [`Scheduler::submit`].
#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    /// No scope configuration registered for the submitted scope.
    #[error("scope not registered with the scheduler")]
    ScopeNotRegistered,
    /// Fragmentation failure.
    #[error("fragmentation: {0}")]
    Fragment(#[from] FragmentError),
}

/// Scheduler runtime stats snapshot.
#[derive(Debug, Clone, Default)]
pub struct SchedulerStats {
    /// Total real envelopes emitted since start, per scope.
    pub real_emitted: HashMap<ScopeKey, u64>,
    /// Total cover envelopes emitted since start, per scope.
    pub cover_emitted: HashMap<ScopeKey, u64>,
    /// Current queue depth, per scope.
    pub queue_depth: HashMap<ScopeKey, u64>,
}

/// Handle to a running scheduler.
#[derive(Clone)]
pub struct SchedulerHandle {
    stats: Arc<Mutex<SchedulerStats>>,
    queues: Arc<HashMap<ScopeKey, Arc<ScopeQueue>>>,
}

impl SchedulerHandle {
    /// Snapshot the scheduler's current stats. Includes per-scope
    /// real/cover counts since start.
    #[must_use]
    pub fn stats(&self) -> SchedulerStats {
        let mut s = self.stats.lock().clone();
        for (scope, q) in self.queues.iter() {
            let depth = q.queue.lock().len() as u64;
            s.queue_depth.insert(scope.clone(), depth);
        }
        s
    }
}

/// §3.1 Poisson emission scheduler.
///
/// The scheduler owns a [`PoissonScheduler`] (CSPRNG-driven Poisson
/// timer source), a [`BudgetMeter`] (lifetime-average λ inequality),
/// and one queue per configured scope. [`Scheduler::start`] spawns
/// a per-scope timer loop on the tokio runtime.
pub struct Scheduler {
    poisson: Arc<PoissonScheduler>,
    budget: Arc<BudgetMeter>,
    queues: Arc<HashMap<ScopeKey, Arc<ScopeQueue>>>,
    emit: EmitFn,
    stats: Arc<Mutex<SchedulerStats>>,
}

impl Scheduler {
    /// Construct a scheduler over `config`. Uses an `OsRng`-derived
    /// CSPRNG seed for the Poisson timer. Caller must call
    /// [`Self::start`] to actually drive emissions.
    #[must_use]
    pub fn new(config: SchedulerConfig, emit: EmitFn) -> Self {
        Self::new_with_poisson(config, emit, Arc::new(PoissonScheduler::new()))
    }

    /// Construct with an explicit Poisson scheduler. **Test-only**.
    #[must_use]
    pub fn new_with_poisson(
        config: SchedulerConfig,
        emit: EmitFn,
        poisson: Arc<PoissonScheduler>,
    ) -> Self {
        let budget = Arc::new(BudgetMeter::new());
        let mut queues = HashMap::new();
        for (scope, scope_cfg) in config.scopes {
            poisson.set_rate(scope.clone(), scope_cfg.lambda);
            budget.configure(
                scope.clone(),
                scope_cfg.target_real_per_window,
                scope_cfg.window,
            );
            queues.insert(
                scope,
                Arc::new(ScopeQueue {
                    config: scope_cfg,
                    queue: Mutex::new(VecDeque::new()),
                    notify: Notify::new(),
                }),
            );
        }
        Self {
            poisson,
            budget,
            queues: Arc::new(queues),
            emit,
            stats: Arc::new(Mutex::new(SchedulerStats::default())),
        }
    }

    /// Submit a real publication payload. The scheduler fragments
    /// it and enqueues each fragment at the matching scope.
    ///
    /// `record_id` is the FSD §2.4 HMAC-SHA3 record_id for the
    /// publication; `fragment_id` is the per-emitter monotonic
    /// counter the reassembler matches on.
    ///
    /// # Errors
    ///
    /// - [`SubmitError::ScopeNotRegistered`] — scope absent from
    ///   the scheduler's configuration.
    /// - [`SubmitError::Fragment`] — fragmentation error (empty
    ///   payload, or count overflow).
    pub fn submit(
        &self,
        scope: &ScopeKey,
        record_id: [u8; 32],
        fragment_id: u32,
        payload: &[u8],
    ) -> Result<u32, SubmitError> {
        let queue = self
            .queues
            .get(scope)
            .ok_or(SubmitError::ScopeNotRegistered)?;
        let scope_tag = scope.scope;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let set = fragment_payload(scope_tag, record_id, fragment_id, now_ms, payload)?;
        // Bounded by `fragment_payload`'s own u32 check.
        let count = u32::try_from(set.fragments.len())
            .expect("fragment_payload's u32 check ensures len ≤ u32::MAX");
        {
            let mut q = queue.queue.lock();
            for f in set.fragments {
                q.push_back(QueuedFragment {
                    header: f.header,
                    payload: f.payload,
                });
            }
        }
        queue.notify.notify_one();
        Ok(count)
    }

    /// Start the scheduler — spawns one tokio task per configured
    /// scope. Returns a [`SchedulerHandle`] usable for stat reads.
    pub fn start(self) -> SchedulerHandle {
        for (scope_key, queue) in self.queues.iter() {
            let scope_key = scope_key.clone();
            let queue = queue.clone();
            let poisson = self.poisson.clone();
            let budget = self.budget.clone();
            let emit = self.emit.clone();
            let stats = self.stats.clone();
            tokio::spawn(async move {
                run_scope_loop(scope_key, queue, poisson, budget, emit, stats).await;
            });
        }
        SchedulerHandle {
            stats: self.stats.clone(),
            queues: self.queues.clone(),
        }
    }
}

impl fmt::Debug for Scheduler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only `queues.len()` is human-meaningful at this level;
        // the other fields are opaque shared handles (CSPRNG state,
        // budget meter, emit closure, stats counters). Using
        // `finish_non_exhaustive` to satisfy clippy's
        // missing-fields-in-debug lint without leaking internals.
        f.debug_struct("Scheduler")
            .field("scopes", &self.queues.len())
            .finish_non_exhaustive()
    }
}

async fn run_scope_loop(
    scope: ScopeKey,
    queue: Arc<ScopeQueue>,
    poisson: Arc<PoissonScheduler>,
    budget: Arc<BudgetMeter>,
    emit: EmitFn,
    stats: Arc<Mutex<SchedulerStats>>,
) {
    let scope_tag = scope.scope;
    let scope_key_bytes = queue.config.scope_key;

    loop {
        // Sample the next interval. None → scope disabled; just
        // sleep on the notify.
        let Some(t_next) = poisson.next_interval(&scope) else {
            queue.notify.notified().await;
            continue;
        };
        tokio::time::sleep(t_next).await;

        // Decide real vs. cover on timer fire.
        let budget_state = budget.query(&scope);

        // Pull head-of-queue if real budget available; otherwise force cover.
        let to_emit = match budget_state {
            BudgetState::UnderBudget { .. } => {
                let head = queue.queue.lock().pop_front();
                if let Some(qf) = head {
                    EmissionTarget::Real(qf)
                } else {
                    EmissionTarget::Cover
                }
            }
            BudgetState::OverBudget { .. } | BudgetState::Unconfigured => EmissionTarget::Cover,
        };

        // Draw a 24-byte nonce + cover-payload bytes (if cover)
        // from the same peer-local CSPRNG.
        let mut nonce = [0u8; ciris_crypto::xchacha::NONCE_LEN];
        poisson.fill_bytes(&mut nonce);

        let envelope_result = match &to_emit {
            EmissionTarget::Real(qf) => {
                seal_envelope(&scope_key_bytes, &nonce, &qf.header, &qf.payload)
            }
            EmissionTarget::Cover => {
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                let header = EmissionHeader::cover(scope_tag, now_ms);
                let mut cover_payload = vec![0u8; MAX_PAYLOAD_BYTES];
                poisson.fill_bytes(&mut cover_payload);
                seal_envelope(&scope_key_bytes, &nonce, &header, &cover_payload)
            }
        };

        let envelope = match envelope_result {
            Ok(env) => env,
            Err(e) => {
                tracing::warn!(
                    target: "ciris_edge::emission::scheduler",
                    scope_kind = ?scope_tag,
                    error = %e,
                    "envelope seal failed; dropping emission slot"
                );
                continue;
            }
        };

        // Update stats + budget BEFORE the await (small race window
        // doesn't matter for stat accuracy).
        match &to_emit {
            EmissionTarget::Real(_) => {
                budget.record_real(&scope);
                let mut s = stats.lock();
                *s.real_emitted.entry(scope.clone()).or_insert(0) += 1;
            }
            EmissionTarget::Cover => {
                budget.record_cover(&scope);
                let mut s = stats.lock();
                *s.cover_emitted.entry(scope.clone()).or_insert(0) += 1;
            }
        }

        emit(envelope).await;
    }
}

enum EmissionTarget {
    Real(QueuedFragment),
    Cover,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn make_emit() -> (EmitFn, Arc<AtomicU64>, Arc<Mutex<Vec<EmissionEnvelope>>>) {
        let count = Arc::new(AtomicU64::new(0));
        let envelopes: Arc<Mutex<Vec<EmissionEnvelope>>> = Arc::new(Mutex::new(Vec::new()));
        let count_inner = count.clone();
        let envelopes_inner = envelopes.clone();
        let f: EmitFn = Arc::new(move |env: EmissionEnvelope| {
            let count_inner = count_inner.clone();
            let envelopes_inner = envelopes_inner.clone();
            Box::pin(async move {
                count_inner.fetch_add(1, Ordering::Relaxed);
                envelopes_inner.lock().push(env);
            })
        });
        (f, count, envelopes)
    }

    fn one_scope_config(lambda: f64) -> SchedulerConfig {
        let mut cfg = SchedulerConfig::default();
        cfg.scopes.insert(
            ScopeKey::community("alpha".into()),
            ScopeConfig {
                lambda,
                target_real_per_window: 100,
                window: Duration::from_secs(10),
                scope_key: [0x42; 32],
            },
        );
        cfg
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cover_emission_when_queue_empty() {
        // High λ, no real submissions — every fire is a cover.
        // We drive the scheduler with λ=1000 (1 ms mean interval)
        // and observe for ~150 ms; should see several emissions.
        let (emit, count, _envs) = make_emit();
        let poisson = Arc::new(PoissonScheduler::from_seed([0x77; 32]));
        let sched = Scheduler::new_with_poisson(one_scope_config(1000.0), emit, poisson);
        let handle = sched.start();

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(count.load(Ordering::Relaxed) > 0, "at least one emission");
        let stats = handle.stats();
        let scope = ScopeKey::community("alpha".into());
        let cover = *stats.cover_emitted.get(&scope).unwrap_or(&0);
        let real = *stats.real_emitted.get(&scope).unwrap_or(&0);
        assert!(cover > 0, "covers should flow when queue empty");
        assert_eq!(real, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn real_drains_queue_then_cover_resumes() {
        let (emit, _count, envs) = make_emit();
        let poisson = Arc::new(PoissonScheduler::from_seed([0x88; 32]));
        let sched = Scheduler::new_with_poisson(one_scope_config(1000.0), emit, poisson);
        sched
            .submit(
                &ScopeKey::community("alpha".into()),
                [0x33; 32],
                7,
                b"hello world",
            )
            .unwrap();
        let _handle = sched.start();

        tokio::time::sleep(Duration::from_millis(200)).await;
        let snap: Vec<EmissionEnvelope> = envs.lock().clone();
        assert!(!snap.is_empty(), "scheduler emitted");
        // First envelope should be the real one (one fragment).
        let key = [0x42u8; 32];
        let (hdr0, _) = super::super::envelope::unseal_envelope(&key, &snap[0].bytes).unwrap();
        assert_eq!(
            hdr0.envelope_type,
            super::super::envelope::EnvelopeType::Real
        );
        assert_eq!(hdr0.fragment_id, 7);
        // Subsequent envelopes (queue empty) should be covers.
        if snap.len() > 1 {
            let (hdr1, _) = super::super::envelope::unseal_envelope(&key, &snap[1].bytes).unwrap();
            assert_eq!(
                hdr1.envelope_type,
                super::super::envelope::EnvelopeType::Cover
            );
        }
    }

    #[test]
    fn submit_unregistered_scope_errors() {
        let (emit, _c, _e) = make_emit();
        let sched = Scheduler::new(SchedulerConfig::default(), emit);
        let err = sched
            .submit(&ScopeKey::federation(), [0; 32], 0, b"x")
            .unwrap_err();
        assert!(matches!(err, SubmitError::ScopeNotRegistered));
    }
}
