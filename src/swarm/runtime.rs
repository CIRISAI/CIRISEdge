//! `FountainSwarmRuntime` — the federation-level swarm orchestration
//! runtime that closes the v5.1.0 → v5.2.0 wiring gap.
//!
//! Sibling to [`crate::replication::runtime::ReplicationRuntime`] in
//! shape; the substrate piece it animates is the v3.10.0 swarm
//! rarity / holding-claim primitive
//! ([`crate::holonomic::swarm_rarity`]). The substrate types are pure,
//! deterministic, byte-equal; this runtime is the live wiring that
//! makes peers actually do:
//!
//! 1. **Publish**: every `publish_cadence`, walk the operator's held
//!    fountain `content_id`s via
//!    [`FountainHoldingsSource::list_held_fountain_content`], build
//!    a [`FountainHoldingClaim`] per content, sign it via the
//!    federation signer, ship it to the cohort over the transport.
//! 2. **Observe**: peer claims arrive at
//!    [`FountainSwarmRuntime::register_observed_claim`] (called from
//!    edge's inbound dispatch path when a peer's holding-claim
//!    envelope is verified) and accumulate in the in-memory
//!    observed-holders map (TTL-pruned each tick).
//! 3. **Converge**: every `observe_cadence`, for every content_id
//!    with observed holders:
//!    - `should_eject_above_target` for over-`H` content → call
//!      `FederationDirectory::evict_fountain_content_to_tier` with
//!      the "t1" label (persist v10.0.0 #270 public-surface promotion);
//!    - observed_count < `min_viable` → emit a
//!      [`SwarmEvent::RepairNeeded`] telemetry record (downstream
//!      cuts wire the blob_swarm fetch off this);
//!    - `ConsentState::Revoked` → call
//!      `FederationDirectory::evict_fountain_content_hard_delete`
//!      (v10.0.0 #270 promotion).
//!
//! ## v7.0.0 adapter collapse (CIRISEdge#194 / CIRISPersist#270)
//!
//! The two v5.2.0 evict-surface adapter traits (`FountainTierEvict`,
//! `PersistFountainEvictHardDelete`) drop here — persist v10.0.0
//! promoted both methods to required `FederationDirectory` methods,
//! and the runtime now holds `Arc<dyn FederationDirectory>` directly
//! (same shape as [`crate::replication::runtime::ReplicationRuntime`]).
//! The `FountainHoldingsSource` adapter survives because the per-symbol
//! `symbol_id` list the [`FountainHoldingClaim`] ships is an
//! operator-local view (publisher's symbol store), NOT a directory
//! surface concern — `FountainHeldMeta` carries only counts.
//!
//! ## Why no per-peer mutation API
//!
//! [`ReplicationRuntime`] needed `register_initiator_peer` /
//! `remove_peer` / `set_peers` because replication is per-peer:
//! each peer in the cohort gets its own coordinator + scheduler
//! task. Swarm orchestration is **federation-wide** — the publisher
//! ships claims to the whole cohort and the converger reads the
//! observed-claims map (not a per-peer queue), so there is no
//! per-peer mutation surface to expose. Hot-changing the cohort
//! membership is the replication runtime's job; the swarm runtime
//! follows.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{watch, RwLock};
use tokio::task::JoinHandle;

use ciris_persist::federation::FederationDirectory;

use super::diversity::{diversity_contribution, NullRttObserver, PeerRttObserver};
use super::persist_fountain_evict::{
    FountainEvictError, FountainHoldingsSource, HeldFountainContent,
};
use crate::holonomic::fountain_defaults::{recommended_policy, FountainPolicy};
use crate::holonomic::swarm_rarity::{
    compute_rarity_score, should_eject_with_diversity, ConsentState, EjectionVerdict,
    FountainHoldingClaim, RarityScore,
};
use crate::identity::{build_envelope, sign_envelope, LocalSigner};
use crate::messages::MessageType;
use crate::transport::Transport;

/// `target_holders` default — the recommended `H` from §R-policy
/// (CEG 1.0 §R / [`crate::holonomic::fountain_defaults::DEFAULT_TARGET_HOLDERS`]).
pub const DEFAULT_TARGET_HOLDERS: u32 = 30;

/// `min_viable` default — the survival floor below which the
/// converger emits `RepairNeeded`. Matches §R-policy's
/// `min_viable_symbols` shape.
pub const DEFAULT_MIN_VIABLE: u32 = 5;

/// `eviction_grace_pct` default — the safety margin above
/// `target_holders` before the converger calls eject. Matches the
/// substrate's [`EJECT_ABOVE_TARGET_SAFETY_MARGIN_PCT`] (locked v1
/// at 15%).
///
/// [`EJECT_ABOVE_TARGET_SAFETY_MARGIN_PCT`]: crate::holonomic::swarm_rarity::EJECT_ABOVE_TARGET_SAFETY_MARGIN_PCT
pub const DEFAULT_EVICTION_GRACE_PCT: u8 = 15;

/// Default observed-claim TTL — claims older than this are pruned
/// on every converger tick. Bound by the substrate's expectation
/// that claims are republished at `publish_cadence`; the TTL
/// should comfortably exceed two publish intervals.
pub const DEFAULT_OBSERVED_CLAIM_TTL: Duration = Duration::from_secs(600);

/// A claim a peer published, as observed by this runtime. The runtime
/// keeps one per `(content_id, peer_id)` — a later observation from
/// the same peer for the same content replaces the prior entry.
#[derive(Debug, Clone)]
pub struct ObservedClaim {
    /// The exact [`FountainHoldingClaim`] envelope-body, verified
    /// upstream before reaching the runtime.
    pub claim: FountainHoldingClaim,
    /// Local wall-clock at which the claim was observed. Drives the
    /// TTL prune on the converger tick.
    pub observed_at: std::time::Instant,
}

/// Configuration for the swarm orchestration runtime. All fields are
/// tunable per deployment; defaults match the v3.10.0 §R-policy.
#[derive(Debug, Clone)]
pub struct SwarmRuntimeConfig {
    /// How often the publisher walks the operator's held content
    /// and broadcasts a [`FountainHoldingClaim`] per content.
    pub publish_cadence: Duration,
    /// How often the converger walks the observed-claims map.
    pub observe_cadence: Duration,
    /// `H` — the §R-policy target holder count.
    pub target_holders: u32,
    /// Below this count the converger emits
    /// [`SwarmEvent::RepairNeeded`].
    pub min_viable: u32,
    /// Safety margin above `target_holders` before the converger
    /// calls eject. Defaults to 15% — wire-determinism-critical
    /// (CEG 1.0 §R conformance vectors).
    pub eviction_grace_pct: u8,
    /// Claims older than this are pruned on every converger tick.
    pub observed_claim_ttl: Duration,
    /// `FountainPolicy` the substrate's
    /// [`should_eject_above_target`] consults. Defaults to
    /// [`recommended_policy()`].
    pub policy: FountainPolicy,
}

impl Default for SwarmRuntimeConfig {
    fn default() -> Self {
        Self {
            publish_cadence: Duration::from_secs(60),
            observe_cadence: Duration::from_secs(30),
            target_holders: DEFAULT_TARGET_HOLDERS,
            min_viable: DEFAULT_MIN_VIABLE,
            eviction_grace_pct: DEFAULT_EVICTION_GRACE_PCT,
            observed_claim_ttl: DEFAULT_OBSERVED_CLAIM_TTL,
            policy: recommended_policy(),
        }
    }
}

/// Telemetry record emitted by the converger. The optional event sink
/// passed at [`FountainSwarmRuntime::start`] receives one of these per
/// per-content_id action the converger takes; downstream consumers
/// (CIRISLens, the test e2e) read off it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwarmEvent {
    /// A claim was published to the cohort.
    Published {
        content_id: String,
        cohort_size: usize,
    },
    /// Observed holders for `content_id` dropped below `min_viable`.
    /// Downstream wires repair-fetch from current holders off this
    /// signal.
    RepairNeeded {
        content_id: String,
        observed_holders: u32,
        min_viable: u32,
    },
    /// `should_eject_above_target` fired; the runtime called
    /// `FederationDirectory::evict_fountain_content_to_tier`
    /// (persist v10.0.0 #270).
    EjectedToTier {
        content_id: String,
        observed_holders: u32,
        tier_label: String,
    },
    /// Consent was revoked for `content_id`; the runtime called
    /// `FederationDirectory::evict_fountain_content_hard_delete`
    /// (persist v10.0.0 #270).
    HardDeleted { content_id: String },
    /// Converger tick observed but took no eviction action for this
    /// content_id (Keep verdict). Surfaced so tests can assert the
    /// converger ran; production deployments may filter these out.
    Keep {
        content_id: String,
        observed_holders: u32,
    },
}

/// A sink for [`SwarmEvent`]s. The runtime emits via this callback;
/// production deployments wire a `tokio::sync::mpsc::Sender` or
/// equivalent (the runtime never blocks on the sink — the callback
/// is invoked synchronously inside the converger task, so it MUST
/// return quickly).
pub type SwarmRuntimeEventSink = Arc<dyn Fn(SwarmEvent) + Send + Sync>;

/// CIRISEdge#184 (v6.3.0) — optional plumbing for the swarm runtime.
///
/// Threaded into [`FountainSwarmRuntime::start_with_options`]; the
/// legacy [`FountainSwarmRuntime::start`] constructs one with every
/// field defaulted and forwards.
///
/// - `signer`: when `Some`, the publisher wraps each
///   [`FountainHoldingClaim`] body in a signed
///   [`crate::messages::EdgeEnvelope`] with discriminator
///   [`crate::messages::MessageType::FountainHoldingClaim`]. When
///   `None`, the publisher falls back to the v5.2.0 path that ships
///   the substrate's `canonical_bytes` raw (tests + bootstrap nodes
///   without a wired signer still drive the runtime).
/// - `rtt_observer`: latency source for the diversity-aware ejection
///   policy. `None` defaults to [`NullRttObserver`] — diversity
///   gating then degrades to rarity-only (the substrate verdict).
///
/// All optionals MAY be `None`; the runtime stays operational on every
/// combination of present/absent fields. New optionals land here
/// without changing the public `start` signature.
#[derive(Clone, Default)]
pub struct SwarmRuntimeOptions {
    /// Outbound-envelope signer. When `None`, publisher emits raw
    /// canonical_bytes (v5.2.0 path) — used by tests and bootstrap.
    pub signer: Option<Arc<LocalSigner>>,
    /// Per-peer RTT source for the diversity-aware ejection policy.
    /// `None` defaults to [`NullRttObserver`] (rarity-only fallback).
    pub rtt_observer: Option<Arc<dyn PeerRttObserver>>,
}

impl std::fmt::Debug for SwarmRuntimeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SwarmRuntimeOptions")
            .field("signer_present", &self.signer.is_some())
            .field("rtt_observer_present", &self.rtt_observer.is_some())
            .finish()
    }
}

/// Live swarm-orchestration runtime — publisher + converger tasks +
/// shutdown handle. Construct via [`Self::start`] (v5.2.0 minimal
/// surface) or [`Self::start_with_options`] (v6.3.0+ for signed-
/// envelope publishing and latency-diversity converger); hold for
/// the lifetime of the application; call [`Self::shutdown`] to stop
/// the background tasks.
pub struct FountainSwarmRuntime {
    config: SwarmRuntimeConfig,
    observed: Arc<RwLock<ObservedClaims>>,
    cancel_tx: watch::Sender<bool>,
    publisher_task: Option<JoinHandle<()>>,
    converger_task: Option<JoinHandle<()>>,
}

/// Internal observed-claims map. Keyed by content_id → peer_id →
/// observed claim. Sorted-map nesting keeps determinism over the
/// observation set — the converger walks in stable order.
///
/// `pub` for the `observed_handle()` test surface — production
/// callers should treat the inner shape as opaque.
#[derive(Debug, Default)]
pub struct ObservedClaims {
    inner: BTreeMap<String, BTreeMap<String, ObservedClaim>>,
}

impl ObservedClaims {
    fn upsert(&mut self, claim: FountainHoldingClaim) {
        let entry = ObservedClaim {
            observed_at: std::time::Instant::now(),
            claim,
        };
        self.inner
            .entry(entry.claim.content_id.clone())
            .or_default()
            .insert(entry.claim.peer_id.clone(), entry);
    }

    /// Drop entries older than `ttl`. Returns the count pruned.
    fn prune_expired(&mut self, ttl: Duration) -> usize {
        let now = std::time::Instant::now();
        let mut dropped = 0usize;
        self.inner.retain(|_, peers| {
            peers.retain(|_, c| {
                let keep = now.duration_since(c.observed_at) <= ttl;
                if !keep {
                    dropped += 1;
                }
                keep
            });
            !peers.is_empty()
        });
        dropped
    }

    fn distinct_holders(&self, content_id: &str) -> u32 {
        self.inner
            .get(content_id)
            .map_or(0, |m| u32::try_from(m.len()).unwrap_or(u32::MAX))
    }

    fn all_claims_for(&self, content_id: &str) -> Vec<FountainHoldingClaim> {
        self.inner
            .get(content_id)
            .map_or_else(Vec::new, |m| m.values().map(|c| c.claim.clone()).collect())
    }

    fn content_ids(&self) -> Vec<String> {
        self.inner.keys().cloned().collect()
    }

    /// CIRISEdge#184 (v6.3.0) — peer ids observed holding
    /// `content_id`. Sorted-map iteration → stable order.
    fn peer_ids_for(&self, content_id: &str) -> Vec<String> {
        self.inner
            .get(content_id)
            .map_or_else(Vec::new, |m| m.keys().cloned().collect())
    }
}

/// CIRISEdge#184 (v6.3.0) — median diversity score across the
/// content_ids we have RTT data for. `None` when no content has a
/// score (every entry is `None`); the converger then falls back to
/// rarity-only verdicts.
fn median_diversity(scores: &BTreeMap<String, Option<f64>>) -> Option<f64> {
    let mut present: Vec<f64> = scores.values().filter_map(|s| *s).collect();
    if present.is_empty() {
        return None;
    }
    present.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = present.len() / 2;
    if present.len() % 2 == 1 {
        Some(present[mid])
    } else {
        Some((present[mid - 1] + present[mid]) / 2.0)
    }
}

impl FountainSwarmRuntime {
    /// Spawn the publisher + converger tasks against the given
    /// substrate handles. The runtime holds clones of every Arc; the
    /// caller can drop their originals after `start` returns.
    ///
    /// Cohort membership is read from `cohort` on every publish tick
    /// — the same shape `ReplicationRuntime` uses for its bridge
    /// callback. The publisher ships one envelope per `(content_id,
    /// peer)` pair on every tick; v5.2.0 uses the transport's
    /// fire-and-forget `send` path (a future cut may switch to
    /// `send_durable` for at-least-once delivery once the substrate
    /// requires it).
    ///
    /// v7.0.0 (CIRISEdge#194): `directory` replaces the v5.2.0
    /// `tier_evict` + `hard_delete` adapter args — persist v10.0.0
    /// promoted both methods to required `FederationDirectory`
    /// methods. The runtime now calls `directory.evict_fountain_*`
    /// directly. `holdings` survives because per-symbol-IDs are an
    /// operator-local view, not a directory-surface concern.
    #[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
    pub fn start(
        config: SwarmRuntimeConfig,
        holdings: Arc<dyn FountainHoldingsSource>,
        directory: Arc<dyn FederationDirectory>,
        transport: Arc<dyn Transport>,
        cohort: Arc<dyn Fn() -> Vec<String> + Send + Sync>,
        local_peer_id: String,
        sink: Option<SwarmRuntimeEventSink>,
    ) -> Self {
        Self::start_with_options(
            config,
            holdings,
            directory,
            transport,
            cohort,
            local_peer_id,
            sink,
            SwarmRuntimeOptions::default(),
        )
    }

    /// CIRISEdge#184 (v6.3.0) — extended constructor with optional
    /// signer (for [`MessageType::FountainHoldingClaim`] envelope
    /// publishing) and latency-diversity observer (for the converger's
    /// over-target ejection heuristic). See [`SwarmRuntimeOptions`].
    ///
    /// When both options are `None` the runtime is byte-equivalent to
    /// [`Self::start`].
    #[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
    pub fn start_with_options(
        config: SwarmRuntimeConfig,
        holdings: Arc<dyn FountainHoldingsSource>,
        directory: Arc<dyn FederationDirectory>,
        transport: Arc<dyn Transport>,
        cohort: Arc<dyn Fn() -> Vec<String> + Send + Sync>,
        local_peer_id: String,
        sink: Option<SwarmRuntimeEventSink>,
        options: SwarmRuntimeOptions,
    ) -> Self {
        let observed = Arc::new(RwLock::new(ObservedClaims::default()));
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let rtt_observer: Arc<dyn PeerRttObserver> = options
            .rtt_observer
            .clone()
            .unwrap_or_else(|| Arc::new(NullRttObserver));

        let publisher_task = {
            let holdings = Arc::clone(&holdings);
            let transport = Arc::clone(&transport);
            let cohort = Arc::clone(&cohort);
            let cadence = config.publish_cadence;
            let cancel_rx = cancel_rx.clone();
            let sink = sink.clone();
            let local_peer = local_peer_id.clone();
            let signer = options.signer.clone();
            tokio::spawn(async move {
                run_publisher(
                    holdings, transport, cohort, local_peer, cadence, cancel_rx, sink, signer,
                )
                .await;
            })
        };

        let converger_task = {
            let observed = Arc::clone(&observed);
            let holdings = Arc::clone(&holdings);
            let directory = Arc::clone(&directory);
            let cfg = config.clone();
            let local_peer = local_peer_id.clone();
            let rtt = Arc::clone(&rtt_observer);
            tokio::spawn(async move {
                run_converger(
                    observed, holdings, directory, cfg, cancel_rx, sink, local_peer, rtt,
                )
                .await;
            })
        };

        Self {
            config,
            observed,
            cancel_tx,
            publisher_task: Some(publisher_task),
            converger_task: Some(converger_task),
        }
    }

    /// Called by the inbound dispatch path when a peer's
    /// [`FountainHoldingClaim`] envelope is verified. Updates the
    /// observed-claims map; the next converger tick consults the
    /// fresh state.
    ///
    /// Idempotent on `(content_id, peer_id)` — a later observation
    /// replaces the prior entry (the substrate's `observed_at_unix_ms`
    /// field carries the producer's own staleness window; the
    /// runtime's TTL prune is a local liveness signal).
    pub async fn register_observed_claim(&self, claim: FountainHoldingClaim) {
        self.observed.write().await.upsert(claim);
    }

    /// Shared observed-claims map for tests + telemetry. Cheap clone
    /// (Arc bump).
    #[doc(hidden)]
    pub fn observed_handle(&self) -> Arc<RwLock<ObservedClaims>> {
        Arc::clone(&self.observed)
    }

    /// The active runtime configuration.
    pub fn config(&self) -> &SwarmRuntimeConfig {
        &self.config
    }

    /// Signal both tasks to stop + await clean exit. Idempotent.
    pub async fn shutdown(&mut self) {
        let _ = self.cancel_tx.send(true);
        if let Some(t) = self.publisher_task.take() {
            let _ = t.await;
        }
        if let Some(t) = self.converger_task.take() {
            let _ = t.await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_publisher(
    holdings: Arc<dyn FountainHoldingsSource>,
    transport: Arc<dyn Transport>,
    cohort: Arc<dyn Fn() -> Vec<String> + Send + Sync>,
    local_peer_id: String,
    cadence: Duration,
    mut cancel_rx: watch::Receiver<bool>,
    sink: Option<SwarmRuntimeEventSink>,
    signer: Option<Arc<LocalSigner>>,
) {
    let mut ticker = tokio::time::interval(cadence);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    tracing::info!("swarm_runtime.publisher: shutdown");
                    return;
                }
            }
            _ = ticker.tick() => {
                if let Err(e) = publish_tick(
                    &holdings,
                    &transport,
                    cohort.as_ref(),
                    &local_peer_id,
                    sink.as_ref(),
                    signer.as_ref(),
                )
                .await
                {
                    tracing::warn!(error = %e, "swarm_runtime.publisher: tick failed");
                }
            }
        }
    }
}

async fn publish_tick(
    holdings: &Arc<dyn FountainHoldingsSource>,
    transport: &Arc<dyn Transport>,
    cohort: &(dyn Fn() -> Vec<String> + Send + Sync),
    local_peer_id: &str,
    sink: Option<&SwarmRuntimeEventSink>,
    signer: Option<&Arc<LocalSigner>>,
) -> Result<usize, FountainEvictError> {
    let held = holdings.list_held_fountain_content().await?;
    let peers = cohort();
    let mut count = 0usize;
    let observed_at_unix_ms = current_unix_ms();
    for content in held {
        let claim = FountainHoldingClaim::new(
            local_peer_id.to_string(),
            content.content_id.clone(),
            content.symbol_ids.clone(),
            observed_at_unix_ms,
        );
        for peer in &peers {
            // Skip self — the cohort callback typically already
            // excludes the local peer, but defense in depth.
            if peer == local_peer_id {
                continue;
            }
            // v6.3.0 (CIRISEdge#184): when a signer is wired, ship a
            // signed `MessageType::FountainHoldingClaim` EdgeEnvelope.
            // When no signer (test surface or bootstrap), fall back to
            // the v5.2.0 substrate-canonical_bytes path so existing
            // tests + bootstrap topologies keep working.
            let envelope_bytes = match signer {
                Some(sig) => {
                    match build_and_sign_holding_claim_envelope(sig, local_peer_id, peer, &claim)
                        .await
                    {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            tracing::warn!(
                                peer = %peer,
                                content_id = %content.content_id,
                                error = %e,
                                "swarm_runtime.publisher: envelope build/sign failed; falling back to canonical_bytes",
                            );
                            claim.canonical_bytes()
                        }
                    }
                }
                None => claim.canonical_bytes(),
            };
            if let Err(e) = transport.send(peer, &envelope_bytes).await {
                tracing::warn!(
                    peer = %peer,
                    content_id = %content.content_id,
                    error = %e,
                    "swarm_runtime.publisher: transport send failed",
                );
            }
        }
        if let Some(sink) = sink {
            sink(SwarmEvent::Published {
                content_id: content.content_id.clone(),
                cohort_size: peers.len(),
            });
        }
        count += 1;
    }
    Ok(count)
}

/// CIRISEdge#184 (v6.3.0) — build + sign a
/// [`MessageType::FountainHoldingClaim`] envelope wrapping the
/// `claim` body. Returns the JSON-serialized envelope bytes ready for
/// `Transport::send`.
async fn build_and_sign_holding_claim_envelope(
    signer: &Arc<LocalSigner>,
    local_peer_id: &str,
    destination_peer_id: &str,
    claim: &FountainHoldingClaim,
) -> Result<Vec<u8>, FountainEvictError> {
    // `local_peer_id` is the peer-id the runtime was constructed with;
    // when a signer is configured, it should match `signer.key_id` —
    // a soft mismatch is logged but not fatal (the canonical_bytes-on-
    // failure path still keeps the runtime live).
    if signer.key_id != local_peer_id {
        tracing::debug!(
            signer_key_id = %signer.key_id,
            local_peer_id,
            "swarm_runtime.publisher: signer key_id differs from local_peer_id",
        );
    }
    let mut envelope = build_envelope(
        MessageType::FountainHoldingClaim,
        &signer.key_id,
        destination_peer_id,
        claim,
        None,
    )
    .map_err(|e| FountainEvictError::HardDeleteFailed(format!("build_envelope: {e}")))?;
    sign_envelope(signer, &mut envelope)
        .await
        .map_err(|e| FountainEvictError::HardDeleteFailed(format!("sign_envelope: {e}")))?;
    serde_json::to_vec(&envelope)
        .map_err(|e| FountainEvictError::HardDeleteFailed(format!("envelope serialize: {e}")))
}

#[allow(clippy::too_many_arguments)]
async fn run_converger(
    observed: Arc<RwLock<ObservedClaims>>,
    holdings: Arc<dyn FountainHoldingsSource>,
    directory: Arc<dyn FederationDirectory>,
    config: SwarmRuntimeConfig,
    mut cancel_rx: watch::Receiver<bool>,
    sink: Option<SwarmRuntimeEventSink>,
    local_peer_id: String,
    rtt: Arc<dyn PeerRttObserver>,
) {
    let mut ticker = tokio::time::interval(config.observe_cadence);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    tracing::info!("swarm_runtime.converger: shutdown");
                    return;
                }
            }
            _ = ticker.tick() => {
                converger_tick(
                    &observed,
                    &holdings,
                    directory.as_ref(),
                    &config,
                    sink.as_ref(),
                    &local_peer_id,
                    rtt.as_ref(),
                )
                .await;
            }
        }
    }
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn converger_tick(
    observed: &Arc<RwLock<ObservedClaims>>,
    holdings: &Arc<dyn FountainHoldingsSource>,
    directory: &dyn FederationDirectory,
    config: &SwarmRuntimeConfig,
    sink: Option<&SwarmRuntimeEventSink>,
    local_peer_id: &str,
    rtt: &dyn PeerRttObserver,
) {
    // Prune stale claims first so the rarity math sees a live view.
    let dropped = observed
        .write()
        .await
        .prune_expired(config.observed_claim_ttl);
    if dropped > 0 {
        tracing::debug!(dropped, "swarm_runtime.converger: pruned stale claims");
    }

    // Snapshot the operator's local holdings for the local-symbol
    // rarity check. A missing holdings source returns an empty Vec,
    // which means the converger treats every content as "not locally
    // held" — no eviction action is taken on content the operator
    // doesn't have a local symbol for.
    let local_held = match holdings.list_held_fountain_content().await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "swarm_runtime.converger: holdings list failed; skipping tick");
            return;
        }
    };
    let local_by_content: BTreeMap<String, HeldFountainContent> = local_held
        .into_iter()
        .map(|h| (h.content_id.clone(), h))
        .collect();

    let observed_snapshot = observed.read().await;
    let content_ids = observed_snapshot.content_ids();
    drop(observed_snapshot);

    // CIRISEdge#184 (v6.3.0) — first pass: gather per-content_id
    // diversity contributions so the second pass can drain in
    // ascending-diversity order (multi-content ordering: the least-
    // diverse positions go first when ejecting under pressure).
    let mut per_content_diversity: BTreeMap<String, Option<f64>> = BTreeMap::new();
    for content_id in &content_ids {
        let snapshot = observed.read().await;
        let others: Vec<String> = snapshot
            .peer_ids_for(content_id)
            .into_iter()
            .filter(|p| p != local_peer_id)
            .collect();
        drop(snapshot);
        per_content_diversity.insert(content_id.clone(), diversity_contribution(rtt, &others));
    }

    // Estimate the diversity floor — the median across the contents
    // we DID measure. Content-ids without a score (no RTT data) drop
    // out of the median estimation; they'll still get processed in
    // the loop below, just with rarity-only verdicts.
    let diversity_floor = median_diversity(&per_content_diversity);

    // Second pass: process content_ids in ASCENDING diversity-score
    // order so the converger drains the least-diverse positions
    // first under pressure. Content-ids with no diversity score sort
    // last (they degrade to rarity-only — substrate verdict still
    // applies, but no diversity-driven multi-content ordering).
    let mut ordered: Vec<(String, Option<f64>)> = content_ids
        .iter()
        .map(|cid| {
            (
                cid.clone(),
                per_content_diversity.get(cid).copied().unwrap_or(None),
            )
        })
        .collect();
    ordered.sort_by(|(_, a), (_, b)| match (a, b) {
        (Some(x), Some(y)) => x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });

    for (content_id, diversity_score) in ordered {
        let snapshot = observed.read().await;
        let observed_count = snapshot.distinct_holders(&content_id);
        let all_claims = snapshot.all_claims_for(&content_id);
        drop(snapshot);

        // Determine consent state. v5.2.0 defaults to Active —
        // revocation routing rides the inbound dispatch path
        // (when a `consent:state:revoked` envelope arrives, edge
        // calls into `register_revocation` on the runtime; that
        // wiring lands in v5.3.0 when the consent envelope shape
        // is normative). For the v5.2.0 cut, the converger acts on
        // the substrate-tier verdicts driven by `holders_observed`
        // alone.
        let consent = ConsentState::Active;

        // Local-symbol rarity: compute over the merged claim set
        // including the local peer's view if it holds a symbol for
        // this content. The substrate's
        // `should_eject_above_target` consults this to avoid
        // evicting the last local copy of a rare symbol.
        let local_symbol_rarity = if let Some(local) = local_by_content.get(&content_id) {
            local.symbol_ids.first().map_or(RarityScore(0), |sym| {
                compute_rarity_score(&content_id, *sym, &all_claims)
            })
        } else {
            RarityScore(0)
        };

        // CIRISEdge#184 (v6.3.0) — diversity refinement on top of
        // the substrate verdict. When either the score OR the floor
        // is None, the sibling function reduces to the substrate's
        // `should_eject_above_target` (rarity-only fallback).
        let verdict = should_eject_with_diversity(
            observed_count,
            &config.policy,
            consent,
            local_symbol_rarity,
            diversity_score,
            diversity_floor,
        );

        match verdict {
            EjectionVerdict::Keep => {
                if observed_count > 0 && observed_count < config.min_viable {
                    tracing::info!(
                        content_id = %content_id,
                        observed_holders = observed_count,
                        min_viable = config.min_viable,
                        "swarm_runtime.converger: repair needed",
                    );
                    if let Some(sink) = sink {
                        sink(SwarmEvent::RepairNeeded {
                            content_id: content_id.clone(),
                            observed_holders: observed_count,
                            min_viable: config.min_viable,
                        });
                    }
                } else if let Some(sink) = sink {
                    sink(SwarmEvent::Keep {
                        content_id: content_id.clone(),
                        observed_holders: observed_count,
                    });
                }
            }
            EjectionVerdict::EjectToTier => {
                let corpus_kind = corpus_kind_for(&local_by_content, &content_id);
                // v7.0.0: persist v10.0.0 promoted the tier evict to
                // the public `FederationDirectory` surface. Target tier
                // is `T2` (`DiskPressure::Warn`-equivalent — keep
                // `n_source`, drop repair; the gentlest step that
                // actually frees symbol rows). Future cuts may consult
                // the per-content_id pressure window to pick a coarser
                // tier under load.
                let tier = ciris_persist::fountain::FountainTier::T2;
                let tier_label = tier.label().to_string();
                if let Err(e) = directory
                    .evict_fountain_content_to_tier(&content_id, &corpus_kind, tier)
                    .await
                {
                    tracing::warn!(
                        content_id = %content_id,
                        error = %e,
                        "swarm_runtime.converger: tier evict failed",
                    );
                } else if let Some(sink) = sink {
                    sink(SwarmEvent::EjectedToTier {
                        content_id: content_id.clone(),
                        observed_holders: observed_count,
                        tier_label,
                    });
                }
            }
            EjectionVerdict::EjectAggregatedTierOnly { tier: _ } => {
                // §19.7.3 tier-only ejection — same dispatch as
                // EjectToTier for v5.2.0 (the named pyramid stratum
                // is consulted by the persist backend once it
                // exposes the tier-granular evict; until then the
                // runtime maps onto the coarse tier evict).
                let corpus_kind = corpus_kind_for(&local_by_content, &content_id);
                if let Err(e) = directory
                    .evict_fountain_content_to_tier(
                        &content_id,
                        &corpus_kind,
                        ciris_persist::fountain::FountainTier::T2,
                    )
                    .await
                {
                    tracing::warn!(
                        content_id = %content_id,
                        error = %e,
                        "swarm_runtime.converger: aggregated-tier evict failed",
                    );
                }
            }
            EjectionVerdict::EjectHardDelete => {
                let corpus_kind = corpus_kind_for(&local_by_content, &content_id);
                if let Err(e) = directory
                    .evict_fountain_content_hard_delete(&content_id, &corpus_kind)
                    .await
                {
                    tracing::warn!(
                        content_id = %content_id,
                        error = %e,
                        "swarm_runtime.converger: hard delete failed",
                    );
                } else if let Some(sink) = sink {
                    sink(SwarmEvent::HardDeleted {
                        content_id: content_id.clone(),
                    });
                }
            }
        }
    }
}

fn corpus_kind_for(
    local_by_content: &BTreeMap<String, HeldFountainContent>,
    content_id: &str,
) -> String {
    local_by_content
        .get(content_id)
        .map_or_else(|| "fountain-corpus".to_string(), |h| h.corpus_kind.clone())
}

fn current_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{InboundFrame, TransportError, TransportId, TransportSendOutcome};
    use async_trait::async_trait;
    use ciris_persist::store::MemoryBackend;
    use std::sync::Mutex;

    // ─── Test fixtures ────────────────────────────────────────────
    //
    // v7.0.0 (CIRISEdge#194): the converger now calls
    // `FederationDirectory::evict_fountain_content_*` directly. Tests
    // use `MemoryBackend` (persist's in-memory FederationDirectory
    // impl) — the evict methods return `Ok(0)` for unknown content
    // (no manifest seeded), so a successful dispatch lights the
    // `SwarmEvent::EjectedToTier` / `HardDeleted` sink emission and
    // tests assert on the sink rather than on a recording stub. That
    // collapses the v5.2.0 RecordingTierEvict + RecordingHardDelete
    // fixtures, exercising the real persist surface instead of an
    // adapter mock.

    struct VecHoldings(Vec<HeldFountainContent>);
    #[async_trait]
    impl FountainHoldingsSource for VecHoldings {
        async fn list_held_fountain_content(
            &self,
        ) -> Result<Vec<HeldFountainContent>, FountainEvictError> {
            Ok(self.0.clone())
        }
    }

    /// `Arc<dyn FederationDirectory>` test handle: a fresh
    /// `MemoryBackend`. Its `evict_fountain_content_*` surfaces no-op
    /// (return `Ok(0)`) on unknown `content_id`, which is exactly the
    /// behaviour the converger tests rely on — they assert on the
    /// `SwarmEvent` sink that fires after a successful dispatch.
    fn test_directory() -> Arc<dyn FederationDirectory> {
        Arc::new(MemoryBackend::new())
    }

    #[derive(Default)]
    struct RecordingTransport {
        sends: Mutex<Vec<(String, Vec<u8>)>>,
    }
    #[async_trait]
    impl Transport for RecordingTransport {
        fn id(&self) -> TransportId {
            TransportId::HTTP
        }
        async fn send(
            &self,
            destination_key_id: &str,
            envelope_bytes: &[u8],
        ) -> Result<TransportSendOutcome, TransportError> {
            self.sends
                .lock()
                .unwrap()
                .push((destination_key_id.to_string(), envelope_bytes.to_vec()));
            Ok(TransportSendOutcome::Delivered)
        }
        async fn listen(
            &self,
            _sink: tokio::sync::mpsc::Sender<InboundFrame>,
        ) -> Result<(), TransportError> {
            unimplemented!("test transports don't drive listen")
        }
    }

    fn fast_config() -> SwarmRuntimeConfig {
        SwarmRuntimeConfig {
            publish_cadence: Duration::from_millis(20),
            observe_cadence: Duration::from_millis(20),
            ..SwarmRuntimeConfig::default()
        }
    }

    // ─── Tests ────────────────────────────────────────────────────

    #[tokio::test]
    async fn empty_holdings_starts_and_shuts_down() {
        let holdings: Arc<dyn FountainHoldingsSource> =
            Arc::new(super::super::NoopFountainHoldingsSource);
        let tx: Arc<dyn Transport> = Arc::new(RecordingTransport::default());
        let cohort: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::new(Vec::new);
        let mut rt = FountainSwarmRuntime::start(
            fast_config(),
            holdings,
            test_directory(),
            tx,
            cohort,
            "alice".to_string(),
            None,
        );
        tokio::time::sleep(Duration::from_millis(60)).await;
        rt.shutdown().await;
    }

    #[tokio::test]
    async fn publisher_ships_one_envelope_per_held_content_per_peer() {
        let holdings: Arc<dyn FountainHoldingsSource> = Arc::new(VecHoldings(vec![
            HeldFountainContent {
                content_id: "c-x".into(),
                corpus_kind: "fountain-corpus".into(),
                symbol_ids: vec![1, 2, 3],
            },
            HeldFountainContent {
                content_id: "c-y".into(),
                corpus_kind: "fountain-corpus".into(),
                symbol_ids: vec![10, 20],
            },
        ]));
        let recording_tx = Arc::new(RecordingTransport::default());
        let tx: Arc<dyn Transport> = recording_tx.clone();
        let cohort: Arc<dyn Fn() -> Vec<String> + Send + Sync> =
            Arc::new(|| vec!["bob".to_string(), "carol".to_string()]);
        let mut rt = FountainSwarmRuntime::start(
            fast_config(),
            holdings,
            test_directory(),
            tx,
            cohort,
            "alice".to_string(),
            None,
        );
        // Let the publisher fire at least once.
        tokio::time::sleep(Duration::from_millis(80)).await;
        rt.shutdown().await;
        let sends = recording_tx.sends.lock().unwrap().clone();
        // 2 content × 2 peers = 4 sends per tick; should be at least 4.
        assert!(
            sends.len() >= 4,
            "expected >=4 publish sends, got {}",
            sends.len()
        );
        // Every send must be addressed to a cohort peer (not self).
        for (dest, _) in &sends {
            assert!(
                dest == "bob" || dest == "carol",
                "self-addressed send: {dest}"
            );
        }
    }

    #[tokio::test]
    async fn register_observed_claim_lands_in_map() {
        let holdings: Arc<dyn FountainHoldingsSource> =
            Arc::new(super::super::NoopFountainHoldingsSource);
        let tx: Arc<dyn Transport> = Arc::new(RecordingTransport::default());
        let cohort: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::new(Vec::new);
        let rt = FountainSwarmRuntime::start(
            SwarmRuntimeConfig {
                publish_cadence: Duration::from_secs(60),
                observe_cadence: Duration::from_secs(60),
                ..Default::default()
            },
            holdings,
            test_directory(),
            tx,
            cohort,
            "alice".to_string(),
            None,
        );

        rt.register_observed_claim(FountainHoldingClaim::new(
            "bob",
            "c-x",
            vec![1, 2],
            1_700_000_000,
        ))
        .await;
        rt.register_observed_claim(FountainHoldingClaim::new(
            "carol",
            "c-x",
            vec![1, 3],
            1_700_000_000,
        ))
        .await;
        let map = rt.observed_handle();
        let g = map.read().await;
        assert_eq!(g.distinct_holders("c-x"), 2);
        assert_eq!(g.distinct_holders("c-y"), 0);
        drop(g);
        let mut rt = rt;
        rt.shutdown().await;
    }

    #[tokio::test]
    async fn converger_fires_eject_above_target_when_observed_holders_exceed_threshold() {
        // 35 holders + local symbol "common" (rarity >= target/2=15)
        // → EjectToTier per the substrate's threshold math.
        let local_content_id = "c-popular";
        let holdings: Arc<dyn FountainHoldingsSource> =
            Arc::new(VecHoldings(vec![HeldFountainContent {
                content_id: local_content_id.into(),
                corpus_kind: "fountain-corpus".into(),
                symbol_ids: vec![1],
            }]));
        let tx: Arc<dyn Transport> = Arc::new(RecordingTransport::default());
        let cohort: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::new(Vec::new);
        let (sink_tx, mut sink_rx) = tokio::sync::mpsc::unbounded_channel::<SwarmEvent>();
        let sink: SwarmRuntimeEventSink = Arc::new(move |ev| {
            let _ = sink_tx.send(ev);
        });
        let rt = FountainSwarmRuntime::start(
            fast_config(),
            holdings,
            test_directory(),
            tx,
            cohort,
            "alice".to_string(),
            Some(sink),
        );
        // Publish 35 distinct peer claims for symbol_id=1 — every
        // peer holds symbol 1, so the local symbol is "common"
        // (rarity score = 35 > target/2=15) and observed_count=35
        // is above target+grace=34, so the converger should eject.
        for i in 0..35 {
            rt.register_observed_claim(FountainHoldingClaim::new(
                format!("peer-{i}"),
                local_content_id,
                vec![1],
                1_700_000_000,
            ))
            .await;
        }
        // Wait a couple of converger ticks.
        tokio::time::sleep(Duration::from_millis(80)).await;
        let mut rt = rt;
        rt.shutdown().await;

        // v7.0.0: assert via the SwarmEvent sink (the converger emits
        // EjectedToTier on `Ok(_)` of the directory call;
        // MemoryBackend returns `Ok(0)` for unknown content_id). Tier
        // label is "t2" — persist v10.0.0's `FountainTier::T2`
        // (DiskPressure::Warn-equivalent: keep `n_source`, drop
        // repair — the gentlest tier that actually frees symbol rows).
        let mut saw_eject = false;
        while let Ok(ev) = sink_rx.try_recv() {
            if let SwarmEvent::EjectedToTier {
                content_id,
                tier_label,
                ..
            } = ev
            {
                if content_id == local_content_id && tier_label == "t2" {
                    saw_eject = true;
                }
            }
        }
        assert!(
            saw_eject,
            "expected EjectedToTier(c-popular, t2) event after converger tick"
        );
    }

    #[tokio::test]
    async fn converger_emits_repair_needed_when_below_min_viable() {
        // 2 holders < min_viable=5 → RepairNeeded telemetry.
        let content_id = "c-rare";
        let holdings: Arc<dyn FountainHoldingsSource> =
            Arc::new(VecHoldings(vec![HeldFountainContent {
                content_id: content_id.into(),
                corpus_kind: "fountain-corpus".into(),
                symbol_ids: vec![7],
            }]));
        let tx: Arc<dyn Transport> = Arc::new(RecordingTransport::default());
        let cohort: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::new(Vec::new);
        let (sink_tx, mut sink_rx) = tokio::sync::mpsc::unbounded_channel::<SwarmEvent>();
        let sink: SwarmRuntimeEventSink = Arc::new(move |ev| {
            let _ = sink_tx.send(ev);
        });
        let rt = FountainSwarmRuntime::start(
            fast_config(),
            holdings,
            test_directory(),
            tx,
            cohort,
            "alice".to_string(),
            Some(sink),
        );
        for i in 0..2 {
            rt.register_observed_claim(FountainHoldingClaim::new(
                format!("peer-{i}"),
                content_id,
                vec![7],
                1_700_000_000,
            ))
            .await;
        }
        tokio::time::sleep(Duration::from_millis(80)).await;
        let mut rt = rt;
        rt.shutdown().await;
        let mut saw_repair = false;
        while let Ok(ev) = sink_rx.try_recv() {
            if let SwarmEvent::RepairNeeded {
                content_id: cid,
                observed_holders,
                min_viable,
            } = ev
            {
                if cid == content_id && observed_holders == 2 && min_viable == DEFAULT_MIN_VIABLE {
                    saw_repair = true;
                }
            }
        }
        assert!(saw_repair, "expected RepairNeeded(c-rare, 2, 5)");
    }

    #[tokio::test]
    async fn observed_claims_prune_when_ttl_elapsed() {
        let mut claims = ObservedClaims::default();
        let claim = FountainHoldingClaim::new("p", "c", vec![1], 1_700_000_000);
        claims.upsert(claim);
        assert_eq!(claims.distinct_holders("c"), 1);
        // TTL=0 → every claim is "expired" instantly.
        let dropped = claims.prune_expired(Duration::from_secs(0));
        assert_eq!(dropped, 1);
        assert_eq!(claims.distinct_holders("c"), 0);
    }

    #[tokio::test]
    async fn observed_claims_dedupe_per_peer_content() {
        let mut claims = ObservedClaims::default();
        claims.upsert(FountainHoldingClaim::new("p", "c", vec![1], 1));
        claims.upsert(FountainHoldingClaim::new("p", "c", vec![1, 2], 2));
        // Same (peer, content) → upsert keeps the latest claim only.
        assert_eq!(claims.distinct_holders("c"), 1);
        let all = claims.all_claims_for("c");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].symbol_ids, vec![1, 2]);
    }
}
