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
//!
//! ## CIRISEdge#546 — the config plane governs a RUNNING swarm
//!
//! Until #546 the *configuration* was equally frozen, and for no such
//! reason: [`FountainSwarmRuntime::start`] took [`SwarmRuntimeConfig`] by
//! value and copied each field into the spawned tasks, so the only moment
//! a value could ever be applied was composition. That is what kept
//! CIRISServer#365's four redundancy keys at `consumed: false` — a
//! boot-only consumer is strictly WORSE than none on a TTL-evaluated
//! plane, because a relief whose TTL expires keeps applying until a
//! restart nobody performs (the eternal 72-hour emergency).
//!
//! Two seams close it, and they meet in one place on purpose:
//!
//! 1. **The operator's ceiling** is a [`watch`] channel.
//!    [`FountainSwarmRuntime::set_config`] replaces it; publisher and
//!    converger re-read it every tick, so an operator change is live
//!    without a restart.
//! 2. **The mesh-config plane's relief** is
//!    [`crate::replication::mesh_config::MeshConfigReader`], resolved on
//!    the converger tick (a cached read inside the reader's TTL) and
//!    folded onto the ceiling by
//!    [`SwarmRuntimeConfig::with_mesh_relief`].
//!
//! Because the relief is re-resolved every tick rather than latched,
//! *"the emergency expired"* and *"the operator changed it"* are the SAME
//! code path — the fold simply stops reporting the key and `min` walks
//! the value back to the ceiling. Which is what the issue asked for in
//! its option 2, expressed in the seam edge already uses everywhere else
//! (`relief()` at the round/tick boundary) rather than a second one.
//!
//! **Relief can only SHRINK.** Every knob is `min(configured, relieved)`,
//! the discipline [`crate::replication::bridge`]'s `effective_page_limit`
//! sets: persist's fold already enforces relieve-never-expand against ITS
//! baseline, but that baseline is persist's `owner_default` ceiling (64
//! holders), not this node's configured 30 — so a row relieving 64 → 40
//! is a genuine relief upstream and would still be an EXPANSION here. The
//! `min` at the consumer is what makes that impossible.

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
use super::scope::{HoldingAnnounce, HoldingsPublishGate};
use crate::holonomic::fountain_defaults::{recommended_policy, FountainPolicy};
use crate::holonomic::swarm_rarity::{
    compute_rarity_score, should_eject_with_diversity, ConsentState, EjectionVerdict,
    FountainHoldingClaim, RarityScore,
};
use crate::identity::{build_envelope, sign_envelope, LocalSigner};
use crate::messages::MessageType;
use crate::replication::mesh_config::{MeshConfigReader, MeshConfigRelief};
use crate::transport::Transport;

/// `target_holders` default — the recommended `H` from §R-policy
/// (CEG 1.0 §R).
///
/// RE-EXPORTED from the fountain-policy authority
/// [`crate::holonomic::fountain_defaults::DEFAULT_TARGET_HOLDERS`]
/// (previously a duplicated `= 30` literal). The two planes share the
/// number BY DESIGN: the fountain plane derives the survival-floor
/// target (`C₁ = N + K` × churn margin, with the §R reconstruction-
/// probability table computed AT this holder count), and this swarm
/// converger EXISTS to drive the observed holder count toward exactly
/// that target. Two literals agreeing by luck would let the converger
/// steady-state at a count the survival math was not computed for, so
/// it is one `const` with one owner.
pub use crate::holonomic::fountain_defaults::DEFAULT_TARGET_HOLDERS;

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
///
/// CIRISEdge#546 — this is the OPERATOR'S CEILING, not necessarily what a
/// tick runs: [`FountainSwarmRuntime::set_config`] replaces it live, and
/// [`Self::with_mesh_relief`] narrows it (never widens it) by whatever the
/// mesh-config plane is currently asking for. `PartialEq` is derived
/// because the converger compares consecutive *effective* configs to decide
/// whether a change is worth an INFO line — the comparison must cover every
/// field, so deriving it is safer than hand-listing the ones we remembered.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// CIRISEdge#546 — the one arithmetic the whole relief seam rests on:
/// **a relief may shrink a bound and may never raise it.**
///
/// `None` (no root spoke, or the row's TTL expired since the last read) is
/// the configured value untouched — absence is not a value. A `Some` is
/// `min`'d against the configured value rather than replacing it, because
/// persist's relieve-never-expand holds against persist's OWN baseline
/// (`owner_default`, e.g. 64 holders), which is a ceiling above what this
/// node actually runs. A row moving 64 → 40 is a relief up there and an
/// expansion down here; the `min` is what makes it a no-op instead.
const fn shrink_to(configured: u32, relieved: Option<u32>) -> u32 {
    // `Ord::min` is not const; the branch is. `None` and a relief that does not
    // shrink are the same answer — the operator's value stands — so they share
    // one arm rather than two identical ones.
    match relieved {
        Some(r) if r < configured => r,
        _ => configured,
    }
}

impl SwarmRuntimeConfig {
    /// CIRISEdge#546 — this configuration narrowed by one mesh-config relief
    /// snapshot: the config a converger tick actually runs under.
    ///
    /// Pure and total, so it is unit-testable against the exact
    /// [`MeshConfigRelief`] the reader produces rather than against a
    /// convenient stand-in. [`MeshConfigRelief::NONE`] — what an empty
    /// plane, an unresolvable plane, and an EXPIRED emergency row all
    /// resolve to — returns `self` field-for-field, which is why expiry
    /// needs no code path of its own.
    ///
    /// Only the four `redundancy.*` keys land here. `publish_cadence` /
    /// `observe_cadence` / `observed_claim_ttl` / `eviction_grace_pct` have
    /// no registered key (`antientropy.round_secs` is the REPLICATION
    /// scheduler's cadence, a different loop — routing it here would be a
    /// second consumer for one key), so they move only by
    /// [`FountainSwarmRuntime::set_config`].
    ///
    /// A relief may take `policy` outside the §R-policy relations the
    /// `const _: () = assert!(…)` block in
    /// [`crate::holonomic::fountain_defaults`] locks. That is deliberate and
    /// not a violation: those asserts bind the recommended DEFAULTS at
    /// compile time, while a root relieving `k_repair` to 2 is asking this
    /// node to hold less — the whole point of a restrict-only plane. The
    /// survival floor degrades exactly as the root asked it to.
    #[must_use]
    pub fn with_mesh_relief(&self, relief: &MeshConfigRelief) -> Self {
        let mut out = self.clone();
        out.target_holders = shrink_to(self.target_holders, relief.target_holders);
        out.min_viable = shrink_to(self.min_viable, relief.min_viable_holders);
        // `policy.target_holders` — NOT a duplicate of the field above.
        // `SwarmRuntimeConfig::target_holders` is the declared knob (and the
        // one CIRISServer#365's `redundancy.target_holders` names), but the
        // value the ejection verdict actually reads is
        // `policy.target_holders`, via `should_eject_above_target`'s
        // `policy.target_holders + safety` threshold. Relieving only the
        // declared field would land a green test on a knob the field never
        // consults; both move, or the key is decorative.
        out.policy.target_holders = shrink_to(self.policy.target_holders, relief.target_holders);
        out.policy.k_repair = shrink_to(self.policy.k_repair, relief.k_repair_symbols);
        out.policy.min_viable_symbols =
            shrink_to(self.policy.min_viable_symbols, relief.min_viable_symbols);
        // `policy.n_source` is untouched: the RaptorQ source-symbol count is
        // the content's own encoding parameter (changing it invalidates
        // already-encoded symbols), and persist registers no key for it.
        out
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
/// - `scope_table` (CIRISEdge#499): the node's scope-address table. Its
///   presence is the ARMING condition for the holdings scope gate — see
///   [`super::scope`]. `None` (every deployment until the MLS exporter
///   label is specified upstream) means the publisher broadcasts exactly
///   as it did pre-#499.
/// - `metrics` (CIRISEdge#433): the withhold-ledger handle. `None` means
///   withholds are logged but not counted; production threads `Edge`'s
///   handle, mirroring
///   `FederationDirectoryReplicationBridge::with_metrics`.
/// - `mesh_config` (CIRISEdge#546): the resolved mesh-config read seam.
///   `Some` lets a root's TTL'd relief shrink the four `redundancy.*`
///   knobs on the RUNNING converger; `None` is byte-identical pre-#546
///   behaviour. Hosts wire
///   [`crate::replication::runtime::ReplicationRuntime::mesh_config_reader`]
///   here — the SAME `Arc` the bridge, the scheduler and the A/V transit
///   gate read, so the whole node shares one fold resolution per TTL
///   window instead of each loop opening its own.
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
    /// CIRISEdge#499 — the scope-address table. `Some` ARMS the holdings
    /// scope gate: a held content's declared scope then decides which
    /// peers are told the holding exists. `None` is pre-#499 behaviour.
    pub scope_table: Option<Arc<crate::scope_addressing::ScopeAddressTable>>,
    /// CIRISEdge#433 — withhold-ledger handle. Every holding withheld from
    /// a peer is booked here with its named reason.
    pub metrics: Option<crate::observability::EdgeMetrics>,
    /// CIRISEdge#546 — the mesh-config relief seam. `Some` ARMS the
    /// converger's per-tick `redundancy.*` re-resolution; `None` leaves the
    /// operator's configured values as the only input (pre-#546).
    pub mesh_config: Option<Arc<MeshConfigReader>>,
}

impl std::fmt::Debug for SwarmRuntimeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SwarmRuntimeOptions")
            .field("signer_present", &self.signer.is_some())
            .field("rtt_observer_present", &self.rtt_observer.is_some())
            .field("scope_native", &self.scope_table.is_some())
            .field("metrics_present", &self.metrics.is_some())
            .field("mesh_config_armed", &self.mesh_config.is_some())
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
    /// CIRISEdge#546 — the OPERATOR'S CEILING, live. Was a plain
    /// `SwarmRuntimeConfig` copied into the tasks at `start`, which is why
    /// nothing filed after composition could ever apply. Both tasks hold a
    /// receiver and re-read it, so [`Self::set_config`] governs a running
    /// swarm.
    config_tx: watch::Sender<SwarmRuntimeConfig>,
    /// CIRISEdge#546 — kept alongside the tasks' own clone so
    /// [`Self::effective_config`] can answer *"what is this node actually
    /// running right now"* for telemetry without racing the converger.
    mesh_config: Option<Arc<MeshConfigReader>>,
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
        // CIRISEdge#546 — the config the tasks read. `config` is no longer
        // copied field-by-field into the spawned loops; both hold a receiver
        // and re-read at their tick boundary, so `set_config` is live.
        let (config_tx, config_rx) = watch::channel(config);
        let rtt_observer: Arc<dyn PeerRttObserver> = options
            .rtt_observer
            .clone()
            .unwrap_or_else(|| Arc::new(NullRttObserver));

        // CIRISEdge#499 — the publish-side scope gate. Built ONCE at start
        // (it holds only an `Option<Arc<ScopeAddressTable>>` + the metrics
        // handle, both cheap clones), but every DECISION it makes is
        // resolved per record on the tick — the table is read live, never
        // snapshotted, so a rotation seal takes effect on the next tick.
        // CIRISPersist#744 — the gate asks its two persist verbs of the
        // runtime's OWN directory, the one already required by this
        // constructor. Deliberately NOT a new `SwarmRuntimeOptions`
        // field: an armed node must never be one forgotten option away
        // from a hard-coded authority class, and the directory it should
        // ask is the same one the rest of the swarm reads.
        let publish_gate = HoldingsPublishGate::new(
            options.scope_table.clone(),
            Some(Arc::clone(&directory)),
            options.metrics.clone(),
        );

        // CIRISEdge#546 — the WIRING decision, logged ONCE here rather than
        // on every relief read: whether this swarm can be governed by the
        // mesh-config plane at all is a composition fact, and an operator
        // diagnosing "my config row did nothing" needs to see it in the boot
        // log. Throttled anyway because `install_swarm_runtime` is
        // LAST-WINS (CIRISEdge#391) — a host that re-composes in a loop must
        // not turn this into a log flood.
        if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
            swarm_config_plane_log().check("wiring")
        {
            tracing::info!(
                mesh_config_armed = options.mesh_config.is_some(),
                suppressed_prev,
                "swarm_runtime: config plane wired (CIRISEdge#546) — set_config governs the \
                 running swarm; mesh-config relief shrinks the redundancy.* knobs when armed"
            );
        }

        let publisher_task = {
            let holdings = Arc::clone(&holdings);
            let transport = Arc::clone(&transport);
            let cohort = Arc::clone(&cohort);
            let config_rx = config_rx.clone();
            let cancel_rx = cancel_rx.clone();
            let sink = sink.clone();
            let local_peer = local_peer_id.clone();
            let signer = options.signer.clone();
            tokio::spawn(async move {
                run_publisher(
                    holdings,
                    transport,
                    cohort,
                    local_peer,
                    config_rx,
                    cancel_rx,
                    sink,
                    signer,
                    publish_gate,
                )
                .await;
            })
        };

        let converger_task = {
            let observed = Arc::clone(&observed);
            let holdings = Arc::clone(&holdings);
            let directory = Arc::clone(&directory);
            let local_peer = local_peer_id.clone();
            let rtt = Arc::clone(&rtt_observer);
            let mesh_config = options.mesh_config.clone();
            tokio::spawn(async move {
                run_converger(
                    observed,
                    holdings,
                    directory,
                    config_rx,
                    mesh_config,
                    cancel_rx,
                    sink,
                    local_peer,
                    rtt,
                )
                .await;
            })
        };

        Self {
            config_tx,
            mesh_config: options.mesh_config.clone(),
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

    /// The active runtime configuration — the OPERATOR'S CEILING, i.e. what
    /// [`Self::set_config`] last stored (composition's value until then).
    ///
    /// CIRISEdge#546 changed this from `&SwarmRuntimeConfig` to an owned
    /// clone: the config lives behind a [`watch`] channel now, and handing
    /// out a borrow into it would either pin a `watch::Ref` across the
    /// caller's `await`s or lie about being live. Use
    /// [`Self::effective_config`] for what a tick actually runs under.
    #[must_use]
    pub fn config(&self) -> SwarmRuntimeConfig {
        self.config_tx.borrow().clone()
    }

    /// CIRISEdge#546 — **the setter the mesh-config plane needed.** Replace
    /// the operator's ceiling on a RUNNING swarm; both loops pick it up
    /// without a restart (the publisher rebuilds its interval at once, the
    /// converger at its next tick boundary).
    ///
    /// This is the OPERATOR's axis, so it is deliberately unbounded: a node's
    /// owner may set their own node to anything. The bound that matters —
    /// *"a config row must never exceed the operator's ceiling"* — is applied
    /// on the other axis, in [`SwarmRuntimeConfig::with_mesh_relief`], which
    /// re-reads THIS value every tick. Handing a folded mesh-config result to
    /// this method instead would invert that: the fold's own baseline is
    /// persist's `owner_default` ceiling, not this node's configured value,
    /// so a "relief" of 64 → 40 holders would land as an expansion past a
    /// configured 30. Hosts should set what the operator configured and arm
    /// [`SwarmRuntimeOptions::mesh_config`]; the plane then relieves it.
    ///
    /// `watch::Sender::send_replace`, not `send`: the value must be stored
    /// even if both task receivers are already gone (post-[`Self::shutdown`]),
    /// so [`Self::config`] never answers with a superseded value.
    pub fn set_config(&self, config: SwarmRuntimeConfig) {
        let previous = self.config_tx.send_replace(config);
        // Only a real change is worth a line, and only within the throttle's
        // budget — `set_config` is operator-driven and therefore rare, but a
        // host polling a control plane into it must not be able to make this
        // a per-poll write.
        let changed = *self.config_tx.borrow() != previous;
        if changed {
            if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                swarm_config_plane_log().check("set_config")
            {
                let now = self.config_tx.borrow().clone();
                tracing::info!(
                    target_holders = now.target_holders,
                    min_viable = now.min_viable,
                    publish_cadence_secs = now.publish_cadence.as_secs_f64(),
                    observe_cadence_secs = now.observe_cadence.as_secs_f64(),
                    suppressed_prev,
                    "swarm_runtime: operator config replaced on a RUNNING swarm \
                     (CIRISEdge#546)"
                );
            }
        }
    }

    /// CIRISEdge#546 — a receiver over the operator's ceiling, for a host
    /// that wants to mirror the value it set (a status endpoint, a config
    /// reconciler). Carries the CEILING, not the effective value: the relief
    /// is resolved on the converger's tick, so there is nothing to publish
    /// here that would not be stale by construction.
    #[must_use]
    pub fn subscribe_config(&self) -> watch::Receiver<SwarmRuntimeConfig> {
        self.config_tx.subscribe()
    }

    /// CIRISEdge#546 — the configuration a converger tick would run under
    /// **right now**: the operator's ceiling narrowed by the live
    /// mesh-config relief.
    ///
    /// With no reader armed this is exactly [`Self::config`]. With one
    /// armed it is a cached read inside the reader's TTL, so a telemetry
    /// caller polling this does not add fold resolutions — and it answers
    /// with the operator's values again the moment an emergency row's TTL
    /// expires, because [`MeshConfigRelief::NONE`] is what the fold then
    /// yields.
    pub async fn effective_config(&self) -> SwarmRuntimeConfig {
        let configured = self.config();
        effective_swarm_config(&configured, self.mesh_config.as_ref()).await
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
    mut config_rx: watch::Receiver<SwarmRuntimeConfig>,
    mut cancel_rx: watch::Receiver<bool>,
    sink: Option<SwarmRuntimeEventSink>,
    signer: Option<Arc<LocalSigner>>,
    publish_gate: HoldingsPublishGate,
) {
    // CIRISEdge#546 — the cadence is now READ, not captured. No mesh-config
    // key governs it (`antientropy.round_secs` is the replication scheduler's
    // knob, a different loop), so this axis moves only by `set_config`.
    let mut cadence = config_rx.borrow_and_update().publish_cadence;
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
            changed = config_rx.changed() => {
                if changed.is_err() {
                    // The runtime was dropped without `shutdown()`, so the
                    // config sender is gone and `changed()` would return
                    // `Err` immediately, forever — a busy loop. Exit on the
                    // same terms `shutdown` would give us.
                    tracing::debug!("swarm_runtime.publisher: config channel closed; exiting");
                    return;
                }
                let next = config_rx.borrow_and_update().publish_cadence;
                if next != cadence {
                    // `interval_at(now + next, next)` schedules the first
                    // tick one full NEW cadence out — the scheduler's
                    // `antientropy.round_secs` idiom (CIRISEdge#440): a
                    // changed cadence takes effect from the next interval,
                    // never as an immediate catch-up burst.
                    tracing::info!(
                        from_secs = cadence.as_secs_f64(),
                        to_secs = next.as_secs_f64(),
                        "swarm_runtime.publisher: cadence changed by set_config \
                         (CIRISEdge#546)"
                    );
                    cadence = next;
                    ticker = tokio::time::interval_at(
                        tokio::time::Instant::now() + cadence,
                        cadence,
                    );
                    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
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
                    &publish_gate,
                )
                .await
                {
                    tracing::warn!(error = %e, "swarm_runtime.publisher: tick failed");
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn publish_tick(
    holdings: &Arc<dyn FountainHoldingsSource>,
    transport: &Arc<dyn Transport>,
    cohort: &(dyn Fn() -> Vec<String> + Send + Sync),
    local_peer_id: &str,
    sink: Option<&SwarmRuntimeEventSink>,
    signer: Option<&Arc<LocalSigner>>,
    publish_gate: &HoldingsPublishGate,
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
        // CIRISEdge#499 — the record's REAL scope, read per record on this
        // tick from the host's declaration. Never cached across ticks and
        // never inferred: a `None` here is *unknown*, and on a scope-native
        // node unknown is withheld, not published (see `super::scope`).
        // Synchronous, so no guard can outlive it into the `.await`s below
        // (CIRISEdge#217).
        let content_scope = holdings.content_scope(&content.content_id);
        for peer in &peers {
            // Skip self — the cohort callback typically already
            // excludes the local peer, but defense in depth.
            if peer == local_peer_id {
                continue;
            }
            // CIRISEdge#499 — the entitlement filter this path never had.
            // A holdings claim discloses `content_id` AND `symbol_ids`;
            // announcing a family- or community-scoped holding to a peer
            // outside its roster is a contextual-integrity violation even
            // though no content bytes move. `admit_and_book` BOOKS the
            // withhold (#433 ledger) and logs it before returning, so this
            // is never a bare `continue`.
            // CIRISPersist#744 — `async` now: the gate resolves the
            // PUBLISHER's authority class and the recipient set through
            // persist. `local_peer_id` is the publisher — this node signs
            // the holding claim — and it is passed rather than held on
            // the gate so the authority is never cached across one.
            // No guard is live across this await (CIRISEdge#217):
            // `content_scope` above is a plain `Option<ContentScope>`.
            match publish_gate
                .admit_and_book(
                    local_peer_id,
                    &content.content_id,
                    content_scope.as_ref(),
                    peer,
                )
                .await
            {
                HoldingAnnounce::Announce => {}
                HoldingAnnounce::Withhold(_) => continue,
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

/// CIRISEdge#546 — the config one converger tick runs under: the operator's
/// ceiling, narrowed by the live mesh-config relief.
///
/// The reader memoizes within its TTL, so calling this every tick costs one
/// fold resolution per TTL window, not one per tick — the same freshness
/// contract the scheduler's `antientropy.round_secs` read rides. And because
/// it RE-RESOLVES rather than latching, an expired emergency row and an
/// operator edit reach the converger by one path: the fold stops naming the
/// key, [`SwarmRuntimeConfig::with_mesh_relief`] sees `None`, and the value
/// is the ceiling again.
async fn effective_swarm_config(
    configured: &SwarmRuntimeConfig,
    mesh_config: Option<&Arc<MeshConfigReader>>,
) -> SwarmRuntimeConfig {
    match mesh_config {
        // No reader wired: byte-identical pre-#546 behaviour. Relief is not a
        // gate — an unwired plane must not change what the converger does.
        None => configured.clone(),
        Some(reader) => configured.with_mesh_relief(&reader.relief().await),
    }
}

/// CIRISEdge#546 — announce an effective-config change ONCE, at INFO,
/// throttled. Fires only on a real transition (the converger holds the
/// previous value), so a steady relief costs nothing per tick; the throttle
/// is the backstop for a plane FLAPPING between two folds, which would
/// otherwise write a line every tick for as long as it flaps.
fn log_effective_config_change(previous: &SwarmRuntimeConfig, next: &SwarmRuntimeConfig) {
    let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
        swarm_config_plane_log().check("effective")
    else {
        return;
    };
    tracing::info!(
        target_holders_from = previous.policy.target_holders,
        target_holders_to = next.policy.target_holders,
        min_viable_from = previous.min_viable,
        min_viable_to = next.min_viable,
        k_repair_from = previous.policy.k_repair,
        k_repair_to = next.policy.k_repair,
        min_viable_symbols_from = previous.policy.min_viable_symbols,
        min_viable_symbols_to = next.policy.min_viable_symbols,
        suppressed_prev,
        "swarm_runtime.converger: effective config changed — a mesh-config relief \
         took effect, expired, or the operator moved the ceiling (CIRISEdge#546)"
    );
}

#[allow(clippy::too_many_arguments)]
async fn run_converger(
    observed: Arc<RwLock<ObservedClaims>>,
    holdings: Arc<dyn FountainHoldingsSource>,
    directory: Arc<dyn FederationDirectory>,
    mut config_rx: watch::Receiver<SwarmRuntimeConfig>,
    mesh_config: Option<Arc<MeshConfigReader>>,
    mut cancel_rx: watch::Receiver<bool>,
    sink: Option<SwarmRuntimeEventSink>,
    local_peer_id: String,
    rtt: Arc<dyn PeerRttObserver>,
) {
    // CIRISEdge#546 — the ceiling, re-read whenever `set_config` fires; the
    // `watch::Ref` is cloned out immediately and never held across an await.
    let mut configured = config_rx.borrow_and_update().clone();
    let mut effective = effective_swarm_config(&configured, mesh_config.as_ref()).await;
    let mut cadence = effective.observe_cadence;
    let mut ticker = tokio::time::interval(cadence);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    tracing::info!("swarm_runtime.converger: shutdown");
                    return;
                }
            }
            changed = config_rx.changed() => {
                if changed.is_err() {
                    // Sender gone (runtime dropped without `shutdown()`) —
                    // `changed()` would spin. See `run_publisher`.
                    tracing::debug!("swarm_runtime.converger: config channel closed; exiting");
                    return;
                }
                configured = config_rx.borrow_and_update().clone();
            }
            _ = ticker.tick() => {
                // Re-resolve at the TICK BOUNDARY, every tick. This is the
                // whole point of #546: a boot-only read would keep applying
                // a relief whose TTL expired until a restart nobody performs,
                // which is a NEW lie rather than the existing gap.
                let next = effective_swarm_config(&configured, mesh_config.as_ref()).await;
                if next != effective {
                    log_effective_config_change(&effective, &next);
                    effective = next;
                }
                if effective.observe_cadence != cadence {
                    cadence = effective.observe_cadence;
                    ticker = tokio::time::interval_at(
                        tokio::time::Instant::now() + cadence,
                        cadence,
                    );
                    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                }
                converger_tick(
                    &observed,
                    &holdings,
                    directory.as_ref(),
                    &effective,
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

/// CIRISEdge#546 — the swarm config plane's log gate. Keyed on a THREE-VALUE
/// closed set (`"wiring"`, `"set_config"`, `"effective"`), never on anything
/// a peer can choose, so the bounded key map is a formality here — the
/// budget is what matters. Generous per key (each is a genuine governance
/// event an operator needs in the log), with a wide window so a flapping
/// mesh-config plane collapses to a suppressed count instead of a line per
/// converger tick.
static SWARM_CONFIG_PLANE_LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> =
    std::sync::OnceLock::new();

fn swarm_config_plane_log() -> &'static crate::log_throttle::LogThrottle {
    SWARM_CONFIG_PLANE_LOG
        .get_or_init(|| crate::log_throttle::LogThrottle::new(5, Duration::from_secs(300), 8))
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

    // ─── CIRISEdge#499 — the publisher's entitlement filter ───────────
    //
    // These drive the REAL publisher loop (not the pure gate — that is
    // pinned in `super::super::scope::tests`), because the defect was in
    // the loop: it broadcast every held content_id AND its symbol_ids to
    // every peer the cohort callback returned. A green gate with an
    // unwired loop would be exactly the "test the convenient input, not
    // the field's input" failure this repo has hit twice.

    use crate::blob_swarm::ContentScope;
    use crate::cohort_scope::CohortScope;
    use crate::observability::{EdgeMetrics, WithholdReason};
    use crate::scope_addressing::{ScopeAddressTable, StubDeriver};

    const INSIDER: &str = "ed25519:bob";
    const OUTSIDER: &str = "ed25519:mallory";

    /// Holdings whose scope is declared by the HOST — the production
    /// shape. Contents not named in `scopes` report `None`
    /// (undeterminable), which is how an unwired consumer behaves.
    struct ScopedHoldings {
        held: Vec<HeldFountainContent>,
        scopes: BTreeMap<String, ContentScope>,
    }
    #[async_trait]
    impl FountainHoldingsSource for ScopedHoldings {
        async fn list_held_fountain_content(
            &self,
        ) -> Result<Vec<HeldFountainContent>, FountainEvictError> {
            Ok(self.held.clone())
        }
        fn content_scope(&self, content_id: &str) -> Option<ContentScope> {
            self.scopes.get(content_id).cloned()
        }
    }

    fn held(content_id: &str, symbol_ids: Vec<u32>) -> HeldFountainContent {
        HeldFountainContent {
            content_id: content_id.into(),
            corpus_kind: "fountain-corpus".into(),
            symbol_ids,
        }
    }

    /// A table with ONE family group `fam-1` whose only member is
    /// `INSIDER`. `OUTSIDER` is reachable on the federation address and
    /// belongs to no scope group — the peer the leak used to reach.
    fn family_table() -> Arc<ScopeAddressTable> {
        let t = ScopeAddressTable::new(Arc::new(StubDeriver));
        t.install_group(&CohortScope::Family, "fam-1", 1, &[0xA1; 32], &[INSIDER])
            .expect("family install");
        Arc::new(t)
    }

    /// Did `peer` receive an announcement naming `content_id`? The
    /// holding claim's signing preimage carries the content_id verbatim
    /// (`u64-lp(content_id)`), so a byte-window search over what the
    /// transport actually shipped is the field's own evidence — no
    /// re-derivation of what we THINK was sent.
    fn announced(sends: &[(String, Vec<u8>)], peer: &str, content_id: &str) -> bool {
        let needle = content_id.as_bytes();
        sends
            .iter()
            .any(|(dest, bytes)| dest == peer && bytes.windows(needle.len()).any(|w| w == needle))
    }

    /// Run the publisher for a few ticks and return what the transport
    /// was actually asked to send.
    async fn drive_publisher(
        holdings: Arc<dyn FountainHoldingsSource>,
        peers: Vec<String>,
        options: SwarmRuntimeOptions,
    ) -> Vec<(String, Vec<u8>)> {
        drive_publisher_as(holdings, peers, options, "alice", test_directory()).await
    }

    /// CIRISPersist#744 — drive the loop under a NAMED publisher against a
    /// NAMED directory, because the publisher's authority class is now an
    /// input to the gate. `drive_publisher` keeps the plain-producer
    /// default; the federation-reach assertions need a real trust root.
    async fn drive_publisher_as(
        holdings: Arc<dyn FountainHoldingsSource>,
        peers: Vec<String>,
        options: SwarmRuntimeOptions,
        publisher: &str,
        directory: Arc<dyn FederationDirectory>,
    ) -> Vec<(String, Vec<u8>)> {
        let recording_tx = Arc::new(RecordingTransport::default());
        let tx: Arc<dyn Transport> = recording_tx.clone();
        let cohort: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::new(move || peers.clone());
        let mut rt = FountainSwarmRuntime::start_with_options(
            fast_config(),
            holdings,
            directory,
            tx,
            cohort,
            publisher.to_string(),
            None,
            options,
        );
        tokio::time::sleep(Duration::from_millis(80)).await;
        rt.shutdown().await;
        let sends = recording_tx.sends.lock().unwrap().clone();
        sends
    }

    /// **THE test.** A family-scoped holding is NOT announced to a peer
    /// outside the family, and a federation-scoped holding IS announced
    /// to that SAME peer on the SAME tick — so this cannot pass by
    /// broadcasting nothing. The family member still gets both, so it
    /// cannot pass by breaking the family plane either.
    #[tokio::test]
    async fn family_holding_is_not_announced_outside_the_cohort_but_federation_still_is() {
        let holdings: Arc<dyn FountainHoldingsSource> = Arc::new(ScopedHoldings {
            held: vec![held("c-family", vec![1, 2]), held("c-federation", vec![9])],
            scopes: BTreeMap::from([
                (
                    "c-family".to_string(),
                    ContentScope::Group {
                        scope: CohortScope::Family,
                        group_id: "fam-1".to_string(),
                    },
                ),
                ("c-federation".to_string(), ContentScope::Federation),
            ]),
        });
        let metrics = EdgeMetrics::default();
        // CIRISPersist#744 — the publisher is a REAL trust root
        // (accord-co-scrubbed `infra:attest`, admitted through persist's
        // own gate). That is what makes the federation-scoped holding
        // reach an outsider at all: `holdings_authority` resolves
        // `AccordCoScrub`, `projection_for` gives `Global`, and persist's
        // recipient verb answers `Unbounded`. Under a plain producer the
        // same content projects `Cohort` at a commons tier, which has no
        // roster table, and persist withholds — see
        // `a_plain_producers_federation_holding_is_withheld_by_the_verb`.
        let (backend, _bundle) = crate::bundle_gate::test_support::field_fixture().await;
        let sends = drive_publisher_as(
            holdings,
            vec![INSIDER.to_string(), OUTSIDER.to_string()],
            SwarmRuntimeOptions {
                scope_table: Some(family_table()),
                metrics: Some(metrics.clone()),
                ..SwarmRuntimeOptions::default()
            },
            crate::bundle_gate::test_support::PIPELINE,
            Arc::new(backend),
        )
        .await;

        assert!(
            !announced(&sends, OUTSIDER, "c-family"),
            "a family-scoped holding leaked to a peer outside the family",
        );
        assert!(
            announced(&sends, OUTSIDER, "c-federation"),
            "the federation-scoped holding must STILL reach that peer — a suite \
             that passes by broadcasting nothing proves nothing",
        );
        assert!(
            announced(&sends, INSIDER, "c-family"),
            "the family MEMBER must still be told; withholding from everyone is \
             not the fix",
        );
        assert!(announced(&sends, INSIDER, "c-federation"));
        assert!(
            metrics.withholds(WithholdReason::HoldingScopePeerNotInRoster) > 0,
            "the withhold must be BOOKED, not a bare continue",
        );
    }

    /// CIRISPersist#744, at the LOOP — the twin of
    /// `family_holding_is_not_announced_outside_the_cohort_but_federation_still_is`.
    ///
    /// The same federation-scoped holding, the same armed table, the same
    /// peers — only the PUBLISHER changes, from a trust root to a plain
    /// producer. Persist projects `Cohort` at a commons tier, holds no
    /// roster table for one, and answers "I cannot judge", so the holding
    /// is withheld and BOOKED under its own reason.
    ///
    /// This is the half-landing guard driven through the real publisher
    /// rather than the pure gate: revert the authority seam and the two
    /// tests collapse onto one answer, which is precisely the collapse
    /// that hid the defect.
    #[tokio::test]
    async fn a_plain_producers_federation_holding_is_withheld_by_the_verb() {
        let holdings: Arc<dyn FountainHoldingsSource> = Arc::new(ScopedHoldings {
            held: vec![held("c-federation", vec![9])],
            scopes: BTreeMap::from([("c-federation".to_string(), ContentScope::Federation)]),
        });
        let metrics = EdgeMetrics::default();
        let (backend, _bundle) = crate::bundle_gate::test_support::field_fixture().await;
        let sends = drive_publisher_as(
            holdings,
            vec![INSIDER.to_string(), OUTSIDER.to_string()],
            SwarmRuntimeOptions {
                scope_table: Some(family_table()),
                metrics: Some(metrics.clone()),
                ..SwarmRuntimeOptions::default()
            },
            // A plain node row — NOT accord-co-scrubbed.
            crate::bundle_gate::test_support::PRESENTER,
            Arc::new(backend),
        )
        .await;

        assert!(
            !announced(&sends, OUTSIDER, "c-federation"),
            "a PLAIN producer's federation holding must not be broadcast: \
             persist projects Cohort at a commons tier, has no roster table \
             for one, and says so",
        );
        assert!(
            !announced(&sends, INSIDER, "c-federation"),
            "'cannot judge' is about the SET, not about one peer — it \
             withholds from everyone, including a family member",
        );
        assert!(
            metrics.withholds(WithholdReason::HoldingScopeRecipientSetUnresolved) > 0,
            "the withhold must be BOOKED under the 'cannot judge' reason, \
             never as peer-not-in-roster",
        );
        assert_eq!(
            metrics.withholds(WithholdReason::HoldingScopePeerNotInRoster),
            0,
            "an admission of ignorance must never be booked as an accusation \
             about the peer",
        );
    }

    /// Unknown scope on a scope-native node is not announced to anyone,
    /// and the refusal carries its own named reason — never folded into
    /// the roster branch, and never read as "public".
    #[tokio::test]
    async fn unknown_scope_is_not_announced_and_books_its_own_reason() {
        // No entry in `scopes` ⇒ `content_scope` returns None.
        let holdings: Arc<dyn FountainHoldingsSource> = Arc::new(ScopedHoldings {
            held: vec![held("c-unclassified", vec![4])],
            scopes: BTreeMap::new(),
        });
        let metrics = EdgeMetrics::default();
        let sends = drive_publisher(
            holdings,
            vec![INSIDER.to_string(), OUTSIDER.to_string()],
            SwarmRuntimeOptions {
                scope_table: Some(family_table()),
                metrics: Some(metrics.clone()),
                ..SwarmRuntimeOptions::default()
            },
        )
        .await;

        assert!(
            sends.is_empty(),
            "an undeterminable scope must not be announced to anyone, got {} sends",
            sends.len(),
        );
        assert!(
            metrics.withholds(WithholdReason::HoldingScopeUndeterminable) > 0,
            "the undeterminable branch must book ITS OWN reason",
        );
        assert_eq!(
            metrics.withholds(WithholdReason::HoldingScopePeerNotInRoster),
            0,
            "'I cannot tell what this is' must never be reported as \
             'you are not on its roster' (CIRISEdge#433)",
        );
        let snap = metrics.snapshot();
        assert!(snap
            .recent_withholds
            .iter()
            .any(|w| w.detail.starts_with("fountain:c-unclassified")));
    }

    /// **The no-regression case.** A deployment with NO scope information
    /// — no address table, no `content_scope` override — announces every
    /// held content to every peer, exactly as it did pre-#499. This is
    /// what makes the cut safe to ship inert.
    #[tokio::test]
    async fn a_deployment_with_no_scope_information_broadcasts_exactly_as_before() {
        // `VecHoldings` does NOT override `content_scope`, so every
        // content reports `None` — the pre-#499 consumer, verbatim.
        let holdings: Arc<dyn FountainHoldingsSource> = Arc::new(VecHoldings(vec![
            held("c-x", vec![1, 2, 3]),
            held("c-y", vec![10, 20]),
        ]));
        let metrics = EdgeMetrics::default();
        let sends = drive_publisher(
            holdings,
            vec![INSIDER.to_string(), OUTSIDER.to_string()],
            SwarmRuntimeOptions {
                // No table ⇒ the gate is not armed.
                scope_table: None,
                metrics: Some(metrics.clone()),
                ..SwarmRuntimeOptions::default()
            },
        )
        .await;

        for peer in [INSIDER, OUTSIDER] {
            for cid in ["c-x", "c-y"] {
                assert!(
                    announced(&sends, peer, cid),
                    "unarmed deployment must announce {cid} to {peer} exactly as before",
                );
            }
        }
        assert!(
            metrics.snapshot().withholds_by_reason.is_empty(),
            "an unarmed deployment withholds nothing and books nothing",
        );
    }

    /// The armed-but-unwired ordering fact, stated as a test so nobody
    /// discovers it in production: installing an address table WITHOUT
    /// overriding `content_scope` fails the holdings plane closed. That
    /// is the correct order of operations (declare scopes, then derive
    /// addresses), and it is loud — every refusal is booked.
    #[tokio::test]
    async fn arming_without_declaring_scopes_fails_closed_and_loud() {
        let holdings: Arc<dyn FountainHoldingsSource> =
            Arc::new(VecHoldings(vec![held("c-x", vec![1])]));
        let metrics = EdgeMetrics::default();
        let sends = drive_publisher(
            holdings,
            vec![OUTSIDER.to_string()],
            SwarmRuntimeOptions {
                scope_table: Some(family_table()),
                metrics: Some(metrics.clone()),
                ..SwarmRuntimeOptions::default()
            },
        )
        .await;
        assert!(sends.is_empty());
        assert!(metrics.withholds(WithholdReason::HoldingScopeUndeterminable) > 0);
    }

    // ─── CIRISEdge#546 — the config plane governs a RUNNING swarm ─────
    //
    // Half of these are pure (`with_mesh_relief` is the whole ceiling
    // arithmetic), half drive the REAL converger loop — because "there is
    // no setter" was a LOOP defect, not an arithmetic one, and a green
    // pure test over a loop that still copies its config at start would
    // be exactly the false confirmation the issue exists to remove.

    /// The relief shape a root's row produces once it has been through
    /// persist's fold: only the keys a root actually moved off the
    /// baseline are `Some`. Built field-by-field rather than by mutating
    /// `NONE` so a new field added to `MeshConfigRelief` breaks this
    /// helper instead of silently defaulting past these assertions.
    const fn redundancy_relief(
        k_repair_symbols: Option<u32>,
        min_viable_symbols: Option<u32>,
        target_holders: Option<u32>,
        min_viable_holders: Option<u32>,
    ) -> MeshConfigRelief {
        MeshConfigRelief {
            round_cadence: None,
            page_limit: None,
            trace_replication_paused: false,
            av_streams_paused: false,
            k_repair_symbols,
            min_viable_symbols,
            target_holders,
            min_viable_holders,
        }
    }

    /// EXPIRY, stated as the identity it is. `MeshConfigRelief::NONE` is
    /// what an empty plane, an unreadable plane, and an emergency row
    /// whose TTL has passed all resolve to — so "the emergency expired"
    /// needs no code path of its own, and this assertion is what says so.
    #[test]
    fn an_expired_or_absent_relief_leaves_the_configuration_field_for_field() {
        let configured = SwarmRuntimeConfig::default();
        assert_eq!(
            configured.with_mesh_relief(&MeshConfigRelief::NONE),
            configured
        );
    }

    /// **THE ceiling test.** Every one of the four keys folds against
    /// persist's `owner_default` (k_repair 20, min_viable_symbols 20,
    /// both holder keys 64), all of which sit ABOVE what this node runs.
    /// So a root moving `target_holders` 64 → 40 is a genuine relief
    /// upstream and would still be an EXPANSION here — 40 > the
    /// configured 30. `min` at the consumer is what makes it a no-op.
    #[test]
    fn a_relief_above_the_operator_ceiling_never_raises_a_knob() {
        let configured = SwarmRuntimeConfig::default();
        // Field-shaped: every value below is < persist's owner_default for
        // its key (so persist marks it `relieved`) and > edge's configured
        // value (so a naive replacement would raise the bound).
        let relief = redundancy_relief(Some(15), Some(12), Some(40), Some(40));
        let effective = configured.with_mesh_relief(&relief);
        assert_eq!(effective, configured, "a relief must never widen a bound");
        assert_eq!(effective.target_holders, DEFAULT_TARGET_HOLDERS);
        assert_eq!(effective.policy.target_holders, DEFAULT_TARGET_HOLDERS);
        assert_eq!(effective.min_viable, DEFAULT_MIN_VIABLE);
        assert_eq!(effective.policy.k_repair, configured.policy.k_repair);
        assert_eq!(
            effective.policy.min_viable_symbols,
            configured.policy.min_viable_symbols
        );
    }

    /// The relief direction is NOT blocked: below the ceiling every knob
    /// moves. `redundancy.target_holders` moves BOTH holder fields —
    /// `SwarmRuntimeConfig::target_holders` is the declared knob, but
    /// `policy.target_holders` is the one `should_eject_above_target`
    /// actually reads, and a key that moved only the declared field would
    /// be decorative.
    #[test]
    fn a_relief_below_the_ceiling_shrinks_every_knob_including_the_policy_twin() {
        let configured = SwarmRuntimeConfig::default();
        let effective =
            configured.with_mesh_relief(&redundancy_relief(Some(2), Some(3), Some(12), Some(1)));
        assert_eq!(effective.target_holders, 12);
        assert_eq!(
            effective.policy.target_holders, 12,
            "the field the ejection verdict reads must move with the declared knob",
        );
        assert_eq!(effective.min_viable, 1);
        assert_eq!(effective.policy.k_repair, 2);
        assert_eq!(effective.policy.min_viable_symbols, 3);
        assert_eq!(
            effective.policy.n_source, configured.policy.n_source,
            "n_source is the content's own encoding parameter — no key governs it",
        );
        assert_eq!(
            effective.publish_cadence, configured.publish_cadence,
            "no redundancy key touches a cadence",
        );
    }

    /// A converger-only rig: an empty cohort (so the publisher ships
    /// nothing and cannot colour the sink), one locally-held content, and
    /// `holders` distinct peer claims for it.
    async fn converger_rig(
        config: SwarmRuntimeConfig,
        options: SwarmRuntimeOptions,
        content_id: &str,
        holders: u32,
    ) -> (
        FountainSwarmRuntime,
        tokio::sync::mpsc::UnboundedReceiver<SwarmEvent>,
    ) {
        let holdings: Arc<dyn FountainHoldingsSource> =
            Arc::new(VecHoldings(vec![held(content_id, vec![7])]));
        let tx: Arc<dyn Transport> = Arc::new(RecordingTransport::default());
        let cohort: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::new(Vec::new);
        let (sink_tx, sink_rx) = tokio::sync::mpsc::unbounded_channel::<SwarmEvent>();
        let sink: SwarmRuntimeEventSink = Arc::new(move |ev| {
            let _ = sink_tx.send(ev);
        });
        let rt = FountainSwarmRuntime::start_with_options(
            config,
            holdings,
            test_directory(),
            tx,
            cohort,
            "alice".to_string(),
            Some(sink),
            options,
        );
        for i in 0..holders {
            rt.register_observed_claim(FountainHoldingClaim::new(
                format!("peer-{i}"),
                content_id,
                vec![7],
                1_700_000_000,
            ))
            .await;
        }
        (rt, sink_rx)
    }

    /// Did the converger emit `RepairNeeded` for `content_id` since the
    /// last drain? Also drains `Keep`, so an empty answer means the
    /// converger ran and chose not to repair — not that it never ran.
    fn drained_repair_and_keep(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<SwarmEvent>,
        content_id: &str,
    ) -> (bool, bool) {
        let (mut repaired, mut kept) = (false, false);
        while let Ok(ev) = rx.try_recv() {
            match ev {
                SwarmEvent::RepairNeeded { content_id: c, .. } if c == content_id => {
                    repaired = true;
                }
                SwarmEvent::Keep { content_id: c, .. } if c == content_id => kept = true,
                _ => {}
            }
        }
        (repaired, kept)
    }

    /// **THE setter test.** A `SwarmRuntimeConfig` filed AFTER `start`
    /// changes what the converger does, on the same running tasks, with
    /// no restart — the gap CIRISServer#365's four keys were parked on.
    /// Asserted in both phases so it cannot pass by emitting nothing: the
    /// first phase must show the converger running and CHOOSING not to
    /// repair.
    #[tokio::test]
    async fn a_config_set_after_start_governs_the_running_converger() {
        let content_id = "c-governed";
        let (rt, mut rx) = converger_rig(
            SwarmRuntimeConfig {
                min_viable: 1,
                ..fast_config()
            },
            SwarmRuntimeOptions::default(),
            content_id,
            2,
        )
        .await;

        tokio::time::sleep(Duration::from_millis(80)).await;
        let (repaired, kept) = drained_repair_and_keep(&mut rx, content_id);
        assert!(!repaired, "2 holders is above a min_viable of 1");
        assert!(
            kept,
            "the converger must have RUN — a silent loop proves nothing"
        );

        // The whole issue, in one call: no restart, no re-composition.
        rt.set_config(SwarmRuntimeConfig {
            min_viable: 5,
            ..fast_config()
        });
        assert_eq!(rt.config().min_viable, 5, "the ceiling is what was set");

        tokio::time::sleep(Duration::from_millis(80)).await;
        let (repaired, _) = drained_repair_and_keep(&mut rx, content_id);
        let mut rt = rt;
        rt.shutdown().await;
        assert!(
            repaired,
            "a config filed after start must govern the RUNNING converger — this is \
             the boot-only-consumer defect (CIRISEdge#546)",
        );
    }

    /// The relief seam at the LOOP. The same fixture that repairs under
    /// the operator's own `min_viable` stops repairing once a root's row
    /// relieves the holder floor beneath it — resolved on the converger's
    /// tick, not at composition.
    #[tokio::test]
    async fn a_mesh_config_relief_shrinks_min_viable_on_a_running_converger() {
        let content_id = "c-relieved";
        // Control: no reader armed ⇒ pre-#546 behaviour, 2 < 5, repair.
        let (rt, mut rx) =
            converger_rig(fast_config(), SwarmRuntimeOptions::default(), content_id, 2).await;
        tokio::time::sleep(Duration::from_millis(80)).await;
        let (unarmed_repaired, _) = drained_repair_and_keep(&mut rx, content_id);
        let mut rt = rt;
        rt.shutdown().await;
        assert!(
            unarmed_repaired,
            "an unarmed deployment must behave exactly as before — a control that \
             does not fire makes the armed case meaningless",
        );

        // Armed: a root relieved the holder floor 64 → 1, well under the
        // configured 5, so 2 observed holders is no longer a shortfall.
        let reader = Arc::new(MeshConfigReader::fixed_for_test(
            test_directory(),
            redundancy_relief(None, None, None, Some(1)),
        ));
        let (rt, mut rx) = converger_rig(
            fast_config(),
            SwarmRuntimeOptions {
                mesh_config: Some(reader),
                ..SwarmRuntimeOptions::default()
            },
            content_id,
            2,
        )
        .await;
        tokio::time::sleep(Duration::from_millis(80)).await;
        let (armed_repaired, armed_kept) = drained_repair_and_keep(&mut rx, content_id);
        let mut rt = rt;
        rt.shutdown().await;
        assert!(armed_kept, "the converger must still be running");
        assert!(
            !armed_repaired,
            "a relieved holder floor of 1 must stop the RepairNeeded the configured \
             floor of 5 produced",
        );
    }

    /// The ceiling, at the LOOP rather than in the arithmetic. A root
    /// asking for a HIGHER holder floor than the operator configured is
    /// still a relief upstream (64 → 5 under persist's owner_default) and
    /// must be a no-op here: the converger keeps the operator's 1.
    #[tokio::test]
    async fn a_relief_above_the_ceiling_cannot_raise_min_viable_on_a_running_converger() {
        let content_id = "c-ceilinged";
        let reader = Arc::new(MeshConfigReader::fixed_for_test(
            test_directory(),
            redundancy_relief(None, None, None, Some(5)),
        ));
        let (rt, mut rx) = converger_rig(
            SwarmRuntimeConfig {
                min_viable: 1,
                ..fast_config()
            },
            SwarmRuntimeOptions {
                mesh_config: Some(reader),
                ..SwarmRuntimeOptions::default()
            },
            content_id,
            2,
        )
        .await;
        tokio::time::sleep(Duration::from_millis(80)).await;
        let (repaired, kept) = drained_repair_and_keep(&mut rx, content_id);
        let mut rt = rt;
        rt.shutdown().await;
        assert!(kept, "the converger must have run");
        assert!(
            !repaired,
            "a config row must never push a knob PAST the operator's own configured \
             value — min(configured, relieved), never replacement",
        );
    }
}
