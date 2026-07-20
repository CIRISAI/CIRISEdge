//! `ReplicationRuntime` — the operator-facing entry point that
//! bundles bridge + registry + scheduler + cohort callback into a
//! single managed runtime.
//!
//! Closes the orchestration concern raised in CIRISEdge#65's
//! FSD §3.7. Per the FSD:
//!
//! > `init_edge_runtime` gains [replication parameters]. Each entry
//! > constructs a `ReplicationCoordinator` (Initiator role, because
//! > the operator chose to peer with this remote for this kind),
//! > registers it with the application-side `ReplicationRegistry`
//! > (for inbound dispatch), and adds it to the
//! > `ReplicationScheduler`'s Initiator set.
//!
//! This module is the small bit of glue that does all of that
//! cohesively + exposes a runtime handle the caller can hold for
//! the lifetime of their application.
//!
//! ## Shape
//!
//! - [`ReplicationRuntime::start`] constructs the bridge, builds
//!   coordinators for each peer/kind in the configured set,
//!   registers them with a shared [`ReplicationRegistry`], hands
//!   the Initiator set to a [`ReplicationScheduler`], and spawns
//!   the scheduler's run loop on the current tokio runtime.
//! - [`ReplicationRuntime::register_peer`] hot-adds a new
//!   `(peer_key_id, kind)` after start.
//! - [`ReplicationRuntime::registry`] returns a shared
//!   `Arc<ReplicationRegistry>` the application's `Transport::listen`
//!   loop calls `route_inbound_bytes` on. The listen-loop integration
//!   itself is operator code — when bytes arrive identifying a
//!   source peer, the operator calls `registry.route_inbound_bytes(
//!   peer_key_id, bytes)` and that's it.
//! - [`ReplicationRuntime::shutdown`] flips the scheduler's cancel
//!   watch to true and awaits the scheduler's run-loop task to
//!   completion.
//!
//! ## Why no auto-routing into transport.listen()
//!
//! Edge's `Transport::listen` already runs in the application's
//! existing dispatch loop. Wiring the registry's `route_inbound_bytes`
//! INTO that loop is operator code (a one-line addition to the
//! application's listen-handler), not edge's job. This keeps the
//! v1 cut clean: the runtime exposes the registry; the operator
//! wires it. A v1.7 follow-up may add an opt-in
//! `Edge::install_replication_routing(runtime)` helper.

use std::collections::HashSet;
use std::sync::Arc;

use ciris_persist::federation::FederationDirectory;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinHandle;

use super::bridge::{BridgeConfig, CohortProvider, FederationDirectoryReplicationBridge};
use super::coordinator::{DriveStep, ReplicationCoordinator};
use super::directory::{DirectoryStateAdapter, MutableDirectoryStateAdapter, ReplicationDirectory};
use super::protocol::EnvelopeKind;
use super::registry::ReplicationRegistry;
use super::scheduler::{
    ReplicationScheduler, RoundEvent, SchedulerCommandError, SchedulerConfig, SchedulerHandle,
};
use super::session::SessionRole;
use super::summary::{StateApplier, StateProvider};
use crate::transport::Transport;

/// CIRISEdge#373 — outer bound on a single responder reply send inside the drive
/// loop, so a stalled reply can't park the inbound drain forever. Sized to sit
/// just ABOVE the reverse-path progress-aware hard cap (`REVERSE_PATH_MAX_TRANSFER`
/// = 45 s, v13.6.1) plus dial margin, so it never severs a LIVE, progressing
/// large-resource transfer — that would re-open the exact live-link cut v13.6.1
/// fixes. A DEAD link now fast-fails at the reverse-path no-progress window (~6 s),
/// so this bound only bites a genuinely pathological send; a progressing transfer
/// is delivering the trace, so letting it run is correct.
const RESPONDER_REPLY_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// CIRISEdge#348 — drive a factory-created **Responder** coordinator.
///
/// The registry only STORES a coordinator; the [`ReplicationScheduler`] drives
/// **Initiators** only (`add_initiator`). A Responder spun up on-demand for an
/// inbound round from a non-consent-pull peer (the #312 responder factory) has
/// no other driver — so this task IS its round engine: pull each inbound
/// replication message, step the round, and emit every reply on the transport.
///
/// Without it, `route_inbound_bytes` `deliver_inbound`'s the round-open into the
/// coordinator's channel and it is NEVER processed — the responder never
/// replies, the initiator times out forever, and (the seam that cost the mesh
/// weeks — #348) NOTHING logs. This was the missing half of #312: it spun up +
/// registered the Responder but never ran the drive loop. Spawned ONCE per
/// (peer, kind) — `get_or_register_with` invokes the factory only on first
/// insert. Every terminal / error path logs; there is no silent discard.
fn spawn_responder_drive(coord: Arc<ReplicationCoordinator>) {
    tokio::spawn(async move {
        let peer = coord.peer_key_id().to_string();
        let kind = coord.kind();
        tracing::debug!(peer = %peer, ?kind, "responder driver started (CIRISEdge#348)");
        loop {
            // Channel closed ⇒ the coordinator was dropped; end the driver.
            let Some(msg) = coord.recv_inbound().await else {
                tracing::debug!(peer = %peer, ?kind, "responder driver ending (channel closed)");
                break;
            };
            match coord.drive_round_step(Some(msg)).await {
                Ok(DriveStep::SendThenWait(msgs)) => {
                    for m in &msgs {
                        // CIRISEdge#373 — BOUND the reply send. This loop is the
                        // responder's only inbound drain; a reply that blocks here
                        // (a reverse-path stall to a churning NAT'd peer + the
                        // NAT-blocked dial fallback = up to ~130 s) parks the drain
                        // while the peer keeps pushing frames, overflowing the
                        // capacity-8 inbound channel and silently dropping 100% of
                        // the trace. Cap it well under the round cadence so a stalled
                        // reply yields the drain; the abandoned send is safe (its
                        // awaits — resource wait, dial — are cancellation-tolerant,
                        // and the anti-entropy protocol is idempotent + retried).
                        match tokio::time::timeout(
                            RESPONDER_REPLY_SEND_TIMEOUT,
                            coord.send_message(m),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                tracing::warn!(
                                    peer = %peer, ?kind, error = %e,
                                    "responder reply send failed — round will not complete (CIRISEdge#348)"
                                );
                                break;
                            }
                            Err(_elapsed) => {
                                tracing::warn!(
                                    peer = %peer, ?kind,
                                    timeout_secs = RESPONDER_REPLY_SEND_TIMEOUT.as_secs(),
                                    "responder reply send TIMED OUT — abandoning it so the inbound \
                                     drain resumes and the peer's trace is not dropped (CIRISEdge#373); \
                                     the next round rides the peer's fresh link"
                                );
                                break;
                            }
                        }
                    }
                }
                Ok(DriveStep::Complete(report)) => {
                    tracing::debug!(
                        peer = %peer, ?kind, ?report,
                        "responder served an anti-entropy round to completion (CIRISEdge#348)"
                    );
                }
                Ok(DriveStep::Refused) => {
                    tracing::warn!(
                        peer = %peer, ?kind,
                        "responder REFUSED an inbound replication message (unexpected role/phase) \
                         — dropped, NOT silently (CIRISEdge#348)"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        peer = %peer, ?kind, error = %e,
                        "responder drive_round_step failed; ending driver (CIRISEdge#348)"
                    );
                    break;
                }
            }
        }
    });
}

/// CIRISEdge#370 — project a scheduler [`RoundEvent`] onto the
/// metrics-facing [`crate::observability::RoundOutcome`] label. The
/// `Completed` report payload and the `Error` string are intentionally
/// dropped here — high-cardinality per-round detail rides the round's
/// tracing span, not the counter key.
fn round_outcome_of(event: &RoundEvent) -> crate::observability::RoundOutcome {
    use crate::observability::RoundOutcome;
    match event {
        RoundEvent::Completed(_) => RoundOutcome::Completed,
        RoundEvent::Refused => RoundOutcome::Refused,
        RoundEvent::TimedOut => RoundOutcome::TimedOut,
        RoundEvent::Error(_) => RoundOutcome::Error,
    }
}

/// A `(peer_key_id, kind)` pair the runtime should anti-entropy with
/// as the Initiator side. Each pair gets one [`ReplicationCoordinator`]
/// in the Initiator role.
#[derive(Debug, Clone)]
pub struct ReplicationPeer {
    pub peer_key_id: String,
    pub kind: EnvelopeKind,
}

/// Configuration for [`ReplicationRuntime::start`].
#[derive(Debug, Clone, Default)]
pub struct ReplicationRuntimeConfig {
    /// Cadence + round-timeout for the scheduler. Defaults to
    /// [`SchedulerConfig::default`] (30 s cadence, 10 s round timeout).
    pub scheduler: SchedulerConfig,
    /// Cache + paging tuning for the bridge. Defaults to
    /// [`BridgeConfig::default`].
    pub bridge: BridgeConfig,
    /// CIRISEdge#370 — optional live metrics handle. When `Some`,
    /// [`ReplicationRuntime::start`] wires the scheduler's `event_sink`
    /// to a consumer task that folds each round's
    /// [`RoundEvent`](crate::replication::scheduler::RoundEvent) into
    /// the [`EdgeMetrics::inc_round_outcome`](crate::observability::EdgeMetrics::inc_round_outcome)
    /// counter — the field instrument for the transport concurrency
    /// ceiling. `None` (the default) preserves the pre-#370
    /// `run_until_cancelled` path with no event-sink overhead. This is a
    /// live shared handle (its counters are `Arc`-backed), not tuning —
    /// it rides on the config only because `start` already threads the
    /// config through to the scheduler-spawn site.
    pub metrics: Option<crate::observability::EdgeMetrics>,
}

/// Live replication runtime — bridge + registry + scheduler task +
/// shutdown handle. Construct via [`Self::start`]; hold the returned
/// handle for the lifetime of the application; call
/// [`Self::shutdown`] to stop the background scheduler.
pub struct ReplicationRuntime {
    transport: Arc<dyn Transport>,
    registry: Arc<ReplicationRegistry>,
    bridge: Arc<FederationDirectoryReplicationBridge>,
    cancel_tx: watch::Sender<bool>,
    scheduler_task: Option<JoinHandle<()>>,
    config: ReplicationRuntimeConfig,
    /// Runtime control channel for the scheduler (CIRISEdge#173,
    /// v5.1.0). Used by [`Self::register_initiator_peer`] /
    /// [`Self::remove_peer`] / [`Self::set_peers`] to mutate the
    /// scheduler's Initiator set without restart.
    scheduler_handle: SchedulerHandle,
    /// Current Initiator set, kept in sync with the scheduler's
    /// live coordinator tasks. Drives [`Self::set_peers`]'s diff.
    /// Pre-v5.1 entries (passed to `start`) populate this on init.
    current_initiators: Arc<Mutex<HashSet<(String, EnvelopeKind)>>>,
    /// CIRISEdge#927 — whether this node's Initiator rounds proactively deliver
    /// their publish set (set iff `start` got a `self_provider`). Applied to
    /// every Initiator coordinator this runtime builds, including hot-adds.
    proactive_publish: bool,
}

/// Failure modes for the v5.1.0 runtime peer-mutation API
/// (CIRISEdge#173).
#[derive(Debug, thiserror::Error)]
pub enum ReplicationRuntimeError {
    /// The scheduler has stopped (e.g. [`ReplicationRuntime::shutdown`]
    /// was called) — runtime control is no longer possible. Subsequent
    /// calls will keep failing.
    #[error("replication runtime has shut down; peer mutation is no longer accepted")]
    SchedulerStopped,
}

impl From<SchedulerCommandError> for ReplicationRuntimeError {
    fn from(_: SchedulerCommandError) -> Self {
        Self::SchedulerStopped
    }
}

impl ReplicationRuntime {
    /// Start the runtime with the given set of Initiator peers.
    ///
    /// `directory` is the persist federation directory (typically
    /// extracted from a cohabitating `PyEngine` via the
    /// [`crate::ffi::pyo3::extract_capsule`] helper, or passed as an
    /// `Arc<dyn FederationDirectory>` from the host code path).
    ///
    /// `transport` is the canonical transport for the peer set
    /// (Reticulum per MISSION §1.4; HTTPS in fallback deployments).
    /// One transport instance is shared across all coordinators —
    /// each coordinator addresses its peer by `peer_key_id`.
    ///
    /// `peers` is the initial Initiator set. Each entry constructs
    /// one [`ReplicationCoordinator`] in Initiator role, registers
    /// it with the registry, and hands it to the scheduler.
    pub async fn start(
        directory: Arc<dyn FederationDirectory>,
        transport: Arc<dyn Transport>,
        peers: Vec<ReplicationPeer>,
        config: ReplicationRuntimeConfig,
        // CIRISEdge#311 — the SELF-plane publish set (collapses the #257
        // key_selector + #305 occurrence_selector into one). `Some` yields the
        // node's OWN + held anchored key_ids (KERI publish-own); the unified
        // engine advertises them across every `SelfOwn` kind (Key,
        // IdentityOccurrence — which carries the content-tier `encryption_pubkeys`
        // for KEX — and TransportDestination). `None` preserves the pre-selector
        // cohort projection. The server computes this set (it holds the anchor
        // knowledge) and hands it to edge alongside the consent-derived cohort —
        // edge only provides the hook.
        self_provider: Option<CohortProvider>,
    ) -> Self {
        // Cohort callback: yields the set of peer_key_ids we
        // anti-entropy with, snapshotted at construction. Hot-adds
        // via [`Self::register_peer`] don't update the snapshot —
        // the FSD §3.6 cohort is operator-configured + serves the
        // bridge's list_envelope_refs path, which can re-read on
        // each tick. We accept the snapshot model here because v1
        // hot-add is uncommon; a follow-up patch can swap in a
        // shared Arc<RwLock<Vec<String>>> if dynamism becomes the
        // common path.
        let cohort_snapshot: Vec<String> = peers.iter().map(|p| p.peer_key_id.clone()).collect();
        let cohort: CohortProvider = Arc::new(move || cohort_snapshot.clone());

        // CIRISEdge#927 — a node started with a self-publish set (`self_provider`
        // / `key_publish_set`) is one whose Initiator rounds should proactively
        // DELIVER that set (initiator-first, so a carrier-NAT'd peer's round can
        // complete without a return-path Diff). Capture before `self_provider` is
        // moved into the bridge.
        let proactive_publish = self_provider.is_some();

        let bridge = Arc::new(
            FederationDirectoryReplicationBridge::with_config(
                Arc::clone(&directory),
                cohort,
                config.bridge,
            )
            .with_self_provider(self_provider),
        );

        let registry = Arc::new(ReplicationRegistry::new());

        // CIRISEdge#312 — install the responder factory so an inbound round
        // from an admitted-but-uncoordinated peer (a #301 advisory source we
        // don't consent-pull from, hence never built an Initiator for)
        // auto-registers a `Responder` and is served rather than dropped at
        // `NoCoordinatorRegistered`. Captures the shared transport + bridge;
        // mirrors `build_coordinator` in `Responder` role.
        {
            let factory_transport = Arc::clone(&transport);
            let factory_bridge = Arc::clone(&bridge);
            registry.set_responder_factory(Arc::new(move |peer_key_id: &str, kind| {
                let bridge_dir: Arc<dyn ReplicationDirectory> = Arc::clone(&factory_bridge) as _;
                let provider: Arc<dyn StateProvider> =
                    Arc::new(DirectoryStateAdapter::new(Arc::clone(&bridge_dir)));
                let applier: Arc<Mutex<dyn StateApplier>> =
                    Arc::new(Mutex::new(MutableDirectoryStateAdapter::new(bridge_dir)));
                let coord = Arc::new(ReplicationCoordinator::new(
                    Arc::clone(&factory_transport),
                    peer_key_id.to_string(),
                    kind,
                    SessionRole::Responder,
                    provider,
                    applier,
                ));
                // CIRISEdge#348 — DRIVE the responder. The registry only stores
                // the coordinator; the scheduler drives INITIATORS only. Without
                // a driver here the round-open is `deliver_inbound`'d into the
                // coordinator's channel and NEVER processed — the responder never
                // replies, the initiator times out forever, and (the seam that
                // cost weeks) NOTHING logs. This was the missing half of the #312
                // responder factory: it spun up + registered the Responder but
                // never ran the recv_inbound → drive_round_step → send_message
                // loop. Spawned ONCE per (peer, kind) — `get_or_register_with`
                // calls the factory only on first insert.
                spawn_responder_drive(Arc::clone(&coord));
                coord
            }));
        }

        // Build coordinators + scheduler. Coordinators share one
        // bridge instance; provider + applier are split-shape per
        // session.rs's borrow story (the bridge is the same object
        // backing both).
        let mut scheduler = ReplicationScheduler::new(config.scheduler);
        let scheduler_handle = scheduler.install_control_channel();
        let coords: Vec<Arc<ReplicationCoordinator>> = peers
            .iter()
            .map(|peer| {
                let bridge_dir: Arc<dyn ReplicationDirectory> = Arc::clone(&bridge) as _;
                let provider: Arc<dyn StateProvider> =
                    Arc::new(DirectoryStateAdapter::new(Arc::clone(&bridge_dir)));
                let applier: Arc<tokio::sync::Mutex<dyn StateApplier>> = Arc::new(
                    tokio::sync::Mutex::new(MutableDirectoryStateAdapter::new(bridge_dir)),
                );
                Arc::new(
                    ReplicationCoordinator::new(
                        Arc::clone(&transport),
                        &peer.peer_key_id,
                        peer.kind,
                        SessionRole::Initiator,
                        provider,
                        applier,
                    )
                    .with_proactive_publish(proactive_publish),
                )
            })
            .collect();

        let mut initial_initiator_set: HashSet<(String, EnvelopeKind)> = HashSet::new();
        for (peer, coord) in peers.iter().zip(coords.iter()) {
            scheduler.add_initiator(Arc::clone(coord));
            initial_initiator_set.insert((peer.peer_key_id.clone(), peer.kind));
            // Register so the operator's listen loop can route
            // inbound replies (the Initiator side receives Summary
            // / Diff / Deliver back from the peer). Inline await
            // because `start` is async.
            registry
                .register(peer.peer_key_id.clone(), peer.kind, Arc::clone(coord))
                .await;
        }

        let (cancel_tx, cancel_rx) = watch::channel(false);
        // CIRISEdge#370 — when a live metrics handle is configured, route
        // the scheduler's per-round `RoundEvent`s through the purpose-built
        // `event_sink` into a consumer task that folds each into the
        // `EdgeMetrics` round-outcome counter (the field instrument for the
        // transport concurrency ceiling, leviculum#29). Absent a handle we
        // keep the zero-overhead `run_until_cancelled` path — no channel, no
        // consumer task. The scheduler tolerates a closed sink, and the
        // consumer's `recv()` returns `None` when the scheduler task ends and
        // drops the sender, so the consumer winds down without its own cancel.
        let scheduler_task = if let Some(metrics) = config.metrics.clone() {
            let (evt_tx, mut evt_rx) = mpsc::channel::<(String, RoundEvent)>(256);
            tokio::spawn(async move {
                while let Some((_peer, event)) = evt_rx.recv().await {
                    metrics.inc_round_outcome(round_outcome_of(&event));
                }
            });
            tokio::spawn(async move {
                scheduler.run_with_events(cancel_rx, Some(evt_tx)).await;
            })
        } else {
            tokio::spawn(async move {
                scheduler.run_until_cancelled(cancel_rx).await;
            })
        };

        // `directory` is consumed by the bridge above (held inside
        // `bridge`'s Arc<dyn FederationDirectory>). Drop the local
        // binding to make the lifecycle explicit.
        drop(directory);

        Self {
            transport,
            registry,
            bridge,
            cancel_tx,
            scheduler_task: Some(scheduler_task),
            config,
            scheduler_handle,
            current_initiators: Arc::new(Mutex::new(initial_initiator_set)),
            proactive_publish,
        }
    }

    /// Hot-add a `(peer_key_id, kind)` peer this node actively replicates
    /// with — routes inbound AND drives periodic anti-entropy rounds.
    ///
    /// v13.7.0 — this is now the ONE hot-add, and it does the unsurprising
    /// thing (active replication). It previously defaulted to a passive
    /// **Responder** (routed inbound but never pulled) — a footgun: it read
    /// like "register this peer" but silently did no rounds, and it duplicated
    /// the #312 responder factory, which already auto-registers a Responder on
    /// the first inbound round from any uncoordinated peer. So **serve-only
    /// peers need no call at all** — the factory handles them; callers who mean
    /// "replicate with this peer" get exactly that.
    ///
    /// Delegates to [`Self::register_initiator_peer`] (the CIRISEdge#173 control
    /// plane); returns its error if the scheduler has stopped.
    pub async fn register_peer(
        &self,
        peer_key_id: impl Into<String>,
        kind: EnvelopeKind,
    ) -> Result<(), ReplicationRuntimeError> {
        self.register_initiator_peer(peer_key_id, kind).await
    }

    /// Hot-add a `(peer_key_id, kind)` **Initiator** coordinator —
    /// CIRISEdge#173, v5.1.0.
    ///
    /// v13.7.0 — [`Self::register_peer`] now does exactly this, so this method
    /// is a redundant alias kept for back-compat; prefer `register_peer`.
    ///
    /// Builds a coordinator in [`SessionRole::Initiator`], registers
    /// it with the registry (so inbound replies route correctly),
    /// AND tells the scheduler's runtime control plane to spawn a
    /// task that fires periodic anti-entropy rounds at the configured
    /// cadence. Idempotent — re-adding an active `(peer, kind)` is a
    /// no-op.
    ///
    /// Use this from CEG-driven reconcilers when `consent:replication`
    /// objects materialize at runtime: the new peer begins active
    /// pull immediately, no restart.
    pub async fn register_initiator_peer(
        &self,
        peer_key_id: impl Into<String>,
        kind: EnvelopeKind,
    ) -> Result<(), ReplicationRuntimeError> {
        let peer_key_id = peer_key_id.into();
        let key = (peer_key_id.clone(), kind);

        {
            let mut active = self.current_initiators.lock().await;
            if active.contains(&key) {
                return Ok(());
            }
            active.insert(key);
        }

        let coord = self.build_coordinator(&peer_key_id, kind, SessionRole::Initiator);
        // Register first so the inbound listen loop can route replies
        // by the time the scheduler picks up the command.
        self.registry
            .register(peer_key_id, kind, Arc::clone(&coord))
            .await;
        self.scheduler_handle.add_initiator(coord).await?;
        Ok(())
    }

    /// Hot-remove a `(peer_key_id, kind)` peer — CIRISEdge#173,
    /// v5.1.0.
    ///
    /// Stops the matching Initiator coordinator's scheduled rounds
    /// (if active) AND deregisters from the registry so inbound
    /// routing for the peer ceases. Idempotent: removing a peer that
    /// was never added is a no-op.
    pub async fn remove_peer(
        &self,
        peer_key_id: impl Into<String>,
        kind: EnvelopeKind,
    ) -> Result<(), ReplicationRuntimeError> {
        let peer_key_id = peer_key_id.into();
        let key = (peer_key_id.clone(), kind);

        let was_initiator = {
            let mut active = self.current_initiators.lock().await;
            active.remove(&key)
        };
        if was_initiator {
            self.scheduler_handle
                .remove_initiator(peer_key_id.clone(), kind)
                .await?;
        }
        self.registry.deregister(&peer_key_id, kind).await;
        Ok(())
    }

    /// Diff-and-converge the live Initiator set against `desired` —
    /// CIRISEdge#173, v5.1.0.
    ///
    /// For each `(peer_key_id, kind)` in `desired` not currently
    /// active, calls [`Self::register_initiator_peer`]. For each
    /// currently-active pair NOT in `desired`, calls
    /// [`Self::remove_peer`]. Net effect: after this call returns,
    /// the runtime's Initiator coordinators exactly match `desired`.
    ///
    /// Atomic per individual add/remove only — partial progress is
    /// possible if a mid-call command fails (the failed pair is
    /// reflected by the returned error; pairs processed before the
    /// failure stay applied). Intended driver for CEG-reconcilers:
    /// call on every consent-object delta.
    pub async fn set_peers(
        &self,
        desired: Vec<ReplicationPeer>,
    ) -> Result<(), ReplicationRuntimeError> {
        let desired_set: HashSet<(String, EnvelopeKind)> = desired
            .iter()
            .map(|p| (p.peer_key_id.clone(), p.kind))
            .collect();
        let current_set: HashSet<(String, EnvelopeKind)> = {
            let active = self.current_initiators.lock().await;
            active.iter().cloned().collect()
        };

        // Adds first; the new peers begin active pull before the
        // departing peers' rounds stop — minimizes the convergence
        // window during a swap.
        for (peer_key_id, kind) in desired_set.difference(&current_set) {
            self.register_initiator_peer(peer_key_id.clone(), *kind)
                .await?;
        }
        for (peer_key_id, kind) in current_set.difference(&desired_set) {
            self.remove_peer(peer_key_id.clone(), *kind).await?;
        }
        Ok(())
    }

    /// Build a [`ReplicationCoordinator`] in the requested role with
    /// the runtime's shared transport + bridge-backed provider/applier.
    /// Internal helper for register_peer / register_initiator_peer.
    fn build_coordinator(
        &self,
        peer_key_id: &str,
        kind: EnvelopeKind,
        role: SessionRole,
    ) -> Arc<ReplicationCoordinator> {
        let bridge_dir: Arc<dyn ReplicationDirectory> = Arc::clone(&self.bridge) as _;
        let provider: Arc<dyn StateProvider> =
            Arc::new(DirectoryStateAdapter::new(Arc::clone(&bridge_dir)));
        let applier: Arc<Mutex<dyn StateApplier>> =
            Arc::new(Mutex::new(MutableDirectoryStateAdapter::new(bridge_dir)));
        // CIRISEdge#927 — hot-added Initiators inherit the runtime's proactive-
        // publish posture. Harmless for Responders (they never `start_round`).
        Arc::new(
            ReplicationCoordinator::new(
                Arc::clone(&self.transport),
                peer_key_id.to_string(),
                kind,
                role,
                provider,
                applier,
            )
            .with_proactive_publish(self.proactive_publish),
        )
    }

    /// Shared registry handle. The operator's `Transport::listen`
    /// loop calls [`ReplicationRegistry::route_inbound_bytes`] on
    /// this when bytes arrive from an identified source peer.
    pub fn registry(&self) -> Arc<ReplicationRegistry> {
        Arc::clone(&self.registry)
    }

    /// The runtime's bridge. Useful for telemetry or tests that
    /// want to inspect cache state.
    pub fn bridge(&self) -> Arc<FederationDirectoryReplicationBridge> {
        Arc::clone(&self.bridge)
    }

    /// Returns the active runtime configuration.
    pub fn config(&self) -> &ReplicationRuntimeConfig {
        &self.config
    }

    /// Signal the scheduler to stop and await its run loop to exit
    /// cleanly. Idempotent — repeated calls return immediately
    /// after the first stop completes.
    pub async fn shutdown(&mut self) {
        let _ = self.cancel_tx.send(true);
        if let Some(task) = self.scheduler_task.take() {
            let _ = task.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_persist::store::MemoryBackend;
    use std::sync::Arc;

    use crate::transport::{InboundFrame, TransportError, TransportId, TransportSendOutcome};
    use async_trait::async_trait;

    struct NoopTransport;
    #[async_trait]
    impl Transport for NoopTransport {
        fn id(&self) -> TransportId {
            TransportId::HTTP
        }
        async fn send(
            &self,
            _destination_key_id: &str,
            _envelope_bytes: &[u8],
        ) -> Result<TransportSendOutcome, TransportError> {
            Ok(TransportSendOutcome::Delivered)
        }
        async fn listen(
            &self,
            _sink: tokio::sync::mpsc::Sender<InboundFrame>,
        ) -> Result<(), TransportError> {
            unimplemented!("runtime tests don't drive listen")
        }
    }

    /// Captured `(destination_key_id, bytes)` sends.
    type SentLog = Arc<tokio::sync::Mutex<Vec<(String, Vec<u8>)>>>;

    /// A transport that RECORDS every `send` so a test can assert the responder
    /// actually replied (CIRISEdge#348).
    struct RecordingTransport {
        sent: SentLog,
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
            self.sent
                .lock()
                .await
                .push((destination_key_id.to_string(), envelope_bytes.to_vec()));
            Ok(TransportSendOutcome::Delivered)
        }
        async fn listen(
            &self,
            _sink: tokio::sync::mpsc::Sender<InboundFrame>,
        ) -> Result<(), TransportError> {
            Ok(())
        }
    }

    /// CIRISEdge#348 — a factory-spun **Responder** is DRIVEN: an inbound
    /// round-open routed through the registry causes the responder to process it
    /// and REPLY on the transport — with NO Initiator, NO scheduler entry, and NO
    /// manual drive. Before the fix the #312 factory registered the coordinator
    /// but never ran its `recv_inbound → drive_round_step → send_message` loop, so
    /// `deliver_inbound` enqueued the Summary and it was never processed: the
    /// responder never replied and the initiator timed out forever (the #348
    /// silent stall). This asserts a reply is emitted back to the initiator.
    // multi_thread: `DirectoryStateAdapter` uses `block_in_place` (directory.rs),
    // which requires a multi-threaded runtime — the shape the real edge runtime
    // always has.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn factory_responder_is_driven_and_replies_to_a_round_open() {
        use super::super::protocol::{ReplicationMessage, SummaryMessage};
        use super::super::registry::RouteOutcome;

        let backend = Arc::new(MemoryBackend::new());
        let directory: Arc<dyn FederationDirectory> = backend;
        let sent = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let transport: Arc<dyn Transport> = Arc::new(RecordingTransport {
            sent: Arc::clone(&sent),
        });
        // No Initiator peers — a PURE responder node (the canonical's shape: the
        // agent pulls from it). The ONLY way it serves a round is the #312
        // factory spinning up a Responder AND the #348 drive running it.
        let mut rt = ReplicationRuntime::start(
            directory,
            transport,
            Vec::new(),
            ReplicationRuntimeConfig::default(),
            None,
        )
        .await;

        let round_open =
            super::super::wire_frame::wrap(&ReplicationMessage::Summary(SummaryMessage {
                kind: EnvelopeKind::Key,
                refs: vec![],
            }));
        let outcome = rt
            .registry()
            .route_inbound_bytes("agent-alice", &round_open)
            .await
            .expect("route_inbound_bytes");
        assert!(
            matches!(outcome, RouteOutcome::Routed),
            "the factory must spin up + route to a Responder, got {outcome:?}",
        );

        // The drive is a spawned task; poll (bounded) for the reply.
        let replied = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if !sent.lock().await.is_empty() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            replied.is_ok(),
            "the factory-spun Responder MUST reply to the round-open (CIRISEdge#348) — \
             nothing was sent, so the responder was registered but never driven",
        );
        assert_eq!(
            sent.lock().await[0].0,
            "agent-alice",
            "the reply must go back to the initiating peer",
        );

        rt.shutdown().await;
    }

    /// `start` with an empty peer list builds the runtime + spawns
    /// the scheduler task; `shutdown` exits cleanly.
    #[tokio::test]
    async fn empty_peer_set_starts_and_shuts_down_cleanly() {
        let backend = Arc::new(MemoryBackend::new());
        let directory: Arc<dyn FederationDirectory> = backend;
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let mut rt = ReplicationRuntime::start(
            directory,
            transport,
            Vec::new(),
            ReplicationRuntimeConfig::default(),
            None,
        )
        .await;
        assert!(rt.registry().is_empty().await);
        rt.shutdown().await;
    }

    /// `start` with one Initiator peer registers it + holds the
    /// registry handle the listen loop would use.
    #[tokio::test]
    async fn one_initiator_peer_registered_at_start() {
        let backend = Arc::new(MemoryBackend::new());
        let directory: Arc<dyn FederationDirectory> = backend;
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let peers = vec![ReplicationPeer {
            peer_key_id: "agent-alice".to_string(),
            kind: EnvelopeKind::Key,
        }];
        let mut rt = ReplicationRuntime::start(
            directory,
            transport,
            peers,
            ReplicationRuntimeConfig::default(),
            None,
        )
        .await;
        let registry = rt.registry();
        assert_eq!(registry.len().await, 1);
        let coord = registry.get("agent-alice", EnvelopeKind::Key).await;
        assert!(coord.is_some());
        rt.shutdown().await;
    }

    /// `register_peer` hot-adds an ACTIVE (Initiator) peer — routes AND
    /// drives — and the registry reflects the add immediately (v13.7.0: it
    /// no longer defaults to a passive Responder).
    #[tokio::test]
    async fn register_peer_hot_adds() {
        let backend = Arc::new(MemoryBackend::new());
        let directory: Arc<dyn FederationDirectory> = backend;
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let mut rt = ReplicationRuntime::start(
            directory,
            transport,
            Vec::new(),
            ReplicationRuntimeConfig::default(),
            None,
        )
        .await;
        rt.register_peer("agent-bob", EnvelopeKind::Attestation)
            .await
            .expect("register_peer succeeds on a live runtime");
        assert_eq!(rt.registry().len().await, 1);
        rt.shutdown().await;
    }

    /// CIRISEdge#173 / v5.1.0 — `register_initiator_peer` hot-adds an
    /// Initiator coordinator (not just Responder) and bumps the
    /// registry. Distinct from `register_peer` (Responder-only).
    #[tokio::test]
    async fn register_initiator_peer_hot_adds_initiator_role() {
        let backend = Arc::new(MemoryBackend::new());
        let directory: Arc<dyn FederationDirectory> = backend;
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let mut rt = ReplicationRuntime::start(
            directory,
            transport,
            Vec::new(),
            ReplicationRuntimeConfig::default(),
            None,
        )
        .await;
        rt.register_initiator_peer("agent-carol", EnvelopeKind::Key)
            .await
            .expect("hot-add succeeds while runtime is live");
        assert_eq!(rt.registry().len().await, 1);
        let coord = rt.registry().get("agent-carol", EnvelopeKind::Key).await;
        assert!(coord.is_some());
        assert_eq!(coord.unwrap().role(), SessionRole::Initiator);
        // Idempotent: re-add is a no-op.
        rt.register_initiator_peer("agent-carol", EnvelopeKind::Key)
            .await
            .expect("idempotent re-add");
        assert_eq!(rt.registry().len().await, 1);
        rt.shutdown().await;
    }

    /// CIRISEdge#173 / v5.1.0 — `remove_peer` stops the matching
    /// coordinator's scheduled rounds AND deregisters from the
    /// registry. Idempotent.
    #[tokio::test]
    async fn remove_peer_drops_initiator_and_deregisters() {
        let backend = Arc::new(MemoryBackend::new());
        let directory: Arc<dyn FederationDirectory> = backend;
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let mut rt = ReplicationRuntime::start(
            directory,
            transport,
            Vec::new(),
            ReplicationRuntimeConfig::default(),
            None,
        )
        .await;
        rt.register_initiator_peer("agent-dave", EnvelopeKind::Attestation)
            .await
            .unwrap();
        assert_eq!(rt.registry().len().await, 1);
        rt.remove_peer("agent-dave", EnvelopeKind::Attestation)
            .await
            .expect("hot-remove succeeds while runtime is live");
        assert!(rt.registry().is_empty().await);
        // Idempotent: removing again is a no-op.
        rt.remove_peer("agent-dave", EnvelopeKind::Attestation)
            .await
            .expect("idempotent re-remove");
        rt.shutdown().await;
    }

    /// CIRISEdge#173 / v5.1.0 — `set_peers` converges the live
    /// Initiator set against the desired set. Verifies that adds
    /// and removes both apply in one call, including starting from
    /// a non-empty pre-existing set.
    #[tokio::test]
    async fn set_peers_diff_converges() {
        let backend = Arc::new(MemoryBackend::new());
        let directory: Arc<dyn FederationDirectory> = backend;
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let initial = vec![
            ReplicationPeer {
                peer_key_id: "peer-keep".to_string(),
                kind: EnvelopeKind::Key,
            },
            ReplicationPeer {
                peer_key_id: "peer-drop".to_string(),
                kind: EnvelopeKind::Key,
            },
        ];
        let mut rt = ReplicationRuntime::start(
            directory,
            transport,
            initial,
            ReplicationRuntimeConfig::default(),
            None,
        )
        .await;
        assert_eq!(rt.registry().len().await, 2);

        let desired = vec![
            ReplicationPeer {
                peer_key_id: "peer-keep".to_string(),
                kind: EnvelopeKind::Key,
            },
            ReplicationPeer {
                peer_key_id: "peer-new".to_string(),
                kind: EnvelopeKind::Attestation,
            },
        ];
        rt.set_peers(desired).await.expect("converge succeeds");

        assert_eq!(rt.registry().len().await, 2);
        assert!(rt
            .registry()
            .get("peer-keep", EnvelopeKind::Key)
            .await
            .is_some());
        assert!(rt
            .registry()
            .get("peer-new", EnvelopeKind::Attestation)
            .await
            .is_some());
        assert!(rt
            .registry()
            .get("peer-drop", EnvelopeKind::Key)
            .await
            .is_none());
        rt.shutdown().await;
    }

    /// `shutdown` is idempotent.
    #[tokio::test]
    async fn shutdown_is_idempotent() {
        let backend = Arc::new(MemoryBackend::new());
        let directory: Arc<dyn FederationDirectory> = backend;
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let mut rt = ReplicationRuntime::start(
            directory,
            transport,
            Vec::new(),
            ReplicationRuntimeConfig::default(),
            None,
        )
        .await;
        rt.shutdown().await;
        rt.shutdown().await; // no panic, no hang
    }
}
