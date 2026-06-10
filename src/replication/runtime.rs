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

use std::sync::Arc;

use ciris_persist::federation::FederationDirectory;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::bridge::{BridgeConfig, CohortProvider, FederationDirectoryReplicationBridge};
use super::coordinator::ReplicationCoordinator;
use super::directory::{DirectoryStateAdapter, MutableDirectoryStateAdapter, ReplicationDirectory};
use super::protocol::EnvelopeKind;
use super::registry::ReplicationRegistry;
use super::scheduler::{ReplicationScheduler, SchedulerConfig};
use super::session::SessionRole;
use super::summary::{StateApplier, StateProvider};
use crate::transport::Transport;

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

        let bridge = Arc::new(FederationDirectoryReplicationBridge::with_config(
            Arc::clone(&directory),
            cohort,
            config.bridge,
        ));

        let registry = Arc::new(ReplicationRegistry::new());

        // Build coordinators + scheduler. Coordinators share one
        // bridge instance; provider + applier are split-shape per
        // session.rs's borrow story (the bridge is the same object
        // backing both).
        let mut scheduler = ReplicationScheduler::new(config.scheduler);
        let coords: Vec<Arc<ReplicationCoordinator>> = peers
            .iter()
            .map(|peer| {
                let bridge_dir: Arc<dyn ReplicationDirectory> = Arc::clone(&bridge) as _;
                let provider: Arc<dyn StateProvider> =
                    Arc::new(DirectoryStateAdapter::new(Arc::clone(&bridge_dir)));
                let applier: Arc<tokio::sync::Mutex<dyn StateApplier>> = Arc::new(
                    tokio::sync::Mutex::new(MutableDirectoryStateAdapter::new(bridge_dir)),
                );
                Arc::new(ReplicationCoordinator::new(
                    Arc::clone(&transport),
                    &peer.peer_key_id,
                    peer.kind,
                    SessionRole::Initiator,
                    provider,
                    applier,
                ))
            })
            .collect();

        for (peer, coord) in peers.iter().zip(coords.iter()) {
            scheduler.add_initiator(Arc::clone(coord));
            // Register so the operator's listen loop can route
            // inbound replies (the Initiator side receives Summary
            // / Diff / Deliver back from the peer). Inline await
            // because `start` is async.
            registry
                .register(peer.peer_key_id.clone(), peer.kind, Arc::clone(coord))
                .await;
        }

        let (cancel_tx, cancel_rx) = watch::channel(false);
        let scheduler_task = tokio::spawn(async move {
            scheduler.run_until_cancelled(cancel_rx).await;
        });

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
        }
    }

    /// Hot-add a new `(peer_key_id, kind)` Initiator. Constructs a
    /// coordinator, registers it, **but does NOT add to the
    /// scheduler's Initiator set** for v1 — that requires the
    /// scheduler to expose dynamic adds (not in the v1 API).
    ///
    /// For now hot-add lets the Responder-side route inbound for
    /// the new peer; the Initiator side would need a runtime
    /// restart to fire periodic rounds. This is acceptable for the
    /// hot-add-is-uncommon v1 posture; a v1.x patch will extend
    /// the scheduler with a dynamic-add API.
    pub async fn register_peer(&self, peer_key_id: impl Into<String>, kind: EnvelopeKind) {
        let peer_key_id = peer_key_id.into();
        let bridge_dir: Arc<dyn ReplicationDirectory> = Arc::clone(&self.bridge) as _;
        let provider: Arc<dyn StateProvider> =
            Arc::new(DirectoryStateAdapter::new(Arc::clone(&bridge_dir)));
        let applier: Arc<tokio::sync::Mutex<dyn StateApplier>> = Arc::new(tokio::sync::Mutex::new(
            MutableDirectoryStateAdapter::new(bridge_dir),
        ));
        let coord = Arc::new(ReplicationCoordinator::new(
            Arc::clone(&self.transport),
            peer_key_id.clone(),
            kind,
            SessionRole::Responder, // hot-add defaults to Responder; cf. doc above
            provider,
            applier,
        ));
        self.registry.register(peer_key_id, kind, coord).await;
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
        )
        .await;
        let registry = rt.registry();
        assert_eq!(registry.len().await, 1);
        let coord = registry.get("agent-alice", EnvelopeKind::Key).await;
        assert!(coord.is_some());
        rt.shutdown().await;
    }

    /// `register_peer` hot-adds and the registry reflects the
    /// add immediately.
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
        )
        .await;
        rt.register_peer("agent-bob", EnvelopeKind::Attestation)
            .await;
        assert_eq!(rt.registry().len().await, 1);
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
        )
        .await;
        rt.shutdown().await;
        rt.shutdown().await; // no panic, no hang
    }
}
