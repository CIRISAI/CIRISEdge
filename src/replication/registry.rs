//! `ReplicationRegistry` — application-side dispatch table for the
//! anti-entropy replication module.
//!
//! Closes the 5th of the 5 design questions raised in CIRISEdge#65's
//! pre-FSD discussion: *"the application's `Transport::listen` loop
//! receives bytes; the CRPL wire-frame prefix (#72) identifies
//! replication bytes; but each peer has its own coordinator, so
//! dispatch is `(remote_key_id, kind) → coordinator`."*
//!
//! The registry holds `Arc<ReplicationCoordinator>` indexed by
//! `(peer_key_id, kind)`, and routes inbound bytes via
//! [`Self::route_inbound_bytes`]:
//!
//! - bytes don't carry the CRPL magic → `Ok(false)` (caller routes to
//!   its non-replication dispatch — existing signed-envelope handler,
//!   key_grant handler, etc.)
//! - bytes carry CRPL + a recognized version + a parseable
//!   `ReplicationMessage` → look up the matching coordinator,
//!   `deliver_inbound`, return `Ok(true)`
//! - bytes carry CRPL but the message is malformed or no coordinator
//!   is registered for `(peer_key_id, kind)` → `Err(…)` (caller logs +
//!   drops)
//!
//! ## Why a registry, not a flat list
//!
//! Anti-entropy is per-peer-per-kind. A federation node may anti-
//! entropy Keys with one peer, Attestations with another, all kinds
//! with a third. The registry lets operators register/deregister at
//! the (peer, kind) granularity without churning the scheduler's
//! Initiator set.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use tokio::sync::RwLock;

use super::coordinator::{CoordinatorError, ReplicationCoordinator};
use super::protocol::EnvelopeKind;
use super::wire_frame;

/// CIRISEdge#312 — a factory that builds a `Responder` coordinator for an
/// inbound `(peer_key_id, kind)` that has no registered coordinator. Installed
/// once by [`ReplicationRuntime::start`](crate::replication::ReplicationRuntime)
/// so the registry can auto-serve a pull from a #301 advisory-admitted peer
/// (whom this node does NOT consent-pull from, so it never built an Initiator
/// for them) instead of dropping the round. The records served are public
/// signed envelopes; admission is already bounded by the transport's #301
/// advisory-admit gate, so no additional consent is required.
pub type ResponderFactory =
    Arc<dyn Fn(&str, EnvelopeKind) -> Arc<ReplicationCoordinator> + Send + Sync>;

/// Outcome of [`ReplicationRegistry::route_inbound_bytes`].
#[derive(Debug)]
pub enum RouteOutcome {
    /// Bytes were a valid replication frame and were routed to a
    /// registered coordinator's `deliver_inbound` queue.
    Routed,
    /// Bytes did NOT carry the CRPL magic prefix. The caller's
    /// dispatcher should fall through to its non-replication
    /// handler.
    NotAReplicationFrame,
    /// Bytes carried the CRPL magic but no coordinator is registered
    /// for the inferred `(peer_key_id, kind)`. The caller typically
    /// logs + drops. (`peer_key_id` is supplied by the caller from
    /// the transport's source-identification layer; the wire frame
    /// itself does NOT carry it — it's transport-medium-identified.)
    NoCoordinatorRegistered { kind: EnvelopeKind },
}

/// Errors from registry routing.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("replication protocol error: {0}")]
    Protocol(#[from] CoordinatorError),
    /// The matching coordinator's inbound channel is full — back-
    /// pressure surfaces. The scheduler isn't keeping up; the caller
    /// typically logs and drops.
    #[error("coordinator inbound channel full for peer={peer_key_id} kind={kind:?}")]
    BackPressure {
        peer_key_id: String,
        kind: EnvelopeKind,
    },
}

/// Dispatch table for inbound replication messages, indexed by
/// `(peer_key_id, kind)`.
///
/// Thread-safe. Multiple application tasks can call
/// [`Self::route_inbound_bytes`] concurrently; the underlying
/// `RwLock` is read-mostly (registration is rare; routing is hot-
/// path).
pub struct ReplicationRegistry {
    by_peer_kind: RwLock<HashMap<(String, EnvelopeKind), Arc<ReplicationCoordinator>>>,
    /// CIRISEdge#312 — set-once factory used by [`Self::route_inbound_bytes`]
    /// to auto-register a `Responder` for an admitted-but-uncoordinated peer
    /// (see [`ResponderFactory`]). `None` (never installed) preserves the
    /// pre-#312 behavior: an inbound round with no coordinator returns
    /// [`RouteOutcome::NoCoordinatorRegistered`].
    responder_factory: OnceLock<ResponderFactory>,
}

impl ReplicationRegistry {
    pub fn new() -> Self {
        Self {
            by_peer_kind: RwLock::new(HashMap::new()),
            responder_factory: OnceLock::new(),
        }
    }

    /// CIRISEdge#312 — install the [`ResponderFactory`] (once). Called by
    /// [`ReplicationRuntime::start`](crate::replication::ReplicationRuntime) so
    /// inbound rounds from advisory-admitted peers auto-register a `Responder`
    /// instead of dropping. A second call is a no-op (the first wins).
    pub fn set_responder_factory(&self, factory: ResponderFactory) {
        let _ = self.responder_factory.set(factory);
    }

    /// Get the coordinator for `(peer_key_id, kind)`, or build+register one via
    /// `build` if absent — atomically under the write lock so two concurrent
    /// inbound rounds can't each spawn a duplicate coordinator.
    async fn get_or_register_with<F>(
        &self,
        peer_key_id: &str,
        kind: EnvelopeKind,
        build: F,
    ) -> Arc<ReplicationCoordinator>
    where
        F: FnOnce() -> Arc<ReplicationCoordinator>,
    {
        self.by_peer_kind
            .write()
            .await
            .entry((peer_key_id.to_string(), kind))
            .or_insert_with(build)
            .clone()
    }

    /// Register a coordinator for `(peer_key_id, kind)`. Replaces
    /// any prior coordinator at that key (the application's
    /// hot-add / hot-replace surface).
    pub async fn register(
        &self,
        peer_key_id: impl Into<String>,
        kind: EnvelopeKind,
        coord: Arc<ReplicationCoordinator>,
    ) {
        let key = (peer_key_id.into(), kind);
        self.by_peer_kind.write().await.insert(key, coord);
    }

    /// Remove the coordinator at `(peer_key_id, kind)`. Returns
    /// the removed coordinator if one was registered; `None` if
    /// no registration existed.
    pub async fn deregister(
        &self,
        peer_key_id: &str,
        kind: EnvelopeKind,
    ) -> Option<Arc<ReplicationCoordinator>> {
        self.by_peer_kind
            .write()
            .await
            .remove(&(peer_key_id.to_string(), kind))
    }

    /// Lookup the coordinator for `(peer_key_id, kind)`. Returns
    /// `None` if no registration exists. Useful for telemetry +
    /// hot-add idempotency checks.
    pub async fn get(
        &self,
        peer_key_id: &str,
        kind: EnvelopeKind,
    ) -> Option<Arc<ReplicationCoordinator>> {
        self.by_peer_kind
            .read()
            .await
            .get(&(peer_key_id.to_string(), kind))
            .cloned()
    }

    /// Number of registered `(peer_key_id, kind)` pairs.
    pub async fn len(&self) -> usize {
        self.by_peer_kind.read().await.len()
    }

    /// Whether the registry is empty (no registrations).
    pub async fn is_empty(&self) -> bool {
        self.by_peer_kind.read().await.is_empty()
    }

    /// All registered keys, snapshot at call time. Useful for
    /// shutdown loops + telemetry.
    pub async fn registered_keys(&self) -> Vec<(String, EnvelopeKind)> {
        self.by_peer_kind.read().await.keys().cloned().collect()
    }

    /// Route inbound bytes from the application's `Transport::listen`
    /// loop. The transport layer supplies the source-identified
    /// `peer_key_id` (Reticulum announces carry the source destination
    /// hash; HTTPS mTLS carries the CN of the client cert verified
    /// against `federation_keys`; etc.).
    ///
    /// Returns:
    /// - `Ok(RouteOutcome::Routed)` — bytes parsed as a replication
    ///   frame for the inferred kind; coordinator's `deliver_inbound`
    ///   queue accepted them.
    /// - `Ok(RouteOutcome::NotAReplicationFrame)` — no CRPL magic.
    ///   Caller falls through to non-replication dispatch.
    /// - `Ok(RouteOutcome::NoCoordinatorRegistered { kind })` —
    ///   CRPL magic + parseable, but no `(peer_key_id, kind)`
    ///   registration. Caller logs + drops.
    /// - `Err(RegistryError::Protocol(_))` — CRPL magic present but
    ///   body malformed or unknown version. Caller logs + drops.
    /// - `Err(RegistryError::BackPressure { … })` — matching
    ///   coordinator's inbound channel is full. Caller logs + drops;
    ///   the next round picks up.
    pub async fn route_inbound_bytes(
        &self,
        peer_key_id: &str,
        bytes: &[u8],
    ) -> Result<RouteOutcome, RegistryError> {
        let msg = match wire_frame::try_unwrap(bytes) {
            Ok(Some(m)) => m,
            Ok(None) => return Ok(RouteOutcome::NotAReplicationFrame),
            Err(e) => return Err(RegistryError::Protocol(e.into())),
        };
        // ReplicationMessage carries a `kind` field on every variant
        // — that's our dispatch key alongside peer_key_id.
        let kind = match &msg {
            super::protocol::ReplicationMessage::Summary(m) => m.kind,
            super::protocol::ReplicationMessage::Diff(m) => m.kind,
            super::protocol::ReplicationMessage::Fetch(m) => m.kind,
            super::protocol::ReplicationMessage::Deliver(m) => m.kind,
        };
        // CIRISEdge#312 — if no coordinator exists for this (peer, kind), this
        // node doesn't consent-pull from the peer (so no Initiator was built),
        // but the peer is an admitted #301 advisory source pulling PUBLIC signed
        // envelopes. Auto-register a `Responder` and serve the round instead of
        // dropping it — the fix that lets an advisory-admitted agent get its
        // IdentityOccurrence round answered (so it can resolve this node's KEX
        // pubkeys and seal). With no factory installed, fall back to the
        // pre-#312 drop.
        let coord = if let Some(coord) = self.get(peer_key_id, kind).await {
            coord
        } else {
            let Some(factory) = self.responder_factory.get() else {
                return Ok(RouteOutcome::NoCoordinatorRegistered { kind });
            };
            let factory = Arc::clone(factory);
            self.get_or_register_with(peer_key_id, kind, || factory(peer_key_id, kind))
                .await
        };
        coord
            .deliver_inbound(msg)
            .map_err(|_| RegistryError::BackPressure {
                peer_key_id: peer_key_id.to_string(),
                kind,
            })?;
        Ok(RouteOutcome::Routed)
    }
}

impl Default for ReplicationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replication::directory::MockReplicationDirectory;
    use crate::replication::directory::{DirectoryStateAdapter, MutableDirectoryStateAdapter};
    use crate::replication::protocol::{ReplicationMessage, SummaryMessage};
    use crate::replication::session::SessionRole;
    use crate::replication::summary::{StateApplier, StateProvider};
    use crate::replication::wire_frame::wrap;
    use crate::transport::{
        InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
    };
    use async_trait::async_trait;
    use tokio::sync::Mutex;

    // ── Test transport (no-op) ──────────────────────────────────────

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
            unimplemented!("registry tests don't drive listen")
        }
    }

    // ── Test coordinator builder ────────────────────────────────────

    fn make_coord(peer: &str, kind: EnvelopeKind) -> Arc<ReplicationCoordinator> {
        let mock = Arc::new(MockReplicationDirectory::new());
        let dir: Arc<dyn crate::replication::directory::ReplicationDirectory> =
            Arc::clone(&mock) as _;
        let provider: Arc<dyn StateProvider> =
            Arc::new(DirectoryStateAdapter::new(Arc::clone(&dir)));
        let applier: Arc<Mutex<dyn StateApplier>> =
            Arc::new(Mutex::new(MutableDirectoryStateAdapter::new(dir)));
        Arc::new(ReplicationCoordinator::new(
            Arc::new(NoopTransport),
            peer,
            kind,
            SessionRole::Initiator,
            provider,
            applier,
        ))
    }

    // ── Smoke ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn empty_registry_routes_inbound_bytes_as_not_a_replication_frame() {
        let registry = ReplicationRegistry::new();
        assert!(registry.is_empty().await);
        // Plain JSON without CRPL magic → NotAReplicationFrame.
        let r = registry
            .route_inbound_bytes("any_peer", b"{\"hello\":\"world\"}")
            .await
            .expect("not an error");
        assert!(matches!(r, RouteOutcome::NotAReplicationFrame));
    }

    #[tokio::test]
    async fn register_then_lookup_round_trips() {
        let registry = ReplicationRegistry::new();
        let coord = make_coord("bob", EnvelopeKind::Key);
        registry
            .register("bob".to_string(), EnvelopeKind::Key, Arc::clone(&coord))
            .await;
        assert_eq!(registry.len().await, 1);
        let found = registry.get("bob", EnvelopeKind::Key).await;
        assert!(found.is_some());
        let keys = registry.registered_keys().await;
        assert_eq!(keys, vec![("bob".to_string(), EnvelopeKind::Key)]);
    }

    #[tokio::test]
    async fn deregister_removes_entry() {
        let registry = ReplicationRegistry::new();
        let coord = make_coord("alice", EnvelopeKind::Attestation);
        registry
            .register("alice", EnvelopeKind::Attestation, coord)
            .await;
        assert_eq!(registry.len().await, 1);
        let removed = registry
            .deregister("alice", EnvelopeKind::Attestation)
            .await;
        assert!(removed.is_some());
        assert!(registry.is_empty().await);
        // Idempotent deregister returns None on second call.
        let second = registry
            .deregister("alice", EnvelopeKind::Attestation)
            .await;
        assert!(second.is_none());
    }

    // ── Routing ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn route_inbound_bytes_routes_to_registered_coordinator() {
        let registry = ReplicationRegistry::new();
        let coord = make_coord("carol", EnvelopeKind::Key);
        registry
            .register("carol", EnvelopeKind::Key, Arc::clone(&coord))
            .await;

        // Build a Summary message wrapped in the CRPL frame.
        let msg = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Key,
            refs: vec![],
        });
        let framed = wrap(&msg);

        let r = registry
            .route_inbound_bytes("carol", &framed)
            .await
            .expect("routed");
        assert!(matches!(r, RouteOutcome::Routed));
    }

    #[tokio::test]
    async fn route_to_unregistered_peer_returns_no_coordinator() {
        let registry = ReplicationRegistry::new();
        // Don't register anything; build a valid frame anyway.
        let msg = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Attestation,
            refs: vec![],
        });
        let framed = wrap(&msg);
        let r = registry
            .route_inbound_bytes("ghost", &framed)
            .await
            .expect("ok");
        match r {
            RouteOutcome::NoCoordinatorRegistered { kind } => {
                assert_eq!(kind, EnvelopeKind::Attestation);
            }
            o => panic!("expected NoCoordinatorRegistered, got {o:?}"),
        }
    }

    /// CIRISEdge#312 — with a responder factory installed, an inbound round
    /// from an UNregistered peer auto-registers a coordinator and routes,
    /// instead of dropping at `NoCoordinatorRegistered`. This is the fix that
    /// lets a #301 advisory-admitted peer's pull get served.
    #[tokio::test]
    async fn route_to_unregistered_peer_auto_registers_with_factory() {
        let registry = ReplicationRegistry::new();
        registry.set_responder_factory(Arc::new(|peer: &str, kind| make_coord(peer, kind)));

        // Nothing pre-registered for "agent".
        assert!(registry
            .get("agent", EnvelopeKind::IdentityOccurrence)
            .await
            .is_none());

        let msg = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::IdentityOccurrence,
            refs: vec![],
        });
        let framed = wrap(&msg);
        let r = registry
            .route_inbound_bytes("agent", &framed)
            .await
            .expect("ok");
        assert!(
            matches!(r, RouteOutcome::Routed),
            "factory auto-registers + routes instead of dropping"
        );
        // The coordinator now persists for subsequent rounds.
        assert!(
            registry
                .get("agent", EnvelopeKind::IdentityOccurrence)
                .await
                .is_some(),
            "auto-registered coordinator is retained"
        );
    }

    #[tokio::test]
    async fn route_with_correct_peer_wrong_kind_returns_no_coordinator() {
        let registry = ReplicationRegistry::new();
        let coord = make_coord("dave", EnvelopeKind::Key);
        registry.register("dave", EnvelopeKind::Key, coord).await;
        // Frame for a DIFFERENT kind than what's registered.
        let msg = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Revocation,
            refs: vec![],
        });
        let framed = wrap(&msg);
        let r = registry
            .route_inbound_bytes("dave", &framed)
            .await
            .expect("ok");
        assert!(matches!(
            r,
            RouteOutcome::NoCoordinatorRegistered {
                kind: EnvelopeKind::Revocation
            }
        ));
    }

    #[tokio::test]
    async fn route_malformed_replication_frame_is_protocol_error() {
        let registry = ReplicationRegistry::new();
        // CRPL magic + version byte + garbage body.
        let mut bytes = wire_frame::REPLICATION_FRAME_MAGIC.to_vec();
        bytes.push(wire_frame::WIRE_PROTOCOL_VERSION);
        bytes.extend_from_slice(b"{not valid json");
        let r = registry.route_inbound_bytes("anyone", &bytes).await;
        assert!(matches!(r, Err(RegistryError::Protocol(_))));
    }

    #[tokio::test]
    async fn route_unknown_version_is_protocol_error() {
        let registry = ReplicationRegistry::new();
        // Forge a v3 frame (v1 and v2 are both recognized as of
        // CIRISEdge v2.0.0; v3 is reserved for a future cut).
        let msg = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Key,
            refs: vec![],
        });
        let v3 = wire_frame::wrap_at_version(&msg, 0x03);
        let r = registry.route_inbound_bytes("anyone", &v3).await;
        // UnknownVersion surfaces via the Protocol error.
        assert!(matches!(r, Err(RegistryError::Protocol(_))));
    }

    /// Filling the coordinator's inbound channel surfaces as
    /// BackPressure. The coordinator's channel capacity is 8 (see
    /// `ReplicationCoordinator::INBOUND_CHANNEL_CAPACITY`); send 9
    /// messages without anything draining it.
    #[tokio::test]
    async fn route_into_full_channel_surfaces_back_pressure() {
        let registry = ReplicationRegistry::new();
        let coord = make_coord("eve", EnvelopeKind::Key);
        registry.register("eve", EnvelopeKind::Key, coord).await;
        let msg = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Key,
            refs: vec![],
        });
        let framed = wrap(&msg);
        // Fill the capacity-8 channel.
        for _ in 0..ReplicationCoordinator::INBOUND_CHANNEL_CAPACITY {
            let r = registry.route_inbound_bytes("eve", &framed).await;
            assert!(matches!(r, Ok(RouteOutcome::Routed)));
        }
        // The 9th surfaces BackPressure.
        let r = registry.route_inbound_bytes("eve", &framed).await;
        match r {
            Err(RegistryError::BackPressure {
                peer_key_id,
                kind: EnvelopeKind::Key,
            }) => assert_eq!(peer_key_id, "eve"),
            o => panic!("expected BackPressure, got {o:?}"),
        }
    }
}
