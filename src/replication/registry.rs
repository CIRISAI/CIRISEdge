//! `ReplicationRegistry` — application-side dispatch table for the
//! anti-entropy replication module.
//!
//! Closes the 5th of the 5 design questions raised in CIRISEdge#65's
//! pre-FSD discussion: *"the application's `Transport::listen` loop
//! receives bytes; the CRPL wire-frame prefix (#72) identifies
//! replication bytes; but each peer has its own coordinator, so
//! dispatch is `(remote_key_id, kind) → coordinator`."* — and, since
//! CIRISEdge#634, the answer has a third coordinate: the ROLE.
//!
//! ## Two tables, never one (CIRISEdge#634)
//!
//! The registry holds `Arc<ReplicationCoordinator>` in TWO tables of the
//! same key type and different meaning:
//!
//! - `responders[(peer, kind)]` — built by the [`ResponderFactory`] on the
//!   first frame of a peer's round; driven by their own task; answer the
//!   peer's rounds.
//! - `initiators[(peer, kind)]` — registered by the runtime; driven by the
//!   scheduler; open OUR rounds toward the peer.
//!
//! Before #634 there was one map keyed `(peer, kind)`: an initiator we ran
//! toward P/K occupied the slot, every inbound frame from P/K was delivered
//! into its channel (drained only while a round was being driven), and the
//! responder factory never ran. The peer's round-open sat or dropped, and
//! the `BackPressure` log blamed "a responder reply". See
//! `FSD/REPLICATION_ROUND_CORRELATION.md` §1.
//!
//! [`Self::route_inbound_bytes`] picks the table from the frame's v3 round
//! metadata (`FSD` §4):
//!
//! - `FROM_RESPONDER = 0` (the peer opened / is driving a round) or a
//!   LEGACY v1/v2 frame (a pre-v26 initiator) → `responders`, built if
//!   absent → [`RouteOutcome::RoutedToResponder`].
//! - `FROM_RESPONDER = 1` (a reply to a round WE opened) → the initiator
//!   for `(peer, kind)`, which accepts it only into the round it names →
//!   [`RouteOutcome::RoutedToInitiator`], else [`RouteOutcome::ReplyDropped`]
//!   with the reason. A reply can never build or reach a responder — that
//!   is the echo-loop guard.
//! - bytes without the CRPL magic → [`RouteOutcome::NotAReplicationFrame`]
//!   (caller falls through to envelope dispatch).
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

use super::coordinator::{CoordinatorError, ReplicationCoordinator, ReplyRefusal};
use super::protocol::EnvelopeKind;
use super::session::SessionRole;
use super::wire_frame::{self, RoundSide};

/// CIRISEdge#312 — a factory that builds a `Responder` coordinator for an
/// inbound `(peer_key_id, kind)` that has no registered responder. Installed
/// once by [`ReplicationRuntime::start`](crate::replication::ReplicationRuntime)
/// so the registry can auto-serve a pull from a #301 advisory-admitted peer
/// (whom this node does NOT consent-pull from, so it never built an Initiator
/// for them) instead of dropping the round.
///
/// CIRISEdge#426 — scope of the "no additional consent" claim: it holds for the
/// SERVE direction ONLY. The records this Responder *serves* are public signed
/// envelopes whose outbound consent is already gated (resolve_attestation_recipient
/// / peer_has_serve_capability / recipient_capability_withholds), so serving them
/// to a #301-admitted peer needs no further consent. It says NOTHING about what
/// this Responder *accepts*: the same coordinator also carries the RECEIVE path,
/// and an admitted peer's writes are bounded by persist v22's put-gates + AV-76
/// per-peer quota (the actual Sybil-write defense), with the authenticated
/// `source_peer` now threaded to the apply layer (#426) so a per-peer receive
/// decision is expressible rather than structurally impossible.
pub type ResponderFactory =
    Arc<dyn Fn(&str, EnvelopeKind) -> Arc<ReplicationCoordinator> + Send + Sync>;

/// Why a reply frame (`FROM_RESPONDER = 1`) was dropped instead of routed
/// (CIRISEdge#634 §4). Every variant is counted in
/// `EdgeMetrics.replication_reply_dropped_total` and logged with the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyDropReason {
    /// We run no initiator toward this `(peer, kind)` — a reply to a round we
    /// never opened.
    NoInitiator,
    /// Our initiator is idle: the round this answers completed or timed out
    /// before the reply arrived.
    NoRoundInFlight,
    /// A round is in flight but the reply names another one — a late reply
    /// to a superseded round.
    RoundMismatch { expected: u64, got: u64 },
}

impl ReplyDropReason {
    /// Stable label for logs and the metrics reason tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoInitiator => "no_initiator",
            Self::NoRoundInFlight => "no_round_in_flight",
            Self::RoundMismatch { .. } => "round_mismatch",
        }
    }
}

/// Outcome of [`ReplicationRegistry::route_inbound_bytes`].
#[derive(Debug)]
pub enum RouteOutcome {
    /// An initiator-marked or LEGACY frame, delivered to the responder for
    /// `(peer, kind)`. `built` is true when the factory made it just now.
    RoutedToResponder { kind: EnvelopeKind, built: bool },
    /// A reply frame, delivered into our initiator's inbox for the round it
    /// names.
    RoutedToInitiator { kind: EnvelopeKind, round: u64 },
    /// A reply frame that answers no round we are driving — dropped here,
    /// visibly, never queued (CIRISEdge#634 §4).
    ReplyDropped {
        kind: EnvelopeKind,
        round: u64,
        reason: ReplyDropReason,
    },
    /// Bytes did NOT carry the CRPL magic prefix. The caller's
    /// dispatcher should fall through to its non-replication
    /// handler.
    NotAReplicationFrame,
    /// Bytes carried the CRPL magic, no responder exists for the inferred
    /// `(peer_key_id, kind)`, and no factory is installed. The caller
    /// typically logs + drops. (`peer_key_id` is supplied by the caller from
    /// the transport's source-identification layer; the wire frame itself
    /// does NOT carry it — it's transport-medium-identified.)
    NoCoordinatorRegistered { kind: EnvelopeKind },
    /// CIRISEdge#621 — `peer_key_id` is THIS node's own key. No coordinator is
    /// looked up and no responder is built: a responder keyed on our own id
    /// replies to itself (CIRISServer#607 — 0 rounds served on the canonical).
    /// Only reachable when [`ReplicationRegistry::set_local_key_id`] was called;
    /// a registry that does not know its own key cannot refuse by it.
    RefusedSelf,
}

impl RouteOutcome {
    /// Whether the frame was consumed by the replication layer (routed or
    /// deliberately dropped) — as opposed to "not ours" / "nowhere to go".
    #[must_use]
    pub fn is_consumed(&self) -> bool {
        matches!(
            self,
            Self::RoutedToResponder { .. }
                | Self::RoutedToInitiator { .. }
                | Self::ReplyDropped { .. }
        )
    }
}

/// Errors from registry routing.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("replication protocol error: {0}")]
    Protocol(#[from] CoordinatorError),
    /// The matching coordinator's inbox is full — back-pressure surfaces.
    /// `role` says WHOSE inbox: a responder's means its driver is stalled on
    /// a reply send (#373); an initiator's means replies outran the round
    /// being driven. The caller typically logs and drops.
    #[error("{role:?} inbox full for peer={peer_key_id} kind={kind:?}")]
    BackPressure {
        peer_key_id: String,
        kind: EnvelopeKind,
        role: SessionRole,
    },
}

/// Dispatch table for inbound replication messages, indexed by
/// `(peer_key_id, kind)` in two role-typed tables (CIRISEdge#634).
///
/// Thread-safe. Multiple application tasks can call
/// [`Self::route_inbound_bytes`] concurrently; the underlying
/// `RwLock`s are read-mostly (registration is rare; routing is hot-
/// path).
pub struct ReplicationRegistry {
    /// Responder coordinators — one per `(peer, kind)` a peer has opened a
    /// round on. Built by the factory, driven by their own task.
    responders: RwLock<HashMap<(String, EnvelopeKind), Arc<ReplicationCoordinator>>>,
    /// Initiator coordinators — one per `(peer, kind)` this node runs rounds
    /// toward. Registered by the runtime, driven by the scheduler. Consulted
    /// ONLY for reply frames.
    initiators: RwLock<HashMap<(String, EnvelopeKind), Arc<ReplicationCoordinator>>>,
    /// CIRISEdge#312 — set-once factory used by [`Self::route_inbound_bytes`]
    /// to auto-register a `Responder` for an admitted-but-uncoordinated peer
    /// (see [`ResponderFactory`]). `None` (never installed) preserves the
    /// pre-#312 behavior: an inbound round with no responder returns
    /// [`RouteOutcome::NoCoordinatorRegistered`].
    responder_factory: OnceLock<ResponderFactory>,
    /// CIRISEdge#621 — this node's own key id, once known. The last line of
    /// defence against a responder for ourselves: the transport refuses the
    /// attribution first (`LinkAttribution::ResolvedToSelf`), but this door is
    /// public and an operator's own listener may hand it anything.
    local_key_id: OnceLock<String>,
}

impl ReplicationRegistry {
    /// An empty registry with no factory and no known local key.
    #[must_use]
    pub fn new() -> Self {
        Self {
            responders: RwLock::new(HashMap::new()),
            initiators: RwLock::new(HashMap::new()),
            responder_factory: OnceLock::new(),
            local_key_id: OnceLock::new(),
        }
    }

    /// CIRISEdge#621 — a registry that knows this node's own key id and will
    /// refuse to route a frame attributed to it.
    #[must_use]
    pub fn with_local_key_id(local_key_id: Option<String>) -> Self {
        let r = Self::new();
        if let Some(k) = local_key_id {
            r.set_local_key_id(k);
        }
        r
    }

    /// CIRISEdge#621 — build from the runtime config so the registry and the
    /// runtime agree on the local key without a second plumbing path.
    #[must_use]
    pub fn for_config(config: &super::runtime::ReplicationRuntimeConfig) -> Self {
        Self::with_local_key_id(config.local_key_id.clone())
    }

    /// CIRISEdge#621 — install this node's own key id. Set-once; a second call
    /// with a different id is logged and ignored (the first binding stands).
    pub fn set_local_key_id(&self, key_id: impl Into<String>) {
        let key_id = key_id.into();
        if let Err(unset) = self.local_key_id.set(key_id) {
            if self.local_key_id.get().map(String::as_str) != Some(unset.as_str()) {
                tracing::warn!(
                    held = ?self.local_key_id.get(),
                    offered = %unset,
                    "ReplicationRegistry::set_local_key_id called twice with different ids; \
                     keeping the first (CIRISEdge#621)"
                );
            }
        }
    }

    /// CIRISEdge#621 — this node's own key id, if installed.
    #[must_use]
    pub fn local_key_id(&self) -> Option<&str> {
        self.local_key_id.get().map(String::as_str)
    }

    /// CIRISEdge#312 — install the responder factory (set-once; a second call
    /// is ignored).
    pub fn set_responder_factory(&self, factory: ResponderFactory) {
        let _ = self.responder_factory.set(factory);
    }

    /// Register a coordinator into the table its ROLE selects
    /// (CIRISEdge#634). Replaces any prior entry for `(peer, kind)` in that
    /// table; the other table is untouched, so an initiator and a responder
    /// for the same pair coexist — that is the point.
    pub async fn register(
        &self,
        peer_key_id: impl Into<String>,
        kind: EnvelopeKind,
        coord: Arc<ReplicationCoordinator>,
    ) {
        let key = (peer_key_id.into(), kind);
        match coord.role() {
            SessionRole::Initiator => {
                self.initiators.write().await.insert(key, coord);
            }
            SessionRole::Responder => {
                self.responders.write().await.insert(key, coord);
            }
        }
    }

    /// Remove BOTH roles' coordinators for `(peer, kind)`. Returns what was
    /// removed as `(initiator, responder)`.
    pub async fn deregister(
        &self,
        peer_key_id: &str,
        kind: EnvelopeKind,
    ) -> (
        Option<Arc<ReplicationCoordinator>>,
        Option<Arc<ReplicationCoordinator>>,
    ) {
        let key = (peer_key_id.to_string(), kind);
        let initiator = self.initiators.write().await.remove(&key);
        let responder = self.responders.write().await.remove(&key);
        (initiator, responder)
    }

    /// The coordinator for `(peer, kind)` in the given ROLE.
    pub async fn get(
        &self,
        peer_key_id: &str,
        kind: EnvelopeKind,
        role: SessionRole,
    ) -> Option<Arc<ReplicationCoordinator>> {
        let key = (peer_key_id.to_string(), kind);
        match role {
            SessionRole::Initiator => self.initiators.read().await.get(&key).cloned(),
            SessionRole::Responder => self.responders.read().await.get(&key).cloned(),
        }
    }

    /// Our initiator toward `(peer, kind)`, if the runtime registered one.
    pub async fn get_initiator(
        &self,
        peer_key_id: &str,
        kind: EnvelopeKind,
    ) -> Option<Arc<ReplicationCoordinator>> {
        self.get(peer_key_id, kind, SessionRole::Initiator).await
    }

    /// The responder answering `(peer, kind)`, if one has been built.
    pub async fn get_responder(
        &self,
        peer_key_id: &str,
        kind: EnvelopeKind,
    ) -> Option<Arc<ReplicationCoordinator>> {
        self.get(peer_key_id, kind, SessionRole::Responder).await
    }

    /// Total registered coordinators across both roles.
    pub async fn len(&self) -> usize {
        self.initiators.read().await.len() + self.responders.read().await.len()
    }

    /// Whether no coordinator of either role is registered.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Every registered `(peer, kind, role)`.
    pub async fn registered_keys(&self) -> Vec<(String, EnvelopeKind, SessionRole)> {
        let mut out: Vec<(String, EnvelopeKind, SessionRole)> = self
            .initiators
            .read()
            .await
            .keys()
            .map(|(p, k)| (p.clone(), *k, SessionRole::Initiator))
            .collect();
        out.extend(
            self.responders
                .read()
                .await
                .keys()
                .map(|(p, k)| (p.clone(), *k, SessionRole::Responder)),
        );
        out
    }

    /// The responder for `(peer, kind)`, building it with the factory when
    /// absent. `None` when there is neither a responder nor a factory.
    async fn responder_or_build(
        &self,
        peer_key_id: &str,
        kind: EnvelopeKind,
    ) -> Option<(Arc<ReplicationCoordinator>, bool)> {
        if let Some(coord) = self.get_responder(peer_key_id, kind).await {
            return Some((coord, false));
        }
        let factory = Arc::clone(self.responder_factory.get()?);
        let mut table = self.responders.write().await;
        let key = (peer_key_id.to_string(), kind);
        if let Some(existing) = table.get(&key) {
            return Some((Arc::clone(existing), false));
        }
        let coord = factory(peer_key_id, kind);
        debug_assert_eq!(
            coord.role(),
            SessionRole::Responder,
            "the responder factory must build a Responder"
        );
        table.insert(key, Arc::clone(&coord));
        Some((coord, true))
    }

    /// Route inbound bytes from `peer_key_id` per
    /// `FSD/REPLICATION_ROUND_CORRELATION.md` §4 (CIRISEdge#634).
    ///
    /// # Errors
    ///
    /// - [`RegistryError::Protocol`] — CRPL magic present but the frame is
    ///   malformed or its version unknown.
    /// - [`RegistryError::BackPressure`] — the selected coordinator's inbox
    ///   is full; `role` names whose.
    pub async fn route_inbound_bytes(
        &self,
        peer_key_id: &str,
        bytes: &[u8],
    ) -> Result<RouteOutcome, RegistryError> {
        let framed = match wire_frame::try_unwrap_framed(bytes) {
            Ok(Some(f)) => f,
            Ok(None) => return Ok(RouteOutcome::NotAReplicationFrame),
            Err(e) => return Err(RegistryError::Protocol(e.into())),
        };
        if self.local_key_id() == Some(peer_key_id) {
            tracing::warn!(
                peer = %peer_key_id,
                "CRPL frame REFUSED — attributed to THIS node's own key; no responder is \
                 built for ourselves (CIRISEdge#621 / CIRISServer#607)"
            );
            return Ok(RouteOutcome::RefusedSelf);
        }
        let kind = framed.msg.kind();
        let meta = framed.meta;
        match meta.map(|m| m.from) {
            // A reply to a round WE opened: the initiator, and only into the
            // round it names. Never a responder (echo-loop guard, FSD §4).
            Some(RoundSide::Responder) => {
                let round = meta.map_or(0, |m| m.round);
                let Some(initiator) = self.get_initiator(peer_key_id, kind).await else {
                    return Ok(RouteOutcome::ReplyDropped {
                        kind,
                        round,
                        reason: ReplyDropReason::NoInitiator,
                    });
                };
                match initiator.deliver_reply(framed.msg, round) {
                    Ok(()) => Ok(RouteOutcome::RoutedToInitiator { kind, round }),
                    Err(ReplyRefusal::BackPressure) => Err(RegistryError::BackPressure {
                        peer_key_id: peer_key_id.to_string(),
                        kind,
                        role: SessionRole::Initiator,
                    }),
                    Err(ReplyRefusal::NoRoundInFlight | ReplyRefusal::WrongRole) => {
                        Ok(RouteOutcome::ReplyDropped {
                            kind,
                            round,
                            reason: ReplyDropReason::NoRoundInFlight,
                        })
                    }
                    Err(ReplyRefusal::RoundMismatch { expected, got }) => {
                        Ok(RouteOutcome::ReplyDropped {
                            kind,
                            round,
                            reason: ReplyDropReason::RoundMismatch { expected, got },
                        })
                    }
                }
            }
            // The peer's round (v3 initiator-marked) or a pre-v26 peer's
            // legacy round: the responder, built on first contact. The
            // initiators table is not consulted — there is no slot to fuse.
            Some(RoundSide::Initiator) | None => {
                let Some((responder, built)) = self.responder_or_build(peer_key_id, kind).await
                else {
                    return Ok(RouteOutcome::NoCoordinatorRegistered { kind });
                };
                responder
                    .deliver_inbound_framed(framed.msg, meta)
                    .map_err(|_| RegistryError::BackPressure {
                        peer_key_id: peer_key_id.to_string(),
                        kind,
                        role: SessionRole::Responder,
                    })?;
                Ok(RouteOutcome::RoutedToResponder { kind, built })
            }
        }
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
        make_coord_with_role(peer, kind, SessionRole::Initiator)
    }

    fn make_responder(peer: &str, kind: EnvelopeKind) -> Arc<ReplicationCoordinator> {
        make_coord_with_role(peer, kind, SessionRole::Responder)
    }

    fn make_coord_with_role(
        peer: &str,
        kind: EnvelopeKind,
        role: SessionRole,
    ) -> Arc<ReplicationCoordinator> {
        let mock = Arc::new(MockReplicationDirectory::new());
        let dir: Arc<dyn crate::replication::directory::ReplicationDirectory> =
            Arc::clone(&mock) as _;
        let provider: Arc<dyn StateProvider> =
            Arc::new(DirectoryStateAdapter::new(Arc::clone(&dir)));
        // CIRISEdge#370 — no mutex: the applier is shared `&self`.
        let applier: Arc<dyn StateApplier> = Arc::new(MutableDirectoryStateAdapter::new(dir));
        Arc::new(ReplicationCoordinator::new(
            Arc::new(NoopTransport),
            peer,
            kind,
            role,
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
        let found = registry.get_initiator("bob", EnvelopeKind::Key).await;
        assert!(found.is_some());
        assert!(
            registry
                .get_responder("bob", EnvelopeKind::Key)
                .await
                .is_none(),
            "an initiator registration never occupies the responder table (CIRISEdge#634)"
        );
        let keys = registry.registered_keys().await;
        assert_eq!(
            keys,
            vec![("bob".to_string(), EnvelopeKind::Key, SessionRole::Initiator)]
        );
    }

    #[tokio::test]
    async fn deregister_removes_entry() {
        let registry = ReplicationRegistry::new();
        let coord = make_coord("alice", EnvelopeKind::Attestation);
        registry
            .register("alice", EnvelopeKind::Attestation, coord)
            .await;
        assert_eq!(registry.len().await, 1);
        let (initiator, responder) = registry
            .deregister("alice", EnvelopeKind::Attestation)
            .await;
        assert!(initiator.is_some());
        assert!(responder.is_none());
        assert!(registry.is_empty().await);
        // Idempotent deregister returns (None, None) on second call.
        let second = registry
            .deregister("alice", EnvelopeKind::Attestation)
            .await;
        assert!(second.0.is_none() && second.1.is_none());
    }

    // ── Routing ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn route_inbound_bytes_routes_to_registered_coordinator() {
        let registry = ReplicationRegistry::new();
        // A legacy round-open is the PEER's round: it reaches a RESPONDER.
        let coord = make_responder("carol", EnvelopeKind::Key);
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
        assert!(
            matches!(r, RouteOutcome::RoutedToResponder { built: false, .. }),
            "got {r:?}"
        );
        assert_eq!(coord.inbound_depth(), 1);
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
        registry.set_responder_factory(Arc::new(|peer: &str, kind| make_responder(peer, kind)));

        // Nothing pre-registered for "agent".
        assert!(registry
            .get_responder("agent", EnvelopeKind::IdentityOccurrence)
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
            matches!(r, RouteOutcome::RoutedToResponder { built: true, .. }),
            "factory auto-registers + routes instead of dropping"
        );
        // The coordinator now persists for subsequent rounds.
        assert!(
            registry
                .get_responder("agent", EnvelopeKind::IdentityOccurrence)
                .await
                .is_some(),
            "auto-registered coordinator is retained"
        );
    }

    #[tokio::test]
    async fn route_with_correct_peer_wrong_kind_returns_no_coordinator() {
        let registry = ReplicationRegistry::new();
        let coord = make_responder("dave", EnvelopeKind::Key);
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
        let coord = make_responder("eve", EnvelopeKind::Key);
        registry.register("eve", EnvelopeKind::Key, coord).await;
        let msg = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Key,
            refs: vec![],
        });
        let framed = wrap(&msg);
        // Fill the capacity-8 channel.
        for _ in 0..ReplicationCoordinator::INBOUND_CHANNEL_CAPACITY {
            let r = registry.route_inbound_bytes("eve", &framed).await;
            assert!(matches!(r, Ok(RouteOutcome::RoutedToResponder { .. })));
        }
        // The 9th surfaces BackPressure — and names WHOSE inbox (#634).
        let r = registry.route_inbound_bytes("eve", &framed).await;
        match r {
            Err(RegistryError::BackPressure {
                peer_key_id,
                kind: EnvelopeKind::Key,
                role: SessionRole::Responder,
            }) => assert_eq!(peer_key_id, "eve"),
            o => panic!("expected responder BackPressure, got {o:?}"),
        }
    }

    // ── CIRISEdge#634 — round routing: the (peer, kind, ROLE) contract ──────
    //
    // Every row of `FSD/REPLICATION_ROUND_CORRELATION.md` §4 / §8 has a test
    // here. The transport RECORDS what a responder sends so "the responder
    // drives the round" is asserted on the wire, not inferred.
    mod round_routing_634 {
        use super::*;
        use crate::replication::coordinator::{DriveStep, ReplyRefusal};
        use crate::replication::wire_frame::{wrap_v3, RoundSide};
        use std::sync::Mutex as StdMutex;

        struct RecordingTransport {
            sent: Arc<StdMutex<Vec<Vec<u8>>>>,
        }
        #[async_trait]
        impl Transport for RecordingTransport {
            fn id(&self) -> TransportId {
                TransportId::HTTP
            }
            async fn send(
                &self,
                _destination_key_id: &str,
                envelope_bytes: &[u8],
            ) -> Result<TransportSendOutcome, TransportError> {
                self.sent
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(envelope_bytes.to_vec());
                Ok(TransportSendOutcome::Delivered)
            }
            async fn listen(
                &self,
                _sink: tokio::sync::mpsc::Sender<InboundFrame>,
            ) -> Result<(), TransportError> {
                unimplemented!()
            }
        }

        fn coord_on(
            transport: Arc<dyn Transport>,
            peer: &str,
            kind: EnvelopeKind,
            role: SessionRole,
        ) -> Arc<ReplicationCoordinator> {
            let mock = Arc::new(MockReplicationDirectory::new());
            let dir: Arc<dyn crate::replication::directory::ReplicationDirectory> =
                Arc::clone(&mock) as _;
            let provider: Arc<dyn StateProvider> =
                Arc::new(DirectoryStateAdapter::new(Arc::clone(&dir)));
            let applier: Arc<dyn StateApplier> = Arc::new(MutableDirectoryStateAdapter::new(dir));
            Arc::new(ReplicationCoordinator::new(
                transport, peer, kind, role, provider, applier,
            ))
        }

        type Wire = Arc<StdMutex<Vec<Vec<u8>>>>;
        type Built = Arc<std::sync::atomic::AtomicUsize>;

        /// A registry with an initiator toward `(P, K)` and a factory that
        /// builds — and DRIVES, like the runtime's — a responder on demand.
        /// Returns the registry, the initiator, the wire recorder, and the
        /// count of responders the factory has built.
        fn fixture() -> (
            ReplicationRegistry,
            Arc<ReplicationCoordinator>,
            Wire,
            Built,
        ) {
            let sent = Arc::new(StdMutex::new(Vec::new()));
            let transport: Arc<dyn Transport> = Arc::new(RecordingTransport {
                sent: Arc::clone(&sent),
            });
            let registry = ReplicationRegistry::new();
            let built = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let factory_transport = Arc::clone(&transport);
            let factory_built = Arc::clone(&built);
            registry.set_responder_factory(Arc::new(move |peer: &str, kind| {
                factory_built.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let coord = coord_on(
                    Arc::clone(&factory_transport),
                    peer,
                    kind,
                    SessionRole::Responder,
                );
                // The runtime's `spawn_responder_drive`, minimally: drain,
                // step, send.
                let drive = Arc::clone(&coord);
                tokio::spawn(async move {
                    while let Some(inbound) = drive.recv_inbound_framed().await {
                        if let Ok(DriveStep::SendThenWait(msgs)) =
                            drive.drive_round_step_framed(Some(inbound)).await
                        {
                            for m in &msgs {
                                let _ = drive.send_message(m).await;
                            }
                        }
                    }
                });
                coord
            }));
            let initiator = coord_on(
                transport,
                "peer-p",
                EnvelopeKind::Community,
                SessionRole::Initiator,
            );
            (registry, initiator, sent, built)
        }

        fn summary() -> ReplicationMessage {
            ReplicationMessage::Summary(SummaryMessage {
                kind: EnvelopeKind::Community,
                refs: vec![],
            })
        }

        async fn wait_for_sends(sent: &Wire, n: usize) -> Vec<Vec<u8>> {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    let snapshot = sent
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone();
                    if snapshot.len() >= n {
                        return snapshot;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the responder must reply within 5s")
        }

        /// The #634 acceptance test as filed: register an Initiator for (P, K);
        /// deliver an inbound Summary for (P, K); a Responder is created and
        /// drives the round, and the initiator's inbox depth stays 0.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn an_inbound_round_open_never_queues_into_an_initiator() {
            let (registry, initiator, sent, built) = fixture();
            registry
                .register("peer-p", EnvelopeKind::Community, Arc::clone(&initiator))
                .await;
            assert!(!initiator.is_round_in_flight(), "idle between rounds");

            // A LEGACY round-open — what a pre-v26 peer sends, and exactly the
            // frame that queued into the initiator's channel before #634.
            let r = registry
                .route_inbound_bytes("peer-p", &wrap(&summary()))
                .await
                .expect("route");
            assert!(
                matches!(
                    r,
                    RouteOutcome::RoutedToResponder {
                        kind: EnvelopeKind::Community,
                        built: true
                    }
                ),
                "got {r:?}"
            );
            assert_eq!(built.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert_eq!(initiator.inbound_depth(), 0, "the initiator never saw it");

            // The responder DRIVES the round: Summary_R + Diff_R on the wire,
            // as legacy frames because the round-open was legacy.
            let frames = wait_for_sends(&sent, 2).await;
            let decoded: Vec<_> = frames
                .iter()
                .map(|f| wire_frame::try_unwrap_framed(f).unwrap().unwrap())
                .collect();
            assert!(matches!(decoded[0].msg, ReplicationMessage::Summary(_)));
            assert!(matches!(decoded[1].msg, ReplicationMessage::Diff(_)));
            assert!(
                decoded.iter().all(|f| f.meta.is_none()),
                "legacy in, legacy out"
            );
        }

        /// A v3 round-open from the peer while OUR round toward it is in
        /// flight — the simultaneous-rounds case the direction bit exists
        /// for. It reaches the responder, not the initiator's live inbox.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_v3_round_open_routes_to_the_responder_even_while_our_round_is_in_flight() {
            let (registry, initiator, sent, built) = fixture();
            registry
                .register("peer-p", EnvelopeKind::Community, Arc::clone(&initiator))
                .await;
            let ours = initiator.begin_round().await;
            assert_ne!(ours, 0);

            let theirs = 0x5151_5151_5151_5151;
            let r = registry
                .route_inbound_bytes("peer-p", &wrap_v3(&summary(), RoundSide::Initiator, theirs))
                .await
                .expect("route");
            assert!(
                matches!(r, RouteOutcome::RoutedToResponder { built: true, .. }),
                "got {r:?}"
            );
            assert_eq!(built.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert_eq!(initiator.inbound_depth(), 0);

            // The responder echoes THEIR round on its replies.
            let frames = wait_for_sends(&sent, 2).await;
            for f in &frames {
                let reply = wire_frame::try_unwrap_framed(f).unwrap().unwrap();
                let meta = reply.meta.expect("v3 reply");
                assert_eq!(meta.from, RoundSide::Responder);
                assert_eq!(meta.round, theirs);
            }
            initiator.end_round().await;
        }

        /// A reply that answers no round we are driving is dropped VISIBLY —
        /// and builds no responder (the echo-loop guard).
        #[tokio::test]
        async fn a_stale_reply_is_dropped_visibly_and_builds_no_responder() {
            let (registry, initiator, _sent, built) = fixture();
            registry
                .register("peer-p", EnvelopeKind::Community, Arc::clone(&initiator))
                .await;
            let r = registry
                .route_inbound_bytes("peer-p", &wrap_v3(&summary(), RoundSide::Responder, 77))
                .await
                .expect("route");
            assert!(
                matches!(
                    r,
                    RouteOutcome::ReplyDropped {
                        kind: EnvelopeKind::Community,
                        round: 77,
                        reason: ReplyDropReason::NoRoundInFlight
                    }
                ),
                "got {r:?}"
            );
            assert_eq!(built.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert_eq!(initiator.inbound_depth(), 0);
            assert!(registry
                .get_responder("peer-p", EnvelopeKind::Community)
                .await
                .is_none());
        }

        /// A reply naming the driven round lands in that round's inbox.
        #[tokio::test]
        async fn a_reply_to_the_driven_round_reaches_its_inbox() {
            let (registry, initiator, _sent, _built) = fixture();
            registry
                .register("peer-p", EnvelopeKind::Community, Arc::clone(&initiator))
                .await;
            let round = initiator.begin_round().await;
            let r = registry
                .route_inbound_bytes("peer-p", &wrap_v3(&summary(), RoundSide::Responder, round))
                .await
                .expect("route");
            assert!(
                matches!(r, RouteOutcome::RoutedToInitiator { kind: EnvelopeKind::Community, round: got } if got == round),
                "got {r:?}"
            );
            assert_eq!(initiator.inbound_depth(), 1);
            let msg = initiator.recv_inbound().await.expect("the driver reads it");
            assert_eq!(msg, summary());
            initiator.end_round().await;
            assert_eq!(
                initiator.inbound_depth(),
                0,
                "the inbox dies with the round"
            );
        }

        /// A reply naming a different round than the one in flight is a late
        /// reply to a superseded round: dropped with both ids named.
        #[tokio::test]
        async fn a_reply_to_a_superseded_round_is_dropped() {
            let (registry, initiator, _sent, _built) = fixture();
            registry
                .register("peer-p", EnvelopeKind::Community, Arc::clone(&initiator))
                .await;
            let round = initiator.begin_round().await;
            let r = registry
                .route_inbound_bytes(
                    "peer-p",
                    &wrap_v3(&summary(), RoundSide::Responder, round ^ 1),
                )
                .await
                .expect("route");
            match r {
                RouteOutcome::ReplyDropped {
                    reason: ReplyDropReason::RoundMismatch { expected, got },
                    ..
                } => {
                    assert_eq!(expected, round);
                    assert_eq!(got, round ^ 1);
                }
                o => panic!("expected RoundMismatch, got {o:?}"),
            }
            assert_eq!(initiator.inbound_depth(), 0);
            initiator.end_round().await;
        }

        /// A reply frame for a pair we run NO initiator toward can never build
        /// a responder: `NoInitiator`, factory untouched.
        #[tokio::test]
        async fn a_reply_frame_can_never_build_a_responder() {
            let (registry, _initiator, _sent, built) = fixture();
            let r = registry
                .route_inbound_bytes("stranger", &wrap_v3(&summary(), RoundSide::Responder, 9))
                .await
                .expect("route");
            assert!(
                matches!(
                    r,
                    RouteOutcome::ReplyDropped {
                        reason: ReplyDropReason::NoInitiator,
                        ..
                    }
                ),
                "got {r:?}"
            );
            assert_eq!(built.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert!(registry.is_empty().await);
        }

        /// The on-demand path: a Pull sent outside a driven round mints a pull
        /// round, and the reply naming it lands in the on-demand inbox.
        #[tokio::test]
        async fn a_pull_reply_routes_by_the_pull_round() {
            let (registry, initiator, sent, _built) = fixture();
            registry
                .register("peer-p", EnvelopeKind::Community, Arc::clone(&initiator))
                .await;
            assert_eq!(initiator.pull_round(), 0);
            initiator.start_pull("subject-x").await.expect("send");
            let pull = initiator.pull_round();
            assert_ne!(pull, 0);
            let on_wire = wire_frame::try_unwrap_framed(&sent.lock().unwrap()[0])
                .unwrap()
                .unwrap();
            assert_eq!(
                on_wire.meta,
                Some(wire_frame::RoundMeta {
                    from: RoundSide::Initiator,
                    round: pull
                })
            );
            let r = registry
                .route_inbound_bytes("peer-p", &wrap_v3(&summary(), RoundSide::Responder, pull))
                .await
                .expect("route");
            assert!(
                matches!(r, RouteOutcome::RoutedToInitiator { .. }),
                "got {r:?}"
            );
            assert_eq!(initiator.inbound_depth(), 1);
            // No driven round in flight: `recv_inbound` still yields it.
            assert_eq!(initiator.recv_inbound().await, Some(summary()));
        }

        /// `deliver_reply` on a responder is a `WrongRole` refusal — the type
        /// system's half of "a reply never reaches a responder".
        #[tokio::test]
        async fn deliver_reply_refuses_a_responder() {
            let responder = coord_on(
                Arc::new(NoopTransport),
                "p",
                EnvelopeKind::Key,
                SessionRole::Responder,
            );
            assert_eq!(
                responder.deliver_reply(summary(), 1),
                Err(ReplyRefusal::WrongRole)
            );
        }
    }
}
