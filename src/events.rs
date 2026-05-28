//! Network event bus (CIRISEdge#34).
//!
//! Mission: replace polling-style status surfaces (`get_interface_stats`
//! et al.) with normalized async iterators that consumers (CIRISAgent
//! UI, lens, registry) subscribe to. Reticulum itself has no internal
//! event bus — every UI today polls; PyEdge owns the normalized
//! stream.
//! ([`MISSION.md`](../../MISSION.md) §2 `events/`.)
//!
//! # Implementation pattern
//!
//! `Edge` owns one [`tokio::sync::broadcast::Sender`] per event
//! category. Every emission point (announce handler, transport state
//! machine, link state machine, path table mutator, resource
//! announcer) calls `sender.send(event)`. Pymethods construct a fresh
//! [`tokio::sync::broadcast::Receiver`] per subscription, wrap it in
//! a `BroadcastStream` adapter, and expose it to Python via
//! `pyo3-async-runtimes` as an `AsyncIterator`.
//!
//! Bounded channels (default capacity `DEFAULT_EVENT_CHANNEL_CAPACITY`):
//! drop oldest on overflow rather than block the emitter. Slow
//! consumers see gaps but never starve the substrate. The drop is
//! observable: a `Lagged` sentinel surfaces via the typed event
//! discriminator so the consumer can render a "missed N events" UI
//! affordance.
//!
//! # v0.11.0 wiring scope
//!
//! - **WIRED**: `subscribe_announces` (PeerResolver cold-start path
//!   emits an `AnnounceEvent` from `handle_event::AnnounceReceived`),
//!   `subscribe_interface_events` (transport listen start emits
//!   `transport_up`; listen-loop exit emits `transport_down`).
//! - **STUBBED**: `subscribe_link_events`, `subscribe_path_events`,
//!   `subscribe_resource_events`. The Reticulum state machine hooks
//!   for these (link establish/close, path discover/lose, resource
//!   announce) land in v0.12+ Transports. The channels exist; they
//!   simply never emit until those hooks land.
//! - `subscribe_all` is the union stream; it re-broadcasts every
//!   category's emissions into a single channel.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Default capacity for each per-category broadcast channel. 1024 is
/// the value pinned in CIRISEdge#34 — a balance between memory
/// footprint and the burst pattern an announce-storm at federation
/// join time produces.
pub const DEFAULT_EVENT_CHANNEL_CAPACITY: usize = 1024;

/// Severity classification for [`NetworkEvent`]. Mirrors the catalog in
/// CIRISEdge#34's issue body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventSeverity {
    Info,
    Warning,
    Error,
}

/// Network event discriminator. Mirrors the catalog in CIRISEdge#34's
/// issue body — extend in-place when v0.12+ wires the remaining
/// channels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    AnnounceReceived,
    AnnounceSent,
    PathDiscovered,
    PathLost,
    LinkEstablished,
    LinkDropped,
    TransportUp,
    TransportDown,
    KeyRotated,
    SignatureFailure,
    PolicyBlock,
    /// Slow-consumer marker — the receiver lagged by N events. Emitted
    /// by the subscription-side adapter, not by the substrate.
    Lagged,
}

/// Per-category broadcast payload. The category-specific fields
/// (`aspect`, `identity_hash`, `link_id`, etc.) ride on this union;
/// PyEdge's per-category subscribe pymethods filter on `kind` and
/// project the union into the typed pyclass the consumer sees.
///
/// We keep one shape (rather than per-category enums) so the union
/// `subscribe_all` channel doesn't need a heterogeneous adapter.
/// The category-specific `Option` fields are `None` when not applicable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub at: DateTime<Utc>,
    pub kind: EventKind,
    pub message: String,
    pub peer_key_id: Option<String>,
    pub transport_id: Option<String>,
    pub severity: EventSeverity,
    /// Reticulum aspect string (`AnnounceEvent` only).
    pub aspect: Option<String>,
    /// 16-byte identity hash (`AnnounceEvent` only).
    pub identity_hash: Option<Vec<u8>>,
    /// Reticulum announce app-data (`AnnounceEvent` only). The
    /// federation-key-signed attestation bytes; opaque to consumers
    /// that don't parse them.
    pub app_data: Option<Vec<u8>>,
    /// Received signal strength (`AnnounceEvent` over LoRa).
    pub rssi_dbm: Option<f64>,
    /// Signal-to-noise ratio (`AnnounceEvent` over LoRa).
    pub snr_db: Option<f64>,
    /// 16-byte link id (`LinkEvent` only).
    pub link_id: Option<Vec<u8>>,
    /// Lag count when `kind == Lagged`.
    pub lagged_count: Option<u64>,
}

impl NetworkEvent {
    /// Construct a minimal interface event. Convenience for the
    /// transport-up / transport-down emissions in
    /// [`Transport::listen`] wiring.
    #[must_use]
    pub fn interface(kind: EventKind, transport_id: &str, message: impl Into<String>) -> Self {
        Self {
            at: Utc::now(),
            kind,
            message: message.into(),
            peer_key_id: None,
            transport_id: Some(transport_id.to_string()),
            severity: EventSeverity::Info,
            aspect: None,
            identity_hash: None,
            app_data: None,
            rssi_dbm: None,
            snr_db: None,
            link_id: None,
            lagged_count: None,
        }
    }

    /// Construct an announce event. Used by the PeerResolver cold-start
    /// path on every announce arrival (rooted OR rejected — consumers
    /// filter by `severity`).
    #[must_use]
    pub fn announce(
        peer_key_id: Option<String>,
        identity_hash: Vec<u8>,
        app_data: Vec<u8>,
        severity: EventSeverity,
        message: impl Into<String>,
    ) -> Self {
        Self {
            at: Utc::now(),
            kind: EventKind::AnnounceReceived,
            message: message.into(),
            peer_key_id,
            transport_id: Some("reticulum-rs".to_string()),
            severity,
            aspect: None,
            identity_hash: Some(identity_hash),
            app_data: Some(app_data),
            rssi_dbm: None,
            snr_db: None,
            link_id: None,
            lagged_count: None,
        }
    }

    /// Construct a lagged sentinel. Emitted by the per-subscription
    /// adapter when a `BroadcastStream::poll_next` returns
    /// `BroadcastStreamRecvError::Lagged(n)` — the consumer missed `n`
    /// events because it didn't drain fast enough.
    #[must_use]
    pub fn lagged(count: u64) -> Self {
        Self {
            at: Utc::now(),
            kind: EventKind::Lagged,
            message: format!("subscriber lagged by {count} events"),
            peer_key_id: None,
            transport_id: None,
            severity: EventSeverity::Warning,
            aspect: None,
            identity_hash: None,
            app_data: None,
            rssi_dbm: None,
            snr_db: None,
            link_id: None,
            lagged_count: Some(count),
        }
    }
}

/// Per-category broadcast bus owned by [`Edge`]. Five categories
/// matching the CIRISEdge#34 surface plus a union channel that
/// fans-in all emissions so `subscribe_all` is a single receiver.
///
/// Consumers acquire a fresh `Receiver` per subscription via
/// [`Self::subscribe_announces`] et al. Senders are interior — every
/// emission point on `Edge` / `ReticulumTransport` calls
/// [`Self::emit_announce`] / [`Self::emit_interface`] / etc.
///
/// Construction is cheap: five `broadcast::channel` builds. Default
/// capacity per channel: [`DEFAULT_EVENT_CHANNEL_CAPACITY`].
#[derive(Debug)]
pub struct EventBus {
    announces: broadcast::Sender<NetworkEvent>,
    links: broadcast::Sender<NetworkEvent>,
    interfaces: broadcast::Sender<NetworkEvent>,
    paths: broadcast::Sender<NetworkEvent>,
    resources: broadcast::Sender<NetworkEvent>,
    /// Fan-in union — every per-category emission ALSO publishes here
    /// so `subscribe_all` is a single bounded channel rather than a
    /// 5-way `select!` adapter on the consumer side.
    all: broadcast::Sender<NetworkEvent>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_EVENT_CHANNEL_CAPACITY)
    }
}

impl EventBus {
    /// Build a bus with the given per-channel capacity. The same
    /// capacity is applied to all six channels; production deployments
    /// use [`DEFAULT_EVENT_CHANNEL_CAPACITY`].
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let (announces, _) = broadcast::channel(capacity);
        let (links, _) = broadcast::channel(capacity);
        let (interfaces, _) = broadcast::channel(capacity);
        let (paths, _) = broadcast::channel(capacity);
        let (resources, _) = broadcast::channel(capacity);
        let (all, _) = broadcast::channel(capacity);
        Self {
            announces,
            links,
            interfaces,
            paths,
            resources,
            all,
        }
    }

    /// Emit an announce event. Routed to the announce channel and the
    /// union channel. `send` errors (no subscribers) are intentionally
    /// swallowed — the event bus is fire-and-forget at the emission
    /// site; subscriber counts are observability noise.
    pub fn emit_announce(&self, event: NetworkEvent) {
        let _ = self.announces.send(event.clone());
        let _ = self.all.send(event);
    }

    /// Emit an interface event (transport_up / transport_down).
    pub fn emit_interface(&self, event: NetworkEvent) {
        let _ = self.interfaces.send(event.clone());
        let _ = self.all.send(event);
    }

    /// Emit a link event. Stubbed in v0.11.0 — the Reticulum
    /// link-state-machine hooks land in v0.12+.
    pub fn emit_link(&self, event: NetworkEvent) {
        let _ = self.links.send(event.clone());
        let _ = self.all.send(event);
    }

    /// Emit a path event. Stubbed in v0.11.0.
    pub fn emit_path(&self, event: NetworkEvent) {
        let _ = self.paths.send(event.clone());
        let _ = self.all.send(event);
    }

    /// Emit a resource event. Stubbed in v0.11.0.
    pub fn emit_resource(&self, event: NetworkEvent) {
        let _ = self.resources.send(event.clone());
        let _ = self.all.send(event);
    }

    /// Subscribe to announce events. Returns a fresh `Receiver`; the
    /// caller wraps it in `BroadcastStream` or polls directly.
    #[must_use]
    pub fn subscribe_announces(&self) -> broadcast::Receiver<NetworkEvent> {
        self.announces.subscribe()
    }

    /// Subscribe to link events (stubbed channel — no emissions in
    /// v0.11.0).
    #[must_use]
    pub fn subscribe_links(&self) -> broadcast::Receiver<NetworkEvent> {
        self.links.subscribe()
    }

    /// Subscribe to interface events. Transport startup / shutdown
    /// emit here.
    #[must_use]
    pub fn subscribe_interfaces(&self) -> broadcast::Receiver<NetworkEvent> {
        self.interfaces.subscribe()
    }

    /// Subscribe to path events (stubbed channel — no emissions in
    /// v0.11.0).
    #[must_use]
    pub fn subscribe_paths(&self) -> broadcast::Receiver<NetworkEvent> {
        self.paths.subscribe()
    }

    /// Subscribe to resource events (stubbed channel — no emissions in
    /// v0.11.0).
    #[must_use]
    pub fn subscribe_resources(&self) -> broadcast::Receiver<NetworkEvent> {
        self.resources.subscribe()
    }

    /// Subscribe to the union stream — every category's emissions
    /// fan-in here in emission order (within each channel).
    #[must_use]
    pub fn subscribe_all(&self) -> broadcast::Receiver<NetworkEvent> {
        self.all.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn emit_announce_reaches_subscribers() {
        let bus = EventBus::default();
        let mut rx = bus.subscribe_announces();
        let mut rx_all = bus.subscribe_all();
        bus.emit_announce(NetworkEvent::announce(
            Some("peer-1".to_string()),
            vec![0xAB; 16],
            vec![],
            EventSeverity::Info,
            "test",
        ));
        let got = timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("did not lag")
            .expect("did not close");
        assert_eq!(got.kind, EventKind::AnnounceReceived);
        assert_eq!(got.peer_key_id.as_deref(), Some("peer-1"));
        let got_all = timeout(Duration::from_millis(100), rx_all.recv())
            .await
            .expect("did not lag")
            .expect("did not close");
        assert_eq!(got_all.kind, EventKind::AnnounceReceived);
    }

    #[tokio::test]
    async fn emit_with_no_subscribers_is_noop() {
        let bus = EventBus::default();
        // No subscribers — must not panic.
        bus.emit_announce(NetworkEvent::announce(
            None,
            vec![0; 16],
            vec![],
            EventSeverity::Info,
            "drop on the floor",
        ));
    }

    #[tokio::test]
    async fn emit_interface_routes_to_interface_channel() {
        let bus = EventBus::default();
        let mut rx = bus.subscribe_interfaces();
        bus.emit_interface(NetworkEvent::interface(
            EventKind::TransportUp,
            "reticulum-rs",
            "listening",
        ));
        let got = rx.recv().await.expect("receive");
        assert_eq!(got.kind, EventKind::TransportUp);
        assert_eq!(got.transport_id.as_deref(), Some("reticulum-rs"));
    }
}
