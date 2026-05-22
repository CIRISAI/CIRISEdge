//! Reticulum-native transport (OQ-07 first impl).
//!
//! Canonical wire per `MISSION.md` §2 — Reticulum is the default
//! medium; HTTP ([`super::http`]) is the documented fallback. Backed
//! by Leviculum (`reticulum-core` + `reticulum-std`, workspace
//! v0.6.3, AGPL-3.0) — consumed from the `CIRISAI/leviculum` fork,
//! which strips upstream's force-removed integ-harness submodules so
//! the repo resolves as a cargo git dep (see `Cargo.toml`). Beechat's
//! reticulum-rs was spiked and rejected — Leviculum is the canonical
//! stack.
//!
//! ## Identity model (AV-17)
//!
//! The Reticulum identity is a **dedicated transport-tier identity**,
//! NOT the federation signing key. Reticulum identities are dual-key
//! (x25519 + ed25519); the destination hash is `hash(x25519 ‖
//! ed25519)`. Edge's local Reticulum identity is generated on first
//! run and persisted (chmod 600) to a config-supplied path, then
//! reloaded for a stable address across restarts. The federation
//! Ed25519 seed — which lives behind `Arc<dyn HardwareSigner>` and
//! never enters edge process memory — is **never** fed to Leviculum.
//! AV-17 holds because the two identities are separate. Envelope
//! authenticity is already end-to-end via the Ed25519 + ML-DSA
//! envelope signatures `verify.rs` checks; Reticulum link encryption
//! is transport hardening only.
//!
//! ## Peer resolution
//!
//! [`Transport::send`] receives a `destination_key_id: &str`. The
//! transport resolves it to a Reticulum destination in two ways:
//!
//! 1. **Directory-seeded** — an injected [`PeerResolver`] (typically a
//!    `FederationDirectory` lookup) yields the peer's dual-key public
//!    bytes → `Identity::from_public_keys`.
//! 2. **Announce-driven** — peers announce their `key_id` as the
//!    announce app-data. The listener populates an in-memory
//!    `key_id → destination` map from received announces.
//!
//! If the peer is not yet resolvable, `send` returns
//! [`TransportError::Unreachable`] and edge's durable dispatcher
//! retries (FSD/EDGE_OUTBOUND_QUEUE.md §4).
//!
//! ## Wire framing
//!
//! Envelopes routinely exceed Reticulum's single-packet MDU (~464
//! bytes — an Ed25519 + ML-DSA envelope alone is larger), so each
//! envelope is shipped as a Reticulum **Resource** over an
//! established Link. The receiver auto-accepts inbound resources
//! (`ResourceStrategy::AcceptAll`) and surfaces the reassembled bytes
//! as a `NodeEvent::ResourceCompleted`, which the listener turns into
//! an [`InboundFrame`].

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::{mpsc, Mutex};

use reticulum_core::link::LinkId;
use reticulum_core::resource::ResourceStrategy;
use reticulum_core::{Destination, DestinationHash, DestinationType, Direction, Identity};
use reticulum_std::driver::{ReticulumNode, ReticulumNodeBuilder};
use reticulum_std::NodeEvent;

use super::{InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome};

/// Maximum envelope body size accepted on send. Mirrors AV-13
/// (`MAX_BODY_BYTES = 8 MiB`); oversized payloads reject before any
/// link is established.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Reticulum app-name for edge's federation destination. The full
/// destination name is `app_name` + aspects; both halves of a peering
/// must agree on this string for announce-driven discovery to align.
const EDGE_APP_NAME: &str = "ciris";

/// Reticulum destination aspect for the federation envelope endpoint.
const EDGE_APP_ASPECT: &str = "edge";

/// How long [`Transport::send`] waits for a link to establish before
/// giving up and surfacing [`TransportError::Timeout`].
const LINK_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(30);

/// How long [`Transport::send`] waits for a resource transfer to
/// complete after the link is up.
const RESOURCE_TRANSFER_TIMEOUT: Duration = Duration::from_secs(120);

// ─── Peer resolution ────────────────────────────────────────────────

/// Out-of-band resolver from a federation `key_id` to a peer's
/// Reticulum dual-key public bytes (64 bytes: x25519 ‖ ed25519).
///
/// Implemented by a `FederationDirectory`-backed adapter when the
/// directory carries Reticulum transport keys. When no resolver is
/// injected, the transport relies solely on announce-driven
/// discovery. The returned bytes feed `Identity::from_public_keys`.
pub trait PeerResolver: Send + Sync + 'static {
    /// Return the peer's 64-byte Reticulum public key (x25519 ‖
    /// ed25519), or `None` if the directory has no transport key for
    /// `key_id`.
    fn resolve(&self, destination_key_id: &str) -> Option<[u8; 64]>;
}

/// A resolved peer — its Reticulum destination hash plus the ed25519
/// verifying key required by `ReticulumNode::connect`.
#[derive(Debug, Clone, Copy)]
struct ResolvedPeer {
    dest_hash: DestinationHash,
    signing_key: [u8; 32],
}

// ─── Configuration ──────────────────────────────────────────────────

/// Reticulum transport configuration. Deliberately small — the MVP
/// surface is a TCP listen addr, bootstrap peer addr(s), the
/// transport-identity file path, and the announce interval.
#[derive(Debug, Clone)]
pub struct ReticulumTransportConfig {
    /// TCP address the node listens on for inbound Reticulum links.
    pub listen_addr: SocketAddr,
    /// Bootstrap peer TCP addresses dialled as Reticulum TCP clients
    /// on startup. Empty is valid (listen-only / announce-discovered).
    pub bootstrap_peers: Vec<SocketAddr>,
    /// Path to the persisted transport-tier Reticulum identity (64
    /// raw private-key bytes). Generated + chmod-600 on first run,
    /// reloaded thereafter for a stable destination across restarts.
    /// This is NOT the federation signing key (AV-17).
    pub identity_path: PathBuf,
    /// Interval between re-announces of edge's own destination. The
    /// destination is also announced once on startup.
    pub announce_interval: Duration,
    /// Edge's own federation `key_id`, advertised as the announce
    /// app-data so peers can map `key_id → destination`.
    pub local_key_id: String,
}

impl ReticulumTransportConfig {
    /// Construct a config with the mandatory fields and sensible
    /// defaults (`0.0.0.0:4242` listen addr, no bootstrap peers,
    /// 5-minute announce interval).
    #[must_use]
    pub fn new(identity_path: PathBuf, local_key_id: impl Into<String>) -> Self {
        Self {
            listen_addr: "0.0.0.0:4242".parse().expect("static addr parses"),
            bootstrap_peers: Vec::new(),
            identity_path,
            announce_interval: Duration::from_secs(300),
            local_key_id: local_key_id.into(),
        }
    }
}

// ─── Transport ──────────────────────────────────────────────────────

/// Reticulum transport. Implements [`Transport`]; constructed via
/// [`ReticulumTransport::new`] and registered on the edge builder.
///
/// A single [`ReticulumNode`] is `Arc`-shared between
/// [`Transport::send`] (which drives links + resource sends — all
/// `&self` node methods) and [`Transport::listen`] (which drains the
/// node's single `NodeEvent` receiver). The node is built and started
/// in [`ReticulumTransport::new`]; the event receiver is taken there
/// too and stashed for `listen` to claim exactly once.
pub struct ReticulumTransport {
    config: ReticulumTransportConfig,
    /// The Leviculum node — built + started in `new`. Shared; `send`
    /// borrows it, `listen` drains its event channel.
    node: Arc<ReticulumNode>,
    /// Hash of edge's own registered destination — the thing we
    /// announce on startup and on the announce timer.
    local_dest_hash: DestinationHash,
    /// The node's single `NodeEvent` receiver. `listen` takes it
    /// exactly once; a second `listen` call is a config error.
    events: Mutex<Option<mpsc::Receiver<NodeEvent>>>,
    /// `key_id → resolved peer`, populated from received announces.
    /// `send` consults this before falling back to the injected
    /// [`PeerResolver`].
    peers: Arc<Mutex<HashMap<String, ResolvedPeer>>>,
    /// Link IDs the event loop has seen reach `LinkEstablished`.
    /// `send` waits on this set after `connect` — the link must be
    /// established on both ends before a resource transfer can start.
    /// The event loop owns the only `NodeEvent` receiver, so this set
    /// is `send`'s sole window onto link state.
    established_links: Arc<Mutex<HashSet<LinkId>>>,
    /// Resource hashes the event loop has seen complete on the
    /// sender side (`ResourceCompleted { is_sender: true }`). `send`
    /// waits on this set so it returns `Delivered` only once the
    /// transfer has actually drained, not merely enqueued.
    sent_resources: Arc<Mutex<HashSet<[u8; 32]>>>,
    /// Optional directory-backed resolver. When `None`, only
    /// announce-driven discovery is available.
    resolver: Option<Arc<dyn PeerResolver>>,
}

impl ReticulumTransport {
    /// Construct + start the transport: load-or-generate the
    /// transport identity, build the Leviculum node with the
    /// configured TCP interfaces, register edge's own federation
    /// destination, take the node's event receiver, and start the
    /// event loop.
    ///
    /// The node is running once this returns. [`Transport::listen`]
    /// drains its events; [`Transport::send`] uses it to dial peers.
    pub async fn new(
        config: ReticulumTransportConfig,
        resolver: Option<Arc<dyn PeerResolver>>,
    ) -> Result<Self, TransportError> {
        let identity = load_or_generate_identity(&config.identity_path)?;

        // Build the node. The transport identity is the node identity;
        // a per-process storage dir alongside the identity file holds
        // Leviculum's known-destinations / packet-hashlist state.
        let storage_path = config
            .identity_path
            .parent()
            .map_or_else(|| PathBuf::from("."), PathBuf::from)
            .join("reticulum_storage");

        let mut builder = ReticulumNodeBuilder::new()
            .identity(identity.clone())
            .storage_path(storage_path)
            .add_tcp_server(config.listen_addr);
        for peer in &config.bootstrap_peers {
            builder = builder.add_tcp_client(*peer);
        }
        let mut node = builder
            .build()
            .await
            .map_err(|e| TransportError::Config(format!("reticulum node build: {e}")))?;

        // Register edge's federation destination. SINGLE/IN — it
        // receives links and can be announced. `accepts_links` must
        // be set or inbound LINK_REQUESTs are dropped.
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            EDGE_APP_NAME,
            &[EDGE_APP_ASPECT],
        )
        .map_err(|e| TransportError::Config(format!("destination build: {e}")))?;
        dest.set_accepts_links(true);
        let local_dest_hash = *dest.hash();
        node.register_destination(dest);

        // Take the single event receiver before starting, then start
        // the event loop. `listen` claims the stashed receiver.
        let events = node
            .take_event_receiver()
            .ok_or_else(|| TransportError::Config("event receiver unavailable".into()))?;
        node.start()
            .await
            .map_err(|e| TransportError::Io(format!("reticulum node start: {e}")))?;

        tracing::info!(
            addr = %config.listen_addr,
            dest = %local_dest_hash,
            "Reticulum transport node started",
        );

        Ok(Self {
            config,
            node: Arc::new(node),
            local_dest_hash,
            events: Mutex::new(Some(events)),
            peers: Arc::new(Mutex::new(HashMap::new())),
            established_links: Arc::new(Mutex::new(HashSet::new())),
            sent_resources: Arc::new(Mutex::new(HashSet::new())),
            resolver,
        })
    }

    /// Whether `destination_key_id` has been resolved — either learnt
    /// from a received announce or directory-resolvable. Primarily a
    /// test + diagnostics hook for confirming announce-driven
    /// discovery has converged before a `send`.
    pub async fn knows_peer(&self, destination_key_id: &str) -> bool {
        self.resolve_peer(destination_key_id).await.is_some()
    }

    /// Resolve a `destination_key_id` to a Reticulum peer. Consults
    /// the announce-populated map first, then the injected
    /// [`PeerResolver`]. Returns `None` if neither yields the peer.
    async fn resolve_peer(&self, destination_key_id: &str) -> Option<ResolvedPeer> {
        if let Some(peer) = self.peers.lock().await.get(destination_key_id).copied() {
            return Some(peer);
        }
        let pubkey = self.resolver.as_ref()?.resolve(destination_key_id)?;
        let mut x25519 = [0u8; 32];
        let mut ed25519 = [0u8; 32];
        x25519.copy_from_slice(&pubkey[..32]);
        ed25519.copy_from_slice(&pubkey[32..]);
        let identity = Identity::from_public_keys(&x25519, &ed25519).ok()?;
        // The peer's destination hash for its `ciris.edge` endpoint is
        // deterministic from its identity hash + the shared app name.
        let name_hash = Destination::compute_name_hash(EDGE_APP_NAME, &[EDGE_APP_ASPECT]);
        let dest_hash = Destination::compute_destination_hash(&name_hash, identity.hash());
        Some(ResolvedPeer {
            dest_hash,
            signing_key: ed25519,
        })
    }
}

#[async_trait]
impl Transport for ReticulumTransport {
    fn id(&self) -> TransportId {
        TransportId::RETICULUM_RS
    }

    async fn send(
        &self,
        destination_key_id: &str,
        envelope_bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError> {
        // AV-13: reject oversized payloads before touching the network.
        if envelope_bytes.len() > MAX_BODY_BYTES {
            return Err(TransportError::BodyTooLarge {
                actual: envelope_bytes.len(),
                limit: MAX_BODY_BYTES,
            });
        }

        let peer = self.resolve_peer(destination_key_id).await.ok_or_else(|| {
            TransportError::Unreachable(format!(
                "no Reticulum destination known for destination_key_id={destination_key_id} \
                 (not directory-resolvable and no announce received)"
            ))
        })?;

        // Establish a link to the peer's destination. `connect`
        // returns immediately; the link is usable once
        // `LinkEstablished` arrives on the event channel. The event
        // loop is owned by `listen`, so we cannot observe that event
        // here — instead we poll `active_link_count` / link presence
        // via a short bounded wait, then send the resource.
        let link = self
            .node
            .connect(&peer.dest_hash, &peer.signing_key)
            .await
            .map_err(|e| TransportError::Io(format!("reticulum connect: {e}")))?;
        let link_id = *link.link_id();

        // Wait for the link to reach `LinkEstablished` on BOTH ends —
        // the peer must have accepted the LINK_REQUEST or a resource
        // transfer cannot start. The event loop records established
        // link IDs in `established_links`; poll it.
        let established = wait_until_async(
            LINK_ESTABLISH_TIMEOUT,
            Duration::from_millis(50),
            || async { self.established_links.lock().await.contains(&link_id) },
        )
        .await;
        if !established {
            return Err(TransportError::Timeout(LINK_ESTABLISH_TIMEOUT));
        }

        // Auto-accept any resources the peer pushes back on this link
        // (e.g. an ACK envelope), and ship our envelope as a resource.
        let _ = self
            .node
            .set_resource_strategy(&link_id, ResourceStrategy::AcceptAll);
        let resource_hash = self
            .node
            .send_resource(&link_id, envelope_bytes, None, true)
            .await
            .map_err(|e| TransportError::Io(format!("reticulum send_resource: {e}")))?;

        // Wait for the sender-side `ResourceCompleted` — the driver
        // paces + retransmits resource parts, and completion means
        // every part was delivered + proven. If the transfer does not
        // complete within the window, treat it as a timeout so edge's
        // durable dispatcher retries.
        let completed = wait_until_async(
            RESOURCE_TRANSFER_TIMEOUT,
            Duration::from_millis(100),
            || async { self.sent_resources.lock().await.remove(&resource_hash) },
        )
        .await;
        if !completed {
            return Err(TransportError::Timeout(RESOURCE_TRANSFER_TIMEOUT));
        }

        Ok(TransportSendOutcome::Delivered)
    }

    async fn listen(&self, sink: mpsc::Sender<InboundFrame>) -> Result<(), TransportError> {
        // Claim the node's single event receiver. A second `listen`
        // call finds it gone — that is a wiring bug, not a runtime
        // condition, so surface it as a config error.
        let mut events = self
            .events
            .lock()
            .await
            .take()
            .ok_or_else(|| TransportError::Config("listen called twice".into()))?;

        tracing::info!(
            addr = %self.config.listen_addr,
            dest = %self.local_dest_hash,
            "Reticulum transport listening",
        );

        // Announce edge's own destination on startup, then on a timer.
        let app_data = self.config.local_key_id.clone().into_bytes();
        if let Err(e) = self
            .node
            .announce_destination(&self.local_dest_hash, Some(&app_data))
            .await
        {
            tracing::warn!(error = %e, "initial announce failed");
        }
        let mut announce_tick = tokio::time::interval(self.config.announce_interval);
        announce_tick.tick().await; // consume the immediate first tick

        loop {
            tokio::select! {
                _ = announce_tick.tick() => {
                    if let Err(e) = self
                        .node
                        .announce_destination(&self.local_dest_hash, Some(&app_data))
                        .await
                    {
                        tracing::warn!(error = %e, "periodic announce failed");
                    }
                }
                event = events.recv() => {
                    let Some(event) = event else {
                        tracing::info!("Reticulum event channel closed; listener exiting");
                        break;
                    };
                    let ctx = EventCtx {
                        node: &self.node,
                        peers: &self.peers,
                        established_links: &self.established_links,
                        sent_resources: &self.sent_resources,
                        sink: &sink,
                    };
                    handle_event(event, &ctx).await;
                }
            }
        }

        Ok(())
    }
}

/// Shared handles the event loop hands to [`handle_event`].
struct EventCtx<'a> {
    node: &'a ReticulumNode,
    peers: &'a Mutex<HashMap<String, ResolvedPeer>>,
    established_links: &'a Mutex<HashSet<LinkId>>,
    sent_resources: &'a Mutex<HashSet<[u8; 32]>>,
    sink: &'a mpsc::Sender<InboundFrame>,
}

/// Handle one [`NodeEvent`]. Announce events populate the peer map;
/// link requests are accepted with auto-resource-accept; established
/// links + completed sender-side resources unblock [`Transport::send`];
/// completed receiver-side resources become [`InboundFrame`]s.
async fn handle_event(event: NodeEvent, ctx: &EventCtx<'_>) {
    match event {
        NodeEvent::AnnounceReceived { announce, .. } => {
            // The announce app-data carries the peer's federation
            // `key_id`; the public key's ed25519 half (bytes 32..64)
            // is the `signing_key` `connect` needs.
            let Some(key_id) = announce.app_data_string().map(str::to_owned) else {
                return;
            };
            let pk = announce.public_key();
            let mut signing_key = [0u8; 32];
            signing_key.copy_from_slice(&pk[32..64]);
            let resolved = ResolvedPeer {
                dest_hash: *announce.destination_hash(),
                signing_key,
            };
            tracing::debug!(key_id = %key_id, dest = %resolved.dest_hash, "peer discovered via announce");
            ctx.peers.lock().await.insert(key_id, resolved);
        }
        NodeEvent::LinkRequest { link_id, .. } => {
            match ctx.node.accept_link(&link_id).await {
                Ok(_) => {
                    // Auto-accept inbound resources on the link so
                    // envelope transfers reassemble without app
                    // intervention.
                    let _ = ctx
                        .node
                        .set_resource_strategy(&link_id, ResourceStrategy::AcceptAll);
                }
                Err(e) => tracing::warn!(error = %e, "accept_link failed"),
            }
        }
        NodeEvent::LinkEstablished { link_id, .. } => {
            // On the responder side, ensure inbound resources are
            // accepted (the LinkRequest branch already set this for
            // links we accepted; this also covers initiator links so
            // ACK envelopes pushed back are reassembled).
            let _ = ctx
                .node
                .set_resource_strategy(&link_id, ResourceStrategy::AcceptAll);
            ctx.established_links.lock().await.insert(link_id);
        }
        NodeEvent::ResourceCompleted {
            link_id,
            data,
            is_sender,
            segment_index,
            resource_hash,
            ..
        } => {
            if is_sender {
                // Our own outbound envelope finished transferring —
                // unblock the `send` waiting on this resource hash.
                ctx.sent_resources.lock().await.insert(resource_hash);
                return;
            }
            // Receiver side: the first segment carries the full
            // envelope (edge envelopes are single-segment for the
            // MVP — an 8 MiB cap fits one Reticulum resource).
            if data.is_empty() || segment_index != 1 {
                return;
            }
            tracing::debug!(
                link = ?link_id,
                bytes = data.len(),
                "inbound envelope resource completed",
            );
            let frame = InboundFrame {
                envelope_bytes: data,
                transport: TransportId::RETICULUM_RS,
                received_at: Utc::now(),
            };
            if let Err(e) = ctx.sink.send(frame).await {
                tracing::error!(error = %e, "inbound channel send failed");
            }
        }
        NodeEvent::LinkClosed {
            link_id, reason, ..
        } => {
            ctx.established_links.lock().await.remove(&link_id);
            tracing::debug!(link = ?link_id, reason = ?reason, "link closed");
        }
        other => {
            tracing::trace!(event = ?other, "unhandled Reticulum event");
        }
    }
}

// ─── Identity persistence (AV-17) ───────────────────────────────────

/// Load the transport identity from `path`, or generate + persist a
/// fresh one on first run. The file holds 64 raw private-key bytes
/// (x25519 ‖ ed25519) and is chmod-600 — readable only by the edge
/// process owner. This is the transport-tier identity; the federation
/// signing key is never written here (AV-17).
fn load_or_generate_identity(path: &std::path::Path) -> Result<Identity, TransportError> {
    if path.exists() {
        let bytes = std::fs::read(path).map_err(|e| {
            TransportError::Config(format!("read identity {}: {e}", path.display()))
        })?;
        return Identity::from_private_key_bytes(&bytes).map_err(|e| {
            TransportError::Config(format!("parse identity {}: {e}", path.display()))
        });
    }

    let identity = reticulum_std::generate_identity();
    let bytes = identity
        .private_key_bytes()
        .map_err(|e| TransportError::Config(format!("serialize identity: {e}")))?;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                TransportError::Config(format!("create identity dir {}: {e}", parent.display()))
            })?;
        }
    }
    std::fs::write(path, bytes)
        .map_err(|e| TransportError::Config(format!("write identity {}: {e}", path.display())))?;
    set_owner_only(path)?;

    tracing::info!(path = %path.display(), "generated new Reticulum transport identity");
    Ok(identity)
}

/// chmod the identity file to `0o600` (owner read/write only). Best
/// effort on non-Unix hosts — the security model assumes Unix.
#[cfg(unix)]
fn set_owner_only(path: &std::path::Path) -> Result<(), TransportError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)
        .map_err(|e| TransportError::Config(format!("chmod 600 {}: {e}", path.display())))
}

#[cfg(not(unix))]
fn set_owner_only(_path: &std::path::Path) -> Result<(), TransportError> {
    Ok(())
}

// ─── Bounded polling helper ─────────────────────────────────────────

/// Poll an async `cond` every `interval` until it resolves to `true`
/// or `timeout` elapses. Returns whether the condition was met. Used
/// by `send` to wait on link establishment + resource completion
/// without owning the `NodeEvent` loop (which `listen` owns).
async fn wait_until_async<F, Fut>(timeout: Duration, interval: Duration, mut cond: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if cond().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_round_trips_through_file() {
        let dir = std::env::temp_dir().join(format!("ciris_edge_ret_id_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("transport.id");

        let first = load_or_generate_identity(&path).expect("generate");
        assert!(path.exists(), "identity file should be created");
        let second = load_or_generate_identity(&path).expect("reload");
        assert_eq!(
            first.hash(),
            second.hash(),
            "reloaded identity must be stable across runs",
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "identity file must be chmod 600");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_new_defaults() {
        let cfg = ReticulumTransportConfig::new(PathBuf::from("/tmp/x.id"), "edge-key-1");
        assert_eq!(cfg.local_key_id, "edge-key-1");
        assert!(cfg.bootstrap_peers.is_empty());
        assert_eq!(cfg.announce_interval, Duration::from_secs(300));
    }
}
