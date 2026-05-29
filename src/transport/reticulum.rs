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
//! ## Peer resolution — the authenticated cold-start path (AV-42)
//!
//! [`Transport::send`] receives a `destination_key_id: &str` and must
//! resolve it to a Reticulum destination. v0.3.1 recorded
//! `key_id → destination` straight off the announce app-data
//! (trust-on-first-use); any peer could announce a `key_id` it does
//! not own and intercept everything addressed to it. That is **AV-42**
//! (`docs/THREAT_MODEL.md` §4). v0.4.0 replaces TOFU with an
//! authenticated cold-start path (CIRISEdge#15 / CIRISVerify#28
//! Phase 3).
//!
//! Each announce carries an [`AnnounceAttestation`] in its app-data —
//! a federation-key signature binding the announcer's transport
//! identity to its `key_id` (see [`super::attestation`]). On receipt
//! the listener:
//!
//! 1. Parses the [`AnnounceAttestation`] from the app-data.
//! 2. **Roots the federation key** — `RootingDirectory::root_binding`
//!    (CIRISPersist v1.12.0) against the persist `federation_keys`
//!    directory. A `Rejected` verdict drops the announce; a
//!    `DirectoryError` is retryable (the peer is not blacklisted),
//!    the seven structural/crypto rejections are terminal and logged
//!    as AV-42 events.
//! 3. **Verifies the attestation signature** over
//!    `{transport_identity_pubkey, key_id, epoch}` against the
//!    now-directory-confirmed Ed25519 pubkey. A forgery fails here.
//! 4. **Applies the consumer [`HybridPolicy`]** to the rooted
//!    provenance chain (`Strict` rejects any hybrid-pending link).
//! 5. Records `key_id → transport identity` as a **rooted**
//!    resolution and caches the `ProvenanceChain`. `send` routes to
//!    it.
//!
//! An optional out-of-band [`PeerResolver`] remains for deployments
//! that seed peers from a directory query rather than announces.
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

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, Mutex};

use reticulum_core::link::LinkId;
use reticulum_core::resource::ResourceStrategy;
use reticulum_core::{Destination, DestinationHash, DestinationType, Direction, Identity};
use reticulum_std::driver::{ReticulumNode, ReticulumNodeBuilder};
use reticulum_std::NodeEvent;

use super::attestation::{AnnounceAttestation, AttestationError, AttestationPayload};
use super::{InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome};
use crate::identity::LocalSigner;
use crate::reachability::{AttemptOutcome, ReachabilityTracker};
use crate::verify::{
    HybridPolicy, ProvenanceChain, RootingDirectory, RootingRejection, RootingVerdict,
};

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
///
/// # Holder resolution (CIRISEdge#21 v0.8.0)
///
/// [`PeerResolver::resolve_holders`] extends the trait with the
/// "which peers hold the bytes for this SHA?" lookup that the
/// `ContentFetch` family needs. The default impl returns an empty
/// `Vec` so v0.7.x-era impls don't break; a production impl wraps
/// persist's `BlobStorage::list_holders` (CIRISPersist#103 / v2.3+)
/// which queries the `holds_bytes:sha256:<prefix>` attestation index
/// and returns `Vec<key_id>`. Each returned `key_id` is then routable
/// via the existing [`PeerResolver::resolve`] path — the holder list
/// IS a list of `key_id` "transport identities" in the existing
/// edge-layer sense (the federation_keys row's id is the addressing
/// unit; the dual-key bytes are the substrate-tier address).
pub trait PeerResolver: Send + Sync + 'static {
    /// Return the peer's 64-byte Reticulum public key (x25519 ‖
    /// ed25519), or `None` if the directory has no transport key for
    /// `key_id`.
    fn resolve(&self, destination_key_id: &str) -> Option<[u8; 64]>;

    /// Return the `key_id`s of every peer that has advertised holding
    /// the bytes for `sha256` — the CIRISEdge#21 v0.8.0 content-fetch
    /// peer-discovery primitive. Default impl returns an empty `Vec`
    /// (v0.7.x-era resolvers don't need to break; the fetcher falls
    /// back to its own resolution path or fails with no candidate
    /// peers).
    ///
    /// # Production wiring
    ///
    /// The CIRISPersist#103 (v2.3+) production impl maps onto
    /// `BlobStorage::list_holders(&sha256_array) -> Vec<String>`
    /// (returns `key_id`s pulled from the
    /// `holds_bytes:sha256:<8-hex-prefix>` attestation index on the
    /// `federation_attestations` table). The returned `key_id`s are
    /// then routable through this trait's existing [`Self::resolve`].
    ///
    /// `BlobStorage` is NOT object-safe in persist v2.3 (uses
    /// `async fn in trait` via `impl Future`), so a downstream adapter
    /// crate erases it the same way edge's [`crate::verify::VerifyDirectory`]
    /// adapter erases `FederationDirectory`. The trait surface here
    /// is `fn -> Vec<String>` (sync return type with async-by-default
    /// shape) so existing test impls don't need an async-trait crate
    /// dependency; production impls that need to await persist can
    /// hold a tokio runtime handle and `block_on` inside the resolver.
    ///
    /// Returns an empty `Vec` when no holders are known (the fetcher
    /// treats this as "no candidate peers" — typed not-found, never a
    /// silent hang per `MISSION.md` §3 anti-pattern 6).
    ///
    /// # CEG §10.1.2 TTL discipline (v0.12.0 / CIRISEdge#42)
    ///
    /// CEG 0.1 §10.1.2 requires `holds_bytes:sha256:{prefix}`
    /// attestations to be considered **stale** after 24h from
    /// `signed_at` (configurable via [`crate::EdgeConfig::holds_bytes_ttl_seconds`]).
    /// Stale attestations MUST NOT be returned here. Impls that wrap
    /// persist's `BlobStorage::list_holders` are expected to either (a)
    /// filter at the persist query layer (preferred — the persist row's
    /// `signed_at` is greater than `now - 24h`), or (b) return ONLY
    /// non-stale rows by implementing
    /// [`Self::resolve_holders_with_signed_at`] and letting
    /// [`Self::resolve_holders`] delegate to a filter helper. Edge does
    /// NOT apply a second TTL on top of this method's return value — by
    /// the time the bytes come back here, they MUST already be live.
    fn resolve_holders(&self, _sha256: &[u8; 32]) -> Vec<String> {
        Vec::new()
    }

    /// TTL-aware companion to [`Self::resolve_holders`] — returns each
    /// candidate holder with the `signed_at` of its `holds_bytes`
    /// attestation, so the caller (edge's content-fetch dispatcher) can
    /// apply the §10.1.2 24h TTL filter centrally without each
    /// impl re-rolling the staleness logic.
    ///
    /// Default impl returns the [`Self::resolve_holders`] result
    /// stamped at [`chrono::Utc::now`] — preserves the v0.7.x-era
    /// contract for resolvers that don't track attestation timestamps
    /// (every returned holder counts as fresh). Production impls
    /// override this with the real `(key_id, signed_at)` rows from
    /// persist's `holds_bytes:sha256:*` attestation index.
    ///
    /// # CEG §10.1.2 (CIRISEdge#42)
    ///
    /// Edge's content-fetch dispatcher calls this entry point in
    /// preference to [`Self::resolve_holders`] so the TTL filter +
    /// holder-downweight ordering can run uniformly across impls.
    fn resolve_holders_with_signed_at(&self, sha256: &[u8; 32]) -> Vec<HolderAttestation> {
        let now = Utc::now();
        self.resolve_holders(sha256)
            .into_iter()
            .map(|key_id| HolderAttestation {
                key_id,
                signed_at: now,
            })
            .collect()
    }
}

/// A `holds_bytes:sha256:*` attestation row — the `(holder_key_id,
/// signed_at)` pair edge's content-fetch dispatcher needs to apply the
/// CEG §10.1.2 24h TTL filter + the rolling ContentMiss downweight.
///
/// Returned from [`PeerResolver::resolve_holders_with_signed_at`].
/// `signed_at` is the wall-clock time the holder signed its
/// `holds_bytes` attestation — NOT the time the row was fetched from
/// persist. The TTL window is computed against `signed_at` so a slow
/// persist round-trip cannot extend the effective freshness.
#[derive(Debug, Clone)]
pub struct HolderAttestation {
    /// The holder's federation `key_id` — addressable via
    /// [`PeerResolver::resolve`].
    pub key_id: String,
    /// Wall-clock time the holder signed the `holds_bytes:sha256:*`
    /// attestation. CEG §10.1.2 — staleness is 24h from this stamp
    /// (configurable via [`crate::EdgeConfig::holds_bytes_ttl_seconds`]).
    pub signed_at: DateTime<Utc>,
}

// ─── Holder TTL + downweight (CEG §10.1.2, CIRISEdge#42) ────────────

pub use crate::edge::{
    DEFAULT_HOLDER_DOWNWEIGHT_MISS_THRESHOLD, DEFAULT_HOLDER_DOWNWEIGHT_WINDOW_SECONDS,
    DEFAULT_HOLDS_BYTES_TTL_SECONDS,
};

/// Per-holder ContentMiss tracker — backs the CEG §10.1.2
/// downweight policy. Each holder gets a ring buffer of miss
/// timestamps; the tracker counts misses inside a rolling window
/// (default 1h) and reports whether the holder is currently
/// downweighted (≥ threshold misses in window).
///
/// Construction is via [`Self::new`] with the window + threshold
/// from edge's [`crate::EdgeConfig`]. Edge owns the `Arc<>` and
/// drives [`Self::record_miss`] from the `dispatch_inbound`
/// ContentMiss arm; [`filter_holders_with_policy`] reads
/// [`Self::is_downweighted`] to sort downweighted holders to the
/// tail of `resolve_holders` output.
///
/// Implementation: plain `Mutex<HashMap<String, VecDeque<DateTime<Utc>>>>`
/// — sufficient for the per-holder miss rate (low-volume; one entry
/// per ContentMiss, not per byte). VecDeque so window eviction is
/// O(window-size); evictions amortize cleanly.
pub struct HolderDownweightTracker {
    inner: Mutex<HashMap<String, VecDeque<DateTime<Utc>>>>,
    window_seconds: u64,
    miss_threshold: u32,
}

impl HolderDownweightTracker {
    /// Construct a tracker with the supplied rolling window + miss
    /// threshold. Mirrors [`crate::EdgeConfig::holder_downweight_window_seconds`]
    /// + [`crate::EdgeConfig::holder_downweight_miss_threshold`].
    #[must_use]
    pub fn new(window_seconds: u64, miss_threshold: u32) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            window_seconds,
            miss_threshold,
        }
    }

    /// Record a ContentMiss against `holder_key_id`. Timestamp =
    /// [`Utc::now`]; this is the canonical entry point that
    /// `dispatch_inbound`'s ContentMiss arm calls.
    pub async fn record_miss(&self, holder_key_id: &str) {
        self.record_miss_at(holder_key_id, Utc::now()).await;
    }

    /// Test-only variant of [`Self::record_miss`] that takes a
    /// caller-supplied timestamp — lets the window-eviction test drive
    /// deterministic ageing without mocking the system clock.
    pub async fn record_miss_at(&self, holder_key_id: &str, at: DateTime<Utc>) {
        let mut map = self.inner.lock().await;
        let buf = map.entry(holder_key_id.to_string()).or_default();
        buf.push_back(at);
        evict_window(buf, at, self.window_seconds);
    }

    /// Whether `holder_key_id` currently meets the downweight criterion
    /// (≥ `miss_threshold` misses in the rolling window). `now` is
    /// supplied so tests can drive ageing deterministically; the
    /// non-test caller passes [`Utc::now`].
    pub async fn is_downweighted_at(&self, holder_key_id: &str, now: DateTime<Utc>) -> bool {
        let mut map = self.inner.lock().await;
        let Some(buf) = map.get_mut(holder_key_id) else {
            return false;
        };
        evict_window(buf, now, self.window_seconds);
        u32::try_from(buf.len()).unwrap_or(u32::MAX) >= self.miss_threshold
    }

    /// Convenience: [`Self::is_downweighted_at`] with `now = Utc::now()`.
    pub async fn is_downweighted(&self, holder_key_id: &str) -> bool {
        self.is_downweighted_at(holder_key_id, Utc::now()).await
    }

    /// Current miss count for `holder_key_id` inside the rolling
    /// window. Primarily a test + diagnostics hook.
    pub async fn miss_count(&self, holder_key_id: &str) -> u32 {
        let now = Utc::now();
        let mut map = self.inner.lock().await;
        let Some(buf) = map.get_mut(holder_key_id) else {
            return 0;
        };
        evict_window(buf, now, self.window_seconds);
        u32::try_from(buf.len()).unwrap_or(u32::MAX)
    }
}

fn evict_window(buf: &mut VecDeque<DateTime<Utc>>, now: DateTime<Utc>, window_seconds: u64) {
    let cutoff = now - chrono::Duration::seconds(i64::try_from(window_seconds).unwrap_or(i64::MAX));
    while let Some(front) = buf.front() {
        if *front < cutoff {
            buf.pop_front();
        } else {
            break;
        }
    }
}

/// Apply CEG §10.1.2 TTL + downweight policy to a holder list, in one
/// place. Returns the live (non-stale) holders, sorted so any holder
/// currently downweighted (≥ `miss_threshold` misses in window) sits
/// at the tail of the result. Caller policy (consumer client) decides
/// whether to attempt downweighted holders at all — the spec's
/// "2-holder-parallel-attempt" policy lands in CIRISEdge#22 Tier 4
/// (not in v0.12.0); here we surface the ordering primitive.
///
/// - `holders`: `(key_id, signed_at)` rows from
///   [`PeerResolver::resolve_holders_with_signed_at`].
/// - `ttl_seconds`: [`crate::EdgeConfig::holds_bytes_ttl_seconds`]
///   (default 24h per CEG §10.1.2).
/// - `tracker`: per-holder ContentMiss tracker; `None` skips the
///   downweight sort (e.g. tests that want pure-TTL behaviour).
/// - `now`: wall-clock anchor — caller-supplied so tests can drive the
///   filter deterministically.
pub async fn filter_holders_with_policy(
    holders: Vec<HolderAttestation>,
    ttl_seconds: u64,
    tracker: Option<&HolderDownweightTracker>,
    now: DateTime<Utc>,
) -> Vec<String> {
    let cutoff = now - chrono::Duration::seconds(i64::try_from(ttl_seconds).unwrap_or(i64::MAX));
    let live: Vec<HolderAttestation> = holders
        .into_iter()
        .filter(|h| h.signed_at >= cutoff)
        .collect();
    let Some(tracker) = tracker else {
        return live.into_iter().map(|h| h.key_id).collect();
    };
    // Partition into normal + downweighted; preserve resolver-supplied
    // order within each partition (no second sort criterion at v0.12.0).
    let mut normal = Vec::with_capacity(live.len());
    let mut downweighted = Vec::with_capacity(live.len());
    for holder in live {
        if tracker.is_downweighted_at(&holder.key_id, now).await {
            downweighted.push(holder.key_id);
        } else {
            normal.push(holder.key_id);
        }
    }
    normal.extend(downweighted);
    normal
}

/// A resolved peer — its Reticulum destination hash plus the ed25519
/// verifying key required by `ReticulumNode::connect`.
#[derive(Debug, Clone, Copy)]
struct ResolvedPeer {
    dest_hash: DestinationHash,
    signing_key: [u8; 32],
}

/// A peer whose `key_id → transport-identity` binding has been
/// **rooted** against the persist `federation_keys` directory and
/// whose announce attestation signature verified — the authenticated
/// cold-start outcome (CIRISEdge#15). `send` routes only to rooted
/// peers (or out-of-band [`PeerResolver`] hits).
#[derive(Debug, Clone)]
struct RootedPeer {
    /// The Reticulum destination + signing key `connect` needs.
    peer: ResolvedPeer,
    /// The transport-identity rotation epoch this binding was
    /// attested at. A later announce with a strictly greater epoch
    /// supersedes; an equal-or-lower epoch is a stale re-announce.
    epoch: u64,
    /// The verified recursive-provenance chain from the rooting
    /// verdict — cached so a consumer can audit provenance without a
    /// second directory round-trip (CIRISVerify WS-4 hand-off).
    #[allow(dead_code)]
    chain: ProvenanceChain,
}

// ─── Configuration ──────────────────────────────────────────────────

/// Reticulum transport configuration. Deliberately small — the MVP
/// surface is a TCP listen addr, bootstrap peer addr(s), the
/// transport-identity file path, and the announce interval.
///
/// v0.12.0 (CIRISEdge#24) — `interfaces` is the typed extension point.
/// When non-empty, the v0.11.x default TCP-server + TCP-client wiring
/// (`listen_addr` + `bootstrap_peers`) is SUPPRESSED and only the
/// supplied [`ReticulumInterfaceConfig`] entries are spawned. When
/// empty, the legacy path runs unchanged
/// (`add_tcp_server(listen_addr)` plus a TCP client per bootstrap
/// peer) — back-compat for every existing
/// `ReticulumTransportConfig::new(_, _)` caller.
#[derive(Debug, Clone)]
pub struct ReticulumTransportConfig {
    /// TCP address the node listens on for inbound Reticulum links.
    /// Legacy v0.11.x field — consulted only when [`Self::interfaces`]
    /// is empty.
    pub listen_addr: SocketAddr,
    /// Bootstrap peer TCP addresses dialled as Reticulum TCP clients
    /// on startup. Empty is valid (listen-only / announce-discovered).
    /// Legacy v0.11.x field — consulted only when [`Self::interfaces`]
    /// is empty.
    pub bootstrap_peers: Vec<SocketAddr>,
    /// Path to the persisted transport-tier Reticulum identity (64
    /// raw private-key bytes). Generated + chmod-600 on first run,
    /// reloaded thereafter for a stable destination across restarts.
    /// This is NOT the federation signing key (AV-17).
    pub identity_path: PathBuf,
    /// Interval between re-announces of edge's own destination. The
    /// destination is also announced once on startup.
    pub announce_interval: Duration,
    /// Edge's own federation `key_id`, advertised in the announce
    /// attestation so peers can root + map `key_id → destination`.
    pub local_key_id: String,
    /// Transport-identity rotation epoch carried in edge's own
    /// announce attestation. Monotonic per `local_key_id` — bump it
    /// when the transport identity rotates so peers supersede their
    /// cached binding. `0` is a fine first-deployment value.
    pub local_epoch: u64,
    /// v0.12.0 (CIRISEdge#24) — typed interface set. When non-empty,
    /// the [`Self::listen_addr`] + [`Self::bootstrap_peers`] legacy
    /// fields are suppressed and only these entries are spawned. The
    /// constructor [`Self::add_interface`] appends one variant; for
    /// gateway-peer deployments (one edge bridging Local + TCP, e.g.)
    /// call it twice.
    pub interfaces: Vec<ReticulumInterfaceConfig>,
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
            local_epoch: 0,
            interfaces: Vec::new(),
        }
    }

    /// Append one [`ReticulumInterfaceConfig`] to [`Self::interfaces`].
    /// Builder-style — chain to register multiple interfaces against
    /// the same Reticulum runtime (the gateway-peer pattern: one node,
    /// many interface kinds, forwarding via the leviculum transport
    /// layer).
    #[must_use]
    pub fn add_interface(mut self, iface: ReticulumInterfaceConfig) -> Self {
        self.interfaces.push(iface);
        self
    }
}

// ─── Interface diversity (CIRISEdge#24, v0.12.0) ────────────────────
//
// Leviculum supports many physical interface kinds — TCP server / TCP
// client / UDP / AutoInterface (LAN UDP multicast discovery) /
// LocalInterface (AF_UNIX / Windows named pipe IPC) / RNodeInterface
// (LoRa via the RNode firmware) / I2P. M-1 says "diverse sentient
// beings may pursue their own flourishing"; at the transport tier
// that means each kind is a first-class adapter, not just LAN-multicast
// (which is what the v0.11.x `AutoInterface` default exposed).
//
// `ReticulumInterfaceConfig` is the typed config enum the public
// constructor [`ReticulumTransport::add_interface`] consumes. Each
// variant gates on its own Cargo sub-feature so a deployment that
// wants ONLY (say) TCP-server can build a smaller binary —
// `transport-reticulum-tcp-server` alone, no AutoInterface code linked.

/// One Reticulum interface. Enum over the v0.12.0 wired interface set;
/// future kinds (KISS / serial / pipe / backbone — listed in
/// [`Cargo.toml`] under DEFERRED) land here when community demand
/// surfaces.
///
/// Each variant gates on its own Cargo feature; building with only
/// (say) `transport-reticulum-tcp-server` enabled compiles the enum
/// itself but only the `TcpServer` arm is constructible.
#[derive(Debug, Clone)]
pub enum ReticulumInterfaceConfig {
    /// `AutoInterface` — zero-configuration LAN auto-discovery via
    /// UDPv6 multicast. The v0.11.x default; back-compat is preserved
    /// via the `transport-reticulum` umbrella feature implying
    /// `transport-reticulum-auto`.
    #[cfg(feature = "transport-reticulum-auto")]
    Auto(AutoInterfaceConfig),
    /// `TcpServerInterface` — bind a TCP socket and accept inbound
    /// Reticulum peers. Production deployments behind a firewall
    /// typically expose this alongside a published peer list.
    #[cfg(feature = "transport-reticulum-tcp-server")]
    TcpServer(TcpServerInterfaceConfig),
    /// `TcpClientInterface` — dial out to a remote Reticulum TCP
    /// server. Restrictive-egress deployments use this to reach a
    /// known relay.
    #[cfg(feature = "transport-reticulum-tcp-client")]
    TcpClient(TcpClientInterfaceConfig),
    /// `UdpInterface` — lightweight UDP point-to-point or multicast.
    /// Cheaper than TCP for high-frequency low-bandwidth flows.
    #[cfg(feature = "transport-reticulum-udp")]
    Udp(UdpInterfaceConfig),
    /// `LocalInterface` — AF_UNIX (Linux/macOS) or Windows named pipe.
    /// IPC cohabitation between co-resident agents on one host. Each
    /// process can either RUN a Local server (`is_server: true`) or
    /// CONNECT to one (`is_server: false`); the shared-instance name
    /// pins the abstract socket path.
    #[cfg(feature = "transport-reticulum-local")]
    Local(LocalInterfaceConfig),
    /// `RNodeInterface` — direct LoRa radio modem via the RNode
    /// firmware. Off-grid relays + solar-powered meshes. Leviculum's
    /// Rust builder doesn't expose an `add_rnode` method yet, so the
    /// adapter pipes this config into the underlying
    /// `reticulum_std::config::InterfaceConfig` row via
    /// [`ReticulumTransport::add_interface`]'s internal config path.
    #[cfg(feature = "transport-reticulum-rnode")]
    RNode(RNodeInterfaceConfig),
    /// `I2PInterface` — anonymous overlay. Phase 3 per OQ-13; v0.12.0
    /// gates the variant but [`ReticulumTransport::add_interface`]
    /// returns [`TransportError::Config`] when handed one (no
    /// implementation yet — the feature gate exists so deployments can
    /// pin "this build is for I²P" without runtime success). Runtime
    /// support tracks community uptake.
    #[cfg(feature = "transport-reticulum-i2p")]
    I2p(I2pInterfaceConfig),
}

/// `AutoInterface` configuration. Mirrors leviculum's
/// `AutoInterfaceConfig` — group id (multicast network discriminator),
/// discovery scope (link / admin / site / organisation / global),
/// discovery / data ports, NIC whitelist/blacklist, multicast loopback.
///
/// All fields are `Option<_>` (or default-friendly types); a
/// `Default` impl yields leviculum's default group + scope.
#[cfg(feature = "transport-reticulum-auto")]
#[derive(Debug, Clone, Default)]
pub struct AutoInterfaceConfig {
    /// Multicast group identifier — peers with the same group id can
    /// discover each other on the LAN. Defaults to leviculum's group.
    pub group_id: Option<String>,
    /// Multicast discovery scope: `link` / `admin` / `site` /
    /// `organisation` / `global`. Defaults to `link`.
    pub discovery_scope: Option<String>,
    /// Discovery port (default 29716 per leviculum).
    pub discovery_port: Option<u16>,
    /// Data port (default 42671 per leviculum).
    pub data_port: Option<u16>,
    /// Comma-separated NIC names to bind to (`None` = all).
    pub devices: Option<String>,
    /// Comma-separated NIC names to ignore.
    pub ignored_devices: Option<String>,
    /// Enable multicast loopback (for same-machine testing).
    pub multicast_loopback: Option<bool>,
}

/// `TcpServerInterface` configuration — bind a TCP socket.
#[cfg(feature = "transport-reticulum-tcp-server")]
#[derive(Debug, Clone)]
pub struct TcpServerInterfaceConfig {
    /// Address the TCP server binds to.
    pub listen_addr: SocketAddr,
}

/// `TcpClientInterface` configuration — dial a remote TCP server.
#[cfg(feature = "transport-reticulum-tcp-client")]
#[derive(Debug, Clone)]
pub struct TcpClientInterfaceConfig {
    /// Target TCP server address to dial.
    pub target_addr: SocketAddr,
}

/// `UdpInterface` configuration — listen + forward addrs.
#[cfg(feature = "transport-reticulum-udp")]
#[derive(Debug, Clone)]
pub struct UdpInterfaceConfig {
    /// UDP address the interface listens on.
    pub listen_addr: SocketAddr,
    /// UDP address outgoing datagrams are sent to.
    pub forward_addr: SocketAddr,
}

/// `LocalInterface` configuration — AF_UNIX / named-pipe IPC. The
/// shared-instance pattern: one process runs a Local SERVER under a
/// named abstract socket; sibling processes CONNECT as clients to the
/// same name.
///
/// Mutually exclusive with `share_instance(true)` on the same builder
/// — leviculum errors if both are set; edge enforces the discipline by
/// surfacing the `is_server` flag here as the single addressable
/// configuration.
#[cfg(feature = "transport-reticulum-local")]
#[derive(Debug, Clone)]
pub struct LocalInterfaceConfig {
    /// Whether this transport is the Local SERVER (`true`) or a CLIENT
    /// connecting to an existing one (`false`).
    pub is_server: bool,
    /// Instance name — pins the abstract socket path to
    /// `\0rns/{instance_name}`. Defaults to leviculum's "default".
    pub instance_name: String,
}

/// `RNodeInterface` configuration — LoRa radio modem parameters.
/// Mirrors the RNode firmware's per-channel knobs.
#[cfg(feature = "transport-reticulum-rnode")]
#[derive(Debug, Clone)]
pub struct RNodeInterfaceConfig {
    /// Serial device path the RNode firmware speaks on (e.g.
    /// `/dev/ttyUSB0` Linux, `COM3` Windows).
    pub device_path: PathBuf,
    /// LoRa frequency in MHz (sub-GHz typical, ~868 EU / ~915 US).
    pub freq_mhz: f64,
    /// LoRa bandwidth in kHz (125 / 250 / 500).
    pub bw_khz: u32,
    /// LoRa spreading factor (7..=12). Higher = longer range, lower
    /// bitrate.
    pub sf: u8,
    /// LoRa coding rate (5..=8, mapped to 4/5 .. 4/8).
    pub cr: u8,
    /// TX power in dBm.
    pub txpower_dbm: i32,
    /// Optional baud rate to the RNode firmware over the serial line
    /// (default 115_200 if `None`).
    pub baud_rate: Option<u32>,
    /// Optional short-term airtime limit as percent (0.0..=100.0).
    pub airtime_limit_short_pct: Option<f64>,
    /// Optional long-term airtime limit as percent (0.0..=100.0).
    pub airtime_limit_long_pct: Option<f64>,
}

/// `I2PInterface` configuration — Phase 3 anonymous overlay; gate
/// exists but runtime support deferred. Empty config for now; the
/// shape lands when the implementation does.
#[cfg(feature = "transport-reticulum-i2p")]
#[derive(Debug, Clone, Default)]
pub struct I2pInterfaceConfig {
    /// Reserved for the I²P SAM bridge address; v0.12.0 ignored. Marked
    /// with `#[allow(dead_code)]` so the struct can land without warning.
    #[allow(dead_code)]
    pub sam_addr: Option<SocketAddr>,
}

/// Opaque handle to a registered Reticulum interface. Returned from
/// [`ReticulumTransport::add_interface`]; consumed by
/// [`ReticulumTransport::transport_stats`] to look up per-interface
/// stats. The `id` is the leviculum-assigned `InterfaceId` index — a
/// monotonically-increasing `usize` per node (the same identifier
/// leviculum's RPC handler uses to key per-interface counters).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InterfaceHandle(pub usize);

/// Per-interface stats — mirrors the shape of Python Reticulum's
/// `RNS.Reticulum.get_interface_stats()`. Per-interface: name, kind,
/// status, online, bitrate, mode, rx/tx bytes, hw_mtu, ifac size +
/// signature, plus radio-specific fields (RSSI / SNR / airtime / CPU /
/// battery) where the underlying interface produces them — `None`
/// otherwise.
///
/// The struct is the public typed surface; v0.13.0 UniFFI pymethod
/// wraps it (per CIRISEdge#24's "DO NOT add pymethods in this release
/// — those land in v0.13.0 under UniFFI" rule).
#[derive(Debug, Clone, PartialEq)]
pub struct TransportStats {
    /// Interface name (the leviculum-assigned name; matches
    /// `RNS.Reticulum.get_interface_stats()` "name" field).
    pub name: String,
    /// Interface kind: `"AutoInterface"` / `"TCPServerInterface"` /
    /// `"TCPClientInterface"` / `"UDPInterface"` / `"LocalInterface"` /
    /// `"RNodeInterface"` / `"I2PInterface"`. Matches leviculum's
    /// `InterfaceConfig::interface_type` string vocabulary.
    pub kind: String,
    /// Interface status — `"online"` / `"offline"` / `"unknown"`.
    pub status: String,
    /// Convenience boolean form of [`Self::status`] — `true` iff
    /// `status == "online"`.
    pub online: bool,
    /// On-air bitrate in bits/sec. `None` for interfaces without a
    /// fixed bitrate (e.g. TCP).
    pub bitrate_bps: Option<u64>,
    /// Interface mode — `"full"` / `"point_to_point"` / `"access_point"`
    /// / `"roaming"` / `"boundary"` / `"gateway"`.
    pub mode: String,
    /// Receive byte counter.
    pub rxb: u64,
    /// Transmit byte counter.
    pub txb: u64,
    /// Hardware MTU. `None` means the interface uses leviculum's base
    /// MTU (500).
    pub hw_mtu: Option<u32>,
    /// IFAC size in bytes (Interface Access Code; access-control
    /// envelope per interface). `None` when IFAC is disabled.
    pub ifac_size: Option<usize>,
    /// IFAC signature when configured (16-byte truncated SHA256 of the
    /// passphrase, base64). `None` when IFAC is disabled.
    pub ifac_signature: Option<String>,
    /// Last received RSSI in dBm — radio interfaces only. `None`
    /// elsewhere.
    pub rssi_dbm: Option<f64>,
    /// Last received SNR in dB — radio interfaces only.
    pub snr_db: Option<f64>,
    /// Long-term airtime usage percent (0.0..=100.0) — radio interfaces
    /// only.
    pub airtime_long_pct: Option<f64>,
    /// Short-term airtime usage percent (0.0..=100.0) — radio
    /// interfaces only.
    pub airtime_short_pct: Option<f64>,
    /// Modem CPU load percent (0.0..=100.0) — RNode only.
    pub cpu_load_pct: Option<f64>,
    /// Battery state-of-charge percent (0.0..=100.0) — radio interfaces
    /// with battery telemetry.
    pub battery_pct: Option<f64>,
}

impl TransportStats {
    /// Construct a "minimal" stats record — non-radio interface, no
    /// IFAC, no battery / airtime / RSSI. Used by the generic adapter
    /// path for TCP / UDP / Local / Auto.
    #[must_use]
    pub fn minimal(
        name: impl Into<String>,
        kind: impl Into<String>,
        status: impl Into<String>,
        rxb: u64,
        txb: u64,
    ) -> Self {
        let status_s: String = status.into();
        let online = status_s == "online";
        Self {
            name: name.into(),
            kind: kind.into(),
            status: status_s,
            online,
            bitrate_bps: None,
            mode: "full".to_string(),
            rxb,
            txb,
            hw_mtu: None,
            ifac_size: None,
            ifac_signature: None,
            rssi_dbm: None,
            snr_db: None,
            airtime_long_pct: None,
            airtime_short_pct: None,
            cpu_load_pct: None,
            battery_pct: None,
        }
    }
}

/// Spec for one configured interface — `InterfaceHandle` + the typed
/// kind that was registered. Lets the test surface assert the same
/// (id, kind) pair was produced by [`ReticulumTransport::add_interface`]
/// even when the underlying interface adapter is opaque.
#[derive(Debug, Clone)]
pub struct TransportSpec {
    /// The handle returned from [`ReticulumTransport::add_interface`].
    pub handle: InterfaceHandle,
    /// String kind label — matches [`TransportStats::kind`].
    pub kind: String,
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
    /// Edge's own announce attestation app-data — built once in
    /// `new` (sign with the federation `LocalSigner`) and emitted
    /// verbatim on every announce. `None` when no signer was
    /// supplied: the transport then cannot prove its own binding and
    /// announces an empty app-data (peers with rooting enabled will
    /// drop it — fail-honest).
    local_attestation: Option<Vec<u8>>,
    /// The node's single `NodeEvent` receiver. `listen` takes it
    /// exactly once; a second `listen` call is a config error.
    events: Mutex<Option<mpsc::Receiver<NodeEvent>>>,
    /// `key_id → rooted peer`, populated by the authenticated
    /// cold-start path from received announces. Every entry has been
    /// rooted against the persist directory + had its attestation
    /// signature verified. `send` consults this before the injected
    /// [`PeerResolver`].
    peers: Arc<Mutex<HashMap<String, RootedPeer>>>,
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
    /// Optional out-of-band directory-backed resolver. When `None`,
    /// only the authenticated announce cold-start path is available.
    resolver: Option<Arc<dyn PeerResolver>>,
    /// Persist `federation_keys` directory adapter for the
    /// authenticated cold-start path. When `None`, announce
    /// attestations cannot be rooted and announces are dropped — the
    /// transport then resolves peers only via the out-of-band
    /// [`PeerResolver`]. Required to close AV-42 on the announce path.
    rooting: Option<Arc<dyn RootingDirectory>>,
    /// Consumer-side hybrid PQC acceptance policy applied to a rooted
    /// peer's provenance chain (CIRISEdge#15 step 4). Mirrors the
    /// `HybridPolicy` edge's verify pipeline runs.
    hybrid_policy: HybridPolicy,
    /// CIRISEdge#34 — shared event bus. Drives the AsyncIterator
    /// surface (`subscribe_announces` / `subscribe_interface_events`)
    /// in `crate::ffi::pyo3`. `None` means a transport built with no
    /// observability bus (the v0.10.x default; back-compat).
    event_bus: Option<Arc<crate::events::EventBus>>,
    /// CIRISEdge#29 (v0.11.0) — per-medium reachability tracker. See
    /// [`ReticulumAuth::reachability`] for the contract; threaded
    /// through to the event loop's [`EventCtx`] so a rooted announce
    /// records an [`AttemptOutcome::AnnounceReceived`].
    reachability: Option<Arc<ReachabilityTracker>>,
    /// CIRISEdge#24 (v0.12.0) — typed registry of every interface
    /// that was wired into the underlying [`ReticulumNode`] via
    /// [`ReticulumTransportConfig::interfaces`]. Each entry pins
    /// `(InterfaceHandle, kind, stats)` so [`Self::transport_stats`] +
    /// [`Self::interface_specs`] can surface the configured set
    /// without re-reading leviculum's internal state.
    ///
    /// The handle's `usize` index is allocated by edge (monotonic per
    /// transport) rather than by leviculum — leviculum's internal
    /// `InterfaceId` is `pub(crate)` from `reticulum-core` and not
    /// stable on the public API. Edge's monotonic counter is the
    /// stable identifier the v0.13.0 UniFFI pymethod will hand back to
    /// Python; this v0.12.0 cut lets us pin it.
    interface_specs: Arc<std::sync::Mutex<Vec<RegisteredInterface>>>,
    /// CIRISEdge#32 (v0.14.0) — link establishment time tracking.
    /// `LinkId → established_at` (UTC unix seconds), populated by
    /// the event loop on `LinkEstablished` and removed on `LinkClosed`
    /// / `LinkStale`. Backs [`Self::link_list`]'s `age_seconds` field.
    link_established_at: Arc<Mutex<HashMap<LinkId, u64>>>,
    /// CIRISEdge#32 (v0.14.0) — request/response slot. The listen-loop
    /// populates this on `NodeEvent::ResponseReceived` keyed by
    /// `request_id`; [`Self::link_request`] polls + removes.
    request_responses: Arc<Mutex<HashMap<[u8; 16], Vec<u8>>>>,
    /// CIRISEdge#32 (v0.14.0) — typed timeout sentinel. The listen-loop
    /// populates this on `NodeEvent::RequestTimedOut`;
    /// [`Self::link_request`] surfaces the `Timeout` error when a
    /// `request_id` lands here. A `HashSet<[u8; 16]>` so multiple
    /// in-flight requests across links never collide.
    timed_out_requests: Arc<Mutex<HashSet<[u8; 16]>>>,
}

/// Internal registry entry behind [`ReticulumTransport::interface_specs`].
/// Pairs an [`InterfaceHandle`] with its spec + a stats snapshot
/// fixture (v0.12.0 stats are populated at registration time and not
/// live-updated — leviculum's per-interface byte counters are
/// `pub(crate)` and not surfaced on the public API, so the v0.12.0
/// `TransportStats` surface is the configured snapshot at registration
/// time; v0.13.0 UniFFI will widen this to live counters when
/// leviculum exposes the RPC `InterfaceStatsMap`).
#[derive(Debug, Clone)]
struct RegisteredInterface {
    handle: InterfaceHandle,
    kind: String,
    stats: TransportStats,
}

/// Federation-authentication wiring for [`ReticulumTransport`] — the
/// pieces the authenticated cold-start path (CIRISEdge#15) needs
/// beyond the bare [`ReticulumTransportConfig`].
///
/// All three handle fields are optional so a transport can run in a
/// reduced mode (e.g. a closed/trusted Reticulum network seeded
/// purely from a [`PeerResolver`]). To close **AV-42** on the
/// announce path, supply at least `signer` (so the transport can
/// attest its own binding) and `rooting` (so it can root incoming
/// announces). [`Default`] yields an all-`None` bundle with the
/// [`HybridPolicy::Strict`] production posture.
pub struct ReticulumAuth {
    /// The federation `LocalSigner` — used once at construction to
    /// sign edge's own announce attestation. The federation Ed25519
    /// key; never fed to Leviculum (AV-17). `None` → the transport
    /// announces empty app-data and rooting peers drop it.
    pub signer: Option<Arc<LocalSigner>>,
    /// The persist `federation_keys` directory adapter used to root
    /// incoming announce attestations. `None` → announces cannot be
    /// rooted and are dropped; peers resolve only via `resolver`.
    pub rooting: Option<Arc<dyn RootingDirectory>>,
    /// Out-of-band directory-seeded resolver (the v0.3.1 path).
    /// Independent of `rooting`; consulted by `send` after the
    /// rooted announce map.
    pub resolver: Option<Arc<dyn PeerResolver>>,
    /// Consumer-side hybrid PQC policy applied to a rooted peer's
    /// provenance chain. [`Default`] is [`HybridPolicy::Strict`] —
    /// the production posture, matching `EdgeConfig::default`.
    pub hybrid_policy: HybridPolicy,
    /// CIRISEdge#34 — optional shared event bus. When supplied, the
    /// transport emits `transport_up` / `transport_down` interface
    /// events at `listen` entry/exit, and `announce_received`
    /// (severity = info | warning per the cold-start verdict) for
    /// every announce processed by [`resolve_announce_cold_start`].
    /// `None` → no events emitted (back-compat for callers that don't
    /// care about the AsyncIterator surface).
    pub event_bus: Option<Arc<crate::events::EventBus>>,
    /// CIRISEdge#29 (v0.11.0) — per-medium reachability tracker. When
    /// `Some`, every successfully-rooted announce records an
    /// [`AttemptOutcome::AnnounceReceived`] against `(peer_key_id,
    /// TransportId::RETICULUM_RS)`. Passive reachability evidence —
    /// proof of liveness, not of delivery. Production wiring threads
    /// `edge.reachability_tracker()` here; tests omit (the field
    /// defaults to `None` so all existing Reticulum tests compile
    /// unchanged).
    pub reachability: Option<Arc<ReachabilityTracker>>,
}

impl Default for ReticulumAuth {
    fn default() -> Self {
        Self {
            signer: None,
            rooting: None,
            resolver: None,
            hybrid_policy: HybridPolicy::Strict,
            event_bus: None,
            reachability: None,
        }
    }
}

impl ReticulumTransport {
    /// Construct + start the transport: load-or-generate the
    /// transport identity, build the Leviculum node with the
    /// configured TCP interfaces, register edge's own federation
    /// destination, build edge's signed announce attestation, take
    /// the node's event receiver, and start the event loop.
    ///
    /// The node is running once this returns. [`Transport::listen`]
    /// drains its events; [`Transport::send`] uses it to dial peers.
    ///
    /// `auth` carries the federation-authentication wiring for the
    /// CIRISEdge#15 cold-start path — see [`ReticulumAuth`]. Pass
    /// `ReticulumAuth::default()` for a transport with no
    /// authenticated discovery (resolver-only / test loopback).
    // v0.12.0 (CIRISEdge#24) — function grew past clippy's 100-line cap
    // once the typed-interface application path landed alongside the
    // legacy TCP-server + bootstrap-clients path. The composition is
    // the construction-site contract: identity load + attestation build
    // + builder wiring + destination registration + event-loop setup
    // all run in lockstep here. Extracting them would fragment the
    // construction-time invariants without adding clarity, so the
    // gate is allowed locally.
    #[allow(clippy::too_many_lines)]
    pub async fn new(
        config: ReticulumTransportConfig,
        auth: ReticulumAuth,
    ) -> Result<Self, TransportError> {
        let ReticulumAuth {
            signer,
            rooting,
            resolver,
            hybrid_policy,
            event_bus,
            reachability,
        } = auth;

        let identity = load_or_generate_identity(&config.identity_path)?;

        // Build edge's own announce attestation: a federation-key
        // signature binding this transport identity to `local_key_id`
        // at `local_epoch` (CIRISEdge#15 send side). The transport
        // identity's Ed25519 public key is the ed25519 half (bytes
        // 32..64) of the dual-key identity.
        let mut transport_ed25519 = [0u8; 32];
        transport_ed25519.copy_from_slice(&identity.public_key_bytes()[32..64]);
        let local_attestation = if let Some(s) = &signer {
            Some(
                build_local_attestation(
                    s,
                    &transport_ed25519,
                    &config.local_key_id,
                    config.local_epoch,
                )
                .await?,
            )
        } else {
            tracing::warn!(
                "Reticulum transport built without a federation signer; \
                 its announce carries no attestation and rooting peers \
                 will drop it (AV-42 fail-honest)",
            );
            None
        };

        // Build the node. The transport identity is the node identity;
        // a per-process storage dir alongside the identity file holds
        // Leviculum's known-destinations / packet-hashlist state.
        let storage_path = config
            .identity_path
            .parent()
            .map_or_else(|| PathBuf::from("."), PathBuf::from)
            .join("reticulum_storage");

        // CIRISEdge#24 (v0.12.0) — apply typed interface set if the
        // operator supplied one; otherwise fall back to v0.11.x's TCP
        // server + TCP client legacy path (`add_tcp_server(listen_addr)`
        // + `add_tcp_client(bootstrap_peers[..])`). The registry tracks
        // what was wired so `transport_stats` + `interface_specs` can
        // surface the configured set.
        let mut interface_specs: Vec<RegisteredInterface> = Vec::new();
        let mut builder = ReticulumNodeBuilder::new()
            .identity(identity.clone())
            .storage_path(storage_path);
        let mut share_instance_local: Option<String> = None;
        let mut connect_instance_local: Option<String> = None;
        if config.interfaces.is_empty() {
            // Legacy v0.11.x defaults — TCP server + bootstrap TCP
            // clients. Registry records each one so the typed surface
            // is uniform.
            builder = builder.add_tcp_server(config.listen_addr);
            interface_specs.push(RegisteredInterface {
                handle: InterfaceHandle(interface_specs.len()),
                kind: "TCPServerInterface".to_string(),
                stats: TransportStats::minimal(
                    format!("tcp-server-{}", config.listen_addr),
                    "TCPServerInterface",
                    "online",
                    0,
                    0,
                ),
            });
            for peer in &config.bootstrap_peers {
                builder = builder.add_tcp_client(*peer);
                interface_specs.push(RegisteredInterface {
                    handle: InterfaceHandle(interface_specs.len()),
                    kind: "TCPClientInterface".to_string(),
                    stats: TransportStats::minimal(
                        format!("tcp-client-{peer}"),
                        "TCPClientInterface",
                        "online",
                        0,
                        0,
                    ),
                });
            }
        } else {
            // Typed v0.12.0 path — each `ReticulumInterfaceConfig`
            // variant maps onto a leviculum builder call (or surfaces
            // `TransportError::Config` if the variant is gated but
            // unimplemented, e.g. I²P).
            for iface in &config.interfaces {
                let (next_builder, kind, name) = apply_interface_config(
                    builder,
                    iface,
                    &mut share_instance_local,
                    &mut connect_instance_local,
                )?;
                builder = next_builder;
                interface_specs.push(RegisteredInterface {
                    handle: InterfaceHandle(interface_specs.len()),
                    kind: kind.to_string(),
                    stats: TransportStats::minimal(name, kind, "online", 0, 0),
                });
            }
        }
        if let Some(name) = share_instance_local.clone() {
            builder = builder.share_instance(true).instance_name(name);
        }
        if let Some(name) = connect_instance_local.clone() {
            builder = builder.connect_to_shared_instance(name);
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
            local_attestation,
            events: Mutex::new(Some(events)),
            peers: Arc::new(Mutex::new(HashMap::new())),
            established_links: Arc::new(Mutex::new(HashSet::new())),
            sent_resources: Arc::new(Mutex::new(HashSet::new())),
            resolver,
            rooting,
            hybrid_policy,
            event_bus,
            reachability,
            interface_specs: Arc::new(std::sync::Mutex::new(interface_specs)),
            link_established_at: Arc::new(Mutex::new(HashMap::new())),
            request_responses: Arc::new(Mutex::new(HashMap::new())),
            timed_out_requests: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    /// CIRISEdge#24 — snapshot every registered interface's typed
    /// spec. Returns a `Vec<TransportSpec>` of `(handle, kind)` pairs.
    /// Order matches the registration order in
    /// [`ReticulumTransportConfig::interfaces`] (or the legacy
    /// `add_tcp_server` + `add_tcp_client(bootstrap_peers)` order when
    /// no typed interfaces were supplied).
    #[must_use]
    pub fn interface_specs(&self) -> Vec<TransportSpec> {
        let specs = self
            .interface_specs
            .lock()
            .expect("interface_specs poisoned");
        specs
            .iter()
            .map(|r| TransportSpec {
                handle: r.handle,
                kind: r.kind.clone(),
            })
            .collect()
    }

    /// CIRISEdge#24 — typed [`TransportStats`] snapshot for one
    /// registered interface. Returns `None` if `handle` is not in the
    /// registry. v0.12.0 stats are populated at registration time and
    /// are NOT live-updated — leviculum's per-interface byte counters
    /// (`InterfaceCounters`) are `pub(crate)` from `reticulum-std` and
    /// not exposed on its public API. The v0.13.0 UniFFI cut will
    /// widen this to live counters when leviculum's RPC
    /// `InterfaceStatsMap` is surfaced; the wire shape of
    /// [`TransportStats`] is the v0.12.0 pin so consumers can hold a
    /// snapshot reference without churn at v0.13.0.
    #[must_use]
    pub fn transport_stats(&self, handle: InterfaceHandle) -> Option<TransportStats> {
        let specs = self
            .interface_specs
            .lock()
            .expect("interface_specs poisoned");
        specs
            .iter()
            .find(|r| r.handle == handle)
            .map(|r| r.stats.clone())
    }

    /// Whether `destination_key_id` has been resolved — either rooted
    /// from a received announce (authenticated cold-start path) or
    /// directory-resolvable via the out-of-band [`PeerResolver`].
    /// Primarily a test + diagnostics hook for confirming the
    /// authenticated discovery has converged before a `send`.
    pub async fn knows_peer(&self, destination_key_id: &str) -> bool {
        self.resolve_peer(destination_key_id).await.is_some()
    }

    /// v0.14.0 (CIRISEdge#32) — return the 16-byte Reticulum
    /// destination hash for a rooted peer. Test seam: the Links FFI
    /// tests need `dest_hash` to drive `link_open(dest_hash)` after
    /// rooting has converged. Production callers use `send(key_id, ...)`
    /// which threads the resolution internally; this accessor surfaces
    /// the dest_hash bytes by name so the test can decouple from the
    /// internal `ResolvedPeer` type.
    #[doc(hidden)]
    pub async fn peer_dest_hash_for_test(&self, destination_key_id: &str) -> Option<[u8; 16]> {
        self.resolve_peer(destination_key_id)
            .await
            .map(|p| p.dest_hash.into_bytes())
    }

    // ─── CIRISEdge#32 (v0.14.0) Links FFI surface ───────────────────
    //
    // The Reticulum link lifecycle is normally an internal substrate
    // concern that `send` drives end-to-end (resolve → connect →
    // wait-established → send_resource → wait-completed → drop). The
    // Links FFI surface elevates the lifecycle to operator-visible
    // primitives so a host (the UniFFI bindings consumer) can:
    //   - enumerate currently-active links (`link_list`)
    //   - count them (`link_count`)
    //   - explicitly establish + tear down a link to a destination
    //     (`open_link` / `teardown_link`)
    //   - send a request/response over a link (`request_on_link`).
    //
    // The lifecycle hooks the event loop already runs
    // (`handle_event::LinkRequest|LinkEstablished|LinkIdentified|LinkClosed|LinkStale`)
    // ALSO emit `LinkEvent`s on `event_bus.emit_link(...)` so the
    // `subscribe_link_events` AsyncIterator (closes the link half of
    // CIRISEdge#34) actually fires.

    /// Snapshot every link the event loop has seen reach `Active`.
    /// State is `Active` by definition (closed/stale links are removed
    /// from the established set). Each entry carries the negotiated
    /// MTU/MDU from leviculum's per-link accessor, the link
    /// establishment time (for `age_seconds`), and the transport id +
    /// kind (`"reticulum-rs"` / `"ReticulumTransport"`).
    ///
    /// v0.14.0 limitation: leviculum's RPC `LinkStats` surface
    /// (rssi/snr/establishment-rate) is `pub(crate)` from
    /// `reticulum-std`; the v0.14.0 FFI returns `None` for those
    /// fields. The wire shape is pinned so a v0.14.x flip to live
    /// values is non-breaking.
    pub async fn link_list(&self) -> Vec<crate::ffi::uniffi_types::EdgeLinkInfo> {
        use crate::ffi::uniffi_types::{EdgeLinkInfo, EdgeLinkState};
        let now_secs = u64::try_from(chrono::Utc::now().timestamp().max(0)).unwrap_or(0);
        let established = self.established_links.lock().await;
        let mut out = Vec::with_capacity(established.len());
        let established_at = self.link_established_at.lock().await;
        for link_id in established.iter() {
            let mtu = self.node.link_negotiated_mtu(link_id).unwrap_or(0);
            let mdu = self
                .node
                .link_mdu(link_id)
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(0);
            let peer_identity_hash = self
                .node
                .get_remote_identity(link_id)
                .map(|id| id.hash().to_vec())
                .unwrap_or_default();
            let age_seconds = established_at
                .get(link_id)
                .map_or(0, |t| now_secs.saturating_sub(*t));
            out.push(EdgeLinkInfo {
                link_id: link_id.as_bytes().to_vec(),
                peer_identity_hash,
                state: EdgeLinkState::Active,
                age_seconds,
                rssi_dbm: None,
                snr_db: None,
                establishment_rate_kbps: None,
                mtu,
                mdu,
                transport_id: TransportId::RETICULUM_RS.0.to_string(),
                transport_kind: "ReticulumTransport".to_string(),
            });
        }
        out
    }

    /// Number of currently-active links. Equivalent to
    /// `link_list().await.len()` but skips the per-link allocation.
    pub async fn link_count(&self) -> usize {
        self.established_links.lock().await.len()
    }

    /// Explicitly open a Reticulum Link to `destination_hash`. The
    /// underlying [`ReticulumNode::connect`] is invoked; this method
    /// then polls until the link reaches `LinkEstablished` on both
    /// ends (or the timeout fires). The peer's transport-tier signing
    /// key is sourced from the rooted-peer map — the destination must
    /// have already been rooted via the authenticated cold-start path
    /// (CIRISEdge#15) for this method to find its signing key.
    /// Otherwise returns `TransportError::Unreachable`.
    ///
    /// On success returns the established `LinkId` bytes. The link
    /// stays in the established set until a `LinkClosed` event arrives
    /// (peer-initiated close OR a [`Self::link_teardown`] call).
    pub async fn link_open(
        &self,
        destination_hash: &[u8],
        timeout: Duration,
    ) -> Result<[u8; 16], TransportError> {
        // Resolve the signing_key from rooted peers — we look up by
        // destination_hash (the rooted-peer map keys on key_id but
        // each entry carries the dest_hash). Linear scan; the rooted
        // map is small (federation member count).
        let dest_hash_array: [u8; 16] = destination_hash.try_into().map_err(|_| {
            TransportError::Config(format!(
                "destination_hash must be 16 bytes, got {}",
                destination_hash.len()
            ))
        })?;
        let dest_hash = DestinationHash::new(dest_hash_array);
        let signing_key = {
            let peers = self.peers.lock().await;
            peers
                .values()
                .find(|p| p.peer.dest_hash == dest_hash)
                .map(|p| p.peer.signing_key)
        };
        let Some(signing_key) = signing_key else {
            return Err(TransportError::Unreachable(format!(
                "no rooted peer known for destination_hash={dest_hash} \
                 (link_open requires a rooted announce; call link_open after \
                  subscribe_announces emits a peer-rooted event)"
            )));
        };

        let link = self
            .node
            .connect(&dest_hash, &signing_key)
            .await
            .map_err(|e| TransportError::Io(format!("reticulum connect: {e}")))?;
        let link_id = *link.link_id();

        let established = wait_until_async(timeout, Duration::from_millis(50), || async {
            self.established_links.lock().await.contains(&link_id)
        })
        .await;
        if !established {
            return Err(TransportError::Timeout(timeout));
        }
        Ok(link_id.into_bytes())
    }

    /// Tear down the link identified by `link_id`. Drains any
    /// in-flight requests (waits up to `RESOURCE_TRANSFER_TIMEOUT` for
    /// the sent-resources set to clear) then sends LINKCLOSE to the
    /// peer.
    ///
    /// Idempotent: a second call (or a call against a link the event
    /// loop has already removed) is a no-op that returns `Ok(())`.
    pub async fn link_teardown(&self, link_id_bytes: &[u8]) -> Result<(), TransportError> {
        let link_id_array: [u8; 16] = link_id_bytes.try_into().map_err(|_| {
            TransportError::Config(format!(
                "link_id must be 16 bytes, got {}",
                link_id_bytes.len()
            ))
        })?;
        let link_id = LinkId::new(link_id_array);

        // Idempotent — if the link isn't in the established set, the
        // peer already closed or we already tore it down.
        if !self.established_links.lock().await.contains(&link_id) {
            return Ok(());
        }

        // Best-effort drain — wait briefly for any pending sender-side
        // resource to drop out of `sent_resources`. The drain is
        // bounded so a wedged peer can't block teardown indefinitely.
        let _drained = wait_until_async(
            Duration::from_millis(500),
            Duration::from_millis(50),
            || async { self.sent_resources.lock().await.is_empty() },
        )
        .await;

        // close_link emits a LinkClosed event on the loop; the loop's
        // handle_event removes the link from `established_links`.
        let _ = self.node.close_link(&link_id).await;
        // Eagerly remove so a second teardown is the no-op above.
        self.established_links.lock().await.remove(&link_id);
        self.link_established_at.lock().await.remove(&link_id);
        Ok(())
    }

    /// Send a request over an established link and wait for the
    /// response. Blocking-style: the response arrives via a
    /// `NodeEvent::ResponseReceived` on the listener loop, which
    /// records it in a per-request-id slot keyed by the returned
    /// `request_id`. This method polls that slot.
    ///
    /// `data` is opaque bytes; leviculum re-wraps for msgpack on the
    /// wire. Returns the response bytes on success or
    /// `TransportError::Timeout` if no response arrives in `timeout`.
    pub async fn link_request(
        &self,
        link_id_bytes: &[u8],
        path: &str,
        data: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, TransportError> {
        let link_id_array: [u8; 16] = link_id_bytes.try_into().map_err(|_| {
            TransportError::Config(format!(
                "link_id must be 16 bytes, got {}",
                link_id_bytes.len()
            ))
        })?;
        let link_id = LinkId::new(link_id_array);

        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        let request_id = self
            .node
            .send_request(&link_id, path, Some(data), Some(timeout_ms))
            .await
            .map_err(|e| TransportError::Io(format!("reticulum send_request: {e}")))?;

        // Poll the per-request response slot. The listen-loop populates
        // `request_responses` on `ResponseReceived` and removes the
        // request_id from `pending_requests` on `RequestTimedOut`.
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            {
                let mut responses = self.request_responses.lock().await;
                if let Some(bytes) = responses.remove(&request_id) {
                    return Ok(bytes);
                }
            }
            {
                let mut timed = self.timed_out_requests.lock().await;
                if timed.remove(&request_id) {
                    return Err(TransportError::Timeout(timeout));
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(TransportError::Timeout(timeout));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Resolve a `destination_key_id` to a Reticulum peer. Consults
    /// the **rooted** announce map first (every entry has cleared the
    /// CIRISEdge#15 cold-start path), then the out-of-band injected
    /// [`PeerResolver`]. Returns `None` if neither yields the peer.
    async fn resolve_peer(&self, destination_key_id: &str) -> Option<ResolvedPeer> {
        if let Some(rooted) = self.peers.lock().await.get(destination_key_id) {
            return Some(rooted.peer);
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

        // CIRISEdge#34 — emit `transport_up` interface event. Consumers
        // subscribed via `PyEdge.subscribe_interface_events()` observe
        // the moment the transport reaches listening state.
        if let Some(bus) = self.event_bus.as_ref() {
            bus.emit_interface(crate::events::NetworkEvent::interface(
                crate::events::EventKind::TransportUp,
                "reticulum-rs",
                format!(
                    "Reticulum transport listening on {} (dest {})",
                    self.config.listen_addr, self.local_dest_hash
                ),
            ));
        }

        // Announce edge's own destination on startup, then on a timer.
        // The app-data is edge's signed announce attestation
        // (CIRISEdge#15 send side) — a federation-key signature
        // binding this transport identity to `local_key_id`. When no
        // signer was supplied the announce carries empty app-data and
        // rooting peers drop it (fail-honest).
        let app_data: &[u8] = self.local_attestation.as_deref().unwrap_or(&[]);
        if let Err(e) = self
            .node
            .announce_destination(&self.local_dest_hash, Some(app_data))
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
                        .announce_destination(&self.local_dest_hash, Some(app_data))
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
                        rooting: self.rooting.as_deref(),
                        hybrid_policy: self.hybrid_policy,
                        event_bus: self.event_bus.as_deref(),
                        reachability: self.reachability.as_ref(),
                        link_established_at: &self.link_established_at,
                        request_responses: &self.request_responses,
                        timed_out_requests: &self.timed_out_requests,
                    };
                    handle_event(event, &ctx).await;
                }
            }
        }

        // CIRISEdge#34 — emit `transport_down` interface event on
        // listener exit. Symmetric with the `transport_up` emission
        // above; consumers observe shutdown via the same channel.
        if let Some(bus) = self.event_bus.as_ref() {
            bus.emit_interface(crate::events::NetworkEvent::interface(
                crate::events::EventKind::TransportDown,
                "reticulum-rs",
                "Reticulum transport listen loop exited",
            ));
        }

        Ok(())
    }
}

/// Shared handles the event loop hands to [`handle_event`].
struct EventCtx<'a> {
    node: &'a ReticulumNode,
    peers: &'a Mutex<HashMap<String, RootedPeer>>,
    established_links: &'a Mutex<HashSet<LinkId>>,
    sent_resources: &'a Mutex<HashSet<[u8; 32]>>,
    sink: &'a mpsc::Sender<InboundFrame>,
    /// Persist directory adapter for the authenticated cold-start
    /// path; `None` → announces are dropped (no rooting possible).
    rooting: Option<&'a dyn RootingDirectory>,
    /// Consumer hybrid PQC policy applied to a rooted chain.
    hybrid_policy: HybridPolicy,
    /// CIRISEdge#34 — shared event bus for announce / interface
    /// emissions. `None` → no events emitted (the transport was
    /// constructed without `ReticulumAuth::event_bus`).
    event_bus: Option<&'a crate::events::EventBus>,
    /// CIRISEdge#29 — per-medium reachability tracker. `Some` →
    /// every successfully-rooted announce records an
    /// `AttemptOutcome::AnnounceReceived` against `(peer_key_id,
    /// TransportId::RETICULUM_RS)`.
    reachability: Option<&'a Arc<ReachabilityTracker>>,
    /// CIRISEdge#32 (v0.14.0) — link establishment timestamps,
    /// populated on `LinkEstablished` / cleared on `LinkClosed` /
    /// `LinkStale`.
    link_established_at: &'a Mutex<HashMap<LinkId, u64>>,
    /// CIRISEdge#32 (v0.14.0) — per-request response slot, populated
    /// on `NodeEvent::ResponseReceived`.
    request_responses: &'a Mutex<HashMap<[u8; 16], Vec<u8>>>,
    /// CIRISEdge#32 (v0.14.0) — per-request timeout sentinel,
    /// populated on `NodeEvent::RequestTimedOut`.
    timed_out_requests: &'a Mutex<HashSet<[u8; 16]>>,
}

/// Handle one [`NodeEvent`]. Announce events populate the peer map;
/// link requests are accepted with auto-resource-accept; established
/// links + completed sender-side resources unblock [`Transport::send`];
/// completed receiver-side resources become [`InboundFrame`]s.
// v0.14.0 (CIRISEdge#32 + #34 link-half) — grew past clippy's 100-line
// cap once the LinkIdentified / LinkStale / ResponseReceived /
// RequestTimedOut arms + the link-event emissions on existing arms
// landed. Each new arm is a small typed routing of one NodeEvent
// variant onto a side-effect (record / emit); extracting would
// fragment the event-loop verdict across multiple helpers.
#[allow(clippy::too_many_lines)]
async fn handle_event(event: NodeEvent, ctx: &EventCtx<'_>) {
    match event {
        NodeEvent::AnnounceReceived { announce, .. } => {
            // The announce app-data carries the peer's signed
            // attestation. Run the authenticated cold-start path —
            // root the federation key, verify the attestation
            // signature, apply the hybrid policy — before the peer
            // is recorded as resolvable. This replaces v0.3.1's
            // trust-on-first-use (CIRISEdge#15, AV-42).
            resolve_announce_cold_start(&announce, ctx).await;
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
            // CIRISEdge#32 (v0.14.0) — record establish time for the
            // Links FFI surface's `age_seconds` derivation.
            let now_secs = u64::try_from(chrono::Utc::now().timestamp().max(0)).unwrap_or(0);
            ctx.link_established_at
                .lock()
                .await
                .insert(link_id, now_secs);
            // CIRISEdge#34 link half (v0.14.0) — emit `link_established`
            // event on the link channel. The bus is fire-and-forget;
            // no subscriber attached → drop silently.
            if let Some(bus) = ctx.event_bus {
                bus.emit_link(link_event(
                    crate::events::EventKind::LinkEstablished,
                    &link_id,
                    None,
                    crate::events::EventSeverity::Info,
                    "link established",
                ));
            }
        }
        NodeEvent::LinkIdentified {
            link_id,
            identity_hash,
        } => {
            // CIRISEdge#34 link half (v0.14.0) — emit `link_identified`
            // event with the peer's truncated identity hash. The peer
            // proved its identity over an already-established link via
            // LINKIDENTIFY; `get_remote_identity(link_id)` now returns
            // Some(_).
            if let Some(bus) = ctx.event_bus {
                use std::fmt::Write as _;
                let mut peer_id_hex = String::with_capacity(identity_hash.len().saturating_mul(2));
                for b in &identity_hash {
                    let _ = write!(peer_id_hex, "{b:02x}");
                }
                bus.emit_link(link_event(
                    crate::events::EventKind::LinkEstablished, // closest existing kind
                    &link_id,
                    Some(peer_id_hex),
                    crate::events::EventSeverity::Info,
                    "link identified",
                ));
            }
        }
        NodeEvent::LinkStale { link_id } => {
            // Bookkeeping cleanup + emit. The link may still be in
            // `established_links` (leviculum hasn't yet seen LinkClosed
            // arrive); leave the set alone — `LinkClosed` is the
            // authoritative removal point — but surface the staleness
            // on the event stream so the UI can render a warning.
            if let Some(bus) = ctx.event_bus {
                bus.emit_link(link_event(
                    crate::events::EventKind::LinkDropped,
                    &link_id,
                    None,
                    crate::events::EventSeverity::Warning,
                    "link became stale",
                ));
            }
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
            ctx.link_established_at.lock().await.remove(&link_id);
            tracing::debug!(link = ?link_id, reason = ?reason, "link closed");
            // CIRISEdge#34 link half (v0.14.0) — emit `link_closed`
            // event. Severity reflects whether the close was graceful.
            if let Some(bus) = ctx.event_bus {
                let severity = match reason {
                    reticulum_core::link::LinkCloseReason::Normal => {
                        crate::events::EventSeverity::Info
                    }
                    _ => crate::events::EventSeverity::Warning,
                };
                bus.emit_link(link_event(
                    crate::events::EventKind::LinkDropped,
                    &link_id,
                    None,
                    severity,
                    format!("link closed: {reason:?}"),
                ));
            }
        }
        NodeEvent::ResponseReceived {
            request_id,
            response_data,
            ..
        } => {
            // CIRISEdge#32 (v0.14.0) — feed the per-request response
            // slot the link_request poller reads.
            ctx.request_responses
                .lock()
                .await
                .insert(request_id, response_data);
        }
        NodeEvent::RequestTimedOut { request_id, .. } => {
            ctx.timed_out_requests.lock().await.insert(request_id);
        }
        other => {
            tracing::trace!(event = ?other, "unhandled Reticulum event");
        }
    }
}

/// Build a [`NetworkEvent`] populated with link-event fields. Helper
/// for the v0.14.0 CIRISEdge#34 link-half wiring — keeps the
/// `handle_event` arms' ceremony low.
fn link_event(
    kind: crate::events::EventKind,
    link_id: &LinkId,
    peer_key_id: Option<String>,
    severity: crate::events::EventSeverity,
    message: impl Into<String>,
) -> crate::events::NetworkEvent {
    crate::events::NetworkEvent {
        at: Utc::now(),
        kind,
        message: message.into(),
        peer_key_id,
        transport_id: Some(TransportId::RETICULUM_RS.0.to_string()),
        severity,
        aspect: None,
        identity_hash: None,
        app_data: None,
        rssi_dbm: None,
        snr_db: None,
        link_id: Some(link_id.as_bytes().to_vec()),
        lagged_count: None,
    }
}

// ─── Authenticated cold-start path (CIRISEdge#15 / AV-42) ──────────

/// Run the authenticated `PeerResolver` cold-start path on a received
/// announce. This is the **AV-42 mitigation** — it replaces v0.3.1's
/// trust-on-first-use announce-recording.
///
/// Steps (the locked CIRISEdge#15 design — persist v1.12.0
/// `root_binding`):
///
/// 1. Parse the [`AnnounceAttestation`] from the announce app-data.
///    A v0.3.1 bare-`key_id` announce, or any non-attestation
///    app-data, fails to parse and is dropped.
/// 2. `root_binding(directory, key_id, claimed_ed25519_pubkey)` —
///    a `Rejected` verdict drops the announce. `DirectoryError` is
///    retryable (the peer is *not* blacklisted — a transient backend
///    fault is not a statement about the binding); the seven
///    structural/crypto rejections are terminal and logged as AV-42
///    events.
/// 3. Verify the attestation signature over
///    `{transport_identity_pubkey, key_id, epoch}` against the
///    now-directory-confirmed Ed25519 pubkey. A forgery fails here.
/// 4. Apply the consumer [`HybridPolicy`] to the rooted provenance
///    chain — `Strict` rejects any hybrid-pending link.
/// 5. Record `key_id → transport identity` as a [`RootedPeer`] and
///    cache the [`ProvenanceChain`].
///
/// A drop at any step leaves the peer map untouched: `send` will
/// surface [`TransportError::Unreachable`] for that `key_id` rather
/// than route to an unauthenticated destination.
// v0.11.0 merge: function grew past clippy's 100-line cap once the
// CIRISEdge#34 announce-event emission and the CIRISEdge#29
// reachability-tracker hook were both layered into the rooted-success
// arm. Each emission is a small, related side-effect on the same
// successful-root verdict; extracting them into a helper would
// fragment the cold-start verdict logic without adding clarity, so
// the gate is allowed locally rather than refactored across the
// merge boundary.
#[allow(clippy::too_many_lines)]
async fn resolve_announce_cold_start(
    announce: &reticulum_core::ReceivedAnnounce,
    ctx: &EventCtx<'_>,
) {
    // Step 0 — the cold-start path needs the persist directory. With
    // no rooting backend the announce cannot be authenticated; drop
    // it (fail-honest — never fall back to TOFU).
    let Some(rooting) = ctx.rooting else {
        tracing::debug!("announce dropped: no rooting directory configured");
        return;
    };

    // Step 1 — parse the attestation from the announce app-data.
    let attestation = match AnnounceAttestation::from_app_data(announce.app_data()) {
        Ok(a) => a,
        Err(e) => {
            tracing::debug!(error = %e, "announce dropped: app-data is not a valid attestation");
            // CIRISEdge#34 — surface the parse failure on the announce
            // stream so operators can see malformed peers without
            // tailing logs. Severity = warning (not error): this is
            // commonly a v0.3.1 peer sending a bare-key_id announce,
            // not a hostile event.
            if let Some(bus) = ctx.event_bus {
                bus.emit_announce(crate::events::NetworkEvent::announce(
                    None,
                    announce.destination_hash().as_bytes().to_vec(),
                    announce.app_data().to_vec(),
                    crate::events::EventSeverity::Warning,
                    format!("announce dropped: app-data is not a valid attestation: {e}"),
                ));
            }
            return;
        }
    };
    let key_id = attestation.federation_key_id.clone();

    // Step 2 — root the federation key against the persist directory.
    let verdict = rooting
        .root_binding(&key_id, &attestation.federation_pubkey_ed25519_base64)
        .await;
    let chain = match verdict {
        RootingVerdict::Confirmed { chain } => chain,
        RootingVerdict::Rejected { rejection } => {
            // DirectoryError is a transient substrate fault — retryable,
            // not a verdict on the binding. The other seven variants
            // are terminal structural/crypto rejections: AV-42 events.
            if matches!(rejection, RootingRejection::DirectoryError { .. }) {
                tracing::warn!(
                    key_id = %key_id,
                    kind = rejection.kind(),
                    "announce rooting deferred: directory error (retryable, peer not blacklisted)",
                );
            } else {
                tracing::warn!(
                    av = "AV-42",
                    key_id = %key_id,
                    kind = rejection.kind(),
                    "announce rejected: federation key did not root \
                     (spoofed transport-identity ↔ federation-key binding)",
                );
            }
            return;
        }
    };

    // Step 3 — verify the attestation signature against the Ed25519
    // pubkey the directory just confirmed (NOT the wire claim).
    if !attestation_verifies_against_chain(&attestation, &chain, &key_id) {
        return;
    }

    // Step 4 — apply the consumer hybrid PQC policy to the rooted
    // chain. `Strict` rejects a chain with any hybrid-pending link;
    // `Ed25519Fallback` accepts the Confirmed verdict as-is;
    // `SoftFreshness` accepts it (the freshness window is a per-row
    // age input the announce path does not carry — consistent with
    // verify.rs's `row_age = None` treatment, which collapses
    // `SoftFreshness` to "accept the rooted chain").
    if !hybrid_policy_accepts(ctx.hybrid_policy, &chain) {
        tracing::warn!(
            key_id = %key_id,
            policy = ?ctx.hybrid_policy,
            "announce rejected: rooted provenance chain is hybrid-pending under Strict policy",
        );
        return;
    }

    // Step 5 — record the rooted resolution. A strictly-newer epoch
    // supersedes a cached binding; an equal-or-older epoch is a stale
    // re-announce and is ignored (keeps the cached chain).
    let transport_pubkey = match attestation.transport_identity_pubkey_bytes() {
        Ok(pk) => pk,
        Err(e) => {
            tracing::warn!(av = "AV-42", key_id = %key_id, error = %e,
                "announce rejected: transport-identity pubkey malformed");
            return;
        }
    };
    let resolved = ResolvedPeer {
        dest_hash: *announce.destination_hash(),
        signing_key: transport_pubkey,
    };
    let mut peers = ctx.peers.lock().await;
    match peers.get(&key_id) {
        Some(existing) if existing.epoch >= attestation.epoch => {
            tracing::trace!(
                key_id = %key_id,
                cached_epoch = existing.epoch,
                announce_epoch = attestation.epoch,
                "stale re-announce ignored (epoch not newer)",
            );
        }
        _ => {
            tracing::info!(
                key_id = %key_id,
                dest = %resolved.dest_hash,
                epoch = attestation.epoch,
                "peer ROOTED via authenticated cold-start path",
            );
            // CIRISEdge#29 (v0.11.0) — record passive-evidence
            // reachability against the (peer, RETICULUM_RS) tuple.
            // Logged BEFORE the event emission and the peer-map
            // insert so a tracker-only consumer observes liveness
            // even if a later panic prevents the insert; the
            // tracker / event / peer-map writes are logically
            // independent (the tracker is observability, the peer
            // map is routing).
            if let Some(tracker) = ctx.reachability {
                tracker.record_attempt(
                    &key_id,
                    TransportId::RETICULUM_RS,
                    AttemptOutcome::AnnounceReceived,
                );
            }
            // CIRISEdge#34 — successful root → emit announce_received
            // event with info severity. The peer key_id is now known
            // to be authentic; surface it on the announce stream so
            // the UI can render "peer X joined".
            if let Some(bus) = ctx.event_bus {
                bus.emit_announce(crate::events::NetworkEvent::announce(
                    Some(key_id.clone()),
                    announce.destination_hash().as_bytes().to_vec(),
                    announce.app_data().to_vec(),
                    crate::events::EventSeverity::Info,
                    format!(
                        "peer rooted via authenticated cold-start path (epoch {})",
                        attestation.epoch
                    ),
                ));
            }
            peers.insert(
                key_id,
                RootedPeer {
                    peer: resolved,
                    epoch: attestation.epoch,
                    chain,
                },
            );
        }
    }
}

/// Verify the announce attestation signature against the **Ed25519
/// pubkey the persist directory confirmed** for `key_id` — the leaf
/// of the rooted provenance `chain`, never the pubkey the announce
/// claimed (CIRISEdge#15 step 3). Returns `false` (logging an AV-42
/// event) on any failure; the caller drops the announce.
fn attestation_verifies_against_chain(
    attestation: &AnnounceAttestation,
    chain: &ProvenanceChain,
    key_id: &str,
) -> bool {
    // The rooted chain's leaf (`chain[0]`) is the queried row; its
    // `pubkey_ed25519_base64` is the directory's confirmed pubkey.
    // `root_binding` already proved this equals the claimed pubkey,
    // so the chain leaf is always present and authoritative.
    let Some(leaf) = chain.chain.first() else {
        tracing::warn!(
            av = "AV-42",
            key_id,
            "announce rejected: rooted chain has no leaf"
        );
        return false;
    };
    let confirmed_pubkey = base64::engine::general_purpose::STANDARD
        .decode(&leaf.pubkey_ed25519_base64)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok());
    let Some(confirmed_pubkey) = confirmed_pubkey else {
        tracing::warn!(
            av = "AV-42",
            key_id,
            "announce rejected: directory-confirmed pubkey is not 32-byte base64",
        );
        return false;
    };
    if let Err(e) = attestation.verify_signature(&confirmed_pubkey) {
        tracing::warn!(
            av = "AV-42",
            key_id,
            error = %e,
            "announce rejected: attestation signature did not verify \
             against the directory-confirmed federation key",
        );
        return false;
    }
    true
}

/// Whether `policy` accepts a rooted provenance `chain` (CIRISEdge#15
/// step 4).
///
/// - `Strict` — every [`ProvenanceLink`] must be hybrid-complete:
///   reject if any link has `pubkey_ml_dsa_65_base64 == None` or
///   `scrub_signature_pqc == None` (a hybrid-pending row).
/// - `Ed25519Fallback` — accept the `Confirmed` verdict as-is; the
///   Ed25519-rooted chain is sufficient.
/// - `SoftFreshness { window }` — the freshness window is a per-row
///   age input the announce path does not carry, so this collapses
///   to "accept the rooted chain", consistent with `verify.rs`'s
///   documented `row_age = None` treatment of `SoftFreshness`.
///
/// [`ProvenanceLink`]: crate::verify::ProvenanceLink
fn hybrid_policy_accepts(policy: HybridPolicy, chain: &ProvenanceChain) -> bool {
    match policy {
        HybridPolicy::Strict => chain.chain.iter().all(|link| {
            link.pubkey_ml_dsa_65_base64.is_some() && link.scrub_signature_pqc.is_some()
        }),
        HybridPolicy::Ed25519Fallback | HybridPolicy::SoftFreshness { .. } => true,
    }
}

/// Build edge's own announce attestation app-data — the CIRISEdge#15
/// send side. Signs `{transport_identity_pubkey, key_id, epoch}` with
/// the federation [`LocalSigner`]'s Ed25519 (classical) key and packs
/// the result as [`AnnounceAttestation`] JSON.
///
/// The federation Ed25519 public key is read from the signer's
/// `HardwareSigner`; it never feeds Leviculum (AV-17). Returns the
/// announce app-data bytes.
async fn build_local_attestation(
    signer: &LocalSigner,
    transport_identity_pubkey: &[u8; 32],
    federation_key_id: &str,
    epoch: u64,
) -> Result<Vec<u8>, TransportError> {
    let fed_pubkey = signer
        .classical
        .public_key()
        .await
        .map_err(|e| TransportError::Config(format!("federation pubkey: {e}")))?;
    if fed_pubkey.len() != 32 {
        return Err(TransportError::Config(format!(
            "federation Ed25519 pubkey must be 32 bytes, got {}",
            fed_pubkey.len()
        )));
    }

    let payload = AttestationPayload::new(transport_identity_pubkey, federation_key_id, epoch);
    let signature = signer
        .classical
        .sign(&payload.canonical_bytes())
        .await
        .map_err(|e| TransportError::Config(format!("attestation sign: {e}")))?;

    let attestation = AnnounceAttestation {
        transport_identity_pubkey: base64::engine::general_purpose::STANDARD
            .encode(transport_identity_pubkey),
        federation_key_id: federation_key_id.to_string(),
        federation_pubkey_ed25519_base64: base64::engine::general_purpose::STANDARD
            .encode(&fed_pubkey),
        epoch,
        signature: base64::engine::general_purpose::STANDARD.encode(&signature),
    };
    attestation
        .to_app_data()
        .map_err(|e: AttestationError| TransportError::Config(format!("attestation encode: {e}")))
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

// ─── Interface-config adapter (CIRISEdge#24) ────────────────────────

/// Apply one [`ReticulumInterfaceConfig`] variant to the leviculum
/// builder. Returns the updated builder, the wire-level "kind" string
/// (matches [`TransportStats::kind`]), and the human-readable name
/// the stats record will carry. Local-interface variants signal
/// share/connect-instance state out-of-band via the two mutable
/// `Option<String>` parameters since leviculum's share-instance is
/// configured via separate builder methods rather than the interface
/// vec.
#[allow(unused_variables, unused_mut)]
// every variant arm is feature-gated
// v0.12.0 (CIRISEdge#24) — the match arms cover seven feature-gated
// interface kinds; each arm carries its own builder + name + spec
// derivation. The composition is what `apply_interface_config` IS;
// fragmenting it across per-kind helpers would require duplicating
// the (builder, &'static str, String) return shape at every site.
#[allow(clippy::too_many_lines)]
fn apply_interface_config(
    mut builder: ReticulumNodeBuilder,
    iface: &ReticulumInterfaceConfig,
    share_instance: &mut Option<String>,
    connect_instance: &mut Option<String>,
) -> Result<(ReticulumNodeBuilder, &'static str, String), TransportError> {
    match iface {
        #[cfg(feature = "transport-reticulum-auto")]
        ReticulumInterfaceConfig::Auto(cfg) => {
            use reticulum_std::interfaces::auto_interface::AutoInterfaceConfig as LevAuto;
            let mut lev = LevAuto::default();
            if let Some(group_id) = &cfg.group_id {
                lev.group_id = group_id.as_bytes().to_vec();
            }
            if let Some(scope) = &cfg.discovery_scope {
                lev.discovery_scope.clone_from(scope);
            }
            if let Some(p) = cfg.discovery_port {
                lev.discovery_port = p;
            }
            if let Some(p) = cfg.data_port {
                lev.data_port = p;
            }
            lev.allowed_devices.clone_from(&cfg.devices);
            lev.ignored_devices.clone_from(&cfg.ignored_devices);
            if let Some(loopback) = cfg.multicast_loopback {
                lev.multicast_loopback = loopback;
            }
            builder = builder.add_auto_interface_with_config(lev);
            Ok((builder, "AutoInterface", "auto".to_string()))
        }
        #[cfg(feature = "transport-reticulum-tcp-server")]
        ReticulumInterfaceConfig::TcpServer(cfg) => {
            let name = format!("tcp-server-{}", cfg.listen_addr);
            builder = builder.add_tcp_server(cfg.listen_addr);
            Ok((builder, "TCPServerInterface", name))
        }
        #[cfg(feature = "transport-reticulum-tcp-client")]
        ReticulumInterfaceConfig::TcpClient(cfg) => {
            let name = format!("tcp-client-{}", cfg.target_addr);
            builder = builder.add_tcp_client(cfg.target_addr);
            Ok((builder, "TCPClientInterface", name))
        }
        #[cfg(feature = "transport-reticulum-udp")]
        ReticulumInterfaceConfig::Udp(cfg) => {
            let name = format!("udp-{}", cfg.listen_addr);
            builder = builder.add_udp_interface(cfg.listen_addr, cfg.forward_addr);
            Ok((builder, "UDPInterface", name))
        }
        #[cfg(feature = "transport-reticulum-local")]
        ReticulumInterfaceConfig::Local(cfg) => {
            // Leviculum's Local interface is wired via share_instance /
            // connect_to_shared_instance on the builder; the abstract
            // socket path is `\0rns/{instance_name}`. Server side runs
            // share_instance(true) + instance_name; client side runs
            // connect_to_shared_instance(name). The two are mutually
            // exclusive on one builder (leviculum errors if both are set
            // — we surface that as `TransportError::Config`).
            if cfg.is_server {
                if connect_instance.is_some() {
                    return Err(TransportError::Config(
                        "Local interface conflict: \
                         transport is configured as both Local server and \
                         Local client (mutually exclusive on one node)"
                            .into(),
                    ));
                }
                *share_instance = Some(cfg.instance_name.clone());
            } else {
                if share_instance.is_some() {
                    return Err(TransportError::Config(
                        "Local interface conflict: \
                         transport is configured as both Local server and \
                         Local client (mutually exclusive on one node)"
                            .into(),
                    ));
                }
                *connect_instance = Some(cfg.instance_name.clone());
            }
            let name = format!(
                "local-{}-{}",
                if cfg.is_server { "server" } else { "client" },
                cfg.instance_name,
            );
            Ok((builder, "LocalInterface", name))
        }
        #[cfg(feature = "transport-reticulum-rnode")]
        ReticulumInterfaceConfig::RNode(cfg) => {
            // Leviculum's Rust builder doesn't expose `add_rnode_interface`
            // yet — RNode is reachable from leviculum but only via
            // `InterfaceConfig` rows in a config file. Once leviculum
            // grows a typed builder method (tracked upstream), this arm
            // switches to it. Until then we surface a typed config
            // error so the v0.12.0 wiring is honest: the gate exists,
            // the runtime path requires upstream support.
            //
            // The config struct is still parsed + recorded so a downstream
            // bridge (e.g. a build-side script that produces a Reticulum
            // INI config from edge config) can consume it.
            let _ = (cfg.device_path.clone(), cfg.freq_mhz, cfg.bw_khz);
            Err(TransportError::Config(format!(
                "RNode interface configured ({} @ {} MHz, SF{}/CR{}/BW{}kHz, {} dBm) \
                 but leviculum's Rust builder does not yet expose `add_rnode_interface` \
                 — RNode currently requires a leviculum INI config file. \
                 Feature gate exists for v0.12.0 typed surface compatibility; runtime \
                 wiring lands when upstream surfaces the builder method.",
                cfg.device_path.display(),
                cfg.freq_mhz,
                cfg.sf,
                cfg.cr,
                cfg.bw_khz,
                cfg.txpower_dbm,
            )))
        }
        #[cfg(feature = "transport-reticulum-i2p")]
        ReticulumInterfaceConfig::I2p(cfg) => {
            // Phase 3 per OQ-13 — the gate is on but no runtime path
            // exists yet. Surface a typed config error so builds with
            // the gate enabled fail at construction (not at first
            // packet) when an I²P interface is supplied.
            let _ = cfg.sam_addr;
            Err(TransportError::Config(
                "I²P interface configured but Phase 3 runtime is not yet implemented; \
                 the feature gate exists for v0.12.0 typed surface compatibility only. \
                 See FSD §1.4 OQ-13 for the Phase 3 roadmap."
                    .into(),
            ))
        }
    }
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
