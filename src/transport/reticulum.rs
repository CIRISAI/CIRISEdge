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
use reticulum_std::driver::{EventReceiver, ReticulumNode, ReticulumNodeBuilder};
use reticulum_std::NodeEvent;

use super::attestation::{
    AnnounceAttestation, AttestationError, AttestationPayload, TransportBindingEnforcement,
};
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
/// giving up and surfacing [`TransportError::Timeout`]. Applies when the
/// node **holds a path** to the target — a relayed path can legitimately be
/// slow (LoRa, multi-hop), so it gets the full patient window.
const LINK_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(30);

/// CIRISEdge#336 — the establishment window for a target the node has **no
/// path** to. This is not a guess: leviculum's `connect` builds a
/// no-path link request with `hops = 1` and *broadcasts* it, so the only
/// thing that can answer is a **directly-attached** neighbor on a live
/// interface — which replies in a single interface round-trip. A
/// relay-reachable peer would have produced a path-table entry (from its
/// announce) and taken the [`LINK_ESTABLISH_TIMEOUT`] branch instead.
/// Therefore, if a no-path link request has not established within this
/// window, no amount of further waiting helps: there is no route. We fail
/// fast with the self-diagnosing [`TransportError::NoRouteToPeer`] rather
/// than stalling the full 30 s and surfacing an opaque timeout. The window
/// is sized with a wide margin over any real direct link (localhost is
/// sub-millisecond; internet-RTT direct TCP is tens of ms) so a genuinely
/// directly-reachable peer — e.g. a `prime_peer`'d bootstrap peer that
/// never announced — is never regressed.
const NO_PATH_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(5);

/// How long [`Transport::send`] waits for a resource transfer to
/// complete after the link is up.
const RESOURCE_TRANSFER_TIMEOUT: Duration = Duration::from_secs(120);

/// CIRISEdge#353 — the classified outcome of shipping a resource on a link.
/// `Busy` is the retryable one-transfer-per-link collision
/// (`ResourceError::TransferInProgress`); `Other` is any other send failure.
enum ShipError {
    /// A resource transfer is already in progress on this link — retryable; the
    /// link is healthy and the in-flight transfer drains in seconds.
    Busy,
    /// Any other send failure — not retryable on the same link.
    Other(TransportError),
}

impl ShipError {
    /// Collapse to a plain [`TransportError`] where the busy/other distinction
    /// doesn't matter (the outbound-dial path — the durable dispatcher retries
    /// either way). `Busy` maps to a resource-in-progress timeout.
    fn into_transport(self) -> TransportError {
        match self {
            ShipError::Busy => {
                TransportError::Io("reticulum send_resource: transfer in progress".to_string())
            }
            ShipError::Other(e) => e,
        }
    }
}

/// CIRISEdge#353 (residual) — how long a reverse-path send keeps retrying a
/// BUSY link (Reticulum permits one resource transfer per link at a time; a
/// reply usually collides with the peer's own inbound payload mid-transfer).
/// Transfers are seconds; 8 s fits inside the 10 s anti-entropy round timeout
/// so a drained link still completes the SAME round instead of the next one.
const REVERSE_PATH_BUSY_RETRY_WINDOW: Duration = Duration::from_secs(8);
/// Pause between busy-retries on the reverse path.
const REVERSE_PATH_BUSY_BACKOFF: Duration = Duration::from_millis(500);

/// CIRISEdge#336 (fast heal) — minimum interval between EVENT-DRIVEN announces.
///
/// RNS reachability is on-demand, not periodic: markqvist's reference stack
/// announces immediately on startup + on interface/link change, and treats the
/// periodic timer as a coarse fallback (Sideband re-announces every 90–300
/// *minutes*). Edge's 300 s [`ReticulumTransportConfig::announce_interval`] as
/// the ONLY heal trigger is the anti-pattern: a peer that connects just after a
/// tick waits ~5 min for the next announce before the #336 belt can heal its
/// route. So we ALSO announce when a link establishes (a peer just connected) —
/// which propagates our routable named dest in seconds. This gate bounds a burst
/// of link-ups to one announce per window (RNS `ANNOUNCE_CAP` spirit), so an
/// announce storm can't be driven by rapid link churn.
const EVENT_ANNOUNCE_MIN_INTERVAL: Duration = Duration::from_secs(10);

/// CIRISEdge#318 — cap on the in-memory `peers` (rooted + advisory bindings)
/// map. Bounds advisory-admit pollution: at cap, an Advisory binding is evicted
/// before a new key is inserted (Rooted bindings are never evicted for advisory
/// churn). Far above any real cohort; the target is unbounded attacker growth.
const MAX_PEERS: usize = 4096;

// ─── CIRISEdge#317 — throttles for attacker-triggerable log sites ────
//
// Announces + link establishment are unauthenticated / advisory-admitted, so a
// peer can flood them. These bound the RCA-critical WARN/INFO lines to
// first-N-per-window (bounded key map, front-drop) so a single broken run still
// self-diagnoses but a flood collapses to a suppressed-count. High-volume detail
// is demoted to DEBUG instead (out of the default INFO stream).

// `OnceLock` (not `LazyLock`) per the crate MSRV 1.75 + the codebase convention.
static PEER_ADMITTED_LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> =
    std::sync::OnceLock::new();
static LINK_ATTRIBUTION_MISS_LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> =
    std::sync::OnceLock::new();
// CIRISEdge#337 — route supersession decisions (verified-only gate + belt heal).
static ROUTE_SUPERSESSION_LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> =
    std::sync::OnceLock::new();

/// Point 1 — peer-admitted (INFO). Keyed on `provenance` (2 values), so the
/// rare `Rooted` admit logs freely while a flood of junk `Advisory` admits is
/// capped. A tiny key map suffices.
fn peer_admitted_log() -> &'static crate::log_throttle::LogThrottle {
    PEER_ADMITTED_LOG
        .get_or_init(|| crate::log_throttle::LogThrottle::new(8, Duration::from_secs(60), 8))
}

/// Point 2 — link-attribution miss (WARN). Keyed on the link-proven identity
/// hash (attacker-chosen), so the key map is capped as the DoS backstop.
fn link_attribution_miss_log() -> &'static crate::log_throttle::LogThrottle {
    LINK_ATTRIBUTION_MISS_LOG
        .get_or_init(|| crate::log_throttle::LogThrottle::new(5, Duration::from_secs(60), 1024))
}

/// CIRISEdge#337 — route supersession decisions (verified-only refusal + belt
/// reroute-heal). Keyed on a fixed low-cardinality reason ("hijack_refused" /
/// "reroute_healed", ≤4 keys), NEVER on the attacker-chosen `key_id`, so a flood
/// of forged supersession attempts collapses to a suppressed-count instead of a
/// per-key log line. The refusal is a genuine attack signal, so it logs the
/// first few per window loudly then summarizes.
fn route_supersession_log() -> &'static crate::log_throttle::LogThrottle {
    ROUTE_SUPERSESSION_LOG
        .get_or_init(|| crate::log_throttle::LogThrottle::new(8, Duration::from_secs(60), 4))
}

static REVERSE_PATH_FALLBACK_LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> =
    std::sync::OnceLock::new();
static NAT_TOPOLOGY_DIAGNOSIS_LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> =
    std::sync::OnceLock::new();

/// CIRISEdge#353 — a reverse-path (live inbound link) send failed and we fell
/// back to an outbound dial. Keyed on the peer key_id (rooted peers only —
/// bounded by the admit gate, capped map as backstop).
fn reverse_path_fallback_log() -> &'static crate::log_throttle::LogThrottle {
    REVERSE_PATH_FALLBACK_LOG
        .get_or_init(|| crate::log_throttle::LogThrottle::new(5, Duration::from_secs(60), 256))
}

static NON_CIRIS_ANNOUNCE_LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> =
    std::sync::OnceLock::new();

/// CIRISEdge#357 — ambient third-party announces on the shared RNS network whose
/// app-data is not a CIRIS AV-42 attestation (too short / wrong magic). On a
/// public fabric this is high-volume NON-actionable traffic; a per-announce WARN
/// drowns the genuinely-useful "a CIRIS peer failed to root" signal. Rolled up:
/// a couple of DEBUG lines per minute + a suppressed-count, keyed on a single
/// fixed discriminant (this is not a per-peer condition — it's "not us").
fn non_ciris_announce_log() -> &'static crate::log_throttle::LogThrottle {
    NON_CIRIS_ANNOUNCE_LOG
        .get_or_init(|| crate::log_throttle::LogThrottle::new(2, Duration::from_secs(60), 4))
}

/// CIRISEdge#353 ask 2 — the NAT'd/initiator-only topology diagnosis. Before
/// this, an outbound dial to an undialable phone was a bare 30 s `Timeout` per
/// kind per round FOREVER (the field symptom: 3 WARNs every 30 s, no cause).
/// One diagnosis per peer per window, then a suppressed-count.
fn nat_topology_diagnosis_log() -> &'static crate::log_throttle::LogThrottle {
    NAT_TOPOLOGY_DIAGNOSIS_LOG
        .get_or_init(|| crate::log_throttle::LogThrottle::new(2, Duration::from_secs(300), 256))
}

/// CIRISEdge#353 ask 2 — emit the topology diagnosis (throttled). Fired when a
/// dial HAD a path (the peer's announce taught us one) yet never established,
/// and the reverse-path check found no live inbound link. The classic cause is
/// a NAT'd / initiator-only peer (phone, emulator, CGNAT): its announce arrives
/// over ITS outbound link, but nothing can dial it back. Name the hypothesis
/// ONCE per window instead of an unexplained 30 s `Timeout` per kind per round
/// forever.
fn log_nat_topology_diagnosis(destination_key_id: &str, establish_timeout: Duration) {
    if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
        nat_topology_diagnosis_log().check(destination_key_id)
    {
        tracing::warn!(
            destination_key_id,
            establish_timeout_secs = establish_timeout.as_secs(),
            suppressed_prev,
            "outbound dial had a path but never established, and the peer has NO \
             live inbound link to ride — if this peer is NAT'd / initiator-only \
             it is structurally unreachable outbound; delivery will succeed over \
             the peer's NEXT inbound link (reverse path, CIRISEdge#353)"
        );
    }
}

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

    /// v7.0.0 (CIRISEdge#191 / #195) — return the peer's 32-byte
    /// **federation** Ed25519 public key, the load-bearing primitive
    /// for explicit-hash routability. The dial side derives the peer's
    /// 16-byte routable destination_hash via
    /// [`crate::transport::addressing::reticulum_destination_for_pubkey`]
    /// on this value. Cross-transport byte-equal parity (IP + packet
    /// radio + HTTP) follows from every transport using the SAME
    /// helper on the SAME pubkey.
    ///
    /// **Default impl** returns `None`: v0.7.x-era resolvers that only
    /// know the transport-tier dual-key bytes fall back to the legacy
    /// announce-bound formula
    /// (`Destination::compute_destination_hash(name_hash, identity.hash())`).
    /// Production wires this against persist's `federation_keys`
    /// directory cache (the v6.0.0 `directory_cache_driver`), which
    /// stores the federation Ed25519 pubkey alongside the key_id.
    ///
    /// Returning `Some(.)` opts the peer into the v7.0.0 explicit-
    /// hash path. The resolver SHOULD coordinate so a peer either
    /// returns `Some(.)` consistently or `None` consistently — mixing
    /// the two between resolve calls would make the dial path
    /// non-deterministic.
    fn resolve_federation_pubkey(&self, _destination_key_id: &str) -> Option<[u8; 32]> {
        None
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

/// Lowercase hex encode without the dev-only `hex` crate. v1.1.0
/// (CIRISEdge#44) — the routing-table FFI needs to project the
/// 16-byte transport identity into a string for the
/// `EdgeRoutingPathEntry.via_transport_id` wire field; the existing
/// inline `write!("{b:02x}")` pattern (used in the LinkEstablished
/// event emit at line ~2365) was hoisted here so both call sites
/// share the same formatter. Gated on `ffi-uniffi` because both
/// consumers are FFI-only — non-FFI builds don't need it.
#[cfg(feature = "ffi-uniffi")]
fn hex_encode_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
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

/// CIRISEdge#299 — a boot-snapshot [`PeerResolver`] built from persist's
/// `list_all_transport_destinations()` at startup. Restores the full
/// `key_id → (x25519 ‖ ed25519)` transport identity for every
/// previously-rooted peer, so `resolve_peer` (hence `knows_peer` +
/// routing) succeeds and sealing has the KEX x25519 the instant edge
/// comes up — zero announces. The write-through side is
/// [`crate::verify::RootingDirectory::persist_transport_binding`]; this is
/// the reload side. Snapshot semantics: loaded in full once at boot; new
/// roots after boot land in the live `peers` map (and are write-through
/// persisted for the next boot).
pub struct PersistedBindingResolver {
    bindings: std::collections::HashMap<String, [u8; 64]>,
}

impl PersistedBindingResolver {
    /// Build the resolver from a `key_id → 64-byte (x25519 ‖ ed25519)` map.
    pub fn new(bindings: std::collections::HashMap<String, [u8; 64]>) -> Self {
        Self { bindings }
    }

    /// Number of persisted bindings loaded.
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// Whether any bindings were loaded.
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
}

impl PeerResolver for PersistedBindingResolver {
    fn resolve(&self, destination_key_id: &str) -> Option<[u8; 64]> {
        self.bindings.get(destination_key_id).copied()
    }
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
    /// CIRISEdge#301 — `None` for an `Advisory` binding (self-consistent
    /// routing hint that did not root against the directory).
    #[allow(dead_code)]
    chain: Option<ProvenanceChain>,
    /// CIRISEdge#301 (CC 3.3.6.2) — `Rooted` (authoritative, chained to a
    /// pinned steward) vs `Advisory` (self-consistent routing hint;
    /// authority composed downstream). Read by the epoch/upgrade guard so
    /// a same-epoch re-announce that finally roots upgrades an existing
    /// advisory binding instead of being ignored as stale.
    provenance: ciris_persist::federation::self_at_login::BindingProvenance,
    /// CIRISEdge#314 — the peer's 16-byte transport identity hash
    /// (`Identity::from_public_keys(x25519, ed25519).hash()`), captured from the
    /// authenticated announce. The inbound-link→key_id attribution
    /// (`NodeEvent::LinkIdentified`) matches the link's proven `identity_hash`
    /// against THIS — **form-agnostic**, so a peer that announced on an
    /// explicit-hash dest (`sha256(fed_pubkey)[..16]`) is attributed exactly as
    /// a named-dest peer is. The pre-#314 attribution recomputed only the NAMED
    /// dest form (`compute_destination_hash(name_hash, identity_hash)`) and
    /// compared it to the stored announced dest, so it missed on the
    /// named-vs-explicit split → `source_key_id` stayed `None` → the CRPL frame
    /// never reached `route_inbound_bytes` (and #312's responder was
    /// unreachable). `[0u8; 16]` for a test-injected peer whose x25519 half is
    /// unavailable (never matches a real identity hash).
    transport_identity_hash: [u8; 16],
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
    /// **CIRISEdge#168 (v5.0)** — Reticulum Transport-node mode. When
    /// `true`, this node forwards inbound packets destined for
    /// non-local destinations back across its warm interfaces — the
    /// load-bearing half of §24 NAT-traversal. The default is `false`
    /// (leaf-node mode; a mobile edge). A public fabric node binding
    /// `0.0.0.0:4242` MUST set this to `true` for NAT'd mobile edges
    /// to route through it.
    ///
    /// Maps to upstream RNS's `[reticulum] enable_transport = Yes/No`
    /// in `reticulum.conf` and to leviculum's
    /// `ReticulumNodeBuilder::enable_transport`. Note leviculum's
    /// builder default when the knob is never called is `true`; edge
    /// always calls it explicitly so this `false` default is honoured
    /// (a leaf edge does NOT relay for strangers unless opted in).
    pub enable_transport: bool,
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
            enable_transport: false,
        }
    }

    /// **CIRISEdge#168** — opt this node into Reticulum Transport-node
    /// mode (forward packets for non-local destinations across warm
    /// interfaces). Builder-style; the default is leaf-node (`false`).
    /// A public fabric node binding `0.0.0.0:4242` calls this with
    /// `true` so NAT'd mobile edges can route through it (§24).
    #[must_use]
    pub fn with_transport_node(mut self, enabled: bool) -> Self {
        self.enable_transport = enabled;
        self
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
    /// v7.4.0 (CIRISEdge#231) — Reticulum-NAMED destination registered
    /// alongside the explicit-hash one (`local_dest_hash`). Both share
    /// the same transport identity for link encryption; they're two
    /// routing-table entries pointing at the same underlying crypto.
    ///
    /// Why the dual registration:
    ///  - Explicit-hash (`local_dest_hash`) is `sha256(fed_pubkey)[..16]`
    ///    — addressable by anyone who knows the federation pubkey, but
    ///    cannot announce (Leviculum guards
    ///    `AnnounceError::ExplicitHashCannotAnnounce`). Direct-dial /
    ///    prime_peer path.
    ///  - Named (`local_named_dest_hash`) is the standard RNS
    ///    `sha256(name_hash || identity_hash)[..16]` derived from
    ///    `(EDGE_APP_NAME, EDGE_APP_ASPECT, transport_identity)`. Fully
    ///    announceable → any RNS fabric (CIRIS or generic) learns the
    ///    path → multi-hop routing + transport relays work for free.
    ///
    /// The announce loop emits under THIS hash. Inbound links to either
    /// hash terminate at the same identity, so federation trust on the
    /// envelope payload is invariant. Operators see `Reticulum transport
    /// listening on ... (dest <explicit_hash>) (named-dest
    /// <named_hash>)` on the `transport_up` interface event.
    local_named_dest_hash: DestinationHash,
    /// v2.1.0 (CIRISPersist `LocalIdentityAggregate` RET-transport
    /// role) — the 64-byte Reticulum dual-key public material edge
    /// minted at startup: `x25519_pub (32) ‖ ed25519_pub (32)`. The
    /// Reticulum destination hash is `sha256(x25519 ‖ ed25519)[..16]`,
    /// which persist can derive from this buffer. Captured here so
    /// cohabiting cdylibs can read it via
    /// [`Self::local_transport_pubkey`] — closes the
    /// LocalIdentityAggregate's RET-transport role with the
    /// conformant source (edge owns the transport identity per
    /// `crate::identity` §"Reticulum-shape identity hash").
    local_transport_pubkey: [u8; 64],
    /// CIRISEdge#340 — this node's full Reticulum transport identity (the
    /// same one bound into `node`), kept so the send side can IDENTIFY an
    /// outbound link after it establishes. A Reticulum link is anonymous by
    /// default; only the initiator may identify it (RNS `Link.identify()`),
    /// and identifying is what makes the responder emit `LinkIdentified` →
    /// populate `link_to_peer_key_id` → attribute inbound replication frames.
    /// Without this, every inbound CRPL frame dropped `SkippedNoSourceKeyId`
    /// (#317) because the link carried no proven identity — the reason the
    /// #314 attribution machinery, though correct, never fired in the field
    /// (and why CIRISServer#235 was never verified end-to-end). Holds the
    /// PRIVATE key (unlike `local_transport_pubkey`), so it can sign the
    /// LINKIDENTIFY packet.
    local_identity: Identity,
    /// Edge's own announce attestation app-data — built once in
    /// `new` (sign with the federation `LocalSigner`) and emitted
    /// verbatim on every announce. `None` when no signer was
    /// supplied: the transport then cannot prove its own binding and
    /// announces an empty app-data (peers with rooting enabled will
    /// drop it — fail-honest).
    local_attestation: Option<Vec<u8>>,
    /// The node's single `NodeEvent` receiver. `listen` takes it
    /// exactly once; a second `listen` call is a config error.
    /// Leviculum PR #9 switched this to an unbounded channel so node
    /// events are never dropped before a consumer attaches.
    /// v3.0.0 — leviculum upstream introduced the two-bounded-plane
    /// channel (lossless control + droppable data) at ffd261d; the
    /// receiver type became `EventReceiver` with the same `.recv()` /
    /// `.try_recv()` surface — call sites unchanged, field type
    /// updated.
    events: Mutex<Option<EventReceiver>>,
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
    /// CIRISEdge#353 test seam — when > 0, the next N `ship_resource_on_link`
    /// calls return [`ShipError::Busy`] (decrementing) BEFORE touching the
    /// network, so a test can deterministically drive the reverse-path
    /// busy-retry loop without racing a real in-flight transfer (loopback
    /// drains too fast to collide). Zero in production: one relaxed atomic
    /// load per ship. Set via [`Self::force_next_sends_busy_for_test`].
    test_force_busy: Arc<std::sync::atomic::AtomicU32>,
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
    /// CIRISEdge#205 (AV-42 Phase 4) — RNS destination-hash binding
    /// enforcement posture on the announce cold-start path.
    transport_binding_enforcement: TransportBindingEnforcement,
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
    /// v3.5.1 (CIRISEdge#119 + #120) — per-link rooted-peer attribution.
    /// Populated on `NodeEvent::LinkIdentified` by deriving the link's
    /// expected destination hash from its remote `identity.hash()` +
    /// the federation name_hash, then scanning the rooted peers map
    /// for a match. Removed on `LinkClosed`. Consumed by
    /// `NodeEvent::ResourceCompleted` to populate
    /// [`InboundFrame::source_key_id`](crate::transport::InboundFrame::source_key_id)
    /// so [`Edge::install_replication_routing`](crate::Edge::install_replication_routing)
    /// can route inbound CRPL frames to the right coordinator.
    ///
    /// `None`-equivalent (link absent from map) when the link hasn't
    /// been LinkIdentified yet, or when the link's remote identity
    /// doesn't match any rooted peer (pre-handshake / cold-start).
    link_to_peer_key_id: Arc<Mutex<HashMap<LinkId, String>>>,
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
    /// CIRISEdge#33 — operator-configured deny-list. Keyed by the
    /// 16-byte Reticulum identity hash of the blocked peer. `send`
    /// consults this BEFORE the leviculum connect call; a hit
    /// increments the entry's `hits` counter (via
    /// `BlackholeRules::blackhole_record_hit`, fire-and-forget on a
    /// spawned task) and returns `TransportError::PeerBlackholed`.
    ///
    /// v0.16.1 (CIRISPersist#120) — flipped from the v0.15.0
    /// in-memory `Arc<RwLock<HashMap<Vec<u8>, BlackholeRecord>>>` to a
    /// persist-backed `Arc<dyn BlackholeRules>` over the V052
    /// `cirislens.blackhole_rules` table. Rules now survive process
    /// restarts — the v0.15.0 acceptance criterion. `None` indicates a
    /// transport built without a blackhole backend (typically a test
    /// fixture that doesn't exercise the routing-table FFI surface);
    /// `routing_blackhole_*` returns `TransportError::Config` in that
    /// case, and the send-path enforcement check is a no-op.
    blackhole: Option<Arc<dyn ciris_persist::federation::BlackholeRules>>,
    /// CIRISEdge#33 (v0.15.0) — process-wall-clock instant the
    /// transport was constructed. Backs `routing_transport_uptime`.
    /// Monotonic via `std::time::Instant`; transport replacement
    /// rebases the counter, which is the documented contract.
    started_at: std::time::Instant,
    /// CIRISEdge#169 (§24 NAT-traversal) — optional store-and-forward
    /// queue. `None` (the default) leaves `send` live-only regardless
    /// of the per-send delivery mode. When wired (public fabric
    /// nodes), a [`PendingDelivery::PendingOrLive`] send to an
    /// unreachable destination is queued here instead of erroring.
    /// Set via [`Self::with_store_and_forward`].
    store_and_forward: Option<Arc<dyn crate::transport::store_and_forward::StoreAndForward>>,
    /// CIRISEdge#169 — default per-send delivery discipline. Live-only
    /// unless overridden. `send` consults this for every send (the
    /// `Transport` trait has no per-call delivery arg in v5.0).
    delivery: crate::transport::PendingDelivery,
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
    /// CIRISEdge#205 (AV-42 Phase 4) — RNS destination-hash binding
    /// enforcement on the announce cold-start path. [`Default`] is
    /// [`TransportBindingEnforcement::Advisory`] (no behavior change); the
    /// flip to `RequireTransportBinding` is a dated fleet-floor event.
    pub transport_binding_enforcement: TransportBindingEnforcement,
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
    /// CIRISEdge#33 (v0.16.1 durable flip) — persist-backed operator
    /// deny-list. When `Some`, `routing_blackhole_*` CRUD methods and
    /// the send-path enforcement check route through the supplied
    /// `Arc<dyn BlackholeRules>` (persist V052 `cirislens.blackhole_rules`
    /// table; CIRISPersist#120). When `None`, the routing-table FFI
    /// blackhole surface returns `TransportError::Config("blackhole
    /// rules unavailable")` — tests that don't care about blackhole
    /// CRUD typically pass `None`; production cohabitation
    /// (`init_edge_runtime`) always passes the engine's
    /// `Arc<dyn BlackholeRules>`. `routing_blackhole_*` calls no longer
    /// touch process-local state — durability survives transport
    /// rebuild AND process restart (the v0.15.0 acceptance criterion).
    pub blackhole_rules: Option<Arc<dyn ciris_persist::federation::BlackholeRules>>,
    /// v3.1.0 (CIRISEdge#99) — keyring-backed RNS transport identity
    /// storage. When `Some`, edge consults the keystore BEFORE the
    /// `identity_path` file:
    ///   - keystore.load(key_id) → `Some` → use those bytes
    ///   - keystore.load(key_id) → `None` AND file exists → adopt-and-
    ///     migrate: read the 64 file bytes, store via
    ///     keystore.store(key_id, bytes), archive the original file to
    ///     `<path>.migrated-<ts>` (rename, never delete — operator
    ///     keeps the recovery copy until they're satisfied)
    ///   - keystore.load(key_id) → `None` AND no file → generate fresh
    ///     via keystore.generate_and_store(key_id), then load
    ///
    /// `None` (the default) preserves the v3.0.x chmod-600 file-only
    /// behavior exactly. When `Some` and the platform tier is
    /// hardware-backed (TPM / SE / StrongBox per the keystore's own
    /// `is_hardware_backed()`), the at-rest exfil class documented in
    /// CIRISEdge#99 (filesystem reads, backups, snapshots, permission
    /// misconfig) is closed.
    ///
    /// AV-17 carve-out: the federation signing key never crosses
    /// here — this is the transport-tier (X25519 + Ed25519) identity
    /// only. Reticulum's `Identity::from_private_key_bytes` still
    /// holds the bytes transiently to construct the in-process
    /// Identity; the keyring trade-off is at-rest only, not RAM.
    /// CIRISEdge#99 documents this explicitly.
    pub transport_identity_keystore: Option<Arc<dyn ciris_keyring::TransportIdentityKeystore>>,
}

impl Default for ReticulumAuth {
    fn default() -> Self {
        Self {
            signer: None,
            rooting: None,
            resolver: None,
            hybrid_policy: HybridPolicy::Strict,
            transport_binding_enforcement: TransportBindingEnforcement::Advisory,
            event_bus: None,
            reachability: None,
            blackhole_rules: None,
            transport_identity_keystore: None,
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
            transport_binding_enforcement,
            event_bus,
            reachability,
            blackhole_rules,
            transport_identity_keystore,
        } = auth;

        // v3.1.0 (CIRISEdge#99) — when the host wired a
        // `TransportIdentityKeystore`, load/adopt/generate via the
        // keystore tier (TPM / SE / StrongBox / software fallback).
        // When `None`, fall through to the v3.0.x chmod-600 file-only
        // path. See [`load_or_adopt_or_generate_identity_with_keystore`]
        // for the precedence rules + migration semantics.
        let identity = if let Some(keystore) = transport_identity_keystore.as_ref() {
            load_or_adopt_or_generate_identity_with_keystore(
                &config.identity_path,
                &config.local_key_id,
                keystore.as_ref(),
            )?
        } else {
            load_or_generate_identity(&config.identity_path)?
        };

        // v2.1.0 (CIRISPersist LocalIdentityAggregate RET-transport
        // role) — copy the 64-byte dual-key public material to a
        // standalone buffer we stash on `ReticulumTransport`. The
        // identity itself is consumed building the destination below;
        // this lets cohabiting cdylibs read the pubkey shape at any
        // later point without re-loading from disk.
        let mut local_transport_pubkey = [0u8; 64];
        local_transport_pubkey.copy_from_slice(&identity.public_key_bytes()[..64]);

        // Build edge's own announce attestation: a federation-key
        // signature binding this transport identity to `local_key_id`
        // at `local_epoch` (CIRISEdge#15 send side). The transport
        // identity's Ed25519 public key is the ed25519 half (bytes
        // 32..64) of the dual-key identity.
        let mut transport_ed25519 = [0u8; 32];
        transport_ed25519.copy_from_slice(&local_transport_pubkey[32..64]);
        // CIRISEdge#317 — the x25519 (encryption) half is bytes 0..32 of the
        // dual-key identity; bind it into the announce so receivers can match
        // the transport identity the link proves.
        let mut transport_x25519 = [0u8; 32];
        transport_x25519.copy_from_slice(&local_transport_pubkey[..32]);
        // CIRISEdge#333 — EVERY announce is self-attested. There is no
        // unattested branch: a node with no federation signer that announced
        // anyway produced a routable-but-unrootable peer — a trap that looks
        // HEALTHY (paths resolve!) yet can never be rooted, and it silently
        // masked the fact that the attested announce was failing to transmit at
        // all. `signer: None` is now a hard configuration error, not a
        // degradation.
        let Some(signer_ref) = &signer else {
            return Err(TransportError::Config(
                "Reticulum transport requires a federation signer: every announce must be \
                 self-attested (CIRISEdge#333). An unattested announce yields a peer that \
                 routes but can never root — it looks healthy and is not."
                    .to_string(),
            ));
        };
        let local_attestation = Some(
            build_local_attestation(
                signer_ref,
                &transport_ed25519,
                &transport_x25519,
                &config.local_key_id,
                config.local_epoch,
            )
            .await?,
        );

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
        // CIRISEdge#168 (v5.0) — Transport-node mode. Called
        // explicitly so the config's `false` default is honoured;
        // leviculum's builder otherwise defaults the knob to `true`.
        let mut builder = ReticulumNodeBuilder::new()
            .identity(identity.clone())
            .storage_path(storage_path)
            .enable_transport(config.enable_transport);
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

        // v7.0.0 (CIRISEdge#191 / #195) — Leviculum v0.7.0 explicit-
        // hash addressing. Edge's local destination is registered under
        // `sha256(fed_ed25519_pubkey)[..16]` — the SAME hash the
        // packet-radio and HTTP transports derive, via the single
        // load-bearing primitive
        // [`crate::transport::addressing::reticulum_destination_for_pubkey`].
        // Cross-transport byte-equal parity is the N1 closure for
        // CIRISEdge#191.
        //
        // The destination's `identity` is still the transport identity
        // (its real Ed25519 secret signs link proofs); only the 16-byte
        // routing index is overridden. Per Leviculum's compatibility
        // guard, explicit-hash destinations MUST NOT be announced — the
        // installed `ScopePrivacyAnnouncePolicy` honours that contract
        // by default-suppressing every registered destination (#195).
        //
        // Bootstrap requirement: a federation signer is needed to
        // derive `fed_ed25519_pubkey`. Without one, edge has no
        // federation identity to address by — fail honest at
        // construction rather than fall back to a non-byte-equal
        // legacy path (those peers' addressing would diverge, and the
        // cohort's directory cache would never reach them).
        let federation_ed25519_pubkey: [u8; 32] = if let Some(s) = &signer {
            let (ed_bytes, _pqc) = s.federation_pubkeys().await.map_err(|e| {
                TransportError::Config(format!(
                    "federation pubkey unavailable for explicit-hash addressing: {e}"
                ))
            })?;
            if ed_bytes.len() != 32 {
                return Err(TransportError::Config(format!(
                    "federation Ed25519 pubkey is {} bytes (expected 32)",
                    ed_bytes.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&ed_bytes);
            arr
        } else {
            return Err(TransportError::Config(
                "Reticulum transport requires a federation signer for v7.0.0 explicit-hash \
                 addressing — no fallback to the legacy keystore-derived destination is \
                 supported (peers would diverge on routability)"
                    .into(),
            ));
        };
        let explicit_dest_hash = crate::transport::addressing::reticulum_destination_for_pubkey(
            &federation_ed25519_pubkey,
        );
        let mut dest = Destination::with_explicit_hash(
            Some(identity.clone()),
            Direction::In,
            DestinationType::Single,
            EDGE_APP_NAME,
            &[EDGE_APP_ASPECT],
            explicit_dest_hash,
        )
        .map_err(|e| TransportError::Config(format!("explicit-hash destination build: {e}")))?;
        dest.set_accepts_links(true);
        let local_dest_hash = *dest.hash();
        debug_assert_eq!(
            local_dest_hash.as_bytes(),
            &explicit_dest_hash,
            "explicit-hash destination must index by the caller-supplied hash",
        );
        node.register_destination_at(local_dest_hash, dest);

        // v7.4.0 (CIRISEdge#231) — register a NAMED destination on
        // the SAME transport identity. Its hash is the standard RNS
        // `sha256(name_hash || identity_hash)[..16]` (NOT the
        // federation-rooted explicit hash above). The named dest is
        // announceable + mesh-discoverable; the explicit-hash stays
        // for prime_peer / direct-dial back-compat (every v7.0.0–v7.3.x
        // peer addresses by explicit hash). Two routing-table entries,
        // one underlying identity → either inbound path reaches the
        // same handler set.
        let mut named_dest = Destination::new(
            // CIRISEdge#340 — clone (not move): `local_identity` on the struct
            // keeps the full transport identity so the send side can identify
            // outbound links after they establish.
            Some(identity.clone()),
            Direction::In,
            DestinationType::Single,
            EDGE_APP_NAME,
            &[EDGE_APP_ASPECT],
        )
        .map_err(|e| TransportError::Config(format!("named destination build: {e}")))?;
        named_dest.set_accepts_links(true);
        let local_named_dest_hash = *named_dest.hash();
        node.register_destination_at(local_named_dest_hash, named_dest);

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
            local_named_dest_hash,
            local_transport_pubkey,
            local_identity: identity.clone(),
            local_attestation,
            events: Mutex::new(Some(events)),
            peers: Arc::new(Mutex::new(HashMap::new())),
            established_links: Arc::new(Mutex::new(HashSet::new())),
            sent_resources: Arc::new(Mutex::new(HashSet::new())),
            test_force_busy: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            resolver,
            rooting,
            hybrid_policy,
            transport_binding_enforcement,
            event_bus,
            reachability,
            interface_specs: Arc::new(std::sync::Mutex::new(interface_specs)),
            link_established_at: Arc::new(Mutex::new(HashMap::new())),
            link_to_peer_key_id: Arc::new(Mutex::new(HashMap::new())),
            request_responses: Arc::new(Mutex::new(HashMap::new())),
            timed_out_requests: Arc::new(Mutex::new(HashSet::new())),
            blackhole: blackhole_rules,
            started_at: std::time::Instant::now(),
            store_and_forward: None,
            delivery: crate::transport::PendingDelivery::LiveOnly,
        })
    }

    /// CIRISEdge#169 (§24 NAT-traversal) — wire a store-and-forward
    /// queue and set the default per-send delivery discipline. A
    /// public fabric node calls this with [`PendingDelivery::PendingOrLive`]
    /// so sends to currently-unreachable destinations are queued for
    /// the destination's wake-up fetch instead of failing.
    #[must_use]
    pub fn with_store_and_forward(
        mut self,
        queue: Arc<dyn crate::transport::store_and_forward::StoreAndForward>,
        delivery: crate::transport::PendingDelivery,
    ) -> Self {
        self.store_and_forward = Some(queue);
        self.delivery = delivery;
        self
    }

    /// CIRISEdge#24 — snapshot every registered interface's typed
    /// v2.1.0 (CIRISPersist `LocalIdentityAggregate` RET-transport
    /// role) — return edge's 64-byte Reticulum transport-identity
    /// public material: `x25519_pub (32) ‖ ed25519_pub (32)`. Captured
    /// in [`Self::new`] from `load_or_generate_identity`'s output.
    ///
    /// The Reticulum destination hash is
    /// `sha256(x25519 ‖ ed25519)[..16]`; cohabiting cdylibs (persist's
    /// LocalIdentityAggregate, lens-core's relay) derive it from this
    /// buffer rather than calling back into Reticulum machinery.
    ///
    /// Edge owns this keypair end-to-end per the
    /// `crate::identity::federation_identity_hash` doc note:
    /// "the Reticulum destination hash lives on the *transport
    /// identity*, a different key pair generated by
    /// `src/transport/reticulum.rs`."
    #[must_use]
    pub fn local_transport_pubkey(&self) -> [u8; 64] {
        self.local_transport_pubkey
    }

    /// v7.2.0 (CIRISEdge#219) — accessor for the internal
    /// `ReticulumNode`. Used by `PyEdge::add_rnode_channel_interface`
    /// to invoke `ReticulumNode::spawn_rnode_channel_interface` for
    /// runtime hot-plug of a phone-attached RNode radio. The handle
    /// is `pub(crate)` so external crates can't bypass the
    /// transport's invariants; the PyO3 wrapper lives in
    /// `src/ffi/pyo3.rs` (same crate). Cfg-gated on `pyo3` because
    /// the PyEdge wrapper is the sole consumer — non-`pyo3` builds
    /// (lib tests, the `transport-reticulum`-only matrix combo) would
    /// trip `-D dead_code` otherwise.
    #[cfg(feature = "pyo3")]
    #[must_use]
    pub(crate) fn node(&self) -> &Arc<ReticulumNode> {
        &self.node
    }

    /// v2.2.2 (CIRISEdge#97) — return edge's announced RNS destination
    /// hash: the 16-byte `*dest.hash()` value Reticulum computes at
    /// `Destination` construction time over the identity + app aspects
    /// (NOT a plain `sha256(pubkey)[..16]` — that's why consumers need
    /// this accessor; they can't re-derive it from
    /// [`Self::local_transport_pubkey`] safely).
    ///
    /// This is the destination peers resolve to dial this node:
    /// announces carry it as `self.local_dest_hash`, the routing
    /// table keys on it, and a peer's path lookup returns it.
    /// Cohabiting cdylibs (CIRISLensCore v1.4.0+'s `install_ret_relay`
    /// per CIRISLensCore#43) call this to surface the dialable RNS
    /// address alongside the transport pubkeys.
    #[must_use]
    pub fn local_dest_hash(&self) -> [u8; 16] {
        let bytes = self.local_dest_hash.as_bytes();
        let mut out = [0u8; 16];
        out.copy_from_slice(bytes);
        out
    }

    /// v7.4.0 (CIRISEdge#231) — the NAMED Reticulum destination hash,
    /// `sha256(name_hash || transport_identity_hash)[..16]`. Distinct
    /// from [`Self::local_dest_hash`] (which is the explicit-hash
    /// `sha256(fed_pubkey)[..16]`); both terminate at the same
    /// transport identity, so inbound links to EITHER reach the same
    /// handler set.
    ///
    /// This is the value the periodic announce emits — RNS peers
    /// receiving our announce store a path to THIS hash. For
    /// mesh-routed delivery (multi-hop, transport relays), peers
    /// should dial this hash. The explicit-hash stays the canonical
    /// direct-dial / prime_peer address for back-compat with
    /// v7.0.0–v7.3.x peers.
    #[must_use]
    pub fn local_named_dest_hash(&self) -> [u8; 16] {
        let bytes = self.local_named_dest_hash.as_bytes();
        let mut out = [0u8; 16];
        out.copy_from_slice(bytes);
        out
    }

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

    /// CIRISEdge#292 — the `key_id`s currently in the live rooted-peer
    /// map (announce-rooted or `prime_peer`'d). The operator readback for
    /// "who can this node actually address right now": diagnosing a
    /// zero-delivery bring-up (CIRISServer#205) previously required an
    /// in-process snapshot of this map. Does NOT include directory-only
    /// (`PeerResolver`) peers that `knows_peer` would resolve on demand —
    /// this is the set that has a live `RootedPeer` entry.
    pub async fn rooted_peers(&self) -> Vec<String> {
        self.peers.lock().await.keys().cloned().collect()
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

    /// v7.0.0 (CIRISEdge#191 / #195) test seam — install a synthetic
    /// rooted-peer entry that bypasses the announce-rooting cold-start.
    ///
    /// v7.0.0 explicit-hash destinations cannot announce (Leviculum
    /// guard: `AnnounceError::ExplicitHashCannotAnnounce`), so loopback
    /// tests that previously waited for B to receive A's announce now
    /// have no announce to wait for. Production peers learn each
    /// other's `(dest_hash, transport-tier ed25519)` binding via the
    /// v6.0.0 directory-cache anti-entropy path (CIRISEdge#175) — this
    /// accessor is the test-only analogue that pre-installs the same
    /// binding without depending on that out-of-band path being wired
    /// up in the test fixture.
    ///
    /// `dest_hash` should be the peer's explicit-hash
    /// (`sha256(fed_pubkey)[..16]`) and `signing_key_ed25519` the
    /// peer's transport-tier Ed25519 verifying key (the 32 bytes that
    /// sign link proofs). After this call, `knows_peer(key_id)` returns
    /// true and `link_open(dest_hash, ..)` finds the entry.
    #[doc(hidden)]
    /// CIRISEdge#353 test seam — force the next `n` resource ships to fail
    /// [`ShipError::Busy`] (the one-transfer-per-link collision), so a test can
    /// drive the reverse-path busy-retry loop deterministically.
    pub fn force_next_sends_busy_for_test(&self, n: u32) {
        self.test_force_busy
            .store(n, std::sync::atomic::Ordering::Relaxed);
    }

    pub async fn inject_rooted_peer_for_test(
        &self,
        destination_key_id: &str,
        dest_hash: [u8; 16],
        signing_key_ed25519: [u8; 32],
    ) {
        let mut peers = self.peers.lock().await;
        peers.insert(
            destination_key_id.to_string(),
            RootedPeer {
                peer: ResolvedPeer {
                    dest_hash: DestinationHash::new(dest_hash),
                    signing_key: signing_key_ed25519,
                },
                epoch: 0,
                // Primed bindings carry no walked provenance chain; the operator
                // asserts them directly (e.g. the canonical), so they are
                // authoritative — CIRISEdge#301 `Rooted`, chain `None`.
                chain: None,
                provenance: ciris_persist::federation::self_at_login::BindingProvenance::Rooted,
                // #314 — the injector has only the ed25519 half (no x25519), so
                // the transport identity hash can't be computed; a zero sentinel
                // never matches a real link identity (explicit-hash test peers
                // are attributed by dest-hash, not this path).
                transport_identity_hash: [0u8; 16],
            },
        );
    }

    /// CIRISEdge#340 test seam — inject a rooted peer with its FULL 64-byte
    /// transport identity (`x25519 ‖ ed25519`), computing the real
    /// `transport_identity_hash` the way the announce path does. Unlike
    /// [`Self::inject_rooted_peer_for_test`] (which stores a `[0u8; 16]`
    /// sentinel because it lacks the x25519 half), this reproduces the FIELD
    /// shape: an announce-rooted peer whose stored identity hash matches the
    /// hash a real identified link proves — the precondition #340 attribution
    /// needs. `dest_hash` is the peer's ROUTABLE (named) dest.
    #[doc(hidden)]
    pub async fn inject_rooted_peer_with_transport_identity_for_test(
        &self,
        destination_key_id: &str,
        dest_hash: [u8; 16],
        transport_pubkey64: [u8; 64],
    ) {
        let x25519: [u8; 32] = transport_pubkey64[..32].try_into().unwrap_or([0u8; 32]);
        let ed25519: [u8; 32] = transport_pubkey64[32..].try_into().unwrap_or([0u8; 32]);
        let transport_identity_hash =
            Identity::from_public_keys(&x25519, &ed25519).map_or([0u8; 16], |id| *id.hash());
        let mut peers = self.peers.lock().await;
        peers.insert(
            destination_key_id.to_string(),
            RootedPeer {
                peer: ResolvedPeer {
                    dest_hash: DestinationHash::new(dest_hash),
                    signing_key: ed25519,
                },
                epoch: 0,
                chain: None,
                provenance: ciris_persist::federation::self_at_login::BindingProvenance::Rooted,
                transport_identity_hash,
            },
        );
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
    #[cfg(feature = "ffi-uniffi")]
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

        // v7.0.0 (CIRISEdge#191): `connect` and `connect_at` are
        // functionally identical in Leviculum v0.7.0; we use the
        // legacy name here because the dial path serves BOTH the
        // explicit-hash route (when `dest_hash` was derived from the
        // peer's federation pubkey) and the legacy announce-bound
        // route (when the peer is still on v6.x). The 16 bytes are
        // opaque to leviculum; the receiver's index dispatches.
        let link = self
            .node
            .connect(&dest_hash, &signing_key)
            .await
            .map_err(|e| TransportError::Io(format!("reticulum connect: {e}")))?;
        let link_id = *link.link_id();

        // CIRISEdge#342 — alias-resolving establishment poll (see `send`): a
        // #66 re-key on a lossy path re-keys the link under a fresh id, so a raw
        // `established_links.contains(&original_id)` misses.
        let established = wait_until_async(timeout, Duration::from_millis(50), || async {
            self.node.link_is_established(&link_id)
        })
        .await;
        if !established {
            return Err(TransportError::Timeout(timeout));
        }
        // CIRISEdge#340 — identify the link so the responder can attribute what
        // arrives on it (same rationale as `send`: an anonymous link yields
        // `source_key_id=None` → dropped). The FFI Links surface establishes
        // links the same way, so it needs the same identify precondition.
        self.node
            .identify_link(&link_id, &self.local_identity)
            .await
            .map_err(|e| TransportError::Io(format!("reticulum identify_link: {e}")))?;
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

    // ─── CIRISEdge#33 (v0.15.0) Routing-table FFI surface ───────────
    //
    // Paths / blackhole / rate / tunnels / announce / reverse. v1.1.0
    // (CIRISEdge#44) flips on the 5 Leviculum accessors that the fork
    // now exposes publicly (`reticulum_std::driver::ReticulumNode::
    // {path_table_entries, rate_table_entries, get_path_clone,
    // remove_path, drop_all_paths_via}`). The remaining 3 read
    // surfaces (`routing_tunnels`, `routing_announce_table`,
    // `routing_reverse_table`) stay documented Vec::new() — those
    // backing data structures don't exist as collections in this
    // Leviculum fork (only `tunnel_synthesize_hash` is computed for
    // control-destination routing) and the reverse_table's stored
    // shape (packet_hash → interface_index pair) doesn't project to
    // the source_hash/destination_hash wire schema Edge pinned.

    /// Project a Leviculum monotonic-clock `expires_ms` (ms since
    /// NodeCore construction) into an RFC-3339 UTC wall-clock string.
    ///
    /// Anchors against `chrono::Utc::now()` plus the delta from the
    /// node's current `now_ms`. The two clocks aren't perfectly
    /// aligned — `now_ms` starts when NodeCore is built, `Utc::now()`
    /// is the actual wall clock — so the projection has up to ~1ms
    /// of jitter per call. That's well within the ms-resolution of
    /// the wire shape's RFC-3339 timestamps and matches the precision
    /// of every other timestamp on the routing FFI surface.
    #[cfg(feature = "ffi-uniffi")]
    fn project_monotonic_ms(&self, target_ms: u64) -> chrono::DateTime<Utc> {
        let now_ms = self.node.now_ms();
        // Compute signed delta so timestamps already in the past
        // (rare — usually expiry sweeps would have removed them, but
        // could happen if expiry just lapsed between the snapshot and
        // this projection) render as past wall-clock values.
        let delta_ms = i64::try_from(target_ms)
            .unwrap_or(i64::MAX)
            .saturating_sub(i64::try_from(now_ms).unwrap_or(i64::MAX));
        chrono::Utc::now() + chrono::Duration::milliseconds(delta_ms)
    }

    /// Resolve a Reticulum destination hash to its rooted peer
    /// `key_id`, when one exists. v1.1.0 (CIRISEdge#44) — the peer
    /// table is keyed by `peer_key_id (String)`; this is the reverse
    /// lookup needed by the routing-table FFI to populate
    /// `EdgeRoutingPathEntry.peer_key_id`. Returns `None` when the
    /// destination is unknown / unrooted (the common case for relay
    /// hops + transient destinations).
    #[cfg(feature = "ffi-uniffi")]
    async fn peer_key_id_for_dest_hash(&self, dest_hash: &[u8; 16]) -> Option<String> {
        let peers = self.peers.lock().await;
        for (key_id, rooted) in peers.iter() {
            if rooted.peer.dest_hash.as_bytes() == dest_hash {
                return Some(key_id.clone());
            }
        }
        None
    }

    /// Snapshot every known path-table entry. v1.1.0 (CIRISEdge#44) —
    /// backed by leviculum's now-public
    /// `ReticulumNode::path_table_entries` (each row is a deep
    /// `PathTableExport` clone; no mutex-borrowed references escape).
    ///
    /// `max_hops` filters the result to entries whose `hops <= max_hops`
    /// when supplied. `None` returns the full table. The `peer_key_id`
    /// field is filled when the destination matches a currently-rooted
    /// peer (CIRISEdge#15 cold-start authenticated path); unknown /
    /// relay destinations get `None`.
    ///
    /// Timestamps are wall-clock projections of leviculum's monotonic
    /// `expires_ms` — see [`Self::project_monotonic_ms`] for the
    /// precision contract. `last_seen_at` is the call-time wall
    /// clock (path entries don't carry an insertion timestamp in
    /// leviculum's storage shape).
    /// CIRISEdge#336 — a compact, single-line snapshot of the node's path
    /// table for the [`TransportError::NoRouteToPeer`] diagnostic. Each entry
    /// renders as `dest via next_hop hops=N` (or `dest direct hops=N` for a
    /// directly-attached neighbor). Synchronous and lock-free —
    /// `path_table_entries()` clones leviculum's rows — so it is safe to call
    /// on the send failure path. Bounded to a handful of rows so an enormous
    /// fabric can't turn one failure into a megabyte log line.
    fn path_table_snapshot(&self) -> String {
        use std::fmt::Write as _;
        const MAX_ROWS: usize = 16;
        let rows = self.node.path_table_entries();
        let total = rows.len();
        let mut out = String::new();
        for (i, entry) in rows.iter().take(MAX_ROWS).enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            let dest = hex::encode(entry.hash);
            match entry.next_hop {
                Some(nh) if entry.hops > 1 => {
                    let _ = write!(out, "{dest} via {} hops={}", hex::encode(nh), entry.hops);
                }
                _ => {
                    let _ = write!(out, "{dest} direct hops={}", entry.hops);
                }
            }
        }
        if total > MAX_ROWS {
            let _ = write!(out, ", …(+{} more)", total - MAX_ROWS);
        }
        if total == 0 {
            out.push_str("<empty>");
        }
        out
    }

    #[cfg(feature = "ffi-uniffi")]
    pub async fn routing_path_table(
        &self,
        max_hops: Option<u32>,
    ) -> Vec<crate::ffi::uniffi_types::EdgeRoutingPathEntry> {
        let raw = self.node.path_table_entries();
        let now_rfc3339 = chrono::Utc::now().to_rfc3339();
        let transport_kind = "reticulum".to_string();
        let mut out = Vec::with_capacity(raw.len());
        for entry in raw {
            if let Some(cap) = max_hops {
                if u32::from(entry.hops) > cap {
                    continue;
                }
            }
            let peer_key_id = self.peer_key_id_for_dest_hash(&entry.hash).await;
            let next_hop_bytes = entry.next_hop.map(|h| h.to_vec()).unwrap_or_default();
            // `via_transport_id` is a free-form string identifier for
            // the transport carrying the path. Leviculum's path-table
            // export doesn't tag each row with the originating
            // interface name (only the index); we surface the
            // routing-layer transport identity as a stable hex
            // identifier so the wire shape carries SOMETHING the
            // operator can correlate with `routing_transport_id`.
            let via_transport_id = hex_encode_lower(&self.node.identity_hash());
            out.push(crate::ffi::uniffi_types::EdgeRoutingPathEntry {
                destination_hash: entry.hash.to_vec(),
                peer_key_id,
                hops: u32::from(entry.hops),
                via_transport_id,
                via_transport_kind: transport_kind.clone(),
                next_hop: next_hop_bytes,
                last_seen_at: now_rfc3339.clone(),
                expires_at: self.project_monotonic_ms(entry.expires_ms).to_rfc3339(),
            });
        }
        out
    }

    /// Look up a single path entry by destination hash. v1.1.0
    /// (CIRISEdge#44) — backed by leviculum's now-public
    /// `ReticulumNode::get_path_clone`. Returns `None` when the
    /// destination is unknown OR when `destination_hash` is not 16
    /// bytes (typed-error-free for the not-found-vs-bad-input
    /// distinction — callers can pre-validate length).
    #[cfg(feature = "ffi-uniffi")]
    pub async fn routing_path_to(
        &self,
        destination_hash: &[u8],
    ) -> Option<crate::ffi::uniffi_types::EdgeRoutingPathEntry> {
        let dest_hash_array: [u8; 16] = destination_hash.try_into().ok()?;
        let dest_hash = DestinationHash::new(dest_hash_array);
        let entry = self.node.get_path_clone(&dest_hash)?;
        let peer_key_id = self.peer_key_id_for_dest_hash(&dest_hash_array).await;
        let next_hop_bytes = entry.next_hop.map(|h| h.to_vec()).unwrap_or_default();
        let via_transport_id = hex_encode_lower(&self.node.identity_hash());
        Some(crate::ffi::uniffi_types::EdgeRoutingPathEntry {
            destination_hash: dest_hash_array.to_vec(),
            peer_key_id,
            hops: u32::from(entry.hops),
            via_transport_id,
            via_transport_kind: "reticulum".to_string(),
            next_hop: next_hop_bytes,
            last_seen_at: chrono::Utc::now().to_rfc3339(),
            expires_at: self.project_monotonic_ms(entry.expires_ms).to_rfc3339(),
        })
    }

    /// Fire a PATH_REQUEST for `destination_hash`. Wraps leviculum's
    /// `ReticulumNode::request_path` — fire-and-forget; the response
    /// arrives later as a `PathFound` event on the listen loop.
    ///
    /// `on_interface` is currently advisory; leviculum's `request_path`
    /// dispatches to all interfaces. A future cut may add a per-
    /// interface override when the upstream API allows.
    pub async fn routing_path_request(
        &self,
        destination_hash: &[u8],
        on_interface: Option<&str>,
    ) -> Result<(), TransportError> {
        let _ = on_interface;
        let dest_hash_array: [u8; 16] = destination_hash.try_into().map_err(|_| {
            TransportError::Config(format!(
                "destination_hash must be 16 bytes, got {}",
                destination_hash.len()
            ))
        })?;
        let dest_hash = DestinationHash::new(dest_hash_array);
        self.node
            .request_path(&dest_hash)
            .await
            .map_err(|e| TransportError::Io(format!("reticulum request_path: {e}")))?;
        Ok(())
    }

    /// Drop a specific path entry by destination hash. v1.1.0
    /// (CIRISEdge#44) — backed by leviculum's now-public
    /// `ReticulumNode::remove_path`. Returns `Ok(())` whether or not
    /// the entry existed (POSIX `rm -f` ergonomics; callers asking to
    /// drop an unknown path get a successful no-op rather than an
    /// error — matches the contract of `routing_blackhole_remove`).
    pub async fn routing_path_drop(&self, destination_hash: &[u8]) -> Result<(), TransportError> {
        let dest_hash_array: [u8; 16] = destination_hash.try_into().map_err(|_| {
            TransportError::Config(format!(
                "destination_hash must be 16 bytes, got {}",
                destination_hash.len()
            ))
        })?;
        let dest_hash = DestinationHash::new(dest_hash_array);
        // Discard the bool — the FFI contract is fire-and-forget
        // idempotent; operators inspect `routing_path_to` afterwards
        // if they need to confirm removal.
        let _ = self.node.remove_path(&dest_hash);
        Ok(())
    }

    /// Drop every path whose `next_hop == transport_identity_hash`.
    /// v1.1.0 (CIRISEdge#44) — backed by leviculum's now-public
    /// `ReticulumNode::drop_all_paths_via`. The return count is
    /// dropped on the FFI floor; operators inspect
    /// `routing_path_table` afterwards if they need to confirm bulk
    /// removal.
    pub async fn routing_path_drop_via(
        &self,
        transport_identity_hash: &[u8],
    ) -> Result<(), TransportError> {
        let via_array: [u8; 16] = transport_identity_hash.try_into().map_err(|_| {
            TransportError::Config(format!(
                "transport_identity_hash must be 16 bytes, got {}",
                transport_identity_hash.len()
            ))
        })?;
        let via_hash = DestinationHash::new(via_array);
        let _ = self.node.drop_all_paths_via(&via_hash);
        Ok(())
    }

    /// Snapshot every blackhole rule. v0.16.1 (CIRISPersist#120 flip)
    /// — backed by persist's V052 `cirislens.blackhole_rules` table.
    /// Returns `TransportError::Config("blackhole rules unavailable")`
    /// when the transport was constructed without a
    /// `ReticulumAuth.blackhole_rules` backend.
    #[cfg(feature = "ffi-uniffi")]
    pub async fn routing_blackhole_list(
        &self,
    ) -> Result<Vec<crate::ffi::uniffi_types::EdgeBlackholeEntry>, TransportError> {
        let store = self
            .blackhole
            .as_ref()
            .ok_or_else(|| TransportError::Config("blackhole rules unavailable".into()))?;
        let rows = store
            .blackhole_list()
            .await
            .map_err(|e| TransportError::Io(format!("blackhole_list: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|rec| crate::ffi::uniffi_types::EdgeBlackholeEntry {
                identity_hash: rec.identity_hash,
                until: rec.until.map(|t| t.to_rfc3339()),
                reason: rec.reason,
                added_at: rec.added_at.to_rfc3339(),
                // Persist's `BlackholeRecord.hits` is i64 (DB-native).
                // Edge's wire surface is u64; saturating cast for
                // negative-impossible defensive posture.
                #[allow(clippy::cast_sign_loss)]
                hits: rec.hits.max(0) as u64,
            })
            .collect())
    }

    /// Add or replace a blackhole rule. `until` is RFC-3339 UTC; pass
    /// `None` for a permanent rule. `reason` is an operator note.
    ///
    /// v0.16.1 (CIRISPersist#120 flip) — backed by persist's V052
    /// `cirislens.blackhole_rules` table; operator-intent fields
    /// (`until`, `reason`) are overwritten on conflict but `hits` and
    /// `added_at` are preserved (re-upsert is intent-change, not
    /// counter-reset — distinct from the v0.15.0 in-memory shape
    /// which reset `hits` on replace).
    pub async fn routing_blackhole_add(
        &self,
        identity_hash: &[u8],
        until: Option<&str>,
        reason: Option<&str>,
    ) -> Result<(), TransportError> {
        if identity_hash.is_empty() {
            return Err(TransportError::Config(
                "identity_hash must be non-empty".into(),
            ));
        }
        // Persist enforces a 16-byte length; surface the bad-length
        // path as our typed Config error rather than letting it leak
        // through as the persist error variant.
        if identity_hash.len() != 16 {
            return Err(TransportError::Config(format!(
                "identity_hash must be 16 bytes, got {}",
                identity_hash.len()
            )));
        }
        let until_parsed = if let Some(s) = until {
            Some(
                chrono::DateTime::parse_from_rfc3339(s)
                    .map_err(|e| TransportError::Config(format!("until is not RFC-3339: {e}")))?
                    .with_timezone(&chrono::Utc),
            )
        } else {
            None
        };
        let store = self
            .blackhole
            .as_ref()
            .ok_or_else(|| TransportError::Config("blackhole rules unavailable".into()))?;
        store
            .blackhole_upsert(identity_hash, until_parsed, reason)
            .await
            .map_err(|e| TransportError::Io(format!("blackhole_upsert: {e}")))
    }

    /// Remove a blackhole rule. Idempotent: returns `Ok(())` whether
    /// or not the rule existed (POSIX `rm -f` ergonomics; persist's
    /// `blackhole_remove` is silent-no-op on unknown identity).
    pub async fn routing_blackhole_remove(
        &self,
        identity_hash: &[u8],
    ) -> Result<(), TransportError> {
        if identity_hash.len() != 16 {
            return Err(TransportError::Config(format!(
                "identity_hash must be 16 bytes, got {}",
                identity_hash.len()
            )));
        }
        let store = self
            .blackhole
            .as_ref()
            .ok_or_else(|| TransportError::Config("blackhole rules unavailable".into()))?;
        store
            .blackhole_remove(identity_hash)
            .await
            .map_err(|e| TransportError::Io(format!("blackhole_remove: {e}")))
    }

    /// v0.18.0 (CIRISEdge#33 background-pruner wiring) — expose the
    /// concrete `Arc<dyn BlackholeRules>` to the [`crate::Edge::run`]
    /// background pruner spawn. Returns `None` when the transport was
    /// built without a backend (test fixtures); the spawn site skips
    /// the task in that case. The clone is cheap (Arc refcount bump);
    /// the actual `blackhole_prune_expired` work happens on the
    /// pruner task's own future, not on this accessor.
    #[must_use]
    pub fn blackhole_rules_handle(
        &self,
    ) -> Option<Arc<dyn ciris_persist::federation::BlackholeRules>> {
        self.blackhole.clone()
    }

    /// Drop every rule whose `until` is in the past relative to `now`.
    /// Returns the number of rows pruned. Permanent rules (`until IS
    /// NULL`) are NEVER pruned — operators must call
    /// [`Self::routing_blackhole_remove`] explicitly.
    ///
    /// v0.18.0 (CIRISEdge#33 background-pruner wiring) — the
    /// [`crate::Edge::run`] task graph now spawns a background loop
    /// that calls this method at
    /// [`crate::EdgeConfig::blackhole_prune_interval_seconds`]
    /// cadence. Operators may still invoke it manually via the
    /// routing-table FFI for on-demand cleanup (e.g. immediately
    /// after editing the deny-list).
    pub async fn routing_blackhole_prune_expired(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, TransportError> {
        let store = self
            .blackhole
            .as_ref()
            .ok_or_else(|| TransportError::Config("blackhole rules unavailable".into()))?;
        store
            .blackhole_prune_expired(now)
            .await
            .map_err(|e| TransportError::Io(format!("blackhole_prune_expired: {e}")))
    }

    /// Snapshot the per-identity announce rate table. v1.1.0
    /// (CIRISEdge#44) — backed by leviculum's now-public
    /// `ReticulumNode::rate_table_entries` (each row is a deep
    /// `RateTableExport` clone). The wire shape projects:
    ///
    /// * `identity_hash` ← `hash` (Reticulum 16-byte destination hash)
    /// * `announce_freq_per_min` — computed from `last_ms`. Leviculum's
    ///   rate table doesn't carry an explicit frequency value; it
    ///   tracks `last_ms` (last accepted announce timestamp) and
    ///   `rate_violations` (cap breaches). We can't reconstruct the
    ///   sliding-window rate from a single observation; v1.1.0 emits
    ///   `0.0` and documents this on the wire shape.
    /// * `violations` ← `rate_violations`
    /// * `blocked_until` ← wall-clock projection of `blocked_until_ms`
    ///   when `> 0`; `None` when the identity is not currently
    ///   blocked.
    #[cfg(feature = "ffi-uniffi")]
    pub async fn routing_rate_table(&self) -> Vec<crate::ffi::uniffi_types::EdgeRateEntry> {
        let raw = self.node.rate_table_entries();
        raw.into_iter()
            .map(|entry| {
                let blocked_until = if entry.blocked_until_ms > 0 {
                    Some(
                        self.project_monotonic_ms(entry.blocked_until_ms)
                            .to_rfc3339(),
                    )
                } else {
                    None
                };
                crate::ffi::uniffi_types::EdgeRateEntry {
                    identity_hash: entry.hash.to_vec(),
                    // Sliding-window rate is not stored in Leviculum's
                    // rate-table export; emitted as 0.0 with the
                    // contract noted in the doc-comment + wire-shape
                    // docblock on `EdgeRateEntry`.
                    announce_freq_per_min: 0.0,
                    violations: u32::from(entry.rate_violations),
                    blocked_until,
                }
            })
            .collect()
    }

    /// Seconds since this `ReticulumTransport` was constructed.
    /// Monotonic. Backs the FFI `routing_transport_uptime`.
    #[must_use]
    pub fn routing_transport_uptime(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// The routing-layer transport identity hash (16 bytes). Mirrors
    /// `ReticulumNode::identity_hash`.
    #[must_use]
    pub fn routing_transport_id(&self) -> Vec<u8> {
        self.node.identity_hash().to_vec()
    }

    /// Snapshot the tunnel synthesize table. v1.1.0 (CIRISEdge#44) —
    /// permanently returns `Vec::new()` in this Leviculum fork. The
    /// CIRISAI/leviculum fork does NOT maintain a tunnels collection:
    /// only `tunnel_synthesize_hash` is computed (a single
    /// well-known hash for control-destination routing), not a
    /// populated `tunnels` dictionary. The wire shape stays pinned
    /// for forward-compat with a future Leviculum cut that grows the
    /// data structure.
    #[cfg(feature = "ffi-uniffi")]
    #[must_use]
    pub async fn routing_tunnels(&self) -> Vec<crate::ffi::uniffi_types::EdgeTunnelInfo> {
        Vec::new()
    }

    /// Snapshot the in-flight outbound announce retry queue. v1.1.0
    /// (CIRISEdge#44) — permanently returns `Vec::new()` in this
    /// Leviculum fork. The retry-queue collection (`retry_queues` in
    /// reticulum-std::driver) is scoped to the driver event loop and
    /// not surfaced on `ReticulumNode` at any visibility level. The
    /// wire shape stays pinned for forward-compat.
    #[cfg(feature = "ffi-uniffi")]
    #[must_use]
    pub async fn routing_announce_table(
        &self,
    ) -> Vec<crate::ffi::uniffi_types::EdgeInFlightAnnounce> {
        Vec::new()
    }

    /// Snapshot the reverse routing table (debugging surface). v1.1.0
    /// (CIRISEdge#44) — permanently returns `Vec::new()` in this
    /// Leviculum fork. The underlying `ReverseEntry` shape stores
    /// `(timestamp_ms, receiving_interface_index,
    /// outbound_interface_index)` keyed by packet hash — it does NOT
    /// carry `source_hash` or `destination_hash` which Edge's wire
    /// shape (`EdgeReverseEntry { source_hash, destination_hash,
    /// last_seen_at }`) requires. Closing this gap needs a Leviculum
    /// design pass to expand ReverseEntry, not just a visibility
    /// widening.
    #[cfg(feature = "ffi-uniffi")]
    #[must_use]
    pub async fn routing_reverse_table(&self) -> Vec<crate::ffi::uniffi_types::EdgeReverseEntry> {
        Vec::new()
    }

    /// CIRISEdge#33 — internal blackhole check. Returns a typed
    /// `TransportError::PeerBlackholed` if `identity_hash` is on the
    /// deny-list (after skipping expired entries — `blackhole_list`
    /// returns all rows including expired ones, so the check filters
    /// `until <= now` here rather than relying on `prune_expired` to
    /// have run); also fires off a `record_hit` to bump the counter.
    /// Called from `send` BEFORE the leviculum connect.
    ///
    /// v0.16.1 (CIRISPersist#120 flip) — the rule lookup is a single
    /// `blackhole_list` round-trip; production deployments expecting
    /// large deny-lists should batch hits client-side per the
    /// `BlackholeRules::blackhole_record_hit` docblock. The hit
    /// increment is fire-and-forget (`tokio::spawn`) so the send-path
    /// latency stays at one DB read.
    ///
    /// When the transport was built without a blackhole backend
    /// (`ReticulumAuth.blackhole_rules == None`), this is a silent
    /// no-op — the send proceeds. Tests that don't care about
    /// blackhole semantics typically omit the backend.
    async fn check_blackhole(&self, identity_hash: &[u8]) -> Result<(), TransportError> {
        let Some(store) = self.blackhole.as_ref() else {
            return Ok(());
        };
        // Pull the full row set; v0.16.1 cohabitation deployments have
        // operator-curated deny-lists in the low-dozens range. A
        // future cut can pivot to a single-row lookup primitive if
        // persist exposes one (the trait surface today is
        // `blackhole_list` only — see #120 docblock for the rationale
        // of batched-flush over per-row lookup).
        let rows = store
            .blackhole_list()
            .await
            .map_err(|e| TransportError::Io(format!("blackhole_list (check): {e}")))?;
        let now = chrono::Utc::now();
        for rec in rows {
            if rec.identity_hash != identity_hash {
                continue;
            }
            if let Some(until) = rec.until {
                if now >= until {
                    // Expired rule — let send proceed. A background
                    // pruner (deferred to a follow-up cut) will drop
                    // it lazily; in the interim operators can call
                    // `routing_blackhole_prune_expired` manually.
                    return Ok(());
                }
            }
            // Live hit — fire-and-forget the hit-record so the
            // counter reflects observation. `record_hit` is race-
            // tolerant (silent no-op if the rule was removed between
            // our check and the spawned increment), so the spawned
            // task's outcome doesn't affect correctness.
            let store_clone = Arc::clone(store);
            let hash_clone = identity_hash.to_vec();
            tokio::spawn(async move {
                if let Err(e) = store_clone.blackhole_record_hit(&hash_clone).await {
                    tracing::warn!(
                        ?hash_clone,
                        error = %e,
                        "blackhole_record_hit failed; the rule blocked the send \
                         correctly but the hits counter did not advance",
                    );
                }
            });
            return Err(TransportError::PeerBlackholed {
                identity_hash: rec.identity_hash,
                reason: rec.reason,
                until: rec.until.map(|t| t.to_rfc3339()),
            });
        }
        Ok(())
    }

    /// Resolve a `destination_key_id` to a Reticulum peer. Consults
    /// the **rooted** announce map first (every entry has cleared the
    /// CIRISEdge#15 cold-start path), then the out-of-band injected
    /// [`PeerResolver`]. Returns `None` if neither yields the peer.
    async fn resolve_peer(&self, destination_key_id: &str) -> Option<ResolvedPeer> {
        if let Some(rooted) = self.peers.lock().await.get(destination_key_id) {
            return Some(rooted.peer);
        }
        let resolver = self.resolver.as_ref()?;
        let pubkey = resolver.resolve(destination_key_id)?;
        let mut x25519 = [0u8; 32];
        let mut ed25519 = [0u8; 32];
        x25519.copy_from_slice(&pubkey[..32]);
        ed25519.copy_from_slice(&pubkey[32..]);

        // v7.0.0 (CIRISEdge#191 / #195) — Leviculum v0.7.0 explicit-
        // hash addressing. When the resolver knows the peer's
        // federation Ed25519 pubkey (v6.0.0 directory-cache path), we
        // route to `sha256(fed_pubkey)[..16]` — the SAME hash the
        // packet-radio / HTTP transports derive — and dial via
        // `node.connect_at(dest_hash, &transport_ed25519)`. The
        // transport-tier Ed25519 still signs link proofs (it remains
        // the destination's structural identity); only the routing
        // index becomes content-addressed by the federation key.
        //
        // When the resolver returns `None` for the federation pubkey
        // (v0.6.x-era resolvers that only know the transport
        // dual-key), fall back to the legacy announce-bound formula —
        // peers that haven't yet adopted v7.0.0 stay reachable.
        let dest_hash =
            if let Some(fed_pubkey) = resolver.resolve_federation_pubkey(destination_key_id) {
                DestinationHash::new(
                    crate::transport::addressing::reticulum_destination_for_pubkey(&fed_pubkey),
                )
            } else {
                let identity = Identity::from_public_keys(&x25519, &ed25519).ok()?;
                // Legacy v0.6.x path: `sha256(name_hash || identity_hash)`.
                let name_hash = Destination::compute_name_hash(EDGE_APP_NAME, &[EDGE_APP_ASPECT]);
                Destination::compute_destination_hash(&name_hash, identity.hash())
            };
        Some(ResolvedPeer {
            dest_hash,
            signing_key: ed25519,
        })
    }

    /// CIRISEdge#353 — the newest LIVE link already attributed to this peer
    /// (the reverse path). Scans `link_to_peer_key_id` — populated by
    /// `LinkIdentified` (the peer dialed + identified to us) — and keeps only
    /// links leviculum still holds `Active` (`link_is_established` resolves
    /// the #66 re-key alias, so a re-keyed inbound link still matches).
    /// Newest-established wins when a peer holds several.
    async fn live_attributed_link_to(&self, destination_key_id: &str) -> Option<LinkId> {
        let candidates: Vec<LinkId> = self
            .link_to_peer_key_id
            .lock()
            .await
            .iter()
            .filter(|(_, peer)| peer.as_str() == destination_key_id)
            .map(|(id, _)| *id)
            .collect();
        let established_at = self.link_established_at.lock().await;
        candidates
            .into_iter()
            .filter(|id| self.node.link_is_established(id))
            .max_by_key(|id| established_at.get(id).copied().unwrap_or(0))
    }

    /// CIRISEdge#353 — REVERSE PATH FIRST. If the peer holds a LIVE link to us
    /// that it dialed + identified (a NAT'd / initiator-only peer's ONLY
    /// connectivity), the reply rides THAT link — a fresh outbound dial to
    /// such a peer is structurally impossible and burned 30 s per kind per
    /// round forever in the field (Node A ↔ Android emulator, the first
    /// mobile trace's last leg). Symmetric topologies also win: no dial
    /// round-trip when a live link already exists. No `identify_link` here —
    /// we are not this link's initiator (RNS permits only the initiator to
    /// identify); the peer attributes our reply by the dest it dialed
    /// (leviculum v0.9.2 `link_destination`, the other half of #353).
    ///
    /// #353 residual (field-verified on Node A, v13.1.1): Reticulum allows ONE
    /// resource transfer per link at a time, and the reply routinely collides
    /// with the peer's own inbound payload mid-transfer. The first cut fell
    /// back to the outbound dial on THAT error — the exact NAT hole the
    /// reverse path exists to avoid (the field signature: links closing
    /// `Timeout` instead of `PeerClosed`). Now a BUSY link is RETRIED with
    /// backoff for [`REVERSE_PATH_BUSY_RETRY_WINDOW`] — transfers drain in
    /// seconds and the link is still up — re-resolving the live link each
    /// attempt (if the original dies and the peer re-dials mid-window, the
    /// retry rides the fresh link). The outbound dial is the LAST resort,
    /// reached only when retries exhaust or the failure is not `busy`.
    ///
    /// Returns `true` iff the envelope was DELIVERED over the reverse path;
    /// `false` means fall through to the outbound dial (each stage logged
    /// distinctly + throttled so the RCA classifier can tell them apart).
    async fn send_via_reverse_path(&self, destination_key_id: &str, envelope_bytes: &[u8]) -> bool {
        let deadline = tokio::time::Instant::now() + REVERSE_PATH_BUSY_RETRY_WINDOW;
        let mut attempts: u32 = 0;
        loop {
            let Some(link_id) = self.live_attributed_link_to(destination_key_id).await else {
                if attempts > 0 {
                    // The link died mid-retry and the peer has not re-dialed.
                    if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                        reverse_path_fallback_log().check(destination_key_id)
                    {
                        tracing::warn!(
                            destination_key_id,
                            attempts,
                            suppressed_prev,
                            "reverse-path link died during busy-retry and no fresh inbound \
                             link exists; falling back to an outbound dial (CIRISEdge#353)"
                        );
                    }
                }
                return false;
            };
            attempts += 1;
            match self.ship_resource_on_link(&link_id, envelope_bytes).await {
                Ok(()) => {
                    tracing::debug!(
                        destination_key_id,
                        link = ?link_id,
                        attempts,
                        "delivered over the peer's live inbound link (reverse path, \
                         CIRISEdge#353)"
                    );
                    return true;
                }
                Err(ShipError::Busy) => {
                    if tokio::time::Instant::now() + REVERSE_PATH_BUSY_BACKOFF >= deadline {
                        if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                            reverse_path_fallback_log().check(destination_key_id)
                        {
                            tracing::warn!(
                                destination_key_id,
                                link = ?link_id,
                                attempts,
                                window_secs = REVERSE_PATH_BUSY_RETRY_WINDOW.as_secs(),
                                suppressed_prev,
                                "reverse-path link stayed BUSY (resource transfer in \
                                 progress) through the whole retry window; falling back \
                                 to an outbound dial as LAST resort (CIRISEdge#353)"
                            );
                        }
                        return false;
                    }
                    tokio::time::sleep(REVERSE_PATH_BUSY_BACKOFF).await;
                }
                Err(ShipError::Other(e)) => {
                    if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                        reverse_path_fallback_log().check(destination_key_id)
                    {
                        tracing::warn!(
                            destination_key_id,
                            link = ?link_id,
                            error = %e,
                            attempts,
                            suppressed_prev,
                            "reverse-path send over the peer's inbound link failed \
                             (non-busy); falling back to an outbound dial (CIRISEdge#353)"
                        );
                    }
                    return false;
                }
            }
        }
    }

    /// Ship one envelope as a resource over an ALREADY-ESTABLISHED link and
    /// wait for the sender-side `ResourceCompleted`. The shared tail of both
    /// send paths (fresh outbound dial AND the #353 reverse path) — one body so
    /// the two can never diverge (the #348 two-loops lesson).
    ///
    /// Errors are classified at the TYPED leviculum seam: `ShipError::Busy` is
    /// the Reticulum one-resource-transfer-per-link constraint
    /// (`ResourceError::TransferInProgress`) — retryable, the link is healthy —
    /// vs `ShipError::Other` for everything else. String-matching the Display
    /// text would be the fragile version of this; the enum can't reword.
    async fn ship_resource_on_link(
        &self,
        link_id: &LinkId,
        envelope_bytes: &[u8],
    ) -> Result<(), ShipError> {
        // CIRISEdge#353 test seam — deterministically simulate the
        // one-transfer-per-link collision (see `test_force_busy`).
        if self
            .test_force_busy
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |n| n.checked_sub(1),
            )
            .is_ok()
        {
            return Err(ShipError::Busy);
        }
        // Auto-accept any resources the peer pushes back on this link
        // (e.g. an ACK envelope), and ship our envelope as a resource.
        let _ = self
            .node
            .set_resource_strategy(link_id, ResourceStrategy::AcceptAll);
        let resource_hash = self
            .node
            .send_resource(link_id, envelope_bytes, None, true)
            .await
            .map_err(|e| match e {
                reticulum_std::error::Error::Resource(
                    reticulum_core::resource::ResourceError::TransferInProgress,
                ) => ShipError::Busy,
                other => ShipError::Other(TransportError::Io(format!(
                    "reticulum send_resource: {other}"
                ))),
            })?;

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
            return Err(ShipError::Other(TransportError::Timeout(
                RESOURCE_TRANSFER_TIMEOUT,
            )));
        }
        Ok(())
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

        let Some(peer) = self.resolve_peer(destination_key_id).await else {
            // CIRISEdge#292 (CIRISServer#205) — an admitted replication
            // target whose Reticulum destination we can't resolve is the
            // silent-zero-delivery class: the round fires, this send
            // fails, and without this line nothing in the log says why.
            // WARN naming the actionable causes (explicit-hash peers must
            // be `prime_peer`'d; announce-rooted peers need a received
            // announce) so an unrooted-but-admitted peer is a log line,
            // not a live-map interrogation. `knows_peer(key_id)` is the
            // readback for the same condition.
            tracing::warn!(
                destination_key_id,
                "replication/send: target is admitted but NOT rooted \
                 (knows_peer=false) — no Reticulum destination resolved. \
                 Cause: a v7 explicit-hash peer (e.g. ciris-canonical-1) that \
                 was never prime_peer'd, or an announce-rooted peer whose \
                 announce has not been received. This send cannot address the \
                 peer; anti-entropy will not converge until it roots."
            );
            // §24 NAT-traversal (CIRISEdge#169): an unreachable
            // destination under `PendingOrLive` with a wired queue is
            // stored for the destination's wake-up fetch rather than
            // failed. Admission-time hybrid-PQC verification is the
            // operator's concern; the queued bytes are the byte-exact
            // signed envelope, carried verbatim.
            if self.delivery == crate::transport::PendingDelivery::PendingOrLive {
                if let Some(saf) = &self.store_and_forward {
                    saf.queue(destination_key_id, envelope_bytes)
                        .map_err(|e| TransportError::Io(format!("store-and-forward queue: {e}")))?;
                    tracing::info!(
                        destination_key_id,
                        "replication/send: unrooted target queued for \
                         store-and-forward wake-up fetch (§24)"
                    );
                    return Ok(TransportSendOutcome::Queued);
                }
            }
            return Err(TransportError::Unreachable(format!(
                "no Reticulum destination known for destination_key_id={destination_key_id} \
                 (not directory-resolvable and no announce received)"
            )));
        };

        // CIRISEdge#33 (v0.15.0) — operator-deny-list check BEFORE the
        // leviculum connect call. The blackhole keys on the peer's
        // 16-byte Reticulum destination_hash (the same bytes
        // `path_table` returns), so an operator that snapshots the
        // path table and decides to ban a peer can pass the hash back
        // unchanged. Resolves `key_id → dest_hash` via `resolve_peer`
        // above — peers not yet resolved are not blackhole-checkable
        // (they couldn't be sent to anyway, so the check is
        // semantically inert at that point).
        let dest_hash_bytes = peer.dest_hash.into_bytes();
        self.check_blackhole(&dest_hash_bytes).await?;

        // CIRISEdge#353 — REVERSE PATH FIRST (see `send_via_reverse_path`).
        // Ordered AFTER the blackhole check so an operator ban still wins.
        if self
            .send_via_reverse_path(destination_key_id, envelope_bytes)
            .await
        {
            return Ok(TransportSendOutcome::Delivered);
        }

        // CIRISEdge#336 — the no-path GUARD. Decide the establishment window
        // from whether the node holds a path to this exact dest BEFORE dialing.
        // A no-path dest is broadcast-only (leviculum sends the link request
        // with hops=1) and can be answered only by a directly-attached
        // neighbor in one round-trip — so it establishes fast or never. A
        // relay-reachable peer has a path and gets the patient window. This is
        // the tripwire that ends the rooting saga's whack-a-mole: a send aimed
        // at an un-routable dest (e.g. the un-announceable explicit-hash while
        // the peer is only reachable on its named dest) fails FAST and LOUD
        // with every operand named, instead of a silent 30 s opaque timeout.
        let has_path = self.node.has_path(&peer.dest_hash);
        let establish_timeout = if has_path {
            LINK_ESTABLISH_TIMEOUT
        } else {
            NO_PATH_ESTABLISH_TIMEOUT
        };

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
        // CIRISEdge#342 — poll leviculum's ALIAS-RESOLVING establishment query,
        // not edge's own `established_links` set. On a lossy path the #66
        // establishment retry re-keys the link under a fresh wire id; the
        // `LinkEstablished` event (hence `established_links`) then carries the
        // RE-KEYED id, while we hold connect's ORIGINAL id. A raw
        // `established_links.contains(&original)` never matches → we time out →
        // never reach `send_resource` → 0 Data frames → the link idles to a
        // keepalive death (the field symptom on the remote/canonical path).
        // `link_is_established` resolves the origin id through leviculum's #66
        // alias table and gates on `LinkState::Active`.
        let established =
            wait_until_async(establish_timeout, Duration::from_millis(50), || async {
                self.node.link_is_established(&link_id)
            })
            .await;
        if !established {
            // CIRISEdge#336 — a no-path target that never established is
            // un-routable, not slow: fail fast with the self-diagnosing error
            // (naming target dest, key_id, and the paths we DO hold — the
            // routable named dest for this peer usually appears there, making
            // the explicit-vs-named mismatch obvious). A had-a-path target that
            // stalled is a genuine slow/dead link → the opaque timeout stands.
            if !has_path {
                let target_dest = hex::encode(peer.dest_hash.into_bytes());
                let paths = self.path_table_snapshot();
                tracing::error!(
                    key_id = %destination_key_id,
                    target_dest = %target_dest,
                    has_path,
                    known_paths = %paths,
                    "link_request target has no route — un-routable dest (CIRISEdge#336). \
                     A no-path dest is broadcast-only and no directly-attached neighbor \
                     answered; if the peer is relay-reachable it must be addressed on its \
                     announced (named) dest, which appears in known_paths."
                );
                return Err(TransportError::NoRouteToPeer {
                    key_id: destination_key_id.to_string(),
                    target_dest,
                    has_path,
                    paths,
                });
            }
            log_nat_topology_diagnosis(destination_key_id, establish_timeout);
            return Err(TransportError::Timeout(establish_timeout));
        }

        // CIRISEdge#340 — IDENTIFY the link before sending. A Reticulum link is
        // anonymous by default; only the initiator may identify it, and the
        // responder emits `LinkIdentified` (→ populates its `link_to_peer_key_id`
        // via the #314 identity-hash match → attributes our inbound frame) ONLY
        // if we do. Without this, every replication frame we send lands on the
        // responder as `source_key_id=None` and is dropped `SkippedNoSourceKeyId`
        // (#317) — the field-confirmed reason attribution never fired and
        // CIRISServer#235 was never verified end-to-end. Ordered before
        // `send_resource` on the same link so the LINKIDENTIFY is processed
        // first. A failure here means the responder cannot attribute the frame,
        // so fail the send (the durable dispatcher retries) rather than ship an
        // unattributable resource that will be silently dropped.
        self.node
            .identify_link(&link_id, &self.local_identity)
            .await
            .map_err(|e| TransportError::Io(format!("reticulum identify_link: {e}")))?;

        // The outbound-dial path we just established this link; a `Busy`
        // collision here is not the reverse-path retry case, so both variants
        // surface as the send's transport error (the durable dispatcher retries).
        self.ship_resource_on_link(&link_id, envelope_bytes)
            .await
            .map_err(ShipError::into_transport)?;

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
            named_dest = %self.local_named_dest_hash,
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
                    "Reticulum transport listening on {} (dest {}, named-dest {})",
                    self.config.listen_addr, self.local_dest_hash, self.local_named_dest_hash,
                ),
            ));
        }

        // v7.4.0 (CIRISEdge#231) — announce edge's NAMED destination
        // (the standard RNS `sha256(name_hash || identity_hash)`),
        // NOT the explicit-hash. The explicit-hash is unannounceable
        // by Leviculum guard — every v7.0.0–v7.3.x cut WARN-spammed
        // on every tick because the announce loop was pointed at it.
        // Now any RNS fabric learning our announce gets a routable
        // path to `local_named_dest_hash`. The explicit-hash stays
        // registered for direct-dial / prime_peer back-compat.
        //
        // The app-data is edge's signed announce attestation
        // (CIRISEdge#15 send side) — a federation-key signature
        // binding this transport identity to `local_key_id`. When no
        // signer was supplied the announce carries empty app-data and
        // rooting peers drop it (fail-honest).
        let app_data: &[u8] = self.local_attestation.as_deref().unwrap_or(&[]);
        if let Err(e) = self
            .node
            .announce_destination(&self.local_named_dest_hash, Some(app_data))
            .await
        {
            tracing::warn!(error = %e, "initial announce (named destination) failed");
        }
        let mut announce_tick = tokio::time::interval(self.config.announce_interval);
        announce_tick.tick().await; // consume the immediate first tick

        // CIRISEdge#336 (fast heal) — rate-limit gate for event-driven announces.
        // `None` until the first link-up, so the first connecting peer triggers an
        // announce immediately.
        let mut last_event_announce: Option<std::time::Instant> = None;

        loop {
            tokio::select! {
                _ = announce_tick.tick() => {
                    if let Err(e) = self
                        .node
                        .announce_destination(&self.local_named_dest_hash, Some(app_data))
                        .await
                    {
                        tracing::warn!(error = %e, "periodic announce (named destination) failed");
                    }
                }
                event = events.recv() => {
                    let Some(event) = event else {
                        tracing::info!("Reticulum event channel closed; listener exiting");
                        break;
                    };
                    // CIRISEdge#336 (fast heal) — RNS-aligned event-driven announce.
                    // A `LinkEstablished` means a peer just connected; re-announce so
                    // it learns our routable NAMED dest in seconds (→ the #336 belt
                    // heals its route now, not after the next ~5 min periodic tick).
                    // Rate-limited so rapid link churn can't storm announces.
                    let link_just_established =
                        matches!(event, NodeEvent::LinkEstablished { .. });
                    let ctx = EventCtx {
                        node: &self.node,
                        peers: &self.peers,
                        established_links: &self.established_links,
                        sent_resources: &self.sent_resources,
                        sink: &sink,
                        rooting: self.rooting.as_deref(),
                        hybrid_policy: self.hybrid_policy,
                        transport_binding_enforcement: self.transport_binding_enforcement,
                        event_bus: self.event_bus.as_deref(),
                        reachability: self.reachability.as_ref(),
                        link_established_at: &self.link_established_at,
                        request_responses: &self.request_responses,
                        timed_out_requests: &self.timed_out_requests,
                        link_to_peer_key_id: &self.link_to_peer_key_id,
                    };
                    handle_event(event, &ctx).await;

                    // `map_or(true, …)` not `is_none_or` — MSRV 1.75 (is_none_or is 1.82).
                    if link_just_established
                        && last_event_announce
                            .map_or(true, |t| t.elapsed() >= EVENT_ANNOUNCE_MIN_INTERVAL)
                    {
                        last_event_announce = Some(std::time::Instant::now());
                        match self
                            .node
                            .announce_destination(&self.local_named_dest_hash, Some(app_data))
                            .await
                        {
                            Ok(()) => tracing::debug!(
                                "event-driven announce on link-up — RNS-aligned fast \
                                 convergence (CIRISEdge#336)"
                            ),
                            Err(e) => tracing::warn!(
                                error = %e,
                                "event-driven announce (link up) failed"
                            ),
                        }
                    }
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
    /// CIRISEdge#205 (AV-42 Phase 4) — RNS destination-hash binding
    /// enforcement posture applied in [`resolve_announce_cold_start`].
    transport_binding_enforcement: TransportBindingEnforcement,
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
    /// v3.5.1 (CIRISEdge#119 + #120) — per-link rooted-peer
    /// attribution. Populated on `NodeEvent::LinkIdentified` after
    /// matching the link's remote identity to a rooted peer; consumed
    /// on `NodeEvent::ResourceCompleted` to populate
    /// `InboundFrame::source_key_id` for the
    /// `Edge::install_replication_routing` lookup.
    link_to_peer_key_id: &'a Mutex<HashMap<LinkId, String>>,
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
        // v7.2.0: Leviculum v0.8.x upstream auto-accepts inbound link
        // requests internally — the v0.7.x `NodeEvent::LinkRequest` +
        // `node.accept_link(...)` dance is gone. We now hear the
        // already-accepted link via `LinkEstablished` directly on the
        // responder side; the resource strategy + bookkeeping run there.
        NodeEvent::LinkEstablished { link_id, .. } => {
            // Auto-accept inbound resources so envelope transfers
            // reassemble without app intervention. Covers BOTH responder
            // (the link the peer just initiated against us) and
            // initiator (so ACK envelopes pushed back are reassembled).
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
            // CIRISEdge#317 observability point 3 — LINKIDENTIFY fired for this
            // link, so attribution can attempt. A frame that later arrives on a
            // link for which get_remote_identity is None is candidate-1
            // (LINKIDENTIFY never completed). DEBUG: this is per-link-establish
            // and attacker-triggerable, so it stays out of the default INFO
            // stream (available under RUST_LOG=debug) — the always-on signal is
            // the point-2 miss WARN + point-1 admit line.
            let remote_identity_present = ctx.node.get_remote_identity(&link_id).is_some();
            tracing::debug!(
                link = ?link_id,
                remote_identity = remote_identity_present,
                link_proven_identity_hash = %hex::encode(identity_hash),
                "link_identified"
            );

            // CIRISEdge#314 — attribute the link to a peer key_id by the link's
            // PROVEN transport identity hash (Branch A, form-agnostic), falling
            // back to the legacy named-dest recompute (Branch B, fast-path). On a
            // miss, `source_key_id` stays `None`, `route_inbound_bytes` is
            // skipped, and the binary CRPL frame falls through to the JSON
            // dispatcher — leaving #312's responder unreachable (CIRISEdge#317).
            let name_hash = Destination::compute_name_hash(EDGE_APP_NAME, &[EDGE_APP_ASPECT]);
            let expected_dest_hash =
                Destination::compute_destination_hash(&name_hash, &identity_hash);
            let peers_guard = ctx.peers.lock().await;
            let matched = peers_guard.iter().find_map(|(k, rp)| {
                if rp.transport_identity_hash == identity_hash {
                    Some((k.clone(), "identity"))
                } else if rp.peer.dest_hash == expected_dest_hash {
                    Some((k.clone(), "dest"))
                } else {
                    None
                }
            });
            // CIRISEdge#317 observability point 2 — the line that localizes the
            // bug in one run. A MATCH is DEBUG (success is not an incident). A
            // MISS is the RCA-critical signal, kept at WARN but THROTTLED
            // (first-N-per-window keyed on link_id, bounded map) so an attacker
            // flooding links can't flood logs. The four operands (link identity,
            // expected dest, remote_identity_present, peers_len) localize the
            // announce-vs-send identity split; the per-peer stored operands ride
            // DEBUG + a cap so the line stays O(1), not O(peers) — closing the
            // prior O(N·M) quadratic-log blowup. The stored side of the compare
            // is separately visible at admit (point 1).
            if let Some((key_id, branch)) = &matched {
                tracing::debug!(
                    link = ?link_id,
                    key_id = %key_id,
                    branch,
                    "link_attribution matched"
                );
            } else {
                let link_key = hex::encode(identity_hash);
                if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                    link_attribution_miss_log().check(&link_key)
                {
                    // First few candidate peers' stored side, capped — only
                    // materialized under DEBUG and never the whole map.
                    let peer_sample: Vec<String> = if tracing::enabled!(tracing::Level::DEBUG) {
                        peers_guard
                            .iter()
                            .take(8)
                            .map(|(k, rp)| {
                                format!(
                                    "{{key_id={k} tid={} dest={}}}",
                                    hex::encode(rp.transport_identity_hash),
                                    hex::encode(rp.peer.dest_hash.into_bytes()),
                                )
                            })
                            .collect()
                    } else {
                        Vec::new()
                    };
                    tracing::warn!(
                        link = ?link_id,
                        link_identity = %link_key,
                        expected_dest = %hex::encode(expected_dest_hash.into_bytes()),
                        remote_identity_present,
                        peers_len = peers_guard.len(),
                        peer_sample = %peer_sample.join(", "),
                        suppressed_prev,
                        "link_attribution_miss — inbound frames from this link cannot be \
                         attributed to a peer key_id (source_key_id will be None); rounds \
                         dropped. Both Branch A (identity) and Branch B (dest) missed \
                         (CIRISEdge#317)"
                    );
                }
            }
            let matched_key = matched.map(|(k, _)| k);
            drop(peers_guard);
            if let Some(key_id) = matched_key {
                ctx.link_to_peer_key_id.lock().await.insert(link_id, key_id);
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
            // v3.5.1 (CIRISEdge#119 + #120) — populate source_key_id
            // from the per-link rooted-peer attribution table when
            // available. `None` falls back to v3.5.0 behavior (no
            // routing fires inside `Edge::install_replication_routing`).
            let mut source_key_id = ctx.link_to_peer_key_id.lock().await.get(&link_id).cloned();
            // CIRISEdge#353 — INITIATOR-side attribution. The table above is
            // fed by `LinkIdentified`, which only fires on links a PEER dialed
            // to us; a reply arriving on a link WE dialed (the reverse path a
            // NAT'd peer's responder now uses) has no entry and would drop as
            // `SkippedNoSourceKeyId`. The stateless, #66-re-key-proof basis is
            // the link's DESTINATION (leviculum v0.9.2 `link_destination`,
            // alias-resolving): we dialed a dest resolved from the VERIFIED
            // route table, and RNS link establishment proves the remote
            // controls that dest's identity keys — so mapping dest → rooted
            // peer attributes the frame on the same trust the outbound send
            // used. A mid-link route supersession can miss here; that falls
            // through to the existing LOUD SkippedNoSourceKeyId path, never a
            // silent drop.
            if source_key_id.is_none() {
                if let Some(dest) = ctx.node.link_destination(&link_id) {
                    source_key_id = ctx
                        .peers
                        .lock()
                        .await
                        .iter()
                        .find(|(_, rooted)| rooted.peer.dest_hash == dest)
                        .map(|(key_id, _)| key_id.clone());
                    if let Some(key_id) = &source_key_id {
                        tracing::debug!(
                            link = ?link_id,
                            peer = %key_id,
                            "inbound frame on a link WE dialed attributed via its \
                             destination (initiator-side reverse path, CIRISEdge#353)"
                        );
                    }
                }
            }
            let frame = InboundFrame {
                envelope_bytes: data,
                transport: TransportId::RETICULUM_RS,
                received_at: Utc::now(),
                source_key_id,
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
            // v3.5.1 (CIRISEdge#119 + #120) — drop the link's rooted
            // peer attribution when the link closes.
            ctx.link_to_peer_key_id.lock().await.remove(&link_id);
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
        destination_hash: None,
        hops: None,
        resource_kind: None,
        measurement: None,
        unit: None,
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
/// The route-table supersession verdict for an admitted announce (CIRISEdge#336
/// belt + CIRISEdge#337 CRITICAL-1 verified-only invariant), factored out as a
/// PURE function so the security-critical decision is exhaustively unit-testable
/// without the event-loop `EventCtx` scaffolding. No I/O, no logging, no clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteSupersession {
    /// No prior entry, or a legitimate supersession / first-root upgrade /
    /// verified reroute-heal — write the incoming route.
    Admit,
    /// A same-or-lower-epoch re-announce with no upgrade and no heal — ignore
    /// (stale); the cached route stands.
    IgnoreStale,
    /// CIRISEdge#337 CRITICAL-1 — an Advisory announce attempting to override a
    /// Rooted route. NEVER written: a self-signed announce (mintable for any
    /// key_id) must not repoint a directory-rooted peer at an attacker dest.
    HijackRefused,
}

/// Decide whether an incoming announce supersedes the cached route for its
/// key_id. `existing` is `(provenance, epoch, dest16)` of the cached entry (if
/// any). `incoming_owns_key` is whether the announcer PROVED control of the key
/// the directory binds to this `key_id` (Confirmed, or an Advisory whose
/// rejection was neither `UnknownKeyId` nor `PubkeyMismatch` — i.e. the pubkey
/// matched and the announce self-verified). This is the load-bearing signal
/// that separates the OWNER rerouting its own dest from a SPOOF.
///
/// Order is load-bearing: the hijack gate is checked FIRST, before any epoch
/// comparison, so a `u64::MAX`-epoch spoof cannot poison a rooted route.
fn route_supersession_decision(
    existing: Option<(
        ciris_persist::federation::self_at_login::BindingProvenance,
        u64,
        [u8; 16],
    )>,
    incoming_provenance: ciris_persist::federation::self_at_login::BindingProvenance,
    incoming_owns_key: bool,
    incoming_epoch: u64,
    incoming_dest16: [u8; 16],
) -> RouteSupersession {
    use ciris_persist::federation::self_at_login::BindingProvenance::{Advisory, Rooted};
    let Some((ex_prov, ex_epoch, ex_dest16)) = existing else {
        // Fresh peer — nothing to supersede.
        return RouteSupersession::Admit;
    };
    // CRITICAL-1 (#337), FIRST and epoch-independent: a Rooted route is never
    // superseded by an announce that CANNOT prove ownership of the key. This
    // refuses the AV-42 spoof (`PubkeyMismatch`: the attacker's federation key ≠
    // the directory's key for the victim's key_id, or `UnknownKeyId`) at any
    // epoch. It does NOT refuse the OWNER re-announcing (which proves ownership
    // via a pubkey match + self-verified signature) — that is the belt, below.
    // #336 regression: the pre-fix gate refused on `Advisory` provenance alone,
    // so the owner's genuine (Advisory, not-steward-rooted) announce hit this and
    // the boot-prime never healed. Provenance is TRUST; ownership is IDENTITY —
    // routing keys on identity, not trust (rooting≠routing, one level up).
    if matches!(ex_prov, Rooted) && !incoming_owns_key {
        return RouteSupersession::HijackRefused;
    }
    // A strictly-newer epoch always supersedes (a genuine transport-identity
    // rotation, or a rooted upgrade at a higher epoch) — the hijack gate above
    // has already excluded a non-owning announce over a rooted route.
    if incoming_epoch > ex_epoch {
        return RouteSupersession::Admit;
    }
    if incoming_epoch == ex_epoch {
        // CIRISEdge#301 — advisory→rooted first-root upgrade at equal epoch.
        let advisory_to_rooted_upgrade =
            matches!(ex_prov, Advisory) && matches!(incoming_provenance, Rooted);
        // CIRISEdge#336 BELT — the OWNER (ownership proven) rerouting to a
        // DIFFERENT dest at the same epoch heals the route (the explicit→named
        // boot-prime trap: existing Rooted@0 on the explicit dest, genuine
        // announce Advisory@0 on the named dest — same owner, so a legitimate
        // routing update, not a hijack). Gated on `incoming_owns_key`, NOT on
        // provenance, so the Advisory-but-owner case (the actual field case)
        // heals while a spoof (already refused above) cannot reach here.
        let owner_reroute = incoming_owns_key && incoming_dest16 != ex_dest16;
        if advisory_to_rooted_upgrade || owner_reroute {
            return RouteSupersession::Admit;
        }
    }
    // Lower epoch, or equal epoch with no upgrade/heal → stale.
    RouteSupersession::IgnoreStale
}

#[allow(clippy::too_many_lines)]
async fn resolve_announce_cold_start(
    announce: &reticulum_core::ReceivedAnnounce,
    ctx: &EventCtx<'_>,
) {
    use ciris_persist::federation::self_at_login::BindingProvenance;
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
            // CIRISEdge#357 — a payload too short / without the CIRIS attestation
            // shape is a NON-CIRIS announce (ambient shared-RNS traffic), NOT a
            // CIRIS peer that failed to root. On a public fabric this floods, so
            // it is a THROTTLED DEBUG rollup — never a per-announce WARN, which
            // must stay reserved for the actionable "CIRIS-shaped attestation
            // failed verification/rooting" case handled below. (A malformed
            // CIRIS peer is rare and still surfaces via the destination-hash /
            // rooting WARNs once its app-data parses.)
            if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                non_ciris_announce_log().check("non-ciris")
            {
                tracing::debug!(
                    error = %e,
                    suppressed_prev,
                    "announce ignored: app-data is not a CIRIS attestation \
                     (ambient non-CIRIS traffic on the shared RNS network, CIRISEdge#357)"
                );
            }
            // CIRISEdge#34 — still surface on the announce stream for operators
            // who subscribe, but at INFO severity: ambient non-CIRIS traffic is
            // informational, not a warning (CIRISEdge#357).
            if let Some(bus) = ctx.event_bus {
                bus.emit_announce(crate::events::NetworkEvent::announce(
                    None,
                    announce.destination_hash().as_bytes().to_vec(),
                    announce.app_data().to_vec(),
                    crate::events::EventSeverity::Info,
                    format!("announce ignored: app-data is not a CIRIS attestation: {e}"),
                ));
            }
            return;
        }
    };
    let key_id = attestation.federation_key_id.clone();

    // CIRISEdge#205 (CIRISVerify#28 Phase 4 / AV-42) — RNS §5.6.8.8.1.1
    // destination-hash consistency gate. `verify_destination_hash()`
    // recomputes `truncated_hash(name_hash ‖ truncated_hash(public_key))`
    // from the announce's OWN identity pubkeys (leviculum-native, already
    // linked) and compares it to the claimed `destination_hash`. A
    // mismatch means the announce's transport identity does not actually
    // own the destination it claims — non-authentic. Under
    // `RequireTransportBinding` we drop it fail-secure BEFORE spending a
    // directory round-trip; `WarnOnly` logs + admits; `Advisory` (default)
    // preserves the current tolerant behavior. The flip is a dated
    // fleet-floor coordination event — see `TransportBindingEnforcement`.
    if !announce.verify_destination_hash() {
        match ctx.transport_binding_enforcement {
            TransportBindingEnforcement::RequireTransportBinding => {
                tracing::warn!(
                    av = "AV-42",
                    key_id = %key_id,
                    policy = ctx.transport_binding_enforcement.as_str(),
                    "announce dropped: destination_hash does not recompute from \
                     the announce identity pubkeys (RNS §5.6.8.8.1.1 mismatch — \
                     spoofed transport-identity binding)",
                );
                if let Some(bus) = ctx.event_bus {
                    bus.emit_announce(crate::events::NetworkEvent::announce(
                        Some(key_id.clone()),
                        announce.destination_hash().as_bytes().to_vec(),
                        announce.app_data().to_vec(),
                        crate::events::EventSeverity::Warning,
                        "announce dropped: destination_hash does not recompute from \
                         announce identity (AV-42, RequireTransportBinding)",
                    ));
                }
                return;
            }
            TransportBindingEnforcement::WarnOnly => {
                tracing::warn!(
                    av = "AV-42",
                    key_id = %key_id,
                    policy = ctx.transport_binding_enforcement.as_str(),
                    "transport-binding destination_hash mismatch (WarnOnly: admitting \
                     — fleet floor not yet enforced)",
                );
            }
            TransportBindingEnforcement::Advisory => {}
        }
    }

    // Step 2 — root the federation key against the persist directory.
    let verdict = rooting
        .root_binding(
            &key_id,
            &base64::engine::general_purpose::STANDARD
                .encode(attestation.federation_pubkey_ed25519),
        )
        .await;
    // CIRISEdge#301 (CC 3.3.6.2) — `root_binding` CLASSIFIES the binding, it
    // does NOT gate it. The AV-42 `dest_hash` crypto check already ran upstream
    // (`verify_destination_hash`, terminal); a `Rejected` here is a TRUST verdict
    // (unknown key / not-rooted-at-steward / genesis-unseeded / transient
    // directory error), never a crypto failure. Per CC 3.3.6.2 a self-consistent
    // announce is ADMITTED + recorded + KEX'd as a routing hint (`advisory`),
    // NEVER dropped — only genuine crypto/structural failures are terminal. This
    // is where a fresh peer FIRST-ROOTS: the binding is recorded on connect and
    // #411/#299 persist + boot-load it. Trust is composed downstream (content
    // gate, CC 6 N1); the manifest-validation-gated KEX (attest a trust-root-
    // blessed build before the record is durably saved) is the post-CIRISServer-
    // 0.6 follow-on tracked up the centipede.
    let (chain_opt, provenance, owns_key) = match verdict {
        RootingVerdict::Confirmed { chain } => {
            // ROOTED — verify the attestation against the directory-CONFIRMED
            // Ed25519 (never the wire claim), then apply the hybrid PQC policy.
            if !attestation_verifies_against_chain(
                &attestation,
                &chain,
                &key_id,
                announce.public_key(),
            ) {
                return;
            }
            if !hybrid_policy_accepts(ctx.hybrid_policy, &chain) {
                tracing::warn!(
                    key_id = %key_id,
                    policy = ?ctx.hybrid_policy,
                    "announce rejected: rooted provenance chain is hybrid-pending under Strict policy",
                );
                return;
            }
            (
                Some(chain),
                ciris_persist::federation::self_at_login::BindingProvenance::Rooted,
                // Confirmed ⇒ the claimed pubkey matched the directory row AND the
                // chain rooted at a pinned steward — the announcer provably owns
                // the key bound to `key_id`.
                true,
            )
        }
        RootingVerdict::Rejected { rejection } => {
            // ADVISORY admit (CC 3.3.6.2). The federation key did not root in the
            // local directory, but the announce is self-consistent. Verify the
            // attestation SELF-signature against the CLAIMED federation key — the
            // crypto floor (proves the announcer controls the key it claims); a
            // forged self-claim is a crypto failure → dropped. On success, admit
            // as an advisory routing hint (authority NOT established) — never drop.
            if !attestation_self_verifies(&attestation, &key_id, announce.public_key()) {
                return;
            }
            // CIRISEdge#336 (belt-heal correctness) — does this Advisory announce
            // PROVE ownership of the key the directory binds to `key_id`? persist's
            // `root_binding` checks in order: key_id exists (else `UnknownKeyId`),
            // claimed pubkey matches the row (else `PubkeyMismatch`), THEN walks the
            // chain to a steward. So a rejection that is neither `UnknownKeyId` nor
            // `PubkeyMismatch` means the claimed pubkey MATCHED the directory row —
            // and `attestation_self_verifies` (above) proved the announcer controls
            // that key. That is the OWNER re-announcing (its route just isn't
            // steward-rooted here), NOT a spoof. This is the routing≠trust
            // distinction one level up: an identity spoof (`PubkeyMismatch`) can
            // never reroute a Rooted peer, but a mere trust-chain gap must not block
            // the owner from healing its OWN routing dest — which is exactly the
            // boot-prime (#238 Rooted, epoch 0, explicit dest) → genuine-announce
            // (Advisory, named dest) heal that #336 depends on.
            let owns_key = !matches!(
                rejection,
                RootingRejection::UnknownKeyId { .. } | RootingRejection::PubkeyMismatch { .. }
            );
            // CIRISEdge#337 §4 — advisory admits are attacker-floodable (mint
            // unlimited self-signed keypairs). DEBUG, not INFO: the always-on
            // admit signal is the THROTTLED `peer_admitted_log` point-1 line
            // below; this per-admit detail must not flood the default stream.
            tracing::debug!(
                av = "AV-42",
                key_id = %key_id,
                reason = rejection.kind(),
                owns_key,
                "announce ADMITTED as advisory (CC 3.3.6.2: routing hint, authority not \
                 established — recorded + KEX'd, not dropped)"
            );
            (
                None,
                ciris_persist::federation::self_at_login::BindingProvenance::Advisory,
                owns_key,
            )
        }
    };

    // Step 5 — record the rooted resolution. A strictly-newer epoch
    // supersedes a cached binding; an equal-or-older epoch is a stale
    // re-announce and is ignored (keeps the cached chain).
    // CIRISEdge#333 — the transport identity comes from the ANNOUNCE ITSELF.
    // `announce.public_key()` IS the transport identity (`x25519 ‖ ed25519`) —
    // leviculum's `build_announce_payload` packs `identity.public_key_bytes()`
    // of the announcing destination. The attestation no longer re-sends those
    // 64 bytes (that duplication is what pushed app_data over the MTU budget and
    // meant an attested announce NEVER transmitted); it BINDS them by signature,
    // and we read them from the packet we just received.
    //
    // This also retires the #317 premise: `announce.public_key()` was never the
    // federation identity. It is, and always was, the transport identity the RNS
    // link authenticates under — so hashing it is exactly right for attribution.
    let announce_pubkey64: [u8; 64] = *announce.public_key();
    let binding_pubkey64: [u8; 64] = announce_pubkey64;
    let Ok(transport_pubkey) = <[u8; 32]>::try_from(&announce_pubkey64[32..]) else {
        tracing::warn!(av = "AV-42", key_id = %key_id,
            "announce rejected: transport-identity pubkey malformed");
        return;
    };
    let resolved = ResolvedPeer {
        dest_hash: *announce.destination_hash(),
        signing_key: transport_pubkey,
    };
    // The identity hash the link's LINKIDENTIFY proves:
    // `truncated_hash(x25519 ‖ ed25519)`.
    let transport_identity_hash: [u8; 16] = {
        let x25519: [u8; 32] = binding_pubkey64[..32].try_into().unwrap_or([0u8; 32]);
        let ed25519: [u8; 32] = binding_pubkey64[32..].try_into().unwrap_or([0u8; 32]);
        Identity::from_public_keys(&x25519, &ed25519).map_or([0u8; 16], |id| *id.hash())
    };
    let dest_hash16: [u8; 16] = (*announce.destination_hash()).into_bytes();
    let announced_dest = *announce.destination_hash();
    let announced_dest16 = announced_dest.into_bytes();
    let newly_rooted_key = {
        let mut peers = ctx.peers.lock().await;
        // Snapshot the existing entry's decision-relevant fields (all Copy), so
        // the pure supersession decision runs without holding a borrow across
        // the admit side effects (which re-borrow `peers` mutably to insert).
        let existing_snapshot = peers
            .get(&key_id)
            .map(|e| (e.provenance, e.epoch, e.peer.dest_hash.into_bytes()));
        match route_supersession_decision(
            existing_snapshot,
            provenance,
            owns_key,
            attestation.epoch,
            announced_dest16,
        ) {
            // CIRISEdge#337 CRITICAL-1 — an Advisory announce cannot override a
            // Rooted route (route-hijack refused). Attacker-floodable, so the
            // WARN is throttled on the fixed "hijack_refused" key, never key_id.
            RouteSupersession::HijackRefused => {
                if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                    route_supersession_log().check("hijack_refused")
                {
                    let (_, ex_epoch, _) = existing_snapshot.unwrap_or_default();
                    tracing::warn!(
                        av = "AV-42",
                        key_id = %key_id,
                        existing_epoch = ex_epoch,
                        announce_epoch = attestation.epoch,
                        suppressed_prev,
                        "route supersession REFUSED — an advisory (self-signed, not \
                         directory-rooted) announce cannot override a rooted route \
                         (CIRISEdge#337 verified-only supersession)"
                    );
                }
                None
            }
            RouteSupersession::IgnoreStale => {
                tracing::trace!(
                    key_id = %key_id,
                    announce_epoch = attestation.epoch,
                    "stale re-announce ignored (epoch not newer, no provenance upgrade, \
                     no verified reroute)",
                );
                None
            }
            RouteSupersession::Admit => {
                // CIRISEdge#336 — surface a reroute-heal distinctly from a fresh
                // admit so the explicit→named transition is visible in the log.
                if let Some((_, _, ex_dest16)) = existing_snapshot {
                    if ex_dest16 != announced_dest16
                        && matches!(provenance, BindingProvenance::Rooted)
                    {
                        if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                            route_supersession_log().check("reroute_healed")
                        {
                            tracing::info!(
                                key_id = %key_id,
                                old_dest = %hex::encode(ex_dest16),
                                new_dest = %hex::encode(announced_dest16),
                                epoch = attestation.epoch,
                                suppressed_prev,
                                "route HEALED from a verified announce — repointed to the \
                                 announced (routable) destination (CIRISEdge#336)"
                            );
                        }
                    }
                }
                // CIRISEdge#337 §4 — DEBUG (was INFO): attacker-floodable per
                // admit. The throttled `peer_admitted_log` point-1 line is the
                // always-on admit signal; this is the verbose companion.
                tracing::debug!(
                    key_id = %key_id,
                    dest = %resolved.dest_hash,
                    epoch = attestation.epoch,
                    provenance = ?provenance,
                    "peer ADMITTED via authenticated cold-start path (CIRISEdge#301: \
                     rooted = authoritative, advisory = routing hint)",
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
                let persisted_key = key_id.clone();
                // CIRISEdge#317 observability point 1 — surface the STORED
                // attribution operands at admit, so the later
                // `link_attribution_miss` comparison's stored side is visible
                // without reading the diff. `transport_identity_hash` is what
                // Branch A matches; `dest_hash` is Branch B's stored side.
                // THROTTLED by provenance: a rare `Rooted` admit logs, a flood of
                // junk `Advisory` admits (attacker minting keypairs) is capped to
                // first-N-per-window + a suppressed-count — closing the log-flood
                // that would otherwise track advisory-pollution 1:1.
                let provenance_key = match provenance {
                    ciris_persist::federation::self_at_login::BindingProvenance::Rooted => "rooted",
                    ciris_persist::federation::self_at_login::BindingProvenance::Advisory => {
                        "advisory"
                    }
                };
                if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                    peer_admitted_log().check(provenance_key)
                {
                    // CIRISEdge#333 — the stored `transport_identity_hash` is derived
                    // from the announce's OWN `public_key` (the transport identity
                    // `x25519 ‖ ed25519`), which is exactly the identity the RNS
                    // link proves at LINKIDENTIFY. The attestation no longer
                    // carries those bytes — it binds them by signature — so there
                    // is nothing left to disagree: the operands are the same 64
                    // bytes the packet arrived with. If link attribution still
                    // misses, `link_attribution_miss` (point 2) reports it.
                    tracing::info!(
                        key_id = %key_id,
                        provenance = ?provenance,
                        epoch = attestation.epoch,
                        dest_hash = %hex::encode(resolved.dest_hash.into_bytes()),
                        transport_identity_hash = %hex::encode(transport_identity_hash),
                        suppressed_prev,
                        "peer_admitted — transport identity taken from the announce's own \
                         public_key (CIRISEdge#333)"
                    );
                }
                // CIRISEdge#318 — bound the peers map against advisory-admit
                // pollution (an attacker minting unlimited self-signed keypairs,
                // each admitting as a distinct `Advisory` entry). At cap, evict an
                // Advisory binding before inserting a new key — NEVER a `Rooted`
                // (accord-blessed, finite) binding for advisory churn. If the map
                // is full of rooted peers (unrealistic — accord-bounded), the new
                // entry is still admitted; the cap targets advisory growth only.
                if !peers.contains_key(&key_id) && peers.len() >= MAX_PEERS {
                    let evict = peers
                        .iter()
                        .find(|(_, rp)| {
                            matches!(
                                rp.provenance,
                                ciris_persist::federation::self_at_login::BindingProvenance::Advisory
                            )
                        })
                        .map(|(k, _)| k.clone());
                    if let Some(evict) = evict {
                        peers.remove(&evict);
                        tracing::debug!(
                            evicted = %evict,
                            cap = MAX_PEERS,
                            "peers map at cap — evicted an advisory binding (CIRISEdge#318)"
                        );
                    }
                }
                peers.insert(
                    key_id,
                    RootedPeer {
                        peer: resolved,
                        epoch: attestation.epoch,
                        chain: chain_opt,
                        provenance,
                        transport_identity_hash,
                    },
                );
                Some(persisted_key)
            }
        }
    };
    // CIRISEdge#299 — write-through the rooted binding to persist AFTER
    // releasing the peers-map lock (the upsert is DB I/O; don't hold the
    // map mutex across it). Only on a genuinely-new / newer-epoch root.
    // On restart this is reloaded by the boot-load resolver, so a KNOWN
    // peer is reachable-and-sealable with zero announces. `rooting` is the
    // FederationDirectory-backed `RootingDirectory`; the write is a no-op
    // for non-directory impls (default trait method).
    if let Some(persisted_key) = newly_rooted_key {
        // CIRISEdge#317 — persist the TRANSPORT identity (binding_pubkey64), not
        // `announce.public_key()` (the federation identity), so the boot-reloaded
        // binding resolves + seals to the identity the link proves.
        rooting
            .persist_transport_binding(
                &persisted_key,
                dest_hash16,
                binding_pubkey64,
                provenance,
                attestation.epoch,
            )
            .await;
        // CIRISEdge#362 (seeder bridge, persist v17.8.0) — also record the
        // announced peer as a non-canonical, untrusted directory BOOKMARK so a
        // LAN-announced peer surfaces in the server's `GET /v1/federation/peers`
        // (`canonical=false`, `trust="unknown"`, `last_seen`). Safe on BOTH
        // Advisory and Rooted admits: the bookmark is invisible to every
        // admission/quorum/rooting path, and once the key roots for real persist
        // anti-joins the bookmark away (no dup, no downgrade). The announce
        // carries only the FEDERATION ed25519 (no PQC pubkey, no claimed
        // identity_type) — persist COALESCE-enriches those on later announces.
        rooting
            .record_announced_peer(
                &persisted_key,
                &base64::engine::general_purpose::STANDARD
                    .encode(attestation.federation_pubkey_ed25519),
                None,
                None,
                chrono::Utc::now(),
            )
            .await;
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
    announce_public_key: &[u8; 64],
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
    if let Err(e) = attestation.verify_signature(&confirmed_pubkey, announce_public_key) {
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

/// CIRISEdge#301 (CC 3.3.6.2) — verify the announce attestation's
/// **self-signature** against the **claimed** federation Ed25519 (the wire
/// claim, `attestation.federation_pubkey_ed25519_base64`), for an ADVISORY
/// admit where no directory-confirmed chain exists. This is the crypto floor:
/// it proves the announcer controls the key it claims (the announce is
/// self-consistent), NOT that the key is authorized — authority is the rooted
/// chain, composed downstream. A forged self-claim (signature does not verify
/// against its own claimed key) fails here and the announce is dropped as a
/// genuine crypto failure. Distinct from
/// [`attestation_verifies_against_chain`], which verifies against the
/// directory-CONFIRMED key for a `Rooted` admit.
fn attestation_self_verifies(
    attestation: &AnnounceAttestation,
    key_id: &str,
    announce_public_key: &[u8; 64],
) -> bool {
    // CIRISEdge#333 — the transport identity is the announce's own public_key;
    // the signature binds it without the attestation re-sending it.
    let claimed = attestation.federation_pubkey_ed25519;
    if let Err(e) = attestation.verify_signature(&claimed, announce_public_key) {
        tracing::warn!(
            av = "AV-42",
            key_id,
            error = %e,
            "announce dropped: attestation self-signature did not verify against the \
             claimed federation key (forged self-claim — genuine crypto failure)",
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
    transport_x25519_pubkey: &[u8; 32],
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

    // CIRISEdge#317 — bind the FULL transport identity (ed25519 ‖ x25519) so the
    // receiver's admit computes `Identity::hash()` = exactly what the RNS link
    // proves. v2 payload (distinct signature domain).
    let payload = AttestationPayload::new(transport_identity_pubkey, federation_key_id, epoch)
        .with_transport_x25519(transport_x25519_pubkey);
    let signature = signer
        .classical
        .sign(&payload.canonical_bytes())
        .await
        .map_err(|e| TransportError::Config(format!("attestation sign: {e}")))?;

    let fed_pubkey32: [u8; 32] = fed_pubkey.as_slice().try_into().map_err(|_| {
        TransportError::Config("federation Ed25519 pubkey must be 32 bytes".to_string())
    })?;
    let signature64: [u8; 64] = signature.as_slice().try_into().map_err(|_| {
        TransportError::Config("attestation signature must be 64 bytes".to_string())
    })?;
    let attestation = AnnounceAttestation {
        federation_key_id: federation_key_id.to_string(),
        federation_pubkey_ed25519: fed_pubkey32,
        epoch,
        signature: signature64,
    };
    attestation
        .to_app_data()
        .map_err(|e: AttestationError| TransportError::Config(format!("attestation encode: {e}")))
}

// ─── Identity persistence (AV-17) ───────────────────────────────────

/// v3.1.0 (CIRISEdge#99) — keystore-tier identity load/adopt/generate.
///
/// Precedence:
///
/// 1. **Keystore hit** — `keystore.load(key_id)` returned the 64 bytes.
///    Use them. No filesystem touch.
///
/// 2. **Keystore miss + existing file** — `keystore.load` returned
///    `None` (fresh keystore entry) AND the chmod-600 file at `path`
///    exists. **Adopt-and-migrate**: read the 64 file bytes,
///    `keystore.store(key_id, bytes)`, then RENAME the file to
///    `<path>.migrated-<unix_ts>`. The destination hash is preserved
///    end-to-end (the bytes are byte-identical) so peer routing
///    tables + signed announces keep working — auto-*regeneration*
///    on upgrade would invalidate every peer's saved destination
///    and is explicitly avoided. The original file is renamed (not
///    deleted) so the operator keeps a recovery copy until they're
///    satisfied; they remove `<path>.migrated-*` manually.
///
/// 3. **Keystore miss + no file** — fresh install.
///    `keystore.generate_and_store(key_id)` (atomic; durable before
///    return; uses hardware RNG where the tier offers it), then
///    `keystore.load(key_id)` for the bytes.
///
/// All branches return a constructed `reticulum_std::Identity`.
/// Failure to construct the Identity from the loaded bytes is a hard
/// `TransportError::Config` — fail-loud, never a silently-misshapen
/// identity.
///
/// Threat model: this closes the at-rest exfil class (filesystem
/// reads, backups, snapshots, permission misconfig). The transient
/// RAM window inside Reticulum's `Identity::from_private_key_bytes`
/// is documented in CIRISEdge#99 as out-of-scope — leviculum's API
/// takes raw bytes for internal crypto; the keyring trade-off is
/// at-rest only, not RAM.
fn load_or_adopt_or_generate_identity_with_keystore(
    path: &std::path::Path,
    key_id: &str,
    keystore: &dyn ciris_keyring::TransportIdentityKeystore,
) -> Result<Identity, TransportError> {
    // Step 1: keystore hit?
    let from_keystore = keystore.load(key_id).map_err(|e| {
        TransportError::Config(format!(
            "keystore load for transport identity {key_id}: {e}"
        ))
    })?;

    let bytes: [u8; 64] = if let Some(b) = from_keystore {
        tracing::info!(
            key_id,
            hardware_backed = keystore.is_hardware_backed(),
            "loaded RNS transport identity from keystore"
        );
        b
    } else if path.exists() {
        // Step 2: adopt-and-migrate from the existing chmod-600 file.
        let file_bytes = std::fs::read(path).map_err(|e| {
            TransportError::Config(format!("adopt: read identity {}: {e}", path.display()))
        })?;
        let arr: [u8; 64] = file_bytes.as_slice().try_into().map_err(|_| {
            TransportError::Config(format!(
                "adopt: identity {} is {} bytes, expected 64",
                path.display(),
                file_bytes.len()
            ))
        })?;
        keystore.store(key_id, &arr).map_err(|e| {
            TransportError::Config(format!("adopt: keystore store for {key_id}: {e}"))
        })?;
        // Rename original file. Best-effort; the keystore copy is
        // already durable so a rename failure is a warning (the
        // operator may need to manually move/secure the file).
        // Falls back to PID+timestamp suffix when SystemTime::now is
        // unsuitable (very unlikely in practice).
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let archived = path.with_extension(format!("migrated-{suffix}"));
        match std::fs::rename(path, &archived) {
            Ok(()) => {
                tracing::warn!(
                    key_id,
                    archived = %archived.display(),
                    hardware_backed = keystore.is_hardware_backed(),
                    "adopted RNS transport identity from file into keystore; \
                     original archived (keystore-tier now load-bearing)"
                );
            }
            Err(e) => {
                tracing::warn!(
                    key_id,
                    path = %path.display(),
                    error = %e,
                    "adopted RNS transport identity into keystore BUT failed \
                     to archive original file; operator should manually \
                     move/secure it (keystore-tier is now load-bearing)"
                );
            }
        }
        arr
    } else {
        // Step 3: fresh install — generate + store atomically.
        keystore.generate_and_store(key_id).map_err(|e| {
            TransportError::Config(format!(
                "generate_and_store transport identity {key_id}: {e}"
            ))
        })?;
        let fresh = keystore
            .load(key_id)
            .map_err(|e| TransportError::Config(format!("post-generate load for {key_id}: {e}")))?
            .ok_or_else(|| {
                TransportError::Config(format!(
                    "post-generate load for {key_id} returned None — \
                     keystore contract violation"
                ))
            })?;
        tracing::info!(
            key_id,
            hardware_backed = keystore.is_hardware_backed(),
            "generated fresh RNS transport identity in keystore"
        );
        fresh
    };

    Identity::from_private_key_bytes(&bytes).map_err(|e| {
        TransportError::Config(format!("parse keystore-loaded identity {key_id}: {e}"))
    })
}

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
///
/// v7.0.12 (CIRISEdge#217) — uses `futures_timer::Delay` +
/// `std::time::Instant` instead of `tokio::time::*` so the poll is
/// runtime-agnostic. The cross-cdylib tokio aliasing class makes
/// `tokio::time::sleep` panic with "no reactor running" when this
/// helper is awaited on a thread whose tokio thread-locals belong to
/// persist's runtime — the bootstrapping-node failure mode in #217.
/// `cond()`'s own awaits (typically `tokio::sync::Mutex::lock`) don't
/// need a Timer driver, just state-machine polling.
async fn wait_until_async<F, Fut>(timeout: Duration, interval: Duration, mut cond: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    loop {
        if cond().await {
            return true;
        }
        if start.elapsed() >= timeout {
            return false;
        }
        futures_timer::Delay::new(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── CIRISEdge#336/#337 route-supersession decision — the saga's tombstone ──
    //
    // One test per prior footgun path, over the PURE `route_supersession_decision`
    // so a regression is a compile-fast unit failure, never a field incident.
    mod route_supersession {
        use super::*;
        use ciris_persist::federation::self_at_login::BindingProvenance::{Advisory, Rooted};

        const EXPLICIT: [u8; 16] = [0x1f; 16]; // stand-in for the un-routable explicit-hash
        const NAMED: [u8; 16] = [0x81; 16]; // stand-in for the routable named dest

        // Signature: route_supersession_decision(existing, incoming_provenance,
        // incoming_owns_key, incoming_epoch, incoming_dest16).
        //
        // `owns_key` is the load-bearing signal (CIRISEdge#336 belt-heal fix): it
        // is whether the announcer PROVED control of the key the directory binds
        // to `key_id` — true for Confirmed, and for an Advisory whose rejection
        // was neither UnknownKeyId nor PubkeyMismatch (pubkey matched + self-
        // verified). It is the OWNER-vs-SPOOF discriminator, independent of the
        // trust `provenance`.

        /// A fresh peer (no cached route) is always admitted.
        #[test]
        fn fresh_peer_is_admitted() {
            assert_eq!(
                route_supersession_decision(None, Rooted, true, 0, NAMED),
                RouteSupersession::Admit
            );
            assert_eq!(
                route_supersession_decision(None, Advisory, false, 7, NAMED),
                RouteSupersession::Admit
            );
        }

        /// CIRISEdge#336 BELT — **THE FIELD CASE**, and the regression the pre-fix
        /// test missed. The boot-prime installs a **Rooted** entry (epoch 0,
        /// explicit dest). The peer's genuine announce arrives **Advisory** (it
        /// self-verifies but is not steward-rooted here → `NotRootedAtSteward`),
        /// so `owns_key = true` (pubkey matched). This MUST heal explicit→named.
        ///
        /// The v13.0.0 test asserted `incoming = Rooted` and passed — but the
        /// field passes `Advisory`, which the old gate refused as a hijack, so the
        /// belt never fired. Green test, wrong path — the saga's signature failure,
        /// now guarded with the ACTUAL field provenance.
        #[test]
        fn belt_heals_the_owners_advisory_reroute_explicit_to_named() {
            assert_eq!(
                route_supersession_decision(
                    Some((Rooted, 0, EXPLICIT)),
                    Advisory, // the field provenance — NOT Rooted
                    true,     // …but the owner proved key control
                    0,
                    NAMED,
                ),
                RouteSupersession::Admit,
                "the owner's genuine Advisory announce MUST heal a boot-primed \
                 explicit-hash route to its named dest (#336)",
            );
        }

        /// CIRISEdge#337 CRITICAL-1 — the route-hijack gate. An announce that
        /// CANNOT prove key ownership (`owns_key = false`: a `PubkeyMismatch` /
        /// `UnknownKeyId` spoof) can NEVER supersede a Rooted route, at any epoch,
        /// any dest. This is the whole verified-only invariant — must never regress.
        #[test]
        fn spoof_without_key_ownership_cannot_override_rooted() {
            // Higher epoch, different dest — the u64::MAX poison attempt.
            assert_eq!(
                route_supersession_decision(
                    Some((Rooted, 5, NAMED)),
                    Advisory,
                    false,
                    u64::MAX,
                    EXPLICIT
                ),
                RouteSupersession::HijackRefused,
            );
            // Equal epoch, same dest — still refused.
            assert_eq!(
                route_supersession_decision(Some((Rooted, 5, NAMED)), Advisory, false, 5, NAMED),
                RouteSupersession::HijackRefused,
            );
            // The exact belt-shaped inputs but WITHOUT ownership → refused. This
            // is the razor: owns_key alone separates the heal from the hijack.
            assert_eq!(
                route_supersession_decision(Some((Rooted, 0, EXPLICIT)), Advisory, false, 0, NAMED),
                RouteSupersession::HijackRefused,
            );
        }

        /// A Confirmed (Rooted, owns_key) reroute at equal epoch also heals — the
        /// steward-rooted owner updating its dest.
        #[test]
        fn equal_epoch_rooted_owner_reroute_heals() {
            assert_eq!(
                route_supersession_decision(Some((Rooted, 0, EXPLICIT)), Rooted, true, 0, NAMED),
                RouteSupersession::Admit,
            );
        }

        /// The owner rotating its transport identity (higher epoch) supersedes,
        /// whether the new announce is Rooted or an owns-key Advisory.
        #[test]
        fn higher_epoch_owner_supersedes() {
            assert_eq!(
                route_supersession_decision(Some((Rooted, 2, NAMED)), Rooted, true, 3, EXPLICIT),
                RouteSupersession::Admit,
            );
            assert_eq!(
                route_supersession_decision(Some((Rooted, 2, NAMED)), Advisory, true, 3, EXPLICIT),
                RouteSupersession::Admit,
            );
        }

        /// CIRISEdge#301 — an advisory entry is upgraded to rooted at equal epoch
        /// (first-root promotion), even with the same dest.
        #[test]
        fn equal_epoch_advisory_to_rooted_upgrades() {
            assert_eq!(
                route_supersession_decision(Some((Advisory, 3, NAMED)), Rooted, true, 3, NAMED),
                RouteSupersession::Admit,
            );
        }

        /// A same-epoch re-announce with the same dest is stale — no needless
        /// churn / persist write / replication gossip.
        #[test]
        fn equal_epoch_same_dest_is_stale() {
            assert_eq!(
                route_supersession_decision(Some((Rooted, 4, NAMED)), Rooted, true, 4, NAMED),
                RouteSupersession::IgnoreStale,
            );
            assert_eq!(
                route_supersession_decision(Some((Advisory, 4, NAMED)), Advisory, true, 4, NAMED),
                RouteSupersession::IgnoreStale,
            );
        }

        /// A lower-epoch announce is stale even from the owner with a different
        /// dest — a replayed/older frame can never rewrite a newer binding (the
        /// durable half of this is persist's `(epoch, asserted_at)` guard, #443).
        #[test]
        fn lower_epoch_is_stale_even_from_owner_with_new_dest() {
            assert_eq!(
                route_supersession_decision(Some((Rooted, 9, NAMED)), Rooted, true, 2, EXPLICIT),
                RouteSupersession::IgnoreStale,
            );
        }

        /// A non-owning advisory over an EXISTING ADVISORY hint at equal epoch is
        /// not honored (no ownership, no upgrade) — but the hijack gate does not
        /// apply (it protects Rooted routes only; advisory entries are unverified
        /// hints bounded by MAX_PEERS).
        #[test]
        fn equal_epoch_non_owner_advisory_over_advisory_is_stale() {
            assert_eq!(
                route_supersession_decision(
                    Some((Advisory, 1, NAMED)),
                    Advisory,
                    false,
                    1,
                    EXPLICIT
                ),
                RouteSupersession::IgnoreStale,
            );
        }
    }

    /// CIRISEdge#299 — the persisted-binding resolver returns the exact
    /// 64-byte identity it was loaded with, and `None` for an unknown peer.
    #[test]
    fn persisted_binding_resolver_resolves_full_identity() {
        let mut map = std::collections::HashMap::new();
        let mut ident = [0u8; 64];
        for (i, b) in ident.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        map.insert("peer-abc".to_string(), ident);
        let r = PersistedBindingResolver::new(map);
        assert_eq!(r.len(), 1);
        assert!(!r.is_empty());
        assert_eq!(r.resolve("peer-abc"), Some(ident));
        assert_eq!(r.resolve("peer-unknown"), None);
    }

    /// CIRISEdge#299 — the full write-through → persist → boot-load →
    /// resolve round-trip through a real `FederationDirectory`
    /// (`MemoryBackend`): a rooted transport identity persisted via
    /// `RootingDirectory::persist_transport_binding` is read back by
    /// `list_all_transport_destinations` and reconstructed into the same
    /// 64-byte `(x25519 ‖ ed25519)` a `PersistedBindingResolver` serves.
    #[tokio::test]
    async fn rooted_transport_write_through_boot_load_round_trip() {
        use crate::verify::RootingDirectory;
        use base64::Engine as _;
        use ciris_persist::federation::FederationDirectory;
        use ciris_persist::store::MemoryBackend;

        let backend = MemoryBackend::new();
        let key_id = "peer-roundtrip";
        let dest_hash = [7u8; 16];
        let mut pubkey = [0u8; 64];
        for (i, b) in pubkey.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap().wrapping_add(3);
        }

        // Seed the occurrence's federation_keys row — put_transport_destination
        // is FK-gated on it (in production, rooting already confirmed this row
        // exists before the write-through fires, so the FK always holds).
        let record = ciris_persist::federation::KeyRecord {
            key_id: key_id.to_string(),
            pubkey_ed25519_base64: String::new(),
            pubkey_ml_dsa_65_base64: None,
            algorithm: "hybrid".to_string(),
            identity_type: "agent".to_string(),
            identity_ref: format!("ref-{key_id}"),
            valid_from: chrono::Utc::now(),
            valid_until: None,
            registration_envelope: serde_json::json!({ "key_id": key_id }),
            original_content_hash: "0".repeat(64),
            scrub_signature_classical: "x".repeat(88),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.to_string(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        FederationDirectory::put_public_key(
            &backend,
            ciris_persist::federation::SignedKeyRecord { record },
        )
        .await
        .expect("seed occurrence key");

        // Write-through (the announce-handler path).
        RootingDirectory::persist_transport_binding(
            &backend,
            key_id,
            dest_hash,
            pubkey,
            ciris_persist::federation::self_at_login::BindingProvenance::Rooted,
            0, // epoch (CIRISEdge#336 / CIRISPersist#443)
        )
        .await;

        // Boot-load: read every persisted binding back.
        let rows = FederationDirectory::list_all_transport_destinations(&backend)
            .await
            .expect("list_all_transport_destinations");
        let row = rows
            .iter()
            .find(|r| r.occurrence_key_id == key_id)
            .expect("the persisted binding is present");
        assert_eq!(row.transport_kind, "reticulum");
        assert_eq!(row.destination, hex::encode(dest_hash));

        // Reconstruct the 64-byte identity the resolver would serve.
        let b64 = base64::engine::general_purpose::STANDARD;
        let xb = b64
            .decode(
                row.transport_x25519_pubkey_base64
                    .as_deref()
                    .expect("x25519"),
            )
            .expect("x25519 b64");
        let eb = b64
            .decode(
                row.transport_ed25519_pubkey_base64
                    .as_deref()
                    .expect("ed25519"),
            )
            .expect("ed25519 b64");
        let mut full = [0u8; 64];
        full[0..32].copy_from_slice(&xb);
        full[32..64].copy_from_slice(&eb);
        assert_eq!(
            full, pubkey,
            "boot-loaded identity matches the write-through"
        );

        let mut map = std::collections::HashMap::new();
        map.insert(row.occurrence_key_id.clone(), full);
        assert_eq!(
            PersistedBindingResolver::new(map).resolve(key_id),
            Some(pubkey)
        );
    }

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

    // CIRISEdge#168 (v5.0) — Transport-node mode (§24 NAT-traversal).

    #[test]
    fn enable_transport_default_false() {
        let cfg = ReticulumTransportConfig::new(PathBuf::from("/tmp/x.id"), "edge-key-1");
        assert!(
            !cfg.enable_transport,
            "a fresh config is leaf-node (does NOT relay for strangers) until opted in",
        );
    }

    // `ReticulumTransportConfig` is not a serde type (it carries
    // `Duration`/`SocketAddr`/`PathBuf` runtime values, not a wire
    // shape — the Python kwarg in `init_edge_runtime` is the
    // operator-facing surface). The serde-roundtrip contract from the
    // spec therefore reduces to: the bool survives a structural
    // clone, both polarities, independent of every other field.
    #[test]
    fn enable_transport_survives_clone_roundtrip() {
        let off = ReticulumTransportConfig::new(PathBuf::from("/tmp/x.id"), "edge-key-1");
        assert!(!off.clone().enable_transport);

        let on = ReticulumTransportConfig::new(PathBuf::from("/tmp/x.id"), "edge-key-1")
            .with_transport_node(true);
        assert!(on.clone().enable_transport);
    }

    #[test]
    fn enable_transport_propagates_through_builder() {
        // The struct accepts both polarities via the builder and via
        // direct field assignment; this is what `init_edge_runtime`
        // pipes into leviculum's `ReticulumNodeBuilder::enable_transport`
        // in `ReticulumTransport::new`.
        let fabric = ReticulumTransportConfig::new(PathBuf::from("/tmp/x.id"), "fabric-key")
            .with_transport_node(true);
        assert!(fabric.enable_transport, "public fabric node forwards");

        let mut leaf = ReticulumTransportConfig::new(PathBuf::from("/tmp/x.id"), "leaf-key");
        leaf.enable_transport = false;
        assert!(!leaf.enable_transport, "mobile leaf edge does not forward");
    }
}
