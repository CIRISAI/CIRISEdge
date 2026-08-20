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
use std::sync::OnceLock;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, Mutex};

use leviculum_core::link::LinkId;
use leviculum_core::resource::ResourceStrategy;
use leviculum_core::{Destination, DestinationHash, DestinationType, Direction, Identity};
use leviculum_std::driver::{CompletionError, EventReceiver, ReticulumNode, ReticulumNodeBuilder};
use leviculum_std::NodeEvent;

use super::attestation::{
    AnnounceAttestation, AttestationError, AttestationPayload, TransportBindingEnforcement,
};
use super::{InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome};
use crate::identity::LocalSigner;
use crate::reachability::{AttemptOutcome, ReachabilityTracker};
use crate::scope_addressing::{InboundAddress, MemberAddress, ScopeAddressTable};
#[cfg(feature = "lxmf")]
use crate::transport::lxmf_serve::ServeOutcome;
use crate::verify::{
    HybridPolicy, ProvenanceChain, RootingDirectory, RootingRejection, RootingVerdict,
};

// Maximum envelope body size accepted on send (AV-13, 8 MiB); oversized
// payloads reject before any link is established. IMPORTED from the
// single transport-wide authority in `frame_fragment` — not re-typed —
// so the send-side admissibility ceiling can never drift from the
// receive-side reassembly budget (one-authority body budget).
use super::frame_fragment::MAX_BODY_BYTES;

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

/// CIRISEdge#363 — the link keepalive interval edge asks leviculum to apply,
/// node-wide, so a freshly-admitted **advisory/bootstrap** link survives long
/// enough to complete the Key + IdentityOccurrence anti-entropy that promotes
/// it to a KEX'd delivery target.
///
/// The bug (converged RCA): a mobile/container peer hears canonical A's announce
/// → advisory admit (`owns_key=false`). To become deliverable it must
/// anti-entropy A's Key (transport binding) *and* IdentityOccurrence (KEX
/// enc-keys) planes over that same link. leviculum derives the keepalive
/// interval from the measured RTT (`calculate_keepalive_from_rtt`) and, on a
/// fast direct TCP link, clamps it to the `LINK_KEEPALIVE_MIN` floor (5 s). The
/// stale timer is `keepalive * LINK_STALE_FACTOR` (= 2), so with no explicit
/// override the link goes **stale at ~10 s and is reaped at ~16 s** — before the
/// two-plane exchange lands, especially when the canonical peer is under heavy
/// churn and its keepalive acks are starved (the field symptom: 3 keepalives
/// sent / 1 acked, dead by `keepalive_timeout`). The enc-keys are NOT derivable
/// from the announce (the occurrence plane carries an ML-KEM-768 PQC key absent
/// from the 64-byte transport identity), so keeping the link alive across the
/// exchange is the load-bearing fix — not promotion from announce data alone.
///
/// 30 s is chosen against the replication cadence, not guessed: the anti-entropy
/// scheduler runs one round every 30 s with a 10 s round timeout
/// (`SchedulerConfig` cadence / `DEFAULT_ROUND_TIMEOUT`). A 30 s keepalive yields
/// a `stale_time` of 60 s (2× the cadence), so a bootstrap link tolerates a full
/// quiet cadence of keepalive-ack silence and still completes the Key +
/// IdentityOccurrence rounds.
///
/// BOUNDED + DoS-aware: leviculum exposes only a **node-global** keepalive knob
/// (`ReticulumNodeBuilder::link_keepalive`), not a per-link one, so this applies
/// to every link — but a *longer* interval means *fewer* keepalive packets (less
/// load, not more), and leviculum still reaps a silently-dead link at
/// `stale_time + rtt*4 + grace` (~65 s here) rather than never. A silently-dead
/// link therefore lingers ~65 s instead of ~16 s — a bounded ~4× hold, itself
/// backstopped by leviculum's link table and edge's `MAX_PEERS` advisory cap. It
/// is NOT an unbounded-link amplifier. See [`effective_link_keepalive_secs`] for
/// the clamp that keeps an operator override inside leviculum's valid band.
const BOOTSTRAP_LINK_KEEPALIVE: Duration = Duration::from_secs(30);

/// CIRISEdge#363 — leviculum's minimum keepalive interval
/// (`leviculum_core::constants::LINK_KEEPALIVE_MIN_SECS`). leviculum clamps an
/// override UP to this floor but does not cap the ceiling, so edge enforces both
/// ends in [`effective_link_keepalive_secs`].
const LINK_KEEPALIVE_MIN_SECS: u64 = 5;

/// CIRISEdge#363 — leviculum's maximum / RTT-derived keepalive interval
/// (`leviculum_core::constants::LINK_KEEPALIVE_SECS`, 6 minutes). Edge caps an
/// operator override here so a stray large value can NOT hold a silently-dead
/// link open longer than leviculum's own RTT-driven ceiling would — the
/// DoS-facing upper bound (leviculum only clamps the lower end).
const LINK_KEEPALIVE_MAX_SECS: u64 = 360;

/// CIRISEdge#363 — the keepalive interval (seconds) edge actually hands
/// leviculum's builder, or `None` to leave leviculum's RTT-derived default in
/// place. Pure so it is unit-testable without a live node.
///
/// `configured` is [`ReticulumTransportConfig::link_keepalive`]. When `Some`, the
/// requested interval is clamped into leviculum's valid band
/// `[LINK_KEEPALIVE_MIN_SECS, LINK_KEEPALIVE_MAX_SECS]` — the lower clamp mirrors
/// leviculum's own `set_keepalive_override` floor; the upper clamp is edge's
/// DoS-facing ceiling (leviculum does not cap the top, so an unbounded value
/// would hold a dead link open indefinitely). A sub-second `Duration` floors to
/// the minimum rather than to 0.
fn effective_link_keepalive_secs(configured: Option<Duration>) -> Option<u64> {
    configured.map(|d| {
        d.as_secs()
            .clamp(LINK_KEEPALIVE_MIN_SECS, LINK_KEEPALIVE_MAX_SECS)
    })
}

/// CIRISEdge#508 item (d) — operator env override for the lossless
/// control-plane event-channel capacity. leviculum documents its 256 default
/// as sized for "small std platforms … servers override larger via config or
/// builder" (leviculum-std `config.rs`), but until this knob existed edge
/// exposed no way to take that advice — the canonical wedged with the default.
///
/// `pub` so binaries / harnesses (e.g. `bin/edge_node.rs`) that set or
/// document the variable reference THIS const instead of re-typing the
/// env-var name literal (a typo'd retype silently reverts the node to
/// leviculum's 256 default).
pub const CONTROL_CHANNEL_CAPACITY_ENV: &str = "CIRIS_EDGE_RETICULUM_CONTROL_CHANNEL_CAPACITY";

/// Lower clamp for [`effective_control_channel_capacity`]. Below leviculum's
/// own 256 default is already a foot-gun; 16 exists only so a deliberate
/// test rig can force saturation, and 0 would panic tokio's `mpsc::channel`.
const CONTROL_CHANNEL_CAPACITY_MIN: usize = 16;

/// Upper clamp for [`effective_control_channel_capacity`]. Each slot is one
/// queued `NodeEvent`; 65 536 bounds worst-case queue memory while being 256×
/// the default — far past any observed saturation (CIRISEdge#508 measured a
/// 256-deep channel overflowing behind a lock stall, not a real 64k burst).
const CONTROL_CHANNEL_CAPACITY_MAX: usize = 65_536;

/// Where the effective control-channel capacity came from — logged at node
/// build so the operator can see which knob (if any) took effect.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum ControlChannelCapacitySource {
    /// `ReticulumTransportConfig::control_channel_capacity` was `Some`.
    Config,
    /// The `CIRIS_EDGE_RETICULUM_CONTROL_CHANNEL_CAPACITY` env var parsed.
    Env,
    /// The env var was set but did not parse as a `usize`; ignored (loudly).
    EnvInvalid,
    /// Nothing configured — leviculum's default applies.
    Default,
}

/// Resolve the control-channel capacity for `ReticulumNodeBuilder`
/// (CIRISEdge#508 item (d)). Precedence: explicit config field, then env var,
/// then leviculum's default (`None`). The result is clamped into
/// [`CONTROL_CHANNEL_CAPACITY_MIN`]..=[`CONTROL_CHANNEL_CAPACITY_MAX`] so an
/// operator typo can neither panic the channel (0) nor commit unbounded
/// queue memory. Pure — `env_raw` is passed in, not read here — so tests
/// exercise the EXACT env-string shapes the field produces.
fn effective_control_channel_capacity(
    configured: Option<usize>,
    env_raw: Option<&str>,
) -> (Option<usize>, ControlChannelCapacitySource) {
    if let Some(cap) = configured {
        return (
            Some(cap.clamp(CONTROL_CHANNEL_CAPACITY_MIN, CONTROL_CHANNEL_CAPACITY_MAX)),
            ControlChannelCapacitySource::Config,
        );
    }
    match env_raw {
        Some(raw) => match raw.trim().parse::<usize>() {
            Ok(cap) => (
                Some(cap.clamp(CONTROL_CHANNEL_CAPACITY_MIN, CONTROL_CHANNEL_CAPACITY_MAX)),
                ControlChannelCapacitySource::Env,
            ),
            Err(_) => (None, ControlChannelCapacitySource::EnvInvalid),
        },
        None => (None, ControlChannelCapacitySource::Default),
    }
}

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
/// CIRISEdge#353b/v13.6.1 — PROGRESS-AWARE reverse-path resource wait.
///
/// v13.6.0 used a flat 10 s cutoff, which was too blunt: a resource completes
/// only after `advertise → accept → parts → AwaitingProof → proof` (leviculum's
/// part/proof timeouts are RTT-scaled), so a LARGE reply (the Attestation Diff,
/// too big for the packet fast-path) over a high-RTT NAT'd link genuinely needs
/// well over 10 s EVEN ON A LIVE LINK. The flat timeout cut off a live, still-
/// progressing transfer (field datum: an 11 s-old live link, non-busy, cut at
/// exactly 10 s). The fix watches leviculum's `Resource{Advertised,TransferStarted,
/// Progress}` events (all carry `resource_hash` + `is_sender`) and distinguishes:
///
/// * NO progress within [`REVERSE_PATH_NO_PROGRESS_WINDOW`] → fast-fail (dead
///   link — even faster than the old 10 s; preserves the #373 drain protection).
/// * Progress flowing → extend up to [`REVERSE_PATH_MAX_TRANSFER`] so a live-but-
///   slow transfer completes.
///
/// Scope (per the field owner's caveat): this closes the PRESENT-mobile / first-
/// reply case (transfer progressing over a link that survives). Burst-and-leave —
/// the mobile gone by reply time, or the link going stale MID-transfer — remains
/// the separate initiator-push end-state; the `LinkStale`-during-transfer path is
/// logged distinctly so that mode stays visible.
const REVERSE_PATH_NO_PROGRESS_WINDOW: Duration = Duration::from_secs(6);
/// Hard cap for a PROGRESSING reverse-path transfer (well inside a present
/// mobile's ~90 s live window; a stalled transfer fails earlier via the
/// no-progress window).
const REVERSE_PATH_MAX_TRANSFER: Duration = Duration::from_secs(45);
/// Defensive size bound on the `sent_resource_progress` mirror. leviculum
/// v0.22 (#59) moved `ResourceTransferStarted` onto the droppable data
/// plane while `ResourceCompleted` (the entry's remover) stays on the
/// control plane, so a saturated node can deliver Started/Progress AFTER
/// their own completion and strand an entry (the pre-existing
/// `ResourceProgress` window, widened). Past this threshold the insert arm
/// prunes entries idle beyond [`REVERSE_PATH_MAX_TRANSFER`] — a live
/// transfer refreshes `last_update` every progress tick, so only orphans
/// qualify. 4096 entries ≈ 200 KB worst case: far above any realistic
/// concurrent-send envelope, cheap enough that the prune almost never runs.
const SENT_RESOURCE_PROGRESS_PRUNE_THRESHOLD: usize = 4096;
/// No-progress window for the OUTBOUND-dial path — a freshly-dialed link we
/// control, so more lenient than the churn-prone reverse path.
const DIAL_NO_PROGRESS_WINDOW: Duration = Duration::from_secs(30);

/// Where a reverse-path resource transfer had reached when it was last observed —
/// the stall-stage that makes a failed transfer field-diagnosable (Outcome B, a
/// live-but-slow transfer, vs Outcome A, a genuine stall — and WHERE it stalled).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResourceSendStage {
    /// Advertised to the peer; awaiting its accept + part requests.
    Advertised,
    /// Parts are flowing (`ResourceProgress` seen); may be awaiting proof.
    Transferring,
}

impl ResourceSendStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Advertised => "advertised (awaiting peer accept/part-request)",
            Self::Transferring => "transferring (parts flowing / awaiting proof)",
        }
    }
}

/// Per-sent-resource progress mirror, keyed by the `resource_hash`
/// `send_resource` returns. Updated by the sender-side
/// `Resource{Advertised,TransferStarted,Progress}` event arms; read by
/// [`ReticulumTransport::ship_resource_on_link`]'s progress-aware wait.
#[derive(Debug, Clone, Copy)]
struct ResourceSendProgress {
    stage: ResourceSendStage,
    last_update: std::time::Instant,
}

/// One tick of the progress-aware reverse-path wait — a PURE decision so the
/// timeout logic is a compile-fast unit test, not a field incident (the
/// `select_reply_link` discipline). All time inputs are pre-measured by the
/// async caller.
#[derive(Debug, PartialEq, Eq)]
enum ReverseWaitStep {
    /// Sender-side `ResourceCompleted` observed — delivered + proven.
    Done,
    /// Keep polling.
    Continue,
    /// No transfer progress within the no-progress window → dead/undialable link.
    StalledNoProgress,
    /// The link went stale/closed MID-transfer (caveat: burst-and-leave churn).
    LinkStale,
    /// Progressing but past the hard cap — bail so the drain isn't parked forever.
    MaxDeadline,
}

fn reverse_path_wait_step(
    completed: bool,
    link_live: bool,
    since_last_progress: Duration,
    since_start: Duration,
    no_progress_window: Duration,
    max_transfer: Duration,
) -> ReverseWaitStep {
    if completed {
        return ReverseWaitStep::Done;
    }
    // Link death mid-transfer is distinct from a slow transfer — surface it so
    // the burst-and-leave failure mode stays visible (v13.6.1 caveat 2).
    if !link_live {
        return ReverseWaitStep::LinkStale;
    }
    if since_start >= max_transfer {
        return ReverseWaitStep::MaxDeadline;
    }
    // `since_last_progress` is measured from the last progress event, or from the
    // send start if none has fired yet — so a link that never even advertises
    // trips this at the no-progress window (fast-fail, no #373 regression).
    if since_last_progress >= no_progress_window {
        return ReverseWaitStep::StalledNoProgress;
    }
    ReverseWaitStep::Continue
}

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

/// CIRISEdge#482 item 3 — bound on the announce cold-start hand-off queue. The
/// EventReceiver task `try_send`s each inbound announce here and a dedicated
/// worker drains it, so a slow/contended rooting directory can no longer
/// head-of-line every other node event behind an announce's DB round-trips.
/// At the cap, `try_send` TAIL-drops — it rejects the NEWEST announce and keeps
/// the 256 already queued — with a LOUD warn, never a silent drop
/// (CIRISEdge#425). RNS announces are periodic + idempotent, so a dropped one
/// self-heals on the peer's next re-announce.
const ANNOUNCE_QUEUE_DEPTH: usize = 256;

/// CIRISEdge#482 item 5 — window a `check_blackhole` deny-list snapshot stays
/// valid before the next dial re-reads `blackhole_list()` from persist. Short
/// enough that operator add/remove takes effect near-immediately; long enough
/// that a dial FLOOD (the hot path this optimizes) collapses to one DB read.
/// See the `blackhole_cache` field docblock for the staleness argument.
const BLACKHOLE_CACHE_TTL: Duration = Duration::from_secs(2);

/// CIRISEdge#482 item 2 — window a `hybrid_transport_binding_exists` verdict
/// stays valid before the next inbound frame re-queries the rooting directory.
/// The inbound attribution path checked this per frame (an uncached directory
/// lookup); caching collapses a burst from one peer to a single query. Kept
/// tight because caching a stale `true` past a binding *revocation* is the
/// security-relevant direction — see the `binding_cache` field docblock.
const BINDING_CACHE_TTL: Duration = Duration::from_secs(3);

/// CIRISEdge#482 item 2 — the memo backing [`binding_exists_cached`]. Keyed by
/// the COMPLETE input to `hybrid_transport_binding_exists` — `(key_id, dest)` —
/// mapping to `(verdict, fetched_at)`. A plain `std::sync::Mutex` (guard never
/// held across an `.await`, keeping the inbound path #217-safe).
type BindingCache = std::sync::Mutex<HashMap<(String, [u8; 16]), (bool, std::time::Instant)>>;

/// CIRISEdge#482 item 5 — the deny-list snapshot cache: `(generation,
/// Option<(fetched_at, rows)>)`. The generation is bumped on local
/// invalidation so a concurrent refresh can't clobber it. See the
/// `blackhole_cache` field docblock.
type BlackholeCache = std::sync::Mutex<(
    u64,
    Option<(
        std::time::Instant,
        Arc<Vec<ciris_persist::federation::BlackholeRecord>>,
    )>,
)>;

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

static CONTROL_PLANE_OVERFLOW_LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> =
    std::sync::OnceLock::new();

/// CIRISEdge#508 — leviculum's `ControlPlaneOverflow` marker consumed instead
/// of falling through the `other =>` trace-level catch-all. The marker is
/// leviculum's designed loss surface (it carries the aggregate dropped_count
/// and is itself never dropped), so DISCARDING it at TRACE meant the one
/// aggregate line an operator needed was invisible while the per-drop
/// EVENT_CHANNEL_FULL flood buried everything 30:1. Keyed on a single fixed
/// key (cardinality 1); throttled because sustained saturation re-arms a
/// marker every drain window, which an announce/link flood can influence —
/// first 6 per minute log loudly, the rest collapse to a suppressed count.
fn control_plane_overflow_log() -> &'static crate::log_throttle::LogThrottle {
    CONTROL_PLANE_OVERFLOW_LOG
        .get_or_init(|| crate::log_throttle::LogThrottle::new(6, Duration::from_secs(60), 1))
}

static INITIATOR_ATTRIBUTION_MISS_LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> =
    std::sync::OnceLock::new();

/// CIRISEdge#424 — the initiator-side attribution arm could not resolve a source
/// for an inbound frame's link: either NO destination is known for the link
/// (`link_destination`=None AND no dialed-dest record — the bug's silent outer
/// `else`) or a known dest matches no rooted peer. LOUD (throttled, keyed per
/// link, capped map as the backstop) so the miss can NEVER again read as absence
/// of work — the #414/#416/#932/#423/#424 silent-refusal class.
fn initiator_attribution_miss_log() -> &'static crate::log_throttle::LogThrottle {
    INITIATOR_ATTRIBUTION_MISS_LOG
        .get_or_init(|| crate::log_throttle::LogThrottle::new(5, Duration::from_secs(60), 256))
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

static INBOUND_DROP_LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> =
    std::sync::OnceLock::new();

/// CIRISEdge#425 — throttle backing [`drop_inbound`]. Keyed on the low-cardinality
/// reason TAG (a fixed set), a floor per window (periodic repeat), never silence.
fn inbound_drop_log() -> &'static crate::log_throttle::LogThrottle {
    INBOUND_DROP_LOG
        .get_or_init(|| crate::log_throttle::LogThrottle::new(3, Duration::from_secs(60), 64))
}

/// CIRISEdge#425 structural-2 — the ONE blessed way for the listen loop to NOT
/// deliver an inbound frame. Owns the throttled `warn!`, so a receive-side drop is
/// never a bare `return;` that vanishes at default log levels (the #932/#424 class
/// on the receive path). `reason_tag` is the low-cardinality throttle key; `detail`
/// is the free-text context. The `inbound_drop_choke_points_are_instrumented`
/// characterization pin greps `handle_event` / `attribute_and_deliver` for
/// `return;` / `continue;` NOT adjacent to a `drop_inbound` or `tracing::` call, so
/// a NEW silent drop fails the build.
fn drop_inbound(link_id: Option<LinkId>, reason_tag: &str, detail: &str) {
    if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
        inbound_drop_log().check(reason_tag)
    {
        tracing::warn!(
            link = ?link_id,
            reason = reason_tag,
            detail,
            suppressed_prev,
            "inbound frame DROPPED — not delivered (CIRISEdge#425 receive-side choke point)"
        );
    }
}

static OVERSIZED_FRAME_DROP_LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> =
    std::sync::OnceLock::new();

/// CIRISEdge#414 / CIRISAgent#932 — an oversized reverse-path reply could NOT be
/// fragmented onto the busy link's packet channel (degenerate MDU below
/// [`crate::transport::frame_fragment::MIN_FRAGMENTABLE_MDU`], or the link Channel
/// backpressured mid-fragment-send). This is the exact class that used to be a
/// SILENT drop onto the one-per-link resource `Busy` gate — the #932 stall. It is
/// now LOUD (throttled WARN, keyed per peer) so the fragmentation gap is a log
/// line, never an interrogation. Bounded like the reverse-path fallback log.
fn oversized_frame_drop_log() -> &'static crate::log_throttle::LogThrottle {
    OVERSIZED_FRAME_DROP_LOG
        .get_or_init(|| crate::log_throttle::LogThrottle::new(5, Duration::from_secs(60), 256))
}

static OWN_BUNDLE_PUSH_LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> =
    std::sync::OnceLock::new();

/// CIRISEdge#436 — a link-up push of this node's own build-attestation bundle
/// could not complete (degenerate MDU / channel backpressure). Best-effort by
/// design (the peer re-receives on the next link-up), but LOUD-throttled, never
/// silent: a peer that can never receive the bundle can never root us at first
/// contact, which would otherwise read as an unexplained Advisory plateau.
fn own_bundle_push_log() -> &'static crate::log_throttle::LogThrottle {
    OWN_BUNDLE_PUSH_LOG
        .get_or_init(|| crate::log_throttle::LogThrottle::new(3, Duration::from_secs(60), 8))
}

static PEER_BUNDLE_ARRIVAL_LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> =
    std::sync::OnceLock::new();

/// CIRISEdge#436 — refusals of a link-borne peer bundle (`CBND` frame). Keyed
/// on the low-cardinality refusal TAG (a fixed set — never attacker-chosen), a
/// floor per window, never silence: a refused package must never look like a
/// stored/verified one (the #423 apply-loud discipline).
fn peer_bundle_arrival_log() -> &'static crate::log_throttle::LogThrottle {
    PEER_BUNDLE_ARRIVAL_LOG
        .get_or_init(|| crate::log_throttle::LogThrottle::new(3, Duration::from_secs(60), 32))
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

/// CIRISEdge#336 (v13.8.0) — provenance of a dial-candidate destination.
/// See [`ReticulumTransport::resolve_dial_candidates`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DialSource {
    /// Announce-bound / `prime_peer`'d dest cached on the rooted entry.
    Cached,
    /// `sha256(fed_pubkey)[..16]` — un-announceable, broadcast-only (#191).
    ExplicitHash,
    /// Legacy `sha256(name_hash‖identity_hash)` from resolver transport keys —
    /// the announceable (relay-routable) address shape.
    ComputedNamed,
}

impl DialSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Cached => "cached",
            Self::ExplicitHash => "explicit_hash",
            Self::ComputedNamed => "computed_named",
        }
    }
}

/// One dialable address for a peer, with the signing key from the SAME
/// provenance as the dest (see `resolve_dial_candidates` on why they pair).
#[derive(Debug, Clone, Copy)]
struct DialCandidate {
    dest_hash: DestinationHash,
    signing_key: [u8; 32],
    source: DialSource,
}

/// CIRISEdge#336 (v13.8.0) — ROUTE-TABLE-FIRST dial selection: the pure
/// decision that makes "dial an unroutable dest while a routable one exists"
/// impossible by construction. Input is the candidate list as
/// `(source, has_path)`; output is the winning index.
///
/// * Any candidate has a path → dial the highest-provenance PATHED one:
///   `Cached` (announce/prime provenance) > `ComputedNamed` (the announceable
///   shape — the #336 field fix) > `ExplicitHash` (pathed ~never; last).
/// * No candidate has a path → BOOTSTRAP broadcast, in exactly the
///   pre-v13.8.0 single-winner order (`Cached` > `ExplicitHash` >
///   `ComputedNamed`) so behavior is byte-identical when the route table is
///   agnostic; the existing fast-fail + loud #336 error bound this dial.
/// * Empty → `None` (unrooted/unresolvable — caller's existing branch).
fn select_dial_candidate(candidates: &[(DialSource, bool)]) -> Option<usize> {
    const PATHED_ORDER: [DialSource; 3] = [
        DialSource::Cached,
        DialSource::ComputedNamed,
        DialSource::ExplicitHash,
    ];
    const BOOTSTRAP_ORDER: [DialSource; 3] = [
        DialSource::Cached,
        DialSource::ExplicitHash,
        DialSource::ComputedNamed,
    ];
    for want in PATHED_ORDER {
        if let Some(i) = candidates
            .iter()
            .position(|(s, pathed)| *pathed && *s == want)
        {
            return Some(i);
        }
    }
    for want in BOOTSTRAP_ORDER {
        if let Some(i) = candidates.iter().position(|(s, _)| *s == want) {
            return Some(i);
        }
    }
    None
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
    /// CIRISEdge#393 (E3) — did this binding PROVE control of the federation key
    /// the directory binds to `key_id`? Captured at admit from the announce
    /// verdict (`Confirmed ⇒ true`; an Advisory admit ⇒ true only when the
    /// rejection was neither `UnknownKeyId` nor `PubkeyMismatch`, i.e. the pubkey
    /// matched and the self-signature verified). This is the load-bearing signal
    /// — alongside `provenance == Rooted` — that
    /// [`crate::transport::SourceKeyId::from_rooted_binding`] gates trace-serve
    /// attribution on: an Advisory or non-owning binding is never attributed, so
    /// it can never be served a peer's `trace:*` corpus.
    owns_key: bool,
    /// CIRISEdge#436 — the FULL 64-byte transport identity
    /// (`x25519 ‖ ed25519`) this entry was admitted with (the announce's own
    /// `public_key`). `transport_identity_hash` above is derived from exactly
    /// these bytes. Kept so the first-contact bundle upgrade can run its
    /// durable half (`persist_transport_binding` needs the full identity) in
    /// the SAME motion as the live-map half — never a second writer with
    /// different operands (the #432 lesson). `[0u8; 64]` x25519-half for the
    /// ed25519-only test injector (whose identity hash is already the
    /// never-matching zero sentinel).
    transport_pubkey64: [u8; 64],
    /// CIRISEdge#436 — the 32-byte manifest commitment this peer's announce
    /// carried (`sha256(JCS(manifest_contribution))` of its build-attestation
    /// bundle), or `None` for a pre-#436 / unbundled announce. NOT
    /// trust-bearing on its own: it only selects WHICH link-borne package may
    /// attempt the Advisory→Rooted upgrade — the package still has to verify
    /// the full CIRISVerify#181 chain against the directory pins.
    manifest_commitment: Option<[u8; 32]>,
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
    /// **"Allow me to be visible to the federation so I can use the mesh."**
    ///
    /// The wizard question, and the ONE opt-in that decides this node's
    /// reachability posture. When `true` the node's named discovery
    /// destination announces, transport nodes learn a path to it, and it
    /// participates in the mesh. When `false` it announces nothing and is
    /// reachable **point-to-point only** — a peer must already hold its
    /// address to reach it.
    ///
    /// Getting the direction right matters, because it is easy to read
    /// scope-native addressing (CIRISEdge#499) as a privacy feature you trade
    /// reach for. It is not. A node that has not opted into federation
    /// visibility is point-to-point **anyway**; scoped destinations being
    /// one-hop (CC 5.4.6, ruled at CIRISConstitution#91) costs such a node
    /// nothing it had. The trade only exists for a node that IS
    /// federation-visible and is choosing to move some flows off that plane.
    ///
    /// Defaults to `true` — NOT because visibility is the right default, but
    /// because flipping a deployed node to invisible on upgrade would silently
    /// remove it from the mesh, and a silent reachability change is the one
    /// failure mode worse than an over-visible default. A wizard MUST ask
    /// rather than inherit this.
    pub federation_visible: bool,
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
    /// **CIRISEdge#363** — node-wide link keepalive interval handed to
    /// leviculum's `ReticulumNodeBuilder::link_keepalive`. `Some(interval)`
    /// overrides leviculum's RTT-derived default; `None` leaves it in place.
    ///
    /// Defaults to `Some(`[`BOOTSTRAP_LINK_KEEPALIVE`]`)` (30 s) so a
    /// freshly-admitted advisory/bootstrap link survives the Key +
    /// IdentityOccurrence anti-entropy instead of being reaped at ~16 s by the
    /// RTT-clamped 5 s default (stale at 10 s). The value is clamped into
    /// leviculum's valid band by [`effective_link_keepalive_secs`] before it
    /// reaches the builder — an operator override cannot escape the DoS bound.
    pub link_keepalive: Option<Duration>,
    /// CIRISEdge#508 item (d) — capacity of leviculum's LOSSLESS control-plane
    /// event channel (`ReticulumNodeBuilder::control_channel_capacity`).
    /// `None` → leviculum's 256 default, which its own docs size for "small
    /// std platforms" with servers expected to override — advice no edge
    /// embedder could take before this field. Operators without a config path
    /// set the `CIRIS_EDGE_RETICULUM_CONTROL_CHANNEL_CAPACITY` env var
    /// instead; an explicit field value wins over the env var, and either is
    /// clamped by [`effective_control_channel_capacity`]. Capacity only buys
    /// headroom in front of a consumer stall (it is deliberately item (d),
    /// LAST, in CIRISEdge#508's priority order) — the stall itself is
    /// leviculum#56–#59.
    pub control_channel_capacity: Option<usize>,
    /// CIRISEdge#492 — node-wide relay (transit) posture applied to the LEGACY
    /// interface path (the `listen_addr` server + `bootstrap_peers` clients, used
    /// when `interfaces` is empty). `None` = leviculum default (relay-by-default);
    /// `Some(false)` = leaf-only. Typed `interfaces` carry their OWN per-interface
    /// posture and ignore this. See [`IfacConfig`].
    pub transit: Option<bool>,
    /// CIRISEdge#492 — node-wide IFAC applied to the LEGACY interface path: `Some`
    /// makes the `listen_addr` server + every bootstrap client a member-only port;
    /// `None` = open. Typed `interfaces` carry their own IFAC.
    pub ifac: Option<IfacConfig>,
}

impl ReticulumTransportConfig {
    /// Construct a config with the mandatory fields and sensible
    /// defaults (`0.0.0.0:4242` listen addr, no bootstrap peers,
    /// 5-minute announce interval).
    #[must_use]
    pub fn new(identity_path: PathBuf, local_key_id: impl Into<String>) -> Self {
        Self {
            listen_addr: "0.0.0.0:4242".parse().expect("static addr parses"),
            federation_visible: true,
            bootstrap_peers: Vec::new(),
            identity_path,
            announce_interval: Duration::from_secs(300),
            local_key_id: local_key_id.into(),
            local_epoch: 0,
            interfaces: Vec::new(),
            enable_transport: false,
            // CIRISEdge#363 — default the bootstrap keepalive ON so advisory
            // links survive the two-plane anti-entropy out of the box.
            link_keepalive: Some(BOOTSTRAP_LINK_KEEPALIVE),
            control_channel_capacity: None,
            transit: None,
            ifac: None,
        }
    }

    /// CIRISEdge#492 — set the node-wide scoped-transit posture for the legacy
    /// interface path: `transit` (`Some(false)` = leaf-only, never rebroadcasts
    /// announces) + an optional IFAC (member-only access code). Builder-style;
    /// applies to the `listen_addr` server + every `bootstrap_peers` client.
    /// Typed `interfaces` carry their own posture and are unaffected.
    #[must_use]
    pub fn with_scoped_transit(mut self, transit: Option<bool>, ifac: Option<IfacConfig>) -> Self {
        self.transit = transit;
        self.ifac = ifac;
        self
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
    /// `leviculum_std::config::InterfaceConfig` row via
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

/// CIRISEdge#492 — per-interface IFAC (Interface Framing Access Code): the
/// shared-secret "network access code" that scopes an interface to CIRIS
/// members. Packets without the code drop AT the interface, so everything past
/// it is member traffic by construction — structural invisibility, no per-packet
/// identity inspection. Maps onto leviculum's `add_tcp_server_ifac` /
/// `add_tcp_client_ifac` / `InterfaceConfig { networkname, passphrase, ifac_size }`.
#[cfg(feature = "_reticulum-module")]
#[derive(Debug, Clone)]
pub struct IfacConfig {
    /// IFAC virtual-network name (`None` = leviculum's unnamed default network).
    pub networkname: Option<String>,
    /// The shared member passphrase. Distributed to hybrid-verified members as a
    /// rotating PQC `key_grant` (CIRISPersist#704) for flag-day-free rotation via
    /// the three rotation verbs; operator-supplied until that lands.
    pub passphrase: String,
    /// IFAC hash-truncation size in BYTES (Python callers pass bits ÷ 8). The
    /// leviculum convention is 16 for a NETWORK interface (TCP/UDP — edge's
    /// relay ports) and 8 for a serial link (RNode/pipe/KISS/AX.25). Both peers
    /// on an interface MUST agree.
    pub ifac_size: usize,
}

/// `TcpServerInterface` configuration — bind a TCP socket.
#[cfg(feature = "transport-reticulum-tcp-server")]
#[derive(Debug, Clone)]
pub struct TcpServerInterfaceConfig {
    /// Address the TCP server binds to.
    pub listen_addr: SocketAddr,
    /// CIRISEdge#492 — relay (transit) posture. `None` = leviculum default
    /// (relay-by-default, leviculum#48/#51); `Some(false)` = a public LEAF port
    /// that never rebroadcasts announces and drops any relay crossing it. Declare
    /// non-transit on a public leaf so no peer builds a path expecting a transit
    /// this CIRIS node won't provide (the Tor-exit-policy lesson — a silent-drop
    /// router is worse than absence).
    pub transit: Option<bool>,
    /// CIRISEdge#492 — IFAC scoping. `Some` = member-only port; `None` = open.
    pub ifac: Option<IfacConfig>,
}

/// `TcpClientInterface` configuration — dial a remote TCP server.
#[cfg(feature = "transport-reticulum-tcp-client")]
#[derive(Debug, Clone)]
pub struct TcpClientInterfaceConfig {
    /// Target TCP server address to dial.
    pub target_addr: SocketAddr,
    /// CIRISEdge#492 — relay (transit) posture for this dialed link. `None` =
    /// leviculum default (relay); `Some(false)` = leaf-only. See
    /// [`TcpServerInterfaceConfig::transit`].
    pub transit: Option<bool>,
    /// CIRISEdge#492 — IFAC scoping. `Some` = the dialed peer is a member port
    /// (member access code applied); `None` = open dial.
    pub ifac: Option<IfacConfig>,
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

/// `I2PInterface` configuration — Phase 3 anonymous overlay; the gate
/// compiles the TYPED CONFIG SURFACE ONLY. The runtime path is not
/// implemented: no SAM session is ever established. This is fail-loud,
/// NOT a silent no-op — supplying an I²P interface to the transport
/// refuses at construction with a typed `TransportError::Config`
/// naming the unimplemented state (see `apply_interface_config`'s
/// `I2p` arm), so a deployment cannot believe it is riding I²P cover
/// traffic when it is not.
#[cfg(feature = "transport-reticulum-i2p")]
#[derive(Debug, Clone, Default)]
pub struct I2pInterfaceConfig {
    /// I²P SAM bridge address the Phase 3 runtime will dial when it
    /// lands. Parsed and carried so config plumbing round-trips; read
    /// by the `apply_interface_config` refusal (named in the error) —
    /// never used to establish a session yet.
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
    /// CIRISEdge#489 — the announce-suppression policy installed on `node`
    /// via `set_announce_control`. Retained here (Arc-backed inner shares
    /// state with the node's boxed clone) so a future scoped destination can
    /// be registered via `register_destination_scope` and the node's
    /// auto-announce loops immediately honour its cohort scope.
    announce_policy: crate::announce_suppression::ScopePrivacyAnnouncePolicy,
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
    /// CIRISEdge#499 — the scope-native address table, installed ONCE
    /// (`install_scope_address_table`) after the cohort/session MLS layer
    /// derives its first group secret. `OnceLock` because the lifecycle is
    /// genuinely write-once-then-read-many: the transport starts long before
    /// any group is joined, and every later mutation (install/rotate/remove)
    /// happens *inside* the table's own lock, not by swapping the handle. A
    /// read is therefore one atomic load on the receive path — no transport
    /// lock, so nothing here can be held across an `.await` (CIRISEdge#217).
    /// `None` until installed: every scope-native lookup then declines and
    /// the federation-scope paths are unaffected.
    scope_addresses: OnceLock<Arc<ScopeAddressTable>>,
    /// CIRISEdge#169 — the LXMF propagation serve node, when this node has
    /// been configured to carry third-party mail. `None` (the default) means
    /// the `RequestReceived` arm declines every propagation request.
    #[cfg(feature = "lxmf")]
    lxmf_serve: OnceLock<Arc<crate::transport::lxmf_serve::LxmfServeNode>>,
    /// Edge's own announce attestation app-data — built once in
    /// `new` (sign with the federation `LocalSigner`) and emitted
    /// verbatim on every announce. `None` when no signer was
    /// supplied: the transport then cannot prove its own binding and
    /// announces an empty app-data (peers with rooting enabled will
    /// drop it — fail-honest).
    local_attestation: Option<Vec<u8>>,
    /// CIRISEdge#406 — the federation `LocalSigner` (mandatory since
    /// CIRISEdge#333), retained past construction so the signed
    /// transport-destination producer can re-arm from the announce
    /// loop. The ciris-keyring `HardwareSigner`/`PqcSigner` handles
    /// inside are THE signing primitive — no raw keys held (AV-17).
    local_signer: Arc<LocalSigner>,
    /// CIRISEdge#406 — idempotent producer state for edge's OWN
    /// hybrid-signed `SignedTransportDestination` (the #393 item-2
    /// gate's missing producer). Bootstrapped in `new`; re-armed by
    /// the periodic announce tick so a boot-time fault (directory not
    /// yet serving / own key not yet registered) heals in place.
    self_route: crate::transport::self_route::SelfSignedRouteProducer,
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
    /// CIRISEdge#353b/v13.6.1 — sender-side transfer progress for in-flight
    /// resources, keyed by `resource_hash`. Populated by the
    /// `Resource{Advertised,TransferStarted,Progress}` (`is_sender: true`) event
    /// arms; read by `ship_resource_on_link`'s progress-aware wait so a live-but-
    /// slow reverse-path transfer is extended while a dead link fast-fails.
    sent_resource_progress: Arc<Mutex<HashMap<[u8; 32], ResourceSendProgress>>>,
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
    /// CIRISEdge#437 — bundle-gate posture on the DURABLE Rooted
    /// transport-binding save. Default [`BundleSaveGateMode::Off`] (no
    /// behavior change); the flip is a dated fleet-floor event — see
    /// [`crate::bundle_gate`].
    bundle_save_gate: crate::bundle_gate::BundleSaveGateMode,
    /// CIRISEdge#437 — per-peer store of presented build-attestation
    /// bundles, consumed by the durable-save gate. Fed by the CIRISEdge#436
    /// arrival transport (announce commitment + link-borne `CBND` package)
    /// and/or via [`Self::register_peer_build_bundle`] (PyO3:
    /// `Edge.register_peer_build_bundle`).
    peer_bundles: Arc<crate::bundle_gate::PeerBundleStore>,
    /// CIRISEdge#436 — this node's own validated build-attestation bundle
    /// (announce commitment + link-up `CBND` push). `None` → v1 announces
    /// byte-identical to pre-#436, nothing served.
    own_bundle: Option<OwnBuildBundle>,
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
    /// CIRISEdge#353 — per-link last-inbound timestamp (unix seconds),
    /// stamped by `attribute_and_deliver` on EVERY inbound frame this link
    /// carries. This is the RNS `last_inbound` liveness signal (leviculum-core
    /// tracks it internally for staleness — `link/mod.rs::last_inbound_secs` —
    /// but the std driver doesn't expose it, so edge mirrors it from the frames
    /// it sees). `live_attributed_link_to` selects the peer's link with the
    /// FRESHEST inbound — the link the peer is actively sending its round on —
    /// so a NAT-dead link that leviculum still reports `Active` (no recent
    /// inbound) is never chosen as the reply target, which is exactly the #353
    /// field failure (a 120 s resource timeout shipping into a dead-but-Active
    /// link). Removed on `LinkClosed`.
    link_last_inbound_at: Arc<Mutex<HashMap<LinkId, u64>>>,
    /// CIRISEdge#414 / CIRISAgent#932 — inbound fragment reassembler. Every frame
    /// arriving over an established link (resource OR packet path — both funnel
    /// through `attribute_and_deliver`) is fed here first: a whole (`CRPL…`) frame
    /// passes straight through; a `CFRG` fragment is buffered until its siblings
    /// complete the frame. This is the receive half of the #932 fix — the send
    /// side fragments an oversized reverse-path reply onto the packet path, and
    /// this reassembles it before it reaches the replication router. Bounded by an
    /// LRU cap on in-flight frames so lost fragments / floods cannot grow memory.
    inbound_reasm: Arc<Mutex<crate::transport::frame_fragment::Reassembler>>,
    /// CIRISEdge#424 — the destination edge dialed for each link it INITIATED,
    /// recorded at `connect` time. leviculum's `link_destination` returns `None`
    /// for a node's own dialed (initiator) links (its `link()` registry lookup
    /// misses for the initiator direction / after a #66 re-key), so the #353
    /// initiator-side attribution arm — which maps an inbound reply's link back to
    /// its peer via the link's destination — exited at step one and dropped every
    /// reply `source_key_id=None`. This map is edge's own re-key-independent record
    /// of "I dialed link L to dest D", consulted when `link_destination` is `None`.
    /// Removed on `LinkClosed`.
    dialed_link_dest: Arc<Mutex<HashMap<LinkId, DestinationHash>>>,
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
    /// CIRISEdge#482 item 5 — short-TTL snapshot of the deny-list so a
    /// dial FLOOD collapses to one `blackhole_list()` DB round-trip per
    /// [`BLACKHOLE_CACHE_TTL`] window instead of one read per dial (the
    /// hot send-path was an uncached full-table read). Holds
    /// `(fetched_at, rows)`; a lookup within the window scans the cached
    /// `Arc<Vec<_>>` with zero DB traffic. The lock is a plain
    /// `std::sync::Mutex` held only across the snapshot swap — never
    /// across the `.await` refresh — so this stays #217-safe (no tokio
    /// timing primitive on a path that can run on persist's runtime
    /// thread). **Staleness bound**: a newly-`add`ed rule takes effect,
    /// and a `remove`d rule stops blocking, within one TTL window; the
    /// deny-list is operator-intent (see the #120 docblock — low-dozens,
    /// human-curated), so a ≤TTL enforcement lag on a peer that was
    /// reachable a moment ago is immaterial, and both directions
    /// fail-safe (over-block briefly on removal, under-block briefly on
    /// add). `None`-backend transports never populate this.
    ///
    /// The leading `u64` is a GENERATION counter bumped by
    /// [`Self::invalidate_blackhole_cache`] under this same lock:
    /// `check_blackhole` snapshots it before its DB read and only commits
    /// the fetched snapshot if the generation is UNCHANGED, so a local
    /// `add`/`remove` that lands DURING an in-flight dial's read is never
    /// clobbered by that dial's stale pre-mutation snapshot re-armed with a
    /// fresh timestamp (CIRISEdge#482 review finding) — the "visible to the
    /// very next dial" invalidation guarantee holds against that race.
    blackhole_cache: BlackholeCache,
    /// CIRISEdge#482 item 2 — per-`(peer, dest)` hybrid-binding memo consulted
    /// on the inbound attribution path (once-per-frame directory lookup → one
    /// query per TTL window). See [`binding_exists_cached`].
    binding_cache: BindingCache,
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
    /// CIRISEdge#437 — bundle gate on the DURABLE Rooted transport-binding
    /// save. [`Default`] is [`BundleSaveGateMode::Off`](crate::bundle_gate::BundleSaveGateMode::Off)
    /// (today's behavior byte-identical); the flip to
    /// `RequireBundleForRootedSave` is a dated fleet-floor event — see
    /// [`crate::bundle_gate`] for the flip-event contract.
    pub bundle_save_gate: crate::bundle_gate::BundleSaveGateMode,
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
    /// CIRISEdge#436 — this node's OWN build-attestation bundle (the JSON
    /// `SignedCegObject` the CI pipeline + presenter signing produced —
    /// CIRISVerify#181). When `Some`:
    ///
    /// - every announce carries the 32-byte **manifest commitment**
    ///   (`sha256(JCS(manifest_contribution))`) in its attestation (wire v2),
    /// - the bundle itself is served over every established link as a `CBND`
    ///   frame, so a fresh peer can validate the package against the
    ///   commitment and root this node **at first contact**.
    ///
    /// Validated at construction (size cap, shape, canonicalizable manifest)
    /// — a malformed bundle is a hard config error, never a silently
    /// commitment-less announce. `None` (the default) announces the
    /// pre-#436 v1 wire byte-identical and serves nothing.
    ///
    /// **Mixed-fleet caveat**: a commitment-bearing announce is attestation
    /// wire v2 — a pre-#436 peer refuses it with its typed unknown-version
    /// parse error (clean, but it will NOT root this node from the announce).
    /// Setting this is therefore a peer-visible opt-in, staged like every
    /// enforcement flip: turn it on once the peers that must root you parse
    /// v2 (i.e. run #436-aware builds).
    pub own_build_bundle: Option<Vec<u8>>,
}

impl Default for ReticulumAuth {
    fn default() -> Self {
        Self {
            signer: None,
            rooting: None,
            resolver: None,
            hybrid_policy: HybridPolicy::Strict,
            transport_binding_enforcement: TransportBindingEnforcement::Advisory,
            bundle_save_gate: crate::bundle_gate::BundleSaveGateMode::Off,
            event_bus: None,
            reachability: None,
            blackhole_rules: None,
            transport_identity_keystore: None,
            own_build_bundle: None,
        }
    }
}

/// CIRISEdge#436 — this node's own validated build-attestation bundle, pinned
/// at construction: the pre-encoded `CBND` frame served on link-up plus the
/// manifest commitment every announce carries.
struct OwnBuildBundle {
    /// The bundle bytes pre-wrapped as a `CBND` v1 frame (encode once).
    frame: Vec<u8>,
    /// `sha256(JCS(manifest_contribution))` — the announce commitment.
    manifest_commitment: [u8; 32],
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
            bundle_save_gate,
            event_bus,
            reachability,
            blackhole_rules,
            transport_identity_keystore,
            own_build_bundle,
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
        let Some(local_signer) = signer else {
            return Err(TransportError::Config(
                "Reticulum transport requires a federation signer: every announce must be \
                 self-attested (CIRISEdge#333). An unattested announce yields a peer that \
                 routes but can never root — it looks healthy and is not."
                    .to_string(),
            ));
        };
        // CIRISEdge#436 — validate + pin this node's OWN build-attestation
        // bundle BEFORE composing the announce attestation, so the announce
        // can carry the manifest commitment from the very first announce.
        // Fail-loud at construction: a bundle that cannot yield a commitment
        // would otherwise silently announce commitment-less and never be
        // rootable-at-first-contact — a #333-class healthy-looking trap.
        let own_bundle = match own_build_bundle {
            None => None,
            Some(bytes) => {
                if bytes.len() > crate::bundle_gate::MAX_PEER_BUNDLE_BYTES {
                    return Err(TransportError::Config(format!(
                        "own_build_bundle is {} bytes; the peer-bundle cap is {} \
                         (CIRISEdge#436/#437)",
                        bytes.len(),
                        crate::bundle_gate::MAX_PEER_BUNDLE_BYTES,
                    )));
                }
                let Some(manifest_commitment) =
                    crate::bundle_gate::manifest_commitment_of_bundle(&bytes)
                else {
                    return Err(TransportError::Config(
                        "own_build_bundle is not a build_attestation_bundle SignedCegObject \
                         with a canonicalizable manifest_contribution — no manifest \
                         commitment can be announced (CIRISEdge#436)"
                            .to_string(),
                    ));
                };
                Some(OwnBuildBundle {
                    frame: crate::transport::peer_bundle_frame::encode(&bytes),
                    manifest_commitment,
                })
            }
        };
        let local_attestation = Some(
            build_local_attestation(
                &local_signer,
                &transport_ed25519,
                &transport_x25519,
                &config.local_key_id,
                config.local_epoch,
                own_bundle.as_ref().map(|b| b.manifest_commitment),
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
        // CIRISEdge#363 — apply the bootstrap link keepalive so an advisory /
        // bootstrap link is not reaped (stale at ~10 s, dead at ~16 s under the
        // RTT-clamped 5 s default) before the Key + IdentityOccurrence
        // anti-entropy that promotes it to a KEX'd delivery target completes.
        // `effective_link_keepalive_secs` clamps into leviculum's valid band so
        // an operator override stays inside the DoS bound. The wiring decision
        // is logged (unthrottled — one line per node build, not attacker-driven)
        // so a silent keepalive misconfig can never again cost a trace weeks.
        match effective_link_keepalive_secs(config.link_keepalive) {
            Some(secs) => {
                builder = builder.link_keepalive(secs);
                tracing::info!(
                    keepalive_secs = secs,
                    stale_secs = secs.saturating_mul(2),
                    "reticulum link keepalive pinned for advisory/bootstrap link \
                     survival (CIRISEdge#363)"
                );
            }
            None => {
                tracing::info!(
                    "reticulum link keepalive left at leviculum's RTT-derived default \
                     (CIRISEdge#363: bootstrap links may reap at ~16 s)"
                );
            }
        }
        // CIRISEdge#508 item (d) — control-plane channel capacity. Same
        // wiring-decision discipline as the keepalive above: one INFO line per
        // node build, so "which capacity is this node actually running" is
        // answerable from logs instead of forensic archaeology. leviculum's
        // 256 default overflowed on the live canonical; the overflow was a
        // SYMPTOM of a consumer stall (leviculum#56–#58), so capacity is
        // headroom, not the fix — but the headroom must at least be settable.
        let env_capacity = std::env::var(CONTROL_CHANNEL_CAPACITY_ENV).ok();
        match effective_control_channel_capacity(
            config.control_channel_capacity,
            env_capacity.as_deref(),
        ) {
            (Some(capacity), source) => {
                builder = builder.control_channel_capacity(capacity);
                tracing::info!(
                    capacity,
                    ?source,
                    "reticulum control-plane event channel capacity overridden \
                     (CIRISEdge#508 item d)"
                );
            }
            (None, source @ ControlChannelCapacitySource::EnvInvalid) => {
                tracing::warn!(
                    env_var = CONTROL_CHANNEL_CAPACITY_ENV,
                    raw = env_capacity.as_deref().unwrap_or(""),
                    ?source,
                    "control-channel capacity env var did not parse as usize — \
                     IGNORED, leviculum default (256) applies (CIRISEdge#508 item d)"
                );
            }
            (None, _) => {
                tracing::info!(
                    "reticulum control-plane event channel at leviculum's 256 default \
                     (CIRISEdge#508 item d: a canonical-scale server should override \
                     via config or CIRIS_EDGE_RETICULUM_CONTROL_CHANNEL_CAPACITY)"
                );
            }
        }
        let mut share_instance_local: Option<String> = None;
        let mut connect_instance_local: Option<String> = None;
        if config.interfaces.is_empty() {
            // Legacy v0.11.x defaults — TCP server + bootstrap TCP
            // clients. Registry records each one so the typed surface
            // is uniform. CIRISEdge#492 — the node-wide `transit`/`ifac`
            // posture (if set) applies to these legacy interfaces via the
            // same shared mapper the typed path uses.
            builder = apply_tcp_server_transit(
                builder,
                config.listen_addr,
                config.transit,
                config.ifac.as_ref(),
            );
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
                builder =
                    apply_tcp_client_transit(builder, *peer, config.transit, config.ifac.as_ref());
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
        // (Signer presence is enforced above, CIRISEdge#333 — the same
        // requirement covers v7.0.0 explicit-hash addressing: no fallback
        // to a legacy keystore-derived destination is supported, peers
        // would diverge on routability.)
        let federation_ed25519_pubkey: [u8; 32] = {
            let (ed_bytes, _pqc) = local_signer.federation_pubkeys().await.map_err(|e| {
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
        };
        let explicit_dest_hash = crate::transport::addressing::reticulum_destination_for_pubkey(
            &federation_ed25519_pubkey,
        );
        // CIRISEdge#371 / leviculum#30 — `Destination::with_explicit_hash` is the
        // ONE fork-only API with no upstream equivalent: upstream `Destination.hash`
        // is private and `Destination::new` derives it from app_name+aspects+identity,
        // so a node cannot otherwise listen on the federation-rooted hash peers
        // address it by (CIRISEdge#191). Re-ported onto the leviculum-* rename in
        // v0.10.1+ciris.1 (the other dropped fork APIs all migrated to upstream
        // idioms: send_on_link → LinkHandle::try_send, connect_at → connect(dest_hash),
        // register_destination_at → register_destination).
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
        // CIRISEdge#371 — the explicit hash rides on the `Destination` itself
        // (via `with_explicit_hash` above), and the core keys the routing table
        // on `dest.hash()`, so upstream's native `register_destination` registers
        // it at exactly `explicit_dest_hash` — the fork-only `register_destination_at`
        // is unnecessary. (The debug_assert above proves `dest.hash()` == the
        // explicit hash we asked for.)
        node.register_destination(dest);

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
        // CIRISEdge#371 — the named dest already carries its RNS-derived hash, so
        // `register_destination` (native) registers it at `local_named_dest_hash`.
        node.register_destination(named_dest);

        // CIRISEdge#489 — INSTALL the announce-suppression policy onto the node.
        // Until this call `ScopePrivacyAnnouncePolicy` was dead code:
        // `set_announce_control` was never invoked anywhere in `src/`, so
        // leviculum's own local-destination auto-announce loops (the periodic
        // management re-announce + the local re-gossip pass) gossiped every
        // local destination unconditionally — a group-scoped destination could
        // be announced in breach of CC 5.4 (§5.4: group-scoped destinations
        // MUST NOT announce). The policy default-SUPPRESSES every UNregistered
        // destination, so the ONE destination that must keep auto-announcing —
        // this node's NAMED discovery address, the Commons-scoped public mesh
        // address peers resolve us by — is registered `Public` here so its
        // auto-re-announce survives. The explicit-hash dest needs no
        // registration: leviculum skips explicit-hash announces structurally,
        // and default-suppress is the belt. Edge's own explicit interval
        // announce of the named dest (`announce_destination`, below) is a
        // SEPARATE path that does not consult the policy, so mesh discovery is
        // preserved on both the explicit and the auto paths; the policy only
        // adds suppression for scoped destinations (register future ones via
        // the retained `announce_policy` handle).
        let announce_policy = crate::announce_suppression::ScopePrivacyAnnouncePolicy::new();
        // The federation-visibility opt-in, and the only thing that decides
        // whether this node is on the mesh at all.
        //
        // `Public` is the one scope the policy lets announce, so registering
        // the named discovery destination as `Public` is what puts this node
        // in the mesh. Leaving it UNregistered is not an oversight — the
        // policy default-SUPPRESSES anything it does not know, so an invisible
        // node falls out of the same rule that keeps scoped destinations
        // silent, rather than needing a second mechanism to be quiet.
        //
        // A point-to-point node is still fully reachable by anyone who already
        // holds its address; what it does not do is advertise so strangers can
        // learn one.
        if config.federation_visible {
            announce_policy.register_destination_scope(
                local_named_dest_hash.into_bytes(),
                crate::cohort_scope::CohortScope::Public,
            );
            // #489 residual — same wiring-log discipline as the keepalive /
            // control-channel knobs above: one INFO line per node build so
            // "is this node announcing, and which destination" is answerable
            // from logs on BOTH branches (previously only the OFF branch
            // below spoke).
            tracing::info!(
                dest = %local_named_dest_hash,
                "federation visibility ON — named discovery destination \
                 registered Public with the announce-suppression policy; its \
                 auto re-announce survives default-suppression (CIRISEdge#489)"
            );
        } else {
            tracing::info!(
                "federation visibility OFF — this node announces nothing and is reachable \
                 point-to-point only. Scoped destinations were already one-hop (CC 5.4.6), \
                 so scope-native addressing costs this posture nothing."
            );
        }
        node.set_announce_control(Some(Box::new(announce_policy.clone())));

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

        // CIRISEdge#406 — bootstrap the hybrid-signed SignedTransportDestination
        // for edge's OWN (announced) destination: the producer for the #393
        // item-2 gate. The announce-compose path above holds every operand —
        // the NAMED dest peers will record, the 64-byte transport identity,
        // the attestation epoch, and the federation signer. Idempotent
        // (emit-only-on-change against the durable store) and fail-open: a
        // boot-time fault (directory not serving / own key not yet
        // registered / Ed25519-only signer) warns loudly and the periodic
        // announce tick re-arms it — transport construction never blocks.
        let self_route = crate::transport::self_route::SelfSignedRouteProducer::new();
        if let Some(rooting_dir) = rooting.as_deref() {
            let mut named16 = [0u8; 16];
            named16.copy_from_slice(local_named_dest_hash.as_bytes());
            let _outcome = self_route
                .ensure(
                    &local_signer,
                    rooting_dir,
                    named16,
                    local_transport_pubkey,
                    config.local_epoch,
                )
                .await;
        }

        Ok(Self {
            config,
            node: Arc::new(node),
            local_dest_hash,
            local_named_dest_hash,
            announce_policy,
            local_transport_pubkey,
            local_identity: identity.clone(),
            scope_addresses: OnceLock::new(),
            #[cfg(feature = "lxmf")]
            lxmf_serve: OnceLock::new(),
            local_attestation,
            local_signer,
            self_route,
            events: Mutex::new(Some(events)),
            peers: Arc::new(Mutex::new(HashMap::new())),
            established_links: Arc::new(Mutex::new(HashSet::new())),
            sent_resource_progress: Arc::new(Mutex::new(HashMap::new())),
            test_force_busy: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            resolver,
            rooting,
            hybrid_policy,
            transport_binding_enforcement,
            bundle_save_gate,
            peer_bundles: Arc::new(crate::bundle_gate::PeerBundleStore::new()),
            own_bundle,
            event_bus,
            reachability,
            interface_specs: Arc::new(std::sync::Mutex::new(interface_specs)),
            link_established_at: Arc::new(Mutex::new(HashMap::new())),
            link_to_peer_key_id: Arc::new(Mutex::new(HashMap::new())),
            link_last_inbound_at: Arc::new(Mutex::new(HashMap::new())),
            inbound_reasm: Arc::new(Mutex::new(
                crate::transport::frame_fragment::Reassembler::new(),
            )),
            dialed_link_dest: Arc::new(Mutex::new(HashMap::new())),
            blackhole: blackhole_rules,
            blackhole_cache: std::sync::Mutex::new((0, None)),
            binding_cache: std::sync::Mutex::new(HashMap::new()),
            started_at: std::time::Instant::now(),
            store_and_forward: None,
            delivery: crate::transport::PendingDelivery::LiveOnly,
        })
    }

    /// CIRISEdge#437 — register (or replace) a peer's presented
    /// build-attestation bundle for the durable-save gate. Shape-gated
    /// fail-closed at registration (size cap / JSON / `kind`); verification
    /// against the federation-directory pins happens lazily at the next
    /// Rooted durable save (and the verified outcome is cached against the
    /// exact bytes — refusals are never cached). The CIRISEdge#436 arrival
    /// transport (announce commitment + link-borne `CBND` package) feeds the
    /// same store; this PyO3 seam remains for server-side registration.
    ///
    /// # Errors
    ///
    /// A typed [`crate::bundle_gate::BundleRegisterError`] naming the first
    /// failing shape check (oversized / not JSON / wrong kind / store full).
    pub fn register_peer_build_bundle(
        &self,
        key_id: &str,
        bundle_bytes: &[u8],
    ) -> Result<(), crate::bundle_gate::BundleRegisterError> {
        self.peer_bundles.register(key_id, bundle_bytes)
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

    /// CIRISEdge#492 — three-phase IFAC membership-key rotation, flag-day-free.
    /// Edge owns the orchestration CADENCE; leviculum owns the MECHANISM, and
    /// the passphrase distribution BETWEEN phases is the persist `key_grant`
    /// handoff (CIRISPersist#704). Phase 1 — `install_next`: the node accepts
    /// BOTH the current code and the next (make-before-break); no member is
    /// excluded yet. Returns the number of interfaces updated.
    pub fn ifac_install_next(
        &self,
        netname: Option<&str>,
        passphrase: &str,
        ifac_size: usize,
    ) -> Result<usize, TransportError> {
        self.node
            .ifac_install_next(netname, passphrase, ifac_size)
            .map_err(|e| TransportError::Io(format!("ifac_install_next: {e}")))
    }

    /// CIRISEdge#492 — phase 2: swap the next IFAC code to PRIMARY. Outbound now
    /// frames under the new code; a straggler still holding only the old code
    /// continues to LAND (both are accepted). Call after the new passphrase has
    /// been distributed to members. Returns the number of interfaces affected.
    #[must_use]
    pub fn ifac_activate_next(&self) -> usize {
        self.node.ifac_activate_next()
    }

    /// CIRISEdge#492 — phase 3: SEAL the rotation — drop the old IFAC code. Any
    /// member that never re-keyed is now excluded (readmission requires a fresh
    /// grant + re-key). Call after the convergence window. Returns the number of
    /// interfaces affected.
    #[must_use]
    pub fn ifac_seal_rotation(&self) -> usize {
        self.node.ifac_seal_rotation()
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

    /// CIRISEdge#489 — register (or update) the cohort scope of a destination
    /// with the installed announce-suppression policy. The node's own
    /// auto-announce loops (management re-announce + local re-gossip) consult
    /// this on their very next pass: a group-scoped destination
    /// (`SelfOnly` / `Family` / `Cohort`) is thereafter SUPPRESSED (CC 5.4 —
    /// group-scoped destinations must not announce), a `Public` (Commons)
    /// destination stays announceable. Idempotent; re-registration overwrites
    /// the prior scope. This is the "register as edge admits each scoped
    /// destination" half of the policy contract — the node's own named
    /// discovery address is registered `Public` at construction; any scoped
    /// destination edge later registers with the node MUST also be scoped here
    /// (a missing registration default-suppresses, which is safer-than-leak).
    pub fn register_announce_scope(
        &self,
        dest_hash: [u8; 16],
        scope: crate::cohort_scope::CohortScope,
    ) {
        self.announce_policy
            .register_destination_scope(dest_hash, scope);
    }

    /// CIRISEdge#499 — install the scope-native address table. Called ONCE,
    /// by whichever layer owns the MLS group secrets, as soon as the first
    /// group is joined. Returns `Err` if a table is already installed rather
    /// than silently displacing it: two tables would mean two disagreeing
    /// answers to "is this inbound hash mine", and the loser's registered
    /// destinations would still be live on the node.
    ///
    /// # Errors
    /// [`TransportError::Config`] if a table was already installed.
    pub fn install_scope_address_table(
        &self,
        table: Arc<ScopeAddressTable>,
    ) -> Result<(), TransportError> {
        self.scope_addresses
            .set(table)
            .map_err(|_| TransportError::Config("scope address table already installed".to_owned()))
    }

    /// CIRISEdge#169 — install the LXMF propagation serve node and register
    /// its request handler, so this node begins carrying third-party mail.
    ///
    /// Called ONCE. Two things happen together on purpose: without the
    /// registration no `RequestReceived` ever arrives, and without the node
    /// the arm declines every one — so installing one without the other is a
    /// node that either cannot hear or cannot answer, and both look like
    /// silence from outside.
    ///
    /// The roster inside the node decides WHO is served
    /// ([`PropagationAudience::from_cohort_membership`] — self, family, and
    /// the communities this node is in; deliberately NOT the RNS transit
    /// rule). This verb decides only THAT the node serves.
    ///
    /// # Errors
    /// [`TransportError::Config`] if a serve node is already installed.
    ///
    /// [`PropagationAudience::from_cohort_membership`]:
    ///     crate::transport::lxmf_serve::PropagationAudience::from_cohort_membership
    #[cfg(feature = "lxmf")]
    pub fn install_lxmf_serve(
        &self,
        serve: Arc<crate::transport::lxmf_serve::LxmfServeNode>,
    ) -> Result<(), TransportError> {
        self.lxmf_serve
            .set(serve)
            .map_err(|_| TransportError::Config("LXMF serve node already installed".to_owned()))?;
        // Register on the node's NAMED discovery destination — the one a
        // client can actually reach. An explicit-hash destination cannot be
        // path-resolved (CC 5.4.6 / CIRISConstitution#91), so a propagation
        // node has to be reachable on the plane that announces.
        self.node.register_request_handler(
            DestinationHash::new(self.local_named_dest_hash()),
            crate::transport::lxmf_serve::MESSAGE_GET_PATH,
            leviculum_core::RequestPolicy::AllowAll,
        );
        tracing::info!(
            path = crate::transport::lxmf_serve::MESSAGE_GET_PATH,
            "CIRISEdge#169 — LXMF propagation serve path REGISTERED. This node now \
             carries mail for the destinations in its roster."
        );
        Ok(())
    }

    /// CIRISEdge#499 — the installed scope-address table, if any.
    ///
    /// This is the accessor the **replication layer** uses to resolve a
    /// scoped address *above* the transport. Per the #499 design fork,
    /// `Transport::send` deliberately grows no scope parameter and the
    /// transport deliberately does not parse scope on the send path: the
    /// caller already computed `projection_for` for the record, so it
    /// already holds the scope, and it hands `send` an address that cannot
    /// be wrong (the [`ResolvedRecipient`] pattern from CIRISEdge#402).
    ///
    /// [`ResolvedRecipient`]: crate::replication::resolved_state::ResolvedRecipient
    #[must_use]
    pub fn scope_address_table(&self) -> Option<&Arc<ScopeAddressTable>> {
        self.scope_addresses.get()
    }

    /// CIRISEdge#499 — listen on a scope-derived destination.
    ///
    /// The address is a [`MemberAddress`], which has no public byte
    /// constructor: the only way to hold one is to have obtained it from a
    /// [`ScopeAddressTable`], which derives it from an MLS `exporter_secret`.
    /// So "this hash was derived from a group secret I possess" is a property
    /// of the *type*, not something this function has to re-check.
    ///
    /// Registration is COLD — once per (group, epoch, member), never per
    /// packet. It does two things that must not drift apart: registers the
    /// explicit-hash destination with the node, and registers its scope with
    /// the announce-suppression policy so the node's auto-announce loops
    /// suppress it (CC 5.4 — group-scoped destinations MUST NOT announce).
    ///
    /// `Public` is refused. A derived per-member address is not a discovery
    /// address; announcing one would publish the very reachability fact the
    /// derivation exists to withhold (CIRISEdge#311 limb (b)), and it would
    /// not even work — leviculum v0.19 answers path requests for
    /// explicit-hash destinations with silence, because a path response *is*
    /// an announce and an announce for a caller-supplied hash is
    /// unverifiable by reference RNS. First contact happens at federation
    /// scope; scoped addresses are derived thereafter.
    ///
    /// # Errors
    /// [`TransportError::Config`] if `scope` is `Public`, or if the
    /// destination cannot be built.
    pub fn register_scoped_destination(
        &self,
        address: &MemberAddress,
        scope: &crate::cohort_scope::CohortScope,
    ) -> Result<(), TransportError> {
        if matches!(scope, crate::cohort_scope::CohortScope::Public) {
            return Err(TransportError::Config(
                "refusing to register a scope-derived destination as Public: \
                 a derived per-member address is not a discovery address"
                    .to_owned(),
            ));
        }
        let hash = *address.as_bytes();
        let mut dest = Destination::with_explicit_hash(
            Some(self.local_identity.clone()),
            Direction::In,
            DestinationType::Single,
            EDGE_APP_NAME,
            &[EDGE_APP_ASPECT],
            hash,
        )
        .map_err(|e| TransportError::Config(format!("scoped destination build: {e}")))?;
        dest.set_accepts_links(true);
        debug_assert_eq!(
            dest.hash().as_bytes(),
            &hash,
            "explicit-hash destination must index by the derived address",
        );
        // Scope FIRST, then register. The policy default-SUPPRESSES an
        // unregistered destination, so this order has no window in which the
        // node holds an announceable destination it has no scope for; the
        // reverse order does.
        self.register_announce_scope(hash, scope.clone());
        self.node.register_destination(dest);
        Ok(())
    }

    /// CIRISEdge#499 — retire a scope-derived destination.
    ///
    /// The inverse of [`Self::register_scoped_destination`], and the
    /// second half of the rotation: after this returns the hash is no
    /// longer one of ours, so a peer that still holds a path and dials
    /// it finds nobody home. Without it a superseded address keeps
    /// answering forever, which re-confirms this node to anyone still
    /// probing it — the reachability disclosure CIRISEdge#311 exists to
    /// prevent, and the reason a rotation that cannot retire only ever
    /// *adds* addresses.
    ///
    /// Landed in leviculum v0.20.0+ciris.1 (leviculum#54). Two contract
    /// points edge relies on, both pinned by leviculum's own
    /// `destination_lifecycle.rs` rather than inferred here:
    ///
    /// - **Idempotent** — retiring an already-gone or never-registered
    ///   hash is a no-op. That is what lets the seal be timing-driven
    ///   ([`crate::scope_lifecycle::ScopeLifecycle::seal_due`] may fire
    ///   twice for one rotation).
    /// - **Established links keep running** — a link is keyed by its
    ///   `LinkId`, not by the destination it was dialled through, so
    ///   only NEW link requests are refused.
    ///
    /// That second point is the behaviour edge wants, and edge
    /// deliberately does NOT follow it with a `close_link` sweep.
    /// A peer holding an established link dialled it while legitimately
    /// in the group; tearing it down would drop a live stream, which is
    /// exactly what the make-before-break rotation window exists to
    /// prevent (a `DestinationHash` is used to dial and listen, never
    /// per chunk). The unlinkability concern is about *new* probes, and
    /// those are what retirement stops. Cutting live links is available
    /// (`close_link` by `LinkId`) and is a separate, deliberate act.
    ///
    /// # Errors
    /// [`TransportError::Config`] never, currently — retained in the
    /// signature because the sink contract
    /// ([`crate::scope_lifecycle::ScopedDestinationSink::retire`]) is
    /// fallible and a future transport may not be able to retire.
    pub fn retire_scoped_destination(
        &self,
        address: &MemberAddress,
        _scope: &crate::cohort_scope::CohortScope,
    ) -> Result<(), TransportError> {
        let hash = *address.as_bytes();
        self.node
            .unregister_destination(&DestinationHash::new(hash));
        // Drop the scope record too, so the policy map does not grow one
        // entry per epoch per group for addresses that are no longer ours.
        self.announce_policy.forget(&hash);
        Ok(())
    }

    /// CIRISEdge#499 — send a byte-exact signed envelope to a peer at its
    /// SCOPE-DERIVED address rather than its federation address.
    ///
    /// This is the send half of scope-native addressing, and its whole design
    /// is in the signature. `Transport::send` deliberately grows no scope
    /// parameter — it has 10 implementors, including HTTP and packet radio,
    /// neither of which has a scope-derived destination plane — and this method
    /// deliberately parses no scope. It takes a [`MemberAddress`], which has no
    /// public byte constructor: the ONLY way a caller holds one is to have
    /// obtained it from a [`ScopeAddressTable`] lookup keyed by a
    /// `member_key_id`. So "this address is the right one for this content's
    /// scope" is a property the caller already proved, above the transport,
    /// and hands down as a value that cannot be wrong — the `ResolvedRecipient`
    /// pattern (CIRISEdge#396/#402), applied to addressing.
    ///
    /// `destination_key_id` is still required, and is NOT the routing input: it
    /// is the peer's federation key id, used only to resolve the transport-tier
    /// Ed25519 the link proof is verified against. The dial target is the
    /// derived address, exclusively — there is no arm of this method that falls
    /// back to a federation candidate, because a silent fallback is precisely
    /// the context collapse the derivation exists to remove.
    ///
    /// # Routability (the open upstream question)
    ///
    /// A scope-derived destination is registered with
    /// [`Self::register_scoped_destination`], which builds an EXPLICIT-HASH
    /// destination and suppresses its announce (CC 5.4 — group-scoped
    /// destinations MUST NOT announce; announcing one would publish the very
    /// reachability fact the derivation withholds). Reference RNS therefore
    /// holds no learned path to it, and leviculum v0.19 answers path requests
    /// for explicit-hash destinations with silence. So this dial is
    /// BROADCAST-ONLY: it reaches a directly-attached neighbour and no further,
    /// exactly like a v7 explicit-hash peer before `prime_peer`.
    ///
    /// **This is a RULED posture, not a gap to fix.** CIRISConstitution#91
    /// asked whether CC 5.4.6's announce prohibition binds the *packet* or the
    /// *leak*, and CC 1.0-rc4 ruled: **the packet, stated as the emission**. A
    /// directed announce iterated over the roster inherits the prohibition
    /// rather than escaping it — the clause binds the emission, not the
    /// addressing mode. Three legs, now in-clause at 5.4.6:
    ///
    /// - No directed announce on RNS transport can satisfy the purposive
    ///   gloss, because multi-hop path learning IS outsider observation, and
    ///   the path state intermediates retain is exactly the class the subpoena
    ///   framing promises does not exist.
    /// - The flat `MUST NOT` was never broadcast-era shorthand: the same
    ///   section bans the targeted, non-broadcast per-destination query in the
    ///   same breath, so the emission class was always the object.
    /// - A directed announce would trade *no emission exists* — structural and
    ///   honestly claimable — for *emissions exist but resist analysis*, which
    ///   is traffic-analysis privacy, precisely the claim CEG/RET declines to
    ///   make outside the Anonymous Tier (CC 1.13.3.1). **A reading must not
    ///   spend a claimable guarantee to purchase an unclaimable one.**
    ///
    /// The ruling also names a bind edge's own filing missed: the derivation
    /// is EPOCH-BOUND, so an announcing scheme must either re-announce
    /// roster-wide on every Add/Remove — a synchronized wave whose cardinality,
    /// timing and churn are themselves the leak — or never rotate, which leaves
    /// a removed member holding every peer's addressing forever.
    ///
    /// So a multi-hop scoped fetch fails at the establish timeout with
    /// [`TransportError::NoRouteToPeer`] — loudly, and without ever having put
    /// the scoped bytes on the federation address. **Do not "fix" this by
    /// announcing.** Multi-hop scoped reach remains open on the amendment
    /// plane with its bar stated: no outsider-observable emission, no
    /// outsider-retained path state, no epoch-correlated wave.
    ///
    /// What the ruling DID keep is that in-group MLS distribution of addressing
    /// material was never prohibited — the cached-directory discipline — so a
    /// roster learning its own members' addresses over MLS stays open.
    ///
    /// # Why one hop is not fatal to a mesh call
    ///
    /// CC 1.0-rc4's Position paragraph at 5.4.6 names the reason, and it holds
    /// in this implementation: **derivation replaces discovery, and determinism
    /// replaces coordination.** Every member can derive every other member's
    /// address from the group secret without asking anyone, so the candidate
    /// set is complete without a discovery round — which is what recovers the
    /// ⌈log_k N⌉ ALM fan-out (CC 6.1.6) that a one-hop-only reading looks like
    /// it should destroy.
    ///
    /// Concretely: [`AlmJoinPlanner::plan`] takes a caller-supplied candidate
    /// set under staleness and reachability filters. It plans over advertised
    /// candidates and established links, never over an assumption that every
    /// member is dialable. So the one-hop property constrains FIRST CONTACT —
    /// which happens on the federation plane, where announces are permitted —
    /// and not the shape of the tree built afterwards.
    ///
    /// [`AlmJoinPlanner::plan`]: crate::transport::realtime_av_alm::AlmJoinPlanner::plan
    ///
    /// # Errors
    /// [`TransportError::BodyTooLarge`] above the AV-13 ceiling;
    /// [`TransportError::Unreachable`] when the peer's transport identity
    /// cannot be resolved (no signing key ⇒ no link proof);
    /// [`TransportError::NoRouteToPeer`] / [`TransportError::Timeout`] when the
    /// derived destination does not establish; [`TransportError::Io`] on a
    /// leviculum fault.
    pub async fn send_to_scoped_destination(
        &self,
        destination_key_id: &str,
        address: &MemberAddress,
        envelope_bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError> {
        if envelope_bytes.len() > MAX_BODY_BYTES {
            return Err(TransportError::BodyTooLarge {
                actual: envelope_bytes.len(),
                limit: MAX_BODY_BYTES,
            });
        }

        let dest_hash = DestinationHash::new(*address.as_bytes());
        // Operator deny-list first, on the DERIVED hash — a ban must not be
        // bypassable by addressing the peer in one of its scopes.
        self.check_blackhole(&dest_hash.into_bytes()).await?;

        // The peer's transport-tier Ed25519, for the link proof. Any candidate
        // carries it (they differ in ROUTING hash, not in signing key), so take
        // the first. The candidate's own dest_hash is deliberately discarded:
        // routing here is the derived address, never a federation one.
        let Some(signing_key) = self
            .resolve_dial_candidates(destination_key_id)
            .await
            .first()
            .map(|c| c.signing_key)
        else {
            return Err(TransportError::Unreachable(format!(
                "scope-native send: no transport identity resolved for \
                 destination_key_id={destination_key_id} — cannot prove a link to its \
                 derived address (CIRISEdge#499)"
            )));
        };

        let (link, established) = self
            .node
            .connect_awaited(&dest_hash, &signing_key)
            .await
            .map_err(|e| TransportError::Io(format!("reticulum connect (scoped): {e}")))?;
        let link_id = *link.link_id();
        // CIRISEdge#424 — record the dest we dialed so a reply arriving on this
        // link attributes to this peer (leviculum's `link_destination` is `None`
        // for our own dialed links).
        self.dialed_link_dest
            .lock()
            .await
            .insert(link_id, dest_hash);

        // Explicit-hash destinations are never pathed (see the routability note
        // above), so this is always the bootstrap-broadcast budget.
        if !matches!(
            with_timeout(NO_PATH_ESTABLISH_TIMEOUT, established).await,
            Some(Ok(()))
        ) {
            tracing::error!(
                key_id = %destination_key_id,
                target_dest = %hex::encode(dest_hash.into_bytes()),
                "scope-native send: derived destination did not establish. A derived \
                 address is announce-suppressed by design (CC 5.4), so it is \
                 broadcast-only — only a directly-attached neighbour answers. Making a \
                 scoped address relay-routable without re-publishing the reachability \
                 fact is unspecified upstream (CIRISEdge#499). NOT retried on the \
                 federation address: that would collapse the very context this \
                 address exists to separate."
            );
            return Err(TransportError::NoRouteToPeer {
                key_id: destination_key_id.to_string(),
                target_dest: hex::encode(dest_hash.into_bytes()),
                has_path: false,
                paths: self.path_table_snapshot(),
            });
        }

        // CIRISEdge#340 — IDENTIFY before shipping, so the responder can
        // attribute the frame. Same ordering as the federation send path.
        self.node
            .identify_link(&link_id, &self.local_identity)
            .await
            .map_err(|e| TransportError::Io(format!("reticulum identify_link (scoped): {e}")))?;

        self.ship_resource_on_link(
            &link_id,
            envelope_bytes,
            DIAL_NO_PROGRESS_WINDOW,
            RESOURCE_TRANSFER_TIMEOUT,
        )
        .await
        .map_err(ShipError::into_transport)?;

        Ok(TransportSendOutcome::Delivered)
    }

    /// CIRISEdge#499 — resolve an inbound destination hash to the scope
    /// group, member and epoch it was derived for, or `None` if it is not one
    /// of ours.
    ///
    /// A `Some` here is a **cryptographic admission fact**, not a hint:
    /// the hash is derived from an MLS `exporter_secret`, which binds
    /// `(group_id, epoch)` per RFC 9420 §8.5, so arrival on it proves the
    /// sender possessed that group secret. This is why scope-native
    /// addressing makes the hottest path (`attribute_and_deliver`) *cheaper*
    /// rather than dearer — admission moves ahead of the parse.
    ///
    /// Returns `None` when no table is installed. The derivation itself
    /// SHIPPED (CIRISVerify#259 → verify's scope-privacy derivation,
    /// adapted by `crate::scope_addressing::ScopePrivacyDeriver`); the
    /// table stays empty until the operator opts in via
    /// `EdgeBuilder::scope_native_addressing`, which installs it.
    #[must_use]
    pub fn inbound_scope(&self, dest_hash: &[u8; 16]) -> Option<InboundAddress> {
        self.scope_addresses.get()?.accepts_inbound(dest_hash)
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
                // #393 — an operator-primed binding asserts key ownership (the
                // operator baked it, e.g. the canonical), so it is attributable.
                owns_key: true,
                // #436 — only the ed25519 half is known here; the zero x25519
                // half mirrors the zero identity-hash sentinel above.
                transport_pubkey64: {
                    let mut pk = [0u8; 64];
                    pk[32..].copy_from_slice(&signing_key_ed25519);
                    pk
                },
                manifest_commitment: None,
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
                // #393 — full-identity test injector simulates an announce-rooted
                // owning peer (the precondition #340 attribution needs).
                owns_key: true,
                transport_pubkey64,
                manifest_commitment: None,
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

    /// ALM-A(cap) passive capacity-estimator seam (leviculum#35,
    /// `docs/AV_ALM_DESIGN.md` §5.1). Snapshot every active link's
    /// cumulative delivery telemetry via leviculum v0.12.0's
    /// [`ReticulumNode::link_stats`] and hand it to the estimator's pure
    /// core as [`LinkCounters`]. This is the ENTIRE impure/leviculum-reading
    /// surface — the sampler differences these against the previous snapshot
    /// ([`capacity_estimator::diff_link`]), aggregates
    /// ([`capacity_estimator::aggregate`]), and feeds
    /// [`CapacityEstimator::observe`]; a ~1 Hz caller re-signs only on a
    /// returned bucket crossing.
    ///
    /// Read-only, one `link_stats` call per active link, zero added wire
    /// bytes, no new task — the design's "one stat read per link per second,
    /// no battery hit".
    #[must_use]
    pub async fn capacity_link_counters(
        &self,
    ) -> Vec<(
        LinkId,
        crate::transport::realtime_av_alm::capacity_estimator::LinkCounters,
    )> {
        use crate::transport::realtime_av_alm::capacity_estimator::LinkCounters;
        let established = self.established_links.lock().await;
        let mut out = Vec::with_capacity(established.len());
        for link_id in established.iter() {
            if let Some(stats) = self.node.link_stats(link_id) {
                out.push((*link_id, LinkCounters::from(&stats)));
            }
        }
        out
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
        // CIRISEdge#484 — leviculum v0.16 `connect_awaited` registers the
        // establishment waiter BEFORE dispatch (the `LinkEstablished` proof can never
        // precede registration), keyed on the ORIGINAL dial id — which is exactly the
        // #342/#66 alias the old 50 ms `link_is_established` poll resolved (a re-key on
        // a lossy path). The future takes NO node lock and resolves `Err(LinkClosed)`
        // if the link dies first, so it never hangs; the caller owns the timeout.
        let (link, established) = self
            .node
            .connect_awaited(&dest_hash, &signing_key)
            .await
            .map_err(|e| TransportError::Io(format!("reticulum connect: {e}")))?;
        let link_id = *link.link_id();
        // CIRISEdge#424 — record the dialed dest for own-dialed-link attribution
        // (see `send`); uniform across every link edge initiates.
        self.dialed_link_dest
            .lock()
            .await
            .insert(link_id, dest_hash);

        // Runtime-agnostic bound (CIRISEdge#217): `established` resolves `Ok(())` on
        // establishment / `Err(LinkClosed)` on link death; anything else — or the
        // timeout — is a failed dial.
        if !matches!(with_timeout(timeout, established).await, Some(Ok(()))) {
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
        // CIRISEdge#436 — initiator-side bundle serve, ordered AFTER the
        // LINKIDENTIFY so the responder can attribute the frame.
        if let Some(own) = self.own_bundle.as_ref() {
            push_own_bundle_frames(&self.node, own, &link_id).await;
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

        // CIRISEdge#484 — the sender-side resource drain is now redundant: every
        // resource send (`ship_resource_on_link`) AWAITS its own completion future
        // before returning (leviculum v0.16), so no send is in flight by the time a
        // caller reaches teardown. The `sent_resources` mirror is deleted with it.

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
        // CIRISEdge#484 — leviculum v0.16 completion future replaces the 20 ms
        // `request_responses`/`timed_out_requests` poll loop (both mirror maps + their
        // `handle_event` populate arms are now deleted). The waiter is registered
        // BEFORE dispatch (the response can never precede registration), takes NO node
        // lock, and resolves `Err(RequestTimedOut)` on the in-protocol timeout or
        // `Err(LinkClosed)` if the link dies first — it never hangs on a dead link.
        let (_request_id, response) = self
            .node
            .send_request_awaited(&link_id, path, Some(data), Some(timeout_ms))
            .await
            .map_err(|e| TransportError::Io(format!("reticulum send_request: {e}")))?;
        // The future self-bounds via the in-protocol `timeout_ms` (resolves
        // `RequestTimedOut`) and via `LinkClosed` on link death, so it ALWAYS
        // resolves — no outer timer is added (CIRISEdge#217: these send/request paths
        // can be awaited on a thread whose tokio-locals belong to persist's runtime,
        // where `tokio::time::*` panics "no reactor running"; the completion future is
        // Timer-free).
        match response.await {
            Ok(info) => Ok(info.response_data),
            Err(CompletionError::RequestTimedOut) => Err(TransportError::Timeout(timeout)),
            Err(CompletionError::LinkClosed { reason }) => Err(TransportError::Io(format!(
                "reticulum request: link closed before response ({reason:?})"
            ))),
            Err(e) => Err(TransportError::Io(format!("reticulum request: {e}"))),
        }
    }

    // ─── CIRISEdge#33 (v0.15.0) Routing-table FFI surface ───────────
    //
    // Paths / blackhole / rate / tunnels / announce / reverse. v1.1.0
    // (CIRISEdge#44) flips on the 5 Leviculum accessors that the fork
    // now exposes publicly (`leviculum_std::driver::ReticulumNode::
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
            .map_err(|e| TransportError::Io(format!("blackhole_upsert: {e}")))?;
        self.invalidate_blackhole_cache();
        Ok(())
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
            .map_err(|e| TransportError::Io(format!("blackhole_remove: {e}")))?;
        self.invalidate_blackhole_cache();
        Ok(())
    }

    /// #482 item 5 — drop the cached deny-list snapshot so a LOCAL rule
    /// mutation (`add`/`remove`) is visible to the very next dial instead
    /// of waiting out [`BLACKHOLE_CACHE_TTL`]. The TTL then only bounds
    /// staleness against rules written by OTHER processes sharing the
    /// persist-backed `cirislens.blackhole_rules` table (which this
    /// process cannot observe without a read).
    fn invalidate_blackhole_cache(&self) {
        let mut guard = self
            .blackhole_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Bump the generation so any dial with an in-flight `blackhole_list()`
        // read (snapshotted the OLD generation before its `.await`) declines to
        // commit its now-stale snapshot, and drop the current snapshot.
        guard.0 = guard.0.wrapping_add(1);
        guard.1 = None;
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
        // #482 item 5 — serve the full deny-list from a short-TTL snapshot
        // so a dial FLOOD collapses to one `blackhole_list()` round-trip per
        // window instead of one per dial. v0.16.1 cohabitation deployments
        // have operator-curated deny-lists in the low-dozens range, so the
        // snapshot is cheap to hold. The `std::sync::Mutex` guard is dropped
        // before the `.await` refresh (never held across it) — keeping this
        // #217-safe on a send-path that can run on persist's runtime thread.
        // A future cut can pivot to a single-row lookup primitive if persist
        // exposes one (the trait surface today is `blackhole_list` only —
        // see #120 docblock for the rationale of batched-flush).
        let (cached, gen_at_miss) = {
            let guard = self
                .blackhole_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let cached = match guard.1.as_ref() {
                Some((fetched_at, rows)) if fetched_at.elapsed() < BLACKHOLE_CACHE_TTL => {
                    Some(Arc::clone(rows))
                }
                _ => None,
            };
            // Snapshot the generation WITH the miss check so a concurrent
            // invalidation during the `.await` below is detected at commit.
            (cached, guard.0)
        };
        let rows = if let Some(rows) = cached {
            rows
        } else {
            let fetched = store
                .blackhole_list()
                .await
                .map_err(|e| TransportError::Io(format!("blackhole_list (check): {e}")))?;
            let rows = Arc::new(fetched);
            // Commit the fresh snapshot ONLY if no invalidation raced our read
            // (generation unchanged since the miss). If a LOCAL add/remove bumped
            // the generation during our `.await`, drop this now-stale snapshot and
            // let the next dial re-read — so the explicit invalidation is never
            // clobbered by a pre-mutation snapshot re-armed with a fresh timestamp
            // (CIRISEdge#482 review finding). Two concurrent stale-misses WITHOUT
            // an interleaved mutation still race benignly (identical data).
            {
                let mut guard = self
                    .blackhole_cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if guard.0 == gen_at_miss {
                    guard.1 = Some((std::time::Instant::now(), Arc::clone(&rows)));
                }
            }
            rows
        };
        let now = chrono::Utc::now();
        match consult_and_prune_blackhole(store, &rows, identity_hash, now).await {
            BlackholeConsult::Clear => Ok(()),
            BlackholeConsult::ExpiredPruned => {
                // The consulted row was reclaimed — drop the snapshot so
                // the next dial re-reads a deny-list without it (and does
                // not re-attempt the remove).
                self.invalidate_blackhole_cache();
                Ok(())
            }
            BlackholeConsult::Blocked { reason, until } => {
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
                Err(TransportError::PeerBlackholed {
                    identity_hash: identity_hash.to_vec(),
                    reason,
                    until: until.map(|t| t.to_rfc3339()),
                })
            }
        }
    }

    /// Resolve a `destination_key_id` to a Reticulum peer. Consults
    /// the **rooted** announce map first (every entry has cleared the
    /// CIRISEdge#15 cold-start path), then the out-of-band injected
    /// [`PeerResolver`]. Returns `None` if neither yields the peer.
    /// CIRISEdge#336 (v13.8.0, holistic) — every destination this peer could
    /// legitimately own, so the DIAL layer can pick by ROUTABILITY instead of
    /// identity-math preference. Pre-v13.8.0 this fn's ancestor synthesized ONE
    /// winner (cache, else explicit-hash, else legacy formula) with no check
    /// that anyone ever announced — or even owns — the synthesized hash; the
    /// route table was consulted only to pick a timeout. Field failure: the
    /// mobile dialed a pathless dest ×24 while the SAME peer's routable dest
    /// sat in the path table with a direct 1-hop route. Candidates:
    ///
    ///  - `Cached` — the announce-bound / `prime_peer`'d dest on the rooted
    ///    entry (carries reachability provenance: it was announced or the
    ///    operator primed it), with the announce-verified signing key.
    ///  - `ExplicitHash` — `sha256(fed_pubkey)[..16]` (#191 byte-equal
    ///    federation addressing). Un-announceable by RNS design → broadcast-
    ///    only: legitimate as bootstrap direct-dial, never routable via relays.
    ///  - `ComputedNamed` — the legacy `sha256(name_hash‖identity_hash)`
    ///    formula from the resolver's transport keys.
    ///
    /// Each candidate carries ITS OWN signing key (the identity from the same
    /// provenance as the dest — a stale cache must not lend its key to a
    /// freshly-computed dest, or the link proof fails confusingly).
    /// Deduped by dest hash, first source wins. Empty ⇒ the peer is unrooted
    /// and unresolvable (caller's existing store-and-forward / WARN branch).
    async fn resolve_dial_candidates(&self, destination_key_id: &str) -> Vec<DialCandidate> {
        let mut out: Vec<DialCandidate> = Vec::with_capacity(3);
        if let Some(rooted) = self.peers.lock().await.get(destination_key_id) {
            out.push(DialCandidate {
                dest_hash: rooted.peer.dest_hash,
                signing_key: rooted.peer.signing_key,
                source: DialSource::Cached,
            });
        }
        if let Some(resolver) = self.resolver.as_ref() {
            if let Some(pubkey) = resolver.resolve(destination_key_id) {
                let mut x25519 = [0u8; 32];
                let mut ed25519 = [0u8; 32];
                x25519.copy_from_slice(&pubkey[..32]);
                ed25519.copy_from_slice(&pubkey[32..]);

                // v7.0.0 (CIRISEdge#191 / #195) — explicit-hash addressing:
                // `sha256(fed_pubkey)[..16]`, the SAME hash the packet-radio /
                // HTTP transports derive. The transport-tier Ed25519 still
                // signs link proofs; only the routing index is content-
                // addressed by the federation key.
                if let Some(fed_pubkey) = resolver.resolve_federation_pubkey(destination_key_id) {
                    out.push(DialCandidate {
                        dest_hash: DestinationHash::new(
                            crate::transport::addressing::reticulum_destination_for_pubkey(
                                &fed_pubkey,
                            ),
                        ),
                        signing_key: ed25519,
                        source: DialSource::ExplicitHash,
                    });
                }
                // Legacy v0.6.x formula — pre-v13.8.0 this was computed only
                // when the resolver did NOT know the federation pubkey; now it
                // is always a candidate, because it is the ANNOUNCEABLE (hence
                // relay-routable) address shape and may be the only one the
                // route table holds a path for (the #336 field case).
                if let Ok(identity) = Identity::from_public_keys(&x25519, &ed25519) {
                    let name_hash =
                        Destination::compute_name_hash(EDGE_APP_NAME, &[EDGE_APP_ASPECT]);
                    out.push(DialCandidate {
                        dest_hash: Destination::compute_destination_hash(
                            &name_hash,
                            identity.hash(),
                        ),
                        signing_key: ed25519,
                        source: DialSource::ComputedNamed,
                    });
                }
            }
        }
        // Dedup by dest hash — e.g. the cached dest IS the explicit-hash for a
        // prime_peer'd target. First (highest-provenance) source wins.
        let mut seen: Vec<DestinationHash> = Vec::with_capacity(out.len());
        out.retain(|c| {
            if seen.contains(&c.dest_hash) {
                false
            } else {
                seen.push(c.dest_hash);
                true
            }
        });
        out
    }

    /// Single-winner resolution, preserved for the non-dial callers
    /// (`knows_peer` / dest readback). Legacy preference order: cached, else
    /// explicit-hash, else computed-named — byte-identical to the pre-v13.8.0
    /// behavior. The DIAL path does NOT use this — it selects by routability
    /// over [`Self::resolve_dial_candidates`].
    async fn resolve_peer(&self, destination_key_id: &str) -> Option<ResolvedPeer> {
        let candidates = self.resolve_dial_candidates(destination_key_id).await;
        for source in [
            DialSource::Cached,
            DialSource::ExplicitHash,
            DialSource::ComputedNamed,
        ] {
            if let Some(c) = candidates.iter().find(|c| c.source == source) {
                return Some(ResolvedPeer {
                    dest_hash: c.dest_hash,
                    signing_key: c.signing_key,
                });
            }
        }
        None
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
        let last_inbound = self.link_last_inbound_at.lock().await;
        let established_at = self.link_established_at.lock().await;
        // CIRISEdge#353 — build the (link, last_inbound, established_at) tuples
        // for the peer's links leviculum still holds `Active`, then let the pure
        // selector choose. `link_is_established` is a NECESSARY liveness gate but
        // NOT sufficient (a NAT-dead link stays `Active` for the whole stale
        // window), so the selector additionally prefers the freshest INBOUND —
        // the link the peer is demonstrably sending on right now.
        let live: Vec<(LinkId, u64, u64)> = candidates
            .into_iter()
            .filter(|id| self.node.link_is_established(id))
            .map(|id| {
                (
                    id,
                    last_inbound.get(&id).copied().unwrap_or(0),
                    established_at.get(&id).copied().unwrap_or(0),
                )
            })
            .collect();
        select_reply_link(&live)
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
    // CIRISEdge#414/#932 — grew past clippy's 100-line cap when the Busy arm's
    // single-packet interleave became the fragment-aware interleave (fragment the
    // oversized reply onto the packet path + the two loud fallback logs). The body
    // is one linear retry loop with a single match; extracting the Busy arm would
    // split the retry/deadline state across a helper for no readability gain.
    #[allow(clippy::too_many_lines)]
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
            match self
                .ship_resource_on_link(
                    &link_id,
                    envelope_bytes,
                    REVERSE_PATH_NO_PROGRESS_WINDOW,
                    REVERSE_PATH_MAX_TRANSFER,
                )
                .await
            {
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
                    // CIRISEdge#353 ask #2 (leviculum#27) — the link is
                    // mid-transfer, so a resource reply can't get on (and the
                    // field proved the 8 s retry window loses). A PACKET can:
                    // a link-Channel send interleaves an in-flight resource
                    // transfer (it goes through the link Channel, never the
                    // one-resource gate). Ship the reply as a packet if it fits
                    // the link MDU — the reverse path carries small control-plane
                    // replies (Summary/Diff, the Key + IdentityOccurrence planes)
                    // that do. This is the field-proven fix (reproduced
                    // deterministically in leviculum#27) for the busy-window
                    // contention. If the reply is too large or the channel itself
                    // is backpressured, fall through to the existing resource
                    // busy-retry / dial.
                    //
                    // CIRISEdge#371 — since leviculum v0.10.0 the fork-only
                    // `driver::send_on_link` wrapper is folded into upstream's
                    // `LinkHandle`; `link_handle(&id).try_send(..)` is the same
                    // core `send_on_link` (Channel / `RawBytesMessage`) and still
                    // returns `Busy` non-blocking, so the interleave semantics are
                    // unchanged. `try_send` (not `send`) keeps the one-shot
                    // behaviour — this call is already inside the busy-retry path.
                    //
                    // CIRISEdge#414 / CIRISAgent#932 — FRAGMENT the reply so it
                    // ALWAYS rides the packet path, not just when it fits the MDU.
                    // Before this, a frame larger than the link MDU (the observed
                    // ~19 KB Attestation Deliver, or a ~1 MiB inline-trace envelope)
                    // failed the `len() <= mdu` gate and fell to the resource path's
                    // one-per-link `Busy` gate — silently dropped on a NAT'd
                    // reverse-path-only peer, so the responder-driven round never
                    // converged. `fragment()` returns the frame in ONE unwrapped
                    // piece when it already fits (identical to the old fast path) and
                    // as N sub-MDU `CFRG` fragments otherwise; each fragment
                    // interleaves the busy resource transfer via the same
                    // non-contending link Channel, and the receiver reassembles in
                    // `attribute_and_deliver`. A best-effort lost fragment just means
                    // the frame re-fragments next round — the same whole-frame retry
                    // unit anti-entropy already relies on.
                    let mdu = self.node.link_mdu(&link_id).unwrap_or(0);
                    if let Some(fragments) =
                        crate::transport::frame_fragment::fragment(envelope_bytes, mdu)
                    {
                        let total = fragments.len();
                        let mut sent = 0usize;
                        for frag in &fragments {
                            if self.node.link_handle(&link_id).try_send(frag).await.is_ok() {
                                sent += 1;
                            } else {
                                break;
                            }
                        }
                        if sent == total {
                            tracing::debug!(
                                destination_key_id,
                                link = ?link_id,
                                attempts,
                                mdu,
                                bytes = envelope_bytes.len(),
                                fragments = total,
                                "delivered as {total} link PACKET(s), interleaving the busy \
                                 resource transfer (CIRISEdge#353 ask #2 / leviculum#27, \
                                 fragmented per CIRISEdge#414/#932)"
                            );
                            return true;
                        }
                        // Channel backpressured mid-send: some fragments landed but
                        // not all, so this frame will NOT reassemble this round.
                        // Loud (the #932 silent-drop class) — the round re-diffs and
                        // re-fragments, so this is recoverable, not fatal.
                        if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                            oversized_frame_drop_log().check(destination_key_id)
                        {
                            tracing::warn!(
                                destination_key_id,
                                link = ?link_id,
                                attempts,
                                mdu,
                                bytes = envelope_bytes.len(),
                                fragments = total,
                                fragments_sent = sent,
                                suppressed_prev,
                                "reverse-path link Channel backpressured mid-fragment-send \
                                 ({sent}/{total} landed); frame will re-fragment next round \
                                 (CIRISEdge#414/#932) — falling back to resource busy-retry"
                            );
                        }
                    } else {
                        // fragment() == None only for a degenerate MDU below
                        // MIN_FRAGMENTABLE_MDU — a pathologically tiny link. Loud, not
                        // silent (this is the #932 class).
                        if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                            oversized_frame_drop_log().check(destination_key_id)
                        {
                            tracing::warn!(
                                destination_key_id,
                                link = ?link_id,
                                attempts,
                                mdu,
                                bytes = envelope_bytes.len(),
                                suppressed_prev,
                                "reverse-path link MDU too small to fragment \
                                 (< MIN_FRAGMENTABLE_MDU); cannot use the packet path \
                                 (CIRISEdge#414/#932) — falling back to resource busy-retry"
                            );
                        }
                    }
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
                                "reverse-path link stayed BUSY and the reply did not fit a \
                                 link packet (too large / channel backpressured) through the \
                                 whole retry window; falling back to an outbound dial as LAST \
                                 resort (CIRISEdge#353)"
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
    #[allow(clippy::too_many_lines)] // the progress-aware wait loop (v13.6.1) is one cohesive unit
    async fn ship_resource_on_link(
        &self,
        link_id: &LinkId,
        envelope_bytes: &[u8],
        // CIRISEdge#353b/v13.6.1 — progress-aware wait budget. `no_progress_window`
        // fast-fails a transfer showing no progress (dead link); `max_transfer` is
        // the hard cap for a progressing transfer. Reverse path passes
        // (`REVERSE_PATH_NO_PROGRESS_WINDOW`, `REVERSE_PATH_MAX_TRANSFER`); the
        // outbound-dial path passes (`DIAL_NO_PROGRESS_WINDOW`, `RESOURCE_TRANSFER_TIMEOUT`).
        no_progress_window: Duration,
        max_transfer: Duration,
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
        let (resource_hash, sent) = self
            .node
            .send_resource_awaited(link_id, envelope_bytes, None, true)
            .await
            .map_err(|e| match e {
                leviculum_std::error::Error::Resource(
                    leviculum_core::resource::ResourceError::TransferInProgress,
                ) => ShipError::Busy,
                other => ShipError::Other(TransportError::Io(format!(
                    "reticulum send_resource: {other}"
                ))),
            })?;

        // CIRISEdge#484 + #353b/v13.6.1 — leviculum v0.16 completion future replaces
        // the 100 ms `sent_resources` completion-poll (and its `link_is_established`
        // liveness re-check): `sent` resolves `Ok` on the proven `ResourceCompleted`
        // and `Err(LinkClosed)` if the link dies mid-transfer, taking NO node lock.
        // The future carries NO progress signal, so the PROGRESS-AWARE #353b fast-fail
        // (extend WHILE parts flow, but bail once `no_progress_window` passes with the
        // link still alive) is preserved by a lean watchdog tick that reuses the
        // (unit-tested) `reverse_path_wait_step` for exactly its {Stalled, MaxDeadline}
        // arms; {Done, LinkStale} now come from the future. `sent_resource_progress`
        // stays (the watchdog reads it); `sent_resources` is deleted with Site 4.
        let start = std::time::Instant::now();
        tokio::pin!(sent);
        let mut poll = tokio::time::interval(Duration::from_millis(100));
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                result = &mut sent => {
                    self.sent_resource_progress.lock().await.remove(&resource_hash);
                    return match result {
                        Ok(_info) => Ok(()),
                        Err(CompletionError::LinkClosed { .. }) => {
                            tracing::warn!(
                                resource = %hex::encode(&resource_hash[..8]),
                                elapsed_secs = start.elapsed().as_secs(),
                                "reverse-path link CLOSED mid-transfer — the peer churned this link \
                                 before the resource completed (CIRISEdge#353b caveat; burst-and-leave \
                                 is the separate initiator-push end-state)"
                            );
                            Err(ShipError::Other(TransportError::Timeout(max_transfer)))
                        }
                        Err(e) => Err(ShipError::Other(TransportError::Io(format!(
                            "reticulum resource send: {e}"
                        )))),
                    };
                }
                _ = poll.tick() => {
                    let (since_last_progress, stage) = {
                        let guard = self.sent_resource_progress.lock().await;
                        guard.get(&resource_hash).map_or_else(
                            || (start.elapsed(), None),
                            |p| (p.last_update.elapsed(), Some(p.stage)),
                        )
                    };
                    // `completed=false` / `link_live=true`: a proven completion or a
                    // dead link fires the `sent` arm above, never here — so this only
                    // ever yields Continue / StalledNoProgress / MaxDeadline.
                    match reverse_path_wait_step(
                        false,
                        true,
                        since_last_progress,
                        start.elapsed(),
                        no_progress_window,
                        max_transfer,
                    ) {
                        ReverseWaitStep::Continue => {}
                        ReverseWaitStep::StalledNoProgress => {
                            self.sent_resource_progress.lock().await.remove(&resource_hash);
                            tracing::debug!(
                                resource = %hex::encode(&resource_hash[..8]),
                                stalled_at = stage.map_or(
                                    "no transfer started (peer never accepted, or advertise lost)",
                                    ResourceSendStage::as_str),
                                elapsed_secs = start.elapsed().as_secs(),
                                "reverse-path resource made no progress; failing fast (CIRISEdge#353b) — \
                                 the stage names WHERE it stalled, so Outcome B (slow) vs A (stuck) is \
                                 field-answerable at DEBUG"
                            );
                            return Err(ShipError::Other(TransportError::Timeout(no_progress_window)));
                        }
                        ReverseWaitStep::MaxDeadline => {
                            self.sent_resource_progress.lock().await.remove(&resource_hash);
                            tracing::warn!(
                                resource = %hex::encode(&resource_hash[..8]),
                                max_secs = max_transfer.as_secs(),
                                "reverse-path resource still transferring at the hard cap; abandoning \
                                 so the responder drain is not parked forever (CIRISEdge#353b/#373)"
                            );
                            return Err(ShipError::Other(TransportError::Timeout(max_transfer)));
                        }
                        ReverseWaitStep::Done | ReverseWaitStep::LinkStale => {
                            unreachable!("Done/LinkStale are owned by the completion future, \
                                          not the progress watchdog (completed=false, link_live=true)");
                        }
                    }
                }
            }
        }
    }
}

#[async_trait]
// `send`'s reverse-path-first + dial-fallback seam crosses 100 lines; async_trait
// attributes the lint to the impl, so the allow lives here (v13.6.1).
#[allow(clippy::too_many_lines)]
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

        // CIRISEdge#336 (v13.8.0) — resolve the peer's FULL candidate address
        // set; the dial target is chosen by ROUTABILITY further down, after the
        // reverse-path attempt. See `resolve_dial_candidates` /
        // `select_dial_candidate` for the holistic-fix rationale.
        let candidates = self.resolve_dial_candidates(destination_key_id).await;
        if candidates.is_empty() {
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
        }

        // CIRISEdge#33 (v0.15.0) — operator-deny-list check BEFORE the
        // leviculum connect call. The blackhole keys on the peer's
        // 16-byte Reticulum destination_hash (the same bytes
        // `path_table` returns), so an operator that snapshots the
        // path table and decides to ban a peer can pass the hash back
        // unchanged.
        //
        // v13.8.0 hardening: check EVERY candidate address, not just the one we
        // end up dialing — route-table-first selection must never let a ban on
        // one of the peer's addresses be bypassed by dialing an alternate.
        for candidate in &candidates {
            self.check_blackhole(&candidate.dest_hash.into_bytes())
                .await?;
        }

        // CIRISEdge#353 — REVERSE PATH FIRST (see `send_via_reverse_path`).
        // Ordered AFTER the blackhole check so an operator ban still wins.
        if self
            .send_via_reverse_path(destination_key_id, envelope_bytes)
            .await
        {
            return Ok(TransportSendOutcome::Delivered);
        }

        // CIRISEdge#336 (v13.8.0) — ROUTE-TABLE-FIRST dial selection. The route
        // table is the source of dial truth; identity math only proposed the
        // candidates above. `select_dial_candidate` picks a PATHED candidate
        // whenever one exists, so dialing an unroutable dest while a routable
        // one exists is impossible by construction (the field failure this
        // closes: ×24 no-route dials at a pathless dest while the same peer's
        // routable dest sat in the path table, direct, 1 hop). With no pathed
        // candidate the order degrades to the pre-v13.8.0 bootstrap dial
        // (broadcast, fast-fail, loud) — prime_peer cold-start keeps working.
        let flags: Vec<(DialSource, bool)> = candidates
            .iter()
            .map(|c| (c.source, self.node.has_path(&c.dest_hash)))
            .collect();
        let Some(chosen_idx) = select_dial_candidate(&flags) else {
            // Unreachable in practice (non-empty candidates always select) —
            // defensive, never a silent fallthrough.
            return Err(TransportError::Unreachable(format!(
                "dial selection yielded no candidate for {destination_key_id}"
            )));
        };
        let has_path = flags[chosen_idx].1;
        let peer = ResolvedPeer {
            dest_hash: candidates[chosen_idx].dest_hash,
            signing_key: candidates[chosen_idx].signing_key,
        };
        {
            // The candidate set + winner, always visible at debug; INFO when
            // routing OVERRODE the legacy preference (the diagnosable case the
            // field was blind to — which address won, and why).
            let set: Vec<String> = candidates
                .iter()
                .zip(&flags)
                .map(|(c, (s, p))| {
                    format!(
                        "{}:{}{}",
                        s.as_str(),
                        hex::encode(c.dest_hash.as_bytes()),
                        if *p { " (path)" } else { "" }
                    )
                })
                .collect();
            if chosen_idx != 0 && has_path {
                tracing::info!(
                    destination_key_id,
                    chosen = %set[chosen_idx],
                    candidates = %set.join(", "),
                    "dial target chosen by ROUTABILITY over legacy preference \
                     (CIRISEdge#336 v13.8.0)"
                );
            } else {
                tracing::debug!(
                    destination_key_id,
                    chosen = %set[chosen_idx],
                    candidates = %set.join(", "),
                    "dial candidate selection (CIRISEdge#336)"
                );
            }
        }
        let establish_timeout = if has_path {
            LINK_ESTABLISH_TIMEOUT
        } else {
            NO_PATH_ESTABLISH_TIMEOUT
        };

        // CIRISEdge#484 — leviculum v0.16 `connect_awaited` returns the handle
        // immediately AND a completion future for `LinkEstablished`, registered
        // BEFORE dispatch (edge no longer needs to observe the event loop `listen`
        // owns). The future keys on the ORIGINAL dial id — the #342/#66 alias the old
        // `link_is_established` poll resolved — takes NO node lock, and resolves
        // `Err(LinkClosed)` on link death. Caller owns the wall-clock bound.
        let (link, established) = self
            .node
            .connect_awaited(&peer.dest_hash, &peer.signing_key)
            .await
            .map_err(|e| TransportError::Io(format!("reticulum connect: {e}")))?;
        let link_id = *link.link_id();
        // CIRISEdge#424 — record the dest we dialed for THIS link so an inbound
        // reply arriving over it (the initiator-side reverse path a NAT'd peer's
        // responder uses) attributes to this peer even though leviculum's
        // `link_destination` returns `None` for our own dialed links.
        self.dialed_link_dest
            .lock()
            .await
            .insert(link_id, peer.dest_hash);

        // Await `LinkEstablished` on BOTH ends — the peer must have accepted the
        // LINK_REQUEST or a resource transfer cannot start. `established` resolves
        // `Ok(())` on establishment, `Err(LinkClosed)` if the peer refused / the link
        // died first; a timeout means no route or a stalled dial.
        let established_ok = matches!(
            with_timeout(establish_timeout, established).await,
            Some(Ok(()))
        );
        if !established_ok {
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

        // CIRISEdge#436 — initiator-side bundle serve, ordered AFTER the
        // LINKIDENTIFY (so the responder attributes it) and BEFORE the
        // resource ship (the fragments ride the link Channel, which never
        // contends with the resource lane — leviculum#27).
        if let Some(own) = self.own_bundle.as_ref() {
            push_own_bundle_frames(&self.node, own, &link_id).await;
        }

        // The outbound-dial path we just established this link; a `Busy`
        // collision here is not the reverse-path retry case, so both variants
        // surface as the send's transport error (the durable dispatcher retries).
        // Freshly-dialed link we control: lenient no-progress window, full
        // [`RESOURCE_TRANSFER_TIMEOUT`] hard cap (v13.6.1 progress-aware wait).
        self.ship_resource_on_link(
            &link_id,
            envelope_bytes,
            DIAL_NO_PROGRESS_WINDOW,
            RESOURCE_TRANSFER_TIMEOUT,
        )
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

        // CIRISEdge#482 item 3 — offload announce cold-start onto a dedicated
        // worker so a slow / contended rooting directory can no longer
        // head-of-line every other node event behind an announce's DB
        // round-trips. The EventReceiver select arm below `try_send`s each
        // inbound announce here; this single worker drains them FIFO (the same
        // serial processing order as the old inline path, just decoupled from
        // the hot event task — so it introduces no new concurrency). The worker
        // exits when `announce_tx` drops on listener shutdown.
        let announce_ctx = AnnounceCtx {
            peers: Arc::clone(&self.peers),
            rooting: self.rooting.clone(),
            event_bus: self.event_bus.clone(),
            reachability: self.reachability.clone(),
            peer_bundles: Arc::clone(&self.peer_bundles),
            hybrid_policy: self.hybrid_policy,
            transport_binding_enforcement: self.transport_binding_enforcement,
            bundle_save_gate: self.bundle_save_gate,
        };
        let (announce_tx, mut announce_rx) =
            mpsc::channel::<leviculum_core::ReceivedAnnounce>(ANNOUNCE_QUEUE_DEPTH);
        tokio::spawn(async move {
            while let Some(announce) = announce_rx.recv().await {
                resolve_announce_cold_start(announce, &announce_ctx).await;
            }
            tracing::debug!("announce cold-start worker exiting (channel closed)");
        });

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
                    // CIRISEdge#406 — re-arm the signed transport-destination
                    // producer on the announce cadence. Memoized once current
                    // (no directory read after success); until then this heals
                    // the boot-order faults (directory unavailable at
                    // construction, own federation key registered after the
                    // transport came up) without a restart.
                    if let Some(rooting) = self.rooting.as_deref() {
                        let _outcome = self
                            .self_route
                            .ensure(
                                &self.local_signer,
                                rooting,
                                self.local_named_dest_hash(),
                                self.local_transport_pubkey,
                                self.config.local_epoch,
                            )
                            .await;
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
                        sent_resource_progress: &self.sent_resource_progress,
                        sink: &sink,
                        rooting: self.rooting.as_deref(),
                        binding_cache: &self.binding_cache,
                        announce_tx: &announce_tx,
                        bundle_save_gate: self.bundle_save_gate,
                        peer_bundles: &self.peer_bundles,
                        own_bundle: self.own_bundle.as_ref(),
                        event_bus: self.event_bus.as_deref(),
                        link_established_at: &self.link_established_at,
                        link_to_peer_key_id: &self.link_to_peer_key_id,
                        link_last_inbound_at: &self.link_last_inbound_at,
                        inbound_reasm: &self.inbound_reasm,
                        dialed_link_dest: &self.dialed_link_dest,
                        scope_addresses: &self.scope_addresses,
                        #[cfg(feature = "lxmf")]
                        lxmf_serve: &self.lxmf_serve,
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

/// CIRISEdge#482 item 3 — the OWNED subset of transport state that
/// [`resolve_announce_cold_start`] needs, so it can run on a dedicated worker
/// task (fed from [`EventCtx::announce_tx`]) instead of inline on the single
/// EventReceiver task. Every field is `Arc`/`Copy` so the whole struct clones
/// cheaply; it mirrors exactly the 8 `EventCtx` fields the cold-start path
/// touches (verified: it delegates `ctx` to no other helper). Built once in
/// [`ReticulumTransport::listen`] and moved into the worker.
#[derive(Clone)]
struct AnnounceCtx {
    peers: Arc<Mutex<HashMap<String, RootedPeer>>>,
    rooting: Option<Arc<dyn RootingDirectory>>,
    event_bus: Option<Arc<crate::events::EventBus>>,
    reachability: Option<Arc<ReachabilityTracker>>,
    peer_bundles: Arc<crate::bundle_gate::PeerBundleStore>,
    hybrid_policy: HybridPolicy,
    transport_binding_enforcement: TransportBindingEnforcement,
    bundle_save_gate: crate::bundle_gate::BundleSaveGateMode,
}

/// Shared handles the event loop hands to [`handle_event`].
struct EventCtx<'a> {
    node: &'a ReticulumNode,
    peers: &'a Mutex<HashMap<String, RootedPeer>>,
    established_links: &'a Mutex<HashSet<LinkId>>,
    /// CIRISEdge#353b/v13.6.1 — sender-side resource transfer progress (see the
    /// field of the same name on [`ReticulumTransport`]).
    sent_resource_progress: &'a Mutex<HashMap<[u8; 32], ResourceSendProgress>>,
    sink: &'a mpsc::Sender<InboundFrame>,
    /// Persist directory adapter for the authenticated cold-start
    /// path; `None` → announces are dropped (no rooting possible).
    rooting: Option<&'a dyn RootingDirectory>,
    /// CIRISEdge#482 item 2 — per-`(peer, dest)` hybrid-binding memo, borrowed
    /// from the owning transport; see [`binding_exists_cached`].
    binding_cache: &'a BindingCache,
    /// CIRISEdge#482 item 3 — hand-off channel to the announce cold-start
    /// worker. The `AnnounceReceived` arm `try_send`s here instead of running
    /// [`resolve_announce_cold_start`] inline on the EventReceiver task.
    announce_tx: &'a mpsc::Sender<leviculum_core::ReceivedAnnounce>,
    /// CIRISEdge#437 — bundle-gate posture on the DURABLE Rooted save,
    /// applied to the write-through in [`resolve_announce_cold_start`].
    bundle_save_gate: crate::bundle_gate::BundleSaveGateMode,
    /// CIRISEdge#437 — the per-peer presented-bundle store the gate
    /// consults (see the field of the same name on [`ReticulumTransport`]).
    peer_bundles: &'a crate::bundle_gate::PeerBundleStore,
    /// CIRISEdge#436 — this node's own validated build bundle, served as a
    /// `CBND` frame on responder-side link-up. `None` → nothing served.
    own_bundle: Option<&'a OwnBuildBundle>,
    /// CIRISEdge#34 — shared event bus for announce / interface
    /// emissions. `None` → no events emitted (the transport was
    /// constructed without `ReticulumAuth::event_bus`).
    event_bus: Option<&'a crate::events::EventBus>,
    /// CIRISEdge#32 (v0.14.0) — link establishment timestamps,
    /// populated on `LinkEstablished` / cleared on `LinkClosed` /
    /// `LinkStale`.
    link_established_at: &'a Mutex<HashMap<LinkId, u64>>,
    /// v3.5.1 (CIRISEdge#119 + #120) — per-link rooted-peer
    /// attribution. Populated on `NodeEvent::LinkIdentified` after
    /// matching the link's remote identity to a rooted peer; consumed
    /// on `NodeEvent::ResourceCompleted` to populate
    /// `InboundFrame::source_key_id` for the
    /// `Edge::install_replication_routing` lookup.
    link_to_peer_key_id: &'a Mutex<HashMap<LinkId, String>>,
    /// CIRISEdge#353 — per-link last-inbound timestamp (RNS `last_inbound`
    /// liveness signal); stamped in `attribute_and_deliver`, consumed by
    /// `live_attributed_link_to` to reply over the peer's freshest live link.
    link_last_inbound_at: &'a Mutex<HashMap<LinkId, u64>>,
    /// CIRISEdge#414/#932 — inbound fragment reassembler (see the field of the
    /// same name on [`ReticulumTransport`]). `attribute_and_deliver` feeds every
    /// inbound frame through it; a fragment that does not yet complete its frame
    /// buffers here and produces no `InboundFrame`.
    inbound_reasm: &'a Mutex<crate::transport::frame_fragment::Reassembler>,
    /// CIRISEdge#424 — dest edge dialed per initiated link (see the field of the
    /// same name on [`ReticulumTransport`]). Consulted in `attribute_and_deliver`
    /// when leviculum's `link_destination` is `None` for an own-dialed link.
    dialed_link_dest: &'a Mutex<HashMap<LinkId, DestinationHash>>,
    /// CIRISEdge#499 — the scope-native address table (see the field of the same
    /// name on [`ReticulumTransport`]). `attribute_and_deliver` probes its
    /// reverse index once per frame to stamp `InboundFrame::arrival_scope`,
    /// which is the receive-side admission fact the blob serve gate consumes.
    /// Empty `OnceLock` (the default: the derivation shipped —
    /// CIRISVerify#259 / `ScopePrivacyDeriver` — but the table is only
    /// installed when the operator opts in via
    /// `EdgeBuilder::scope_native_addressing`) ⇒ every frame is stamped
    /// `None`, i.e. federation arrival, i.e. exactly pre-#499 behaviour.
    scope_addresses: &'a OnceLock<Arc<ScopeAddressTable>>,
    /// CIRISEdge#169 — the LXMF serve node, borrowed like every other
    /// sub-protocol's state (the `EventCtx` field pattern).
    #[cfg(feature = "lxmf")]
    lxmf_serve: &'a OnceLock<Arc<crate::transport::lxmf_serve::LxmfServeNode>>,
}

/// CIRISEdge#424 — the classified result of attributing an inbound frame's link to
/// a source peer. Every arm is explicit so a `None` attribution can NEVER again be
/// a silent fall-through: #424 was diagnosed precisely because the instrumented
/// miss-branch never fired — execution exited an un-instrumented outer `else`.
#[derive(Debug, PartialEq, Eq)]
enum LinkAttribution {
    /// A peer dialed us; attributed via the `LinkIdentified`-fed table.
    ViaIdentified(String),
    /// We dialed the link; attributed via the destination edge recorded at
    /// `connect` (the #353/#424 initiator reverse path). This is the arm the bug
    /// could not reach because leviculum's `link_destination` is `None` here.
    ViaDialedDest(String),
    /// NO destination is known for this link — not `LinkIdentified` (no peer dialed
    /// us) AND no dialed-dest record (`link_destination`=None for own-dialed links,
    /// and edge never recorded a dial). THE #424 class; loudly logged, not silent.
    NoDest,
    /// A destination IS known but matches no rooted peer in the map (e.g. the peer
    /// has not rooted yet).
    DestUnmatched(DestinationHash),
}

/// Pure attribution decision (unit-tested — the layer the server's loopback round
/// harness cannot reach, per CIRISEdge#424). The `LinkIdentified` table wins; else
/// the link's known destination is mapped back to a rooted peer; else a CLASSIFIED
/// miss (never an unlabelled `None`). `peer_for_dest` closes over the live peer map.
fn resolve_link_attribution(
    identified: Option<String>,
    dest: Option<DestinationHash>,
    peer_for_dest: impl FnOnce(DestinationHash) -> Option<String>,
) -> LinkAttribution {
    if let Some(key_id) = identified {
        return LinkAttribution::ViaIdentified(key_id);
    }
    match dest {
        None => LinkAttribution::NoDest,
        Some(d) => match peer_for_dest(d) {
            Some(key_id) => LinkAttribution::ViaDialedDest(key_id),
            None => LinkAttribution::DestUnmatched(d),
        },
    }
}

/// CIRISEdge#482 item 2 — consult a per-`(peer, dest)` TTL memo before querying
/// the rooting directory for a hybrid transport binding. The inbound attribution
/// path calls `hybrid_transport_binding_exists` once PER FRAME; a peer that is
/// actively sending re-proves the SAME `(key_id, dest)` binding on every frame,
/// so a short-TTL memo collapses that to one directory query per
/// [`BINDING_CACHE_TTL`] window (the hot receive path this optimizes).
///
/// `(key_id, dest)` is the COMPLETE input to `hybrid_transport_binding_exists`,
/// so the cache key is exact: a re-key (new `key_id`) or re-home (new `dest`)
/// changes the key and misses, re-querying live. **Staleness bound**: a binding
/// *revocation* (persist supports subject-revoked bindings) propagates to this
/// gate within one TTL window — bounded, and additive to the rooting
/// directory's own federation-propagation latency, not the sole delay. The
/// window is deliberately tight (seconds) because a stale `true` is the
/// security-relevant direction on this load-bearing E3 attribution gate; a
/// stale `false` is fail-closed (a just-rooted peer is briefly not attributed,
/// then self-heals on the next window).
async fn binding_exists_cached(
    cache: &BindingCache,
    rooting: &dyn RootingDirectory,
    key_id: &str,
    dest: [u8; 16],
) -> bool {
    {
        let guard = cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((verdict, at)) = guard.get(&(key_id.to_string(), dest)) {
            if at.elapsed() < BINDING_CACHE_TTL {
                return *verdict;
            }
        }
    }
    let verdict = rooting.hybrid_transport_binding_exists(key_id, dest).await;
    {
        let mut guard = cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Bound memory: prune expired entries before inserting. The live set is
        // naturally bounded by the rooted-peer population (item 1 gates entry to
        // this check), but departed peers must not accumulate.
        guard.retain(|_, (_, at)| at.elapsed() < BINDING_CACHE_TTL);
        guard.insert(
            (key_id.to_string(), dest),
            (verdict, std::time::Instant::now()),
        );
    }
    verdict
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
/// CIRISEdge#353/#365 — attribute an inbound link frame to its source peer and
/// hand it to the inbound sink. Shared by BOTH the resource path
/// (`ResourceCompleted`) and the packet path (`LinkDataReceived`, the #353 ask #2
/// non-contending reverse-path reply) so the two can NEVER diverge in how they
/// attribute or route a frame (the #348 two-loops lesson). Attribution order:
/// the `LinkIdentified`-fed table first (a peer dialed us), then the link's
/// DESTINATION (a link WE dialed — the reverse path), then `None`
/// (SkippedNoSourceKeyId downstream, never a silent drop).
async fn attribute_and_deliver(ctx: &EventCtx<'_>, link_id: LinkId, data: Vec<u8>) {
    // CIRISEdge#353 — stamp last-inbound for the reverse-path link selector
    // (RNS `last_inbound`). This frame proves the peer is ALIVE on THIS link
    // right now, so a subsequent reply rides it rather than a dead-but-`Active`
    // link leviculum hasn't yet flipped to Stale. Stamped for both the resource
    // and packet inbound paths (both funnel here), so any traffic keeps the link
    // fresh in the selector.
    {
        let now_secs = u64::try_from(chrono::Utc::now().timestamp().max(0)).unwrap_or(0);
        ctx.link_last_inbound_at
            .lock()
            .await
            .insert(link_id, now_secs);
    }
    // CIRISEdge#414 / CIRISAgent#932 — REASSEMBLE before attributing/routing. A
    // whole (`CRPL…`) frame passes straight through unchanged; a `CFRG` fragment
    // (the send side split an oversized reverse-path reply onto the packet path)
    // is buffered until its siblings arrive, at which point the reassembled frame
    // is routed exactly as if it had crossed whole. An incomplete/malformed
    // fragment produces NO `InboundFrame` — the last-inbound stamp above already
    // recorded the packet as link liveness, and anti-entropy re-diffs + re-sends
    // the frame next round. This is the receive twin of the send-side fragmenter;
    // both inbound paths (resource + packet) funnel here so neither can bypass it.
    let data = {
        let Some(frame) = ctx.inbound_reasm.lock().await.accept(&data) else {
            tracing::trace!(
                link = ?link_id,
                bytes = data.len(),
                "inbound fragment buffered; frame not yet complete (CIRISEdge#414/#932)"
            );
            return;
        };
        frame
    };
    // CIRISEdge#393 (E3) — resolve the candidate peer key_id for this link, then
    // gate it through `SourceKeyId::from_rooted_binding`: attribution survives
    // ONLY for a `Rooted ∧ owns_key` peer. An Advisory or non-owning binding —
    // the announce-spoof vector (an attacker announcing a serve-capable victim's
    // key_id under its own transport identity) — yields `None`, so the frame is
    // delivered unattributed and dropped downstream (`SkippedNoSourceKeyId`),
    // never reaching `peer_has_serve_capability`. Both attribution bases are
    // gated identically (the #348 "two loops must never diverge" lesson).
    let identified = ctx.link_to_peer_key_id.lock().await.get(&link_id).cloned();
    // CIRISEdge#353/#424 — INITIATOR-side attribution. `link_to_peer_key_id` is fed
    // by `LinkIdentified`, which only fires on links a PEER dialed to us; a reply
    // arriving on a link WE dialed (the reverse path a NAT'd peer's responder uses)
    // has no entry. The basis is the link's DESTINATION: we dialed a dest resolved
    // from the VERIFIED route table, and RNS establishment proves the remote
    // controls that dest's keys — same trust the outbound send used.
    //
    // leviculum's `link_destination` answers this for links a peer dialed to us,
    // but returns `None` for our OWN dialed links (its `link()` registry misses the
    // initiator direction / a #66 re-key). That `None` is exactly what dropped
    // every initiator-side reply `source_key_id=None` (CIRISEdge#424): the arm
    // exited at step one into an un-instrumented `else`. Fall back to edge's own
    // connect-time record (`dialed_link_dest`), which is re-key-independent.
    let dest = match ctx.node.link_destination(&link_id) {
        Some(d) => Some(d),
        None => ctx.dialed_link_dest.lock().await.get(&link_id).copied(),
    };
    let candidate_key_id = {
        let peers = ctx.peers.lock().await;
        let outcome = resolve_link_attribution(identified, dest, |d| {
            peers
                .iter()
                .find(|(_, rooted)| rooted.peer.dest_hash == d)
                .map(|(key_id, _)| key_id.clone())
        });
        drop(peers);
        match outcome {
            LinkAttribution::ViaIdentified(key_id) => Some(key_id),
            LinkAttribution::ViaDialedDest(key_id) => {
                tracing::debug!(
                    link = ?link_id,
                    peer = %key_id,
                    "inbound frame on a link WE dialed attributed via its recorded \
                     destination (initiator-side reverse path, CIRISEdge#353/#424)"
                );
                Some(key_id)
            }
            // The #424 class — now LOUD, never a silent outer `else`. Throttled per
            // link (capped map = DoS backstop). If this fires POST-fix, edge got a
            // frame on a link it neither accepted nor recorded dialing.
            LinkAttribution::NoDest => {
                if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                    initiator_attribution_miss_log().check(&format!("{link_id:?}"))
                {
                    tracing::warn!(
                        link = ?link_id,
                        suppressed_prev,
                        "inbound frame's link has NO known destination — not \
                         LinkIdentified (no peer dialed us) and no dialed-dest record \
                         (leviculum `link_destination`=None for own-dialed links). The \
                         #353 initiator arm cannot resolve a source; frame dropped \
                         unattributed (CIRISEdge#424)"
                    );
                }
                None
            }
            LinkAttribution::DestUnmatched(d) => {
                // A DROP, so it speaks at WARN — at debug this was invisible at the
                // level a harness actually runs, which is how a dropped frame kept
                // reading as absence-of-work (CIRISAgent#932/#425). Throttled per
                // link (floor, not silence, not per-frame flood).
                if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                    initiator_attribution_miss_log().check(&format!("{link_id:?}"))
                {
                    tracing::warn!(
                        link = ?link_id,
                        dest = %hex::encode(d.into_bytes()),
                        suppressed_prev,
                        "inbound frame DROPPED unattributed — the link's destination \
                         matches NO rooted peer (dest resolved, peers-map lookup missed; \
                         peer not yet rooted, or rooted under a different dest) (CIRISEdge#425)"
                    );
                }
                None
            }
        }
    };
    // CIRISEdge#436 — a link-borne build-attestation-bundle frame (`CBND`) is
    // a TRANSPORT-level control frame, consumed here exactly like a `CFRG`
    // fragment — never an envelope, never an `InboundFrame`. Intercepted with
    // the RAW candidate attribution, BEFORE the E3 `Rooted∧owns_key∧hybrid`
    // gate below: its whole purpose is to upgrade a peer that is still
    // Advisory — the very peers the gate (correctly) nulls.
    if crate::transport::peer_bundle_frame::is_peer_bundle_frame(&data) {
        handle_peer_bundle_frame(ctx, link_id, candidate_key_id, &data).await;
        // choke-ok: consumed as a transport control frame, not a drop — every
        // outcome inside `handle_peer_bundle_frame` speaks (INFO on the
        // one-motion upgrade; `drop_inbound` / throttled WARN on any refusal).
        return;
    }
    // Gate (CIRISEdge#393): admit the attribution only if the candidate's binding
    // is `Rooted ∧ owns_key` (item 1) AND its transport identity is bound by a
    // hybrid-verified `SignedTransportDestination` (item 2, the PQ half). Any
    // shortfall → `None` (SkippedNoSourceKeyId downstream, never served).
    // CIRISEdge#402 — the raw transport-level link key_id (the self-consistent
    // advisory binding), captured BEFORE the E3 `Rooted∧owns_key∧hybrid` gate
    // below narrows it to `None`. A routing hint only (see `InboundFrame::link_key_id`);
    // the E3 attacker (`PubkeyMismatch`) never reaches `link_to_peer_key_id`, so
    // this is `Some` only for a self-consistent binding.
    let link_key_id = candidate_key_id.clone();
    let source_key_id = match candidate_key_id {
        Some(key_id) => {
            // Item 1 — Rooted ∧ owns_key, plus capture the peer's dest for the
            // item-2 lookup. `dest` is `None` when the peer isn't in the map.
            // CIRISEdge#404 — ALSO snapshot the RESOLVED binding's operands
            // (provenance, owns_key, epoch) so the attribution-miss log can name
            // WHICH conjunct failed (a `provenance=Advisory ∧ owns_key=true` is a
            // churn downgrade, indistinguishable from an owns_key failure without it).
            let (item1, dest, resolved) = {
                let peers = ctx.peers.lock().await;
                match peers.get(&key_id) {
                    Some(rooted) => (
                        crate::transport::SourceKeyId::from_rooted_binding(
                            key_id.clone(),
                            rooted.provenance,
                            rooted.owns_key,
                        ),
                        Some(rooted.peer.dest_hash.into_bytes()),
                        Some((rooted.provenance, rooted.owns_key, rooted.epoch)),
                    ),
                    None => (None, None, None),
                }
            };
            // Item 2 — the PQ transport binding. Fail-closed without a rooting
            // directory (can't prove the hybrid route ⇒ not attributable).
            let gated = match (item1, dest, ctx.rooting) {
                (Some(sid), Some(d), Some(rooting)) => {
                    if binding_exists_cached(ctx.binding_cache, rooting, &key_id, d).await {
                        Some(sid)
                    } else if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                        link_attribution_miss_log().check(key_id.as_str())
                    {
                        tracing::warn!(
                            link = ?link_id,
                            peer = %key_id,
                            dest = %hex::encode(d),
                            suppressed_prev,
                            "inbound frame DROPPED — item 1 PASSED (Rooted∧owns_key) but \
                             item 2 FAILED: no hybrid-verified SignedTransportDestination \
                             binds this (peer, dest) pair (CIRISEdge#393 item 2). This is \
                             the ONLY failing conjunct"
                        );
                        None
                    } else {
                        None
                    }
                }
                (Some(_), _, None) => {
                    // A CONFIG condition that nulls EVERY attribution — throttled on a
                    // FIXED discriminant (one condition, not per-peer) so a misconfig
                    // reminds periodically without one-warn-per-frame flooding.
                    if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                        link_attribution_miss_log().check("no-rooting-directory")
                    {
                        tracing::warn!(
                            link = ?link_id,
                            peer = %key_id,
                            suppressed_prev,
                            "inbound frame DROPPED — NO ROOTING DIRECTORY wired on this \
                             transport, so item 2 can never be evaluated (fail-closed). This \
                             nulls EVERY attribution regardless of kind or path — check the \
                             Edge builder wires a RootingDirectory (CIRISEdge#393 item 2)"
                        );
                    }
                    None
                }
                _ => None,
            };
            let gated = if gated.is_some() {
                gated
            } else if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                // CIRISEdge#404/#432 — the attribution decision has a voice AND a
                // remedy, both bounded by this per-key_id throttle (the 1024-cap
                // map bounds an attacker-chosen flood; the throttle's Emit floor
                // also bounds the heal's directory point-read to a few per window
                // — and the FIRST failing frame always Emits, so a genuine
                // divergence heals on frame one, not after a window).
                link_attribution_miss_log().check(key_id.as_str())
            {
                // CIRISEdge#432 — before declaring the miss, consult the DURABLE
                // store. The live map and the store have independent writers (a
                // replication-side or server-side rooting updates only the store),
                // so "resolved Advisory" can be stale while persist holds
                // `rooted` — the two-day dark-Attestation-plane class. If the
                // store roots the SAME transport identity this link proved,
                // upgrade the live entry in place (a one-peer mid-session boot
                // prime — exactly the motion a process restart performs) and
                // attribute THIS frame.
                heal_or_report_attribution_miss(ctx, &key_id, resolved, link_id, suppressed_prev)
                    .await
            } else {
                None
            };
            gated
        }
        // NO candidate key_id at all — the frame is dropped unattributed. This is
        // NOT a silent drop: the specific cause (`NoDest` / `DestUnmatched`) was
        // ALREADY logged loudly + throttled by the `resolve_link_attribution` arm
        // above (CIRISEdge#424/#425), so this terminal arm just forwards the `None`
        // without re-logging (a second per-frame log here would double-flood the
        // exact condition already stated upstream).
        None => None,
    };
    // CIRISEdge#499 — resolve the SCOPE-DERIVED address this frame arrived on,
    // here, once, BEFORE the envelope is parsed. `dest` is the link's
    // destination, already in hand for the attribution above; the resolution is
    // a single hash-map probe against the reverse index (the table exists
    // precisely so the packet path never derives — see
    // `scope_addressing::lookup_never_calls_the_deriver`).
    //
    // `None` — no table installed, or a hash that is not one of ours — means the
    // frame arrived on the FEDERATION address, which downstream reads as
    // `CohortScope::Public`. That is not a downgrade: it is the literal truth
    // about what reaching a public discovery address demonstrates.
    //
    // This is a receive-side ADMISSION FACT, orthogonal to `source_key_id`: it
    // says which group secret the sender possessed, not who the sender is. A
    // frame can carry one without the other, and the blob serve gate needs
    // exactly this one.
    let arrival_scope = dest.and_then(|d| {
        ctx.scope_addresses
            .get()
            .and_then(|t| t.accepts_inbound(&d.into_bytes()))
    });
    let frame = InboundFrame {
        envelope_bytes: data,
        transport: TransportId::RETICULUM_RS,
        received_at: Utc::now(),
        source_key_id,
        link_key_id,
        arrival_scope,
    };
    if let Err(e) = ctx.sink.send(frame).await {
        tracing::error!(error = %e, "inbound channel send failed");
    }
}

/// CIRISEdge#353 — choose which of a peer's live links a reply rides.
///
/// Prefer the link with the most recent INBOUND activity (RNS's `last_inbound`
/// liveness signal, `RNS.Link.last_inbound` / leviculum `last_inbound_secs`):
/// the peer is demonstrably sending its round on that link right now, so the
/// reply lands. A NAT-dead link that leviculum still reports `Active` has stale
/// inbound and loses — which stops the reply from committing to a corpse (the
/// #353 field failure: a 120 s resource timeout shipping into a dead-but-Active
/// link, then a NAT-blocked fallback dial). Tie-break on establishment time
/// (newer wins) so two links opened in the same second choose deterministically.
///
/// Threat-model guardrail: `live` is ALREADY liveness-filtered AND attributed to
/// the peer by the caller (identity-proof / verified-dest). This fn only ORDERS
/// those candidates — it never widens attribution, so it can never route a reply
/// to a link the peer did not prove control of.
fn select_reply_link(
    live: &[(
        LinkId,
        u64, /* last_inbound */
        u64, /* established_at */
    )],
) -> Option<LinkId> {
    live.iter()
        .copied()
        .max_by_key(|(_, last_inbound, established_at)| (*last_inbound, *established_at))
        .map(|(id, _, _)| id)
}

#[allow(clippy::too_many_lines)] // one exhaustive NodeEvent dispatch match; splitting it hurts readability
async fn handle_event(event: NodeEvent, ctx: &EventCtx<'_>) {
    match event {
        NodeEvent::AnnounceReceived { announce, .. } => {
            // The announce app-data carries the peer's signed attestation; the
            // authenticated cold-start path roots the federation key, verifies
            // the attestation signature, and applies the hybrid policy before
            // the peer is recorded as resolvable (replaces v0.3.1 TOFU —
            // CIRISEdge#15, AV-42). CIRISEdge#482 item 3 — that work is now
            // handed to a dedicated worker (non-blocking `try_send`) so its DB
            // round-trips don't head-of-line every other node event. Both drop
            // paths are LOUD (never silent — CIRISEdge#425), but split so a DEAD
            // worker (channel Closed) is diagnosable rather than masked as
            // ordinary backpressure (queue Full).
            match ctx.announce_tx.try_send(announce) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::warn!(
                        "announce DROPPED — cold-start worker queue FULL \
                         (backpressure); RNS re-announce will retry (CIRISEdge#482 item 3)"
                    );
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    // The worker task is gone (exited or panicked). This is NOT
                    // routine backpressure — every subsequent announce will be
                    // dropped until the transport is rebuilt, so it is an ERROR.
                    tracing::error!(
                        "announce DROPPED — cold-start worker is GONE (channel \
                         closed: the worker task exited); announces are no longer \
                         being processed (CIRISEdge#482 item 3)"
                    );
                }
            }
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
            // CIRISEdge#436 — serve our own build-attestation bundle on
            // link-up, RESPONDER side only (a link the peer dialed to us: the
            // peer attributes our frames via its own dialed-dest record, so no
            // ordering hazard). For links WE dialed the push happens on the
            // dial paths right after `identify_link`, so the bundle frame can
            // never outrun the LINKIDENTIFY the receiver attributes it by.
            if let Some(own) = ctx.own_bundle {
                let own_dialed = ctx.dialed_link_dest.lock().await.contains_key(&link_id);
                if !own_dialed {
                    push_own_bundle_frames(ctx.node, own, &link_id).await;
                }
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
        // leviculum#25 (v0.9.3+ciris.1) — the driver DESTROYED frames because
        // their interface died: it cannot re-home them (a frame is bound to its
        // interface, and link traffic's link died with it), so the bytes are
        // gone and the sender must re-send on a fresh link. Pre-#25 this loss
        // was silent below us, which is precisely why an in-flight iface drop
        // read as a permanent delivery park and misrouted debugging across three
        // repos (CIRISServer#294 / CIRISEdge#365). Surface it LOUDLY here:
        // edge's durable dispatcher already retries with backoff, so the
        // operator-facing need is knowing the loss happened at all. WARN is
        // right — for an accept-only node serving a NAT'd initiator, interface
        // replacement is the steady state, so this is expected-but-actionable,
        // not a fault. Unthrottled: it is bounded by real interface deaths
        // (~1/60s per NAT rebind), not attacker-drivable.
        NodeEvent::FramesDropped {
            iface_id,
            count,
            reason,
        } => {
            tracing::warn!(
                iface_id,
                frames = count,
                ?reason,
                "transport DESTROYED {count} in-flight frame(s) — their interface died and the \
                 driver cannot re-home them; the durable dispatcher will re-send on a fresh \
                 link (leviculum#25)"
            );
        }
        NodeEvent::LinkStale { link_id } => {
            // Bookkeeping cleanup + emit. The link may still be in
            // `established_links` (leviculum hasn't yet seen LinkClosed
            // arrive); leave the set alone — `LinkClosed` is the
            // authoritative removal point — but surface the staleness
            // on the event stream so the UI can render it.
            //
            // CIRISEdge#460 — `Info`, NOT `Warning`. A link going stale is the
            // routine idle-reap precursor (idle → reaped at 60/90s → closed),
            // not a fault. Emitting it at Warning made routine link turnover 70%
            // of the server's WARN stream, training readers to skip the level
            // and burying real refusals (#459) in the noise. Fault teardowns are
            // classified by `LinkCloseReason` at the `LinkClosed` arm below.
            if let Some(bus) = ctx.event_bus {
                bus.emit_link(link_event(
                    crate::events::EventKind::LinkDropped,
                    &link_id,
                    None,
                    crate::events::EventSeverity::Info,
                    "link became stale",
                ));
            }
        }
        // CIRISEdge#353b/v13.6.1 — mirror sender-side transfer progress so
        // `ship_resource_on_link` can distinguish a live-but-slow transfer
        // (extend the deadline) from a dead link (fast-fail), and log WHERE a
        // stalled transfer got stuck. `ResourceAdvertised` carries no `is_sender`;
        // its entry is harmless (the wait only looks up its own hash) and is
        // cleaned on completion/failure.
        NodeEvent::ResourceAdvertised { resource_hash, .. } => {
            ctx.sent_resource_progress.lock().await.insert(
                resource_hash,
                ResourceSendProgress {
                    stage: ResourceSendStage::Advertised,
                    last_update: std::time::Instant::now(),
                },
            );
        }
        // TransferStarted + Progress both mean "parts are flowing" → Transferring.
        //
        // leviculum v0.22 (#59) reclassified `ResourceTransferStarted` from the
        // lossless control plane to the droppable data plane (`ResourceProgress`
        // was Data already). Both now ride a DIFFERENT channel than the Control
        // `ResourceCompleted` that removes this entry, so under saturation a
        // queued Started/Progress can arrive AFTER its own completion and
        // re-insert a stale entry no one will ever remove (the waiter that
        // owns the other removal has already returned). The insert stays (it
        // is the self-healing arm when the `ResourceAdvertised` insert was
        // lost to a control-plane drop), but the map gets a defensive bound:
        // past the cap, entries idle beyond the reverse-path hard transfer
        // cap are pruned — a live transfer refreshes `last_update` on every
        // progress tick, so only orphans qualify.
        NodeEvent::ResourceTransferStarted {
            resource_hash,
            is_sender,
            ..
        }
        | NodeEvent::ResourceProgress {
            resource_hash,
            is_sender,
            ..
        } => {
            if is_sender {
                let mut guard = ctx.sent_resource_progress.lock().await;
                if guard.len() >= SENT_RESOURCE_PROGRESS_PRUNE_THRESHOLD {
                    guard.retain(|_, p| p.last_update.elapsed() < REVERSE_PATH_MAX_TRANSFER);
                }
                guard.insert(
                    resource_hash,
                    ResourceSendProgress {
                        stage: ResourceSendStage::Transferring,
                        last_update: std::time::Instant::now(),
                    },
                );
            }
        }
        NodeEvent::ResourceFailed {
            resource_hash,
            is_sender,
            error,
            ..
        } => {
            ctx.sent_resource_progress
                .lock()
                .await
                .remove(&resource_hash);
            if is_sender {
                tracing::debug!(
                    resource = %hex::encode(&resource_hash[..8]),
                    error = %error,
                    "reverse-path resource transfer FAILED at the driver (CIRISEdge#353b)"
                );
            } else {
                // CIRISEdge#425 — an INBOUND envelope resource that began arriving
                // and never completed used to leave no trace on the receive side.
                drop_inbound(
                    None,
                    "inbound-resource-failed",
                    &format!(
                        "an inbound envelope resource transfer failed mid-flight \
                         (resource={}): {error}",
                        hex::encode(&resource_hash[..8])
                    ),
                );
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
            // CIRISEdge#353b/v13.6.1 — the transfer concluded; drop its progress
            // mirror (bounds the map for both sent + received resources).
            ctx.sent_resource_progress
                .lock()
                .await
                .remove(&resource_hash);
            if is_sender {
                // choke-ok: sender-side completion is NOT an inbound drop — our own
                // outbound envelope finished transferring. CIRISEdge#484 — it is now
                // delivered to the `ship_resource_on_link` waiter by the leviculum v0.16
                // completion future (no `sent_resources` mirror); here we only need to
                // NOT process our own outbound completion as a receiver-side frame.
                return;
            }
            // Receiver side: the first segment carries the full envelope (edge
            // envelopes are single-segment for the MVP — an 8 MiB cap fits one
            // Reticulum resource). CIRISEdge#425 — these two causes used to fuse
            // into ONE silent `return`; split + loud (a multi-segment resource is a
            // real assumption break if leviculum ever chunks a large transfer).
            if data.is_empty() {
                drop_inbound(
                    Some(link_id),
                    "empty-resource",
                    "receiver-side resource completed with no data",
                );
                return;
            }
            if segment_index != 1 {
                drop_inbound(
                    Some(link_id),
                    "multi-segment-resource",
                    &format!(
                        "segment_index={segment_index} — edge assumes single-segment \
                         envelopes (MVP); segments >1 are NOT reassembled and are dropped"
                    ),
                );
                return;
            }
            tracing::debug!(
                link = ?link_id,
                bytes = data.len(),
                "inbound envelope resource completed",
            );
            attribute_and_deliver(ctx, link_id, data).await;
        }
        // CIRISEdge#353 ask #2 / #363 — a reverse-path reply that arrived as a
        // link PACKET (a link-Channel send, `LinkHandle::try_send` since
        // CIRISEdge#371 / leviculum v0.10.0) rather than a resource, because the
        // link was mid-transfer. leviculum#27: a packet interleaves an in-flight
        // resource transfer (it goes through the link Channel, never the
        // one-resource gate), so a small anti-entropy reply (Summary/Diff — the
        // Key + IdentityOccurrence planes) gets through a busy link instead of
        // contending and losing the retry window. Routed EXACTLY like a resource
        // frame (same attribution + inbound sink), so `route_replication_frame`
        // dispatches it identically — the sender chose packet-vs-resource purely
        // on payload size; the receiver need not care which arrived.
        //
        // The link-Channel send ships via the link's CHANNEL, so it arrives as
        // `MessageReceived` (the channel-demuxed variant), NOT the raw
        // `LinkDataReceived`. We route BOTH: any bytes delivered over an
        // established link are candidate replication frames (CRPL-gated
        // downstream in `route_replication_frame`; a non-CRPL message falls
        // through to envelope dispatch, exactly as a resource frame does).
        NodeEvent::MessageReceived { link_id, data, .. }
        | NodeEvent::LinkDataReceived { link_id, data } => {
            if data.is_empty() {
                // CIRISEdge#425 — an empty packet on the link-Channel path was a
                // silent `return` too; route it through the choke point.
                drop_inbound(
                    Some(link_id),
                    "empty-packet",
                    "inbound link packet had no data",
                );
                return;
            }
            tracing::debug!(
                link = ?link_id,
                bytes = data.len(),
                "inbound link packet received (reverse-path reply, CIRISEdge#353 ask #2)",
            );
            attribute_and_deliver(ctx, link_id, data).await;
        }
        NodeEvent::LinkClosed {
            link_id, reason, ..
        } => {
            ctx.established_links.lock().await.remove(&link_id);
            ctx.link_established_at.lock().await.remove(&link_id);
            // v3.5.1 (CIRISEdge#119 + #120) — drop the link's rooted
            // peer attribution when the link closes.
            ctx.link_to_peer_key_id.lock().await.remove(&link_id);
            // CIRISEdge#353 — drop the link's last-inbound stamp too, so a
            // closed link can never win the reverse-path selector.
            ctx.link_last_inbound_at.lock().await.remove(&link_id);
            // CIRISEdge#424 — drop the dialed-dest record for the closed link.
            ctx.dialed_link_dest.lock().await.remove(&link_id);
            tracing::debug!(link = ?link_id, reason = ?reason, "link closed");
            // CIRISEdge#34 link half (v0.14.0) — emit `link_closed`
            // event. Severity reflects whether the close was graceful.
            //
            // CIRISEdge#460 — `Stale` (idle-timeout reap) is ROUTINE, like
            // `Normal`: it is the authoritative close of a link idled out at
            // 60/90s, not a fault. Only reasons that indicate a real problem
            // (Timeout / InvalidProof / ChannelExhausted / Blackholed, and
            // PeerClosed as the peer's unilateral teardown) stay `Warning`.
            if let Some(bus) = ctx.event_bus {
                bus.emit_link(link_event(
                    crate::events::EventKind::LinkDropped,
                    &link_id,
                    None,
                    link_close_severity(reason),
                    format!("link closed: {reason:?}"),
                ));
            }
        }
        // CIRISEdge#169 — the LXMF propagation HOST serve path.
        //
        // The decision is made by `LxmfServeNode`, which is sans-I/O: no async,
        // no `.await`, no clock of its own. This arm does the I/O and nothing
        // else — which is why the serve logic can be exhaustively tested
        // without a node, and why no lock can cross a suspension point here.
        #[cfg(feature = "lxmf")]
        NodeEvent::RequestReceived {
            link_id,
            request_id,
            ref path,
            ref data,
            ..
        } if path == crate::transport::lxmf_serve::MESSAGE_GET_PATH => {
            let Some(serve) = ctx.lxmf_serve.get() else {
                // Not configured to carry third-party mail. Declining is the
                // DEFAULT posture (`PropagationAudience::Disabled`), not a
                // fault, so this is a trace rather than a withhold: nothing
                // was refused, because nothing was ever offered.
                tracing::trace!(
                    %path,
                    "LXMF propagation request on a node that carries no third-party mail"
                );
                return;
            };

            // The requester is the LINK's own remote identity — never a
            // wire-supplied field. A propagation node that took the requester
            // from the request body would serve any mailbox on demand, which
            // is the whole attack the per-recipient scoping exists to stop.
            let requester = ctx.node.get_remote_identity(&link_id).map(|id| {
                let mut out = [0u8; leviculum_lxmf::constants::DESTINATION_LENGTH];
                out.copy_from_slice(&id.hash()[..leviculum_lxmf::constants::DESTINATION_LENGTH]);
                out
            });

            let result = serve.serve_get(requester, data, std::time::Instant::now());

            // The notices carry typed `WithholdReason`s and BELONG in the
            // counted ledger — but the transport holds no `EdgeMetrics`
            // handle (`inc_withhold` is never called from this file). That is
            // the serve/inbound attribution asymmetry recorded in
            // `crate::contextual_integrity`, meeting a serve path that happens
            // to live in the event loop. Until the transport carries a metrics
            // handle these are LOUD but uncounted, which is stated rather than
            // silently accepted.
            for notice in &result.notices {
                drop_inbound(Some(link_id), notice.reason.as_str(), notice.detail);
            }

            if let ServeOutcome::Respond(ref bytes) = result.outcome {
                match ctx.node.send_response(&link_id, &request_id, bytes).await {
                    Ok(()) => {
                        // MEASURED CONTRACT (leviculum#55): `Ok` means HANDED
                        // TO THE LINK, not delivered. If the peer vanished
                        // before the link's death was processed, this returns
                        // `Ok(())` and the bytes go nowhere — and for a
                        // propagation node serving churning mobiles that is
                        // the normal case, not the edge case.
                        //
                        // So the mailbox entry is NOT dropped here. Delivery
                        // evidence has to come from the application layer —
                        // the peer's next request implying receipt — and
                        // `serve_get` is deliberately non-destructive for
                        // exactly this reason.
                        tracing::debug!(?link_id, "LXMF propagation response handed to link");
                    }
                    Err(e) => {
                        // A link known to be dead answers `LinkNotFound` — the
                        // typed signal, and the honest one.
                        drop_inbound(
                            Some(link_id),
                            "lxmf-response-undeliverable",
                            &format!("{e}"),
                        );
                    }
                }
            }
        }

        // CIRISEdge#484 — `ResponseReceived` / `RequestTimedOut` are now resolved by
        // the leviculum v0.16 completion registry (fed at the dispatch layer), so
        // `link_request` no longer mirrors them here — the events fall through to the
        // trace arm and the `request_responses` / `timed_out_requests` maps are gone.
        // CIRISEdge#508 — the control-plane loss marker, consumed. leviculum
        // drops lossless-plane events with try_send when the channel is full,
        // then delivers ONE ControlPlaneOverflow carrying the aggregate count
        // once the channel has room — the marker is the designed observable
        // and is itself never dropped. Before this arm it fell into the
        // `other =>` TRACE catch-all: the single line an operator needed was
        // invisible while ~1000 per-drop EVENT_CHANNEL_FULL warns (buried
        // 30:1 on the canonical) said nothing actionable. WARN with the
        // consequence stated; throttled (see `control_plane_overflow_log`)
        // because saturation frequency is attacker-influenceable. Dropped
        // control events mean edge may have MISSED LinkEstablished /
        // LinkClosed / AnnounceReceived — so link bookkeeping here may be
        // stale until the next event for the affected link arrives.
        NodeEvent::ControlPlaneOverflow { dropped_count } => {
            if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                control_plane_overflow_log().check("overflow")
            {
                tracing::warn!(
                    dropped_count,
                    suppressed_prev,
                    "leviculum control-plane channel overflowed: {dropped_count} lossless \
                     event(s) were DROPPED before this marker — edge may have missed link \
                     lifecycle or announce events and its link bookkeeping may be stale \
                     until the affected links next produce an event. Sustained overflow \
                     means the event consumer is stalling (leviculum#58) or the channel \
                     is undersized for this deployment — raise it via \
                     ReticulumTransportConfig::control_channel_capacity or \
                     CIRIS_EDGE_RETICULUM_CONTROL_CHANNEL_CAPACITY (CIRISEdge#508)"
                );
            }
        }
        other => {
            tracing::trace!(event = ?other, "unhandled Reticulum event");
        }
    }
}

/// CIRISEdge#460 — severity for a `LinkClosed` event, decided PURELY from the
/// [`LinkCloseReason`](leviculum_core::link::LinkCloseReason) (no I/O, unit-
/// tested over every variant). `Normal` and `Stale` (idle-timeout reap) are
/// ROUTINE link turnover → `Info`; every reason that signals a real problem
/// stays `Warning`, so a node under investigation still sees fault teardowns at
/// the level it scans. A routine reap must never train readers to skip WARN.
fn link_close_severity(
    reason: leviculum_core::link::LinkCloseReason,
) -> crate::events::EventSeverity {
    use crate::events::EventSeverity;
    use leviculum_core::link::LinkCloseReason;
    match reason {
        LinkCloseReason::Normal | LinkCloseReason::Stale => EventSeverity::Info,
        // Timeout / InvalidProof / PeerClosed / ChannelExhausted / Blackholed —
        // a real problem or the peer's unilateral teardown; keep it loud. The
        // non-exhaustive `_` also fails safe (louder) on any future variant.
        _ => EventSeverity::Warning,
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
    /// verified reroute-heal — write the incoming route AND its trust classification.
    Admit,
    /// CIRISEdge#404 — the OWNER (ownership proven) re-announced over an existing
    /// **Rooted** binding but its own announce only classified **Advisory** (a
    /// transient rooting-walk gap under churn), on a new dest/epoch. Heal the
    /// ROUTE (dest/epoch/transport-identity) but PRESERVE the established
    /// `Rooted ∧ owns_key` trust — a churn blip must never de-attribute a rooted
    /// peer. Safe: only the SAME owner reaches here (CRITICAL-1 refused the
    /// non-owning case first), and the serve gate re-roots live, so a genuine
    /// de-rooting is still refused downstream regardless of this transport-tier hint.
    AdmitRouteKeepTrust,
    /// A same-or-lower-epoch re-announce with no upgrade and no heal — ignore
    /// (stale); the cached route stands.
    IgnoreStale,
    /// CIRISEdge#337 CRITICAL-1 — an Advisory announce attempting to override a
    /// Rooted route. NEVER written: a self-signed announce (mintable for any
    /// key_id) must not repoint a directory-rooted peer at an attacker dest.
    HijackRefused,
}

/// Whether an Advisory announce's `rejection` proves the announcer OWNS the
/// federation key — i.e. its claimed pubkey MATCHED the directory row. Only
/// rejections raised AFTER the pubkey comparison qualify, so this is an
/// **allowlist** of post-match variants; everything else (including any
/// future-added variant) is fail-CLOSED.
///
/// SECURITY (v16 review, `owns_key` route-hijack): a former denylist
/// `!matches!(UnknownKeyId | PubkeyMismatch)` FAILED OPEN on `DirectoryError`.
/// persist's `root_binding` returns `DirectoryError` when a `lookup_public_key`
/// call errors — and the FIRST such lookup happens BEFORE any pubkey comparison,
/// so a first-lookup error proves NO match. It is also indistinguishable from a
/// mid-walk error by variant alone, so ALL `DirectoryError` must be fail-closed.
/// The old denylist mapped it to `owns_key=true`, letting a transient directory
/// error during a hostile announce defeat the CRITICAL-1 verified-only
/// supersession gate and hijack a Rooted peer's route.
fn owns_key_from_rooting_rejection(rejection: &RootingRejection) -> bool {
    matches!(
        rejection,
        RootingRejection::BrokenProvenanceLink { .. }
            | RootingRejection::UnsignedProvenanceLink { .. }
            | RootingRejection::NotRootedAtSteward { .. }
            | RootingRejection::TerminusNotInAnchor { .. }
            | RootingRejection::CycleDetected { .. }
            | RootingRejection::OverDepth { .. }
    )
}

/// Decide whether an incoming announce supersedes the cached route for its
/// key_id. `existing` is `(provenance, epoch, dest16)` of the cached entry (if
/// any). `incoming_owns_key` is whether the announcer PROVED control of the key
/// the directory binds to this `key_id` (Confirmed, or an Advisory whose
/// rejection is a POST-pubkey-match variant per
/// [`owns_key_from_rooting_rejection`] — i.e. the pubkey matched and the announce
/// self-verified; a pre-match rejection or a lookup `DirectoryError` is
/// fail-closed to `false`). This is the load-bearing signal that separates the
/// OWNER rerouting its own dest from a SPOOF.
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
    // CIRISEdge#404 — an OWNER's (owns_key proven; the non-owning case was just
    // refused) **Advisory** announce over an existing **Rooted** binding is a
    // transient rooting-walk gap under churn, NOT a de-rooting. It must HEAL the
    // route (owner moved dest / rotated epoch) WITHOUT downgrading the established
    // trust. Pre-#404, this fell through to `Admit` and overwrote the binding with
    // the Advisory verdict → `from_rooted_binding` then failed on the *provenance*
    // conjunct (mis-read as an `owns_key` failure) → every inbound trace frame
    // dropped `SkippedNoSourceKeyId`. If nothing about the route changed, it is a
    // plain stale re-announce (keep everything). This sits BEFORE the epoch checks
    // so it also covers a higher-epoch transport rotation whose walk transiently
    // fell to Advisory.
    if matches!(ex_prov, Rooted) && matches!(incoming_provenance, Advisory) {
        if incoming_epoch > ex_epoch || incoming_dest16 != ex_dest16 {
            return RouteSupersession::AdmitRouteKeepTrust;
        }
        return RouteSupersession::IgnoreStale;
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

/// CIRISEdge#432 — the pure heal decision: should the live entry be upgraded
/// from the durable store?
///
/// Inputs are exactly what the field produces: the live entry's operands
/// (`(Advisory, owns_key=false)` for a first-contact announce admitted at
/// `UnknownKeyId` — both production reproductions) + its link-proven transport
/// identity hash, and the store's row. The upgrade requires ALL of:
/// - the live binding actually fails `Rooted ∧ owns_key` (never touch a
///   passing binding),
/// - the store says `Rooted` (the store is authority for TRUST…),
/// - the stored transport identity equals the identity the link proved
///   (…but never for IDENTITY — a stored row binding a different transport
///   identity must not launder trust onto this link).
fn divergence_heal_decision(
    live_provenance: ciris_persist::federation::self_at_login::BindingProvenance,
    live_owns_key: bool,
    live_identity_hash: [u8; 16],
    stored: &crate::verify::StoredTransportBinding,
) -> DivergenceHeal {
    use ciris_persist::federation::self_at_login::BindingProvenance::Rooted;
    if matches!(live_provenance, Rooted) && live_owns_key {
        return DivergenceHeal::LiveAlreadyPasses;
    }
    if !matches!(stored.provenance, Rooted) {
        return DivergenceHeal::StoreNotRooted;
    }
    let x25519: [u8; 32] = stored.transport_pubkey64[..32]
        .try_into()
        .unwrap_or([0u8; 32]);
    let ed25519: [u8; 32] = stored.transport_pubkey64[32..]
        .try_into()
        .unwrap_or([0u8; 32]);
    let stored_hash =
        Identity::from_public_keys(&x25519, &ed25519).map_or([0u8; 16], |id| *id.hash());
    if stored_hash != live_identity_hash {
        return DivergenceHeal::IdentityMismatch;
    }
    DivergenceHeal::Upgrade
}

/// CIRISEdge#432 — the [`divergence_heal_decision`] verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DivergenceHeal {
    /// Live entry already passes `Rooted ∧ owns_key` — nothing to heal.
    LiveAlreadyPasses,
    /// The store does not hold a `Rooted` binding — no divergence to act on.
    StoreNotRooted,
    /// The store roots a DIFFERENT transport identity than the link proved —
    /// divergence detected but NOT healable onto this link (trust must never
    /// be laundered across identities).
    IdentityMismatch,
    /// Upgrade the live entry: `provenance = Rooted`, `owns_key = true`.
    Upgrade,
}

/// CIRISEdge#432 — attribution-failure handler: attempt the live-map divergence
/// heal against the durable store, then report whatever remains, with the
/// stored provenance alongside the resolved operands (#432 ask 3) and a hint
/// that matches its own evidence.
///
/// Runs ONLY under the caller's throttle `Emit` (first failing frame + the
/// periodic floor), so the directory point-read is flood-bounded. On a
/// successful heal the SAME frame is attributed (item 2 permitting) — the dark
/// plane converges in zero additional frames.
async fn heal_or_report_attribution_miss(
    ctx: &EventCtx<'_>,
    key_id: &str,
    resolved: Option<(
        ciris_persist::federation::self_at_login::BindingProvenance,
        bool,
        u64,
    )>,
    link_id: LinkId,
    suppressed_prev: u64,
) -> Option<crate::transport::SourceKeyId> {
    use ciris_persist::federation::self_at_login::BindingProvenance::Rooted;
    let stored = match ctx.rooting {
        Some(rooting) => rooting.stored_reticulum_binding(key_id).await,
        None => None,
    };
    // The heal arm: a live entry that fails the gate + a store that roots the
    // same link-proven identity ⇒ upgrade in place, attribute this frame.
    if let (Some((live_prov, live_ok, _)), Some(s)) = (resolved, stored.as_ref()) {
        let (decision, dest16) = {
            let mut peers = ctx.peers.lock().await;
            match peers.get_mut(key_id) {
                Some(entry) => {
                    let d = divergence_heal_decision(
                        live_prov,
                        live_ok,
                        entry.transport_identity_hash,
                        s,
                    );
                    if matches!(d, DivergenceHeal::Upgrade) {
                        entry.provenance = Rooted;
                        entry.owns_key = true;
                        entry.epoch = entry.epoch.max(s.epoch);
                    }
                    (Some(d), Some(entry.peer.dest_hash.into_bytes()))
                }
                None => (None, None),
            }
        };
        match decision {
            Some(DivergenceHeal::Upgrade) => {
                tracing::warn!(
                    link = ?link_id,
                    peer = %key_id,
                    resolved_provenance = ?live_prov,
                    resolved_owns_key = live_ok,
                    stored_epoch = s.epoch,
                    suppressed_prev,
                    "live peers map DIVERGED from the durable store — HEALED in place \
                     (resolved failed Rooted∧owns_key, store holds rooted for the SAME \
                     link-proven transport identity). This peer was admitted at Advisory \
                     on first contact and rooted through a writer that never updated the \
                     live map; pre-heal the plane stayed dark until a restart \
                     (CIRISEdge#432)"
                );
                // Item 2 still applies — the heal upgrades item 1 only.
                if let (Some(d), Some(rooting)) = (dest16, ctx.rooting) {
                    if binding_exists_cached(ctx.binding_cache, rooting, key_id, d).await {
                        return crate::transport::SourceKeyId::from_rooted_binding(
                            key_id.to_string(),
                            Rooted,
                            true,
                        );
                    }
                    tracing::warn!(
                        link = ?link_id,
                        peer = %key_id,
                        dest = %hex::encode(d),
                        "CIRISEdge#432 heal upgraded item 1, but item 2 still FAILS: no \
                         hybrid-verified SignedTransportDestination binds this (peer, dest) \
                         pair — see CIRISEdge#406 (the signed transport-dest producer gap)"
                    );
                }
                return None;
            }
            Some(DivergenceHeal::IdentityMismatch) => {
                tracing::warn!(
                    link = ?link_id,
                    peer = %key_id,
                    resolved_provenance = ?live_prov,
                    resolved_owns_key = live_ok,
                    suppressed_prev,
                    "divergence detected but NOT healed — the durable store roots a \
                     DIFFERENT transport identity than this link proved (stale rotation, \
                     or an identity-squat attempt); trust is never laundered across \
                     identities (CIRISEdge#432)"
                );
                return None;
            }
            // LiveAlreadyPasses cannot reach here (the gate would have admitted);
            // StoreNotRooted / no live entry fall through to the miss report.
            _ => {}
        }
    }
    report_attribution_miss(
        key_id,
        resolved,
        stored.as_ref().map(|s| s.provenance),
        link_id,
        suppressed_prev,
    );
    None
}

/// CIRISEdge#404/#432 — the residual miss report: the #404 voice, now carrying
/// the STORED provenance beside the resolved operands, with a hint that matches
/// its own evidence (the old unconditional "churn downgrade" hint printed
/// against `owns_key=false` operands and sent the reader to the wrong cause).
fn report_attribution_miss(
    key_id: &str,
    resolved: Option<(
        ciris_persist::federation::self_at_login::BindingProvenance,
        bool,
        u64,
    )>,
    stored_provenance: Option<ciris_persist::federation::self_at_login::BindingProvenance>,
    link_id: LinkId,
    suppressed_prev: u64,
) {
    use ciris_persist::federation::self_at_login::BindingProvenance::{Advisory, Rooted};
    if let Some((provenance, owns_key, epoch)) = resolved {
        let hint = match (provenance, owns_key) {
            (Advisory, true) => {
                "a churn downgrade (owner reroute overwrote a Rooted binding), not an \
                 owns_key failure"
            }
            (Advisory, false) => {
                "a first-contact Advisory admit whose binding never rooted in this \
                 process (CIRISEdge#432); stored_provenance names whether the durable \
                 store diverges"
            }
            (Rooted, false) => {
                "an owns_key failure — the announce could not prove control of the \
                 federation key"
            }
            (Rooted, true) => "unreachable: a passing binding does not miss",
        };
        tracing::warn!(
            link = ?link_id,
            peer = %key_id,
            resolved_provenance = ?provenance,
            resolved_owns_key = owns_key,
            resolved_epoch = epoch,
            stored_provenance = ?stored_provenance,
            suppressed_prev,
            "inbound frame NOT attributed — resolved binding fails Rooted∧owns_key; \
             these are the ACTUAL operands (CIRISEdge#404). {hint}"
        );
    } else {
        tracing::warn!(
            link = ?link_id,
            peer = %key_id,
            stored_provenance = ?stored_provenance,
            suppressed_prev,
            "inbound frame DROPPED — item 1 has NO binding in the peers map for this \
             link's key_id (candidate resolved, peers-map miss) (CIRISEdge#404 \
             link-resolution miss). A stored_provenance=Rooted here means the durable \
             store knows this peer but the live map lost it (cap eviction / restart \
             ordering) — divergence detected, not auto-installed (no link-proven \
             identity in the map to bind against) (CIRISEdge#432)"
        );
    }
}

/// CIRISEdge#436 — serve this node's own build-attestation bundle over an
/// established link, best-effort: `CFRG`-fragment the pre-encoded `CBND` frame
/// onto the link's packet path (`try_send` — the same non-contending Channel
/// the reverse-path replies ride, so it interleaves any in-flight resource
/// transfer) and let the receiver's `attribute_and_deliver` reassemble it. A
/// lost/backpressured push is recoverable (the next link-up re-serves) but
/// never silent (throttled WARN).
async fn push_own_bundle_frames(node: &ReticulumNode, own: &OwnBuildBundle, link_id: &LinkId) {
    let mdu = node.link_mdu(link_id).unwrap_or(0);
    let Some(fragments) = crate::transport::frame_fragment::fragment(&own.frame, mdu) else {
        if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
            own_bundle_push_log().check("degenerate-mdu")
        {
            tracing::warn!(
                link = ?link_id,
                mdu,
                bytes = own.frame.len(),
                suppressed_prev,
                "own build-bundle push skipped — link MDU too small to fragment; the peer \
                 cannot root us at first contact over this link (CIRISEdge#436)"
            );
        }
        return;
    };
    let total = fragments.len();
    let mut sent = 0usize;
    for frag in &fragments {
        if node.link_handle(link_id).try_send(frag).await.is_ok() {
            sent += 1;
        } else {
            break;
        }
    }
    if sent == total {
        tracing::debug!(
            link = ?link_id,
            bytes = own.frame.len(),
            fragments = total,
            "own build-attestation bundle served on link-up (CIRISEdge#436)"
        );
    } else if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
        own_bundle_push_log().check("channel-backpressure")
    {
        tracing::warn!(
            link = ?link_id,
            fragments = total,
            fragments_sent = sent,
            suppressed_prev,
            "own build-bundle push incomplete ({sent}/{total} fragments) — link Channel \
             backpressured; the peer re-receives on the next link-up (CIRISEdge#436)"
        );
    }
}

/// CIRISEdge#436 — why a link-borne peer bundle (`CBND` frame) was refused.
/// Every variant is a hard, LOUD refusal (throttled WARN on the fixed tag) and
/// leaves the peer exactly as it was: no store slot, no live-map change, no
/// durable write. Fail-closed — a refusal can never widen anything.
#[derive(Debug)]
enum PeerBundleRefusal {
    /// The frame is `CBND`-tagged but not a well-formed v1 frame, or the
    /// carried bundle has no canonicalizable `manifest_contribution`.
    Malformed(&'static str),
    /// The carried bundle exceeds [`crate::bundle_gate::MAX_PEER_BUNDLE_BYTES`]
    /// (checked before any parse/hash — cheap reject first).
    Oversized { actual: usize, limit: usize },
    /// The attributed peer has no live peers-map entry (announce not yet
    /// admitted, or evicted) — there is no announced commitment to bind to.
    PeerNotInMap,
    /// The peer's announce carried NO manifest commitment — an unsolicited
    /// package has nothing binding it to the announce; today's (pre-#436)
    /// path stays untouched.
    NoAnnouncedCommitment,
    /// The package's manifest hashes to a DIFFERENT value than the announced
    /// commitment — the announce→package binding failed (evidence swap /
    /// stale bundle).
    CommitmentMismatch,
    /// The link's proven identity (or, for a link we dialed, its dialed
    /// destination) does not match the live entry — trust is never laundered
    /// across identities (the #432 heal's exact rule).
    LinkBindingMismatch,
    /// The shape-gated store registration refused (typed).
    RegisterRefused(crate::bundle_gate::BundleRegisterError),
    /// The pins held or failed edge-side; verify's fail-closed chain (or the
    /// directory pinning that precedes it) refused the bundle.
    VerifyRefused(crate::bundle_gate::BundleGateRefusal),
}

impl PeerBundleRefusal {
    /// Low-cardinality throttle tag (fixed set, never attacker-chosen).
    fn tag(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "malformed",
            Self::Oversized { .. } => "oversized",
            Self::PeerNotInMap => "peer-not-in-map",
            Self::NoAnnouncedCommitment => "no-announced-commitment",
            Self::CommitmentMismatch => "commitment-mismatch",
            Self::LinkBindingMismatch => "link-binding-mismatch",
            Self::RegisterRefused(_) => "register-refused",
            Self::VerifyRefused(_) => "verify-refused",
        }
    }
}

impl std::fmt::Display for PeerBundleRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "malformed bundle frame: {what}"),
            Self::Oversized { actual, limit } => {
                write!(f, "bundle too large: {actual} > {limit} bytes")
            }
            Self::PeerNotInMap => write!(f, "peer has no live peers-map entry"),
            Self::NoAnnouncedCommitment => {
                write!(f, "peer's announce carried no manifest commitment")
            }
            Self::CommitmentMismatch => {
                write!(f, "package manifest hash != announced commitment")
            }
            Self::LinkBindingMismatch => {
                write!(f, "link identity/destination does not match the live entry")
            }
            Self::RegisterRefused(e) => write!(f, "store registration refused: {e}"),
            Self::VerifyRefused(r) => write!(f, "bundle verification refused: {r}"),
        }
    }
}

/// CIRISEdge#436 — typed outcome of processing a link-borne peer bundle.
#[derive(Debug)]
enum PeerBundleOutcome {
    /// The full chain held; the peer was upgraded Advisory→Rooted in ONE
    /// motion (live map + durable store). `already_passed` when the live
    /// entry was already `Rooted ∧ owns_key` (the durable half was still
    /// re-asserted — idempotent).
    Upgraded { already_passed: bool },
    /// No verdict — a typed refusal; nothing changed anywhere.
    Refused(PeerBundleRefusal),
}

/// CIRISEdge#436 — the pure link↔entry binding rule, the #432 heal's
/// identity-equality semantics applied at bundle arrival: the package may only
/// upgrade the entry whose transport identity THIS link proved.
///
/// - The link proved an identity (its `LINKIDENTIFY` / remote identity is
///   known) → that identity's hash must equal the entry's announce-derived
///   `transport_identity_hash`. Never laundered across identities.
/// - No proven identity (a link WE dialed — the initiator side, where the
///   remote never LINKIDENTIFYs to us) → the link's destination (leviculum's
///   `link_destination`, or edge's own dialed-dest record) must equal the
///   entry's announced dest: we dialed the peer's verified dest and RNS
///   establishment proved the remote controls that destination's identity
///   keys — the same basis initiator-side frame attribution stands on
///   (CIRISEdge#353/#424).
/// - Neither → no binding evidence at all; refuse.
fn peer_bundle_link_binding_ok(
    link_identity_hash: Option<[u8; 16]>,
    link_dest16: Option<[u8; 16]>,
    entry_identity_hash: [u8; 16],
    entry_dest16: [u8; 16],
) -> bool {
    match link_identity_hash {
        Some(proven) => proven == entry_identity_hash,
        None => link_dest16 == Some(entry_dest16),
    }
}

/// CIRISEdge#436 — process one link-borne build-attestation-bundle frame: the
/// arrival transport that feeds the #437 gate, and on a full verdict performs
/// the **one-motion Advisory→Rooted upgrade** (live map + durable store — the
/// #432 lesson: never two writers that diverge).
///
/// The chain, fail-closed at every step (any refusal leaves EVERYTHING as it
/// was):
///
/// 1. frame shape (`CBND` v1) + size cap (before any parse),
/// 2. the live entry's ANNOUNCED commitment must exist and equal
///    `sha256(JCS(manifest_contribution))` of the received package — the
///    commitment BINDS announce to package,
/// 3. the link↔entry binding ([`peer_bundle_link_binding_ok`] — the #432
///    identity-equality rule),
/// 4. shape-gated registration into the [`PeerBundleStore`]
///    (the #437 store — a later gated Rooted save reuses the cached verdict),
/// 5. the full CIRISVerify#181 chain via
///    [`RootingDirectory::verify_peer_build_bundle`] (presenter = THIS peer's
///    directory row; pipeline + accord anchors pinned from the directory),
/// 6. on ELIGIBLE: live entry → `Rooted ∧ owns_key`, and the durable
///    write-through — routed through [`gated_save_provenance`], the single
///    #437 choke every Rooted durable save runs (a cache-hit here, since the
///    verdict was just cached) — with the SAME operands the live entry holds.
///
/// What the verdict does NOT prove stays advisory exactly as CIRISVerify#181
/// frames it: this is the artifact chain to the shared trust root (L1), never
/// remote-execution proof — the peer's self-report of *running* the validated
/// binary is Advisory forever (no Rooted bit derives from it anywhere here).
///
/// [`PeerBundleStore`]: crate::bundle_gate::PeerBundleStore
/// [`gated_save_provenance`]: crate::bundle_gate::gated_save_provenance
// The parameter list IS the test seam: exactly the operands the wrapper reads
// off the EventCtx, split out so the field-provenance tests can drive the full
// chain against a real `MemoryBackend` + peers map without a live node
// (the #424 "the layer the loopback harness cannot reach" lesson).
#[allow(clippy::too_many_arguments)]
async fn process_peer_bundle_frame(
    frame: &[u8],
    key_id: &str,
    link_identity_hash: Option<[u8; 16]>,
    link_dest16: Option<[u8; 16]>,
    peers: &Mutex<HashMap<String, RootedPeer>>,
    bundles: &crate::bundle_gate::PeerBundleStore,
    rooting: &dyn RootingDirectory,
    gate: crate::bundle_gate::BundleSaveGateMode,
) -> PeerBundleOutcome {
    use PeerBundleOutcome::Refused;

    let Some(bundle_bytes) = crate::transport::peer_bundle_frame::decode(frame) else {
        return Refused(PeerBundleRefusal::Malformed("not a CBND v1 frame"));
    };
    if bundle_bytes.len() > crate::bundle_gate::MAX_PEER_BUNDLE_BYTES {
        return Refused(PeerBundleRefusal::Oversized {
            actual: bundle_bytes.len(),
            limit: crate::bundle_gate::MAX_PEER_BUNDLE_BYTES,
        });
    }
    // Snapshot the entry's decision operands; the lock is NOT held across the
    // hash / registration / directory verification below.
    let snapshot = {
        let peers = peers.lock().await;
        peers.get(key_id).map(|e| {
            (
                e.manifest_commitment,
                e.transport_identity_hash,
                e.peer.dest_hash.into_bytes(),
            )
        })
    };
    let Some((announced, entry_identity_hash, entry_dest16)) = snapshot else {
        return Refused(PeerBundleRefusal::PeerNotInMap);
    };
    let Some(announced) = announced else {
        return Refused(PeerBundleRefusal::NoAnnouncedCommitment);
    };
    if !peer_bundle_link_binding_ok(
        link_identity_hash,
        link_dest16,
        entry_identity_hash,
        entry_dest16,
    ) {
        return Refused(PeerBundleRefusal::LinkBindingMismatch);
    }
    let Some(computed) = crate::bundle_gate::manifest_commitment_of_bundle(bundle_bytes) else {
        return Refused(PeerBundleRefusal::Malformed(
            "no canonicalizable manifest_contribution in the carried bundle",
        ));
    };
    if computed != announced {
        return Refused(PeerBundleRefusal::CommitmentMismatch);
    }
    if let Err(e) = bundles.register(key_id, bundle_bytes) {
        return Refused(PeerBundleRefusal::RegisterRefused(e));
    }
    match rooting.verify_peer_build_bundle(key_id, bundle_bytes).await {
        crate::bundle_gate::BundleGateVerdict::Refused(refusal) => {
            // The bundle stays registered (shape-passed); refusals are never
            // cached, so a directory row replicating in later un-sticks the
            // #437 gate — but NO upgrade happens now (fail-closed).
            Refused(PeerBundleRefusal::VerifyRefused(refusal))
        }
        crate::bundle_gate::BundleGateVerdict::Verified(verdict) => {
            bundles.note_verified(key_id, crate::bundle_gate::sha256_of(bundle_bytes));
            commit_one_motion_upgrade(
                key_id,
                link_identity_hash,
                link_dest16,
                peers,
                bundles,
                rooting,
                gate,
                &verdict,
            )
            .await
        }
    }
}

/// CIRISEdge#436 — **the one-motion upgrade site**: with the bundle verdict in
/// hand, flip the peer Advisory→Rooted in the live map AND the durable store as
/// one write sequence with ONE set of operands (the #432 lesson: never two
/// writers that diverge).
///
/// Live half: re-take the lock, re-check the link↔entry binding against the
/// CURRENT entry (it may have been superseded during the directory round-trip
/// — never upgrade an entry the link no longer binds), flip
/// `Rooted ∧ owns_key`, and snapshot the durable operands FROM THE SAME ENTRY.
///
/// Durable half: through [`gated_save_provenance`] — the single #437 choke
/// every Rooted durable save runs (gate Off → Rooted untouched; gate ON → a
/// cache-hit on the verdict the caller just cached) — then
/// `persist_transport_binding` with the live entry's exact operands.
///
/// [`gated_save_provenance`]: crate::bundle_gate::gated_save_provenance
#[allow(clippy::too_many_arguments)] // the one-motion writer takes exactly the upgrade's operands
async fn commit_one_motion_upgrade(
    key_id: &str,
    link_identity_hash: Option<[u8; 16]>,
    link_dest16: Option<[u8; 16]>,
    peers: &Mutex<HashMap<String, RootedPeer>>,
    bundles: &crate::bundle_gate::PeerBundleStore,
    rooting: &dyn RootingDirectory,
    gate: crate::bundle_gate::BundleSaveGateMode,
    verdict: &ciris_verify_core::build_attestation_bundle::BundleVerdict,
) -> PeerBundleOutcome {
    use ciris_persist::federation::self_at_login::BindingProvenance::Rooted;
    let upgraded = {
        let mut peers = peers.lock().await;
        match peers.get_mut(key_id) {
            Some(entry)
                if peer_bundle_link_binding_ok(
                    link_identity_hash,
                    link_dest16,
                    entry.transport_identity_hash,
                    entry.peer.dest_hash.into_bytes(),
                ) =>
            {
                let already_passed = matches!(entry.provenance, Rooted) && entry.owns_key;
                entry.provenance = Rooted;
                entry.owns_key = true;
                Some((
                    already_passed,
                    entry.peer.dest_hash.into_bytes(),
                    entry.transport_pubkey64,
                    entry.epoch,
                ))
            }
            _ => None,
        }
    };
    let Some((already_passed, dest16, pubkey64, epoch)) = upgraded else {
        return PeerBundleOutcome::Refused(PeerBundleRefusal::LinkBindingMismatch);
    };
    let persist_provenance =
        crate::bundle_gate::gated_save_provenance(gate, Rooted, key_id, bundles, rooting).await;
    rooting
        .persist_transport_binding(key_id, dest16, pubkey64, persist_provenance, epoch)
        .await;
    tracing::info!(
        key_id,
        target = %verdict.build.target,
        build_id = %verdict.build.build_id,
        binary_version = %verdict.build.binary_version,
        transparency = ?verdict.transparency,
        already_passed,
        "first-contact rooting: link-borne build-attestation bundle VERIFIED against \
         the announced commitment + directory pins — Advisory→Rooted in ONE motion \
         (live map + durable store) (CIRISEdge#436). Execution self-reports remain \
         Advisory: this is the artifact chain to the shared trust root (L1), not \
         remote-execution proof"
    );
    PeerBundleOutcome::Upgraded { already_passed }
}

/// CIRISEdge#436 — the transport-side wrapper: resolve the link's binding
/// operands from the event context, run [`process_peer_bundle_frame`], and
/// speak every refusal loudly (throttled on the fixed refusal tag — a refused
/// package must never look like a stored/verified one).
async fn handle_peer_bundle_frame(
    ctx: &EventCtx<'_>,
    link_id: LinkId,
    candidate_key_id: Option<String>,
    frame: &[u8],
) {
    let Some(key_id) = candidate_key_id else {
        drop_inbound(
            Some(link_id),
            "bundle-unattributed-link",
            "a CBND bundle frame arrived on a link attributed to no peer key_id — there \
             is no announced commitment to bind it to; the peer's announce (or our dial \
             record) must land first (CIRISEdge#436)",
        );
        return;
    };
    let Some(rooting) = ctx.rooting else {
        drop_inbound(
            Some(link_id),
            "bundle-no-rooting-directory",
            "a CBND bundle frame arrived but no rooting directory is wired — nothing can \
             verify, nothing can root (fail-closed) (CIRISEdge#436)",
        );
        return;
    };
    let link_identity_hash = ctx.node.get_remote_identity(&link_id).map(|id| *id.hash());
    let link_dest16 = match ctx.node.link_destination(&link_id) {
        Some(d) => Some(d.into_bytes()),
        None => ctx
            .dialed_link_dest
            .lock()
            .await
            .get(&link_id)
            .map(|d| d.into_bytes()),
    };
    match process_peer_bundle_frame(
        frame,
        &key_id,
        link_identity_hash,
        link_dest16,
        ctx.peers,
        ctx.peer_bundles,
        rooting,
        ctx.bundle_save_gate,
    )
    .await
    {
        PeerBundleOutcome::Upgraded { already_passed } => {
            // The one-motion success already logged (INFO, with the verified
            // build facts) inside `process_peer_bundle_frame`.
            tracing::debug!(
                link = ?link_id,
                peer = %key_id,
                already_passed,
                "peer bundle frame consumed — one-motion upgrade path complete (CIRISEdge#436)"
            );
        }
        PeerBundleOutcome::Refused(refusal) => {
            if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                peer_bundle_arrival_log().check(refusal.tag())
            {
                tracing::warn!(
                    link = ?link_id,
                    peer = %key_id,
                    refusal = %refusal,
                    suppressed_prev,
                    "link-borne build-attestation bundle REFUSED — no store slot taken \
                     beyond shape-registration, no live-map change, no durable write \
                     (fail-closed; the peer stays exactly as admitted) (CIRISEdge#436)"
                );
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn resolve_announce_cold_start(
    announce: leviculum_core::ReceivedAnnounce,
    ctx: &AnnounceCtx,
) {
    use ciris_persist::federation::self_at_login::BindingProvenance;
    // Step 0 — the cold-start path needs the persist directory. With
    // no rooting backend the announce cannot be authenticated; drop
    // it (fail-honest — never fall back to TOFU).
    let Some(rooting) = ctx.rooting.as_deref() else {
        // CIRISEdge#425 — no rooting directory means EVERY announce is dropped, so
        // no peer can ever root: the mesh silently never forms. A floored WARN
        // (fixed discriminant — one config condition) so a misconfigured node says
        // so periodically instead of dropping every announce at debug.
        if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
            link_attribution_miss_log().check("announce-no-rooting-directory")
        {
            tracing::warn!(
                suppressed_prev,
                "announce DROPPED — no rooting directory configured on this transport, so \
                 NO peer can ever root (the mesh cannot form). Wire a RootingDirectory on \
                 the Edge builder (CIRISEdge#425)"
            );
        }
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
            if let Some(bus) = ctx.event_bus.as_deref() {
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
                if let Some(bus) = ctx.event_bus.as_deref() {
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
            // SECURITY (v16 review): owns_key is an ALLOWLIST of post-pubkey-match
            // rejections — a lookup `DirectoryError` (or any pre-match rejection)
            // does NOT prove the announcer owns the key, so it is fail-closed here.
            let owns_key = owns_key_from_rooting_rejection(&rejection);
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
    // CIRISEdge#404 — the provenance actually WRITTEN + persisted. Normally the
    // incoming verdict, but an `AdmitRouteKeepTrust` route-heal preserves the
    // existing Rooted trust (set inside that arm), so the boot-reloaded binding
    // keeps its Rooted classification rather than the transient Advisory.
    let mut persist_provenance = provenance;
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
                // CIRISEdge#436 — an OWNER's otherwise-stale re-announce may still
                // rotate its manifest commitment (a binary upgrade with no epoch
                // bump / dest change). Metadata-only refresh: not trust-bearing
                // (the bundle still has to verify the full chain) and gated on
                // proven ownership, so a spoofer can never repoint a victim's
                // commitment (its announce fails `owns_key` upstream).
                if owns_key {
                    if let Some(existing) = peers.get_mut(&key_id) {
                        if existing.manifest_commitment != attestation.manifest_commitment {
                            existing.manifest_commitment = attestation.manifest_commitment;
                            tracing::debug!(
                                key_id = %key_id,
                                "manifest commitment refreshed from an owner's stale \
                                 re-announce (CIRISEdge#436)"
                            );
                        }
                    }
                }
                tracing::trace!(
                    key_id = %key_id,
                    announce_epoch = attestation.epoch,
                    "stale re-announce ignored (epoch not newer, no provenance upgrade, \
                     no verified reroute)",
                );
                None
            }
            // CIRISEdge#404 — heal the ROUTE of a Rooted binding whose owner's
            // re-announce transiently classified Advisory, WITHOUT downgrading the
            // trust. Update the route fields in place; provenance/owns_key/chain
            // stand. This is the fix for the epoch-0-churn de-attribution that
            // stalled the ladder at `4.ship=0`.
            RouteSupersession::AdmitRouteKeepTrust => {
                if let Some(existing) = peers.get_mut(&key_id) {
                    existing.peer = resolved;
                    existing.epoch = attestation.epoch;
                    existing.transport_identity_hash = transport_identity_hash;
                    // #436 — the identity + commitment follow the healed route
                    // (the pubkey64 is what the identity hash above hashes; the
                    // commitment is the owner's current one).
                    existing.transport_pubkey64 = binding_pubkey64;
                    existing.manifest_commitment = attestation.manifest_commitment;
                    // Persist the PRESERVED Rooted provenance, not the incoming
                    // Advisory verdict, so a boot-reload keeps the binding rooted.
                    persist_provenance = existing.provenance;
                }
                if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                    route_supersession_log().check("reroute_healed_keep_trust")
                {
                    tracing::info!(
                        key_id = %key_id,
                        new_dest = %hex::encode(announced_dest16),
                        epoch = attestation.epoch,
                        suppressed_prev,
                        "route HEALED, trust PRESERVED — an owner's Advisory re-announce \
                         updated a Rooted binding's route without downgrading it \
                         (CIRISEdge#404); inbound frames stay attributed under churn"
                    );
                }
                Some(key_id.clone())
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
                if let Some(tracker) = ctx.reachability.as_ref() {
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
                if let Some(bus) = ctx.event_bus.as_deref() {
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
                        // #393 — captured from the admit verdict (destructured at
                        // the `match verdict` above): Confirmed ⇒ true; Advisory ⇒
                        // true only when the pubkey matched + self-sig verified.
                        owns_key,
                        // #436 — the announce's own 64-byte transport identity
                        // (what `transport_identity_hash` hashes) + the manifest
                        // commitment it carried, consumed by the link-borne
                        // bundle's one-motion Advisory→Rooted upgrade.
                        transport_pubkey64: binding_pubkey64,
                        manifest_commitment: attestation.manifest_commitment,
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
        // CIRISEdge#437 — the bundle gate on the DURABLE save, and ONLY the
        // durable save: the live-map entry inserted above keeps its verdict
        // (routing ≠ trust). Gate Off, or an Advisory save → returns
        // `persist_provenance` untouched (today's behavior byte-identical).
        // Gate ON + Rooted → requires a verified build-attestation bundle
        // for this peer, else the SAVE downgrades to Advisory with a loud
        // named warn (see `crate::bundle_gate::gated_save_provenance`).
        let persist_provenance = crate::bundle_gate::gated_save_provenance(
            ctx.bundle_save_gate,
            persist_provenance,
            &persisted_key,
            &ctx.peer_bundles,
            rooting,
        )
        .await;
        // CIRISEdge#317 — persist the TRANSPORT identity (binding_pubkey64), not
        // `announce.public_key()` (the federation identity), so the boot-reloaded
        // binding resolves + seals to the identity the link proves.
        rooting
            .persist_transport_binding(
                &persisted_key,
                dest_hash16,
                binding_pubkey64,
                // CIRISEdge#404 — the EFFECTIVE provenance (an AdmitRouteKeepTrust
                // heal preserves the existing Rooted, not the incoming Advisory).
                persist_provenance,
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
    // CIRISEdge#436 — this node's own bundle manifest commitment; `Some`
    // upgrades the wire to v2 (v1 + trailing 32 B). Not part of the SIGNED
    // payload (see `AnnounceAttestation::manifest_commitment`), so the
    // signature domain is unchanged either way.
    manifest_commitment: Option<[u8; 32]>,
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
        manifest_commitment,
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
/// All branches return a constructed `leviculum_std::Identity`.
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

    let identity = leviculum_std::generate_identity();
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
/// CIRISEdge#492 — apply a TCP SERVER interface's scoped-transit posture to the
/// leviculum builder. THE single source of truth for the `(transit, ifac)` →
/// builder-method mapping, shared by [`apply_interface_config`] (typed path) and
/// the node-wide legacy path so the two can never diverge on a security-relevant
/// predicate. IFAC-only → `add_tcp_server_ifac`; no-transit-only →
/// `add_tcp_server_no_transit`; the IFAC+no-transit combo (a member-only LEAF
/// port — no convenience method covers it) → the general `add_interface_config`.
fn apply_tcp_server_transit(
    builder: ReticulumNodeBuilder,
    addr: SocketAddr,
    transit: Option<bool>,
    ifac: Option<&IfacConfig>,
) -> ReticulumNodeBuilder {
    match (ifac, transit == Some(false)) {
        (Some(ifac), true) => {
            builder.add_interface_config(leviculum_std::config::InterfaceConfig {
                interface_type: "TCPServerInterface".to_string(),
                name: "TCP Server".to_string(),
                listen_ip: Some(addr.ip().to_string()),
                listen_port: Some(addr.port()),
                transit: Some(false),
                networkname: ifac.networkname.clone(),
                passphrase: Some(ifac.passphrase.clone()),
                ifac_size: Some(ifac.ifac_size),
                ..Default::default()
            })
        }
        (Some(ifac), false) => builder.add_tcp_server_ifac(
            addr,
            ifac.networkname.as_deref(),
            &ifac.passphrase,
            ifac.ifac_size,
        ),
        (None, true) => builder.add_tcp_server_no_transit(addr),
        (None, false) => builder.add_tcp_server(addr),
    }
}

/// CIRISEdge#492 — apply a TCP CLIENT interface's scoped-transit posture.
/// leviculum has `add_tcp_client_ifac` but NO `add_tcp_client_no_transit`, so any
/// no-transit client (with or without IFAC) rides `add_interface_config`.
fn apply_tcp_client_transit(
    builder: ReticulumNodeBuilder,
    addr: SocketAddr,
    transit: Option<bool>,
    ifac: Option<&IfacConfig>,
) -> ReticulumNodeBuilder {
    match (ifac, transit == Some(false)) {
        (ifac_opt, true) => builder.add_interface_config(leviculum_std::config::InterfaceConfig {
            interface_type: "TCPClientInterface".to_string(),
            name: "TCP Client".to_string(),
            target_host: Some(addr.ip().to_string()),
            target_port: Some(addr.port()),
            transit: Some(false),
            networkname: ifac_opt.as_ref().and_then(|i| i.networkname.clone()),
            passphrase: ifac_opt.as_ref().map(|i| i.passphrase.clone()),
            ifac_size: ifac_opt.as_ref().map(|i| i.ifac_size),
            ..Default::default()
        }),
        (Some(ifac), false) => builder.add_tcp_client_ifac(
            addr,
            ifac.networkname.as_deref(),
            &ifac.passphrase,
            ifac.ifac_size,
        ),
        (None, false) => builder.add_tcp_client(addr),
    }
}

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
            use leviculum_std::interfaces::auto_interface::AutoInterfaceConfig as LevAuto;
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
            // CIRISEdge#492 — scoped-transit posture via the shared mapper.
            builder =
                apply_tcp_server_transit(builder, cfg.listen_addr, cfg.transit, cfg.ifac.as_ref());
            Ok((builder, "TCPServerInterface", name))
        }
        #[cfg(feature = "transport-reticulum-tcp-client")]
        ReticulumInterfaceConfig::TcpClient(cfg) => {
            let name = format!("tcp-client-{}", cfg.target_addr);
            // CIRISEdge#492 — scoped-transit posture via the shared mapper.
            builder =
                apply_tcp_client_transit(builder, cfg.target_addr, cfg.transit, cfg.ifac.as_ref());
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
            // packet) when an I²P interface is supplied: the feature
            // compiling must NEVER read as I²P working.
            Err(TransportError::Config(format!(
                "I²P interface configured (sam_addr: {:?}) but the \
                 transport-reticulum-i2p feature compiles ONLY the typed config \
                 surface — the Phase 3 runtime is NOT WIRED and no SAM session \
                 will be established. Remove the I²P interface (or build without \
                 the feature). See FSD §1.4 OQ-13 for the Phase 3 roadmap.",
                cfg.sam_addr,
            )))
        }
    }
}

// ─── Blackhole consult + opportunistic prune ────────────────────────

/// Verdict of consulting the deny-list snapshot for one identity.
/// Produced by [`consult_and_prune_blackhole`]; consumed by
/// `check_blackhole` on the send path.
enum BlackholeConsult {
    /// No rule for this identity — send proceeds.
    Clear,
    /// A rule matched but its `until` has passed. The spent row was
    /// reclaimed (best-effort) at consult time — send proceeds, and the
    /// caller must invalidate its deny-list snapshot cache so the next
    /// dial does not re-see (and re-prune) the removed row.
    ExpiredPruned,
    /// Live rule — send refused; the caller records the hit and builds
    /// the typed `PeerBlackholed` error.
    Blocked {
        /// Operator-readable reason from the rule row.
        reason: Option<String>,
        /// Soft-expiry from the rule row (`None` = permanent).
        until: Option<chrono::DateTime<chrono::Utc>>,
    },
}

/// Scan the deny-list snapshot for `identity_hash` and, when the
/// matching rule is EXPIRED, reclaim its row IMMEDIATELY (opportunistic
/// prune) instead of letting the send proceed while the row accretes.
///
/// Pre-audit, the expired branch returned "proceed" and left the row
/// for the background pruner / a manual `routing_blackhole_prune_expired`
/// call — on a hosting shape with neither running, expired rows grew
/// without bound on a hot send path. The remove is awaited inline (one
/// row delete) rather than spawned: it is amortized to at most one
/// round-trip per expired rule, because the caller invalidates its
/// snapshot cache on the [`BlackholeConsult::ExpiredPruned`] verdict so
/// subsequent dials never re-consult the reclaimed row. Removal failure
/// is non-fatal (WARN; the send still proceeds — the rule IS expired).
///
/// Permanent rules (`until = None`) never reach the prune branch — they
/// block forever until an explicit `routing_blackhole_remove`. Rules
/// for OTHER identities are never touched here, expired or not (the
/// scan is a consult, not a sweep — the background pruner owns the
/// sweep). No bounded-size backstop is possible at this seam: the table
/// is persist's durable `cirislens.blackhole_rules` behind
/// `Arc<dyn BlackholeRules>`, whose trait surface exposes no capacity
/// bound — reclamation (this fn + the `Edge::run` pruner) is the bound.
///
/// Free fn (not a method) so the audit-required test — insert expired
/// rule, consult, assert REMOVED — runs against an in-memory
/// `BlackholeRules` without constructing a live transport.
async fn consult_and_prune_blackhole(
    store: &Arc<dyn ciris_persist::federation::BlackholeRules>,
    rows: &[ciris_persist::federation::BlackholeRecord],
    identity_hash: &[u8],
    now: chrono::DateTime<chrono::Utc>,
) -> BlackholeConsult {
    for rec in rows {
        if rec.identity_hash != identity_hash {
            continue;
        }
        if let Some(until) = rec.until {
            if now >= until {
                if let Err(e) = store.blackhole_remove(identity_hash).await {
                    tracing::warn!(
                        ?identity_hash,
                        error = %e,
                        "expired blackhole rule consulted but could not be \
                         reclaimed; send proceeds — the row lingers until the \
                         next consult or background prune",
                    );
                } else {
                    tracing::debug!(
                        ?identity_hash,
                        until = %until,
                        "expired blackhole rule reclaimed at consult time \
                         (opportunistic prune)",
                    );
                }
                return BlackholeConsult::ExpiredPruned;
            }
        }
        return BlackholeConsult::Blocked {
            reason: rec.reason.clone(),
            until: rec.until,
        };
    }
    BlackholeConsult::Clear
}

// ─── Runtime-agnostic timeout helper ────────────────────────────────

/// Bound `fut` by `dur`, returning `None` on timeout. Runtime-agnostic:
/// `futures_timer::Delay` carries its OWN timer thread, so this needs NO tokio
/// Timer driver — unlike `tokio::time::timeout`.
///
/// CIRISEdge#217/#484 — the leviculum v0.16 completion futures (`connect_awaited`
/// etc.) that retired edge's six poll loops are Timer-free themselves, but the dial
/// paths still need a CALLER bound (leviculum's own establishment timeout, scaled
/// for LoRa + retries, is longer than edge's budget). Those dial paths can be
/// awaited on a thread whose tokio thread-locals belong to persist's runtime — the
/// #217 bootstrapping-node case — where `tokio::time::*` panics "no reactor
/// running", so the bound is `futures_timer`-based, the same rationale the retired
/// `wait_until_async` poll helper carried.
async fn with_timeout<F: std::future::Future>(dur: Duration, fut: F) -> Option<F::Output> {
    tokio::pin!(fut);
    tokio::select! {
        out = &mut fut => Some(out),
        () = futures_timer::Delay::new(dur) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Audit item 9 — opportunistic blackhole-rule pruning: an expired
    /// rule consulted on the send path is REMOVED then, not left to
    /// accrete for a background task that may never run.
    mod blackhole_opportunistic_prune {
        use super::*;
        use chrono::Utc;
        use ciris_persist::federation::{BlackholeRecord, BlackholeRules};
        use std::sync::Mutex as StdMutex;

        /// Minimal in-memory `BlackholeRules` — exactly enough store to
        /// prove the consult removes (or preserves) rows. Methods the
        /// consult path never drives are `unreachable!` so an accidental
        /// call fails the test loudly instead of faking success.
        struct MemRules(StdMutex<Vec<BlackholeRecord>>);

        impl MemRules {
            fn with(rows: Vec<BlackholeRecord>) -> Arc<Self> {
                Arc::new(Self(StdMutex::new(rows)))
            }
            fn rows(&self) -> Vec<BlackholeRecord> {
                self.0.lock().unwrap().clone()
            }
        }

        #[async_trait::async_trait]
        impl BlackholeRules for MemRules {
            async fn blackhole_list(
                &self,
            ) -> Result<Vec<BlackholeRecord>, ciris_persist::federation::Error> {
                Ok(self.rows())
            }
            async fn blackhole_upsert(
                &self,
                _identity_hash: &[u8],
                _until: Option<chrono::DateTime<Utc>>,
                _reason: Option<&str>,
            ) -> Result<(), ciris_persist::federation::Error> {
                unreachable!("consult path never upserts")
            }
            async fn blackhole_remove(
                &self,
                identity_hash: &[u8],
            ) -> Result<(), ciris_persist::federation::Error> {
                self.0
                    .lock()
                    .unwrap()
                    .retain(|r| r.identity_hash != identity_hash);
                Ok(())
            }
            async fn blackhole_record_hit(
                &self,
                _identity_hash: &[u8],
            ) -> Result<(), ciris_persist::federation::Error> {
                Ok(())
            }
            async fn blackhole_prune_expired(
                &self,
                _now: chrono::DateTime<Utc>,
            ) -> Result<u64, ciris_persist::federation::Error> {
                unreachable!("consult path prunes opportunistically, not by sweep")
            }
        }

        fn rule(byte: u8, until: Option<chrono::DateTime<Utc>>) -> BlackholeRecord {
            BlackholeRecord {
                identity_hash: vec![byte; 16],
                until,
                reason: Some("test".into()),
                added_at: Utc::now(),
                hits: 0,
                persist_row_hash: String::new(),
            }
        }

        /// The audit-required shape: insert expired rule → consult →
        /// assert removed (and the send proceeds).
        #[tokio::test]
        async fn expired_rule_is_reclaimed_on_consult() {
            let mem = MemRules::with(vec![rule(
                0xAA,
                Some(Utc::now() - chrono::Duration::seconds(60)),
            )]);
            let store: Arc<dyn BlackholeRules> = mem.clone();
            let rows = store.blackhole_list().await.unwrap();
            let verdict = consult_and_prune_blackhole(&store, &rows, &[0xAA; 16], Utc::now()).await;
            assert!(matches!(verdict, BlackholeConsult::ExpiredPruned));
            assert!(
                mem.rows().is_empty(),
                "the expired row must be REMOVED at consult time, not left \
                 for a background pruner that may never run"
            );
        }

        #[tokio::test]
        async fn live_rule_blocks_and_is_not_pruned() {
            let mem = MemRules::with(vec![rule(
                0xAA,
                Some(Utc::now() + chrono::Duration::seconds(3600)),
            )]);
            let store: Arc<dyn BlackholeRules> = mem.clone();
            let rows = store.blackhole_list().await.unwrap();
            let verdict = consult_and_prune_blackhole(&store, &rows, &[0xAA; 16], Utc::now()).await;
            assert!(matches!(verdict, BlackholeConsult::Blocked { .. }));
            assert_eq!(mem.rows().len(), 1, "a live rule is never reclaimed");
        }

        #[tokio::test]
        async fn permanent_rule_blocks_and_is_never_pruned() {
            let mem = MemRules::with(vec![rule(0xAA, None)]);
            let store: Arc<dyn BlackholeRules> = mem.clone();
            let rows = store.blackhole_list().await.unwrap();
            let verdict = consult_and_prune_blackhole(&store, &rows, &[0xAA; 16], Utc::now()).await;
            assert!(
                matches!(verdict, BlackholeConsult::Blocked { until: None, .. }),
                "until = NULL is the operator's permanent signal"
            );
            assert_eq!(mem.rows().len(), 1);
        }

        #[tokio::test]
        async fn other_identitys_expired_rule_is_left_alone() {
            let mem = MemRules::with(vec![rule(
                0xAA,
                Some(Utc::now() - chrono::Duration::seconds(60)),
            )]);
            let store: Arc<dyn BlackholeRules> = mem.clone();
            let rows = store.blackhole_list().await.unwrap();
            // Consult a DIFFERENT identity: verdict Clear, and the scan is
            // a consult, not a sweep — the unrelated expired row stays for
            // its own consult / the background pruner.
            let verdict = consult_and_prune_blackhole(&store, &rows, &[0xBB; 16], Utc::now()).await;
            assert!(matches!(verdict, BlackholeConsult::Clear));
            assert_eq!(mem.rows().len(), 1);
        }
    }

    /// CIRISEdge#460 — the `LinkClosed` severity mapping. Routine turnover
    /// (`Normal`, `Stale`) is `Info`; every fault reason is `Warning`. Pins that
    /// a routine idle reap never re-enters the WARN stream (70% of the server's
    /// log was this) and that fault teardowns stay loud. `LinkCloseReason` is
    /// `#[non_exhaustive]`, so production and this table both fail SAFE (a
    /// future/unknown reason → `Warning`, verified via a synthetic default arm).
    #[test]
    fn link_close_severity_is_info_only_for_routine_turnover() {
        use crate::events::EventSeverity::{Info, Warning};
        use leviculum_core::link::LinkCloseReason;
        let table = [
            (LinkCloseReason::Normal, Info),
            (LinkCloseReason::Stale, Info),
            (LinkCloseReason::Timeout, Warning),
            (LinkCloseReason::InvalidProof, Warning),
            (LinkCloseReason::PeerClosed, Warning),
            (LinkCloseReason::ChannelExhausted, Warning),
            (LinkCloseReason::Blackholed, Warning),
        ];
        for (reason, expected) in table {
            assert_eq!(
                link_close_severity(reason),
                expected,
                "LinkCloseReason::{reason:?} severity regressed (CIRISEdge#460)"
            );
        }
    }

    // ── CIRISEdge#424 initiator-side link attribution — the pure decision ──
    //
    // leviculum's `link_destination` returns `None` for a node's OWN dialed links,
    // so the #353 initiator arm exited at step one and dropped every inbound reply
    // `source_key_id=None` (13 reproductions/run). The failure was invisible
    // because execution took an un-instrumented outer `else`. The fix records the
    // dialed dest at connect and consults it; the decision is extracted here so it
    // is unit-testable — the layer the server's loopback round harness cannot reach.
    /// CIRISEdge#425 structural-2 — the STRUCTURAL guard for the receive-side drop
    /// choke point. Every `return;` / `continue;` inside `attribute_and_deliver` /
    /// `handle_event` must be adjacent (≤8 lines) to a `drop_inbound(` call, a
    /// `tracing::` log, or an explicit `// choke-ok:` marker justifying a non-drop
    /// exit. A NEW bare `return;` that vanishes at default log levels — the silent
    /// receive-side drop class that cost this arc days (#414/#416/#932/#424/#425) —
    /// FAILS this pin. This is what makes the cure structural, not a convention that
    /// has now failed review five times (the issue's own argument).
    #[test]
    fn inbound_exits_are_instrumented_or_marked() {
        let src = include_str!("reticulum.rs");
        let lines: Vec<&str> = src.lines().collect();
        let mut violations: Vec<String> = Vec::new();
        for sig in ["async fn attribute_and_deliver(", "async fn handle_event("] {
            let start = lines
                .iter()
                .position(|l| l.starts_with(sig))
                .unwrap_or_else(|| panic!("characterization pin: fn not found: {sig}"));
            // Body ends at the next column-0 closing brace.
            let end = lines[start + 1..]
                .iter()
                .position(|l| l.starts_with('}'))
                .map_or(lines.len(), |p| start + 1 + p);
            for (offset, raw) in lines[start..end].iter().enumerate() {
                let line = raw.trim();
                if line.starts_with("//") {
                    continue; // comments that mention `return;` are not exits
                }
                if line != "return;" && line != "continue;" {
                    continue;
                }
                let idx = start + offset;
                let lo = idx.saturating_sub(8);
                let window = lines[lo..=idx].join("\n");
                let instrumented = window.contains("drop_inbound(")
                    || window.contains("tracing::")
                    || window.contains("choke-ok");
                if !instrumented {
                    violations.push(format!("{sig} @ line {}: `{line}`", idx + 1));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "CIRISEdge#425 — un-instrumented inbound exit(s); route through `drop_inbound(...)` \
             or a `tracing::` log, or annotate `// choke-ok: <why it is not a silent drop>`:\n{}",
            violations.join("\n")
        );
    }

    mod initiator_attribution {
        use super::*;

        fn dh(b: u8) -> DestinationHash {
            DestinationHash::new([b; 16])
        }

        #[test]
        fn identified_table_wins_even_with_a_dest() {
            // A peer dialed us: the `LinkIdentified` table is authoritative and the
            // dest map is not even consulted.
            let out = resolve_link_attribution(Some("peer-a".into()), Some(dh(1)), |_| {
                panic!("peer_for_dest must not be consulted when identified")
            });
            assert_eq!(out, LinkAttribution::ViaIdentified("peer-a".into()));
        }

        #[test]
        fn own_dialed_link_resolves_via_recorded_dest() {
            // THE #424 FIX: no `LinkIdentified` (we dialed the link), but the dest
            // edge recorded at connect maps back to the peer — attribution now
            // succeeds where leviculum's `link_destination`=None used to drop it.
            let out = resolve_link_attribution(None, Some(dh(7)), |d| {
                (d == dh(7)).then(|| "canonical-1".to_string())
            });
            assert_eq!(out, LinkAttribution::ViaDialedDest("canonical-1".into()));
        }

        #[test]
        fn no_dest_is_classified_not_a_silent_else() {
            // THE #424 BUG CONDITION, now a NAMED outcome: `link_destination`=None
            // AND no dialed-dest record. Must never again be an unlabelled `None`.
            let out = resolve_link_attribution(None, None, |_| {
                panic!("peer_for_dest must not be consulted with no dest")
            });
            assert_eq!(out, LinkAttribution::NoDest);
        }

        #[test]
        fn known_dest_with_no_rooted_peer_is_dest_unmatched() {
            // A dest is known but no peer matches it (not yet rooted) — a distinct,
            // logged outcome from "no dest at all".
            let out = resolve_link_attribution(None, Some(dh(9)), |_| None);
            assert_eq!(out, LinkAttribution::DestUnmatched(dh(9)));
        }
    }

    // ── CIRISEdge#353 reverse-path reply-link selection — the pure decision ──
    //
    // Field failure (Node A ↔ mobile, edge v13.5.0): the mobile churns ~10 links
    // /30 s; a NAT-dead link stays leviculum-`Active` for the stale window and is
    // the NEWEST-established, so the pre-fix selector (`max_by established_at`)
    // shipped the reply into a corpse → 120 s resource timeout → NAT-blocked dial.
    // The fix orders by last-INBOUND (RNS `last_inbound`): a dead link receives
    // nothing, so the peer's CURRENT live link wins. Pure fn ⇒ compile-fast guard.
    mod reply_link_selection {
        use super::*;

        fn lid(b: u8) -> LinkId {
            LinkId::new([b; 16])
        }

        #[test]
        fn prefers_freshest_inbound_over_newest_established() {
            let dead = lid(0xDE); // NEWEST established, but STALE inbound (NAT-dead, still Active)
            let live = lid(0x11); // older established, FRESH inbound (the peer's current link)
                                  // (link, last_inbound, established_at)
            let candidates = [(dead, 100, 200), (live, 150, 150)];
            // Pre-fix `max_by(established_at)` picks `dead`; the fix picks `live`.
            assert_eq!(select_reply_link(&candidates), Some(live));
        }

        #[test]
        fn tie_breaks_on_established_when_inbound_equal() {
            let older = lid(0x01);
            let newer = lid(0x02);
            assert_eq!(
                select_reply_link(&[(older, 100, 10), (newer, 100, 20)]),
                Some(newer)
            );
        }

        #[test]
        fn only_a_corpse_left_still_returns_it_so_the_caller_can_fast_fail() {
            // The peer's only Active link is the dead one (its fresh link is still
            // Pending). We still return it; #353b fast-fails the send so the next
            // round rides the fresh link — no 120 s hang on the corpse.
            let dead = lid(0xDE);
            assert_eq!(select_reply_link(&[(dead, 100, 200)]), Some(dead));
            assert_eq!(select_reply_link(&[]), None);
        }
    }

    // ── CIRISEdge#336/v13.8.0 route-table-first dial selection — pure decision ──
    //
    // Field failure (mobile → canonical, edge v13.7.0): the send dialed a
    // pathless dest ×24 (no route → round errors, envelopes_sent=0) while the
    // SAME peer's routable dest sat in the path table with a direct 1-hop
    // route. Root: address selection was identity-math-first; the route table
    // only picked the timeout. These tests pin the inversion.
    mod dial_selection {
        use super::*;
        use DialSource::{Cached, ComputedNamed, ExplicitHash};

        #[test]
        fn pathed_candidate_beats_pathless_legacy_preference() {
            // THE field scenario: cached announce-bound dest is pathless (stale
            // / unroutable), the computed-named dest holds the path. Pre-fix
            // the legacy preference dialed index 0 into the void ×24.
            let c = [
                (Cached, false),
                (ExplicitHash, false),
                (ComputedNamed, true),
            ];
            assert_eq!(select_dial_candidate(&c), Some(2));
        }

        #[test]
        fn cached_with_path_stays_the_happy_path() {
            let c = [(Cached, true), (ExplicitHash, false), (ComputedNamed, true)];
            assert_eq!(select_dial_candidate(&c), Some(0));
        }

        #[test]
        fn all_pathless_degrades_to_the_legacy_bootstrap_order() {
            // Route table agnostic → byte-identical to pre-v13.8.0 behavior:
            // cached first; else explicit-hash (the designed broadcast
            // bootstrap, e.g. a prime_peer'd cold-start) before computed-named.
            let with_cache = [
                (Cached, false),
                (ExplicitHash, false),
                (ComputedNamed, false),
            ];
            assert_eq!(select_dial_candidate(&with_cache), Some(0));
            let no_cache = [(ExplicitHash, false), (ComputedNamed, false)];
            assert_eq!(select_dial_candidate(&no_cache), Some(0));
        }

        #[test]
        fn among_pathed_the_announceable_shape_beats_explicit_hash() {
            // An explicit-hash dest with a "path" is near-impossible (it is
            // un-announceable); if both somehow have paths, prefer the
            // announceable computed-named shape.
            let c = [(ExplicitHash, true), (ComputedNamed, true)];
            assert_eq!(select_dial_candidate(&c), Some(1));
        }

        #[test]
        fn empty_candidates_select_nothing() {
            assert_eq!(select_dial_candidate(&[]), None);
        }
    }

    // ── CIRISEdge#353b/v13.6.1 progress-aware reverse-path wait — pure decision ──
    //
    // v13.6.0's flat 10s cutoff SEVERED a live, still-progressing large-resource
    // transfer (field: an 11s-old live link, non-busy, cut at exactly 10s). The
    // fix extends while parts flow and fast-fails only on no-progress / link death.
    mod resource_wait {
        use super::*;
        use ReverseWaitStep::{Continue, Done, LinkStale, MaxDeadline, StalledNoProgress};
        const NPW: Duration = Duration::from_secs(6); // no-progress window
        const MAX: Duration = Duration::from_secs(45); // hard cap

        #[test]
        fn completed_is_done() {
            assert_eq!(
                reverse_path_wait_step(
                    true,
                    true,
                    Duration::ZERO,
                    Duration::from_secs(3),
                    NPW,
                    MAX
                ),
                Done
            );
        }

        #[test]
        fn live_and_progressing_keeps_waiting_past_the_old_flat_cutoff() {
            // THE regression the fix exists for: 12s in, a live link that made
            // progress 2s ago keeps going — v13.6.0's flat 10s would have cut it.
            assert_eq!(
                reverse_path_wait_step(
                    false,
                    true,
                    Duration::from_secs(2),
                    Duration::from_secs(12),
                    NPW,
                    MAX
                ),
                Continue
            );
        }

        #[test]
        fn no_progress_past_window_fast_fails() {
            // Dead link: no progress for >= the window → fast-fail (faster than the
            // old 10s), preserving the #373 drain protection.
            assert_eq!(
                reverse_path_wait_step(
                    false,
                    true,
                    Duration::from_secs(6),
                    Duration::from_secs(6),
                    NPW,
                    MAX
                ),
                StalledNoProgress
            );
        }

        #[test]
        fn link_death_mid_transfer_is_distinct_not_a_generic_timeout() {
            // Even while progressing, a dead link is LinkStale (caveat 2) — so the
            // burst-and-leave churn mode stays field-visible.
            assert_eq!(
                reverse_path_wait_step(
                    false,
                    false,
                    Duration::from_secs(1),
                    Duration::from_secs(20),
                    NPW,
                    MAX
                ),
                LinkStale
            );
        }

        #[test]
        fn progressing_but_past_hard_cap_bails() {
            assert_eq!(
                reverse_path_wait_step(
                    false,
                    true,
                    Duration::from_secs(1),
                    Duration::from_secs(45),
                    NPW,
                    MAX
                ),
                MaxDeadline
            );
        }

        #[test]
        fn completion_wins_over_link_death() {
            // A resource proven on its last part is Done even if the link just
            // dropped — never turn a success into a LinkStale.
            assert_eq!(
                reverse_path_wait_step(
                    true,
                    false,
                    Duration::ZERO,
                    Duration::from_secs(5),
                    NPW,
                    MAX
                ),
                Done
            );
        }
    }

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
        ///
        /// CIRISEdge#404 REFINEMENT: the heal now returns `AdmitRouteKeepTrust`,
        /// not `Admit`. #336 healed the ROUTE but overwrote the binding with the
        /// incoming Advisory verdict — a provenance DOWNGRADE that left the peer
        /// reachable-but-UNATTRIBUTED (`from_rooted_binding` fails on provenance),
        /// which under epoch-0 churn dropped every inbound trace frame. The route
        /// still heals (explicit→named); the established Rooted trust is preserved.
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
                RouteSupersession::AdmitRouteKeepTrust,
                "the owner's genuine Advisory announce MUST heal a boot-primed \
                 explicit-hash route to its named dest WITHOUT downgrading the \
                 Rooted trust (#336 heal + #404 keep-trust)",
            );
        }

        /// CIRISEdge#404 — the epoch-0-churn de-attribution, at the decision fn.
        /// An owner's Advisory re-announce over a Rooted binding NEVER downgrades:
        /// it heals the route (new dest / higher epoch) or is a no-op stale
        /// re-announce (same dest) — never `Admit` (which would write Advisory).
        #[test]
        fn owner_advisory_never_downgrades_a_rooted_binding() {
            // Equal-epoch reroute (the churn case) → heal route, keep trust.
            assert_eq!(
                route_supersession_decision(Some((Rooted, 0, EXPLICIT)), Advisory, true, 0, NAMED),
                RouteSupersession::AdmitRouteKeepTrust,
            );
            // Higher-epoch (transport rotation) whose walk fell to Advisory →
            // heal route, keep trust (the key_id is still rooted in the directory).
            assert_eq!(
                route_supersession_decision(Some((Rooted, 2, NAMED)), Advisory, true, 3, EXPLICIT),
                RouteSupersession::AdmitRouteKeepTrust,
            );
            // SAME dest, same epoch → nothing to heal; a plain stale re-announce
            // that must NOT rewrite (and must NOT downgrade) the Rooted binding.
            assert_eq!(
                route_supersession_decision(Some((Rooted, 4, NAMED)), Advisory, true, 4, NAMED),
                RouteSupersession::IgnoreStale,
            );
            // The razor still holds: WITHOUT ownership it is a hijack, refused.
            assert_eq!(
                route_supersession_decision(Some((Rooted, 0, EXPLICIT)), Advisory, false, 0, NAMED),
                RouteSupersession::HijackRefused,
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

        /// SECURITY (v16 review): `owns_key` is fail-CLOSED on every rejection that
        /// does NOT prove a pubkey match. The route-hijack bug was `DirectoryError`
        /// (a first-lookup error, raised BEFORE any pubkey comparison) reading as
        /// owns_key=true under the old denylist. Exhaustive over all 9 variants.
        #[test]
        fn owns_key_is_a_post_pubkey_match_allowlist() {
            use super::RootingRejection as R;
            let s = String::new;
            // Fail-CLOSED — these prove NO pubkey match (pre-match or the mismatch itself):
            for r in [
                R::UnknownKeyId { key_id: s() },
                R::PubkeyMismatch {
                    key_id: s(),
                    claimed_pubkey_ed25519_base64: s(),
                    directory_pubkey_ed25519_base64: s(),
                },
                // THE FIX: a lookup DirectoryError is indistinguishable from a
                // first-lookup (no-match) error, so it can never imply ownership.
                R::DirectoryError { detail: s() },
            ] {
                assert!(
                    !owns_key_from_rooting_rejection(&r),
                    "must be fail-closed (no proven pubkey match): {r:?}"
                );
            }
            // ALLOWED — the pubkey matched; only the trust chain fell short. This is
            // the OWNER healing its own route (the #336 boot-prime→genuine-announce).
            for r in [
                R::BrokenProvenanceLink {
                    key_id: s(),
                    missing_parent_key_id: s(),
                },
                R::UnsignedProvenanceLink {
                    key_id: s(),
                    signed_by_key_id: s(),
                    detail: s(),
                },
                R::NotRootedAtSteward {
                    key_id: s(),
                    identity_type: s(),
                },
                R::TerminusNotInAnchor {
                    key_id: s(),
                    terminus_pubkey_ed25519_base64: s(),
                },
                R::CycleDetected { key_id: s() },
                R::OverDepth { max_depth: 8 },
            ] {
                assert!(
                    owns_key_from_rooting_rejection(&r),
                    "a post-pubkey-match rejection is the owner healing its route: {r:?}"
                );
            }
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

        /// The owner rotating its transport identity (higher epoch) supersedes.
        /// A Rooted incoming takes the route + trust (`Admit`); a same-owner
        /// Advisory incoming heals the route but PRESERVES the Rooted trust
        /// (`AdmitRouteKeepTrust`, CIRISEdge#404) — never a downgrade.
        #[test]
        fn higher_epoch_owner_supersedes() {
            assert_eq!(
                route_supersession_decision(Some((Rooted, 2, NAMED)), Rooted, true, 3, EXPLICIT),
                RouteSupersession::Admit,
            );
            assert_eq!(
                route_supersession_decision(Some((Rooted, 2, NAMED)), Advisory, true, 3, EXPLICIT),
                RouteSupersession::AdmitRouteKeepTrust,
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

    // ── CIRISEdge#363 bootstrap-link keepalive — the delivery-convergence fix ──
    //
    // The advisory/bootstrap link must outlive the Key + IdentityOccurrence
    // anti-entropy that promotes it to a KEX'd target. leviculum's RTT-derived
    // default reaps a fast direct link at ~16 s (5 s keepalive → 10 s stale);
    // these lock in the clamp + the shipped default over the PURE decision fn so
    // a regression is a compile-fast unit failure, never another lost trace.
    mod bootstrap_keepalive {
        use super::*;

        /// The shipped default keepalive (30 s) survives the clamp unchanged and
        /// is at least 2× the 30 s anti-entropy cadence' worth of stale slack
        /// (stale = keepalive × 2 = 60 s), so a bootstrap link tolerates a full
        /// quiet cadence of keepalive-ack silence.
        #[test]
        fn shipped_default_is_thirty_seconds_and_survives_the_clamp() {
            assert_eq!(BOOTSTRAP_LINK_KEEPALIVE, Duration::from_secs(30));
            assert_eq!(
                effective_link_keepalive_secs(Some(BOOTSTRAP_LINK_KEEPALIVE)),
                Some(30),
            );
            // `ReticulumTransportConfig::new` ships the bootstrap keepalive ON.
            let cfg = ReticulumTransportConfig::new(std::path::PathBuf::from("/x"), "k");
            assert_eq!(cfg.link_keepalive, Some(BOOTSTRAP_LINK_KEEPALIVE));
            assert_eq!(effective_link_keepalive_secs(cfg.link_keepalive), Some(30));
        }

        /// `None` leaves leviculum's RTT-derived default in place (opt-out).
        #[test]
        fn none_leaves_leviculum_default() {
            assert_eq!(effective_link_keepalive_secs(None), None);
        }

        /// A below-floor / sub-second override clamps UP to leviculum's minimum
        /// (matches leviculum's own `set_keepalive_override` floor) — never 0.
        #[test]
        fn below_floor_clamps_up_to_min() {
            assert_eq!(
                effective_link_keepalive_secs(Some(Duration::from_secs(1))),
                Some(LINK_KEEPALIVE_MIN_SECS),
            );
            assert_eq!(
                effective_link_keepalive_secs(Some(Duration::from_millis(200))),
                Some(LINK_KEEPALIVE_MIN_SECS),
            );
        }

        /// The DoS bound: an unbounded override is capped at leviculum's own
        /// RTT-driven ceiling so a stray value can NOT hold a silently-dead link
        /// open longer than leviculum itself ever would (leviculum only clamps
        /// the lower end).
        #[test]
        fn above_ceiling_clamps_down_to_max() {
            assert_eq!(
                effective_link_keepalive_secs(Some(Duration::from_secs(86_400))),
                Some(LINK_KEEPALIVE_MAX_SECS),
            );
        }

        /// An in-band operator override passes through untouched.
        #[test]
        fn in_band_override_passes_through() {
            assert_eq!(
                effective_link_keepalive_secs(Some(Duration::from_secs(45))),
                Some(45),
            );
        }
    }

    /// CIRISEdge#508 item (d) — the control-channel capacity resolver.
    /// Exercised with the EXACT input shapes the field produces: an explicit
    /// config value, raw env strings (valid / padded / garbage / empty), and
    /// nothing at all.
    mod control_channel_capacity {
        use super::*;

        /// Config wins over env, and passes through when in band.
        #[test]
        fn config_wins_over_env_and_passes_through() {
            assert_eq!(
                effective_control_channel_capacity(Some(4096), Some("1024")),
                (Some(4096), ControlChannelCapacitySource::Config),
            );
            // `ReticulumTransportConfig::new` ships it OFF (leviculum default).
            let cfg = ReticulumTransportConfig::new(std::path::PathBuf::from("/x"), "k");
            assert_eq!(cfg.control_channel_capacity, None);
        }

        /// A valid env var applies when no config field is set — including the
        /// whitespace-padded form a compose file or systemd unit produces.
        #[test]
        fn env_applies_when_config_absent() {
            assert_eq!(
                effective_control_channel_capacity(None, Some("1024")),
                (Some(1024), ControlChannelCapacitySource::Env),
            );
            assert_eq!(
                effective_control_channel_capacity(None, Some(" 2048\n")),
                (Some(2048), ControlChannelCapacitySource::Env),
            );
        }

        /// Both sources clamp into the safe band: 0 would panic tokio's
        /// `mpsc::channel`, and an absurd value would commit unbounded queue
        /// memory (each slot is a queued NodeEvent).
        #[test]
        fn both_sources_clamp_into_band() {
            assert_eq!(
                effective_control_channel_capacity(Some(0), None),
                (
                    Some(CONTROL_CHANNEL_CAPACITY_MIN),
                    ControlChannelCapacitySource::Config
                ),
            );
            assert_eq!(
                effective_control_channel_capacity(None, Some("999999999")),
                (
                    Some(CONTROL_CHANNEL_CAPACITY_MAX),
                    ControlChannelCapacitySource::Env
                ),
            );
        }

        /// Garbage / empty env is IGNORED (loudly at the call site), never a
        /// panic and never a silent zero — leviculum's default stays in force.
        #[test]
        fn invalid_env_is_ignored_not_applied() {
            for raw in ["lots", "-1", "", "0x400", "1024 events"] {
                assert_eq!(
                    effective_control_channel_capacity(None, Some(raw)),
                    (None, ControlChannelCapacitySource::EnvInvalid),
                    "raw env {raw:?} must be ignored",
                );
            }
        }

        /// Nothing configured → leviculum's default, and the decision says so.
        #[test]
        fn absent_everywhere_is_leviculum_default() {
            assert_eq!(
                effective_control_channel_capacity(None, None),
                (None, ControlChannelCapacitySource::Default),
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
            // CIRISPersist v22 (#543) — federation_keys now reject a pubkey that
            // doesn't decode to a 32-byte Ed25519 key (the fixture used to seed an
            // EMPTY string). A real occurrence carries its real 32-byte key; the
            // round-trip under test doesn't depend on the key's value, only its
            // presence, so any valid 32-byte encoding satisfies the gate.
            pubkey_ed25519_base64: {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode([7u8; 32])
            },
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
            capability_roles: Vec::new(),
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

    /// CIRISEdge#432 — a minimal valid `federation_keys` fixture row (the FK
    /// gate `put_transport_destination` enforces). Same shape as the inline
    /// record in `rooted_transport_write_through_boot_load_round_trip`.
    fn fixture_key_record_for_transport_tests(
        key_id: &str,
    ) -> ciris_persist::federation::KeyRecord {
        use base64::Engine as _;
        ciris_persist::federation::KeyRecord {
            key_id: key_id.to_string(),
            pubkey_ed25519_base64: base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
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
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// CIRISEdge#432 — a 64-byte `(x25519 ‖ ed25519)` transport identity whose
    /// ed25519 half is a VALID curve point (an arbitrary-bytes ed25519 pubkey
    /// fails decompression, making `from_public_keys` return `Err` and every
    /// identity hash collapse to the `[0u8; 16]` default — which would let the
    /// heal's identity-equality test pass vacuously).
    fn valid_transport_pubkey64(seed: u8) -> [u8; 64] {
        use ciris_crypto::Ed25519Signer;
        let ed = Ed25519Signer::from_seed(&[seed; 32])
            .expect("ed25519 from seed")
            .verifying_key()
            .to_bytes();
        let mut pk = [0u8; 64];
        pk[..32].copy_from_slice(&[seed.wrapping_add(1); 32]); // x25519: any 32B is valid
        pk[32..].copy_from_slice(&ed);
        pk
    }

    fn identity_hash_of64(pk: &[u8; 64]) -> [u8; 16] {
        let x: [u8; 32] = pk[..32].try_into().unwrap();
        let e: [u8; 32] = pk[32..].try_into().unwrap();
        *Identity::from_public_keys(&x, &e)
            .expect("valid identity")
            .hash()
    }

    /// CIRISEdge#432 — the heal decision, driven with the EXACT operands both
    /// production reproductions logged: live `(Advisory, owns_key=false)` (the
    /// first-contact `UnknownKeyId` admit) vs a store holding `rooted` for the
    /// same link-proven transport identity ⇒ upgrade. The identity-equality
    /// conjunct is load-bearing: a stored rooted row binding a DIFFERENT
    /// transport identity must never launder trust onto this link.
    #[test]
    fn divergence_heal_upgrades_only_same_identity_rooted_store() {
        use ciris_persist::federation::self_at_login::BindingProvenance::{Advisory, Rooted};
        let pk = valid_transport_pubkey64(7);
        let live_hash = identity_hash_of64(&pk);
        let stored_rooted = crate::verify::StoredTransportBinding {
            provenance: Rooted,
            transport_pubkey64: pk,
            epoch: 3,
        };
        // The field case: (Advisory, false) + rooted store, same identity → Upgrade.
        assert_eq!(
            divergence_heal_decision(Advisory, false, live_hash, &stored_rooted),
            DivergenceHeal::Upgrade
        );
        // (Advisory, true) — the #404 churn shape — also heals when the store roots.
        assert_eq!(
            divergence_heal_decision(Advisory, true, live_hash, &stored_rooted),
            DivergenceHeal::Upgrade
        );
        // A store rooting a DIFFERENT identity: divergence, NOT healable.
        let other = crate::verify::StoredTransportBinding {
            provenance: Rooted,
            transport_pubkey64: valid_transport_pubkey64(9),
            epoch: 3,
        };
        assert_eq!(
            divergence_heal_decision(Advisory, false, live_hash, &other),
            DivergenceHeal::IdentityMismatch
        );
        // A store that is itself Advisory: nothing to act on.
        let stored_advisory = crate::verify::StoredTransportBinding {
            provenance: Advisory,
            transport_pubkey64: pk,
            epoch: 0,
        };
        assert_eq!(
            divergence_heal_decision(Advisory, false, live_hash, &stored_advisory),
            DivergenceHeal::StoreNotRooted
        );
        // A live binding that already passes is never touched.
        assert_eq!(
            divergence_heal_decision(Rooted, true, live_hash, &stored_rooted),
            DivergenceHeal::LiveAlreadyPasses
        );
    }

    /// CIRISEdge#432 — `stored_reticulum_binding` (the heal's read half) against
    /// the REAL write-through shapes: the first-contact Advisory write, then the
    /// later rooted write at a higher epoch (the independent-writer sequence the
    /// production canonical exhibited). The read must return the best live row —
    /// rooted, max epoch — with both identity halves intact.
    #[tokio::test]
    async fn stored_reticulum_binding_returns_the_best_live_row() {
        use crate::verify::RootingDirectory;
        use ciris_persist::federation::self_at_login::BindingProvenance::{Advisory, Rooted};
        use ciris_persist::store::MemoryBackend;

        let backend = MemoryBackend::new();
        let key_id = "peer-heal-read";
        // FK gate: the occurrence's federation_keys row must exist.
        let mut record = fixture_key_record_for_transport_tests(key_id);
        record.key_id = key_id.to_string();
        ciris_persist::federation::FederationDirectory::put_public_key(
            &backend,
            ciris_persist::federation::SignedKeyRecord { record },
        )
        .await
        .expect("seed occurrence key");

        let pk = valid_transport_pubkey64(11);
        // No row yet → None.
        assert!(
            RootingDirectory::stored_reticulum_binding(&backend, key_id)
                .await
                .is_none(),
            "no stored binding before any write-through"
        );
        // First contact: the Advisory admit's write-through (epoch 0).
        RootingDirectory::persist_transport_binding(&backend, key_id, [3u8; 16], pk, Advisory, 0)
            .await;
        let s = RootingDirectory::stored_reticulum_binding(&backend, key_id)
            .await
            .expect("advisory row read back");
        assert_eq!(s.provenance, Advisory);
        assert_eq!(s.transport_pubkey64, pk, "identity halves intact");
        // The independent writer roots it later (higher epoch).
        RootingDirectory::persist_transport_binding(&backend, key_id, [3u8; 16], pk, Rooted, 1)
            .await;
        let s = RootingDirectory::stored_reticulum_binding(&backend, key_id)
            .await
            .expect("rooted row read back");
        assert_eq!(s.provenance, Rooted, "the best live row is the rooted one");
        assert_eq!(s.epoch, 1);
        assert_eq!(s.transport_pubkey64, pk);
    }

    /// CIRISEdge#436 — first-contact rooting: the announce commitment + the
    /// link-borne package → the ONE-motion Advisory→Rooted upgrade, driven
    /// with the EXACT field artifacts (a verify-producer-minted bundle over
    /// persist's real admission — the shared #437 fixture) and the EXACT live
    /// entry the first-contact Advisory admit inserts (the #432 reproduction
    /// operands: `Advisory ∧ owns_key=false`).
    mod first_contact_rooting {
        use super::*;
        use crate::bundle_gate::test_support::{field_fixture, tampered, PIPELINE, PRESENTER};
        use crate::bundle_gate::{
            manifest_commitment_of_bundle, sha256_of, BundleSaveGateMode, PeerBundleStore,
            MAX_PEER_BUNDLE_BYTES,
        };
        use crate::verify::RootingDirectory;
        use ciris_persist::federation::self_at_login::BindingProvenance::{Advisory, Rooted};

        const DEST: [u8; 16] = [3u8; 16];

        /// The live peers map exactly as the field's first-contact announce
        /// admit leaves it: an `Advisory ∧ owns_key=false` entry carrying the
        /// announced manifest commitment + the announce's own transport
        /// identity (both halves) — the #336/#432 test-field-provenance rule.
        fn live_map_after_first_contact_admit(
            key_id: &str,
            pk: [u8; 64],
            commitment: Option<[u8; 32]>,
        ) -> Mutex<HashMap<String, RootedPeer>> {
            let ed25519: [u8; 32] = pk[32..].try_into().unwrap();
            let mut map = HashMap::new();
            map.insert(
                key_id.to_string(),
                RootedPeer {
                    peer: ResolvedPeer {
                        dest_hash: DestinationHash::new(DEST),
                        signing_key: ed25519,
                    },
                    epoch: 0,
                    chain: None,
                    provenance: Advisory,
                    transport_identity_hash: identity_hash_of64(&pk),
                    owns_key: false,
                    transport_pubkey64: pk,
                    manifest_commitment: commitment,
                },
            );
            Mutex::new(map)
        }

        /// The acceptance path: announce-with-commitment → link → package →
        /// ELIGIBLE verdict → live map `Rooted ∧ owns_key` AND durable store
        /// `Rooted` in ONE motion — and attribution item 1 passes on the very
        /// next frame.
        #[tokio::test]
        async fn verified_link_borne_bundle_roots_first_contact_in_one_motion() {
            let (backend, bundle) = field_fixture().await;
            let pk = valid_transport_pubkey64(7);
            let commitment = manifest_commitment_of_bundle(&bundle).expect("commitment");
            let peers = live_map_after_first_contact_admit(PRESENTER, pk, Some(commitment));
            // The admit's durable write-through (Advisory, epoch 0) — the row
            // the one-motion upgrade must flip to Rooted.
            RootingDirectory::persist_transport_binding(&backend, PRESENTER, DEST, pk, Advisory, 0)
                .await;
            let store = PeerBundleStore::new();
            let frame = crate::transport::peer_bundle_frame::encode(&bundle);

            let out = process_peer_bundle_frame(
                &frame,
                PRESENTER,
                // The link proved exactly the announce's transport identity.
                Some(identity_hash_of64(&pk)),
                None,
                &peers,
                &store,
                &backend,
                BundleSaveGateMode::Off,
            )
            .await;
            assert!(
                matches!(
                    out,
                    PeerBundleOutcome::Upgraded {
                        already_passed: false
                    }
                ),
                "expected the one-motion upgrade, got {out:?}"
            );

            // Live half: Rooted ∧ owns_key — attribution item 1 passes NOW.
            let entry = peers.lock().await.get(PRESENTER).cloned().expect("entry");
            assert_eq!(entry.provenance, Rooted);
            assert!(entry.owns_key);
            assert!(
                crate::transport::SourceKeyId::from_rooted_binding(
                    PRESENTER.to_string(),
                    entry.provenance,
                    entry.owns_key,
                )
                .is_some(),
                "the E3 item-1 gate admits this binding post-upgrade"
            );

            // Durable half, SAME motion: the store row is Rooted with the
            // SAME transport identity the link proved.
            let stored = RootingDirectory::stored_reticulum_binding(&backend, PRESENTER)
                .await
                .expect("durable row");
            assert_eq!(stored.provenance, Rooted);
            assert_eq!(stored.transport_pubkey64, pk);

            // And the #437 store now holds the VERIFIED bundle (cached against
            // the exact bytes) — a later gated Rooted save is a cache-hit.
            assert!(store.is_verified(PRESENTER, sha256_of(&bundle)));
        }

        /// Composition with the #437 gate ON: the durable half rides the same
        /// `gated_save_provenance` choke and stays Rooted (the verdict was
        /// cached in the same motion) — the gate never sees an unbundled peer
        /// here by construction.
        #[tokio::test]
        async fn one_motion_upgrade_composes_with_the_437_gate_on() {
            let (backend, bundle) = field_fixture().await;
            let pk = valid_transport_pubkey64(7);
            let commitment = manifest_commitment_of_bundle(&bundle).expect("commitment");
            let peers = live_map_after_first_contact_admit(PRESENTER, pk, Some(commitment));
            let store = PeerBundleStore::new();
            let frame = crate::transport::peer_bundle_frame::encode(&bundle);
            let out = process_peer_bundle_frame(
                &frame,
                PRESENTER,
                Some(identity_hash_of64(&pk)),
                None,
                &peers,
                &store,
                &backend,
                BundleSaveGateMode::RequireBundleForRootedSave,
            )
            .await;
            assert!(matches!(out, PeerBundleOutcome::Upgraded { .. }));
            let stored = RootingDirectory::stored_reticulum_binding(&backend, PRESENTER)
                .await
                .expect("durable row");
            assert_eq!(
                stored.provenance, Rooted,
                "gate ON: the just-verified bundle satisfies the #437 choke — \
                 the durable save stays Rooted, not downgraded"
            );
        }

        /// NEGATIVE — the commitment BINDS announce to package: a package
        /// whose manifest hash differs from the announced commitment refuses
        /// LOUDLY with NO store slot, NO live-map change, NO durable write.
        #[tokio::test]
        async fn commitment_mismatch_refuses_with_no_upgrade_anywhere() {
            let (backend, bundle) = field_fixture().await;
            let pk = valid_transport_pubkey64(7);
            let commitment = manifest_commitment_of_bundle(&bundle).expect("commitment");
            let peers = live_map_after_first_contact_admit(PRESENTER, pk, Some(commitment));
            RootingDirectory::persist_transport_binding(&backend, PRESENTER, DEST, pk, Advisory, 0)
                .await;
            let store = PeerBundleStore::new();
            // The evidence swap: a tampered manifest → a different commitment.
            let frame = crate::transport::peer_bundle_frame::encode(&tampered(&bundle));
            let out = process_peer_bundle_frame(
                &frame,
                PRESENTER,
                Some(identity_hash_of64(&pk)),
                None,
                &peers,
                &store,
                &backend,
                BundleSaveGateMode::Off,
            )
            .await;
            assert!(
                matches!(
                    out,
                    PeerBundleOutcome::Refused(PeerBundleRefusal::CommitmentMismatch)
                ),
                "expected CommitmentMismatch, got {out:?}"
            );
            assert!(store.is_empty(), "a mismatched package takes no store slot");
            let entry = peers.lock().await.get(PRESENTER).cloned().unwrap();
            assert_eq!(entry.provenance, Advisory);
            assert!(!entry.owns_key);
            assert_eq!(
                RootingDirectory::stored_reticulum_binding(&backend, PRESENTER)
                    .await
                    .unwrap()
                    .provenance,
                Advisory,
                "the durable row is untouched"
            );
        }

        /// NEGATIVE — absent commitment = today's path untouched: a peer whose
        /// announce carried NO commitment refuses any unsolicited package
        /// (nothing binds it to the announce) and stays exactly as admitted.
        #[tokio::test]
        async fn absent_announced_commitment_keeps_todays_path_untouched() {
            let (backend, bundle) = field_fixture().await;
            let pk = valid_transport_pubkey64(7);
            let peers = live_map_after_first_contact_admit(PRESENTER, pk, None);
            let store = PeerBundleStore::new();
            let frame = crate::transport::peer_bundle_frame::encode(&bundle);
            let out = process_peer_bundle_frame(
                &frame,
                PRESENTER,
                Some(identity_hash_of64(&pk)),
                None,
                &peers,
                &store,
                &backend,
                BundleSaveGateMode::Off,
            )
            .await;
            assert!(
                matches!(
                    out,
                    PeerBundleOutcome::Refused(PeerBundleRefusal::NoAnnouncedCommitment)
                ),
                "expected NoAnnouncedCommitment, got {out:?}"
            );
            assert!(store.is_empty());
            let entry = peers.lock().await.get(PRESENTER).cloned().unwrap();
            assert_eq!(entry.provenance, Advisory);
            assert!(!entry.owns_key);
        }

        /// NEGATIVE — an oversized package refuses BEFORE any hashing,
        /// registration, or directory work; malformed / unknown-version frames
        /// refuse the same way.
        #[tokio::test]
        async fn oversized_and_malformed_packages_refuse_before_any_work() {
            let pk = valid_transport_pubkey64(7);
            let peers = live_map_after_first_contact_admit(PRESENTER, pk, Some([0xAA; 32]));
            let store = PeerBundleStore::new();
            // Oversized: cap + 1 bytes of payload.
            let big =
                crate::transport::peer_bundle_frame::encode(&vec![b'x'; MAX_PEER_BUNDLE_BYTES + 1]);
            let out = process_peer_bundle_frame(
                &big,
                PRESENTER,
                Some(identity_hash_of64(&pk)),
                None,
                &peers,
                &store,
                &NoDirectoryRootingForBundles,
                BundleSaveGateMode::Off,
            )
            .await;
            assert!(matches!(
                out,
                PeerBundleOutcome::Refused(PeerBundleRefusal::Oversized { .. })
            ));
            // Malformed: an unknown frame version.
            let mut v2 = crate::transport::peer_bundle_frame::encode(b"{}");
            v2[4] = 0x7F;
            let out = process_peer_bundle_frame(
                &v2,
                PRESENTER,
                Some(identity_hash_of64(&pk)),
                None,
                &peers,
                &store,
                &NoDirectoryRootingForBundles,
                BundleSaveGateMode::Off,
            )
            .await;
            assert!(matches!(
                out,
                PeerBundleOutcome::Refused(PeerBundleRefusal::Malformed(_))
            ));
            assert!(store.is_empty());
        }

        /// NEGATIVE — the #432 identity-equality rule at bundle arrival: a
        /// link that proved a DIFFERENT transport identity than the entry's
        /// announce can never upgrade it, even with a fully valid package.
        /// Trust is never laundered across identities.
        #[tokio::test]
        async fn link_identity_mismatch_never_launders_trust() {
            let (backend, bundle) = field_fixture().await;
            let pk = valid_transport_pubkey64(7);
            let other_pk = valid_transport_pubkey64(9);
            let commitment = manifest_commitment_of_bundle(&bundle).expect("commitment");
            let peers = live_map_after_first_contact_admit(PRESENTER, pk, Some(commitment));
            let store = PeerBundleStore::new();
            let frame = crate::transport::peer_bundle_frame::encode(&bundle);
            let out = process_peer_bundle_frame(
                &frame,
                PRESENTER,
                // The link proved the OTHER identity (a squat / stale rotation).
                Some(identity_hash_of64(&other_pk)),
                None,
                &peers,
                &store,
                &backend,
                BundleSaveGateMode::Off,
            )
            .await;
            assert!(
                matches!(
                    out,
                    PeerBundleOutcome::Refused(PeerBundleRefusal::LinkBindingMismatch)
                ),
                "expected LinkBindingMismatch, got {out:?}"
            );
            let entry = peers.lock().await.get(PRESENTER).cloned().unwrap();
            assert_eq!(entry.provenance, Advisory);
            assert!(!entry.owns_key);
        }

        /// NEGATIVE — the presenter binding survives this seam: a RELAYED
        /// valid bundle (another peer's package announced + served under a
        /// different key_id) passes the commitment check but fails verify's
        /// `PresenterKeyMismatch` — refused, no upgrade. The bundle stays
        /// registered (shape-passed; refusals are never cached) exactly as
        /// the #437 store contract says.
        #[tokio::test]
        async fn relayed_bundle_fails_the_presenter_binding_and_never_upgrades() {
            let (backend, bundle) = field_fixture().await;
            let pk = valid_transport_pubkey64(11);
            let commitment = manifest_commitment_of_bundle(&bundle).expect("commitment");
            // The PIPELINE peer wears the PRESENTER's bundle + commitment.
            let peers = live_map_after_first_contact_admit(PIPELINE, pk, Some(commitment));
            let store = PeerBundleStore::new();
            let frame = crate::transport::peer_bundle_frame::encode(&bundle);
            let out = process_peer_bundle_frame(
                &frame,
                PIPELINE,
                Some(identity_hash_of64(&pk)),
                None,
                &peers,
                &store,
                &backend,
                BundleSaveGateMode::Off,
            )
            .await;
            assert!(
                matches!(
                    out,
                    PeerBundleOutcome::Refused(PeerBundleRefusal::VerifyRefused(_))
                ),
                "expected VerifyRefused(PresenterKeyMismatch), got {out:?}"
            );
            let entry = peers.lock().await.get(PIPELINE).cloned().unwrap();
            assert_eq!(
                entry.provenance, Advisory,
                "no upgrade for a relayed bundle"
            );
            assert!(
                !store.is_verified(PIPELINE, sha256_of(&bundle)),
                "a refusal is never cached"
            );
        }

        /// The pure link↔entry binding rule (the #432 identity-equality
        /// semantics), all four evidence corners.
        #[test]
        fn link_binding_rule_covers_all_evidence_corners() {
            let entry_id = [1u8; 16];
            let entry_dest = [2u8; 16];
            // Proven identity wins/refuses regardless of dest evidence.
            assert!(peer_bundle_link_binding_ok(
                Some(entry_id),
                None,
                entry_id,
                entry_dest
            ));
            assert!(!peer_bundle_link_binding_ok(
                Some([9u8; 16]),
                Some(entry_dest),
                entry_id,
                entry_dest
            ));
            // No proven identity: the dialed dest must match the entry's.
            assert!(peer_bundle_link_binding_ok(
                None,
                Some(entry_dest),
                entry_id,
                entry_dest
            ));
            assert!(!peer_bundle_link_binding_ok(
                None,
                Some([9u8; 16]),
                entry_id,
                entry_dest
            ));
            // No evidence at all: refuse.
            assert!(!peer_bundle_link_binding_ok(
                None, None, entry_id, entry_dest
            ));
        }

        /// A rooting double whose required methods are unreachable — the
        /// oversized/malformed arms must refuse BEFORE any directory call.
        struct NoDirectoryRootingForBundles;

        #[async_trait::async_trait]
        impl RootingDirectory for NoDirectoryRootingForBundles {
            async fn root_binding(
                &self,
                _key_id: &str,
                _claimed: &str,
            ) -> crate::verify::RootingVerdict {
                unreachable!("shape refusals precede every directory call")
            }
            async fn provenance_chain(
                &self,
                _key_id: &str,
            ) -> Result<crate::verify::ProvenanceChain, crate::verify::RootingRejection>
            {
                unreachable!("shape refusals precede every directory call")
            }
        }
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

/// CIRISEdge#499 — the transport half of scope-native addressing.
///
/// These live in-crate rather than in `tests/` on purpose: `StubDeriver` is
/// `#[cfg(test)]`, so an integration test cannot build a [`ScopeAddressTable`]
/// at all. That is the point — outside this crate's own tests there is no way
/// to obtain a [`MemberAddress`] except from a real derivation.
#[cfg(test)]
mod scope_native_addressing_tests {
    use super::*;
    use crate::cohort_scope::CohortScope;
    use crate::scope_addressing::StubDeriver;
    use leviculum_core::AnnounceControl as _;

    /// A hybrid signer — CIRISEdge#333 refuses a transport that cannot
    /// self-attest its announces.
    fn test_signer(key_id: &str) -> Arc<LocalSigner> {
        let mut ed_seed = [0u8; 32];
        let mut pqc_seed = [0u8; 32];
        let salt = u8::try_from(key_id.len() % 251).expect("in range");
        for (i, b) in ed_seed.iter_mut().enumerate() {
            *b = u8::try_from(i % 251).expect("in range") ^ salt;
        }
        pqc_seed.copy_from_slice(&ed_seed);
        pqc_seed[0] ^= 0x55;
        let classical: Arc<dyn ciris_keyring::HardwareSigner> = Arc::new(
            ciris_keyring::Ed25519SoftwareSigner::from_bytes(&ed_seed, key_id).expect("ed25519"),
        );
        let pqc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(
            ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(
                &pqc_seed,
                format!("{key_id}-pqc"),
            )
            .expect("ml_dsa_65"),
        );
        Arc::new(LocalSigner::new(key_id, classical, Some(pqc)))
    }

    async fn transport_with(config: ReticulumTransportConfig, key_id: &str) -> ReticulumTransport {
        let signer = test_signer(key_id);
        ReticulumTransport::new(
            config,
            ReticulumAuth {
                signer: Some(signer),
                ..ReticulumAuth::default()
            },
        )
        .await
        .expect("transport")
    }

    async fn bare_transport(dir: &std::path::Path, key_id: &str) -> ReticulumTransport {
        let signer = test_signer(key_id);

        // No typed interfaces, and the default `0.0.0.0:4242` server replaced
        // with an ephemeral port so these four tests can run concurrently. The
        // node comes up with a routing table and a local identity; nothing here
        // sends a byte.
        let mut config = ReticulumTransportConfig::new(dir.join("transport.id"), key_id);
        config.listen_addr = "127.0.0.1:0".parse().expect("ephemeral addr parses");
        ReticulumTransport::new(
            config,
            ReticulumAuth {
                signer: Some(signer),
                ..ReticulumAuth::default()
            },
        )
        .await
        .expect("bare transport")
    }

    fn table_with_group(
        scope: &CohortScope,
        group_id: &str,
        members: &[&str],
    ) -> Arc<ScopeAddressTable> {
        let table = Arc::new(ScopeAddressTable::new(Arc::new(StubDeriver)));
        table
            .install_group(scope, group_id, 1, &[9u8; 32], members)
            .expect("install group");
        table
    }

    #[tokio::test]
    async fn federation_visibility_off_makes_the_node_announce_nothing() {
        // The wizard's "allow me to be visible to the federation so I can use
        // the mesh" opt-in. OFF means point-to-point only: the node announces
        // nothing, so no stranger can learn an address for it.
        //
        // Asserted on the POLICY rather than on the flag, because the flag
        // being read is not the property — the property is that the named
        // discovery destination stops being announceable.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = ReticulumTransportConfig::new(dir.path().join("t.id"), "edge-invisible");
        config.listen_addr = "127.0.0.1:0".parse().expect("addr");
        config.federation_visible = false;

        let transport = transport_with(config, "edge-invisible").await;
        assert!(
            transport
                .announce_policy
                .should_suppress_announce(&DestinationHash::new(transport.local_named_dest_hash())),
            "an invisible node must not announce its discovery destination",
        );
        assert_eq!(
            transport.announce_policy.len(),
            0,
            "invisibility is the policy's DEFAULT-suppress, not a second \
             mechanism — nothing should be registered at all",
        );
    }

    #[tokio::test]
    async fn federation_visibility_on_keeps_the_node_discoverable() {
        // The other half, so the pair cannot pass by suppressing everything.
        let dir = tempfile::tempdir().expect("tempdir");
        let transport = bare_transport(dir.path(), "edge-visible").await;
        assert!(
            !transport
                .announce_policy
                .should_suppress_announce(&DestinationHash::new(transport.local_named_dest_hash())),
            "a federation-visible node must still announce discovery",
        );
    }

    #[tokio::test]
    async fn scope_address_table_installs_exactly_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let transport = bare_transport(dir.path(), "edge-once").await;

        assert!(
            transport.scope_address_table().is_none(),
            "a fresh transport has no table — the default until the operator \
             opts in via EdgeBuilder::scope_native_addressing",
        );

        let first = Arc::new(ScopeAddressTable::new(Arc::new(StubDeriver)));
        transport
            .install_scope_address_table(Arc::clone(&first))
            .expect("first install succeeds");

        // A second install must be REFUSED, not silently accepted: the loser's
        // destinations would still be registered on the node, so two tables
        // would disagree about which inbound hashes are ours.
        let second = Arc::new(ScopeAddressTable::new(Arc::new(StubDeriver)));
        let err = transport
            .install_scope_address_table(second)
            .expect_err("second install must be refused");
        assert!(
            format!("{err}").contains("already installed"),
            "displacement must be named, got: {err}",
        );
        assert!(
            transport
                .scope_address_table()
                .is_some_and(|t| Arc::ptr_eq(t, &first)),
            "the FIRST table stays installed after a refused displacement",
        );
    }

    #[tokio::test]
    async fn public_scope_is_refused_for_a_derived_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let transport = bare_transport(dir.path(), "edge-public").await;

        let scope = CohortScope::Family;
        let table = table_with_group(&scope, "grp-a", &["member-a"]);
        let address = table
            .send_address(&scope, "grp-a", "member-a")
            .expect("derived address");

        // Registering a derived address as Public would hand it to the node's
        // auto-announce loops, publishing the reachability fact the derivation
        // exists to withhold (CIRISEdge#311 limb (b)).
        let err = transport
            .register_scoped_destination(&address, &CohortScope::Public)
            .expect_err("Public must be refused");
        assert!(
            format!("{err}").contains("not a discovery address"),
            "the refusal must say why, got: {err}",
        );

        // ...and the group scopes it exists for are all accepted.
        for accepted in [
            CohortScope::SelfOnly,
            CohortScope::Family,
            CohortScope::Cohort {
                cohort_id: "c-1".to_owned(),
            },
        ] {
            transport
                .register_scoped_destination(&address, &accepted)
                .unwrap_or_else(|e| panic!("{accepted:?} must register: {e}"));
        }
    }

    #[tokio::test]
    async fn registering_a_scoped_destination_suppresses_its_announce() {
        let dir = tempfile::tempdir().expect("tempdir");
        let transport = bare_transport(dir.path(), "edge-suppress").await;

        let scope = CohortScope::Cohort {
            cohort_id: "neighbourhood".to_owned(),
        };
        let table = table_with_group(&scope, "grp-b", &["member-b"]);
        let address = table
            .send_address(&scope, "grp-b", "member-b")
            .expect("derived address");
        let hash = *address.as_bytes();

        let registered_before = transport.announce_policy.len();
        transport
            .register_scoped_destination(&address, &scope)
            .expect("register");

        // The scope must actually be RECORDED, not merely fail-safe. Dropping
        // the `register_announce_scope` call leaves the destination suppressed
        // anyway (the policy default-suppresses anything unregistered), so a
        // suppression assertion alone is blind to that mutation — verified by
        // deleting the call and watching this test stay green. The entry count
        // is what distinguishes "suppressed because we said so" from
        // "suppressed because we forgot".
        assert_eq!(
            transport.announce_policy.len(),
            registered_before + 1,
            "the derived destination's scope must be recorded in the policy map",
        );

        // CC 5.4 — a group-scoped destination MUST NOT announce. The named
        // discovery destination registered at construction still must.
        assert!(
            transport
                .announce_policy
                .should_suppress_announce(&DestinationHash::new(hash)),
            "a scope-derived destination must never be announced",
        );
        assert!(
            !transport
                .announce_policy
                .should_suppress_announce(
                    &DestinationHash::new(transport.local_named_dest_hash()),
                ),
            "the named Commons discovery destination still announces",
        );
    }

    #[tokio::test]
    async fn a_scoped_destination_round_trips_register_then_retire() {
        // leviculum#54 (v0.20.0+ciris.1) — the seal half of the rotation.
        // Without retirement a superseded address keeps answering forever
        // and an observer who learned it can re-confirm this node, which
        // is the reachability disclosure the whole feature removes.
        let dir = tempfile::tempdir().expect("tempdir");
        let transport = bare_transport(dir.path(), "edge-retire").await;

        let scope = CohortScope::Family;
        let table = table_with_group(&scope, "grp-r", &["member-r"]);
        let address = table
            .send_address(&scope, "grp-r", "member-r")
            .expect("derived address");
        let hash = *address.as_bytes();

        let before = transport.announce_policy.len();
        transport
            .register_scoped_destination(&address, &scope)
            .expect("register");
        assert_eq!(transport.announce_policy.len(), before + 1);

        transport
            .retire_scoped_destination(&address, &scope)
            .expect("retire");
        // The scope record goes too, or the policy map grows one entry per
        // epoch per group for addresses that are no longer ours.
        assert_eq!(
            transport.announce_policy.len(),
            before,
            "retiring must drop the scope record, not just the destination",
        );

        // Idempotent — leviculum pins this, and the seal is timing-driven
        // so it may genuinely fire twice for one rotation.
        transport
            .retire_scoped_destination(&address, &scope)
            .expect("retiring twice is a no-op");
        assert_eq!(transport.announce_policy.len(), before);

        // And re-registering the same address afterwards still works: a
        // member re-admitted at a later epoch must not be poisoned by the
        // earlier retirement.
        transport
            .register_scoped_destination(&address, &scope)
            .expect("re-register after retire");
        assert_eq!(transport.announce_policy.len(), before + 1);
        assert!(
            transport
                .announce_policy
                .should_suppress_announce(&DestinationHash::new(hash)),
            "a re-registered scoped destination is still never announced",
        );
    }

    #[tokio::test]
    async fn inbound_scope_declines_without_a_table_and_resolves_with_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let transport = bare_transport(dir.path(), "edge-inbound").await;

        let scope = CohortScope::Family;
        let table = table_with_group(&scope, "grp-c", &["member-c", "member-d"]);
        let address = table
            .send_address(&scope, "grp-c", "member-c")
            .expect("derived address");
        let hash = *address.as_bytes();

        // Production state today: no table installed → every scope-native
        // lookup declines and the federation-scope paths are untouched.
        assert!(
            transport.inbound_scope(&hash).is_none(),
            "no table installed → decline",
        );

        transport
            .install_scope_address_table(Arc::clone(&table))
            .expect("install");

        let resolved = transport
            .inbound_scope(&hash)
            .expect("installed table resolves its own derived address");
        assert_eq!(resolved.group().scope(), &scope);
        assert_eq!(resolved.group().group_id(), "grp-c");
        assert_eq!(
            resolved.member_key_id(),
            "member-c",
            "the address resolves to the member it was derived FOR — not merely \
             to the group; a per-member hash is what keeps the RNS routing entry \
             unambiguous",
        );
        assert_eq!(resolved.epoch(), 1);

        // A hash that is not ours stays not-ours.
        assert!(
            transport.inbound_scope(&[0u8; 16]).is_none(),
            "an unrelated hash must not resolve",
        );
    }
}

/// CIRISEdge#499 — the transport as the lifecycle's destination sink.
///
/// Keeps the two halves that must not drift — edge's address table and
/// the leviculum node's routing table — behind one object, so a
/// transition cannot update one and forget the other.
impl crate::scope_lifecycle::ScopedDestinationSink for ReticulumTransport {
    fn register(
        &self,
        address: &MemberAddress,
        scope: &crate::cohort_scope::CohortScope,
    ) -> Result<(), String> {
        self.register_scoped_destination(address, scope)
            .map_err(|e| e.to_string())
    }

    fn retire(
        &self,
        address: &MemberAddress,
        scope: &crate::cohort_scope::CohortScope,
    ) -> Result<(), String> {
        self.retire_scoped_destination(address, scope)
            .map_err(|e| e.to_string())
    }
}
