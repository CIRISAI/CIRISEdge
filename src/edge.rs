//! Edge — top-level construct.
//!
//! Holds the persist directory + outbound queue handles, the
//! local signer, the registered transports, the verify pipeline,
//! the typed handler dispatch table, and the durable-outbound
//! dispatcher. Single shape across every CIRIS peer (lens, agent,
//! registry); peers compose around edge, not into it
//! (`MISSION.md` §3 anti-pattern 6).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use base64::Engine as _;
use chrono::Utc;
use futures::future::BoxFuture;
use tokio::sync::{broadcast, mpsc, oneshot, watch, Mutex};

use crate::cohort_scope::{CohortScope, CohortScopeEnforcement};
use crate::handler::{
    AbandonReason, Delivery, DurableHandle, DurableOutcome, DurableStatus, FederationPriority,
    Handler, HandlerContext, HandlerError, InlineTextMessage, Message,
};
use crate::identity::{build_envelope, envelope_body_sha256, sign_envelope, LocalSigner};
use crate::messages::{
    is_federation_attestation_emitting_type, AnnouncementPriority, EdgeEnvelope,
    FederationAnnouncement, MessageType, RefusalReason, ACCORD_THRESHOLD_M_OF_N,
};
use crate::outbound::{
    run_dispatcher, run_sweeps, DispatcherConfig, OutboundHandle, PeerDirectory,
    PeerSubscriptionFilter, StewardDirectory, StewardKey,
};
use crate::reachability::{record_if_tracking, AttemptOutcome, ReachabilityTracker};
use crate::transport::{InboundFrame, Transport, TransportError, TransportSendOutcome};
use crate::verify::{
    AccordHolderKey, HybridPolicy, VerifiedEnvelope, VerifyDirectory, VerifyError, VerifyPipeline,
};

// ─── Public configuration ───────────────────────────────────────────

// ─── CEG §10.1.2 spec constants (CIRISEdge#42, v0.12.0) ─────────────

/// Default TTL for a `holds_bytes:sha256:*` attestation row — 24
/// hours from `signed_at`, per CEG 0.1 §10.1.2. Configurable via
/// [`EdgeConfig::holds_bytes_ttl_seconds`]; this constant is the
/// spec-pinned default the [`Default`] impl on [`EdgeConfig`] reads.
/// Lives at the crate root (not behind the reticulum-feature gate) so
/// non-reticulum builds compile EdgeConfig::default unchanged.
pub const DEFAULT_HOLDS_BYTES_TTL_SECONDS: u64 = 24 * 60 * 60;

/// Default rolling window for the per-holder ContentMiss downweight
/// — 1 hour, per CEG 0.1 §10.1.2. A holder with ≥
/// [`DEFAULT_HOLDER_DOWNWEIGHT_MISS_THRESHOLD`] ContentMisses inside
/// this window is sorted to the tail of
/// `filter_holders_with_policy` output; after the window lapses
/// without further misses, the downweight clears and the holder
/// reappears at normal priority.
pub const DEFAULT_HOLDER_DOWNWEIGHT_WINDOW_SECONDS: u64 = 60 * 60;

/// Default ContentMiss count threshold within the rolling window — a
/// holder hitting this many misses is downweighted. Per CEG 0.1
/// §10.1.2: "Holders with >= 3 ContentMisses in the window are
/// downweighted".
pub const DEFAULT_HOLDER_DOWNWEIGHT_MISS_THRESHOLD: u32 = 3;

/// Default interval (seconds) at which the v0.18.0 background pruner
/// task calls
/// [`crate::transport::reticulum::ReticulumTransport::routing_blackhole_prune_expired`]
/// — 1 hour. `0` disables the background pruner; operators may then
/// call the prune surface manually via the routing-table FFI.
pub const DEFAULT_BLACKHOLE_PRUNE_INTERVAL_SECONDS: u64 = 3600;

/// CIRISEdge#45 — operator agent posture for the cohabiting peer.
///
/// Wire-string codec: `"client" / "proxy" / "server"` (snake_case) to
/// match the agent-side `AgentMode` enum from CIRISAgent release/2.9.4
/// (commit `64e026fcc`). Decoded by [`AgentMode::from_wire`]; the
/// translation into `EdgeConfig` knobs is owned by
/// [`AgentMode::apply_defaults`] — single source of truth for the
/// mode → config mapping (no scatter across init paths).
///
/// Behaviour matrix (v0.18.0):
///
/// | Mode     | Listener bound | Outbound queue max |
/// |----------|----------------|--------------------|
/// | Client   | no             | 256                |
/// | Proxy    | yes            | 4096 (current default) |
/// | Server   | yes + propagate| 65536              |
///
/// Transport-posture translation (Roaming / Full / Gateway / AP)
/// remains deferred — the v0.12.0 Leviculum interface-diversity work
/// did not surface a `reticulum_default_posture` enum on EdgeConfig,
/// so the v0.18.0 cut configures only the listener bind + outbound
/// queue cap. Transport-posture follow-up tracks the v0.19.0
/// observability cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AgentMode {
    /// Egress-only posture; the edge runtime does not bind a
    /// listener and ships a minimal (256-row) outbound queue.
    Client,
    /// Bidirectional; binds the configured listener, keeps the
    /// existing v0.17.x outbound-queue default. The CIRISEdge#45
    /// default mode — preserves v0.17.x behaviour when callers do
    /// not pass an `agent_mode` kwarg.
    #[default]
    Proxy,
    /// Always-on listener + propagate; bootstrap-node posture with
    /// a large outbound queue (65536 rows).
    Server,
}

impl AgentMode {
    /// Decode the wire-string token `"client" / "proxy" / "server"`.
    /// Returns `None` on any other value — the FFI surface maps `None`
    /// to a typed `ValueError` (PyO3) / `InvalidArgument` (UniFFI).
    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "client" => Some(Self::Client),
            "proxy" => Some(Self::Proxy),
            "server" => Some(Self::Server),
            _ => None,
        }
    }

    /// Wire-string encoder — inverse of [`Self::from_wire`].
    #[must_use]
    pub fn as_wire(&self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Proxy => "proxy",
            Self::Server => "server",
        }
    }

    /// Whether this mode binds the operator-configured listener
    /// (`listen_addr`). [`Self::Client`] is the only mode that returns
    /// `false`.
    #[must_use]
    pub fn binds_listener(&self) -> bool {
        !matches!(self, Self::Client)
    }

    /// Default outbound-queue cap for the mode (rows). The v0.17.x
    /// default is the [`Self::Proxy`] value; client / server widen /
    /// shrink around it.
    #[must_use]
    pub fn default_outbound_queue_max(&self) -> u32 {
        match self {
            Self::Client => 256,
            Self::Proxy => 4096,
            Self::Server => 65536,
        }
    }

    /// Apply the mode-derived defaults onto `config`. CRITICAL: the
    /// only place the mode → knob mapping lives. Every init path that
    /// accepts an `AgentMode` calls this exactly once before
    /// [`EdgeBuilder::config`] is invoked.
    pub fn apply_defaults(&self, config: &mut EdgeConfig) {
        config.agent_mode = *self;
        config.listener_bound = self.binds_listener();
        config.outbound_queue_max = self.default_outbound_queue_max();
    }
}

/// CIRISEdge#46 — canonical bootstrap-peer record. Operator-supplied
/// at every init via the new `bootstrap_peers` init param; reseeded
/// idempotently into persist's `federation_keys` directory. The
/// canonical INVARIANT: `peer_remove(handle, hard=true)` against a
/// canonical peer returns
/// [`EdgeBindingsError::CannotRemoveCanonicalPeer`] — the operator
/// cannot permanently lose knowledge of these rooting anchors. Soft
/// removal (`hard=false`) is permitted and preserved across restarts
/// (the reseed does NOT clear `removed_at`).
#[derive(Debug, Clone)]
pub struct CanonicalBootstrapPeer {
    /// Persist `federation_keys.key_id` for the canonical peer.
    pub key_id: String,
    /// Operator-friendly display name; surfaces on `peer_list` /
    /// `peer_get` projections as `EdgePeerInfo.alias`.
    pub alias: String,
    /// Base64-encoded Ed25519 public key — the load-bearing identity
    /// field. Persist's [`add_peer_record`] is idempotent on a
    /// matching pubkey; rejects with `Conflict` on a differing one.
    pub pubkey_ed25519_base64: String,
    /// Optional transport hint (e.g. `"tcp://agents.ciris.ai:4242"`).
    /// Persist stores this verbatim on the
    /// `federation_peer_metadata.transport_identity` field.
    pub transport_hint: Option<String>,
    /// Operator-supplied free-form description (purpose, owner,
    /// rotation cadence). Surfaces on the `EdgePeerInfo.notes`
    /// projection.
    pub description: Option<String>,
}

/// Top-level configuration. Defaults match the v0.1.0 P0 invariants
/// (`docs/THREAT_MODEL.md` §10).
#[derive(Debug, Clone)]
pub struct EdgeConfig {
    /// Consumer-side hybrid PQC acceptance policy (OQ-11).
    pub hybrid_policy: HybridPolicy,
    /// Replay-window width (AV-3, OQ-08). Default 5 minutes.
    pub replay_window_seconds: u64,
    /// Replay-window capacity (AV-12). Default 100k.
    pub max_replay_entries: usize,
    /// Max envelope body size at the verify pipeline; AV-13 P0.
    pub max_body_bytes: usize,
    /// Max [`crate::messages::ContentBody::bytes`] size accepted on
    /// inbound dispatch (CIRISEdge#21 v0.8.0). Extends the AV-13 body-
    /// size family with a separate cap for the content-addressable
    /// byte-fetch path — `max_body_bytes` already gates the envelope
    /// at verify-pipeline entry, but `ContentBody.bytes` may
    /// reasonably exceed the envelope cap (a JSON envelope wrapping
    /// 16 MiB of bytes serializes to ~21 MiB with base64), so the
    /// content-fetch path lifts the envelope cap and re-applies a
    /// content-specific cap on the bytes field after parse. Default
    /// [`crate::messages::DEFAULT_MAX_CONTENT_BODY_BYTES`] = 16 MiB
    /// (CIRISEdge#21 Phase 1 spec point 7). Oversized rejects with
    /// the existing AV-13 family error
    /// ([`crate::verify::VerifyError::BodyTooLarge`]).
    pub max_content_body_bytes: usize,
    /// Outbound dispatcher tunables.
    pub dispatcher: DispatcherConfig,
    /// CIRISEdge#31 — optional file path persisting the operator-set
    /// local display name. `None` → display name lives only in-process
    /// (lost on restart). `Some(path)` → the name is read from `path`
    /// at `Edge::build` and written on every `set_local_display_name`
    /// call. UTF-8 text file; whitespace-trimmed; max 256 bytes
    /// enforced at the setter site. Read errors at build time are
    /// non-fatal (no name set); write errors at setter time surface as
    /// [`EdgeError::Config`].
    pub display_name_path: Option<std::path::PathBuf>,
    /// CIRISEdge#34 — per-channel capacity for the
    /// [`crate::events::EventBus`] broadcast channels. Default
    /// [`crate::events::DEFAULT_EVENT_CHANNEL_CAPACITY`] (1024).
    pub event_channel_capacity: usize,
    /// CIRISEdge#29 (v0.11.0) — rolling window in seconds for the
    /// per-medium reachability tracker. Default 300s (5 minutes). The
    /// tracker counts `(peer, transport)` attempts and successes
    /// recorded by the send / dispatch / inbound hook sites; the
    /// CIRISEdge#22 Tier 3 pymethod surface (v0.16.0) consumes the
    /// snapshot to render `peer_reachability(key_id) → dict[str, float]`.
    pub reachability_window_seconds: u64,
    /// CIRISEdge#42 (v0.12.0, CEG §10.1.2) — TTL in seconds for
    /// `holds_bytes:sha256:{prefix}` attestations. After this many
    /// seconds elapse from `signed_at`, the attestation is **stale**
    /// and `PeerResolver::resolve_holders_with_signed_at` results are
    /// filtered to exclude it before `filter_holders_with_policy`
    /// returns. Default [`DEFAULT_HOLDS_BYTES_TTL_SECONDS`] (86_400s =
    /// 24 hours per CEG §10.1.2 spec). Test deployments may shorten
    /// this to verify the staleness logic; production should leave it
    /// at the default.
    pub holds_bytes_ttl_seconds: u64,
    /// CIRISEdge#42 (v0.12.0, CEG §10.1.2) — rolling window in seconds
    /// for the per-holder ContentMiss downweight tracker. A holder
    /// with ≥ [`Self::holder_downweight_miss_threshold`] misses inside
    /// this window is sorted to the tail of
    /// `filter_holders_with_policy` output. Default
    /// [`DEFAULT_HOLDER_DOWNWEIGHT_WINDOW_SECONDS`] (3600s = 1 hour
    /// per CEG §10.1.2 spec).
    pub holder_downweight_window_seconds: u64,
    /// CIRISEdge#42 (v0.12.0, CEG §10.1.2) — ContentMiss count
    /// threshold inside the downweight window. Default
    /// [`DEFAULT_HOLDER_DOWNWEIGHT_MISS_THRESHOLD`] (3 per CEG §10.1.2
    /// spec). A holder hitting this count is downweighted; after the
    /// window lapses without further misses, the downweight clears.
    pub holder_downweight_miss_threshold: u32,
    /// CIRISEdge#39 (slotted v0.17.0) — Counter-RII probe-pattern
    /// observer toggle. Default `false` — observation is opt-in per
    /// deployment per the privacy posture (CIRISEdge#39 spec
    /// "Configurable on/off"). When `true`, [`Edge::build`] wires a
    /// [`crate::ProbePatternObserver`] from the federation directory
    /// plus [`Self::probe_pattern_observer_config`]; when `false`,
    /// `Edge::detector` is `None` and the `dispatch_inbound` hook is
    /// a single `Option::is_some` branch.
    pub probe_pattern_observer_enabled: bool,
    /// CIRISEdge#39 — detector tuning. When
    /// [`Self::probe_pattern_observer_enabled`] is `true`, this config
    /// is cloned into the constructed observer. Calibration-channel
    /// parameters (cohort centroids, thresholds) reach the detector
    /// through this field; lens-core's startup load of the current
    /// `CalibrationBundle` shapes the per-deployment thresholds before
    /// edge boots. Defaults to [`crate::ProbePatternConfig::default`]
    /// (conservative thresholds favouring false-negatives).
    pub probe_pattern_observer_config: crate::ProbePatternConfig,
    /// CIRISEdge#45 (v0.18.0) — the operator-declared posture for the
    /// cohabiting peer. [`AgentMode::Proxy`] is the default
    /// (preserves v0.17.x behaviour); init paths that accept the
    /// `agent_mode` kwarg call [`AgentMode::apply_defaults`] to flip
    /// the derived fields ([`Self::listener_bound`],
    /// [`Self::outbound_queue_max`]) before this `EdgeConfig` reaches
    /// [`EdgeBuilder::config`]. See `AgentMode` for the wire-string
    /// codec + the full behaviour matrix.
    pub agent_mode: AgentMode,
    /// CIRISEdge#45 (v0.18.0) — derived from [`Self::agent_mode`] by
    /// [`AgentMode::apply_defaults`]. `true` for `proxy / server`,
    /// `false` for `client`. Hosts that bind their own listener (PyO3
    /// `init_edge_runtime` Step 4) consult this to decide whether to
    /// call `transport_config.listen_addr = ...`.
    pub listener_bound: bool,
    /// CIRISEdge#45 (v0.18.0) — derived from [`Self::agent_mode`] by
    /// [`AgentMode::apply_defaults`]. Mode-default outbound queue cap
    /// (256 / 4096 / 65536). Surfaces on the operator dashboard as
    /// the configured cap; the actual enforcement lives in the
    /// outbound dispatcher's row-admission path (already pinned by
    /// persist's queue plumbing).
    pub outbound_queue_max: u32,
    /// CIRISEdge#33 background pruner (v0.18.0 lifecycle hook) —
    /// seconds between `routing_blackhole_prune_expired` ticks on the
    /// `Edge::run` task graph. `0` disables the background pruner;
    /// operators may then call the prune surface manually via the
    /// routing-table FFI. Default
    /// [`DEFAULT_BLACKHOLE_PRUNE_INTERVAL_SECONDS`] (3600s = 1 hour).
    pub blackhole_prune_interval_seconds: u64,
    /// CIRISEdge#48-A (v0.19.1) — cohort-scope enforcement posture
    /// per FSD `FEDERATION_SCALING_MODEL.md` + CIRISNodeCore SCHEMA
    /// §3.2. Default is [`CohortScopeEnforcement::Strict`] —
    /// **wire-format invariant**, not a deployment knob. Operators
    /// who need a staged rollout may temporarily set `WarnOnly`;
    /// production MUST default to `Strict`.
    ///
    /// `Strict` rejects with a typed [`EdgeError::CohortScopeRefused*`]
    /// variant. `WarnOnly` emits a `tracing::warn!` and allows the
    /// envelope through. `Off` skips the check entirely — testing /
    /// dev only.
    ///
    /// See [`crate::cohort_scope`] for the enforcement rules.
    pub cohort_scope_enforcement: CohortScopeEnforcement,
}

impl Default for EdgeConfig {
    fn default() -> Self {
        Self {
            hybrid_policy: HybridPolicy::Strict,
            replay_window_seconds: 300,
            max_replay_entries: 100_000,
            max_body_bytes: 8 * 1024 * 1024,
            // CIRISEdge#21 v0.8.0 — separate AV-13 cap for
            // `ContentBody.bytes`. A consumer that wants to actually
            // receive 16 MiB `ContentBody` payloads must also raise
            // `max_body_bytes` accordingly (`bytes: Vec<u8>`
            // serializes to ~3x its raw size as JSON integer-array,
            // so 16 MiB raw ≈ 48 MiB envelope-wire); the
            // content-fetch path's `dispatch_inbound` enforces THIS
            // field post-parse on the bytes vector itself. The
            // envelope-level cap is the cheap pre-check; this is the
            // body-level pin.
            max_content_body_bytes: crate::messages::DEFAULT_MAX_CONTENT_BODY_BYTES,
            dispatcher: DispatcherConfig::default(),
            display_name_path: None,
            event_channel_capacity: crate::events::DEFAULT_EVENT_CHANNEL_CAPACITY,
            // CIRISEdge#29 — 5min window matches the v0.4.0 PeerResolver
            // announce-recording cadence + the replay window: a peer
            // whose announces are still being recorded is by definition
            // reachable in this window.
            reachability_window_seconds: 300,
            // CIRISEdge#42 (CEG §10.1.2) — spec-pinned defaults. The
            // 24h TTL and 1h downweight window are normative; the 3-miss
            // threshold mirrors the spec's "Holders with >= 3
            // ContentMisses in the window are downweighted" sentence.
            holds_bytes_ttl_seconds: DEFAULT_HOLDS_BYTES_TTL_SECONDS,
            holder_downweight_window_seconds: DEFAULT_HOLDER_DOWNWEIGHT_WINDOW_SECONDS,
            holder_downweight_miss_threshold: DEFAULT_HOLDER_DOWNWEIGHT_MISS_THRESHOLD,
            // CIRISEdge#39 — observation is opt-in per deployment
            // (privacy posture). Default-off means an unmodified
            // EdgeConfig leaves the detector field as `None`.
            probe_pattern_observer_enabled: false,
            probe_pattern_observer_config: crate::ProbePatternConfig::default(),
            // CIRISEdge#45 (v0.18.0) — default mode is Proxy. The
            // listener_bound + outbound_queue_max defaults mirror the
            // Proxy column of `AgentMode::apply_defaults` so an
            // unmodified `EdgeConfig::default()` matches v0.17.x.
            agent_mode: AgentMode::Proxy,
            listener_bound: true,
            outbound_queue_max: 4096,
            // v0.18.0 — background blackhole-rule pruner default.
            // 0 disables; `Edge::run` skips the spawn when the value
            // is 0 OR no `Arc<dyn BlackholeRules>` was wired through
            // the Reticulum transport.
            blackhole_prune_interval_seconds: DEFAULT_BLACKHOLE_PRUNE_INTERVAL_SECONDS,
            // v0.19.1 (CIRISEdge#48-A) — wire-format invariant; the
            // default MUST be `Strict`. WarnOnly is a migration aid;
            // Off is the escape hatch.
            cohort_scope_enforcement: CohortScopeEnforcement::Strict,
        }
    }
}

/// Top-level error type.
#[derive(thiserror::Error, Debug)]
pub enum EdgeError {
    #[error("verify error: {0}")]
    Verify(#[from] VerifyError),
    #[error("transport error: {0}")]
    Transport(#[from] crate::TransportError),
    #[error("destination unreachable: {0}")]
    Unreachable(String),
    #[error("persist error: {0}")]
    Persist(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("handler error: {0}")]
    Handler(#[from] HandlerError),
    #[error("no handler registered for message type: {0:?}")]
    NoHandler(MessageType),
    #[error("delivery class mismatch: {0:?} declared {1} but called as {2}")]
    DeliveryClassMismatch(MessageType, &'static str, &'static str),
    /// CIRISEdge#20 — `Edge::send_federation` was called but the
    /// configured [`StewardDirectory`] returned an empty steward set.
    /// Typed (NOT a panic) so the caller can surface the operational
    /// condition: a federation with no stewards in its
    /// `federation_keys` directory cannot accept high-priority
    /// federation traffic until the steward set is seeded
    /// (MISSION.md §3 anti-pattern 6 — fail-loud, no silent drops).
    #[error(
        "no stewards registered for FederationPriority::{0:?} \
         (federation_keys directory has zero identity_type=\"steward\" rows)"
    )]
    NoStewards(FederationPriority),
    /// CIRISEdge#48-A (v0.19.1) — refused `send_federation` /
    /// federation-class fan-out because the message-level cohort_scope
    /// is `SelfOnly` or `Family` (locality variants MUST NOT cross
    /// federation-class hops). Wire-format invariant per FSD
    /// `FEDERATION_SCALING_MODEL.md`.
    #[error(
        "cohort_scope {cohort_scope:?} refused on federation-class fan-out \
         (locality variants MUST NOT cross federation hops; CIRISEdge#48-A)"
    )]
    CohortScopeRefusedFederation {
        /// The declared cohort scope.
        cohort_scope: CohortScope,
    },
    /// CIRISEdge#48-A (v0.19.1) — refused `send_mandatory` because
    /// the message-level cohort_scope is `SelfOnly` or `Family`.
    /// Wire-format invariant per FSD `FEDERATION_SCALING_MODEL.md`.
    #[error(
        "cohort_scope {cohort_scope:?} refused on mandatory broadcast \
         (locality variants MUST NOT broadcast federation-wide; CIRISEdge#48-A)"
    )]
    CohortScopeRefusedMandatory {
        /// The declared cohort scope.
        cohort_scope: CohortScope,
    },
    /// CIRISEdge#48-A (v0.19.1) — refused point-to-point
    /// (`send` / `send_durable`) because the recipient is not authorized
    /// for the declared cohort scope (recipient not in family cohort
    /// / not in named cohort / not self).
    #[error(
        "cohort_scope {cohort_scope:?} refused: recipient {recipient_key_id} \
         is not authorized for this scope (CIRISEdge#48-A)"
    )]
    CohortScopeRefusedRecipient {
        /// The declared cohort scope.
        cohort_scope: CohortScope,
        /// The recipient `federation_keys.key_id` that failed the
        /// scope authorization.
        recipient_key_id: String,
    },
    /// CIRISEdge#48-A (v0.19.1) — consumer-side symmetric check.
    /// Inbound envelope's claimed `cohort_scope` does not match the
    /// sender's directory-recorded scope. Emitted at
    /// `dispatch_inbound` and projected as a moderation-signal event
    /// on the EventBus.
    #[error(
        "cohort_scope violation: sender {sender_key_id} claimed \
         {claimed_scope:?} but directory records {directory_scope:?} \
         (CIRISEdge#48-A)"
    )]
    CohortScopeViolation {
        /// The sender's `federation_keys.key_id`.
        sender_key_id: String,
        /// The cohort scope the sender CLAIMED on the envelope.
        claimed_scope: CohortScope,
        /// The cohort scope the directory records for this sender
        /// (`None` = no recorded scope; defaults to `Public`).
        directory_scope: Option<CohortScope>,
    },
}

// ─── Type-erased handler dispatch ───────────────────────────────────
//
// `Handler<M>` is generic over the typed message; the registry stores
// erased closures that take a verified envelope and produce response
// bytes. Each `register_handler<M, H>` call captures the typed
// handler in a closure that does parse → dispatch → serialize.

type ErasedHandlerFn = Arc<
    dyn for<'a> Fn(&'a EdgeEnvelope, HandlerContext) -> BoxFuture<'a, Result<Vec<u8>, HandlerError>>
        + Send
        + Sync,
>;

struct RegisteredHandler {
    erased: ErasedHandlerFn,
}

// ─── Edge ───────────────────────────────────────────────────────────

/// Inline-text inbound subscriber registry entry (CIRISEdge#22 Tier 2).
///
/// Each entry holds an unbounded sender that the inbound dispatcher
/// pushes `(sender_key_id, body_text)` tuples onto. A Python-owned
/// drainer thread (spawned in [`crate::ffi::pyo3`] when
/// `register_inline_text_handler` is called) receives from the matching
/// receiver, acquires the GIL, and invokes the user-supplied Python
/// callback. Dropping the sender (via [`Edge::unregister_inline_text_subscriber`])
/// causes the drainer to observe a closed channel and exit cleanly —
/// the subscription-lifecycle invariant the Python `SubscriptionHandle`
/// enforces.
///
/// Unbounded by design: dropping events under back-pressure would
/// degrade the CommunicationBus-replacement semantic the Python adapter
/// builds on. Subscribers that can't keep up must drop their handle —
/// a closed channel removes the entry from the registry on the next
/// dispatch (lazy cleanup, no separate sweep needed).
pub(crate) type InlineTextSubscriber = mpsc::UnboundedSender<(String, String)>;

/// CIRISEdge#22 Tier 3 (v0.17.0) — projection of a verified envelope
/// onto the wire surface the `subscribe_feed` AsyncIterator delivers.
/// Kept thin (the verify substrate already produced the full
/// [`VerifiedEnvelope`] internally; we surface the fields the
/// Python-side consumer needs for routing + correlation).
#[derive(Debug, Clone)]
pub struct VerifiedEnvelopeSnapshot {
    /// The verified envelope itself — sender, message_type, body bytes,
    /// signatures, nonce, sent_at — all stable wire fields.
    pub envelope: EdgeEnvelope,
    /// The body_sha256 the substrate computed at verify time. Same
    /// shape as `EdgeEnvelope`'s `in_reply_to` field — useful for
    /// joining inbound responses to outbound requests.
    pub body_sha256: [u8; 32],
    /// Transport the frame arrived on (`reticulum-rs` / `http` / etc.).
    pub transport_id: crate::transport::TransportId,
    /// Wall-clock at which the inbound frame was received (frame.received_at).
    pub received_at: chrono::DateTime<chrono::Utc>,
}

/// CIRISEdge#22 Tier 3 (v0.17.0) — result of an [`Edge::fetch_content`]
/// call. The Python `fetch_content` pymethod returns the JSON-shaped
/// projection of this enum.
#[derive(Debug, Clone)]
pub enum ContentResult {
    /// The peer returned a verified `ContentBody` whose
    /// `sha256(bytes) == requested_sha256` invariant holds (the
    /// `dispatch_inbound` ContentBody gate validates this before
    /// signalling the pending channel).
    Bytes(Vec<u8>),
    /// The peer returned a `ContentMiss` (typed reason). Fetcher
    /// SHOULD try another peer per the MissReason taxonomy.
    ContentMiss { reason: String },
}

/// Top-level edge handle. Construct via [`Edge::builder`].
pub struct Edge {
    verify: Arc<VerifyPipeline>,
    queue: Arc<dyn OutboundHandle>,
    signer: Arc<LocalSigner>,
    transports: Vec<Arc<dyn Transport>>,
    handlers: Arc<Mutex<HashMap<MessageType, RegisteredHandler>>>,
    /// Inline-text inbound fan-out registry (CIRISEdge#22 Tier 2;
    /// v0.9.0). Distinct from `handlers` because the typed handler
    /// dispatch supports exactly **one** handler per [`MessageType`] —
    /// the Python `register_inline_text_handler` surface must accept
    /// multiple concurrent subscribers (one per `EdgeCommunicationAdapter`
    /// consumer at minimum). Subscriptions are keyed by an
    /// monotonically-increasing u64 (`inline_text_next_id`); the Python
    /// `SubscriptionHandle::unsubscribe` removes by id.
    inline_text_subscribers: Arc<std::sync::Mutex<HashMap<u64, InlineTextSubscriber>>>,
    /// Subscription id allocator for [`Self::inline_text_subscribers`].
    /// `AtomicU64::fetch_add` so the allocator is lock-free.
    inline_text_next_id: Arc<AtomicU64>,
    /// CIRISEdge#22 Tier 3 (v0.17.0) — broadcast channel carrying every
    /// verified inbound `EdgeEnvelope` for the `subscribe_feed`
    /// AsyncIterator surface. Construction is unconditional; emission
    /// in `dispatch_inbound` swallows the channel's "no subscribers"
    /// error so a build without subscribers pays only an `Arc` refcount.
    /// Capacity is bounded by [`crate::events::DEFAULT_EVENT_CHANNEL_CAPACITY`]
    /// (same as `EventBus`) — slow consumers see `Lagged` and skip ahead.
    verified_envelope_tx: broadcast::Sender<VerifiedEnvelopeSnapshot>,
    /// CIRISEdge#22 Tier 3 (v0.17.0) — in-flight content-fetch
    /// correlation map. Each entry pairs a `body_sha256` with a oneshot
    /// sender; when `dispatch_inbound` sees a verified `ContentBody` or
    /// `ContentMiss` matching a pending fetch's sha256, the sender is
    /// signalled and the entry removed. Bounded by call-site lifecycle —
    /// `Edge::fetch_content` drops the receiver on timeout, which
    /// closes the oneshot and the dispatcher prunes lazily.
    content_fetch_pending: Arc<std::sync::Mutex<HashMap<[u8; 32], oneshot::Sender<ContentResult>>>>,
    /// Optional pipeline run on outbound inline-text envelopes
    /// (SPEAK responses, LLM prompts, WBD bodies, DSAR text). When
    /// `Some`, `send_inline` / `send_durable_inline` invoke this
    /// before signing — classify, scrub, encrypt-and-store secret
    /// spans per FSD §1.4. When `None`, those methods skip the
    /// pipeline and behave identically to `send` / `send_durable`.
    /// Construct via `default_speak_pipeline(secrets, actor_id)` in
    /// `ciris_persist::pipeline`. Closes CIRISAgent#756 Q1.
    speak_pipeline:
        Option<Arc<ciris_persist::pipeline::Pipeline<ciris_persist::prelude::InlineTextEnvelope>>>,
    /// Optional peer-enumeration adapter consumed by
    /// [`Edge::send_mandatory`] to fan out a `Delivery::Mandatory`
    /// envelope to every peer in the directory (CIRISEdge#18 / FSD
    /// §3.2). When `None`, `send_mandatory` returns a typed config
    /// error — the federation broadcast cannot pick recipients.
    peer_directory: Option<Arc<dyn PeerDirectory>>,
    /// Optional steward-enumeration adapter consumed by
    /// [`Edge::send_federation`] for the high-priority steward-class
    /// fan-out (CIRISEdge#20). Resolved dynamically on every send —
    /// the rotation-aware semantic the issue's ask #4 requires. When
    /// `None`, `send_federation` returns a typed config error.
    /// Production deployments pass `Arc<dyn FederationDirectory>`
    /// (any persist backend); the blanket impl in `crate::outbound`
    /// lifts it via persist v2.7.0's `list_keys_by_identity_type`.
    steward_directory: Option<Arc<dyn StewardDirectory>>,
    /// Optional per-peer subscription filter. Consulted by
    /// subscription-respecting code paths; **deliberately bypassed**
    /// by `Delivery::Mandatory` (the load-bearing wire change of
    /// CIRISEdge#18; the bypass is exercised in
    /// `tests/federation_announcement_mandatory.rs`).
    subscription_filter: Option<Arc<dyn PeerSubscriptionFilter>>,
    /// CIRISEdge#34 — per-category broadcast bus for AsyncIterator
    /// subscribers. Construction is unconditional (`Arc<EventBus>`
    /// always present); emission is fire-and-forget at the call site,
    /// so a build without subscribers has zero overhead beyond the
    /// `Arc` refcount.
    events: Arc<crate::events::EventBus>,
    /// CIRISEdge#28 (v0.19.0) — counter + gauge bag. Every send /
    /// receive / verify-failure / transport-bytes path increments
    /// the appropriate field; `metrics_snapshot` on the PyO3 / UniFFI
    /// surface projects the live state. Cheap clone (every field is
    /// an `Arc`). See [`crate::observability::EdgeMetrics`].
    metrics: crate::observability::EdgeMetrics,
    /// CIRISEdge#31 — operator-set local display name. Backs
    /// `local_display_name` / `set_local_display_name` on the
    /// pyo3 surface. Persisted to disk if [`EdgeConfig::display_name_path`]
    /// is set; otherwise lives only for the lifetime of the process.
    /// `Arc<RwLock<_>>` so the read path (called from every UI render)
    /// doesn't block writers; setter is rare (operator-initiated).
    display_name: Arc<std::sync::RwLock<Option<String>>>,
    /// CIRISEdge#29 (v0.11.0) — per-(peer × medium) reachability
    /// tracker. Always present (constructed from
    /// `EdgeConfig::reachability_window_seconds` in
    /// [`EdgeBuilder::build`]); the send / durable-dispatch / inbound
    /// hook sites record attempts here. Surfaces via
    /// [`Self::reachability_tracker`] for the v0.16.0 CIRISEdge#22
    /// Tier 3 pymethod consumer (the sibling FFI agent's territory —
    /// no pymethods added in this scope per the issue's "Scope NOT in
    /// this issue" note).
    reachability: Arc<ReachabilityTracker>,
    /// CIRISEdge#32 (v0.14.0) — typed handle to the Reticulum
    /// transport, if one was registered via
    /// [`EdgeBuilder::reticulum_transport`]. The transport is ALSO
    /// upcast and pushed into [`Self::transports`] so the listen-loop
    /// machinery is unchanged; this sidecar gives the Links FFI surface
    /// a path to the concrete `ReticulumTransport::link_*` methods
    /// without an `Any`-style downcast. `None` when only HTTP / other
    /// non-Reticulum transports were registered — the UniFFI
    /// `link_open` / `link_request` / `link_teardown` then return
    /// `EdgeBindingsError::Unsupported`.
    #[cfg(feature = "_reticulum-module")]
    reticulum_transport: Option<Arc<crate::transport::reticulum::ReticulumTransport>>,
    /// CIRISEdge#26 mutation surface (v0.15.1) — optional
    /// concrete-typed `Arc<dyn FederationDirectory>` retained so the
    /// UniFFI peer-mutation surface (`peer_add` / `peer_remove` /
    /// `peer_set_{alias,trust,notes,policy}`) can drive the 6 persist
    /// v3.1.0 (CIRISPersist#117) methods that aren't reachable through
    /// the type-erased [`VerifyDirectory`] adapter.
    ///
    /// `None` when the host didn't wire one (e.g., tests that only need
    /// the verify pipeline); the 6 mutation FFIs surface
    /// `EdgeBindingsError::Unsupported` in that case. The pyo3
    /// cohabitation init path
    /// (`crate::ffi::pyo3::init_edge_runtime`) populates it from the
    /// `federation_directory_capsule` it already extracts; the
    /// `from_keyring_seed_dir` convenience constructor populates it
    /// from the same `FederationDirectorySqlite` it opens for verify.
    federation_directory: Option<Arc<dyn ciris_persist::federation::FederationDirectory>>,
    /// CIRISEdge#39 (slotted v0.17.0) — optional Counter-RII probe-
    /// pattern detector. `None` when
    /// [`EdgeConfig::probe_pattern_observer_enabled`] is `false` (the
    /// default). The `dispatch_inbound` hook gates emission on
    /// `if let Some(detector) = ...` — disabled deployments pay zero
    /// runtime cost beyond the Option branch.
    pub detector: Option<Arc<crate::ProbePatternObserver>>,
    /// CIRISEdge#46 (v0.18.0) — set of `key_id`s declared canonical by
    /// the operator via the init-time `bootstrap_peers` parameter. The
    /// HashSet is populated at [`EdgeBuilder::build`] from
    /// [`EdgeBuilder::canonical_bootstrap_peers`] (which the
    /// PyO3 / UniFFI cohabitation init paths feed). Consulted by
    /// [`Self::is_canonical_peer`] (the `peer_remove` hard-remove
    /// guard) and by `EdgePeerInfo` projection. Wrapped in an
    /// `Arc<RwLock<_>>` so future operator-driven mutations (a
    /// hypothetical `add_canonical_peer` FFI) can update it without
    /// re-building Edge — v0.18.0 ships with a load-time-only setter
    /// (the reseed runs once per init); the lock makes the path
    /// forward-compatible without binding-side churn.
    canonical_peers: Arc<std::sync::RwLock<HashSet<String>>>,
    /// CIRISEdge#48-A (v0.19.1) — operator-declared per-peer cohort
    /// scope, sourced from the peer's `policy_blob.cohort` field on
    /// `peer_set_policy` calls. Populated lazily — peers absent from
    /// the map default to [`CohortScope::Public`] (the implicit pre-
    /// v0.19.1 behaviour).
    ///
    /// Producer-side outbound enforcement (`Edge::send_*`) consults
    /// this map to decide whether the explicit recipient is
    /// authorized for the declared scope. Consumer-side
    /// (`dispatch_inbound`) consults it to check the sender's claimed
    /// scope against the directory-recorded one.
    ///
    /// **v0.19.1 dependency on persist**: persist v3.2.0 does not
    /// expose a `peer_metadata_for(key_id) → PeerMetadataRow` read
    /// accessor on the `FederationDirectory` trait, so this map is
    /// the edge-side mirror of what the operator declared via the
    /// peer-mutation FFI. A future persist cut exposing
    /// `peer_metadata_for` (or a first-class `cohort_membership`
    /// API) would allow the read path to consult persist directly;
    /// for v0.19.1 the in-process map is the authoritative source
    /// (matches the "edge-only enforcement, no persist coordination"
    /// constraint of #48-A).
    pub(crate) cohort_membership: Arc<std::sync::RwLock<HashMap<String, CohortScope>>>,
    config: EdgeConfig,
}

/// Builder for [`Edge`]. See FSD §3.2 for the call shape.
pub struct EdgeBuilder {
    directory: Option<Arc<dyn VerifyDirectory>>,
    /// CIRISEdge#26 mutation surface (v0.15.1) — see
    /// [`Edge::federation_directory`]. Set via
    /// [`EdgeBuilder::federation_directory`]; `None` → the 6 UniFFI
    /// peer-mutation entry points surface `Unsupported`.
    federation_directory: Option<Arc<dyn ciris_persist::federation::FederationDirectory>>,
    queue: Option<Arc<dyn OutboundHandle>>,
    signer: Option<Arc<LocalSigner>>,
    transports: Vec<Arc<dyn Transport>>,
    speak_pipeline:
        Option<Arc<ciris_persist::pipeline::Pipeline<ciris_persist::prelude::InlineTextEnvelope>>>,
    peer_directory: Option<Arc<dyn PeerDirectory>>,
    steward_directory: Option<Arc<dyn StewardDirectory>>,
    subscription_filter: Option<Arc<dyn PeerSubscriptionFilter>>,
    events: Option<Arc<crate::events::EventBus>>,
    /// CIRISEdge#32 (v0.14.0) — see [`Edge::reticulum_transport`]. Set
    /// via [`EdgeBuilder::reticulum_transport`]; the same `Arc` is also
    /// pushed into `transports` so listen+send fan-out is unchanged.
    #[cfg(feature = "_reticulum-module")]
    reticulum_transport: Option<Arc<crate::transport::reticulum::ReticulumTransport>>,
    /// CIRISEdge#34 (v0.14.0 wiring) — optionally pre-built
    /// reachability tracker so a Reticulum transport constructed BEFORE
    /// Edge (the pyo3 cohabitation init order) can share the same
    /// tracker instance Edge ends up exposing via
    /// [`Edge::reachability_tracker`]. `None` → the builder constructs
    /// one at `build()` from [`EdgeConfig::reachability_window_seconds`]
    /// (the v0.11.0 behaviour).
    reachability: Option<Arc<ReachabilityTracker>>,
    /// CIRISEdge#39 (v0.17.0) — optional persist `DerivedSchema`
    /// admission handle. When set AND the probe-pattern observer is
    /// enabled, the constructed [`crate::ProbePatternObserver`] is
    /// configured with this handle so `emit_verdict` writes through
    /// `put_edge_detection_event` (persist v3.1.1+ / #118). When
    /// unset, the detector falls back to the v0.13.0 STUB behavior
    /// (`tracing::warn!` log only).
    derived_schema: Option<Arc<dyn crate::detector::EdgeDetectionAdmission>>,
    /// CIRISEdge#46 (v0.18.0) — operator-supplied canonical bootstrap
    /// peers. Populates [`Edge::canonical_peers`] at `build()`. The
    /// **persist reseed** (calling
    /// `FederationDirectory::add_peer_record` per row) does NOT happen
    /// here — `build()` is sync and the directory's contract is async.
    /// Cohabitation init paths call
    /// [`reseed_canonical_bootstrap_peers`] separately with the same
    /// `Vec` before threading it into the builder.
    canonical_bootstrap_peers: Vec<CanonicalBootstrapPeer>,
    config: EdgeConfig,
}

/// CIRISEdge#33 background-pruner loop (v0.18.0 lifecycle hook) —
/// the extracted body of the [`Edge::run`] pruner spawn, exposed so
/// tests can drive it directly without standing up a Reticulum
/// transport. Production callers SHOULD NOT spawn this themselves;
/// `Edge::run` owns the lifecycle.
///
/// Loops at `interval_seconds` cadence calling
/// [`BlackholeRules::blackhole_prune_expired`] with `Utc::now()`.
/// Exits cleanly when the shutdown watcher fires.
/// `MissedTickBehavior::Skip` so a system suspend / GC pause doesn't
/// produce a burst of prune calls on wake.
pub async fn run_blackhole_pruner(
    rules: Arc<dyn ciris_persist::federation::BlackholeRules>,
    interval_seconds: u64,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    if interval_seconds == 0 {
        // Defensive: callers SHOULD gate the spawn at interval > 0,
        // but if a caller routes here with 0, exit cleanly rather
        // than panicking inside `tokio::time::interval` (which
        // panics on zero-duration tickers).
        return;
    }
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_seconds));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                tracing::info!("blackhole pruner: shutdown");
                break;
            }
            _ = ticker.tick() => {
                match rules.blackhole_prune_expired(Utc::now()).await {
                    Ok(n) => {
                        if n > 0 {
                            tracing::info!(
                                pruned = n,
                                "blackhole pruner: dropped expired rules",
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "blackhole pruner: prune failed",
                        );
                    }
                }
            }
        }
    }
}

/// CIRISEdge#46 (v0.18.0) — idempotent reseed of canonical bootstrap
/// peers into persist's `federation_keys` directory.
///
/// For each [`CanonicalBootstrapPeer`]:
///   - Calls
///     [`FederationDirectory::add_peer_record`](ciris_persist::federation::FederationDirectory::add_peer_record)
///     with `identity_type = "agent"`. Persist's contract: idempotent
///     on matching pubkey (silent OK); `Conflict` on differing pubkey.
///   - Operator-set TRUST state on a LIVE row is preserved: persist's
///     `add_peer_record` short-circuits on a live metadata row whose
///     `transport_identity` matches (idempotent no-op).
///   - Soft-removed rows ARE re-admitted: per the persist v3.1.0+
///     sqlite contract (see
///     `tests/canonical_peer.rs::canonical_peer_after_soft_remove_reappears_only_when_unhidden`),
///     `add_peer_record` against a row whose `removed_at IS NOT NULL`
///     clears `removed_at` AND resets the metadata fields to defaults
///     (`trust = Untrusted`, `alias = NULL`, `notes = NULL`). So the
///     init-time reseed effectively REVERSES a prior soft-hide for
///     canonical peers. The canonical INVARIANT is "cannot
///     HARD-remove" (permanent knowledge loss); the persist re-admit
///     means a canonical row that was operator-soft-hidden returns to
///     live state at the next init.
///   - If [`CanonicalBootstrapPeer::alias`] / `description` are
///     non-empty, fires
///     [`update_peer_alias`](ciris_persist::federation::FederationDirectory::update_peer_alias)
///     / `update_peer_notes` so operator-friendly labels appear on
///     the routing dashboard. The post-`add_peer_record` call lands
///     against the now-live row (re-admitted from the soft-hidden
///     state if applicable) — these calls are best-effort (errors
///     are logged but don't fail the reseed).
///
/// Propagates `add_peer_record` errors verbatim — operator
/// misconfiguration (a differing pubkey for an existing key_id) MUST
/// surface, not silently pass.
pub async fn reseed_canonical_bootstrap_peers(
    directory: &Arc<dyn ciris_persist::federation::FederationDirectory>,
    peers: &[CanonicalBootstrapPeer],
) -> Result<(), ciris_persist::federation::Error> {
    for peer in peers {
        directory
            .add_peer_record(
                &peer.key_id,
                &peer.pubkey_ed25519_base64,
                ciris_persist::federation::types::identity_type::AGENT,
                peer.transport_hint.clone(),
            )
            .await?;
        // Best-effort alias/notes refresh. If the metadata row is
        // soft-removed (the canonical-but-hidden case) these surface
        // a `PeerNotFound` from persist — swallowed deliberately so
        // operator-soft-removed canonicals stay hidden (the row's
        // labels become re-applicable when the operator un-hides).
        if !peer.alias.is_empty() {
            let _ = directory
                .update_peer_alias(&peer.key_id, Some(peer.alias.clone()))
                .await;
        }
        if let Some(notes) = peer.description.as_ref() {
            let _ = directory
                .update_peer_notes(&peer.key_id, Some(notes.clone()))
                .await;
        }
    }
    Ok(())
}

impl Edge {
    #[must_use]
    pub fn builder() -> EdgeBuilder {
        EdgeBuilder {
            directory: None,
            federation_directory: None,
            queue: None,
            signer: None,
            transports: Vec::new(),
            speak_pipeline: None,
            peer_directory: None,
            steward_directory: None,
            subscription_filter: None,
            events: None,
            #[cfg(feature = "_reticulum-module")]
            reticulum_transport: None,
            reachability: None,
            derived_schema: None,
            canonical_bootstrap_peers: Vec::new(),
            config: EdgeConfig::default(),
        }
    }

    /// CIRISEdge#46 (v0.18.0) — check whether `key_id` is in the
    /// canonical bootstrap-peer set. Backs the `peer_remove` hard-
    /// remove guard + the `EdgePeerInfo.canonical` projection.
    /// O(1) HashSet lookup.
    #[must_use]
    pub fn is_canonical_peer(&self, key_id: &str) -> bool {
        self.canonical_peers
            .read()
            .is_ok_and(|set| set.contains(key_id))
    }

    /// CIRISEdge#46 (v0.18.0) — snapshot of the canonical set as a
    /// `Vec<String>` (cloned key_ids). Useful for diagnostics and the
    /// `peer_list` projection (although the projection's hot path
    /// uses [`Self::is_canonical_peer`] for O(1) checks per row).
    #[must_use]
    pub fn canonical_peer_ids(&self) -> Vec<String> {
        self.canonical_peers
            .read()
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// CIRISEdge#48-A (v0.19.1) — declare a peer's cohort scope. The
    /// operator-declared scope is consulted by both the producer-side
    /// outbound enforcement and the consumer-side
    /// `dispatch_inbound` symmetric check. Idempotent — re-declaring
    /// the same scope is a no-op.
    ///
    /// Backed by an in-process map; persist v3.2.0 does not yet
    /// expose a first-class cohort_membership API. The cohabitation
    /// FFI / pyo3 init paths may seed this via the existing
    /// `peer_set_policy` write surface — see
    /// [`crate::ffi::uniffi_impl::peer_set_policy`].
    pub fn declare_peer_cohort_scope(&self, key_id: &str, scope: CohortScope) {
        if let Ok(mut map) = self.cohort_membership.write() {
            map.insert(key_id.to_string(), scope);
        }
    }

    /// CIRISEdge#48-A (v0.19.1) — clear a peer's declared cohort
    /// scope. After this call the peer is treated as
    /// [`CohortScope::Public`] (the implicit pre-v0.19.1 behaviour).
    pub fn clear_peer_cohort_scope(&self, key_id: &str) {
        if let Ok(mut map) = self.cohort_membership.write() {
            map.remove(key_id);
        }
    }

    /// CIRISEdge#48-A (v0.19.1) — look up a peer's declared cohort
    /// scope. Returns `None` when the peer has no declared scope; the
    /// caller interprets `None` as [`CohortScope::Public`] (the
    /// pre-v0.19.1 implicit default).
    #[must_use]
    pub fn peer_cohort_scope(&self, key_id: &str) -> Option<CohortScope> {
        self.cohort_membership
            .read()
            .ok()
            .and_then(|map| map.get(key_id).cloned())
    }

    /// CIRISEdge#48-A (v0.19.1) accessor — current enforcement
    /// posture.
    #[must_use]
    pub fn cohort_scope_enforcement(&self) -> CohortScopeEnforcement {
        self.config.cohort_scope_enforcement
    }

    /// CIRISEdge#34 accessor — the shared [`crate::events::EventBus`].
    /// Cheap Arc clone; consumers (the pyo3 surface, internal emission
    /// helpers, tests) call `subscribe_*` to get a fresh receiver.
    #[must_use]
    pub fn events(&self) -> Arc<crate::events::EventBus> {
        self.events.clone()
    }

    /// CIRISEdge#28 (v0.19.0) accessor — the live
    /// [`crate::observability::EdgeMetrics`] bag. Cheap clone; consumers
    /// (PyO3 / UniFFI projection methods, internal emission helpers,
    /// tests) call `.snapshot()` to render a typed bundle.
    #[must_use]
    pub fn metrics(&self) -> crate::observability::EdgeMetrics {
        self.metrics.clone()
    }

    /// CIRISEdge#31 — read the operator-set local display name. Returns
    /// `None` when no name was ever set, OR when the configured
    /// `display_name_path` couldn't be read at `Edge::build` time.
    /// O(1) — backed by an `Arc<RwLock<Option<String>>>`.
    #[must_use]
    pub fn local_display_name(&self) -> Option<String> {
        self.display_name
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// CIRISEdge#31 — set the operator-set local display name. `name`
    /// is whitespace-trimmed; empty after trim clears the name; longer
    /// than 256 bytes after trim rejects with [`EdgeError::Config`].
    /// When [`EdgeConfig::display_name_path`] is set, the trimmed
    /// value (or empty file) is written atomically (`tempfile + rename`
    /// would be ideal; for v0.11 we use a plain write — the file is a
    /// single-process owner and a half-written name on crash means the
    /// next build sees a partial UTF-8 sequence and falls back to
    /// `None`, which is the right failure mode).
    pub fn set_local_display_name(&self, name: &str) -> Result<(), EdgeError> {
        let trimmed = name.trim();
        if trimmed.len() > 256 {
            return Err(EdgeError::Config(format!(
                "display name must be <= 256 bytes after trim, got {}",
                trimmed.len()
            )));
        }
        let new_value = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
        if let Some(path) = self.config.display_name_path.as_ref() {
            let payload = new_value.as_deref().unwrap_or("");
            std::fs::write(path, payload).map_err(|e| {
                EdgeError::Config(format!("write display_name_path {}: {e}", path.display()))
            })?;
        }
        {
            let mut guard = self
                .display_name
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *guard = new_value;
        }
        Ok(())
    }

    /// Register a typed handler for message type `M`. Compile-time
    /// guarantee: the handler signature matches `M::Response`. Runtime
    /// guarantee: dispatch only fires post-verify (AV-9 invariant).
    pub async fn register_handler<M, H>(&self, handler: H) -> Result<(), EdgeError>
    where
        M: Message,
        H: Handler<M>,
    {
        let handler = Arc::new(handler);
        let erased: ErasedHandlerFn = Arc::new(move |env: &EdgeEnvelope, ctx: HandlerContext| {
            let handler = handler.clone();
            let body_str = env.body.get().to_string();
            Box::pin(async move {
                let parsed: M = serde_json::from_str(&body_str)
                    .map_err(|e| HandlerError::SchemaInvalid(format!("body parse: {e}")))?;
                let response = handler.handle(parsed, ctx).await?;
                serde_json::to_vec(&response)
                    .map_err(|e| HandlerError::SchemaInvalid(format!("response serialize: {e}")))
            })
        });

        let mut handlers = self.handlers.lock().await;
        handlers.insert(M::TYPE, RegisteredHandler { erased });
        Ok(())
    }

    /// Send an ephemeral message. Caller-owned retry — failure is
    /// visible (OQ-09 closure). Compile-time: `M::DELIVERY` must be
    /// `Ephemeral`; runtime check rejects `Durable` mis-use.
    #[tracing::instrument(
        name = "edge.send",
        skip(self, msg),
        fields(
            recipient_key_id = %destination_key_id,
            message_type = ?M::TYPE,
            delivery_class = "ephemeral",
            signing_key_id = %self.signer.key_id,
        ),
    )]
    pub async fn send<M: Message>(
        &self,
        destination_key_id: &str,
        msg: M,
    ) -> Result<M::Response, EdgeError> {
        self.send_with_cohort_scope(destination_key_id, msg, None)
            .await
    }

    /// CIRISEdge#48-A (v0.19.1) — send an ephemeral message tagged
    /// with an explicit `cohort_scope`. The locality variants
    /// (`SelfOnly`, `Family`, `Cohort`) refuse to outbound when the
    /// explicit recipient is not authorized for the scope per the
    /// recipient-determination rules of CIRISEdge#48-A.
    ///
    /// Refusal returns a typed [`EdgeError::CohortScopeRefusedRecipient`].
    pub async fn send_with_cohort_scope<M: Message>(
        &self,
        destination_key_id: &str,
        msg: M,
        cohort_scope: Option<CohortScope>,
    ) -> Result<M::Response, EdgeError> {
        if !matches!(M::DELIVERY, Delivery::Ephemeral) {
            let declared = match M::DELIVERY {
                Delivery::Ephemeral => "Ephemeral",
                Delivery::Durable { .. } => "Durable",
                Delivery::Federation { .. } => "Federation",
                Delivery::Mandatory { .. } => "Mandatory",
            };
            return Err(EdgeError::DeliveryClassMismatch(
                M::TYPE,
                declared,
                "Ephemeral",
            ));
        }

        // CIRISEdge#48-A (v0.19.1) — producer-side recipient
        // enforcement BEFORE building the signed envelope. Point-to-
        // point: SelfOnly requires recipient == self.signer.key_id;
        // Family / Cohort require directory-recorded scope match.
        self.enforce_point_to_point_scope(cohort_scope.as_ref(), destination_key_id)?;

        let envelope_bytes = self
            .build_signed_envelope_with_cohort_scope(destination_key_id, &msg, None, cohort_scope)
            .await?;

        if self.transports.is_empty() {
            return Err(EdgeError::Config("no transport configured".into()));
        }
        let transport = &self.transports[0];
        let envelope_size = envelope_bytes.len() as u64;

        // CIRISEdge#29 — record the send-path attempt against the
        // tracker. Failure-class capture covers both the
        // `Err(TransportError)` arm (typed transport fault) and the
        // `Ok(Reject)` arm (peer returned a wire reject). The
        // `Ok(Delivered)` arm is success.
        // CIRISEdge#28 (v0.19.0) — instrument the transport-send leg
        // as a nested span; use `Instrument` (not `.entered()`) so
        // the span is `Send`-friendly across the await.
        use tracing::Instrument as _;
        let send_span = tracing::debug_span!(
            "transport.send",
            transport_id = %transport.id().0,
            recipient_key_id = %destination_key_id,
            bytes = envelope_size,
        );
        let send_result = transport
            .send(destination_key_id, &envelope_bytes)
            .instrument(send_span)
            .await;
        let outcome = match send_result {
            Ok(o) => {
                let attempt_outcome = match &o {
                    TransportSendOutcome::Delivered => AttemptOutcome::SendSuccess,
                    TransportSendOutcome::Reject { class, .. } => AttemptOutcome::SendFailure {
                        error_class: class.clone(),
                    },
                };
                self.reachability.record_attempt(
                    destination_key_id,
                    transport.id(),
                    attempt_outcome,
                );
                // CIRISEdge#28 (v0.19.0) — count the bytes shipped, and
                // bump the sent counter on a successful delivery. A
                // `Reject` arm counts as a send_failure with the
                // peer-reported class.
                if matches!(&o, TransportSendOutcome::Delivered) {
                    self.metrics.add_bytes_out(transport.id(), envelope_size);
                    self.metrics.inc_sent(&M::TYPE);
                } else if let TransportSendOutcome::Reject { class, .. } = &o {
                    self.metrics.inc_send_failure(transport.id(), class);
                }
                o
            }
            Err(e) => {
                let error_class = transport_error_class(&e).to_string();
                self.reachability.record_attempt(
                    destination_key_id,
                    transport.id(),
                    AttemptOutcome::SendFailure {
                        error_class: error_class.clone(),
                    },
                );
                self.metrics.inc_send_failure(transport.id(), &error_class);
                tracing::error!(
                    event = "edge.send.transport_error",
                    transport_id = %transport.id().0,
                    error_class = %error_class,
                    error = %e,
                    "transport send error",
                );
                return Err(EdgeError::Transport(e));
            }
        };

        match outcome {
            TransportSendOutcome::Delivered => {
                // Phase 1 simplification: ephemeral request-response is
                // not yet wired through a correlation channel. Lens
                // cutover doesn't need request-response on the outbound
                // side; the inbound side does (handlers return typed
                // responses, edge serializes back). Returning a default
                // response here is incorrect for real ephemeral
                // request-response — TODO Phase 2: wire correlation
                // via in_reply_to + body_sha256 + a oneshot map.
                Err(EdgeError::Config(
                    "ephemeral request-response correlation not wired (Phase 2)".into(),
                ))
            }
            TransportSendOutcome::Reject { class, detail } => {
                Err(EdgeError::Unreachable(format!("reject {class}: {detail}")))
            }
        }
    }

    /// Send a durable message. Edge-owned retry; the returned handle
    /// observes the eventual outcome (OQ-09 closure).
    #[tracing::instrument(
        name = "edge.send_durable",
        skip(self, msg),
        fields(
            recipient_key_id = %destination_key_id,
            message_type = ?M::TYPE,
            delivery_class = "durable",
            signing_key_id = %self.signer.key_id,
        ),
    )]
    pub async fn send_durable<M: Message>(
        &self,
        destination_key_id: &str,
        msg: M,
    ) -> Result<DurableHandle, EdgeError> {
        self.send_durable_with_cohort_scope(destination_key_id, msg, None)
            .await
    }

    /// CIRISEdge#48-A (v0.19.1) — send a durable message tagged with
    /// an explicit `cohort_scope`. Producer-side recipient enforcement
    /// matches [`Self::send_with_cohort_scope`].
    pub async fn send_durable_with_cohort_scope<M: Message>(
        &self,
        destination_key_id: &str,
        msg: M,
        cohort_scope: Option<CohortScope>,
    ) -> Result<DurableHandle, EdgeError> {
        let (requires_ack, max_attempts, ttl_seconds, ack_timeout_seconds) = match M::DELIVERY {
            Delivery::Ephemeral => {
                return Err(EdgeError::DeliveryClassMismatch(
                    M::TYPE,
                    "Ephemeral",
                    "Durable",
                ));
            }
            Delivery::Federation { .. } => {
                return Err(EdgeError::DeliveryClassMismatch(
                    M::TYPE,
                    "Federation",
                    "Durable",
                ));
            }
            Delivery::Mandatory { .. } => {
                return Err(EdgeError::DeliveryClassMismatch(
                    M::TYPE,
                    "Mandatory",
                    "Durable",
                ));
            }
            Delivery::Durable {
                requires_ack,
                max_attempts,
                ttl_seconds,
                ack_timeout_seconds,
            } => (
                requires_ack,
                i32::try_from(max_attempts).unwrap_or(i32::MAX),
                i64::try_from(ttl_seconds).unwrap_or(i64::MAX),
                ack_timeout_seconds.map(|s| i64::try_from(s).unwrap_or(i64::MAX)),
            ),
        };

        // CIRISEdge#48-A (v0.19.1) — producer-side recipient
        // enforcement BEFORE enqueueing.
        self.enforce_point_to_point_scope(cohort_scope.as_ref(), destination_key_id)?;

        let envelope_bytes = self
            .build_signed_envelope_with_cohort_scope(destination_key_id, &msg, None, cohort_scope)
            .await?;
        let envelope: EdgeEnvelope = serde_json::from_slice(&envelope_bytes)
            .map_err(|e| EdgeError::Config(format!("re-parse own envelope: {e}")))?;
        let body_sha256 = envelope_body_sha256(&envelope);
        let body_size_bytes = i32::try_from(envelope_bytes.len()).unwrap_or(i32::MAX);

        let queue_id = self
            .queue
            .enqueue_outbound(
                &self.signer.key_id,
                destination_key_id,
                &message_type_str(&envelope.message_type),
                "1.0.0",
                &envelope_bytes,
                &body_sha256,
                body_size_bytes,
                requires_ack,
                ack_timeout_seconds,
                max_attempts,
                ttl_seconds,
                Utc::now(),
            )
            .await
            .map_err(|e| EdgeError::Persist(format!("enqueue_outbound: {e}")))?;

        // CIRISEdge#28 (v0.19.0) — durable enqueue is the metric-visible
        // moment for the durable class. Counts toward both
        // `envelopes_sent_total` (the type was offered to the wire
        // through the durable surface) and `durable_queue_depth`.
        self.metrics.inc_sent(&M::TYPE);
        self.metrics
            .inc_durable_queue(crate::observability::DeliveryClass::Durable);
        // ResourceEvent — surface the durable-queue accumulation as a
        // resource-pressure observation so consumers' meta-observability
        // streams see queue growth in real time. Conservative: severity
        // = Info; the call site has no threshold view of "pressure",
        // we just emit the delta.
        let depth_snap = self
            .metrics
            .durable_queue_depth
            .read()
            .get(&crate::observability::DeliveryClass::Durable)
            .copied()
            .unwrap_or(0);
        #[allow(clippy::cast_precision_loss)]
        self.events
            .emit_resource(crate::events::NetworkEvent::resource(
                "durable_queue_depth",
                depth_snap as f64,
                "count",
                crate::events::EventSeverity::Info,
                "durable enqueue (CIRISEdge#28 v0.19.0)",
            ));

        Ok(DurableHandle { queue_id })
    }

    /// Send an inline-text message — runs the configured
    /// `speak_pipeline` on the text body (classify + scrub +
    /// encrypt-and-store) before signing + shipping. When no
    /// pipeline is configured, behaves identically to
    /// [`Self::send`]. Cleartext secrets are substituted with
    /// `{SECRET:uuid:description}` placeholders before the envelope
    /// is signed, so the wire payload never carries unredacted
    /// sensitive spans. Per FSD §1.4 and CIRISAgent#756 Q1.
    pub async fn send_inline<M: InlineTextMessage>(
        &self,
        destination_key_id: &str,
        mut msg: M,
    ) -> Result<M::Response, EdgeError> {
        self.run_speak_pipeline(&mut msg).await?;
        self.send(destination_key_id, msg).await
    }

    /// Durable variant of [`Self::send_inline`] — same pipeline-then-
    /// sign path, but enqueues to `cirislens.edge_outbound_queue` for
    /// edge-owned retry. Returns a [`DurableHandle`] to observe the
    /// eventual outcome.
    pub async fn send_durable_inline<M: InlineTextMessage>(
        &self,
        destination_key_id: &str,
        mut msg: M,
    ) -> Result<DurableHandle, EdgeError> {
        self.run_speak_pipeline(&mut msg).await?;
        self.send_durable(destination_key_id, msg).await
    }

    /// Send a federation-tier authority-signed broadcast — fans the
    /// signed envelope to **every peer** in the [`PeerDirectory`]
    /// regardless of any subscription filter. Closes CIRISEdge#18
    /// + CIRISNodeCore FSD §3.2 (substrate-tier Mandatory wire class).
    ///
    /// The load-bearing semantic is in
    /// [`Delivery::Mandatory::bypass_subscription`]: even when a
    /// [`PeerSubscriptionFilter`] is configured, this path does NOT
    /// consult it. The federation's governance reach requires that
    /// every node observe an authority-signed announcement; the
    /// subscription model belongs to the application layer, not the
    /// substrate.
    ///
    /// Returns one [`DurableHandle`] per peer the announcement was
    /// enqueued to — callers may observe each independently. The
    /// local steward's own `key_id` is filtered out (a Mandatory
    /// fan-out does not loopback through edge).
    ///
    /// # Errors
    ///
    /// - [`EdgeError::DeliveryClassMismatch`] when `M::DELIVERY` is
    ///   not `Delivery::Mandatory`.
    /// - [`EdgeError::Config`] when no peer directory is configured
    ///   on the [`EdgeBuilder`] — the substrate broadcast cannot pick
    ///   recipients without it.
    /// - [`EdgeError::Persist`] on enqueue failure.
    #[tracing::instrument(
        name = "edge.send_mandatory",
        skip(self, msg),
        fields(
            message_type = ?M::TYPE,
            delivery_class = "mandatory",
            signing_key_id = %self.signer.key_id,
        ),
    )]
    pub async fn send_mandatory<M: Message>(
        &self,
        msg: M,
    ) -> Result<Vec<DurableHandle>, EdgeError> {
        self.send_mandatory_with_cohort_scope(msg, None).await
    }

    /// CIRISEdge#48-A (v0.19.1) — send a `Delivery::Mandatory`
    /// broadcast tagged with an explicit `cohort_scope`. Refuses
    /// federation-wide fan-out for locality scopes (`SelfOnly`,
    /// `Family`, `Cohort`) — wire-format invariant per FSD
    /// `FEDERATION_SCALING_MODEL.md`. Refusal returns a typed
    /// [`EdgeError::CohortScopeRefusedMandatory`].
    #[allow(clippy::too_many_lines)] // fan-out body matches send_mandatory
    pub async fn send_mandatory_with_cohort_scope<M: Message>(
        &self,
        msg: M,
        cohort_scope: Option<CohortScope>,
    ) -> Result<Vec<DurableHandle>, EdgeError> {
        // CIRISEdge#48-A (v0.19.1) — refuse mandatory fan-out for any
        // locality scope BEFORE walking peer_directory. Structural
        // wire-format invariant; happens before recipient enumeration.
        self.enforce_federation_class_scope(cohort_scope.as_ref(), false)?;
        let (max_attempts, ttl_seconds) = match M::DELIVERY {
            Delivery::Ephemeral => {
                return Err(EdgeError::DeliveryClassMismatch(
                    M::TYPE,
                    "Ephemeral",
                    "Mandatory",
                ));
            }
            Delivery::Durable { .. } => {
                return Err(EdgeError::DeliveryClassMismatch(
                    M::TYPE,
                    "Durable",
                    "Mandatory",
                ));
            }
            Delivery::Federation { .. } => {
                return Err(EdgeError::DeliveryClassMismatch(
                    M::TYPE,
                    "Federation",
                    "Mandatory",
                ));
            }
            Delivery::Mandatory {
                authority_signed: _,
                bypass_subscription,
            } => {
                // Edge does not gate on authority_signed (NodeCore's
                // job per FSD §3.4); the flag is a wire contract
                // marker. Refuse to fan out if a Mandatory variant
                // somehow sets bypass_subscription=false — that is a
                // programmer mistake that, if accepted, would silently
                // turn a federation broadcast back into an opt-in.
                if !bypass_subscription {
                    return Err(EdgeError::Config(format!(
                        "Mandatory message_type {:?} declared bypass_subscription=false; \
                         refusing to fan out (FSD §3.2 wire contract)",
                        M::TYPE
                    )));
                }
                // FSD §3.2.1 dispatch contract on FederationAnnouncement
                // itself (the only Mandatory consumer at v0.1) — the
                // announcement is durable + fire-and-forget. The
                // per-peer DeliveryAttestation IS the audit observable;
                // no edge-level ACK is requested. v0.1 defaults: 14d
                // TTL, 100 attempts (mirrors BuildManifestPublication's
                // long-haul durability since announcements are
                // similarly durable substrate-tier records).
                (100i32, 14 * 24 * 60 * 60i64)
            }
        };

        let peer_dir = self.peer_directory.as_ref().ok_or_else(|| {
            EdgeError::Config(
                "send_mandatory: no PeerDirectory configured on EdgeBuilder \
                 (federation broadcast cannot enumerate recipients)"
                    .into(),
            )
        })?;

        let peers = peer_dir
            .list_recipients()
            .await
            .map_err(|e| EdgeError::Persist(format!("PeerDirectory::list_recipients: {e}")))?;

        let mut handles = Vec::with_capacity(peers.len());
        for peer in peers {
            // Local steward never gets its own Mandatory fan-out —
            // sender == receiver would loopback through edge's verify
            // (AV-8 self-destination is structurally a misroute) and
            // waste a queue row.
            if peer == self.signer.key_id {
                continue;
            }
            // **Bypass-subscription invariant** — DO NOT consult
            // `self.subscription_filter` here. Mandatory is the FSD
            // §3.2 wire-level expression of "federation-wide push
            // regardless of per-peer opt-in"; calling
            // `is_subscribed(peer, M::TYPE)` here would re-introduce
            // the opt-in gate this class exists to remove.
            let envelope_bytes = self
                .build_signed_envelope_with_cohort_scope(&peer, &msg, None, cohort_scope.clone())
                .await?;
            let envelope: EdgeEnvelope = serde_json::from_slice(&envelope_bytes)
                .map_err(|e| EdgeError::Config(format!("re-parse own envelope: {e}")))?;
            let body_sha256 = envelope_body_sha256(&envelope);
            let body_size_bytes = i32::try_from(envelope_bytes.len()).unwrap_or(i32::MAX);

            let queue_id = self
                .queue
                .enqueue_outbound(
                    &self.signer.key_id,
                    &peer,
                    &message_type_str(&envelope.message_type),
                    "1.0.0",
                    &envelope_bytes,
                    &body_sha256,
                    body_size_bytes,
                    false, // requires_ack: false — attestation IS observable
                    None,  // ack_timeout_seconds: None
                    max_attempts,
                    ttl_seconds,
                    Utc::now(),
                )
                .await
                .map_err(|e| EdgeError::Persist(format!("enqueue_outbound (mandatory): {e}")))?;
            handles.push(DurableHandle { queue_id });
            // CIRISEdge#28 (v0.19.0) — count per peer (one envelope
            // signed/enqueued per recipient on Mandatory fan-out).
            self.metrics.inc_sent(&M::TYPE);
            self.metrics
                .inc_durable_queue(crate::observability::DeliveryClass::Mandatory);
        }
        Ok(handles)
    }

    /// Send a steward-class federation directive — high-priority
    /// recipient class derived dynamically from persist's
    /// `federation_keys` directory (`identity_type="steward"`).
    /// CIRISEdge#20.
    ///
    /// # Routing semantic
    ///
    /// Mirrors [`Self::send_mandatory`]'s fan-out shape but over the
    /// steward subset (not the every-peer directory) and DOES respect
    /// the configured [`PeerSubscriptionFilter`]:
    ///
    /// - **Recipient set**: re-resolved on every call via
    ///   [`StewardDirectory::current_stewards`] — no caching. Steward
    ///   rotation (Registry FSD-002 §2.1) propagates atomically.
    /// - **Subscription gate**: consulted (DIFFERENT from `Mandatory`,
    ///   which bypasses it). Federation routes with preference, not
    ///   federation-wide push; per the issue's distinction "guaranteed-
    ///   reachable, not bypass-subscription-by-default but
    ///   routed-with-preference".
    /// - **Self-loopback**: filtered (self-delivery would loopback
    ///   through edge's verify; AV-8 structural misroute — same as
    ///   `send_mandatory`).
    /// - **Per-row durability**: the [`Delivery::Federation`] per-row
    ///   config from `M::DELIVERY` (`max_attempts`, `ttl_seconds`,
    ///   `requires_ack`, `ack_timeout_seconds`) — the call's
    ///   `ack_timeout_seconds` argument overrides the type-level
    ///   default when present (production deployments may want a
    ///   tighter timeout for rotation-window directives).
    ///
    /// # Compile-time vs. runtime DELIVERY check
    ///
    /// Conceptually `M::DELIVERY` must equal a `Delivery::Federation`
    /// variant. Rust's trait-system can't express that as a where-
    /// clause on an associated constant (no const-generic dispatch on
    /// enum variant), so the check is runtime — a wrong delivery
    /// class returns [`EdgeError::DeliveryClassMismatch`] (typed, not
    /// a panic; consistent with [`Self::send`] / [`Self::send_durable`]
    /// / [`Self::send_mandatory`]'s mismatch handling).
    ///
    /// # Errors
    ///
    /// - [`EdgeError::DeliveryClassMismatch`] when `M::DELIVERY` is
    ///   not `Delivery::Federation`.
    /// - [`EdgeError::Config`] when no [`StewardDirectory`] is
    ///   configured on the builder.
    /// - [`EdgeError::NoStewards`] when the directory resolves to
    ///   zero stewards — surfaced as a typed error rather than a
    ///   silent no-op (MISSION.md §3 anti-pattern 6).
    /// - [`EdgeError::Persist`] on enqueue / directory-read failure.
    ///
    /// # Returns
    ///
    /// One [`DurableHandle`] per steward the directive was enqueued
    /// to — callers may observe each independently. The handle count
    /// reflects the post-filter recipient set (stewards minus self
    /// minus subscription-rejected).
    #[allow(clippy::too_many_lines)] // delivery-class match arms + fan-out body
    #[tracing::instrument(
        name = "edge.send_federation",
        skip(self, msg),
        fields(
            message_type = ?M::TYPE,
            delivery_class = "federation",
            signing_key_id = %self.signer.key_id,
        ),
    )]
    pub async fn send_federation<M: Message>(
        &self,
        msg: M,
        ack_timeout_seconds: Option<u64>,
    ) -> Result<Vec<DurableHandle>, EdgeError> {
        self.send_federation_with_cohort_scope(msg, ack_timeout_seconds, None)
            .await
    }

    /// CIRISEdge#48-A (v0.19.1) — send a `Delivery::Federation`
    /// steward-class directive tagged with an explicit `cohort_scope`.
    /// Refuses federation-class fan-out for locality scopes
    /// (`SelfOnly`, `Family`, `Cohort`) — wire-format invariant per
    /// FSD `FEDERATION_SCALING_MODEL.md`. Refusal returns a typed
    /// [`EdgeError::CohortScopeRefusedFederation`].
    #[allow(clippy::too_many_lines)] // fan-out body matches send_federation
    pub async fn send_federation_with_cohort_scope<M: Message>(
        &self,
        msg: M,
        ack_timeout_seconds: Option<u64>,
        cohort_scope: Option<CohortScope>,
    ) -> Result<Vec<DurableHandle>, EdgeError> {
        // CIRISEdge#48-A (v0.19.1) — refuse federation-class fan-out
        // for any locality scope BEFORE enumerating stewards.
        self.enforce_federation_class_scope(cohort_scope.as_ref(), true)?;
        let (priority, requires_ack, max_attempts, ttl_seconds, type_ack_timeout) =
            match M::DELIVERY {
                Delivery::Ephemeral => {
                    return Err(EdgeError::DeliveryClassMismatch(
                        M::TYPE,
                        "Ephemeral",
                        "Federation",
                    ));
                }
                Delivery::Durable { .. } => {
                    return Err(EdgeError::DeliveryClassMismatch(
                        M::TYPE,
                        "Durable",
                        "Federation",
                    ));
                }
                Delivery::Mandatory { .. } => {
                    return Err(EdgeError::DeliveryClassMismatch(
                        M::TYPE,
                        "Mandatory",
                        "Federation",
                    ));
                }
                Delivery::Federation {
                    priority,
                    requires_ack,
                    max_attempts,
                    ttl_seconds,
                    ack_timeout_seconds,
                } => (
                    priority,
                    requires_ack,
                    i32::try_from(max_attempts).unwrap_or(i32::MAX),
                    i64::try_from(ttl_seconds).unwrap_or(i64::MAX),
                    ack_timeout_seconds,
                ),
            };

        let steward_dir = self.steward_directory.as_ref().ok_or_else(|| {
            EdgeError::Config(
                "send_federation: no StewardDirectory configured on EdgeBuilder \
                 (high-priority federation fan-out cannot enumerate recipients)"
                    .into(),
            )
        })?;

        // CIRISEdge#20 ask #4 — re-resolve on every call (no caching).
        // Steward rotation per Registry FSD-002 §2.1 propagates
        // atomically: the next send sees the post-rotation set.
        let stewards: Vec<StewardKey> = steward_dir
            .current_stewards()
            .await
            .map_err(|e| EdgeError::Persist(format!("StewardDirectory::current_stewards: {e}")))?;

        if stewards.is_empty() {
            return Err(EdgeError::NoStewards(priority));
        }

        // Per-row ack_timeout precedence: call-site arg wins when
        // present (operational override for rotation-window
        // directives); otherwise the type-level default from
        // `M::DELIVERY`. Mirrors persist's per-row config precedence
        // pattern (FSD/EDGE_OUTBOUND_QUEUE.md §4).
        let ack_timeout_seconds_i64 = ack_timeout_seconds
            .or(type_ack_timeout)
            .map(|s| i64::try_from(s).unwrap_or(i64::MAX));

        let mut handles = Vec::with_capacity(stewards.len());
        for steward in stewards {
            // Self-loopback filter — same invariant as `send_mandatory`
            // (sender == receiver loopbacks through edge's verify;
            // AV-8 structural misroute).
            if steward.key_id == self.signer.key_id {
                continue;
            }

            // CIRISEdge#20 — Federation respects subscription filter
            // (the distinction from Mandatory). Stewards may opt out
            // of message types they don't consume; Federation routes
            // with preference, not federation-wide push.
            if !self
                .would_subscription_accept(&steward.key_id, &M::TYPE)
                .await
            {
                tracing::debug!(
                    steward_key_id = %steward.key_id,
                    identity_ref = %steward.identity_ref,
                    message_type = ?M::TYPE,
                    "send_federation: steward filtered by PeerSubscriptionFilter",
                );
                continue;
            }

            let envelope_bytes = self
                .build_signed_envelope_with_cohort_scope(
                    &steward.key_id,
                    &msg,
                    None,
                    cohort_scope.clone(),
                )
                .await?;
            let envelope: EdgeEnvelope = serde_json::from_slice(&envelope_bytes)
                .map_err(|e| EdgeError::Config(format!("re-parse own envelope: {e}")))?;
            let body_sha256 = envelope_body_sha256(&envelope);
            let body_size_bytes = i32::try_from(envelope_bytes.len()).unwrap_or(i32::MAX);

            let queue_id = self
                .queue
                .enqueue_outbound(
                    &self.signer.key_id,
                    &steward.key_id,
                    &message_type_str(&envelope.message_type),
                    "1.0.0",
                    &envelope_bytes,
                    &body_sha256,
                    body_size_bytes,
                    requires_ack,
                    ack_timeout_seconds_i64,
                    max_attempts,
                    ttl_seconds,
                    Utc::now(),
                )
                .await
                .map_err(|e| EdgeError::Persist(format!("enqueue_outbound (federation): {e}")))?;
            handles.push(DurableHandle { queue_id });
            // CIRISEdge#28 (v0.19.0) — federation fan-out per steward.
            self.metrics.inc_sent(&M::TYPE);
            self.metrics
                .inc_durable_queue(crate::observability::DeliveryClass::Federation);
        }
        Ok(handles)
    }

    /// Register an inbound inline-text subscriber (CIRISEdge#22 Tier 2;
    /// v0.9.0). Every verified [`crate::MessageType::InlineText`]
    /// envelope dispatched through [`Self::run`]'s inbound loop is
    /// fanned out to every subscriber registered here, as a
    /// `(sender_key_id, body_text)` tuple pushed onto the returned
    /// receiver.
    ///
    /// The caller owns the receiver — drop it (or call
    /// [`Self::unregister_inline_text_subscriber`] with the returned id)
    /// to stop the fan-out. The dispatcher lazy-prunes entries whose
    /// `send` returns `Err(SendError)` (closed receiver), so dropping
    /// the receiver alone is sufficient for correctness — the explicit
    /// unregister exists for tests and for the Python
    /// `SubscriptionHandle::unsubscribe` surface which needs synchronous
    /// removal (so a subsequent inbound that arrives before the next
    /// dispatch's lazy prune cannot fire a callback the consumer
    /// considers detached).
    ///
    /// # Used by
    ///
    /// [`crate::ffi::pyo3::PyEdge::register_inline_text_handler`] — the
    /// Python-facing surface CIRISAgent 2.9.5's `EdgeCommunicationAdapter`
    /// consumes. The Rust-level method exists so the same fan-out is
    /// reachable to non-Python embedders (uniffi / swift-bridge shells
    /// landing in Phase 3).
    pub fn register_inline_text_subscriber(
        &self,
    ) -> (u64, mpsc::UnboundedReceiver<(String, String)>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let id = self.inline_text_next_id.fetch_add(1, Ordering::Relaxed);
        let mut subs = self
            .inline_text_subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        subs.insert(id, tx);
        (id, rx)
    }

    /// Remove an inline-text subscriber by id. Idempotent — returns
    /// `true` if the id was registered, `false` if not (matches persist
    /// `PyEngine::unsubscribe` ergonomics).
    pub fn unregister_inline_text_subscriber(&self, id: u64) -> bool {
        let mut subs = self
            .inline_text_subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        subs.remove(&id).is_some()
    }

    /// Snapshot count of live inline-text subscribers. Diagnostics
    /// helper — used by the Python tests to verify the lifecycle (a
    /// `SubscriptionHandle::unsubscribe` or `__exit__` must observe the
    /// count drop).
    pub fn inline_text_subscriber_count(&self) -> usize {
        self.inline_text_subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// CIRISEdge#22 Tier 3 (v0.17.0) — subscribe to the verified-
    /// envelope feed. Every successfully-verified inbound envelope is
    /// published on this broadcast channel as a
    /// [`VerifiedEnvelopeSnapshot`]; the Python `subscribe_feed`
    /// AsyncIterator wraps the resulting `Receiver`.
    ///
    /// Cheap: one `broadcast::subscribe` call. Subscribers that lag
    /// past the channel's capacity see `Lagged` errors and skip ahead.
    #[must_use]
    pub fn subscribe_verified_feed(&self) -> broadcast::Receiver<VerifiedEnvelopeSnapshot> {
        self.verified_envelope_tx.subscribe()
    }

    /// CIRISEdge#22 Tier 3 (v0.17.0) — count of live verified-feed
    /// subscribers. Diagnostic surface for tests.
    #[must_use]
    pub fn verified_feed_subscriber_count(&self) -> usize {
        self.verified_envelope_tx.receiver_count()
    }

    /// CIRISEdge#22 Tier 3 (v0.17.0) — fetch content addressed by
    /// `sha256` from `peer_key_id`. Sends a
    /// [`crate::MessageType::ContentFetch`] envelope to the peer, then
    /// awaits a matching [`crate::MessageType::ContentBody`] or
    /// [`crate::MessageType::ContentMiss`] envelope.
    ///
    /// Returns one of:
    /// - `ContentResult::Bytes(bytes)` — the peer served the bytes.
    ///   The `ContentBody` integrity gate
    ///   (`sha256(bytes) == requested_sha256`) is enforced in
    ///   [`dispatch_inbound`] before this returns.
    /// - `ContentResult::ContentMiss { reason }` — the peer reports
    ///   the bytes are not available (typed
    ///   [`crate::messages::MissReason`]).
    ///
    /// # Timeout
    ///
    /// Caller-supplied. Returns `EdgeError::Config("fetch_content
    /// timeout")` if no matching response arrives within
    /// `timeout`.
    ///
    /// # Concurrent fetches
    ///
    /// Pending fetches are keyed by `sha256` — only one in-flight
    /// fetch per `sha256` is supported. Re-issuing while another is
    /// pending replaces the earlier waiter (the prior call's oneshot
    /// drops, signalling a closed-channel error on the prior
    /// `await`).
    ///
    /// # AV-13 / integrity
    ///
    /// The dispatch-side ContentBody gate already enforces the
    /// content-addressed integrity invariant. This method trusts that
    /// gate — by the time the pending channel resolves with
    /// `ContentResult::Bytes`, the bytes have been verified against
    /// the requested sha256.
    pub async fn fetch_content(
        &self,
        peer_key_id: &str,
        sha256: [u8; 32],
        timeout: std::time::Duration,
    ) -> Result<ContentResult, EdgeError> {
        // Register the pending fetch BEFORE sending — there is a
        // race window otherwise where the response arrives before
        // the waiter is in the map (the dispatcher walks the map
        // under a sync::Mutex; if no entry, the response is dropped
        // on the floor and we'd hang).
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self
                .content_fetch_pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // If a prior fetch is pending for the same sha256, drop
            // its sender (the prior await observes a closed channel
            // and errors out). Re-issue semantics — last writer wins.
            pending.insert(sha256, tx);
        }

        // Build + send the ContentFetch envelope. We use the typed
        // `crate::MessageType::ContentFetch` body shape — the
        // existing Edge::send returns `EdgeError::Config(...)` for
        // ephemeral request/response (the v0.8.0 "Phase 2"
        // correlation not wired carve-out), which is exactly the
        // success-of-transport path. We map that one specific error
        // back to Ok so the caller's await proceeds.
        let fetch = crate::messages::ContentFetch {
            sha256,
            response_hint: None,
        };
        match self.send(peer_key_id, fetch).await {
            Ok(()) => {}
            Err(EdgeError::Config(s))
                if s.contains("ephemeral request-response correlation not wired") =>
            {
                // Transport accepted the bytes — proceed to await.
            }
            Err(e) => {
                // Send failed — clean the pending entry and surface.
                let mut pending = self
                    .content_fetch_pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                pending.remove(&sha256);
                return Err(e);
            }
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_recv_err)) => {
                // oneshot sender dropped — either a concurrent fetch
                // replaced our waiter, or the dispatcher dropped on
                // a poisoned mutex. Surface as a config error.
                Err(EdgeError::Config(
                    "fetch_content waiter closed before response arrived".into(),
                ))
            }
            Err(_) => {
                // Timeout — clean the pending entry on our way out.
                let mut pending = self
                    .content_fetch_pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                pending.remove(&sha256);
                Err(EdgeError::Config(format!(
                    "fetch_content timeout after {timeout:?}"
                )))
            }
        }
    }

    /// CIRISEdge#22 Tier 3 (v0.17.0) — test-only helper to inject a
    /// fake ContentBody / ContentMiss response into the pending-fetch
    /// signal map. Used by the integration tests so the fetch_content
    /// happy path can be exercised without a real Reticulum loopback.
    #[doc(hidden)]
    pub fn complete_pending_fetch_for_test(&self, sha256: [u8; 32], result: ContentResult) {
        let mut pending = self
            .content_fetch_pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(tx) = pending.remove(&sha256) {
            let _ = tx.send(result);
        }
    }

    /// CIRISEdge#22 Tier 3 (v0.17.0) — test-only helper to fan out a
    /// VerifiedEnvelopeSnapshot to verified-feed subscribers without
    /// running a real verify pipeline. Mirrors the
    /// `fan_out_inline_text_for_test` pattern.
    #[doc(hidden)]
    pub fn fan_out_verified_envelope_for_test(&self, snapshot: VerifiedEnvelopeSnapshot) {
        let _ = self.verified_envelope_tx.send(snapshot);
    }

    /// Manually fan out an InlineText payload to every subscriber.
    /// Public for tests + future non-dispatcher embedders that want to
    /// inject a synthetic inbound without going through the verify
    /// pipeline. The production inbound path calls the free-function
    /// equivalent from [`dispatch_inbound`].
    pub fn fan_out_inline_text_for_test(&self, sender_key_id: &str, body_text: &str) {
        fan_out_inline_text(&self.inline_text_subscribers, sender_key_id, body_text);
    }

    /// Synchronous one-shot driver for the inbound dispatch pipeline.
    /// Test-only helper: lets integration suites drive a single
    /// `InboundFrame` through the same code path `Edge::run` invokes
    /// per inbound message, then observe outbound queue state (refusal
    /// attestation per CIRISEdge#19, acceptance attestation per #18 +
    /// StewardDirective per #20, InlineText fan-out per Tier 2, typed
    /// handler dispatch) without standing up the full listener /
    /// dispatcher topology.
    ///
    /// Production callers are the `Edge::run` listener loop; this
    /// shares the same `dispatch_inbound` body, so a regression in
    /// the wire-layer gate is caught from either entry point.
    pub async fn dispatch_inbound_for_test(&self, frame: InboundFrame) {
        let directory = self.verify.directory();
        dispatch_inbound(
            frame,
            &self.verify,
            &self.handlers,
            &self.queue,
            &self.signer,
            &self.inline_text_subscribers,
            self.config.max_content_body_bytes,
            &directory,
            Some(&self.reachability),
            self.detector.as_ref(),
            &self.verified_envelope_tx,
            &self.content_fetch_pending,
            &self.metrics,
            &self.events,
            &self.cohort_membership,
            self.config.cohort_scope_enforcement,
        )
        .await;
    }

    /// Rust-level accessor returning a clone of the outbound queue
    /// `Arc`. Used by [`crate::ffi::pyo3::PyDurableHandle`] to poll
    /// `outbound_status` for `await_ack` semantics independently of
    /// the `PyEdge`'s lifetime.
    #[must_use]
    pub fn outbound_queue_handle(&self) -> Arc<dyn OutboundHandle> {
        self.queue.clone()
    }

    /// Rust-level accessor returning a clone of the per-medium
    /// reachability tracker `Arc` (CIRISEdge#29; v0.11.0). The
    /// consumer surface is locked here for the CIRISEdge#22 Tier 3
    /// pymethod cut (v0.16.0): the FFI shell calls
    /// [`ReachabilityTracker::snapshot`] / [`ReachabilityTracker::snapshot_all`]
    /// and shapes the result into the Python `dict[str, float]` /
    /// `list[PeerMediumReachability]` surface the Trust Topology UI
    /// drives. **No pymethods are added in this scope** — that's the
    /// sibling FFI agent's territory (the v0.11.0 FFI bundle #31 +
    /// #34 + #35).
    #[must_use]
    pub fn reachability_tracker(&self) -> Arc<ReachabilityTracker> {
        self.reachability.clone()
    }

    /// Rust-level accessor returning the local signer's `key_id` —
    /// the `signing_key_id` field on outbound envelopes. Used by the
    /// PyO3 `send_inline_text` body-sha256 pre-computation step.
    #[must_use]
    pub fn signer_key_id(&self) -> &str {
        &self.signer.key_id
    }

    /// CIRISEdge#31 (v0.13.0 UniFFI cut) — Rust-level accessor returning
    /// a clone of the local signer `Arc`. The UniFFI bindings
    /// (`src/ffi/uniffi_impl.rs`) use this to drive the read-only
    /// Identity surface (`identity_hash`, `identity_pubkeys`,
    /// `current_ratchet_id`, `last_rotation_at`). Mutations
    /// (`set_local_display_name`, QR import/export) stay PyO3.
    #[must_use]
    pub fn signer(&self) -> Arc<LocalSigner> {
        self.signer.clone()
    }

    /// CIRISEdge#26 (v0.13.0 UniFFI cut) — Rust-level accessor returning
    /// a clone of the federation-key directory `Arc`. The UniFFI bindings
    /// drive `peer_list` / `peer_get` reads against this. Mutations
    /// (`peer_add`, `peer_remove`) need a wider trait than
    /// `VerifyDirectory` exposes today — those land as stubs pending a
    /// persist-side follow-up.
    #[must_use]
    pub fn verify_directory(&self) -> Arc<dyn VerifyDirectory> {
        self.verify.directory()
    }

    /// CIRISEdge#26 mutation surface (v0.15.1) — concrete-typed
    /// `Arc<dyn FederationDirectory>` if the host wired one via
    /// [`EdgeBuilder::federation_directory`] (or one of the
    /// convenience constructors that opens its own backend).
    ///
    /// `None` when no concrete directory was wired — the 6 UniFFI
    /// peer-mutation entry points
    /// (`peer_add` / `peer_remove` / `peer_set_{alias,trust,notes,policy}`)
    /// consult this accessor and return `EdgeBindingsError::Unsupported`
    /// when it returns `None`.
    ///
    /// Distinct from [`Self::verify_directory`] (which returns the
    /// type-erased `Arc<dyn VerifyDirectory>` adapter the verify
    /// pipeline holds): persist's `FederationDirectory` trait is
    /// object-safe via `#[async_trait]`, so we can hold it as a
    /// distinct trait object alongside the verify-adapter without a
    /// `Sized` downcast.
    #[must_use]
    pub fn federation_directory(
        &self,
    ) -> Option<Arc<dyn ciris_persist::federation::FederationDirectory>> {
        self.federation_directory.clone()
    }

    /// CIRISEdge#25 (v0.13.0 UniFFI cut) — Rust-level accessor returning
    /// the transport set. UniFFI's `transport_list` enumerates this and
    /// derives per-transport stats via [`Transport::id`] + (for Reticulum)
    /// `interface_specs()` / `transport_stats(handle)`.
    #[must_use]
    pub fn transports(&self) -> Vec<Arc<dyn Transport>> {
        self.transports.clone()
    }

    /// CIRISEdge#25 (v0.13.0 UniFFI cut) — Reticulum-specific stats
    /// drill-down by `InterfaceHandle`. v0.14.0 (CIRISEdge#32) — wired
    /// through the typed [`Self::reticulum_transport`] handle: routes
    /// to the concrete `ReticulumTransport::transport_stats`. Returns
    /// `None` if no Reticulum transport was registered OR the handle
    /// id is out of range (the v0.12.0 contract — registered indices
    /// only).
    #[cfg(feature = "_reticulum-module")]
    #[must_use]
    pub fn reticulum_stats_for_handle(
        &self,
        id: usize,
    ) -> Option<crate::transport::reticulum::TransportStats> {
        let transport = self.reticulum_transport.as_ref()?;
        transport.transport_stats(crate::transport::reticulum::InterfaceHandle(id))
    }

    /// CIRISEdge#32 (v0.14.0) — typed accessor for the Reticulum
    /// transport. Returns `None` if the Edge was built without
    /// [`EdgeBuilder::reticulum_transport`] (e.g. an HTTP-only deployment
    /// or a test that registered `Arc<dyn Transport>` via the generic
    /// [`EdgeBuilder::transport`] path). The Links UniFFI surface
    /// consults this; `None` → `EdgeBindingsError::Unsupported`.
    #[cfg(feature = "_reticulum-module")]
    #[must_use]
    pub fn reticulum_transport(
        &self,
    ) -> Option<Arc<crate::transport::reticulum::ReticulumTransport>> {
        self.reticulum_transport.clone()
    }

    /// Pub-crate variant of [`Self::run_speak_pipeline`] reachable
    /// from `crate::ffi::pyo3`. The Python `send_inline_text` /
    /// `send_durable_inline_text` wrappers need to run the pipeline
    /// against a typed `InlineText` body to compute the post-pipeline
    /// `body_sha256` BEFORE calling `send_inline` (which would consume
    /// the message). Idempotent — running it twice produces the same
    /// bytes.
    pub async fn run_speak_pipeline_for_external<M: InlineTextMessage>(
        &self,
        msg: &mut M,
    ) -> Result<(), EdgeError> {
        self.run_speak_pipeline(msg).await
    }

    /// Test/diagnostics helper — `true` if `peer_key_id` would be
    /// admitted by the configured [`PeerSubscriptionFilter`] for
    /// `message_type`. When no filter is configured, returns `true`
    /// (everything is "subscribed" in the default open posture).
    ///
    /// `Delivery::Mandatory` paths deliberately do NOT call this —
    /// see [`Self::send_mandatory`]. Exposed so the
    /// `tests/federation_announcement_mandatory.rs` round-trip can
    /// assert the bypass property: a peer whose filter would reject
    /// the MessageType MUST still receive the Mandatory broadcast.
    pub async fn would_subscription_accept(
        &self,
        peer_key_id: &str,
        message_type: &MessageType,
    ) -> bool {
        let Some(filter) = self.subscription_filter.as_ref() else {
            return true;
        };
        filter.is_subscribed(peer_key_id, message_type).await
    }

    /// Run the configured outbound `speak_pipeline` over the
    /// message's text body. Mutates `msg` in place via
    /// `InlineTextMessage::set_text`. No-op when no pipeline is
    /// configured. Logs sidecar via tracing.
    async fn run_speak_pipeline<M: InlineTextMessage>(&self, msg: &mut M) -> Result<(), EdgeError> {
        let Some(pipeline) = self.speak_pipeline.as_ref() else {
            return Ok(());
        };
        let mut env = ciris_persist::prelude::InlineTextEnvelope::new(msg.text().to_string());
        let mut state = ciris_persist::pipeline::PipelineState::default();
        pipeline
            .run(&mut env, &mut state)
            .await
            .map_err(|e| EdgeError::Persist(format!("speak_pipeline: {e}")))?;
        tracing::debug!(
            stages = ?state.stages_executed,
            fields_modified = state.fields_modified,
            pii_scrubbed = state.pii_scrubbed,
            "speak_pipeline ran"
        );
        msg.set_text(env.text);
        Ok(())
    }

    /// Run the listeners + dispatch loops + outbound dispatcher.
    /// Returns when the shutdown signal fires.
    // v0.18.0 — function grew past clippy's 100-line cap once the #33
    // background blackhole-pruner spawn landed alongside the existing
    // listener / dispatcher / sweeps / inbound spawn graph. The
    // spawn-graph composition is the construction-time contract; extracting
    // it would fragment the lifecycle invariants without adding clarity.
    #[allow(clippy::too_many_lines)]
    pub async fn run(self, shutdown_rx: watch::Receiver<bool>) -> Result<(), EdgeError> {
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<InboundFrame>(1024);

        // Spawn one listener per transport.
        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        for transport in &self.transports {
            let t = transport.clone();
            let tx = inbound_tx.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) = t.listen(tx).await {
                    tracing::error!(transport = ?t.id(), error = %e, "transport listen exited");
                }
            }));
        }
        // Drop our copy of the sender; only the listeners hold it.
        drop(inbound_tx);

        // Spawn outbound dispatcher + sweeps.
        {
            let q = self.queue.clone();
            let ts = self.transports.clone();
            let cfg = self.config.dispatcher.clone();
            let sd = shutdown_rx.clone();
            let reach = Some(self.reachability.clone());
            tasks.push(tokio::spawn(async move {
                run_dispatcher(q, ts, cfg, sd, reach).await;
            }));
        }
        {
            let q = self.queue.clone();
            let sd = shutdown_rx.clone();
            tasks.push(tokio::spawn(async move {
                run_sweeps(q, sd).await;
            }));
        }

        // CIRISEdge#33 background pruner (v0.18.0 lifecycle hook —
        // closes the v0.16.1 TODO documented on
        // `ReticulumTransport::routing_blackhole_prune_expired`). Walks
        // the persist-backed deny-list, dropping rows whose `until` is
        // past `Utc::now()`. Permanent rules (`until IS NULL`) are
        // NEVER pruned. Spawns iff (a) `blackhole_prune_interval_seconds`
        // > 0 AND (b) the Reticulum transport actually wired an
        // `Arc<dyn BlackholeRules>` backend (test fixtures and
        // HTTP-only deployments don't). Cancellation: the task lives
        // for the runtime lifetime; the shutdown watcher is consulted
        // each tick so a clean shutdown reclaims it without leaking.
        #[cfg(feature = "_reticulum-module")]
        {
            let interval = self.config.blackhole_prune_interval_seconds;
            if interval > 0 {
                if let Some(rules) = self
                    .reticulum_transport
                    .as_ref()
                    .and_then(|t| t.blackhole_rules_handle())
                {
                    let sd = shutdown_rx.clone();
                    tasks.push(tokio::spawn(async move {
                        run_blackhole_pruner(rules, interval, sd).await;
                    }));
                }
            }
        }

        // Inbound dispatch loop — verify + handler dispatch +
        // ACK matching + FederationAnnouncement→DeliveryAttestation
        // emission (FSD §3.2.1 v0.1 emission gate: post-verify,
        // pre-application-layer-handler) + InlineText fan-out
        // (CIRISEdge#22 Tier 2; the EdgeCommunicationAdapter inbound
        // path).
        let verify = self.verify.clone();
        let handlers = self.handlers.clone();
        let queue = self.queue.clone();
        let signer = self.signer.clone();
        let inline_subs = self.inline_text_subscribers.clone();
        let max_content_body_bytes = self.config.max_content_body_bytes;
        let reachability = self.reachability.clone();
        let detector = self.detector.clone();
        let verified_tx = self.verified_envelope_tx.clone();
        let content_pending = self.content_fetch_pending.clone();
        let metrics = self.metrics.clone();
        let events = self.events.clone();
        // CIRISEdge#48-A (v0.19.1) — clone the cohort_membership
        // handle + enforcement mode into the dispatcher loop so the
        // consumer-side check can access both.
        let cohort_membership = self.cohort_membership.clone();
        let cohort_enforcement = self.config.cohort_scope_enforcement;
        let mut shutdown = shutdown_rx;
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!("edge: shutdown signal received");
                    break;
                }
                Some(frame) = inbound_rx.recv() => {
                    let verify_clone = verify.clone();
                    let handlers_clone = handlers.clone();
                    let queue_clone = queue.clone();
                    let signer_clone = signer.clone();
                    let its = inline_subs.clone();
                    let reach_clone = reachability.clone();
                    let directory_clone = verify_clone.directory();
                    let detector_clone = detector.clone();
                    let verified_tx_clone = verified_tx.clone();
                    let content_pending_clone = content_pending.clone();
                    let metrics_clone = metrics.clone();
                    let events_clone = events.clone();
                    let cohort_membership_clone = cohort_membership.clone();
                    tokio::spawn(async move {
                        dispatch_inbound(
                            frame,
                            &verify_clone,
                            &handlers_clone,
                            &queue_clone,
                            &signer_clone,
                            &its,
                            max_content_body_bytes,
                            &directory_clone,
                            Some(&reach_clone),
                            detector_clone.as_ref(),
                            &verified_tx_clone,
                            &content_pending_clone,
                            &metrics_clone,
                            &events_clone,
                            &cohort_membership_clone,
                            cohort_enforcement,
                        ).await;
                    });
                }
                else => break,
            }
        }

        for t in tasks {
            let _ = t.await;
        }
        Ok(())
    }

    /// CIRISEdge#48-A (v0.19.1) — build + sign an envelope with an
    /// optional cohort_scope slot. Sets the slot BEFORE the canonical-
    /// bytes signature so the scope is committed-to by the sender's
    /// signature. Callers passing `None` for `cohort_scope` produce a
    /// v0.19.0-equivalent envelope (slot omitted from JSON via
    /// `skip_serializing_if`).
    async fn build_signed_envelope_with_cohort_scope<M: Message>(
        &self,
        destination_key_id: &str,
        msg: &M,
        in_reply_to: Option<[u8; 32]>,
        cohort_scope: Option<CohortScope>,
    ) -> Result<Vec<u8>, EdgeError> {
        let mut envelope = build_envelope(
            M::TYPE,
            &self.signer.key_id,
            destination_key_id,
            msg,
            in_reply_to,
        )?;
        envelope.cohort_scope = cohort_scope;
        sign_envelope(&self.signer, &mut envelope).await?;
        let bytes = serde_json::to_vec(&envelope)
            .map_err(|e| EdgeError::Config(format!("envelope serialize: {e}")))?;
        if bytes.len() > self.config.max_body_bytes {
            return Err(EdgeError::Config(format!(
                "envelope {} bytes exceeds max_body_bytes {}",
                bytes.len(),
                self.config.max_body_bytes
            )));
        }
        Ok(bytes)
    }

    /// CIRISEdge#48-A (v0.19.1) — producer-side enforcement gate for
    /// `Delivery::Federation` / `Delivery::Mandatory` fan-outs. The
    /// locality variants (`SelfOnly`, `Family`, `Cohort`) MUST NOT
    /// cross federation-class hops. Returns `Ok(())` when public OR
    /// when enforcement is off/warn (warn logs but allows).
    fn enforce_federation_class_scope(
        &self,
        cohort_scope: Option<&CohortScope>,
        federation_variant: bool,
    ) -> Result<(), EdgeError> {
        let Some(scope) = cohort_scope else {
            return Ok(());
        };
        if !scope.is_restricted() {
            return Ok(());
        }
        match self.config.cohort_scope_enforcement {
            CohortScopeEnforcement::Off => Ok(()),
            CohortScopeEnforcement::WarnOnly => {
                tracing::warn!(
                    event = "edge.cohort_scope.warn_only",
                    enforcement = %CohortScopeEnforcement::WarnOnly.as_str(),
                    cohort_scope = ?scope,
                    federation_variant,
                    "cohort_scope locality refusal bypassed (WarnOnly mode); CIRISEdge#48-A",
                );
                Ok(())
            }
            CohortScopeEnforcement::Strict => {
                if federation_variant {
                    Err(EdgeError::CohortScopeRefusedFederation {
                        cohort_scope: scope.clone(),
                    })
                } else {
                    Err(EdgeError::CohortScopeRefusedMandatory {
                        cohort_scope: scope.clone(),
                    })
                }
            }
        }
    }

    /// CIRISEdge#48-A (v0.19.1) — producer-side enforcement gate for
    /// `Delivery::Ephemeral` / `Delivery::Durable` (point-to-point).
    /// `SelfOnly` requires recipient == self.signer.key_id; `Family`
    /// requires the recipient's recorded scope to be Family; `Cohort`
    /// requires matching cohort_id.
    fn enforce_point_to_point_scope(
        &self,
        cohort_scope: Option<&CohortScope>,
        recipient_key_id: &str,
    ) -> Result<(), EdgeError> {
        let Some(scope) = cohort_scope else {
            return Ok(());
        };
        if !scope.is_restricted() {
            return Ok(());
        }
        let allowed = match scope {
            CohortScope::Public => true,
            CohortScope::SelfOnly => recipient_key_id == self.signer.key_id,
            CohortScope::Family | CohortScope::Cohort { .. } => {
                let recipient_scope = self.peer_cohort_scope(recipient_key_id);
                match recipient_scope.as_ref() {
                    Some(rs) => scope.allows_recipient_scope(rs),
                    None => false,
                }
            }
        };
        if allowed {
            return Ok(());
        }
        match self.config.cohort_scope_enforcement {
            CohortScopeEnforcement::Off => Ok(()),
            CohortScopeEnforcement::WarnOnly => {
                tracing::warn!(
                    event = "edge.cohort_scope.warn_only",
                    enforcement = %CohortScopeEnforcement::WarnOnly.as_str(),
                    cohort_scope = ?scope,
                    recipient_key_id,
                    "cohort_scope recipient refusal bypassed (WarnOnly mode); CIRISEdge#48-A",
                );
                Ok(())
            }
            CohortScopeEnforcement::Strict => Err(EdgeError::CohortScopeRefusedRecipient {
                cohort_scope: scope.clone(),
                recipient_key_id: recipient_key_id.to_string(),
            }),
        }
    }
}

/// Inbound dispatch: verify → maybe-ACK-match → `ContentBody`
/// AV-13/integrity gate (CIRISEdge#21 v0.8.0) → `FederationAnnouncement`
/// `AccordCarrier` 2-of-3 multi-sig wire-layer gate (CIRISEdge#19,
/// v0.10.0) → `FederationAnnouncement` attestation-emission (FSD §3.2.1
/// v0.1 gate) → `InlineText` fan-out (CIRISEdge#22 Tier 2 v0.9.0) →
/// typed handler dispatch.
#[allow(clippy::too_many_lines)] // dispatch is the load-bearing pipeline composition site
#[allow(clippy::too_many_arguments)] // composition site for all dispatch primitives
#[tracing::instrument(
    name = "edge.dispatch_inbound",
    skip(
        frame,
        verify,
        handlers,
        queue,
        signer,
        inline_text_subscribers,
        directory,
        reachability,
        detector,
        verified_envelope_tx,
        content_fetch_pending,
        metrics,
        events,
        cohort_membership,
    ),
    fields(
        transport_id = %frame.transport.0,
        envelope_bytes = frame.envelope_bytes.len(),
        signing_key_id = tracing::field::Empty,
        message_type = tracing::field::Empty,
        body_sha256_prefix = tracing::field::Empty,
        verify_outcome = tracing::field::Empty,
    ),
)]
async fn dispatch_inbound(
    frame: InboundFrame,
    verify: &VerifyPipeline,
    handlers: &Mutex<HashMap<MessageType, RegisteredHandler>>,
    queue: &Arc<dyn OutboundHandle>,
    signer: &Arc<LocalSigner>,
    inline_text_subscribers: &std::sync::Mutex<HashMap<u64, InlineTextSubscriber>>,
    max_content_body_bytes: usize,
    directory: &Arc<dyn VerifyDirectory>,
    reachability: Option<&Arc<ReachabilityTracker>>,
    detector: Option<&Arc<crate::ProbePatternObserver>>,
    verified_envelope_tx: &broadcast::Sender<VerifiedEnvelopeSnapshot>,
    content_fetch_pending: &std::sync::Mutex<HashMap<[u8; 32], oneshot::Sender<ContentResult>>>,
    metrics: &crate::observability::EdgeMetrics,
    events: &Arc<crate::events::EventBus>,
    cohort_membership: &std::sync::RwLock<HashMap<String, CohortScope>>,
    cohort_enforcement: CohortScopeEnforcement,
) {
    let received_at = frame.received_at;
    let transport = frame.transport;
    // CIRISEdge#28 (v0.19.0) — count the bytes consumed by the
    // listener side regardless of verify outcome (the wire spent the
    // bytes; observability covers them).
    metrics.add_bytes_in(transport, frame.envelope_bytes.len() as u64);
    let verified = match verify.verify(&frame.envelope_bytes, transport).await {
        Ok(v) => v,
        Err(e) => {
            let class = crate::observability::VerifyErrorClass::from_verify_error(&e);
            metrics.inc_verify_failure(class);
            tracing::Span::current().record("verify_outcome", class.as_str());
            tracing::error!(
                event = "edge.dispatch_inbound.verify_rejected",
                transport_id = %transport.0,
                verify_error_class = class.as_str(),
                error = %e,
                "verify rejected",
            );
            return;
        }
    };

    let VerifiedEnvelope {
        envelope,
        body_sha256,
        verify_outcome,
        ..
    } = verified;

    // CIRISEdge#28 (v0.19.0) — record structured span fields the
    // tracing-subscriber consumers (CIRISLens, CIRISAgent UI)
    // downstream alert on.
    {
        let span = tracing::Span::current();
        span.record("signing_key_id", envelope.signing_key_id.as_str());
        span.record(
            "message_type",
            tracing::field::debug(&envelope.message_type),
        );
        let mut prefix = String::with_capacity(16);
        for b in &body_sha256[..8] {
            use std::fmt::Write as _;
            let _ = write!(prefix, "{b:02x}");
        }
        span.record("body_sha256_prefix", prefix.as_str());
        span.record("verify_outcome", tracing::field::debug(&verify_outcome));
    }

    // CIRISEdge#28 (v0.19.0) — count the verified inbound envelope.
    metrics.inc_received(&envelope.message_type);

    // CIRISEdge#22 Tier 3 (v0.17.0) — fan out every verified envelope
    // on the broadcast channel BEFORE any type-specific gating. The
    // subscribe_feed AsyncIterator consumer receives the full set; if
    // there are no subscribers the send returns Err and we swallow it.
    let _ = verified_envelope_tx.send(VerifiedEnvelopeSnapshot {
        envelope: envelope.clone(),
        body_sha256,
        transport_id: transport,
        received_at,
    });

    // CIRISEdge#48-A (v0.19.1) — consumer-side symmetric cohort_scope
    // check. AFTER verify (signature gates everything; we trust the
    // claimed scope only insofar as the sender's key vouches for it)
    // and BEFORE handler dispatch (a violation MUST NOT reach the
    // application tier). Producer-side refusal at outbound_enqueue
    // is the structural primitive; this consumer-side check is the
    // symmetric pair per the CIRISEdge#48-A issue body.
    //
    // Wire-format invariant: for ContributionSubmit envelopes (and any
    // other envelope carrying a `cohort_scope`), if the claimed scope
    // is `SelfOnly` or `Family` AND the sender's directory-recorded
    // scope doesn't match the claim, REJECT with a moderation-signal
    // event so lens-core can downweight the sender. `Public` and
    // `Cohort{id}` are NOT short-circuited here at v0.19.1 — `Public`
    // is the implicit baseline, and `Cohort` membership lookup is
    // future work alongside the same persist `cohort_membership` API
    // dependency this whole feature documents.
    if let Some(claimed) = envelope.cohort_scope.as_ref() {
        if matches!(claimed, CohortScope::SelfOnly | CohortScope::Family) {
            let recorded_scope = cohort_membership
                .read()
                .ok()
                .and_then(|map| map.get(&envelope.signing_key_id).cloned());
            let matches_directory = match recorded_scope.as_ref() {
                Some(rs) => rs == claimed,
                None => false,
            };
            if !matches_directory {
                match cohort_enforcement {
                    CohortScopeEnforcement::Off => {
                        // No enforcement; fall through to handler.
                    }
                    CohortScopeEnforcement::WarnOnly => {
                        tracing::warn!(
                            event = "edge.cohort_scope.violation.warn_only",
                            enforcement = %CohortScopeEnforcement::WarnOnly.as_str(),
                            sender_key_id = %envelope.signing_key_id,
                            claimed_scope = ?claimed,
                            directory_scope = ?recorded_scope,
                            "consumer-side cohort_scope violation bypassed (WarnOnly mode); CIRISEdge#48-A",
                        );
                    }
                    CohortScopeEnforcement::Strict => {
                        tracing::Span::current().record("verify_outcome", "cohort_scope_violation");
                        tracing::warn!(
                            event = "edge.cohort_scope.violation",
                            sender_key_id = %envelope.signing_key_id,
                            claimed_scope = ?claimed,
                            directory_scope = ?recorded_scope,
                            "consumer-side cohort_scope violation REJECTED (CIRISEdge#48-A)",
                        );
                        // CIRISEdge#48-A — moderation-signal event on
                        // the EventBus so lens-core can downweight the
                        // sender. Wire shape: resource event tagged
                        // with the sender's key id + a severity of
                        // Warning. The scope-violation discriminator
                        // lives in the description string so consumers
                        // can grep without re-parsing the event tree.
                        events.emit_resource(crate::events::NetworkEvent::resource(
                            "cohort_scope_violation",
                            1.0,
                            "count",
                            crate::events::EventSeverity::Warning,
                            "cohort_scope violation (CIRISEdge#48-A)",
                        ));
                        return;
                    }
                }
            }
        }
    }

    // CIRISEdge#39 (slotted v0.17.0) — Counter-RII probe-pattern
    // observation. Runs AFTER verify (the signature gates everything,
    // and a malformed envelope is filtered before we touch the
    // detector), BEFORE handler dispatch. Consent-role gating and the
    // enabled-flag check live inside `observe_inbound` so the call
    // site is one Option-is-Some branch + one await.
    if let Some(observer) = detector {
        observer.observe_inbound(&envelope, transport).await;
        if let Some(verdict) = observer.check_for_detection(&envelope.signing_key_id).await {
            observer.emit_verdict(&verdict).await;
        }
    }

    // CIRISEdge#21 v0.8.0 — `ContentBody` AV-13 size cap + content-
    // addressed integrity check, applied post-verify and BEFORE
    // handler dispatch. The signature on the envelope binds the
    // (sha256, bytes) pair to the responder; this gate binds the
    // bytes to the SHA. Without this re-hash the content-addressed
    // invariant collapses to "trust whatever the responder said the
    // SHA was" — which defeats the entire point of byte-fetch over a
    // federation directory.
    //
    // Reject reasons map to the existing AV-13 family error
    // (`VerifyError::BodyTooLarge`) and a typed integrity-mismatch
    // log (handlers never see a bad ContentBody). Fail-loud at the
    // `tracing::warn!` boundary — no silent drops (MISSION.md §3
    // anti-pattern 6).
    if envelope.message_type == MessageType::ContentBody {
        match validate_content_body(&envelope, max_content_body_bytes) {
            Ok(()) => {}
            Err(e) => {
                tracing::warn!(
                    transport = ?transport,
                    error = %e,
                    body_sha256 = ?body_sha256,
                    "ContentBody rejected at dispatch gate (AV-13 / integrity)",
                );
                return;
            }
        }
        // CIRISEdge#22 Tier 3 (v0.17.0) — verified + integrity-checked
        // `ContentBody` arrived. Signal any in-flight `fetch_content`
        // waiter for this sha256 with the bytes. The match key is the
        // body's own `sha256` field (echoed back in `ContentBody`),
        // not the envelope-level body_sha256.
        if let Ok(body) = serde_json::from_str::<crate::messages::ContentBody>(envelope.body.get())
        {
            let mut pending = content_fetch_pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(tx) = pending.remove(&body.sha256) {
                let _ = tx.send(ContentResult::Bytes(body.bytes));
            }
        }
    }

    // CIRISEdge#22 Tier 3 (v0.17.0) — `ContentMiss` arm of the
    // fetch_content correlation. Same match-by-body-sha256 rule.
    if envelope.message_type == MessageType::ContentMiss {
        if let Ok(miss) = serde_json::from_str::<crate::messages::ContentMiss>(envelope.body.get())
        {
            let mut pending = content_fetch_pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(tx) = pending.remove(&miss.sha256) {
                let reason = format!("{:?}", miss.reason);
                let _ = tx.send(ContentResult::ContentMiss { reason });
            }
        }
    }

    // CIRISEdge#19 v0.10.0 — wire-layer 2-of-3 multi-sig authority
    // gate for `priority == AccordCarrier`. Defense in depth on the
    // v0.6.0 application-tier `FederationAnnouncement` consumer check:
    // a compromised peer can no longer propagate an invalid
    // CONSTITUTIONAL envelope past the first hop running verified
    // edge code. Failures REFUSE propagation and emit a substrate-
    // signed `DeliveryRefusalAttestation` (so adversarial suppression
    // of legitimate accords stays distinguishable from suppression of
    // forged ones).
    //
    // The accord-multi-sig set lives on the `FederationAnnouncement`
    // BODY (not on the surrounding `EdgeEnvelope`'s single sender
    // signature) — re-parse the body once here for the gate. The
    // existing `DeliveryAttestation` emission below stays bypassed on
    // refusal (the refusal IS the observable for AccordCarrier; a
    // refused envelope MUST NOT also emit an acceptance attestation).
    if envelope.message_type == MessageType::FederationAnnouncement {
        match serde_json::from_str::<FederationAnnouncement>(envelope.body.get()) {
            Ok(ann) if ann.priority == AnnouncementPriority::AccordCarrier => {
                match verify_accord_carrier(&ann, directory).await {
                    Ok(()) => {
                        // Threshold met — fall through to the normal
                        // v0.6.0 acceptance attestation + handler
                        // dispatch path.
                    }
                    Err(reason) => {
                        tracing::warn!(
                            announcement_id = ?derive_announcement_id_from_body_hash(&body_sha256),
                            ?reason,
                            "AccordCarrier FederationAnnouncement REFUSED at wire-layer multi-sig gate (CIRISEdge#19)",
                        );
                        // CIRISEdge#34 v0.19.0 — refusal IS a path-lost
                        // signal: edge-substrate declined to propagate
                        // because the multi-sig threshold wasn't met.
                        events.emit_path(crate::events::NetworkEvent::path(
                            crate::events::EventKind::PathLost,
                            body_sha256.to_vec(),
                            0,
                            Some(transport.0.to_string()),
                            Some(envelope.signing_key_id.clone()),
                            crate::events::EventSeverity::Warning,
                            "AccordCarrier refused at wire-layer gate",
                        ));
                        if let Err(e) = emit_delivery_refusal_attestation(
                            &envelope,
                            body_sha256,
                            transport,
                            signer,
                            queue,
                            reason,
                        )
                        .await
                        {
                            tracing::warn!(
                                error = %e,
                                "DeliveryRefusalAttestation emission failed (CIRISEdge#19)",
                            );
                        }
                        // Drop the announcement from edge's downstream
                        // propagation — no handler dispatch, no
                        // acceptance attestation.
                        return;
                    }
                }
            }
            Ok(_) => {
                // Non-AccordCarrier priority: the wire-layer gate is
                // bypassed (FSD §4.5 reserves the multi-sig
                // requirement to AccordCarrier; other priorities ride
                // the single-signature envelope path).
            }
            Err(e) => {
                // Body did not parse as FederationAnnouncement — let
                // the existing acceptance attestation emit attempt
                // continue and the typed-handler dispatch path
                // discover the schema issue. The substrate is not
                // additionally responsible for app-layer schema gates.
                tracing::debug!(
                    error = %e,
                    "FederationAnnouncement body parse failed at AccordCarrier gate; downstream paths handle",
                );
            }
        }
    }

    // CIRISEdge#29 (v0.11.0) — inbound `DeliveryAttestation` is the
    // strongest reachability signal: the peer cryptographically
    // confirmed receipt of one of our envelopes. Record an
    // `AttestationReceived` outcome against `(peer_key_id,
    // transport_id_from_body)` — note that we use the peer-reported
    // medium from the attestation body, NOT the transport the
    // attestation itself arrived over (the attestation may be relayed
    // via a different medium than the original message it
    // acknowledges, and the wire-recorded transport_id in the body is
    // the medium that actually carried the original delivery).
    if envelope.message_type == MessageType::DeliveryAttestation {
        if let Ok(att) =
            serde_json::from_str::<crate::messages::DeliveryAttestation>(envelope.body.get())
        {
            let medium_id = transport_id_from_medium(att.transport_id);
            record_if_tracking(
                reachability,
                &att.peer_key_id,
                medium_id,
                AttemptOutcome::AttestationReceived,
            );
            // CIRISEdge#34 v0.19.0 — peer cryptographically confirmed
            // a delivery via `medium_id`. Project this as a PathEvent
            // (PathDiscovered) so consumers' meta-observability streams
            // see the cold-start reach signal.
            //
            // `destination_hash` here is the body_sha256 of the
            // attestation envelope (the attestation's own join key);
            // it isn't the Reticulum 16-byte dest hash, but the wire
            // shape carries arbitrary bytes and downstream consumers
            // route on (peer_key_id, kind) primarily. The Reticulum
            // path-table-side emission lands the canonical 16-byte
            // hash on its own arms.
            events.emit_path(crate::events::NetworkEvent::path(
                crate::events::EventKind::PathDiscovered,
                body_sha256.to_vec(),
                0,
                Some(medium_id.0.to_string()),
                Some(att.peer_key_id.clone()),
                crate::events::EventSeverity::Info,
                "delivery attestation confirms reach",
            ));
        }
    }

    // CIRISEdge#42 (v0.12.0, CEG §10.1.2) — `ContentMiss` is the
    // canonical CEG §10.1.2 trigger for emitting a `Withdraws`
    // attestation against the holder. The peer (the holder) advertised
    // `holds_bytes:sha256:{prefix}` for this SHA, we asked, and the
    // holder responded with a typed miss. The withdrawal is shipped
    // via the existing federation evidence path; receivers aggregate
    // per `(holder_key_id, sha256)` and apply the downweight policy in
    // their own PeerResolver.
    //
    // This hook fires BEFORE typed handler dispatch — application
    // handlers see the ContentMiss after the substrate has recorded
    // its observability. The emission failure does NOT block
    // application dispatch (same discipline as the
    // DeliveryAttestation emission below).
    if envelope.message_type == MessageType::ContentMiss {
        if let Ok(miss) = serde_json::from_str::<crate::messages::ContentMiss>(envelope.body.get())
        {
            if let Err(e) = emit_withdraws(
                &envelope.signing_key_id,
                miss.sha256,
                crate::messages::WithdrawalReason::ContentMiss,
                signer,
                queue,
            )
            .await
            {
                tracing::warn!(
                    holder_key_id = %envelope.signing_key_id,
                    reason = ?miss.reason,
                    error = %e,
                    "Withdraws emission failed (CIRISEdge#42, CEG §10.1.2)",
                );
            }
        }
    }

    // FSD §3.2.1 v0.1 emission gate — post-verify-pipeline, the
    // announcement has cleared edge's signature + freshness + replay
    // gates. NodeCore's authority-class verifier runs at the consumer
    // handler; for v0.1 edge emits at this point (per the FSD's
    // pragmatic gate). Application-layer-acceptance tightening is a
    // v0.2+ option per FSD §7 OQ-6.
    //
    // CIRISEdge#20 — the emission fires on both the FederationAnnouncement
    // wire type (Mandatory class) AND the StewardDirective wire type
    // (Federation class). `is_federation_attestation_emitting_type`
    // owns the wire-type allowlist so adding future Federation- or
    // Mandatory-class wire types only touches one helper, not this
    // dispatch site.
    if is_federation_attestation_emitting_type(&envelope.message_type) {
        if let Err(e) =
            emit_delivery_attestation(&envelope, body_sha256, transport, signer, queue).await
        {
            // The attestation is observability; a failure to emit
            // does NOT block application-layer dispatch. Log and
            // continue (FSD §3.2.1 — missing-attestation-as-
            // delivery-gap is the legitimate observable).
            tracing::warn!(
                message_type = ?envelope.message_type,
                error = %e,
                "DeliveryAttestation emission failed",
            );
        }
    }

    // ACK matching — if envelope.in_reply_to is set, this is a
    // response to one of our outbound durable rows. Look up + mark
    // ack_received before dispatching to the application handler.
    if let Some(in_reply_to) = envelope.in_reply_to {
        match queue.match_ack_to_outbound(&in_reply_to).await {
            Ok(Some(row)) => {
                if let Err(e) = queue
                    .mark_ack_received(&row.queue_id, &frame.envelope_bytes)
                    .await
                {
                    tracing::error!(error = %e, "mark_ack_received failed");
                }
                // Don't dispatch to a handler — ACK envelopes are
                // bookkeeping, not application-level events.
                return;
            }
            Ok(None) => {
                tracing::debug!(
                    in_reply_to = ?in_reply_to,
                    "in_reply_to set but no matching outbound row; dropping",
                );
                return;
            }
            Err(e) => {
                tracing::error!(error = %e, "match_ack_to_outbound failed");
                return;
            }
        }
    }

    // CIRISEdge#22 Tier 2 (v0.9.0) — InlineText fan-out. The Python
    // `register_inline_text_handler` surface supports multiple
    // concurrent subscribers, which the singleton `handlers` HashMap
    // does not (one entry per `MessageType`). Fan out to every
    // registered subscriber here; the typed-handler dispatch still
    // runs below (so a Rust-side typed `Handler<InlineText>` registered
    // via `register_handler` continues to work, parallel to the
    // Python fan-out).
    //
    // We parse the body once here; the typed-handler path re-parses
    // (via the erased handler closure) — the cost is negligible
    // (the body is already a `RawValue`), and keeping the two paths
    // independent is structurally simpler than threading a parsed
    // body through the erased dispatch.
    if envelope.message_type == MessageType::InlineText {
        match serde_json::from_str::<crate::messages::InlineText>(envelope.body.get()) {
            Ok(inline) => {
                fan_out_inline_text(
                    inline_text_subscribers,
                    &envelope.signing_key_id,
                    &inline.text,
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    transport = ?transport,
                    "InlineText body parse failed at dispatch fan-out",
                );
            }
        }
    }

    // Application handler dispatch.
    let registered = {
        let handlers = handlers.lock().await;
        handlers
            .get(&envelope.message_type)
            .map(|h| h.erased.clone())
    };
    let Some(erased) = registered else {
        // InlineText with no typed Rust handler is not an error — the
        // Python fan-out above is the intended consumer. Suppress the
        // `no handler registered` warning for that one type.
        if envelope.message_type != MessageType::InlineText {
            tracing::warn!(
                message_type = ?envelope.message_type,
                "no handler registered; dropping",
            );
        }
        return;
    };

    let ctx = HandlerContext {
        signing_key_id: envelope.signing_key_id.clone(),
        body_sha256,
        transport,
        verify_outcome,
        received_at,
    };

    match (erased)(&envelope, ctx).await {
        Ok(_response_bytes) => {
            // Phase 1: response bytes are computed but not wired back
            // through the transport's response channel. Lens cutover
            // doesn't need outbound responses (lens always receives,
            // never replies). When Phase 2 wires register_handler
            // responses through the transport, this is where the
            // response envelope assembles + signs + ships back.
        }
        Err(e) => {
            tracing::error!(
                message_type = ?envelope.message_type,
                error = %e,
                "handler error",
            );
        }
    }
}

// ─── Builder ────────────────────────────────────────────────────────

impl EdgeBuilder {
    /// Sovereign-mode convenience: load steward identity from
    /// filesystem seeds via `ciris-keyring`, open persist's
    /// SQLite-backed federation directory + edge outbound queue at
    /// `db_path`, and return a fully-wired builder. Caller still
    /// adds transports + (optionally) a `speak_pipeline` before
    /// `build()`. Use this in deployments that have no
    /// `ciris_persist::Engine` in-process (Reticulum-only sovereign
    /// agents, Pi/iOS hosts). Closes the sovereign half of
    /// CIRISLensCore#7 / CIRISPersist#43 / CIRISVerify#20.
    ///
    /// `key_id` is the steward identity advertised on outbound
    /// envelopes (`federation_keys.key_id`). `seed_path` points at
    /// the directory containing `ed25519.seed` (and optionally
    /// `ml_dsa_65.seed`); the constructor reads both and produces
    /// `Arc<dyn HardwareSigner>` + optional `Arc<dyn PqcSigner>` via
    /// the keyring loader.
    pub async fn from_keyring_seed_dir(
        key_id: impl Into<String>,
        seed_dir: PathBuf,
        db_path: PathBuf,
    ) -> Result<Self, EdgeError> {
        // v0.10.0 (CIRISEdge#13): signer-load delegates to the
        // standalone `LocalSigner::from_keyring_seed_dir` so consumers
        // that share an existing persist Engine (cohabitation case)
        // can reuse the same seed-layout convention without
        // re-implementing it. The builder still owns the
        // db_path-opens-its-own-pool path here.
        let signer = LocalSigner::from_keyring_seed_dir(key_id, seed_dir).await?;

        let directory = ciris_persist::prelude::FederationDirectorySqlite::open(&db_path)
            .await
            .map_err(|e| EdgeError::Persist(format!("FederationDirectorySqlite::open: {e}")))?;
        let queue = ciris_persist::prelude::EdgeOutboundQueueSqlite::open(&db_path)
            .await
            .map_err(|e| EdgeError::Persist(format!("EdgeOutboundQueueSqlite::open: {e}")))?;

        // v0.15.1 (CIRISEdge#26 mutation surface) — the underlying
        // `FederationDirectorySqlite` IS a `FederationDirectory`; clone
        // the `Arc` so the UniFFI peer-mutation entry points reach the
        // 6 persist v3.1.0 (CIRISPersist#117) methods without an
        // unsized downcast through `VerifyDirectory`.
        let federation_directory: Arc<dyn ciris_persist::federation::FederationDirectory> =
            directory.clone();
        Ok(Edge::builder()
            .directory(directory)
            .federation_directory(federation_directory)
            .queue(queue)
            .signer(Arc::new(signer)))
    }

    #[must_use]
    pub fn directory(mut self, directory: Arc<dyn VerifyDirectory>) -> Self {
        self.directory = Some(directory);
        self
    }

    /// CIRISEdge#26 mutation surface (v0.15.1) — wire the concrete
    /// `Arc<dyn FederationDirectory>` the UniFFI peer-mutation entry
    /// points need. Optional; if omitted, those entry points surface
    /// `EdgeBindingsError::Unsupported`. Distinct from
    /// [`Self::directory`] because persist's `FederationDirectory`
    /// trait is object-safe (`#[async_trait]`) while
    /// [`VerifyDirectory`] is a separate adapter trait that uses an
    /// unsized blanket impl over `FederationDirectory`.
    ///
    /// Production callers (pyo3 cohabitation init) typically pass the
    /// same `Arc` they pass to `.directory(...)` after an
    /// upcast — the two trait objects can refer to the same backend.
    #[must_use]
    pub fn federation_directory(
        mut self,
        directory: Arc<dyn ciris_persist::federation::FederationDirectory>,
    ) -> Self {
        self.federation_directory = Some(directory);
        self
    }

    #[must_use]
    pub fn queue(mut self, queue: Arc<dyn OutboundHandle>) -> Self {
        self.queue = Some(queue);
        self
    }

    #[must_use]
    pub fn signer(mut self, signer: Arc<LocalSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    #[must_use]
    pub fn transport(mut self, transport: Arc<dyn Transport>) -> Self {
        self.transports.push(transport);
        self
    }

    /// CIRISEdge#32 (v0.14.0) — register the Reticulum transport with
    /// BOTH a typed `Arc<ReticulumTransport>` retained on the builder
    /// AND its `Arc<dyn Transport>` upcast pushed into the transport
    /// collection (so the listen / send fan-out is identical to the
    /// generic [`Self::transport`] path). The typed side feeds the
    /// Links FFI surface (`link_open` / `link_request` / `link_teardown`
    /// / `link_list` / `link_count`) which needs the concrete
    /// `ReticulumTransport::link_*` methods.
    ///
    /// Existing call sites that don't need the Links surface can keep
    /// using [`Self::transport`] with an upcast Arc; this method is the
    /// additive variant. The typed handle is OPTIONAL — `link_open`
    /// returns `EdgeBindingsError::Unsupported` when no Reticulum
    /// transport is registered.
    #[cfg(feature = "_reticulum-module")]
    #[must_use]
    pub fn reticulum_transport(
        mut self,
        transport: Arc<crate::transport::reticulum::ReticulumTransport>,
    ) -> Self {
        self.transports
            .push(Arc::clone(&transport) as Arc<dyn Transport>);
        self.reticulum_transport = Some(transport);
        self
    }

    /// CIRISEdge#34 — supply a pre-built [`crate::events::EventBus`].
    /// Optional; if omitted the builder constructs one at `build()`
    /// time with [`EdgeConfig::event_channel_capacity`]. Useful when
    /// a sibling cdylib (CIRISLensCore, CIRISNodeCore) wants to wire
    /// edge's event emissions into the same bus the host already
    /// owns — share the `Arc<EventBus>` across the construction.
    #[must_use]
    pub fn events(mut self, events: Arc<crate::events::EventBus>) -> Self {
        self.events = Some(events);
        self
    }

    /// CIRISEdge#34 (v0.14.0 wiring) — supply a pre-built
    /// [`ReachabilityTracker`]. Optional; if omitted the builder
    /// constructs one at `build()` from
    /// [`EdgeConfig::reachability_window_seconds`]. The pyo3 cohabitation
    /// init path uses this to share a tracker `Arc` between Edge and a
    /// Reticulum transport built BEFORE Edge (which can't reach back
    /// through `Edge::reachability_tracker()`).
    #[must_use]
    pub fn reachability(mut self, tracker: Arc<ReachabilityTracker>) -> Self {
        self.reachability = Some(tracker);
        self
    }

    /// CIRISEdge#39 (v0.17.0) — supply a persist `DerivedSchema`
    /// admission handle for the probe-pattern observer's `emit_verdict`
    /// path. Required for the observer to write `EdgeDetectionEvent`
    /// rows via `put_edge_detection_event` (persist v3.1.1+ / #118);
    /// without it the observer falls back to the v0.13.0 STUB
    /// `tracing::warn!` behavior. The production cohabitation init
    /// path (`init_edge_runtime`) derives the handle from the same
    /// `BackendDispatch` arm that produced the outbound queue + the
    /// blackhole rules (sibling traits on the same backend).
    #[must_use]
    pub fn derived_schema(
        mut self,
        schema: Arc<dyn crate::detector::EdgeDetectionAdmission>,
    ) -> Self {
        self.derived_schema = Some(schema);
        self
    }

    /// CIRISEdge#46 (v0.18.0) — supply the operator-declared canonical
    /// bootstrap-peer set. Each `key_id` is dropped into the in-memory
    /// canonical HashSet on the constructed [`Edge`], so the `peer_get`
    /// / `peer_list` projections fill the `canonical: bool` field and
    /// the `peer_remove` hard-remove guard fires correctly.
    ///
    /// This setter populates the IN-MEMORY set only. The persist
    /// reseed (`add_peer_record` per row) is async and lives in
    /// [`reseed_canonical_bootstrap_peers`] — cohabitation init paths
    /// call it before `build()` is invoked. Test fixtures that only
    /// need the in-memory canonical state (e.g. the `peer_remove`
    /// guard) can use this setter standalone.
    #[must_use]
    pub fn canonical_bootstrap_peers(mut self, peers: Vec<CanonicalBootstrapPeer>) -> Self {
        self.canonical_bootstrap_peers = peers;
        self
    }

    /// Configure the outbound inline-text pipeline. When set, edge
    /// runs it on every `send_inline` / `send_durable_inline` call
    /// before signing + shipping. Construct via
    /// `ciris_persist::pipeline::default_speak_pipeline(secrets,
    /// actor_id)` for the canonical Classify + Scrub + EncryptAndStore
    /// stage set, or compose stages directly. Optional — when unset,
    /// `send_inline` falls through to the ephemeral `send` path
    /// without transit-touch.
    #[must_use]
    pub fn speak_pipeline(
        mut self,
        pipeline: Arc<
            ciris_persist::pipeline::Pipeline<ciris_persist::prelude::InlineTextEnvelope>,
        >,
    ) -> Self {
        self.speak_pipeline = Some(pipeline);
        self
    }

    /// Wire a [`PeerDirectory`] adapter for `Edge::send_mandatory`
    /// fan-out (CIRISEdge#18). Without it `send_mandatory` returns
    /// [`EdgeError::Config`] — the federation broadcast has no
    /// recipient enumeration.
    #[must_use]
    pub fn peer_directory(mut self, dir: Arc<dyn PeerDirectory>) -> Self {
        self.peer_directory = Some(dir);
        self
    }

    /// Wire a [`StewardDirectory`] adapter for `Edge::send_federation`
    /// fan-out (CIRISEdge#20). Without it `send_federation` returns
    /// [`EdgeError::Config`] — the high-priority federation push has
    /// no recipient enumeration.
    ///
    /// Any `Arc<dyn FederationDirectory>` (persist v2.7.0+) satisfies
    /// this via the blanket impl in [`crate::outbound`] — the same
    /// `Arc` passed to [`Self::directory`] for the verify pipeline
    /// can be cloned and passed here. Tests stub it with a static
    /// `Vec<StewardKey>`.
    #[must_use]
    pub fn steward_directory(mut self, dir: Arc<dyn StewardDirectory>) -> Self {
        self.steward_directory = Some(dir);
        self
    }

    /// Wire a [`PeerSubscriptionFilter`] for subscription-respecting
    /// code paths. **Not consulted by `Delivery::Mandatory`** — the
    /// bypass-subscription wire contract (FSD §3.2 + CIRISEdge#18).
    /// **Consulted by `Delivery::Federation`** — the high-priority
    /// fan-out routes with preference, not federation-wide push
    /// (CIRISEdge#20).
    #[must_use]
    pub fn subscription_filter(mut self, filter: Arc<dyn PeerSubscriptionFilter>) -> Self {
        self.subscription_filter = Some(filter);
        self
    }

    #[must_use]
    pub fn config(mut self, config: EdgeConfig) -> Self {
        self.config = config;
        self
    }

    pub fn build(self) -> Result<Edge, EdgeError> {
        let directory = self
            .directory
            .ok_or_else(|| EdgeError::Config("directory not set".into()))?;
        let queue = self
            .queue
            .ok_or_else(|| EdgeError::Config("outbound queue not set".into()))?;
        let signer = self
            .signer
            .ok_or_else(|| EdgeError::Config("local signer not set".into()))?;
        if self.transports.is_empty() {
            return Err(EdgeError::Config("no transport configured".into()));
        }

        let verify = Arc::new(VerifyPipeline::new(
            directory,
            self.config.hybrid_policy,
            signer.key_id.clone(),
            self.config.max_body_bytes,
            self.config.replay_window_seconds,
            self.config.max_replay_entries,
        ));

        let events = self.events.unwrap_or_else(|| {
            Arc::new(crate::events::EventBus::with_capacity(
                self.config.event_channel_capacity,
            ))
        });

        // CIRISEdge#31 — load display_name from disk if configured.
        // Best-effort: a missing/unreadable file leaves the name unset
        // (operator hasn't set one yet, or filesystem hiccup); the
        // setter path is the canonical source of truth going forward.
        let display_name = self
            .config
            .display_name_path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s.len() <= 256);

        let reachability = self.reachability.unwrap_or_else(|| {
            Arc::new(ReachabilityTracker::new(
                self.config.reachability_window_seconds,
            ))
        });

        // CIRISEdge#39 (slotted v0.17.0) — construct the probe-pattern
        // observer iff the deployment opted in. The observer's
        // `enabled` flag mirrors the EdgeConfig toggle so a runtime
        // misconfiguration (enabled flag flipped but the inner config
        // disabled) still no-ops correctly; we propagate both for
        // belt-and-suspenders.
        //
        // v0.17.0 — when a `derived_schema` handle is wired AND the
        // observer is enabled, attach it via `with_derived_schema`
        // so `emit_verdict` admits rows into
        // `cirislens.edge_detection_events` (persist v3.1.1+ / #118).
        // Without the handle, the observer falls back to the v0.13.0
        // STUB `tracing::warn!` behavior — exercised by unit tests
        // that don't stand up a backend.
        let detector = if self.config.probe_pattern_observer_enabled {
            let mut detector_cfg = self.config.probe_pattern_observer_config.clone();
            detector_cfg.enabled = true;
            let mut observer = crate::ProbePatternObserver::new(verify.directory(), detector_cfg)
                .with_signing_key_id(signer.key_id.clone());
            if let Some(schema) = self.derived_schema.clone() {
                observer = observer.with_derived_schema(schema);
            }
            Some(Arc::new(observer))
        } else {
            None
        };

        // CIRISEdge#22 Tier 3 (v0.17.0) — verified-envelope broadcast +
        // content-fetch pending map. The broadcast capacity matches the
        // EventBus channel capacity so the two fan-in surfaces age
        // gracefully under the same back-pressure regime.
        let (verified_envelope_tx, _) =
            broadcast::channel(self.config.event_channel_capacity.max(1));
        let content_fetch_pending = Arc::new(std::sync::Mutex::new(HashMap::new()));

        // CIRISEdge#46 (v0.18.0) — populate the in-memory canonical
        // bootstrap-peer set. Empty HashSet when the operator passed no
        // bootstrap_peers; full set when they did. The persist reseed
        // is the COHAB INIT path's responsibility (see
        // `reseed_canonical_bootstrap_peers`); this builder step only
        // covers the in-memory invariant the `peer_remove` guard +
        // `EdgePeerInfo.canonical` projection depend on.
        let canonical_peers = Arc::new(std::sync::RwLock::new(
            self.canonical_bootstrap_peers
                .iter()
                .map(|p| p.key_id.clone())
                .collect::<HashSet<String>>(),
        ));

        Ok(Edge {
            verify,
            queue,
            signer,
            transports: self.transports,
            handlers: Arc::new(Mutex::new(HashMap::new())),
            inline_text_subscribers: Arc::new(std::sync::Mutex::new(HashMap::new())),
            inline_text_next_id: Arc::new(AtomicU64::new(1)),
            verified_envelope_tx,
            content_fetch_pending,
            speak_pipeline: self.speak_pipeline,
            peer_directory: self.peer_directory,
            steward_directory: self.steward_directory,
            subscription_filter: self.subscription_filter,
            events,
            display_name: Arc::new(std::sync::RwLock::new(display_name)),
            reachability,
            #[cfg(feature = "_reticulum-module")]
            reticulum_transport: self.reticulum_transport,
            federation_directory: self.federation_directory,
            detector,
            canonical_peers,
            cohort_membership: Arc::new(std::sync::RwLock::new(HashMap::new())),
            metrics: crate::observability::EdgeMetrics::new(),
            config: self.config,
        })
    }
}

// ─── DurableHandle helpers ──────────────────────────────────────────

impl DurableHandle {
    /// Snapshot via persist's `outbound_status`. Implementation lands
    /// here so DurableHandle stays a thin wire-format type without an
    /// engine reference.
    pub async fn status_via(&self, queue: &dyn OutboundHandle) -> Result<DurableStatus, EdgeError> {
        let row = queue
            .outbound_status(&self.queue_id)
            .await
            .map_err(|e| EdgeError::Persist(format!("outbound_status: {e}")))?;
        match row {
            Some(r) => Ok(map_row_to_status(&r)),
            None => Err(EdgeError::Persist(format!(
                "outbound row {} not found",
                self.queue_id
            ))),
        }
    }
}

/// Pub-crate re-export so [`crate::ffi::pyo3::PyDurableHandle`] can
/// reuse the same outbound-row → DurableStatus mapping the
/// `DurableHandle::status_via` Rust method uses. Only the pyo3
/// surface consumes it today (CIRISEdge#22 Tier 2; v0.9.0); the
/// `#[cfg]` gate matches the consumer so the non-pyo3 build doesn't
/// see a dead-code warning.
#[cfg(feature = "pyo3")]
pub(crate) fn map_outbound_row_to_status(
    row: &ciris_persist::prelude::OutboundRow,
) -> DurableStatus {
    map_row_to_status(row)
}

fn map_row_to_status(row: &ciris_persist::prelude::OutboundRow) -> DurableStatus {
    use ciris_persist::prelude::OutboundStatus as P;
    let attempt_count = u32::try_from(row.attempt_count).unwrap_or(0);
    match row.status {
        P::Pending => DurableStatus::Pending {
            attempt_count,
            next_attempt_after: row.next_attempt_after,
        },
        P::Sending => DurableStatus::Sending,
        P::AwaitingAck => DurableStatus::AwaitingAck {
            transport_delivered_at: row.transport_delivered_at.unwrap_or_else(Utc::now),
        },
        P::Delivered => DurableStatus::Terminal(DurableOutcome::Delivered {
            ack: None,
            delivered_at: row.delivered_at.unwrap_or_else(Utc::now),
        }),
        P::Abandoned => {
            let reason = match row.abandoned_reason {
                Some(ciris_persist::prelude::AbandonedReason::MaxAttempts) => {
                    AbandonReason::MaxAttempts
                }
                Some(ciris_persist::prelude::AbandonedReason::TtlExpired) => {
                    AbandonReason::TtlExpired
                }
                Some(ciris_persist::prelude::AbandonedReason::OperatorCancel) => {
                    AbandonReason::OperatorCancel
                }
                None => AbandonReason::MaxAttempts,
            };
            DurableStatus::Terminal(DurableOutcome::Abandoned {
                reason,
                abandoned_at: row.abandoned_at.unwrap_or_else(Utc::now),
                last_error_class: row.last_error_class.clone(),
            })
        }
    }
}

/// Fan out an inbound InlineText payload to every subscriber in the
/// registry. Lazily prunes entries whose `send` returns `Err` (the
/// Python `SubscriptionHandle` has gone out of scope without an
/// explicit `unsubscribe()` — channel-closed semantics from the
/// drainer-thread side). Free-function form because `dispatch_inbound`
/// is itself a free function — the `Edge::fan_out_inline_text` method
/// (on the type) is a thin wrapper around this same logic for
/// non-dispatcher callers (tests, future embedders).
fn fan_out_inline_text(
    inline_text_subscribers: &std::sync::Mutex<HashMap<u64, InlineTextSubscriber>>,
    sender_key_id: &str,
    body_text: &str,
) {
    let mut subs = inline_text_subscribers
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if subs.is_empty() {
        return;
    }
    let payload = (sender_key_id.to_string(), body_text.to_string());
    let mut dead: Vec<u64> = Vec::new();
    for (id, tx) in subs.iter() {
        if tx.send(payload.clone()).is_err() {
            dead.push(*id);
        }
    }
    for id in dead {
        subs.remove(&id);
    }
}

/// CIRISEdge#29 — collapse the wire-level [`crate::messages::TransportMedium`]
/// enum back to a [`crate::transport::TransportId`] for tracker
/// recording. The forward mapping (`TransportId → TransportMedium`)
/// is lossy (multiple transports can collapse onto one medium tag —
/// e.g. RETICULUM_RS and LEVICULUM both → Reticulum); the reverse uses
/// the canonical representative `TransportId` per medium. Consumers
/// SHOULD treat the tracker's `TransportId` as a medium-level tag for
/// `DeliveryAttestation`-sourced records, not a sub-medium discriminator.
fn transport_id_from_medium(
    medium: crate::messages::TransportMedium,
) -> crate::transport::TransportId {
    use crate::messages::TransportMedium;
    use crate::transport::TransportId;
    match medium {
        TransportMedium::Reticulum => TransportId::RETICULUM_RS,
        TransportMedium::HttpOverTls | TransportMedium::TcpTls => TransportId::HTTP,
        TransportMedium::Other => TransportId("other"),
    }
}

/// CIRISEdge#29 — classifier string for a [`TransportError`], used as
/// the `error_class` field on a [`AttemptOutcome::SendFailure`]. Mirrors
/// the dispatcher's mapping in `src/outbound.rs::dispatch_one` so the
/// `last_error_class` field on the [`crate::PeerMediumReachability`]
/// snapshot is consistent across send-path (this method's mapping)
/// and durable-dispatcher-path (the dispatcher's mapping) outcomes.
fn transport_error_class(e: &TransportError) -> &'static str {
    match e {
        TransportError::Unreachable(_) => "unreachable",
        TransportError::Timeout(_) => "timeout",
        TransportError::Config(_) => "config",
        TransportError::Io(_) => "io",
        TransportError::BodyTooLarge { .. } => "body_too_large",
        // v0.15.0 (CIRISEdge#33) — blackholed peer (operator deny-list
        // hit) is a distinct reachability class from substrate
        // unreachability. Surface it to the reachability tracker so
        // operators can disambiguate "peer down" from "peer banned".
        TransportError::PeerBlackholed { .. } => "peer_blackholed",
    }
}

fn message_type_str(mt: &MessageType) -> String {
    serde_json::to_value(mt)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{mt:?}"))
}

/// Validate a `ContentBody`-typed envelope against (a) the AV-13
/// content-body cap and (b) the content-addressed integrity invariant
/// (`sha256(bytes) == claimed_sha256`). CIRISEdge#21 v0.8.0 spec
/// points 2 + 7.
///
/// Returns:
///
/// - `Ok(())` — the body parsed, `bytes.len() <=
///   max_content_body_bytes`, and `sha256(bytes) == claimed_sha256`.
/// - `Err(VerifyError::BodyTooLarge { .. })` — the AV-13 family error
///   reused: oversized rejects look identical to envelope-tier AV-13
///   rejects so a downstream metric collector sees one error category.
/// - `Err(VerifyError::SchemaInvalid(_))` — body did not parse OR the
///   integrity check failed. The integrity-mismatch case folds to
///   `SchemaInvalid` (the envelope's typed `MessageType::ContentBody`
///   was advertised but the body bytes don't match their own claimed
///   SHA — a typed schema violation under the content-addressed
///   contract).
fn validate_content_body(
    envelope: &EdgeEnvelope,
    max_content_body_bytes: usize,
) -> Result<(), VerifyError> {
    use crate::messages::{sha256_of, ContentBody};

    let body: ContentBody = serde_json::from_str(envelope.body.get())
        .map_err(|e| VerifyError::SchemaInvalid(format!("ContentBody body parse: {e}")))?;

    // AV-13 family — oversized rejects with the same error variant as
    // the envelope-tier check (`VerifyError::BodyTooLarge`). One error
    // category across the AV-13 surface.
    if body.bytes.len() > max_content_body_bytes {
        return Err(VerifyError::BodyTooLarge {
            actual: body.bytes.len(),
            limit: max_content_body_bytes,
        });
    }

    // Content-addressed integrity gate — CEG §10.1.1 NORMATIVE +
    // CIRISEdge#21 spec point 2.
    //
    // `sha256(bytes) == claimed_sha256` is the WHOLE POINT of the
    // content-fetch primitive; a mismatch is a typed integrity
    // violation under the content-addressed contract.
    //
    // # CEG §10.1.1 short-circuit-verify pin (CIRISEdge#42, v0.12.0)
    //
    // The spec is normative on FULL-SHA verify: the entire `body.bytes`
    // payload is hashed and compared against the entire `body.sha256`
    // claim. Verifying only a prefix (first N bytes / prefix of the
    // hash) is REJECTED by CEG §10.1.1. The `sha256_of` call below
    // hashes the complete byte vector; any future "optimization" that
    // hashes only `body.bytes[..N]` or compares only `body.sha256[..N]`
    // is a spec violation.
    //
    // This invariant is regression-tested by
    // `tests/ceg_content_discipline.rs::content_body_short_circuit_verify_pinned_off`
    // — that test passes ONLY when the full-SHA verify path executes.
    // A regression that short-circuits will fail that test.
    let actual = sha256_of(&body.bytes);
    if actual != body.sha256 {
        return Err(VerifyError::ContentIntegrity {
            claimed_sha256: hex_encode(&body.sha256),
            actual_sha256: hex_encode(&actual),
        });
    }

    Ok(())
}

/// Cheap hex-encode helper for diagnostic log lines. Uses
/// `std::fmt::Write` over the byte slice (clippy:
/// `format_push_string` lints away a `format!`-append). Not
/// security-critical; just makes mismatch errors actionable.
fn hex_encode(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Derive a deterministic UUID `announcement_id` from the announcement
/// envelope's `body_sha256` — the bytes the peer actually received.
///
/// Persist's `put_delivery_attestation` parses `announcement_id` as a
/// UUID (`Uuid::parse_str`), so the wire field is constrained to that
/// shape. In production NodeCore stamps the surrounding Contribution
/// envelope with its `contribution_id` and the receiver propagates
/// that; for edge's v0.1 emission gate we don't yet wrap the
/// announcement in a NodeCore Contribution at the edge layer, so the
/// pragmatic choice is to derive the id from the body bytes
/// themselves.
///
/// Properties: same envelope bytes → same `announcement_id` at every
/// peer (the persist PK `(announcement_id, peer_key_id)` correctly
/// collates attestations from many peers to one announcement). Same
/// envelope bytes at the same peer → same `(announcement_id,
/// peer_key_id)` → persist's INSERT is idempotent on replay
/// (FSD §3.2.1 "AV: replayed attestation collapsed").
///
/// The UUID layout uses the body_sha256's first 16 bytes verbatim
/// with the v4 (random) variant + version bits set — wire-format
/// valid UUID without dragging in `uuid::v5` (no extra dependency
/// surface beyond the v4 feature already enabled).
fn derive_announcement_id_from_body_hash(body_sha256: &[u8; 32]) -> String {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&body_sha256[..16]);
    // Set RFC 4122 variant bits (top of byte 8 = 10xxxxxx).
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    // Set version 4 bits (top of byte 6 = 0100xxxx). Edge's emission
    // is deterministic-from-hash but the wire constraint is "any
    // RFC 4122 UUID" — the version bits just need to be syntactically
    // valid; v4 keeps the surface compatible with persist's parse.
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    uuid::Uuid::from_bytes(bytes).to_string()
}

/// Build, sign, and enqueue a [`crate::DeliveryAttestation`] for a
/// freshly-verified [`crate::FederationAnnouncement`] envelope. The
/// attestation rides `Delivery::Durable { requires_ack: false }`
/// (FSD §3.2.1 dispatch contract) — subscription-respecting fan-out
/// (NOT Mandatory), per-peer queued for delivery to whichever
/// federation collector is downstream of the local edge.
///
/// The peer's federation Ed25519 (and optional ML-DSA-65) key signs
/// the canonical-bytes encoding from
/// [`crate::DeliveryAttestation::canonical_bytes`] — byte-equal with
/// persist v2.2.0's encoder so a federation collector can verify the
/// attestation via `verify_hybrid_via_directory` against
/// `federation_keys[peer_key_id]`.
async fn emit_delivery_attestation(
    envelope: &EdgeEnvelope,
    body_sha256: [u8; 32],
    transport: crate::transport::TransportId,
    signer: &Arc<LocalSigner>,
    queue: &Arc<dyn OutboundHandle>,
) -> Result<(), EdgeError> {
    use crate::messages::{
        encode_canonical_hash_base64, encode_signature_base64, DeliveryAttestation, TransportMedium,
    };

    let announcement_id = derive_announcement_id_from_body_hash(&body_sha256);
    let peer_pubkey_bytes = signer
        .classical
        .public_key()
        .await
        .map_err(|e| EdgeError::Persist(format!("local pubkey: {e}")))?;
    let peer_pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(&peer_pubkey_bytes);

    // Canonical hash = SHA-256 of the full envelope-as-received. The
    // FSD §3.2.1 wire field is "SHA-256 of the full canonicalized
    // Contribution envelope INCLUDING its authority signature" — at
    // the edge layer the "full envelope" IS the EdgeEnvelope JSON,
    // and `body_sha256` already covers the body (which carries the
    // FederationAnnouncement payload). For v0.1, using body_sha256
    // pins the announcement payload bytes the peer received; the
    // surrounding signature is in the EdgeEnvelope and re-verified
    // upstream against `federation_keys[envelope.signing_key_id]`.
    let canonical_hash_b64 = encode_canonical_hash_base64(&body_sha256);

    // Build the attestation with a placeholder signature first so we
    // can produce canonical bytes (the signature itself is over
    // canonical_bytes, not part of canonical_bytes).
    let received_at = chrono::Utc::now();
    let mut att = DeliveryAttestation {
        announcement_id,
        announcement_canonical_hash_base64: canonical_hash_b64,
        peer_key_id: signer.key_id.clone(),
        peer_pubkey_ed25519_base64: peer_pubkey_b64,
        received_at,
        transport_id: TransportMedium::from(transport),
        signature_classical_base64: String::new(),
        signature_pqc_base64: None,
    };

    let canonical = att
        .canonical_bytes()
        .map_err(|e| EdgeError::Config(format!("delivery_attestation canonical_bytes: {e}")))?;

    // Mandatory classical Ed25519 sign.
    let ed25519_sig = signer
        .classical
        .sign(&canonical)
        .await
        .map_err(|e| EdgeError::Persist(format!("attestation classical sign: {e}")))?;
    att.signature_classical_base64 = encode_signature_base64(&ed25519_sig);

    // Optional PQC ML-DSA-65 over `canonical || classical_sig` per
    // persist's AV-33 bound-signature convention (FSD §3.2.1).
    if let Some(pqc) = signer.pqc.as_ref() {
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed25519_sig);
        let pqc_sig = pqc
            .sign(&bound)
            .await
            .map_err(|e| EdgeError::Persist(format!("attestation pqc sign: {e}")))?;
        att.signature_pqc_base64 = Some(encode_signature_base64(&pqc_sig));
    }

    // Wrap in a typed envelope. Destination is the **original
    // announcement sender** (envelope.signing_key_id) — the federation
    // steward / collector who'll aggregate the per-peer attestations.
    // FSD §3.2 "missing-attestation-as-delivery-gap" is observable at
    // the steward end.
    let envelope_bytes = {
        let mut env = build_envelope(
            MessageType::DeliveryAttestation,
            &signer.key_id,
            &envelope.signing_key_id,
            &att,
            None,
        )?;
        sign_envelope(signer, &mut env).await?;
        serde_json::to_vec(&env)
            .map_err(|e| EdgeError::Config(format!("attestation envelope serialize: {e}")))?
    };
    let env: EdgeEnvelope = serde_json::from_slice(&envelope_bytes)
        .map_err(|e| EdgeError::Config(format!("re-parse attestation envelope: {e}")))?;
    let body_sha256_att = envelope_body_sha256(&env);
    let body_size_bytes = i32::try_from(envelope_bytes.len()).unwrap_or(i32::MAX);

    // Match DeliveryAttestation::DELIVERY exactly (FSD §3.2.1 dispatch
    // table — fire-and-forget Durable).
    let (max_attempts, ttl_seconds) = match crate::DeliveryAttestation::DELIVERY {
        Delivery::Durable {
            max_attempts,
            ttl_seconds,
            ..
        } => (
            i32::try_from(max_attempts).unwrap_or(i32::MAX),
            i64::try_from(ttl_seconds).unwrap_or(i64::MAX),
        ),
        _ => (20, 24 * 60 * 60),
    };

    queue
        .enqueue_outbound(
            &signer.key_id,
            &envelope.signing_key_id,
            &message_type_str(&MessageType::DeliveryAttestation),
            "1.0.0",
            &envelope_bytes,
            &body_sha256_att,
            body_size_bytes,
            false, // requires_ack: false (FSD §3.2.1)
            None,
            max_attempts,
            ttl_seconds,
            Utc::now(),
        )
        .await
        .map_err(|e| EdgeError::Persist(format!("enqueue_outbound (attestation): {e}")))?;

    Ok(())
}

/// CIRISEdge#42 (v0.12.0, CEG §10.1.2) — emit a [`Withdraws`]
/// attestation against `holder_key_id` for the bytes hashing to
/// `sha256`. Signed by the consumer's local key via the surrounding
/// envelope (hybrid Ed25519 + ML-DSA-65); shipped via the existing
/// federation evidence path (`Delivery::Durable`).
///
/// Receivers aggregate per `(holder_key_id, sha256)` and apply the
/// downweight policy in their own
/// [`crate::transport::reticulum::PeerResolver`]. The destination of
/// the withdrawal envelope is the **holder itself** — the peer who
/// advertised the `holds_bytes` attestation we are withdrawing against
/// (so the holder sees its own observability). Future federation
/// collectors that aggregate withdrawals can subscribe via the
/// `Delivery::Mandatory` retransmission path; v0.12.0 ships the
/// point-to-point shape only.
async fn emit_withdraws(
    holder_key_id: &str,
    sha256: [u8; 32],
    reason: crate::messages::WithdrawalReason,
    signer: &Arc<LocalSigner>,
    queue: &Arc<dyn OutboundHandle>,
) -> Result<(), EdgeError> {
    use crate::messages::Withdraws;

    let withdraws = Withdraws {
        holder_key_id: holder_key_id.to_string(),
        sha256,
        withdrawal_reason: reason,
        observed_at: Utc::now(),
    };

    // Wrap in a typed envelope addressed to the holder. The envelope's
    // hybrid signature IS the proof-of-authority — no body-internal
    // signature (same shape as GoalRetirement, CIRISEdge#41).
    let envelope_bytes = {
        let mut env = build_envelope(
            MessageType::Withdraws,
            &signer.key_id,
            holder_key_id,
            &withdraws,
            None,
        )?;
        sign_envelope(signer, &mut env).await?;
        serde_json::to_vec(&env)
            .map_err(|e| EdgeError::Config(format!("withdraws envelope serialize: {e}")))?
    };
    let env: EdgeEnvelope = serde_json::from_slice(&envelope_bytes)
        .map_err(|e| EdgeError::Config(format!("re-parse withdraws envelope: {e}")))?;
    let body_sha256_w = envelope_body_sha256(&env);
    let body_size_bytes = i32::try_from(envelope_bytes.len()).unwrap_or(i32::MAX);

    // Match Withdraws::DELIVERY (same shape as DeliveryAttestation —
    // fire-and-forget Durable, 24h TTL, 20 attempts).
    let (max_attempts, ttl_seconds) = match crate::messages::Withdraws::DELIVERY {
        Delivery::Durable {
            max_attempts,
            ttl_seconds,
            ..
        } => (
            i32::try_from(max_attempts).unwrap_or(i32::MAX),
            i64::try_from(ttl_seconds).unwrap_or(i64::MAX),
        ),
        _ => (20, 24 * 60 * 60),
    };

    queue
        .enqueue_outbound(
            &signer.key_id,
            holder_key_id,
            &message_type_str(&MessageType::Withdraws),
            "1.0.0",
            &envelope_bytes,
            &body_sha256_w,
            body_size_bytes,
            false, // requires_ack: false (Withdraws is fire-and-forget)
            None,
            max_attempts,
            ttl_seconds,
            Utc::now(),
        )
        .await
        .map_err(|e| EdgeError::Persist(format!("enqueue_outbound (withdraws): {e}")))?;

    Ok(())
}

/// CIRISEdge#19 — wire-layer accord-multi-sig gate. Returns `Ok(())`
/// iff ≥ [`ACCORD_THRESHOLD_M_OF_N`].0 valid signatures from DISTINCT
/// accord-holder keys cover the announcement's canonical bytes;
/// returns the appropriate [`RefusalReason`] otherwise.
///
/// # Algorithm (CIRISEdge#19 issue body §"Ask")
///
/// 1. Query `directory.list_accord_holders()` — persist's `federation_keys`
///    rows where `identity_type = 'accord_holder'`.
/// 2. If the accord-holder set is empty → `NoAccordHoldersConfigured`
///    (substrate isn't bootstrapped for constitutional traffic;
///    refusal IS correct even for a perfectly-signed envelope, because
///    the trust chain has no root).
/// 3. Derive the canonical bytes the accord-holders sign via
///    [`FederationAnnouncement::canonical_bytes_for_accord_signatures`].
/// 4. For each `AccordSignature` in the announcement, verify it
///    against the matching accord-holder pubkey. Track DISTINCT
///    holders whose signatures verify (duplicate signatures from the
///    same holder count once — CIRISEdge#19 distinct-holders
///    invariant).
/// 5. If at least `ACCORD_THRESHOLD_M_OF_N.0` distinct holders
///    verified → `Ok(())`. Otherwise:
///    - If at least one signature *did* verify (but threshold not
///      met) → `InsufficientAccordSignatures { found, required }`.
///    - If ZERO signatures verified AND there was at least one
///      signature attempt → `InvalidAccordSignature`.
///    - If ZERO signatures were provided at all → that collapses to
///      `InsufficientAccordSignatures { found: 0, required }` —
///      same forensic conclusion (the envelope didn't satisfy the
///      threshold).
async fn verify_accord_carrier(
    ann: &FederationAnnouncement,
    directory: &Arc<dyn VerifyDirectory>,
) -> Result<(), RefusalReason> {
    let required = ACCORD_THRESHOLD_M_OF_N.0;
    let holders: Vec<AccordHolderKey> = match directory.list_accord_holders().await {
        Ok(v) => v,
        Err(e) => {
            // Substrate fault: persist call failed. Treat as
            // "not configured" — refusing is the conservative
            // safe-default for the substrate-unavailable case (the
            // alternative would be to silently propagate, defeating
            // the wire-layer gate's defense-in-depth purpose).
            tracing::warn!(
                error = %e,
                "list_accord_holders failed; treating as NoAccordHoldersConfigured",
            );
            return Err(RefusalReason::NoAccordHoldersConfigured);
        }
    };
    if holders.is_empty() {
        return Err(RefusalReason::NoAccordHoldersConfigured);
    }

    let canonical = ann
        .canonical_bytes_for_accord_signatures()
        .map_err(|_e| RefusalReason::InvalidAccordSignature)?;

    // Build a key_id → pubkey map for O(1) per-sig lookup. The holder
    // set is small (3 by FSD spec), so a Vec scan is fine; map is
    // future-proofing if 3-of-5 ships.
    let by_id: std::collections::HashMap<&str, &[u8; 32]> = holders
        .iter()
        .map(|h| (h.key_id.as_str(), &h.pubkey_ed25519))
        .collect();

    let mut verified_holders = std::collections::HashSet::<String>::new();
    let mut any_attempted = false;
    for sig in &ann.accord_signatures {
        any_attempted = true;
        // The presented key_id MUST appear in the accord-holder set;
        // a sig from a non-accord-holder counts as zero verifications
        // toward the threshold. We don't even attempt verification
        // against a non-accord-holder pubkey.
        let Some(pubkey_bytes) = by_id.get(sig.key_id.as_str()) else {
            continue;
        };
        if verify_ed25519_signature(pubkey_bytes, &canonical, &sig.signature_ed25519_base64) {
            verified_holders.insert(sig.key_id.clone());
        }
    }

    let found = u32::try_from(verified_holders.len()).unwrap_or(u32::MAX);
    if found >= required {
        return Ok(());
    }

    // Forensic discrimination: at least one signature verified but
    // threshold not met → `InsufficientAccordSignatures`. ZERO
    // verified AND at least one signature was attempted →
    // `InvalidAccordSignature` (every signature was either against a
    // non-accord-holder key or had bad bytes). ZERO signatures at all
    // → `InsufficientAccordSignatures { found: 0, required }` —
    // same threshold-not-met forensic story.
    if found == 0 && any_attempted {
        Err(RefusalReason::InvalidAccordSignature)
    } else {
        Err(RefusalReason::InsufficientAccordSignatures { found, required })
    }
}

/// Verify one Ed25519 signature against a 32-byte pubkey and the
/// canonical bytes. Returns `false` on base64-decode failure, wrong
/// signature length, or signature-verification failure (any error is
/// "this signature does not pass"; the gate's job is to count
/// confirming verifications, not surface error taxonomy).
fn verify_ed25519_signature(pubkey: &[u8; 32], canonical: &[u8], sig_b64: &str) -> bool {
    use ciris_crypto::ClassicalVerifier as _;

    let Ok(sig_bytes) = base64::engine::general_purpose::STANDARD.decode(sig_b64.as_bytes()) else {
        return false;
    };
    if sig_bytes.len() != 64 {
        return false;
    }
    // Use ciris-crypto's verifier — the same primitive persist's
    // verify_hybrid_via_directory composes (single-source-of-truth
    // for Ed25519 verify across the federation).
    matches!(
        ciris_crypto::Ed25519Verifier::new().verify(pubkey, canonical, &sig_bytes),
        Ok(true)
    )
}

/// CIRISEdge#19 — build, sign, and enqueue a [`crate::DeliveryRefusalAttestation`]
/// for a `priority == AccordCarrier` `FederationAnnouncement` envelope
/// that failed the wire-layer multi-sig threshold check. Mirrors
/// [`emit_delivery_attestation`] exactly (same Ed25519 + optional
/// PQC bound-signature discipline, same UUID derivation, same
/// Durable fire-and-forget queue contract); the refusal IS the
/// observable that lets a steward end distinguish adversarial
/// suppression of legitimate accords from suppression of forged ones.
async fn emit_delivery_refusal_attestation(
    envelope: &EdgeEnvelope,
    body_sha256: [u8; 32],
    transport: crate::transport::TransportId,
    signer: &Arc<LocalSigner>,
    queue: &Arc<dyn OutboundHandle>,
    refusal_reason: RefusalReason,
) -> Result<(), EdgeError> {
    use crate::messages::{
        encode_canonical_hash_base64, encode_signature_base64, DeliveryRefusalAttestation,
        TransportMedium,
    };

    let announcement_id = derive_announcement_id_from_body_hash(&body_sha256);
    let peer_pubkey_bytes = signer
        .classical
        .public_key()
        .await
        .map_err(|e| EdgeError::Persist(format!("local pubkey: {e}")))?;
    let peer_pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(&peer_pubkey_bytes);
    let canonical_hash_b64 = encode_canonical_hash_base64(&body_sha256);

    let refused_at = chrono::Utc::now();
    let mut refusal = DeliveryRefusalAttestation {
        announcement_id,
        announcement_canonical_hash_base64: canonical_hash_b64,
        peer_key_id: signer.key_id.clone(),
        peer_pubkey_ed25519_base64: peer_pubkey_b64,
        refused_at,
        transport_id: TransportMedium::from(transport),
        refusal_reason,
        signature_classical_base64: String::new(),
        signature_pqc_base64: None,
    };

    let canonical = refusal.canonical_bytes().map_err(|e| {
        EdgeError::Config(format!("delivery_refusal_attestation canonical_bytes: {e}"))
    })?;

    let ed25519_sig = signer
        .classical
        .sign(&canonical)
        .await
        .map_err(|e| EdgeError::Persist(format!("refusal classical sign: {e}")))?;
    refusal.signature_classical_base64 = encode_signature_base64(&ed25519_sig);

    if let Some(pqc) = signer.pqc.as_ref() {
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed25519_sig);
        let pqc_sig = pqc
            .sign(&bound)
            .await
            .map_err(|e| EdgeError::Persist(format!("refusal pqc sign: {e}")))?;
        refusal.signature_pqc_base64 = Some(encode_signature_base64(&pqc_sig));
    }

    let envelope_bytes = {
        let mut env = build_envelope(
            MessageType::DeliveryRefusalAttestation,
            &signer.key_id,
            &envelope.signing_key_id,
            &refusal,
            None,
        )?;
        sign_envelope(signer, &mut env).await?;
        serde_json::to_vec(&env)
            .map_err(|e| EdgeError::Config(format!("refusal envelope serialize: {e}")))?
    };
    let env: EdgeEnvelope = serde_json::from_slice(&envelope_bytes)
        .map_err(|e| EdgeError::Config(format!("re-parse refusal envelope: {e}")))?;
    let body_sha256_refusal = envelope_body_sha256(&env);
    let body_size_bytes = i32::try_from(envelope_bytes.len()).unwrap_or(i32::MAX);

    // Same Durable fire-and-forget shape as DeliveryAttestation.
    let (max_attempts, ttl_seconds) = match crate::DeliveryRefusalAttestation::DELIVERY {
        Delivery::Durable {
            max_attempts,
            ttl_seconds,
            ..
        } => (
            i32::try_from(max_attempts).unwrap_or(i32::MAX),
            i64::try_from(ttl_seconds).unwrap_or(i64::MAX),
        ),
        _ => (20, 24 * 60 * 60),
    };

    queue
        .enqueue_outbound(
            &signer.key_id,
            &envelope.signing_key_id,
            &message_type_str(&MessageType::DeliveryRefusalAttestation),
            "1.0.0",
            &envelope_bytes,
            &body_sha256_refusal,
            body_size_bytes,
            false, // requires_ack: false (refusal IS the observable)
            None,
            max_attempts,
            ttl_seconds,
            Utc::now(),
        )
        .await
        .map_err(|e| EdgeError::Persist(format!("enqueue_outbound (refusal): {e}")))?;

    Ok(())
}
