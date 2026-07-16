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
    Handler, HandlerContext, HandlerError, Message,
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
    AccordHolderKey, HybridPolicy, VerifiedEnvelope, VerifyDirectory, VerifyError, VerifyOutcome,
    VerifyPipeline,
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
/// Behaviour matrix (v0.20.0 RC1 — CEWP L0/L1 tier refinement):
///
/// | Mode     | Listener | Out-queue | Disk budget   | Trust recursion |
/// |----------|----------|-----------|---------------|-----------------|
/// | Client   | no       | 256       | 0             | 0               |
/// | Proxy    | yes      | 4096      | 256 GB (L0)   | 0 (strict)      |
/// | Server   | yes      | 65536     | 1 TB (L1)     | 1 (FoF)         |
///
/// v0.20.0 RC1 (CIRISEdge#51) extends the v0.18.0 listener/queue
/// mapping with the full CEWP L0/L1 tier vocabulary. The
/// `disk_budget_bytes` field is **advisory** at the edge tier (persist
/// or the host enforces capacity-gated admission); the
/// `trust_recursion_depth` is **consulted** at `dispatch_inbound`'s
/// trust short-circuit (it's the `recursion_depth` argument to
/// `TrustScoring::trust_score`, replacing v0.19.6's hardcoded `0`).
/// L2+ tiers are deferred to a post-v1.0 cut.
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

    /// CIRISEdge#51 (v0.20.0 RC1) — default disk budget for the mode
    /// (bytes). Advisory at the edge tier — persist or the host
    /// consults this via [`Edge::disk_budget_bytes`] to enforce
    /// capacity-gated admission. Client = 0 (no storage), Proxy = 256
    /// GB (L0 CEWP tier), Server = 1 TB (L1 CEWP tier). L2+ tiers
    /// deferred to a post-v1.0 cut.
    #[must_use]
    pub fn default_disk_budget_bytes(&self) -> u64 {
        match self {
            Self::Client => 0,
            Self::Proxy => 256 * 1024 * 1024 * 1024, // 256 GB
            Self::Server => 1024 * 1024 * 1024 * 1024, // 1 TB
        }
    }

    /// CIRISEdge#51 (v0.20.0 RC1) — default trust recursion depth for
    /// the mode. Consumed at [`dispatch_inbound`]'s trust short-circuit
    /// as the `recursion_depth` argument to
    /// `TrustScoring::trust_score` (replacing v0.19.6's hardcoded `0`).
    /// Client = 0 (no inbound dispatch), Proxy = 0 (strict — direct
    /// attestations only), Server = 1 (friend-of-friends — walks one
    /// `delegates_to` hop). L2+ tiers deferred to a post-v1.0 cut.
    ///
    /// `match_same_arms` is allowed here because Client and Proxy
    /// share the value (`0`) for distinct semantic reasons — Client
    /// has no inbound dispatch at all (the value is moot), Proxy has
    /// inbound dispatch but pins strict direct trust per the CEWP L0
    /// "tight blast radius" stance. Collapsing the arms would erase
    /// the per-mode documentation site.
    #[must_use]
    #[allow(clippy::match_same_arms)]
    pub fn default_trust_recursion_depth(&self) -> u8 {
        match self {
            Self::Client => 0,
            Self::Proxy => 0,
            Self::Server => 1,
        }
    }

    /// Apply the mode-derived defaults onto `config`. CRITICAL: the
    /// only place the mode → knob mapping lives. Every init path that
    /// accepts an `AgentMode` calls this exactly once before
    /// [`EdgeBuilder::config`] is invoked.
    ///
    /// v0.20.0 RC1 (CIRISEdge#51) — extended from the v0.18.0
    /// listener/queue knobs to cover the full CEWP L0/L1 tier
    /// vocabulary: `disk_budget_bytes` + `trust_recursion_depth`.
    /// Operator overrides on [`init_edge_runtime`] re-set the fields
    /// AFTER `apply_defaults`, so the mode-default is the floor not
    /// the ceiling.
    pub fn apply_defaults(&self, config: &mut EdgeConfig) {
        config.agent_mode = *self;
        config.listener_bound = self.binds_listener();
        config.outbound_queue_max = self.default_outbound_queue_max();
        config.disk_budget_bytes = self.default_disk_budget_bytes();
        config.trust_recursion_depth = self.default_trust_recursion_depth();
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
///
/// `EdgeConfig` carries four independent operator booleans
/// (`probe_pattern_observer_enabled`, `listener_bound`,
/// `trust_short_circuit_enabled`, `l1_cdn_edge_enabled`); each maps
/// directly onto a distinct substrate feature. Bundling them into a
/// sub-struct would obscure the flat surface the cohabitation init
/// path + UniFFI bindings depend on, so the
/// `clippy::struct_excessive_bools` lint is suppressed at the
/// struct level (not at any call site).
#[allow(clippy::struct_excessive_bools)]
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
    /// CIRISEdge#48-B (v0.19.6) — trust-score threshold for the
    /// inbound dispatch short-circuit. Verified envelopes whose
    /// `signing_key_id` scores BELOW this threshold are dropped at
    /// `dispatch_inbound` (after signature verify, before handler
    /// dispatch) and a moderation signal fires on the EventBus.
    ///
    /// Default `0.0` — bootstrap-permissive. Operators raise this as
    /// trust accumulates across their federation; e.g. set to `0.5`
    /// once the corpus stabilizes. Values are clamped to `[0.0, 1.0]`
    /// at the resolver tier (persist's `AdmissionGate` discipline).
    ///
    /// **Bootstrap semantics**: `0.0` is functionally equivalent to
    /// "short-circuit disabled" — the `dispatch_inbound` code path
    /// guards on `> 0.0` to skip the SQL-backed `trust_score` call
    /// entirely. Persist's `AdmissionGate::check` mirrors this
    /// posture (admit at `threshold ≤ 0.0` without dispatching).
    pub trust_threshold: f64,
    /// CIRISEdge#48-B (v0.19.6) — explicit on/off override for the
    /// inbound trust short-circuit. Default `true`; the effective
    /// short-circuit is the AND of (`enabled`, `threshold > 0.0`,
    /// `Arc<dyn TrustScoring>` wired). The boolean exists so tests
    /// (and migration / dev deployments) can disable the check
    /// independently of the threshold value.
    pub trust_short_circuit_enabled: bool,
    /// CIRISEdge#51 (v0.20.0 RC1) — CEWP L0/L1 storage budget for the
    /// edge tier (bytes). **Advisory at edge** — persist or the host
    /// reads this via [`Edge::disk_budget_bytes`] to enforce
    /// capacity-gated admission. Defaults are sourced from
    /// [`AgentMode::default_disk_budget_bytes`]: Client = 0, Proxy =
    /// 256 GB (L0), Server = 1 TB (L1). Operator override on
    /// `init_edge_runtime` (the new `disk_budget_bytes` kwarg) pins a
    /// per-deployment value AFTER `apply_defaults` runs. See
    /// `MISSION.md` §11 (L0/L1 tier table) and `THREAT_MODEL.md` §4.9
    /// (CEWP tier as security boundary).
    pub disk_budget_bytes: u64,
    /// CIRISEdge#51 (v0.20.0 RC1) — CEWP L0/L1 trust-graph recursion
    /// depth for the [`dispatch_inbound`] short-circuit. Threaded
    /// into `TrustScoring::trust_score(key_id, recursion_depth)` as
    /// the second arg (replacing v0.19.6's hardcoded `0`). Defaults
    /// from [`AgentMode::default_trust_recursion_depth`]: Client = 0,
    /// Proxy = 0 (strict direct trust), Server = 1 (friend-of-
    /// friends — one `delegates_to` hop). Operator override on
    /// `init_edge_runtime` (the new `trust_recursion_depth` kwarg)
    /// pins a per-deployment value (e.g. a curated server pinning
    /// depth = 0 even though L1 default is 1). L2+ depths deferred
    /// to a post-v1.0 cut.
    pub trust_recursion_depth: u8,
    /// CIRISEdge#52 (v0.20.1) — L1-as-CDN-edge opt-in per
    /// MEDIA_SHARING.md §2.7. When `true` AND
    /// [`Self::agent_mode`] is `AgentMode::Server` (L1), edge
    /// pre-fetches external multimedia content + re-emits its own
    /// `holds_bytes:sha256:{hash}` attestation so federation peers
    /// can fetch through the operator's CDN tier. Default `false`
    /// (opt-in per the spec); Client and Proxy modes ignore the
    /// flag regardless of its value.
    ///
    /// **Implementation status at v0.20.1**: the dispatch hook fires
    /// [`crate::multimedia::cdn_edge_prefetch_stub`] which logs the
    /// opt-in trigger via `tracing::info!` but does NOT perform the
    /// actual HTTP fetch — the wire shape + dispatch path are locked
    /// here; the full bytes-fetching implementation is a post-v1.0
    /// follow-up. See `docs/THREAT_MODEL.md` AV-49.
    pub l1_cdn_edge_enabled: bool,
    /// CIRISEdge#52 (v0.20.1) — operator's S3-class base URI for
    /// L1-as-CDN-edge re-publication. Required when
    /// [`Self::l1_cdn_edge_enabled`] is `true`; ignored otherwise.
    /// The prefetch stub re-publishes content at
    /// `{l1_cdn_edge_external_uri_base}/{sha256_hex}` and emits a
    /// fresh `holds_bytes` attestation against that URI.
    ///
    /// `None` when L1-CDN-edge is disabled (the default); operators
    /// who flip the boolean MUST also supply this base before
    /// `Edge::build`.
    pub l1_cdn_edge_external_uri_base: Option<String>,
    /// CIRISEdge#108 part 2 (v3.2.0) — operator-driven on/off switch
    /// for the federation-tier delegation authority gate on inbound
    /// dispatch. When `true`, edge walks persist's `delegates_to`
    /// chain (CEG §8.1.12.7 — persist v6.5.0 `Engine::self_at_login`)
    /// from each configured trust root (the
    /// [`CanonicalBootstrapPeer`] set already wired via
    /// `EdgeBuilder::canonical_bootstrap_peers`) and refuses any
    /// envelope whose signer cannot be reached through a non-
    /// retracted, in-scope chain.
    ///
    /// Default `false` — bootstrap-permissive while v3.2.0 stabilizes.
    /// Operators who enable this MUST also configure trust roots
    /// (via `canonical_bootstrap_peers`); enabling the gate with an
    /// empty trust-root set refuses every InlineText envelope.
    ///
    /// **At v3.2.0-pre1 the gate applies to `MessageType::InlineText`
    /// only.** All other MessageType variants bypass the gate
    /// regardless of this flag — narrowing the blast radius while the
    /// design settles. Coverage extends to `FederationAnnouncement`,
    /// `ContributionSubmit`, and the durable variants in v3.2.x
    /// follow-ups.
    pub delegation_authority_gate_enabled: bool,
    /// CIRISEdge#108 part 2 (v3.2.0) — BFS depth bound for the
    /// `build_delegation_graph` walk that backs the authority gate.
    /// Clamped at persist's `MAX_DELEGATION_DEPTH = 16` regardless of
    /// this value. Default `4` — covers user→agent (the `self_at_login`
    /// 1-hop case) plus 3 levels of sub-delegation, which is the
    /// FSD-002 §2.2.1 default transitive depth + 1 hop of headroom.
    pub delegation_graph_max_depth: usize,
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
            // v0.19.6 (CIRISEdge#48-B) — bootstrap-permissive default.
            // Threshold 0.0 ⇒ the short-circuit code path skips the
            // scoring resolver entirely. Operators raise this as
            // trust accumulates across their federation.
            trust_threshold: 0.0,
            // v0.19.6 (CIRISEdge#48-B) — explicit on/off override.
            // Default `true` (effective check still gated on
            // threshold > 0.0 AND an `Arc<dyn TrustScoring>` wired);
            // tests / dev paths flip to false to disable independent
            // of the threshold value.
            trust_short_circuit_enabled: true,
            // v0.20.0 RC1 (CIRISEdge#51) — defaults mirror the Proxy
            // column of `AgentMode::default_*` so an unmodified
            // `EdgeConfig::default()` continues to match the v0.18.0
            // proxy posture (256 GB / depth 0). `apply_defaults`
            // overwrites both per declared mode; operator overrides
            // on init_edge_runtime overwrite again per deployment.
            disk_budget_bytes: 256 * 1024 * 1024 * 1024,
            trust_recursion_depth: 0,
            // v0.20.1 (CIRISEdge#52) — opt-in per MEDIA_SHARING.md
            // §2.7. Disabled by default across every mode; operators
            // flip the boolean on L1 servers that want to act as
            // CDN edges for external multimedia content.
            l1_cdn_edge_enabled: false,
            l1_cdn_edge_external_uri_base: None,
            // v3.2.0-pre1 (CIRISEdge#108 part 2) — opt-in. Default
            // off so adding the field is non-breaking for every
            // existing deployment + test.
            delegation_authority_gate_enabled: false,
            // FSD-002 §2.2.1 default transitive delegation depth = 2,
            // plus 2 hops of headroom for sub-delegation chains a
            // future cut may introduce. Persist clamps at 16.
            delegation_graph_max_depth: 4,
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
    /// CIRISEdge#48-B (v0.19.6) — `dispatch_inbound` dropped a
    /// verified envelope because the sender's trust score fell below
    /// [`EdgeConfig::trust_threshold`]. Wire-string error kind
    /// `trust_short_circuit`. Surfaced through the typed-error
    /// projection on the UniFFI surface and as a moderation signal
    /// (`EventKind::TrustShortCircuited`) on the EventBus.
    #[error(
        "trust short-circuit: sender {signing_key_id} scored {score} \
         below threshold {threshold} (CIRISEdge#48-B)"
    )]
    TrustShortCircuit {
        /// The sender's `federation_keys.key_id`.
        signing_key_id: String,
        /// Observed score returned by the configured
        /// `TrustScoring::trust_score` resolver.
        score: f64,
        /// Operator-configured floor below which the dispatcher drops.
        threshold: f64,
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

/// CC 0.7 opaque-event inbound subscriber registry entry
/// (CIRISEdge#241, v8.0.0 — the generic successor of the ripped
/// inline-text subscriber).
///
/// Each entry pairs a `kind` discriminator with an unbounded sender the
/// inbound dispatcher pushes `(sender_key_id, kind, payload)` tuples
/// onto for every verified [`crate::MessageType::OpaqueEvent`] envelope
/// whose `kind` matches. A consumer-owned drainer (e.g. the
/// [`crate::ffi::pyo3`] GIL drainer) receives from the matching receiver
/// and invokes the user callback. Dropping the sender (via
/// [`Edge::unregister_opaque_subscriber`]) causes the drainer to observe
/// a closed channel and exit cleanly.
///
/// Unbounded by design: dropping events under back-pressure would
/// degrade the fan-out semantic downstream consumers build on.
/// Subscribers that can't keep up must drop their handle — a closed
/// channel removes the entry from the registry on the next dispatch
/// (lazy cleanup, no separate sweep needed).
pub(crate) type OpaqueSubscriber = (u32, mpsc::UnboundedSender<(String, u32, Vec<u8>)>);

/// CC 0.7 opaque-request handler (CIRISEdge#241, v8.0.0). Keyed by
/// `kind`; invoked with `(sender_key_id, payload)` and returns the
/// [`crate::OpaqueResponse`] edge ships back. An unknown `kind` (no
/// registered handler) is answered by edge with a `501` response —
/// never a silent drop (MISSION §6 anti-pattern 7).
pub(crate) type OpaqueRequestHandlerFn =
    Arc<dyn Fn(String, Vec<u8>) -> crate::messages::OpaqueResponse + Send + Sync>;

/// CC 0.7 opaque-request→response correlation map (CIRISEdge#241).
/// Keyed by the request envelope's `body_sha256`; the responder stamps
/// that value into the response envelope's `in_reply_to` so the
/// dispatcher can resolve the pending [`Edge::send_opaque_request`]
/// oneshot. Mirrors the `content_fetch_pending` correlation pattern.
type OpaqueRequestPendingMap =
    std::sync::Mutex<HashMap<[u8; 32], oneshot::Sender<crate::messages::OpaqueResponse>>>;

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

/// CIRISEdge#55 — type alias for the swarm-fetch pending-map shape.
/// Keyed by `(blob_sha256, chunk_sha256)` — the scheduler runs many
/// chunk fetches in parallel across multiple blobs, and chunk-SHA
/// alone can't disambiguate. Lifted to a type to keep
/// `clippy::type_complexity` happy at the dispatcher signature.
type BlobChunkPendingMap =
    std::sync::Mutex<HashMap<([u8; 32], [u8; 32]), oneshot::Sender<ChunkResult>>>;

/// CIRISEdge#55 — result of a single [`Edge::fetch_blob_chunk`] call.
///
/// One-chunk-from-one-peer atomic primitive the swarm scheduler
/// orchestrates. Distinct from [`ContentResult`] because chunk
/// fetching has different semantics:
/// - No External variant (chunks are always inline; external
///   bodies are whole-blob, never chunked).
/// - No in-dispatch SHA verification — the integrity gate is
///   `persist.put_blob_chunk(blob_sha, chunk_sha, bytes)` which
///   verifies + stores atomically per the §10.1.1 trust seam. The
///   scheduler hands bytes from this enum directly to put_blob_chunk;
///   on `ChunkMismatch` from persist the scheduler demotes the peer.
#[derive(Debug, Clone)]
pub enum ChunkResult {
    /// The peer returned a `BlobChunkBody` carrying the chunk bytes.
    /// The scheduler MUST hand these to `put_blob_chunk` for the
    /// SHA verification + store step (see seam doc above).
    Bytes(Vec<u8>),
    /// The peer returned a `BlobChunkMiss` (typed reason). Scheduler
    /// behavior depends on the reason: `NotHeld` → try another
    /// holder; `Withdrawn` / `Revoked` → abort the whole blob fetch;
    /// `PolicyDenied` → demote this peer for the session.
    ChunkMiss { reason: String },
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
    /// CIRISEdge#52 (v0.20.1) — multimedia tier: the peer returned a
    /// `BlobBody::External` pointer (MEDIA_SHARING.md §2.6). Edge
    /// does NOT fetch the bytes; the consumer's client fetches
    /// directly from `external_uri` and verifies against
    /// `external_sha256_hex`. The fetcher's Python surface projects
    /// this as a dict `{"external_uri": ..., "external_sha256_hex": ...}`.
    External {
        /// Publisher's S3-class pointer.
        external_uri: String,
        /// Hex-encoded SHA-256 of the external bytes. The consumer's
        /// client verifies fetched bytes against this hash.
        external_sha256_hex: String,
    },
}

/// CIRISEdge#175 (v6.1.0, FSD §3.2) — the `PublishOutcome` returned
/// from every `Edge::send_*` / `publish_*` PyO3 entry point so the
/// caller observes the chosen scope ("published at scope=X to
/// audience=Y") without silent demotion.
///
/// The outcome carries:
///
/// - `scope` — the [`CohortScope`] the substrate actually wrote
///   the publication at. Echoed back so the operator API at the
///   PyO3 layer can surface it in the `(scope, holder_count,
///   record_id, ...)` tuple consumed by CIRISAgent / CIRISServer.
/// - `holder_count` — number of holders the publication's
///   fragments have been admitted to (or are scheduled to be
///   admitted to). At v6.1.0 this is a best-effort static count
///   from the §2.4 RaptorQ default (`target_holders=30`); a
///   per-publication-actual count flows once the swarm scheduler
///   is wired (CIRISEdge#175 follow-up).
/// - `record_id` — the FSD §2.4 HMAC-SHA3 record_id, as
///   lowercase hex.
/// - `audience` — the caller's stated audience string (the
///   `community_id`, `family_id`, or `"federation"` they targeted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishOutcome {
    /// Scope the publication was written at — the §3.2 default-
    /// flip resolution, or the operator's explicit scope if they
    /// passed one. Never `None`; the §3.2 default NEVER returns
    /// `Public` (federation is opt-in).
    pub scope: CohortScope,
    /// Caller-stated audience. Free-form — opaque to edge.
    pub audience: String,
    /// Number of holders the publication has been (or will be)
    /// admitted to. Best-effort at v6.1.0 — see struct-level docs.
    pub holder_count: u32,
    /// Lowercase-hex FSD §2.4 record_id (32 bytes → 64 hex chars).
    /// `None` if the publication path bypassed the scope-privacy
    /// substrate (pre-v6.0.0 federation-public envelopes).
    pub record_id_hex: Option<String>,
}

impl PublishOutcome {
    /// Construct a scope-echo outcome with no record_id (the
    /// pre-v6.0.0 path) — used by the `send_*` entry points that
    /// haven't been retrofitted onto the §2.4 fountain admission
    /// path yet.
    #[must_use]
    pub fn new(scope: CohortScope, audience: impl Into<String>) -> Self {
        Self {
            scope,
            audience: audience.into(),
            holder_count: 0,
            record_id_hex: None,
        }
    }

    /// Construct with all four fields. Used by the §2.4-wired
    /// publication paths (the v6.1.0 retrofit completion target).
    #[must_use]
    pub fn with_record(
        scope: CohortScope,
        audience: impl Into<String>,
        holder_count: u32,
        record_id_hex: impl Into<String>,
    ) -> Self {
        Self {
            scope,
            audience: audience.into(),
            holder_count,
            record_id_hex: Some(record_id_hex.into()),
        }
    }
}

/// Top-level edge handle. Construct via [`Edge::builder`].
pub struct Edge {
    verify: Arc<VerifyPipeline>,
    queue: Arc<dyn OutboundHandle>,
    signer: Arc<LocalSigner>,
    /// v1.1.1 (CIRISEdge#50 darwin follow-on; mirrors CIRISPersist#137/#138
    /// `select_signer`). When the cohabitation init path supplies a
    /// local seed signer that names the same `key_id` as `signer`, this
    /// holds the in-memory adapter so envelope signing skips the
    /// platform-keyring IPC. `scrub_signer()` resolves to this when
    /// the alias matches; falls back to `signer` otherwise. None for
    /// non-cohabitation builds + sw_file deployments that don't supply
    /// `local_key_path`.
    local_signer: Option<Arc<LocalSigner>>,
    transports: Vec<Arc<dyn Transport>>,
    handlers: Arc<Mutex<HashMap<MessageType, RegisteredHandler>>>,
    /// CC 0.7 opaque-event inbound fan-out registry (CIRISEdge#241,
    /// v8.0.0 — generic successor of the inline-text subscriber). Keyed
    /// by a monotonically-increasing u64 (`opaque_next_id`); each entry
    /// carries its subscribed `kind`. Multiple concurrent subscribers
    /// per `kind` are supported (distinct from the one-handler-per-type
    /// `handlers` map).
    opaque_subscribers: Arc<std::sync::Mutex<HashMap<u64, OpaqueSubscriber>>>,
    /// Subscription id allocator for [`Self::opaque_subscribers`].
    /// `AtomicU64::fetch_add` so the allocator is lock-free.
    opaque_next_id: Arc<AtomicU64>,
    /// CC 0.7 opaque-request handler registry (CIRISEdge#241), keyed by
    /// `kind`. An inbound [`crate::MessageType::OpaqueRequest`] whose
    /// `kind` is absent here is answered with a `501` response.
    opaque_handlers: Arc<std::sync::Mutex<HashMap<u32, OpaqueRequestHandlerFn>>>,
    /// CC 0.7 opaque request→response correlation map (CIRISEdge#241).
    /// Keyed by the request envelope `body_sha256`.
    opaque_request_pending: Arc<OpaqueRequestPendingMap>,
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
    /// CIRISEdge#55 v2.5.0 — chunked-blob swarm fetch correlation map.
    // Type-alias on the line above intentionally not lifted to a `type` —
    // the existing `content_fetch_pending` field declares its type inline
    // verbatim, and the swarm field mirrors that shape for code-review
    // consistency. Clippy's "very complex type" is suppressed below at
    // the field, not at the struct, to scope the allow narrowly.
    /// Keyed by `(blob_sha256, chunk_sha256)` because the scheduler
    /// runs many chunk fetches in parallel across multiple blobs;
    /// chunk-SHA alone can't disambiguate (two blobs could in principle
    /// share a chunk, and the scheduler's per-blob state needs the
    /// blob-SHA at the routing layer anyway).
    ///
    /// Same lifecycle discipline as `content_fetch_pending`: the
    /// receiver-side `Edge::fetch_blob_chunk` drops the receiver on
    /// timeout, closing the oneshot; the dispatcher prunes lazily.
    blob_chunk_fetch_pending: Arc<BlobChunkPendingMap>,
    /// CIRISEdge#55 v3.4.0-pre1 — server-side hook for inbound
    /// `BlobChunkFetch` envelopes. When `Some`, `dispatch_inbound`
    /// consults this trait object to answer chunk-fetch requests with
    /// either `BlobChunkBody` (we hold the chunk) or `BlobChunkMiss`
    /// (we don't). When `None`, edge silently drops inbound
    /// `BlobChunkFetch` envelopes — same posture as edge#21 phase 1
    /// `ContentFetch`, which also has no in-core responder; consumer
    /// crates (lens-core / agent) wrap their persist `BlobStorage`
    /// handle in a `BlobChunkSource` impl.
    blob_chunk_source: Option<Arc<dyn crate::blob_swarm::BlobChunkSource>>,
    /// v3.5.1 (CIRISEdge#119) — opt-in replication routing hook.
    /// Headless composition roots (CIRISServer) call
    /// [`Edge::install_replication_routing`] to register the
    /// `ReplicationRuntime`'s registry; `Edge::run` then checks every
    /// inbound frame against [`ReplicationRegistry::route_inbound_bytes`]
    /// BEFORE the normal handler dispatch path. Replication frames
    /// (CRPL magic prefix) get delivered to the matching coordinator;
    /// everything else falls through.
    ///
    /// `OnceLock` because the lifecycle is `install once before
    /// Edge::run` — the lookup is a cheap atomic load on every
    /// inbound frame. Wrapped in `Arc` so the inbound dispatch loop
    /// can hold a clone without contention.
    ///
    /// `None` (uninitialized) preserves the v3.5.0 behavior exactly:
    /// no replication routing, every frame goes to `dispatch_inbound`.
    replication_registry:
        Arc<std::sync::OnceLock<Arc<crate::replication::registry::ReplicationRegistry>>>,
    /// v5.2.0 (CIRISEdge#143) — opt-in fountain swarm orchestration
    /// runtime. Set-once via `OnceLock`; the [`Edge::install_swarm_runtime`]
    /// post-build setter holds the runtime for the lifetime of
    /// `Edge`. When set, the operator's dispatch path may call
    /// [`crate::swarm::FountainSwarmRuntime::register_observed_claim`]
    /// on verified inbound holding-claim bodies. When `None`, no
    /// swarm orchestration runs — the substrate primitives stay
    /// reachable for tests but no live publisher / converger fires.
    ///
    /// `OnceLock<Arc<_>>` because the lifecycle is `install once
    /// before run`; cheap atomic load from the inbound side.
    swarm_runtime: Arc<std::sync::OnceLock<Arc<crate::swarm::FountainSwarmRuntime>>>,
    /// v5.2.0 (CIRISEdge#143) — opt-in consent-decay scheduler
    /// shutdown handle. Same lifecycle as [`Self::swarm_runtime`];
    /// when set, [`Edge::shutdown_swarm_runtime`] also signals the
    /// decay scheduler to stop. `None` keeps the v5.1.0 behavior
    /// exactly (the operator drives the scheduler manually).
    #[cfg(feature = "holonomic-consent-decay")]
    consent_decay_shutdown: Arc<std::sync::OnceLock<tokio::sync::watch::Sender<()>>>,
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
    /// CIRISEdge#48-B (v0.19.6) — optional trust-scoring backend for
    /// the `dispatch_inbound` short-circuit. When set AND
    /// [`EdgeConfig::trust_short_circuit_enabled`] is `true` AND
    /// [`EdgeConfig::trust_threshold`] is positive, the inbound
    /// dispatcher drops verified envelopes whose
    /// `signing_key_id` scores below the threshold (per persist's
    /// `TrustScoring::trust_score` resolution). When `None`, the
    /// short-circuit is structurally disabled — same posture as
    /// `trust_threshold = 0.0` (bootstrap-permissive).
    ///
    /// **Persist dependency** (v3.4.0+ / CIRISPersist#123): persist
    /// exposes `Arc<dyn TrustScoring>` via `AdmissionGate` (set on the
    /// engine through `Engine::set_admission_gate`). The cohabitation
    /// init path can derive this from the engine's installed gate or
    /// wire its own scorer; tests pass `MemoryTrustScoring` for
    /// deterministic fixtures.
    pub(crate) trust_scoring: Option<Arc<dyn ciris_persist::federation::TrustScoring>>,
    /// CIRISEdge#208 — test/conformance override for
    /// [`EdgeConfig::trust_threshold`]. When `Some(v)` ,
    /// [`Self::dispatch_inbound_for_test`] passes `v` to `dispatch_inbound`
    /// instead of `self.config.trust_threshold` AND forces
    /// `trust_short_circuit_enabled = true` so the override actually
    /// gates a single envelope. Production paths (the `Edge::run`
    /// listener loop) ignore this field. The PyO3 surface
    /// `PyEdge::set_trust_threshold` mutates this slot.
    trust_threshold_override: Arc<std::sync::RwLock<Option<f64>>>,
    /// CIRISEdge#208 — test/conformance override for
    /// [`Self::trust_scoring`]. When `Some(scoring)`,
    /// [`Self::dispatch_inbound_for_test`] passes `scoring` to
    /// `dispatch_inbound` instead of the builder-wired `self.trust_scoring`.
    /// Production paths ignore this field. The PyO3 surface
    /// `PyEdge::install_trust_resolver` mutates this slot with a
    /// `Python-callback-backed` impl.
    trust_scoring_override:
        Arc<std::sync::RwLock<Option<Arc<dyn ciris_persist::federation::TrustScoring>>>>,
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
    /// v1.1.1 — see `Edge::local_signer`.
    local_signer: Option<Arc<LocalSigner>>,
    transports: Vec<Arc<dyn Transport>>,
    peer_directory: Option<Arc<dyn PeerDirectory>>,
    steward_directory: Option<Arc<dyn StewardDirectory>>,
    /// CIRISEdge#55 v3.4.0-pre1 — see [`Edge::blob_chunk_source`].
    blob_chunk_source: Option<Arc<dyn crate::blob_swarm::BlobChunkSource>>,
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
    /// CIRISEdge#48-B (v0.19.6) — optional trust-scoring backend (see
    /// [`Edge::trust_scoring`]). The cohabitation init path can derive
    /// this from persist's `Engine::admission_gate_for_backend()`
    /// when an admission gate is installed; tests pass
    /// `MemoryTrustScoring` directly.
    trust_scoring: Option<Arc<dyn ciris_persist::federation::TrustScoring>>,
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
            local_signer: None,
            transports: Vec::new(),
            peer_directory: None,
            steward_directory: None,
            blob_chunk_source: None,
            subscription_filter: None,
            events: None,
            #[cfg(feature = "_reticulum-module")]
            reticulum_transport: None,
            reachability: None,
            derived_schema: None,
            canonical_bootstrap_peers: Vec::new(),
            trust_scoring: None,
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

    /// CIRISEdge#48-A → #48-A-completion (v0.19.6) — look up a peer's
    /// declared cohort scope from persist's `federation_peer_metadata`
    /// directory.
    ///
    /// Sources the scope from
    /// `FederationDirectory::peer_metadata_for(key_id).policy_blob.cohort_scope`
    /// (persist v3.4.1 / CIRISPersist#127). Returns `None` when:
    ///
    ///   - no federation_directory is wired on this [`Edge`] (tests
    ///     that didn't pass one — the caller interprets `None` as
    ///     [`CohortScope::Public`], the pre-v0.19.1 implicit default);
    ///   - the directory has no peer row for `key_id`;
    ///   - the row's `policy_blob` is absent or doesn't carry a
    ///     `cohort_scope` field;
    ///   - the `cohort_scope` JSON value fails to deserialize as a
    ///     [`CohortScope`] (the lenient posture — a malformed blob
    ///     defaults to Public + warns; the moderation signal lets
    ///     lens-core observe the misconfigured row).
    ///
    /// The expected JSON shape for `policy_blob.cohort_scope` matches
    /// the wire form (`#[serde(tag = "kind")]`):
    /// `{"kind": "public" | "self" | "family", ...}` or
    /// `{"kind": "cohort", "cohort_id": "..."}`. See
    /// [`crate::cohort_scope::CohortScope`] for the full enum.
    ///
    /// **Migration from v0.19.1**: callers previously seeded scope via
    /// `Edge::declare_peer_cohort_scope(key_id, scope)` (removed at
    /// v0.19.6); the persist-backed path uses
    /// `engine.update_peer_policy(key_id, PeerPolicyBlob::new(json!({"cohort_scope": scope})))`
    /// (persist v3.1.0+ / CIRISPersist#117 mutation surface).
    pub async fn peer_cohort_scope_from_persist(&self, key_id: &str) -> Option<CohortScope> {
        let directory = self.federation_directory.as_ref()?;
        let metadata = match directory.peer_metadata_for(key_id).await {
            Ok(opt) => opt?,
            Err(e) => {
                tracing::warn!(
                    event = "edge.cohort_scope.persist_lookup_failed",
                    key_id,
                    error = %e,
                    "peer_metadata_for failed; treating peer as Public",
                );
                return None;
            }
        };
        let policy_blob = metadata.policy_blob.as_ref()?;
        let cohort_value = policy_blob.as_value().get("cohort_scope")?;
        match serde_json::from_value::<CohortScope>(cohort_value.clone()) {
            Ok(scope) => Some(scope),
            Err(e) => {
                tracing::warn!(
                    event = "edge.cohort_scope.malformed_policy_blob",
                    key_id,
                    error = %e,
                    cohort_value = %cohort_value,
                    "policy_blob.cohort_scope failed to deserialize; treating peer as Public",
                );
                None
            }
        }
    }

    /// v2.4.0 (CIRISEdge#95) — resolve a remote peer's hybrid KEM
    /// pubkeys (x25519 + ML-KEM-768) from persist's federation
    /// directory for `FederationSession::initiate` consumers.
    ///
    /// `occurrence_key_id` is the per-device occurrence key (NOT the
    /// identity key) — content KEM keys live at the occurrence level
    /// per CEG §5.6.8.4.
    ///
    /// Returns:
    /// - `Ok(Some(PeerKexPubkeys))` when persist has both halves
    ///   registered for the occurrence
    /// - `Ok(None)` when the occurrence is unknown, expired
    ///   (`valid_until` in the past), or has no `encryption_pubkeys`
    ///   block
    /// - `Err(EdgeError::Persist)` on persist-backend error
    ///
    /// Delegates to
    /// [`FederationDirectory::resolve_encryption_keys`](ciris_persist::federation::FederationDirectory::resolve_encryption_keys)
    /// (persist v4.13.0+, `EncryptionPubkeys { x25519_base64,
    /// ml_kem_768_base64 }`) and base64-decodes the two halves into
    /// the wire-byte shape `PeerKexPubkeys` carries. A decode failure
    /// or wrong byte count surfaces as `Err(EdgeError::Persist)`
    /// rather than silent `Ok(None)` — a malformed row in persist
    /// must be operator-visible.
    pub async fn resolve_peer_kex_pubkeys(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Option<crate::transport::federation_session::PeerKexPubkeys>, EdgeError> {
        use base64::Engine as _;
        let Some(directory) = self.federation_directory.as_ref() else {
            return Ok(None);
        };
        let encryption_pubkeys = directory
            .resolve_encryption_keys(occurrence_key_id)
            .await
            .map_err(|e| EdgeError::Persist(format!("resolve_encryption_keys: {e}")))?;
        let Some(pk) = encryption_pubkeys else {
            return Ok(None);
        };
        let b64 = base64::engine::general_purpose::STANDARD;
        let x25519_raw = b64.decode(&pk.x25519_base64).map_err(|e| {
            EdgeError::Persist(format!(
                "resolve_peer_kex_pubkeys({occurrence_key_id}): x25519 base64 decode: {e}"
            ))
        })?;
        let x25519_pub: [u8; 32] = x25519_raw.as_slice().try_into().map_err(|_| {
            EdgeError::Persist(format!(
                "resolve_peer_kex_pubkeys({occurrence_key_id}): x25519 wrong length \
                 ({}; expected 32)",
                x25519_raw.len()
            ))
        })?;
        let mlkem768_pub = b64.decode(&pk.ml_kem_768_base64).map_err(|e| {
            EdgeError::Persist(format!(
                "resolve_peer_kex_pubkeys({occurrence_key_id}): ml-kem-768 base64 decode: {e}"
            ))
        })?;
        Ok(Some(crate::transport::federation_session::PeerKexPubkeys {
            x25519_pub,
            mlkem768_pub: Some(mlkem768_pub),
        }))
    }

    /// v3.1.0 (CIRISEdge#108 / CIRISPersist#183, CEG §5.6.8.8.1) —
    /// list every reachable transport address registered for an
    /// occurrence ("how do I reach this occurrence?"). Delegates to
    /// persist's `FederationDirectory::list_transport_destinations_for`
    /// (V078 `transport_destinations` table).
    ///
    /// Returns the full set unfiltered — liveness filtering (on
    /// `last_seen_at` age) is the caller's responsibility per
    /// persist's documented contract; reachability is mutable +
    /// disposable. A typical caller filters by `transport_kind ==
    /// "reticulum"` for RNS dialing, and discards rows whose
    /// `last_seen_at` is older than some operator-tier threshold.
    ///
    /// Returns:
    /// - `Ok(Vec<_>)` — zero or more rows; empty when the
    ///   occurrence has no registered addresses (not an error)
    /// - `Ok(Vec::new())` — Edge has no federation_directory wired
    ///   (test constructors); a graceful no-op so call sites don't
    ///   need to introspect
    /// - `Err(EdgeError::Persist)` on persist-backend error
    pub async fn list_transport_destinations_for(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Vec<ciris_persist::federation::self_at_login::TransportDestination>, EdgeError>
    {
        let Some(directory) = self.federation_directory.as_ref() else {
            return Ok(Vec::new());
        };
        directory
            .list_transport_destinations_for(occurrence_key_id)
            .await
            .map_err(|e| EdgeError::Persist(format!("list_transport_destinations_for: {e}")))
    }

    /// CIRISEdge#48-A (v0.19.1) accessor — current enforcement
    /// posture.
    #[must_use]
    pub fn cohort_scope_enforcement(&self) -> CohortScopeEnforcement {
        self.config.cohort_scope_enforcement
    }

    /// CIRISEdge#48-B (v0.19.6) — accessor for the configured
    /// trust-scoring backend. Used by tests + the v0.20.0 RC1 metrics
    /// projection. Cheap `Arc` clone; `None` when no scorer was wired
    /// (the short-circuit is structurally disabled).
    #[must_use]
    pub fn trust_scoring(&self) -> Option<Arc<dyn ciris_persist::federation::TrustScoring>> {
        self.trust_scoring.clone()
    }

    /// CIRISEdge#51 (v0.20.0 RC1) — CEWP L0/L1 advisory disk budget
    /// (bytes) sourced from [`EdgeConfig::disk_budget_bytes`]. Edge
    /// does not enforce this — persist or the host consults the
    /// accessor to enforce capacity-gated admission.
    #[must_use]
    pub fn disk_budget_bytes(&self) -> u64 {
        self.config.disk_budget_bytes
    }

    /// CIRISEdge#51 (v0.20.0 RC1) — CEWP L0/L1 trust-graph recursion
    /// depth sourced from [`EdgeConfig::trust_recursion_depth`].
    /// Threaded into `dispatch_inbound`'s `TrustScoring::trust_score`
    /// call; exposed here so hosts can mirror the same depth on
    /// out-of-band trust queries.
    #[must_use]
    pub fn trust_recursion_depth(&self) -> u8 {
        self.config.trust_recursion_depth
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

    /// v3.5.1 (CIRISEdge#119) — install the replication runtime's
    /// registry so [`Self::run`]'s inbound dispatch loop routes CRPL
    /// (replication-protocol) frames to
    /// [`ReplicationRegistry::route_inbound_bytes`](crate::replication::registry::ReplicationRegistry::route_inbound_bytes)
    /// BEFORE the normal handler dispatch path.
    ///
    /// This is the opt-in seam the
    /// [`ReplicationRuntime`](crate::replication::runtime::ReplicationRuntime)
    /// module docs name as the v1.7 follow-up — unblocks headless
    /// composition roots (CIRISServer) where the application doesn't
    /// own the transport.listen loop and therefore can't manually
    /// call `route_inbound_bytes` on inbound bytes.
    ///
    /// # Lifecycle
    ///
    /// Set-once via `OnceLock`. Call BEFORE [`Self::run`]; calls after
    /// `run` has started take effect on the NEXT inbound frame. A
    /// second install attempt is silently ignored (the first wins;
    /// re-routing mid-run would race the dispatch loop's atomic load).
    ///
    /// # Source attribution
    ///
    /// Replication routing fires ONLY when the inbound frame carries
    /// a transport-confirmed `source_key_id`
    /// ([`InboundFrame::source_key_id`](crate::transport::InboundFrame::source_key_id)
    /// is `Some`). Per-transport attribution (Reticulum link-rooted
    /// peer lookup, HTTPS mTLS surfacing) lands as separate v3.5.x
    /// cuts; until then, replication routing is no-op for any
    /// transport that hasn't been wired for peer attribution.
    ///
    /// # See also
    ///
    /// - [`Self::run`] consumes the registered registry.
    /// - [`ReplicationRuntime::registry`](crate::replication::runtime::ReplicationRuntime::registry)
    ///   produces the `Arc<ReplicationRegistry>` to pass here.
    pub fn install_replication_routing(
        &self,
        runtime: &crate::replication::runtime::ReplicationRuntime,
    ) {
        // Idempotent — first call wins. A second call returns Err but
        // we ignore it: the OnceLock semantics + the lifecycle
        // (install-before-run) make this a no-op race-free guarantee.
        let _ = self.replication_registry.set(runtime.registry());
    }

    /// v5.2.0 (CIRISEdge#143) — register a
    /// [`crate::swarm::FountainSwarmRuntime`] with `Edge`. Set-once;
    /// the runtime is held for the lifetime of `Edge`. After
    /// installation:
    ///
    /// - [`Self::swarm_runtime_handle`] returns the registered
    ///   runtime (None until install).
    /// - The operator's inbound dispatch path routes verified
    ///   [`MessageType::FountainHoldingClaim`] envelopes into
    ///   [`crate::swarm::FountainSwarmRuntime::register_observed_claim`]
    ///   (CIRISEdge#184 v6.3.0 — the v5.2.0 deferral closed here).
    ///
    /// Idempotent: a second call is silently ignored (first wins).
    pub fn install_swarm_runtime(&self, runtime: Arc<crate::swarm::FountainSwarmRuntime>) {
        let _ = self.swarm_runtime.set(runtime);
    }

    /// v5.2.0 — return the installed
    /// [`crate::swarm::FountainSwarmRuntime`], if any. `None` when
    /// [`Self::install_swarm_runtime`] has not been called yet.
    pub fn swarm_runtime_handle(&self) -> Option<Arc<crate::swarm::FountainSwarmRuntime>> {
        self.swarm_runtime.get().cloned()
    }

    /// v5.2.0 (CIRISEdge#143) — register a consent-decay scheduler
    /// shutdown handle. The operator spawns
    /// [`crate::holonomic::consent_decay::ConsentDecayScheduler::run`]
    /// against a `tokio::sync::watch::channel(())` receiver and hands
    /// the sender to this method; [`Self::shutdown_consent_decay`]
    /// then flips the channel on `Edge` teardown.
    ///
    /// Gated on the `holonomic-consent-decay` feature.
    #[cfg(feature = "holonomic-consent-decay")]
    pub fn install_consent_decay_shutdown(&self, shutdown_tx: tokio::sync::watch::Sender<()>) {
        let _ = self.consent_decay_shutdown.set(shutdown_tx);
    }

    /// v5.2.0 — flip the registered consent-decay shutdown channel.
    /// Idempotent; no-op when nothing was registered.
    #[cfg(feature = "holonomic-consent-decay")]
    pub fn shutdown_consent_decay(&self) {
        if let Some(tx) = self.consent_decay_shutdown.get() {
            let _ = tx.send(());
        }
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
        self.enforce_point_to_point_scope(cohort_scope.as_ref(), destination_key_id)
            .await?;

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
        // as a nested span; use `tracing::Instrument` (not
        // `.entered()`) so the span is `Send`-friendly across the
        // await. v0.19.4 — clippy 1.95 `items_after_statements`
        // ratchet: import via the fully-qualified path instead of a
        // mid-function `use` statement (lint complains about items
        // appearing after statements within a scope).
        let send_span = tracing::debug_span!(
            "transport.send",
            transport_id = %transport.id().0,
            recipient_key_id = %destination_key_id,
            bytes = envelope_size,
        );
        let send_result = tracing::Instrument::instrument(
            transport.send(destination_key_id, &envelope_bytes),
            send_span,
        )
        .await;
        let outcome = match send_result {
            Ok(o) => {
                let attempt_outcome = match &o {
                    // §24 NAT-traversal (#169): a queued send accepted
                    // the bytes for later wake-up fetch — treat as a
                    // successful attempt for reachability accounting.
                    TransportSendOutcome::Delivered | TransportSendOutcome::Queued => {
                        AttemptOutcome::SendSuccess
                    }
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
                if matches!(
                    &o,
                    TransportSendOutcome::Delivered | TransportSendOutcome::Queued
                ) {
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
            // §24 NAT-traversal (#169): a store-and-forward queue is a
            // durable-tier concept; ephemeral request-response cannot
            // observe a wake-up-fetch delivery, so a queued send on the
            // ephemeral path is a config error (callers wanting
            // store-and-forward use the durable path).
            TransportSendOutcome::Queued => Err(EdgeError::Config(
                "store-and-forward queued send is not valid on the ephemeral request-response \
                 path (use send_durable)"
                    .into(),
            )),
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
        self.enforce_point_to_point_scope(cohort_scope.as_ref(), destination_key_id)
            .await?;

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

    /// CC 0.7 (CIRISEdge#241, v8.0.0) — send an opaque request and
    /// await the peer's opaque response. `kind` is an app-owned
    /// discriminator; `payload` is opaque bytes edge never interprets.
    ///
    /// Correlation rides the request envelope's `body_sha256`: the
    /// responder stamps it into the response's `in_reply_to`, and the
    /// inbound dispatcher resolves this call's pending oneshot. Requires
    /// the edge's inbound dispatch loop to be running (so the response
    /// envelope is observed). Times out after `timeout_ms`.
    ///
    /// MISSION §1.3: edge holds no typed struct for the payload; the
    /// APP owns inner canonicalization + any inner signature.
    pub async fn send_opaque_request(
        &self,
        destination_key_id: &str,
        kind: u32,
        payload: Vec<u8>,
        timeout_ms: u64,
    ) -> Result<crate::messages::OpaqueResponse, EdgeError> {
        use crate::messages::OpaqueRequest;
        let msg = OpaqueRequest { kind, payload };
        // Build + sign the request envelope up front so we can key the
        // pending map on its body_sha256 (the correlation token the
        // responder echoes into `in_reply_to`).
        let envelope_bytes = self
            .build_signed_envelope_with_cohort_scope(destination_key_id, &msg, None, None)
            .await?;
        let envelope: EdgeEnvelope = serde_json::from_slice(&envelope_bytes)
            .map_err(|e| EdgeError::Config(format!("re-parse own envelope: {e}")))?;
        let correlation = envelope_body_sha256(&envelope);

        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self
                .opaque_request_pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pending.insert(correlation, tx);
        }

        if self.transports.is_empty() {
            self.opaque_request_pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&correlation);
            return Err(EdgeError::Config("no transport configured".into()));
        }
        let transport = &self.transports[0];
        if let Err(e) = transport.send(destination_key_id, &envelope_bytes).await {
            self.opaque_request_pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&correlation);
            return Err(EdgeError::Transport(e));
        }
        self.metrics.inc_sent(&OpaqueRequest::TYPE);

        match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_recv)) => Err(EdgeError::Config(
                "opaque request correlation channel dropped".into(),
            )),
            Err(_elapsed) => {
                self.opaque_request_pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&correlation);
                Err(EdgeError::Unreachable(
                    "opaque request timed out awaiting response".into(),
                ))
            }
        }
    }

    /// CC 0.7 (CIRISEdge#241, v8.0.0) — publish an opaque event on the
    /// durable (persistent) delivery class. Fire-and-forget; the
    /// returned [`DurableHandle`] observes the edge-owned-queue outcome.
    /// Receivers fan the event out to their per-`kind` subscribers.
    ///
    /// Unscoped (`cohort_scope: None` → `Public`) — the back-compat Rust
    /// default. Use [`Self::send_opaque_event_with_cohort_scope`] to publish
    /// at a holder scope (`self` / `family` / `cohort`) for holder-gated
    /// delivery (CIRISEdge#265 / #274).
    pub async fn send_opaque_event(
        &self,
        destination_key_id: &str,
        kind: u32,
        payload: Vec<u8>,
    ) -> Result<DurableHandle, EdgeError> {
        self.send_opaque_event_with_cohort_scope(destination_key_id, kind, payload, None)
            .await
    }

    /// CIRISEdge#265 / #274 — publish an opaque event tagged with an explicit
    /// [`CohortScope`], so delivery is holder-gated per the edge's
    /// `cohort_scope_enforcement` (FSD §3.2). A peer receives the event only
    /// when it is a genuine holder of the published scope:
    ///
    /// - [`CohortScope::SelfOnly`] — only the publisher's **own nodes** (the
    ///   owner-bound node set; CIRISConstitution#23 / #274 cross-device
    ///   self-replication). A `self`-scoped send to a foreign identity is
    ///   refused under `Strict` (the CC 1.13.3.4 anti-leak default).
    /// - [`CohortScope::Family`] / [`CohortScope::Cohort`] — family / named-
    ///   cohort holders only.
    /// - [`CohortScope::Public`] / `None` — ungated (federation baseline).
    pub async fn send_opaque_event_with_cohort_scope(
        &self,
        destination_key_id: &str,
        kind: u32,
        payload: Vec<u8>,
        cohort_scope: Option<CohortScope>,
    ) -> Result<DurableHandle, EdgeError> {
        let msg = crate::messages::OpaqueEvent { kind, payload };
        self.send_durable_with_cohort_scope(destination_key_id, msg, cohort_scope)
            .await
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

    /// CC 0.7 (CIRISEdge#241, v8.0.0) — register an inbound opaque-event
    /// subscriber for a given `kind`. Every verified
    /// [`crate::MessageType::OpaqueEvent`] envelope whose `kind` matches
    /// is fanned out to every subscriber registered here, as a
    /// `(sender_key_id, kind, payload)` tuple pushed onto the returned
    /// receiver.
    ///
    /// The caller owns the receiver — drop it (or call
    /// [`Self::unregister_opaque_subscriber`] with the returned id) to
    /// stop the fan-out. The dispatcher lazy-prunes entries whose `send`
    /// returns `Err(SendError)` (closed receiver). Generic successor of
    /// the ripped inline-text subscriber surface.
    pub fn register_opaque_subscriber(
        &self,
        kind: u32,
    ) -> (u64, mpsc::UnboundedReceiver<(String, u32, Vec<u8>)>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let id = self.opaque_next_id.fetch_add(1, Ordering::Relaxed);
        let mut subs = self
            .opaque_subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        subs.insert(id, (kind, tx));
        (id, rx)
    }

    /// Remove an opaque-event subscriber by id. Idempotent — returns
    /// `true` if the id was registered, `false` otherwise.
    pub fn unregister_opaque_subscriber(&self, id: u64) -> bool {
        let mut subs = self
            .opaque_subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        subs.remove(&id).is_some()
    }

    /// Snapshot count of live opaque-event subscribers. Diagnostics
    /// helper for lifecycle tests.
    #[must_use]
    pub fn opaque_subscriber_count(&self) -> usize {
        self.opaque_subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// CC 0.7 (CIRISEdge#241, v8.0.0) — register an opaque-request
    /// handler for `kind`. The inbound dispatcher invokes `f(sender_key_id,
    /// payload)` for every verified [`crate::MessageType::OpaqueRequest`]
    /// carrying that `kind`, then ships the returned
    /// [`crate::messages::OpaqueResponse`] back to the sender. A `kind`
    /// with no registered handler is answered with a `501` response —
    /// never a silent drop (MISSION §6 anti-pattern 7). Registering the
    /// same `kind` twice replaces the prior handler.
    pub fn register_opaque_handler<F>(&self, kind: u32, f: F)
    where
        F: Fn(String, Vec<u8>) -> crate::messages::OpaqueResponse + Send + Sync + 'static,
    {
        let mut handlers = self
            .opaque_handlers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        handlers.insert(kind, Arc::new(f));
    }

    /// Remove an opaque-request handler by `kind`. Idempotent.
    pub fn unregister_opaque_handler(&self, kind: u32) -> bool {
        let mut handlers = self
            .opaque_handlers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        handlers.remove(&kind).is_some()
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

    /// CIRISEdge#55 v2.5.0 — fetch a single chunk of a chunked blob
    /// from `peer_key_id`. The atomic primitive the swarm scheduler
    /// orchestrates.
    ///
    /// Sends a [`crate::MessageType::BlobChunkFetch`] envelope to the
    /// peer, awaits a matching [`crate::MessageType::BlobChunkBody`]
    /// (`ChunkResult::Bytes`) or [`crate::MessageType::BlobChunkMiss`]
    /// (`ChunkResult::ChunkMiss`).
    ///
    /// # Integrity gate (CIRISPersist#145 §10.1.1 seam)
    ///
    /// **This method does NOT verify the chunk SHA in-dispatch.** The
    /// caller MUST hand the returned bytes to
    /// `persist.put_blob_chunk(blob_sha, chunk_sha, &bytes)` for the
    /// atomic verify+store step. Persist returns `ChunkMismatch` on
    /// hash failure; the swarm scheduler treats that as dishonest-peer
    /// evidence and demotes per [`crate::blob_swarm::PeerState`]
    /// `record_dishonest_strike`. Skipping the put_blob_chunk step
    /// drops the integrity guarantee.
    ///
    /// # Timeout
    ///
    /// Caller-supplied. Returns
    /// `EdgeError::Config("fetch_blob_chunk timeout")` if no matching
    /// response arrives within `timeout`. The swarm scheduler's
    /// per-request cap pairs with this.
    ///
    /// # Concurrent fetches
    ///
    /// Keyed by `(blob_sha256, chunk_sha256)` — exactly one in-flight
    /// fetch per chunk per peer. Re-issuing while another is pending
    /// replaces the earlier waiter (prior call observes a closed
    /// channel). The scheduler's per-peer in-flight cap prevents this
    /// in normal operation.
    pub async fn fetch_blob_chunk(
        &self,
        peer_key_id: &str,
        blob_sha256: [u8; 32],
        chunk_sha256: [u8; 32],
        timeout: std::time::Duration,
    ) -> Result<ChunkResult, EdgeError> {
        let key = (blob_sha256, chunk_sha256);
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self
                .blob_chunk_fetch_pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pending.insert(key, tx);
        }

        let fetch = crate::messages::BlobChunkFetch {
            blob_sha256,
            chunk_sha256,
            response_hint: None,
        };
        match self.send(peer_key_id, fetch).await {
            Ok(()) => {}
            Err(EdgeError::Config(s))
                if s.contains("ephemeral request-response correlation not wired") =>
            {
                // Same v0.17.0 carve-out as fetch_content — transport
                // accepted the bytes; the correlation rides our
                // pending-map, not the transport's request/response
                // primitive.
            }
            Err(e) => {
                let mut pending = self
                    .blob_chunk_fetch_pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                pending.remove(&key);
                return Err(e);
            }
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Err(EdgeError::Config(
                "fetch_blob_chunk channel closed before response".into(),
            )),
            Err(_) => {
                let mut pending = self
                    .blob_chunk_fetch_pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                pending.remove(&key);
                Err(EdgeError::Config(format!(
                    "fetch_blob_chunk timeout after {timeout:?}"
                )))
            }
        }
    }

    /// CIRISEdge#55 — test-only sibling of
    /// [`Self::complete_pending_fetch_for_test`]: inject a fake
    /// `BlobChunkBody` / `BlobChunkMiss` outcome into the pending-chunk
    /// signal map. Used by the swarm scheduler's integration tests so
    /// the orchestrator can be exercised without a real loopback.
    #[doc(hidden)]
    pub fn complete_pending_chunk_fetch_for_test(
        &self,
        blob_sha256: [u8; 32],
        chunk_sha256: [u8; 32],
        result: ChunkResult,
    ) -> bool {
        let mut pending = self
            .blob_chunk_fetch_pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(tx) = pending.remove(&(blob_sha256, chunk_sha256)) {
            let _ = tx.send(result);
            true
        } else {
            false
        }
    }

    /// CIRISEdge#22 Tier 3 (v0.17.0) — test-only helper to fan out a
    /// VerifiedEnvelopeSnapshot to verified-feed subscribers without
    /// running a real verify pipeline. Mirrors the
    /// `fan_out_opaque_event_for_test` pattern.
    #[doc(hidden)]
    pub fn fan_out_verified_envelope_for_test(&self, snapshot: VerifiedEnvelopeSnapshot) {
        let _ = self.verified_envelope_tx.send(snapshot);
    }

    /// CC 0.7 (CIRISEdge#241) — manually fan out an opaque event to
    /// every subscriber for its `kind`. Public for tests + future
    /// non-dispatcher embedders that want to inject a synthetic inbound
    /// without going through the verify pipeline. The production inbound
    /// path calls the free-function equivalent from [`dispatch_inbound`].
    pub fn fan_out_opaque_event_for_test(&self, sender_key_id: &str, kind: u32, payload: &[u8]) {
        fan_out_opaque_event(&self.opaque_subscribers, sender_key_id, kind, payload);
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
        // CIRISEdge#208 — read overrides BEFORE the await so the
        // RwLock guards stay narrow + don't cross an await point.
        let override_scoring = self
            .trust_scoring_override
            .read()
            .expect("trust_scoring_override poisoned")
            .clone();
        let override_threshold = *self
            .trust_threshold_override
            .read()
            .expect("trust_threshold_override poisoned");
        let trust_scoring_arc = override_scoring.clone();
        let trust_scoring_ref = trust_scoring_arc.as_ref().or(self.trust_scoring.as_ref());
        let trust_threshold = override_threshold.unwrap_or(self.config.trust_threshold);
        // When an override is set, force the short-circuit ON; the
        // conformance harness is opting INTO gating for the duration of
        // its test (the bootstrap-permissive operator default is
        // structurally bypassed).
        let trust_short_circuit_enabled =
            override_threshold.is_some() || self.config.trust_short_circuit_enabled;
        dispatch_inbound(
            frame,
            &self.verify,
            &self.handlers,
            &self.queue,
            &self.signer,
            &self.opaque_subscribers,
            &self.opaque_handlers,
            &self.opaque_request_pending,
            self.transports.first(),
            self.config.max_content_body_bytes,
            &directory,
            Some(&self.reachability),
            self.detector.as_ref(),
            &self.verified_envelope_tx,
            &self.content_fetch_pending,
            &self.blob_chunk_fetch_pending,
            &self.metrics,
            &self.events,
            self.federation_directory.as_ref(),
            self.config.cohort_scope_enforcement,
            trust_scoring_ref,
            trust_threshold,
            trust_short_circuit_enabled,
            self.config.trust_recursion_depth,
            self.config.agent_mode,
            self.config.l1_cdn_edge_enabled,
            self.config.l1_cdn_edge_external_uri_base.clone(),
            self.config.delegation_authority_gate_enabled,
            self.config.delegation_graph_max_depth,
            self.canonical_peers.clone(),
            self.blob_chunk_source.as_ref(),
            self.swarm_runtime.get(),
        )
        .await;
    }

    /// CIRISEdge#208 — install a runtime override for the
    /// `dispatch_inbound` trust threshold. Used by the PyO3 surface
    /// `PyEdge::set_trust_threshold` to drive the conformance harness's
    /// intake-gate test. Setting forces
    /// `trust_short_circuit_enabled = true` at the
    /// [`Self::dispatch_inbound_for_test`] call site so the override
    /// actually gates a single envelope (config defaults are
    /// bootstrap-permissive). `None` clears the override.
    pub fn set_trust_threshold_override(&self, threshold: Option<f64>) {
        *self
            .trust_threshold_override
            .write()
            .expect("trust_threshold_override poisoned") = threshold;
    }

    /// CIRISEdge#208 — install a runtime override for the
    /// `TrustScoring` resolver consulted by the `dispatch_inbound` trust
    /// short-circuit. Used by the PyO3 surface
    /// `PyEdge::install_trust_resolver` to wire a Python callback as
    /// the scorer. `None` clears the override.
    pub fn install_trust_scoring_override(
        &self,
        scoring: Option<Arc<dyn ciris_persist::federation::TrustScoring>>,
    ) {
        *self
            .trust_scoring_override
            .write()
            .expect("trust_scoring_override poisoned") = scoring;
    }

    /// CIRISEdge#208 — counterpart to
    /// [`Self::dispatch_inbound_for_test`] that returns a stable
    /// wire-string outcome derived from metrics deltas around the
    /// dispatch. The conformance harness's `test_200` intake-gate test
    /// drives this through `PyEdge::dispatch_inbound_bytes` to verify
    /// the trust short-circuit refusal arm executes.
    ///
    /// Outcomes:
    /// - `"trust_short_circuited"` — `inbound_dropped_low_trust`
    ///   counter incremented (the #48-B arm fired).
    /// - `"received"` — `envelopes_received_total[mt]` incremented for
    ///   any `MessageType` (verify passed AND the envelope reached
    ///   handler dispatch).
    /// - `"verify_failed"` — neither counter moved; the envelope was
    ///   dropped at the verify pipeline (signature failure, replay,
    ///   misroute, body-too-large, schema-invalid). The harness can
    ///   inspect tracing / metrics in detail if a finer split is
    ///   needed.
    pub async fn dispatch_inbound_observed_outcome_for_test(
        &self,
        frame: InboundFrame,
    ) -> &'static str {
        let before_low_trust = self.metrics.inbound_dropped_low_trust();
        let before_received_total: u64 = {
            let guard = self.metrics.envelopes_received_total.read();
            guard.values().sum()
        };
        self.dispatch_inbound_for_test(frame).await;
        let after_low_trust = self.metrics.inbound_dropped_low_trust();
        let after_received_total: u64 = {
            let guard = self.metrics.envelopes_received_total.read();
            guard.values().sum()
        };
        if after_low_trust > before_low_trust {
            "trust_short_circuited"
        } else if after_received_total > before_received_total {
            "received"
        } else {
            "verify_failed"
        }
    }

    /// Rust-level accessor returning a clone of the outbound queue
    /// `Arc`. Used by [`crate::ffi::pyo3::PyDurableHandle`] to poll
    /// `outbound_status` for `await_ack` semantics independently of
    /// the `PyEdge`'s lifetime.
    #[must_use]
    pub fn outbound_queue_handle(&self) -> Arc<dyn OutboundHandle> {
        self.queue.clone()
    }

    /// CIRISEdge#220 — spawn the transport listen tasks + inbound
    /// dispatch loop on the supplied tokio runtime handle, returning
    /// the join handles so the caller can hold them for the lifetime
    /// of the edge runtime.
    ///
    /// Use this from `init_edge_runtime` when the production code path
    /// does NOT take ownership of `Edge` via [`Self::run`]: it spawns
    /// the minimum-viable background tasks (one `transport.listen()`
    /// per configured transport, plus the inbound `dispatch_inbound`
    /// drain) so the receiver-side can accept inbound `LinkRequest`s
    /// + drive verified envelopes to handlers.
    ///
    /// Out of scope: outbound dispatcher, blackhole pruner, sweeps.
    /// Those are wired only by [`Self::run`] and aren't needed for the
    /// from-Python `send_inline_text`/`send_durable_inline_text`
    /// surfaces today — the send path itself runs synchronously on
    /// the persist executor via `run_async`.
    ///
    /// **Runtime split:** the supplied `runtime` MUST be an edge-side
    /// `tokio::runtime::Handle`. The listen task's
    /// `tokio::time::interval` (announce ticker) requires an edge-tokio
    /// Timer driver registered in edge-tokio's thread-locals — persist's
    /// executor's runtime symbols don't satisfy that (CIRISEdge#217
    /// closed the same class for `wait_until_async` via futures_timer;
    /// the listener loop carries similar tokio-time primitives that
    /// can't be runtime-agnosticised as cheaply).
    pub fn spawn_background_listeners(
        self: &Arc<Self>,
        runtime: &tokio::runtime::Handle,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<InboundFrame>(1024);
        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        // One listen task per registered transport. Each `listen()`
        // owns its transport's NodeEvent loop — accepts inbound
        // `LinkRequest`s, drives `LinkEstablished` bookkeeping, and
        // pushes resource-completed envelopes onto `inbound_tx` as
        // `InboundFrame`s.
        for transport in &self.transports {
            let t = transport.clone();
            let tx = inbound_tx.clone();
            tasks.push(runtime.spawn(async move {
                if let Err(e) = t.listen(tx).await {
                    tracing::error!(
                        transport = ?t.id(),
                        error = %e,
                        "transport listen exited",
                    );
                }
            }));
        }
        drop(inbound_tx);

        // Inbound dispatch task — drain the InboundFrame channel,
        // hand each frame to the same `dispatch_inbound` codepath the
        // [`Self::dispatch_inbound_for_test`] seam already drives. The
        // dispatch consults the override slots (CIRISEdge#208) BUT
        // those default to `None` in production so the production-path
        // behaviour is byte-equal to what [`Self::run`]'s inline loop
        // would have done.
        let edge_for_dispatch = Arc::clone(self);
        tasks.push(runtime.spawn(async move {
            while let Some(frame) = inbound_rx.recv().await {
                // CIRISEdge#348 — route CRPL replication frames to the registry
                // FIRST (the hop `run` had but this loop was missing, so the agent
                // never delivered round-opens to the responder). Only fall through
                // to envelope dispatch when it's not consumed by replication.
                if route_replication_frame(edge_for_dispatch.replication_registry.get(), &frame)
                    .await
                {
                    continue;
                }
                edge_for_dispatch
                    .dispatch_inbound_observed_outcome_for_test(frame)
                    .await;
            }
        }));

        tasks
    }

    /// CIRISEdge#243 — spawn the outbound dispatcher + periodic sweeps on
    /// the supplied edge-side runtime `Handle`. This is the exact spawn
    /// block [`Self::run`] wires inline; extracting it into one method
    /// gives [`init_edge_runtime`] (which drives transport via
    /// [`Self::spawn_background_listeners`], NOT [`Self::run`]) a way to
    /// go live on the durable send path — `send_durable` /
    /// `send_opaque_event` / DSAR durable sends only *enqueue* to the
    /// outbound queue; without this dispatcher nothing drains + transmits
    /// them, so a `DurableHandle` never progressed past "queued" from the
    /// Python runtime. Ephemeral sends (`send_opaque_request`,
    /// `transport.send`) transmit inline and were unaffected.
    ///
    /// **Caller contract (busy-loop hazard):** the caller MUST keep the
    /// [`watch::Sender`] paired with `shutdown_rx` alive for the runtime's
    /// lifetime. `run_dispatcher`'s idle-poll arm `select!`s on
    /// `shutdown.changed()`; if the sender is *dropped*, `changed()`
    /// returns `Err` immediately and the loop hot-spins on
    /// `claim_pending_outbound`. Signal `true` on teardown (clean exit)
    /// rather than dropping the sender mid-flight.
    ///
    /// **Runtime split:** as with [`Self::spawn_background_listeners`],
    /// `runtime` MUST be the edge-side `Handle` — `run_dispatcher` /
    /// `run_sweeps` carry `tokio::time` primitives that need edge-tokio's
    /// Timer driver (CIRISEdge#217 / the v7.1.0 split).
    pub fn spawn_outbound_dispatcher(
        self: &Arc<Self>,
        runtime: &tokio::runtime::Handle,
        shutdown_rx: &watch::Receiver<bool>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        {
            let q = self.queue.clone();
            let ts = self.transports.clone();
            let cfg = self.config.dispatcher.clone();
            let sd = shutdown_rx.clone();
            let reach = Some(self.reachability.clone());
            tasks.push(runtime.spawn(async move {
                run_dispatcher(q, ts, cfg, sd, reach).await;
            }));
        }
        {
            let q = self.queue.clone();
            let sd = shutdown_rx.clone();
            tasks.push(runtime.spawn(async move {
                run_sweeps(q, sd).await;
            }));
        }
        tasks
    }

    /// CIRISEdge#175 (v6.1.0, FSD §3.2) — resolve the default
    /// `cohort_scope` for a stated audience without actually
    /// publishing. Callers preview the §3.2 default-flip rule
    /// before they commit to a `send_*` call.
    ///
    /// The rule (per [`CohortScope::default_for_audience`]):
    ///
    /// - if `active_community_id` is `Some` → `Cohort { community_id }`
    /// - else if `in_family_context` → `Family`
    /// - else → `SelfOnly`
    ///
    /// Federation scope is NEVER returned — federation is opt-in
    /// at the call site (the operator passes
    /// `CohortScope::Public` explicitly to opt up).
    ///
    /// This is the wire-format invariant. The PyO3 surface
    /// (`Edge.resolve_default_scope`) drives off this method
    /// without re-deriving the rule.
    #[must_use]
    pub fn resolve_default_scope(
        &self,
        active_community_id: Option<&str>,
        in_family_context: bool,
    ) -> CohortScope {
        CohortScope::default_for_audience(active_community_id, in_family_context)
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

    /// v1.1.1 — choose between the in-memory local signer and the
    /// forensic (platform-keyring) signer at envelope-sign time.
    /// Mirrors CIRISPersist#137/#138 `select_signer` discipline:
    /// when the local signer's `key_id` matches `signer`'s (the
    /// common cohabitation case where `local_key_path` was supplied
    /// at Engine construction), prefer the in-memory adapter so
    /// signing skips the keychain/dbus/libsecret IPC.
    ///
    /// Closes the CIRISEdge#50 darwin headless-CI follow-on:
    /// platform-keyring `sign()` fails on macOS runners where the
    /// Keychain isn't unlocked → `send_durable_inline_text` crashed
    /// the subprocess at the envelope sign step → conformance
    /// `test_durable_send_enqueues_to_outbound_queue` got an empty
    /// stdout → JSONDecodeError. With the local-signer fast-path,
    /// the sign is an in-memory Ed25519 op (~14µs) that works
    /// regardless of platform keyring state.
    ///
    /// Returns `&self.signer` (forensic) when no `local_signer` was
    /// supplied or when the local alias doesn't match — preserving
    /// the v0.13.1 split for hardware-rooted forensic envelope
    /// signing.
    fn scrub_signer(&self) -> &Arc<LocalSigner> {
        match self.local_signer.as_ref() {
            Some(local) if local.key_id == self.signer.key_id => local,
            _ => &self.signer,
        }
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

    /// CIRISEdge#359 bench seam — run the `AccordCarrier` wire-layer multi-sig
    /// gate ([`verify_accord_carrier`]) DIRECTLY on a pre-built announcement,
    /// bypassing envelope dispatch + the replay window. The dispatch path runs
    /// the verify pipeline (incl. the replay gate) BEFORE the accord gate, so a
    /// benchmark that replays a pooled envelope measures replay-reject, not the
    /// (now post-quantum, ML-DSA-65-dominated) multi-sig cost. This seam lets
    /// the `accord_threshold_verify` bench measure the real per-signature hybrid
    /// verify. Compile-fenced behind `test-anchor` so it never exists in a
    /// production build.
    #[cfg(feature = "test-anchor")]
    pub async fn verify_accord_carrier_for_bench(
        &self,
        ann: &crate::messages::FederationAnnouncement,
    ) -> Result<(), crate::messages::RefusalReason> {
        verify_accord_carrier(ann, &self.verify_directory()).await
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

    /// v2.1.0 (CIRISPersist `LocalIdentityAggregate` RET-transport
    /// role) — return edge's 64-byte Reticulum transport-identity
    /// public material when a Reticulum transport is wired:
    /// `x25519_pub (32) ‖ ed25519_pub (32)`. Cohabiting cdylibs (the
    /// LocalIdentityAggregate constructor on persist's side; lens-core
    /// relay) read this to populate the RET-transport role of their
    /// aggregate hashes — edge owns the transport identity per
    /// `crate::identity::federation_identity_hash` doc note.
    ///
    /// Returns `None` for an Edge built without
    /// [`EdgeBuilder::reticulum_transport`] (HTTP-only deployments or
    /// tests that registered `Arc<dyn Transport>` via the generic
    /// [`EdgeBuilder::transport`] path). The Reticulum destination
    /// hash (`sha256(buf)[..16]`) is left to the caller — persist's
    /// aggregate already has its own hash machinery.
    #[cfg(feature = "_reticulum-module")]
    #[must_use]
    pub fn local_transport_pubkey(&self) -> Option<[u8; 64]> {
        self.reticulum_transport
            .as_ref()
            .map(|t| t.local_transport_pubkey())
    }

    /// v2.2.2 (CIRISEdge#97) — return edge's announced RNS destination
    /// hash when a Reticulum transport is wired: the 16-byte
    /// `*dest.hash()` value peers resolve to dial this node.
    /// Cohabiting cdylibs (CIRISLensCore v1.4.0+'s `install_ret_relay`)
    /// read this to surface the dialable RNS address alongside the
    /// pubkeys from [`Self::local_transport_pubkey`].
    ///
    /// Returns `None` for HTTPS-only / transport-less Edge builds
    /// (`disable_reticulum=True` at `init_edge_runtime`, or a wheel
    /// built without the `_reticulum-module` feature) — same posture
    /// as [`Self::local_transport_pubkey`].
    #[cfg(feature = "_reticulum-module")]
    #[must_use]
    pub fn local_dest_hash(&self) -> Option<[u8; 16]> {
        self.reticulum_transport
            .as_ref()
            .map(|t| t.local_dest_hash())
    }

    /// CIRISEdge#309 — the **named** destination hash
    /// (`sha256(name_hash("ciris",["edge"]) ‖ identity_hash)[..16]`) this
    /// node announces + listens on for mesh-routed delivery. Distinct from
    /// [`Self::local_dest_hash`] (the *explicit* `sha256(fed_pubkey)[..16]`).
    /// This is the value `verify_transport_binding` recomputes for a signed
    /// occurrence's `transport_destination`, so a consumer building that
    /// binding must use THIS authoritative accessor rather than recomputing
    /// `compute_destination_hash` itself (byte-identical today, but drifts if
    /// edge ever changes the app/aspects or hash shape). Returns `None` for
    /// HTTPS-only / transport-less builds — same posture as
    /// [`Self::local_dest_hash`].
    #[cfg(feature = "_reticulum-module")]
    #[must_use]
    pub fn local_named_dest_hash(&self) -> Option<[u8; 16]> {
        self.reticulum_transport
            .as_ref()
            .map(|t| t.local_named_dest_hash())
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

    /// Run the listeners + dispatch loops + outbound dispatcher.
    /// Returns when the shutdown signal fires.
    ///
    /// v8.2.0 (CIRISEdge#249) — takes `self: Arc<Self>` instead of `self`.
    /// The lifecycle only *clones* fields out of the edge into its spawned
    /// tasks (it never moves the edge apart), so an `Arc` receiver keeps
    /// the running edge callable: a node wraps its `Edge` in an `Arc`,
    /// spawns `Arc::clone(&edge).run(shutdown_rx)`, and keeps the other
    /// clone to issue `&self` calls — `send_opaque_request` /
    /// `send_opaque_event` — from a separate task (e.g. an HTTP handler)
    /// on the SAME running edge. That is the CC-0.7 mesh control-plane
    /// **initiator** leg (`0x0000_*`); before this it was unreachable on a
    /// `run()`-lifecycle node because `run(self)` consumed the edge.
    /// Distinct from CIRISEdge#243 (the `init_edge_runtime` outbound
    /// dispatcher gap) — this is the `run()` path, and it keeps run()'s
    /// CRPL replication pre-dispatch + sweeps intact (which
    /// `spawn_background_listeners` alone drops).
    // v0.18.0 — function grew past clippy's 100-line cap once the #33
    // background blackhole-pruner spawn landed alongside the existing
    // listener / dispatcher / sweeps / inbound spawn graph. The
    // spawn-graph composition is the construction-time contract; extracting
    // it would fragment the lifecycle invariants without adding clarity.
    #[allow(clippy::too_many_lines)]
    pub async fn run(self: Arc<Self>, shutdown_rx: watch::Receiver<bool>) -> Result<(), EdgeError> {
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

        // Spawn outbound dispatcher + sweeps. CIRISEdge#243 — shared with
        // `init_edge_runtime` via `spawn_outbound_dispatcher` so the durable
        // send path is identical on both lifecycles. `run().await` is always
        // polled inside a runtime, so `Handle::current()` is the edge runtime
        // here; `shutdown_rx`'s sender is `run`'s own `shutdown_tx`, alive for
        // the whole call, so no busy-loop.
        tasks.extend(
            self.spawn_outbound_dispatcher(&tokio::runtime::Handle::current(), &shutdown_rx),
        );

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
        let opaque_subs = self.opaque_subscribers.clone();
        let opaque_handlers = self.opaque_handlers.clone();
        let opaque_request_pending = self.opaque_request_pending.clone();
        let response_transport = self.transports.first().cloned();
        let max_content_body_bytes = self.config.max_content_body_bytes;
        let reachability = self.reachability.clone();
        let detector = self.detector.clone();
        let verified_tx = self.verified_envelope_tx.clone();
        let content_pending = self.content_fetch_pending.clone();
        let blob_chunk_pending = self.blob_chunk_fetch_pending.clone();
        let metrics = self.metrics.clone();
        let events = self.events.clone();
        // CIRISEdge#48-A → #48-A-completion (v0.19.6) — clone the
        // persist federation_directory handle + enforcement mode +
        // trust short-circuit knobs into the dispatcher loop.
        let federation_directory_for_cohort = self.federation_directory.clone();
        let cohort_enforcement = self.config.cohort_scope_enforcement;
        let trust_scoring = self.trust_scoring.clone();
        let trust_threshold = self.config.trust_threshold;
        let trust_short_circuit_enabled = self.config.trust_short_circuit_enabled;
        // CIRISEdge#51 (v0.20.0 RC1) — capture into the dispatcher loop
        // so each spawned `dispatch_inbound` task gets the operator-
        // configured recursion depth (CEWP L0/L1 0/1 default).
        let trust_recursion_depth = self.config.trust_recursion_depth;
        // CIRISEdge#52 (v0.20.1) — multimedia tier knobs threaded
        // into each dispatched envelope. `agent_mode` gates the
        // L1-as-CDN-edge prefetch arm; the URI base is `Option`
        // because the prefetch hook only fires when both the
        // boolean is `true` AND a base is supplied.
        let agent_mode_for_dispatch = self.config.agent_mode;
        let l1_cdn_edge_enabled = self.config.l1_cdn_edge_enabled;
        let l1_cdn_edge_external_uri_base = self.config.l1_cdn_edge_external_uri_base.clone();
        // CIRISEdge#108 part 2 (v3.2.0-pre1) — delegation authority
        // gate knobs. The trust-roots `Arc<RwLock>` is the same one
        // `Edge::canonical_peers` exposes; read inside the gate so a
        // future operator-driven mutation takes effect on the next
        // envelope without rebuilding dispatch.
        let delegation_authority_gate_enabled = self.config.delegation_authority_gate_enabled;
        let delegation_graph_max_depth = self.config.delegation_graph_max_depth;
        let delegation_trust_roots = self.canonical_peers.clone();
        // CIRISEdge#55 v3.4.0-pre1 — server-side responder hook.
        let blob_chunk_source = self.blob_chunk_source.clone();
        // CIRISEdge#184 (v6.3.0) — swarm-runtime inbound hook for
        // verified `MessageType::FountainHoldingClaim` envelopes.
        // Clone of the `Arc<OnceLock<Arc<FountainSwarmRuntime>>>`; the
        // OnceLock load inside the dispatch is a cheap atomic.
        let swarm_runtime = self.swarm_runtime.clone();
        // CIRISEdge#119 v3.5.1 — opt-in replication routing. When the
        // OnceLock has been populated by
        // `Edge::install_replication_routing`, the inbound loop
        // consults the registry's `route_inbound_bytes` BEFORE
        // dispatching as a normal envelope. CRPL frames (magic prefix)
        // get delivered to the matching coordinator; everything else
        // falls through to `dispatch_inbound`. The Arc clone is cheap
        // (atomic refcount bump per inbound frame) and the OnceLock
        // load inside the loop is a cheap atomic.
        let replication_registry = self.replication_registry.clone();
        let mut shutdown = shutdown_rx;
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!("edge: shutdown signal received");
                    break;
                }
                Some(frame) = inbound_rx.recv() => {
                    // CIRISEdge#348 — the SHARED transport→replication ingest hop
                    // (v3.5.1 CIRISEdge#119 CRPL pre-dispatch), factored out so this
                    // loop and `spawn_background_listeners` (the agent's loop) can
                    // NEVER diverge again. Routes CRPL replication frames to the
                    // registry; returns true when consumed (→ do not envelope-
                    // dispatch). Every branch logs, throttled.
                    if route_replication_frame(replication_registry.get(), &frame).await {
                        continue;
                    }
                    let verify_clone = verify.clone();
                    let handlers_clone = handlers.clone();
                    let queue_clone = queue.clone();
                    let signer_clone = signer.clone();
                    let opaque_subs_clone = opaque_subs.clone();
                    let opaque_handlers_clone = opaque_handlers.clone();
                    let opaque_request_pending_clone = opaque_request_pending.clone();
                    let response_transport_clone = response_transport.clone();
                    let reach_clone = reachability.clone();
                    let directory_clone = verify_clone.directory();
                    let detector_clone = detector.clone();
                    let verified_tx_clone = verified_tx.clone();
                    let content_pending_clone = content_pending.clone();
                    let blob_chunk_pending_clone = blob_chunk_pending.clone();
                    let metrics_clone = metrics.clone();
                    let events_clone = events.clone();
                    let fed_dir_for_cohort_clone = federation_directory_for_cohort.clone();
                    let trust_scoring_clone = trust_scoring.clone();
                    let l1_cdn_edge_external_uri_base_clone = l1_cdn_edge_external_uri_base.clone();
                    let delegation_trust_roots_clone = delegation_trust_roots.clone();
                    let blob_chunk_source_clone = blob_chunk_source.clone();
                    let swarm_runtime_clone = swarm_runtime.clone();
                    tokio::spawn(async move {
                        dispatch_inbound(
                            frame,
                            &verify_clone,
                            &handlers_clone,
                            &queue_clone,
                            &signer_clone,
                            &opaque_subs_clone,
                            &opaque_handlers_clone,
                            &opaque_request_pending_clone,
                            response_transport_clone.as_ref(),
                            max_content_body_bytes,
                            &directory_clone,
                            Some(&reach_clone),
                            detector_clone.as_ref(),
                            &verified_tx_clone,
                            &content_pending_clone,
                            &blob_chunk_pending_clone,
                            &metrics_clone,
                            &events_clone,
                            fed_dir_for_cohort_clone.as_ref(),
                            cohort_enforcement,
                            trust_scoring_clone.as_ref(),
                            trust_threshold,
                            trust_short_circuit_enabled,
                            trust_recursion_depth,
                            agent_mode_for_dispatch,
                            l1_cdn_edge_enabled,
                            l1_cdn_edge_external_uri_base_clone,
                            delegation_authority_gate_enabled,
                            delegation_graph_max_depth,
                            delegation_trust_roots_clone,
                            blob_chunk_source_clone.as_ref(),
                            swarm_runtime_clone.get(),
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
        sign_envelope(self.scrub_signer(), &mut envelope).await?;
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

    /// CIRISEdge#48-A → #48-A-completion (v0.19.6) — producer-side
    /// enforcement gate for `Delivery::Ephemeral` / `Delivery::Durable`
    /// (point-to-point). `SelfOnly` requires
    /// recipient == self.signer.key_id; `Family` requires the
    /// recipient's recorded scope to be Family; `Cohort` requires
    /// matching cohort_id. Recorded scope is sourced from persist's
    /// `peer_metadata_for` (NOT the v0.19.1 in-process registry; that
    /// path is removed at v0.19.6).
    async fn enforce_point_to_point_scope(
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
            // CIRISEdge#274 — `self` spans the owner's node set, not just this
            // key: admit iff the recipient is one of MY own nodes. Fails closed
            // on an unresolvable/ambiguous owner (CIRISConstitution#23).
            CohortScope::SelfOnly => {
                key_is_own_node(
                    self.federation_directory.as_ref(),
                    &self.signer.key_id,
                    recipient_key_id,
                )
                .await
            }
            CohortScope::Family | CohortScope::Cohort { .. } => {
                let recipient_scope = self.peer_cohort_scope_from_persist(recipient_key_id).await;
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

/// CIRISConstitution#23 / CIRISEdge#274 (CC 1.13.3.3 / CC 3.2) — is
/// `other_key_id` a member of `local_key_id`'s OWN node set? The `self` cohort
/// boundary spans the owner's owned-node graph (distinct keys unified by the
/// owner-binding), NOT a single signing key: CIRISServer models "nodes I own"
/// as `nodes_stewarded_by(owner)`, and the default owner-binding is persisted
/// `cohort_scope: self`. So a `SelfOnly` event between two of a person's own
/// nodes is genuine self-replication, not a cross-identity leak.
///
/// Resolution: `local`'s owning identity is persist's single-owner
/// [`owner_of`](ciris_persist::federation::admission::owner_of) — the
/// dimension-precise owner (a node has at most one, enforced at admission by
/// persist's single-owner gate) — or `local` itself when it is an unowned
/// self-anchor (a `user`-role key owns its own node set). Membership is then
/// `other ∈ nodes_stewarded_by(owner)`.
///
/// **Fails closed.** An absent directory, an ambiguous owner
/// ([`Error::AmbiguousNodeOwner`](ciris_persist::federation::Error)), or any
/// read error yields `false` — a `self` boundary is NEVER resolved from an
/// ambiguous owner (CIRISConstitution#23 consumer-fail-closed rule). `other ==
/// local` is trivially true and needs no directory.
async fn key_is_own_node(
    directory: Option<&Arc<dyn ciris_persist::federation::FederationDirectory>>,
    local_key_id: &str,
    other_key_id: &str,
) -> bool {
    if other_key_id == local_key_id {
        return true;
    }
    let Some(directory) = directory else {
        return false; // no directory → cannot resolve ownership → fail closed
    };
    let dir: &dyn ciris_persist::federation::FederationDirectory = directory.as_ref();
    let owner = match ciris_persist::federation::admission::owner_of(dir, local_key_id).await {
        Ok(Some(owner)) => owner,
        // Unowned: a `user`-role self-anchor owns its own set; an unowned node
        // owns nothing (nodes_stewarded_by → ∅), so only `other == local` (handled
        // above) is self. Either way, anchor on `local`.
        Ok(None) => local_key_id.to_string(),
        // Ambiguous owner / read error → fail closed (never leak self content).
        Err(_) => return false,
    };
    match ciris_persist::federation::admission::nodes_stewarded_by(dir, &owner).await {
        Ok(nodes) => nodes.iter().any(|n| n == other_key_id),
        Err(_) => false,
    }
}

// CIRISEdge#317 — throttles for the two attacker-triggerable, per-frame inbound
// log sites (points 4 + 5). Both are keyed on a LOW-cardinality discriminant
// (transport id / verify-error class), so a flood of junk frames collapses to a
// bounded first-N-per-window + suppressed-count rather than a per-frame line.
// The always-on rate lives in `EdgeMetrics` (`inc_verify_failure`).
static INBOUND_UNROUTABLE_CRPL_LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> =
    std::sync::OnceLock::new();
static INBOUND_VERIFY_REJECT_LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> =
    std::sync::OnceLock::new();

/// Point 4 — a CRPL replication frame that couldn't be attributed (no
/// `source_key_id`). Keyed on transport id (a handful of values).
fn inbound_unroutable_crpl_log() -> &'static crate::log_throttle::LogThrottle {
    INBOUND_UNROUTABLE_CRPL_LOG.get_or_init(|| {
        crate::log_throttle::LogThrottle::new(5, std::time::Duration::from_secs(60), 16)
    })
}

/// Point 5 — a verify-rejected inbound frame (attacker-expected junk). Keyed on
/// the verify-error class (a small closed set).
fn inbound_verify_reject_log() -> &'static crate::log_throttle::LogThrottle {
    INBOUND_VERIFY_REJECT_LOG.get_or_init(|| {
        crate::log_throttle::LogThrottle::new(5, std::time::Duration::from_secs(60), 32)
    })
}

// CIRISEdge#348 — observability for the transport→replication INGEST hop. This is
// the hand-off that silently swallowed anti-entropy round-opens (the agent's
// `spawn_background_listeners` loop never routed CRPL frames, and NOTHING logged
// between resource-reassembly and the drop). Both are keyed on a LOW-cardinality
// discriminant (transport id / peer key_id with a capped map) — safe under a
// frame flood, per the crate's LogThrottle discipline.
static INBOUND_INGEST_LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> =
    std::sync::OnceLock::new();
static INBOUND_ROUTED_LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> =
    std::sync::OnceLock::new();

/// A frame CROSSED transport→replication ingest. Keyed on transport id (a handful
/// of values). Makes the previously-invisible hop VISIBLE at `ciris_edge=debug`.
fn inbound_ingest_log() -> &'static crate::log_throttle::LogThrottle {
    INBOUND_INGEST_LOG.get_or_init(|| {
        crate::log_throttle::LogThrottle::new(8, std::time::Duration::from_secs(60), 16)
    })
}

/// A CRPL frame was ROUTED to a replication responder (the success path — the one
/// that was silent). Keyed on peer key_id (attacker-influenceable ⇒ capped map).
fn inbound_routed_log() -> &'static crate::log_throttle::LogThrottle {
    INBOUND_ROUTED_LOG.get_or_init(|| {
        crate::log_throttle::LogThrottle::new(8, std::time::Duration::from_secs(60), 256)
    })
}

/// CIRISEdge#348 — the SHARED transport→replication ingest hop.
///
/// Called by BOTH inbound loops ([`Edge::run`] AND
/// [`Edge::spawn_background_listeners`], the one the agent/PyEngine actually
/// drives) so they CANNOT diverge. They did: only `run` carried the CRPL
/// `route_inbound_bytes` pre-dispatch, so the agent never delivered anti-entropy
/// round-opens to the responder — the round-open reassembled, then vanished with
/// no log. Extracting the hop into one function fixes both the divergence and the
/// silence.
///
/// Returns `true` when the frame was consumed by replication ingest (routed to a
/// coordinator, or dropped as an unroutable/failed replication frame → the caller
/// must NOT also envelope-dispatch it); `false` when the caller should fall
/// through to envelope dispatch. Every branch logs (throttled).
async fn route_replication_frame(
    registry: Option<&std::sync::Arc<crate::replication::registry::ReplicationRegistry>>,
    frame: &InboundFrame,
) -> bool {
    use crate::log_throttle::ThrottleDecision;
    use crate::replication::registry::RouteOutcome;

    // The frame reached ingest — the hop that used to be invisible.
    if let ThrottleDecision::Emit { suppressed_prev } =
        inbound_ingest_log().check(frame.transport.0)
    {
        tracing::debug!(
            transport_id = %frame.transport.0,
            bytes = frame.envelope_bytes.len(),
            source_key_id = ?frame.source_key_id,
            suppressed_prev,
            "inbound frame reached replication ingest (CIRISEdge#348)"
        );
    }

    let Some(registry) = registry else {
        return false; // no replication runtime installed → envelope dispatch
    };
    let Some(source) = frame.source_key_id.as_deref() else {
        // No attribution: a CRPL frame here is unroutable (drop, loudly); a
        // non-CRPL frame is a normal unattributed envelope (fall through).
        if frame
            .envelope_bytes
            .starts_with(&crate::replication::wire_frame::REPLICATION_FRAME_MAGIC)
        {
            if let ThrottleDecision::Emit { suppressed_prev } =
                inbound_unroutable_crpl_log().check(frame.transport.0)
            {
                tracing::warn!(
                    transport_id = %frame.transport.0,
                    bytes = frame.envelope_bytes.len(),
                    first_bytes_hex = %first_bytes_hex(&frame.envelope_bytes),
                    route = "SkippedNoSourceKeyId",
                    suppressed_prev,
                    "inbound CRPL replication frame with source_key_id=None — transport could \
                     not attribute the sending link to a peer; dropping (CIRISEdge#317)"
                );
            }
            return true;
        }
        return false;
    };

    match registry
        .route_inbound_bytes(source, &frame.envelope_bytes)
        .await
    {
        Ok(RouteOutcome::Routed) => {
            if let ThrottleDecision::Emit { suppressed_prev } = inbound_routed_log().check(source) {
                tracing::debug!(
                    peer = %source,
                    suppressed_prev,
                    "CRPL frame ROUTED to replication responder (CIRISEdge#348)"
                );
            }
            true
        }
        Ok(RouteOutcome::NotAReplicationFrame) => false, // → envelope dispatch
        Ok(RouteOutcome::NoCoordinatorRegistered { kind }) => {
            tracing::warn!(
                peer = %source,
                ?kind,
                "CRPL frame DROPPED — no coordinator and no responder factory for (peer, kind); \
                 the ReplicationRuntime is not wired (CIRISEdge#348)"
            );
            true
        }
        Err(e) => {
            tracing::warn!(
                peer = %source,
                error = %e,
                "replication route_inbound_bytes failed; dropping frame (CIRISEdge#348)"
            );
            true
        }
    }
}

/// Hex of the first up-to-8 bytes of a frame — distinguishes a binary CRPL frame
/// that was misrouted to the JSON verifier from a genuinely-malformed envelope.
fn first_bytes_hex(bytes: &[u8]) -> String {
    hex::encode(&bytes[..bytes.len().min(8)])
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
        opaque_subscribers,
        opaque_handlers,
        opaque_request_pending,
        response_transport,
        directory,
        reachability,
        detector,
        verified_envelope_tx,
        content_fetch_pending,
        metrics,
        events,
        federation_directory_for_cohort,
        trust_scoring,
        delegation_trust_roots,
        blob_chunk_source,
        swarm_runtime,
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
    opaque_subscribers: &std::sync::Mutex<HashMap<u64, OpaqueSubscriber>>,
    // CC 0.7 (CIRISEdge#241) — opaque-request handler registry (keyed by
    // `kind`) + request→response correlation map + the transport used to
    // ship the OpaqueResponse back to the request sender.
    opaque_handlers: &std::sync::Mutex<HashMap<u32, OpaqueRequestHandlerFn>>,
    opaque_request_pending: &OpaqueRequestPendingMap,
    response_transport: Option<&Arc<dyn Transport>>,
    max_content_body_bytes: usize,
    directory: &Arc<dyn VerifyDirectory>,
    reachability: Option<&Arc<ReachabilityTracker>>,
    detector: Option<&Arc<crate::ProbePatternObserver>>,
    verified_envelope_tx: &broadcast::Sender<VerifiedEnvelopeSnapshot>,
    content_fetch_pending: &std::sync::Mutex<HashMap<[u8; 32], oneshot::Sender<ContentResult>>>,
    // CIRISEdge#55 — sibling pending-map for chunked-blob swarm fetch.
    // Keyed by `(blob_sha256, chunk_sha256)` because the scheduler runs
    // many chunk fetches in parallel across multiple blobs; blob-SHA
    // alone can't disambiguate concurrent fetches against the same
    // chunk-SHA across distinct blobs.
    blob_chunk_fetch_pending: &BlobChunkPendingMap,
    metrics: &crate::observability::EdgeMetrics,
    events: &Arc<crate::events::EventBus>,
    // CIRISEdge#48-A → #48-A-completion (v0.19.6) — persist-backed
    // cohort_scope source-of-truth. Optional because tests that don't
    // wire a federation_directory still drive this surface; absent
    // directory means "treat every peer as Public" (lenient default).
    federation_directory_for_cohort: Option<
        &Arc<dyn ciris_persist::federation::FederationDirectory>,
    >,
    cohort_enforcement: CohortScopeEnforcement,
    // CIRISEdge#48-B (v0.19.6) — persist-backed trust scoring. The
    // short-circuit fires only when ALL of: scoring is wired,
    // `trust_short_circuit_enabled`, and `trust_threshold > 0.0`.
    trust_scoring: Option<&Arc<dyn ciris_persist::federation::TrustScoring>>,
    trust_threshold: f64,
    trust_short_circuit_enabled: bool,
    // CIRISEdge#51 (v0.20.0 RC1) — trust-graph recursion depth threaded
    // through to `TrustScoring::trust_score(key_id, recursion_depth)`.
    // v0.19.6 hardcoded `0` (strict direct trust); v0.20.0 RC1 honours
    // `EdgeConfig::trust_recursion_depth` (CEWP L0/L1 default 0/1).
    trust_recursion_depth: u8,
    // CIRISEdge#52 (v0.20.1) — multimedia tier: agent_mode gates
    // L1-as-CDN-edge (only `Server`/L1 acts); the cdn-edge knobs are
    // captured here so the dispatch sub-arm on `ContributionSubmit`
    // can fire the prefetch stub without re-reading the config.
    agent_mode: AgentMode,
    l1_cdn_edge_enabled: bool,
    l1_cdn_edge_external_uri_base: Option<String>,
    // CIRISEdge#108 part 2 (v3.2.0-pre1) — federation-tier delegation
    // authority gate. `delegation_trust_roots` is the
    // `Arc<RwLock<HashSet<String>>>` of canonical bootstrap peer
    // key_ids that `Edge` already maintains; we read it inside the
    // gate so an operator-driven canonical-peer mutation (a future
    // FFI cut) takes effect on the next inbound envelope without
    // restarting dispatch.
    delegation_authority_gate_enabled: bool,
    delegation_graph_max_depth: usize,
    delegation_trust_roots: Arc<std::sync::RwLock<HashSet<String>>>,
    // CIRISEdge#55 v3.4.0-pre1 — optional server-side responder for
    // inbound `BlobChunkFetch` envelopes. None → silently drop the
    // envelope (same posture as ContentFetch in edge#21 phase 1).
    blob_chunk_source: Option<&Arc<dyn crate::blob_swarm::BlobChunkSource>>,
    // CIRISEdge#184 (v6.3.0) — optional swarm orchestration runtime.
    // When set (via `Edge::install_swarm_runtime`), verified inbound
    // `MessageType::FountainHoldingClaim` envelopes are routed into
    // `register_observed_claim`. When None, the envelope is observed
    // (verify still runs) but no runtime hook fires — same posture as
    // `blob_chunk_source` for the chunked-blob swarm.
    swarm_runtime: Option<&Arc<crate::swarm::FountainSwarmRuntime>>,
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
            // CIRISEdge#317 point 5 — a verify-rejected frame is attacker-EXPECTED
            // traffic, not an operational error, so the always-on signal is the
            // `verify_failures_total[class]` counter (below), and the per-event
            // line is a THROTTLED WARN (was ERROR — always shipped). It carries
            // `source_key_id` explicitly (log `None`, don't omit) + `first_bytes_hex`
            // so a binary CRPL frame misrouted here vs a genuinely-malformed
            // signed envelope is one glance. Keyed on the verify class (small
            // closed set) so a flood of one class collapses to a suppressed-count.
            let class = crate::observability::VerifyErrorClass::from_verify_error(&e);
            metrics.inc_verify_failure(class);
            tracing::Span::current().record("verify_outcome", class.as_str());
            if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                inbound_verify_reject_log().check(class.as_str())
            {
                tracing::warn!(
                    event = "edge.dispatch_inbound.verify_rejected",
                    transport_id = %transport.0,
                    verify_error_class = class.as_str(),
                    source_key_id = ?frame.source_key_id,
                    bytes = frame.envelope_bytes.len(),
                    first_bytes_hex = %first_bytes_hex(&frame.envelope_bytes),
                    suppressed_prev,
                    error = %e,
                    "verify rejected (CIRISEdge#317)",
                );
            }
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

    // CIRISEdge#48-A → #48-A-completion (v0.19.6) — consumer-side
    // symmetric cohort_scope check. AFTER verify (signature gates
    // everything; we trust the claimed scope only insofar as the
    // sender's key vouches for it) and BEFORE handler dispatch (a
    // violation MUST NOT reach the application tier). Producer-side
    // refusal at outbound_enqueue is the structural primitive; this
    // consumer-side check is the symmetric pair.
    //
    // v0.19.6 sources the sender's recorded scope from persist's
    // `peer_metadata_for(key_id).policy_blob.cohort_scope` (CIRISPersist
    // #127, v3.4.1). The in-process `cohort_membership` HashMap from
    // v0.19.1 is REMOVED — operators declare cohort_scope via
    // `Engine::update_peer_policy(key_id, json!({"cohort_scope": ...}))`
    // and the substrate carries the source of truth.
    //
    // Wire-format invariant: for envelopes carrying a `cohort_scope`,
    // if the claimed scope is restricted (`SelfOnly` / `Family` /
    // `Cohort`) AND the sender's directory-recorded scope doesn't
    // match the claim, REJECT with a moderation-signal event so
    // lens-core can downweight the sender. `Public` short-circuits to
    // OK (the implicit baseline). v0.19.6 adds the `Cohort{id}` arm
    // that v0.19.1 deferred — the persist read accessor unblocks it.
    if let Some(claimed) = envelope.cohort_scope.as_ref() {
        if claimed.is_restricted() {
            let recorded_scope = match federation_directory_for_cohort {
                Some(dir) => match dir.peer_metadata_for(&envelope.signing_key_id).await {
                    Ok(opt) => opt
                        .as_ref()
                        .and_then(|row| row.policy_blob.as_ref())
                        .and_then(|blob| blob.as_value().get("cohort_scope").cloned())
                        .and_then(|v| serde_json::from_value::<CohortScope>(v).ok()),
                    Err(e) => {
                        tracing::warn!(
                            event = "edge.cohort_scope.persist_lookup_failed",
                            sender_key_id = %envelope.signing_key_id,
                            error = %e,
                            "consumer-side peer_metadata_for failed; treating sender as Public",
                        );
                        None
                    }
                },
                None => None,
            };
            // CIRISEdge#274 (CC 1.13.3.3 / CC 3.2) — a `SelfOnly` inbound is
            // admissible iff the SENDER is one of MY own nodes (self spans the
            // owner's node set), symmetric with the producer-side gate — NOT
            // merely a peer whose directory-recorded scope happens to be
            // `SelfOnly`. Family/Cohort keep the recorded-scope match.
            let matches_directory = if claimed == &CohortScope::SelfOnly {
                key_is_own_node(
                    federation_directory_for_cohort,
                    &signer.key_id,
                    &envelope.signing_key_id,
                )
                .await
            } else {
                match recorded_scope.as_ref() {
                    Some(rs) => rs == claimed,
                    None => false,
                }
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

    // CIRISEdge#48-B (v0.19.6) — trust short-circuit. AFTER verify
    // (the signature gates everything; verify still runs so persist's
    // scoring surface sees the corpus) and BEFORE handler dispatch
    // (a sender below the threshold MUST NOT reach the application
    // tier). The check is gated on all three of:
    //
    //   - `trust_short_circuit_enabled` — operator override for
    //     migration / tests;
    //   - `trust_threshold > 0.0` — bootstrap-permissive default;
    //   - `trust_scoring` wired — tests that don't supply a scorer
    //     fall through with no overhead.
    //
    // Persist's `AdmissionGate::check` short-circuits to admit at
    // threshold ≤ 0.0 (see CIRISPersist src/federation/replication/
    // admission.rs); we mirror that posture here so the
    // bootstrap-permissive baseline does NOT dispatch the (potentially
    // SQL-backed) `trust_score` call per envelope.
    if trust_short_circuit_enabled && trust_threshold > 0.0 {
        if let Some(scorer) = trust_scoring {
            let score = scorer
                .trust_score(&envelope.signing_key_id, trust_recursion_depth)
                .await;
            let observed = match score {
                Ok(s) => s,
                Err(ciris_persist::federation::TrustScoringError::KeyNotFound(_)) => {
                    // Unknown key → 0.0 (matches persist AdmissionGate
                    // discipline; unknown identity has no trust).
                    0.0
                }
                Err(e) => {
                    tracing::warn!(
                        event = "edge.trust_short_circuit.scoring_error",
                        sender_key_id = %envelope.signing_key_id,
                        error = %e,
                        "trust_score resolver failed; treating as 0.0 (drop if threshold > 0)",
                    );
                    0.0
                }
            };
            if observed < trust_threshold {
                tracing::Span::current().record("verify_outcome", "trust_short_circuit");
                tracing::warn!(
                    event = "edge.trust_short_circuit",
                    sender_key_id = %envelope.signing_key_id,
                    score = observed,
                    threshold = trust_threshold,
                    "inbound envelope dropped — sender trust below threshold (CIRISEdge#48-B)",
                );
                metrics.inc_inbound_dropped_low_trust();
                // Moderation signal — `TrustShortCircuited` event with
                // peer_key_id + observed score + threshold-in-message.
                // Routed onto the resource channel because lens-core
                // already subscribes there for the cohort_scope
                // moderation signal; the typed `EventKind` lets it
                // discriminate without a second subscription. Fire-
                // and-forget at the call site per the EventBus
                // discipline.
                events.emit_resource(crate::events::NetworkEvent::trust_short_circuited(
                    envelope.signing_key_id.clone(),
                    observed,
                    trust_threshold,
                ));
                return;
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
        //
        // CIRISEdge#52 (v0.20.1) — the External variant correlates
        // by the hex-decoded `external_sha256_hex` and signals via
        // `ContentResult::External` so the fetcher sees a typed
        // "this is a pointer, not bytes" outcome. Edge does NOT
        // dereference the pointer; the consumer's client fetches the
        // bytes directly from `external_uri` (MEDIA_SHARING.md §2.6).
        if is_external_content_body(envelope.body.get().as_bytes()) {
            if let Ok(external) =
                serde_json::from_str::<ContentBodyExternalProbe>(envelope.body.get())
            {
                if let Ok(sha) = hex_to_sha256(&external.external_sha256_hex) {
                    let mut pending = content_fetch_pending
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if let Some(tx) = pending.remove(&sha) {
                        let _ = tx.send(ContentResult::External {
                            external_uri: external.external_uri,
                            external_sha256_hex: external.external_sha256_hex,
                        });
                    }
                }
            }
        } else if let Ok(body) =
            serde_json::from_str::<crate::messages::ContentBody>(envelope.body.get())
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

    // CIRISEdge#55 — chunked-blob swarm correlation arms. Mirror the
    // ContentBody / ContentMiss shape exactly, except:
    //
    // - Key is (blob_sha256, chunk_sha256) — both echoed in the
    //   responder's body so we can match against the scheduler's
    //   pending-map without correlating envelope `in_reply_to`.
    //
    // - We do NOT in-dispatch verify `sha256(bytes) == chunk_sha256`.
    //   That gate is `persist.put_blob_chunk(blob_sha, chunk_sha, bytes)`
    //   (CIRISPersist#145 §10.1.1 seam) — the swarm scheduler hands the
    //   bytes from the pending oneshot directly to put_blob_chunk; on
    //   ChunkMismatch the scheduler demotes the responding peer. This
    //   dispatcher only enforces AV-13 (size); persist owns SHA verify.
    //
    // - AV-13 size gate: chunks above the ceiling are dropped at the
    //   dispatch boundary with a tracing::warn (same shape as ContentBody).
    if envelope.message_type == MessageType::BlobChunkBody {
        if envelope.body.get().len() > max_content_body_bytes {
            tracing::warn!(
                transport = ?transport,
                body_bytes = envelope.body.get().len(),
                max_content_body_bytes,
                "BlobChunkBody rejected at dispatch gate (AV-13 size cap)",
            );
            return;
        }
        if let Ok(body) =
            serde_json::from_str::<crate::messages::BlobChunkBody>(envelope.body.get())
        {
            let mut pending = blob_chunk_fetch_pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(tx) = pending.remove(&(body.blob_sha256, body.chunk_sha256)) {
                let _ = tx.send(ChunkResult::Bytes(body.bytes));
            }
        }
    }

    if envelope.message_type == MessageType::BlobChunkMiss {
        if let Ok(miss) =
            serde_json::from_str::<crate::messages::BlobChunkMiss>(envelope.body.get())
        {
            let mut pending = blob_chunk_fetch_pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(tx) = pending.remove(&(miss.blob_sha256, miss.chunk_sha256)) {
                let reason = format!("{:?}", miss.reason);
                let _ = tx.send(ChunkResult::ChunkMiss { reason });
            }
        }
    }

    // CIRISEdge#55 v3.4.0-pre1 — server-side `BlobChunkFetch` handler.
    // When a `BlobChunkSource` is wired and the envelope is addressed
    // to us, look up the chunk in our local store and respond with
    // either `BlobChunkBody` (we hold it) or `BlobChunkMiss` (we don't
    // / refused). When no source is wired, drop the envelope — same
    // posture as edge#21 phase 1 ContentFetch (consumer-crate owned
    // responder; edge core stays domain-agnostic at the substrate
    // tier and this hook is opt-in).
    if envelope.message_type == MessageType::BlobChunkFetch {
        if let Some(source) = blob_chunk_source {
            if let Ok(req) =
                serde_json::from_str::<crate::messages::BlobChunkFetch>(envelope.body.get())
            {
                use crate::messages::{
                    BlobChunkBody, BlobChunkMiss as BlobChunkMissBody, MissReason,
                };
                let (response_kind, response_envelope_bytes) = match source
                    .read_chunk(req.blob_sha256, req.chunk_sha256)
                {
                    Ok(Some(bytes)) => {
                        // AV-13 size gate on outbound: refuse to
                        // emit a chunk that exceeds the ceiling
                        // (the peer would drop it anyway, but the
                        // wire surface should never propose an
                        // oversize body).
                        if bytes.len() > max_content_body_bytes {
                            tracing::warn!(
                                transport = ?transport,
                                chunk_size = bytes.len(),
                                max = max_content_body_bytes,
                                "BlobChunkFetch responder: chunk exceeds AV-13 ceiling, replying NotHeld",
                            );
                            let miss = BlobChunkMissBody {
                                blob_sha256: req.blob_sha256,
                                chunk_sha256: req.chunk_sha256,
                                reason: MissReason::NotHeld,
                            };
                            match build_chunk_response_envelope(
                                MessageType::BlobChunkMiss,
                                &envelope.signing_key_id,
                                signer,
                                &miss,
                                body_sha256,
                            )
                            .await
                            {
                                Ok(bytes) => (MessageType::BlobChunkMiss, Some(bytes)),
                                Err(e) => {
                                    tracing::warn!(
                                        error = %e,
                                        "BlobChunkFetch responder: failed to build miss envelope",
                                    );
                                    (MessageType::BlobChunkMiss, None)
                                }
                            }
                        } else {
                            let body = BlobChunkBody {
                                blob_sha256: req.blob_sha256,
                                chunk_sha256: req.chunk_sha256,
                                bytes,
                            };
                            match build_chunk_response_envelope(
                                MessageType::BlobChunkBody,
                                &envelope.signing_key_id,
                                signer,
                                &body,
                                body_sha256,
                            )
                            .await
                            {
                                Ok(bytes) => (MessageType::BlobChunkBody, Some(bytes)),
                                Err(e) => {
                                    tracing::warn!(
                                        error = %e,
                                        "BlobChunkFetch responder: failed to build body envelope",
                                    );
                                    (MessageType::BlobChunkBody, None)
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        let miss = BlobChunkMissBody {
                            blob_sha256: req.blob_sha256,
                            chunk_sha256: req.chunk_sha256,
                            reason: MissReason::NotHeld,
                        };
                        match build_chunk_response_envelope(
                            MessageType::BlobChunkMiss,
                            &envelope.signing_key_id,
                            signer,
                            &miss,
                            body_sha256,
                        )
                        .await
                        {
                            Ok(bytes) => (MessageType::BlobChunkMiss, Some(bytes)),
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "BlobChunkFetch responder: failed to build miss envelope",
                                );
                                (MessageType::BlobChunkMiss, None)
                            }
                        }
                    }
                    Err(refusal) => {
                        let miss = BlobChunkMissBody {
                            blob_sha256: req.blob_sha256,
                            chunk_sha256: req.chunk_sha256,
                            reason: refusal.to_miss_reason(),
                        };
                        match build_chunk_response_envelope(
                            MessageType::BlobChunkMiss,
                            &envelope.signing_key_id,
                            signer,
                            &miss,
                            body_sha256,
                        )
                        .await
                        {
                            Ok(bytes) => (MessageType::BlobChunkMiss, Some(bytes)),
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "BlobChunkFetch responder: failed to build refusal envelope",
                                );
                                (MessageType::BlobChunkMiss, None)
                            }
                        }
                    }
                };

                if let Some(bytes) = response_envelope_bytes {
                    let env: Result<EdgeEnvelope, _> = serde_json::from_slice(&bytes);
                    if let Ok(env) = env {
                        let body_sha = envelope_body_sha256(&env);
                        let body_size = i32::try_from(bytes.len()).unwrap_or(i32::MAX);
                        // Ephemeral delivery class — short TTL, single attempt.
                        // The fetcher's per-request timeout governs retry,
                        // not the outbound queue.
                        let _ = queue
                            .enqueue_outbound(
                                &signer.key_id,
                                &envelope.signing_key_id,
                                &message_type_str(&response_kind),
                                "1.0.0",
                                &bytes,
                                &body_sha,
                                body_size,
                                false,
                                None,
                                1,
                                60,
                                Utc::now(),
                            )
                            .await;
                    }
                }
            }
        } else {
            tracing::debug!(
                transport = ?transport,
                signing_key_id = %envelope.signing_key_id,
                "BlobChunkFetch received but no BlobChunkSource wired; dropping (CIRISEdge#55)",
            );
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
    //
    // CC 0.7 (CIRISEdge#241, v8.0.0) — EXCLUDE `OpaqueResponse`. It
    // carries `in_reply_to` as its OWN Tier-2 request/response
    // correlation token (the request envelope's `body_sha256`, resolved
    // by the dedicated OpaqueResponse dispatch arm below), NOT as a
    // durable-send ACK. Without this guard the `Ok(None)` "no matching
    // outbound row; dropping" arm swallows every OpaqueResponse before
    // it reaches its correlation — breaking `send_opaque_request`'s
    // round-trip (the #240 mesh-control-plane response leg).
    if envelope.message_type != MessageType::OpaqueResponse {
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
    }

    // CIRISEdge#108 part 2 (v3.2.0-pre1) — federation-tier
    // delegation authority gate. Walks persist v6.5.0's
    // `delegates_to` chain (the substrate side of CEG §8.1.12.7) from
    // each canonical bootstrap peer; refuses envelopes whose signer
    // can't be tied back via a non-retracted, in-scope edge.
    //
    // At v3.2.0-pre1 the gate fires for `MessageType::InlineText`
    // ONLY. Every other variant falls through (gate-disabled in
    // `delegation_scope_for_message_type`). Operators opt in via
    // `EdgeConfig::delegation_authority_gate_enabled`; default off so
    // adding the gate is non-breaking. Substrate not wired (no
    // federation directory) → bypass entirely.
    if delegation_authority_gate_enabled {
        if let Some(required_scope) = delegation_scope_for_message_type(&envelope.message_type) {
            if let Some(fed_dir) = federation_directory_for_cohort {
                let trust_roots = {
                    let guard = delegation_trust_roots
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    guard.iter().cloned().collect::<Vec<_>>()
                };
                match verify_self_at_login_delegation(
                    &envelope.signing_key_id,
                    fed_dir,
                    &trust_roots,
                    required_scope,
                    delegation_graph_max_depth,
                )
                .await
                {
                    Ok(()) => {
                        // Authorized — fall through to fan-out + handler.
                    }
                    Err(sub_reason) => {
                        tracing::warn!(
                            event = "edge.delegation_gate.refused",
                            sender_key_id = %envelope.signing_key_id,
                            message_type = ?envelope.message_type,
                            required_scope = required_scope,
                            ?sub_reason,
                            "envelope REFUSED at delegation authority gate (CIRISEdge#108 part 2)",
                        );
                        let refusal_reason = RefusalReason::DelegationNotAuthorized {
                            required_scope: required_scope.to_owned(),
                            sub_reason,
                        };
                        if let Err(e) = emit_delivery_refusal_attestation(
                            &envelope,
                            body_sha256,
                            transport,
                            signer,
                            queue,
                            refusal_reason,
                        )
                        .await
                        {
                            tracing::warn!(
                                error = %e,
                                "DeliveryRefusalAttestation emission failed (CIRISEdge#108 part 2)",
                            );
                        }
                        return;
                    }
                }
            } else {
                // Gate enabled but no federation_directory wired —
                // structurally cannot verify; warn once and bypass.
                // (The bypass is intentional: tests + bootstrap paths
                // that flip the boolean before wiring persist would
                // otherwise refuse every envelope.)
                tracing::warn!(
                    event = "edge.delegation_gate.bypassed_no_directory",
                    "delegation_authority_gate_enabled but no federation_directory wired; bypassing gate (CIRISEdge#108 part 2)",
                );
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
    // CIRISEdge#184 (v6.3.0) — swarm-converger wire-up. Verified
    // `MessageType::FountainHoldingClaim` envelopes route into the
    // installed runtime's `register_observed_claim`. AV-9 verify-then-
    // dispatch invariant is preserved because we're past the verify
    // gate at this point. When no runtime is installed, the envelope
    // is observed but no hook fires (same posture as `blob_chunk_source`
    // for the chunked-blob swarm).
    if envelope.message_type == MessageType::FountainHoldingClaim {
        if let Some(runtime) = swarm_runtime {
            match serde_json::from_str::<crate::holonomic::swarm_rarity::FountainHoldingClaim>(
                envelope.body.get(),
            ) {
                Ok(claim) => {
                    runtime.register_observed_claim(claim).await;
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        transport = ?transport,
                        sender_key_id = %envelope.signing_key_id,
                        "FountainHoldingClaim body parse failed at dispatch (CIRISEdge#184)",
                    );
                }
            }
        }
    }

    // CC 0.7 opaque wire vocabulary (CIRISEdge#241, v8.0.0) — three
    // dispatch arms. Edge treats `payload` as opaque bytes throughout;
    // it holds no typed struct, no canonicalization, no Message-semantic
    // knowledge for any migrant (MISSION §1.3).
    //
    // OpaqueEvent → fan out to every per-`kind` subscriber (the generic
    // successor of the inline-text fan-out).
    if envelope.message_type == MessageType::OpaqueEvent {
        match serde_json::from_str::<crate::messages::OpaqueEvent>(envelope.body.get()) {
            Ok(ev) => {
                fan_out_opaque_event(
                    opaque_subscribers,
                    &envelope.signing_key_id,
                    ev.kind,
                    &ev.payload,
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    transport = ?transport,
                    "OpaqueEvent body parse failed at dispatch fan-out",
                );
            }
        }
    }

    // OpaqueResponse → correlate back to the pending `send_opaque_request`
    // via the envelope `in_reply_to` (the request's body_sha256).
    if envelope.message_type == MessageType::OpaqueResponse {
        match serde_json::from_str::<crate::messages::OpaqueResponse>(envelope.body.get()) {
            Ok(resp) => {
                if let Some(correlation) = envelope.in_reply_to {
                    let tx = {
                        let mut pending = opaque_request_pending
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        pending.remove(&correlation)
                    };
                    if let Some(tx) = tx {
                        let _ = tx.send(resp);
                    } else {
                        tracing::debug!(
                            transport = ?transport,
                            "OpaqueResponse with no matching pending request (late/duplicate)",
                        );
                    }
                } else {
                    tracing::warn!(
                        transport = ?transport,
                        "OpaqueResponse missing in_reply_to correlation token",
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    transport = ?transport,
                    "OpaqueResponse body parse failed at dispatch",
                );
            }
        }
    }

    // OpaqueRequest → dispatch to the per-`kind` handler; an unknown
    // `kind` is answered with a `501` OpaqueResponse (NEVER a silent
    // drop, MISSION §6 anti-pattern 7). The response is signed +
    // shipped back to the sender with `in_reply_to = request body_sha256`.
    if envelope.message_type == MessageType::OpaqueRequest {
        match serde_json::from_str::<crate::messages::OpaqueRequest>(envelope.body.get()) {
            Ok(req) => {
                let handler = {
                    let handlers = opaque_handlers
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    handlers.get(&req.kind).cloned()
                };
                let response = if let Some(h) = handler {
                    h(envelope.signing_key_id.clone(), req.payload)
                } else {
                    tracing::warn!(
                        kind = req.kind,
                        sender_key_id = %envelope.signing_key_id,
                        "OpaqueRequest for unknown kind; replying 501 (no silent drop)",
                    );
                    crate::messages::OpaqueResponse {
                        kind: req.kind,
                        status: 501,
                        payload: b"unknown kind".to_vec(),
                    }
                };
                // Ship the response back to the sender. Correlation rides
                // `in_reply_to = request body_sha256`.
                if let Some(transport) = response_transport {
                    match build_envelope(
                        MessageType::OpaqueResponse,
                        &signer.key_id,
                        &envelope.signing_key_id,
                        &response,
                        Some(body_sha256),
                    ) {
                        Ok(mut resp_env) => {
                            if let Err(e) = sign_envelope(signer, &mut resp_env).await {
                                tracing::warn!(error = %e, "OpaqueResponse sign failed");
                            } else {
                                match serde_json::to_vec(&resp_env) {
                                    Ok(bytes) => {
                                        if let Err(e) =
                                            transport.send(&envelope.signing_key_id, &bytes).await
                                        {
                                            tracing::warn!(
                                                error = %e,
                                                "OpaqueResponse transport send failed",
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(error = %e, "OpaqueResponse serialize failed");
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "OpaqueResponse envelope build failed");
                        }
                    }
                } else {
                    tracing::warn!(
                        "OpaqueRequest handled but no transport to ship the response back",
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    transport = ?transport,
                    "OpaqueRequest body parse failed at dispatch",
                );
            }
        }
    }

    // CIRISEdge#52 (v0.20.1) — multimedia tier sub-dispatch on
    // `MessageType::ContributionSubmit`. Inspects the body's
    // `subject_kind` discriminator (additive at v0.20.1 per
    // MEDIA_SHARING.md). The probe is observation-only — the
    // existing typed-handler dispatch below is preserved on every
    // branch (the sub-dispatch fires observables + the L1-CDN
    // prefetch stub, but does NOT consume the envelope).
    //
    // Branches (per MEDIA_SHARING.md §5.2 + §2.6 + §2.7):
    //
    //   1. `takedown_notice` + fast-path `legal_basis` (TVEC /
    //      GIFCT-CIP / NCMEC) → emit `edge.dispatch.takedown_fast_path`
    //      span event so observability streams see the
    //      legal-compliance trigger; pass through to handler.
    //   2. `key_grant` → emit `edge.dispatch.key_grant` event with
    //      the addressed `recipient_key_id`; edge does NOT
    //      gossip-propagate (KeyGrants ride point-to-point on the
    //      envelope's existing `destination_key_id`).
    //   3. Contribution carrying `blob_body.kind == "external"`
    //      AND `agent_mode == Server` (L1) AND
    //      `l1_cdn_edge_enabled` → `tokio::spawn` the prefetch
    //      stub (full impl deferred post-v1.0).
    //   4. Any other Contribution → pass through; the existing
    //      typed handler dispatch path picks it up unchanged.
    if envelope.message_type == MessageType::ContributionSubmit {
        let probe = crate::multimedia::ContributionDispatchProbe::from_body_bytes(
            envelope.body.get().as_bytes(),
        );
        match probe.typed_subject_kind() {
            Some(crate::multimedia::ContributionSubjectKind::TakedownNotice) => {
                if let Some(basis) = probe.fast_path_basis() {
                    tracing::info!(
                        event = "edge.dispatch.takedown_fast_path",
                        sender_key_id = %envelope.signing_key_id,
                        legal_basis = basis.as_str(),
                        content_sha256_hex = probe.content_sha256_hex.as_deref().unwrap_or(""),
                        "takedown_notice fast-path triggered (CIRISEdge#52)",
                    );
                    tracing::Span::current().record("multimedia_dispatch", "takedown_fast_path");
                    // Synthetic FederationAnnouncement to known
                    // holders: best-effort observability emission via
                    // the resource event channel. The federation-tier
                    // emission lands in a future cut (when persist's
                    // holds_bytes index reachable at edge); for now
                    // the tracing span IS the cross-peer observable
                    // (lens-core consumes the span and ships it).
                    events.emit_resource(crate::events::NetworkEvent::resource(
                        "takedown_fast_path",
                        1.0,
                        "count",
                        crate::events::EventSeverity::Warning,
                        basis.as_str(),
                    ));
                } else {
                    tracing::debug!(
                        event = "edge.dispatch.takedown_standard",
                        sender_key_id = %envelope.signing_key_id,
                        legal_basis = probe.legal_basis.as_deref().unwrap_or(""),
                        "takedown_notice standard-dispatch (non-fast-path legal_basis)",
                    );
                }
            }
            Some(crate::multimedia::ContributionSubjectKind::KeyGrant) => {
                tracing::info!(
                    event = "edge.dispatch.key_grant",
                    sender_key_id = %envelope.signing_key_id,
                    recipient_key_id = probe.recipient_key_id.as_deref().unwrap_or(""),
                    destination_key_id = %envelope.destination_key_id,
                    "key_grant addressed-delivery (point-to-point; not gossiped)",
                );
                tracing::Span::current().record("multimedia_dispatch", "key_grant");
                // Point-to-point semantics: edge's existing fan-out
                // is bound by `envelope.destination_key_id` already
                // (the Contribution rides Durable/Ephemeral classes;
                // no Mandatory broadcast); KeyGrants therefore do
                // NOT gossip-propagate by structural design — no
                // additional gate is needed at this hook.
            }
            None => {
                // Unknown / unset subject_kind — legacy Contribution
                // pre-v0.20.1, or a NodeCore subject_kind we don't
                // discriminate at the transport tier. Fall through
                // to the existing handler dispatch unchanged.
            }
        }

        // CIRISEdge#52 (v0.20.1) — L1-as-CDN-edge prefetch hook
        // per MEDIA_SHARING.md §2.7. Three conjunctive gates:
        // (1) operator declared L1 mode (`AgentMode::Server`),
        // (2) operator opted in via `l1_cdn_edge_enabled = true`,
        // (3) operator supplied an `l1_cdn_edge_external_uri_base`.
        // Client + Proxy modes IGNORE the flag regardless of its
        // value (spec §2.7 — "L1 operators can opt in").
        if matches!(agent_mode, AgentMode::Server)
            && l1_cdn_edge_enabled
            && probe.blob_body_kind.as_deref()
                == Some(crate::multimedia::ExternalRefWithAcl::WIRE_KIND)
        {
            if let (Some(uri), Some(sha_hex), Some(base)) = (
                probe.external_uri.clone(),
                probe.content_sha256_hex.clone(),
                l1_cdn_edge_external_uri_base.clone(),
            ) {
                tracing::info!(
                    event = "edge.l1_cdn_edge.prefetch_hook_fired",
                    external_uri = %uri,
                    external_sha256_hex = %sha_hex,
                    operator_base = %base,
                    "L1-as-CDN-edge prefetch hook fired (stub at v0.20.1)",
                );
                tokio::spawn(crate::multimedia::cdn_edge_prefetch_stub(
                    uri, sha_hex, base,
                ));
            } else {
                tracing::debug!(
                    event = "edge.l1_cdn_edge.prefetch_skipped_missing_fields",
                    "L1-CDN-edge enabled but external_uri/sha/base missing on this Contribution",
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
        // The CC 0.7 opaque wire types are dispatched above (subscriber
        // fan-out for OpaqueEvent, kind-keyed handler + 501 for
        // OpaqueRequest, correlation for OpaqueResponse) — a missing
        // typed `Handler<M>` entry for them is expected, not an error.
        // Suppress the `no handler registered` warning for those.
        if !matches!(
            envelope.message_type,
            MessageType::OpaqueEvent | MessageType::OpaqueRequest | MessageType::OpaqueResponse
        ) {
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

    /// v1.1.1 — supply an in-memory local-seed signer alongside the
    /// hot-path forensic signer. When the local signer's `key_id`
    /// matches the forensic signer's, `Edge::scrub_signer()` resolves
    /// to the local one so envelope signing skips the platform-keyring
    /// IPC. Mirrors CIRISPersist#137/#138 `select_signer` discipline
    /// on the edge side — closes the CIRISEdge#50 darwin headless-CI
    /// follow-on where keychain-IPC fails the durable-send sign step.
    #[must_use]
    pub fn local_signer(mut self, local_signer: Arc<LocalSigner>) -> Self {
        self.local_signer = Some(local_signer);
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

    /// CIRISEdge#48-B (v0.19.6) — supply a persist-backed trust-scoring
    /// resolver. When set AND
    /// [`EdgeConfig::trust_short_circuit_enabled`] is `true` AND
    /// [`EdgeConfig::trust_threshold`] is positive, the inbound
    /// dispatcher drops verified envelopes whose `signing_key_id`
    /// scores below the threshold (CIRISPersist#123, v3.4.0).
    ///
    /// Production callers (the cohabitation pyo3 init path) derive the
    /// scorer from the engine's `AdmissionGate`; tests can pass
    /// `MemoryTrustScoring` directly.
    #[must_use]
    pub fn trust_scoring(
        mut self,
        scoring: Arc<dyn ciris_persist::federation::TrustScoring>,
    ) -> Self {
        self.trust_scoring = Some(scoring);
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

    /// CIRISEdge#55 v3.4.0-pre1 — wire a [`crate::blob_swarm::BlobChunkSource`]
    /// hook so this edge can answer inbound `BlobChunkFetch` envelopes
    /// from its local blob store. Without it, edge silently drops
    /// inbound `BlobChunkFetch` envelopes (same posture as edge#21
    /// phase 1 `ContentFetch`). Consumer crates wrap their persist
    /// `BlobStorage` handle.
    #[must_use]
    pub fn blob_chunk_source(
        mut self,
        source: Arc<dyn crate::blob_swarm::BlobChunkSource>,
    ) -> Self {
        self.blob_chunk_source = Some(source);
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
        // CIRISEdge#55 — sibling pending-map for chunk fetches.
        let blob_chunk_fetch_pending = Arc::new(std::sync::Mutex::new(HashMap::new()));

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
            local_signer: self.local_signer,
            transports: self.transports,
            handlers: Arc::new(Mutex::new(HashMap::new())),
            opaque_subscribers: Arc::new(std::sync::Mutex::new(HashMap::new())),
            opaque_next_id: Arc::new(AtomicU64::new(1)),
            opaque_handlers: Arc::new(std::sync::Mutex::new(HashMap::new())),
            opaque_request_pending: Arc::new(std::sync::Mutex::new(HashMap::new())),
            verified_envelope_tx,
            content_fetch_pending,
            blob_chunk_fetch_pending,
            peer_directory: self.peer_directory,
            steward_directory: self.steward_directory,
            blob_chunk_source: self.blob_chunk_source,
            replication_registry: Arc::new(std::sync::OnceLock::new()),
            swarm_runtime: Arc::new(std::sync::OnceLock::new()),
            #[cfg(feature = "holonomic-consent-decay")]
            consent_decay_shutdown: Arc::new(std::sync::OnceLock::new()),
            subscription_filter: self.subscription_filter,
            events,
            display_name: Arc::new(std::sync::RwLock::new(display_name)),
            reachability,
            #[cfg(feature = "_reticulum-module")]
            reticulum_transport: self.reticulum_transport,
            federation_directory: self.federation_directory,
            detector,
            canonical_peers,
            trust_scoring: self.trust_scoring,
            trust_threshold_override: Arc::new(std::sync::RwLock::new(None)),
            trust_scoring_override: Arc::new(std::sync::RwLock::new(None)),
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

/// CC 0.7 (CIRISEdge#241) — fan out an inbound opaque event to every
/// subscriber registered for its `kind`. Lazily prunes entries whose
/// `send` returns `Err` (the consumer's receiver has been dropped —
/// channel-closed semantics). Free-function form because
/// `dispatch_inbound` is itself a free function — the
/// `Edge::fan_out_opaque_event_for_test` method is a thin wrapper for
/// non-dispatcher callers (tests, future embedders).
fn fan_out_opaque_event(
    opaque_subscribers: &std::sync::Mutex<HashMap<u64, OpaqueSubscriber>>,
    sender_key_id: &str,
    kind: u32,
    payload: &[u8],
) {
    let mut subs = opaque_subscribers
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if subs.is_empty() {
        return;
    }
    let mut dead: Vec<u64> = Vec::new();
    for (id, (sub_kind, tx)) in subs.iter() {
        if *sub_kind != kind {
            continue;
        }
        let msg = (sender_key_id.to_string(), kind, payload.to_vec());
        if tx.send(msg).is_err() {
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
        // CIRISEdge#336 — target dest has no route (un-routable dest, e.g. the
        // explicit-hash while the peer is only reachable on its named dest). A
        // distinct reachability class from a slow-link `timeout`: it is an
        // addressing/rooting fault the belt heals on the next verified announce.
        TransportError::NoRouteToPeer { .. } => "no_route_to_peer",
    }
}

fn message_type_str(mt: &MessageType) -> String {
    serde_json::to_value(mt)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{mt:?}"))
}

/// CIRISEdge#55 v3.4.0-pre1 — build + sign a typed `EdgeEnvelope`
/// carrying a `BlobChunkBody` or `BlobChunkMiss` response. Returns
/// the serialized bytes for enqueue. Pure helper; no queue side-effect.
async fn build_chunk_response_envelope<M: serde::Serialize>(
    message_type: MessageType,
    destination_key_id: &str,
    signer: &Arc<LocalSigner>,
    body: &M,
    in_reply_to: [u8; 32],
) -> Result<Vec<u8>, EdgeError> {
    let mut env = build_envelope(
        message_type,
        &signer.key_id,
        destination_key_id,
        body,
        Some(in_reply_to),
    )?;
    sign_envelope(signer, &mut env).await?;
    serde_json::to_vec(&env)
        .map_err(|e| EdgeError::Config(format!("chunk response envelope serialize: {e}")))
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

    // CIRISEdge#52 (v0.20.1) — multimedia tier: a `ContentBody`
    // carrying a `BlobBody::External` pointer (wire-form
    // `kind == "external"`) is NOT subject to the inline-bytes AV-13
    // size cap NOR the SHA-256 integrity gate. External multimedia
    // bytes ride the publisher's S3-class store directly; edge
    // carries only the metadata + ACL pointer. The consumer's
    // client is responsible for fetching from `external_uri` and
    // verifying the bytes against `external_sha256_hex` (NOT
    // against the envelope-level SHA — those are distinct hashes).
    //
    // Per MEDIA_SHARING.md §2.6 + THREAT_MODEL AV-49: edge does
    // NOT scrub external bytes (the scrub primitive is for
    // inline_text_pipeline only). The discriminator probe runs
    // BEFORE the inline-bytes parse so we don't fail-fast on a
    // body that intentionally lacks the inline `bytes` field.
    if is_external_content_body(envelope.body.get().as_bytes()) {
        return Ok(());
    }

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

/// CIRISEdge#52 (v0.20.1) — detect whether a `ContentBody` envelope
/// carries a `BlobBody::External` pointer (the multimedia-tier shape
/// per MEDIA_SHARING.md §2.6) vs the inline-bytes shape (v0.8.0+).
///
/// The discriminator lives at JSON `body.kind == "external"`. Probes
/// via a minimal `serde_json` parse — best-effort, returns `false`
/// on parse error (the calling site falls through to the inline-bytes
/// parse which surfaces the schema error via the standard AV-13
/// error path).
fn is_external_content_body(body_bytes: &[u8]) -> bool {
    #[derive(serde::Deserialize)]
    struct KindProbe {
        #[serde(default)]
        kind: Option<String>,
    }
    let probe: KindProbe = match serde_json::from_slice(body_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    probe.kind.as_deref() == Some(crate::multimedia::ExternalRefWithAcl::WIRE_KIND)
}

/// CIRISEdge#52 (v0.20.1) — minimal projection of the
/// `BlobBody::External` `ContentBody` wire shape used to correlate
/// the `fetch_content` pending channel by `external_sha256_hex`.
#[derive(serde::Deserialize)]
struct ContentBodyExternalProbe {
    external_uri: String,
    external_sha256_hex: String,
}

/// CIRISEdge#52 (v0.20.1) — hex-decode a 64-char SHA-256 hex string
/// to its raw 32-byte form, for the `content_fetch_pending` join
/// key. Returns `Err(())` on length / charset mismatch.
fn hex_to_sha256(hex_str: &str) -> Result<[u8; 32], ()> {
    if hex_str.len() != 64 {
        return Err(());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex_str.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| ())?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| ())?;
    }
    Ok(out)
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

    // Build a key_id → ed25519-pubkey map for O(1) per-sig lookup. The holder
    // set is small (3 by FSD spec), so a Vec scan is fine.
    let by_id: std::collections::HashMap<&str, &[u8; 32]> = holders
        .iter()
        .map(|h| (h.key_id.as_str(), &h.pubkey_ed25519))
        .collect();

    // CIRISEdge#359 finding 3 — the SEATED roster (one seat per human), pinned
    // by verify. `list_accord_holders` returns EVERY `accord_holder` row incl. a
    // human's spare (A2) as a distinct key_id, so counting distinct key_ids let
    // one human's primary+spare meet a 2-of-N alone. Count against the pinned
    // SEAT pubkeys instead, deduped by seat — a spare's key is not a seat, so it
    // contributes nothing, and one seat is counted once regardless of how many
    // of its keys sign.
    let seated: std::collections::HashSet<[u8; 32]> =
        ciris_verify_core::accord_genesis::accord_holder_bootstrap_anchor()
            .into_iter()
            .collect();

    let mut verified_seats = std::collections::HashSet::<[u8; 32]>::new();
    let mut any_attempted = false;
    for sig in &ann.accord_signatures {
        any_attempted = true;
        // The presented key_id MUST be a known accord holder …
        let Some(pubkey_bytes) = by_id.get(sig.key_id.as_str()) else {
            continue;
        };
        // … AND its key must occupy a pinned SEAT (finding 3 — excludes spares).
        if !seated.contains(*pubkey_bytes) {
            continue;
        }
        // CIRISEdge#359 finding 2 — verify the HYBRID (Ed25519 + ML-DSA-65)
        // signature under the require-hybrid policy (`HybridPolicy::Strict`
        // rejects a classical-only row: ml_dsa `None` ⇒ `HybridPendingRejected`).
        // The accord carrier is constitutional kill-switch-class traffic; a
        // classical-only signature must NOT count toward the quorum. The
        // directory holds both pubkeys, so `verify_hybrid_via_directory` gates
        // both signatures for us.
        let outcome = directory
            .verify_hybrid_via_directory(
                &canonical,
                &sig.key_id,
                &sig.signature_ed25519_base64,
                sig.signature_ml_dsa_65_base64.as_deref(),
                HybridPolicy::Strict,
                None,
            )
            .await;
        // Under RequireHybrid, `HybridVerified` is the ONLY success — the
        // Ed25519-only outcomes (`Ed25519VerifiedHybridPending` /
        // `…Fallback`) are unreachable under this policy, so this match is the
        // exact "both signatures verified" gate finding 2 requires.
        if matches!(outcome, Ok(VerifyOutcome::HybridVerified)) {
            verified_seats.insert(**pubkey_bytes);
        }
    }

    let found = u32::try_from(verified_seats.len()).unwrap_or(u32::MAX);
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

/// CIRISEdge#108 part 2 (v3.2.0, CEG §8.1.12.7) — scope tokens the
/// authority gate honors, mirroring persist v6.5.0's
/// `SELF_AT_LOGIN_DELEGATION_SCOPE` constants. Pinned locally so edge
/// doesn't import the const directly (and so a future persist rename
/// surfaces at this site instead of silently).
pub(crate) const SCOPE_MESSAGE_IO: &str = "message_io";
#[allow(dead_code)] // v3.2.x follow-up: FederationAnnouncement gate
pub(crate) const SCOPE_NETWORK_PRESENCE: &str = "network_presence";
#[allow(dead_code)] // v3.2.x follow-up: ContributionSubmit gate
pub(crate) const SCOPE_ACT_ON_BEHALF: &str = "act_on_behalf";
#[allow(dead_code)] // v3.2.x follow-up: depth > 1 chain gate
pub(crate) const SCOPE_SUB_DELEGATION: &str = "sub_delegation";

/// CIRISEdge#108 part 2 (v3.2.0) — federation-tier delegation authority
/// gate.
///
/// Persist v6.5.0's `Engine::self_at_login` (CEG §8.1.12.7) co-admits
/// an app occurrence + an agent occurrence under one identity key,
/// writes `delegates_to(user → agent, scope: SELF_AT_LOGIN_DELEGATION_SCOPE)`,
/// and promotes that delegation to the federation tier. Edge consumes
/// that promotion HERE: given an inbound envelope signed by some
/// `agent_key_X`, walk the federation directory to find a chain of
/// non-retracted `delegates_to` edges from a trusted root to
/// `agent_key_X` that carries `required_scope`.
///
/// # Algorithm (v7.0.0 — CIRISEdge#194)
///
/// 1. Empty trust-root set → `NoTrustRoots` (refuse; substrate not
///    bootstrapped for delegation-gated traffic).
/// 2. For each trust root call persist v10.0.0's
///    [`reachable_under_scope_with_reasons`] (CIRISPersist#272), which
///    runs the §11.10 `MODERATION_DUTY` scope-bearing `delegates_to`
///    walk and returns a typed [`ReachabilityVerdict`] discriminating
///    *why* a non-Reachable result was reached. The first `Reachable`
///    verdict admits.
/// 3. If no root admits, fold the per-root verdicts into the most
///    informative [`DelegationRefusalSubReason`] using a
///    most-specific-wins precedence:
///    `MissingScope > RetractedAtRoot > SubstrateUnavailable > SignerUnreached`.
///    The persist verdict `NoTrustRoots` (issuer emitted no delegation
///    edges at all) maps onto edge's `SignerUnreached` — the issuer
///    simply never delegated to anyone.
///
/// The persist walk handles depth bounding (`max_depth.min(MAX_WITHDRAWS_DELEGATION_DEPTH)`),
/// scope-bearing-edge ⊆-attenuation, deputization past depth 1
/// (`sub_delegation` gate), and per-edge `withdraws`/`recants`
/// skipping — collapsing edge's prior hand-rolled multi-root walk +
/// raw-envelope scope re-fetch onto persist's single canonical API.
/// SubstrateUnavailable verdict short-circuits the per-root walk
/// (persist returns it instead of `Err` so the `match` is total per
/// the v10.0.0 contract).
///
/// [`reachable_under_scope_with_reasons`]: ciris_persist::federation::admission::reachable_under_scope_with_reasons
/// [`ReachabilityVerdict`]: ciris_persist::federation::ReachabilityVerdict
async fn verify_self_at_login_delegation(
    signer_key: &str,
    directory: &Arc<dyn ciris_persist::federation::FederationDirectory>,
    trusted_roots: &[String],
    required_scope: &str,
    max_depth: usize,
) -> Result<(), crate::messages::DelegationRefusalSubReason> {
    use crate::messages::DelegationRefusalSubReason;
    use ciris_persist::federation::admission::reachable_under_scope_with_reasons;
    use ciris_persist::federation::ReachabilityVerdict;

    if trusted_roots.is_empty() {
        return Err(DelegationRefusalSubReason::NoTrustRoots);
    }

    // Cross-root accumulator: most-specific-wins folding. Each root's
    // verdict maps onto one of these flags. If any root admits, we
    // short-circuit; otherwise the precedence below picks the most
    // informative refusal.
    let mut saw_missing_scope = false;
    let mut saw_retracted = false;
    let mut saw_substrate_fault = false;
    // Both `SignerUnreached` and persist's `NoTrustRoots` (issuer
    // emitted no delegation edges) map onto edge's `SignerUnreached`
    // — they're indistinguishable from the gate's vantage. We don't
    // need a flag because it's the default fall-through.

    for root in trusted_roots {
        match reachable_under_scope_with_reasons(
            directory.as_ref(),
            root,
            signer_key,
            required_scope,
            max_depth,
        )
        .await
        {
            Ok(verdict) => match verdict {
                ReachabilityVerdict::Reachable => return Ok(()),
                ReachabilityVerdict::MissingScope => saw_missing_scope = true,
                ReachabilityVerdict::RetractedAtRoot => saw_retracted = true,
                ReachabilityVerdict::SubstrateUnavailable => {
                    tracing::warn!(
                        event = "edge.delegation_gate.substrate_fault",
                        root = %root,
                        "reachable_under_scope_with_reasons returned SubstrateUnavailable verdict",
                    );
                    saw_substrate_fault = true;
                }
                ReachabilityVerdict::SignerUnreached | ReachabilityVerdict::NoTrustRoots => {
                    // Both fall through to the default `SignerUnreached`
                    // refusal — the issuer's chain doesn't reach the
                    // target, whether by absence of edges or by absence
                    // of scoped paths.
                }
                // `#[non_exhaustive]` — a future persist refinement may
                // add reasons. Treat as substrate-fault until edge is
                // taught the new variant; refuse conservatively.
                _ => {
                    tracing::warn!(
                        event = "edge.delegation_gate.unknown_verdict",
                        root = %root,
                        verdict = ?verdict,
                        "ReachabilityVerdict variant unrecognized; refusing as substrate-fault",
                    );
                    saw_substrate_fault = true;
                }
            },
            Err(e) => {
                // The with-reasons walk reserves `Err` for argument
                // shape problems (per v10.0.0 contract: substrate read
                // failures come back as the `SubstrateUnavailable`
                // verdict, not `Err`). Conservative refuse.
                tracing::warn!(
                    event = "edge.delegation_gate.substrate_fault",
                    root = %root,
                    error = %e,
                    "reachable_under_scope_with_reasons returned Err",
                );
                saw_substrate_fault = true;
            }
        }
    }

    // Most-specific-wins precedence — a successful admit short-
    // circuits above; falling through means refuse.
    if saw_missing_scope {
        Err(DelegationRefusalSubReason::MissingScope)
    } else if saw_retracted {
        Err(DelegationRefusalSubReason::RetractedAtRoot)
    } else if saw_substrate_fault {
        Err(DelegationRefusalSubReason::SubstrateUnavailable)
    } else {
        Err(DelegationRefusalSubReason::SignerUnreached)
    }
}

/// CIRISEdge#108 part 2 (v3.2.0) — does the `scope` field on a
/// `delegates_to` envelope contain `wanted`?
///
/// The `self_at_login` envelope writes scope as a JSON **array** of
/// tokens (per persist v6.5.0
/// `src/federation/self_at_login.rs::delegates_to_agent_envelope`);
/// other delegation writers may use a string. Handle both shapes — a
/// non-`self_at_login` writer that emits a single string scope
/// matches when the string equals `wanted`.
///
/// v7.0.0 (CIRISEdge#194): no longer used by
/// `verify_self_at_login_delegation` (collapsed onto persist v10.0.0's
/// [`reachable_under_scope_with_reasons`]). Retained as `pub(crate)`
/// for its test coverage of the JSON-array vs string scope-shape
/// dispatch — a regression here would silently re-break the gate
/// against future delegation writers.
///
/// [`reachable_under_scope_with_reasons`]: ciris_persist::federation::admission::reachable_under_scope_with_reasons
#[allow(dead_code)]
fn envelope_scope_contains(envelope: &serde_json::Value, wanted: &str) -> bool {
    match envelope.get("scope") {
        Some(serde_json::Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(wanted)),
        Some(serde_json::Value::String(s)) => s == wanted,
        _ => false,
    }
}

/// CIRISEdge#108 part 2 (v3.2.0) — which scope token a given
/// `MessageType` requires for the delegation gate. Returns `None` for
/// MessageType variants where the gate does NOT apply.
///
/// CC 0.7 (CIRISEdge#241, v8.0.0): the message-io scope now gates the
/// opaque application-payload types [`MessageType::OpaqueRequest`] +
/// [`MessageType::OpaqueEvent`] — the successors of the migrated
/// inline-text family. `OpaqueResponse` is un-gated (it rides back to
/// an already-authorized requester). Every other variant returns `None`.
pub(crate) fn delegation_scope_for_message_type(mt: &MessageType) -> Option<&'static str> {
    match mt {
        MessageType::OpaqueRequest | MessageType::OpaqueEvent => Some(SCOPE_MESSAGE_IO),
        // follow-ups (deferred):
        //   FederationAnnouncement      → SCOPE_NETWORK_PRESENCE
        //   ContributionSubmit          → SCOPE_ACT_ON_BEHALF
        //   StewardDirective            → SCOPE_ACT_ON_BEHALF (TBD)
        //   OpaqueResponse              → un-gated (reply to authorized peer)
        //   DeliveryAttestation         → un-gated (substrate-emitted)
        //   DeliveryRefusalAttestation  → un-gated (substrate-emitted)
        //   ContentMiss / ContentBody   → un-gated (content-routing)
        _ => None,
    }
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

/// CIRISEdge#108 part 2 (v3.2.0) — local mirror of persist v6.5.0
/// `SELF_AT_LOGIN_DELEGATION_SCOPE` for test fixtures only. Persist's
/// constant is `[&str; 4]` of `&'static str`; we mirror the bytes here
/// so the test module can pass `&SELF_AT_LOGIN_SCOPE_TOKENS` without
/// pulling persist's const into the runtime path (the gate logic
/// itself parses the tokens out of the envelope's `scope` JSON
/// array — it has no compile-time dependency on the constant).
#[cfg(test)]
const SELF_AT_LOGIN_SCOPE_TOKENS: [&str; 4] = [
    SCOPE_ACT_ON_BEHALF,
    SCOPE_MESSAGE_IO,
    SCOPE_NETWORK_PRESENCE,
    SCOPE_SUB_DELEGATION,
];

// ── CIRISEdge#108 part 2 (v3.2.0-pre1) — delegation gate tests ─────
#[cfg(test)]
mod delegation_gate_tests {
    //! Unit coverage for [`verify_self_at_login_delegation`] + the
    //! supporting envelope helpers. The fixtures mirror the persist
    //! v6.5.0 `Engine::self_at_login` write shape (CEG §8.1.12.7):
    //! `attestation_type = "delegates_to"`, envelope with
    //! `kind: "delegates_to"`, `dimension:
    //! "self:delegates_to:agent_occurrence:v1"`, `scope: [...]`.
    //!
    //! v6.3.2 (CIRISEdge#166): the seed builders carry **REAL** hybrid
    //! PQC signatures so they pass the persist v9.0.0 federation-tier
    //! ingest gate (`verify_federation_tier_ingest`, CC 5.3.2.4.3.1).
    //! See [`fixture_sigs`] below for the deterministic-keypair pattern.
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use ciris_crypto::{ClassicalSigner as _, Ed25519Signer, MlDsa65Signer, PqcSigner as _};
    use ciris_persist::federation::types::{
        algorithm, attestation_type as att_type, identity_type, Attestation, KeyRecord,
        SignedAttestation, SignedKeyRecord,
    };
    use ciris_persist::store::MemoryBackend;
    use sha2::{Digest as _, Sha256};

    // ── v6.3.2 fixture-signature helpers ────────────────────────────
    //
    // Mirrors persist's `federation::tier_ingest::test_support` shape
    // (`pub(crate)` over there, so we replicate here). Deterministic
    // per-`key_id` Ed25519 + ML-DSA-65 keypair → the registered key
    // and the signing key collapse to the same identity without
    // threading a signer through every fixture call.
    //
    // Canonicalizer: persist v10.0.0 (#273) re-exports
    // `ceg_produce_canonicalize` from its prelude — same RFC 8785 JCS
    // bytes the federation-tier ingest gate verifies against, but
    // routed through persist's V2Jcs `produce_canon_version()` gate so
    // a future canon flip lands without touching this fixture surface.
    // This replaces the v6.3.2 direct `ciris_verify_core::jcs::canonicalize`
    // call, fixing the layering inversion where fixtures reached past
    // persist to a sibling crate.

    /// Deterministic 32-byte seed for `key_id` — the first ≤32 bytes
    /// of the key_id over a `0x11` fill. Same shape persist uses for
    /// its own tier-ingest fixtures, so corpora stay coherent.
    fn seed_for(key_id: &str) -> [u8; 32] {
        let mut seed = [0x11u8; 32];
        for (i, b) in key_id.bytes().take(32).enumerate() {
            seed[i] = b;
        }
        seed
    }

    /// `key_id`'s registered hybrid pubkeys, base64. Fills a
    /// `KeyRecord`'s `pubkey_ed25519_base64` /
    /// `pubkey_ml_dsa_65_base64` so the registered key matches what
    /// [`sign_attestation_envelope`] signs with.
    fn hybrid_pubkeys(key_id: &str) -> (String, Option<String>) {
        let ed = Ed25519Signer::from_seed(&seed_for(key_id)).expect("ed seed");
        // ML-DSA-65 secret key is multi-KiB; box it to keep async
        // test frames small.
        let mldsa = Box::new(MlDsa65Signer::from_seed(&seed_for(key_id)).expect("mldsa seed"));
        let ed_pk = B64.encode(ed.public_key().expect("ed pk"));
        let mldsa_pk = B64.encode(mldsa.public_key().expect("mldsa pk"));
        (ed_pk, Some(mldsa_pk))
    }

    /// Hybrid-sign `envelope` (through the CEG produce canonicalizer
    /// — JCS / RFC 8785) with `signing_key_id`'s deterministic keys.
    /// Returns `(original_content_hash, scrub_signature_classical,
    /// scrub_signature_pqc)` — the three fields the federation-tier
    /// ingest gate verifies. PQC half signs the bound payload
    /// `canonical || ed25519_sig` (CC 3.1.2.1 strip-attack guard).
    fn sign_attestation_envelope(
        signing_key_id: &str,
        envelope: &serde_json::Value,
    ) -> (String, String, Option<String>) {
        let ed = Ed25519Signer::from_seed(&seed_for(signing_key_id)).expect("ed seed");
        let mldsa =
            Box::new(MlDsa65Signer::from_seed(&seed_for(signing_key_id)).expect("mldsa seed"));
        // v7.0.0 (CIRISEdge#194): persist v10.0.0 re-exports
        // `ceg_produce_canonicalize` from its prelude (#273), so the
        // fixture layering inverts back: edge calls into persist for
        // canonicalization rather than reaching past persist to
        // `ciris-verify-core`. Byte-identical output — both sides route
        // through `V2Jcs::canonicalize_value` (RFC 8785 JCS).
        let canonical =
            ciris_persist::prelude::ceg_produce_canonicalize(envelope).expect("ceg canonicalize");
        let original_content_hash = hex::encode(Sha256::digest(&canonical));
        let ed_sig = ed.sign(&canonical).expect("ed sign");
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = mldsa.sign(&bound).expect("mldsa sign");
        (
            original_content_hash,
            B64.encode(&ed_sig),
            Some(B64.encode(&pqc_sig)),
        )
    }

    fn key_record(key_id: &str, identity_type_: &str) -> KeyRecord {
        let now = Utc::now();
        let (ed_pk, mldsa_pk) = hybrid_pubkeys(key_id);
        // KeyRecord rows are NOT subject to the attestation-tier
        // ingest gate; persist's `put_public_key` does not
        // hybrid-verify the registration. Only the PUBKEYS must be
        // real, so the attestations signed by this key verify against
        // the directory entry. The scrub fields stay placeholders.
        KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: algorithm::HYBRID.into(),
            identity_type: identity_type_.into(),
            identity_ref: format!("{identity_type_}-ref-{key_id}"),
            valid_from: now,
            valid_until: None,
            registration_envelope: serde_json::json!({
                "key_id": key_id,
                "identity_type": identity_type_,
            }),
            original_content_hash: "0".repeat(64),
            scrub_signature_classical: "x".repeat(88),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.into(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// Build a `delegates_to` Attestation row matching the persist
    /// v6.5.0 `self_at_login` shape: scope as JSON array.
    #[allow(clippy::similar_names)] // granter/grantee mirrors persist's column names
    fn delegates_to_row(granter: &str, grantee: &str, scope: &[&str]) -> Attestation {
        let now = Utc::now();
        let envelope = serde_json::json!({
            "kind": "delegates_to",
            "dimension": "self:delegates_to:agent_occurrence:v1",
            "agent_occurrence_key_id": grantee,
            "bilateral_pair_id": format!("pair-{granter}-{grantee}"),
            "scope": scope,
        });
        let (hash, ed_sig, pqc_sig) = sign_attestation_envelope(granter, &envelope);
        Attestation {
            attestation_id: format!("att-{granter}-{grantee}"),
            attesting_key_id: granter.into(),
            attested_key_id: grantee.into(),
            attestation_type: att_type::DELEGATES_TO.into(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: hash,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: granter.into(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".into(),
            tier: "federation".into(),
            promoted_at: None,
        }
    }

    fn withdraws_row(granter: &str, target: &str) -> Attestation {
        let now = Utc::now();
        let envelope = serde_json::json!({
            "kind": "withdraws",
            "dimension": "withdraws:self:delegates_to:agent_occurrence:v1",
            "target_attestation_id": format!("att-{granter}-{target}"),
        });
        let (hash, ed_sig, pqc_sig) = sign_attestation_envelope(granter, &envelope);
        Attestation {
            attestation_id: format!("withdraws-{granter}-{target}"),
            attesting_key_id: granter.into(),
            attested_key_id: target.into(),
            attestation_type: att_type::WITHDRAWS.into(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: hash,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: granter.into(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".into(),
            tier: "federation".into(),
            promoted_at: None,
        }
    }

    async fn seed_keys(backend: &Arc<MemoryBackend>, keys: &[(&str, &str)]) {
        use ciris_persist::federation::FederationDirectory;
        for (kid, itype) in keys {
            backend
                .put_public_key(SignedKeyRecord {
                    record: key_record(kid, itype),
                })
                .await
                .expect("seed key");
        }
    }

    async fn seed_attestation(backend: &Arc<MemoryBackend>, att: Attestation) {
        use ciris_persist::federation::FederationDirectory;
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .expect("seed attestation");
    }

    #[test]
    fn envelope_scope_contains_handles_array_string_and_missing() {
        // self_at_login shape: array.
        let v = serde_json::json!({"scope": ["act_on_behalf", "message_io"]});
        assert!(envelope_scope_contains(&v, SCOPE_MESSAGE_IO));
        assert!(!envelope_scope_contains(&v, SCOPE_NETWORK_PRESENCE));
        // Other-writer shape: single string.
        let v = serde_json::json!({"scope": "message_io"});
        assert!(envelope_scope_contains(&v, SCOPE_MESSAGE_IO));
        assert!(!envelope_scope_contains(&v, SCOPE_ACT_ON_BEHALF));
        // Missing/malformed.
        let v = serde_json::json!({});
        assert!(!envelope_scope_contains(&v, SCOPE_MESSAGE_IO));
        let v = serde_json::json!({"scope": 42});
        assert!(!envelope_scope_contains(&v, SCOPE_MESSAGE_IO));
    }

    #[test]
    fn scope_map_gates_opaque_application_types() {
        // CC 0.7 (CIRISEdge#241): OpaqueRequest + OpaqueEvent are gated
        // on message_io; every other variant returns None.
        assert_eq!(
            delegation_scope_for_message_type(&MessageType::OpaqueRequest),
            Some(SCOPE_MESSAGE_IO),
        );
        assert_eq!(
            delegation_scope_for_message_type(&MessageType::OpaqueEvent),
            Some(SCOPE_MESSAGE_IO),
        );
        assert_eq!(
            delegation_scope_for_message_type(&MessageType::OpaqueResponse),
            None,
        );
        assert_eq!(
            delegation_scope_for_message_type(&MessageType::FederationAnnouncement),
            None,
        );
        assert_eq!(
            delegation_scope_for_message_type(&MessageType::ContributionSubmit),
            None,
        );
        assert_eq!(
            delegation_scope_for_message_type(&MessageType::DeliveryAttestation),
            None,
        );
    }

    #[tokio::test]
    async fn empty_trust_roots_refuses_with_no_trust_roots() {
        let backend = Arc::new(MemoryBackend::new());
        seed_keys(&backend, &[("agent", identity_type::AGENT)]).await;
        let dir: Arc<dyn ciris_persist::federation::FederationDirectory> = backend;
        let out = verify_self_at_login_delegation(
            "agent",
            &dir,
            &[], // no trust roots
            SCOPE_MESSAGE_IO,
            4,
        )
        .await;
        assert_eq!(
            out,
            Err(crate::messages::DelegationRefusalSubReason::NoTrustRoots),
        );
    }

    // v6.3.2 (CIRISEdge#166): real hybrid PQC fixture sigs now wired
    // through `sign_attestation_envelope` above — these tests admit
    // through persist v9.0.0's federation-tier ingest gate (CC
    // 5.3.2.4.3.1). Prior to v6.3.2 they were `#[ignore]`d behind a
    // placeholder-signature fixture pattern.
    #[tokio::test]
    async fn happy_path_admits_signer_reached_via_in_scope_chain() {
        let backend = Arc::new(MemoryBackend::new());
        seed_keys(
            &backend,
            &[
                ("user-root", identity_type::USER),
                ("agent", identity_type::AGENT),
            ],
        )
        .await;
        seed_attestation(
            &backend,
            delegates_to_row("user-root", "agent", &super::SELF_AT_LOGIN_SCOPE_TOKENS),
        )
        .await;
        let dir: Arc<dyn ciris_persist::federation::FederationDirectory> = backend;
        let out = verify_self_at_login_delegation(
            "agent",
            &dir,
            &["user-root".into()],
            SCOPE_MESSAGE_IO,
            4,
        )
        .await;
        assert_eq!(out, Ok(()));
    }

    #[tokio::test]
    async fn missing_delegation_refuses_with_signer_unreached() {
        let backend = Arc::new(MemoryBackend::new());
        seed_keys(
            &backend,
            &[
                ("user-root", identity_type::USER),
                ("agent", identity_type::AGENT),
            ],
        )
        .await;
        // NO attestation seeded — the user never delegated to the
        // agent.
        let dir: Arc<dyn ciris_persist::federation::FederationDirectory> = backend;
        let out = verify_self_at_login_delegation(
            "agent",
            &dir,
            &["user-root".into()],
            SCOPE_MESSAGE_IO,
            4,
        )
        .await;
        assert_eq!(
            out,
            Err(crate::messages::DelegationRefusalSubReason::SignerUnreached),
        );
    }

    #[tokio::test]
    async fn retracted_delegation_refuses_with_retracted_at_root() {
        let backend = Arc::new(MemoryBackend::new());
        seed_keys(
            &backend,
            &[
                ("user-root", identity_type::USER),
                ("agent", identity_type::AGENT),
            ],
        )
        .await;
        seed_attestation(
            &backend,
            delegates_to_row("user-root", "agent", &super::SELF_AT_LOGIN_SCOPE_TOKENS),
        )
        .await;
        // Same granter retracts the delegation — persist's
        // build_delegation_graph buckets the retraction and stamps
        // `withdrawn_by` on the DelegationEdge.
        seed_attestation(&backend, withdraws_row("user-root", "agent")).await;
        let dir: Arc<dyn ciris_persist::federation::FederationDirectory> = backend;
        let out = verify_self_at_login_delegation(
            "agent",
            &dir,
            &["user-root".into()],
            SCOPE_MESSAGE_IO,
            4,
        )
        .await;
        assert_eq!(
            out,
            Err(crate::messages::DelegationRefusalSubReason::RetractedAtRoot),
        );
    }

    #[tokio::test]
    async fn delegation_without_required_scope_refuses_with_missing_scope() {
        let backend = Arc::new(MemoryBackend::new());
        seed_keys(
            &backend,
            &[
                ("user-root", identity_type::USER),
                ("agent", identity_type::AGENT),
            ],
        )
        .await;
        // Delegate ONLY network_presence — the InlineText path
        // requires message_io, so the gate refuses on scope.
        seed_attestation(
            &backend,
            delegates_to_row("user-root", "agent", &[SCOPE_NETWORK_PRESENCE]),
        )
        .await;
        let dir: Arc<dyn ciris_persist::federation::FederationDirectory> = backend;
        let out = verify_self_at_login_delegation(
            "agent",
            &dir,
            &["user-root".into()],
            SCOPE_MESSAGE_IO,
            4,
        )
        .await;
        assert_eq!(
            out,
            Err(crate::messages::DelegationRefusalSubReason::MissingScope),
        );
    }

    // v7.0.0 (CIRISEdge#194): the cross-root precedence the
    // verdict-routing fold uses (`MissingScope > RetractedAtRoot >
    // SubstrateUnavailable > SignerUnreached`). Two trusted roots:
    // one delegates the wrong scope (→ persist returns `MissingScope`
    // verdict), one retracts (→ persist returns `RetractedAtRoot`).
    // The fold must surface `MissingScope` — the most informative
    // signal across the union.
    #[tokio::test]
    async fn multi_root_fold_prefers_missing_scope_over_retracted() {
        let backend = Arc::new(MemoryBackend::new());
        seed_keys(
            &backend,
            &[
                ("user-root-A", identity_type::USER),
                ("user-root-B", identity_type::USER),
                ("agent", identity_type::AGENT),
            ],
        )
        .await;
        // Root A: delegate wrong-scope only — persist sees a
        // present-but-unscoped edge → `MissingScope` verdict.
        seed_attestation(
            &backend,
            delegates_to_row("user-root-A", "agent", &[SCOPE_NETWORK_PRESENCE]),
        )
        .await;
        // Root B: delegate the right scope, then retract — persist
        // sees a scope-bearing-but-retracted edge → `RetractedAtRoot`.
        seed_attestation(
            &backend,
            delegates_to_row("user-root-B", "agent", &super::SELF_AT_LOGIN_SCOPE_TOKENS),
        )
        .await;
        seed_attestation(&backend, withdraws_row("user-root-B", "agent")).await;
        let dir: Arc<dyn ciris_persist::federation::FederationDirectory> = backend;
        let out = verify_self_at_login_delegation(
            "agent",
            &dir,
            &["user-root-A".into(), "user-root-B".into()],
            SCOPE_MESSAGE_IO,
            4,
        )
        .await;
        // Most-specific-wins precedence picks MissingScope (it carries
        // strictly more information than RetractedAtRoot).
        assert_eq!(
            out,
            Err(crate::messages::DelegationRefusalSubReason::MissingScope),
        );
    }
}

#[cfg(test)]
mod inbound_ingest_tests {
    //! CIRISEdge#348 — the shared transport→replication ingest hop. These guard
    //! the exact seam that silently swallowed anti-entropy round-opens on the
    //! agent: a CRPL replication frame MUST be consumed by `route_replication_frame`
    //! (routed to replication, never envelope-dispatched), and a plain envelope
    //! MUST fall through. Both inbound loops (`run` + `spawn_background_listeners`)
    //! call this ONE function, so they cannot diverge again.
    use super::*;
    use crate::replication::protocol::{EnvelopeKind, ReplicationMessage, SummaryMessage};
    use crate::replication::registry::ReplicationRegistry;
    use crate::transport::TransportId;

    fn frame(bytes: Vec<u8>, source: Option<&str>) -> InboundFrame {
        InboundFrame {
            envelope_bytes: bytes,
            transport: TransportId::RETICULUM_RS,
            received_at: chrono::Utc::now(),
            source_key_id: source.map(str::to_string),
        }
    }

    /// A CRPL frame with attribution is CONSUMED by replication ingest (returns
    /// `true` ⇒ the caller must NOT envelope-dispatch it) — even with no
    /// coordinator (it's dropped LOUDLY, not fed to the JSON verifier). This is
    /// exactly what the agent's loop failed to do before #348.
    #[tokio::test]
    async fn crpl_frame_is_consumed_by_replication_ingest() {
        let registry = std::sync::Arc::new(ReplicationRegistry::new());
        let crpl =
            crate::replication::wire_frame::wrap(&ReplicationMessage::Summary(SummaryMessage {
                kind: EnvelopeKind::Key,
                refs: vec![],
            }));
        assert!(
            route_replication_frame(Some(&registry), &frame(crpl, Some("agent-peer"))).await,
            "a CRPL replication frame MUST be consumed by ingest, never envelope-dispatched (#348)",
        );
    }

    /// A plain (non-CRPL) envelope FALLS THROUGH to envelope dispatch.
    #[tokio::test]
    async fn plain_envelope_falls_through_to_dispatch() {
        let registry = std::sync::Arc::new(ReplicationRegistry::new());
        assert!(
            !route_replication_frame(
                Some(&registry),
                &frame(
                    b"{\"edge_schema_version\":\"2.0.0\"}".to_vec(),
                    Some("agent-peer")
                )
            )
            .await,
            "a plain envelope must fall through to envelope dispatch",
        );
    }

    /// No replication runtime installed → always fall through (envelope dispatch
    /// handles everything, as on a node with no replication configured).
    #[tokio::test]
    async fn no_registry_falls_through() {
        let crpl =
            crate::replication::wire_frame::wrap(&ReplicationMessage::Summary(SummaryMessage {
                kind: EnvelopeKind::Key,
                refs: vec![],
            }));
        assert!(!route_replication_frame(None, &frame(crpl, Some("agent-peer"))).await);
    }
}
