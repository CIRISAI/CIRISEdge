//! `ciris-edge` — Reticulum-native federation transport for the CIRIS stack.
//!
//! Edge handles wire I/O. Persist handles substrate. Host code handles
//! peer-specific reasoning. One shape, many peers.
//!
//! See [`MISSION.md`](../../MISSION.md) for M-1 alignment per module,
//! [`FSD/CIRIS_EDGE.md`](../../FSD/CIRIS_EDGE.md) for the architecture,
//! [`docs/THREAT_MODEL.md`](../../docs/THREAT_MODEL.md) for the v0.1.0
//! P0 invariants (AV-9 + AV-13 + AV-14 + AV-17 + hybrid-verify-via-persist).
//!
//! # Public API
//!
//! - [`Edge`] / [`EdgeBuilder`] — top-level construction and lifecycle.
//! - [`Handler`] / [`Message`] — typed handler registration with
//!   compile-time delivery-class enforcement (OQ-09 closure).
//! - [`Transport`] — trait for network media (HTTP fallback in Phase 1;
//!   Reticulum-rs canonical; LoRa / serial / I²P at Phase 3).
//! - [`EdgeEnvelope`] — the signed wire envelope.
//! - [`HybridPolicy`] / [`VerifyOutcome`] — consumer-side PQC policy
//!   (OQ-11 closure: day-1 hybrid Ed25519 + ML-DSA-65 verify).

// v0.9.2 (CIRISEdge#22 cohabitation) — relaxed from `forbid` to `deny`
// to allow the scoped `PyCapsule` extraction helpers in
// `src/ffi/pyo3.rs` (`extract_capsule`) to opt into `unsafe` with a
// documented `#[allow(unsafe_code)]` + `# Safety` block. Everywhere
// else in the crate, `unsafe` is still rejected.
//
// v0.13.0 (CIRISEdge#36 GO) — further relaxed for the `ffi-uniffi`
// path. UniFFI's generated scaffolding emits `unsafe extern "C"`
// FFI-shim functions (`uniffi_ciris_edge_fn_func_*`) and
// `unsafe(no_mangle)` static-export attributes; the
// `uniffi::include_scaffolding!("ciris_edge");` macro pulls that
// generated code into the crate root. The `unsafe_code` lint is
// scoped down to `deny` (not `forbid`) so the macro-expanded code
// can opt in via its internal `#[allow(unsafe_code)]` markers.
// No new hand-written `unsafe` is introduced in this crate.
// v0.13.0 — `unsafe_code` is `deny` when `ffi-uniffi` is off (the
// PyCapsule extract_capsule helper opts in via #[allow] at item scope)
// and downgraded to `allow` when `ffi-uniffi` is on. The
// `include_scaffolding!` macro emits ~30 `#[unsafe(no_mangle)]`
// FFI-shim items whose item-level `#[allow]` doesn't propagate; the
// macro's `#![allow(...)]` inner attribute is rejected (inner attrs
// can't follow non-module items). The least-invasive fix is the
// crate-level downgrade — every hand-written `unsafe` site in the
// crate is still scoped behind its own audit comment + #[allow], so
// the downgrade only loosens the scaffolding-generated items.
#![cfg_attr(not(feature = "ffi-uniffi"), deny(unsafe_code))]
#![deny(rust_2018_idioms)]
#![doc(html_root_url = "https://docs.rs/ciris-edge/0.1.0-pre1")]

pub mod blob_swarm;
pub mod cohort_scope;
#[cfg(feature = "debug-tools")]
pub mod debug;
pub mod detector;
// v6.1.0 (CIRISEdge#175, FSD §3.3) — announce-suppression policy
// + edge-side registry mirroring the recommended Leviculum
// `AnnounceControl` extension shape.
pub mod announce_suppression;
// v6.0.0 (CIRISEdge#175, FSD §3.3) — cached federation directory.
pub mod directory_cache;
// v6.1.0 (CIRISEdge#175, FSD §3.3) — federation_keys anti-entropy
// driver: pulls DirectoryEvents off an mpsc channel and applies
// them to the cache (the v6.1.0-promised active driver).
pub mod directory_cache_driver;
mod edge;
// v6.1.0 (CIRISEdge#175, FSD §3.1) — Poisson emission discipline
// with substrate-maintenance cover.
pub mod emission;
pub mod events;
pub mod ffi;
pub mod handler;
// v3.9.0 Layer 1 Task D introduced consent-decay (gated under
// `holonomic-consent-decay`); v3.10.0 lands the four-piece holonomic
// substrate bundle — swarm rarity (#134), WholenessWitness (#135),
// deterministic ALM (#136), recursive trust bootstrap (#137).  The
// four v3.10.0 modules are always compiled; `consent_decay` keeps its
// per-feature gate inside `holonomic::mod`.
pub mod holonomic;
pub mod identity;
pub mod key_boundary;
pub mod manifest;
pub mod messages;
// v6.0.0 (CIRISEdge#175, FSD §3.3 / §3.5 / §6) — substrate-tier MLS
// state for scope-native privacy. Distinct from
// `transport::realtime_av_mls` (per-stream AV MLS).
pub mod mls;
pub mod multimedia;
pub mod observability;
pub mod outbound;
pub mod reachability;
pub mod replication;
pub mod sas;
mod sas_wordlist;
// v6.0.0 (CIRISEdge#175) — CC 1.13.3.4 substrate.
pub mod scope_privacy;
pub mod swarm;
pub mod transport;
pub mod verify;
pub mod version;

/// CC 0.7 wire-vocabulary pin (CIRISEdge#241, v8.0.0). The SHA-256 of
/// `WIRE_VOCABULARY.md` v1.0.1 §3.3 as ratified for the opaque-payload
/// break. Downstream conformance harnesses assert this const matches
/// the spec byte-hash they carry, so an accidental vocabulary drift
/// (new typed variant re-introduced, opaque contract changed) is a
/// compile-visible pin failure rather than a silent wire skew.
///
/// sha256 = c6bd6aa44111b226a6f204801b1afaa7153fb43296652c1f7cbc23228ac9346c
pub const WIRE_VOCABULARY_HASH: [u8; 32] = [
    0xc6, 0xbd, 0x6a, 0xa4, 0x41, 0x11, 0xb2, 0x26, 0xa6, 0xf2, 0x04, 0x80, 0x1b, 0x1a, 0xfa, 0xa7,
    0x15, 0x3f, 0xb4, 0x32, 0x96, 0x65, 0x2c, 0x1f, 0x7c, 0xbc, 0x23, 0x22, 0x8a, 0xc9, 0x34, 0x6c,
];

#[cfg(test)]
mod wire_vocabulary_hash_tests {
    use super::WIRE_VOCABULARY_HASH;

    /// Pins the CC 0.7 wire-vocabulary hash to its hex source of truth.
    /// A drift here is a coordinated wire-break signal, not a bug fix.
    #[test]
    fn wire_vocabulary_hash_pinned() {
        const HEX: &str = "c6bd6aa44111b226a6f204801b1afaa7153fb43296652c1f7cbc23228ac9346c";
        let mut expected = [0u8; 32];
        for (i, byte) in expected.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&HEX[i * 2..i * 2 + 2], 16).unwrap();
        }
        assert_eq!(WIRE_VOCABULARY_HASH, expected);
    }
}

pub use blob_swarm::{
    BlobChunkSource, BlobChunkVerifier, ChunkManifestLite, ChunkSourceRefusal, ChunkVerifyError,
    PeerState, SwarmConfig, SwarmError, SwarmScheduler,
};
pub use cohort_scope::{CohortScope, CohortScopeEnforcement, CryptoTier};
// v6.0.0 (CIRISEdge#175) — scope-native privacy surface re-exports.
pub use announce_suppression::{should_suppress_announce, AnnounceSuppressionRegistry};
pub use detector::{
    ConsentRole, DetectionVerdict, EdgeDetectionAdmission, ProbePatternConfig,
    ProbePatternObserver, ProbePatternState,
};
pub use directory_cache::{
    DirectoryCache, DirectoryRecord, FederationKeyId, IdentityType, Reachability, XWingPublic,
};
// v6.1.0 (CIRISEdge#175, FSD §3.3) — anti-entropy driver surface.
pub use directory_cache_driver::{
    channel as directory_event_channel, DirectoryAntiEntropyDriver, DirectoryEvent,
    DirectoryEventReceiver, DirectoryEventSender, DriverStats as DirectoryDriverStats,
    DEFAULT_CHANNEL_CAPACITY as DIRECTORY_DRIVER_CHANNEL_CAPACITY,
};
pub use edge::{
    reseed_canonical_bootstrap_peers, run_blackhole_pruner, AgentMode, CanonicalBootstrapPeer,
    ChunkResult, ContentResult, Edge, EdgeBuilder, EdgeConfig, EdgeError, PublishOutcome,
    VerifiedEnvelopeSnapshot, DEFAULT_BLACKHOLE_PRUNE_INTERVAL_SECONDS,
};
// v6.1.0 (CIRISEdge#175, FSD §3.1) — Poisson emission surface.
pub use emission::{
    seal_envelope, unseal_envelope, BudgetMeter, BudgetState, EmissionEnvelope,
    EmissionEnvelopeError, EmissionHeader, EnvelopeType, PoissonScheduler, Reassembler,
    ReassemblyOutcome, Scheduler as EmissionScheduler, SchedulerConfig as EmissionSchedulerConfig,
    SchedulerHandle as EmissionSchedulerHandle, SchedulerStats as EmissionSchedulerStats,
    ScopeKey as EmissionScopeKey, SubmitError as EmissionSubmitError, ENVELOPE_BYTES,
    MAX_PAYLOAD_BYTES,
};
pub use events::{
    EventBus, EventKind, EventSeverity, NetworkEvent, PathEvent, ResourceEvent,
    DEFAULT_EVENT_CHANNEL_CAPACITY,
};
pub use handler::{
    AbandonReason, Delivery, DurableHandle, DurableOutcome, DurableStatus, FederationPriority,
    Handler, HandlerContext, HandlerError, Message,
};
pub use identity::LocalSigner;
pub use key_boundary::{
    KeyBoundaryParseError, KeyBoundaryScope, KEY_BOUNDARY_PREFIX, KEY_BOUNDARY_SUFFIX,
    LEGACY_NO_SEED_IN_HEAP,
};
pub use messages::{
    is_federation_attestation_emitting_type, AccordCarrier, AccordSignature, AnnouncementKind,
    AnnouncementPriority, AttestationGossip, AttestationRef, AuthorityClass,
    BuildManifestPublication, BuildManifestPublicationResponse, ContentBody, ContentFetch,
    ContentMiss, DSARRequest, DSARResponse, DeliveryAttestation, DeliveryAttestationError,
    DeliveryRefusalAttestation, EdgeEnvelope, FederationAnnouncement, GoalDeclaration,
    GoalDeclarationResponse, GoalRetirement, GoalRetirementResponse, HintShape, MessageType,
    MissReason, OpaqueEvent, OpaqueRequest, OpaqueResponse, PublicKeyRegistration,
    PublicKeyRegistrationResponse, RefusalReason, SchemaVersion, StewardDirective,
    TestimonialWitness, TransportMedium, WithdrawalReason, Withdraws, ACCORD_THRESHOLD_M_OF_N,
    DEFAULT_MAX_CONTENT_BODY_BYTES, DELIVERY_ATTESTATION_DOMAIN,
    DELIVERY_REFUSAL_ATTESTATION_DOMAIN, FEDERATION_ANNOUNCEMENT_ACCORD_SIG_DOMAIN,
    GOAL_DECLARATION_DOMAIN, GOAL_RETIREMENT_DOMAIN,
};
pub use mls::{
    unwrap_welcome, wrap_welcome, ArchiveMode, ArchiveModeError, FederationDirectoryEntry,
    ScopeStateProvider, ScopeStateProviderError, WelcomeWrapError, WrappedWelcome,
    DEFAULT_ROTATE_FORWARD_WINDOW_DAYS,
};
pub use multimedia::{
    cdn_edge_prefetch_stub, is_fast_path_legal_basis, ContributionDispatchProbe,
    ContributionSubjectKind, ExternalRefWithAcl, FastPathLegalBasis,
};
pub use observability::{
    DeliveryClass as MetricsDeliveryClass, EdgeMetrics, EdgeMetricsBundle, VerifyErrorClass,
};
pub use outbound::{
    DispatcherConfig, OutboundHandle, PeerDirectory, PeerSubscriptionFilter, StewardDirectory,
    StewardKey,
};
pub use reachability::{AttemptOutcome, PeerMediumReachability, ReachabilityTracker};
pub use scope_privacy::{
    derive_record_id, derive_symbol_key, k_record_id, k_symbol, witness_cover_leaf, RecordType,
    HPKE_SUITE_ID, LABEL_RECORD_ID, LABEL_SYMBOL,
};
pub use transport::{InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome};
pub use verify::{
    AccordHolderKey, HybridPolicy, ProvenanceChain, ProvenanceLink, RootingDirectory,
    RootingRejection, RootingVerdict, VerifiedEnvelope, VerifiedTrace, VerifyDirectory,
    VerifyError, VerifyOutcome, VerifyPipeline,
};

// ─── UniFFI scaffolding — v0.13.0 (CIRISEdge#36 GO) ─────────────────
//
// The UDL declares the type / function shapes; `build.rs` invokes
// `uniffi::generate_scaffolding` to produce `$OUT_DIR/ciris_edge.uniffi.rs`,
// which we pull in below. The pulled file emits:
//
//   - `setup_scaffolding!("ciris_edge")` — registers `UniFfiTag`,
//     metadata, contract version, `RustBuffer` plumbing.
//   - Type definitions: `EdgeError`, `PeerInfo`, `PeerHandle`,
//     `TransportInfo`, etc. — directly at the crate root, named
//     exactly as the UDL declared.
//   - `#[export_for_udl]` stubs for each function — at macro-expand
//     time the stub is REPLACED by a marshalling shell that calls a
//     same-named function visible at the crate root. We satisfy that
//     by re-importing every function from `ffi::uniffi_impl` below
//     under its UDL name.
//
// IMPORTANT: the function `use` statements MUST come BEFORE the
// `include_scaffolding!` invocation — the macro expansion references
// each function by its bare name, so the import has to be in scope at
// that point.
// UDL-declared types live in `ffi::uniffi_types` — re-exported here
// so the `include_scaffolding!` expansion (which references each type
// by bare name at the crate root) resolves them. ALL of these MUST be
// visible at the crate root before `include_scaffolding!` runs.
#[cfg(feature = "ffi-uniffi")]
pub use ffi::uniffi_types::{
    EdgeBindingsError, EdgeBlackholeEntry, EdgeErrorEvent, EdgeInFlightAnnounce, EdgeLinkHandle,
    EdgeLinkInfo, EdgeLinkState, EdgeMetricsSnapshot, EdgeNetworkEvent, EdgePathEntry,
    EdgePeerFilter, EdgePeerHandle, EdgePeerHealth, EdgePeerInfo, EdgePeerPolicy, EdgePeerTrust,
    EdgeProbeResult, EdgeRateEntry, EdgeReverseEntry, EdgeRoutingPathEntry, EdgeTransportHandle,
    EdgeTransportHealth, EdgeTransportInfo, EdgeTransportSpec, EdgeTransportStats, EdgeTunnelInfo,
};

// UDL function bodies live in `ffi::uniffi_impl` — re-exported here
// under their UDL names. The scaffolding's marshalling shells look up
// `crate::peer_list` etc. by bare name.
#[cfg(feature = "ffi-uniffi")]
pub use ffi::uniffi_impl::{
    crate_version, current_ratchet_id, identity_hash, identity_pubkeys, last_rotation_at,
    metrics_snapshot, path_table, peer_add, peer_get, peer_health_summary, peer_list, peer_probe,
    peer_remove, peer_set_alias, peer_set_notes, peer_set_policy, peer_set_trust, queue_depth,
    recent_errors, recent_events, transport_add, transport_config_blob, transport_disable,
    transport_enable, transport_health, transport_list, transport_remove, transport_set_mode,
    transport_stats,
};

// v0.14.0 (CIRISEdge#32) — Links FFI bodies. The scaffolding looks
// these up by bare name at the crate root, the same pattern v0.13.0
// established for the #25 / #26 / #28 / #31 reads cut.
#[cfg(feature = "ffi-uniffi")]
pub use ffi::uniffi_impl_links::{link_count, link_list, link_open, link_request, link_teardown};

// v0.15.0 (CIRISEdge#33) — Routing-table FFI bodies. Same crate-root
// bare-name discipline; the scaffolding's marshalling shells look up
// `crate::routing_path_table` etc. by bare name.
#[cfg(feature = "ffi-uniffi")]
pub use ffi::uniffi_impl_routing::{
    routing_announce_table, routing_blackhole_add, routing_blackhole_list,
    routing_blackhole_prune_expired, routing_blackhole_remove, routing_path_drop,
    routing_path_drop_via, routing_path_request, routing_path_table, routing_path_to,
    routing_rate_table, routing_reverse_table, routing_transport_id, routing_transport_uptime,
    routing_tunnels,
};

// The included scaffolding emits ~30 `#[unsafe(no_mangle)]` FFI shim
// declarations (`uniffi_ciris_edge_fn_func_*` + `ffi_*_uniffi_contract_version`
// + `RustBuffer` plumbing). The crate-level `deny(unsafe_code)` would
// reject those — they aren't hand-written and the scaffolding's
// `#![allow(unsafe_code)]` doesn't propagate.
//
// Safety: every `no_mangle` item is generated by UniFFI 0.31's
// scaffolding from the UDL declarations in `udl/ciris_edge.udl`;
// the marshalling FFI shells in turn delegate to the safe Rust
// functions re-exported above (`peer_list`, `transport_stats`, ...).
// No hand-written `unsafe` is introduced; the carve-out is the same
// shape persist's PyCapsule pattern uses (CIRISEdge#22 cohabitation,
// v0.9.2).
//
// The `include!` (not `include_scaffolding!`) is wrapped in a module
// won't work because the scaffolding's `setup_scaffolding!` macro
// emits `pub struct UniFfiTag` at its expansion site — UniFFI's
// derive macros emit `impl<UT> FfiConverter<UT> for X` blocks that
// reference `crate::UniFfiTag` in `udl_derive` mode. So the include
// MUST happen at the crate root. We allow at the macro call site
// instead.
#[cfg(feature = "ffi-uniffi")]
uniffi::include_scaffolding!("ciris_edge");
