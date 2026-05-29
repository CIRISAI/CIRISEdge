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

pub mod detector;
mod edge;
pub mod events;
pub mod ffi;
pub mod handler;
pub mod identity;
pub mod key_boundary;
pub mod manifest;
pub mod messages;
pub mod observability;
pub mod outbound;
pub mod reachability;
pub mod sas;
pub mod transport;
pub mod verify;

pub use detector::{
    ConsentRole, DetectionVerdict, EdgeDetectionAdmission, ProbePatternConfig,
    ProbePatternObserver, ProbePatternState,
};
pub use edge::{ContentResult, Edge, EdgeBuilder, EdgeConfig, EdgeError, VerifiedEnvelopeSnapshot};
pub use events::{
    EventBus, EventKind, EventSeverity, NetworkEvent, DEFAULT_EVENT_CHANNEL_CAPACITY,
};
pub use handler::{
    AbandonReason, Delivery, DurableHandle, DurableOutcome, DurableStatus, FederationPriority,
    Handler, HandlerContext, HandlerError, InlineTextMessage, Message,
};
pub use identity::LocalSigner;
pub use key_boundary::{
    KeyBoundaryParseError, KeyBoundaryScope, KEY_BOUNDARY_PREFIX, KEY_BOUNDARY_SUFFIX,
    LEGACY_NO_SEED_IN_HEAP,
};
pub use messages::{
    is_federation_attestation_emitting_type, AccordCarrier, AccordEventsBatch,
    AccordEventsResponse, AccordSignature, AnnouncementKind, AnnouncementPriority,
    AttestationGossip, AttestationRef, AuthorityClass, BuildManifestPublication,
    BuildManifestPublicationResponse, ContentBody, ContentFetch, ContentMiss, DSARRequest,
    DSARResponse, DeliveryAttestation, DeliveryAttestationError, DeliveryRefusalAttestation,
    EdgeEnvelope, FederationAnnouncement, FederationKeyDirectoryQuery,
    FederationKeyDirectoryQueryResponse, GoalDeclaration, GoalDeclarationResponse, GoalRetirement,
    GoalRetirementResponse, HintShape, InlineText, InlineTextDurable, MessageType, MissReason,
    PublicKeyRegistration, PublicKeyRegistrationResponse, RefusalReason, SchemaVersion,
    StewardDirective, TestimonialWitness, TransportMedium, WithdrawalReason, Withdraws,
    ACCORD_THRESHOLD_M_OF_N, DEFAULT_MAX_CONTENT_BODY_BYTES, DELIVERY_ATTESTATION_DOMAIN,
    DELIVERY_REFUSAL_ATTESTATION_DOMAIN, FEDERATION_ANNOUNCEMENT_ACCORD_SIG_DOMAIN,
    GOAL_DECLARATION_DOMAIN, GOAL_RETIREMENT_DOMAIN,
};
pub use outbound::{
    DispatcherConfig, OutboundHandle, PeerDirectory, PeerSubscriptionFilter, StewardDirectory,
    StewardKey,
};
pub use reachability::{AttemptOutcome, PeerMediumReachability, ReachabilityTracker};
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
