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
pub mod bundle_gate;
pub mod chat;
pub mod cohort_scope;
/// CIRISEdge#552/#554 — the contact ladder: announce → discover → request →
/// consent → chat, with one greppable log shape per rung.
pub mod contact;
#[cfg(feature = "debug-tools")]
pub mod debug;
pub mod delivery_mode;
pub mod detector;
/// CIRISEdge#554 — the receiver-side budget on unsolicited contact requests.
pub mod invite_gate;
pub mod rate_limit;
#[cfg(test)]
mod role_matrix_gauntlet;
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
pub mod field_conformance;
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
pub mod log_throttle;
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
// CIRISEdge#499 (workstream B) — scope-native derived-address table.
// `(scope, group_id, epoch, member)` -> 16-byte Reticulum destination
// hash, derived on membership/epoch change and read (never derived) on
// the packet path, with the three-phase epoch rotation that keeps the
// receive accept-set a superset of the send-set (CIRISEdge#492 shape).
pub mod av_addressing;
pub mod cohort_addressing;
pub mod contextual_integrity;
pub mod family_gates;
pub mod scope_addressing;
pub mod scope_lifecycle;
// v6.0.0 (CIRISEdge#175) — CC 1.13.3.4 substrate.
pub mod scope_privacy;
pub mod swarm;
pub mod touch_claim;
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

/// CIRISEdge#393 / persist v21 (#501/#502) — the cross-repo drift witness for
/// the Registry-of-Record admission policy. persist owns the APPLY policy for
/// all 14 replicated kinds and exports it as
/// [`ciris_persist::federation::replication_policy::REPLICATION_POLICY_HASH`];
/// edge (the SERVE/ADVERTISE half) and CIRISServer both PIN it. A persist-side
/// change to which signer-source admits a kind — the class that silently
/// widened trust before v21 — flips this hash, failing edge's build until the
/// re-pin is a deliberate, reviewed act across the triple (the same posture as
/// [`WIRE_VOCABULARY_HASH`], now for the admission surface rather than the wire
/// vocabulary).
// v31.1.0 re-pin: persist's replication policy moved with the ceremony trust-root
// bake (#665, "install the plane it confers") + the exclusion-plane rebuild
// (#655/#662). Edge's serve/advertise half is UNCHANGED — its own
// SERVE_ADVERTISE_POLICY_HASH test + all 815 behavioral tests still pass — so this
// is a clean witness re-pin of the persist-internal apply policy (CIRISEdge#393).
pub const PERSIST_REPLICATION_POLICY_HASH: &str =
    "3af30bccf437679ecccba325e2db055824b4721eeac069fc30a38d7a0723bbef";

#[cfg(test)]
mod replication_policy_hash_tests {
    /// Pins persist's `REPLICATION_POLICY_HASH` from the linked crate against
    /// edge's expected value. A mismatch is a coordinated admission-policy
    /// change persist made that edge's serve/advertise half must be re-reviewed
    /// against — never a silent skew. See CIRISEdge#393 §4.3 manifest witness.
    #[test]
    fn persist_replication_policy_hash_pinned() {
        assert_eq!(
            ciris_persist::federation::replication_policy::REPLICATION_POLICY_HASH,
            super::PERSIST_REPLICATION_POLICY_HASH,
            "persist's REPLICATION_POLICY_HASH changed — its admission policy for \
             one of the 14 replicated kinds moved. Re-review edge's serve/advertise \
             half against the new policy, then re-pin deliberately (CIRISEdge#393)."
        );
    }
}

/// CIRISEdge#397 / persist v21.2.0 (CIRISPersist#510 P1) — the closed consent
/// grammar's cross-repo drift witness. persist validates every
/// `consent:replication:v1` grant against an exhaustive, fail-closed grammar
/// (the 15 kinds, `strip_field` signed-post-transform) and exports it as
/// [`ciris_persist::federation::consent_grammar::CONSENT_GRAMMAR_HASH`]. Edge
/// pins it now so that when edge later implements serve-side
/// `recipient_capability` enforcement (#396 item 6), the op vocabulary is drawn
/// from a manifest whose drift is a BUILD failure first, a behavior change
/// second — the same posture as [`PERSIST_REPLICATION_POLICY_HASH`].
// v31.1.0 re-pin: the closed consent grammar moved with the baked plane the
// ceremony trust root confers (#665). Edge's consent handling is UNCHANGED (no
// consent test regressed), so this is a clean witness re-pin (CIRISEdge#397 §5).
pub const PERSIST_CONSENT_GRAMMAR_HASH: &str =
    "b66870da9639c8560538a26c566168fea9759139eaa67ad4116ff8a5f290d69f";

#[cfg(test)]
mod consent_grammar_hash_tests {
    /// Pins persist's `CONSENT_GRAMMAR_HASH` from the linked crate. A mismatch
    /// is a consent-grammar change persist made that edge's (future) serve-side
    /// capability enforcement must be re-reviewed against — never a silent skew.
    #[test]
    fn persist_consent_grammar_hash_pinned() {
        assert_eq!(
            ciris_persist::federation::consent_grammar::CONSENT_GRAMMAR_HASH,
            super::PERSIST_CONSENT_GRAMMAR_HASH,
            "persist's CONSENT_GRAMMAR_HASH changed — the closed consent grammar moved. \
             Re-review edge's consent handling (and the future #396 capability \
             enforcement), then re-pin deliberately (CIRISEdge#397 §5)."
        );
    }
}

/// Pinned SHA-256 of persist's `YUBICO_ATTESTATION_ROOT_1_DER` — the single
/// trust anchor the CIRISPersist#513 canonical-admission gate chains every
/// FIPS-140-3 accord custody attestation to (a valid canonical = a co-scrub by a
/// Yubico-attested FIPS-140-3 accord of ≥3, the hardware anti-Sybil floor on
/// trust-root minting). Edge does NOT admit canonicals, but it pins the anchor as
/// a cross-repo drift witness: the root of trust for the anti-Sybil floor must
/// never move silently. A mismatch is a BUILD failure first, forcing a DELIBERATE
/// re-pin in lockstep with persist + CIRISServer — the same posture as
/// [`PERSIST_CONSENT_GRAMMAR_HASH`] / [`PERSIST_REPLICATION_POLICY_HASH`].
pub const PERSIST_YUBICO_ATTESTATION_ROOT_HASH: &str =
    "62760c6a6ef91679f454c8902b80fd009825b3f25da90f1fbace2ec6586cd5a8";

#[cfg(test)]
mod yubico_attestation_root_hash_tests {
    use sha2::{Digest, Sha256};

    /// Cross-repo lockstep witness for the CIRISPersist#513 anti-Sybil floor's
    /// trust anchor — mirrors persist's own `yubico_root_pin_sha256_513`. If
    /// persist ever swaps the pinned Yubico attestation root, this breaks first.
    #[test]
    fn persist_yubico_attestation_root_pinned() {
        assert_eq!(
            hex::encode(Sha256::digest(
                ciris_persist::federation::admission::YUBICO_ATTESTATION_ROOT_1_DER
            )),
            super::PERSIST_YUBICO_ATTESTATION_ROOT_HASH,
            "persist's YUBICO_ATTESTATION_ROOT_1_DER changed — the FIPS-140-3 anti-Sybil \
             floor's root of trust moved. Re-pin DELIBERATELY, in lockstep with persist + \
             CIRISServer (CIRISPersist#513)."
        );
    }
}

/// Pinned namespace-manifest version (CIRISPersist#519 / manifest `0.3.0`). The
/// `field_processor_matrix`, the per-family transform algebra, and the cohort
/// namespace all version together under this string; edge's field processors
/// (CIRISEdge#411 §1) and its transform application (§3) are written against
/// exactly this manifest revision. A bump edge has not re-reviewed must fail the
/// build — the same WIRE_VOCABULARY discipline as the hash pins below.
pub const PERSIST_NAMESPACE_MANIFEST_VERSION: &str = "0.3.0";

/// Pinned SHA-256 of persist's closed **transform algebra** (CIRISPersist#519,
/// `transform::TRANSFORM_ALGEBRA_HASH`). Edge does NOT apply `strip_field` at
/// the serve path — serve-time stripping is unsound on edge's content-addressed
/// signed wire (the recipient fetches by content-hash and re-verifies the hybrid
/// signature, so a strip breaks both; #397). The strip is a persist
/// WIDENING-side transform (`widen_audience`'s `strip`, listed in `differs_in`,
/// persist v39.0.0); at edge's
/// serve layer `StripField` deliberately resolves to a no-op
/// (`bridge.rs` `recipient_capability` collection) and the deferral is accounted
/// for in `field_conformance::DEFERRED_PENDING_PLANE`. Pinning the algebra hash
/// makes a persist change to the op vocabulary — a new strip, a changed shape
/// op — a BUILD failure at edge first, forcing a deliberate re-review of that
/// no-op boundary before the wire behavior can drift.
pub const PERSIST_TRANSFORM_ALGEBRA_HASH: &str =
    "b7bd779468f4ad1ab551a5fd2dc0392df01e6f2e0ed393f924a806ed49686b4b";

#[cfg(test)]
mod manifest_and_transform_pin_tests {
    /// Pins the namespace-manifest version from the linked crate. A mismatch is a
    /// manifest revision persist shipped that edge's field processors + transform
    /// application must be re-reviewed against (CIRISEdge#411) — never a silent skew.
    #[test]
    fn persist_namespace_manifest_version_pinned() {
        assert_eq!(
            ciris_persist::federation::namespace::supersets::VENDORED_MANIFEST_VERSION,
            super::PERSIST_NAMESPACE_MANIFEST_VERSION,
            "persist's VENDORED_MANIFEST_VERSION changed — the namespace manifest \
             (field_processor_matrix + transform algebra + cohort namespace) moved. \
             Re-review edge's field processors + transform application, then re-pin \
             deliberately (CIRISEdge#411 §0)."
        );
    }

    /// Pins persist's `TRANSFORM_ALGEBRA_HASH`. A mismatch is a change to the closed
    /// transform op vocabulary edge applies at serve — re-review §3, then re-pin.
    #[test]
    fn persist_transform_algebra_hash_pinned() {
        assert_eq!(
            ciris_persist::federation::transform::TRANSFORM_ALGEBRA_HASH,
            super::PERSIST_TRANSFORM_ALGEBRA_HASH,
            "persist's TRANSFORM_ALGEBRA_HASH changed — the closed transform algebra \
             moved. Re-review edge's serve-time transform application (CIRISEdge#411 §3), \
             then re-pin deliberately."
        );
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
    baked_canonical_genesis_ids, baked_canonical_ip_dials, reseed_canonical_bootstrap_peers,
    run_blackhole_pruner, AgentMode, CanonicalBootstrapPeer, ChunkResult, ContentResult, Edge,
    EdgeBuilder, EdgeConfig, EdgeError, PublishOutcome, VerifiedEnvelopeSnapshot,
    DEFAULT_BLACKHOLE_PRUNE_INTERVAL_SECONDS,
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
pub use transport::{
    InboundFrame, NullTransport, Transport, TransportError, TransportId, TransportSendOutcome,
};
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
// CIRISEdge#289 — downstream in-process accessor for the embedded Edge
// (NOT a UDL function; the process-global handle is installed by
// `init_edge_runtime`). Re-exported so CIRISServer's `start_federation_delivery`
// controller can drive the live `Arc<Edge>`, mirroring persist's
// `current_rust_engine()`. See `ffi::uniffi_impl::current_edge`.
#[cfg(feature = "ffi-uniffi")]
pub use ffi::uniffi_impl::current_edge;

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
