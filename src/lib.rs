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
#![deny(unsafe_code)]
#![deny(rust_2018_idioms)]
#![doc(html_root_url = "https://docs.rs/ciris-edge/0.1.0-pre1")]

mod edge;
pub mod ffi;
pub mod handler;
pub mod identity;
pub mod manifest;
pub mod messages;
pub mod observability;
pub mod outbound;
pub mod transport;
pub mod verify;

pub use edge::{Edge, EdgeBuilder, EdgeConfig, EdgeError};
pub use handler::{
    AbandonReason, Delivery, DurableHandle, DurableOutcome, DurableStatus, Handler, HandlerContext,
    HandlerError, InlineTextMessage, Message,
};
pub use identity::LocalSigner;
pub use messages::{
    AccordCarrier, AccordEventsBatch, AccordEventsResponse, AnnouncementKind, AnnouncementPriority,
    AttestationGossip, AttestationRef, AuthorityClass, BuildManifestPublication,
    BuildManifestPublicationResponse, ContentBody, ContentFetch, ContentMiss, DSARRequest,
    DSARResponse, DeliveryAttestation, DeliveryAttestationError, EdgeEnvelope,
    FederationAnnouncement, FederationKeyDirectoryQuery, FederationKeyDirectoryQueryResponse,
    HintShape, InlineText, InlineTextDurable, MessageType, MissReason, PublicKeyRegistration,
    PublicKeyRegistrationResponse, SchemaVersion, TransportMedium, DEFAULT_MAX_CONTENT_BODY_BYTES,
    DELIVERY_ATTESTATION_DOMAIN,
};
pub use outbound::{DispatcherConfig, OutboundHandle, PeerDirectory, PeerSubscriptionFilter};
pub use transport::{InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome};
pub use verify::{
    HybridPolicy, ProvenanceChain, ProvenanceLink, RootingDirectory, RootingRejection,
    RootingVerdict, VerifiedEnvelope, VerifiedTrace, VerifyDirectory, VerifyError, VerifyOutcome,
    VerifyPipeline,
};
