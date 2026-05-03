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

#![forbid(unsafe_code)]
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
    HandlerError, Message,
};
pub use identity::StewardSigner;
pub use messages::{
    AccordEventsBatch, AccordEventsResponse, AttestationGossip, BuildManifestPublication,
    BuildManifestPublicationResponse, DSARRequest, DSARResponse, EdgeEnvelope,
    FederationKeyDirectoryQuery, FederationKeyDirectoryQueryResponse, MessageType,
    PublicKeyRegistration, PublicKeyRegistrationResponse, SchemaVersion,
};
pub use outbound::{DispatcherConfig, OutboundHandle};
pub use transport::{InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome};
pub use verify::{
    HybridPolicy, VerifiedEnvelope, VerifiedTrace, VerifyDirectory, VerifyError, VerifyOutcome,
    VerifyPipeline,
};
