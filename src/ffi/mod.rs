//! Foreign-function interface shells.
//!
//! Mirrors the discipline persist established (`CIRISPersist/src/ffi/`):
//! every CIRIS deployment target reaches the same Rust core. The lens
//! FastAPI integration (Phase 1) is the first PyO3 consumer; agent's
//! Python pipeline (Phase 2) is the second; iOS / Android shells
//! (Phase 3) reach via swift-bridge / uniffi against the same
//! crate.
//!
//! Phase 1: PyO3 (lens cutover).
//! Phase 2: PyO3 (agent adoption).
//! Phase 3: swift-bridge (iOS) + uniffi (Android), composing against
//!          the same Rust surface this module gates.

#[cfg(feature = "pyo3")]
pub mod pyo3;

// v0.13.0 (CIRISEdge#36 GO) — UniFFI bindings surface (#25 transport
// mgmt + #26 peer mgmt + #31 identity reads + #28 snapshot reads).
// `uniffi_types` declares the Rust type definitions the UDL references;
// `uniffi_impl` carries the function bodies. Both are re-exported at
// the crate root by `lib.rs` so the `include_scaffolding!` expansion
// resolves names against them. The language-side bindings are
// committed under `bindings/{python,kotlin,swift}/`.
#[cfg(feature = "ffi-uniffi")]
pub mod uniffi_types;

#[cfg(feature = "ffi-uniffi")]
pub mod uniffi_impl;
