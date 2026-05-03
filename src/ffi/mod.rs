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
