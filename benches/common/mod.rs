//! Shared bench fixtures (docs/BENCHMARKS.md).
//!
//! Mirrors `tests/common/mod.rs`'s shape — a real persist SQLite
//! `FederationDirectory` + `OutboundQueue` seeded with scrub-signed
//! federation_keys rows — so the bench surface composes the real
//! verify path (hybrid_verify_via_directory) against a real outbound
//! queue without spinning up a transport listener.
//!
//! # Modules
//!
//! - [`mock_directory`] — in-memory `FederationDirectory + OutboundQueue`
//!   seeded via persist's SQLite `:memory:` backend, plus the
//!   scrub-signed `KeyRecord` builder.
//! - [`mock_signer`] — software Ed25519 (+ optional ML-DSA-65)
//!   `LocalSigner` driven from a deterministic 32-byte seed.
//! - [`mock_transport`] — a no-op transport (`send` returns
//!   `Delivered`; `listen` returns `Ok(())` immediately). Lets a
//!   bench register an `Edge` without standing up an HTTP / Reticulum
//!   listener — what we measure is verify + dispatch + enqueue.
//!
//! All three are bench-scoped (`#[path = ...] mod common;` per
//! bench file) — the bench harness compiles each module against the
//! one bench that imports it, so a bench that doesn't need the
//! signer doesn't pull keyring code.

#![allow(clippy::pedantic, clippy::needless_pass_by_value, clippy::missing_errors_doc, clippy::missing_panics_doc, clippy::cast_possible_truncation, clippy::cast_lossless, clippy::cast_sign_loss, clippy::cast_possible_wrap, clippy::items_after_statements, clippy::used_underscore_binding, clippy::field_reassign_with_default, clippy::needless_raw_string_hashes)]

#![allow(dead_code)] // not every bench uses every helper
#![allow(unused_imports)] // each bench cherry-picks a subset of re-exports

pub mod mock_directory;
pub mod mock_signer;
pub mod mock_transport;

pub use mock_directory::{
    build_in_memory_backend, seed_accord_holders, seed_stewards, signed_record, BenchFedKey,
};
pub use mock_signer::bench_local_signer;
pub use mock_transport::NullTransport;
