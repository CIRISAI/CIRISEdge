//! Build script — drives UniFFI scaffolding generation against
//! `udl/ciris_edge.udl` when the `ffi-uniffi` Cargo feature is on.
//!
//! v0.13.0 (CIRISEdge#36 GO) — the spike's `udl + build.rs + lib.rs
//! include!()` pattern, productionized for the bundled #25 + #26 +
//! #31 reads + #28 snapshot reads cut.
//!
//! Per-feature gating: `[build-dependencies]` ignores Cargo features
//! at the crate-graph level, so `uniffi`'s build-script dep is always
//! present. The body below short-circuits via the
//! `CARGO_FEATURE_FFI_UNIFFI` env var — Cargo sets this when the
//! `ffi-uniffi` feature is enabled. Non-uniffi builds compile a no-op
//! `build.rs`, so the only overhead is the one-time crate compile.
//!
//! Drift: the generated bindings (`bindings/python/ciris_edge.py` +
//! `bindings/kotlin/ai/ciris/edge/ciris_edge.kt` +
//! `bindings/swift/ciris_edge.swift`) are committed to the repo so
//! consumers don't need `uniffi-bindgen` on their build host. A CI
//! gate regenerates them and `git diff --exit-code`s — see
//! `.github/workflows/ci.yml::uniffi-drift`.

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_FFI_UNIFFI");
    println!("cargo:rerun-if-changed=udl/ciris_edge.udl");
    println!("cargo:rerun-if-changed=uniffi.toml");

    if std::env::var_os("CARGO_FEATURE_FFI_UNIFFI").is_some() {
        // `generate_scaffolding` writes `target/.../ciris_edge.uniffi.rs`
        // which `src/ffi/uniffi.rs` pulls in via `uniffi::include_scaffolding!`.
        uniffi::generate_scaffolding("udl/ciris_edge.udl")
            .expect("uniffi: generate_scaffolding(udl/ciris_edge.udl) failed");
    }
}
