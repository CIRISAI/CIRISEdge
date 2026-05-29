//! Local uniffi-bindgen driver — v0.13.0 (CIRISEdge#36 GO).
//!
//! UniFFI 0.31 no longer publishes a standalone `uniffi-bindgen` crate
//! on crates.io. The recommended pattern is each project compiles its
//! own minimal CLI driver using `uniffi::uniffi_bindgen_main()`. That's
//! what this binary is.
//!
//! Used by:
//!   - `cargo run --features uniffi-bindgen-cli --bin uniffi_bindgen_cli -- generate udl/ciris_edge.udl --language python --out-dir bindings/python/`
//!   - The CI drift gate (`.github/workflows/ci.yml::uniffi-drift`)
//!   - The Python wrapper's bootstrap when `bindings/python/ciris_edge.py`
//!     is regenerated.

fn main() {
    uniffi::uniffi_bindgen_main();
}
