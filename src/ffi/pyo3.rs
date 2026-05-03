//! PyO3 bindings — Python-facing Edge surface.
//!
//! Phase 1 lens cutover shape: lens constructs an `Edge` instance
//! pointing at its existing `ciris_persist.Engine`, registers the
//! standard handler set (verify + persist for `AccordEventsBatch`),
//! and runs the dispatch loop. Lens's Python doesn't customize
//! handler logic — the canonical verify-and-persist path lives in
//! Rust. Customization (peer-specific handlers) lands in Phase 2 when
//! agent + registry adopt edge.
//!
//! Implementation lands in subsequent commits. The stub here gates the
//! `pyo3` feature so downstream pin contracts (`pip install
//! ciris-edge`) are stable from v0.1.0; symbols come online as the
//! verify pipeline + transport implementations land.

use pyo3::prelude::*;

/// Wire-format schema versions edge supports. Strict allowlist (AV-7);
/// out-of-set values reject at the verify pipeline. Mirrors persist's
/// `SUPPORTED_SCHEMA_VERSIONS` export.
const SUPPORTED_SCHEMA_VERSIONS: [&str; 1] = ["1.0.0"];

/// Crate version (compile-time). Surfaces as `ciris_edge.__version__`.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Top-level Python module entry point. `import ciris_edge` triggers
/// this; per-symbol bindings register here as they land.
#[pymodule]
fn ciris_edge(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", VERSION)?;
    m.add("SUPPORTED_SCHEMA_VERSIONS", SUPPORTED_SCHEMA_VERSIONS.to_vec())?;

    // Edge — the top-level Python class. Wraps Rust `Edge`.
    // m.add_class::<Edge>()?;
    // Other classes (DurableHandle, HybridPolicy, etc.) register here
    // as the Rust surface stabilizes.

    Ok(())
}
