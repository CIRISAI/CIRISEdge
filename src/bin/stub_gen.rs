//! CIRISEdge#35 — pyo3-stub-gen driver.
//!
//! Walks the inventory of `#[gen_stub_pyclass]` /
//! `#[gen_stub_pymethods]` / `#[gen_stub_pyfunction]` items registered
//! at link time by the `pyo3-stub-gen` derive macros, and writes the
//! aggregated `.pyi` stub to `python/ciris_edge/__init__.pyi`.
//!
//! # Invocation
//!
//! ```sh
//! cargo run --features pyo3 --bin stub_gen
//! ```
//!
//! Output: `python/ciris_edge/__init__.pyi` (replaced on every run).
//!
//! # CI drift gate
//!
//! `.github/workflows/ci.yml` runs:
//!
//! ```sh
//! cargo run --features pyo3 --bin stub_gen
//! git diff --exit-code python/ciris_edge/__init__.pyi
//! ```
//!
//! A non-zero diff means a `#[pymethod]` / `#[pyclass]` / `#[pyfunction]`
//! was added or renamed without re-running the generator. The fix is
//! the same command the gate runs.
//!
//! # Bundling into the wheel
//!
//! `pyproject.toml`'s `[tool.maturin]` `include` list carries
//! `python/ciris_edge/__init__.pyi` so `maturin build` ships the stub
//! alongside the compiled `.so` under the `ciris_edge` package
//! directory. `pip install ciris-edge` then gives mypy / pyright
//! / VS Code IntelliSense the full surface.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stub = ciris_edge::ffi::pyo3::stub_info()?;
    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("python")
        .join("ciris_edge");
    std::fs::create_dir_all(&out_dir)?;
    // pyo3-stub-gen's `StubInfo::generate` writes one .pyi per module
    // into the manifest-relative `python/<module>/` directory; we
    // build with that exact layout so the output path matches the
    // `pyproject.toml` `[tool.maturin] include` glob.
    stub.generate()?;
    println!("ciris_edge stub generated at python/ciris_edge/__init__.pyi");
    Ok(())
}
