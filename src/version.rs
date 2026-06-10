//! Crate version exposure.
//!
//! Three surfaces for the same `CARGO_PKG_VERSION` literal — each one
//! exists so a distinct consumer can read **what the loaded binary
//! actually is**, not just what the pip pin claims:
//!
//! 1. **`pub const VERSION`** — Rust callers (and the PyO3 layer's
//!    `__version__` module attribute) read this directly.
//!
//! 2. **`pub extern "C" fn ciris_edge_version()`** — C FFI accessor
//!    matching the `ciris-verify` template. The `#[no_mangle]` +
//!    `extern "C"` symbol is retained through `strip` / LTO; the null-
//!    terminated literal it returns is `strings`-discoverable in the
//!    compiled cdylib. This is what `CIRISAgent/tools/update_android_libs.py`
//!    binary-refresh integrity reads to assert the per-ABI `.so` matches
//!    the pinned wheel (closes the cohabitation-skew class where a
//!    stale/swapped `.so` slips through silently).
//!
//! 3. **PyO3 `__version__`** — Python consumers `import ciris_edge;
//!    ciris_edge.__version__`. Wired in `src/ffi/pyo3.rs` against this
//!    module's [`VERSION`] constant so the three surfaces never drift.
//!
//! The agent's Trust page (CIRISPersist#189 driver) needs the
//! **binary's self-reported version read at runtime**, not just the
//! pip pin — so a binary that doesn't match its pin (or the registry's
//! canonical manifest) is *visibly* flagged. All three surfaces above
//! satisfy that requirement.
//!
//! See CIRISVerify's `src/ciris-verify-ffi/src/lib.rs` (the reference
//! implementation that already satisfies `strings libciris_verify_ffi.so
//! | grep <version>`) and CIRISPersist#189 for the cross-fabric ask.

use std::ffi::c_char;

/// Crate version literal — `env!("CARGO_PKG_VERSION")` evaluated at
/// compile time. Public so downstream Rust callers can compare without
/// re-parsing the Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// `VERSION` with a trailing NUL byte appended at compile time, so the
/// `as_ptr()` cast in [`ciris_edge_version`] yields a valid C string
/// without runtime allocation. The literal stays embedded in the
/// compiled cdylib (`strings`-discoverable) by virtue of the
/// `#[no_mangle] extern "C"` function retaining it.
const VERSION_CSTR: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

/// C FFI accessor: returns a static null-terminated UTF-8 byte string
/// with the crate version. Matches the `ciris_verify_version()`
/// template in `libciris_verify_ffi.so` so cross-fabric tooling
/// (`update_android_libs.py`, the agent Trust-page Android binding,
/// the registry canonical-build-hash verifier) uses one calling
/// convention across every CIRIS cdylib.
///
/// The returned pointer is to a `'static` string baked into the
/// binary — callers MUST NOT free it. Safe to call from any thread.
///
/// # Safety
///
/// The `#[no_mangle]` + `extern "C"` symbol must be retained by the
/// linker. Edge's release profile sets `strip = "symbols"` (NOT
/// `strip = "debuginfo"`) in maturin builds, and the `no_mangle`
/// attribute marks the symbol as `KEEP` for the linker; both keep
/// this function reachable post-strip.
///
/// `#[allow(unsafe_code)]` scopes the crate-level deny to this single
/// item — the rest of the module stays under the strict regime.
/// `no_mangle` is technically an `unsafe_code` site (the linker can't
/// dedupe collisions for manually-exported symbols), but the symbol
/// name `ciris_edge_version` is unique to this crate (the C FFI naming
/// convention is `<crate>_version`, matching `ciris_verify_version` /
/// `ciris_persist_version` etc.) so the cross-cdylib collision risk
/// the lint warns about does not apply.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn ciris_edge_version() -> *const c_char {
    VERSION_CSTR.as_ptr().cast::<c_char>()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `VERSION` matches the Cargo metadata under test build (which
    /// is the same as the cdylib build for the version literal).
    #[test]
    fn version_constant_matches_cargo_pkg_version() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
    }

    /// `VERSION_CSTR` is `VERSION` plus a trailing NUL.
    #[test]
    fn version_cstr_terminates_with_nul() {
        let bytes = VERSION_CSTR.as_bytes();
        assert_eq!(bytes[bytes.len() - 1], 0);
        let body = &bytes[..bytes.len() - 1];
        assert_eq!(std::str::from_utf8(body).unwrap(), VERSION);
    }

    /// The C FFI accessor returns a pointer that round-trips back to
    /// the same `VERSION` string through `CStr::from_ptr`. The
    /// `#[allow(unsafe_code)]` is item-scoped — the test body is the
    /// one place we round-trip through a raw pointer to exercise the
    /// real consumer's calling convention.
    #[allow(unsafe_code)]
    #[test]
    fn ciris_edge_version_round_trips_via_cstr() {
        let ptr = ciris_edge_version();
        assert!(!ptr.is_null());
        // SAFETY: ptr was returned by `ciris_edge_version`, which
        // hands out a pointer to a static null-terminated UTF-8
        // literal embedded in the binary. CStr::from_ptr is the
        // canonical way to read it back; no ownership transfer.
        let cstr = unsafe { std::ffi::CStr::from_ptr(ptr) };
        assert_eq!(cstr.to_str().unwrap(), VERSION);
    }

    /// The version literal is non-empty (defence against a future
    /// build script that accidentally strips it).
    #[test]
    fn version_is_non_empty() {
        assert!(!VERSION.is_empty());
        // semver-shaped — at least one dot. (Not a full semver parse;
        // pre-release suffixes like `1.5.1-rc1` are fine.)
        assert!(
            VERSION.contains('.'),
            "VERSION `{VERSION}` is not semver-shaped"
        );
    }
}
