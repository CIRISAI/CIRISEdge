//! CIRISEdge#960 — `src/ffi/kept_directory.rs` is generated from the persist
//! trait edge is pinned to, and must be current. The wrapper delegates every
//! `FederationDirectory` method to persist's directory-ops proxy; if persist
//! adds a defaulted method the proxy overrides and the wrapper is not
//! regenerated, the wrapper answers it with the trait default and nothing
//! fails. This re-runs the generator against the pinned persist source and
//! fails on any difference.

#[test]
fn the_kept_directory_wrapper_matches_the_pinned_persist_trait() {
    let out = std::process::Command::new("python3")
        .args([
            "-I",
            "tools/gen_kept_directory.py",
            "--from-cargo-metadata",
            "--check",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("python3 runs");
    assert!(
        out.status.success(),
        "src/ffi/kept_directory.rs is stale against the pinned persist trait; run \
         `python3 tools/gen_kept_directory.py --from-cargo-metadata`:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// CIRISEdge#988 — every implementor of persist's `FederationDirectory` in
/// this tree (the generated `KeptDirectory`, the counting test double) defines
/// EVERY trait method of the pinned persist, so no caller reaches a trait
/// default body through it. A default answers `Unsupported`, or a plausible
/// empty, where the store would answer, and a witness over the double then
/// tests the default (the 165-of-262 counting double did exactly that). A
/// persist bump that adds a trait method fails here, naming the double and the
/// method.
#[test]
fn every_federation_directory_double_defines_every_trait_method() {
    let out = std::process::Command::new("python3")
        .args([
            "-I",
            "tools/gen_kept_directory.py",
            "--from-cargo-metadata",
            "--check-doubles",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("python3 runs");
    assert!(
        out.status.success(),
        "a FederationDirectory implementor lacks trait methods (a caller would reach the \
         trait default): delegate them, or make each one panic by name:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
