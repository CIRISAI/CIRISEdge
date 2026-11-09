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
