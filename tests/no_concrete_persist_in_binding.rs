//! Edge never operates on a store object the persist wheel built, except
//! through an ops capsule whose bodies run in the wheel.
//!
//! In a two-wheel process (`ciris_persist` + `ciris_edge` installed side by
//! side) each `.so` statically links its own `parking_lot_core` and its own
//! tokio (1.54 in persist 61.2.3, 1.53 in edge 45.0). A concrete
//! `Arc<SqliteBackend>` lifted out of a capsule runs EDGE's compiled copy of
//! persist's store code against the wheel's object: its `parking_lot` mutexes
//! lose wakeups across the two waiter queues (the v45.0.0 / v45.0.2
//! `dispatch_inbound_bytes` hang), and its tokio mutexes are a foreign layout.
//! Single-binary hosts (edge_node, ciris-server) link one persist and are
//! unaffected, which is why every in-process test passed.
//!
//! Two rules, over non-test code:
//!
//! 1. The binding (`src/ffi/`) names no concrete backend and unwraps no
//!    raw-layout store or runtime capsule, apart from the RESIDUAL counted
//!    below.
//! 2. Elsewhere, only the modules that serve single-binary hosts (they take a
//!    Rust `ciris_persist::Engine` or `BackendDispatch` the host built in its
//!    own binary, which the binding never holds) may name one. A new module
//!    that does fails here until it is reviewed and listed.

use std::path::{Path, PathBuf};

const CONCRETE: [&str; 3] = ["SqliteBackend", "PostgresBackend", "BackendDispatch"];

/// Raw-layout capsules that hand over a store or a runtime.
const RAW_STORE_CAPSULES: [&str; 4] = [
    "\"outbound_queue_capsule\"",
    "\"blob_storage_capsule\"",
    "\"federation_directory_capsule\"",
    "extract_capsule::<tokio::runtime::Handle",
];

/// The binding's remaining concrete references, all in `init_edge_runtime`:
/// the `use`, the `outbound_queue_capsule` unwrap, and the three views lifted
/// from it (`rooting_dir`, `blackhole_rules`, `derived_schema`) whose methods
/// have no persist ops yet (CIRISPersist#1227 / #1244). v45.0.3 does not ship
/// until this is zero; lowering it here is part of that change.
const BINDING_RESIDUAL: usize = 11;

/// Single-binary host modules (rule 2).
const HOST_MODULES: [&str; 6] = [
    "src/store_open.rs",
    "src/receipts.rs",
    "src/group_content/persist_store.rs",
    "src/blob_swarm/persist_source.rs",
    "src/replication/key_grant_emitter.rs",
    "src/bin/edge_node.rs",
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Lines of `src` outside `#[cfg(test)]`-gated `mod` blocks and outside
/// `//` comments, with their 1-based numbers. rustfmt puts a module's
/// closing brace at the indentation of its `mod` line, which is what ends
/// the skip.
fn non_test_code(src: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[cfg(") && trimmed.contains("test") {
            let mut j = i + 1;
            while j < lines.len() && lines[j].trim_start().starts_with("#[") {
                j += 1;
            }
            let item = lines.get(j).copied().unwrap_or("");
            let item_trim = item.trim_start();
            let is_mod = (item_trim.starts_with("mod ")
                || item_trim.starts_with("pub(crate) mod "))
                && item_trim.ends_with('{');
            if is_mod {
                let indent = &item[..item.len() - item_trim.len()];
                let close = format!("{indent}}}");
                let mut k = j + 1;
                while k < lines.len() && lines[k] != close {
                    k += 1;
                }
                i = k + 1;
                continue;
            }
            // A gated single item (`use`, `fn` line): skip just that line.
            i = j + 1;
            continue;
        }
        let code = line.split("//").next().unwrap_or("");
        out.push((i + 1, code.to_string()));
        i += 1;
    }
    out
}

fn is_test_file(rel: &str) -> bool {
    rel.ends_with("_tests.rs")
        || rel.ends_with("/tests.rs")
        || rel.contains("/tests/")
        || rel.ends_with("_invariants.rs")
}

#[test]
fn edge_reaches_persist_owned_store_objects_only_through_ops_capsules() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    files.sort();

    let mut binding_hits = Vec::new();
    let mut stray = Vec::new();
    for path in &files {
        let rel = path
            .strip_prefix(root)
            .expect("under root")
            .to_string_lossy()
            .replace('\\', "/");
        if is_test_file(&rel) {
            continue;
        }
        let src = std::fs::read_to_string(path).expect("read source");
        for (n, code) in non_test_code(&src) {
            let concrete = CONCRETE.iter().any(|t| {
                code.match_indices(t).any(|(at, _)| {
                    let before = code[..at].chars().next_back();
                    let after = code[at + t.len()..].chars().next();
                    !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
                        && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
                })
            });
            let raw_capsule = RAW_STORE_CAPSULES.iter().any(|c| code.contains(c));
            if rel.starts_with("src/ffi/") {
                if concrete || raw_capsule {
                    binding_hits.push(format!("{rel}:{n}: {}", code.trim()));
                }
            } else if concrete && !HOST_MODULES.contains(&rel.as_str()) {
                stray.push(format!("{rel}:{n}: {}", code.trim()));
            }
        }
    }

    assert!(
        stray.is_empty(),
        "a module outside the single-binary host list names a concrete persist backend; \
         reach the store through an ops capsule, or review it and add it to HOST_MODULES \
         if it serves only hosts that link persist themselves:\n{}",
        stray.join("\n")
    );
    assert_eq!(
        binding_hits.len(),
        BINDING_RESIDUAL,
        "the binding's concrete / raw-capsule references changed. A NEW one is the \
         two-wheel lost-wakeup defect again: route it through an ops capsule. If one was \
         REMOVED, lower BINDING_RESIDUAL to match:\n{}",
        binding_hits.join("\n")
    );
}

#[test]
fn the_scan_skips_test_modules_and_comments() {
    let src = "use a::SqliteBackend;\n// SqliteBackend in a comment\n#[cfg(test)]\nmod tests {\n    use b::SqliteBackend;\n}\nfn f() {}\n";
    let code = non_test_code(src);
    let named: Vec<_> = code
        .iter()
        .filter(|(_, c)| c.contains("SqliteBackend"))
        .map(|(n, _)| *n)
        .collect();
    assert_eq!(named, vec![1], "only the non-test, non-comment line counts");
}
