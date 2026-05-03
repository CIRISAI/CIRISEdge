//! Emit `EdgeExtras` JSON for the build manifest.
//!
//! Invoked from CI before `ciris-build-sign` to produce the
//! primitive-specific extras blob the BuildManifest references.
//! Reads the source tree directly (Cargo.toml + Cargo.lock + spec
//! docs + the runtime's `SchemaVersion` enum) so the extras are
//! deterministic per checkout.
//!
//! Usage:
//!
//! ```text
//! cargo run --release --bin emit_edge_extras > edge-extras.json
//! ```
//!
//! Output is compact JSON on stdout. Non-zero exit = something
//! broke; the JSON in stdout is incomplete and MUST NOT be signed.

use std::process::Command;

use ciris_edge::manifest::EdgeExtras;
use sha2::{Digest, Sha256};

fn main() {
    let extras = match build() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("emit_edge_extras: {e}");
            std::process::exit(1);
        }
    };
    let json = serde_json::to_string(&extras).expect("EdgeExtras serialises");
    println!("{json}");
}

fn build() -> Result<EdgeExtras, String> {
    // Hard-coded to the SchemaVersion enum's variants. The enum is
    // exhaustive-matched at the verify pipeline (AV-7 strict
    // allowlist); this list is the externally-visible mirror.
    let supported_schema_versions = vec!["1.0.0".to_string()];

    let enabled_transports = current_transports();

    let persist_pin = read_dep_pin("ciris-persist").unwrap_or_else(|| "unknown".to_string());
    let keyring_pin = read_dep_pin("ciris-keyring").unwrap_or_else(|| "unknown".to_string());

    let dep_tree_sha256 = hash_dep_tree().map_err(|e| format!("dep_tree_sha256: {e}"))?;
    let spec_set_sha256 = hash_spec_set().map_err(|e| format!("spec_set_sha256: {e}"))?;

    Ok(EdgeExtras {
        supported_schema_versions,
        enabled_transports,
        persist_pin,
        keyring_pin,
        dep_tree_sha256,
        spec_set_sha256,
    })
}

/// Which transports are compiled into the running emit binary. Each
/// `transport-*` Cargo feature enables a `cfg(feature = "...")` guard
/// in `src/transport/`; we mirror those here.
fn current_transports() -> Vec<String> {
    let mut v = Vec::new();
    if cfg!(feature = "transport-http") {
        v.push("http".to_string());
    }
    // Future: transport-reticulum-rs, transport-leviculum, transport-lora, etc.
    v.sort();
    v
}

/// Read the version constraint for `name` from Cargo.toml.
/// Falls back to None if the dep isn't found or the line shape
/// doesn't match.
fn read_dep_pin(name: &str) -> Option<String> {
    let toml = std::fs::read_to_string("Cargo.toml").ok()?;
    for line in toml.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{name} ")) {
            // Lines like `ciris-persist = { git = "...", tag = "v0.4.1", ... }`
            if let Some(start) = rest.find("tag = \"") {
                let after = &rest[start + 7..];
                if let Some(end) = after.find('"') {
                    return Some(after[..end].to_string());
                }
            }
        }
    }
    None
}

/// SHA-256 over `cargo tree --prefix none --no-dedupe` output.
/// Deterministic across machines (cargo tree is stable for a given
/// Cargo.lock); the hash is a strong fingerprint for "this exact
/// transitive closure."
fn hash_dep_tree() -> Result<String, String> {
    let output = Command::new("cargo")
        .args([
            "tree",
            "--prefix",
            "none",
            "--no-dedupe",
            "--target",
            "x86_64-unknown-linux-gnu",
        ])
        .output()
        .map_err(|e| format!("spawn cargo tree: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo tree failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(format!("sha256:{:x}", Sha256::digest(&output.stdout)))
}

/// SHA-256 over the lex-sorted concatenation of edge's spec files,
/// line-endings normalised to LF + a trailing newline-after-each-file.
/// Order of file traversal doesn't change the hash.
fn hash_spec_set() -> Result<String, String> {
    let files = [
        "FSD/CIRIS_EDGE.md",
        "FSD/EDGE_OUTBOUND_QUEUE.md",
        "FSD/OPEN_QUESTIONS.md",
        "MISSION.md",
        "docs/THREAT_MODEL.md",
    ];
    let mut sorted = files.to_vec();
    sorted.sort_unstable();

    let mut hasher = Sha256::new();
    for path in sorted {
        let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
        // Normalise CRLF → LF so the hash is stable across OSes.
        let normalised: Vec<u8> = bytes.iter().copied().filter(|&b| b != b'\r').collect();
        hasher.update(&normalised);
        hasher.update(b"\n");
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}
