//! Build-manifest extras — `EdgeExtras` shape.
//!
//! Mirrors `ciris_persist::manifest::PersistExtras` and
//! `ciris_lens::LensExtras`. Carries primitive-specific provenance
//! that downstream verifiers gate on alongside the binary hash.
//!
//! Emitted by `src/bin/emit_edge_extras.rs` during the `build-manifest`
//! CI job; the JSON output is fed to `ciris-build-sign --extras`.
//!
//! Trust posture: the BuildManifest hybrid (Ed25519 + ML-DSA-65)
//! signature is the cryptographic root for "this binary was built
//! by CIRISAI's signing key from this commit." `EdgeExtras` adds
//! "and these are its primitive-specific properties" — what wire
//! schemas it supports, what transports are compiled in, what
//! version of persist it pins against, what its spec contracts
//! are. Consumers verifying a CIRISEdge build manifest from
//! CIRISRegistry can refuse builds whose properties don't match
//! their tier / federation policy (OQ-12 closure).

use serde::{Deserialize, Serialize};

/// Edge's primitive-specific build-manifest extras.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeExtras {
    /// Wire-format schema versions this build accepts. AV-7 closure
    /// — peers gate on a strict allowlist; consumers refuse
    /// envelopes whose `edge_schema_version` isn't in this list.
    pub supported_schema_versions: Vec<String>,

    /// Cargo features compiled into this build. Useful for
    /// "is this build Reticulum-capable?" / "is this an HTTP-only
    /// fallback build?" gates at deploy time.
    pub enabled_transports: Vec<String>,

    /// `ciris-persist` version pin — must be `>=` whatever floor
    /// edge's verify pipeline + outbound dispatcher require
    /// (currently 0.4.1 for `verify_hybrid_via_directory` +
    /// `edge_outbound_queue` substrate).
    pub persist_pin: String,

    /// `ciris-keyring` + `ciris-crypto` version pin. Same source as
    /// persist's pin — the federation runs single-versioned upstream
    /// crypto stacks.
    pub keyring_pin: String,

    /// SHA-256 over the lex-sorted Cargo.lock dep tree (or `cargo
    /// tree` output) — pinpoints the exact transitive closure this
    /// build linked against. Lets a verifier reject builds with
    /// known-vulnerable deps without recompiling locally.
    pub dep_tree_sha256: String,

    /// SHA-256 over the lex-sorted concatenation of the wire-format
    /// and threat-model spec files (CIRIS_EDGE, EDGE_OUTBOUND_QUEUE,
    /// THREAT_MODEL). Drift here means the build's stated contract
    /// has shifted; downstream peers can refuse to upgrade until
    /// they re-review.
    pub spec_set_sha256: String,
}
