//! CEG 1.0-RC11 §19 conformance vectors — the #57 freeze gate.
//!
//! Emits byte-exact KAT (Known Answer Test) fixtures for every §19 wire
//! shape into `conformance_vectors/19/*.json`. CIRISVerify v5.8.0's
//! `ciris_verify_core::holonomic` MUST reproduce each emitted vector
//! byte-for-byte to ratify cross-impl conformance.
//!
//! Each test in this module either:
//!
//! 1. **EMITS** — if the JSON file does NOT exist, the test generates
//!    the canonical bytes / merkle root / nonce for a fixed deterministic
//!    input and WRITES the JSON vector file. The test panics with a
//!    "vector EMITTED — commit and re-run" message so CI catches first-
//!    run uncommitted output.
//!
//! 2. **VERIFIES** — if the JSON file exists, the test re-generates the
//!    canonical bytes from the same input and asserts byte-equality
//!    against the checked-in expected bytes. Any divergence is a wire
//!    drift, not a missing vector.
//!
//! This pattern (emit-once, verify-always) is the locked-at-v1 KAT
//! discipline matching the §19.6 freeze gate.

use ciris_edge::holonomic::recursive_trust_bootstrap::{SignedClaim, MAX_WITNESS_CHAIN_LEN};
use ciris_edge::holonomic::swarm_rarity::{
    FountainCompressRequest, FountainHoldingClaim, COMPRESS_REQUEST_DOMAIN,
    COMPRESS_REQUEST_VERSION, HOLDING_CLAIM_DOMAIN, HOLDING_CLAIM_VERSION,
};
use ciris_edge::holonomic::wholeness_witness::{
    compute_merkle_root, WholenessWitness, WITNESS_PREIMAGE_DOMAIN,
};

/// v1 wire schema version for [`WholenessWitness`] — locked at v1
/// alongside the WW-PREIMAGE-v1 domain. Mirrors the test-time u16
/// field encoding.
const WITNESS_VERSION_V1: u16 = 1;
/// v1 wire schema version for [`SignedClaim`] — locked at v1 alongside
/// the CIRIS-CLAIM-v1 domain.
const CLAIM_VERSION_V1: u16 = 1;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const VECTORS_ROOT: &str = "conformance_vectors/19";

/// A single canonical-bytes KAT — input → expected hex-encoded bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CanonicalBytesVector {
    vector_id: String,
    description: String,
    domain_separator_hex: String,
    #[serde(flatten)]
    input: serde_json::Value,
    expected_canonical_bytes_hex: String,
}

/// A Merkle-root KAT — leaf set → expected 32-byte root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct MerkleRootVector {
    vector_id: String,
    description: String,
    leaves_hex: Vec<String>,
    expected_root_hex: String,
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_ROOT)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("hex write");
    }
    s
}

/// EMIT-or-VERIFY a JSON vector. First call writes the file and panics
/// (so CI catches uncommitted output); subsequent calls verify byte-
/// equality against the checked-in file.
fn emit_or_verify<T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug>(
    relative_path: &str,
    actual: &T,
) {
    let path = vectors_dir().join(relative_path);
    if !path.exists() {
        // EMIT path
        std::fs::create_dir_all(path.parent().unwrap()).expect("create vector dir");
        let json = serde_json::to_string_pretty(actual).expect("serialize vector");
        std::fs::write(&path, json + "\n").expect("write vector file");
        panic!("vector EMITTED: {relative_path} — commit conformance_vectors/ and re-run");
    }
    // VERIFY path
    let raw = std::fs::read_to_string(&path).expect("read vector file");
    let expected: T = serde_json::from_str(&raw).expect("parse vector file");
    assert_eq!(
        actual, &expected,
        "VECTOR DRIFT at {relative_path} — substrate wire changed without bumping vector"
    );
}

// ──────────────────────────── §19.1 WholenessWitness ────────────────────

#[test]
fn vector_wholeness_witness_canonical_preimage_empty_namespaces() {
    // Empty leaf set → empty witness; canonical preimage covers the
    // (peer_id, epoch_id, merkle_root, leaf_count, claim_namespaces,
    // observed_at_unix_ms, witness_version) tuple with the
    // WW-PREIMAGE-v1 domain separator.
    let witness = WholenessWitness {
        peer_id: "test_peer_alpha".to_string(),
        epoch_id: 42,
        merkle_root: compute_merkle_root(&[]),
        leaf_count: 0,
        claim_namespaces: vec![],
        observed_at_unix_ms: 1_700_000_000_000,
        witness_version: WITNESS_VERSION_V1,
        signature: String::new(),
        signature_ml_dsa_65: String::new(),
        pqc_key_id: String::new(),
    };
    let vector = CanonicalBytesVector {
        vector_id: "wholeness_witness/canonical_preimage/empty".to_string(),
        description: "WholenessWitness canonical preimage at epoch=42 with empty leaf set; \
                      merkle_root is the WW-v1-empty sentinel SHA-256(\"WW-v1-empty\"); \
                      claim_namespaces is empty."
            .to_string(),
        domain_separator_hex: hex_encode(WITNESS_PREIMAGE_DOMAIN),
        input: serde_json::to_value(&witness).expect("serialize input"),
        expected_canonical_bytes_hex: hex_encode(&witness.canonical_preimage_bytes()),
    };
    emit_or_verify("wholeness_witness/canonical_preimage_empty.json", &vector);
}

#[test]
fn vector_wholeness_witness_canonical_preimage_with_namespaces() {
    let witness = WholenessWitness {
        peer_id: "test_peer_beta".to_string(),
        epoch_id: 17,
        merkle_root: compute_merkle_root(&[b"leaf-zero".to_vec(), b"leaf-one".to_vec()]),
        leaf_count: 2,
        claim_namespaces: vec![
            "holding_claim".to_string(),
            "relay_capacity".to_string(),
            "signed_claim".to_string(),
        ],
        observed_at_unix_ms: 1_700_000_001_000,
        witness_version: WITNESS_VERSION_V1,
        signature: String::new(),
        signature_ml_dsa_65: String::new(),
        pqc_key_id: String::new(),
    };
    let vector = CanonicalBytesVector {
        vector_id: "wholeness_witness/canonical_preimage/three_namespaces".to_string(),
        description: "WholenessWitness canonical preimage at epoch=17 with two leaves and \
                      three claim_namespaces (lex-sorted internally)."
            .to_string(),
        domain_separator_hex: hex_encode(WITNESS_PREIMAGE_DOMAIN),
        input: serde_json::to_value(&witness).expect("serialize input"),
        expected_canonical_bytes_hex: hex_encode(&witness.canonical_preimage_bytes()),
    };
    emit_or_verify(
        "wholeness_witness/canonical_preimage_three_namespaces.json",
        &vector,
    );
}

#[test]
fn vector_merkle_root_empty_returns_ww_v1_sentinel() {
    let root = compute_merkle_root(&[]);
    let vector = MerkleRootVector {
        vector_id: "merkle_root/empty_sentinel".to_string(),
        description: "Empty leaf set returns the WW-v1-empty sentinel: SHA-256(b\"WW-v1-empty\"). \
                      Verify v5.8.0's compute_merkle_root MUST emit byte-identical bytes."
            .to_string(),
        leaves_hex: vec![],
        expected_root_hex: hex_encode(&root),
    };
    emit_or_verify("merkle_root/empty_sentinel.json", &vector);
}

#[test]
fn vector_merkle_root_single_leaf() {
    let leaf = b"sole-leaf-fixed-input".to_vec();
    let root = compute_merkle_root(std::slice::from_ref(&leaf));
    let vector = MerkleRootVector {
        vector_id: "merkle_root/single_leaf".to_string(),
        description: "Single-leaf Merkle root: SHA-256(SHA-256(leaf_bytes)). \
                      Tests the leaf-hash-then-root degenerate case."
            .to_string(),
        leaves_hex: vec![hex_encode(&leaf)],
        expected_root_hex: hex_encode(&root),
    };
    emit_or_verify("merkle_root/single_leaf.json", &vector);
}

#[test]
fn vector_merkle_root_three_leaves_odd_node_duplicated() {
    // Three leaves exercises the odd-node duplicate-last invariant.
    let leaves: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 8]).collect();
    let root = compute_merkle_root(&leaves);
    let vector = MerkleRootVector {
        vector_id: "merkle_root/three_leaves_odd_dup".to_string(),
        description:
            "Three leaves: layer 1 produces 2 nodes (l0 hashed, l1 hashed, l2 hashed + l2 dup); \
                      layer 2 produces 1 root. Tests odd-node duplicate-last convention."
                .to_string(),
        leaves_hex: leaves.iter().map(|l| hex_encode(l)).collect(),
        expected_root_hex: hex_encode(&root),
    };
    emit_or_verify("merkle_root/three_leaves_odd_dup.json", &vector);
}

#[test]
fn vector_merkle_root_lex_sort_invariance() {
    // The same leaves in different input order MUST produce the same
    // root — compute_merkle_root lex-sorts internally (§19.1 WW-2).
    let leaves_a = vec![b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()];
    let leaves_b = vec![b"gamma".to_vec(), b"alpha".to_vec(), b"beta".to_vec()];
    let root_a = compute_merkle_root(&leaves_a);
    let root_b = compute_merkle_root(&leaves_b);
    assert_eq!(
        root_a, root_b,
        "compute_merkle_root MUST lex-sort leaves (§19.1 WW-2)"
    );
    let vector = MerkleRootVector {
        vector_id: "merkle_root/lex_sort_invariance".to_string(),
        description: "Leaves alpha, beta, gamma — input order MUST NOT change the root. \
                      §19.1 WW-2 lex-sort guarantee."
            .to_string(),
        leaves_hex: vec![
            hex_encode(b"alpha"),
            hex_encode(b"beta"),
            hex_encode(b"gamma"),
        ],
        expected_root_hex: hex_encode(&root_a),
    };
    emit_or_verify("merkle_root/lex_sort_invariance.json", &vector);
}

// ──────────────────────────── §19.2 SignedClaim ──────────────────────────

#[test]
fn vector_signed_claim_canonical_bytes_no_owner_binding() {
    // SignedClaim with no owner-binding (back-compat — legacy and
    // all-None claims produce byte-identical canonical values).
    let claim = SignedClaim {
        claim_kind: "trust_grant".to_string(),
        signer_peer_id: "test_signer_gamma".to_string(),
        claim_bytes: vec![0x01, 0x02, 0x03, 0xff],
        signed_at_unix_ms: 1_700_000_000_000,
        claim_version: CLAIM_VERSION_V1,
        user_owner: None,
        delegates_to: None,
        identity_occurrence: None,
        signature_ed25519_base64: String::new(),
        signature_ml_dsa_65_base64: String::new(),
        verified: false,
    };
    let vector = CanonicalBytesVector {
        vector_id: "signed_claim/canonical_bytes/no_owner_binding".to_string(),
        description: "SignedClaim canonical bytes with no owner-binding fields (all-None). \
                      The CIRIS-CLAIM-v1 domain separator + locked field order applies; \
                      owner-binding trio appended as 0x00 presence flags (3 trailing zero bytes)."
            .to_string(),
        domain_separator_hex: hex_encode(SignedClaim::DOMAIN_SEP),
        input: serde_json::to_value(&claim).expect("serialize input"),
        expected_canonical_bytes_hex: hex_encode(&claim.canonical_value()),
    };
    emit_or_verify(
        "signed_claim/canonical_bytes_no_owner_binding.json",
        &vector,
    );
}

#[test]
fn vector_signed_claim_canonical_bytes_with_owner_binding() {
    // SignedClaim with full owner-binding (§5.6.8.10 destination
    // membership gate ready).
    let claim = SignedClaim {
        claim_kind: "membership_request".to_string(),
        signer_peer_id: "test_signer_delta".to_string(),
        claim_bytes: vec![0xfe, 0xed, 0xfa, 0xce],
        signed_at_unix_ms: 1_700_000_002_000,
        claim_version: CLAIM_VERSION_V1,
        user_owner: Some("user_root_peer".to_string()),
        delegates_to: Some("delegated_peer_target".to_string()),
        identity_occurrence: Some("occurrence_001".to_string()),
        signature_ed25519_base64: String::new(),
        signature_ml_dsa_65_base64: String::new(),
        verified: false,
    };
    let vector = CanonicalBytesVector {
        vector_id: "signed_claim/canonical_bytes/with_owner_binding".to_string(),
        description: "SignedClaim canonical bytes with full owner-binding trio (user_owner, \
                      delegates_to, identity_occurrence all Some). Each appended as 0x01 \
                      presence flag + length-prefixed UTF-8."
            .to_string(),
        domain_separator_hex: hex_encode(SignedClaim::DOMAIN_SEP),
        input: serde_json::to_value(&claim).expect("serialize input"),
        expected_canonical_bytes_hex: hex_encode(&claim.canonical_value()),
    };
    emit_or_verify(
        "signed_claim/canonical_bytes_with_owner_binding.json",
        &vector,
    );
}

// ──────────────────────────── §19.3 Fountain ────────────────────────────

#[test]
fn vector_fountain_holding_claim_canonical_bytes() {
    let claim = FountainHoldingClaim::new(
        "test_holder_epsilon",
        "content_id_fixed_alpha",
        vec![5, 1, 3, 2, 4], // intentionally unsorted; encoder sorts
        1_700_000_003_000,
    );
    let vector = CanonicalBytesVector {
        vector_id: "fountain_holding_claim/canonical_bytes".to_string(),
        description: "FountainHoldingClaim canonical bytes — symbol_ids [5,1,3,2,4] sorted \
                      ascending to [1,2,3,4,5] before encoding (§19.3). Domain \
                      ciris-edge/holding-claim/v1."
            .to_string(),
        domain_separator_hex: hex_encode(HOLDING_CLAIM_DOMAIN),
        input: serde_json::to_value(&claim).expect("serialize input"),
        expected_canonical_bytes_hex: hex_encode(&claim.canonical_bytes()),
    };
    emit_or_verify("fountain_holding_claim/canonical_bytes.json", &vector);
}

#[test]
fn vector_fountain_compress_request_canonical_bytes() {
    let req = FountainCompressRequest::new(
        "test_compressor_zeta",
        "content_id_fixed_beta",
        100,
        200,
        1_700_000_004_000,
    );
    let vector = CanonicalBytesVector {
        vector_id: "fountain_compress_request/canonical_bytes".to_string(),
        description: "FountainCompressRequest canonical bytes — evicting symbol range \
                      [100, 200) with deadline at fixed unix_ms. Domain \
                      ciris-edge/compress-request/v1."
            .to_string(),
        domain_separator_hex: hex_encode(COMPRESS_REQUEST_DOMAIN),
        input: serde_json::to_value(&req).expect("serialize input"),
        expected_canonical_bytes_hex: hex_encode(&req.canonical_bytes()),
    };
    emit_or_verify("fountain_compress_request/canonical_bytes.json", &vector);
}

// ──────────────────────────── §19 schema-version locks ──────────────────

#[test]
fn vector_schema_version_anchors() {
    // The version constants are wire-locked at v1. Pinning them here as
    // an explicit vector is the cleanest way for Verify to assert wire
    // schema lockstep without re-deriving from source.
    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct SchemaVersionLocks {
        witness_version: u32,
        claim_version: u32,
        holding_claim_version: u32,
        compress_request_version: u32,
        max_witness_chain_len: u32,
    }
    let locks = SchemaVersionLocks {
        witness_version: u32::from(WITNESS_VERSION_V1),
        claim_version: u32::from(CLAIM_VERSION_V1),
        holding_claim_version: HOLDING_CLAIM_VERSION,
        compress_request_version: COMPRESS_REQUEST_VERSION,
        max_witness_chain_len: u32::try_from(MAX_WITNESS_CHAIN_LEN).unwrap(),
    };
    emit_or_verify("schema_versions.json", &locks);
}

#[test]
fn vector_domain_separators() {
    // All §19 domain separators in one place — Verify can read this
    // single file to confirm cross-impl domain-sep agreement.
    #[allow(clippy::struct_field_names)]
    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct DomainSeparators {
        witness_preimage_v1_hex: String,
        signed_claim_v1_hex: String,
        holding_claim_v1_hex: String,
        compress_request_v1_hex: String,
    }
    let seps = DomainSeparators {
        witness_preimage_v1_hex: hex_encode(WITNESS_PREIMAGE_DOMAIN),
        signed_claim_v1_hex: hex_encode(SignedClaim::DOMAIN_SEP),
        holding_claim_v1_hex: hex_encode(HOLDING_CLAIM_DOMAIN),
        compress_request_v1_hex: hex_encode(COMPRESS_REQUEST_DOMAIN),
    };
    emit_or_verify("domain_separators.json", &seps);
}

// Sanity test on the emit-or-verify infrastructure itself.
#[test]
fn emit_or_verify_path_resolves() {
    let p = vectors_dir();
    assert!(
        p.is_absolute() || p.exists(),
        "vectors_dir resolves cleanly"
    );
    assert!(p.ends_with(Path::new(VECTORS_ROOT)));
}
