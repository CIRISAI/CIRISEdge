//! §19.7 forever-memory aggregation pyramid — `AggregationMetaV1` producer
//! (CEG 1.0-RC14, CIRISEdge#152, paired with CIRISVerify#79 / v5.10.0 + CIRISPersist#230 / v8.4.0).
//!
//! §19.7 reframes revocation / retirement / capacity-eviction / aging as **one
//! pressure-driven operator**: a monotonic descent of an item's fidelity toward
//! and below the **noise floor** (the individual-recoverability boundary).
//! Descent never terminates at zero — the *collective gist* (a picture of a
//! thousand pictures) persists below the floor forever, so the federation
//! remembers all of history in **O(log T)** via N→1 aggregation.
//!
//! This module is the **producer** side of §19.7. CIRISVerify v5.10.0 authored
//! the §19.7 wire vectors (since no reference impl predated the contract);
//! this module emits byte-for-byte identical bytes from edge's producer path
//! so the round-trip lifts §19.7 from RC-grade to 1.0.
//!
//! # Wire shape (LOCKED at v1 per §19.7.1)
//!
//! ```text
//! signing_preimage =
//!     AGG-META-v1\0\0\0\0\0 (16 bytes)
//!     || u32_be(version)
//!     || lp(content_id)            // lp = u32_be(len) || utf8(bytes)
//!     || lp(corpus_kind)
//!     || u32_be(tier)
//!     || lp(aggregation_algorithm_id)
//!     || u32_be(source_count)
//!     || member_commitment[32]     // fixed 32 bytes
//!     || lp(noise_floor_descriptor)
//! ```
//!
//! # member_commitment (LOCKED at v1 per §19.7.1.1)
//!
//! The Merkle root over the tier's source member ids, using the §19.1
//! WholenessWitness construction **reused verbatim**:
//!
//! 1. Each `source_member_id` is hashed: `leaf = SHA-256(utf8(member_id))`
//! 2. Leaves lex-sorted (the WW-2 sort discipline)
//! 3. Binary Merkle tree with odd-node duplicate-last (CT convention)
//! 4. Empty input → `SHA-256(b"WW-v1-empty")` sentinel (= `2280d27f...49563464f`)
//!
//! Reusing [`compute_merkle_root`](super::wholeness_witness::compute_merkle_root)
//! ensures the federation runs one Merkle scheme across both §19.1 witness leaves
//! and §19.7 member commitments — no schema fork.

use serde::{Deserialize, Serialize};

use super::wholeness_witness::compute_merkle_root;

/// Locked v1 domain-separation tag for [`AggregationMetaV1`] signed bytes.
/// 16 bytes, null-padded.
pub const AGG_META_DOMAIN: &[u8; 16] = b"AGG-META-v1\0\0\0\0\0";

/// Locked v1 schema version pinned into the signed preimage.
pub const AGG_META_VERSION: u32 = 1;

/// One tier of the §19.7 memory pyramid — which content, at what aggregation
/// tier, over which source members, by which mechanical operator.
///
/// A substrate wire shape (NOT a §4 attestation); byte layout pinned by §19.7.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationMetaV1 {
    /// Schema version (`1`).
    pub version: u32,
    /// The root content this pyramid is for.
    pub content_id: String,
    /// `"trace" | "blob" | "av_chunk" | …`.
    pub corpus_kind: String,
    /// `0` = source granularity; higher = more aggregated.
    pub tier: u32,
    /// Opaque codec id, e.g. `"raptorq-pyramid-v1"`.
    pub aggregation_algorithm_id: String,
    /// N members aggregated into this tier (the descent fan-in).
    pub source_count: u32,
    /// §19.7.1.1 Merkle root over the source member ids (raw 32 bytes).
    pub member_commitment: [u8; 32],
    /// What survives below the floor (codec-specific, canonical).
    pub noise_floor_descriptor: String,
}

impl AggregationMetaV1 {
    /// Build the §19.7.1 canonical signing preimage (normative byte order).
    ///
    /// Two implementations of §19.7.1 MUST produce byte-identical output from
    /// byte-identical input. Verified against CIRISVerify v5.10.0's authored
    /// vectors in `tests/conformance_vectors_v19_7.rs`.
    #[must_use]
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            16 + 4
                + (4 + self.content_id.len())
                + (4 + self.corpus_kind.len())
                + 4
                + (4 + self.aggregation_algorithm_id.len())
                + 4
                + 32
                + (4 + self.noise_floor_descriptor.len()),
        );
        out.extend_from_slice(AGG_META_DOMAIN);
        out.extend_from_slice(&self.version.to_be_bytes());
        push_lp(&mut out, self.content_id.as_bytes());
        push_lp(&mut out, self.corpus_kind.as_bytes());
        out.extend_from_slice(&self.tier.to_be_bytes());
        push_lp(&mut out, self.aggregation_algorithm_id.as_bytes());
        out.extend_from_slice(&self.source_count.to_be_bytes());
        out.extend_from_slice(&self.member_commitment);
        push_lp(&mut out, self.noise_floor_descriptor.as_bytes());
        out
    }
}

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    let len: u32 = u32::try_from(bytes.len()).expect("lp field length exceeds u32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// §19.7.1.1 — compute the `member_commitment` Merkle root over a tier's
/// source member ids. Reuses the §19.1 WholenessWitness construction
/// **verbatim**: pass the UTF-8 bytes of each member id as a leaf;
/// [`compute_merkle_root`] handles lex-sort + leaf hashing + odd-node
/// duplicate-last + the `WW-v1-empty` empty sentinel.
///
/// Two implementations of §19.7.1.1 MUST produce byte-identical 32-byte output
/// from byte-identical input. Matches CIRISVerify v5.10.0's
/// `holonomic::aggregation::member_commitment` byte-for-byte.
#[must_use]
pub fn compute_member_commitment(source_member_ids: &[String]) -> [u8; 32] {
    let leaves: Vec<Vec<u8>> = source_member_ids
        .iter()
        .map(|id| id.as_bytes().to_vec())
        .collect();
    compute_merkle_root(&leaves)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_meta() -> AggregationMetaV1 {
        // Matches CIRISVerify v5.10.0's authored vector at
        // tests/vectors/holonomic_v19_7/aggregation_meta/canonical_bytes.json
        // so the byte-equality assertion proves cross-impl conformance.
        let source_ids: Vec<String> = ["src-001", "src-002", "src-003"]
            .into_iter()
            .map(String::from)
            .collect();
        let member_commitment = compute_member_commitment(&source_ids);
        AggregationMetaV1 {
            version: AGG_META_VERSION,
            content_id: "content-root-fixed".to_string(),
            corpus_kind: "trace".to_string(),
            tier: 2,
            aggregation_algorithm_id: "raptorq-pyramid-v1".to_string(),
            source_count: 3,
            member_commitment,
            noise_floor_descriptor: "mean+stddev".to_string(),
        }
    }

    #[test]
    fn agg_meta_domain_is_16_bytes_null_padded() {
        assert_eq!(AGG_META_DOMAIN.len(), 16);
        assert_eq!(&AGG_META_DOMAIN[..11], b"AGG-META-v1");
        assert_eq!(&AGG_META_DOMAIN[11..], &[0u8; 5]);
    }

    #[test]
    fn signing_preimage_matches_verify_v5_10_0_vector_byte_for_byte() {
        // Locked v1 expected bytes from CIRISVerify v5.10.0's authored vector
        // (src/ciris-verify-core/tests/vectors/holonomic_v19_7/aggregation_meta/canonical_bytes.json).
        let expected_hex = "4147472d4d4554412d763100000000000000000100000012636f6e74656e742d726f6f742d66697865640000000574726163650000000200000012726170746f72712d707972616d69642d763100000003a10bc0ec2399f1cd431be79a863385a4b895987dae604aaf2ec3532f3753bd9d0000000b6d65616e2b737464646576";
        let actual = fixed_meta().signing_preimage();
        let mut actual_hex = String::with_capacity(actual.len() * 2);
        for b in &actual {
            use std::fmt::Write;
            write!(&mut actual_hex, "{b:02x}").expect("hex write");
        }
        assert_eq!(
            actual_hex, expected_hex,
            "AggregationMetaV1 preimage MUST match Verify v5.10.0 byte-for-byte"
        );
    }

    #[test]
    fn member_commitment_empty_returns_ww_v1_sentinel() {
        // The §19.7.1.1 / §19.1 shared sentinel: empty input → SHA-256("WW-v1-empty").
        let root = compute_member_commitment(&[]);
        let mut hex = String::with_capacity(64);
        for b in &root {
            use std::fmt::Write;
            write!(&mut hex, "{b:02x}").expect("hex write");
        }
        assert_eq!(
            hex,
            "2280d27f232100367e86211b5349fe0d6fbaee98e4c2b489a86008049563464f"
        );
    }

    #[test]
    fn member_commitment_lex_sorts_internally() {
        // Verify v5.10.0's authored vector at member_commitment/three_unsorted.json
        // uses ["m3", "m1", "m2"] (unsorted) → expects 1bfd0a8a... Our impl must
        // produce the same root from the same unsorted input.
        let source: Vec<String> = ["m3", "m1", "m2"].into_iter().map(String::from).collect();
        let root = compute_member_commitment(&source);
        let mut hex = String::with_capacity(64);
        for b in &root {
            use std::fmt::Write;
            write!(&mut hex, "{b:02x}").expect("hex write");
        }
        assert_eq!(
            hex, "1bfd0a8a367f375a67ad08b3f19cf1a6d82876e753eea631a698d7dcca58226d",
            "member_commitment must lex-sort source ids (WW-2 discipline)"
        );
    }

    #[test]
    fn member_commitment_matches_aggregation_meta_struct_field() {
        // The struct's `member_commitment` field MUST equal the
        // compute_member_commitment over the documented source ids; otherwise
        // the AggregationMetaV1's signed preimage carries a commitment that
        // verifiers reject as inconsistent.
        let source_ids: Vec<String> = ["src-001", "src-002", "src-003"]
            .into_iter()
            .map(String::from)
            .collect();
        let expected = compute_member_commitment(&source_ids);
        let meta = fixed_meta();
        assert_eq!(meta.member_commitment, expected);
    }

    #[test]
    fn signing_preimage_changes_on_any_field_mutation() {
        // Every field MUST appear in the canonical preimage. Mutate each in turn
        // and assert the preimage changes — guards against future field-omission
        // regressions that would break the cross-impl byte-equality.
        let base = fixed_meta().signing_preimage();

        let mut m = fixed_meta();
        m.version += 1;
        assert_ne!(m.signing_preimage(), base, "version must affect preimage");

        let mut m = fixed_meta();
        m.content_id.push_str("-mutated");
        assert_ne!(
            m.signing_preimage(),
            base,
            "content_id must affect preimage"
        );

        let mut m = fixed_meta();
        m.corpus_kind = "blob".to_string();
        assert_ne!(
            m.signing_preimage(),
            base,
            "corpus_kind must affect preimage"
        );

        let mut m = fixed_meta();
        m.tier += 1;
        assert_ne!(m.signing_preimage(), base, "tier must affect preimage");

        let mut m = fixed_meta();
        m.aggregation_algorithm_id = "av1-svc-quality-v1".to_string();
        assert_ne!(
            m.signing_preimage(),
            base,
            "aggregation_algorithm_id must affect preimage"
        );

        let mut m = fixed_meta();
        m.source_count += 1;
        assert_ne!(
            m.signing_preimage(),
            base,
            "source_count must affect preimage"
        );

        let mut m = fixed_meta();
        m.member_commitment[0] ^= 0xff;
        assert_ne!(
            m.signing_preimage(),
            base,
            "member_commitment must affect preimage"
        );

        let mut m = fixed_meta();
        m.noise_floor_descriptor = "max".to_string();
        assert_ne!(
            m.signing_preimage(),
            base,
            "noise_floor_descriptor must affect preimage"
        );
    }
}
