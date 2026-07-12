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
//! # The canonical shapes are verify's now (CIRISEdge#267 / CIRISVerify#167)
//!
//! [`AggregationMetaV1`], its `signing_preimage`, the §19.7.1.2 dominance
//! surface ([`effective_source_count`] + [`passes_dominance_gate`]), the
//! §19.7.1.1 [`member_commitment`] Merkle, and the PQC-mandatory ingest gate
//! ([`verify_aggregation_meta`]) live in
//! [`ciris_verify_core::holonomic::aggregation`], the canonical home for every
//! §19/§Q signed shape, on verify's shared `Preimage` builder + bound-hybrid
//! gate (verify v8.7.0). Edge **re-exports** them here so the producer path
//! keeps one import path, and adds only the producer-side tier assembly below.
//!
//! Edge previously carried a standalone v1-only reimplementation (v4.3.0 /
//! CIRISEdge#152) — its own `push_lp` preimage discipline and a serde-derived
//! struct. That predated the #167 wire change; #267 dropped it in favor of
//! verify's, exactly as #269 did for the §Q storage-contention shapes. The
//! domain separator is byte-identical (`AGG-META-v1\0\0\0\0\0`) and a
//! **version-1** tier's preimage is **byte-identical** to the pre-#167 layout,
//! so every already-signed v1 tier and the committed
//! `conformance_vectors/19_7/aggregation_meta/canonical_bytes.json` golden
//! verify unchanged.
//!
//! # Wire shape (§19.7.1, v2 gated per §19.7.1.2 / CIRISVerify#167)
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
//!     [|| u32_be(n_eff)  iff version >= 2]   // §19.7.1.2 signed dominance surface
//! ```
//!
//! The v2 trailing `u32_be(n_eff)` makes the fold's **effective** source count
//! checkable: `source_count` is raw N and `member_commitment` is unweighted,
//! so a composite where one source supplies ~90% of the mass (the 900/1000
//! case, CC 6.1.2 noise floor) was previously indistinguishable from a
//! balanced fold. Downstream dominance gates ([`passes_dominance_gate`])
//! require a *signed* `n_eff` — a v1 tier fails closed.
//!
//! # member_commitment (LOCKED at v1 per §19.7.1.1)
//!
//! The Merkle root over the tier's source member ids, using the §19.1
//! WholenessWitness construction **reused verbatim** (`leaf =
//! SHA-256(utf8(member_id))`, lex-sort, odd-node duplicate-last, `WW-v1-empty`
//! empty sentinel) — one Merkle scheme across §19.1 + §19.7, no schema fork.

// ── the canonical §19.7 shapes + verify gates (verify-owned) ──────────
pub use ciris_verify_core::holonomic::aggregation::{
    descend_order, effective_source_count, mass_commitment, mass_to_fixed, member_commitment,
    passes_dominance_gate, passes_multiplicity_gate, verify_aggregation_meta,
    verify_member_commitment, AggregationMetaV1, AggregationMetaVerification,
    MASS_FIXED_POINT_SCALE,
};
pub use ciris_verify_core::holonomic::preimage::DOMAIN_AGG_META as AGG_META_DOMAIN;

/// §19.7.1.1 producer alias — the historical edge name for verify's canonical
/// [`member_commitment`], kept so producer call-sites and the #57 freeze-gate
/// vector tests read unchanged across the #267 re-export cut.
pub use ciris_verify_core::holonomic::aggregation::member_commitment as compute_member_commitment;

/// Locked v1 schema version — the pre-#167 layout (no signed `n_eff`).
/// Preserved for the committed v1 goldens; **new tiers MUST be v2**
/// ([`AGG_META_VERSION_V2`]) so downstream can dominance-gate.
pub const AGG_META_VERSION: u32 = 1;

/// §19.7.1.2 schema version (CIRISVerify#167 / CC 6.1.2): the v1 layout plus a
/// trailing big-endian `u32(n_eff)` in the signed preimage. What
/// [`assemble_tier_meta_v2`] emits.
pub const AGG_META_VERSION_V2: u32 = 2;

/// §19.7.1.3 schema version (CIRISVerify#191 / CC 6.1.2.1.2 R9): the v2 layout
/// plus a trailing `u32(max_source_multiplicity) ‖ mass_commitment[32]` in the
/// signed preimage. What [`assemble_tier_meta_v3`] emits — the **go-forward**
/// version: persist ≥ 16 fail-closes any tier below v3 at `put_aggregated_tier`
/// (the flag-day cut; no deprecation window).
pub const AGG_META_VERSION_V3: u32 = 3;

/// §19.7.1.2 producer side (CIRISEdge#267): assemble a **version-2** tier meta
/// from the per-member source ids and content masses — computing
/// `source_count` (raw fan-in N), the §19.7.1.1 [`member_commitment`] Merkle,
/// and the effective source count `n_eff = round((Σmᵢ)² / Σmᵢ²)`
/// ([`effective_source_count`], the inverse-Simpson / participation ratio) so
/// the emitted meta carries the signed dominance surface downstream gates
/// check. A balanced fold of N equal-mass sources has `n_eff == N`; the
/// 900/1000-dominated case collapses toward `n_eff ≈ 1` and
/// [`passes_dominance_gate`] rejects it.
///
/// `member_masses[i]` is the content mass of `source_member_ids[i]`
/// (codec-specific — e.g. source bytes folded into the tier). The two slices
/// MUST be index-aligned; masses need not be pre-sorted (`n_eff` is
/// order-independent) and `member_commitment` lex-sorts internally.
///
/// Signing is the caller's: the returned meta's
/// [`signing_preimage`](AggregationMetaV1::signing_preimage) covers `n_eff`
/// (version ≥ 2), so the bound-hybrid signature binds the dominance surface.
///
/// **#266 gap note:** the §19.7 pyramid *fold operator* (CIRISEdge#266) is the
/// in-tree call-site that will drive this when it assembles tiers from held
/// fountain content; until it lands, this is the complete producer surface
/// for the #167 wire change, exercised by the conformance vectors.
///
/// # Panics
///
/// If `source_member_ids` and `member_masses` lengths differ, or the fan-in
/// exceeds `u32::MAX` (a tier cannot represent it on the wire).
#[must_use]
pub fn assemble_tier_meta_v2(
    content_id: &str,
    corpus_kind: &str,
    tier: u32,
    aggregation_algorithm_id: &str,
    source_member_ids: &[String],
    member_masses: &[f64],
    noise_floor_descriptor: &str,
) -> AggregationMetaV1 {
    assert_eq!(
        source_member_ids.len(),
        member_masses.len(),
        "source_member_ids and member_masses must be index-aligned"
    );
    let source_count =
        u32::try_from(source_member_ids.len()).expect("tier fan-in exceeds u32 wire range");
    AggregationMetaV1 {
        version: AGG_META_VERSION_V2,
        content_id: content_id.to_string(),
        corpus_kind: corpus_kind.to_string(),
        tier,
        aggregation_algorithm_id: aggregation_algorithm_id.to_string(),
        source_count,
        member_commitment: member_commitment(source_member_ids),
        noise_floor_descriptor: noise_floor_descriptor.to_string(),
        n_eff: effective_source_count(member_masses),
        // CIRISVerify#191 v3 fields — NEUTRAL and UNSIGNED at v2: the signing
        // preimage appends them only iff `version >= 3`, so a v2 tier's bytes
        // (and its golden vectors) are untouched. A v2 tier fails
        // `passes_multiplicity_gate` closed by construction — that is the
        // flag-day cut, not a regression. Use `assemble_tier_meta_v3` to
        // produce a tier that persist >= 16 will admit.
        max_source_multiplicity: 0,
        mass_commitment: [0u8; 32],
    }
}

/// §19.7.1.3 (CIRISVerify#191 / CC 6.1.2.1.2 R9) — assemble a **v3** tier meta:
/// the v2 surface plus the *measured* content-similarity multiplicity and the
/// auditable mass commitment. **This is the go-forward producer**: persist ≥ 16
/// enforces `passes_dominance_gate` AND `passes_multiplicity_gate` at
/// `put_aggregated_tier`, and a pre-v3 tier **fails closed** at every peer.
///
/// `member_masses` + `max_source_multiplicity` come from the fold —
/// `realtime_av_codec::fountain::content_multiplicity` (behind the codec
/// feature), the only point in the pipeline holding member payloads. Pass its
/// `ContentMultiplicity` fields straight through. The masses are a *measured*
/// output (each member's share of content energy), so `n_eff` and
/// `mass_commitment` are both auditable: an auditor holding the members
/// recomputes this root and can prove a lying `n_eff` or multiplicity.
///
/// The gate persist applies is `max_source_multiplicity · n_min <= source_count`
/// (`n_min` corpus-pinned persist-side, default 2) — so a fold whose largest
/// near-duplicate cluster exceeds half the members is rejected. The 900/1000
/// near-duplicate fold that v2 admitted (`n_eff == 1000`, honestly) is rejected
/// here.
///
/// # Panics
///
/// If `source_member_ids` and `member_masses` lengths differ, or the fan-in
/// exceeds `u32::MAX`.
#[must_use]
// The §19.7.1.3 producer is a composition site for the full signed tier surface
// (identity + fan-in + the two measured v3 fields); grouping them into a struct
// would just move the arity, and every field is independently supplied by the
// caller's fold. Mirrors `assemble_tier_meta_v2`.
#[allow(clippy::too_many_arguments)]
pub fn assemble_tier_meta_v3(
    content_id: &str,
    corpus_kind: &str,
    tier: u32,
    aggregation_algorithm_id: &str,
    source_member_ids: &[String],
    member_masses: &[f64],
    max_source_multiplicity: u32,
    noise_floor_descriptor: &str,
) -> AggregationMetaV1 {
    assert_eq!(
        source_member_ids.len(),
        member_masses.len(),
        "source_member_ids and measured member_masses must be index-aligned"
    );
    let source_count =
        u32::try_from(source_member_ids.len()).expect("tier fan-in exceeds u32 wire range");

    // §19.7.1.3 mass commitment: Merkle root over (member_id, fixed-point mass),
    // pinned at MASS_FIXED_POINT_SCALE = 1e6 verify-side.
    let mass_leaves: Vec<(String, u64)> = source_member_ids
        .iter()
        .cloned()
        .zip(member_masses.iter().map(|m| mass_to_fixed(*m)))
        .collect();

    AggregationMetaV1 {
        version: AGG_META_VERSION_V3,
        content_id: content_id.to_string(),
        corpus_kind: corpus_kind.to_string(),
        tier,
        aggregation_algorithm_id: aggregation_algorithm_id.to_string(),
        source_count,
        member_commitment: member_commitment(source_member_ids),
        noise_floor_descriptor: noise_floor_descriptor.to_string(),
        n_eff: effective_source_count(member_masses),
        max_source_multiplicity,
        mass_commitment: mass_commitment(&mass_leaves),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_source_ids() -> Vec<String> {
        ["src-001", "src-002", "src-003"]
            .into_iter()
            .map(String::from)
            .collect()
    }

    fn fixed_meta() -> AggregationMetaV1 {
        // Matches CIRISVerify's authored vector at
        // tests/vectors/holonomic_v19_7/aggregation_meta/canonical_bytes.json
        // so the byte-equality assertion proves cross-impl conformance.
        let source_ids = fixed_source_ids();
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
            // Neutral placeholder on a v1 tier — NOT in the v1 preimage
            // (asserted below), NOT accepted by passes_dominance_gate.
            n_eff: 3,
            // §19.7.1.3 (#191): likewise neutral + un-signed at v1 — appended to
            // the preimage only iff version >= 3, so the v1 golden bytes below
            // stay byte-identical.
            max_source_multiplicity: 0,
            mass_commitment: [0u8; 32],
        }
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            write!(&mut s, "{b:02x}").expect("hex write");
        }
        s
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
        // A v1 preimage MUST stay byte-identical across the #167 v2 cut.
        let expected_hex = "4147472d4d4554412d763100000000000000000100000012636f6e74656e742d726f6f742d66697865640000000574726163650000000200000012726170746f72712d707972616d69642d763100000003a10bc0ec2399f1cd431be79a863385a4b895987dae604aaf2ec3532f3753bd9d0000000b6d65616e2b737464646576";
        assert_eq!(
            hex(&fixed_meta().signing_preimage()),
            expected_hex,
            "AggregationMetaV1 v1 preimage MUST match Verify's authored vector byte-for-byte"
        );
    }

    #[test]
    fn v2_signing_preimage_matches_verify_v8_7_0_vector_byte_for_byte() {
        // §19.7.1.2 (CIRISVerify#167): locked v2 expected bytes from verify
        // v8.7.0's authored vector (.../aggregation_meta/canonical_bytes_v2.json)
        // — the v1 layout with version=2 and a trailing u32_be(n_eff)=3.
        let expected_hex = "4147472d4d4554412d763100000000000000000200000012636f6e74656e742d726f6f742d66697865640000000574726163650000000200000012726170746f72712d707972616d69642d763100000003a10bc0ec2399f1cd431be79a863385a4b895987dae604aaf2ec3532f3753bd9d0000000b6d65616e2b73746464657600000003";
        let mut meta = fixed_meta();
        meta.version = AGG_META_VERSION_V2;
        assert_eq!(
            hex(&meta.signing_preimage()),
            expected_hex,
            "AggregationMetaV1 v2 preimage MUST match Verify v8.7.0's authored vector byte-for-byte"
        );
    }

    #[test]
    fn v1_preimage_is_byte_identical_regardless_of_n_eff() {
        // Backward-compat pin (#167): a v1 tier ignores n_eff in the preimage,
        // so every pre-#167 signature/vector verifies unchanged.
        let mut a = fixed_meta();
        let mut b = fixed_meta();
        a.n_eff = 7;
        b.n_eff = 999;
        assert_eq!(a.signing_preimage(), b.signing_preimage());
    }

    #[test]
    fn member_commitment_empty_returns_ww_v1_sentinel() {
        // The §19.7.1.1 / §19.1 shared sentinel: empty input → SHA-256("WW-v1-empty").
        assert_eq!(
            hex(&compute_member_commitment(&[])),
            "2280d27f232100367e86211b5349fe0d6fbaee98e4c2b489a86008049563464f"
        );
    }

    #[test]
    fn member_commitment_lex_sorts_internally() {
        // Verify's authored vector at member_commitment/three_unsorted.json
        // uses ["m3", "m1", "m2"] (unsorted) → expects 1bfd0a8a... The
        // re-exported impl must produce the same root from unsorted input.
        let source: Vec<String> = ["m3", "m1", "m2"].into_iter().map(String::from).collect();
        assert_eq!(
            hex(&compute_member_commitment(&source)),
            "1bfd0a8a367f375a67ad08b3f19cf1a6d82876e753eea631a698d7dcca58226d",
            "member_commitment must lex-sort source ids (WW-2 discipline)"
        );
    }

    #[test]
    fn member_commitment_matches_aggregation_meta_struct_field() {
        // The struct's `member_commitment` field MUST equal the
        // compute_member_commitment over the documented source ids; otherwise
        // the AggregationMetaV1's signed preimage carries a commitment that
        // verifiers reject as inconsistent.
        let expected = compute_member_commitment(&fixed_source_ids());
        assert_eq!(fixed_meta().member_commitment, expected);
    }

    #[test]
    fn assemble_tier_meta_v2_computes_n_eff_and_commitment() {
        // Producer side (#267 slice 2): a balanced 3-fold → version=2,
        // n_eff == source_count == 3, commitment = §19.7.1.1 Merkle.
        let ids = fixed_source_ids();
        let meta = assemble_tier_meta_v2(
            "content-root-fixed",
            "trace",
            2,
            "raptorq-pyramid-v1",
            &ids,
            &[10.0, 10.0, 10.0],
            "mean+stddev",
        );
        assert_eq!(meta.version, AGG_META_VERSION_V2);
        assert_eq!(meta.source_count, 3);
        assert_eq!(meta.n_eff, 3, "balanced fold: n_eff == N");
        assert_eq!(meta.member_commitment, compute_member_commitment(&ids));
        assert!(
            passes_dominance_gate(&meta, 0.5),
            "a balanced v2 fold passes the dominance gate"
        );
        // And the emitted meta signs the v2 layout (trailing u32_be(n_eff)).
        let pre = meta.signing_preimage();
        assert_eq!(&pre[pre.len() - 4..], 3u32.to_be_bytes());
    }

    #[test]
    fn assemble_tier_meta_v2_dominated_fold_fails_dominance_gate() {
        // CC 6.1.2 / the 900/1000 case: one source holds 90% of the mass →
        // n_eff collapses toward 1 and the emitted tier is gate-rejected,
        // which is the whole point of signing n_eff (#167).
        let ids: Vec<String> = (0..1000).map(|i| format!("src-{i:04}")).collect();
        let mut masses = vec![900.0];
        masses.extend(std::iter::repeat_n(100.0 / 999.0, 999));
        let meta = assemble_tier_meta_v2(
            "content-root-dominated",
            "trace",
            1,
            "raptorq-pyramid-v1",
            &ids,
            &masses,
            "mean+stddev",
        );
        assert_eq!(meta.source_count, 1000);
        assert!(
            meta.n_eff <= 2,
            "900/1000-dominated fold must have n_eff ≈ 1, got {}",
            meta.n_eff
        );
        assert!(!passes_dominance_gate(&meta, 0.5));
        assert!(
            !passes_dominance_gate(&meta, 0.1),
            "even a lenient floor rejects it"
        );
    }

    #[test]
    fn dominance_gate_fails_closed_on_v1() {
        // A v1 tier has no *signed* n_eff — whatever placeholder it carries,
        // the gate fails closed (verify-owned behavior, pinned here because
        // edge's producer relied on it when choosing to emit v2).
        let m = fixed_meta(); // version 1, n_eff placeholder = 3 = source_count
        assert!(!passes_dominance_gate(&m, 0.5));
    }

    #[test]
    fn signing_preimage_changes_on_any_field_mutation() {
        // Every field MUST appear in the canonical preimage (v2: including
        // n_eff). Mutate each in turn and assert the preimage changes —
        // guards against future field-omission regressions that would break
        // the cross-impl byte-equality.
        let v2_meta = || {
            let mut m = fixed_meta();
            m.version = AGG_META_VERSION_V2;
            m
        };
        let base = v2_meta().signing_preimage();

        let mut m = v2_meta();
        m.version += 1;
        assert_ne!(m.signing_preimage(), base, "version must affect preimage");

        let mut m = v2_meta();
        m.content_id.push_str("-mutated");
        assert_ne!(
            m.signing_preimage(),
            base,
            "content_id must affect preimage"
        );

        let mut m = v2_meta();
        m.corpus_kind = "blob".to_string();
        assert_ne!(
            m.signing_preimage(),
            base,
            "corpus_kind must affect preimage"
        );

        let mut m = v2_meta();
        m.tier += 1;
        assert_ne!(m.signing_preimage(), base, "tier must affect preimage");

        let mut m = v2_meta();
        m.aggregation_algorithm_id = "av1-svc-quality-v1".to_string();
        assert_ne!(
            m.signing_preimage(),
            base,
            "aggregation_algorithm_id must affect preimage"
        );

        let mut m = v2_meta();
        m.source_count += 1;
        assert_ne!(
            m.signing_preimage(),
            base,
            "source_count must affect preimage"
        );

        let mut m = v2_meta();
        m.member_commitment[0] ^= 0xff;
        assert_ne!(
            m.signing_preimage(),
            base,
            "member_commitment must affect preimage"
        );

        let mut m = v2_meta();
        m.noise_floor_descriptor = "max".to_string();
        assert_ne!(
            m.signing_preimage(),
            base,
            "noise_floor_descriptor must affect preimage"
        );

        let mut m = v2_meta();
        m.n_eff += 1;
        assert_ne!(
            m.signing_preimage(),
            base,
            "n_eff must affect the v2 preimage (§19.7.1.2 signed dominance surface)"
        );
    }

    // ── §19.7.1.3 v3 producer (CIRISEdge#325 / CIRISVerify#191) ──────────

    /// The persist-side gate, mirrored: `max_source_multiplicity * n_min <=
    /// source_count`, `n_min` default 2 (`multiplicity_n_min_for`).
    const N_MIN: u32 = 2;

    /// The dominance-gate floor: `n_eff / source_count >= min_ratio`. Both the
    /// balanced fold AND the R9 near-duplicate fold score 1.0 here — which is
    /// precisely why the mass gate alone cannot see R9.
    const DOMINANCE_MIN_RATIO: f64 = 0.5;

    /// A v3 tier from a BALANCED fold (mutually distinct members, multiplicity
    /// 1) carries the signed v3 surface and is ADMITTED by both gates.
    #[test]
    fn v3_meta_from_balanced_fold_passes_both_gates() {
        let ids: Vec<String> = (0..10).map(|i| format!("src-{i:03}")).collect();
        let masses = vec![0.1_f64; 10]; // balanced
        let meta = assemble_tier_meta_v3(
            "content-v3",
            "trace",
            2,
            "raptorq-pyramid-v1",
            &ids,
            &masses,
            1, // measured multiplicity: distinct members
            "mean+stddev",
        );
        assert_eq!(meta.version, AGG_META_VERSION_V3);
        assert_eq!(meta.max_source_multiplicity, 1);
        assert_ne!(meta.mass_commitment, [0u8; 32], "mass commitment is bound");
        assert!(
            passes_dominance_gate(&meta, DOMINANCE_MIN_RATIO),
            "balanced fold: dominance ok"
        );
        assert!(
            passes_multiplicity_gate(&meta, N_MIN),
            "balanced fold: multiplicity ok (1*2 <= 10)"
        );
    }

    /// THE R9 CASE end-to-end: 900 near-duplicates in a 1000-member fold. The
    /// masses are HONEST (all equal ⇒ `n_eff == 1000`), so the v2 dominance gate
    /// ADMITS — but the measured multiplicity (900) makes the v3 gate REJECT.
    /// This is exactly the residual CIRISVerify#191 closes.
    #[test]
    fn v3_meta_rejects_the_900_near_duplicate_fold_the_mass_gate_admits() {
        let ids: Vec<String> = (0..1000).map(|i| format!("src-{i:04}")).collect();
        let masses = vec![0.001_f64; 1000]; // equal mass — honest n_eff == 1000
        let meta = assemble_tier_meta_v3(
            "content-r9",
            "trace",
            2,
            "raptorq-pyramid-v1",
            &ids,
            &masses,
            900, // measured at fold: the near-duplicate cluster
            "mean+stddev",
        );
        assert_eq!(meta.n_eff, 1000, "the mass gate sees an honest n_eff");
        assert!(
            passes_dominance_gate(&meta, DOMINANCE_MIN_RATIO),
            "the v2 mass gate ADMITS this fold — that is the R9 residual"
        );
        assert!(
            !passes_multiplicity_gate(&meta, N_MIN),
            "the v3 multiplicity gate REJECTS it (900*2 > 1000)"
        );
    }

    /// A v2 tier lacks the v3 surface and FAILS CLOSED at the multiplicity gate
    /// — the flag-day cut (persist >= 16 rejects it at every peer).
    #[test]
    fn v2_meta_fails_closed_at_the_multiplicity_gate() {
        let ids = fixed_source_ids();
        let meta = assemble_tier_meta_v2(
            "content-v2",
            "trace",
            2,
            "raptorq-pyramid-v1",
            &ids,
            &[0.33, 0.33, 0.34],
            "mean+stddev",
        );
        assert_eq!(meta.version, AGG_META_VERSION_V2);
        assert!(
            !passes_multiplicity_gate(&meta, N_MIN),
            "a pre-v3 tier must fail closed (no deprecation window)"
        );
    }
}
