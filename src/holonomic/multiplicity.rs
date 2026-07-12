//! §19.7.1.3 content-similarity multiplicity — the CC 6.1.2.1.2 **R9** closure
//! (CIRISEdge#323 / CIRISVerify#191).
//!
//! # The residual this closes
//!
//! 900 near-duplicate contents folded as 900 *distinct members at equal mass*
//! **honestly** compute `n_eff == 1000` and **pass** the v2 mass-dominance gate
//! — yet the composite blur IS the data subject (a false erasure certificate).
//! The mass gate structurally cannot see this: `member_commitment` is a Merkle
//! root over member **ids** and is blind to content by construction.
//!
//! The **fold** is the only point in the pipeline holding member payloads, so
//! the multiplicity is measured here and signed into `AggregationMetaV1` v3
//! ([`super::aggregation::assemble_tier_meta_v3`]). Persist ≥ 16 enforces
//! `passes_multiplicity_gate` at `put_aggregated_tier` and **fails closed**
//! below v3 (the CIRISVerify#191 flag-day).
//!
//! # Why this lives in `holonomic`, not in the codec
//!
//! It is a §19.7 **producer** surface (sibling of [`super::aggregation`]), and it
//! depends on nothing but byte math — no `raptorq`, no codec. Keeping it out of
//! the `codec-fountain` gate is load-bearing: raptorq does not build on
//! `armeabi-v7a` (ARM NEON intrinsics are unstable on 32-bit ARM), and the
//! Python wheel MUST ship this producer or no descent driver can build a tier
//! persist ≥ 16 will admit.
//!
//! [`resample_nearest`] is the SINGLE definition of the resample basis, shared
//! with the fold (`realtime_av_codec::fountain::aggregate_symbols`). That
//! sharing is a correctness requirement, not a convenience: similarity must be
//! measured on exactly the content the fold collapsed — two definitions could
//! silently drift and fork a **signed** field.

use std::collections::HashMap;

/// The fixed-point scale for the pinned similarity threshold (milli-units).
/// Integer/fixed-point throughout: the clustering feeds a SIGNED wire field, so
/// it must be bit-deterministic across platforms — no `f64` in the decision path.
const SIMILARITY_SCALE_MILLI: u64 = 1000;

/// Errors measuring the multiplicity surface. Mirrors the fold's preconditions —
/// the two run over the same member set.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MultiplicityError {
    /// The member set is empty — there is nothing to fold.
    #[error("no members: the multiplicity surface requires at least one member")]
    NoMembers,
    /// A member has zero bytes and cannot be resampled. `0` is its index.
    #[error("empty member at index {0}: zero-length payloads cannot be resampled")]
    EmptyMember(usize),
    /// More members than the `u32` `source_count` wire width can carry.
    #[error("too many members: {0} exceeds the u32 source_count width")]
    TooManyMembers(usize),
}

/// Nearest-neighbor 1-D resample of `src` to exactly `dst_len` bytes: output
/// position `i` reads `src[i * src_len / dst_len]`. Identity when
/// `dst_len == src_len`. `src` MUST be non-empty and `dst_len` non-zero.
///
/// **The single definition of the resample basis** — used by both the fold and
/// the similarity measurement (see the module docs).
#[must_use]
pub fn resample_nearest(src: &[u8], dst_len: usize) -> Vec<u8> {
    debug_assert!(!src.is_empty() && dst_len > 0);
    (0..dst_len)
        .map(|i| {
            // u128 intermediate: i * src_len can overflow usize on 32-bit
            // targets for large payloads.
            #[allow(clippy::cast_possible_truncation)] // result < src_len by construction
            let idx = ((i as u128 * src.len() as u128) / dst_len as u128) as usize;
            src[idx]
        })
        .collect()
}

/// **Normative producer pin** (CIRISVerify#191 / CC 6.1.2 `(R, ε)`): the
/// per-`corpus_kind` content-similarity threshold above which two members count
/// as near-duplicates, in milli-units (`950` = 0.950).
///
/// The metric is `1 − normalized L1 distance` over the resampled payloads (see
/// [`members_are_similar`]). Calibration: byte-identical members score `1.000`;
/// near-duplicates (small perturbations) score `≥ 0.99`; independent
/// high-entropy members score `≈ 0.667` (mean |Δ| of uniform bytes ≈ 85/255).
/// `0.950` separates those populations with wide margin. (Cosine similarity
/// would be wrong here: byte vectors are all-positive, so even independent
/// members score ≈ 0.75.)
///
/// **This pin is wire-affecting** — it determines a signed field, so a producer
/// that changes it forks the multiplicity any verifier recomputes from held
/// evidence. Keep it in lockstep with the CC 6.1.2 conformance fixture; add
/// per-`corpus_kind` arms HERE (one place) rather than at call sites.
#[must_use]
pub fn multiplicity_similarity_threshold_milli(corpus_kind: &str) -> u64 {
    // Per-`corpus_kind` arms belong HERE (the single source of truth), e.g.
    //   "audio/pcm16" => 970,
    // Until a kind pins its own (R, ε), every corpus takes the default.
    let _ = corpus_kind;
    950
}

/// The §19.7.1.3 surface measured at fold time — what a producer needs to
/// populate `AggregationMetaV1` v3 (CIRISEdge#325).
#[derive(Debug, Clone, PartialEq)]
pub struct ContentMultiplicity {
    /// Per-member content mass, index-aligned with the input members and
    /// summing to `1.0`: each member's share of total content energy, measured
    /// as its normalized L1 norm over the resample basis. This makes the masses
    /// a **measured output of the fold**, not the aggregator's own accounting —
    /// so `n_eff` (inverse-Simpson over these) and `mass_commitment` are both
    /// auditable from held evidence.
    pub member_masses: Vec<f64>,
    /// The size of the largest cluster of members whose pairwise content
    /// similarity exceeds the `corpus_kind`-pinned threshold. `1` for a fold of
    /// mutually-distinct members; `≈ N_dup` when `N_dup` near-duplicates are
    /// folded under distinct ids.
    pub max_source_multiplicity: u32,
}

/// Are two equal-length resampled members near-duplicates under the pinned
/// threshold? `similarity = 1 − (Σ|aᵢ − bᵢ|) / (255 · len)`, evaluated entirely
/// in integer space:
///
/// `similarity > threshold  ⟺  SCALE · Σ|Δ|  <  (SCALE − threshold_milli) · 255 · len`
#[must_use]
fn members_are_similar(a: &[u8], b: &[u8], threshold_milli: u64) -> bool {
    debug_assert_eq!(a.len(), b.len(), "similarity compares resampled members");
    if a.is_empty() {
        return true;
    }
    let l1: u64 = a
        .iter()
        .zip(b.iter())
        .map(|(x, y)| u64::from(x.abs_diff(*y)))
        .sum();
    let slack = SIMILARITY_SCALE_MILLI.saturating_sub(threshold_milli);
    let bound = slack * 255 * a.len() as u64;
    SIMILARITY_SCALE_MILLI * l1 < bound
}

/// Union-find root with path-halving — the clustering primitive for
/// [`content_multiplicity`]'s connected-component pass.
fn uf_find(parent: &mut [usize], mut x: usize) -> usize {
    while parent[x] != x {
        parent[x] = parent[parent[x]];
        x = parent[x];
    }
    x
}

/// Measure the §19.7.1.3 content multiplicity + per-member masses from the
/// member payloads (CIRISEdge#323). Members are nearest-neighbor resampled to
/// the max member length — the SAME normalization the fold applies — so
/// similarity is measured on exactly the content that was collapsed.
///
/// **Clustering**: the largest **connected component** of the similarity graph
/// (union-find, `O(N²)` pairwise — acceptable at the fan-ins §19.7 folds carry;
/// an LSH/simhash prefilter is the escape hatch if it ever isn't). This is a
/// deliberate *conservative superset* of the max-clique reading: a component's
/// members are transitively similar, so this can only ever **over**-estimate the
/// multiplicity — which only ever **tightens** `passes_multiplicity_gate`. The
/// fail-safe direction for a privacy gate (and max-clique is NP-hard).
///
/// Deterministic: byte-equal inputs yield an identical result on every platform
/// (integer-only decision path), as required of a signed wire field.
///
/// # Errors
/// [`MultiplicityError::NoMembers`], [`MultiplicityError::EmptyMember`],
/// [`MultiplicityError::TooManyMembers`].
pub fn content_multiplicity(
    members: &[&[u8]],
    corpus_kind: &str,
) -> Result<ContentMultiplicity, MultiplicityError> {
    if members.is_empty() {
        return Err(MultiplicityError::NoMembers);
    }
    if let Some(idx) = members.iter().position(|m| m.is_empty()) {
        return Err(MultiplicityError::EmptyMember(idx));
    }
    let n = members.len();
    u32::try_from(n).map_err(|_| MultiplicityError::TooManyMembers(n))?;

    // Same resample basis as the fold — similarity must be measured on the
    // content that was actually collapsed.
    let max_len = members.iter().map(|m| m.len()).max().unwrap_or(1);
    let resampled: Vec<Vec<u8>> = members
        .iter()
        .map(|m| resample_nearest(m, max_len))
        .collect();

    // Per-member masses: normalized L1 norm (content energy share). The sums are
    // exact u64; the f64 conversion produces a VALUE (a mass fraction), never a
    // decision — the clustering that feeds the signed multiplicity is
    // integer-only (see `members_are_similar`). Masses are in turn committed via
    // the fixed-point `mass_to_fixed` (1e6) before signing, so the wire is not
    // f64-sensitive either.
    #[allow(clippy::cast_precision_loss)]
    let member_masses: Vec<f64> = {
        let norms: Vec<u64> = resampled
            .iter()
            .map(|m| m.iter().map(|b| u64::from(*b)).sum())
            .collect();
        let total: u64 = norms.iter().sum();
        if total == 0 {
            // All-zero payloads: fall back to a uniform (balanced) mass split so
            // n_eff reflects the honest fan-in rather than dividing by zero.
            vec![1.0 / n as f64; n]
        } else {
            norms.iter().map(|w| *w as f64 / total as f64).collect()
        }
    };

    // Similarity graph → largest connected component (union-find).
    let threshold_milli = multiplicity_similarity_threshold_milli(corpus_kind);
    let mut parent: Vec<usize> = (0..n).collect();
    for i in 0..n {
        for j in (i + 1)..n {
            if members_are_similar(&resampled[i], &resampled[j], threshold_milli) {
                let (ri, rj) = (uf_find(&mut parent, i), uf_find(&mut parent, j));
                if ri != rj {
                    parent[ri] = rj;
                }
            }
        }
    }
    let mut sizes: HashMap<usize, u32> = HashMap::new();
    for i in 0..n {
        let root = uf_find(&mut parent, i);
        *sizes.entry(root).or_insert(0) += 1;
    }
    let max_source_multiplicity = sizes.values().copied().max().unwrap_or(1);

    Ok(ContentMultiplicity {
        member_masses,
        max_source_multiplicity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic LCG — distinct high-entropy members without a rand dep.
    fn pseudo_member(seed: u64, len: usize) -> Vec<u8> {
        let mut s = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        (0..len)
            .map(|_| {
                s = s
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                // Deliberate truncation: one byte of the LCG state.
                u8::try_from((s >> 33) & 0xFF).expect("masked to one byte")
            })
            .collect()
    }

    /// THE R9 CASE: 900 near-duplicates under distinct ids + 100 genuinely
    /// distinct members. The v2 mass gate sees `n_eff == 1000` (honest — all
    /// equal mass) and admits; the content-similarity multiplicity sees the
    /// blur. `max_source_multiplicity >= 900` ⇒ `900 * n_min(2) > 1000` ⇒
    /// `passes_multiplicity_gate` REJECTS.
    #[test]
    fn content_multiplicity_detects_the_900_near_duplicate_fold() {
        let base = pseudo_member(7, 64);
        let mut owned: Vec<Vec<u8>> = (0..900)
            .map(|i| {
                let mut m = base.clone();
                m[i % 64] = m[i % 64].wrapping_add(1);
                m
            })
            .collect();
        owned.extend((0..100).map(|i| pseudo_member(1000 + i, 64)));
        let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();

        let m = content_multiplicity(&refs, "test/corpus").expect("multiplicity");
        assert!(
            m.max_source_multiplicity >= 900,
            "the 900-near-duplicate cluster must surface (got {})",
            m.max_source_multiplicity
        );
        assert!(
            u64::from(m.max_source_multiplicity) * 2 > refs.len() as u64,
            "the R9 fold must fail passes_multiplicity_gate"
        );
    }

    /// A balanced fold of mutually-distinct members collapses to multiplicity 1
    /// — and passes the gate (1 * 2 <= N).
    #[test]
    fn content_multiplicity_balanced_distinct_members_is_one() {
        let owned: Vec<Vec<u8>> = (0..64).map(|i| pseudo_member(i, 64)).collect();
        let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();

        let m = content_multiplicity(&refs, "test/corpus").expect("multiplicity");
        assert_eq!(
            m.max_source_multiplicity, 1,
            "distinct members must not cluster"
        );
        assert!(u64::from(m.max_source_multiplicity) * 2 <= refs.len() as u64);
        assert_eq!(m.member_masses.len(), refs.len());
        let total: f64 = m.member_masses.iter().sum();
        assert!(
            (total - 1.0).abs() < 1e-9,
            "masses must sum to 1 (got {total})"
        );
    }

    /// The multiplicity feeds a SIGNED wire field — byte-equal inputs must
    /// produce a byte-equal result (integer-only decision path).
    #[test]
    fn content_multiplicity_is_deterministic() {
        let owned: Vec<Vec<u8>> = (0..32)
            .map(|i| {
                if i < 20 {
                    pseudo_member(3, 48)
                } else {
                    pseudo_member(100 + i, 48)
                }
            })
            .collect();
        let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();

        let a = content_multiplicity(&refs, "test/corpus").expect("a");
        let b = content_multiplicity(&refs, "test/corpus").expect("b");
        assert_eq!(a, b, "identical inputs must yield an identical surface");
        assert!(a.max_source_multiplicity >= 20);
    }

    /// Identical members are maximally similar; independent high-entropy members
    /// fall well below the pinned threshold — the separation the 0.95 pin needs.
    #[test]
    fn similarity_separates_duplicates_from_distinct_members() {
        let a = pseudo_member(11, 128);
        let b = a.clone();
        let c = pseudo_member(12, 128);
        let t = multiplicity_similarity_threshold_milli("test/corpus");
        assert!(members_are_similar(&a, &b, t), "identical → similar");
        assert!(
            !members_are_similar(&a, &c, t),
            "independent high-entropy members must NOT cluster"
        );
    }

    /// Empty / oversized member sets are typed errors, not panics.
    #[test]
    fn rejects_degenerate_member_sets() {
        assert_eq!(
            content_multiplicity(&[], "k").unwrap_err(),
            MultiplicityError::NoMembers
        );
        let empty: &[u8] = &[];
        let ok: &[u8] = &[1, 2, 3];
        assert_eq!(
            content_multiplicity(&[ok, empty], "k").unwrap_err(),
            MultiplicityError::EmptyMember(1)
        );
    }
}
