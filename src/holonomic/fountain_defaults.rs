//! Fountain content replication-policy defaults (CIRISRegistry#86 →
//! CEG 1.0 §R-policy).
//!
//! Edge applications producing fountain content (per CIRISPersist's
//! `FountainContentV1` contract) consume these constants to pick the
//! `(n_source, k_repair, min_viable_symbols, target_holders)` tuple
//! that lands as the recommended default.
//!
//! # Derivation
//!
//! The optimal `target_holders` is the max of three independent
//! constraints (any of which can bind):
//!
//! ## C₁ — Survival floor (the dominant constraint)
//!
//! With N+K symbols distributed one-per-peer over R peers each at
//! per-fetch availability `q`, reconstruction succeeds when
//! `≥ N` symbols are reachable. By binomial:
//!
//! ```text
//! P(reconstruction) = P(X ≥ N)   where X ~ Binomial(R, q)
//! ```
//!
//! At `(N=20, K=6, R=30)`:
//!
//! | per-peer availability `q` | P(reconstruction) |
//! |---|---|
//! | 0.95 (datacenter)         | 0.99996 |
//! | 0.90 (typical wifi)       | 0.9994  |
//! | 0.85 (medium churn)       | 0.9961  |
//! | 0.80 (high churn)         | 0.974   |
//!
//! Design target: 99.95% reconstruction at q=0.85 (typical wifi /
//! community-mesh churn).
//!
//! ## C₂ — Demand-spike capacity (rarely binds)
//!
//! ALM tree at fanout X=12 (per FEDERATION_SCALING_MODEL §4.4):
//! depth-2 serves 157 viewers per copy; depth-3 serves 1,885.
//! Swarm-rarity (#134) organically elevates copy count under load.
//! Cold-AND-suddenly-viral content is the only case where this
//! constraint becomes binding.
//!
//! ## C₃ — Locality reach
//!
//! Per CEWP locality dividend (FEDERATION_SCALING_MODEL §9): each
//! populated locality serves LAN-internally; inter-locality is signed-
//! claim bridge, not synchronous relay. For a 10-locality federation:
//! `C₃ = 10`.
//!
//! ## Compose
//!
//! ```text
//! target_holders = max(C₁=26, C₂=7, C₃=10) × 1.15 churn-safety = 30
//! ```
//!
//! # Status
//!
//! Informative defaults; substrate accepts any `(N, K, min_viable,
//! target_holders)` tuple a producer publishes. These constants are
//! the RECOMMENDED policy when the producer hasn't pinned its own.
//! Normatively absorbed into CEG 1.0 §R-policy via CIRISRegistry#86.

/// RaptorQ source-symbol count (the lossless reconstruction threshold).
///
/// At least this many distinct symbols must be reachable for a peer's
/// codec to decode the original content bit-exactly.
pub const DEFAULT_N_SOURCE: u32 = 20;

/// RaptorQ repair-symbol count (FEC headroom above [`DEFAULT_N_SOURCE`]).
///
/// 6/20 = 30% overhead matches RFC 6330's empirical overhead profile
/// for 99.9% decode probability. Higher gives diminishing returns;
/// lower drops decode probability below 99% at q=0.85 typical churn.
pub const DEFAULT_K_REPAIR: u32 = 6;

/// Total symbols stored = source + repair.
pub const DEFAULT_TOTAL_SYMBOLS: u32 = DEFAULT_N_SOURCE + DEFAULT_K_REPAIR;

/// BLINKING_DOT floor: below this many symbols present, persist returns
/// [`FountainContent::EnvelopeOnly`] — manifest + symbol_hash chain
/// survives, content is unrecoverable but auditable.
///
/// `N/4 = 5` matches the locality-bandwidth + decoder-CPU floor
/// the BLINKING_DOT policy lever assumes.
///
/// [`FountainContent::EnvelopeOnly`]: ../../../../ciris-persist/src/fountain/types.rs.html
pub const DEFAULT_MIN_VIABLE_SYMBOLS: u32 = 5;

/// Target number of distinct peers holding ≥1 symbol of any given
/// fountain content.
///
/// `C₁(q=0.85) × 1.15 churn-safety = 26 × 1.15 ≈ 30`. The swarm-rarity
/// scorer ([`crate::holonomic::swarm_rarity::compute_rarity_score`])
/// drives local eviction policy toward this target — content whose
/// observed holder count drops below it gets rarity-promoted; content
/// above it can be evicted without harming the federation's survival
/// floor.
pub const DEFAULT_TARGET_HOLDERS: u32 = 30;

/// The recommended fountain replication policy bundled as one
/// structure. Returned by [`recommended_policy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FountainPolicy {
    /// RaptorQ source-symbol count.
    pub n_source: u32,
    /// RaptorQ repair-symbol count.
    pub k_repair: u32,
    /// BLINKING_DOT floor below which content goes EnvelopeOnly.
    pub min_viable_symbols: u32,
    /// Distinct peers holding ≥1 symbol (swarm-rarity target).
    pub target_holders: u32,
}

// Compile-time invariants — CEG 1.0 §R-policy locks these relations.
// Any modification to the DEFAULT_* constants above that violates one
// of these invariants is a build-time error, not a test-time failure.

// Total symbols MUST equal N + K (otherwise the constants don't
// describe a coherent RaptorQ parameter set).
const _: () = assert!(DEFAULT_TOTAL_SYMBOLS == DEFAULT_N_SOURCE + DEFAULT_K_REPAIR);

// min_viable MUST be strictly between 0 and N — at 0 the EnvelopeOnly
// tier loses its meaning; at ≥N it's never entered (the Full tier
// dominates).
const _: () = assert!(DEFAULT_MIN_VIABLE_SYMBOLS > 0);
const _: () = assert!(DEFAULT_MIN_VIABLE_SYMBOLS < DEFAULT_N_SOURCE);

// target_holders MUST ≥ total_symbols so single-symbol-per-peer
// distribution is feasible (the C₁ binomial assumes this).
const _: () = assert!(DEFAULT_TARGET_HOLDERS >= DEFAULT_TOTAL_SYMBOLS);

// k/N must land in the RaptorQ overhead band (20–40%). Outside this
// the parameter choice is wrong: too low and decode probability drops
// below 99% at q=0.85 medium churn; too high and bandwidth is wasted.
const _: () = assert!(DEFAULT_K_REPAIR * 100 / DEFAULT_N_SOURCE >= 20);
const _: () = assert!(DEFAULT_K_REPAIR * 100 / DEFAULT_N_SOURCE <= 40);

// target_holders MUST clear the medium-churn survival floor C₁ ≈ 29
// (N/q + 3·σ at q=0.85). 30 with 15% safety margin lands here.
const _: () = assert!(DEFAULT_TARGET_HOLDERS >= 29);

/// The CIRIS-recommended default fountain-content policy
/// (CIRISRegistry#86 / CEG 1.0 §R-policy).
///
/// Producers SHOULD use this when they haven't pinned their own
/// content-specific policy. The substrate's swarm-rarity scorer
/// converges all peers toward `target_holders` distinct holders
/// over time.
#[must_use]
pub const fn recommended_policy() -> FountainPolicy {
    FountainPolicy {
        n_source: DEFAULT_N_SOURCE,
        k_repair: DEFAULT_K_REPAIR,
        min_viable_symbols: DEFAULT_MIN_VIABLE_SYMBOLS,
        target_holders: DEFAULT_TARGET_HOLDERS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_values_match_ceg_1_0_r_policy() {
        // These must exactly match CIRISRegistry#86 / CEG 1.0 §R-policy.
        // Any change here is a wire-policy change and requires a CEG
        // amendment, NOT a quick local tweak.
        assert_eq!(DEFAULT_N_SOURCE, 20);
        assert_eq!(DEFAULT_K_REPAIR, 6);
        assert_eq!(DEFAULT_TOTAL_SYMBOLS, 26);
        assert_eq!(DEFAULT_MIN_VIABLE_SYMBOLS, 5);
        assert_eq!(DEFAULT_TARGET_HOLDERS, 30);
    }

    #[test]
    fn recommended_policy_returns_locked_tuple() {
        let p = recommended_policy();
        assert_eq!(p.n_source, DEFAULT_N_SOURCE);
        assert_eq!(p.k_repair, DEFAULT_K_REPAIR);
        assert_eq!(p.min_viable_symbols, DEFAULT_MIN_VIABLE_SYMBOLS);
        assert_eq!(p.target_holders, DEFAULT_TARGET_HOLDERS);
    }

    // Note: the survival-floor / k_repair-band / min_viable / target_holders
    // invariants are enforced at COMPILE TIME via `const _: () = assert!(...)`
    // blocks above. Any modification to the DEFAULT_* constants that
    // violates them fails the build, not just `cargo test`.
}
