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
//! `N + K = 26` distinct symbols distributed one-per-peer over
//! `R = 30` peers. With `R > N + K`, the `R − (N + K) = 4` surplus
//! peers hold duplicates. The model assumes the duplicates land on
//! **4 distinct symbols** (best-spread placement — 22 symbols held by
//! exactly one peer, 4 held by two). Concentrated duplication
//! (several surplus peers on one symbol) is strictly worse, so within
//! the one-symbol-per-peer family this column is the upper end; the
//! hard lower bound is the all-distinct floor `P(Bin(26, q) ≥ 20)`
//! (= 0.916673 at q = 0.85).
//!
//! With each peer independently reachable at per-fetch availability
//! `q`, reconstruction requires **≥ N distinct** symbols:
//!
//! ```text
//! X = X_single + X_dup
//!     X_single ~ Binomial(22, q)            (singly-held symbols)
//!     X_dup    ~ Binomial(4, p₂),  p₂ = 1 − (1 − q)²   (doubly-held)
//!
//! P(reconstruction) = P(X ≥ 20)
//!                   = Σ_{b=0..4} C(4,b)·p₂ᵇ·(1−p₂)⁴⁻ᵇ · P(Bin(22, q) ≥ 20 − b)
//! ```
//!
//! [`distinct_symbol_availability`] computes this exactly (it IS the
//! stated computation — the table below reproduces from it, and the
//! Monte-Carlo dump `tests::bench_dump_fountain_metrics` measures it
//! on the bench trend page as
//! `fountain/reconstruction/avail{q}pct_x100000`):
//!
//! | per-peer availability `q` | P(reconstruction) | naive `P(Bin(30,q) ≥ 20)` |
//! |---|---|---|
//! | 0.95 (datacenter)         | 0.999926 | 0.999997 |
//! | 0.90 (typical wifi)       | 0.995039 | 0.999911 |
//! | 0.85 (medium churn)       | 0.957288 | 0.997058 |
//! | 0.80 (high churn)         | 0.845021 | 0.974384 |
//!
//! The naive column treats all 30 peers as independent draws toward
//! the ≥ N threshold; it over-counts because a duplicate holder can
//! only re-supply a symbol another holder already covers — only 26
//! distinct symbols exist. It is shown as the upper bound only; the
//! honest column is the claim.
//!
//! **Design target (CIRISEdge#438): ≥ 99% reconstruction at q = 0.90
//! (typical wifi) — met at 0.995039 — and ≥ 99.9% at q = 0.95
//! (datacenter) — met at 0.999926.** At q = 0.85 (medium churn) a
//! single snapshot yields 95.7%; sustained sub-0.90 availability is
//! recovered by swarm-rarity repair re-raising the holder count
//! toward [`DEFAULT_TARGET_HOLDERS`], not by snapshot-level FEC
//! headroom.
//!
//! > Historical note (CIRISEdge#438): pre-#438 this section claimed
//! > "99.95% at q = 0.85" directly beneath a table whose own q = 0.85
//! > row read 0.9961. The target had been drafted against the q = 0.90
//! > column (the "typical wifi" label), and the table itself
//! > reproduced from no stated computation (naive-model ballpark,
//! > exact under none). Both are replaced by the exact values above,
//! > which the Monte-Carlo bench reproduces.
//!
//! The table is the **symbol-availability** term only. RaptorQ decode
//! from exactly `N` distinct symbols occasionally needs 1–2 overhead
//! symbols (RFC 6330 overhead profile);
//! `benches/fountain_reconstruction.rs` measures the per-count
//! decode-success curve `d(m)` with the real codec and prints the
//! composite `Σ_m P(X = m) · d(m)` alongside this table.
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
//! `C₁ = N + K = 26` enters the composition as the **feasibility
//! floor**: fewer peers than symbols cannot host the full symbol set
//! one-per-peer at all.
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
/// 6/20 = 30% overhead sits inside the 20–40% RaptorQ FEC band, and is
/// where the survival floor's K-sensitivity knee lands at the R = 30
/// operating point (exact, spread-duplicate model, q = 0.90 typical
/// wifi — see [`distinct_symbol_availability`]): K=5 → 0.9871 (misses
/// the ≥ 99% design target), K=6 → 0.9950 (meets it), K=7 → 0.9981
/// (+0.31 pp — diminishing returns). The
/// `tests::repair_headroom_knee_at_k_6` property pins this.
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
/// `C₁ = N + K = 26` (the one-symbol-per-peer feasibility floor)
/// `× 1.15 churn-safety ≈ 30`. The swarm-rarity scorer
/// ([`crate::holonomic::swarm_rarity::compute_rarity_score`])
/// drives local eviction policy toward this target — content whose
/// observed holder count drops below it gets rarity-promoted; content
/// above it can be evicted without harming the federation's survival
/// floor. At R = 30 the exact survival floor is
/// [`recommended_reconstruction_probability`] — see the module-level
/// table.
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
// distribution is feasible (the C₁ model assumes this — the
// feasibility-floor reading of C₁ = 26).
const _: () = assert!(DEFAULT_TARGET_HOLDERS >= DEFAULT_TOTAL_SYMBOLS);

// k/N must land in the RaptorQ overhead band (20–40%). Outside this
// the parameter choice is wrong: too low and the survival floor misses
// the ≥ 99% design target at q = 0.90 typical wifi (K=5 → 0.9871, see
// DEFAULT_K_REPAIR docs); too high and bandwidth is wasted for
// diminishing survival-floor returns.
const _: () = assert!(DEFAULT_K_REPAIR * 100 / DEFAULT_N_SOURCE >= 20);
const _: () = assert!(DEFAULT_K_REPAIR * 100 / DEFAULT_N_SOURCE <= 40);

// target_holders MUST NOT be quietly lowered below the sizing rule's
// output floor: feasibility floor 26 × 1.15 churn-safety rounds to 30;
// 29 is the last value that keeps ANY churn-safety margin above the
// feasibility floor. The exact survival-floor consequence of R is
// computed by `distinct_symbol_availability` (runtime) and pinned by
// the `tests::design_target_met_at_stated_operating_points` property.
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

// ─── Survival-floor math (the C₁ derivation, executable) ────────────────
//
// CIRISEdge#438: the module-level table must REPRODUCE from a stated
// computation. These functions ARE that computation — the doc table, the
// property tests, the Monte-Carlo dump, and the criterion bench
// (`benches/fountain_reconstruction.rs`) all consume the same code.

/// Binomial probability mass `P(Bin(n, p) = k)`, exact in `f64` for the
/// small `n` (≤ ~60) this module operates on. `C(n, k)` is built by the
/// multiplicative recurrence and the `p`/`(1−p)` powers by repeated
/// multiplication — no casts, no `powi`, well-conditioned at these sizes
/// (`C(30, 15) < 2^28` — exactly representable).
fn binomial_pmf(n: u32, k: u32, p: f64) -> f64 {
    if k > n {
        return 0.0;
    }
    let mut pmf = 1.0_f64;
    for i in 0..k {
        pmf = pmf * f64::from(n - i) / f64::from(i + 1);
    }
    for _ in 0..k {
        pmf *= p;
    }
    for _ in 0..(n - k) {
        pmf *= 1.0 - p;
    }
    pmf
}

/// Binomial survival `P(Bin(n, p) ≥ threshold)`. Empty range (threshold
/// > n) sums to 0.
fn binomial_sf(n: u32, threshold: u32, p: f64) -> f64 {
    (threshold..=n).map(|k| binomial_pmf(n, k, p)).sum()
}

/// Exact `P(≥ min_distinct distinct symbols reachable)` under the C₁
/// spread-duplicate one-symbol-per-peer placement (module docs).
///
/// `total_symbols` distinct symbols over `peers ≥ total_symbols` peers,
/// one symbol per peer: the `d = peers − total_symbols` surplus peers
/// duplicate `d` **distinct** symbols, so `total_symbols − d` symbols
/// are singly-held (reachable w.p. `q`) and `d` are doubly-held
/// (reachable w.p. `1 − (1−q)²`). Returns `P(X ≥ min_distinct)` where
/// `X` is the number of distinct reachable symbols.
///
/// This is the stated computation behind the module-level reliability
/// table; `recommended_reconstruction_probability` applies it at the
/// shipped tuple.
///
/// # Panics
///
/// If the placement is infeasible (`peers < total_symbols`, more
/// surplus peers than symbols to spread over, `total_symbols == 0`) or
/// `per_peer_availability` is outside `[0, 1]`.
#[must_use]
pub fn distinct_symbol_availability(
    total_symbols: u32,
    peers: u32,
    min_distinct: u32,
    per_peer_availability: f64,
) -> f64 {
    assert!(total_symbols > 0, "total_symbols must be positive");
    assert!(
        peers >= total_symbols,
        "one-symbol-per-peer placement is infeasible: {peers} peers < {total_symbols} symbols"
    );
    let dups = peers - total_symbols;
    assert!(
        dups <= total_symbols,
        "spread-duplicate placement needs surplus ({dups}) <= total_symbols ({total_symbols})"
    );
    assert!(
        (0.0..=1.0).contains(&per_peer_availability),
        "per_peer_availability must be a probability, got {per_peer_availability}"
    );

    let singles = total_symbols - dups;
    let q = per_peer_availability;
    let p_dup = 1.0 - (1.0 - q) * (1.0 - q);
    (0..=dups)
        .map(|b| {
            binomial_pmf(dups, b, p_dup) * binomial_sf(singles, min_distinct.saturating_sub(b), q)
        })
        .sum()
}

/// [`distinct_symbol_availability`] at the recommended tuple: the exact
/// survival-floor reconstruction probability `P(X ≥ N)` at
/// `(N = 20, K = 6, R = 30)` as a function of per-peer availability
/// `q`. This function generates the module-level reliability table.
#[must_use]
pub fn recommended_reconstruction_probability(per_peer_availability: f64) -> f64 {
    distinct_symbol_availability(
        DEFAULT_TOTAL_SYMBOLS,
        DEFAULT_TARGET_HOLDERS,
        DEFAULT_N_SOURCE,
        per_peer_availability,
    )
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

    // ─── Survival-floor properties (CIRISEdge#438) ──────────────────────
    //
    // These check PROPERTIES of the C₁ model — monotonicity, target
    // satisfaction, structural bounds — never a verbatim table value
    // (the protect-the-number anti-pattern the issue names). The table
    // itself is reproduced by `recommended_reconstruction_probability`
    // and MEASURED by `bench_dump_fountain_metrics` below.

    #[test]
    fn survival_floor_monotone_in_availability() {
        let mut prev = recommended_reconstruction_probability(0.50);
        for step in 51_u32..=99 {
            let q = f64::from(step) / 100.0;
            let p = recommended_reconstruction_probability(q);
            assert!(
                p > prev,
                "P(reconstruction) must strictly increase in q: P({q}) = {p} <= {prev}"
            );
            prev = p;
        }
    }

    #[test]
    fn design_target_met_at_stated_operating_points() {
        // The PROPERTY the module docs claim (CIRISEdge#438 design
        // target), not a table value.
        let wifi = recommended_reconstruction_probability(0.90);
        assert!(
            wifi >= 0.99,
            "design target: >= 99% reconstruction at q=0.90 typical wifi, got {wifi}"
        );
        let datacenter = recommended_reconstruction_probability(0.95);
        assert!(
            datacenter >= 0.999,
            "design target: >= 99.9% reconstruction at q=0.95 datacenter, got {datacenter}"
        );
        // Guard against the inflated pre-#438 claim creeping back: at
        // q=0.85 medium churn the honest model does NOT clear 99% (the
        // old comment claimed 99.95% there). Anyone re-raising the doc
        // claim must consciously delete this assertion.
        let churn = recommended_reconstruction_probability(0.85);
        assert!(
            (0.90..0.99).contains(&churn),
            "q=0.85 medium churn is a degraded operating point (~0.957) — \
             a value outside [0.90, 0.99) means the model changed: {churn}"
        );
    }

    #[test]
    fn duplicate_model_sandwiched_between_floor_and_naive() {
        // Structural bound: for 0 < q < 1 the spread-duplicate model
        // sits STRICTLY between the all-distinct floor (26 singly-held
        // symbols) and the naive 30-independent-draws model the pre-#438
        // table approximated. Catches both classes of model error:
        // treating duplicate holders as distinct symbols (inflation) and
        // dropping the duplicates' contribution (deflation).
        for step in (55_u32..=95).step_by(5) {
            let q = f64::from(step) / 100.0;
            let floor = binomial_sf(DEFAULT_TOTAL_SYMBOLS, DEFAULT_N_SOURCE, q);
            let naive = binomial_sf(DEFAULT_TARGET_HOLDERS, DEFAULT_N_SOURCE, q);
            let honest = recommended_reconstruction_probability(q);
            assert!(
                honest > floor,
                "q={q}: duplicates must help over the all-distinct floor ({honest} <= {floor})"
            );
            assert!(
                honest < naive,
                "q={q}: only 26 distinct symbols exist — the model must not \
                 reach the naive 30-draw bound ({honest} >= {naive})"
            );
        }
    }

    #[test]
    fn all_distinct_placement_reduces_to_plain_binomial() {
        // With peers == total_symbols there are no duplicates and the
        // model must collapse to P(Bin(total, q) >= N) exactly.
        for step in (50_u32..=95).step_by(5) {
            let q = f64::from(step) / 100.0;
            let collapsed = distinct_symbol_availability(
                DEFAULT_TOTAL_SYMBOLS,
                DEFAULT_TOTAL_SYMBOLS,
                DEFAULT_N_SOURCE,
                q,
            );
            let plain = binomial_sf(DEFAULT_TOTAL_SYMBOLS, DEFAULT_N_SOURCE, q);
            assert!(
                (collapsed - plain).abs() < 1e-12,
                "q={q}: zero-duplicate case must equal the plain binomial \
                 ({collapsed} vs {plain})"
            );
        }
    }

    #[test]
    fn repair_headroom_knee_at_k_6() {
        // Backs the DEFAULT_K_REPAIR doc claim: at the R=30 operating
        // point and q=0.90 typical wifi, K=5 misses the >= 99% design
        // target, K=6 meets it, and K=7's gain over K=6 is smaller than
        // K=6's over K=5 (diminishing returns).
        let at = |k: u32| {
            distinct_symbol_availability(
                DEFAULT_N_SOURCE + k,
                DEFAULT_TARGET_HOLDERS,
                DEFAULT_N_SOURCE,
                0.90,
            )
        };
        let k5 = at(5);
        let k6 = at(6);
        let k7 = at(7);
        assert!(
            k5 < 0.99,
            "K=5 must miss the >= 99% target at q=0.90, got {k5}"
        );
        assert!(
            k6 >= 0.99,
            "K=6 must meet the >= 99% target at q=0.90, got {k6}"
        );
        assert!(
            k7 - k6 < k6 - k5,
            "returns must diminish past the K=6 knee: +{} (K6->K7) vs +{} (K5->K6)",
            k7 - k6,
            k6 - k5
        );
    }

    #[test]
    fn monte_carlo_reproduces_exact_model() {
        // The measured oracle and the stated computation must agree —
        // this is the reproducibility contract CIRISEdge#438 demands.
        // 200k trials: sigma <= ~0.0011 at the worst point (q=0.80), so
        // 0.005 is a > 4.5-sigma tolerance; the fixed seed makes the
        // run deterministic besides.
        for &pct in &[80_u32, 85, 90, 95] {
            let q = f64::from(pct) / 100.0;
            let exact = recommended_reconstruction_probability(q);
            let measured = measure_reconstruction_ratio(q, 200_000, MC_SEED);
            assert!(
                (measured - exact).abs() < 0.005,
                "q={q}: Monte-Carlo ({measured}) diverged from exact model ({exact})"
            );
        }
    }

    // ─── Monte-Carlo measurement (shared by the test above + the dump) ──

    /// Fixed seed — the dump's published numbers are deterministic on
    /// (seed, commit), per the bench suite's reproducibility rule.
    const MC_SEED: u64 = 0x0438_C1B1_5EED_0001;

    /// SplitMix64 (Vigna) — same tiny deterministic generator the bench
    /// calibration anchor uses. No `rand` dependency in the lib.
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut x = *state;
        x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        x ^ (x >> 31)
    }

    /// One Bernoulli(q) draw from the top 53 bits.
    fn bernoulli(state: &mut u64, q: f64) -> bool {
        // (x >> 11) has at most 53 significant bits — exactly
        // representable in f64, so the cast is lossless.
        #[allow(clippy::cast_precision_loss)]
        let unit = (splitmix64(state) >> 11) as f64 * (1.0 / 9_007_199_254_740_992.0); // 2^-53
        unit < q
    }

    /// Monte-Carlo measurement of the C₁ survival floor at the shipped
    /// tuple: simulates the ACTUAL spread-duplicate placement (22
    /// singly-held + 4 doubly-held symbols over 30 peers), draws each
    /// peer up/down at availability `q`, counts DISTINCT reachable
    /// symbols, and reports the fraction of trials with >= N distinct.
    fn measure_reconstruction_ratio(q: f64, trials: u32, seed: u64) -> f64 {
        let dups = DEFAULT_TARGET_HOLDERS - DEFAULT_TOTAL_SYMBOLS;
        let singles = DEFAULT_TOTAL_SYMBOLS - dups;
        let mut state = seed;
        let mut successes = 0_u32;
        for _ in 0..trials {
            let mut distinct = 0_u32;
            for _ in 0..singles {
                if bernoulli(&mut state, q) {
                    distinct += 1;
                }
            }
            for _ in 0..dups {
                // Both draws must happen regardless of the first's
                // outcome — `||` on pre-drawn bools, not short-circuited
                // draws — so the RNG stream stays trial-shape-independent.
                let first_holder_up = bernoulli(&mut state, q);
                let second_holder_up = bernoulli(&mut state, q);
                if first_holder_up || second_holder_up {
                    distinct += 1;
                }
            }
            if distinct >= DEFAULT_N_SOURCE {
                successes += 1;
            }
        }
        f64::from(successes) / f64::from(trials)
    }

    // ────────────────────────────────────────────────────────────────────
    // VALUE-EMITTING DUMP (CIRISEdge#438) — the fountain-plane member of
    // the honest publishing lane (twin of realtime_av_alm::sim::tests::
    // bench_dump_mesh_metrics + replication::sim::tests::
    // bench_dump_replication_metrics). PRINTS the measured survival-floor
    // reconstruction ratio at each table operating point as a sentinel-
    // prefixed libtest-bencher line so benchmark-action trends it
    // per-release. Never asserts (named honesty — the agreement gate is
    // `monte_carlo_reproduces_exact_model` above).
    //
    // Wire contract with `.github/workflows/bench.yml`: lines are
    //   `SIMBENCH test fountain/<name> ... bench: <int> ns/iter (+/- 0)`
    // appended UN-normalized (ratios are semantic, not wall-time). The
    // `ns/iter` unit is a libtest artifact; `_x100000` ⇒ ratio×100000
    // (100000 ⇒ 1.0). Lane B: one name per availability point, the set
    // forms the reconstruction-vs-availability curve.
    //
    // Run: cargo test --release --lib bench_dump_fountain_metrics -- --nocapture
    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn bench_dump_fountain_metrics() {
        fn dump(name: &str, value: i64) {
            println!("SIMBENCH test {name} ... bench: {value} ns/iter (+/- 0)");
        }

        // Lane B — measured reconstruction ratio vs per-peer availability
        // at the shipped (N=20, K=6, R=30) tuple, 100k trials per point,
        // fixed seed. These are the module-level table's honest column,
        // measured rather than received.
        for &pct in &[80_u32, 85, 90, 95] {
            let q = f64::from(pct) / 100.0;
            let ratio = measure_reconstruction_ratio(q, 100_000, MC_SEED);
            dump(
                &format!("fountain/reconstruction/avail{pct}pct_x100000"),
                (ratio * 100_000.0).round() as i64,
            );
        }
    }
}

/// CIRISEdge#453 — the fountain/swarm consumer-floor manifest, emitted from
/// the SAME constants the planner runs on (never transcribed): persist's
/// `mesh_config` registry names `repair_planner` as the consumer of the
/// `redundancy.*` knobs, and its v29-era hand-transcription of these values
/// produced two defects only edge could detect (`k_repair_target` carrying
/// `n_source`'s 20, and a `min_viable_floor` ceiling of 3 under our floor of
/// 5 — an UNSATISFIABLE knob). Persist vendors
/// `evidence/CIRISEdge.fountain_floors.json` (regenerated from this fn, kept
/// honest by the `fountain_floors_json_matches_emitted` drift test) and gates
/// its ceilings against these floors instead of a hand-kept table.
///
/// Shape notes: `schema_version` versions the MANIFEST SHAPE only — the
/// values' provenance is the git tag persist vendors at (no crate-version
/// stamp, so the vendored copy does not churn on edge releases that leave
/// the floors untouched). Keys mirror persist v30.0.0's four typed axes
/// (`Symbols` vs `Holders` — the split that made this expressible) plus
/// `n_source_symbols` for the axis the original defect confused.
#[must_use]
pub fn fountain_floor_manifest() -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "consumer": "repair_planner",
        "symbols": {
            "n_source": DEFAULT_N_SOURCE,
            "k_repair": DEFAULT_K_REPAIR,
            "min_viable": DEFAULT_MIN_VIABLE_SYMBOLS,
        },
        "holders": {
            "target": crate::swarm::runtime::DEFAULT_TARGET_HOLDERS,
            "min_viable": crate::swarm::runtime::DEFAULT_MIN_VIABLE,
        },
    })
}

#[cfg(test)]
mod floor_manifest_tests {
    use super::*;

    /// CIRISEdge#453 — the vendored manifest is byte-locked to the emitter
    /// (which reads the live constants), so a constant change without a
    /// regenerated artifact is a build failure — transcription is
    /// structurally impossible in either repo's direction.
    #[test]
    fn fountain_floors_json_matches_emitted() {
        let vendored: serde_json::Value = serde_json::from_str(include_str!(
            "../../evidence/CIRISEdge.fountain_floors.json"
        ))
        .expect("vendored manifest parses");
        assert_eq!(
            vendored,
            fountain_floor_manifest(),
            "evidence/CIRISEdge.fountain_floors.json drifted from the live \
             constants — regenerate from fountain_floor_manifest() (CIRISEdge#453)"
        );
    }

    /// The knee pin travels WITH the manifest: k_repair in the emitted
    /// artifact is the property-tested K=6, not an independent number.
    #[test]
    fn manifest_k_repair_is_the_pinned_knee() {
        assert_eq!(fountain_floor_manifest()["symbols"]["k_repair"], 6);
    }
}
