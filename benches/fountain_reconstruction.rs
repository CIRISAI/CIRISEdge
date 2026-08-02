//! CIRISEdge#438 — fountain reconstruction bench: the REAL-CODEC half
//! of the survival-floor oracle.
//!
//! `src/holonomic/fountain_defaults.rs` states the C₁ reliability table
//! as a symbol-AVAILABILITY probability (`P(≥ N distinct symbols
//! reachable)` — exact math in `distinct_symbol_availability`, measured
//! by the `bench_dump_fountain_metrics` sim dump). That table assumes
//! `≥ N distinct symbols ⇒ decode succeeds`; RaptorQ actually carries a
//! small per-count decode-failure probability at exactly `N` (RFC 6330
//! overhead profile: occasionally 1–2 overhead symbols are needed).
//! This bench measures that assumption with the real codec:
//!
//! **Report (printed before the timing groups, `FOUNTAIN-RECON` lines):**
//! - `d(m)` — decode-success ratio from `m` distinct symbols, measured
//!   over 1000 deterministic random subsets per `m ∈ 18..=26` at the
//!   recommended `(N=20, K=6)` tuple. Expected shape: 0 below `N`
//!   (information-theoretic floor), ≈0.99 at exactly `N`, →1 by `N+2`.
//! - the composite `Σ_m P(X = m) · d(m)` per table availability point —
//!   the full reconstruction probability (availability × decode) next
//!   to the availability-only table value, so the doc's stated caveat
//!   is a measured number, not a received one.
//!
//! **Criterion groups (wall-clock, Lane-A shape if wired):**
//! - `fountain_reconstruction/decode/m{20,23,26}` — wrap-layer decode
//!   cost from a fixed decodable subset of `m` symbols (the decoder-CPU
//!   floor referenced by `DEFAULT_MIN_VIABLE_SYMBOLS`).
//! - `fountain_reconstruction/encode_n20_k6` — encode cost at the
//!   recommended tuple (~20 KiB payload).
//!
//! Run locally:
//! ```bash
//! cargo bench --features "codec-fountain" --bench fountain_reconstruction
//! ```
//!
//! NOT yet wired into CI lanes (noted in CIRISEdge#438): publishing it
//! in `.github/workflows/bench.yml` needs a
//! `run_bench "codec-fountain" fountain_reconstruction` line, and
//! compile-gating it in ci.yml's `benches` job needs `codec-fountain`
//! added to that job's `--features` list. The always-on half of the
//! oracle is the sim dump, which requires no workflow change.

use ciris_edge::holonomic::fountain_defaults::{
    distinct_symbol_availability, recommended_policy, DEFAULT_TARGET_HOLDERS,
};
use ciris_edge::transport::realtime_av_codec::fountain::{
    fountain_decode, fountain_encode, FountainConfig, FountainEncoded, FountainSymbol,
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

/// Uniform symbol size for the fixture. 1024 B × N=20 ⇒ ~20 KiB
/// payload — representative of a small fountain-wrapped content
/// object without making the subset sweep slow.
const SYMBOL_SIZE: u32 = 1024;

/// Deterministic seed — the printed report reproduces on (seed, commit).
const SEED: u64 = 0x0438_F0F0_5EED_0002;

/// Subsets sampled per `m` for the decode-success curve.
const SUBSET_TRIALS: u32 = 1000;

/// SplitMix64 (Vigna) — same deterministic generator as
/// `benches/calibration.rs`; no `rand` dependency.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut x = *state;
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

struct Fixture {
    config: FountainConfig,
    payload: Vec<u8>,
    encoded: FountainEncoded,
}

impl Fixture {
    fn build() -> Self {
        let policy = recommended_policy();
        let config = FountainConfig {
            n_source: policy.n_source,
            k_repair: policy.k_repair,
            symbol_size: SYMBOL_SIZE,
            min_viable_symbols: policy.min_viable_symbols,
        };
        // Deterministic pseudo-random payload, deliberately NOT a
        // multiple of symbol_size so the pad/trim path is exercised.
        let len = usize::try_from(policy.n_source * SYMBOL_SIZE - 37).expect("fixture len fits");
        let mut payload = Vec::with_capacity(len + 8);
        let mut state = SEED;
        while payload.len() < len {
            payload.extend_from_slice(&splitmix64(&mut state).to_le_bytes());
        }
        payload.truncate(len);
        let encoded = fountain_encode(&payload, &config).expect("fixture must encode");
        assert_eq!(
            encoded.symbols.len(),
            usize::try_from(policy.n_source + policy.k_repair).expect("total fits"),
            "encode must produce exactly N+K symbols"
        );
        Self {
            config,
            payload,
            encoded,
        }
    }

    /// Draw a subset of `m` distinct symbols (partial Fisher–Yates).
    fn random_subset(&self, m: usize, state: &mut u64) -> Vec<FountainSymbol> {
        let n = self.encoded.symbols.len();
        assert!(m <= n);
        let mut idx: Vec<usize> = (0..n).collect();
        for i in 0..m {
            let span = u64::try_from(n - i).expect("span fits");
            let offset = usize::try_from(splitmix64(state) % span).expect("offset < span");
            idx.swap(i, i + offset);
        }
        idx[..m]
            .iter()
            .map(|&i| self.encoded.symbols[i].clone())
            .collect()
    }

    /// One decode attempt; success requires bit-exact payload recovery
    /// (a successful-but-corrupt decode panics loud — codec bug).
    fn try_decode(&self, subset: &[FountainSymbol]) -> bool {
        match fountain_decode(
            subset,
            &self.encoded.symbol_hashes,
            self.encoded.original_content_length,
            &self.config,
        ) {
            Ok(decoded) => {
                assert!(
                    decoded == self.payload,
                    "decode succeeded but payload mismatched — codec bug"
                );
                true
            }
            Err(_) => false,
        }
    }

    /// Measured decode-success ratio `d(m)` over `SUBSET_TRIALS`
    /// deterministic random subsets.
    fn decode_success_ratio(&self, m: usize, state: &mut u64) -> f64 {
        let mut successes = 0_u32;
        for _ in 0..SUBSET_TRIALS {
            let subset = self.random_subset(m, state);
            if self.try_decode(&subset) {
                successes += 1;
            }
        }
        f64::from(successes) / f64::from(SUBSET_TRIALS)
    }

    /// A fixed subset of size `m` that decodes — for the wall-clock
    /// groups (timing a known-good decode, not retry noise).
    fn decodable_subset(&self, m: usize, state: &mut u64) -> Vec<FountainSymbol> {
        for _ in 0..10_000 {
            let subset = self.random_subset(m, state);
            if self.try_decode(&subset) {
                return subset;
            }
        }
        panic!("no decodable subset of size {m} found in 10k draws — decode is broken at this m");
    }

    /// Print the measured `d(m)` curve + the availability×decode
    /// composite next to the availability-only table values.
    fn print_reconstruction_report(&self) {
        let total = self.config.n_source + self.config.k_repair;
        let mut state = SEED ^ 0xD00D;
        println!("FOUNTAIN-RECON d(m): decode-success ratio from m distinct symbols");
        println!(
            "FOUNTAIN-RECON   (N={}, K={}, {SUBSET_TRIALS} subsets per m, seed-deterministic)",
            self.config.n_source, self.config.k_repair
        );
        let mut d = vec![0.0_f64; usize::try_from(total).expect("total fits") + 1];
        let first_measured = usize::try_from(self.config.n_source).expect("n fits") - 2;
        for (m, slot) in d.iter_mut().enumerate().skip(first_measured) {
            *slot = self.decode_success_ratio(m, &mut state);
            println!("FOUNTAIN-RECON   d({m}) = {slot:.4}");
        }
        // Full-set decode is the codec contract — hard-assert it.
        assert!(
            (d[usize::try_from(total).expect("total fits")] - 1.0).abs() < f64::EPSILON,
            "decode from all {total} symbols must always succeed"
        );

        println!("FOUNTAIN-RECON composite P(reconstruct) = sum_m P(X=m)*d(m) vs availability-only table:");
        for &pct in &[80_u32, 85, 90, 95] {
            let q = f64::from(pct) / 100.0;
            // P(X = m) = P(X >= m) - P(X >= m+1) from the exact
            // spread-duplicate model at the shipped tuple.
            let sf = |threshold: u32| {
                distinct_symbol_availability(total, DEFAULT_TARGET_HOLDERS, threshold, q)
            };
            let mut composite = 0.0_f64;
            for (m, &dm) in d.iter().enumerate() {
                let m32 = u32::try_from(m).expect("m fits");
                composite += (sf(m32) - sf(m32 + 1)) * dm;
            }
            let availability_only = sf(self.config.n_source);
            println!(
                "FOUNTAIN-RECON   q={q:.2}: composite {composite:.6} \
                 (availability-only {availability_only:.6}, decode overhead cost {:.6})",
                availability_only - composite
            );
        }
    }
}

fn bench_fountain_reconstruction(c: &mut Criterion) {
    let fixture = Fixture::build();

    // The measured reconstruction-success report (the #438 oracle for
    // the doc table's decode-assumption caveat) prints before the
    // timing groups — bencher-format output ignores non-`test` lines.
    fixture.print_reconstruction_report();

    let mut group = c.benchmark_group("fountain_reconstruction");
    let mut state = SEED ^ 0xBEEF;
    let n_source = usize::try_from(fixture.config.n_source).expect("n fits");
    let total = usize::try_from(fixture.config.n_source + fixture.config.k_repair).expect("fits");
    for &m in &[n_source, n_source + 3, total] {
        let subset = fixture.decodable_subset(m, &mut state);
        group.bench_with_input(
            BenchmarkId::new("decode", format!("m{m}")),
            &subset,
            |b, s| {
                b.iter(|| {
                    fountain_decode(
                        black_box(s),
                        &fixture.encoded.symbol_hashes,
                        fixture.encoded.original_content_length,
                        &fixture.config,
                    )
                    .expect("subset pre-verified decodable")
                });
            },
        );
    }
    group.bench_function("encode_n20_k6", |b| {
        b.iter(|| fountain_encode(black_box(&fixture.payload), &fixture.config).expect("encodes"));
    });
    group.finish();
}

criterion_group!(benches, bench_fountain_reconstruction);
criterion_main!(benches);
