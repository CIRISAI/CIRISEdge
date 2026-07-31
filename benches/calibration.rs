//! v15.7.0 — Calibration bench for runner-noise normalization
//! (CIRISEdge#430 bench-superset). Anchor for the bench workflow's
//! normalization step in `.github/workflows/bench.yml`. Adapted verbatim
//! (same inner loops, same anchor names) from CIRISPersist's
//! `benches/calibration.rs` (CIRISPersist#116/#122) so the two repos'
//! trend charts share a runner-noise model — a shared-substrate build on
//! the same Actions image should read the same CPU/DRAM anchor.
//!
//! ## Why this exists
//!
//! `benchmark-action/github-action-benchmark` raises regression alerts
//! based on absolute `ns/iter` values. On shared GitHub Actions runners,
//! neighbor-tenant load variation between consecutive runs produces
//! uniform 1.4×–2.5× swings across every bench in the suite. A cut that
//! touches nothing in any benched hot path (a doc bump, a pin currency
//! move) can trip a wall of performance alerts purely from runner noise —
//! exactly the false-positive class normalization solves. Edge's A/V +
//! transport benches (`realtime_av_relay`, `transport_reticulum_loopback`,
//! …) are wall-clock end-to-end and are the noisiest of the suite, so the
//! anchor matters more here than in persist.
//!
//! ## Two anchors — CPU + DRAM
//!
//! [`bench_calibration_splitmix`] is the CPU-bound anchor;
//! [`bench_calibration_dram_walk`] is the DRAM/cache-bound companion
//! (CIRISPersist#122). The workflow classifies each downstream bench by
//! name prefix and divides its `ns/iter` by the appropriate anchor:
//! - Memory-bandwidth-bound families → DRAM walk anchor
//! - Default (compute-/crypto-bound: the Ed25519+ML-DSA-65 verify path,
//!   canonicalization, seal/open) → SplitMix64 CPU anchor
//!
//! Edge's default classifier routes everything to the CPU anchor (the
//! hybrid-verify + AEAD seal hot paths are compute-bound); the DRAM anchor
//! is computed + published as its own trend series and is available for
//! reclassification (see the workflow's `case` block) should a
//! throughput-bound family (e.g. a large-frame `content_fetch_roundtrip`
//! sweep) show memory-axis false positives.
//!
//! ## Do not modify the inner loops without bumping the baseline
//!
//! The trend chart's historical points are anchored to THESE workloads.
//! Changing iteration counts, constants, the inner loop shapes, or the
//! buffer size silently invalidates the calibration baselines — the
//! gh-pages history would compare apples to oranges. If a real upgrade is
//! needed, treat it as a new metric (rename the bench function) and let the
//! trend chart reset. NOT feature-gated; runs under default features so the
//! anchor is available to every feature-set variant of the suite.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

/// SplitMix64 — Sebastiano Vigna's reference implementation. Tight,
/// branchless, deterministic, no allocator/IO. Hardware-portable: pure
/// 64-bit integer arithmetic + multiplies, both of which every modern
/// x86_64/aarch64 CPU executes at roughly the same per-cycle throughput
/// regardless of microarchitecture.
#[inline(always)]
fn splitmix64(z: &mut u64) -> u64 {
    *z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut x = *z;
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

fn bench_calibration_splitmix(c: &mut Criterion) {
    // 10 million inner iterations. Sized so each Criterion sample takes
    // ~20-50ms on a typical runner — enough work for the measurement to
    // dominate harness overhead, short enough that 20 samples fit
    // comfortably in the default 5s/group budget.
    const ITERATIONS: usize = 10_000_000;

    c.bench_function("calibration/splitmix64_10m", |b| {
        b.iter(|| {
            let mut z: u64 = 0xCAFE_BABE_DEAD_BEEF;
            for _ in 0..ITERATIONS {
                z = black_box(splitmix64(&mut z));
            }
            z
        });
    });
}

/// DRAM-bound calibration anchor for memory/cache-axis runner-noise
/// normalization (CIRISPersist#122).
///
/// Walks a 64MB buffer (well past any L1/L2/L3 on Actions runners —
/// largest GHA L3 observed is ~36MB on the newer `ubuntu-24.04` AMD EPYC
/// images) via a deterministic LCG-driven index sequence that defeats the
/// hardware prefetcher. Each access misses cache and goes to DRAM, so the
/// bench measures the runner's effective DRAM latency + bandwidth-under-
/// contention.
///
/// Pairs with [`bench_calibration_splitmix`] (pure CPU); the workflow
/// applies whichever anchor matches each bench's bottleneck.
fn bench_calibration_dram_walk(c: &mut Criterion) {
    // 64MB buffer of u64. Sized to exceed L3 on every runner we'll
    // realistically encounter (Azure Actions runner specs cap at 36MB
    // shared L3 for the newest AMD image).
    const BUF_ELEMS: usize = 8 * 1024 * 1024;
    // 500k random reads per iteration. With ~100ns DRAM-miss latency, each
    // Criterion sample takes ~50ms — fits 20 samples in the default 5s
    // budget with margin.
    const N_ACCESSES: usize = 500_000;

    // Allocate + init once outside the bench loop (allocation cost isn't
    // what we want to measure). Sequential fill so dead-code elimination
    // can't drop the buffer.
    let buf: Vec<u64> = (0..BUF_ELEMS as u64).collect();

    c.bench_function("calibration/dram_random_walk_500k", |b| {
        b.iter(|| {
            // Numerical-Recipes LCG — `idx = a * idx + c (mod 2^64)`
            // produces a stream the hardware prefetcher can't pattern-
            // match. Each step is ~3 cycles; the DRAM miss dominates.
            let mut idx: u64 = 0x1234_5678_DEAD_BEEF;
            let mut sum: u64 = 0;
            for _ in 0..N_ACCESSES {
                idx = idx
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                // Use the high bits — they have better randomness than the
                // low bits for an LCG.
                let i = (idx >> 32) as usize % BUF_ELEMS;
                sum = sum.wrapping_add(buf[i]);
            }
            black_box(sum)
        });
    });
}

criterion_group!(
    benches,
    bench_calibration_splitmix,
    bench_calibration_dram_walk,
);
criterion_main!(benches);
