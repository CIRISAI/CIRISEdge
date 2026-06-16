//! `realtime_av_fanout` — sender-side CPU as a function of mesh size N,
//! frame size, and codec/layer configuration. The Layer-4 bench A for
//! v3.8.0 (CIRISEdge#122 + #128).
//!
//! # What this bench measures
//!
//! Three variants of fanning out ONE realtime A/V chunk to N mesh
//! participants. All three produce byte-identical wires per receiver —
//! the differences are pure sender CPU.
//!
//! 1. **`naive_seal_chunk_n_recipients`** — v3.7.0 baseline. Calls
//!    [`seal_av_chunk`] once per participant. Inner AEAD work runs N
//!    times; outer AEAD work runs N times. This is what the production
//!    PyO3 wrapper used at v3.7.0 (and what cross-wheel Python callers
//!    that have not yet adopted the fan-out split still do).
//!
//! 2. **`inner_once_outer_n_recipients`** — CIRISEdge#122 split.
//!    `seal_av_inner` runs once per chunk; `seal_av_outer` runs N
//!    times. The substrate's claimed ~1.98× speedup at N=50, 16 KiB
//!    frames comes from this curve being roughly half the slope of the
//!    naive curve at small N (and approaching 1/2 asymptotically at
//!    large N + small frames where the inner AEAD dominates).
//!
//! 3. **`layered_inner_once_outer_admitted`** — CIRISEdge#128 layer
//!    policy composed with #122 split. Participants are split between
//!    UNCAPPED and BLINKING_DOT [`ReceiverLayerPolicy`] (50/50);
//!    [`RealtimeFanout::plan_layered`] filters by reachability ∧
//!    per-receiver policy; only admitted participants pay the outer
//!    seal cost. For a chunk above the BASE cell (e.g. spatial layer
//!    1+), the BLINKING_DOT half is dropped — the bench measures the
//!    realized work which scales with `|admitted|` not `N`.
//!
//! # Issues
//!
//! - CIRISEdge#122 — fan-out optimization (inner-once / outer-N split).
//!   The "~2× win at N=50" claim is the value this bench audits.
//! - CIRISEdge#128 — codec namespace + per-receiver layer policy. The
//!   `plan_layered` filter is the surface exercised here.
//!
//! # Where the numbers land
//!
//! Criterion writes per-group HTML to `target/criterion/<group>/` —
//! the same path the existing benches use (see docs/BENCHMARKS.md). The
//! CI workflow `.github/workflows/bench.yml` uploads it as the
//! `criterion-report` artifact.
//!
//! # Reachability fixture
//!
//! [`RealtimeFanout::plan_layered`] consumes a [`ReachabilityTracker`].
//! The bench builds one tracker per run and seeds 10/10 success for
//! every participant so the reachability filter is a no-op — the bench
//! is measuring AEAD + dispatch cost, not the reachability scan. The
//! plan call IS still inside the timed region so the per-chunk overhead
//! of running the filter is included in variant 3.

#![allow(
    clippy::pedantic,
    clippy::needless_pass_by_value,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::items_after_statements,
    clippy::used_underscore_binding,
    clippy::field_reassign_with_default,
    clippy::needless_raw_string_hashes
)]

use std::time::Duration;

use ciris_edge::reachability::{AttemptOutcome, ReachabilityTracker};
use ciris_edge::transport::realtime_av::{
    seal_av_chunk, seal_av_inner, seal_av_outer, ChunkLayer, ChunkSeq, Epoch, EpochDek,
    MeshParticipant, RealtimeFanout, ReceiverLayerPolicy, StreamId, CODEC_AV1_SVC, CODEC_OPAQUE,
};
use ciris_edge::transport::TransportId;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

// ─── Parameter sweeps ────────────────────────────────────────────────

const N_RECIPIENTS: &[usize] = &[2, 8, 16, 32, 64, 128, 200];
const FRAME_SIZES: &[usize] = &[1024, 4 * 1024, 16 * 1024, 64 * 1024];

const TRANSPORT_ID: TransportId = TransportId("reticulum");
const REACH_WINDOW_SECS: u64 = 60;

// ─── Synthetic fixtures ──────────────────────────────────────────────
//
// Per the task brief, these are bench fixtures, not real keys. The AEAD
// + dispatching cost is what's being measured, so deterministic byte
// patterns suffice.

fn fixture_dek() -> EpochDek {
    EpochDek::from_bytes([0x3Du8; 32])
}

fn fixture_stream() -> StreamId {
    StreamId([0xAB; 32])
}

fn fixture_transit_key(i: usize) -> [u8; 32] {
    // Per-recipient transit key — distinct so each outer seal pays its
    // own AES schedule cost (closer to the real-world fan-out shape).
    let mut k = [0u8; 32];
    for (j, slot) in k.iter_mut().enumerate() {
        *slot = ((i as u32).wrapping_mul(2654435761).wrapping_add(j as u32) & 0xFF) as u8;
    }
    k
}

fn fixture_link_id(i: usize) -> Vec<u8> {
    format!("link-{i:04}").into_bytes()
}

fn fixture_plaintext(size: usize) -> Vec<u8> {
    // Deterministic non-repeating pattern — AEAD cost is data-dependent
    // only via length, but a non-zero pattern keeps any future SIMD
    // optimization from short-circuiting on all-zero blocks.
    (0..size).map(|i| (i & 0xFF) as u8).collect()
}

/// Build N participants. `layered` controls the policy mix:
/// - `false` — every participant is UNCAPPED (variants 1 + 2).
/// - `true` — alternating UNCAPPED / BLINKING_DOT (variant 3).
fn fixture_participants(n: usize, layered: bool) -> Vec<MeshParticipant> {
    (0..n)
        .map(|i| {
            let mut p = MeshParticipant::new(format!("peer-{i:04}"), fixture_link_id(i));
            if layered && i % 2 == 1 {
                p.layer_policy = ReceiverLayerPolicy::BLINKING_DOT;
            } else {
                p.layer_policy = ReceiverLayerPolicy::UNCAPPED;
            }
            p
        })
        .collect()
}

/// Build a [`ReachabilityTracker`] with 10/10 success seeded for each
/// participant — so the reachability filter is a no-op and the bench
/// measures AEAD + dispatch cost, not reachability bookkeeping.
fn fixture_tracker(participants: &[MeshParticipant]) -> ReachabilityTracker {
    let tracker = ReachabilityTracker::new(REACH_WINDOW_SECS);
    for p in participants {
        for _ in 0..10 {
            tracker.record_attempt(&p.peer_key_id, TRANSPORT_ID, AttemptOutcome::SendSuccess);
        }
    }
    tracker
}

// ─── Layer configurations for variant 3 ──────────────────────────────

/// Layer configurations swept in variant 3:
/// - "1-layer opaque": one CODEC_OPAQUE chunk at BASE.
/// - "3-spatial AV1 SVC": three CODEC_AV1_SVC chunks at spatial 0/1/2.
/// - "7-cell full SVC": the full spatial × temporal × quality cube
///   trimmed to 7 representative cells.
fn layer_configs() -> Vec<(&'static str, u8, Vec<ChunkLayer>)> {
    vec![
        ("1-layer-opaque", CODEC_OPAQUE, vec![ChunkLayer::BASE]),
        (
            "3-spatial-av1-svc",
            CODEC_AV1_SVC,
            vec![
                ChunkLayer {
                    spatial: 0,
                    temporal: 0,
                    quality: 0,
                },
                ChunkLayer {
                    spatial: 1,
                    temporal: 0,
                    quality: 0,
                },
                ChunkLayer {
                    spatial: 2,
                    temporal: 0,
                    quality: 0,
                },
            ],
        ),
        (
            "7-cell-full-svc",
            CODEC_AV1_SVC,
            vec![
                // Base
                ChunkLayer {
                    spatial: 0,
                    temporal: 0,
                    quality: 0,
                },
                // Temporal enhancement
                ChunkLayer {
                    spatial: 0,
                    temporal: 1,
                    quality: 0,
                },
                // Quality enhancement
                ChunkLayer {
                    spatial: 0,
                    temporal: 0,
                    quality: 1,
                },
                // Spatial enhancement (level 1)
                ChunkLayer {
                    spatial: 1,
                    temporal: 0,
                    quality: 0,
                },
                // Spatial+temporal
                ChunkLayer {
                    spatial: 1,
                    temporal: 1,
                    quality: 0,
                },
                // Spatial+quality
                ChunkLayer {
                    spatial: 1,
                    temporal: 0,
                    quality: 1,
                },
                // Top of cube
                ChunkLayer {
                    spatial: 2,
                    temporal: 1,
                    quality: 1,
                },
            ],
        ),
    ]
}

// ─── Variant 1 — naive seal_av_chunk × N ─────────────────────────────

fn bench_naive_seal_chunk_n_recipients(c: &mut Criterion) {
    let dek = fixture_dek();
    let stream = fixture_stream();
    let epoch = Epoch(1);

    let mut group = c.benchmark_group("naive_seal_chunk_n_recipients");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(5));

    for &frame_size in FRAME_SIZES {
        let plaintext = fixture_plaintext(frame_size);
        for &n in N_RECIPIENTS {
            // Per-iteration work = N seal_av_chunk calls on a frame of
            // `frame_size` bytes. Report throughput in bytes/sec
            // representing the TOTAL bytes pushed across the mesh per
            // iteration (frame_size × N) — the most useful number for
            // sizing a sender's CPU budget.
            let total_bytes = (frame_size as u64) * (n as u64);
            group.throughput(Throughput::Bytes(total_bytes));
            let transit_keys: Vec<[u8; 32]> = (0..n).map(fixture_transit_key).collect();
            let link_ids: Vec<Vec<u8>> = (0..n).map(fixture_link_id).collect();
            group.bench_with_input(
                BenchmarkId::new(format!("frame{frame_size}B"), n),
                &n,
                |b, &n| {
                    b.iter(|| {
                        let mut chunk_seq = 0u64;
                        for i in 0..n {
                            let sealed = seal_av_chunk(
                                black_box(&plaintext),
                                black_box(&transit_keys[i]),
                                black_box(&link_ids[i]),
                                black_box(chunk_seq),
                                &dek,
                                stream,
                                epoch,
                                ChunkSeq(chunk_seq),
                                CODEC_OPAQUE,
                                ChunkLayer::BASE,
                            )
                            .expect("seal");
                            black_box(sealed);
                            chunk_seq = chunk_seq.wrapping_add(1);
                        }
                    });
                },
            );
        }
    }
    group.finish();
}

// ─── Variant 2 — seal_av_inner × 1 + seal_av_outer × N ──────────────

fn bench_inner_once_outer_n_recipients(c: &mut Criterion) {
    let dek = fixture_dek();
    let stream = fixture_stream();
    let epoch = Epoch(1);

    let mut group = c.benchmark_group("inner_once_outer_n_recipients");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(5));

    for &frame_size in FRAME_SIZES {
        let plaintext = fixture_plaintext(frame_size);
        for &n in N_RECIPIENTS {
            let total_bytes = (frame_size as u64) * (n as u64);
            group.throughput(Throughput::Bytes(total_bytes));
            let transit_keys: Vec<[u8; 32]> = (0..n).map(fixture_transit_key).collect();
            let link_ids: Vec<Vec<u8>> = (0..n).map(fixture_link_id).collect();
            group.bench_with_input(
                BenchmarkId::new(format!("frame{frame_size}B"), n),
                &n,
                |b, &n| {
                    b.iter(|| {
                        let inner = seal_av_inner(
                            black_box(&plaintext),
                            &dek,
                            stream,
                            epoch,
                            ChunkSeq(0),
                            CODEC_OPAQUE,
                            ChunkLayer::BASE,
                        )
                        .expect("inner");
                        for i in 0..n {
                            let sealed = seal_av_outer(
                                black_box(&inner),
                                black_box(&transit_keys[i]),
                                black_box(&link_ids[i]),
                                black_box(i as u64),
                            )
                            .expect("outer");
                            black_box(sealed);
                        }
                    });
                },
            );
        }
    }
    group.finish();
}

// ─── Variant 3 — plan_layered + inner × 1 + outer × |admitted| ──────

fn bench_layered_inner_once_outer_admitted(c: &mut Criterion) {
    let dek = fixture_dek();
    let stream = fixture_stream();
    let epoch = Epoch(1);

    let mut group = c.benchmark_group("layered_inner_once_outer_admitted");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(5));

    let configs = layer_configs();
    for (cfg_label, codec_id, layers) in &configs {
        for &frame_size in FRAME_SIZES {
            let plaintext = fixture_plaintext(frame_size);
            for &n in N_RECIPIENTS {
                let total_bytes = (frame_size as u64) * (n as u64);
                group.throughput(Throughput::Bytes(total_bytes));
                let participants = fixture_participants(n, true);
                let tracker = fixture_tracker(&participants);
                let transit_keys: Vec<[u8; 32]> = (0..n).map(fixture_transit_key).collect();
                let bench_id = BenchmarkId::new(format!("{cfg_label}-frame{frame_size}B"), n);
                group.bench_with_input(bench_id, &n, |b, &_n| {
                    b.iter(|| {
                        let mut chunk_seq: u64 = 0;
                        for layer in layers {
                            let inner = seal_av_inner(
                                black_box(&plaintext),
                                &dek,
                                stream,
                                epoch,
                                ChunkSeq(chunk_seq),
                                *codec_id,
                                *layer,
                            )
                            .expect("inner");
                            let admitted = RealtimeFanout::plan_layered(
                                black_box(&participants),
                                *layer,
                                black_box(&tracker),
                                TRANSPORT_ID,
                                0.5,
                            );
                            for p in &admitted {
                                // Recover the per-participant index from
                                // the synthetic peer_key_id so we can
                                // reuse the fixture transit_keys slot.
                                let i: usize = p.peer_key_id["peer-".len()..]
                                    .parse()
                                    .expect("peer index parses");
                                let sealed = seal_av_outer(
                                    black_box(&inner),
                                    black_box(&transit_keys[i]),
                                    black_box(&p.link_id),
                                    black_box(chunk_seq),
                                )
                                .expect("outer");
                                black_box(sealed);
                            }
                            chunk_seq = chunk_seq.wrapping_add(1);
                        }
                    });
                });
            }
        }
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_naive_seal_chunk_n_recipients,
    bench_inner_once_outer_n_recipients,
    bench_layered_inner_once_outer_admitted,
);
criterion_main!(benches);
