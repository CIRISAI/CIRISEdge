//! `realtime_av_relay` — Layer 4 bench C for the v3.8.0 CEWP A/V scale
//! cut. Measures the realtime A/V **SFU relay** end-to-end:
//!
//!  - per-subscriber fan-out cost ([`RelayNode::forward`]) — `#122`
//!    inner-once / outer-N split at the relay tier;
//!  - the layer-admission filter overhead — `#128 / L2-C` per-
//!    subscriber `ReceiverLayerPolicy` early-drop semantics;
//!  - the mesh-vs-relay crossover — direct publisher mesh
//!    fan-out (N × [`seal_av_chunk`]) vs publisher → relay → N
//!    (publisher 1 × [`seal_av_inner`], relay N × [`seal_av_outer`]).
//!
//! # What this bench reveals (and what to read it for)
//!
//! 1. **Where the SFU helps** — the relay amortizes the publisher's
//!    [`seal_av_inner`] work (`#122` split: publisher seals once;
//!    relay seals outer per-subscriber). The publisher's CPU floor is
//!    `1 × inner_seal`, regardless of N. The cost moves to the relay.
//!    Read `mesh_vs_relay_comparison` `publisher_side` vs `relay_side`
//!    at large N to see where this lands.
//!
//! 2. **Where the layer filter helps** — a relay with mixed-policy
//!    subscribers can drop chunks BEFORE [`seal_av_outer`] —
//!    bandwidth + CPU savings at the source. The bench
//!    (`relay_forward_n_subscribers_with_layer_filter`) surfaces the
//!    per-skipped-subscriber savings vs the per-admitted-subscriber
//!    cost: a 50/50 mix at a non-BASE layer halves the per-frame
//!    fan-out cost. Frames at `ChunkLayer::BASE` are admitted by
//!    every policy (including `BLINKING_DOT`) so the filter has no
//!    effect at BASE — this is the v3.7.0 wire-compat property and
//!    the bench measures it (BASE rows match the UNCAPPED bench).
//!
//! 3. **Mesh-vs-relay crossover** — at small N (typically N ≤ 8),
//!    the direct mesh path may be cheaper because the relay adds an
//!    extra hop. At larger N, the publisher's CPU savings dominate.
//!    The bench (`mesh_vs_relay_comparison`) gives the empirical
//!    crossover by measuring both sides separately at every N.
//!    A consumer (capacity planner) compares
//!    `publisher_side / mesh_publisher` to decide when to enable SFU.
//!
//! # Parameter sweeps
//!
//! - **`N` (subscribers)** ∈ `{2, 8, 32, 128, 500}`
//! - **frame size** ∈ `{4 KiB, 16 KiB, 64 KiB}`
//! - **layer configurations** (for the layered variants):
//!   - all UNCAPPED (every chunk admitted)
//!   - all BLINKING_DOT (only `(0,0,0)` chunks admitted)
//!   - half UNCAPPED + half BLINKING_DOT (50/50 admission)
//!
//! # Setup cost discipline
//!
//! [`RelayNode`] construction is non-trivial — the test pattern in
//! `src/transport/realtime_av_relay.rs::tests::test_node` builds a
//! real [`reticulum_std::driver::ReticulumNode`] (writes an identity
//! file to a temp dir, allocates a tokio runtime, etc., via
//! `ReticulumNodeBuilder::build_sync`). The full subscriber roster
//! is also wired at setup time. Every `bench_with_input` group uses
//! `iter_batched` (or a wholly external setup closure) so the
//! relay-construction + subscriber-roster cost lands OUTSIDE the
//! steady-state measurement window — criterion only times the
//! `forward` / `seal_*` calls themselves. The `setup_*` helpers
//! return a populated `RelayNode` (or a populated mesh roster)
//! once per benchmark; the iter closure re-uses it for every
//! sample.
//!
//! # Reference issues
//!
//!  - CIRISEdge#66 — the bench's explicit charter (measure
//!    relay/SFU role);
//!  - CIRISEdge#122 — `seal_av_inner` / `seal_av_outer` split (the
//!    publisher-amortization story the SFU concretizes);
//!  - CIRISEdge#128 / L2-C — per-receiver layer-admission policy
//!    (`ReceiverLayerPolicy::admits` early-drop in `RelayNode::forward`).
//!
//! # Companion bench files
//!
//! Layer 4 bench A — `realtime_av_fanout.rs` (publisher-side
//! mesh fan-out; the direct-mesh comparison surface this bench
//! consumes); Layer 4 bench B — `realtime_av_session.rs` (session
//! tracker overhead). This file (bench C) is the relay tier.

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
    clippy::needless_range_loop
)]
#![cfg(feature = "_reticulum-module")]

use std::sync::Arc;
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use ciris_edge::transport::realtime_av::{
    seal_av_chunk, seal_av_inner, seal_av_outer, ChunkLayer, ChunkSeq, Epoch, EpochDek,
    InnerSealed, ReceiverLayerPolicy, StreamId, CODEC_AV1_SVC, CODEC_OPAQUE,
};
use ciris_edge::transport::realtime_av_relay::{PeerKeyId, RelayNode};

use reticulum_core::{DestinationHash, Identity};
use reticulum_std::driver::{ReticulumNode, ReticulumNodeBuilder};

// ─── Parameter sweep tables (held here so every group reads the
//     same constants — keeps cross-bench results lined up). ───────────

const N_SUBSCRIBERS: &[usize] = &[2, 8, 32, 128, 500];
const FRAME_SIZES: &[usize] = &[4 * 1024, 16 * 1024, 64 * 1024];

// ─── Throwaway RelayNode fixtures (mirrors the in-source test
//     pattern at src/transport/realtime_av_relay.rs::tests::test_node).
//
// `ReticulumNodeBuilder::build_sync` writes identity state to disk and
// constructs a real tokio runtime handle inside the node. We never
// drive the node for I/O (the bench targets the pure-compute fan-out
// path on `RelayNode::forward`), but we DO need a valid handle so the
// `RelayNode::new` constructor accepts it. Each fixture allocates its
// own temp directory (UUIDed) so concurrent benches in the same
// criterion run don't collide on disk. The temp dirs are leaked at the
// end of the process — fine for bench runs; the harness owns its
// `target/criterion/` tree and CI's bench runner cleans up via
// `rm -rf` on the runner sandbox. ────────────────────────────────────

fn bench_node() -> Arc<ReticulumNode> {
    let mut priv_bytes = [0u8; 64];
    for (i, b) in priv_bytes.iter_mut().enumerate() {
        // Deterministic synthetic key fill — matches the in-source
        // tests so the bench fixture shape stays consistent.
        *b = u8::try_from(i)
            .expect("index < 64")
            .wrapping_mul(31)
            .wrapping_add(1);
    }
    let identity =
        Identity::from_private_key_bytes(&priv_bytes).expect("build identity from synthetic key");
    let storage =
        std::env::temp_dir().join(format!("ciris-edge-relay-bench-{}", uuid::Uuid::new_v4()));
    let node = ReticulumNodeBuilder::new()
        .identity(identity)
        .storage_path(storage)
        .build_sync()
        .expect("build relay bench node");
    Arc::new(node)
}

fn bench_address() -> DestinationHash {
    DestinationHash::new([0x42u8; 16])
}

fn bench_stream(seed: u8) -> StreamId {
    StreamId([seed; 32])
}

fn bench_dek() -> EpochDek {
    EpochDek::from_bytes([0x77u8; 32])
}

fn bench_transit_key(idx: usize) -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, byte) in k.iter_mut().enumerate() {
        let mixed = (idx.wrapping_add(i)) as u8;
        *byte = mixed.wrapping_mul(13).wrapping_add(7);
    }
    k
}

fn bench_subscriber_id(idx: usize) -> PeerKeyId {
    format!("bench-sub-{idx:05}")
}

/// Build an `InnerSealed` chunk at a specific `(layer, codec_id)` for
/// use as input to `RelayNode::forward`. The bench picks `codec_id`
/// based on whether the layer is BASE (must be `CODEC_OPAQUE` per the
/// module invariant) or non-BASE (uses `CODEC_AV1_SVC` so the
/// admission path actually exercises — `CODEC_OPAQUE` chunks are
/// unconditionally admitted by every policy).
fn make_inner_chunk(
    plaintext: &[u8],
    dek: &EpochDek,
    stream: StreamId,
    chunk_seq: u64,
    layer: ChunkLayer,
) -> InnerSealed {
    let codec_id = if layer == ChunkLayer::BASE {
        CODEC_OPAQUE
    } else {
        CODEC_AV1_SVC
    };
    seal_av_inner(
        plaintext,
        dek,
        stream,
        Epoch(1),
        ChunkSeq(chunk_seq),
        codec_id,
        layer,
    )
    .expect("inner seal")
}

/// Allocate a `Vec<u8>` of `len` bytes filled with a deterministic
/// pattern. Frame payloads are not crypto-sensitive for the bench;
/// they just need a stable byte sequence so AEAD work is uniform.
fn make_frame_payload(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    for i in 0..len {
        v.push((i & 0xFF) as u8);
    }
    v
}

/// Build a `RelayNode` populated with `n` subscribers, all on the same
/// stream, each with their own synthetic transit key + `policy`.
/// Returns the populated relay + the stream id used.
fn setup_uniform_relay(n: usize, policy: ReceiverLayerPolicy) -> (RelayNode, StreamId) {
    let mut relay = RelayNode::new(bench_node(), bench_address());
    let stream = bench_stream(0xA1);
    for i in 0..n {
        relay
            .subscribe(stream, bench_subscriber_id(i), bench_transit_key(i), policy)
            .expect("subscribe");
    }
    (relay, stream)
}

/// Build a `RelayNode` populated with `n` subscribers, half at
/// `UNCAPPED` and half at `BLINKING_DOT`. Returns the populated relay
/// + the stream id.
fn setup_mixed_relay(n: usize) -> (RelayNode, StreamId) {
    let mut relay = RelayNode::new(bench_node(), bench_address());
    let stream = bench_stream(0xB2);
    for i in 0..n {
        let policy = if i % 2 == 0 {
            ReceiverLayerPolicy::UNCAPPED
        } else {
            ReceiverLayerPolicy::BLINKING_DOT
        };
        relay
            .subscribe(stream, bench_subscriber_id(i), bench_transit_key(i), policy)
            .expect("subscribe");
    }
    (relay, stream)
}

// ─── Group 1 — relay_forward_n_subscribers_uncapped ────────────────
//
// Pure inner-once / outer-N relay fan-out cost with NO layer-policy
// filtering — every subscriber is `UNCAPPED` so every chunk is
// admitted. This is the v3.7.0-compat baseline; the layered variants
// below compare against this. Per-iteration: ONE `forward` call → N
// `seal_av_outer` calls inside the relay. The publisher's
// `seal_av_inner` is NOT in this measurement — it's the relay-side
// cost surface only.

fn bench_relay_forward_uncapped(c: &mut Criterion) {
    let dek = bench_dek();
    let mut group = c.benchmark_group("relay_forward_n_subscribers_uncapped");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(8));

    for &frame_size in FRAME_SIZES {
        for &n in N_SUBSCRIBERS {
            // Throughput = bytes shipped per subscriber × N. Reports
            // the aggregate per-frame fan-out byte volume so cross-N
            // comparisons line up.
            group.throughput(Throughput::Bytes((frame_size as u64) * (n as u64)));
            // Setup OUTSIDE the iter closure: build relay + the
            // inner-sealed chunk once; `forward` is the only call
            // inside the measurement window. The relay's
            // `next_link_seq` advances on every iteration; this is
            // fine — the bench measures steady-state per-frame fan-
            // out cost, and `link_seq` advance is part of that path.
            let id = BenchmarkId::new(format!("frame_{frame_size}B"), n);
            group.bench_with_input(id, &(frame_size, n), |b, &(frame_size, n)| {
                let (mut relay, stream) = setup_uniform_relay(n, ReceiverLayerPolicy::UNCAPPED);
                let plaintext = make_frame_payload(frame_size);
                let inner = make_inner_chunk(&plaintext, &dek, stream, 0, ChunkLayer::BASE);
                b.iter(|| {
                    let out = relay.forward(stream, &inner).expect("forward");
                    black_box(out);
                });
            });
        }
    }

    group.finish();
}

// ─── Group 2 — relay_forward_n_subscribers_with_layer_filter ───────
//
// Per-subscriber layer-admission filter overhead. Three layer configs
// per (N, frame_size):
//
//   (a) all UNCAPPED — baseline; identical fan-out shape to Group 1.
//       Included here so the cross-config delta is read inline (vs
//       flipping benches).
//   (b) all BLINKING_DOT, chunk at non-BASE — every subscriber
//       rejects; `forward` returns an empty Vec. Measures the cost
//       of the filter check alone (one `admits()` per subscriber +
//       `continue`) WITHOUT any `seal_av_outer` work. The lower
//       bound on a "saturated drop" scenario.
//   (c) 50/50 mixed (half UNCAPPED, half BLINKING_DOT), chunk at
//       non-BASE — exactly half the subscribers admitted; reveals
//       the per-(admitted vs skipped) cost ratio. Demonstrates the
//       L2-C bandwidth saving: ~½ the fan-out cost vs (a).
//
// Note — for the BLINKING_DOT (b) and mixed (c) configs we ship the
// chunk at `ChunkLayer { 1, 0, 0 }` so it's NOT BASE (otherwise every
// policy admits and the filter is a no-op). The BASE-layer measurement
// is already covered by Group 1.

fn bench_relay_forward_with_layer_filter(c: &mut Criterion) {
    let dek = bench_dek();
    let mut group = c.benchmark_group("relay_forward_n_subscribers_with_layer_filter");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(8));

    // Non-BASE chunk layer so the filter is actually consulted.
    let non_base = ChunkLayer {
        spatial: 1,
        temporal: 0,
        quality: 0,
    };

    for &frame_size in FRAME_SIZES {
        for &n in N_SUBSCRIBERS {
            group.throughput(Throughput::Bytes((frame_size as u64) * (n as u64)));

            // (a) all UNCAPPED — baseline (filter no-ops; full N
            // outer seals).
            let id_a = BenchmarkId::new(format!("all_uncapped/frame_{frame_size}B"), n);
            group.bench_with_input(id_a, &(frame_size, n), |b, &(frame_size, n)| {
                let (mut relay, stream) = setup_uniform_relay(n, ReceiverLayerPolicy::UNCAPPED);
                let plaintext = make_frame_payload(frame_size);
                let inner = make_inner_chunk(&plaintext, &dek, stream, 0, non_base);
                b.iter(|| {
                    let out = relay.forward(stream, &inner).expect("forward");
                    black_box(out);
                });
            });

            // (b) all BLINKING_DOT — every subscriber rejects; filter
            // check only, NO outer seal work.
            let id_b = BenchmarkId::new(format!("all_blinking_dot/frame_{frame_size}B"), n);
            group.bench_with_input(id_b, &(frame_size, n), |b, &(frame_size, n)| {
                let (mut relay, stream) = setup_uniform_relay(n, ReceiverLayerPolicy::BLINKING_DOT);
                let plaintext = make_frame_payload(frame_size);
                let inner = make_inner_chunk(&plaintext, &dek, stream, 0, non_base);
                b.iter(|| {
                    let out = relay.forward(stream, &inner).expect("forward");
                    // Sanity — every subscriber rejected the
                    // non-BASE chunk; this proves the bench is
                    // hitting the filter path and not silently
                    // doing the full fan-out.
                    debug_assert!(out.is_empty());
                    black_box(out);
                });
            });

            // (c) 50/50 mixed — half admitted, half skipped; reveals
            // the per-(admitted vs skipped) cost ratio.
            let id_c = BenchmarkId::new(format!("mixed_50_50/frame_{frame_size}B"), n);
            group.bench_with_input(id_c, &(frame_size, n), |b, &(frame_size, n)| {
                let (mut relay, stream) = setup_mixed_relay(n);
                let plaintext = make_frame_payload(frame_size);
                let inner = make_inner_chunk(&plaintext, &dek, stream, 0, non_base);
                b.iter(|| {
                    let out = relay.forward(stream, &inner).expect("forward");
                    // The exact admitted count is `n / 2 + n % 2`
                    // (the even-indexed subs are UNCAPPED). Don't
                    // assert here — bench correctness; the
                    // structural shape is validated in the in-
                    // source `realtime_av_relay::tests`.
                    black_box(out);
                });
            });
        }
    }

    group.finish();
}

// ─── Group 3 — relay_set_policy_overhead ────────────────────────────
//
// Per-call cost of `RelayNode::set_policy` against a populated relay.
// The relay holds N subscribers (uniformly UNCAPPED); per iteration
// we flip ONE subscriber's policy to BLINKING_DOT then back to
// UNCAPPED. Two `set_policy` calls per criterion iteration so the
// relay's roster state doesn't drift over the iteration count —
// each iter is policy-conserving (UNCAPPED-in / UNCAPPED-out for
// the toggled subscriber). The reported time is for the two calls.
// Subscribers are picked via a rotating index `i % n` so the cache
// line for the targeted `(subscriber, stream)` state moves on every
// iter — measures the realistic case where a bandwidth-budget shift
// can arrive for any subscriber.

fn bench_relay_set_policy_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("relay_set_policy_overhead");
    group
        .sample_size(50)
        .measurement_time(Duration::from_secs(5));

    for &n in N_SUBSCRIBERS {
        // No throughput tag — this is a per-call latency
        // measurement, not a per-byte one.
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let (mut relay, stream) = setup_uniform_relay(n, ReceiverLayerPolicy::UNCAPPED);
            let mut idx: usize = 0;
            b.iter(|| {
                let sub = bench_subscriber_id(idx % n);
                relay
                    .set_policy(stream, &sub, ReceiverLayerPolicy::BLINKING_DOT)
                    .expect("set_policy down");
                relay
                    .set_policy(stream, &sub, ReceiverLayerPolicy::UNCAPPED)
                    .expect("set_policy up");
                idx = idx.wrapping_add(1);
                black_box(idx);
            });
        });
    }

    group.finish();
}

// ─── Group 4 — mesh_vs_relay_comparison ─────────────────────────────
//
// The empirical crossover question — at what N does going through an
// SFU beat the direct mesh path on the **publisher**? Four sub-benches
// per (N, frame_size) cell so the comparison is read inline:
//
//   mesh_publisher     — direct mesh: publisher does N × `seal_av_chunk`
//                        (one full inner+outer seal per subscriber).
//                        This is the publisher CPU bill on the
//                        N=anything direct path.
//   relay_publisher    — SFU path, publisher side: 1 × `seal_av_inner`.
//                        Constant cost regardless of N — the #122
//                        amortization story.
//   relay_relay        — SFU path, relay side: N × `seal_av_outer`,
//                        plus the relay's per-subscriber bookkeeping
//                        (`next_link_seq` advance, `RelayForwardOut`
//                        push). Reported per `RelayNode::forward` call.
//   relay_total        — `relay_publisher + relay_relay` (computed by
//                        the criterion consumer; both are independently
//                        timed here). Comparing `mesh_publisher` to
//                        `relay_publisher + relay_relay` answers
//                        "where does the relay hop pay for itself"
//                        end-to-end CPU-wise, vs comparing
//                        `mesh_publisher` to `relay_publisher` alone
//                        answers "what's the publisher CPU savings".
//
// Implementation notes:
//
//  - `mesh_publisher` uses N synthetic transit keys + `link_id`
//    bytes per subscriber — same construction as the relay's
//    per-subscriber state. The mesh path doesn't have a relay; it's
//    "publisher would send N times direct".
//  - `relay_publisher` measures just the inner seal — no outer at
//    all, since on the SFU path the publisher ships the inner
//    ciphertext to the relay over its OWN single Link (also an
//    outer seal, but that's a single seal regardless of N — it's a
//    publisher→relay link, not a publisher→subscriber link, and the
//    bench targets the per-N cost).
//  - `relay_relay` re-uses the Group 1 fixture shape — populated
//    relay, all-UNCAPPED subscribers, full fan-out. Re-measuring it
//    here (instead of cross-referencing Group 1's numbers) is
//    deliberate: keeping the four lines in ONE criterion group
//    makes the crossover read directly from the HTML report.

fn bench_mesh_vs_relay_comparison(c: &mut Criterion) {
    let dek = bench_dek();
    let mut group = c.benchmark_group("mesh_vs_relay_comparison");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(8));

    for &frame_size in FRAME_SIZES {
        for &n in N_SUBSCRIBERS {
            group.throughput(Throughput::Bytes((frame_size as u64) * (n as u64)));

            // mesh_publisher — N × seal_av_chunk (publisher CPU on
            // the direct-mesh path).
            let id_mesh = BenchmarkId::new(format!("mesh_publisher/frame_{frame_size}B"), n);
            group.bench_with_input(id_mesh, &(frame_size, n), |b, &(frame_size, n)| {
                // Precompute the per-subscriber (transit_key, link_id)
                // tuples so the bench inner loop pays only for the
                // crypto, not for vec allocations.
                let plaintext = make_frame_payload(frame_size);
                let stream = bench_stream(0xC3);
                let transit_keys: Vec<[u8; 32]> = (0..n).map(bench_transit_key).collect();
                let link_ids: Vec<Vec<u8>> = (0..n)
                    .map(|i| bench_subscriber_id(i).as_bytes().to_vec())
                    .collect();
                let mut chunk_seq: u64 = 0;
                b.iter(|| {
                    // One frame → N seals, one per subscriber. The
                    // `chunk_seq` advances once per frame (per the
                    // direct-mesh semantics: each frame is a single
                    // chunk).
                    for i in 0..n {
                        let sealed = seal_av_chunk(
                            &plaintext,
                            &transit_keys[i],
                            &link_ids[i],
                            chunk_seq,
                            &dek,
                            stream,
                            Epoch(1),
                            ChunkSeq(chunk_seq),
                            CODEC_OPAQUE,
                            ChunkLayer::BASE,
                        )
                        .expect("seal_av_chunk");
                        black_box(sealed);
                    }
                    chunk_seq = chunk_seq.wrapping_add(1);
                });
            });

            // relay_publisher — 1 × seal_av_inner. The publisher's
            // entire per-frame CPU bill on the SFU path is one
            // inner seal; the per-subscriber outer is the relay's
            // problem.
            let id_pub = BenchmarkId::new(format!("relay_publisher/frame_{frame_size}B"), n);
            group.bench_with_input(id_pub, &(frame_size, n), |b, &(frame_size, _n)| {
                let plaintext = make_frame_payload(frame_size);
                let stream = bench_stream(0xC4);
                let mut chunk_seq: u64 = 0;
                b.iter(|| {
                    let inner = seal_av_inner(
                        &plaintext,
                        &dek,
                        stream,
                        Epoch(1),
                        ChunkSeq(chunk_seq),
                        CODEC_OPAQUE,
                        ChunkLayer::BASE,
                    )
                    .expect("seal_av_inner");
                    chunk_seq = chunk_seq.wrapping_add(1);
                    black_box(inner);
                });
            });

            // relay_relay — N × seal_av_outer at the relay, in the
            // RelayNode::forward shape (so the bench captures the
            // relay's per-subscriber bookkeeping, not just raw
            // crypto).
            let id_relay = BenchmarkId::new(format!("relay_relay/frame_{frame_size}B"), n);
            group.bench_with_input(id_relay, &(frame_size, n), |b, &(frame_size, n)| {
                let (mut relay, stream) = setup_uniform_relay(n, ReceiverLayerPolicy::UNCAPPED);
                let plaintext = make_frame_payload(frame_size);
                let inner = make_inner_chunk(&plaintext, &dek, stream, 0, ChunkLayer::BASE);
                b.iter(|| {
                    let out = relay.forward(stream, &inner).expect("forward");
                    black_box(out);
                });
            });

            // relay_outer_only — raw N × seal_av_outer (NO RelayNode
            // bookkeeping). The lower-bound on relay-side cost; the
            // delta to `relay_relay` is the per-frame
            // HashMap-lookup + push + link_seq advance overhead.
            let id_outer = BenchmarkId::new(format!("relay_outer_only/frame_{frame_size}B"), n);
            group.bench_with_input(id_outer, &(frame_size, n), |b, &(frame_size, n)| {
                let plaintext = make_frame_payload(frame_size);
                let stream = bench_stream(0xC5);
                let inner = make_inner_chunk(&plaintext, &dek, stream, 0, ChunkLayer::BASE);
                let transit_keys: Vec<[u8; 32]> = (0..n).map(bench_transit_key).collect();
                let link_ids: Vec<Vec<u8>> = (0..n)
                    .map(|i| bench_subscriber_id(i).as_bytes().to_vec())
                    .collect();
                let mut link_seq: u64 = 0;
                b.iter(|| {
                    for i in 0..n {
                        let sealed =
                            seal_av_outer(&inner, &transit_keys[i], &link_ids[i], link_seq)
                                .expect("seal_av_outer");
                        black_box(sealed);
                    }
                    link_seq = link_seq.wrapping_add(1);
                });
            });
        }
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_relay_forward_uncapped,
    bench_relay_forward_with_layer_filter,
    bench_relay_set_policy_overhead,
    bench_mesh_vs_relay_comparison
);
criterion_main!(benches);
