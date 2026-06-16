//! `realtime_av_mesh_e2e` — full holographic-mesh round-trip bench
//! (v3.8.0 CIRISEdge#128 MDC substrate validation).
//!
//! # User narrative
//!
//! "8K → 2 × 4K → 4 × 2K → 2 × 4K → 1 × 8K"
//!
//! Translated to the substrate's byte semantics:
//!
//! - "8K" = a 64 KiB total frame payload at the publisher.
//! - "→ 2 × 4K" = first dyadic decomposition: 2 descriptions at depth 1.
//! - "→ 4 × 2K" = second decomposition: each of those splits → 4
//!   sub-streams at depth 2. Each carries a 16 KiB sub-stream payload.
//! - "→ 2 × 4K" = the receiver re-aggregates pairs of 16 KiB plaintexts
//!   into 2 mid-level 32 KiB descriptions on its way back up.
//! - "→ 1 × 8K" = final reassembly: receiver concatenates the 4
//!   plaintexts back into the original 64 KiB frame.
//!
//! The substrate is **byte-level and codec-agnostic**. This bench
//! validates that the [`seal_av_inner`] / [`seal_av_outer`] +
//! [`MultiParentSubscription`] composition is correct end-to-end and
//! cheap enough to be viable; it does NOT validate a real MDC codec
//! (cf. `docs/V3_8_0_SOTA_VALIDATION.md` for the codec-availability
//! story).
//!
//! # Topology
//!
//! ```text
//!                 ┌─ relay@[0,0] ─→ MPS@[0,0] ─┐
//!                 ├─ relay@[0,1] ─→ MPS@[0,1] ─┤
//!  publisher ─────┤                            ├──→ reassemble (64 KiB)
//!                 ├─ relay@[1,0] ─→ MPS@[1,0] ─┤
//!                 └─ relay@[1,1] ─→ MPS@[1,1] ─┘
//! ```
//!
//! - 1 publisher emits 4 inner-sealed sub-stream chunks per frame.
//! - 4 [`RelayNode`] instances (one tree per sub-stream).
//! - 1 receiver runs 4 parallel [`MultiParentSubscription`] instances
//!   (one per sub-stream path).
//! - The receiver opens each chunk with [`open_av_chunk`] and
//!   reassembles the 4 sub-stream plaintexts back into the original
//!   64 KiB frame.
//!
//! At the substrate tier each sub-stream IS an independent
//! `[`StreamId`]` — the dyadic `sub_stream_path` lives on the
//! [`MultiParentSubscription`] header for dedup, and the substrate's
//! `seal_av_inner` is per-`(StreamId, Epoch, ChunkSeq)`. The bench
//! threads one `StreamId` per sub-stream so the relay tree and dedup
//! ring see independent streams (as production MDC routing would).
//!
//! # Bench groups
//!
//! 1. `mesh_e2e_round_trip_correctness` — single-parent fan-out, 64 KiB
//!    full round-trip. Asserts reassembled bytes == original frame.
//! 2. `mesh_e2e_multi_parent_dedup` — 2 parents per sub-stream.
//!    Validates that [`MultiParentSubscription::observe_chunk`] dedup
//!    yields exactly 4 [`ObserveOutcome::FirstDelivery`] + 4
//!    [`ObserveOutcome::Duplicate`] per frame.
//! 3. `mesh_e2e_degraded_quality` — sweep subscribed sub-streams ∈ {1,
//!    2, 3, 4}; bytes-length proportional to subscribed count. The
//!    substrate-level demonstration of "any subset reconstructs at
//!    proportional fidelity" (the user-visible holographic property).
//! 4. `mesh_e2e_planner_picks_distinct_parents` —
//!    [`AlmJoinPlanner::plan_for_substream`] must pick 4 DIFFERENT
//!    primary parents (one specialist per sub-stream) out of a
//!    candidate pool of 10 peers (4 single-substream specialists +
//!    6 opaque/other peers).
//! 5. `mesh_e2e_full_round_trip_cost_decomposition` — per-step cost
//!    decomposition: inner-seal, outer-seal, dedup observe, AEAD open,
//!    reassemble. Each criterion sub-bench reports one component.
//!
//! # Codec-agnostic framing
//!
//! All chunks use [`CODEC_MDC`] + [`ChunkLayer::BASE`]. There is no
//! real MDC codec in the bench — the substrate operates on opaque
//! plaintext bytes, and a real codec would feed actual MDC-encoded
//! descriptions through the same [`seal_av_inner`] surface without
//! changing the substrate's wire shape or correctness story.
//!
//! # What this bench does NOT validate
//!
//! - PSNR / SSIM / any quality metric — that's a codec test.
//! - Real network egress — in-process bench.
//! - The MDC codec's bitstream layout — the bench is codec-agnostic.
//!
//! # Setup discipline
//!
//! Bench fixtures (4 [`RelayNode`] instances, deterministic transit
//! keys, the receiver-side [`MultiParentSubscription`] vector) are
//! built OUTSIDE the criterion `iter_*` closure so the timed window
//! only sees the round-trip itself.

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
    clippy::needless_range_loop,
    clippy::similar_names,
    clippy::too_many_lines
)]
#![cfg(feature = "_reticulum-module")]

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use ciris_edge::transport::realtime_av::ReceiverLayerPolicy;
use ciris_edge::transport::realtime_av::{
    open_av_chunk, seal_av_inner, ChunkLayer, ChunkSeq, Epoch, EpochDek, InnerSealed, StreamId,
    CODEC_MDC,
};
use ciris_edge::transport::realtime_av_alm::{
    AlmJoinPlanner, JoinPlan, MultiParentSubscription, ObserveOutcome, ParentCandidate,
    RelayCapacity, SignedRelayCapacity, SubStreamCommitment,
};
use ciris_edge::transport::realtime_av_relay::{PeerKeyId, RelayForwardOut, RelayNode};

use reticulum_core::{DestinationHash, Identity};
use reticulum_std::driver::{ReticulumNode, ReticulumNodeBuilder};

// ─── Frame layout constants (the "8K → 2×4K → 4×2K" narrative) ─────

/// Total frame size in bytes: "8K" in the user narrative = 64 KiB.
const FRAME_BYTES: usize = 64 * 1024;
/// Number of leaf sub-streams at depth 2: 4 (the "4 × 2K" tier).
const NUM_SUBSTREAMS: usize = 4;
/// Per-sub-stream payload: 64 KiB / 4 = 16 KiB.
const SUBSTREAM_BYTES: usize = FRAME_BYTES / NUM_SUBSTREAMS;

/// The 4 dyadic sub-stream paths at depth 2 in canonical order.
/// `[0,0]`, `[0,1]`, `[1,0]`, `[1,1]`.
fn substream_paths() -> [Vec<u8>; NUM_SUBSTREAMS] {
    [vec![0, 0], vec![0, 1], vec![1, 0], vec![1, 1]]
}

// ─── Reticulum-node bench fixture (mirrors realtime_av_relay.rs) ────

fn bench_node() -> Arc<ReticulumNode> {
    let mut priv_bytes = [0u8; 64];
    for (i, b) in priv_bytes.iter_mut().enumerate() {
        *b = u8::try_from(i)
            .expect("index < 64")
            .wrapping_mul(31)
            .wrapping_add(1);
    }
    let identity =
        Identity::from_private_key_bytes(&priv_bytes).expect("build identity from synthetic key");
    let storage = std::env::temp_dir().join(format!(
        "ciris-edge-mesh-e2e-bench-{}",
        uuid::Uuid::new_v4()
    ));
    let node = ReticulumNodeBuilder::new()
        .identity(identity)
        .storage_path(storage)
        .build_sync()
        .expect("build mesh-e2e bench node");
    Arc::new(node)
}

fn bench_address(seed: u8) -> DestinationHash {
    DestinationHash::new([seed; 16])
}

/// Each sub-stream gets its own `StreamId` (production MDC routing
/// treats each sub-stream as an independently routable entity at the
/// substrate tier; the dyadic path is the receiver-side dedup key).
fn substream_stream_id(idx: usize) -> StreamId {
    let mut seed = [0u8; 32];
    seed[0] = 0xE0 ^ (idx as u8);
    seed[1] = 0x55;
    StreamId(seed)
}

fn bench_dek() -> EpochDek {
    EpochDek::from_bytes([0x88u8; 32])
}

/// Deterministic 32-byte transit key per `(relay_idx, parent_idx)`.
fn bench_transit_key(relay_idx: usize, parent_idx: usize) -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, byte) in k.iter_mut().enumerate() {
        let mixed = (relay_idx
            .wrapping_mul(31)
            .wrapping_add(parent_idx.wrapping_mul(7))
            .wrapping_add(i)) as u8;
        *byte = mixed.wrapping_mul(13).wrapping_add(7);
    }
    k
}

/// Receiver `key_id` used as the subscriber id on each relay AND as
/// the `link_id` input to the outer AEAD nonce. The `link_id` thread
/// through `subscribe()` keys the relay's per-(stream, subscriber)
/// outer state; the receiver MUST use the same bytes when opening.
fn receiver_id_for_substream(parent_idx: usize, substream_idx: usize) -> PeerKeyId {
    format!("rx-p{parent_idx:02}-ss{substream_idx:02}")
}

/// Deterministic per-sub-stream payload — distinct prefix per
/// sub-stream so a misaligned reassembly is caught by the equality
/// assertion. The first byte stamps `(0xA0 + substream_idx)` to make
/// any cross-talk visible.
fn make_substream_payload(substream_idx: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(SUBSTREAM_BYTES);
    let tag = 0xA0u8.wrapping_add(substream_idx as u8);
    v.push(tag);
    for i in 1..SUBSTREAM_BYTES {
        v.push(((i.wrapping_add(substream_idx.wrapping_mul(257))) & 0xFF) as u8);
    }
    v
}

/// Concatenated full-frame payload (deterministic, equals the
/// receiver-side reassembly target).
fn make_full_frame() -> Vec<u8> {
    let mut frame = Vec::with_capacity(FRAME_BYTES);
    for i in 0..NUM_SUBSTREAMS {
        frame.extend_from_slice(&make_substream_payload(i));
    }
    debug_assert_eq!(frame.len(), FRAME_BYTES);
    frame
}

// ─── Publisher: inner-seal each sub-stream ──────────────────────────

/// Inner-seal the per-sub-stream payload for one frame. Uses
/// [`CODEC_MDC`] + [`ChunkLayer::BASE`] — the substrate doesn't
/// inspect the codec discriminator beyond stamping it into the wire
/// header, and BASE keeps the chunk admitted by every
/// [`ReceiverLayerPolicy`] (so the substrate test isn't muddied by
/// admission filtering).
fn publisher_inner_seal_substream(
    payload: &[u8],
    dek: &EpochDek,
    stream_id: StreamId,
    chunk_seq: u64,
) -> InnerSealed {
    seal_av_inner(
        payload,
        dek,
        stream_id,
        Epoch(1),
        ChunkSeq(chunk_seq),
        CODEC_MDC,
        ChunkLayer::BASE,
    )
    .expect("inner seal")
}

/// Inner-seal all 4 sub-streams for one frame.
fn publisher_inner_seal_frame(
    substream_payloads: &[Vec<u8>; NUM_SUBSTREAMS],
    dek: &EpochDek,
    chunk_seq: u64,
) -> [InnerSealed; NUM_SUBSTREAMS] {
    let inners: Vec<InnerSealed> = (0..NUM_SUBSTREAMS)
        .map(|i| {
            publisher_inner_seal_substream(
                &substream_payloads[i],
                dek,
                substream_stream_id(i),
                chunk_seq,
            )
        })
        .collect();
    // Convert Vec → fixed array.
    [
        inners[0].clone(),
        inners[1].clone(),
        inners[2].clone(),
        inners[3].clone(),
    ]
}

// ─── Relay fixtures (one RelayNode per sub-stream, per-parent) ──────

/// Build `num_parents` RelayNodes for ONE sub-stream and subscribe
/// the receiver to each one. Returns the populated relays + the
/// per-parent receiver `key_id`s (which double as the `link_id` for
/// outer AEAD nonce derivation).
fn build_substream_relay_tree(
    substream_idx: usize,
    num_parents: usize,
) -> (Vec<RelayNode>, Vec<PeerKeyId>) {
    let stream = substream_stream_id(substream_idx);
    let mut relays = Vec::with_capacity(num_parents);
    let mut receiver_ids = Vec::with_capacity(num_parents);
    for parent_idx in 0..num_parents {
        let mut relay = RelayNode::new(
            bench_node(),
            bench_address((0x10 + substream_idx as u8) ^ (parent_idx as u8)),
        );
        let receiver = receiver_id_for_substream(parent_idx, substream_idx);
        relay
            .subscribe(
                stream,
                receiver.clone(),
                bench_transit_key(substream_idx, parent_idx),
                ReceiverLayerPolicy::UNCAPPED,
            )
            .expect("subscribe");
        relays.push(relay);
        receiver_ids.push(receiver);
    }
    (relays, receiver_ids)
}

/// Build the 4 single-parent relay trees (one tree per sub-stream).
fn build_single_parent_topology() -> (Vec<Vec<RelayNode>>, Vec<Vec<PeerKeyId>>) {
    let mut relay_trees = Vec::with_capacity(NUM_SUBSTREAMS);
    let mut receiver_id_trees = Vec::with_capacity(NUM_SUBSTREAMS);
    for ss in 0..NUM_SUBSTREAMS {
        let (relays, ids) = build_substream_relay_tree(ss, 1);
        relay_trees.push(relays);
        receiver_id_trees.push(ids);
    }
    (relay_trees, receiver_id_trees)
}

/// Build the 4 dual-parent relay trees (2 parents per sub-stream =
/// 8 relays total).
fn build_dual_parent_topology() -> (Vec<Vec<RelayNode>>, Vec<Vec<PeerKeyId>>) {
    let mut relay_trees = Vec::with_capacity(NUM_SUBSTREAMS);
    let mut receiver_id_trees = Vec::with_capacity(NUM_SUBSTREAMS);
    for ss in 0..NUM_SUBSTREAMS {
        let (relays, ids) = build_substream_relay_tree(ss, 2);
        relay_trees.push(relays);
        receiver_id_trees.push(ids);
    }
    (relay_trees, receiver_id_trees)
}

// ─── Receiver fixtures (MultiParentSubscription per sub-stream) ─────

/// Build `NUM_SUBSTREAMS` [`MultiParentSubscription`] instances. The
/// `JoinPlan` references the receiver's per-parent `key_id`s — same
/// bytes the relays were `subscribe()`'d with so `observe_chunk`'s
/// `from_parent` match succeeds.
fn build_subscriptions(receiver_id_trees: &[Vec<PeerKeyId>]) -> Vec<MultiParentSubscription> {
    let paths = substream_paths();
    receiver_id_trees
        .iter()
        .enumerate()
        .map(|(ss, ids)| {
            let primary = ids[0].clone();
            let backups: Vec<PeerKeyId> = ids.iter().skip(1).cloned().collect();
            let plan = JoinPlan {
                primary_parent: primary,
                backup_parents: backups,
                stream_bitrate_mbps: 2.5,
            };
            MultiParentSubscription::new(substream_stream_id(ss), paths[ss].clone(), plan)
        })
        .collect()
}

// ─── Full round-trip (single-parent) — one frame end-to-end ─────────

/// Drive the publisher → relay → receiver round-trip for one frame
/// and return the reassembled bytes.
///
/// `chunk_seq` advances per call so successive iterations don't trip
/// the dedup ring on the same `(epoch, chunk_seq)` key.
///
/// `subscribed_count` is how many of the 4 sub-streams the receiver
/// actively subscribes to (1..=NUM_SUBSTREAMS) — drives the
/// degraded-quality sweep. The publisher still emits all 4 inner
/// seals; the relays for non-subscribed sub-streams just aren't
/// `forward()`'d (mirrors the receiver-side bandwidth saving — the
/// substrate doesn't pay for what the receiver doesn't subscribe to).
fn one_frame_round_trip_single_parent(
    relay_trees: &mut [Vec<RelayNode>],
    subscriptions: &mut [MultiParentSubscription],
    dek: &EpochDek,
    substream_payloads: &[Vec<u8>; NUM_SUBSTREAMS],
    chunk_seq: u64,
    subscribed_count: usize,
    wall_clock_ms: u64,
) -> Vec<u8> {
    // Publisher: 4 inner seals.
    let inners = publisher_inner_seal_frame(substream_payloads, dek, chunk_seq);

    let mut plaintexts: Vec<Vec<u8>> = Vec::with_capacity(subscribed_count);
    for ss in 0..subscribed_count {
        // Relay-side outer-seal for the single parent.
        let stream = substream_stream_id(ss);
        let outs: Vec<RelayForwardOut> = relay_trees[ss][0]
            .forward(stream, &inners[ss])
            .expect("relay forward");
        debug_assert_eq!(outs.len(), 1);
        let RelayForwardOut { subscriber, sealed } = &outs[0];
        // Receiver-side dedup + open.
        let outcome = subscriptions[ss].observe_chunk(
            subscriber,
            sealed.epoch,
            sealed.chunk_seq,
            wall_clock_ms,
        );
        debug_assert_eq!(outcome, ObserveOutcome::FirstDelivery);
        // Open the outer AEAD. `link_id` = subscriber key_id bytes
        // (matches RelayNode's subscribe-time capture); `link_seq` =
        // 0 for the first chunk per (sub-stream, parent), and
        // advances each iter — track it via `chunk_seq` since each
        // iter sends exactly one chunk per parent.
        let plaintext = open_av_chunk(
            sealed,
            &bench_transit_key(ss, 0),
            subscriber.as_bytes(),
            chunk_seq,
            dek,
        )
        .expect("open av chunk");
        plaintexts.push(plaintext);
    }

    // Reassemble.
    let mut reassembled = Vec::with_capacity(subscribed_count * SUBSTREAM_BYTES);
    for p in &plaintexts {
        reassembled.extend_from_slice(p);
    }
    reassembled
}

/// Same round-trip but with 2 parents per sub-stream — each chunk is
/// forwarded by each parent, the receiver observes both copies, and
/// expects exactly one [`ObserveOutcome::FirstDelivery`] + one
/// [`ObserveOutcome::Duplicate`] per sub-stream.
fn one_frame_round_trip_dual_parent(
    relay_trees: &mut [Vec<RelayNode>],
    subscriptions: &mut [MultiParentSubscription],
    dek: &EpochDek,
    substream_payloads: &[Vec<u8>; NUM_SUBSTREAMS],
    chunk_seq: u64,
    wall_clock_ms: u64,
) -> (Vec<u8>, usize, usize) {
    let inners = publisher_inner_seal_frame(substream_payloads, dek, chunk_seq);

    let mut plaintexts: Vec<Vec<u8>> = Vec::with_capacity(NUM_SUBSTREAMS);
    let mut first_deliveries = 0usize;
    let mut duplicates = 0usize;

    for ss in 0..NUM_SUBSTREAMS {
        let stream = substream_stream_id(ss);
        // Both parents forward.
        let outs0: Vec<RelayForwardOut> = relay_trees[ss][0]
            .forward(stream, &inners[ss])
            .expect("relay forward p0");
        let outs1: Vec<RelayForwardOut> = relay_trees[ss][1]
            .forward(stream, &inners[ss])
            .expect("relay forward p1");
        debug_assert_eq!(outs0.len(), 1);
        debug_assert_eq!(outs1.len(), 1);

        // Receiver: observe p0's chunk → FirstDelivery, open + reassemble.
        let f0 = &outs0[0];
        let outcome0 = subscriptions[ss].observe_chunk(
            &f0.subscriber,
            f0.sealed.epoch,
            f0.sealed.chunk_seq,
            wall_clock_ms,
        );
        match outcome0 {
            ObserveOutcome::FirstDelivery => first_deliveries += 1,
            ObserveOutcome::Duplicate => duplicates += 1,
            ObserveOutcome::UnknownParent => panic!("p0 unknown parent — fixture wiring bug"),
        }
        let plaintext = open_av_chunk(
            &f0.sealed,
            &bench_transit_key(ss, 0),
            f0.subscriber.as_bytes(),
            chunk_seq,
            dek,
        )
        .expect("open av chunk p0");
        plaintexts.push(plaintext);

        // Receiver: observe p1's chunk → Duplicate (same (epoch, chunk_seq)).
        let f1 = &outs1[0];
        let outcome1 = subscriptions[ss].observe_chunk(
            &f1.subscriber,
            f1.sealed.epoch,
            f1.sealed.chunk_seq,
            wall_clock_ms,
        );
        match outcome1 {
            ObserveOutcome::FirstDelivery => first_deliveries += 1,
            ObserveOutcome::Duplicate => duplicates += 1,
            ObserveOutcome::UnknownParent => panic!("p1 unknown parent — fixture wiring bug"),
        }
        // (No need to open p1's chunk — already deduplicated; in
        // production the caller would drop the bytes silently.)
        black_box(f1);
    }

    let mut reassembled = Vec::with_capacity(FRAME_BYTES);
    for p in &plaintexts {
        reassembled.extend_from_slice(p);
    }
    (reassembled, first_deliveries, duplicates)
}

// ─── Group 1 — mesh_e2e_round_trip_correctness ──────────────────────

fn bench_round_trip_correctness(c: &mut Criterion) {
    let dek = bench_dek();
    let payloads: [Vec<u8>; NUM_SUBSTREAMS] = [
        make_substream_payload(0),
        make_substream_payload(1),
        make_substream_payload(2),
        make_substream_payload(3),
    ];
    let expected = make_full_frame();

    let mut group = c.benchmark_group("mesh_e2e_round_trip_correctness");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(8))
        .throughput(Throughput::Bytes(FRAME_BYTES as u64));

    group.bench_function("full_64KiB_frame", |b| {
        // Setup outside the timed window — relays + subscriptions
        // built once.
        let (mut relays, receiver_ids) = build_single_parent_topology();
        let mut subs = build_subscriptions(&receiver_ids);
        let mut chunk_seq: u64 = 0;
        let mut wall: u64 = 10_000;
        b.iter(|| {
            let reassembled = one_frame_round_trip_single_parent(
                &mut relays,
                &mut subs,
                &dek,
                &payloads,
                chunk_seq,
                NUM_SUBSTREAMS,
                wall,
            );
            // Correctness assertion — full 64 KiB round-trip.
            debug_assert_eq!(reassembled.len(), FRAME_BYTES);
            debug_assert_eq!(reassembled, expected);
            chunk_seq = chunk_seq.wrapping_add(1);
            wall = wall.wrapping_add(1);
            black_box(reassembled);
        });
    });

    group.finish();
}

// ─── Group 2 — mesh_e2e_multi_parent_dedup ──────────────────────────

fn bench_multi_parent_dedup(c: &mut Criterion) {
    let dek = bench_dek();
    let payloads: [Vec<u8>; NUM_SUBSTREAMS] = [
        make_substream_payload(0),
        make_substream_payload(1),
        make_substream_payload(2),
        make_substream_payload(3),
    ];
    let expected = make_full_frame();

    let mut group = c.benchmark_group("mesh_e2e_multi_parent_dedup");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(8))
        .throughput(Throughput::Bytes(FRAME_BYTES as u64));

    group.bench_function("dual_parent_64KiB_frame", |b| {
        let (mut relays, receiver_ids) = build_dual_parent_topology();
        let mut subs = build_subscriptions(&receiver_ids);
        let mut chunk_seq: u64 = 0;
        let mut wall: u64 = 10_000;
        b.iter(|| {
            let (reassembled, firsts, dups) = one_frame_round_trip_dual_parent(
                &mut relays,
                &mut subs,
                &dek,
                &payloads,
                chunk_seq,
                wall,
            );
            // Per-frame dedup invariant: exactly NUM_SUBSTREAMS first
            // deliveries + NUM_SUBSTREAMS duplicates (one of each per
            // sub-stream).
            debug_assert_eq!(firsts, NUM_SUBSTREAMS);
            debug_assert_eq!(dups, NUM_SUBSTREAMS);
            debug_assert_eq!(reassembled.len(), FRAME_BYTES);
            debug_assert_eq!(reassembled, expected);
            chunk_seq = chunk_seq.wrapping_add(1);
            wall = wall.wrapping_add(1);
            black_box((reassembled, firsts, dups));
        });
    });

    group.finish();
}

// ─── Group 3 — mesh_e2e_degraded_quality ────────────────────────────

fn bench_degraded_quality(c: &mut Criterion) {
    let dek = bench_dek();
    let payloads: [Vec<u8>; NUM_SUBSTREAMS] = [
        make_substream_payload(0),
        make_substream_payload(1),
        make_substream_payload(2),
        make_substream_payload(3),
    ];

    let mut group = c.benchmark_group("mesh_e2e_degraded_quality");
    group
        .sample_size(15)
        .measurement_time(Duration::from_secs(6));

    for subscribed in 1..=NUM_SUBSTREAMS {
        let expected_bytes = subscribed * SUBSTREAM_BYTES;
        group.throughput(Throughput::Bytes(expected_bytes as u64));
        let id = BenchmarkId::new("subscribed_substreams", subscribed);
        group.bench_with_input(id, &subscribed, |b, &subscribed| {
            let (mut relays, receiver_ids) = build_single_parent_topology();
            let mut subs = build_subscriptions(&receiver_ids);
            // Expected prefix = concat of subscribed sub-streams in
            // path order [0,0], [0,1], [1,0], [1,1].
            let mut expected = Vec::with_capacity(expected_bytes);
            for i in 0..subscribed {
                expected.extend_from_slice(&payloads[i]);
            }
            let mut chunk_seq: u64 = 0;
            let mut wall: u64 = 10_000;
            b.iter(|| {
                let reassembled = one_frame_round_trip_single_parent(
                    &mut relays,
                    &mut subs,
                    &dek,
                    &payloads,
                    chunk_seq,
                    subscribed,
                    wall,
                );
                // Proportional-fidelity invariant.
                debug_assert_eq!(reassembled.len(), expected_bytes);
                debug_assert_eq!(reassembled, expected);
                chunk_seq = chunk_seq.wrapping_add(1);
                wall = wall.wrapping_add(1);
                black_box(reassembled);
            });
        });
    }

    group.finish();
}

// ─── Group 4 — mesh_e2e_planner_picks_distinct_parents ──────────────
//
// Build a candidate pool of 10 peers. Peers 1..=4 each commit to ONE
// specific sub-stream path ([0,0], [0,1], [1,0], [1,1] respectively);
// peers 5..=10 are opaque-mode candidates (no sub-stream commitments).
// Per the ALM-B `plan_for_substream` contract, the planner should
// prefer the specialist commitment for each sub-stream path because
// opaque-mode candidates are admitted as fallback (the test asserts
// each plan's primary differs across the 4 paths — i.e. the 4 plans
// return 4 DIFFERENT specialists).
//
// We tune RTT so the per-path specialist has the lowest RTT among any
// candidate that admits that path — gives a deterministic primary.
// The opaque-mode candidates have higher RTT so they only land in the
// backup slot.

fn build_planner_candidate_pool() -> Vec<ParentCandidate> {
    let paths = substream_paths();
    let mut candidates = Vec::with_capacity(10);
    // Peers 1..=4: specialist commitments, low RTT (20ms).
    for (i, path) in paths.iter().enumerate() {
        let commitment = SubStreamCommitment {
            sub_stream_path: path.clone(),
            uplink_budget_mbps: 10.0,
            max_subscribers: 4,
        };
        let capacity = RelayCapacity::with_substream_commitments(
            100.0,
            16,
            64,
            ReceiverLayerPolicy::UNCAPPED,
            1_000,
            vec![commitment],
        );
        let signed = SignedRelayCapacity {
            advertiser_key_id: format!("specialist-{i}"),
            capacity,
            stream_id: substream_stream_id(i),
            epoch: Epoch(1),
            signature_ed25519_base64: String::new(),
            signature_ml_dsa_65_base64: String::new(),
        };
        candidates.push(ParentCandidate {
            signed_capacity: signed,
            reachability_ratio: Some(0.95),
            rtt_ms_estimate: Some(20 + i as u32),
        });
    }
    // Peers 5..=10: opaque-mode candidates, higher RTT (100..150ms).
    for i in 0..6 {
        let capacity = RelayCapacity::new(100.0, 16, 64, ReceiverLayerPolicy::UNCAPPED, 1_000);
        let signed = SignedRelayCapacity {
            advertiser_key_id: format!("opaque-{i}"),
            capacity,
            stream_id: substream_stream_id(0),
            epoch: Epoch(1),
            signature_ed25519_base64: String::new(),
            signature_ml_dsa_65_base64: String::new(),
        };
        candidates.push(ParentCandidate {
            signed_capacity: signed,
            reachability_ratio: Some(0.95),
            rtt_ms_estimate: Some(100 + i as u32),
        });
    }
    candidates
}

fn bench_planner_picks_distinct_parents(c: &mut Criterion) {
    let candidates = build_planner_candidate_pool();
    let paths = substream_paths();

    let mut group = c.benchmark_group("mesh_e2e_planner_picks_distinct_parents");
    group
        .sample_size(50)
        .measurement_time(Duration::from_secs(5));

    // One-shot correctness sanity check before the timed loop: the
    // 4 plans MUST return 4 distinct primaries. If this fails the
    // bench is misconfigured (and the planner needs investigation).
    let primaries: Vec<String> = paths
        .iter()
        .map(|p| {
            AlmJoinPlanner::plan_for_substream(
                &candidates,
                p,
                2.5,
                ReceiverLayerPolicy::UNCAPPED,
                5_000,
            )
            .expect("specialist must be feasible")
            .primary_parent
        })
        .collect();
    let unique: std::collections::HashSet<&String> = primaries.iter().collect();
    assert_eq!(
        unique.len(),
        NUM_SUBSTREAMS,
        "planner failed to pick distinct specialists across sub-streams: {primaries:?}"
    );

    group.bench_function("plan_4_substreams", |b| {
        b.iter(|| {
            for path in &paths {
                let plan = AlmJoinPlanner::plan_for_substream(
                    &candidates,
                    path,
                    2.5,
                    ReceiverLayerPolicy::UNCAPPED,
                    5_000,
                )
                .expect("specialist must be feasible");
                black_box(plan);
            }
        });
    });

    group.finish();
}

// ─── Group 5 — mesh_e2e_full_round_trip_cost_decomposition ──────────
//
// Per-step cost decomposition using criterion's `iter_custom`. Each
// sub-bench runs ONE step of the round-trip per iteration and reports
// its own time. The criterion HTML report then shows the per-component
// breakdown side-by-side.

fn bench_cost_decomposition(c: &mut Criterion) {
    let dek = bench_dek();
    let payloads: [Vec<u8>; NUM_SUBSTREAMS] = [
        make_substream_payload(0),
        make_substream_payload(1),
        make_substream_payload(2),
        make_substream_payload(3),
    ];

    let mut group = c.benchmark_group("mesh_e2e_full_round_trip_cost_decomposition");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(6))
        .throughput(Throughput::Bytes(FRAME_BYTES as u64));

    // (a) Inner-seal step — publisher CPU. 4 inner seals per iter.
    group.bench_function("step_inner_seal_4x", |b| {
        let mut chunk_seq: u64 = 0;
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let inners = publisher_inner_seal_frame(&payloads, &dek, chunk_seq);
                black_box(inners);
                chunk_seq = chunk_seq.wrapping_add(1);
            }
            start.elapsed()
        });
    });

    // (b) Outer-seal step — relay CPU. 4 forward calls per iter (one
    // per sub-stream, single parent).
    group.bench_function("step_outer_seal_4x", |b| {
        let (mut relays, _ids) = build_single_parent_topology();
        let inners = publisher_inner_seal_frame(&payloads, &dek, 0);
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                for ss in 0..NUM_SUBSTREAMS {
                    let stream = substream_stream_id(ss);
                    let outs = relays[ss][0].forward(stream, &inners[ss]).expect("forward");
                    black_box(outs);
                }
            }
            start.elapsed()
        });
    });

    // (c) Dedup observe step — receiver CPU. 4 observe_chunk calls
    // per iter. Each iter uses a fresh (epoch, chunk_seq) so the ring
    // doesn't dedupe.
    group.bench_function("step_dedup_observe_4x", |b| {
        let (_relays, ids) = build_single_parent_topology();
        let mut subs = build_subscriptions(&ids);
        let mut chunk_seq: u64 = 0;
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                for ss in 0..NUM_SUBSTREAMS {
                    let parent = &ids[ss][0];
                    let outcome =
                        subs[ss].observe_chunk(parent, Epoch(1), ChunkSeq(chunk_seq), 10_000);
                    black_box(outcome);
                }
                chunk_seq = chunk_seq.wrapping_add(1);
            }
            start.elapsed()
        });
    });

    // (d) AEAD open step — receiver CPU. Pre-seal 4 chunks; the timed
    // loop only opens them. `link_seq` matches the relay's first
    // forward (= 0).
    group.bench_function("step_aead_open_4x", |b| {
        let (mut relays, ids) = build_single_parent_topology();
        let inners = publisher_inner_seal_frame(&payloads, &dek, 0);
        // Pre-seal a stable set of 4 outer-sealed chunks.
        let sealed_set: Vec<RelayForwardOut> = (0..NUM_SUBSTREAMS)
            .map(|ss| {
                let stream = substream_stream_id(ss);
                relays[ss][0]
                    .forward(stream, &inners[ss])
                    .expect("forward")
                    .pop()
                    .expect("one subscriber")
            })
            .collect();
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                for ss in 0..NUM_SUBSTREAMS {
                    let f = &sealed_set[ss];
                    let plaintext = open_av_chunk(
                        &f.sealed,
                        &bench_transit_key(ss, 0),
                        ids[ss][0].as_bytes(),
                        0,
                        &dek,
                    )
                    .expect("open");
                    black_box(plaintext);
                }
            }
            start.elapsed()
        });
    });

    // (e) Reassemble step — receiver CPU. Concat 4 × 16 KiB → 64 KiB.
    group.bench_function("step_reassemble_4x", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let mut out = Vec::with_capacity(FRAME_BYTES);
                for ss in 0..NUM_SUBSTREAMS {
                    out.extend_from_slice(&payloads[ss]);
                }
                black_box(out);
            }
            start.elapsed()
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_round_trip_correctness,
    bench_multi_parent_dedup,
    bench_degraded_quality,
    bench_planner_picks_distinct_parents,
    bench_cost_decomposition
);
criterion_main!(benches);
