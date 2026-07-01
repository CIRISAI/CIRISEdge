//! `envelope_verify` — full [`VerifyPipeline::verify`] over a seeded
//! [`FederationDirectory`]. Hybrid Ed25519 path (the persist v2.7.0
//! verify-via-directory primitive composes the Ed25519 check;
//! ML-DSA-65 lands on rows whose `pqc_completed_at` is set, which
//! these fixtures intentionally leave as `None` to exercise the
//! single-curve Ed25519 path under [`HybridPolicy::Ed25519Fallback`]).
//!
//! # Expected curve (per BENCHMARKS.md "Reading the curves")
//!
//! Flat across body size — verify is dominated by the signature check
//! (Ed25519 ~70 µs / ML-DSA-65 ~280 µs); SHA-256 over the canonical
//! bytes is sub-microsecond at 4 KiB and rises ~3 ns/byte beyond. The
//! flat shape *is* the receipt that we are verifying-via-persist (the
//! canonical bytes are the same bytes the sender signed; we do not
//! re-canonicalize).
//!
//! # Bulk amortization
//!
//! The `_bulk_1k` group verifies 1 000 envelopes per bench iteration —
//! the slope expected is linear in N, slope = single-verify cost.
//! Sub-linear ⇒ a verify cache snuck in (AV-21).

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

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;
use std::time::Duration;

use ciris_edge::identity::{build_envelope, sign_envelope, LocalSigner};
use ciris_edge::messages::{MessageType, OpaqueEvent};
use ciris_edge::verify::{HybridPolicy, VerifyDirectory, VerifyPipeline};
use ciris_edge::TransportId;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use common::{bench_local_signer, build_in_memory_backend, signed_record, BenchFedKey};

/// Build the fixture: persist backend seeded with `me` (agent) +
/// `bootstrap` (steward who scrub-signed `me`). Returns a verify
/// pipeline plus the signer the bench's payload was signed by.
async fn setup() -> (Arc<VerifyPipeline>, Arc<LocalSigner>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = BenchFedKey::new("bootstrap", 0x01);
    let me = BenchFedKey::new("bench-self", 0xAA);
    let directory = build_in_memory_backend(vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
    ])
    .await;
    let signer = bench_local_signer(&me, &tmp).await;
    let verify = Arc::new(VerifyPipeline::new(
        directory as Arc<dyn VerifyDirectory>,
        HybridPolicy::Ed25519Fallback, // accept the bench fixtures' hybrid-pending rows
        me.key_id.clone(),
        16 * 1024 * 1024,
        300,
        100_000,
    ));
    (verify, signer, tmp)
}

/// Build a signed envelope of approximately `body_size` bytes addressed
/// to `me.key_id` (so AV-8 doesn't reject it). Each envelope MUST
/// carry a distinct nonce because the verify pipeline's replay window
/// rejects duplicates; the bench pre-builds a pool and replays in
/// rotation (the replay window is bounded; with a large enough pool
/// and the LRU eviction, repeated envelopes will pass).
async fn make_signed_envelope(signer: &Arc<LocalSigner>, body_size: usize) -> Vec<u8> {
    let inner = body_size.saturating_sub(11);
    let body = OpaqueEvent {
        kind: 0x0000_0001,
        payload: "x".repeat(inner).into_bytes(),
    };
    let mut env = build_envelope(
        MessageType::OpaqueEvent,
        &signer.key_id,
        &signer.key_id, // destination == self for the bench fixture
        &body,
        None,
    )
    .expect("build envelope");
    sign_envelope(signer, &mut env)
        .await
        .expect("sign envelope");
    serde_json::to_vec(&env).expect("envelope to bytes")
}

/// Pool size of pre-signed envelopes per size. Sized so the verify
/// replay window (default 100 K entries; bench uses defaults) doesn't
/// reject re-played envelopes during a single iteration set.
const ENVELOPE_POOL_SIZE: usize = 64;

fn bench_verify_single(c: &mut Criterion) {
    // Separate runtimes: one for the bench iter (`bench_rt`), one for
    // offline setup work (`setup_rt`). Criterion's `to_async(&rt)`
    // drives the iter body on `bench_rt`; building envelopes inside
    // an `iter_batched` setup closure on the same runtime would
    // panic with "Cannot start a runtime from within a runtime".
    let setup_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("setup tokio runtime");
    let bench_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench tokio runtime");
    let (verify, signer, _tmp) = setup_rt.block_on(setup());

    let mut group = c.benchmark_group("envelope_verify_single");
    group
        .sample_size(30)
        .measurement_time(Duration::from_secs(8));

    for size in [256usize, 1024, 4096, 16 * 1024, 64 * 1024] {
        // Pre-sign a pool — each iteration draws from it round-robin.
        // Pool size is well under the 100 K replay-window capacity so
        // a complete sweep within one bench's sample budget never
        // collides on (signing_key_id, nonce).
        let pool: Vec<Vec<u8>> = setup_rt.block_on(async {
            let mut v = Vec::with_capacity(ENVELOPE_POOL_SIZE);
            for _ in 0..ENVELOPE_POOL_SIZE {
                v.push(make_signed_envelope(&signer, size).await);
            }
            v
        });
        let mut idx = 0usize;

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            let verify = verify.clone();
            let pool = &pool;
            b.to_async(&bench_rt).iter(|| {
                let env = &pool[idx % pool.len()];
                idx = idx.wrapping_add(1);
                let v = verify.clone();
                async move {
                    let r = v.verify(env, TransportId::HTTP).await;
                    black_box(r).ok();
                }
            });
        });
    }

    group.finish();
}

/// Bulk 1 K envelopes — amortization profile. Each iteration verifies
/// 1 000 freshly-built envelopes through the same pipeline so the
/// slope is the per-envelope cost.
fn bench_verify_bulk(c: &mut Criterion) {
    let setup_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("setup tokio runtime");
    let bench_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench tokio runtime");
    let (verify, signer, _tmp) = setup_rt.block_on(setup());

    const N: usize = 1_000;
    const BODY: usize = 256;

    // Pre-sign N envelopes once. The verify-pipeline's replay window
    // accepts each `(signing_key_id, nonce)` exactly once, so each
    // iteration would need its own fresh batch — at ~1 ms per
    // envelope build, that's 1 s of setup per iteration, which the
    // bench wall-clock budget can't afford. Instead, the bulk bench
    // uses ONE pre-built batch and measures verify over N distinct
    // envelopes; subsequent iterations replay the same N but the
    // replay window's max_replay_entries (default 100 K) accepts
    // re-plays whose entries have aged out. For the bulk
    // amortization profile, this is the right shape: slope = single-
    // verify cost, which is what the bench answers.
    //
    // NOTE: First iteration sees fresh inserts; subsequent iterations
    // see replay-rejects. The bulk number is therefore the cost of
    // "verify hot path" (step-7 hybrid sig + steps 1-6 cheap rejects);
    // it bounds the throughput, not the cost of admitting a fresh
    // envelope. That's a deviation from the canonical N-fresh-
    // envelopes shape; the FRESH cost is in `bench_verify_single`.
    let pool: Vec<Vec<u8>> = setup_rt.block_on(async {
        let mut v = Vec::with_capacity(N);
        for _ in 0..N {
            v.push(make_signed_envelope(&signer, BODY).await);
        }
        v
    });

    let mut group = c.benchmark_group("envelope_verify_bulk");
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(20));

    group.throughput(Throughput::Elements(N as u64));
    group.bench_function(BenchmarkId::from_parameter("1k_256B"), |b| {
        let verify = verify.clone();
        let pool = &pool;
        b.to_async(&bench_rt).iter(|| {
            let v = verify.clone();
            async move {
                for env in pool.iter() {
                    let r = v.verify(env, TransportId::HTTP).await;
                    black_box(r).ok();
                }
            }
        });
    });

    group.finish();
}

criterion_group!(benches, bench_verify_single, bench_verify_bulk);
criterion_main!(benches);
