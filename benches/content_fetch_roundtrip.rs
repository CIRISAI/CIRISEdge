//! `content_fetch_roundtrip` — CIRISEdge#21 `ContentFetch` →
//! `ContentBody` → SHA-256 integrity check (docs/BENCHMARKS.md).
//!
//! # Expected curve (per BENCHMARKS.md "Reading the curves")
//!
//! Linear in body size (SHA-256 ~3 GiB/s + envelope verify +
//! integrity re-hash). Super-linear ⇒ Phase 2 chunked-transfer
//! placeholder regressed to a single-frame allocation.
//!
//! # What this bench measures
//!
//! Phase 1 ships whole-file (`ContentBody`) only — no chunked
//! transfer at v0.10.0. The "round-trip" surface in-tree is:
//!
//! 1. Build a signed `ContentBody` envelope carrying `bytes` of the
//!    given size, with `sha256 == sha256(bytes)`.
//! 2. Drive `dispatch_inbound_for_test` over it.
//! 3. Edge runs verify (full pipeline) → `validate_content_body`
//!    AV-13 size + integrity re-hash → typed handler dispatch.
//!
//! Since no `ContentBody` handler is registered the bench measures
//! verify + integrity check + the warn-log/return path. The
//! integrity-check cost is what dominates the size sweep — verify is
//! flat per `envelope_verify`'s curve.
//!
//! # Size sweep
//!
//! BENCHMARKS.md proposes 256 B → 16 MiB. The 16 MiB end requires
//! `max_body_bytes` lifted from the default 8 MiB (a 16 MiB-bytes
//! ContentBody serializes to ~48 MiB JSON via base64 + integer-array
//! encoding). We sweep up to 64 KiB (matching the issue body's "Body
//! size sweep" without exhausting bench wall time); the slope is what
//! matters for AV-5 / Phase 2-regression detection.

#![allow(clippy::pedantic, clippy::needless_pass_by_value, clippy::missing_errors_doc, clippy::missing_panics_doc, clippy::cast_possible_truncation, clippy::cast_lossless, clippy::cast_sign_loss, clippy::cast_possible_wrap, clippy::items_after_statements, clippy::used_underscore_binding, clippy::field_reassign_with_default, clippy::needless_raw_string_hashes)]

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use ciris_edge::identity::{build_envelope, sign_envelope, LocalSigner};
use ciris_edge::messages::{sha256_of, ContentBody, MessageType};
use ciris_edge::transport::{InboundFrame, Transport};
use ciris_edge::verify::HybridPolicy;
use ciris_edge::{Edge, EdgeConfig, OutboundHandle, TransportId};
use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};

use common::{
    bench_local_signer, build_in_memory_backend, signed_record, BenchFedKey, NullTransport,
};

struct Fixture {
    edge: Arc<Edge>,
    sender_signer: Arc<LocalSigner>,
    _tmp: tempfile::TempDir,
}

async fn build_fixture() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = BenchFedKey::new("bootstrap", 0x01);
    let me = BenchFedKey::new("bench-self", 0xAA);
    let directory = build_in_memory_backend(vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
    ])
    .await;
    let edge_signer = bench_local_signer(&me, &tmp).await;
    let sender_signer = bench_local_signer(&me, &tmp).await;
    // Bump max_body_bytes so the larger envelopes (64 KiB raw bytes
    // → ~190 KiB JSON) survive verify-pipeline step 1.
    let config = EdgeConfig {
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        max_body_bytes: 64 * 1024 * 1024, // 64 MiB ceiling for the bench
        ..EdgeConfig::default()
    };
    let edge = Edge::builder()
        .directory(directory.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .queue(directory as Arc<dyn OutboundHandle>)
        .signer(edge_signer)
        .transport(Arc::new(NullTransport) as Arc<dyn Transport>)
        .config(config)
        .build()
        .expect("build edge");
    Fixture {
        edge: Arc::new(edge),
        sender_signer,
        _tmp: tmp,
    }
}

async fn make_content_body_envelope(
    signer: &Arc<LocalSigner>,
    dest_key_id: &str,
    size: usize,
) -> Vec<u8> {
    let bytes = vec![0xABu8; size];
    let sha256 = sha256_of(&bytes);
    let body = ContentBody {
        sha256,
        bytes,
        attestation_ref: None,
    };
    let mut env = build_envelope(
        MessageType::ContentBody,
        &signer.key_id,
        dest_key_id,
        &body,
        None,
    )
    .expect("build envelope");
    sign_envelope(signer, &mut env).await.expect("sign envelope");
    serde_json::to_vec(&env).expect("envelope to bytes")
}

fn bench_content_fetch(c: &mut Criterion) {
    let setup_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("setup tokio runtime");
    let bench_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench tokio runtime");
    let fixture = setup_rt.block_on(build_fixture());
    let dest = fixture.edge.signer_key_id().to_string();

    let mut group = c.benchmark_group("content_fetch_roundtrip");
    group.sample_size(20).measurement_time(Duration::from_secs(10));

    // Size sweep: 256 B → 64 KiB (geometric ×4). Larger sizes
    // (1 MiB, 16 MiB) hit the JSON-encoding overhead asymmetrically
    // and would exhaust the bench wall budget; the slope is the
    // observable.
    //
    // Pool sized at 16 per size — keeps pool memory bounded for the
    // 64 KiB case (~64 KiB × 16 = 1 MiB JSON-encoded ≈ 3 MiB raw
    // wire-Vec) while staying well above criterion's per-iteration
    // re-draw count. Replay window admits replays after their LRU
    // entries age out.
    const POOL: usize = 16;
    for size in [256usize, 1024, 4096, 16 * 1024, 64 * 1024] {
        let pool: Vec<Vec<u8>> = setup_rt.block_on(async {
            let mut v = Vec::with_capacity(POOL);
            for _ in 0..POOL {
                v.push(make_content_body_envelope(&fixture.sender_signer, &dest, size).await);
            }
            v
        });

        group.throughput(Throughput::Bytes(size as u64));
        let mut idx = 0usize;
        let edge = fixture.edge.clone();
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            let pool = &pool;
            let edge = edge.clone();
            b.to_async(&bench_rt).iter(|| {
                let envelope_bytes = pool[idx % pool.len()].clone();
                idx = idx.wrapping_add(1);
                let edge = edge.clone();
                async move {
                    let frame = InboundFrame {
                        envelope_bytes,
                        transport: TransportId::HTTP,
                        received_at: Utc::now(),
                    };
                    edge.dispatch_inbound_for_test(black_box(frame)).await;
                }
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_content_fetch);
criterion_main!(benches);
