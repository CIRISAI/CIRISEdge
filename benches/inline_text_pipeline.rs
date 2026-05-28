//! `inline_text_pipeline` — Classify + Scrub on outbound text via
//! persist's `default_outbound_pipeline::<InlineTextEnvelope>` (the
//! two-stage variant; EncryptAndStore needs a SecretsService impl
//! which is application-tier, not edge's surface).
//!
//! # Expected curve (per BENCHMARKS.md "Reading the curves")
//!
//! Linear in text length (Classify scans, Scrub regex-walks; AES-GCM
//! encrypts when the full speak_pipeline runs). Flat ⇒ a transit-touch
//! step skipped silently — mission violation (cleartext crosses the
//! wire).
//!
//! # Stages covered
//!
//! The bench composes Classify + Scrub directly via persist's pipeline
//! surface — this is the substring of `default_speak_pipeline` that
//! does NOT require a SecretsService implementation. The
//! EncryptAndStore stage's cost is dominated by AES-GCM which is
//! benched as part of `ciris-crypto`'s own bench suite (the
//! federation-crypto bench in CIRISVerify); the linear scan + scrub
//! is what edge owns.
//!
//! # Text-length sweep
//!
//! BENCHMARKS.md proposes 64 B / 256 B / 1 KiB / 4 KiB. The fixture
//! uses an email-bearing template so the Classify stage actually has
//! a detection to make (otherwise the curve degenerates to flat —
//! and a flat curve is the bug-shape we're checking for, so we MUST
//! exercise the loaded code path).

#![allow(clippy::pedantic, clippy::needless_pass_by_value, clippy::missing_errors_doc, clippy::missing_panics_doc, clippy::cast_possible_truncation, clippy::cast_lossless, clippy::cast_sign_loss, clippy::cast_possible_wrap, clippy::items_after_statements, clippy::used_underscore_binding, clippy::field_reassign_with_default, clippy::needless_raw_string_hashes)]

use std::time::Duration;

use ciris_persist::pipeline::{default_outbound_pipeline, PipelineState};
use ciris_persist::prelude::InlineTextEnvelope;
use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};

/// Build a text body of approximately `size` bytes containing one
/// scrubbable email address (so Classify reports a finding and Scrub
/// does in-place replacement).
fn template_text(size: usize) -> String {
    let needle = "Reach me at alice@example.com about the matter.";
    let needle_len = needle.len();
    if size <= needle_len {
        return needle[..size.min(needle_len)].to_string();
    }
    let pad = "x".repeat(size - needle_len);
    format!("{needle}{pad}")
}

fn bench_pipeline(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench tokio runtime");
    let pipeline = default_outbound_pipeline::<InlineTextEnvelope>();

    let mut group = c.benchmark_group("inline_text_pipeline");
    group.sample_size(30).measurement_time(Duration::from_secs(8));

    for size in [64usize, 256, 1024, 4096] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.to_async(&rt).iter_batched(
                || InlineTextEnvelope::new(template_text(size)),
                |mut env| {
                    let pipeline = &pipeline;
                    async move {
                        let mut state = PipelineState::default();
                        let r = pipeline.run(black_box(&mut env), &mut state).await;
                        black_box(r).ok();
                        black_box(env);
                    }
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_pipeline);
criterion_main!(benches);
