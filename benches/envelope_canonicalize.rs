//! `envelope_canonicalize` — `ciris_persist::canonicalize_envelope_for_signing`
//! over a typed [`EdgeEnvelope`] body, swept geometrically across body
//! size (docs/BENCHMARKS.md).
//!
//! # Expected curve (per BENCHMARKS.md "Reading the curves")
//!
//! Linear in body size — the canonicalizer writes `RawValue` bytes
//! verbatim plus a fixed-size domain-separated frame. Non-linear ⇒
//! canonicalization started re-serializing the body (AV-5 regression,
//! CIRISPersist#7 trap).

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

use chrono::Utc;
use ciris_edge::messages::{EdgeEnvelope, MessageType, SchemaVersion};
use ciris_persist::prelude::canonicalize_envelope_for_signing;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use serde_json::value::to_raw_value;

/// Build an `EdgeEnvelope` whose body is a JSON `{"text": "<filler>"}`
/// of approximately the requested byte size. Wraps the same shape the
/// `InlineText` wire body uses; the canonicalizer doesn't care about
/// the body's semantic — only its bytes — so a single fixture covers
/// every `MessageType` body that lands at the same approximate size.
fn make_envelope(body_size: usize) -> EdgeEnvelope {
    // Account for the surrounding {"text":""} = 11 bytes.
    let inner_size = body_size.saturating_sub(11);
    let payload = "x".repeat(inner_size);
    let body_value = serde_json::json!({ "text": payload });
    let body = to_raw_value(&body_value).expect("raw value");

    EdgeEnvelope {
        edge_schema_version: SchemaVersion::V2_0_0,
        signing_key_id: "bench-sender".into(),
        destination_key_id: "bench-receiver".into(),
        message_type: MessageType::OpaqueEvent,
        sent_at: Utc::now(),
        nonce: [0x42u8; 16],
        body,
        signature: String::new(),
        signature_pqc: None,
        in_reply_to: None,
        testimonial_witness: None,
        key_boundary_scope: None,
        cohort_scope: None,
    }
}

fn bench_canonicalize(c: &mut Criterion) {
    let mut group = c.benchmark_group("envelope_canonicalize");

    // Size sweep: 256 B → 64 KiB geometric ×4 per docs/BENCHMARKS.md
    // (the canonical-curve test for AV-5: linear-in-body-size).
    for size in [256usize, 1024, 4096, 16 * 1024, 64 * 1024] {
        let envelope = make_envelope(size);
        let envelope_value = serde_json::to_value(&envelope).expect("envelope to_value");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &envelope_value,
            |b, ev| {
                b.iter(|| {
                    let bytes =
                        canonicalize_envelope_for_signing(black_box(ev)).expect("canonicalize");
                    black_box(bytes);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_canonicalize);
criterion_main!(benches);
