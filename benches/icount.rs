//! `icount` — DETERMINISTIC instruction-count benchmarks (iai-callgrind /
//! Valgrind Callgrind) for edge's hot, pure-compute paths.
//!
//! # Why this exists (CIRISEdge#461)
//!
//! The wall-clock criterion lane (`.github/workflows/bench.yml`) is normalized
//! against a calibration anchor, but shared GitHub runners are noisy enough that
//! even same-runner A/B produces false signals (a same-binary comparison drew a
//! spurious −28% "improvement" from transient load). Wall-time on shared CI
//! cannot be made a *real* regression gate.
//!
//! Callgrind counts the exact instructions a run executes — it SIMULATES the CPU,
//! so the number is identical on every runner regardless of load or SKU. A change
//! here is therefore a REAL code change, never runner noise: this is the precise,
//! actionable regression gate. It complements (does not replace) the wall-clock
//! trend lane, which still catches memory-bandwidth / cache effects instruction
//! counts miss.
//!
//! Scope: `canonicalize_envelope_for_signing` — the signing-preimage hot path and
//! the AV-5 "canonicalization re-serialized the body" trap (CIRISPersist#7). Pure,
//! synchronous, allocation-bounded → a perfect instruction-count subject. Async /
//! directory-I/O paths (verify pipeline) are deliberately left on the wall-clock
//! lane.

#![allow(clippy::pedantic, clippy::missing_panics_doc)]

use std::hint::black_box;

use chrono::{DateTime, Utc};
use ciris_edge::messages::{EdgeEnvelope, MessageType, SchemaVersion};
use ciris_persist::prelude::canonicalize_envelope_for_signing;
use iai_callgrind::{
    library_benchmark, library_benchmark_group, main, Callgrind, EventKind, LibraryBenchmarkConfig,
};
use serde_json::value::to_raw_value;

/// A FIXED timestamp — no `Utc::now()`: this bench must be byte-for-byte
/// deterministic so the instruction count is stable across runs (a wall-clock
/// bench doesn't care; an instruction-count bench does). The timestamp value
/// doesn't change the canonicalizer's instruction count anyway (RFC3339 is
/// fixed-width), but a fixed input keeps the whole fixture reproducible.
fn fixed_ts() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("fixed ts")
        .with_timezone(&Utc)
}

/// Build an `EdgeEnvelope` whose body is `{"text": "<filler>"}` of approximately
/// `body_size` bytes — mirrors `benches/envelope_canonicalize.rs::make_envelope`
/// (the canonicalizer keys only on the body's bytes, not its semantics). Runs as
/// iai-callgrind `setup` (UNCOUNTED — only the benched call below is measured).
fn make_envelope(body_size: usize) -> EdgeEnvelope {
    let inner_size = body_size.saturating_sub(11);
    let payload = "x".repeat(inner_size);
    let body_value = serde_json::json!({ "text": payload });
    let body = to_raw_value(&body_value).expect("raw value");

    EdgeEnvelope {
        edge_schema_version: SchemaVersion::V2_0_0,
        signing_key_id: "bench-sender".into(),
        destination_key_id: "bench-receiver".into(),
        message_type: MessageType::OpaqueEvent,
        sent_at: fixed_ts(),
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

// Setup: build the envelope AND serialize it to the `serde_json::Value` the
// canonicalizer consumes — both UNCOUNTED, exactly as `benches/
// envelope_canonicalize.rs` keeps `to_value` outside its `b.iter`, so the two
// lanes measure the identical span (canonicalization only, not serialization).
fn make_envelope_value(body_size: usize) -> serde_json::Value {
    serde_json::to_value(make_envelope(body_size)).expect("envelope to_value")
}

// The measured hot path: canonicalize the signing preimage. Callgrind counts only
// the instructions of this body.
// NB: `#[library_benchmark]` rejects `///` doc attributes on the target fn — keep
// this a plain `//` comment.
#[library_benchmark]
#[bench::b256(args = (256,), setup = make_envelope_value)]
#[bench::b4096(args = (4096,), setup = make_envelope_value)]
#[bench::b16384(args = (16384,), setup = make_envelope_value)]
fn canonicalize(ev: serde_json::Value) -> Vec<u8> {
    canonicalize_envelope_for_signing(black_box(&ev)).expect("canonicalize")
}

library_benchmark_group!(name = canon; benchmarks = canonicalize);

// The GATE: fail the bench if instruction reads (EventKind::Ir) regress >5%
// versus the saved baseline (CI restores the previous run's target/iai). 5% is
// generously above Callgrind's own run-to-run jitter (near-zero — it SIMULATES
// the CPU) while still catching a real algorithmic regression. Because the metric
// is deterministic, a failure here is ALWAYS a real code change, never runner
// noise — which is the whole point of CIRISEdge#461. On the first run (no
// baseline) it establishes one and passes.
main!(
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::default().soft_limits([(EventKind::Ir, 5_f64)]));
    library_benchmark_groups = canon
);
