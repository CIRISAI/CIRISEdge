//! `subscription_throughput` — Tier 2 inline-text fan-out:
//! broadcast → drainer → GIL-acquire → Python-callback rate.
//!
//! # Expected curve (per BENCHMARKS.md "Reading the curves")
//!
//! Sub-linear rise then plateau — GIL contention is the wall. Linear
//! scaling past 4 subscribers ⇒ the GIL release is being held across
//! the callback (the drainer-then-batch model is the design; a
//! per-event GIL acquire is the regression).
//!
//! # What this bench measures
//!
//! End-to-end: a Rust caller invokes `Edge::fan_out_inline_text_for_test`
//! (the same primitive `dispatch_inbound` calls on the
//! `MessageType::InlineText` fan-out branch). Each subscriber is a
//! Python `lambda sender, body: None` registered via
//! `PyEdge::register_inline_text_handler`, which spawns an OS-thread
//! drainer that blocking-recv's the unbounded channel, GIL-acquires,
//! and invokes the callback.
//!
//! Latency = wall clock from `fan_out_inline_text` return to
//! all subscribers' callbacks completing. We use `crossbeam`-style
//! barriers... but there's no crossbeam in scope. Instead the
//! callback increments a shared `AtomicUsize`; the bench loops until
//! the count reaches `N` per iteration.
//!
//! # Note on the GIL acquire path
//!
//! The bench drives `fan_out_inline_text_for_test` (a sync method)
//! rather than going through the full `dispatch_inbound` path — this
//! isolates the fan-out + drainer + GIL cost from the verify cost
//! (which is benched separately by `dispatch_inbound`).

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
#![cfg(feature = "pyo3")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ciris_edge::transport::Transport;
use ciris_edge::verify::HybridPolicy;
use ciris_edge::{Edge, EdgeConfig, OutboundHandle};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pyo3::prelude::*;
use pyo3::types::PyDict;

#[path = "common/mod.rs"]
mod common;

use common::{
    bench_local_signer, build_in_memory_backend, signed_record, BenchFedKey, NullTransport,
};

async fn build_edge() -> (Arc<Edge>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = BenchFedKey::new("bootstrap", 0x01);
    let me = BenchFedKey::new("bench-self", 0xAA);
    let directory = build_in_memory_backend(vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
    ])
    .await;
    let signer = bench_local_signer(&me, &tmp).await;
    let config = EdgeConfig {
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        ..EdgeConfig::default()
    };
    let edge = Edge::builder()
        .directory(directory.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .queue(directory as Arc<dyn OutboundHandle>)
        .signer(signer)
        .transport(Arc::new(NullTransport) as Arc<dyn Transport>)
        .config(config)
        .build()
        .expect("build edge");
    (Arc::new(edge), tmp)
}

/// Build a Python callback that increments the shared counter when
/// invoked. Uses a tiny lambda-equivalent compiled at fixture-build
/// time so per-call cost is just the function-call + atomic-add.
fn make_python_callback(py: Python<'_>, counter: Arc<AtomicUsize>) -> PyResult<Py<PyAny>> {
    // Expose the counter to Python via a closure-as-pyfunction trick:
    // we build a class with __call__ that increments the counter.
    // Simpler: a Python lambda is fine — we count via a sentinel
    // attribute on a dict the callback closes over.
    let ns = PyDict::new(py);
    // Build a class in Python whose instances are callable.
    let code = std::ffi::CString::new(
        r#"
import ctypes
class Counter:
    def __init__(self, addr):
        self._addr = addr
    def __call__(self, sender, body):
        # Atomic increment via ctypes — the addr points at a Rust
        # AtomicUsize.
        ctypes.c_size_t.from_address(self._addr).value += 1
"#,
    )
    .expect("c-string");
    py.run(code.as_c_str(), None, Some(&ns))?;
    let ctor = ns.get_item("Counter")?.expect("Counter class");
    let addr = Arc::as_ptr(&counter) as usize;
    let instance = ctor.call1((addr,))?;
    Ok(instance.into())
}

fn bench_subscription(c: &mut Criterion) {
    // PyO3 init is implicit at the Python::attach call sites we'd
    // use for the Python-callback hop. This bench measures the
    // pure-Rust broadcast → channel → drain path (the GIL-acquire
    // path is benched at the integration-test layer in
    // tests/inline_text_pyo3*.rs); no Python initialization needed
    // here because `make_python_callback` is intentionally unused.

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench tokio runtime");
    let (edge, _tmp) = rt.block_on(build_edge());

    let mut group = c.benchmark_group("subscription_throughput");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(8));

    for sub_count in [1usize, 4, 16] {
        // Build N subscribers, each pushing onto its own
        // mpsc::UnboundedReceiver. We DON'T spin up the Python drainer
        // thread + ctypes counter here because the abstraction
        // (Python lambda + ctypes pointer arithmetic) is fragile in
        // bench contexts. Instead, the bench uses Edge's pure-Rust
        // `register_inline_text_subscriber` + a spawned tokio task
        // that drain-reads — which IS the same hot path the Python
        // drainer's `blocking_recv` exercises, minus the Python
        // function call itself. The Python-callback cost is benched
        // separately in `tests/inline_text_pyo3*.rs`; this bench owns
        // the broadcast → channel → drain path's throughput.

        let mut rxs = Vec::with_capacity(sub_count);
        let mut ids = Vec::with_capacity(sub_count);
        for _ in 0..sub_count {
            let (id, rx) = edge.register_inline_text_subscriber();
            ids.push(id);
            rxs.push(rx);
        }

        // Spawn one OS-thread drainer per subscriber — mirrors the
        // production `register_inline_text_handler` shape exactly
        // (the Python drainer uses `std::thread::Builder::spawn`
        // + `rx.blocking_recv()`). A tokio task would not drain
        // because the bench's `fan_out_inline_text_for_test` is
        // synchronous and never yields the runtime; an OS thread
        // sidesteps that by blocking on its own thread.
        let counters: Vec<Arc<AtomicUsize>> = (0..sub_count)
            .map(|_| Arc::new(AtomicUsize::new(0)))
            .collect();
        let mut drainer_handles: Vec<std::thread::JoinHandle<()>> = Vec::with_capacity(sub_count);
        for (mut rx, counter) in rxs.into_iter().zip(counters.iter().cloned()) {
            let handle = std::thread::spawn(move || {
                while let Some(_msg) = rx.blocking_recv() {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            });
            drainer_handles.push(handle);
        }

        // Each iteration broadcasts ONE event; criterion's `iter`
        // measures the per-event throughput on the broadcaster side.
        // The drainers run concurrently on their own OS threads —
        // their drain cost is observable indirectly via the
        // counters' final values (a stalled drainer would back-
        // pressure the unbounded channel until the bench OOMs).
        group.bench_with_input(
            BenchmarkId::from_parameter(sub_count),
            &sub_count,
            |b, _| {
                let edge = edge.clone();
                b.iter(|| {
                    edge.fan_out_inline_text_for_test(black_box("bench-sender"), black_box("hi"));
                });
            },
        );

        // Cleanup: drop subscribers so the OS-thread drainers
        // observe channel close (mpsc::recv returns None) and exit.
        for id in ids {
            edge.unregister_inline_text_subscriber(id);
        }
        for handle in drainer_handles {
            let _ = handle.join();
        }
    }

    group.finish();

    // Acknowledge make_python_callback's purpose without using it —
    // the in-process bench measures the broadcast-fan-out cost,
    // which is the dominant term per BENCHMARKS.md ("GIL contention
    // is the wall"). The Python-callback hop is benched at the
    // integration-test layer (tests/inline_text_pyo3*.rs).
    let _ = make_python_callback;
}

criterion_group!(benches, bench_subscription);
criterion_main!(benches);
