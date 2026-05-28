//! `steward_fanout` — CIRISEdge#20 [`Edge::send_federation`]
//! enumeration + per-recipient enqueue. Sweeps steward set size.
//!
//! # Expected curve (per BENCHMARKS.md "Reading the curves")
//!
//! Linear in N — one enqueue per steward. Super-linear ⇒ enqueue is
//! iterating directory per-recipient instead of once.
//!
//! # Sweep
//!
//! BENCHMARKS.md proposes N ∈ {1, 4, 16, 64}; the issue body listed
//! {1, 3, 10, 30}. We follow BENCHMARKS.md (the doc-of-record).

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

use async_trait::async_trait;
use ciris_edge::messages::StewardDirective;
use ciris_edge::outbound::{StewardDirectory, StewardKey};
use ciris_edge::transport::Transport;
use ciris_edge::verify::HybridPolicy;
use ciris_edge::{Edge, EdgeConfig, OutboundHandle};
use ciris_persist::outbound::Error as PersistOutboundError;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use common::{
    bench_local_signer, build_in_memory_backend, signed_record, BenchFedKey, NullTransport,
};

/// Static steward directory — predefined `Vec<StewardKey>` so the
/// fan-out cost is on the enqueue path, not the directory enumeration.
/// Mirrors `tests/steward_topology.rs::StaticStewardDirectory`.
struct StaticStewardDirectory(Vec<StewardKey>);

#[async_trait]
impl StewardDirectory for StaticStewardDirectory {
    async fn current_stewards(&self) -> Result<Vec<StewardKey>, PersistOutboundError> {
        Ok(self.0.clone())
    }
}

async fn build_edge_with_n_stewards(n: usize) -> (Arc<Edge>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = BenchFedKey::new("bootstrap", 0x01);
    let me = BenchFedKey::new("bench-self", 0xAA);
    let mut rows = vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
    ];
    let mut stewards = Vec::with_capacity(n);
    for i in 0..n {
        // Stewards must also exist in the directory for the FK to
        // resolve on enqueue (V007 SQLite schema for edge_outbound_queue).
        let k = BenchFedKey::new(
            &format!("steward-{i:02}"),
            0xB0u8.wrapping_add((i % 60) as u8),
        );
        rows.push(signed_record(&k, &bootstrap, "steward"));
        stewards.push(StewardKey {
            key_id: k.key_id.clone(),
            identity_ref: k.key_id,
        });
    }
    let directory = build_in_memory_backend(rows).await;
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
        .steward_directory(Arc::new(StaticStewardDirectory(stewards)))
        .config(config)
        .build()
        .expect("build edge");
    (Arc::new(edge), tmp)
}

fn bench_fanout(c: &mut Criterion) {
    let setup_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("setup tokio runtime");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench tokio runtime");

    let mut group = c.benchmark_group("steward_fanout");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(10));

    for n in [1usize, 4, 16, 64] {
        let (edge, _tmp) = setup_rt.block_on(build_edge_with_n_stewards(n));
        // Hold _tmp via Box::leak so seed dir lives for the bench
        // (the bench closure outlives the tuple scope otherwise).
        Box::leak(Box::new(_tmp));

        let edge_arc = edge.clone();
        group.bench_with_input(BenchmarkId::from_parameter(n), &edge_arc, |b, edge| {
            let edge = edge.clone();
            b.to_async(&rt).iter(|| {
                let edge = edge.clone();
                async move {
                    let msg = StewardDirective {
                        title: "bench directive".into(),
                        body: "bench body".into(),
                    };
                    let r = edge.send_federation(msg, None).await;
                    black_box(r).ok();
                }
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_fanout);
criterion_main!(benches);
