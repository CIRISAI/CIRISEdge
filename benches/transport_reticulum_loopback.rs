//! `transport_reticulum_loopback` — round-trip over Leviculum
//! LocalInterface-equivalent (loopback TCP). Wall-clock per envelope.
//!
//! # Expected curve (per BENCHMARKS.md "Reading the curves")
//!
//! Step at MDU (~470 B) where Resources kick in, then linear. Flat
//! after the MDU step ⇒ resource reassembly is short-circuiting;
//! below-MDU rise ⇒ packet-layer regressed.
//!
//! # Bench shape
//!
//! `tests/reticulum_loopback.rs` shows the canonical setup — two
//! `ReticulumTransport` instances over loopback TCP, B dials A, B
//! roots A's announce attestation, then B sends envelopes to A. The
//! ~30 s cold-start discovery cost is paid ONCE at fixture build
//! (outside the bench loop); each criterion iteration measures the
//! steady-state per-envelope `send` → inbound frame on A.
//!
//! # Size sweep
//!
//! 256 B → 64 KiB geometric ×4 per BENCHMARKS.md. The MDU step
//! is somewhere between 256 B and 1 KiB; the curve should show it.

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
#![cfg(feature = "transport-reticulum")]

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use ciris_edge::identity::LocalSigner;
use ciris_edge::messages::{EdgeEnvelope, MessageType, SchemaVersion};
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport};
use ciris_edge::verify::RootingDirectory;
use ciris_edge::HybridPolicy;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use serde_json::value::RawValue;
use tokio::sync::{mpsc, Mutex};

use common::{build_in_memory_backend, signed_record, BenchFedKey};

async fn signer_for(key: &BenchFedKey, base: &std::path::Path) -> Arc<LocalSigner> {
    let seed_dir = key.write_seed_dir(base);
    let (classical, _pqc) = ciris_keyring::load_local_seed(ciris_keyring::LocalSeedConfig {
        key_id: key.key_id.clone(),
        key_path: seed_dir.join("ed25519.seed"),
        pqc_key_id: None,
        pqc_key_path: None,
    })
    .await
    .expect("load_local_seed");
    Arc::new(LocalSigner {
        key_id: key.key_id.clone(),
        classical,
        pqc: None,
    })
}

async fn auth_for(
    key: &BenchFedKey,
    directory: Arc<ciris_persist::store::sqlite::SqliteBackend>,
    base: &std::path::Path,
) -> ReticulumAuth {
    ReticulumAuth {
        signer: Some(signer_for(key, base).await),
        rooting: Some(directory as Arc<dyn RootingDirectory>),
        resolver: None,
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        ..ReticulumAuth::default()
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

async fn wait_for<F, Fut>(timeout: Duration, mut cond: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if cond().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

struct LoopbackFixture {
    transport_b: Arc<ReticulumTransport>,
    rx_a: Arc<Mutex<mpsc::Receiver<InboundFrame>>>,
    _listen_a: tokio::task::JoinHandle<()>,
    _listen_b: tokio::task::JoinHandle<()>,
    _tmp: tempfile::TempDir,
}

async fn build_loopback() -> LoopbackFixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let steward = BenchFedKey::new("steward-loopback", 0x01);
    let key_a = BenchFedKey::new("edge-key-aaaa", 0x0a);
    let key_b = BenchFedKey::new("edge-key-bbbb", 0x0b);
    let directory = build_in_memory_backend(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&key_a, &steward, "agent"),
        signed_record(&key_b, &steward, "agent"),
    ])
    .await;

    let port_a = free_port();
    let cfg_a = {
        let mut c =
            ReticulumTransportConfig::new(tmp.path().join("a/transport.id"), "edge-key-aaaa");
        c.listen_addr = format!("127.0.0.1:{port_a}").parse().unwrap();
        c.announce_interval = Duration::from_secs(2);
        c
    };
    let cfg_b = {
        let mut c =
            ReticulumTransportConfig::new(tmp.path().join("b/transport.id"), "edge-key-bbbb");
        c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        c.bootstrap_peers = vec![format!("127.0.0.1:{port_a}").parse().unwrap()];
        c.announce_interval = Duration::from_secs(2);
        c
    };

    let auth_a = auth_for(&key_a, directory.clone(), tmp.path()).await;
    let auth_b = auth_for(&key_b, directory.clone(), tmp.path()).await;

    let transport_a = Arc::new(
        ReticulumTransport::new(cfg_a, auth_a)
            .await
            .expect("build transport A"),
    );
    let transport_b = Arc::new(
        ReticulumTransport::new(cfg_b, auth_b)
            .await
            .expect("build transport B"),
    );

    let (tx_a, rx_a) = mpsc::channel::<InboundFrame>(256);
    let (tx_b, _rx_b) = mpsc::channel::<InboundFrame>(16);

    let la = transport_a.clone();
    let lb = transport_b.clone();
    let listen_a = tokio::spawn(async move {
        let _ = la.listen(tx_a).await;
    });
    let listen_b = tokio::spawn(async move {
        let _ = lb.listen(tx_b).await;
    });

    // Wait for B to root A.
    let discovered = wait_for(Duration::from_secs(60), || {
        let t = transport_b.clone();
        async move { t.knows_peer("edge-key-aaaa").await }
    })
    .await;
    assert!(
        discovered,
        "node B did not root node A's announce attestation within 60s",
    );

    LoopbackFixture {
        transport_b,
        rx_a: Arc::new(Mutex::new(rx_a)),
        _listen_a: listen_a,
        _listen_b: listen_b,
        _tmp: tmp,
    }
}

fn sample_envelope(body_size: usize) -> Vec<u8> {
    let payload = "x".repeat(body_size.saturating_sub(32));
    let body_json = format!(r#"{{"text":"{payload}"}}"#);
    let body = RawValue::from_string(body_json).expect("raw value");
    let env = EdgeEnvelope {
        edge_schema_version: SchemaVersion::V1_0_0,
        signing_key_id: "edge-key-bbbb".into(),
        destination_key_id: "edge-key-aaaa".into(),
        message_type: MessageType::InlineText,
        sent_at: Utc::now(),
        nonce: [0x5a; 16],
        body,
        signature: "ZmFrZS1lZDI1NTE5LXNpZ25hdHVyZS1ieXRlcw==".to_string(),
        signature_pqc: None,
        in_reply_to: None,
    };
    serde_json::to_vec(&env).expect("serialize")
}

fn bench_reticulum(c: &mut Criterion) {
    // Multi-thread runtime — Leviculum's event loop and link drive
    // need a real tokio runtime, not the default single-threaded.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio multi-thread runtime");
    let fixture = rt.block_on(build_loopback());

    let mut group = c.benchmark_group("transport_reticulum_loopback");
    // Reticulum sends are slow (resource reassembly, link negotiation);
    // tight measurement-time budget to keep the bench under a minute.
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(20));

    for size in [256usize, 1024, 4096, 16 * 1024, 64 * 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        let transport = fixture.transport_b.clone();
        let rx = fixture.rx_a.clone();
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let transport = transport.clone();
            let rx = rx.clone();
            b.to_async(&rt).iter(|| {
                let bytes = sample_envelope(size);
                let transport = transport.clone();
                let rx = rx.clone();
                async move {
                    // Send + wait for the frame to arrive on A's sink.
                    let outcome = transport
                        .send("edge-key-aaaa", &bytes)
                        .await
                        .expect("send B -> A");
                    black_box(outcome);
                    let frame = tokio::time::timeout(Duration::from_secs(30), async {
                        let mut g = rx.lock().await;
                        g.recv().await
                    })
                    .await
                    .expect("timed out waiting for inbound frame on A")
                    .expect("A inbound channel closed");
                    black_box(frame.envelope_bytes);
                }
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_reticulum);
criterion_main!(benches);
