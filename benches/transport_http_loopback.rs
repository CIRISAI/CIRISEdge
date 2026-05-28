//! `transport_http_loopback` — round-trip over the HTTP transport.
//! End-to-end wall clock; comparison anchor for the Reticulum curve.
//!
//! # Expected curve (per BENCHMARKS.md "Reading the curves")
//!
//! Linear in size — TCP throughput-bound. Flat ⇒ the HTTP transport
//! is buffering before send (latency hidden behind buffer).
//!
//! # Setup
//!
//! Two `HttpTransport` instances. A listens on loopback; B is
//! configured with A's URL in `peer_urls`. B `send`s to A; A's
//! inbound handler pushes the frame onto an `mpsc::Sender<InboundFrame>`
//! that the bench drains.

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
#![cfg(feature = "transport-http")]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ciris_edge::transport::http::{HttpTransport, HttpTransportConfig};
use ciris_edge::transport::{InboundFrame, Transport};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tokio::sync::{mpsc, Mutex};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

struct HttpFixture {
    transport_b: Arc<HttpTransport>,
    rx_a: Arc<Mutex<mpsc::Receiver<InboundFrame>>>,
    _listen_a: tokio::task::JoinHandle<()>,
}

async fn build_http_loopback() -> HttpFixture {
    let port_a = free_port();
    let addr_a: std::net::SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();

    let mut a_cfg = HttpTransportConfig::default();
    a_cfg.listen_addr = addr_a;
    let transport_a = Arc::new(HttpTransport::new(a_cfg).expect("HttpTransport A"));

    let mut peer_urls = HashMap::new();
    peer_urls.insert(
        "a".to_string(),
        format!("http://127.0.0.1:{port_a}/edge/inbound"),
    );
    let b_cfg = HttpTransportConfig {
        peer_urls,
        request_timeout: Duration::from_secs(10),
        ..HttpTransportConfig::default()
    };
    let transport_b = Arc::new(HttpTransport::new(b_cfg).expect("HttpTransport B"));

    let (tx_a, rx_a) = mpsc::channel::<InboundFrame>(1024);
    let listen_a = {
        let t = transport_a.clone();
        tokio::spawn(async move {
            let _ = t.listen(tx_a).await;
        })
    };

    // Wait for A's listener to be ready.
    for _ in 0..50 {
        if std::net::TcpStream::connect_timeout(&addr_a, Duration::from_millis(50)).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    HttpFixture {
        transport_b,
        rx_a: Arc::new(Mutex::new(rx_a)),
        _listen_a: listen_a,
    }
}

fn bench_http(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio multi-thread runtime");
    let fixture = rt.block_on(build_http_loopback());

    let mut group = c.benchmark_group("transport_http_loopback");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(8));

    for size in [256usize, 1024, 4096, 16 * 1024, 64 * 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        let transport = fixture.transport_b.clone();
        let rx = fixture.rx_a.clone();
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let transport = transport.clone();
            let rx = rx.clone();
            b.to_async(&rt).iter(|| {
                // Build a payload of `size` bytes (the body is opaque
                // to the HTTP transport — it just forwards the bytes).
                let bytes = vec![0x42u8; size];
                let transport = transport.clone();
                let rx = rx.clone();
                async move {
                    let outcome = transport.send("a", &bytes).await.expect("send B -> A");
                    black_box(outcome);
                    let frame = tokio::time::timeout(Duration::from_secs(10), async {
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

criterion_group!(benches, bench_http);
criterion_main!(benches);
