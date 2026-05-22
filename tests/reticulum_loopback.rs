//! Loopback acceptance gate for the Reticulum transport (OQ-07).
//!
//! Stands up two [`ReticulumTransport`] instances over loopback TCP,
//! lets them discover each other via announces, and asserts a single
//! signed-shaped [`EdgeEnvelope`] round-trips **byte-exact** from one
//! to the other. This is the acceptance gate for the Leviculum-backed
//! transport: if the envelope bytes that arrive in the inbound sink
//! differ by one byte from what was sent, the verify pipeline (which
//! checks the signature over canonical bytes, AV-5) would reject it.
//!
//! Requires the `transport-reticulum` feature:
//! `cargo test --features transport-reticulum --test reticulum_loopback`

#![cfg(feature = "transport-reticulum")]

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use ciris_edge::messages::{EdgeEnvelope, MessageType, SchemaVersion};
use ciris_edge::transport::reticulum::{ReticulumTransport, ReticulumTransportConfig};
use ciris_edge::transport::{InboundFrame, Transport};
use serde_json::value::RawValue;
use tokio::sync::mpsc;

/// Build a representative signed-shaped envelope. The signatures here
/// are placeholder strings — the loopback test exercises *transport*
/// byte-fidelity, not verify; the bytes just have to survive the
/// Reticulum resource round-trip unchanged.
fn sample_envelope(signing: &str, destination: &str) -> EdgeEnvelope {
    let body: Box<RawValue> =
        RawValue::from_string(r#"{"trace_events_inserted":7,"deduplicated":2}"#.to_string())
            .expect("raw value");
    EdgeEnvelope {
        edge_schema_version: SchemaVersion::V1_0_0,
        signing_key_id: signing.to_string(),
        destination_key_id: destination.to_string(),
        message_type: MessageType::AccordEventsBatch,
        sent_at: Utc::now(),
        nonce: [0x5a; 16],
        body,
        signature: "ZmFrZS1lZDI1NTE5LXNpZ25hdHVyZS1ieXRlcw==".to_string(),
        signature_pqc: Some("ZmFrZS1tbC1kc2EtNjUtc2lnbmF0dXJl".to_string()),
        in_reply_to: None,
    }
}

/// Pick an ephemeral loopback TCP port by binding and immediately
/// releasing it.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn envelope_round_trips_byte_exact_over_loopback() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();

    let tmp = tempfile::tempdir().expect("tempdir");
    let port_a = free_port();

    // Node A: the receiver. Listens on `port_a`; no bootstrap peers.
    let cfg_a = {
        let mut c =
            ReticulumTransportConfig::new(tmp.path().join("a/transport.id"), "edge-key-aaaa");
        c.listen_addr = format!("127.0.0.1:{port_a}").parse().unwrap();
        c.announce_interval = Duration::from_secs(2);
        c
    };

    // Node B: the sender. Dials A as a bootstrap peer.
    let cfg_b = {
        let mut c =
            ReticulumTransportConfig::new(tmp.path().join("b/transport.id"), "edge-key-bbbb");
        c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        c.bootstrap_peers = vec![format!("127.0.0.1:{port_a}").parse().unwrap()];
        c.announce_interval = Duration::from_secs(2);
        c
    };

    let transport_a = Arc::new(
        ReticulumTransport::new(cfg_a, None)
            .await
            .expect("build transport A"),
    );
    let transport_b = Arc::new(
        ReticulumTransport::new(cfg_b, None)
            .await
            .expect("build transport B"),
    );

    // Drive both listeners. A's sink is what we assert on.
    let (tx_a, mut rx_a) = mpsc::channel::<InboundFrame>(16);
    let (tx_b, _rx_b) = mpsc::channel::<InboundFrame>(16);

    let la = transport_a.clone();
    let lb = transport_b.clone();
    let listen_a = tokio::spawn(async move { la.listen(tx_a).await });
    let listen_b = tokio::spawn(async move { lb.listen(tx_b).await });

    // Wait for B to discover A via announce — `send` on B resolves
    // `destination_key_id` from B's announce-populated peer map.
    let discovered = wait_for(Duration::from_secs(30), || {
        let t = transport_b.clone();
        async move { t.knows_peer("edge-key-aaaa").await }
    })
    .await;
    assert!(
        discovered,
        "node B did not discover node A's announce within 30s",
    );

    // Round-trip one envelope B → A.
    let envelope = sample_envelope("edge-key-bbbb", "edge-key-aaaa");
    let sent_bytes = serde_json::to_vec(&envelope).expect("serialize envelope");

    let outcome = transport_b
        .send("edge-key-aaaa", &sent_bytes)
        .await
        .expect("send B -> A");
    println!("[loopback] send outcome: {outcome:?}");

    // The envelope must arrive on A's inbound sink, byte-exact.
    let frame = tokio::time::timeout(Duration::from_secs(60), rx_a.recv())
        .await
        .expect("timed out waiting for inbound frame on A")
        .expect("A inbound channel closed");

    assert_eq!(
        frame.transport,
        Transport::id(&*transport_a),
        "inbound frame must be tagged with the Reticulum transport id",
    );
    assert_eq!(
        frame.envelope_bytes, sent_bytes,
        "envelope bytes must survive the Reticulum resource round-trip unchanged",
    );

    // The bytes must still parse back into an equivalent envelope.
    let received: EdgeEnvelope =
        serde_json::from_slice(&frame.envelope_bytes).expect("re-parse received envelope");
    assert_eq!(received.signing_key_id, "edge-key-bbbb");
    assert_eq!(received.destination_key_id, "edge-key-aaaa");
    assert_eq!(received.nonce, [0x5a; 16]);
    assert_eq!(received.signature, envelope.signature);

    println!(
        "[loopback] OK — {} envelope bytes round-tripped byte-exact",
        sent_bytes.len(),
    );

    listen_a.abort();
    listen_b.abort();
}

/// Poll `cond` until it returns `true` or `timeout` elapses.
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
