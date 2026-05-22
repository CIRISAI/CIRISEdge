//! Loopback acceptance gate for the Reticulum transport (OQ-07) and
//! the authenticated rooted-resolution cold-start path (CIRISEdge#15
//! deliverable (a)).
//!
//! Stands up two [`ReticulumTransport`] instances over loopback TCP,
//! each wired with a federation signer + a shared persist
//! `federation_keys` directory. Node B discovers node A **only by
//! rooting A's signed announce attestation** against the directory —
//! the v0.4.0 cold-start path that replaces v0.3.1's
//! trust-on-first-use. The test then asserts a single signed-shaped
//! [`EdgeEnvelope`] round-trips **byte-exact** A ← B.
//!
//! This is the acceptance gate for the Leviculum-backed transport AND
//! for the legitimate-rooted-resolution half of AV-42: if rooting or
//! the attestation verify were broken, node B would never resolve
//! node A and the send would fail.
//!
//! Requires the `transport-reticulum` feature:
//! `cargo test --features transport-reticulum --test reticulum_loopback`

#![cfg(feature = "transport-reticulum")]

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
use serde_json::value::RawValue;
use tokio::sync::mpsc;

use common::{directory_with, signed_record, TestFedKey};

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

/// Load an edge `LocalSigner` (Ed25519-only) from a `TestFedKey`'s
/// written seed directory.
async fn signer_for(key: &TestFedKey, base: &std::path::Path) -> Arc<LocalSigner> {
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

/// Build a `ReticulumAuth` for `key`, rooted against the shared
/// `directory`. `Ed25519Fallback` policy — the test fixtures carry
/// no PQC components (hybrid-pending rows).
async fn auth_for(
    key: &TestFedKey,
    directory: Arc<ciris_persist::store::sqlite::SqliteBackend>,
    base: &std::path::Path,
) -> ReticulumAuth {
    ReticulumAuth {
        signer: Some(signer_for(key, base).await),
        rooting: Some(directory as Arc<dyn RootingDirectory>),
        resolver: None,
        hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rooted_resolution_round_trips_envelope_byte_exact() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();

    let tmp = tempfile::tempdir().expect("tempdir");

    // ─── Federation directory: steward → {edge-A, edge-B} ──────────
    // Both edge keys are rooted directly under a self-signed steward
    // bootstrap. The rows carry no PQC components (hybrid-pending),
    // so the transports run the `Ed25519Fallback` policy.
    let steward = TestFedKey::new("steward-loopback", 0x01);
    let key_a = TestFedKey::new("edge-key-aaaa", 0x0a);
    let key_b = TestFedKey::new("edge-key-bbbb", 0x0b);
    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&key_a, &steward, "agent"),
        signed_record(&key_b, &steward, "agent"),
    ])
    .await;

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

    // Drive both listeners. A's sink is what we assert on.
    let (tx_a, mut rx_a) = mpsc::channel::<InboundFrame>(16);
    let (tx_b, _rx_b) = mpsc::channel::<InboundFrame>(16);

    let la = transport_a.clone();
    let lb = transport_b.clone();
    let listen_a = tokio::spawn(async move { la.listen(tx_a).await });
    let listen_b = tokio::spawn(async move { lb.listen(tx_b).await });

    // Wait for B to ROOT A's announce attestation — `knows_peer`
    // returns true only once the cold-start path (root_binding +
    // attestation verify + hybrid policy) has accepted the binding.
    let discovered = wait_for(Duration::from_secs(30), || {
        let t = transport_b.clone();
        async move { t.knows_peer("edge-key-aaaa").await }
    })
    .await;
    assert!(
        discovered,
        "node B did not root node A's announce attestation within 30s",
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
        "[loopback] OK — rooted resolution + {} envelope bytes round-tripped byte-exact",
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
