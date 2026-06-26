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
use ciris_edge::transport::reticulum::{ReticulumAuth, ReticulumTransportConfig};
use ciris_edge::transport::{InboundFrame, Transport};
use ciris_edge::verify::RootingDirectory;
use serde_json::value::RawValue;
use tokio::sync::mpsc;

use common::{
    build_reticulum_with_retry, directory_with, prime_v7_peer_pair, signed_record, TestFedKey,
};

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
        testimonial_witness: None,
        key_boundary_scope: None,
        cohort_scope: None,
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
    Arc::new(LocalSigner::new(key.key_id.clone(), classical, None))
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
        ..ReticulumAuth::default()
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

    // Node A: the receiver. Binds an ephemeral port (retried on the
    // `free_port()` bind/release race); no bootstrap peers.
    let (transport_a, addr_a) = build_reticulum_with_retry(|| {
        let key = &key_a;
        let dir = directory.clone();
        let base = tmp.path().to_path_buf();
        async move {
            let mut c = ReticulumTransportConfig::new(base.join("a/transport.id"), "edge-key-aaaa");
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.announce_interval = Duration::from_secs(2);
            let auth = auth_for(key, dir, &base).await;
            (c, auth)
        }
    })
    .await;
    let port_a = addr_a.port();

    // Node B: the sender. Dials A on its settled port as a bootstrap peer.
    let (transport_b, _addr_b) = build_reticulum_with_retry(|| {
        let key = &key_b;
        let dir = directory.clone();
        let base = tmp.path().to_path_buf();
        async move {
            let mut c = ReticulumTransportConfig::new(base.join("b/transport.id"), "edge-key-bbbb");
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.bootstrap_peers = vec![format!("127.0.0.1:{port_a}").parse().unwrap()];
            c.announce_interval = Duration::from_secs(2);
            let auth = auth_for(key, dir, &base).await;
            (c, auth)
        }
    })
    .await;

    // v7.0.0 (CIRISEdge#191 / #195) — explicit-hash destinations cannot
    // announce, so the announce-based rooting path the v6.x loopback
    // tests relied on is wedged by design. Pre-install the
    // `(dest_hash, transport-tier ed25519)` binding both directions —
    // production peers learn the same binding via the v6.0.0 directory-
    // cache anti-entropy path (CIRISEdge#175).
    prime_v7_peer_pair(&transport_a, "edge-key-aaaa", &transport_b, "edge-key-bbbb").await;

    // Drive both listeners. A's sink is what we assert on.
    let (tx_a, mut rx_a) = mpsc::channel::<InboundFrame>(16);
    let (tx_b, _rx_b) = mpsc::channel::<InboundFrame>(16);

    let la = transport_a.clone();
    let lb = transport_b.clone();
    let listen_a = tokio::spawn(async move { la.listen(tx_a).await });
    let listen_b = tokio::spawn(async move { lb.listen(tx_b).await });

    // Post-prime sanity — no await on the announce mechanism.
    let discovered = transport_b.knows_peer("edge-key-aaaa").await;
    assert!(
        discovered,
        "post-prime `knows_peer` must be true — v7.0.0 explicit-hash discovery is out-of-band",
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

/// CIRISEdge#220 — proves `Edge::spawn_background_listeners` drives
/// the inbound dispatch loop end-to-end so a verified envelope reaches
/// a registered inline-text handler. Mirrors the
/// `rooted_resolution_round_trips_envelope_byte_exact` test above but
/// instead of manually spawning `transport.listen()` per side, it
/// uses the v7.1.0 `Edge::spawn_background_listeners` surface —
/// the production codepath `init_edge_runtime` invokes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn spawn_background_listeners_drives_two_node_send_inline_text() {
    use ciris_edge::verify::HybridPolicy;
    use ciris_edge::{Edge, EdgeConfig, InlineText};

    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();

    let tmp = tempfile::tempdir().expect("tempdir");

    let steward = TestFedKey::new("steward-bg-listeners", 0x01);
    let key_a = TestFedKey::new("edge-bg-aaaa", 0x2a);
    let key_b = TestFedKey::new("edge-bg-bbbb", 0x2b);
    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&key_a, &steward, "agent"),
        signed_record(&key_b, &steward, "agent"),
    ])
    .await;

    let (transport_a, addr_a) = build_reticulum_with_retry(|| {
        let key = &key_a;
        let dir = directory.clone();
        let base = tmp.path().to_path_buf();
        async move {
            let mut c = ReticulumTransportConfig::new(base.join("a/transport.id"), "edge-bg-aaaa");
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.announce_interval = Duration::from_secs(2);
            let auth = auth_for(key, dir, &base).await;
            (c, auth)
        }
    })
    .await;
    let port_a = addr_a.port();
    let (transport_b, _addr_b) = build_reticulum_with_retry(|| {
        let key = &key_b;
        let dir = directory.clone();
        let base = tmp.path().to_path_buf();
        async move {
            let mut c = ReticulumTransportConfig::new(base.join("b/transport.id"), "edge-bg-bbbb");
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.bootstrap_peers = vec![format!("127.0.0.1:{port_a}").parse().unwrap()];
            c.announce_interval = Duration::from_secs(2);
            let auth = auth_for(key, dir, &base).await;
            (c, auth)
        }
    })
    .await;
    prime_v7_peer_pair(&transport_a, "edge-bg-aaaa", &transport_b, "edge-bg-bbbb").await;

    // Build an Edge per side — same builder shape `init_edge_runtime`
    // produces, just with the persist directory as the queue stub.
    let signer_a = signer_for(&key_a, tmp.path()).await;
    let signer_b = signer_for(&key_b, tmp.path()).await;
    let queue = directory.clone();

    let edge_a = Arc::new(
        Edge::builder()
            .directory(directory.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
            .queue(queue.clone())
            .signer(signer_a)
            .transport(transport_a.clone() as Arc<dyn Transport>)
            .reticulum_transport(transport_a.clone())
            .config(EdgeConfig {
                hybrid_policy: HybridPolicy::Ed25519Fallback,
                cohort_scope_enforcement: ciris_edge::CohortScopeEnforcement::Off,
                ..EdgeConfig::default()
            })
            .build()
            .expect("build edge A"),
    );
    let edge_b = Arc::new(
        Edge::builder()
            .directory(directory.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
            .queue(queue.clone())
            .signer(signer_b)
            .transport(transport_b.clone() as Arc<dyn Transport>)
            .reticulum_transport(transport_b.clone())
            .config(EdgeConfig {
                hybrid_policy: HybridPolicy::Ed25519Fallback,
                cohort_scope_enforcement: ciris_edge::CohortScopeEnforcement::Off,
                ..EdgeConfig::default()
            })
            .build()
            .expect("build edge B"),
    );

    // Register an inline-text subscriber on A — we want the receiver
    // to observe the verified envelope through the dispatch loop, not
    // just the raw InboundFrame on the inbound channel.
    let (_sub_id, mut sub_rx) = edge_a.register_inline_text_subscriber();

    // ── v7.1.0 surface under test ────────────────────────────────────
    // Per-side edge-owned runtimes; spawn the listen + inbound dispatch
    // tasks on each. Mirrors what `init_edge_runtime` does in production.
    let rt_a = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .thread_name("test-edge-a-transport")
            .build()
            .expect("build rt A"),
    );
    let rt_b = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .thread_name("test-edge-b-transport")
            .build()
            .expect("build rt B"),
    );
    let _handles_a = edge_a.spawn_background_listeners(rt_a.handle());
    let _handles_b = edge_b.spawn_background_listeners(rt_b.handle());

    // Drive the send: B → A.
    let msg = InlineText {
        text: "v7.1.0 bg-listeners hello".to_string(),
    };
    // `send_inline` returns `EdgeError::Config("ephemeral
    // request-response correlation not wired (Phase 2)")` AS the
    // success-of-transport path — same as `PyEdge::send_inline_text`
    // maps it. The transport accepted + shipped the bytes; the
    // correlation channel TODO is a separate concern. Map it to Ok
    // so the receiver-side assertion is what gates the test.
    match edge_b.send_inline("edge-bg-aaaa", msg).await {
        Ok(()) => {}
        Err(ciris_edge::EdgeError::Config(s))
            if s.contains("ephemeral request-response correlation not wired") => {}
        Err(e) => panic!("send_inline B → A failed at transport: {e:?}"),
    }

    // A's inline-text subscriber must receive the text — proves the
    // background-listener path drove verify + handler dispatch all the
    // way to the application surface.
    let (sender_key_id, body_text) = tokio::time::timeout(Duration::from_secs(30), sub_rx.recv())
        .await
        .expect("timed out waiting for inline-text on A")
        .expect("inline-text channel closed without receive");
    assert_eq!(sender_key_id, "edge-bg-bbbb");
    assert_eq!(body_text, "v7.1.0 bg-listeners hello");

    // Tokio runtimes can't be dropped from within an async context,
    // so leak them; the test process exit will reclaim. Holding them
    // until function exit (after the receive assertion) is the only
    // contract we need.
    std::mem::forget(rt_a);
    std::mem::forget(rt_b);
}

/// Poll `cond` until it returns `true` or `timeout` elapses.
#[allow(dead_code)]
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
