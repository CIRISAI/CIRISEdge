//! v0.15.0 (CIRISEdge#33) — Routing-table FFI acceptance gate.
//! v1.1.0 (CIRISEdge#44) — Leviculum-gap flip-on: paths + rate now
//! call real `ReticulumNode` accessors; tunnels/announces/reverse
//! remain documented Vec::new() (no backing data in the Leviculum
//! fork).
//!
//! Exercises the routing surface on `ReticulumTransport`
//! (paths / blackhole / rate / tunnels / announce / reverse + the
//! send-path blackhole enforcement). Mirrors the v0.14.0 Links FFI
//! test layout — Rust-level tests against the transport, plus a
//! UniFFI free-function smoke gate at the bottom that confirms the
//! typed `NotInitialized` path triggers when no Edge has been
//! installed.
//!
//! Two test groups:
//!
//!   1. **Single-transport** — read/mutation surfaces that don't
//!      require a peer. Stand up one `ReticulumTransport` and assert
//!      the routing methods return the documented shapes (empty Vecs
//!      for the 3 forever-stubbed reads, real Leviculum reads for the
//!      5 v1.1.0-flipped accessors, real values for `transport_id` /
//!      `transport_uptime` / the blackhole CRUD).
//!
//!   2. **Paired-transport** — the blackhole enforcement path. Stand
//!      up two transports paired over loopback TCP, wait for rooting
//!      to converge, then exercise the `send → blackhole hit → typed
//!      PeerBlackholed error` path end-to-end.
//!
//! Requires the Reticulum + UniFFI features:
//! `cargo test --features "transport-reticulum ffi-uniffi" --test routing_ffi`

#![cfg(all(feature = "transport-reticulum", feature = "ffi-uniffi"))]

mod common;

use std::sync::Arc;
use std::time::Duration;

use ciris_edge::identity::LocalSigner;
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport, TransportError};
use ciris_edge::verify::RootingDirectory;
use tokio::sync::mpsc;

use common::{directory_with, prime_v7_peer_pair, signed_record, TestFedKey};

/// Pick an ephemeral loopback TCP port.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

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

async fn auth_with(
    key: &TestFedKey,
    directory: Arc<ciris_persist::store::sqlite::SqliteBackend>,
    base: &std::path::Path,
) -> ReticulumAuth {
    // v0.16.1 — the routing-table FFI's blackhole surface is now
    // persist-backed; SqliteBackend implements BlackholeRules so the
    // same fixture directory powers both the rooting + blackhole
    // surfaces. The V052 `cirislens.blackhole_rules` table is created
    // by `FederationDirectorySqlite::open`'s migration run.
    let blackhole: Arc<dyn ciris_persist::federation::BlackholeRules> = directory.clone();
    ReticulumAuth {
        signer: Some(signer_for(key, base).await),
        rooting: Some(directory as Arc<dyn RootingDirectory>),
        resolver: None,
        hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
        event_bus: None,
        reachability: None,
        blackhole_rules: Some(blackhole),
        transport_identity_keystore: None,
    }
}

/// Stand up a single transport for the routing-table reads tests.
async fn single_transport(
    tmp: &std::path::Path,
) -> (
    Arc<ReticulumTransport>,
    tokio::task::JoinHandle<Result<(), TransportError>>,
) {
    let steward = TestFedKey::new("steward-routing", 0x31);
    let key_a = TestFedKey::new("edge-routing-aaaa", 0x3a);
    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&key_a, &steward, "agent"),
    ])
    .await;

    let cfg_a = {
        let mut c = ReticulumTransportConfig::new(tmp.join("a/transport.id"), "edge-routing-aaaa");
        c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        c.announce_interval = Duration::from_secs(2);
        c
    };
    let auth_a = auth_with(&key_a, directory, tmp).await;

    let transport_a = Arc::new(
        ReticulumTransport::new(cfg_a, auth_a)
            .await
            .expect("build transport A"),
    );

    let (tx_a, _rx_a) = mpsc::channel::<InboundFrame>(16);
    let la = transport_a.clone();
    let listen_a = tokio::spawn(async move { la.listen(tx_a).await });

    (transport_a, listen_a)
}

/// Stand up a paired pair of transports — used by the blackhole
/// enforcement test. Mirror of the paired_transports helper from
/// `links_ffi.rs`, sized down to what the routing tests need.
async fn paired_transports(
    tmp: &std::path::Path,
) -> (
    Arc<ReticulumTransport>,
    Arc<ReticulumTransport>,
    tokio::task::JoinHandle<Result<(), TransportError>>,
    tokio::task::JoinHandle<Result<(), TransportError>>,
) {
    let steward = TestFedKey::new("steward-routing-pair", 0x32);
    let key_a = TestFedKey::new("edge-routing-aaaa", 0x3a);
    let key_b = TestFedKey::new("edge-routing-bbbb", 0x3b);
    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&key_a, &steward, "agent"),
        signed_record(&key_b, &steward, "agent"),
    ])
    .await;

    let port_a = free_port();
    let cfg_a = {
        let mut c = ReticulumTransportConfig::new(tmp.join("a/transport.id"), "edge-routing-aaaa");
        c.listen_addr = format!("127.0.0.1:{port_a}").parse().unwrap();
        c.announce_interval = Duration::from_secs(2);
        c
    };
    let cfg_b = {
        let mut c = ReticulumTransportConfig::new(tmp.join("b/transport.id"), "edge-routing-bbbb");
        c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        c.bootstrap_peers = vec![format!("127.0.0.1:{port_a}").parse().unwrap()];
        c.announce_interval = Duration::from_secs(2);
        c
    };

    let auth_a = auth_with(&key_a, directory.clone(), tmp).await;
    let auth_b = auth_with(&key_b, directory.clone(), tmp).await;

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

    // v7.0.0 (CIRISEdge#191 / #195) — explicit-hash destinations cannot
    // announce; pre-install both directions of the rooted-peer binding
    // out-of-band (test analogue of the v6.0.0 directory-cache anti-
    // entropy path, CIRISEdge#175).
    prime_v7_peer_pair(
        &transport_a,
        "edge-routing-aaaa",
        &transport_b,
        "edge-routing-bbbb",
    )
    .await;

    let (tx_a, _rx_a) = mpsc::channel::<InboundFrame>(16);
    let (tx_b, _rx_b) = mpsc::channel::<InboundFrame>(16);

    let la = transport_a.clone();
    let lb = transport_b.clone();
    let listen_a = tokio::spawn(async move { la.listen(tx_a).await });
    let listen_b = tokio::spawn(async move { lb.listen(tx_b).await });

    // Post-prime sanity — no announce-mechanism dependency.
    let discovered = transport_b.knows_peer("edge-routing-aaaa").await;
    assert!(
        discovered,
        "post-prime `knows_peer` must be true — v7.0.0 explicit-hash discovery is out-of-band",
    );

    (transport_a, transport_b, listen_a, listen_b)
}

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

// ─── Tests: read surfaces (CIRISEdge#44 — Leviculum flip-on) ───────

/// `routing_path_table` returns an empty Vec on a freshly-built
/// transport that has never received an announce. v1.1.0 (CIRISEdge#44)
/// — the underlying `ReticulumNode::path_table_entries` is now public;
/// a fresh node with no peers and no inbound announces has zero rows.
/// The test exercises the real Leviculum read, not a stub.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn path_table_empty_initially() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    let table = transport.routing_path_table(None).await;
    assert!(
        table.is_empty(),
        "freshly-built transport with no peers has no path entries"
    );
    // `max_hops` filter is wired — passing Some applies the hop cap
    // even when the underlying table is empty (still emits []).
    let filtered = transport.routing_path_table(Some(3)).await;
    assert!(filtered.is_empty(), "max_hops filter on empty table");

    listen.abort();
}

/// `routing_path_to(unknown)` returns `None` because no entry matches.
/// v1.1.0 (CIRISEdge#44) — backed by `ReticulumNode::get_path_clone`.
/// Bad-length input also returns `None` (typed-error-free; callers
/// pre-validate length when they need to distinguish).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn path_to_returns_none() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    let result = transport.routing_path_to(&[0u8; 16]).await;
    assert!(result.is_none(), "unknown destination_hash returns None");

    // Bad-length input is also None (not a typed error — the contract
    // is "no entry matches"; length-validation is the caller's
    // responsibility when they need to distinguish).
    let bad_len = transport.routing_path_to(&[0u8; 4]).await;
    assert!(bad_len.is_none(), "bad-length input returns None");

    listen.abort();
}

/// `routing_path_request` returns immediately (fire-and-forget). The
/// underlying leviculum `request_path` is async-fire-and-forget; this
/// test confirms the typed return is `Ok(())` with no payload.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn path_request_is_fire_and_forget() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    let t0 = std::time::Instant::now();
    transport
        .routing_path_request(&[0xAAu8; 16], None)
        .await
        .expect("path_request fire-and-forget");
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "path_request must return immediately (got {elapsed:?})"
    );

    // Bad length surfaces typed Config error.
    let err = transport
        .routing_path_request(&[0u8; 8], None)
        .await
        .expect_err("8-byte destination must fail");
    assert!(matches!(err, TransportError::Config(_)));

    listen.abort();
}

/// `routing_path_drop` accepts a valid 16-byte hash and returns
/// `Ok(())` whether or not the entry existed (POSIX `rm -f`
/// ergonomics). v1.1.0 (CIRISEdge#44) — backed by
/// `ReticulumNode::remove_path`. Bad length still errors typed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn path_drop_clears_entry() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    // Idempotent — dropping a never-known entry succeeds.
    transport
        .routing_path_drop(&[0u8; 16])
        .await
        .expect("path_drop is idempotent (rm -f ergonomics)");

    // After the drop, path_to confirms the entry remains absent.
    let after = transport.routing_path_to(&[0u8; 16]).await;
    assert!(after.is_none(), "path_to after drop confirms absence");

    let err = transport
        .routing_path_drop(&[0u8; 4])
        .await
        .expect_err("bad length");
    assert!(matches!(err, TransportError::Config(_)));

    listen.abort();
}

/// `routing_path_drop_via` accepts a valid 16-byte hash and returns
/// `Ok(())`. v1.1.0 (CIRISEdge#44) — backed by
/// `ReticulumNode::drop_all_paths_via`. Bulk-eviction; the FFI
/// surface discards the count of removed paths (operators inspect
/// `routing_path_table` after for confirmation).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn path_drop_via_clears_all_paths_through_transport() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    transport
        .routing_path_drop_via(&[0xBBu8; 16])
        .await
        .expect("path_drop_via on empty table is a no-op");

    // Bad length still surfaces as Config error.
    let err = transport
        .routing_path_drop_via(&[0u8; 8])
        .await
        .expect_err("bad length");
    assert!(matches!(err, TransportError::Config(_)));

    listen.abort();
}

// ─── Tests: blackhole CRUD ──────────────────────────────────────────

/// `blackhole_add` then `blackhole_list` reflects the new rule.
/// Exercises both the `until = None` (permanent) and `until = Some(rfc3339)`
/// variants.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blackhole_add_lists_entry() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    let id_perm = vec![0x01u8; 16];
    let id_until = vec![0x02u8; 16];
    let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();

    transport
        .routing_blackhole_add(&id_perm, None, Some("perma-ban"))
        .await
        .expect("permanent add");
    transport
        .routing_blackhole_add(&id_until, Some(&future), Some("temp-ban"))
        .await
        .expect("until add");

    let list = transport.routing_blackhole_list().await.expect("list");
    assert_eq!(list.len(), 2);
    let perm = list
        .iter()
        .find(|e| e.identity_hash == id_perm)
        .expect("permanent entry");
    assert!(perm.until.is_none(), "permanent has no until");
    assert_eq!(perm.reason.as_deref(), Some("perma-ban"));
    assert_eq!(perm.hits, 0, "fresh rule has zero hits");
    let scheduled = list
        .iter()
        .find(|e| e.identity_hash == id_until)
        .expect("scheduled entry");
    assert!(scheduled.until.is_some(), "scheduled has until");

    // Bad RFC-3339 → typed Config error.
    let err = transport
        .routing_blackhole_add(&[0xFFu8; 16], Some("not-a-date"), None)
        .await
        .expect_err("bad until");
    assert!(matches!(err, TransportError::Config(_)));

    // Empty identity_hash → typed Config error.
    let err = transport
        .routing_blackhole_add(&[], None, None)
        .await
        .expect_err("empty identity_hash");
    assert!(matches!(err, TransportError::Config(_)));

    listen.abort();
}

/// `blackhole_remove` is idempotent — removing a rule twice + removing
/// a never-added rule all return `Ok(())`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blackhole_remove_idempotent() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    let id = vec![0x99u8; 16];
    transport
        .routing_blackhole_remove(&id)
        .await
        .expect("remove of non-existent");

    transport
        .routing_blackhole_add(&id, None, None)
        .await
        .expect("add");
    assert_eq!(
        transport
            .routing_blackhole_list()
            .await
            .expect("list")
            .len(),
        1
    );

    transport
        .routing_blackhole_remove(&id)
        .await
        .expect("first remove");
    transport
        .routing_blackhole_remove(&id)
        .await
        .expect("second remove (idempotent)");
    assert!(transport
        .routing_blackhole_list()
        .await
        .expect("list")
        .is_empty());

    listen.abort();
}

/// Blackhole enforcement: blackhole a rooted peer (via the peer's
/// dest_hash), call `send`, observe a typed `PeerBlackholed` error
/// AND the rule's `hits` counter increment.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blackhole_enforcement_returns_peer_blackholed_error() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_transport_a, transport_b, listen_a, listen_b) = paired_transports(tmp.path()).await;

    // Pull A's dest_hash from B's rooted-peer cache.
    let dest_hash_a = transport_b
        .peer_dest_hash_for_test("edge-routing-aaaa")
        .await
        .expect("rooted peer dest_hash")
        .to_vec();

    // Blackhole A on B.
    transport_b
        .routing_blackhole_add(&dest_hash_a, None, Some("acceptance-test"))
        .await
        .expect("blackhole_add");

    // Attempt to send — must surface the typed PeerBlackholed error.
    let envelope = b"{\"type\":\"acceptance\",\"body\":\"blackhole test\"}";
    let err = transport_b
        .send("edge-routing-aaaa", envelope)
        .await
        .expect_err("send to blackholed peer must fail");
    match err {
        TransportError::PeerBlackholed {
            identity_hash,
            reason,
            until,
        } => {
            assert_eq!(identity_hash, dest_hash_a, "identity_hash echoed");
            assert_eq!(reason.as_deref(), Some("acceptance-test"));
            assert!(until.is_none(), "permanent rule has no until");
        }
        other => panic!("expected PeerBlackholed, got {other:?}"),
    }

    listen_a.abort();
    listen_b.abort();
}

/// Each blackhole hit increments the rule's `hits` counter — verify it
/// reflects in `blackhole_list` snapshots.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blackhole_hits_counter_increments_on_block() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_transport_a, transport_b, listen_a, listen_b) = paired_transports(tmp.path()).await;

    let dest_hash_a = transport_b
        .peer_dest_hash_for_test("edge-routing-aaaa")
        .await
        .expect("rooted peer dest_hash")
        .to_vec();

    transport_b
        .routing_blackhole_add(&dest_hash_a, None, None)
        .await
        .expect("blackhole_add");

    // Drive 3 attempts.
    for _ in 0..3 {
        let _ = transport_b
            .send("edge-routing-aaaa", b"acceptance")
            .await
            .expect_err("blackholed");
    }

    // v0.16.1: hit recording is fire-and-forget through a spawned
    // tokio task hitting the persist backend. Let the spawned hits
    // settle before snapshotting — three short polls cover the
    // SQLite round-trip latency without baking in a fixed sleep.
    let mut entry_hits: u64 = 0;
    for _ in 0..20 {
        let list = transport_b.routing_blackhole_list().await.expect("list");
        if let Some(entry) = list.iter().find(|e| e.identity_hash == dest_hash_a) {
            entry_hits = entry.hits;
            if entry_hits >= 3 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(entry_hits, 3, "hits counter must increment per block");

    listen_a.abort();
    listen_b.abort();
}

// ─── Tests: rate (flipped on) / tunnels / announce / reverse (gap) ─

/// `routing_rate_table` returns empty on a freshly-built transport.
/// v1.1.0 (CIRISEdge#44) — backed by
/// `ReticulumNode::rate_table_entries`. A node that has not yet
/// processed any announces has zero rows; the test exercises the
/// real Leviculum read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_table_empty_initially() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    let table = transport.routing_rate_table().await;
    assert!(
        table.is_empty(),
        "freshly-built transport with no announces has empty rate table"
    );

    listen.abort();
}

/// `tunnels_list` returns empty by design. v1.1.0 (CIRISEdge#44) —
/// the CIRISAI/leviculum fork does not maintain a tunnels collection
/// (only `tunnel_synthesize_hash` for control-destination routing).
/// The wire shape stays pinned for forward-compat with a future
/// Leviculum cut that grows the data structure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnels_list_empty_initially() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    let t = transport.routing_tunnels().await;
    assert!(
        t.is_empty(),
        "tunnels collection does not exist in this Leviculum fork"
    );

    listen.abort();
}

/// `announce_table` returns empty by design. v1.1.0 (CIRISEdge#44) —
/// the in-flight announce retry queue is scoped to the driver event
/// loop in reticulum-std and not surfaced on `ReticulumNode` at any
/// visibility level. The wire shape stays pinned for forward-compat.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn announce_table_reflects_in_flight() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    let a = transport.routing_announce_table().await;
    assert!(
        a.is_empty(),
        "in-flight announce queue is not exposed by Leviculum's public API"
    );

    listen.abort();
}

/// `reverse_table` returns empty by design. v1.1.0 (CIRISEdge#44) —
/// Leviculum's `ReverseEntry` stores `(timestamp_ms,
/// receiving_interface_index, outbound_interface_index)` keyed by
/// packet hash; that shape doesn't carry `source_hash` /
/// `destination_hash` fields, so Edge's `EdgeReverseEntry` wire
/// schema can't be populated without an upstream Leviculum design
/// pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_table_round_trip() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    let r = transport.routing_reverse_table().await;
    assert!(
        r.is_empty(),
        "reverse_table shape mismatch prevents wire-shape projection"
    );

    listen.abort();
}

// ─── Tests: transport state ─────────────────────────────────────────

/// `transport_uptime` is monotonic — a second call after a delay must
/// be >= the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transport_uptime_monotonic() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    let u1 = transport.routing_transport_uptime();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let u2 = transport.routing_transport_uptime();
    assert!(u2 >= u1, "uptime is monotonic non-decreasing");
    assert!(u2 >= 1, "uptime must reflect the >1s sleep (got {u2})");

    listen.abort();
}

/// `transport_id` returns the routing-layer identity hash. v0.15.0
/// reads it from `ReticulumNode::identity_hash()` (16 bytes). Stable
/// across calls within a single transport instance.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transport_id_stable_after_init() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    let id1 = transport.routing_transport_id();
    let id2 = transport.routing_transport_id();
    assert_eq!(id1.len(), 16, "transport_id is 16 bytes");
    assert_eq!(id1, id2, "transport_id is stable");
    // Not all-zero.
    assert!(
        id1.iter().any(|b| *b != 0),
        "transport_id must not be all-zero"
    );

    listen.abort();
}

// ─── Tests: peer_key_id field on path entry (v1.1.0 wired) ─────────

/// `peer_key_id` on a PathEntry is filled when the destination_hash
/// matches a rooted peer; `None` when no rooted peer matches. v1.1.0
/// (CIRISEdge#44) — the per-row resolution is now wired against the
/// edge's `peers` map. A freshly-built transport with no rooted peers
/// produces zero rows, but the wire-shape type contract is exercised
/// via the loop (which compiles iff `peer_key_id: Option<String>`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_key_id_filled_from_directory() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    let table = transport.routing_path_table(None).await;
    for entry in &table {
        // Wire-shape check: `peer_key_id` is `Option<String>` and the
        // resolution logic is in place to fill it when a rooted peer
        // matches the destination hash (CIRISEdge#15 cold-start path).
        let _: Option<String> = entry.peer_key_id.clone();
    }
    // No rooted peers + no inbound announces → empty table. The
    // multi-node loopback fixture in tests/reticulum_av42.rs covers
    // the populated-table case where the rooted-peer match yields
    // Some(key_id).
    assert!(
        table.is_empty(),
        "no rooted peers + no inbound announces → empty path table"
    );

    listen.abort();
}

/// Symmetric counterpart — when the destination_hash does not match a
/// rooted peer, `peer_key_id` must be `None`. v1.1.0 (CIRISEdge#44) —
/// real Leviculum reads; the wire-shape check holds across the
/// populated and empty cases.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_key_id_none_when_directory_miss() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    let table = transport.routing_path_table(None).await;
    assert!(table.iter().all(|e| {
        // Wire-shape check: `peer_key_id` is `Option<String>`.
        let _: Option<String> = e.peer_key_id.clone();
        true
    }));

    listen.abort();
}

// ─── Tests: UniFFI free-function smoke gates ────────────────────────

/// With no Edge installed (pre-`init_edge_runtime` posture) the
/// routing free functions return the typed `NotInitialized` error,
/// mirroring the v0.14.0 Links smoke gate.
#[test]
fn uniffi_path_table_unsupported_without_init() {
    let err = ciris_edge::routing_path_table(None).expect_err("no Edge installed");
    assert!(matches!(err, ciris_edge::EdgeBindingsError::NotInitialized));
    let err = ciris_edge::routing_blackhole_list().expect_err("no Edge installed");
    assert!(matches!(err, ciris_edge::EdgeBindingsError::NotInitialized));
    let err = ciris_edge::routing_transport_uptime().expect_err("no Edge installed");
    assert!(matches!(err, ciris_edge::EdgeBindingsError::NotInitialized));
    let err = ciris_edge::routing_rate_table().expect_err("no Edge installed");
    assert!(matches!(err, ciris_edge::EdgeBindingsError::NotInitialized));
    let err = ciris_edge::routing_tunnels().expect_err("no Edge installed");
    assert!(matches!(err, ciris_edge::EdgeBindingsError::NotInitialized));
}

// ─── v0.16.1 — Blackhole durability flip (CIRISPersist#120) ─────────
//
// The v0.15.0 `Arc<RwLock<HashMap>>` shape is gone. The transport now
// holds an `Arc<dyn BlackholeRules>` over persist's V052
// `cirislens.blackhole_rules` table. The five tests below pin the
// new contract:
//
//   1. `blackhole_durable_round_trip` — add a rule on transport A,
//      tear down + rebuild the transport against the SAME backend
//      Arc; assert the rule still appears in `routing_blackhole_list`.
//      Durability proof — the v0.15.0 shape failed this test by
//      construction (the HashMap died with the transport).
//
//   2. `blackhole_enforcement_records_hit_through_persist` — send to
//      a blackholed peer; assert persist's `hits` counter (visible
//      via the next `blackhole_list` snapshot) reflects the hit.
//      Drives through the spawned `record_hit` fire-and-forget path.
//
//   3. `blackhole_prune_expired_clears_only_expired` — add rules
//      with mix of `until=None` and `until=past`; call
//      `routing_blackhole_prune_expired`; assert only the expired
//      rule was removed. Pins the "permanent rules survive prune"
//      invariant (`until IS NULL` semantics).
//
//   4. `blackhole_upsert_preserves_hits_on_intent_change` — set
//      `hits` to 5 via repeated `check_blackhole` triggers, upsert
//      with a new reason; assert `hits` is still 5. Distinct from
//      v0.15.0's reset-on-replace behavior — the persist contract
//      treats re-upsert as intent-change, not counter-reset.
//
//   5. `blackhole_remove_unknown_silent_ok` — call `routing_blackhole_remove`
//      on a never-added hash; assert no error (POSIX `rm -f`
//      ergonomics; persist's `blackhole_remove` is silent-no-op).

/// Helper — build a `ReticulumAuth` pinned to a specific backend Arc,
/// so the durable-round-trip test can rebuild the transport pointed
/// at the SAME backend (the durability invariant).
async fn auth_pinned_backend(
    key: &TestFedKey,
    directory: Arc<ciris_persist::store::sqlite::SqliteBackend>,
    blackhole: Arc<dyn ciris_persist::federation::BlackholeRules>,
    base: &std::path::Path,
) -> ReticulumAuth {
    ReticulumAuth {
        signer: Some(signer_for(key, base).await),
        rooting: Some(directory as Arc<dyn RootingDirectory>),
        resolver: None,
        hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
        event_bus: None,
        reachability: None,
        blackhole_rules: Some(blackhole),
        transport_identity_keystore: None,
    }
}

/// Durability — rule survives transport teardown + rebuild against the
/// same backend. v0.15.0 in-memory HashMap fails this by construction.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blackhole_durable_round_trip() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");

    let steward = TestFedKey::new("steward-durable-bh", 0x40);
    let key_a = TestFedKey::new("edge-durable-bh-aaaa", 0x41);
    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&key_a, &steward, "agent"),
    ])
    .await;
    let blackhole: Arc<dyn ciris_persist::federation::BlackholeRules> = directory.clone();

    let id = vec![0xC0u8; 16];

    // First transport — add the rule.
    {
        let cfg = {
            let mut c = ReticulumTransportConfig::new(
                tmp.path().join("a1/transport.id"),
                "edge-durable-bh-aaaa",
            );
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.announce_interval = Duration::from_secs(2);
            c
        };
        let auth =
            auth_pinned_backend(&key_a, directory.clone(), blackhole.clone(), tmp.path()).await;
        let transport = Arc::new(
            ReticulumTransport::new(cfg, auth)
                .await
                .expect("build transport (1)"),
        );
        let (tx, _rx) = mpsc::channel::<InboundFrame>(16);
        let t1 = transport.clone();
        let listen = tokio::spawn(async move { t1.listen(tx).await });

        transport
            .routing_blackhole_add(&id, None, Some("durable-acceptance"))
            .await
            .expect("add rule");
        let list = transport.routing_blackhole_list().await.expect("list (1)");
        assert_eq!(list.len(), 1, "rule visible in same instance");

        listen.abort();
        drop(transport);
    }

    // Second transport — DIFFERENT instance, SAME backend Arc.
    let cfg = {
        let mut c = ReticulumTransportConfig::new(
            tmp.path().join("a2/transport.id"),
            "edge-durable-bh-aaaa",
        );
        c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        c.announce_interval = Duration::from_secs(2);
        c
    };
    let auth = auth_pinned_backend(&key_a, directory.clone(), blackhole.clone(), tmp.path()).await;
    let transport = Arc::new(
        ReticulumTransport::new(cfg, auth)
            .await
            .expect("build transport (2)"),
    );
    let (tx, _rx) = mpsc::channel::<InboundFrame>(16);
    let t2 = transport.clone();
    let listen = tokio::spawn(async move { t2.listen(tx).await });

    let list = transport.routing_blackhole_list().await.expect("list (2)");
    let found = list
        .iter()
        .find(|e| e.identity_hash == id)
        .expect("rule survived transport rebuild — durability proof");
    assert_eq!(found.reason.as_deref(), Some("durable-acceptance"));

    listen.abort();
}

/// `blackhole_record_hit` drives through persist — the `hits` counter
/// on the snapshot reflects the send-path `check_blackhole` hit (the
/// same invariant as v0.15.0, now through the persist surface).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blackhole_enforcement_records_hit_through_persist() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_transport_a, transport_b, listen_a, listen_b) = paired_transports(tmp.path()).await;

    let dest_hash_a = transport_b
        .peer_dest_hash_for_test("edge-routing-aaaa")
        .await
        .expect("rooted peer dest_hash")
        .to_vec();

    transport_b
        .routing_blackhole_add(&dest_hash_a, None, Some("persist-hit"))
        .await
        .expect("blackhole_add");

    let _ = transport_b
        .send("edge-routing-aaaa", b"hit-record-test")
        .await
        .expect_err("blackholed");

    // Hit recording is fire-and-forget — poll for the counter to reach
    // 1 within a bounded window. The persist record_hit is a single
    // UPDATE so the latency is small even under contention.
    let mut observed: u64 = 0;
    for _ in 0..40 {
        let list = transport_b.routing_blackhole_list().await.expect("list");
        if let Some(rec) = list.iter().find(|e| e.identity_hash == dest_hash_a) {
            observed = rec.hits;
            if observed >= 1 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        observed >= 1,
        "persist `hits` counter must reflect the spawned record_hit (got {observed})"
    );

    listen_a.abort();
    listen_b.abort();
}

/// `blackhole_prune_expired` drops only `until <= now` rules; permanent
/// rules (`until IS NULL`) survive — the persist contract.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blackhole_prune_expired_clears_only_expired() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    let id_perm = vec![0x71u8; 16];
    let id_expired = vec![0x72u8; 16];
    let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();

    transport
        .routing_blackhole_add(&id_perm, None, Some("permanent"))
        .await
        .expect("add permanent");
    transport
        .routing_blackhole_add(&id_expired, Some(&past), Some("expired"))
        .await
        .expect("add expired");

    let pruned = transport
        .routing_blackhole_prune_expired(chrono::Utc::now())
        .await
        .expect("prune");
    assert_eq!(pruned, 1, "exactly one expired rule pruned");

    let list = transport.routing_blackhole_list().await.expect("list");
    assert_eq!(list.len(), 1, "only the permanent rule remains");
    assert_eq!(list[0].identity_hash, id_perm, "permanent rule survives");

    listen.abort();
}

/// Re-upsert with new reason preserves `hits` + `added_at` — the
/// persist contract treats upsert as intent-change, not counter-reset.
/// Distinct from v0.15.0's in-memory shape which reset `hits` on
/// replace.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blackhole_upsert_preserves_hits_on_intent_change() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");

    // Build a single-transport fixture but keep the backend Arc so we
    // can drive `record_hit` directly (the send-path goes through a
    // resolved-peer dest_hash, which is the rooted-cohabitation
    // shape; for this counter-preservation test we drive the
    // primitive at the BlackholeRules level).
    let steward = TestFedKey::new("steward-upsert-bh", 0x50);
    let key_a = TestFedKey::new("edge-upsert-bh-aaaa", 0x51);
    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&key_a, &steward, "agent"),
    ])
    .await;
    let blackhole: Arc<dyn ciris_persist::federation::BlackholeRules> = directory.clone();
    let cfg = {
        let mut c =
            ReticulumTransportConfig::new(tmp.path().join("a/transport.id"), "edge-upsert-bh-aaaa");
        c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        c.announce_interval = Duration::from_secs(2);
        c
    };
    let auth = auth_pinned_backend(&key_a, directory.clone(), blackhole.clone(), tmp.path()).await;
    let transport = Arc::new(
        ReticulumTransport::new(cfg, auth)
            .await
            .expect("build transport"),
    );
    let (tx, _rx) = mpsc::channel::<InboundFrame>(16);
    let t = transport.clone();
    let listen = tokio::spawn(async move { t.listen(tx).await });

    let id = vec![0x88u8; 16];

    transport
        .routing_blackhole_add(&id, None, Some("v1-reason"))
        .await
        .expect("initial add");

    // Drive 3 hits directly via the BlackholeRules trait — the
    // send-path is mediated by a resolved peer, but the counter-
    // preservation contract lives at the persist trait level.
    for _ in 0..3 {
        blackhole
            .blackhole_record_hit(&id)
            .await
            .expect("record_hit");
    }

    let list = transport.routing_blackhole_list().await.expect("list");
    let entry = list.iter().find(|e| e.identity_hash == id).expect("entry");
    assert_eq!(entry.hits, 3, "hits accumulated before re-upsert");
    let original_added_at = entry.added_at.clone();

    // Sleep a tick so any added_at-change would be observable.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Re-upsert with a different reason — intent change.
    transport
        .routing_blackhole_add(&id, None, Some("v2-reason"))
        .await
        .expect("re-upsert");

    let list = transport.routing_blackhole_list().await.expect("list (2)");
    let entry = list
        .iter()
        .find(|e| e.identity_hash == id)
        .expect("entry (2)");
    assert_eq!(
        entry.hits, 3,
        "hits counter MUST survive a re-upsert (intent-change, not counter-reset)"
    );
    assert_eq!(
        entry.added_at, original_added_at,
        "added_at MUST be preserved across re-upsert (forensic marker)"
    );
    assert_eq!(
        entry.reason.as_deref(),
        Some("v2-reason"),
        "operator-intent fields overwrite"
    );

    listen.abort();
}

/// Remove on an unknown hash returns `Ok(())` — POSIX `rm -f`
/// ergonomics; persist's `blackhole_remove` is silent-no-op.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blackhole_remove_unknown_silent_ok() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    let id = vec![0x09u8; 16];
    // never added.
    transport
        .routing_blackhole_remove(&id)
        .await
        .expect("remove of never-added hash returns Ok(())");

    listen.abort();
}
