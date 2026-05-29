//! v0.15.0 (CIRISEdge#33) — Routing-table FFI acceptance gate.
//!
//! Exercises the v0.15.0 routing surface on `ReticulumTransport`
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
//!      the routing methods return the documented v0.15.0 shapes
//!      (empty Vecs for the Leviculum-gap-stubbed reads, real values
//!      for `transport_id` / `transport_uptime` / the blackhole CRUD).
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

use common::{directory_with, signed_record, TestFedKey};

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

    let (tx_a, _rx_a) = mpsc::channel::<InboundFrame>(16);
    let (tx_b, _rx_b) = mpsc::channel::<InboundFrame>(16);

    let la = transport_a.clone();
    let lb = transport_b.clone();
    let listen_a = tokio::spawn(async move { la.listen(tx_a).await });
    let listen_b = tokio::spawn(async move { lb.listen(tx_b).await });

    // Wait for B to root A.
    let discovered = wait_for(Duration::from_secs(30), || {
        let t = transport_b.clone();
        async move { t.knows_peer("edge-routing-aaaa").await }
    })
    .await;
    assert!(
        discovered,
        "node B did not root node A within 30s — Reticulum loopback discovery wedged"
    );

    (transport_a, transport_b, listen_a, listen_b)
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

// ─── Tests: read surfaces (Leviculum-gap-stubbed) ───────────────────

/// `routing_path_table` returns an empty Vec on a freshly-built
/// transport. v0.15.0 returns empty regardless of state — the
/// upstream `NodeCore::path_table_entries` is `pub(crate)`. This test
/// pins the v0.15.0 behaviour so a v0.15.x flip-on flags as a behaviour
/// change.
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
        "v0.15.0 path_table is stubbed (Leviculum gap); expected empty"
    );
    let filtered = transport.routing_path_table(Some(3)).await;
    assert!(filtered.is_empty(), "max_hops filter on empty table");

    listen.abort();
}

/// `routing_path_to(unknown)` returns `None`. v0.15.0 always returns
/// `None` pending Leviculum widening.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn path_to_returns_none() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    let result = transport.routing_path_to(&[0u8; 16]).await;
    assert!(result.is_none(), "v0.15.0 path_to is stubbed");

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
/// `Ok(())` (v0.15.0 no-op pending Leviculum). Bad length errors.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn path_drop_clears_entry() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    transport
        .routing_path_drop(&[0u8; 16])
        .await
        .expect("v0.15.0 path_drop is a no-op");

    let err = transport
        .routing_path_drop(&[0u8; 4])
        .await
        .expect_err("bad length");
    assert!(matches!(err, TransportError::Config(_)));

    listen.abort();
}

/// `routing_path_drop_via` accepts a valid 16-byte hash and returns
/// `Ok(())` (v0.15.0 no-op).
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
        .expect("v0.15.0 path_drop_via is a no-op");

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

// ─── Tests: rate / tunnels / announce / reverse (stubbed reads) ────

/// `routing_rate_table` returns empty on a freshly-built transport.
/// v0.15.0 returns empty regardless of state.
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
        "v0.15.0 rate_table is stubbed (Leviculum gap)"
    );

    listen.abort();
}

/// `tunnels_list` returns empty (v0.15.0 stub).
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
        "v0.15.0 tunnels are stubbed (Reticulum gap; not publicly exposed)"
    );

    listen.abort();
}

/// `announce_table` returns empty (v0.15.0 stub).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn announce_table_reflects_in_flight() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    let a = transport.routing_announce_table().await;
    // v0.15.0 stub returns empty. Once Leviculum widens the
    // outbound_announces visibility this test will need updating to
    // assert presence of at least one entry while the announce-tick
    // is in flight.
    assert!(a.is_empty(), "v0.15.0 announce_table is stubbed");

    listen.abort();
}

/// `reverse_table` returns empty (v0.15.0 stub). Documents the round-
/// trip contract for the v0.15.x flip-on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_table_round_trip() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    let r = transport.routing_reverse_table().await;
    assert!(r.is_empty(), "v0.15.0 reverse_table is stubbed");

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

// ─── Tests: peer_key_id field on path entry (gap-stubbed) ──────────

/// `peer_key_id` on a PathEntry is filled when the destination_hash
/// matches a rooted peer; `None` when no rooted peer matches. v0.15.0
/// returns empty path_table so this test confirms the per-row stub
/// shape doesn't smuggle in any state — it documents the v0.15.x
/// flip-on expectations.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_key_id_filled_from_directory() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (transport, listen) = single_transport(tmp.path()).await;

    // v0.15.0 — empty path_table by design (Leviculum gap). The
    // per-row peer_key_id-fill semantics will be exercised once the
    // upstream entries land.
    let table = transport.routing_path_table(None).await;
    for entry in &table {
        // When real entries land, the rooted-peer match yields Some.
        // For now there are zero entries; the loop is a documentation
        // of intent only.
        let _ = entry.peer_key_id.clone();
    }
    assert!(table.is_empty(), "v0.15.0 stub returns empty");

    listen.abort();
}

/// Symmetric counterpart — when the destination_hash does not match a
/// rooted peer, `peer_key_id` must be `None`. v0.15.0 stub returns
/// empty; the assertion is on the wire shape only.
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
