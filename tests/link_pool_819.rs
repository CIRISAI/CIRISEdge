//! **CIRISEdge#819 — the dial pool shrinks.** Two Reticulum nodes on
//! loopback; B dials A.
//!
//! The pools (#531/#532 identity, #739 scoped) grow to demand and, before
//! #819, let go of a link only when it CLOSED. Edge is the initiator on these
//! links, so its keepalives kept every idle lane open for good: each
//! concurrency peak toward a peer left its extra lanes behind, and the
//! canonical's established links climbed ~1,024 per 35 min.
//!
//! - a burst of concurrent sends to one peer leaves at most the idle cap of
//!   lanes pooled once it is over, and none after the idle bound;
//! - a busy lane is never closed, however long it is busy.
#![cfg(feature = "transport-reticulum")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use ciris_edge::identity::LocalSigner;
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport};
use ciris_edge::verify::RootingDirectory;
use tokio::sync::mpsc;

use common::{
    build_reticulum_with_retry, build_reticulum_with_retry_metrics, directory_with,
    prime_v7_peer_pair, signed_record, TestFedKey,
};

const IDLE_BOUND: Duration = Duration::from_secs(3);
const IDLE_CAP: usize = 1;
const BURST: usize = 8;

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
    let pqc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(key.pqc_signer());
    Arc::new(LocalSigner::new(key.key_id.clone(), classical, Some(pqc)))
}

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

struct Pair {
    a_key: String,
    a: Arc<ReticulumTransport>,
    b: Arc<ReticulumTransport>,
    metrics_b: ciris_edge::EdgeMetrics,
    rx_a: mpsc::Receiver<InboundFrame>,
    b_key: String,
    rx_b: mpsc::Receiver<InboundFrame>,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
    _tmp: tempfile::TempDir,
}

/// A and B, primed with each other's route, B's pool bounded at
/// `IDLE_BOUND` / `IDLE_CAP`, both listening (B's listen loop runs the reaper).
async fn pair(tag: &str) -> Pair {
    pair_with(tag, IDLE_BOUND).await
}

/// [`pair`] with B's idle bound at `bound` (the reaper's cadence follows it).
async fn pair_with(tag: &str, bound: Duration) -> Pair {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=info")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let steward = TestFedKey::new(&format!("steward-819-{tag}"), 0x01);
    let key_a = TestFedKey::new(&format!("edge-a-819-{tag}"), 0x0a);
    let key_b = TestFedKey::new(&format!("edge-b-819-{tag}"), 0x0b);
    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&key_a, &steward, "agent"),
        signed_record(&key_b, &steward, "agent"),
    ])
    .await;
    let (a, addr_a) = build_reticulum_with_retry(|| {
        let key = &key_a;
        let dir = directory.clone();
        let base = tmp.path().to_path_buf();
        async move {
            let mut c = ReticulumTransportConfig::new(base.join("a/transport.id"), &key.key_id);
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.announce_interval = Duration::from_secs(2);
            let auth = auth_for(key, dir, &base).await;
            (c, auth)
        }
    })
    .await;
    let port_a = addr_a.port();
    let metrics_b = ciris_edge::EdgeMetrics::new();
    let (b, _) = build_reticulum_with_retry_metrics(
        || {
            let key = &key_b;
            let dir = directory.clone();
            let base = tmp.path().to_path_buf();
            async move {
                let mut c = ReticulumTransportConfig::new(base.join("b/transport.id"), &key.key_id);
                c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
                c.bootstrap_peers = vec![format!("127.0.0.1:{port_a}").parse().unwrap()];
                c.announce_interval = Duration::from_secs(2);
                let auth = auth_for(key, dir, &base).await;
                (c, auth)
            }
        },
        metrics_b.clone(),
    )
    .await;
    // Before `listen`, so the reaper's cadence follows the short bound.
    b.set_link_pool_policy(bound, IDLE_CAP);
    assert_eq!(b.link_pool_policy(), (bound, IDLE_CAP));
    prime_v7_peer_pair(&a, &key_a.key_id, &b, &key_b.key_id).await;
    let (tx_a, rx_a) = mpsc::channel::<InboundFrame>(256);
    let (tx_b, rx_b) = mpsc::channel::<InboundFrame>(256);
    let (la, lb) = (Arc::clone(&a), Arc::clone(&b));
    let tasks = vec![
        tokio::spawn(async move {
            let _ = la.listen(tx_a).await;
        }),
        tokio::spawn(async move {
            let _ = lb.listen(tx_b).await;
        }),
    ];
    assert!(b.knows_peer(&key_a.key_id).await, "B knows A after priming");
    Pair {
        a_key: key_a.key_id.clone(),
        a,
        b,
        metrics_b,
        rx_a,
        b_key: key_b.key_id.clone(),
        rx_b,
        _tasks: tasks,
        _tmp: tmp,
    }
}

/// **A burst leaves at most the cap behind, and nothing after the bound.**
/// Eight concurrent sends B→A dial parallel lanes (one Resource per link);
/// once they are done B's pool holds at most `IDLE_CAP` lanes, and after
/// `IDLE_BOUND` of quiet it holds none and the lanes are closed. Fails on
/// v40.0.6, where every lane the burst dialed stays pooled and open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_leaves_at_most_the_idle_cap_and_none_after_the_bound_819() {
    let mut p = pair("burst").await;
    let dest = p.a_key.clone();
    let body = vec![0x5au8; 256 * 1024];
    let sends = (0..BURST).map(|_| {
        let b = Arc::clone(&p.b);
        let dest = dest.clone();
        let body = body.clone();
        tokio::spawn(async move { b.send(&dest, &body).await })
    });
    for s in futures::future::join_all(sends).await {
        s.expect("send task").expect("send B -> A");
    }
    let mut got = 0;
    while got < BURST {
        tokio::time::timeout(Duration::from_secs(60), p.rx_a.recv())
            .await
            .expect("A receives the burst")
            .expect("A's sink open");
        got += 1;
    }
    let (pooled, _) = p.b.pooled_link_counts_for_test().await;
    let closed = p.b.pooled_links_closed();
    assert!(
        pooled + usize::try_from(closed).unwrap() >= 2,
        "the burst needed parallel lanes (pooled {pooled} + closed {closed}); a burst \
         carried on one lane would not exercise the pool"
    );
    assert!(
        pooled <= IDLE_CAP,
        "right after the burst B keeps at most {IDLE_CAP} idle lane(s) to A, not every \
         lane the burst dialed: {pooled} pooled"
    );
    let drained = wait_for(IDLE_BOUND * 4, || async {
        p.b.pooled_link_counts_for_test().await.0 == 0 && p.b.link_count().await == 0
    })
    .await;
    assert!(
        drained,
        "after {IDLE_BOUND:?} of quiet B's pool is empty and its dialed links are closed: \
         pooled {:?}, established {}",
        p.b.pooled_link_counts_for_test().await,
        p.b.link_count().await
    );
    // The telemetry tells the same story (CIRISServer#746): what the burst
    // left over the cap closed as `pool_full`, the rest as `idle_expired`, and
    // the pool gauges read zero once the reaper has run on the empty pool.
    let reaped = wait_for(IDLE_BOUND * 2, || async {
        p.metrics_b.snapshot().link_pool_links == 0
    })
    .await;
    let bundle = p.metrics_b.snapshot();
    let by = |r: &str| bundle.link_pool_closed_by_reason.get(r).copied();
    assert!(reaped, "the pool-size gauge returns to 0: {bundle:?}");
    assert_eq!(bundle.link_pool_max_per_destination, 0);
    assert_eq!(
        by("pool_full").unwrap_or(0) + by("idle_expired").unwrap_or(0),
        p.b.pooled_links_closed(),
        "every close the transport made is in the bundle, by reason"
    );
    assert!(
        by("idle_expired").unwrap_or(0) >= 1,
        "the last idle lane closed for idleness: {:?}",
        bundle.link_pool_closed_by_reason
    );
    assert_eq!(
        by("link_closed"),
        Some(0),
        "every reason token is present, and no pooled link closed on its own"
    );
}

/// **A busy lane is never closed.** B dials A once; the lane is then held
/// busy (as a transfer in flight holds it) for three idle bounds and is still
/// pooled and open. Released, it is closed after the bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_busy_lane_is_never_reaped_819() {
    let mut p = pair("busy").await;
    let dest = p.a_key.clone();
    p.b.send(&dest, b"one lane").await.expect("send B -> A");
    tokio::time::timeout(Duration::from_secs(60), p.rx_a.recv())
        .await
        .expect("A receives")
        .expect("A's sink open");
    assert_eq!(
        p.b.pooled_link_counts_for_test().await.0,
        1,
        "one lane pooled"
    );
    assert_eq!(p.b.hold_pooled_links_busy_for_test(true).await, 1);
    tokio::time::sleep(IDLE_BOUND * 3).await;
    assert_eq!(
        p.b.pooled_link_counts_for_test().await.0,
        1,
        "a busy lane is still pooled after three idle bounds"
    );
    assert_eq!(p.b.link_count().await, 1, "and still open");
    assert_eq!(p.b.pooled_links_closed(), 0, "nothing was closed");
    p.b.hold_pooled_links_busy_for_test(false).await;
    let drained = wait_for(IDLE_BOUND * 4, || async {
        p.b.pooled_link_counts_for_test().await.0 == 0
    })
    .await;
    assert!(drained, "released, it is reaped once idle past the bound");
    let bundle = p.metrics_b.snapshot();
    assert_eq!(
        bundle.link_pool_closed_by_reason.get("idle_expired"),
        Some(&1),
        "the one lane closed for idleness, once released"
    );
}

async fn recv_one(rx: &mut mpsc::Receiver<InboundFrame>, what: &str) -> InboundFrame {
    tokio::time::timeout(Duration::from_secs(60), rx.recv())
        .await
        .unwrap_or_else(|_| panic!("{what}: timed out"))
        .unwrap_or_else(|| panic!("{what}: sink closed"))
}

/// **Codex on #821, finding 1 — a lane handed out is RESERVED until its
/// sender owns the transfer.** B holds two idle lanes to A under a cap of 2;
/// a send takes one from the pool (the `reusable_link_to` hand-out), the cap
/// drops to 1, and before the sender claims its lane another transfer
/// releases the other lane, which applies the cap. The handed-out lane must
/// survive: it is the one a sender is about to ship on. Fails on 03277e3,
/// where the hand-out only stamped the lane: the release stamped the other
/// one newer, and the cap trim closed the lane that had just been handed out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lane_handed_out_is_not_trimmed_before_its_sender_claims_it_819() {
    let mut p = pair("handout").await;
    // A long bound: only the cap is under test.
    p.b.set_link_pool_policy(Duration::from_secs(600), 2);
    let dest = p.a_key.clone();
    // The pool is per DESTINATION. A's first announce heals B's primed route
    // to A's announced destination, and lanes dialed either side of that heal
    // sit in two different pools; wait for it, so both lanes share one pool.
    let named = p.a.local_named_dest_hash();
    let healed = wait_for(Duration::from_secs(30), || async {
        p.b.peer_dest_hash_for_test(&dest).await == Some(named)
    })
    .await;
    assert!(healed, "B routes to A's announced destination");
    p.b.send(&dest, b"lane one").await.expect("send 1");
    recv_one(&mut p.rx_a, "A receives send 1").await;
    // Hold lane one busy so the second send dials lane two.
    assert_eq!(p.b.hold_pooled_links_busy_for_test(true).await, 1);
    p.b.send(&dest, b"lane two").await.expect("send 2");
    recv_one(&mut p.rx_a, "A receives send 2").await;
    p.b.hold_pooled_links_busy_for_test(false).await;
    let lanes = p.b.pooled_link_ids_for_test().await;
    assert_eq!(lanes.len(), 2, "two idle lanes pooled under a cap of 2");
    assert_eq!(
        p.b.peer_dest_hash_for_test(&dest).await,
        Some(named),
        "both lanes were dialed to the one destination"
    );

    let taken =
        p.b.take_pooled_link_for_test(&dest)
            .await
            .expect("a send takes an idle lane");
    let other = *lanes.iter().find(|l| **l != taken).expect("the other lane");
    p.b.set_link_pool_policy(Duration::from_secs(600), 1);
    // Another transfer ends on the other lane: the release applies the cap.
    p.b.release_link_for_test(other).await;

    assert!(
        p.b.pooled_link_ids_for_test().await.contains(&taken),
        "the lane handed to a sender is still pooled"
    );
    assert!(
        p.b.node_link_established_for_test(taken),
        "and still open: the sender ships on it next"
    );
    p.b.release_link_for_test(taken).await;
}

/// **Codex on #821, finding 5 — a pooled victim is closed at the NODE even
/// if the listener has not mirrored it as established.** The lane's entry in
/// the listener's `established_links` mirror is dropped (as when its
/// `LinkEstablished` event has not been processed yet); once it is idle past
/// the bound the reaper takes it out of the pool and closes it, and the node
/// must no longer hold it. Fails on 03277e3: `link_teardown` returned early on
/// the mirror, so the lane left the pool, was counted closed, and stayed open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reaped_lane_closes_at_the_node_without_the_mirror_819() {
    let mut p = pair("mirror").await;
    let dest = p.a_key.clone();
    p.b.send(&dest, b"one lane").await.expect("send");
    recv_one(&mut p.rx_a, "A receives").await;
    let lane =
        *p.b.pooled_link_ids_for_test()
            .await
            .first()
            .expect("one lane pooled");
    p.b.forget_established_mirror_for_test(lane).await;
    let closed = wait_for(IDLE_BOUND * 4, || async {
        !p.b.node_link_established_for_test(lane)
    })
    .await;
    assert!(
        p.b.pooled_link_ids_for_test().await.is_empty(),
        "the reaper took the idle lane out of the pool"
    );
    assert!(
        closed,
        "and closed it at the node, though the listener's mirror never listed it"
    );
}

/// **Codex on #821, finding 4 — a lane carrying an INBOUND transfer is busy.**
/// B dials A (one pooled lane). Just before that lane's idle bound runs out,
/// A sends B a 6 MiB envelope on it (A's reverse path rides the link B
/// dialed). B's reaper must not close the lane while the transfer is still
/// arriving: B receives the whole envelope, and the lane is open after it.
/// Fails on 03277e3, where only outbound transfers counted as busy: the reaper
/// closed the lane mid-receive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_inbound_transfer_keeps_its_lane_from_the_reaper_819() {
    // A 1 s bound puts B's reaper on a 250 ms cadence, so a pass is certain
    // to land while the transfer is still arriving.
    const BOUND: Duration = Duration::from_secs(1);
    let mut p = pair_with("inbound", BOUND).await;
    let dest = p.a_key.clone();
    p.b.send(&dest, b"dial the lane").await.expect("B -> A");
    recv_one(&mut p.rx_a, "A receives").await;
    let lane =
        *p.b.pooled_link_ids_for_test()
            .await
            .first()
            .expect("one lane pooled");
    // Let the lane age to just under its bound, then start the transfer.
    // 800 ms: 200 ms short of `BOUND`.
    tokio::time::sleep(Duration::from_millis(800)).await;
    let body = vec![0x3cu8; 8 * 1024 * 1024 - 4096];
    let len = body.len();
    let a = Arc::clone(&p.a);
    let b_key = p.b_key.clone();
    let started = tokio::time::Instant::now();
    let send = tokio::spawn(async move { a.send(&b_key, &body).await });
    let frame = recv_one(&mut p.rx_b, "B receives A's envelope").await;
    let took = started.elapsed();
    let open_after = p.b.node_link_established_for_test(lane);
    send.await
        .expect("A's send task")
        .expect("A's send completes");
    assert_eq!(frame.envelope_bytes.len(), len);
    assert_eq!(
        p.a.pooled_link_counts_for_test().await.0,
        0,
        "A answered on B's lane (the reverse path) rather than dialing its own"
    );
    assert!(
        took > Duration::from_millis(200) + BOUND / 4 * 2,
        "the transfer must outlast the lane's remaining idle time plus two reaper \
         ticks for this to test anything (took {took:?})"
    );
    assert!(
        open_after,
        "the lane that carried the inbound transfer is still open"
    );
}
