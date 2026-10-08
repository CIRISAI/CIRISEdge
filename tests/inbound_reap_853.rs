//! **CIRISEdge#853 — the responder reaps an idle INBOUND link.** Two
//! Reticulum nodes on loopback; B dials A.
//!
//! #819's reap closes idle links in the DIALING node's pools. The canonical
//! is the responder for every other node's pool, and nothing on that side let
//! go of an inbound link that was idle at the application layer: the
//! initiator's keepalives kept it alive for good, and a peer whose pools never
//! shrink (pre-#819 edge, or an adversary) grew the canonical's link table
//! ~90 links/min toward leviculum's 1,024-link envelope.
//!
//! - (a) B dials A and goes quiet: A closes its inbound link after the bound
//!   (`inbound_link_closed_by_reason.idle_expired` = 1), B sees the link
//!   close, and B's next send re-dials and is delivered;
//! - (b) a link with an inbound transfer in progress is not reaped;
//! - (c) with the inbound bound at 0 the link stays open past the bound;
//! - (d) the gauges count one inbound link on A and one outbound on B.
#![cfg(feature = "transport-reticulum")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use ciris_edge::identity::LocalSigner;
use ciris_edge::transport::reticulum::{
    LinkDirection, ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport};
use ciris_edge::verify::RootingDirectory;
use tokio::sync::mpsc;

use common::{
    build_reticulum_with_retry_metrics, directory_with, prime_v7_peer_pair, signed_record,
    TestFedKey,
};

/// A's inbound idle bound. The `last_inbound` stamps are whole seconds, so a
/// link closes between `BOUND` and `BOUND + 1 s` after its last frame (plus a
/// reaper tick of `BOUND / 4`).
const BOUND: Duration = Duration::from_secs(2);

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
    metrics_a: ciris_edge::EdgeMetrics,
    metrics_b: ciris_edge::EdgeMetrics,
    rx_a: mpsc::Receiver<InboundFrame>,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
    _tmp: tempfile::TempDir,
}

/// A and B, primed with each other's route, both listening. A's inbound idle
/// bound is `inbound_bound` and its reaper ticks every `BOUND / 4`; B's pool
/// keeps its lanes for 600 s, so the only thing that can close B's link to A
/// is A.
async fn pair(tag: &str, inbound_bound: Duration) -> Pair {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=info")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let steward = TestFedKey::new(&format!("steward-853-{tag}"), 0x01);
    let key_a = TestFedKey::new(&format!("edge-a-853-{tag}"), 0x0a);
    let key_b = TestFedKey::new(&format!("edge-b-853-{tag}"), 0x0b);
    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&key_a, &steward, "agent"),
        signed_record(&key_b, &steward, "agent"),
    ])
    .await;
    let metrics_a = ciris_edge::EdgeMetrics::new();
    let (a, addr_a) = build_reticulum_with_retry_metrics(
        || {
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
        },
        metrics_a.clone(),
    )
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
    // Before `listen`: the reaper's cadence is fixed there. A's pool bound is
    // short only so its tick is (A has no pool); its inbound bound is the one
    // under test.
    a.set_link_pool_policy(BOUND, 4);
    a.set_inbound_link_idle_bound(inbound_bound);
    assert_eq!(a.inbound_link_idle_bound(), inbound_bound);
    b.set_link_pool_policy(Duration::from_secs(600), 4);
    prime_v7_peer_pair(&a, &key_a.key_id, &b, &key_b.key_id).await;
    let (tx_a, rx_a) = mpsc::channel::<InboundFrame>(256);
    let (tx_b, _rx_b) = mpsc::channel::<InboundFrame>(256);
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
        metrics_a,
        metrics_b,
        rx_a,
        _tasks: tasks,
        _tmp: tmp,
    }
}

async fn recv_one(rx: &mut mpsc::Receiver<InboundFrame>, what: &str) {
    tokio::time::timeout(Duration::from_secs(60), rx.recv())
        .await
        .unwrap_or_else(|_| panic!("{what}: timed out"))
        .unwrap_or_else(|| panic!("{what}: sink closed"));
}

/// The one inbound link on A (B's dial), once A's listener has recorded it.
async fn a_inbound_link(p: &Pair) -> [u8; 16] {
    let found = wait_for(Duration::from_secs(10), || async {
        p.a.link_directions_for_test()
            .iter()
            .any(|(_, d)| *d == LinkDirection::Inbound)
    })
    .await;
    assert!(
        found,
        "A records B's link as inbound: {:?}",
        p.a.link_directions_for_test()
    );
    let inbound: Vec<[u8; 16]> =
        p.a.link_directions_for_test()
            .into_iter()
            .filter(|(_, d)| *d == LinkDirection::Inbound)
            .map(|(id, _)| id)
            .collect();
    assert_eq!(inbound.len(), 1, "exactly one inbound link on A");
    inbound[0]
}

fn idle_expired(m: &ciris_edge::EdgeMetrics) -> u64 {
    m.inbound_link_closed_by_reason()["idle_expired"]
}

/// **(a) B dials A and goes quiet: A closes the link, B self-heals.** Fails
/// on v40.0.9, where nothing on A's side ever closes an inbound link: it
/// stays open for as long as B's keepalives run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_quiet_inbound_link_is_closed_by_the_responder_and_the_initiator_redials_853() {
    let mut p = pair("quiet", BOUND).await;
    let dest = p.a_key.clone();
    p.b.send(&dest, b"one frame, then quiet")
        .await
        .expect("send B -> A");
    recv_one(&mut p.rx_a, "A receives").await;
    let t0 = std::time::Instant::now();
    let link = a_inbound_link(&p).await;
    assert!(p.b.node_link_established_for_test(link), "B holds the link");

    let closed = wait_for(BOUND * 6, || async {
        p.a.link_direction_counts() == (0, 0) && idle_expired(&p.metrics_a) == 1
    })
    .await;
    assert!(
        closed,
        "A closes its idle inbound link after {BOUND:?}: directions {:?}, closes {:?}",
        p.a.link_directions_for_test(),
        p.metrics_a.inbound_link_closed_by_reason()
    );
    assert!(
        t0.elapsed() >= Duration::from_millis(1500),
        "not before the bound: closed {:?} after the frame",
        t0.elapsed()
    );
    assert!(
        !p.a.node_link_established_for_test(link),
        "closed at A's NODE, not just forgotten"
    );
    assert_eq!(
        p.metrics_a.inbound_links(),
        0,
        "A's inbound gauge drops to 0"
    );

    // B sees the close (LINKCLOSE), so its pool lets go of the lane.
    let b_saw = wait_for(Duration::from_secs(10), || async {
        !p.b.node_link_established_for_test(link) && p.b.pooled_link_counts_for_test().await.0 == 0
    })
    .await;
    assert!(
        b_saw,
        "B observes LinkClosed and drops the lane: established {}, pooled {:?}",
        p.b.node_link_established_for_test(link),
        p.b.pooled_link_counts_for_test().await
    );
    assert_eq!(
        p.metrics_b.link_pool_closed_by_reason()["link_closed"],
        1,
        "B counts its lane as closed by the far end"
    );

    // B's next send re-dials and is delivered.
    p.b.send(&dest, b"after the reap")
        .await
        .expect("B re-dials A after the responder closed the link");
    recv_one(&mut p.rx_a, "A receives after the reap").await;
    let fresh = a_inbound_link(&p).await;
    assert_ne!(fresh, link, "a new link");
    let reasons = p.metrics_a.inbound_link_closed_by_reason();
    assert_eq!(reasons["idle_expired"], 1, "{reasons:?}");
    assert_eq!(
        reasons["link_closed"], 0,
        "the reaped link's own LinkClosed event is not counted twice: {reasons:?}"
    );
}

/// **(b) A link with an inbound transfer in progress is not reaped.** The
/// link is marked receiving exactly as the event loop's
/// `ResourceTransferStarted` / `ResourceProgress` arms mark it, and held so
/// for three bounds: still open. Once the transfer concludes it is closed
/// after the bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_inbound_link_mid_transfer_is_not_reaped_853() {
    let mut p = pair("busy", BOUND).await;
    let dest = p.a_key.clone();
    p.b.send(&dest, b"one frame").await.expect("send B -> A");
    recv_one(&mut p.rx_a, "A receives").await;
    let link = a_inbound_link(&p).await;
    p.a.note_inbound_transfer_for_test(link, true);
    tokio::time::sleep(BOUND * 3).await;
    assert_eq!(
        p.a.link_direction_counts(),
        (1, 0),
        "a link mid-receive is busy: still open after three bounds"
    );
    assert!(p.a.node_link_established_for_test(link));
    assert_eq!(idle_expired(&p.metrics_a), 0, "nothing was reaped");

    p.a.note_inbound_transfer_for_test(link, false);
    let closed = wait_for(BOUND * 6, || async {
        idle_expired(&p.metrics_a) == 1 && !p.a.node_link_established_for_test(link)
    })
    .await;
    assert!(
        closed,
        "once the transfer is over, the idle link is reaped: {:?}",
        p.metrics_a.inbound_link_closed_by_reason()
    );
}

/// **(c) + (d) With the inbound bound at 0 the link stays open, and the
/// gauges count one inbound on A and one outbound on B.**
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_zero_bound_disables_the_reap_and_the_gauges_count_directions_853() {
    let mut p = pair("off", Duration::ZERO).await;
    let dest = p.a_key.clone();
    p.b.send(&dest, b"one frame").await.expect("send B -> A");
    recv_one(&mut p.rx_a, "A receives").await;
    let link = a_inbound_link(&p).await;

    // (d) — on both ends, in the transport and in the metrics bag.
    let counted = wait_for(Duration::from_secs(10), || async {
        p.a.link_direction_counts() == (1, 0)
            && p.b.link_direction_counts() == (0, 1)
            && p.metrics_a.inbound_links() == 1
            && p.metrics_a.outbound_links() == 0
            && p.metrics_b.inbound_links() == 0
            && p.metrics_b.outbound_links() == 1
    })
    .await;
    let (sa, sb) = (p.metrics_a.snapshot(), p.metrics_b.snapshot());
    assert!(
        counted,
        "A: {:?} in={} out={}; B: {:?} in={} out={}",
        p.a.link_direction_counts(),
        sa.inbound_links,
        sa.outbound_links,
        p.b.link_direction_counts(),
        sb.inbound_links,
        sb.outbound_links
    );
    assert_eq!(
        p.b.link_directions_for_test(),
        vec![(link, LinkDirection::Outbound)],
        "the same link, seen from the end that dialled it"
    );
    #[cfg(feature = "ffi-uniffi")]
    {
        use ciris_edge::EdgeLinkDirection;
        let on_a = p.a.link_list().await;
        assert_eq!(on_a.len(), 1);
        assert_eq!(on_a[0].direction, EdgeLinkDirection::Inbound);
        let on_b = p.b.link_list().await;
        assert_eq!(on_b.len(), 1);
        assert_eq!(on_b[0].direction, EdgeLinkDirection::Outbound);
    }

    // (c) — three bounds of quiet, with A's reaper ticking every BOUND / 4.
    tokio::time::sleep(BOUND * 3).await;
    assert_eq!(
        p.a.reap_idle_inbound_links().await,
        0,
        "a pass on demand closes nothing either"
    );
    assert_eq!(p.a.link_direction_counts(), (1, 0), "still open");
    assert!(p.a.node_link_established_for_test(link));
    assert!(p.b.node_link_established_for_test(link));
    assert_eq!(idle_expired(&p.metrics_a), 0, "the reap is off");
}
