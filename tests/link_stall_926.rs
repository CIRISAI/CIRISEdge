//! **CIRISEdge#926 — the link stall guard.** Two Reticulum nodes on loopback;
//! B dials A, so A holds B's link to it (the reverse path, #353) and can also
//! dial B.
//!
//! Field incident (2026-10-31): on the reverse-path links a peer had opened,
//! every frame the other node sent stalled `0/N landed …
//! fragment_pacing_timeout`, and each round chose the same link again for
//! about fourteen minutes, until leviculum closed it `ChannelExhausted`.
//!
//! The seam (`stop_acks_on_link_for_test`) makes B "stop acknowledging" on that
//! one link, as A sees it: the Channel window never opens again, so each
//! fragment's pacing wait runs out, and the link's one Resource slot stays
//! held (`Busy`). A real ack drop on loopback would not do: leviculum
//! retransmits at loopback RTT and exhausts the Channel on its own in a few
//! seconds, which is not what a long-RTT field link did.
//!
//! - a link whose Channel sends land nothing is judged dead after three of
//!   them, closed, and the send (and the next) goes over a fresh link;
//! - a slow link whose sends land SOME fragments is never closed;
//! - a landed send ends the run, so stalls separated by a success never add
//!   up to three.
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
    b_key: String,
    a: Arc<ReticulumTransport>,
    metrics_a: ciris_edge::EdgeMetrics,
    rx_b: mpsc::Receiver<InboundFrame>,
    /// The link B opened to A and identified: A's reverse path to B.
    reverse: [u8; 16],
    _b: Arc<ReticulumTransport>,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
    _tmp: tempfile::TempDir,
}

/// A and B primed with each other, both listening, A's route to B healed to
/// B's announced destination (so A's dial to B is the one it keeps), and B's
/// link to A up, identified, and settled (nothing of A's still unacknowledged
/// on it, so no late delivery proof restarts a stall run under the witness).
async fn pair(tag: &str) -> Pair {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=info")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let steward = TestFedKey::new(&format!("steward-926-{tag}"), 0x01);
    let key_a = TestFedKey::new(&format!("edge-a-926-{tag}"), 0x0a);
    let key_b = TestFedKey::new(&format!("edge-b-926-{tag}"), 0x0b);
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
    let (b, _) = build_reticulum_with_retry(|| {
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
    })
    .await;
    prime_v7_peer_pair(&a, &key_a.key_id, &b, &key_b.key_id).await;
    let (tx_a, mut rx_a) = mpsc::channel::<InboundFrame>(256);
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
    let b_key = key_b.key_id.clone();
    let b_named = b.local_named_dest_hash();
    assert!(
        wait_for(Duration::from_secs(30), || {
            let a = Arc::clone(&a);
            let k = b_key.clone();
            async move { a.peer_dest_hash_for_test(&k).await == Some(b_named) }
        })
        .await,
        "A's route to B heals to B's announced destination"
    );

    // B dials A and ships: the link A answers on.
    b.send(&key_a.key_id, b"round-open-926")
        .await
        .expect("B -> A");
    tokio::time::timeout(Duration::from_secs(60), rx_a.recv())
        .await
        .expect("A receives B within 60s")
        .expect("A channel open");
    let reverse = settled_reverse_link(&a, &b_key).await;
    Pair {
        b_key,
        a,
        metrics_a,
        rx_b,
        reverse,
        _b: b,
        _tasks: tasks,
        _tmp: tmp,
    }
}

/// The one link B opened to A and identified (A's reverse path to B), once
/// A's Channel on it has nothing outstanding.
async fn settled_reverse_link(a: &Arc<ReticulumTransport>, b_key: &str) -> [u8; 16] {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let reverse = loop {
        let links = a.reverse_links_for_test(b_key).await;
        if links.len() == 1 {
            break links;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "A holds exactly one link B identified to it, got {links:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let reverse = reverse[0];
    assert!(
        wait_for(Duration::from_secs(30), || {
            let a = Arc::clone(a);
            async move { a.link_channel_settled_for_test(reverse) }
        })
        .await,
        "A's Channel on B's link settles"
    );
    reverse
}

fn payload(len: usize, salt: u8) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i * 31 + usize::from(salt)) % 251).unwrap())
        .collect()
}

async fn expect_frame(rx: &mut mpsc::Receiver<InboundFrame>, want: &[u8], what: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let frame = tokio::time::timeout(left, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("B never received the {what}"))
            .expect("B inbound channel open");
        if frame.envelope_bytes == want {
            return;
        }
    }
}

fn stall_count(m: &ciris_edge::EdgeMetrics, label: &str) -> u64 {
    m.link_stall().get(label).copied().unwrap_or(0)
}

/// **Dead link → closed → fresh link.** With B acknowledging nothing on its
/// link, A's send goes reverse-path first exactly as in the field: Channel
/// first (0/1 landed), the Resource slot `Busy`, the Channel again from the
/// busy-retry. The third zero-landing Channel send makes the link dead: it is
/// closed at the node, and the send falls through to a fresh dial and
/// delivers. The NEXT send never touches the dead link: no pacing stall, no
/// busy-retry window, straight onto the fresh link.
///
/// Without the guard the first send still delivers (over a dial, after the
/// 8 s busy-retry window), but the dead link stays open and the next send
/// pays the stall and the window again: the fourteen minutes of the field.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_that_lands_nothing_is_closed_and_the_next_send_redials_926() {
    let mut p = pair("dead").await;
    let dead = p.reverse;
    p.a.stop_acks_on_link_for_test(dead, Some(0));

    // Each send rides the dead link first (Channel, then the busy-retry's
    // Channel) until three zero-landing sends make it dead; how many of them
    // fit one send's busy-retry window depends on the clock, so up to three
    // sends, each of which must still deliver over a fresh link.
    for salt in 1..=3u8 {
        let frame = payload(200, salt);
        p.a.send(&p.b_key, &frame)
            .await
            .expect("the send falls through to a fresh link and delivers");
        expect_frame(&mut p.rx_b, &frame, "frame sent while the link was dead").await;
        if !p.a.node_link_established_for_test(dead) {
            break;
        }
    }
    assert!(
        !p.a.node_link_established_for_test(dead),
        "the link that landed nothing is closed at the node"
    );
    let (zero_sends, is_dead) = p.a.link_stall_for_test(dead);
    assert!(is_dead, "the guard judged the link dead");
    assert_eq!(zero_sends, 3, "after exactly three zero-landing sends");
    assert_eq!(
        stall_count(&p.metrics_a, ciris_edge::observability::LINK_STALL_CLOSED),
        1,
        "one link closed, counted: {:?}",
        p.metrics_a.link_stall()
    );
    assert_eq!(
        stall_count(
            &p.metrics_a,
            ciris_edge::observability::LINK_STALL_ZERO_LANDED_SEND
        ),
        3,
        "{:?}",
        p.metrics_a.link_stall()
    );
    let fresh = p.a.pooled_link_ids_for_test().await;
    assert!(
        !fresh.is_empty() && !fresh.contains(&dead),
        "A dialled a fresh link to B: {fresh:?}"
    );

    // The next send rides the fresh link without touching the dead one: well
    // under one pacing stall (3 s) plus the busy-retry window (8 s).
    let second = payload(200, 9);
    let t = std::time::Instant::now();
    p.a.send(&p.b_key, &second)
        .await
        .expect("the next send delivers");
    let took = t.elapsed();
    expect_frame(&mut p.rx_b, &second, "frame after the close").await;
    assert!(
        took < Duration::from_secs(7),
        "the next send never stalled on the dead link (took {took:?})"
    );
    assert_eq!(
        stall_count(
            &p.metrics_a,
            ciris_edge::observability::LINK_STALL_ZERO_LANDED_SEND
        ),
        3,
        "no Channel send went to the dead link again"
    );
}

/// **A slow link is not dead.** B's window opens for one fragment of each
/// frame and then stays shut past the pacing bound, so every Channel send on
/// the link stops short, but each lands something. Across the whole
/// busy-retry window (Channel first, then the Channel from each busy-retry)
/// the run never starts and the link stays open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_link_that_lands_some_fragments_is_not_closed_926() {
    let mut p = pair("slow").await;
    let slow = p.reverse;
    p.a.stop_acks_on_link_for_test(slow, Some(1));

    // Three fragments at the link's Channel MDU (within the Channel-first
    // cap), so each send lands 1 of 3 and then waits out the pacing bound.
    let mdu = p.a.channel_fragment_bytes_for_test(slow);
    assert!(mdu > 0, "the link has a Channel MDU");
    let frame = payload(mdu * 5 / 2, 3);
    let t = std::time::Instant::now();
    p.a.send(&p.b_key, &frame)
        .await
        .expect("the send delivers (over a dial once the busy-retry window ends)");
    assert!(
        t.elapsed() >= Duration::from_secs(7),
        "the send rode the slow link's Channel through the whole busy-retry window \
         (took {:?})",
        t.elapsed()
    );
    expect_frame(
        &mut p.rx_b,
        &frame,
        "frame sent over the slow link's window",
    )
    .await;

    assert!(
        p.a.node_link_established_for_test(slow),
        "a link that lands some fragments is never closed"
    );
    assert_eq!(p.a.link_stall_for_test(slow), (0, false));
    assert_eq!(
        stall_count(&p.metrics_a, ciris_edge::observability::LINK_STALL_CLOSED),
        0,
        "{:?}",
        p.metrics_a.link_stall()
    );
    assert_eq!(
        stall_count(
            &p.metrics_a,
            ciris_edge::observability::LINK_STALL_ZERO_LANDED_SEND
        ),
        0
    );
}

/// **A landed send resets the guard.** Two zero-landing sends, then one that
/// lands (the peer acknowledges again), then two more: four stalls, never
/// three in a row, and the link stays open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_landed_send_resets_the_stall_run_926() {
    let p = pair("reset").await;
    let link = p.reverse;
    let frame = payload(200, 4);

    p.a.stop_acks_on_link_for_test(link, Some(0));
    for _ in 0..2 {
        let (sent, total) = p.a.send_channel_for_test(link, &frame).await;
        assert_eq!((sent, total), (0, 1));
    }
    assert_eq!(p.a.link_stall_for_test(link), (2, false));

    p.a.stop_acks_on_link_for_test(link, None);
    let (sent, total) = p.a.send_channel_for_test(link, &frame).await;
    assert_eq!((sent, total), (1, 1), "the restored link lands the frame");
    assert_eq!(
        p.a.link_stall_for_test(link),
        (0, false),
        "the landed send ended the run"
    );
    // Its delivery proof arrives before the next stall, so the witness reads
    // the landed-send rule, not a proof landing mid-run.
    assert!(
        wait_for(Duration::from_secs(30), || {
            let a = Arc::clone(&p.a);
            async move { a.link_channel_settled_for_test(link) }
        })
        .await,
        "the landed frame is acknowledged"
    );

    p.a.stop_acks_on_link_for_test(link, Some(0));
    for _ in 0..2 {
        let (sent, _) = p.a.send_channel_for_test(link, &frame).await;
        assert_eq!(sent, 0);
    }
    assert_eq!(p.a.link_stall_for_test(link), (2, false));
    assert!(
        p.a.node_link_established_for_test(link),
        "four stalls never three in a row: the link stays open"
    );
    assert_eq!(
        stall_count(&p.metrics_a, ciris_edge::observability::LINK_STALL_CLOSED),
        0
    );
}
