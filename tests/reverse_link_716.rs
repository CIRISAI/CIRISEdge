//! CIRISEdge#716 — a frame of MORE THAN ONE fragment sent over a reverse-path
//! link (the peer dialled us; we answer on the link it opened, #353) must land.
//!
//! Field signature (CIRISServer native harness, three processes on loopback):
//! every multi-fragment frame stalled at fragment 0 with
//! `stalled="link_send_error"`, while every single-fragment frame delivered.
//!
//! Root cause: `frame_fragment::fragment` was sized to the link's PACKET MDU
//! (`Link::mdu()`, 431 B at the 500 B base MTU), but the fragments ride the
//! link CHANNEL, whose MDU is six bytes smaller (the channel envelope header,
//! `Channel::mdu = link_mdu - CHANNEL_ENVELOPE_HEADER_SIZE`). Every full-size
//! fragment was refused `ChannelError::TooLarge`, which `send_on_link` reports
//! as `SendError::LinkFailed` — edge's `link_send_error`. A frame that fits in
//! one piece is sent unwrapped and is shorter than the channel MDU, so it went.
//!
//! The model is the #353 NAT shape: A knows B only on a PHANTOM (undialable)
//! destination, so an outbound-dial fallback cannot rescue the send — the frame
//! either rides the link B opened or it does not arrive.
//!
//! Requires the `transport-reticulum` feature:
//! `cargo test --features transport-reticulum --test reverse_link_716`

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

use common::{build_reticulum_with_retry, directory_with, signed_record, TestFedKey};

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

/// A pair where B dialled A and A can reach B ONLY over that link.
struct ReversePair {
    a: Arc<ReticulumTransport>,
    rx_b: mpsc::Receiver<InboundFrame>,
    _tmp: tempfile::TempDir,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

async fn reverse_pair(tag: &str) -> ReversePair {
    let tmp = tempfile::tempdir().expect("tempdir");
    let steward = TestFedKey::new(&format!("steward-716-{tag}"), 0x01);
    let key_a = TestFedKey::new("edge-key-aaaa", 0x0a);
    let key_b = TestFedKey::new("edge-key-bbbb", 0x0b);
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
            let mut c = ReticulumTransportConfig::new(base.join("a/transport.id"), "edge-key-aaaa");
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.announce_interval = Duration::from_secs(30);
            (c, auth_for(key, dir, &base).await)
        }
    })
    .await;
    let port_a = addr_a.port();
    let (transport_b, _addr_b) = build_reticulum_with_retry(|| {
        let key = &key_b;
        let dir = directory.clone();
        let base = tmp.path().to_path_buf();
        async move {
            let mut c = ReticulumTransportConfig::new(base.join("b/transport.id"), "edge-key-bbbb");
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.bootstrap_peers = vec![format!("127.0.0.1:{port_a}").parse().unwrap()];
            c.announce_interval = Duration::from_secs(30);
            (c, auth_for(key, dir, &base).await)
        }
    })
    .await;

    // A knows B only on a phantom dest (B's real transport identity, so the
    // link B opens is attributed to B): an outbound dial cannot reach B.
    transport_a
        .inject_rooted_peer_with_transport_identity_for_test(
            "edge-key-bbbb",
            [0xab; 16],
            transport_b.local_transport_pubkey(),
        )
        .await;
    let mut a_ed = [0u8; 32];
    a_ed.copy_from_slice(&transport_a.local_transport_pubkey()[32..64]);
    transport_b
        .inject_rooted_peer_for_test("edge-key-aaaa", transport_a.local_dest_hash(), a_ed)
        .await;

    let (tx_a, mut rx_a) = mpsc::channel::<InboundFrame>(16);
    let (tx_b, rx_b) = mpsc::channel::<InboundFrame>(16);
    let la = transport_a.clone();
    let lb = transport_b.clone();
    let tasks = vec![
        tokio::spawn(async move {
            let _ = la.listen(tx_a).await;
        }),
        tokio::spawn(async move {
            let _ = lb.listen(tx_b).await;
        }),
    ];

    // B dials A and ships (the round-open) — this is the link A answers on.
    transport_b
        .send("edge-key-aaaa", b"round-open-716")
        .await
        .expect("B -> A");
    tokio::time::timeout(Duration::from_secs(60), rx_a.recv())
        .await
        .expect("A receives B within 60s")
        .expect("A channel open");

    ReversePair {
        a: transport_a,
        rx_b,
        _tmp: tmp,
        _tasks: tasks,
    }
}

/// Deterministic payload of `len` bytes (not all-equal, so a mis-ordered or
/// mis-sized reassembly cannot compare equal).
fn payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i * 31 + i / 251) % 251).unwrap())
        .collect()
}

async fn expect_frame(rx: &mut mpsc::Receiver<InboundFrame>, want: &[u8], what: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let frame = tokio::time::timeout(left, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("B never received the {what} over the reverse link"))
            .expect("B inbound channel open");
        if frame.envelope_bytes == want {
            return;
        }
    }
}

/// The Channel leg in isolation: the resource ship is forced BUSY for the whole
/// retry window, so the frame can only arrive as CFRG fragments on the link
/// Channel. On main every fragment is 6 bytes over the Channel MDU and the send
/// stalls at fragment 0 (`link_send_error`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_fragment_frame_rides_the_reverse_link_channel_716() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let mut p = reverse_pair("chan").await;

    // ~3.4 KB — the issue's "small file row" (8 fragments at the 431 B MDU).
    let frame = payload(3_400);
    p.a.force_next_sends_busy_for_test(1_000);
    p.a.send("edge-key-bbbb", &frame)
        .await
        .expect("a multi-fragment frame must ride the reverse-path link Channel");
    expect_frame(&mut p.rx_b, &frame, "3.4 KB frame").await;
}

/// Channel-first (the default path for <= 8 fragments), no forcing: the frame
/// must land on the link B opened. Not a regression witness on its own — on an
/// IDLE link the pre-fix Channel stall fell through to the Resource path, which
/// delivered; in the field the link's one resource slot was occupied, so the
/// Resource fallback answered `Busy` and the frame's only interleave was the
/// broken Channel. The two forced-busy tests pin that shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn small_multi_fragment_frame_channel_first_716() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let mut p = reverse_pair("first").await;

    let frame = payload(1_200);
    p.a.send("edge-key-bbbb", &frame)
        .await
        .expect("a 3-fragment frame must deliver over the reverse-path link");
    expect_frame(&mut p.rx_b, &frame, "1.2 KB frame").await;
}

/// A ~200 KB frame (the issue's 470-fragment Attestation Deliver): the Resource
/// path first, as in production, immediately after the link came up. Passes on
/// main too: a Resource on a reverse-path link is not itself broken (#716's
/// Resource failures were the one-per-link `Busy` gate, see above).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_frame_rides_the_reverse_link_716() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let mut p = reverse_pair("large").await;

    let frame = payload(194_820);
    p.a.send("edge-key-bbbb", &frame)
        .await
        .expect("a ~200 KB frame must deliver over the reverse-path link");
    expect_frame(&mut p.rx_b, &frame, "~200 KB frame").await;
}

/// The same ~200 KB frame with the Resource path forced busy: it must land as
/// 470-odd Channel fragments (the issue's `0/470 landed` log line).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_frame_rides_the_reverse_link_channel_when_resource_busy_716() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();
    let mut p = reverse_pair("large-busy").await;

    let frame = payload(194_820);
    p.a.force_next_sends_busy_for_test(1_000);
    p.a.send("edge-key-bbbb", &frame).await.expect(
        "a ~200 KB frame must ride the reverse-path link Channel when the resource slot is busy",
    );
    expect_frame(&mut p.rx_b, &frame, "~200 KB frame (channel)").await;
}
