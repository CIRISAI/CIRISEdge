//! Route-table end-to-end regression gate — the CIRISEdge#336/#337 saga's
//! tombstone. Every prior footgun of the rooting saga gets a named test here so
//! it can never silently bleed back.
//!
//! The route-table DECISION logic (verified-only supersession, the belt
//! reroute-heal, epoch monotonicity) is unit-tested exhaustively over the pure
//! `route_supersession_decision` in `src/transport/reticulum.rs`. This file
//! holds the LIVE-TRANSPORT regressions that need a real Leviculum node:
//!
//!   * the no-path GUARD — a send to an un-routable dest must fail FAST and
//!     LOUD (`NoRouteToPeer`, the self-diagnosing error naming the mismatch),
//!     never the silent 30-second `Timeout` that cost this saga days per round.
//!
//! Requires the `transport-reticulum` feature:
//! `cargo test --features transport-reticulum --test route_table_e2e`

#![cfg(feature = "transport-reticulum")]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use ciris_edge::identity::LocalSigner;
use ciris_edge::transport::reticulum::{ReticulumAuth, ReticulumTransportConfig};
use ciris_edge::transport::{InboundFrame, Transport, TransportError};
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
    Arc::new(LocalSigner::new(key.key_id.clone(), classical, None))
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

/// CIRISEdge#336 GUARD — a send to a rooted peer whose destination has NO route
/// must fail FAST with the self-diagnosing `NoRouteToPeer`, not stall the full
/// `LINK_ESTABLISH_TIMEOUT` (30 s) and surface an opaque `Timeout`.
///
/// This is the anti-whack-a-mole tripwire. Every round of the rooting saga cost
/// days because "send to a dest with no route" failed *silently* after 30 s and
/// shape-shifted into a dozen plausible-but-wrong causes. A no-path dest is
/// broadcast-only and answerable solely by a directly-attached neighbor in one
/// round-trip; if none answers within the short no-path window, no amount of
/// waiting helps — so we fail loud and immediately, naming the target dest, the
/// key_id, and the paths we DO hold.
///
/// The test injects a rooted peer on a fabricated dest that is reachable on no
/// interface (the sender has no bootstrap peer and no path to it), sends, and
/// asserts: (1) the error is `NoRouteToPeer` with the operands populated, and
/// (2) it returned in well under the 30 s establish timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_path_send_fails_fast_and_loud_not_a_silent_30s_timeout() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();

    let tmp = tempfile::tempdir().expect("tempdir");

    let steward = TestFedKey::new("steward-guard", 0x01);
    let sender = TestFedKey::new("edge-key-sender", 0x0a);
    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&sender, &steward, "agent"),
    ])
    .await;

    // A lone sender node — listens on loopback, has NO bootstrap peer, so it
    // holds a path to nothing.
    let (sender_transport, _addr) = build_reticulum_with_retry(|| {
        let key = &sender;
        let dir = directory.clone();
        let base = tmp.path().to_path_buf();
        async move {
            let mut c =
                ReticulumTransportConfig::new(base.join("s/transport.id"), "edge-key-sender");
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.announce_interval = Duration::from_secs(30);
            let auth = auth_for(key, dir, &base).await;
            (c, auth)
        }
    })
    .await;

    // Drive the event loop so `connect` can progress (and, crucially, so a
    // never-establishing link is observed as such rather than hanging).
    let (tx, _rx) = tokio::sync::mpsc::channel(16);
    let listener = sender_transport.clone();
    let _listen = tokio::spawn(async move { listener.listen(tx).await });

    // Inject a rooted peer on a FABRICATED dest reachable on no interface — the
    // exact shape of the #336 bug (a peer primed on an un-routable dest).
    let phantom_dest = [0xab; 16];
    let phantom_ed25519 = [0xcd; 32];
    sender_transport
        .inject_rooted_peer_for_test("edge-key-phantom", phantom_dest, phantom_ed25519)
        .await;
    assert!(
        sender_transport.knows_peer("edge-key-phantom").await,
        "peer must be rooted so the send reaches the connect/guard path",
    );

    // Send to the un-routable peer and time it.
    let started = Instant::now();
    let result = sender_transport
        .send("edge-key-phantom", b"payload that can never be routed")
        .await;
    let elapsed = started.elapsed();

    // (1) FAST — well under the 30 s LINK_ESTABLISH_TIMEOUT. The no-path window
    // is 5 s; allow generous CI slack but stay far below the patient timeout.
    assert!(
        elapsed < Duration::from_secs(20),
        "no-path send must fail fast (< 20 s), took {elapsed:?} — the silent 30 s \
         timeout is exactly the #336 footgun this guard exists to kill",
    );

    // (2) LOUD + self-diagnosing — `NoRouteToPeer`, not an opaque `Timeout`,
    // carrying the operands that name the mismatch at a glance.
    match result {
        Err(TransportError::NoRouteToPeer {
            key_id,
            target_dest,
            has_path,
            ..
        }) => {
            assert_eq!(key_id, "edge-key-phantom");
            assert_eq!(target_dest, hex::encode(phantom_dest));
            assert!(!has_path, "the whole point: the target had no path");
        }
        other => panic!(
            "expected NoRouteToPeer (fast, self-diagnosing); got {other:?} — a bare Timeout \
             here is the silent-failure regression the #336 guard must prevent",
        ),
    }
}

/// CIRISEdge#340 — a replication link MUST be IDENTIFIED by the initiator so the
/// responder can attribute the inbound frame to the sender's key_id. A Reticulum
/// link is anonymous by default; before this fix `send` established the link and
/// shipped the resource WITHOUT identifying, so every inbound frame landed on the
/// responder as `source_key_id=None` and dropped `SkippedNoSourceKeyId` (#317) —
/// the field-confirmed reason the #314 attribution machinery never fired and
/// CIRISServer#235 was never verified end-to-end.
///
/// The test reproduces the FIELD shape (an announce-rooted peer whose stored
/// `transport_identity_hash` is the REAL one, not the `[0;16]` sentinel that
/// `prime_v7_peer_pair` injects): B sends to A; A must attribute the inbound
/// frame to `edge-key-bbbb` via the link B identified. The assertion is on
/// `InboundFrame::source_key_id` — the exact operand that was `None` in the
/// field logs. Delivery alone (the existing loopback test) does not catch this;
/// attribution does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identified_link_lets_the_responder_attribute_the_inbound_frame() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();

    let tmp = tempfile::tempdir().expect("tempdir");

    let steward = TestFedKey::new("steward-340", 0x01);
    let key_a = TestFedKey::new("edge-key-aaaa", 0x0a);
    let key_b = TestFedKey::new("edge-key-bbbb", 0x0b);
    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&key_a, &steward, "agent"),
        signed_record(&key_b, &steward, "agent"),
    ])
    .await;

    // Node A — the receiver.
    let (transport_a, addr_a) = build_reticulum_with_retry(|| {
        let key = &key_a;
        let dir = directory.clone();
        let base = tmp.path().to_path_buf();
        async move {
            let mut c = ReticulumTransportConfig::new(base.join("a/transport.id"), "edge-key-aaaa");
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.announce_interval = Duration::from_secs(30);
            let auth = auth_for(key, dir, &base).await;
            (c, auth)
        }
    })
    .await;
    let port_a = addr_a.port();

    // Node B — the sender; dials A.
    let (transport_b, _addr_b) = build_reticulum_with_retry(|| {
        let key = &key_b;
        let dir = directory.clone();
        let base = tmp.path().to_path_buf();
        async move {
            let mut c = ReticulumTransportConfig::new(base.join("b/transport.id"), "edge-key-bbbb");
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.bootstrap_peers = vec![format!("127.0.0.1:{port_a}").parse().unwrap()];
            c.announce_interval = Duration::from_secs(30);
            let auth = auth_for(key, dir, &base).await;
            (c, auth)
        }
    })
    .await;

    // A must know B by B's REAL transport identity (the field shape), so the
    // identity B proves when it identifies the link matches A's stored hash and
    // attribution fires. B must know A's dest so the link can establish.
    transport_a
        .inject_rooted_peer_with_transport_identity_for_test(
            "edge-key-bbbb",
            transport_b.local_dest_hash(),
            transport_b.local_transport_pubkey(),
        )
        .await;
    let mut a_ed = [0u8; 32];
    a_ed.copy_from_slice(&transport_a.local_transport_pubkey()[32..64]);
    transport_b
        .inject_rooted_peer_for_test("edge-key-aaaa", transport_a.local_dest_hash(), a_ed)
        .await;

    let (tx_a, mut rx_a) = mpsc::channel::<InboundFrame>(16);
    let (tx_b, _rx_b) = mpsc::channel::<InboundFrame>(16);
    let la = transport_a.clone();
    let lb = transport_b.clone();
    let _listen_a = tokio::spawn(async move { la.listen(tx_a).await });
    let _listen_b = tokio::spawn(async move { lb.listen(tx_b).await });

    // B → A. The send identifies the link before shipping the resource.
    transport_b
        .send("edge-key-aaaa", b"attributed-inbound-frame")
        .await
        .expect("send B -> A");

    let frame = tokio::time::timeout(Duration::from_secs(60), rx_a.recv())
        .await
        .expect("frame must arrive within 60s")
        .expect("inbound channel open");

    assert_eq!(
        frame.source_key_id.as_deref(),
        Some("edge-key-bbbb"),
        "the responder must ATTRIBUTE the inbound frame to the sender via the \
         identified link — source_key_id=None is the #340 SkippedNoSourceKeyId drop",
    );
}

/// CIRISEdge#353 — the NAT'd / initiator-only reply leg, the asymmetric twin of
/// the #340 attribution test and the field shape of the first mobile trace
/// (Android emulator behind NAT ↔ Node A):
///
///   * B (the "phone") can dial A, but A CANNOT dial B — B is rooted at A on a
///     fabricated, un-routable dest (the strongest possible "structurally
///     unreachable outbound", the #336 guard's phantom shape) while carrying
///     B's REAL transport identity so link attribution still fires.
///   * B dials + identifies a link to A (its round-open).
///   * A's reply to B MUST ride that live inbound link (reverse path) — before
///     the fix this send fast-failed `NoRouteToPeer` (and in the field burned a
///     silent 30 s `Timeout` per kind per round, forever).
///   * The reply frame must arrive at B ATTRIBUTED to A — B never receives a
///     `LinkIdentified` for a link it initiated, so this exercises the
///     initiator-side `link_destination` attribution (leviculum v0.9.2), the
///     other half of #353. Unattributed would be the #317
///     `SkippedNoSourceKeyId` drop: delivered bytes, dead round.
#[tokio::test]
async fn reply_to_a_nat_d_initiator_rides_the_live_inbound_link() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=debug")
        .try_init();

    let tmp = tempfile::tempdir().expect("tempdir");

    let steward = TestFedKey::new("steward-353", 0x01);
    let key_a = TestFedKey::new("edge-key-aaaa", 0x0a);
    let key_b = TestFedKey::new("edge-key-bbbb", 0x0b);
    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&key_a, &steward, "agent"),
        signed_record(&key_b, &steward, "agent"),
    ])
    .await;

    // Node A — the canonical: dialable.
    let (transport_a, addr_a) = build_reticulum_with_retry(|| {
        let key = &key_a;
        let dir = directory.clone();
        let base = tmp.path().to_path_buf();
        async move {
            let mut c = ReticulumTransportConfig::new(base.join("a/transport.id"), "edge-key-aaaa");
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.announce_interval = Duration::from_secs(30);
            let auth = auth_for(key, dir, &base).await;
            (c, auth)
        }
    })
    .await;
    let port_a = addr_a.port();

    // Node B — the "phone": dials A. (Its listener exists but A is never
    // taught a routable dest for it, so A-side it is initiator-only.)
    let (transport_b, _addr_b) = build_reticulum_with_retry(|| {
        let key = &key_b;
        let dir = directory.clone();
        let base = tmp.path().to_path_buf();
        async move {
            let mut c = ReticulumTransportConfig::new(base.join("b/transport.id"), "edge-key-bbbb");
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.bootstrap_peers = vec![format!("127.0.0.1:{port_a}").parse().unwrap()];
            c.announce_interval = Duration::from_secs(30);
            let auth = auth_for(key, dir, &base).await;
            (c, auth)
        }
    })
    .await;

    // A roots B with B's REAL transport identity (so `LinkIdentified`
    // attribution fires) but a PHANTOM dest reachable on no interface — the
    // NAT model: A structurally cannot dial B.
    transport_a
        .inject_rooted_peer_with_transport_identity_for_test(
            "edge-key-bbbb",
            [0xab; 16],
            transport_b.local_transport_pubkey(),
        )
        .await;
    // B roots A on A's REAL dest — the phone can always dial out.
    let mut a_ed = [0u8; 32];
    a_ed.copy_from_slice(&transport_a.local_transport_pubkey()[32..64]);
    transport_b
        .inject_rooted_peer_for_test("edge-key-aaaa", transport_a.local_dest_hash(), a_ed)
        .await;

    let (tx_a, mut rx_a) = mpsc::channel::<InboundFrame>(16);
    let (tx_b, mut rx_b) = mpsc::channel::<InboundFrame>(16);
    let la = transport_a.clone();
    let lb = transport_b.clone();
    let _listen_a = tokio::spawn(async move { la.listen(tx_a).await });
    let _listen_b = tokio::spawn(async move { lb.listen(tx_b).await });

    // Leg 1 — the "round-open": B dials + identifies + ships to A.
    transport_b
        .send("edge-key-aaaa", b"round-open-from-the-phone")
        .await
        .expect("B -> A send (the phone's outbound leg) must deliver");
    let inbound_at_a = tokio::time::timeout(Duration::from_secs(60), rx_a.recv())
        .await
        .expect("A must receive B's frame within 60s")
        .expect("A inbound channel open");
    assert_eq!(
        inbound_at_a.source_key_id.as_deref(),
        Some("edge-key-bbbb"),
        "precondition (#340): A must attribute B's inbound link",
    );

    // Leg 2 — the REPLY: A -> B must ride B's live inbound link. Before the
    // fix this fast-failed NoRouteToPeer (phantom dest, no path).
    transport_a
        .send("edge-key-bbbb", b"reply-over-the-reverse-path")
        .await
        .expect(
            "A -> B reply MUST deliver over B's live inbound link (CIRISEdge#353) — \
             an outbound dial to a NAT'd initiator is structurally impossible",
        );

    // Leg 3 — attribution at B (initiator side): the reply must carry
    // source_key_id=A, else the replication registry drops it.
    let reply_at_b = tokio::time::timeout(Duration::from_secs(60), rx_b.recv())
        .await
        .expect("B must receive A's reply within 60s")
        .expect("B inbound channel open");
    assert_eq!(reply_at_b.envelope_bytes, b"reply-over-the-reverse-path");
    assert_eq!(
        reply_at_b.source_key_id.as_deref(),
        Some("edge-key-aaaa"),
        "the reply on B's own dialed link must be ATTRIBUTED via link_destination \
         (initiator-side half of CIRISEdge#353) — None is the #317 \
         SkippedNoSourceKeyId drop and the round dies delivered-but-dead",
    );
}
