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
use ciris_edge::transport::{Transport, TransportError};
use ciris_edge::verify::RootingDirectory;

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
