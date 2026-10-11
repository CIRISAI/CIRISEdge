//! **CIRISEdge#820 — counted drops and suppressed log lines, read where the
//! host reads them.** Two real `Edge`s over Reticulum on loopback. B sends A
//! malformed `CANN` announce frames over a real link; A's receive-side choke
//! point (`drop_inbound`) drops each as `announce_frame_malformed`.
//!
//! The witness is the PRODUCTION reader, not a bag the test built: A's
//! `Edge::metrics().snapshot()` (what the bindings' `metrics_snapshot` read)
//! and `Edge::publish_metrics()` under a recorder (what the host's `/metrics`
//! reads). It must show both the counted drops and the `reticulum.inbound_drop`
//! throttle's suppressed lines (its budget is 3 per reason per minute).
#![cfg(feature = "transport-reticulum")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use ciris_edge::identity::LocalSigner;
use ciris_edge::transport::reticulum::{ReticulumAuth, ReticulumTransportConfig};
use ciris_edge::transport::Transport;
use ciris_edge::verify::{HybridPolicy, RootingDirectory};
use ciris_edge::{Edge, EdgeConfig};
use metrics_util::debugging::{DebugValue, DebuggingRecorder};

use common::{
    build_reticulum_with_retry, directory_with, prime_v7_peer_pair, signed_record, TestFedKey,
};

/// How many malformed frames B sends: past the throttle's per-minute budget
/// of 3, so at least 2 lines are suppressed.
const FRAMES: u64 = 6;
const KEY_A: &str = "edge-drops-820-a";
const KEY_B: &str = "edge-drops-820-b";

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
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        ..ReticulumAuth::default()
    }
}

fn runtime(name: &str) -> Arc<tokio::runtime::Runtime> {
    Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .thread_name(name)
            .build()
            .expect("build runtime"),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_inbound_drops_and_suppressed_lines_reach_the_hosts_read() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=info")
        .try_init();
    let tmp = tempfile::tempdir().expect("tempdir");
    let steward = TestFedKey::new("steward-drops-820", 0x01);
    let key_a = TestFedKey::new(KEY_A, 0x3a);
    let key_b = TestFedKey::new(KEY_B, 0x3b);
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
            let mut c = ReticulumTransportConfig::new(base.join("a/transport.id"), KEY_A);
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.announce_interval = Duration::from_secs(2);
            (c, auth_for(key, dir, &base).await)
        }
    })
    .await;
    let port_a = addr_a.port();
    let (transport_b, _) = build_reticulum_with_retry(|| {
        let key = &key_b;
        let dir = directory.clone();
        let base = tmp.path().to_path_buf();
        async move {
            let mut c = ReticulumTransportConfig::new(base.join("b/transport.id"), KEY_B);
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.bootstrap_peers = vec![format!("127.0.0.1:{port_a}").parse().unwrap()];
            c.announce_interval = Duration::from_secs(2);
            (c, auth_for(key, dir, &base).await)
        }
    })
    .await;
    prime_v7_peer_pair(&transport_a, KEY_A, &transport_b, KEY_B).await;

    let build = |signer: Arc<LocalSigner>,
                 t: &Arc<ciris_edge::transport::reticulum::ReticulumTransport>| {
        Arc::new(
            Edge::builder()
                .directory(directory.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
                .queue(directory.clone())
                .signer(signer)
                .transport(t.clone() as Arc<dyn Transport>)
                .reticulum_transport(t.clone())
                .config(EdgeConfig {
                    hybrid_policy: HybridPolicy::Ed25519Fallback,
                    cohort_scope_enforcement: ciris_edge::CohortScopeEnforcement::Off,
                    ..EdgeConfig::default()
                })
                .build()
                .expect("build edge"),
        )
    };
    let edge_a = build(signer_for(&key_a, tmp.path()).await, &transport_a);
    let edge_b = build(signer_for(&key_b, tmp.path()).await, &transport_b);
    let (rt_a, rt_b) = (runtime("drops-820-a"), runtime("drops-820-b"));
    let _handles_a = edge_a.spawn_background_listeners(rt_a.handle());
    let _handles_b = edge_b.spawn_background_listeners(rt_b.handle());

    let suppressed_before = edge_a.metrics().snapshot().log_suppressed["reticulum.inbound_drop"];

    // A `CANN` frame that does not decode: magic, then a truncated body.
    let mut malformed = ciris_edge::transport::announce_frame::ANNOUNCE_FRAME_MAGIC.to_vec();
    malformed.extend_from_slice(&[1, 0, 0]);
    for _ in 0..FRAMES {
        transport_b
            .send(KEY_A, &malformed)
            .await
            .expect("B ships the frame to A");
    }

    // The production reader: A's own Edge snapshot.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let drops = loop {
        let n = edge_a
            .metrics()
            .snapshot()
            .transport_inbound_drops
            .get("announce_frame_malformed")
            .copied()
            .unwrap_or(0);
        if n >= FRAMES || tokio::time::Instant::now() >= deadline {
            break n;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(drops, FRAMES, "every malformed frame is a counted drop");
    let suppressed = edge_a.metrics().snapshot().log_suppressed["reticulum.inbound_drop"];
    assert!(
        suppressed >= suppressed_before + (FRAMES - 3),
        "the inbound-drop throttle's suppressed lines are counted: {suppressed_before} -> {suppressed}"
    );

    // The host's facade read: one `Edge::publish_metrics` under a recorder.
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || edge_a.publish_metrics());
    let series: Vec<_> = snapshotter.snapshot().into_vec();
    let value = |name: &str, key: &str, label: &str| {
        series.iter().find_map(|(ck, _, _, v)| {
            let k = ck.key();
            (k.name() == name && k.labels().any(|l| l.key() == key && l.value() == label))
                .then_some(v)
        })
    };
    assert_eq!(
        value(
            "ciris.edge.transport.inbound.drop",
            "reason",
            "announce_frame_malformed"
        ),
        Some(&DebugValue::Counter(FRAMES))
    );
    match value(
        "ciris.edge.log.suppressed",
        "site",
        "reticulum.inbound_drop",
    ) {
        Some(DebugValue::Counter(n)) => assert!(*n >= FRAMES - 3, "published suppressed: {n}"),
        other => panic!("ciris.edge.log.suppressed{{site=reticulum.inbound_drop}}: {other:?}"),
    }

    std::mem::forget(rt_a);
    std::mem::forget(rt_b);
}
