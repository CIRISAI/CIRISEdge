//! **CIRISEdge#820 — the publish pipe emits, end to end.** A real (loopback)
//! Reticulum transport with an attached `EdgeMetrics` bag; one
//! `Transport::refresh_metrics` call under a `DebuggingRecorder` must land
//! BOTH leviculum's series and edge's in the recorder. A green catalogue gate
//! with a dead publish call is the failure this rules out.
#![cfg(feature = "transport-reticulum")]

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use ciris_edge::transport::reticulum::{ReticulumAuth, ReticulumTransportConfig};
use ciris_edge::transport::Transport;
use metrics_util::debugging::DebuggingRecorder;

use common::{build_reticulum_with_retry_metrics, TestFedKey};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

/// A federation signer for `key`: a Reticulum transport refuses to build
/// without one (every announce is self-attested, CIRISEdge#333).
async fn signer_for(
    key: &TestFedKey,
    base: &std::path::Path,
) -> Arc<ciris_edge::identity::LocalSigner> {
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
    Arc::new(ciris_edge::identity::LocalSigner::new(
        key.key_id.clone(),
        classical,
        Some(pqc),
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_metrics_lands_leviculum_and_edge_series_in_the_recorder() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let key = TestFedKey::new("edge-telemetry-820", 0x20);
    let bag = ciris_edge::EdgeMetrics::new();
    let (transport, _) = build_reticulum_with_retry_metrics(
        || {
            let base = tmp.path().to_path_buf();
            let key = &key;
            async move {
                let mut c = ReticulumTransportConfig::new(base.join("transport.id"), &key.key_id);
                c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
                c.announce_interval = Duration::from_secs(60);
                let auth = ReticulumAuth {
                    signer: Some(signer_for(key, &base).await),
                    ..ReticulumAuth::default()
                };
                (c, auth)
            }
        },
        bag.clone(),
    )
    .await;
    // Something for the bag to say, so edge's series carry a value.
    bag.inc_recovered_links();
    bag.observe_sweep_permit_wait(Duration::from_millis(5));

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || transport.refresh_metrics());
    let names: BTreeSet<String> = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .map(|(ck, _, _, _)| ck.key().name().to_owned())
        .collect();

    let leviculum: Vec<&String> = names
        .iter()
        .filter(|n| n.starts_with("leviculum."))
        .collect();
    let edge: Vec<&String> = names
        .iter()
        .filter(|n| n.starts_with("ciris.edge."))
        .collect();
    assert!(
        !leviculum.is_empty(),
        "no leviculum series reached the recorder: {names:?}"
    );
    assert!(
        !edge.is_empty(),
        "no edge series reached the recorder: {names:?}"
    );
    assert!(
        names.contains("ciris.edge.link.recovered"),
        "the bag's own counter is published: {edge:?}"
    );
    // Leviculum's names are its catalogue's (its completeness is delegated to
    // leviculum's own gate; this pins that the delegation holds at the pin).
    for n in &leviculum {
        assert!(
            leviculum_std::telemetry::METRIC_CATALOG
                .iter()
                .any(|s| s.name == n.as_str()),
            "{n} is not in leviculum's METRIC_CATALOG"
        );
    }
    // Every edge name is in edge's catalogue.
    for n in &edge {
        assert!(
            ciris_edge::telemetry_catalog::METRIC_CATALOG
                .iter()
                .any(|s| s.name == n.as_str()),
            "{n} is not in edge's METRIC_CATALOG"
        );
    }
}
