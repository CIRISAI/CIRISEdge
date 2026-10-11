//! **CIRISEdge#820 P1 — the sweep, peer-resolve and serve-tier histograms,
//! read where the host reads them.** A real `Edge` over Reticulum on
//! loopback, with a `ReplicationRuntime` started the way the bindings start
//! one: its metrics bag IS the `Edge`'s (`edge.metrics()`), never a bag the
//! test built. One start-up round per configured plane runs the production
//! measurement points: the advertise sweep (pages, rows), the attestation
//! plane's per-peer recipient resolution, and the serve-tier trust walk.
//!
//! Two readers, both production ones:
//! - the `Edge`'s own snapshot (`edge.metrics().snapshot()`, what the
//!   bindings' `metrics_snapshot` read);
//! - the `metrics` facade. A histogram takes samples, so it is recorded at
//!   its site on whatever worker runs the round; a thread-local recorder
//!   cannot see that. This binary installs ONE global `DebuggingRecorder`
//!   (its own binary, so nothing else shares it), and the facade's sample
//!   count must equal the bag's observation count for every histogram.
#![cfg(feature = "transport-reticulum")]

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ciris_edge::identity::LocalSigner;
use ciris_edge::replication::{
    EnvelopeKind, ReplicationPeer, ReplicationRuntime, ReplicationRuntimeConfig, SchedulerConfig,
};
use ciris_edge::transport::reticulum::{ReticulumAuth, ReticulumTransportConfig};
use ciris_edge::transport::Transport;
use ciris_edge::verify::{HybridPolicy, RootingDirectory};
use ciris_edge::{Edge, EdgeConfig};
use ciris_persist::federation::FederationDirectory;
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

use common::{build_reticulum_with_retry, directory_with, signed_record, TestFedKey};

const KEY_A: &str = "edge-hist-820-a";
const KEY_B: &str = "edge-hist-820-b";
const KINDS: [EnvelopeKind; 2] = [EnvelopeKind::Key, EnvelopeKind::Attestation];

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

/// The facade's histogram sample counts by name, summed over label sets,
/// from ONE snapshot (a snapshot may drain histogram samples).
fn facade_samples(snapshotter: &Snapshotter) -> HashMap<String, u64> {
    let mut out = HashMap::new();
    for (ck, _, _, v) in snapshotter.snapshot().into_vec() {
        if let DebugValue::Histogram(samples) = v {
            *out.entry(ck.key().name().to_owned()).or_insert(0) += samples.len() as u64;
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sweep_resolve_and_serve_tier_histograms_reach_both_production_readers() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder
        .install()
        .expect("the binary's one global recorder");
    // Facade baseline: a snapshot drains histogram samples, so everything
    // drained from here on was recorded after this point.
    let _ = facade_samples(&snapshotter);

    let tmp = tempfile::tempdir().expect("tempdir");
    let steward = TestFedKey::new("steward-hist-820", 0x01);
    let key_a = TestFedKey::new(KEY_A, 0x4a);
    let key_b = TestFedKey::new(KEY_B, 0x4b);
    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&key_a, &steward, "agent"),
        signed_record(&key_b, &steward, "agent"),
    ])
    .await;
    let (transport_a, _) = build_reticulum_with_retry(|| {
        let key = &key_a;
        let dir = directory.clone();
        let base = tmp.path().to_path_buf();
        async move {
            let mut c = ReticulumTransportConfig::new(base.join("a/transport.id"), KEY_A);
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.announce_interval = Duration::from_secs(60);
            let auth = ReticulumAuth {
                signer: Some(signer_for(key, &base).await),
                rooting: Some(dir as Arc<dyn RootingDirectory>),
                hybrid_policy: HybridPolicy::Ed25519Fallback,
                ..ReticulumAuth::default()
            };
            (c, auth)
        }
    })
    .await;
    let edge_a = Edge::builder()
        .directory(directory.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .queue(directory.clone())
        .signer(signer_for(&key_a, tmp.path()).await)
        .transport(transport_a.clone() as Arc<dyn Transport>)
        .reticulum_transport(transport_a.clone())
        .config(EdgeConfig {
            hybrid_policy: HybridPolicy::Ed25519Fallback,
            cohort_scope_enforcement: ciris_edge::CohortScopeEnforcement::Off,
            ..EdgeConfig::default()
        })
        .build()
        .expect("build edge");

    // Bag baseline, before the runtime starts: every assertion is a delta.
    let baseline = Counts::of(&edge_a.metrics().snapshot());

    // The bindings' wiring: the runtime counts into the Edge's own bag.
    let _runtime = ReplicationRuntime::start(
        directory.clone() as Arc<dyn FederationDirectory>,
        transport_a.clone() as Arc<dyn Transport>,
        KINDS
            .iter()
            .map(|k| ReplicationPeer {
                peer_key_id: KEY_B.to_owned(),
                kind: *k,
            })
            .collect(),
        ReplicationRuntimeConfig {
            scheduler: SchedulerConfig {
                cadence: Duration::from_secs(3600),
                round_timeout: Duration::from_secs(3),
                ..SchedulerConfig::default()
            },
            local_key_id: Some(KEY_A.to_owned()),
            serve_tier_subject_key_id: Some(KEY_A.to_owned()),
            metrics: Some(edge_a.metrics()),
            ..Default::default()
        },
        None,
    )
    .await;

    // The start-up tick runs one round per plane; wait for both to end.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let rounds: u64 = edge_a
            .metrics()
            .snapshot()
            .replication_round_outcomes_total
            .values()
            .sum();
        if rounds >= KINDS.len() as u64 || tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let grew = Counts::of(&edge_a.metrics().snapshot()).minus(&baseline);
    assert!(grew.pages > 0, "a sweep ran and was recorded: {grew:?}");
    assert_eq!(
        grew.pages, grew.rows,
        "pages and rows are recorded once per sweep, together"
    );
    assert!(
        grew.resolves > 0,
        "the attestation plane resolved its peer: {grew:?}"
    );
    assert!(
        grew.walks > 0,
        "the serve tier walked at least once: {grew:?}"
    );

    // The host's facade sees exactly the samples the bag counted. A sample
    // lands in the bag a few instructions before the facade, so the drained
    // total may trail by one for a moment: accumulate until it matches (the
    // round traffic is over; this converges at once), never loosen the match.
    let mut facade: HashMap<String, u64> = HashMap::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let grew = loop {
        for (name, n) in facade_samples(&snapshotter) {
            *facade.entry(name).or_insert(0) += n;
        }
        let grew = Counts::of(&edge_a.metrics().snapshot()).minus(&baseline);
        if grew.matches(&facade) || tokio::time::Instant::now() >= deadline {
            break grew;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    for (name, counted) in grew.by_name() {
        assert_eq!(
            facade.get(name).copied().unwrap_or(0),
            counted,
            "{name}: facade samples vs the Edge's snapshot delta"
        );
    }
}

/// Observation counts of the four P1c histograms in one bag snapshot.
#[derive(Debug, Clone, Copy)]
struct Counts {
    pages: u64,
    rows: u64,
    resolves: u64,
    walks: u64,
}

impl Counts {
    fn of(b: &ciris_edge::EdgeMetricsBundle) -> Self {
        Self {
            pages: b.sweep_pages.values().map(|h| h.count).sum(),
            rows: b.sweep_rows.values().map(|h| h.count).sum(),
            resolves: b.peer_resolve_seconds.values().map(|h| h.count).sum(),
            walks: b.serve_tier_refresh_seconds.count,
        }
    }

    fn minus(self, base: &Self) -> Self {
        Self {
            pages: self.pages - base.pages,
            rows: self.rows - base.rows,
            resolves: self.resolves - base.resolves,
            walks: self.walks - base.walks,
        }
    }

    fn by_name(self) -> [(&'static str, u64); 4] {
        [
            (ciris_edge::telemetry_catalog::SWEEP_PAGES, self.pages),
            (ciris_edge::telemetry_catalog::SWEEP_ROWS, self.rows),
            (ciris_edge::telemetry_catalog::PEER_RESOLVE, self.resolves),
            (
                ciris_edge::telemetry_catalog::SERVE_TIER_REFRESH,
                self.walks,
            ),
        ]
    }

    fn matches(self, facade: &HashMap<String, u64>) -> bool {
        self.by_name()
            .iter()
            .all(|(n, c)| facade.get(*n).copied().unwrap_or(0) == *c)
    }
}
