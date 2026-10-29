//! Startup probe: time each phase a node pays before it is ready, so a
//! release-over-release regression names its phase. Run it in an optimized
//! build, several runs, and read the median — a single run, or a debug build,
//! measures the host's load as much as edge:
//! `STARTUP_PROBE_RUNS=7 cargo test --release --features transport-reticulum
//! --test startup_probe -- --ignored --nocapture`. Each run prints one
//! `STARTUP_PROBE {json}` line; the Bench workflow takes the per-phase median.
//!
//! Phases:
//! - `db_fresh_ms`: open a new file-backed SQLite directory and run every
//!   migration (a first boot);
//! - `db_reopen_ms`: reopen that file and run migrations again (a restart);
//! - `transport_cold_ms`: `ReticulumTransport::new` with no identity on disk;
//! - `self_route_ms`: from the cold build returning until the node's own
//!   signed route row is in the directory (when it can be reached at all);
//! - `transport_warm_ms`: `ReticulumTransport::new` again over the same
//!   identity file (a restart).

#![cfg(feature = "transport-reticulum")]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use ciris_edge::identity::LocalSigner;
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::verify::RootingDirectory;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::SignedKeyRecord;
use ciris_persist::store::sqlite::SqliteBackend;
use ciris_persist::store::Backend as _;

use common::{signed_record, TestFedKey};

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

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

async fn one_run(run: usize) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db = tmp.path().join("edge.db");
    let db_path = db.to_string_lossy().to_string();

    let t = Instant::now();
    let fresh = SqliteBackend::open(db_path.clone()).await.expect("open");
    let db_open = t.elapsed();
    fresh.run_migrations().await.expect("migrate");
    let db_fresh = t.elapsed();
    let db_migrate = db_fresh - db_open;
    drop(fresh);

    let t = Instant::now();
    let reopened = SqliteBackend::open(db_path).await.expect("reopen");
    reopened.run_migrations().await.expect("migrate again");
    let db_reopen = t.elapsed();
    let dir = Arc::new(reopened);

    let steward = TestFedKey::new("steward-probe", 0x01);
    let key = TestFedKey::new("edge-probe", 0x0a);
    for rec in [
        signed_record(&steward, &steward, "steward"),
        signed_record(&key, &steward, "agent"),
    ] {
        dir.put_public_key(SignedKeyRecord { record: rec })
            .await
            .expect("put key");
    }
    let signer = signer_for(&key, tmp.path()).await;
    let config = || {
        let mut c =
            ReticulumTransportConfig::new(tmp.path().join("t/transport.id"), key.key_id.as_str());
        c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        c
    };
    let auth = || ReticulumAuth {
        signer: Some(signer.clone()),
        rooting: Some(dir.clone() as Arc<dyn RootingDirectory>),
        resolver: None,
        hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
        ..ReticulumAuth::default()
    };

    let t = Instant::now();
    let cold = ReticulumTransport::new(config(), auth())
        .await
        .expect("cold build");
    let transport_cold = t.elapsed();

    let t = Instant::now();
    let mut self_route = None;
    while t.elapsed() < Duration::from_secs(20) {
        if !dir
            .list_signed_transport_destinations_for(&key.key_id)
            .await
            .unwrap_or_default()
            .is_empty()
        {
            self_route = Some(t.elapsed());
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    drop(cold);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let t = Instant::now();
    let warm = ReticulumTransport::new(config(), auth())
        .await
        .expect("warm build");
    let transport_warm = t.elapsed();
    drop(warm);

    println!(
        "STARTUP_PROBE {{\"run\":{run},\"db_open_ms\":{:.1},\"db_migrate_ms\":{:.1},\"db_fresh_ms\":{:.1},\"db_reopen_ms\":{:.1},\
         \"transport_cold_ms\":{:.1},\"self_route_ms\":{},\"transport_warm_ms\":{:.1}}}",
        ms(db_open),
        ms(db_migrate),
        ms(db_fresh),
        ms(db_reopen),
        ms(transport_cold),
        self_route.map_or("null".to_owned(), |d| format!("{:.1}", ms(d))),
        ms(transport_warm),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "startup probe: run explicitly with --ignored --nocapture"]
async fn startup_probe() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()))
        .with_test_writer()
        .try_init();
    let runs: usize = std::env::var("STARTUP_PROBE_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    for run in 0..runs {
        one_run(run).await;
    }
}
