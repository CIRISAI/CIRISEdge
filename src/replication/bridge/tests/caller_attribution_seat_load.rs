//! Seat load 2026-11-13 (S0) — **in one binary, persist credits each edge read
//! to the site that made it.** The seat is a single Rust binary, and
//! `persist_reads` in `metrics_snapshot()` is the per-caller split v45.1.0
//! gives it. Over a real `SqliteBackend` (no double), a read through the
//! production feed probe is credited `edge.feed`, a read through the
//! production advertise history page `edge.advertise.history`, each on the
//! `list_attestations_since` door, and a read outside any scope lands
//! `unattributed`. (Across two Python wheels the label is lost: the capsule op
//! carries none; CIRISPersist#1270 ask 4.)
//!
//! persist's counters are process-wide, so each assertion reads a delta. Run
//! alone for the mutation: `cargo test --lib
//! a_seat_reads_its_store_under_each_sites_label_in_one_binary_seat_load`.
//! Mutation that turns it red: remove the `read_caller::scoped(Site::Feed, …)`
//! wrapper in `catch_up_attestation_feed` (or `Site::AdvertiseHistory` in
//! `attestation_page`).
use super::*;

const DOOR: &str = "list_attestations_since";

fn reads(caller: &str) -> u64 {
    crate::observability::persist_reads_snapshot()
        .get(&format!("{DOOR}:{caller}.reads"))
        .copied()
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_seat_reads_its_store_under_each_sites_label_in_one_binary_seat_load() {
    let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
    let dir: Arc<dyn FederationDirectory> = backend.clone();
    let cohort: CohortProvider = Arc::new(|| vec!["attr-node".to_owned()]);
    let bridge = FederationDirectoryReplicationBridge::with_config(
        dir,
        cohort,
        BridgeConfig {
            feed_probe_spacing: Duration::ZERO,
            ..BridgeConfig::default()
        },
    )
    .with_local_key_id(Some("attr-node".to_owned()));

    let feed = crate::read_caller::Site::Feed.label();
    let before = reads(feed);
    let _ = bridge.catch_up_attestation_feed(Instant::now(), None).await;
    assert!(
        reads(feed) > before,
        "the feed probe's read is credited {feed} on {DOOR}"
    );

    let history = crate::read_caller::Site::AdvertiseHistory.label();
    let before = reads(history);
    let _ = bridge
        .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some("attr-peer"))
        .await;
    assert!(
        reads(history) > before,
        "the advertise page's read is credited {history} on {DOOR}"
    );

    let unattributed = ciris_persist::observe::CALLER_UNATTRIBUTED;
    let before = reads(unattributed);
    let _ = backend.list_attestations_since(None, 10).await;
    assert!(
        reads(unattributed) > before,
        "a read outside any scope lands {unattributed}"
    );
}
