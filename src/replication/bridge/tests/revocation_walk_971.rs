//! **CIRISEdge#971 — what the seat pays to list the Revocation plane for one
//! idle responder round.**
//!
//! With v45's bundle-seat mode every device keeps one Revocation round with
//! the seat (every 30 s once attributed). The seat's offer there is
//! `Projection::Global` (its self set and its cohort). The bytes on the wire
//! are small, but each listing builds that subject set and walks it per key
//! (`list_revocation_rows` → `key_plane_listing`). The #930 memo removes the
//! per-subject store read, not the walk.
//!
//! Measured here, at `K` subjects (8,700, about canonical-1's 8,698 keys, and
//! 17,400 to see whether it is linear):
//! - the cold fill (the first listing: one store read per subject);
//! - a warm listing's wall time, its store reads (probe pages and subject
//!   reads) and its width permits;
//! - N listings started together: the per-plane memo lock is held for the
//!   whole listing, so they serialize; the spread of their finish times is
//!   the lock wait.
//!
//! The memo's rebuild period is `key_plane_memo::MEMO_TTL`; a rebuild repeats
//! the cold fill. Figures are printed (`971 revocation-walk`); the assertions
//! pin only that a warm listing reads no subject from the store.
//!
//! The v45 per-listing read budget (`KEY_PLANE_READ_BUDGET`) spreads a cold
//! fill over many listings. This measures the walk and the lock with the
//! budget LIFTED, so the cold fill is still one listing; that the default
//! budget bounds the first listing is asserted at the end on its own bridge.
//!
//! `cargo test --lib revocation_walk_971 -- --nocapture --test-threads=1`
use super::*;

const PEER: &str = "device-971-walk";
/// Concurrent responder rounds in the lock-wait measurement.
const N_CONCURRENT: usize = 16;

fn sweep(m: &crate::observability::EdgeMetrics, label: &str) -> u64 {
    m.key_plane_sweep().get(label).copied().unwrap_or(0)
}

fn permits(m: &crate::observability::EdgeMetrics) -> u64 {
    m.sweep_permit_wait_seconds
        .read()
        .snapshot(crate::observability::SWEEP_PERMIT_WAIT_BUCKETS_SECONDS)
        .count
}

async fn measure(k: usize) {
    use crate::observability as obs;
    let cohort: Vec<String> = (0..k).map(|i| format!("walk-971-key-{i:06}")).collect();
    let (_backend, bridge) = test_fixtures::make_bridge(&cohort);
    let metrics = crate::observability::EdgeMetrics::new();
    let bridge = Arc::new(bridge.with_metrics(Some(metrics.clone())));
    bridge.set_key_plane_read_budget(usize::MAX);
    let list = |b: Arc<FederationDirectoryReplicationBridge>| async move {
        let t = std::time::Instant::now();
        let refs = b
            .list_envelope_refs_for_peer(EnvelopeKind::Revocation, Some(PEER))
            .await;
        (t.elapsed(), refs.len())
    };

    // Cold: the first listing fills the memo.
    let (r0, p0) = (
        sweep(&metrics, obs::KEY_PLANE_SUBJECT_READS),
        sweep(&metrics, obs::KEY_PLANE_PROBE_READS),
    );
    let w0 = permits(&metrics);
    let (cold, refs) = list(Arc::clone(&bridge)).await;
    let cold_subject_reads = sweep(&metrics, obs::KEY_PLANE_SUBJECT_READS) - r0;
    let cold_probes = sweep(&metrics, obs::KEY_PLANE_PROBE_READS) - p0;
    let cold_permits = permits(&metrics) - w0;

    // Warm: the steady-state idle listing, median of 9.
    let mut warm = Vec::new();
    let (r1, p1, w1) = (
        sweep(&metrics, obs::KEY_PLANE_SUBJECT_READS),
        sweep(&metrics, obs::KEY_PLANE_PROBE_READS),
        permits(&metrics),
    );
    for _ in 0..9 {
        warm.push(list(Arc::clone(&bridge)).await.0);
    }
    warm.sort();
    let warm_subject_reads = sweep(&metrics, obs::KEY_PLANE_SUBJECT_READS) - r1;
    let warm_probes = sweep(&metrics, obs::KEY_PLANE_PROBE_READS) - p1;
    let warm_permits = permits(&metrics) - w1;

    // N rounds together: the lock serializes them.
    let started = std::time::Instant::now();
    let handles: Vec<_> = (0..N_CONCURRENT)
        .map(|_| tokio::spawn(list(Arc::clone(&bridge))))
        .collect();
    let mut finished = Vec::new();
    for h in handles {
        let _ = h.await.expect("listing task");
        finished.push(started.elapsed());
    }
    finished.sort();
    let together = finished.last().copied().unwrap_or_default();

    eprintln!(
        "971 revocation-walk K={k}: refs={refs} cold_ms={} cold_subject_reads={cold_subject_reads} \
         cold_probe_reads={cold_probes} cold_permits={cold_permits} | warm_median_us={} \
         warm_max_us={} warm_subject_reads_per_listing={} warm_probe_reads_per_listing={} \
         warm_permits_per_listing={} | {N_CONCURRENT}_together_ms={} \
         (serial-equivalent {}us each) | memo_ttl_s={}",
        cold.as_millis(),
        warm[warm.len() / 2].as_micros(),
        warm[warm.len() - 1].as_micros(),
        warm_subject_reads as f64 / 9.0,
        warm_probes as f64 / 9.0,
        warm_permits as f64 / 9.0,
        together.as_millis(),
        together.as_micros() / N_CONCURRENT as u128,
        crate::replication::key_plane_memo::MEMO_TTL.as_secs(),
    );
    assert_eq!(
        cold_subject_reads,
        u64::try_from(k).expect("k"),
        "the cold fill reads every subject once"
    );
    assert_eq!(warm_subject_reads, 0, "a warm listing reads no subject");

    // The default budget: a cold seat's first listing reads at most the
    // budget, never all K at once.
    let (_backend, budgeted) = test_fixtures::make_bridge(&cohort);
    let budgeted_metrics = crate::observability::EdgeMetrics::new();
    let budgeted = Arc::new(budgeted.with_metrics(Some(budgeted_metrics.clone())));
    let _ = budgeted
        .list_envelope_refs_for_peer(EnvelopeKind::Revocation, Some(PEER))
        .await;
    assert_eq!(
        sweep(&budgeted_metrics, obs::KEY_PLANE_SUBJECT_READS),
        u64::try_from(k.min(crate::replication::key_plane_memo::KEY_PLANE_READ_BUDGET))
            .expect("budget"),
        "a cold listing reads at most the per-listing budget"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_revocation_walk_per_idle_round_at_canonical_scale_971() {
    measure(8_700).await;
    measure(17_400).await;
}
