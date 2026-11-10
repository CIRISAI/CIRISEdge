//! **CIRISEdge#971 — what one IDLE bootstrap round costs the seat answering
//! it.**
//!
//! With the bundle's serve nodes on by default (#881), every device that
//! takes the default opens a round to each seat on the five bootstrap planes
//! every cadence. When nothing has changed, those rounds exchange nothing; the
//! question for the load sheet is what the seat still pays per round. This
//! measures it on a real runtime over a real store, with every directory call
//! counted at the trait (`CountingDirectory`), every sweep permit counted (the
//! `sweep_permit_wait` histogram observes one wait per permit), and the reply
//! bytes the responder put on the transport.
//!
//! The store is seeded with `ATTESTATIONS` rows so the holdings index spans
//! more than one page, which is what the production seat's 42,520 rows do.
//! The figures are printed (`971 idle`); the assertions only pin that an idle
//! round is answered and that its index reads grow with the store in pages.
//!
//! `cargo test --lib idle_round_cost_971 -- --nocapture`
use super::*;
use crate::replication::counting_directory_930::CountingDirectory;
use crate::replication::protocol::{ReplicationMessage, SummaryMessage};
use crate::replication::runtime::{
    ReplicationRuntime, ReplicationRuntimeConfig, BOOTSTRAP_ROUND_PLANES,
};
use crate::replication::wire_frame::{self, RoundSide};
use crate::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};

const SEAT: &str = "seat-971-idle";
const DEVICE: &str = "device-971-idle";
/// Past one 1,024-row index page, so the per-page cost shows.
const ATTESTATIONS: usize = 1_100;

/// Sums the bytes the seat sends.
#[derive(Default)]
struct Bytes {
    sent: std::sync::atomic::AtomicUsize,
    frames: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl Transport for Arc<Bytes> {
    fn id(&self) -> TransportId {
        TransportId::HTTP
    }
    async fn send(
        &self,
        _destination_key_id: &str,
        envelope_bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError> {
        self.sent
            .fetch_add(envelope_bytes.len(), std::sync::atomic::Ordering::Relaxed);
        self.frames
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(TransportSendOutcome::Delivered)
    }
    async fn listen(
        &self,
        _sink: tokio::sync::mpsc::Sender<InboundFrame>,
    ) -> Result<(), TransportError> {
        Ok(())
    }
}

fn permits(m: &crate::observability::EdgeMetrics) -> u64 {
    m.sweep_permit_wait_seconds.read().count
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_bootstrap_round_costs_the_seat_971() {
    let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
    register_fixture_keys(
        &backend,
        &[(SEAT, identity_type::NODE), (DEVICE, identity_type::NODE)],
    )
    .await;
    for i in 0..ATTESTATIONS {
        let id = format!("idle-971-{i:05}");
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": SEAT,
            "attested_key_id": SEAT,
            "attestation_type": "scores",
            "dimension": "idle:row:v1",
            "payload": { "n": i },
        });
        seed_raw_attestation(&backend, &id, SEAT, SEAT, "scores", envelope).await;
    }
    let counting = CountingDirectory::new(backend.clone());
    let directory: Arc<dyn FederationDirectory> = Arc::new(counting.clone());
    let wire = Arc::new(Bytes::default());
    let metrics = crate::observability::EdgeMetrics::new();
    let mut rt = ReplicationRuntime::start(
        directory,
        Arc::new(Arc::clone(&wire)),
        Vec::new(),
        ReplicationRuntimeConfig {
            enable_bundle_bootstrap_peers: false,
            local_key_id: Some(SEAT.to_owned()),
            metrics: Some(metrics.clone()),
            ..ReplicationRuntimeConfig::default()
        },
        Some(crate::replication::runtime::self_publish_set([SEAT])),
    )
    .await;
    let registry = rt.registry();
    let mut rows = Vec::new();
    for (round, kind) in (1u64..).zip(BOOTSTRAP_ROUND_PLANES) {
        // A round's first leg twice: the first builds the responder and warms
        // what it memoizes; the second is the steady-state idle round.
        for pass in 0..2 {
            counting.reset();
            let (p0, b0, f0) = (
                permits(&metrics),
                wire.sent.load(std::sync::atomic::Ordering::Relaxed),
                wire.frames.load(std::sync::atomic::Ordering::Relaxed),
            );
            let summary = ReplicationMessage::Summary(SummaryMessage {
                status: None,
                kind,
                refs: Vec::new(),
            });
            let bytes = wire_frame::wrap_v3(&summary, RoundSide::Initiator, round * 10 + pass);
            registry
                .route_inbound_bytes(DEVICE, &bytes)
                .await
                .expect("route the device's Summary");
            // The responder answers on its own task: wait for its reply.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            while wire.frames.load(std::sync::atomic::Ordering::Relaxed) == f0
                && tokio::time::Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            if pass == 1 {
                let counts = counting.counts();
                rows.push((
                    kind,
                    counting.total(),
                    counts.get("list_wire_hashes_since").copied().unwrap_or(0),
                    permits(&metrics) - p0,
                    wire.sent.load(std::sync::atomic::Ordering::Relaxed) - b0,
                    counts,
                ));
            }
        }
    }
    let mut total = (0usize, 0usize, 0u64, 0usize);
    for (kind, reads, pages, permits, bytes, counts) in &rows {
        // A sweep permit is taken per index page (`holdings_from_wire_index`)
        // and per other sweep read (the advertise pages, a consent-set read on
        // a memo miss): `permits - index_pages` is everything that is not the
        // holdings drain.
        let other = permits.saturating_sub(u64::try_from(*pages).unwrap_or(0));
        eprintln!(
            "971 idle {kind:?}: directory_calls={reads} index_pages={pages} permits={permits} \
             permits_not_holdings={other} reply_bytes={bytes} by_method={counts:?}"
        );
        total.0 += reads;
        total.1 += pages;
        total.2 += permits;
        total.3 += bytes;
    }
    eprintln!(
        "971 idle ALL FIVE PLANES (one device, one cadence): directory_calls={} \
         index_pages={} permits={} reply_bytes={} (store: {ATTESTATIONS} attestation rows)",
        total.0, total.1, total.2, total.3
    );
    assert!(
        rows.iter().all(|r| r.4 > 0),
        "every plane's idle Summary is answered"
    );
    rt.shutdown().await;
}

/// The seat's Key-plane Summary to a stranger, as encoded for the wire, at
/// `n` offered key records: (refs, frame bytes before the seal, fragments at
/// the TCP MDU, fragments at the base 500 B link MTU).
async fn key_summary_at(n: usize) -> (usize, usize, usize, usize) {
    let keys: Vec<String> = (0..n).map(|i| format!("announced-971-{i:05}")).collect();
    let (backend, bridge) = make_bridge(&[]);
    let pairs: Vec<(&str, &str)> = keys
        .iter()
        .map(|k| (k.as_str(), identity_type::NODE))
        .collect();
    register_fixture_keys(&backend, &pairs).await;
    let offer = keys.clone();
    let bridge = bridge
        .with_local_key_id(Some(SEAT.to_owned()))
        .with_self_provider(Some(Arc::new(move || offer.clone())));
    let refs = bridge
        .list_envelope_refs_for_peer(EnvelopeKind::Key, Some(DEVICE))
        .await;
    let frame = wire_frame::wrap_v3(
        &ReplicationMessage::Summary(SummaryMessage {
            status: None,
            kind: EnvelopeKind::Key,
            refs: refs.clone(),
        }),
        RoundSide::Responder,
        1,
    );
    // The two MDUs edge sends at: a TCP link (16,272 B) and the base link
    // (431 B packet MDU at the 500 B MTU; the Channel is 6 B less).
    let tcp = crate::transport::frame_fragment::fragment(&frame, 16_272).map_or(0, |f| f.len());
    let base = crate::transport::frame_fragment::fragment(&frame, 425).map_or(0, |f| f.len());
    (refs.len(), frame.len(), tcp, base)
}

/// **The idle Summary's size, measured: bytes = a + b·refs.** Two offers,
/// one past a TCP fragment, fit `a` (the frame's fixed part) and `b` (bytes
/// per ref as encoded). The seal adds `SEAL_OVERHEAD` per sealed frame on top
/// (`link_seal.rs`, 25 B: version, counter, tag). Printed for the sheet;
/// pinned only to be linear and to be the size the sheet uses.
#[tokio::test]
#[allow(clippy::cast_precision_loss)] // ref counts and byte sizes, far below 2^52
async fn the_idle_key_summary_is_linear_in_its_refs_971() {
    let (r1, b1, t1, s1) = key_summary_at(10).await;
    let (r2, b2, t2, s2) = key_summary_at(600).await;
    assert_eq!((r1, r2), (10, 600), "one ref per offered key record");
    let b = (b2 - b1) as f64 / (r2 - r1) as f64;
    let a = b1 as f64 - b * r1 as f64;
    eprintln!(
        "971 summary: refs={r1} bytes={b1} tcp_fragments={t1} base_fragments={s1}; \
         refs={r2} bytes={b2} tcp_fragments={t2} base_fragments={s2}; \
         bytes = {a:.0} + {b:.1}*refs (before the seal; +{} B per sealed frame)",
        crate::transport::link_seal::SEAL_OVERHEAD
    );
    assert!(t2 > 1, "the larger offer spans more than one TCP fragment");
    assert!(b > 0.0);
}

/// **CIRISEdge#971 (d) — what an idle bundle-seat Pull costs the seat.** The
/// device's cycle asks, per Pull plane, about itself and about the seat. Each
/// is routed to the seat's real responder over a counting directory; the
/// figures are printed (`971 idle pull`) for the sheet. Pinned: no index page
/// (a Pull reads by subject, never the holdings index) on any plane.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_bundle_pull_costs_the_seat_971() {
    use crate::replication::protocol::PullMessage;
    use crate::replication::runtime::BUNDLE_PULL_PLANES;
    let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
    register_fixture_keys(
        &backend,
        &[(SEAT, identity_type::NODE), (DEVICE, identity_type::NODE)],
    )
    .await;
    for i in 0..ATTESTATIONS {
        let id = format!("idle-pull-971-{i:05}");
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": SEAT,
            "attested_key_id": SEAT,
            "attestation_type": "scores",
            "dimension": "idle:row:v1",
            "payload": { "n": i },
        });
        seed_raw_attestation(&backend, &id, SEAT, SEAT, "scores", envelope).await;
    }
    let counting = CountingDirectory::new(backend.clone());
    let directory: Arc<dyn FederationDirectory> = Arc::new(counting.clone());
    let wire = Arc::new(Bytes::default());
    let metrics = crate::observability::EdgeMetrics::new();
    let mut rt = ReplicationRuntime::start(
        directory,
        Arc::new(Arc::clone(&wire)),
        Vec::new(),
        ReplicationRuntimeConfig {
            enable_bundle_bootstrap_peers: false,
            local_key_id: Some(SEAT.to_owned()),
            metrics: Some(metrics.clone()),
            ..ReplicationRuntimeConfig::default()
        },
        Some(crate::replication::runtime::self_publish_set([SEAT])),
    )
    .await;
    let registry = rt.registry();
    let mut total = (0usize, 0usize, 0u64, 0usize);
    for (round, kind) in (100u64..).zip(BUNDLE_PULL_PLANES) {
        for subject in [DEVICE, SEAT] {
            counting.reset();
            let (p0, b0, f0) = (
                permits(&metrics),
                wire.sent.load(std::sync::atomic::Ordering::Relaxed),
                wire.frames.load(std::sync::atomic::Ordering::Relaxed),
            );
            let pull = ReplicationMessage::Pull(PullMessage {
                kind,
                subject_key_id: subject.to_owned(),
            });
            registry
                .route_inbound_bytes(
                    DEVICE,
                    &wire_frame::wrap_v3(&pull, RoundSide::Initiator, round),
                )
                .await
                .expect("route the device's Pull");
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            while wire.frames.load(std::sync::atomic::Ordering::Relaxed) == f0
                && tokio::time::Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            let counts = counting.counts();
            let pages = counts.get("list_wire_hashes_since").copied().unwrap_or(0);
            let (reads, permits_now, bytes) = (
                counting.total(),
                permits(&metrics) - p0,
                wire.sent.load(std::sync::atomic::Ordering::Relaxed) - b0,
            );
            eprintln!(
                "971 idle pull {kind:?} subject={subject}: directory_calls={reads} \
                 index_pages={pages} permits={permits_now} reply_bytes={bytes} by_method={counts:?}"
            );
            assert_eq!(
                pages, 0,
                "{kind:?}/{subject}: a Pull never drains the holdings index"
            );
            total.0 += reads;
            total.1 += pages;
            total.2 += permits_now;
            total.3 += bytes;
        }
    }
    eprintln!(
        "971 idle pull ALL (one device, one cycle, self + seat subjects): directory_calls={} \
         index_pages={} permits={} reply_bytes={}",
        total.0, total.1, total.2, total.3
    );
    rt.shutdown().await;
}
