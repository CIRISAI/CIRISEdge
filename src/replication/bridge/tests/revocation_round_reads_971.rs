//! **CIRISEdge#971 — the v45 release claim for the #881 Revocation round.**
//!
//! In bundle-seat mode every attributed device keeps one Summary round with
//! the seat on [`BUNDLE_ROUND_PLANES`] (the Revocation plane), every cadence.
//! The seat answers it in `on_summary`, which asks its holdings what it still
//! lacks of the device's offer, even for an empty offer. The Revocation plane
//! lives in persist's `Attestation` wire index (`persist_index_kind`), so
//! before the holdings index that ask drained the WHOLE Attestation index, one
//! sweep permit per page, every round, for every device.
//!
//! Over a real runtime, a real store and the real inbound route:
//!
//! - **index on, booted** — the device's idle Revocation round (after the one
//!   that fills the key-plane memo and listing cache) costs the seat zero
//!   directory calls and zero sweep permits;
//! - **index off** (the pre-v45 path, `holdings_index: false`) — the same
//!   round drains the whole Attestation index: exactly the pages a full
//!   drain at the seat's page budget takes, each under a permit.
//!
//! Determinism: the background warm-up is awaited on its own event
//! (`holdings_warmed`), the reply on the transport's send event, and the
//! feed probe is spaced beyond the test's life, so only a dirt mark could
//! make it read. No sleep decides an assertion.
//!
//! `cargo test --lib revocation_round_reads_971`
use super::*;
use crate::replication::counting_directory_930::CountingDirectory;
use crate::replication::holdings_index_971_tests::{index_drain, NO_TEST_OUTLIVES};
use crate::replication::protocol::{ReplicationMessage, SummaryMessage};
use crate::replication::runtime::{
    ReplicationRuntime, ReplicationRuntimeConfig, BUNDLE_ROUND_PLANES,
};
use crate::replication::wire_frame::{self, RoundSide};
use crate::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};

const SEAT: &str = "seat-971-revround";
const DEVICE: &str = "device-971-revround";
/// Past one 1,024-row index page, so a drain is more than one page.
const ATTESTATIONS: usize = 1_100;
/// An event bound: the seat answers long before this, or the test fails.
const ANSWERED_WITHIN: Duration = Duration::from_secs(30);

/// Signals every frame the seat sends.
#[derive(Default)]
struct Sent {
    frames: std::sync::atomic::AtomicUsize,
    sent: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl Transport for Arc<Sent> {
    fn id(&self) -> TransportId {
        TransportId::HTTP
    }
    async fn send(
        &self,
        _destination_key_id: &str,
        _envelope_bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError> {
        self.frames
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.sent.notify_one();
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
    m.sweep_permit_wait_seconds
        .read()
        .snapshot(crate::observability::SWEEP_PERMIT_WAIT_BUCKETS_SECONDS)
        .count
}

/// What one idle Revocation round cost the seat: (directory calls, index
/// pages, sweep permits, calls by method).
struct Cost {
    calls: usize,
    pages: usize,
    permits: u64,
    by_method: std::collections::BTreeMap<&'static str, usize>,
}

struct Seat {
    rt: ReplicationRuntime,
    counting: CountingDirectory,
    wire: Arc<Sent>,
    metrics: crate::observability::EdgeMetrics,
    backend: Arc<ciris_persist::store::sqlite::SqliteBackend>,
}

async fn seat(holdings_index: bool) -> Seat {
    let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
    register_fixture_keys(
        &backend,
        &[(SEAT, identity_type::NODE), (DEVICE, identity_type::NODE)],
    )
    .await;
    // Spread over attesters under persist's per-peer admission burst, as the
    // idle-cost witness does (one attester's 1,100 rows trip `PeerBurst`).
    super::idle_round_cost_971::seed_store_about(&backend, SEAT, "revround-971", ATTESTATIONS)
        .await;
    let counting = CountingDirectory::new(backend.clone());
    let directory: Arc<dyn FederationDirectory> = Arc::new(counting.clone());
    let wire = Arc::new(Sent::default());
    let metrics = crate::observability::EdgeMetrics::new();
    let rt = ReplicationRuntime::start(
        directory,
        Arc::new(Arc::clone(&wire)),
        Vec::new(),
        ReplicationRuntimeConfig {
            disable_bundle_bootstrap_peers: true,
            local_key_id: Some(SEAT.to_owned()),
            metrics: Some(metrics.clone()),
            bridge: BridgeConfig {
                holdings_index,
                feed_probe_spacing: NO_TEST_OUTLIVES,
                ..BridgeConfig::default()
            },
            ..ReplicationRuntimeConfig::default()
        },
        Some(crate::replication::runtime::self_publish_set([SEAT])),
    )
    .await;
    if holdings_index {
        tokio::time::timeout(ANSWERED_WITHIN, rt.bridge().holdings_warmed())
            .await
            .expect("the holdings index warms");
        for kind in [
            EnvelopeKind::Attestation,
            EnvelopeKind::TransportDestination,
        ] {
            assert_eq!(
                rt.bridge().holdings_index_status(kind),
                Some(crate::replication::holdings_index::Status::Ready),
                "{kind:?}: the warm-up booted it"
            );
        }
    }
    Seat {
        rt,
        counting,
        wire,
        metrics,
        backend,
    }
}

/// One device Summary on the Revocation plane (an idle device: no refs), and
/// what the seat paid for it, measured from the route to the seat's reply.
/// Every read of the round happens in `on_summary` before the reply is sent.
async fn round(s: &Seat, round_id: u64) -> Cost {
    let kind = BUNDLE_ROUND_PLANES[0];
    s.counting.reset();
    let p0 = permits(&s.metrics);
    let f0 = s.wire.frames.load(std::sync::atomic::Ordering::SeqCst);
    let summary = ReplicationMessage::Summary(SummaryMessage {
        status: None,
        kind,
        refs: Vec::new(),
    });
    s.rt.registry()
        .route_inbound_bytes(
            DEVICE,
            &wire_frame::wrap_v3(&summary, RoundSide::Initiator, round_id),
        )
        .await
        .expect("route the device's Summary");
    tokio::time::timeout(ANSWERED_WITHIN, async {
        while s.wire.frames.load(std::sync::atomic::Ordering::SeqCst) == f0 {
            s.wire.sent.notified().await;
        }
    })
    .await
    .expect("the seat answers the device's Revocation Summary");
    let by_method = s.counting.counts();
    Cost {
        calls: s.counting.total(),
        pages: by_method
            .get("list_wire_hashes_since")
            .copied()
            .unwrap_or(0),
        permits: permits(&s.metrics) - p0,
        by_method,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bundle_revocation_round_reads_nothing_with_the_index_and_drains_without_it_971() {
    assert_eq!(BUNDLE_ROUND_PLANES, [EnvelopeKind::Revocation]);
    assert_eq!(
        EnvelopeKind::Revocation.persist_index_kind(),
        Some("Attestation"),
        "the Revocation plane's holdings are the Attestation index"
    );

    // Index on: the first round fills the key-plane memo and listing cache;
    // the second is the steady state a device pays every cadence. The runtime
    // applies the environment lever over its config (`resolve_holdings_index`),
    // so under `CIRIS_EDGE_HOLDINGS_INDEX=0` (the gate's lever-off leg) this
    // half cannot have the index it witnesses and is skipped, said so; the
    // index-off half below runs in every leg.
    if BridgeConfig::default().holdings_index {
        let mut on = seat(true).await;
        let _fill = round(&on, 10).await;
        let idle = round(&on, 11).await;
        eprintln!(
            "971 revocation round, index ON: calls={} pages={} permits={} by_method={:?}",
            idle.calls, idle.pages, idle.permits, idle.by_method
        );
        assert_eq!(
            (idle.calls, idle.permits),
            (0, 0),
            "an idle Revocation round reads nothing and takes no permit: {:?}",
            idle.by_method
        );
        on.rt.shutdown().await;
    } else {
        eprintln!(
            "971 revocation round, index ON half SKIPPED: {}=0 turns the runtime's index \
             off, so the zero-reads claim is not measurable in this leg",
            BridgeConfig::HOLDINGS_INDEX_ENV
        );
    }

    // Index off: the pre-v45 receive diff drains the whole index each round.
    let mut off = seat(false).await;
    let held = index_drain(&*off.backend, "Attestation").await.len();
    let budget = off.rt.bridge().sweep_page_budget().await as usize;
    let full_drain_pages = held / budget + 1;
    assert!(
        full_drain_pages >= 2,
        "the store spans more than one index page"
    );
    let _fill = round(&off, 20).await;
    let drained = round(&off, 21).await;
    eprintln!(
        "971 revocation round, index OFF: calls={} pages={} permits={} \
         (index={held} hashes, page={budget}) by_method={:?}",
        drained.calls, drained.pages, drained.permits, drained.by_method
    );
    assert_eq!(
        drained.pages, full_drain_pages,
        "without the index the round drains the whole Attestation index"
    );
    assert!(
        drained.permits >= u64::try_from(full_drain_pages).expect("pages"),
        "one permit per drained page"
    );
    off.rt.shutdown().await;
}
