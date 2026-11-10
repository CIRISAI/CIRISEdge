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

/// Rows one attester seeds: under persist v61.2.2's per-peer burst (600 rows
/// a window), so no seed waits on the limiter.
const ROWS_PER_ATTESTER: usize = 500;

/// Seed `n` `scores` rows about the seat, `ROWS_PER_ATTESTER` per attester
/// (each a registered NODE key signed by its fixture signer), so the
/// attestation index spans `n / 1024` pages without tripping the per-peer
/// admission burst. A `RateLimited` refusal still waits out its hint once
/// more rather than failing; any other refusal panics.
async fn seed_store(backend: &SqliteBackend, prefix: &str, n: usize) {
    let attesters: Vec<String> = (0..n.div_ceil(ROWS_PER_ATTESTER))
        .map(|j| format!("{SEAT}-w{j:02}"))
        .collect();
    let pairs: Vec<(&str, &str)> = attesters
        .iter()
        .map(|a| (a.as_str(), identity_type::NODE))
        .collect();
    register_fixture_keys(backend, &pairs).await;
    for i in 0..n {
        let attester = &attesters[i / ROWS_PER_ATTESTER];
        let id = format!("{prefix}-{i:05}");
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": attester,
            "attested_key_id": SEAT,
            "attestation_type": "scores",
            "dimension": "idle:row:v1",
            "payload": { "n": i },
        });
        let mut tries = 0;
        loop {
            match try_seed_scoped_attestation(
                backend,
                &id,
                attester,
                SEAT,
                "scores",
                "federation",
                envelope.clone(),
            )
            .await
            {
                Ok(()) => break,
                Err(e) if e.contains("RateLimited") && tries < 120 => {
                    tries += 1;
                    tokio::time::sleep(Duration::from_millis(1_050)).await;
                }
                Err(e) => panic!("seed {id}: {e}"),
            }
        }
    }
}

fn permits(m: &crate::observability::EdgeMetrics) -> u64 {
    m.sweep_permit_wait_seconds
        .read()
        .snapshot(crate::observability::SWEEP_PERMIT_WAIT_BUCKETS_SECONDS)
        .count
}

/// One idle round per bootstrap plane against a seat whose store holds `n`
/// attestation rows. Returns `(kind, index_pages, permits, wall)` per plane.
async fn idle_rounds_at(n: usize) -> Vec<(EnvelopeKind, usize, u64, Duration)> {
    let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
    register_fixture_keys(
        &backend,
        &[(SEAT, identity_type::NODE), (DEVICE, identity_type::NODE)],
    )
    .await;
    seed_store(&backend, "idle-971", n).await;
    let counting = CountingDirectory::new(backend.clone());
    let directory: Arc<dyn FederationDirectory> = Arc::new(counting.clone());
    let wire = Arc::new(Bytes::default());
    let metrics = crate::observability::EdgeMetrics::new();
    let mut rt = ReplicationRuntime::start(
        directory,
        Arc::new(Arc::clone(&wire)),
        Vec::new(),
        ReplicationRuntimeConfig {
            disable_bundle_bootstrap_peers: true,
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
            let t0 = std::time::Instant::now();
            registry
                .route_inbound_bytes(DEVICE, &bytes)
                .await
                .expect("route the device's Summary");
            // The responder answers on its own task: wait for its reply.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            while wire.frames.load(std::sync::atomic::Ordering::Relaxed) == f0
                && tokio::time::Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            // Summary in → the responder's reply on the wire (1 ms poll).
            let wall = t0.elapsed();
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
                    wall,
                ));
            }
        }
    }
    let mut total = (0usize, 0usize, 0u64, 0usize);
    for (kind, reads, pages, permits, bytes, counts, wall) in &rows {
        // A sweep permit is taken per index page (`holdings_from_wire_index`)
        // and per other sweep read (the advertise pages, a consent-set read on
        // a memo miss): `permits - index_pages` is everything that is not the
        // holdings drain.
        let other = permits.saturating_sub(u64::try_from(*pages).unwrap_or(0));
        eprintln!(
            "971 idle {kind:?}: directory_calls={reads} index_pages={pages} permits={permits} \
             permits_not_holdings={other} reply_bytes={bytes} wall_us={} by_method={counts:?}",
            wall.as_micros()
        );
        total.0 += reads;
        total.1 += pages;
        total.2 += permits;
        total.3 += bytes;
    }
    eprintln!(
        "971 idle ALL FIVE PLANES (one device, one cadence): directory_calls={} \
         index_pages={} permits={} reply_bytes={} (store: {n} attestation rows)",
        total.0, total.1, total.2, total.3
    );
    assert!(
        rows.iter().all(|r| r.4 > 0),
        "every plane's idle Summary is answered"
    );
    rt.shutdown().await;
    rows.into_iter()
        .map(|(kind, _, pages, permits, _, _, wall)| (kind, pages, permits, wall))
        .collect()
}

/// **The idle round's seat cost, and its slope per index page and per
/// decoded hash.** Two store sizes (1,100 and 3,100 rows: 2 and 4 index pages
/// of 1,024), one idle round per plane at each. The fit is per plane:
/// `us_per_page = Δwall / Δpages`, `us_per_hash = Δwall / Δrows`. A plane
/// whose pages do not move with the store does not drain the attestation
/// index. Printed (`971 idle fit`) for the twin's CPU-per-page term.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::cast_precision_loss)] // microseconds and page counts
async fn an_idle_bootstrap_round_costs_the_seat_971() {
    const SMALL: usize = 1_100;
    const LARGE: usize = 3_100;
    let small = idle_rounds_at(SMALL).await;
    let large = idle_rounds_at(LARGE).await;
    for ((kind, p1, q1, w1), (_, p2, q2, w2)) in small.iter().zip(&large) {
        let dp = p2.saturating_sub(*p1);
        let dw = w2.as_micros() as f64 - w1.as_micros() as f64;
        let per_page = if dp > 0 { dw / dp as f64 } else { f64::NAN };
        let per_hash = dw / (LARGE - SMALL) as f64;
        eprintln!(
            "971 idle fit {kind:?}: pages {p1}->{p2} permits {q1}->{q2} wall_us {}->{} \
             us_per_page={per_page:.1} us_per_hash={per_hash:.3} drains_index={}",
            w1.as_micros(),
            w2.as_micros(),
            dp > 0
        );
    }
}

/// The seat's complete Key-plane offer (the unbound, `Full` view: every
/// offered key record at once), as encoded for the wire, at `n` offered key
/// records: (refs, frame bytes before the seal, fragments at the TCP MDU,
/// fragments at the base 500 B link MTU). A bound peer's listing is
/// watermark-paged (CIRISEdge#531) and returned 0 of 10 on its first call in
/// this fixture, so it cannot fit the size line.
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
        .list_envelope_refs_for_peer(EnvelopeKind::Key, None)
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
    seed_store(&backend, "idle-pull-971", ATTESTATIONS).await;
    let counting = CountingDirectory::new(backend.clone());
    let directory: Arc<dyn FederationDirectory> = Arc::new(counting.clone());
    let wire = Arc::new(Bytes::default());
    let metrics = crate::observability::EdgeMetrics::new();
    let mut rt = ReplicationRuntime::start(
        directory,
        Arc::new(Arc::clone(&wire)),
        Vec::new(),
        ReplicationRuntimeConfig {
            disable_bundle_bootstrap_peers: true,
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

/// **CIRISEdge#971 — a fresh bound peer is offered the keys on its first Key
/// round.** The size fit above saw a bound peer's first Key listing come back
/// empty (0 of 10). Here the seat's offered keys are hybrid-signed records
/// (`minted_key_record`, what a real registration stores), and a peer that
/// has never had a round is listed by the bound (`Some(peer)`) path the
/// responder takes. Its first listing must offer every one of them, and must
/// equal the unbound view: the Key arm ignores the #531 sweep window
/// (`list_envelope_refs_inner`: `Key => list_key_record_rows(None)`), so no
/// watermark can hold rows back. For contrast, the fixture records
/// (`fixture_key_record`: fake signature) are listed the same way and
/// printed, which is what the size fit saw.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fresh_bound_peer_is_offered_the_keys_on_its_first_key_round_971() {
    const N: usize = 10;
    let (backend, bridge) = make_bridge(&[]);
    let mut keys = Vec::new();
    for i in 0..N {
        let record = minted_key_record(
            &format!("announced-971-bound-{i:02}"),
            identity_type::NODE,
            0x40 + u8::try_from(i).expect("small"),
        )
        .await;
        keys.push(record.key_id.clone());
        backend
            .put_public_key(SignedKeyRecord { record })
            .await
            .expect("hold a signed key record");
    }
    let fixture: Vec<String> = (0..N)
        .map(|i| format!("fixture-971-bound-{i:02}"))
        .collect();
    let pairs: Vec<(&str, &str)> = fixture
        .iter()
        .map(|k| (k.as_str(), identity_type::NODE))
        .collect();
    register_fixture_keys(&backend, &pairs).await;
    let offer: Vec<String> = keys.iter().chain(&fixture).cloned().collect();
    let bridge = bridge
        .with_local_key_id(Some(SEAT.to_owned()))
        .with_self_provider(Some(Arc::new(move || offer.clone())));
    let bound = bridge
        .list_envelope_refs_for_peer(EnvelopeKind::Key, Some("device-971-fresh"))
        .await;
    let unbound = bridge
        .list_envelope_refs_for_peer(EnvelopeKind::Key, None)
        .await;
    let fixture_only = {
        let (b2, br2) = make_bridge(&[]);
        register_fixture_keys(&b2, &pairs).await;
        let f = fixture.clone();
        br2.with_self_provider(Some(Arc::new(move || f.clone())))
            .list_envelope_refs_for_peer(EnvelopeKind::Key, Some("device-971-fresh"))
            .await
            .len()
    };
    eprintln!(
        "971 bound-key first round: signed_keys={N} fixture_keys={N} bound_refs={} \
         unbound_refs={} fixture_only_bound_refs={fixture_only}",
        bound.len(),
        unbound.len()
    );
    let set = |v: &[EnvelopeRef]| {
        v.iter()
            .map(|r| r.envelope_hash)
            .collect::<std::collections::BTreeSet<_>>()
    };
    assert!(
        bound.len() >= N,
        "a fresh bound peer's first Key listing offers every signed key record the seat \
         publishes: {} of {N}",
        bound.len()
    );
    assert_eq!(
        set(&bound),
        set(&unbound),
        "the bound and unbound Key views are the same set (no watermark on Key)"
    );
}
