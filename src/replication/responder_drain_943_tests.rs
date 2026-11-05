//! CIRISEdge#943 — a reply the reverse path is holding must not hold the
//! frames behind it.
//!
//! Everything here is the production path below the transport: frames an
//! initiator's real session produced (`start_round` with #927 proactive
//! publish: `Summary` then `Deliver`, v3-stamped), routed by the real registry
//! into the real responder driver over a real session. The seam is one
//! transport whose `send` parks while the plane is held.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use super::coordinator::{DriveStep, ReplicationCoordinator};
use super::directory::{
    DirectoryStateAdapter, MockReplicationDirectory, MutableDirectoryStateAdapter,
    ReplicationDirectory,
};
use super::protocol::{DeliverMessage, EnvelopeKind, EnvelopeRef, PullMessage, ReplicationMessage};
use super::registry::ReplicationRegistry;
use super::reply_lane::{ReplyLane, REPLY_QUEUE_BYTES, REPLY_QUEUE_JOBS};
use super::runtime::spawn_responder_drive;
use super::session::{SessionRole, MAX_DELIVER_ENVELOPE_BYTES};
use super::summary::ApplyOutcome;
use super::wire_frame::{self, RoundSide};
use crate::observability::{self as obs, EdgeMetrics};
use crate::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};

const PEER: &str = "agent-943";

/// What left the responder: the plane, the round the frame was stamped with,
/// and which message.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sent {
    kind: EnvelopeKind,
    round: u64,
    what: &'static str,
}

fn name_of(msg: &ReplicationMessage) -> &'static str {
    match msg {
        ReplicationMessage::Summary(_) => "summary",
        ReplicationMessage::Diff(_) => "diff",
        ReplicationMessage::Deliver(_) => "deliver",
        ReplicationMessage::Fetch(_) => "fetch",
        ReplicationMessage::Pull(_) => "pull",
        ReplicationMessage::CursorPull(_) => "cursor_pull",
    }
}

/// The seam: `send` parks while its frame's plane is in `held`. `fail` makes
/// the send return an error instead once released, a dead path's second half.
struct ReverseSeam {
    held: watch::Sender<HashSet<EnvelopeKind>>,
    entered: StdMutex<Vec<Sent>>,
    sent: StdMutex<Vec<Sent>>,
    /// The bytes of each frame in `sent`, not yet read by a test's initiator.
    wire: StdMutex<Vec<Vec<u8>>>,
    fail: std::sync::atomic::AtomicBool,
}

impl ReverseSeam {
    fn new() -> Arc<Self> {
        let (held, _) = watch::channel(HashSet::new());
        Arc::new(Self {
            held,
            entered: StdMutex::default(),
            sent: StdMutex::default(),
            wire: StdMutex::default(),
            fail: std::sync::atomic::AtomicBool::new(false),
        })
    }
    fn hold(&self, kind: EnvelopeKind) {
        self.held.send_modify(|h| {
            h.insert(kind);
        });
    }
    fn release(&self, kind: EnvelopeKind) {
        self.held.send_modify(|h| {
            h.remove(&kind);
        });
    }
    fn sent(&self) -> Vec<Sent> {
        self.sent.lock().unwrap().clone()
    }
    fn entered(&self) -> Vec<Sent> {
        self.entered.lock().unwrap().clone()
    }
}

#[async_trait]
impl Transport for ReverseSeam {
    fn id(&self) -> TransportId {
        TransportId::HTTP
    }
    async fn send(
        &self,
        _destination_key_id: &str,
        envelope_bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError> {
        let framed = wire_frame::try_unwrap_framed(envelope_bytes)
            .expect("a responder sends well-formed frames")
            .expect("a responder sends CRPL frames");
        let kind = framed.msg.kind();
        let record = Sent {
            kind,
            round: framed.meta.map_or(0, |m| m.round),
            what: name_of(&framed.msg),
        };
        self.entered.lock().unwrap().push(record.clone());
        let mut held = self.held.subscribe();
        held.wait_for(|h| !h.contains(&kind))
            .await
            .expect("the seam outlives the driver");
        if self.fail.load(std::sync::atomic::Ordering::Acquire) {
            return Err(TransportError::Io("reverse path dead".to_string()));
        }
        self.sent.lock().unwrap().push(record);
        self.wire.lock().unwrap().push(envelope_bytes.to_vec());
        Ok(TransportSendOutcome::Delivered)
    }
    async fn listen(
        &self,
        _sink: tokio::sync::mpsc::Sender<InboundFrame>,
    ) -> Result<(), TransportError> {
        Ok(())
    }
}

/// Keeps every frame the initiator's session put on the wire, in order.
#[derive(Default)]
struct Capture(StdMutex<Vec<Vec<u8>>>);

#[async_trait]
impl Transport for Capture {
    fn id(&self) -> TransportId {
        TransportId::HTTP
    }
    async fn send(
        &self,
        _destination_key_id: &str,
        envelope_bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError> {
        self.0.lock().unwrap().push(envelope_bytes.to_vec());
        Ok(TransportSendOutcome::Delivered)
    }
    async fn listen(
        &self,
        _sink: tokio::sync::mpsc::Sender<InboundFrame>,
    ) -> Result<(), TransportError> {
        Ok(())
    }
}

/// The peer's side: a real initiator session holding `rows` on `kind`.
struct Initiator {
    coord: Arc<ReplicationCoordinator>,
    wire: Arc<Capture>,
}

async fn initiator(kind: EnvelopeKind, rows: &[&[u8]]) -> Initiator {
    let dir = Arc::new(MockReplicationDirectory::new());
    for (i, row) in rows.iter().enumerate() {
        let hash: [u8; 32] = Sha256::digest(row).into();
        dir.seed(kind, hash, row.to_vec(), i as u64 + 1).await;
    }
    let directory: Arc<dyn ReplicationDirectory> = dir;
    let wire = Arc::new(Capture::default());
    let coord = ReplicationCoordinator::new(
        Arc::clone(&wire) as Arc<dyn Transport>,
        "responder-943",
        kind,
        SessionRole::Initiator,
        Arc::new(DirectoryStateAdapter::new(Arc::clone(&directory))),
        Arc::new(MutableDirectoryStateAdapter::new(directory)),
    )
    .with_proactive_publish(true);
    Initiator {
        coord: Arc::new(coord),
        wire,
    }
}

impl Initiator {
    /// One round-open, as the scheduler sends it: every message of the first
    /// step, on the wire in order, stamped with the round.
    async fn open_round(&self) -> Vec<Vec<u8>> {
        let DriveStep::SendThenWait(msgs) = self
            .coord
            .drive_round_step(None)
            .await
            .expect("a round opens")
        else {
            panic!("an initiator's round opens with SendThenWait");
        };
        for m in &msgs {
            self.coord
                .send_message(m)
                .await
                .expect("capture never fails");
        }
        std::mem::take(&mut *self.wire.0.lock().unwrap())
    }
}

/// The mock, counting the plane reads a step costs: what a frame that wants an
/// answer spends on this node.
struct CountingDir {
    inner: Arc<MockReplicationDirectory>,
    reads: Arc<AtomicUsize>,
}

#[async_trait]
impl ReplicationDirectory for CountingDir {
    async fn list_envelope_refs(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.list_envelope_refs(kind).await
    }
    async fn fetch_envelope_bytes(
        &self,
        kind: EnvelopeKind,
        envelope_hash: &[u8; 32],
    ) -> Option<Vec<u8>> {
        self.inner.fetch_envelope_bytes(kind, envelope_hash).await
    }
    async fn apply_envelope_bytes(
        &self,
        kind: EnvelopeKind,
        envelope_bytes: &[u8],
        source_peer: Option<&str>,
    ) -> ApplyOutcome {
        self.inner
            .apply_envelope_bytes(kind, envelope_bytes, source_peer)
            .await
    }
}

/// The responder's side: the real registry and the real driver.
struct Responder {
    registry: Arc<ReplicationRegistry>,
    dir: Arc<MockReplicationDirectory>,
    reads: Arc<AtomicUsize>,
    seam: Arc<ReverseSeam>,
    metrics: EdgeMetrics,
}

fn responder() -> Responder {
    let registry = Arc::new(ReplicationRegistry::new());
    let dir = Arc::new(MockReplicationDirectory::new());
    let seam = ReverseSeam::new();
    let metrics = EdgeMetrics::new();
    let reads = Arc::new(AtomicUsize::new(0));
    let (d, s, m, c) = (
        Arc::clone(&dir),
        Arc::clone(&seam),
        metrics.clone(),
        Arc::clone(&reads),
    );
    registry.set_responder_factory(Arc::new(move |peer, kind| {
        let directory: Arc<dyn ReplicationDirectory> = Arc::new(CountingDir {
            inner: Arc::clone(&d),
            reads: Arc::clone(&c),
        });
        let coord = Arc::new(
            ReplicationCoordinator::new(
                Arc::clone(&s) as Arc<dyn Transport>,
                peer,
                kind,
                SessionRole::Responder,
                Arc::new(DirectoryStateAdapter::new(Arc::clone(&directory))),
                Arc::new(MutableDirectoryStateAdapter::new(directory)),
            )
            .with_metrics(Some(m.clone())),
        );
        spawn_responder_drive(Arc::clone(&coord));
        coord
    }));
    Responder {
        registry,
        dir,
        reads,
        seam,
        metrics,
    }
}

impl Responder {
    async fn route(&self, frames: &[Vec<u8>]) {
        for f in frames {
            self.registry
                .route_inbound_bytes(PEER, f)
                .await
                .expect("the inbox takes the frame");
        }
    }

    /// The driver has taken everything routed so far off the inbox.
    async fn drained(&self, kind: EnvelopeKind) {
        let coord = self
            .registry
            .get_responder(PEER, kind)
            .await
            .expect("a frame built the responder");
        eventually("the driver drains its inbox", || coord.inbound_depth() == 0).await;
    }

    fn rounds(&self, kind: EnvelopeKind, outcome: &str) -> u64 {
        self.metrics
            .responder_rounds_total()
            .get(&format!("{}:{outcome}", kind.as_wire_str()))
            .copied()
            .unwrap_or(0)
    }
}

async fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !cond() {
        assert!(tokio::time::Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// **The witness.** The proactive shape from the field: `Summary` then
/// `Deliver` on one plane. The reply to the `Summary` parks on the dead
/// reverse path. The `Deliver` behind it is already in the inbox and must
/// apply while that reply is still parked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_reply_does_not_hold_the_deliver_behind_it_943() {
    let r = responder();
    let i = initiator(EnvelopeKind::Key, &[b"key-row-1"]).await;
    let frames = i.open_round().await;
    assert_eq!(frames.len(), 2, "Summary then proactive Deliver");

    r.seam.hold(EnvelopeKind::Key);
    r.route(&frames).await;
    eventually("the Summary's reply reaches the held send", || {
        !r.seam.entered().is_empty()
    })
    .await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while r.dir.count(EnvelopeKind::Key).await == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the Deliver sat in the inbox behind a reply the reverse path held"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        r.seam.sent().is_empty(),
        "the row landed while the reply was still held"
    );
    r.seam.release(EnvelopeKind::Key);
    eventually("the held reply still leaves once released", || {
        r.seam.sent().iter().any(|s| s.what == "diff")
    })
    .await;
}

/// The scope of the wedge. The issue reads as one loop across planes; each
/// `(peer, kind)` has its own driver. A reply held on one plane never held
/// another plane's frames, before this fix or after it: the field's Key frame
/// waited on the Key plane's OWN replies, and a route row on another plane ran
/// ahead of it. This pins that.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_reply_never_held_another_plane_943() {
    let r = responder();
    let att = initiator(EnvelopeKind::Attestation, &[b"att-row"]).await;
    let key = initiator(EnvelopeKind::Key, &[b"key-row"]).await;

    r.seam.hold(EnvelopeKind::Attestation);
    r.route(&att.open_round().await).await;
    eventually("the Attestation reply reaches the held send", || {
        !r.seam.entered().is_empty()
    })
    .await;

    r.route(&key.open_round().await).await;
    eventually("the Key plane's reply left past the held plane", || {
        r.seam
            .sent()
            .iter()
            .any(|s| s.kind == EnvelopeKind::Key && s.what == "diff")
    })
    .await;
    assert_eq!(r.dir.count(EnvelopeKind::Key).await, 1);
    r.seam.release(EnvelopeKind::Attestation);
}

fn pull_frame(kind: EnvelopeKind, round: u64) -> Vec<u8> {
    wire_frame::wrap_v3(
        &ReplicationMessage::Pull(PullMessage {
            kind,
            subject_key_id: "subject-943".to_string(),
        }),
        RoundSide::Initiator,
        round,
    )
}

/// **Per-peer order, and the round on the frame.** A `Pull` runs on a round of
/// its own and rebinds the responder while the first round's reply is still
/// held. Every frame still leaves in the order its answer was stepped, stamped
/// with the round it answers: read at send time, the held job's `Diff` would
/// carry the Pull's round and be dropped at the initiator as a mismatch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replies_keep_their_order_and_their_round_943() {
    let r = responder();
    let i = initiator(EnvelopeKind::Key, &[]).await;
    let frames = i.open_round().await;
    let round = i.coord.current_round();
    r.seam.hold(EnvelopeKind::Key);
    r.route(&frames).await;
    eventually("the first reply reaches the held send", || {
        !r.seam.entered().is_empty()
    })
    .await;

    let pull_round = round ^ 0x943;
    r.route(&[pull_frame(EnvelopeKind::Key, pull_round)]).await;
    r.drained(EnvelopeKind::Key).await;
    let coord = r
        .registry
        .get_responder(PEER, EnvelopeKind::Key)
        .await
        .expect("built");
    eventually("the Pull rebinds the responder", || {
        coord.current_round() == pull_round
    })
    .await;
    r.seam.release(EnvelopeKind::Key);
    eventually("all three frames leave", || r.seam.sent().len() == 3).await;

    let sent: Vec<(u64, &str)> = r.seam.sent().iter().map(|s| (s.round, s.what)).collect();
    assert_eq!(
        sent,
        vec![(round, "summary"), (round, "diff"), (pull_round, "summary")]
    );
}

/// **The bound, and what the park was doing by accident.** With the reverse
/// path held the lane takes one reply on the wire and [`REPLY_QUEUE_JOBS`]
/// behind it. Every further frame that wants an answer is shed unstepped: it
/// costs no plane read, it is counted, and the inbox never overflows. A
/// `Deliver` is never shed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_lane_sheds_unstepped_and_never_sheds_a_deliver_943() {
    const EXTRA: usize = 5;
    let r = responder();
    r.seam.hold(EnvelopeKind::Key);

    let mut reads_at_bound = 0;
    for n in 0..=REPLY_QUEUE_JOBS + EXTRA {
        let i = initiator(EnvelopeKind::Key, &[]).await;
        r.route(&i.open_round().await).await;
        r.drained(EnvelopeKind::Key).await;
        if n == 0 {
            eventually("the first reply is on the wire", || {
                !r.seam.entered().is_empty()
            })
            .await;
        }
        eventually("the step finished", || {
            let shed = r.rounds(EnvelopeKind::Key, obs::RESPONDER_ROUND_REPLY_SHED);
            n <= REPLY_QUEUE_JOBS || shed == (n - REPLY_QUEUE_JOBS) as u64
        })
        .await;
        if n == REPLY_QUEUE_JOBS {
            reads_at_bound = r.reads.load(Ordering::SeqCst);
        }
    }
    assert_eq!(
        r.rounds(EnvelopeKind::Key, obs::RESPONDER_ROUND_REPLY_SHED),
        EXTRA as u64,
        "every frame past the bound is shed, and counted"
    );
    assert_eq!(
        r.reads.load(Ordering::SeqCst),
        reads_at_bound,
        "a shed frame costs no plane read: a reverse-dead peer's Summaries are \
         stepped no faster than replies leave"
    );
    assert_eq!(r.metrics.inbound_backpressure_drops(), 0);
    assert_eq!(r.seam.entered().len(), 1, "one send at a time");

    // The lane is full, and a Deliver still lands.
    let i = initiator(EnvelopeKind::Key, &[b"key-row-past-the-bound"]).await;
    let frames = i.open_round().await;
    r.route(&frames[1..]).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while r.dir.count(EnvelopeKind::Key).await == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "a Deliver was held or shed by a full lane"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    r.seam.release(EnvelopeKind::Key);
}

/// The other half of the bound: a `Diff` costs a peer a few hashes and this
/// node a page of bodies, so the lane is bounded in bytes too, and they come
/// back when the job is done.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_lane_is_bounded_in_bytes_and_gives_them_back_943() {
    let seam = ReverseSeam::new();
    let directory: Arc<dyn ReplicationDirectory> = Arc::new(MockReplicationDirectory::new());
    let coord = Arc::new(ReplicationCoordinator::new(
        Arc::clone(&seam) as Arc<dyn Transport>,
        PEER,
        EnvelopeKind::Key,
        SessionRole::Responder,
        Arc::new(DirectoryStateAdapter::new(Arc::clone(&directory))),
        Arc::new(MutableDirectoryStateAdapter::new(directory)),
    ));
    let lane = ReplyLane::spawn(Arc::clone(&coord));
    seam.hold(EnvelopeKind::Key);
    let page = || {
        vec![ReplicationMessage::Deliver(DeliverMessage {
            kind: EnvelopeKind::Key,
            envelopes: vec![vec![0u8; MAX_DELIVER_ENVELOPE_BYTES]],
        })]
    };
    let pages = REPLY_QUEUE_BYTES / MAX_DELIVER_ENVELOPE_BYTES;
    assert!(
        pages < REPLY_QUEUE_JOBS,
        "the byte bound is the one that bites"
    );
    for n in 0..pages {
        assert!(lane.has_room(), "page {n} fits");
        lane.enqueue(&coord, page(), 7, None);
    }
    assert!(!lane.has_room(), "a lane holding its bytes takes no more");
    seam.release(EnvelopeKind::Key);
    eventually("the pages leave", || seam.sent().len() == pages).await;
    eventually("their bytes come back", || lane.has_room()).await;
}

/// A reply that outlived its round is not sent: on a dead path it would only
/// spend the next round's reply another stall.
#[tokio::test(start_paused = true)]
async fn a_reply_that_outlived_its_round_is_not_sent_943() {
    let r = responder();
    let first = initiator(EnvelopeKind::Key, &[]).await;
    let second = initiator(EnvelopeKind::Key, &[]).await;
    r.seam.hold(EnvelopeKind::Key);
    r.route(&first.open_round().await).await;
    eventually("the first reply is on the wire", || {
        !r.seam.entered().is_empty()
    })
    .await;
    r.route(&second.open_round().await).await;
    r.drained(EnvelopeKind::Key).await;
    tokio::task::yield_now().await;

    tokio::time::advance(
        super::scheduler::SchedulerConfig::DEFAULT_ROUND_TIMEOUT + Duration::from_secs(1),
    )
    .await;
    r.seam.release(EnvelopeKind::Key);
    eventually("the queued reply expires, counted", || {
        r.rounds(EnvelopeKind::Key, obs::RESPONDER_ROUND_REPLY_EXPIRED) == 1
    })
    .await;
    let round = second.coord.current_round();
    assert!(
        !r.seam.entered().iter().any(|s| s.round == round),
        "the expired reply never reached the transport: {:?}",
        r.seam.entered()
    );

    // The lane is free again: the next round's reply goes straight out.
    let third = initiator(EnvelopeKind::Key, &[]).await;
    r.route(&third.open_round().await).await;
    let round = third.coord.current_round();
    eventually("the next round is answered", || {
        r.seam.sent().iter().any(|s| s.round == round)
    })
    .await;
}

/// **A dropped reply lets the round end, and the next one runs.** The reply
/// fails: the rest of its job is not sent, the failure is counted, and the
/// initiator's round ends the way the scheduler ends it. The next round, a new
/// id on the same two sessions, runs to completion over a healed path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_reply_is_retried_by_the_next_round_943() {
    let r = responder();
    let i = initiator(EnvelopeKind::Key, &[b"key-row-1"]).await;
    let first = i.open_round().await;
    let dead_round = i.coord.current_round();

    r.seam
        .fail
        .store(true, std::sync::atomic::Ordering::Release);
    r.route(&first).await;
    eventually("the failed reply is counted", || {
        r.rounds(EnvelopeKind::Key, obs::RESPONDER_ROUND_REPLY_SEND_FAILED) == 1
    })
    .await;
    assert_eq!(
        r.seam.entered().len(),
        1,
        "the rest of a failed job is not sent"
    );

    // The scheduler's timeout arm, then its next tick.
    i.coord.abandon_round().await;
    r.seam
        .fail
        .store(false, std::sync::atomic::Ordering::Release);
    r.route(&i.open_round().await).await;
    let round = i.coord.current_round();
    assert_ne!(round, dead_round);

    let exchange = async {
        loop {
            let frames = std::mem::take(&mut *r.seam.wire.lock().unwrap());
            for frame in frames {
                let reply = wire_frame::try_unwrap_framed(&frame)
                    .expect("well-formed")
                    .expect("CRPL");
                let meta = reply.meta.expect("a reply to a v3 round is v3");
                assert_eq!(
                    meta.round, round,
                    "the dead round has no reply left in flight"
                );
                i.coord
                    .deliver_reply(reply.msg, meta.round)
                    .expect("the live round takes its reply");
                let msg = i.coord.recv_inbound().await.expect("the round is open");
                match i.coord.drive_round_step(Some(msg)).await.expect("a step") {
                    DriveStep::Complete(report) => return report,
                    DriveStep::SendThenComplete(msgs, report) => {
                        for m in &msgs {
                            i.coord.send_message(m).await.expect("capture");
                        }
                        let out = std::mem::take(&mut *i.wire.0.lock().unwrap());
                        r.route(&out).await;
                        return report;
                    }
                    DriveStep::SendThenWait(msgs) => {
                        for m in &msgs {
                            i.coord.send_message(m).await.expect("capture");
                        }
                        let out = std::mem::take(&mut *i.wire.0.lock().unwrap());
                        r.route(&out).await;
                    }
                    DriveStep::Refused => panic!("the healed round was refused"),
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    let report = tokio::time::timeout(Duration::from_secs(5), exchange)
        .await
        .expect("the round after the failure completes");
    assert_eq!(report.kind, EnvelopeKind::Key);
}

/// v44 — the three signals M2 is read from: the frame's wait in the inbox,
/// the reply's wait in the lane, and the lane's depth, which rises while the
/// reverse path holds and falls when it lets go.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_reply_shows_on_the_lane_gauges_and_its_wait_on_the_histograms() {
    let r = responder();
    let i = initiator(EnvelopeKind::Key, &[b"key-row-1"]).await;
    let frames = i.open_round().await;
    let key = EnvelopeKind::Key.as_wire_str();
    let snapshot = r.metrics.snapshot();
    assert_eq!(snapshot.replication_reply_queued["sum"], 0);
    assert_eq!(snapshot.replication_inbound_wait_seconds[key].count, 0);

    r.seam.hold(EnvelopeKind::Key);
    r.route(&frames).await;
    r.drained(EnvelopeKind::Key).await;
    eventually("the reply reaches the held send", || {
        !r.seam.entered().is_empty()
    })
    .await;
    let held = r.metrics.snapshot();
    assert!(
        held.replication_reply_queued["sum"] >= 1,
        "the lane holds it"
    );
    assert_eq!(
        held.replication_reply_queued["max"], held.replication_reply_queued["sum"],
        "one lane"
    );
    assert_eq!(
        held.replication_inbound_wait_seconds[key].count,
        frames.len() as u64,
        "every stepped frame was timed"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    r.seam.release(EnvelopeKind::Key);
    eventually("the lane drains", || {
        r.metrics.snapshot().replication_reply_queued["sum"] == 0
    })
    .await;
    assert!(r.metrics.snapshot().replication_reply_wait_seconds[key].count >= 1);
}
