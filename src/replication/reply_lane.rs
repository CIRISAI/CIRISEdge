//! CIRISEdge#943 — the responder's reply lane.
//!
//! A responder coordinator has one driver: it takes a frame from the inbox and
//! steps the session. Replies used to be sent from that same loop, so a reply
//! the reverse path was holding held every frame behind it, up to the send
//! timeout per reply. The field's Key `Deliver` sat 79 s behind the Key plane's
//! own failing replies while the route row on another plane landed, and that
//! row parked on the absent Key. A driver is per `(peer, kind)`: one plane's
//! held reply never held another plane, it put that plane behind the others.
//!
//! So the driver steps and this lane sends: one FIFO task per coordinator.
//!
//! ## What stays the same
//!
//! - **Step order.** The driver is still the only stepper, so the session sees
//!   frames in arrival order.
//! - **Reply order.** One lane, one send at a time, per `(peer, kind)`. The
//!   rest of a job is dropped when one of its messages fails, as before.
//! - **The round on the frame.** A job carries the round bound when its frame
//!   was stepped. Read at send time it could name a later one: a `Pull` runs on
//!   a round of its own and rebinds the responder.
//!
//! ## What the parked loop was doing by accident
//!
//! It rate-limited the work a reverse-dead peer could cause: frames that want
//! an answer (a `Summary` reads the plane, a `Diff` reads bodies) were stepped
//! no faster than replies left. Replies are bounded by count and by bytes
//! ([`REPLY_QUEUE_JOBS`], [`REPLY_QUEUE_BYTES`]), and past the bound the driver
//! SHEDS such a frame unstepped ([`obs::RESPONDER_ROUND_REPLY_SHED`]): no read,
//! no session change, the same O(1) cost as the inbox drop it replaces, and the
//! same recovery. The rate at which those frames cost anything is still the
//! rate replies leave.
//!
//! A `Deliver` is never shed: it wants no answer, and it is the frame this
//! lane exists for. It now applies at the rate a peer with a healthy reverse
//! path could already drive, under the same inbox and the same admission gates.
//!
//! The parked loop never pushed back on the transport: routing is a `try_send`
//! into the inbox, so a peer's only signal was always a silent drop.
//!
//! ## A reply that does not leave
//!
//! Shed, expired or failed, the round ends the same way a failed send always
//! ended it: the initiator's wait runs out, it abandons the round and opens a
//! new one, and the new round id rebinds this session, so nothing of the dead
//! round is inherited (CIRISEdge#634 §5.2). A legacy `Summary` resets it too.
//! The anti-entropy protocol is idempotent. A page the advertise watermark
//! passed in a lost reply comes back on the re-sweep: "a row lost with a
//! dropped frame" is one of the three cases that design exists for
//! (`PlaneWatermark`, CIRISEdge#531). A shed frame moves no watermark at all.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;

use super::coordinator::{ReplicationCoordinator, RoundReport};
use super::protocol::ReplicationMessage;
use super::scheduler::{pacing_timeout, SchedulerConfig};
use super::session::MAX_DELIVER_ENVELOPE_BYTES;
use crate::log_throttle::{LogThrottle, ThrottleDecision};
use crate::observability as obs;

/// CIRISEdge#373 — outer bound on one reply send. Sized to sit just ABOVE the
/// reverse-path progress-aware hard cap (`REVERSE_PATH_MAX_TRANSFER` = 45 s,
/// v13.6.1) plus dial margin, so it never severs a LIVE, progressing
/// large-resource transfer. A DEAD link fast-fails at the reverse-path
/// no-progress window (~6 s), so this bound only bites a genuinely pathological
/// send. The abandoned send is safe: its awaits (resource wait, dial) are
/// cancellation-tolerant.
pub(super) const RESPONDER_REPLY_SEND_TIMEOUT: Duration = Duration::from_secs(60);

/// Replies waiting behind the one on the wire. The inbox's capacity, so a burst
/// the inbox could absorb when replies were sent inline (a contact lookup is up
/// to [`ReplicationCoordinator::MAX_PULL_EXCHANGES`] Pulls at once) is not shed
/// now that stepping outruns sending.
pub(super) const REPLY_QUEUE_JOBS: usize = ReplicationCoordinator::INBOUND_CHANNEL_CAPACITY;

/// `Deliver` bytes one lane may hold, the job on the wire included. A `Diff`
/// costs the peer a few hashes and costs this node a page of bodies, so a count
/// alone would let a reverse-dead peer pin [`REPLY_QUEUE_JOBS`] pages per plane.
/// Checked before a step, so a lane can pass it by one page.
pub(super) const REPLY_QUEUE_BYTES: usize = 4 * MAX_DELIVER_ENVELOPE_BYTES;

/// A round this reply belonged to that has been given up on: the longest a
/// default initiator waits for a frame, paced as the scheduler paces it on a
/// shaped link. Past this the reply answers nobody, and sending it down a dead
/// path would only cost the next round's reply another stall.
fn max_queued(coord: &ReplicationCoordinator) -> Duration {
    pacing_timeout(SchedulerConfig::DEFAULT_ROUND_TIMEOUT, coord.pacing_gap())
}

/// Does this frame want an answer? Exhaustive on purpose: a new message type
/// has to decide.
#[must_use]
pub(super) fn wants_reply(msg: &ReplicationMessage) -> bool {
    match msg {
        ReplicationMessage::Summary(_)
        | ReplicationMessage::Diff(_)
        | ReplicationMessage::Fetch(_)
        | ReplicationMessage::Pull(_)
        | ReplicationMessage::CursorPull(_) => true,
        ReplicationMessage::Deliver(_) => false,
    }
}

fn deliver_bytes(msgs: &[ReplicationMessage]) -> usize {
    msgs.iter()
        .map(|m| match m {
            ReplicationMessage::Deliver(d) => d.envelopes.iter().map(Vec::len).sum(),
            _ => 0,
        })
        .sum()
}

/// A round the send completes (CIRISEdge#380's initiator-final path).
pub(super) struct Finish {
    pub(super) report: RoundReport,
    pub(super) began: std::time::Instant,
}

struct ReplyJob {
    msgs: Vec<ReplicationMessage>,
    round: u64,
    queued_at: Instant,
    bytes: usize,
    finishes: Option<Finish>,
}

#[derive(Default)]
struct LaneState {
    /// `Deliver` bytes queued or on the wire.
    bytes: AtomicUsize,
    /// A send failed since the driver last looked: the round's clock restarts.
    send_failed: AtomicBool,
}

/// The driver's end of the lane. Dropping it ends the task once the queue
/// drains.
pub(super) struct ReplyLane {
    tx: mpsc::Sender<ReplyJob>,
    state: Arc<LaneState>,
}

static LANE_LOG: OnceLock<LogThrottle> = OnceLock::new();

/// A peer picks how often this fires, so it is throttled; the counter is not.
fn lane_log() -> &'static LogThrottle {
    LANE_LOG.get_or_init(|| LogThrottle::new(8, Duration::from_secs(60), 256))
}

fn count(coord: &ReplicationCoordinator, outcome: &'static str) {
    if let Some(m) = coord.metrics() {
        m.inc_responder_round(coord.kind(), outcome);
    }
}

impl ReplyLane {
    pub(super) fn spawn(coord: Arc<ReplicationCoordinator>) -> Self {
        let (tx, rx) = mpsc::channel(REPLY_QUEUE_JOBS);
        let state = Arc::new(LaneState::default());
        tokio::spawn(run(coord, rx, Arc::clone(&state)));
        Self { tx, state }
    }

    /// Is there room for the answer to a frame stepped now?
    #[must_use]
    pub(super) fn has_room(&self) -> bool {
        self.tx.capacity() > 0 && self.state.bytes.load(Ordering::Acquire) < REPLY_QUEUE_BYTES
    }

    /// Whether a send failed since the last call.
    pub(super) fn take_send_failed(&self) -> bool {
        self.state.send_failed.swap(false, Ordering::AcqRel)
    }

    /// A frame that wanted an answer, or an answer, with nowhere to go.
    pub(super) fn shed(&self, coord: &ReplicationCoordinator, what: &'static str) {
        count(coord, obs::RESPONDER_ROUND_REPLY_SHED);
        if let ThrottleDecision::Emit { suppressed_prev } = lane_log().check(coord.peer_key_id()) {
            tracing::warn!(
                peer = %coord.peer_key_id(),
                kind = ?coord.kind(),
                what,
                link = %coord.last_inbound_link_hex(),
                queued_jobs = REPLY_QUEUE_JOBS - self.tx.capacity(),
                queued_bytes = self.state.bytes.load(Ordering::Acquire),
                suppressed_prev,
                "responder reply lane FULL — shed, unanswered: replies to this peer are not \
                 leaving; its round times out and the next one is served (CIRISEdge#943)"
            );
        }
    }

    /// Queue `msgs`, stamped with `round`. Never waits. The driver checks
    /// [`Self::has_room`] before stepping a frame that wants an answer and is
    /// the only producer, so a job is refused here only when a `Deliver` was
    /// answered, which a responder does not do today.
    pub(super) fn enqueue(
        &self,
        coord: &ReplicationCoordinator,
        msgs: Vec<ReplicationMessage>,
        round: u64,
        finishes: Option<Finish>,
    ) {
        let bytes = deliver_bytes(&msgs);
        self.state.bytes.fetch_add(bytes, Ordering::AcqRel);
        let job = ReplyJob {
            msgs,
            round,
            queued_at: Instant::now(),
            bytes,
            finishes,
        };
        if self.tx.try_send(job).is_err() {
            self.state.bytes.fetch_sub(bytes, Ordering::AcqRel);
            self.shed(coord, "reply");
        }
    }
}

async fn run(
    coord: Arc<ReplicationCoordinator>,
    mut rx: mpsc::Receiver<ReplyJob>,
    state: Arc<LaneState>,
) {
    while let Some(job) = rx.recv().await {
        let queued = job.queued_at.elapsed();
        if queued > max_queued(&coord) {
            count(&coord, obs::RESPONDER_ROUND_REPLY_EXPIRED);
            if let ThrottleDecision::Emit { suppressed_prev } =
                lane_log().check(coord.peer_key_id())
            {
                tracing::warn!(
                    peer = %coord.peer_key_id(),
                    kind = ?coord.kind(),
                    round = job.round,
                    queued_ms = u64::try_from(queued.as_millis()).unwrap_or(u64::MAX),
                    suppressed_prev,
                    "responder reply EXPIRED in the lane — its round has been given up on, \
                     so it is not sent (CIRISEdge#943)"
                );
            }
        } else {
            send(&coord, &state, &job).await;
        }
        state.bytes.fetch_sub(job.bytes, Ordering::AcqRel);
    }
}

async fn send(coord: &ReplicationCoordinator, state: &LaneState, job: &ReplyJob) {
    let peer = coord.peer_key_id();
    let kind = coord.kind();
    let failed = if job.finishes.is_some() {
        obs::RESPONDER_ROUND_SEND_THEN_COMPLETE_FAILED
    } else {
        obs::RESPONDER_ROUND_REPLY_SEND_FAILED
    };
    for m in &job.msgs {
        match tokio::time::timeout(RESPONDER_REPLY_SEND_TIMEOUT, coord.send_reply(m, job.round))
            .await
        {
            Ok(Ok(())) => continue,
            Ok(Err(e)) => tracing::warn!(
                peer = %peer, ?kind, error = %e,
                link = %coord.last_inbound_link_hex(),
                "responder reply send failed — round will not complete (history: CIRISEdge#348)"
            ),
            Err(_elapsed) => tracing::warn!(
                peer = %peer, ?kind,
                link = %coord.last_inbound_link_hex(),
                timeout_secs = RESPONDER_REPLY_SEND_TIMEOUT.as_secs(),
                "responder reply send TIMED OUT — abandoned (history: CIRISEdge#373); the next \
                 round rides the peer's fresh link"
            ),
        }
        count(coord, failed);
        state.send_failed.store(true, Ordering::Release);
        return;
    }
    if let Some(Finish { report, began }) = &job.finishes {
        count(coord, obs::RESPONDER_ROUND_COMPLETED_INITIATOR_FINAL);
        tracing::info!(
            peer = %peer, ?kind, ?report,
            link = %coord.last_inbound_link_hex(),
            duration_ms = u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX),
            "responder round complete (initiator-final path, CIRISEdge#380)"
        );
    }
}
