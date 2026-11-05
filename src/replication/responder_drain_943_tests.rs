//! CIRISEdge#943 — a reply the reverse path is holding must not hold the
//! frames behind it.
//!
//! Everything here is the production path below the transport: frames an
//! initiator's real session produced (`start_round` with #927 proactive
//! publish: `Summary` then `Deliver`, v3-stamped), routed by the real registry
//! into the real responder driver over a real session. The seam is one
//! transport whose `send` parks while the plane is held.

use std::collections::HashSet;
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
use super::protocol::{EnvelopeKind, ReplicationMessage};
use super::registry::ReplicationRegistry;
use super::runtime::spawn_responder_drive;
use super::session::SessionRole;
use super::wire_frame;
use crate::observability::EdgeMetrics;
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
    fail: std::sync::atomic::AtomicBool,
}

impl ReverseSeam {
    fn new() -> Arc<Self> {
        let (held, _) = watch::channel(HashSet::new());
        Arc::new(Self {
            held,
            entered: StdMutex::default(),
            sent: StdMutex::default(),
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

/// The responder's side: the real registry and the real driver.
struct Responder {
    registry: Arc<ReplicationRegistry>,
    dir: Arc<MockReplicationDirectory>,
    seam: Arc<ReverseSeam>,
    metrics: EdgeMetrics,
}

fn responder() -> Responder {
    let registry = Arc::new(ReplicationRegistry::new());
    let dir = Arc::new(MockReplicationDirectory::new());
    let seam = ReverseSeam::new();
    let metrics = EdgeMetrics::new();
    let (d, s, m) = (Arc::clone(&dir), Arc::clone(&seam), metrics.clone());
    registry.set_responder_factory(Arc::new(move |peer, kind| {
        let directory: Arc<dyn ReplicationDirectory> = d.clone();
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
