//! **CIRISEdge#968 (wait A) — a plane a new peer drops unattributed is asked
//! again soon after the peer can attribute it, not a cadence later.**
//!
//! Server's docker rig: a new node's first Attestation round to the canonical
//! was dropped because the canonical had not rooted it yet. The canonical
//! rooted it 12 s later; nothing asked again until the node's next tick, so
//! the canonical took the node's owner-binding 40 s after the kick and the
//! contact waited 37 s on it.
//!
//! A real scheduler on a paused clock against a scripted peer with exactly
//! that rule: the bootstrap planes are answered at once (they are admitted
//! unattributed), and an Attestation Summary is dropped, with no reply, until
//! the peer's rooting lands. Every time here is exact.
//!
//! `cargo test --lib first_contact_retry_968`

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::watch;
use tokio::time::Instant;

use super::coordinator::ReplicationCoordinator;
use super::protocol::{
    DeliverMessage, DiffMessage, EnvelopeKind, EnvelopeRef, ReplicationMessage, SummaryMessage,
};
use super::scheduler::{ReplicationScheduler, SchedulerConfig};
use super::session::SessionRole;
use super::summary::{ApplyOutcome, StateApplier, StateProvider};
use super::wire_frame;
use crate::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};

const PEER: &str = "canonical-968";
const PLANES: [EnvelopeKind; 2] = [EnvelopeKind::Attestation, EnvelopeKind::Key];
/// The rig's measured lag between the first dropped round and the rooting.
const ROOTING_LAG: Duration = Duration::from_secs(12);

/// When the scripted peer answers which plane.
#[derive(Clone, Copy)]
enum Peer {
    /// Bootstrap planes at once; Attestation only from `start + ROOTING_LAG`.
    RootsAfterLag,
    /// Bootstrap planes at once; Attestation never (it never roots us).
    NeverRoots,
    /// Nothing at all: down, or overloaded.
    Silent,
}

struct Canonical {
    rule: Peer,
    start: Instant,
    /// The send time of every Attestation Summary it saw.
    attestation_summaries: Mutex<Vec<Instant>>,
    /// When an Attestation round was first ANSWERED.
    answered_at: Mutex<Option<Instant>>,
    coords: Mutex<Vec<Arc<ReplicationCoordinator>>>,
}

impl Canonical {
    fn new(rule: Peer) -> Arc<Self> {
        Arc::new(Self {
            rule,
            start: Instant::now(),
            attestation_summaries: Mutex::new(Vec::new()),
            answered_at: Mutex::new(None),
            coords: Mutex::new(Vec::new()),
        })
    }

    fn answers(&self, kind: EnvelopeKind) -> bool {
        match (self.rule, kind) {
            (Peer::Silent, _) => false,
            (_, k) if k != EnvelopeKind::Attestation => true,
            (Peer::RootsAfterLag, _) => Instant::now() >= self.start + ROOTING_LAG,
            (Peer::NeverRoots, _) => false,
        }
    }

    fn reply(&self, kind: EnvelopeKind, round: u64, msg: ReplicationMessage) {
        let coord = self
            .coords
            .lock()
            .unwrap()
            .iter()
            .find(|c| c.kind() == kind)
            .cloned();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            if let Some(c) = coord {
                let _ = c.deliver_reply(msg, round);
            }
        });
    }
}

#[async_trait]
impl Transport for Canonical {
    fn id(&self) -> TransportId {
        TransportId::RETICULUM_RS
    }
    async fn send(
        &self,
        _destination_key_id: &str,
        bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError> {
        let framed = wire_frame::try_unwrap_framed(bytes)
            .expect("a frame")
            .expect("a replication frame");
        let round = framed.meta.map_or(0, |m| m.round);
        match framed.msg {
            ReplicationMessage::Summary(s) => {
                let kind = s.kind;
                if kind == EnvelopeKind::Attestation {
                    self.attestation_summaries
                        .lock()
                        .unwrap()
                        .push(Instant::now());
                }
                if !self.answers(kind) {
                    // Dropped at attribution: no reply of any kind.
                    return Ok(TransportSendOutcome::Delivered);
                }
                self.reply(
                    kind,
                    round,
                    ReplicationMessage::Summary(SummaryMessage {
                        status: None,
                        kind,
                        refs: Vec::new(),
                    }),
                );
                self.reply(
                    kind,
                    round,
                    ReplicationMessage::Diff(DiffMessage {
                        kind,
                        want: Vec::new(),
                    }),
                );
            }
            ReplicationMessage::Diff(d) => {
                self.reply(
                    d.kind,
                    round,
                    ReplicationMessage::Deliver(DeliverMessage {
                        kind: d.kind,
                        envelopes: Vec::new(),
                    }),
                );
            }
            _ => {}
        }
        Ok(TransportSendOutcome::Delivered)
    }
    async fn listen(
        &self,
        _sink: tokio::sync::mpsc::Sender<InboundFrame>,
    ) -> Result<(), TransportError> {
        Ok(())
    }
}

/// One row on every plane; records when an Attestation round completed.
struct Rows {
    canonical: Arc<Canonical>,
}

#[async_trait]
impl StateProvider for Rows {
    async fn local_refs(&self, _kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        vec![EnvelopeRef {
            envelope_hash: [9; 32],
            seq: 1,
        }]
    }
    async fn fetch_envelope(&self, _kind: EnvelopeKind, _h: &[u8; 32]) -> Option<Vec<u8>> {
        Some(vec![1])
    }
    fn round_ended(&self, kind: EnvelopeKind, lost: bool) {
        if kind == EnvelopeKind::Attestation && !lost {
            let mut at = self.canonical.answered_at.lock().unwrap();
            if at.is_none() {
                *at = Some(Instant::now());
            }
        }
    }
}

#[async_trait]
impl StateApplier for Rows {
    async fn apply_envelope(
        &self,
        _kind: EnvelopeKind,
        _bytes: &[u8],
        _source_peer: Option<&str>,
    ) -> ApplyOutcome {
        ApplyOutcome::Duplicate
    }
}

/// A node that starts with the canonical as a peer on Attestation and Key
/// (a restart's peer list: no bootstrap hold), run for `run`.
async fn run_node(rule: Peer, cadence: Duration, run: Duration) -> Arc<Canonical> {
    let canonical = Canonical::new(rule);
    let rows = Arc::new(Rows {
        canonical: Arc::clone(&canonical),
    });
    let mut sched = ReplicationScheduler::new(SchedulerConfig {
        cadence,
        round_timeout: SchedulerConfig::DEFAULT_ROUND_TIMEOUT,
        ..SchedulerConfig::default()
    });
    for kind in PLANES {
        let coord = Arc::new(ReplicationCoordinator::new(
            Arc::clone(&canonical) as Arc<dyn Transport>,
            PEER,
            kind,
            SessionRole::Initiator,
            Arc::clone(&rows) as Arc<dyn StateProvider>,
            Arc::clone(&rows) as Arc<dyn StateApplier>,
        ));
        canonical.coords.lock().unwrap().push(Arc::clone(&coord));
        sched.add_initiator(coord);
    }
    let (cancel, cancel_rx) = watch::channel(false);
    let task = tokio::spawn(sched.run_until_cancelled(cancel_rx));
    tokio::time::sleep(run).await;
    let _ = cancel.send(true);
    let _ = task.await;
    canonical
}

/// **The witness.** The canonical drops the first Attestation round and roots
/// the node 12 s in. The round is answered within a few seconds of that, not
/// at the next tick 30 s in. With the retry ladder removed the first answer is
/// the tick's (30 s), and this fails.
#[tokio::test(start_paused = true)]
async fn a_dropped_first_round_is_answered_soon_after_rooting_lands_968() {
    let c = run_node(
        Peer::RootsAfterLag,
        SchedulerConfig::DEFAULT_CADENCE,
        Duration::from_secs(45),
    )
    .await;
    let answered = c
        .answered_at
        .lock()
        .unwrap()
        .expect("the Attestation round is answered");
    let rooted = c.start + ROOTING_LAG;
    assert!(answered >= rooted, "nothing is answered before the rooting");
    assert!(
        answered - rooted < Duration::from_secs(7),
        "answered {:?} after the rooting landed, not at the next tick ({:?} in); \
         summaries at {:?}",
        answered - rooted,
        SchedulerConfig::DEFAULT_CADENCE,
        c.attestation_summaries
            .lock()
            .unwrap()
            .iter()
            .map(|t| *t - c.start)
            .collect::<Vec<_>>()
    );
}

/// **No amplification on a silent peer.** A peer that answers no plane is down
/// or overloaded, not refusing one plane for want of attribution: its rounds
/// keep the cadence. 100 s at 30 s is the ticks at 0, 30, 60 and 90. With the
/// "answers elsewhere" lease removed, the ladder adds retries and this fails.
#[tokio::test(start_paused = true)]
async fn a_silent_peer_gets_the_cadence_and_no_early_retries_968() {
    let c = run_node(
        Peer::Silent,
        SchedulerConfig::DEFAULT_CADENCE,
        Duration::from_secs(100),
    )
    .await;
    let sent = c.attestation_summaries.lock().unwrap().len();
    assert_eq!(sent, 4, "one Attestation round per tick, nothing more");
}

/// **Bounded.** A peer that answers its bootstrap planes but never roots this
/// node gets exactly [`super::scheduler`]'s three early retries, then the
/// cadence. At a 60 s cadence an early retry follows the dropped round by its
/// 10 s timeout plus at most 24 s; a cadence gap is 60 s. With the bound
/// removed every gap is short, and this fails.
#[tokio::test(start_paused = true)]
async fn a_peer_that_never_roots_costs_three_early_retries_then_the_cadence_968() {
    let c = run_node(
        Peer::NeverRoots,
        Duration::from_mins(1),
        Duration::from_secs(400),
    )
    .await;
    let sent = c.attestation_summaries.lock().unwrap().clone();
    let gaps: Vec<Duration> = sent.windows(2).map(|w| w[1] - w[0]).collect();
    let short = gaps
        .iter()
        .filter(|g| **g < Duration::from_secs(40))
        .count();
    assert_eq!(
        short, 3,
        "three early retries, then the cadence: gaps {gaps:?}"
    );
    assert!(
        gaps.iter().skip(3).all(|g| *g >= Duration::from_secs(59)),
        "after the ladder, the cadence: gaps {gaps:?}"
    );
}
