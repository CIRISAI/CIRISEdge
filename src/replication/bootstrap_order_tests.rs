//! **A new peer's first Attestation round is not lost to attribution.**
//!
//! The rig (`t442-rig`, p1a/p1b): A's first Attestation round toward a new
//! contact left with the bootstrap planes. B could not attribute the frames
//! until it held A's route row, dropped them, and A sat out the round timeout:
//! 11 s of contact. B also refused the route until the key landed, so a
//! bootstrap round's END did not mean the peer held the row.
//!
//! A real scheduler on a paused clock against a scripted peer with exactly
//! those rules, so every time here is exact.
//!
//! `cargo test --lib bootstrap_order`

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

const PEER: &str = "new-contact";
/// How long the peer takes to admit a row.
const ADMIT: Duration = Duration::from_millis(300);

#[derive(Default)]
struct PeerState {
    key_at: Option<Instant>,
    occurrence_at: Option<Instant>,
    route_at: Option<Instant>,
    grant_at: Option<Instant>,
    dropped: usize,
    /// The route row is refused for good: a plane that cannot land.
    refuse_route: bool,
}

/// The new contact: admits the bootstrap planes unattributed, refuses a route
/// whose signer's key it lacks, and drops an Attestation frame it cannot
/// attribute, with no reply.
struct NewContact {
    state: Mutex<PeerState>,
    coords: Mutex<Vec<Arc<ReplicationCoordinator>>>,
}

impl NewContact {
    fn holds(&self, kind: EnvelopeKind) -> bool {
        let s = self.state.lock().unwrap();
        let at = match kind {
            EnvelopeKind::Key => s.key_at,
            EnvelopeKind::IdentityOccurrence => s.occurrence_at,
            EnvelopeKind::TransportDestination => s.route_at,
            _ => s.grant_at,
        };
        at.is_some_and(|t| t <= Instant::now())
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

    fn take(&self, kind: EnvelopeKind) {
        let held_key = self.holds(EnvelopeKind::Key);
        let mut s = self.state.lock().unwrap();
        let at = Some(Instant::now() + ADMIT);
        match kind {
            EnvelopeKind::Key => s.key_at = s.key_at.or(at),
            EnvelopeKind::IdentityOccurrence if held_key => {
                s.occurrence_at = s.occurrence_at.or(at);
            }
            EnvelopeKind::TransportDestination if held_key && !s.refuse_route => {
                s.route_at = s.route_at.or(at);
            }
            EnvelopeKind::Attestation => s.grant_at = s.grant_at.or(Some(Instant::now())),
            _ => {}
        }
    }
}

#[async_trait]
impl Transport for NewContact {
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
        let attribution_failed = |kind| {
            kind == EnvelopeKind::Attestation && !self.holds(EnvelopeKind::TransportDestination)
        };
        match framed.msg {
            ReplicationMessage::Summary(s) if attribution_failed(s.kind) => {
                self.state.lock().unwrap().dropped += 1;
            }
            ReplicationMessage::Summary(s) => {
                let kind = s.kind;
                self.reply(
                    kind,
                    round,
                    ReplicationMessage::Summary(SummaryMessage {
                        status: None,
                        kind,
                        refs: Vec::new(),
                    }),
                );
                let want = if self.holds(kind) {
                    Vec::new()
                } else {
                    s.refs.iter().map(|r| r.envelope_hash).collect()
                };
                self.reply(
                    kind,
                    round,
                    ReplicationMessage::Diff(DiffMessage { kind, want }),
                );
            }
            ReplicationMessage::Deliver(d) if !d.envelopes.is_empty() => self.take(d.kind),
            ReplicationMessage::Diff(d) => {
                let kind = d.kind;
                self.reply(
                    kind,
                    round,
                    ReplicationMessage::Deliver(DeliverMessage {
                        kind,
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

struct OneRow;

#[async_trait]
impl StateProvider for OneRow {
    async fn local_refs(&self, _kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        vec![EnvelopeRef {
            envelope_hash: [7; 32],
            seq: 1,
        }]
    }
    async fn fetch_envelope(&self, _kind: EnvelopeKind, _h: &[u8; 32]) -> Option<Vec<u8>> {
        Some(vec![1])
    }
}

#[async_trait]
impl StateApplier for OneRow {
    async fn apply_envelope(
        &self,
        _kind: EnvelopeKind,
        _bytes: &[u8],
        _source_peer: Option<&str>,
    ) -> ApplyOutcome {
        ApplyOutcome::Duplicate
    }
}

/// Run a new peer on all four planes for `run`, the host adding Attestation
/// first, and read the contact's state.
async fn new_peer(refuse_route: bool, run: Duration) -> Arc<NewContact> {
    let contact = Arc::new(NewContact {
        state: Mutex::new(PeerState {
            refuse_route,
            ..PeerState::default()
        }),
        coords: Mutex::new(Vec::new()),
    });
    let mut sched = ReplicationScheduler::new(SchedulerConfig {
        round_timeout: SchedulerConfig::DEFAULT_ROUND_TIMEOUT,
        ..SchedulerConfig::default()
    });
    for kind in [
        EnvelopeKind::Attestation,
        EnvelopeKind::Key,
        EnvelopeKind::IdentityOccurrence,
        EnvelopeKind::TransportDestination,
    ] {
        let coord = Arc::new(ReplicationCoordinator::new(
            Arc::clone(&contact) as Arc<dyn Transport>,
            PEER,
            kind,
            SessionRole::Initiator,
            Arc::new(OneRow),
            Arc::new(OneRow),
        ));
        contact.coords.lock().unwrap().push(Arc::clone(&coord));
        sched.add_initiator(coord);
    }
    let (cancel, cancel_rx) = watch::channel(false);
    let task = tokio::spawn(sched.run_until_cancelled(cancel_rx));
    tokio::time::sleep(run).await;
    let _ = cancel.send(true);
    let _ = task.await;
    contact
}

/// The rig's case: no frame is lost, and the grant lands right behind the route.
#[tokio::test(start_paused = true)]
async fn a_new_peers_first_attestation_round_is_not_lost_to_attribution() {
    let started = Instant::now();
    let contact = new_peer(false, Duration::from_secs(20)).await;
    let s = contact.state.lock().unwrap();
    assert_eq!(
        s.dropped, 0,
        "no Attestation frame reached it unattributable"
    );
    let route = s.route_at.expect("the route lands");
    let grant = s.grant_at.expect("the grant lands");
    assert!(grant >= route, "the grant waits for the route");
    assert!(
        grant - route < Duration::from_secs(2),
        "and lands right behind it, not a round timeout later: {:?}",
        grant - route
    );
    assert!(
        grant - started < Duration::from_secs(4),
        "from the start: {:?}",
        grant - started
    );
}

/// A plane that cannot land holds nothing for long: the round runs at the bound.
#[tokio::test(start_paused = true)]
async fn a_bootstrap_plane_that_cannot_land_does_not_hold_the_round_for_ever() {
    let contact = new_peer(true, Duration::from_secs(8)).await;
    let s = contact.state.lock().unwrap();
    assert!(s.route_at.is_none());
    assert_eq!(s.dropped, 1, "the round ran once the bound passed");
}
