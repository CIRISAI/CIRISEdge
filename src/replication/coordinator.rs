//! Transport binding + round orchestration for the anti-entropy protocol.
//!
//! Layer (b) of CIRISEdge#65. Layer (a) — the protocol state machine
//! ([`super::session::Session`]) — is wire-bytes-in / wire-bytes-out and
//! has no networking. This module bridges the state machine to a live
//! [`crate::transport::Transport`] instance + drives a full anti-entropy
//! round end-to-end with a configured peer.
//!
//! Layer (c) (concrete [`StateProvider`] / [`StateApplier`] over
//! `FederationDirectory`) lands in a subsequent PR; the protocol +
//! coordinator surfaces in this PR consume the trait shapes via generic
//! parameters, so the layer-(c) adapters drop in without coordinator
//! changes.
//!
//! ## What this module owns
//!
//! - [`ReplicationCoordinator`] — pairs one [`super::Session`] with one
//!   transport peer-key-id. Exposes the verbs the application's
//!   scheduler calls to run anti-entropy.
//! - [`RoundReport`] — what the coordinator returns at the end of a
//!   round (admitted / refused / staleness). The application's metrics
//!   pipeline + the `τ_partial` signal flow off this.
//!
//! ## What this module does NOT own
//!
//! - **Scheduler**. The decision to run a round every N seconds, per
//!   peer, per kind, is operator policy. The application calls
//!   [`ReplicationCoordinator::run_initiator_round`] from its own
//!   `tokio::time::interval` loop; this module provides the verb,
//!   not the loop.
//! - **Inbound dispatch**. The application's [`Transport::listen`]
//!   delivers [`crate::transport::InboundFrame`]s; some of those frames
//!   carry replication protocol bytes, others carry signed federation
//!   envelopes. The application routes based on a wire-format
//!   discriminator (out of scope for this PR — followed up by an
//!   explicit frame-kind prefix in a subsequent PR). For now, the
//!   application identifies replication bytes some other way (e.g.
//!   per-medium port mapping) and hands them to
//!   [`ReplicationCoordinator::feed_inbound_bytes`].

use std::sync::Arc;

use tokio::sync::Mutex;

use crate::transport::{Transport, TransportError};

use super::protocol::{EnvelopeKind, ProtocolError, ReplicationMessage};
use super::session::{ReplicationOutcome, Session, SessionRole};
use super::summary::{StalenessSignal, StateApplier, StateProvider};

/// What an anti-entropy round produced. Surfaced to the application's
/// metrics + τ_partial signal pipelines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundReport {
    pub kind: EnvelopeKind,
    /// How many envelopes the [`StateApplier`] admitted (changed local
    /// state).
    pub admitted: usize,
    /// How many envelopes were delivered but refused (duplicates,
    /// signature-validation failures, anti-rollback collisions).
    pub refused: usize,
    /// The bounded-staleness signal at round close.
    pub staleness: StalenessSignal,
}

#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    #[error("replication protocol decode: {0}")]
    Protocol(#[from] ProtocolError),
    /// The peer sent an unexpected message for the current session
    /// state (e.g. a Deliver before any Diff was exchanged). Not
    /// fatal; the caller decides whether to retry or drop the peer.
    #[error("unexpected message in current session state")]
    UnexpectedMessage,
    /// `feed_inbound_bytes` was called but no round is in progress.
    /// Either the application's framing layer mis-routed a packet,
    /// or a late-arriving message from a round that already timed out.
    #[error("no round in progress — late or mis-routed inbound message")]
    NoRoundInProgress,
}

/// Binds one [`Session`] to one transport peer. The application
/// constructs one of these per `(peer_key_id, kind, role)` triple,
/// holds it across the lifetime of that anti-entropy relationship,
/// and drives rounds via [`Self::drive_round_step`] +
/// [`Self::send_message`] from its scheduler / listen-loop glue.
///
/// ## Long-lived session
///
/// The [`Session`] is held inside a `Mutex` for the coordinator's
/// lifetime. The state machine's `last_summary_sent`,
/// `last_remote_summary`, and `diff_want_count` persist across the
/// Summary → Diff → Deliver phase boundaries, so the post-Apply
/// [`StalenessSignal`] computes correctly (`BoundedBy { missing }` /
/// `InSync`) instead of degrading to `Unknown`. After a round
/// completes (`DriveStep::Complete` is observed), the coordinator
/// auto-resets the session so the next round can begin without
/// caller bookkeeping; the application's scheduler just calls
/// `drive_round_step(None)` (initiator) again to start the next
/// round, or `drive_round_step(Some(inbound))` (responder) on the
/// next inbound Summary.
pub struct ReplicationCoordinator {
    transport: Arc<dyn Transport>,
    peer_key_id: String,
    kind: EnvelopeKind,
    role: SessionRole,
    provider: Arc<dyn StateProvider>,
    applier: Arc<Mutex<dyn StateApplier>>,
    /// The long-lived state machine for this peer-pair anti-entropy
    /// relationship. Wrapped in `Mutex` so `drive_round_step` can
    /// take `&self` (matching the existing API + letting the
    /// scheduler / listen-loop call it concurrently from different
    /// tasks; the mutex serializes them — anti-entropy is sequential
    /// per peer-pair by protocol).
    session: Mutex<Session>,
    /// Sender half of the inbound-message channel. The application's
    /// [`Transport::listen`] loop calls
    /// [`Self::deliver_inbound`] which routes here; the
    /// [`super::scheduler::ReplicationScheduler`] reads the other
    /// end via [`Self::recv_inbound`] to step a round between
    /// `SendThenWait` and the next inbound. Bounded capacity 8 —
    /// enough to absorb the few in-flight Summary / Diff / Deliver
    /// messages without blocking the listen loop on a slow round.
    inbound_tx: tokio::sync::mpsc::Sender<ReplicationMessage>,
    inbound_rx: Mutex<tokio::sync::mpsc::Receiver<ReplicationMessage>>,
}

impl ReplicationCoordinator {
    /// Default inbound mpsc capacity. A round in flight has at most
    /// 3 messages queued (Summary + Diff + Deliver); 8 gives slack
    /// for a slightly-late deliver while the scheduler is mid-step.
    pub const INBOUND_CHANNEL_CAPACITY: usize = 8;

    pub fn new(
        transport: Arc<dyn Transport>,
        peer_key_id: impl Into<String>,
        kind: EnvelopeKind,
        role: SessionRole,
        provider: Arc<dyn StateProvider>,
        applier: Arc<Mutex<dyn StateApplier>>,
    ) -> Self {
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(Self::INBOUND_CHANNEL_CAPACITY);
        Self {
            transport,
            peer_key_id: peer_key_id.into(),
            kind,
            role,
            provider,
            applier,
            session: Mutex::new(Session::new(role, kind)),
            inbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
        }
    }

    /// Deliver an inbound replication message into this coordinator's
    /// queue. Called by the application's [`Transport::listen`] loop
    /// after [`Self::parse_inbound_bytes`] yields a
    /// [`ReplicationMessage`].
    ///
    /// Returns `Err(NoRoundInProgress)` if the inbound channel is full
    /// (the scheduler isn't keeping up; back-pressure surfaces). The
    /// listen loop typically logs + drops the frame.
    pub fn deliver_inbound(&self, msg: ReplicationMessage) -> Result<(), CoordinatorError> {
        self.inbound_tx
            .try_send(msg)
            .map_err(|_| CoordinatorError::NoRoundInProgress)
    }

    /// Wait for the next inbound replication message from the
    /// listen-loop-fed queue. Returns `None` if the channel is
    /// permanently closed (the coordinator is being dropped). The
    /// scheduler awaits on this between `SendThenWait` and the
    /// next round step.
    pub async fn recv_inbound(&self) -> Option<ReplicationMessage> {
        self.inbound_rx.lock().await.recv().await
    }

    /// Step the held [`Session`] one transition forward.
    ///
    /// - `msg = None` — start a new round (initiator only). Returns
    ///   `SendThenWait` with our outbound Summary.
    /// - `msg = Some(inbound)` — feed an inbound replication message
    ///   into the session.
    ///
    /// The session is long-lived across the call boundary, so
    /// `diff_want_count` recorded during the Diff phase carries into
    /// the Deliver phase — the post-Apply [`StalenessSignal`]
    /// computes correctly (`BoundedBy` / `InSync`), no longer
    /// `Unknown`.
    ///
    /// When the session completes (Applied outcome), the coordinator
    /// auto-resets it so the next `drive_round_step(None)` /
    /// inbound Summary starts a fresh round without caller
    /// bookkeeping.
    pub async fn drive_round_step(
        &self,
        msg: Option<ReplicationMessage>,
    ) -> Result<DriveStep, CoordinatorError> {
        let mut session = self.session.lock().await;
        let outcome = match msg {
            None => session.start_round(self.provider.as_ref()),
            Some(m) => {
                let mut applier = self.applier.lock().await;
                session.on_message(m, self.provider.as_ref(), &mut *applier)
            }
        };
        let step = Self::outcome_to_step(outcome);
        // Auto-reset on round completion so the next call can drive
        // a fresh round without the caller threading state.
        if matches!(step, DriveStep::Complete(_)) {
            session.reset();
        }
        Ok(step)
    }

    /// Whether this coordinator's session has completed its current
    /// round (Applied has been observed). Useful for the scheduler
    /// to decide whether to start a new round or wait. Note that
    /// `drive_round_step` auto-resets on Complete, so this returns
    /// `true` only briefly during a `drive_round_step` call that
    /// observes Applied; in practice the scheduler reads the
    /// `DriveStep::Complete` return directly.
    pub async fn is_round_complete(&self) -> bool {
        self.session.lock().await.is_complete()
    }

    /// The session's configured role. Fixed at construction; used
    /// by the scheduler to decide which side calls
    /// `drive_round_step(None)` to initiate each round.
    pub fn role(&self) -> SessionRole {
        self.role
    }

    /// The envelope kind this coordinator's anti-entropy round
    /// runs over. Fixed at construction; the scheduler reads this
    /// when fanning round cadence across (peer × kind) pairs.
    pub fn kind(&self) -> EnvelopeKind {
        self.kind
    }

    /// The peer identity this coordinator is bound to. Fixed at
    /// construction; metrics + telemetry consumers tag round
    /// reports with this.
    pub fn peer_key_id(&self) -> &str {
        &self.peer_key_id
    }

    fn outcome_to_step(outcome: ReplicationOutcome) -> DriveStep {
        match outcome {
            ReplicationOutcome::Send(msgs) => DriveStep::SendThenWait(msgs),
            ReplicationOutcome::Applied {
                kind,
                admitted,
                refused,
                staleness,
            } => DriveStep::Complete(RoundReport {
                kind,
                admitted,
                refused,
                staleness,
            }),
            ReplicationOutcome::RoundComplete { kind } => DriveStep::Complete(RoundReport {
                kind,
                admitted: 0,
                refused: 0,
                staleness: StalenessSignal::Unknown,
            }),
            ReplicationOutcome::UnexpectedMessage => DriveStep::Refused,
        }
    }

    /// Emit a [`ReplicationMessage`] on the underlying transport.
    /// Wraps via [`super::wire_frame::wrap`] (4-byte CRPL magic
    /// prefix + JSON body), then hands to [`Transport::send`]
    /// addressed at the configured peer_key_id.
    ///
    /// The magic prefix lets the application's [`Transport::listen`]
    /// loop route inbound bytes to the replication path without
    /// parsing every byte as every possible payload kind.
    pub async fn send_message(&self, msg: &ReplicationMessage) -> Result<(), CoordinatorError> {
        // v2.0.0 (FSD §3.7) — pick the wire version automatically from
        // the message's EnvelopeKind. v1 trust kinds emit at 0x01; v2
        // operational kinds emit at 0x02. The receiver's try_unwrap
        // accepts both, so v2-capable peers exchange both versions and
        // v1-only peers reject 0x02 frames at UnknownVersion (FSD §3.5).
        let bytes = super::wire_frame::wrap_for_kind(msg);
        self.transport
            .send(&self.peer_key_id, &bytes)
            .await
            .map(|_| ())
            .map_err(CoordinatorError::from)
    }

    /// Try to parse on-wire bytes as a [`ReplicationMessage`].
    /// Returns:
    ///
    /// - `Ok(Some(msg))` — bytes carry the CRPL magic and the JSON
    ///   body decoded cleanly. The caller's listen-loop dispatcher
    ///   feeds the message to [`Self::drive_round_step`].
    /// - `Ok(None)` — bytes are not a replication frame (magic
    ///   absent). The caller's dispatcher falls through to its
    ///   non-replication path (existing signed-envelope handler,
    ///   future key_grant handler, etc.).
    /// - `Err(CoordinatorError::Protocol)` — bytes have the CRPL
    ///   magic but the JSON body is malformed. Protocol violation
    ///   by the sender; the caller typically logs + drops the frame.
    pub fn try_parse_inbound_bytes(
        bytes: &[u8],
    ) -> Result<Option<ReplicationMessage>, CoordinatorError> {
        super::wire_frame::try_unwrap(bytes).map_err(CoordinatorError::from)
    }

    /// Strict parser that REQUIRES bytes to be a valid replication
    /// frame at the locked [`super::wire_frame::WIRE_PROTOCOL_VERSION`]
    /// (v1). Returns `Err` if the magic prefix is absent, the version
    /// byte is unrecognized, or the body is malformed. Prefer
    /// [`Self::try_parse_inbound_bytes`] in new dispatcher code so
    /// non-replication bytes route cleanly (Ok(None)) without
    /// surfacing as errors.
    ///
    /// ## v1 wire-stability — no pre-v1 bare-JSON tolerance
    ///
    /// Prior cuts of the replication module (#69 / #70) shipped a
    /// `parse_inbound_bytes` that tolerated bare-JSON inputs (no
    /// `CRPL` magic) to ease the rolling-upgrade window when the
    /// wire-frame prefix landed (#72). v1 LOCKS the wire format
    /// per `FSD/REPLICATION_WIRE_FORMAT_V1.md` §3.5: every
    /// replication frame MUST carry the 5-byte preamble (`CRPL` +
    /// `VER`). Bare-JSON inputs now surface as
    /// `CoordinatorError::Protocol(Decode(_))`. This is the
    /// version-stable contract going forward.
    pub fn parse_inbound_bytes(bytes: &[u8]) -> Result<ReplicationMessage, CoordinatorError> {
        match super::wire_frame::try_unwrap(bytes) {
            Ok(Some(msg)) => Ok(msg),
            Ok(None) => Err(CoordinatorError::Protocol(ProtocolError::Decode(
                "replication frame magic absent — wire format requires CRPL+VER preamble (v1)"
                    .into(),
            ))),
            Err(e) => Err(CoordinatorError::from(e)),
        }
    }
}

/// Step the [`ReplicationCoordinator::drive_round_step`] driver
/// returns. The caller threads these to make progress on the round.
#[derive(Debug, Clone)]
pub enum DriveStep {
    /// The session wants to send these messages out + then wait for
    /// the peer's reply. The caller sends each via
    /// [`ReplicationCoordinator::send_message`], then awaits the
    /// next inbound message + calls `drive_round_step(Some(msg))`.
    SendThenWait(Vec<ReplicationMessage>),
    /// The round completed; the report is the final state.
    Complete(RoundReport),
    /// The peer sent a message that didn't make sense in this round's
    /// current state. NOT fatal; the application may drop the peer
    /// or retry the round.
    Refused,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replication::protocol::{
        DeliverMessage, DiffMessage, EnvelopeKind, EnvelopeRef, SummaryMessage,
    };
    use crate::replication::summary::LocalState;
    use crate::transport::{InboundFrame, TransportId, TransportSendOutcome};
    use async_trait::async_trait;
    use std::collections::HashMap;

    /// In-memory transport for end-to-end coordinator tests. Two
    /// transports share a `MailBus` so peer A's send → peer B's
    /// recv-side channel. Cancellation-safe.
    #[derive(Clone)]
    struct InMemTransport {
        id: TransportId,
        /// Maps destination_key_id → outbound mpsc::Sender (delivers to
        /// that peer's mailbox).
        peer_inbox: HashMap<String, tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
        /// This peer's own mailbox.
        my_inbox: Arc<Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>>,
    }

    #[async_trait]
    impl Transport for InMemTransport {
        fn id(&self) -> TransportId {
            self.id
        }
        async fn send(
            &self,
            destination_key_id: &str,
            envelope_bytes: &[u8],
        ) -> Result<TransportSendOutcome, TransportError> {
            self.peer_inbox
                .get(destination_key_id)
                .ok_or_else(|| {
                    TransportError::Unreachable(format!("no in-mem peer for {destination_key_id}"))
                })?
                .send(envelope_bytes.to_vec())
                .map_err(|e| TransportError::Io(format!("inbox closed: {e}")))?;
            Ok(TransportSendOutcome::Delivered)
        }
        async fn listen(
            &self,
            _sink: tokio::sync::mpsc::Sender<InboundFrame>,
        ) -> Result<(), TransportError> {
            // Unused in these tests — we drive feed_inbound directly.
            unimplemented!("test fixture doesn't drive listen")
        }
    }

    fn alice_bob_transports() -> (InMemTransport, InMemTransport) {
        let (a_tx, a_rx) = tokio::sync::mpsc::unbounded_channel();
        let (b_tx, b_rx) = tokio::sync::mpsc::unbounded_channel();
        let alice = InMemTransport {
            id: TransportId::HTTP,
            peer_inbox: HashMap::from([("bob".to_string(), b_tx)]),
            my_inbox: Arc::new(Mutex::new(a_rx)),
        };
        let bob = InMemTransport {
            id: TransportId::HTTP,
            peer_inbox: HashMap::from([("alice".to_string(), a_tx)]),
            my_inbox: Arc::new(Mutex::new(b_rx)),
        };
        (alice, bob)
    }

    /// Provider backed by a static [`LocalState`] + bytes table.
    struct StaticProvider {
        state: LocalState,
        envelopes: HashMap<[u8; 32], Vec<u8>>,
    }
    impl StateProvider for StaticProvider {
        fn local_refs(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef> {
            self.state.refs_for(kind)
        }
        fn fetch_envelope(&self, _kind: EnvelopeKind, h: &[u8; 32]) -> Option<Vec<u8>> {
            self.envelopes.get(h).cloned()
        }
    }

    /// Applier that records every admitted envelope into a Vec the
    /// test can inspect.
    struct RecordingApplier {
        admitted_bytes: Vec<Vec<u8>>,
        known: HashMap<Vec<u8>, [u8; 32]>,
        local_hashes: std::collections::HashSet<[u8; 32]>,
    }
    impl StateApplier for RecordingApplier {
        fn apply_envelope(&mut self, _kind: EnvelopeKind, bytes: &[u8]) -> bool {
            if let Some(hash) = self.known.get(bytes).copied() {
                if self.local_hashes.contains(&hash) {
                    return false;
                }
                self.local_hashes.insert(hash);
                self.admitted_bytes.push(bytes.to_vec());
                true
            } else {
                false
            }
        }
    }

    fn h(seed: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = seed;
        a
    }

    /// Build a peer pair with disjoint state. Each peer holds two
    /// envelopes, none in common. After one anti-entropy round both
    /// should know all four.
    ///
    /// `clippy::too_many_lines` allowed because the seven explicit
    /// phases are the test — collapsing them into helpers obscures
    /// the round-shape this fixture demonstrates.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn two_coordinators_converge_via_in_memory_transport() {
        let (alice_t, bob_t) = alice_bob_transports();
        let alice_t = Arc::new(alice_t);
        let bob_t = Arc::new(bob_t);

        // Alice has env_1 + env_2.
        let mut a_state = LocalState::new();
        a_state.insert(EnvelopeKind::Key, h(1), 1);
        a_state.insert(EnvelopeKind::Key, h(2), 2);
        let a_provider = Arc::new(StaticProvider {
            state: a_state,
            envelopes: HashMap::from([(h(1), b"env_1".to_vec()), (h(2), b"env_2".to_vec())]),
        });
        // Bob has env_3 + env_4.
        let mut b_state = LocalState::new();
        b_state.insert(EnvelopeKind::Key, h(3), 3);
        b_state.insert(EnvelopeKind::Key, h(4), 4);
        let b_provider = Arc::new(StaticProvider {
            state: b_state,
            envelopes: HashMap::from([(h(3), b"env_3".to_vec()), (h(4), b"env_4".to_vec())]),
        });

        let a_applier: Arc<Mutex<dyn StateApplier>> = Arc::new(Mutex::new(RecordingApplier {
            admitted_bytes: Vec::new(),
            known: HashMap::from([(b"env_3".to_vec(), h(3)), (b"env_4".to_vec(), h(4))]),
            local_hashes: [h(1), h(2)].into_iter().collect(),
        }));
        let b_applier: Arc<Mutex<dyn StateApplier>> = Arc::new(Mutex::new(RecordingApplier {
            admitted_bytes: Vec::new(),
            known: HashMap::from([(b"env_1".to_vec(), h(1)), (b"env_2".to_vec(), h(2))]),
            local_hashes: [h(3), h(4)].into_iter().collect(),
        }));

        let alice_coord = ReplicationCoordinator::new(
            alice_t.clone(),
            "bob",
            EnvelopeKind::Key,
            SessionRole::Initiator,
            a_provider.clone(),
            a_applier.clone(),
        );
        let bob_coord = ReplicationCoordinator::new(
            bob_t.clone(),
            "alice",
            EnvelopeKind::Key,
            SessionRole::Responder,
            b_provider.clone(),
            b_applier.clone(),
        );

        // Drive the full anti-entropy round end-to-end across both
        // coordinators. With the long-lived session refactor, each
        // coordinator's Session preserves last_summary_sent +
        // diff_want_count across the Summary → Diff → Deliver phase
        // boundaries — so the final Applied outcomes carry correct
        // `StalenessSignal::InSync` instead of degrading to `Unknown`.

        // 1. Alice initiates → emits Summary.
        let alice_step1 = alice_coord.drive_round_step(None).await.unwrap();
        let alice_summary = match alice_step1 {
            DriveStep::SendThenWait(ref msgs) => {
                assert_eq!(msgs.len(), 1);
                msgs[0].clone()
            }
            o => panic!("expected SendThenWait, got {o:?}"),
        };
        alice_coord.send_message(&alice_summary).await.unwrap();

        // 2. Bob receives Alice's Summary → emits {Summary, Diff}.
        let bob_received_bytes = {
            let mut inbox = bob_t.my_inbox.lock().await;
            inbox.recv().await.expect("bob inbox")
        };
        let bob_inbound = ReplicationCoordinator::parse_inbound_bytes(&bob_received_bytes).unwrap();
        let bob_step1 = bob_coord.drive_round_step(Some(bob_inbound)).await.unwrap();
        let (bob_summary, bob_diff) = match bob_step1 {
            DriveStep::SendThenWait(ref msgs) => {
                assert_eq!(msgs.len(), 2);
                (msgs[0].clone(), msgs[1].clone())
            }
            o => panic!("expected SendThenWait, got {o:?}"),
        };
        bob_coord.send_message(&bob_summary).await.unwrap();
        bob_coord.send_message(&bob_diff).await.unwrap();

        // 3. Alice receives Bob's Summary → emits Diff (recording
        //    diff_want_count = 2 into the held Session).
        let alice_recv_summary_bytes = {
            let mut inbox = alice_t.my_inbox.lock().await;
            inbox.recv().await.expect("alice recv summary")
        };
        let alice_recv_summary =
            ReplicationCoordinator::parse_inbound_bytes(&alice_recv_summary_bytes).unwrap();
        let alice_step2 = alice_coord
            .drive_round_step(Some(alice_recv_summary))
            .await
            .unwrap();
        let alice_diff = match alice_step2 {
            DriveStep::SendThenWait(ref msgs) => {
                assert_eq!(msgs.len(), 1);
                msgs[0].clone()
            }
            o => panic!("expected SendThenWait, got {o:?}"),
        };
        alice_coord.send_message(&alice_diff).await.unwrap();

        // 4. Alice receives Bob's Diff → emits Deliver(env_1, env_2).
        let alice_recv_diff_bytes = {
            let mut inbox = alice_t.my_inbox.lock().await;
            inbox.recv().await.expect("alice recv diff")
        };
        let alice_recv_diff =
            ReplicationCoordinator::parse_inbound_bytes(&alice_recv_diff_bytes).unwrap();
        let alice_step3 = alice_coord
            .drive_round_step(Some(alice_recv_diff))
            .await
            .unwrap();
        let alice_deliver = match alice_step3 {
            DriveStep::SendThenWait(ref msgs) => {
                assert_eq!(msgs.len(), 1);
                msgs[0].clone()
            }
            o => panic!("expected SendThenWait, got {o:?}"),
        };
        alice_coord.send_message(&alice_deliver).await.unwrap();

        // 5. Bob receives Alice's Diff → emits Deliver(env_3, env_4).
        let bob_recv_diff_bytes = {
            let mut inbox = bob_t.my_inbox.lock().await;
            inbox.recv().await.expect("bob recv diff")
        };
        let bob_recv_diff =
            ReplicationCoordinator::parse_inbound_bytes(&bob_recv_diff_bytes).unwrap();
        let bob_step2 = bob_coord
            .drive_round_step(Some(bob_recv_diff))
            .await
            .unwrap();
        let bob_deliver = match bob_step2 {
            DriveStep::SendThenWait(ref msgs) => {
                assert_eq!(msgs.len(), 1);
                msgs[0].clone()
            }
            o => panic!("expected SendThenWait, got {o:?}"),
        };
        bob_coord.send_message(&bob_deliver).await.unwrap();

        // 6. Alice receives Bob's Deliver → Applied(admitted=2, InSync).
        let alice_recv_deliver_bytes = {
            let mut inbox = alice_t.my_inbox.lock().await;
            inbox.recv().await.expect("alice recv deliver")
        };
        let alice_recv_deliver =
            ReplicationCoordinator::parse_inbound_bytes(&alice_recv_deliver_bytes).unwrap();
        let alice_final = alice_coord
            .drive_round_step(Some(alice_recv_deliver))
            .await
            .unwrap();
        match alice_final {
            DriveStep::Complete(report) => {
                assert_eq!(report.kind, EnvelopeKind::Key);
                assert_eq!(report.admitted, 2);
                assert_eq!(report.refused, 0);
                // The long-lived session preserved diff_want_count = 2
                // from step 3 through to here — both admitted, so InSync.
                assert_eq!(report.staleness, StalenessSignal::InSync);
            }
            o => panic!("expected Complete, got {o:?}"),
        }

        // 7. Bob receives Alice's Deliver → Applied(admitted=2, InSync).
        let bob_recv_deliver_bytes = {
            let mut inbox = bob_t.my_inbox.lock().await;
            inbox.recv().await.expect("bob recv deliver")
        };
        let bob_recv_deliver =
            ReplicationCoordinator::parse_inbound_bytes(&bob_recv_deliver_bytes).unwrap();
        let bob_final = bob_coord
            .drive_round_step(Some(bob_recv_deliver))
            .await
            .unwrap();
        match bob_final {
            DriveStep::Complete(report) => {
                assert_eq!(report.admitted, 2);
                assert_eq!(report.staleness, StalenessSignal::InSync);
            }
            o => panic!("expected Complete, got {o:?}"),
        }

        // Both coordinators auto-reset on completion (the round is
        // ready to begin again on the next scheduler tick).
        assert!(!alice_coord.is_round_complete().await);
        assert!(!bob_coord.is_round_complete().await);
    }

    /// `try_parse_inbound_bytes` returns `Ok(None)` for non-replication
    /// bytes — the caller routes to non-replication dispatch.
    #[test]
    fn try_parse_inbound_bytes_returns_none_for_non_replication() {
        let r = ReplicationCoordinator::try_parse_inbound_bytes(b"{\"agent\":\"alice\"}")
            .expect("not an error");
        assert!(r.is_none());
    }

    /// `try_parse_inbound_bytes` returns `Ok(Some(msg))` for properly
    /// framed replication bytes (round-trip via the new wire frame).
    #[test]
    fn try_parse_inbound_bytes_round_trips_framed() {
        let msg = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Key,
            refs: vec![],
        });
        let framed = super::super::wire_frame::wrap(&msg);
        let parsed = ReplicationCoordinator::try_parse_inbound_bytes(&framed)
            .expect("not an error")
            .expect("some");
        assert_eq!(parsed, msg);
    }

    /// `try_parse_inbound_bytes` surfaces `Err(Protocol)` when the
    /// magic is present but the body is malformed.
    #[test]
    fn try_parse_inbound_bytes_protocol_error_on_bad_body() {
        let mut bytes = super::super::wire_frame::REPLICATION_FRAME_MAGIC.to_vec();
        bytes.extend_from_slice(b"{not json");
        let r = ReplicationCoordinator::try_parse_inbound_bytes(&bytes);
        assert!(matches!(r, Err(CoordinatorError::Protocol(_))));
    }

    /// `parse_inbound_bytes` is STRICT at v1: bare-JSON without the
    /// CRPL+VER preamble surfaces as `Protocol(Decode)`. The pre-v1
    /// rolling-upgrade tolerance is gone per FSD §3.5.
    #[test]
    fn parse_inbound_bytes_strict_v1_rejects_bare_json() {
        let msg = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Key,
            refs: vec![],
        });
        // Bare form — refused.
        let bare = msg.to_bytes();
        let r = ReplicationCoordinator::parse_inbound_bytes(&bare);
        assert!(
            matches!(r, Err(CoordinatorError::Protocol(_))),
            "v1 wire requires CRPL+VER preamble; bare-JSON must refuse"
        );
        // Framed form (CRPL+VER+body) — accepted.
        let framed = super::super::wire_frame::wrap(&msg);
        let parsed = ReplicationCoordinator::parse_inbound_bytes(&framed).expect("parse");
        assert_eq!(parsed, msg);
    }

    /// `parse_inbound_bytes` refuses junk cleanly — defence against
    /// the application's mis-routed frame.
    #[test]
    fn parse_inbound_bytes_refuses_junk() {
        let r = ReplicationCoordinator::parse_inbound_bytes(b"{not a replication message");
        assert!(matches!(r, Err(CoordinatorError::Protocol(_))));
    }

    /// Round-tripping a [`RoundReport`] through equality holds the
    /// shape we surface to metrics consumers.
    #[test]
    fn round_report_shape() {
        let report = RoundReport {
            kind: EnvelopeKind::Revocation,
            admitted: 5,
            refused: 1,
            staleness: StalenessSignal::BoundedBy { missing: 2 },
        };
        assert_eq!(report.kind, EnvelopeKind::Revocation);
        assert_eq!(report.admitted, 5);
        assert_eq!(report.refused, 1);
        assert_eq!(report.staleness, StalenessSignal::BoundedBy { missing: 2 });
    }

    /// `send_message` propagates [`TransportError::Unreachable`] when
    /// the configured peer isn't in the in-mem bus's peer_inbox map.
    #[tokio::test]
    async fn send_to_unknown_peer_surfaces_unreachable() {
        let (alice_t, _bob_t) = alice_bob_transports();
        let alice_t = Arc::new(alice_t);
        let a_provider = Arc::new(StaticProvider {
            state: LocalState::new(),
            envelopes: HashMap::new(),
        });
        let a_applier: Arc<Mutex<dyn StateApplier>> = Arc::new(Mutex::new(RecordingApplier {
            admitted_bytes: Vec::new(),
            known: HashMap::new(),
            local_hashes: std::collections::HashSet::new(),
        }));
        let coord = ReplicationCoordinator::new(
            alice_t,
            "nobody_home",
            EnvelopeKind::Key,
            SessionRole::Initiator,
            a_provider,
            a_applier,
        );
        let m = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Key,
            refs: vec![],
        });
        let r = coord.send_message(&m).await;
        assert!(matches!(
            r,
            Err(CoordinatorError::Transport(TransportError::Unreachable(_)))
        ));
    }

    /// `drive_round_step(None)` from an Initiator yields a Summary
    /// outbound. Smoke test on the simplest happy path.
    #[tokio::test]
    async fn initiator_first_step_is_summary() {
        let (alice_t, _bob_t) = alice_bob_transports();
        let mut alice_state = LocalState::new();
        alice_state.insert(EnvelopeKind::Key, h(1), 1);
        let provider = Arc::new(StaticProvider {
            state: alice_state,
            envelopes: HashMap::from([(h(1), b"e1".to_vec())]),
        });
        let applier: Arc<Mutex<dyn StateApplier>> = Arc::new(Mutex::new(RecordingApplier {
            admitted_bytes: Vec::new(),
            known: HashMap::new(),
            local_hashes: [h(1)].into_iter().collect(),
        }));
        let coord = ReplicationCoordinator::new(
            Arc::new(alice_t),
            "bob",
            EnvelopeKind::Key,
            SessionRole::Initiator,
            provider,
            applier,
        );
        let step = coord.drive_round_step(None).await.unwrap();
        match step {
            DriveStep::SendThenWait(msgs) => {
                assert_eq!(msgs.len(), 1);
                if let ReplicationMessage::Summary(s) = &msgs[0] {
                    assert_eq!(s.kind, EnvelopeKind::Key);
                    assert_eq!(s.refs.len(), 1);
                    assert_eq!(s.refs[0].envelope_hash, h(1));
                } else {
                    panic!("expected Summary, got {:?}", msgs[0]);
                }
            }
            o => panic!("expected SendThenWait, got {o:?}"),
        }
    }

    /// Responder side: feeding a Summary in produces SendThenWait
    /// with two outbound messages (my Summary + my Diff).
    #[tokio::test]
    async fn responder_side_emits_summary_then_diff() {
        let (alice_t, _bob_t) = alice_bob_transports();
        let provider = Arc::new(StaticProvider {
            state: LocalState::new(),
            envelopes: HashMap::new(),
        });
        let applier: Arc<Mutex<dyn StateApplier>> = Arc::new(Mutex::new(RecordingApplier {
            admitted_bytes: Vec::new(),
            known: HashMap::new(),
            local_hashes: std::collections::HashSet::new(),
        }));
        let coord = ReplicationCoordinator::new(
            Arc::new(alice_t),
            "bob",
            EnvelopeKind::Key,
            SessionRole::Responder,
            provider,
            applier,
        );
        let remote_summary = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Key,
            refs: vec![EnvelopeRef {
                envelope_hash: h(99),
                seq: 1,
            }],
        });
        let step = coord.drive_round_step(Some(remote_summary)).await.unwrap();
        match step {
            DriveStep::SendThenWait(msgs) => {
                assert_eq!(msgs.len(), 2);
                assert!(matches!(msgs[0], ReplicationMessage::Summary(_)));
                if let ReplicationMessage::Diff(d) = &msgs[1] {
                    // We want h(99) — the only thing the remote claims to have.
                    assert_eq!(d.want, vec![h(99)]);
                } else {
                    panic!("expected Diff in msgs[1], got {:?}", msgs[1]);
                }
            }
            o => panic!("expected SendThenWait, got {o:?}"),
        }
    }

    /// Deliver fed directly into a session that never saw a prior
    /// Diff yields `StalenessSignal::Unknown` — the session's
    /// `diff_want_count` is `None`, the honest signal is "I don't
    /// know how stale I am." NOT the same as the prior (pre-long-
    /// lived) `Unknown` bug; here it's correct.
    #[tokio::test]
    async fn deliver_without_prior_diff_yields_unknown_staleness() {
        let (alice_t, _bob_t) = alice_bob_transports();
        let provider = Arc::new(StaticProvider {
            state: LocalState::new(),
            envelopes: HashMap::new(),
        });
        let applier: Arc<Mutex<dyn StateApplier>> = Arc::new(Mutex::new(RecordingApplier {
            admitted_bytes: Vec::new(),
            known: HashMap::from([(b"e1".to_vec(), h(1))]),
            local_hashes: std::collections::HashSet::new(),
        }));
        let coord = ReplicationCoordinator::new(
            Arc::new(alice_t),
            "bob",
            EnvelopeKind::Key,
            SessionRole::Initiator,
            provider,
            applier,
        );
        let deliver_msg = ReplicationMessage::Deliver(DeliverMessage {
            kind: EnvelopeKind::Key,
            envelopes: vec![b"e1".to_vec()],
        });
        let step = coord.drive_round_step(Some(deliver_msg)).await.unwrap();
        match step {
            DriveStep::Complete(report) => {
                assert_eq!(report.kind, EnvelopeKind::Key);
                assert_eq!(report.admitted, 1);
                assert_eq!(report.refused, 0);
                // No prior Diff → diff_want_count is None → honest
                // Unknown. (Contrast with the full-round path in
                // `two_coordinators_converge_via_in_memory_transport`
                // where the long-lived session carries diff_want_count
                // through and reports InSync.)
                assert_eq!(report.staleness, StalenessSignal::Unknown);
            }
            o => panic!("expected Complete, got {o:?}"),
        }
    }

    /// Long-lived Session: driving the full Initiator-side phase
    /// chain (Summary → recv remote Summary → recv Diff → recv
    /// Deliver) through a single coordinator yields the correct
    /// post-Apply staleness — the held session preserves
    /// `diff_want_count` across the call boundaries.
    #[tokio::test]
    async fn long_lived_session_preserves_diff_want_count_across_calls() {
        let (alice_t, _bob_t) = alice_bob_transports();
        // Alice has env_1; will learn env_3 + env_4 from "bob"
        // (synthesized via direct drive_round_step calls).
        let mut alice_state = LocalState::new();
        alice_state.insert(EnvelopeKind::Key, h(1), 1);
        let provider = Arc::new(StaticProvider {
            state: alice_state,
            envelopes: HashMap::from([(h(1), b"env_1".to_vec())]),
        });
        let applier: Arc<Mutex<dyn StateApplier>> = Arc::new(Mutex::new(RecordingApplier {
            admitted_bytes: Vec::new(),
            known: HashMap::from([(b"env_3".to_vec(), h(3)), (b"env_4".to_vec(), h(4))]),
            local_hashes: [h(1)].into_iter().collect(),
        }));
        let coord = ReplicationCoordinator::new(
            Arc::new(alice_t),
            "bob",
            EnvelopeKind::Key,
            SessionRole::Initiator,
            provider,
            applier,
        );

        // Phase 1: Initiator starts a round → Summary out.
        let _ = coord.drive_round_step(None).await.unwrap();

        // Phase 2: Synthesize Bob's Summary (advertising env_3 + env_4)
        // and feed it. Session computes Diff (want = [h(3), h(4)],
        // diff_want_count = 2) and stores it.
        let bob_summary = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Key,
            refs: vec![
                EnvelopeRef {
                    envelope_hash: h(3),
                    seq: 3,
                },
                EnvelopeRef {
                    envelope_hash: h(4),
                    seq: 4,
                },
            ],
        });
        let step2 = coord.drive_round_step(Some(bob_summary)).await.unwrap();
        match step2 {
            DriveStep::SendThenWait(msgs) => {
                if let ReplicationMessage::Diff(d) = &msgs[0] {
                    assert_eq!(d.want, vec![h(3), h(4)]);
                } else {
                    panic!("expected Diff");
                }
            }
            o => panic!("expected SendThenWait, got {o:?}"),
        }

        // Phase 3: Synthesize Bob's Diff (asking for env_1) → Deliver out.
        let bob_diff = ReplicationMessage::Diff(DiffMessage {
            kind: EnvelopeKind::Key,
            want: vec![h(1)],
        });
        let _ = coord.drive_round_step(Some(bob_diff)).await.unwrap();

        // Phase 4: Synthesize Bob's Deliver (env_3 + env_4).
        // The session's diff_want_count = 2 from phase 2 is still set;
        // both envelopes admit; staleness should be InSync.
        let bob_deliver = ReplicationMessage::Deliver(DeliverMessage {
            kind: EnvelopeKind::Key,
            envelopes: vec![b"env_3".to_vec(), b"env_4".to_vec()],
        });
        let step4 = coord.drive_round_step(Some(bob_deliver)).await.unwrap();
        match step4 {
            DriveStep::Complete(report) => {
                assert_eq!(report.admitted, 2);
                assert_eq!(report.refused, 0);
                assert_eq!(report.staleness, StalenessSignal::InSync);
            }
            o => panic!("expected Complete, got {o:?}"),
        }
    }

    /// After a round completes, the coordinator auto-resets the
    /// session so the next call begins a fresh round — the
    /// scheduler doesn't have to track per-peer "in flight" state.
    #[tokio::test]
    async fn round_auto_resets_after_complete() {
        let (alice_t, _bob_t) = alice_bob_transports();
        let provider = Arc::new(StaticProvider {
            state: LocalState::new(),
            envelopes: HashMap::new(),
        });
        let applier: Arc<Mutex<dyn StateApplier>> = Arc::new(Mutex::new(RecordingApplier {
            admitted_bytes: Vec::new(),
            known: HashMap::from([(b"e1".to_vec(), h(1))]),
            local_hashes: std::collections::HashSet::new(),
        }));
        let coord = ReplicationCoordinator::new(
            Arc::new(alice_t),
            "bob",
            EnvelopeKind::Key,
            SessionRole::Initiator,
            provider,
            applier,
        );
        // Drive into Applied (degenerate path: Deliver without Diff).
        let deliver = ReplicationMessage::Deliver(DeliverMessage {
            kind: EnvelopeKind::Key,
            envelopes: vec![b"e1".to_vec()],
        });
        let step = coord.drive_round_step(Some(deliver)).await.unwrap();
        assert!(matches!(step, DriveStep::Complete(_)));
        // After Complete, the session auto-reset; is_complete is false.
        assert!(!coord.is_round_complete().await);
        // The next drive_round_step(None) starts a fresh round
        // (would otherwise be a debug_assert panic if the session
        // were still mid-round).
        let _ = coord.drive_round_step(None).await.unwrap();
    }

    /// Mismatched-kind inbound message produces `DriveStep::Refused`
    /// — the application can decide to drop the peer or retry.
    #[tokio::test]
    async fn mismatched_kind_inbound_refused() {
        let (alice_t, _bob_t) = alice_bob_transports();
        let provider = Arc::new(StaticProvider {
            state: LocalState::new(),
            envelopes: HashMap::new(),
        });
        let applier: Arc<Mutex<dyn StateApplier>> = Arc::new(Mutex::new(RecordingApplier {
            admitted_bytes: Vec::new(),
            known: HashMap::new(),
            local_hashes: std::collections::HashSet::new(),
        }));
        let coord = ReplicationCoordinator::new(
            Arc::new(alice_t),
            "bob",
            EnvelopeKind::Key, // ← session is for Key
            SessionRole::Responder,
            provider,
            applier,
        );
        let wrong_kind = ReplicationMessage::Diff(DiffMessage {
            kind: EnvelopeKind::Revocation, // ← inbound for Revocation
            want: vec![],
        });
        let step = coord.drive_round_step(Some(wrong_kind)).await.unwrap();
        assert!(matches!(step, DriveStep::Refused));
    }
}
