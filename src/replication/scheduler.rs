//! Periodic round-driver for the anti-entropy protocol.
//!
//! Closes the `replication::mod.rs` documented non-goal — "the
//! decision to run a round every N seconds, per peer, per kind, is
//! operator policy." This module *is* that operator policy, expressed
//! as a small composable harness: bind any number of Initiator-side
//! [`ReplicationCoordinator`]s to a cadence, spawn one tokio task per
//! coordinator, and the scheduler runs Summary → SendThenWait → recv
//! inbound → DriveStep loops on each one independently.
//!
//! ## Where this fits
//!
//! The application's two integration touch points with anti-entropy
//! are:
//!
//! - **Inbound** — [`Transport::listen`](crate::transport::Transport::listen)
//!   delivers framed bytes; the listen loop calls
//!   [`ReplicationCoordinator::parse_inbound_bytes`] (or the trichotomy
//!   variant) and routes the [`ReplicationMessage`] to the matching
//!   coordinator via [`ReplicationCoordinator::deliver_inbound`].
//!   That works for BOTH the Initiator-side (mid-round replies) and
//!   the Responder-side (round-starting Summary from a remote peer).
//!
//! - **Outbound timer** — for each Initiator-side coordinator, a
//!   tokio task fires `interval.tick()` at the configured cadence and
//!   runs one round to completion (or timeout). That's this module.
//!
//! Responder-side rounds need no scheduler: the Responder's
//! `drive_round_step` runs synchronously inside the listen loop's
//! dispatch path, returning `SendThenWait { Summary, Diff }` which
//! the listen loop sends via the coordinator's transport, then
//! `Deliver` arrives on the inbound channel and the next
//! `drive_round_step(Some(...))` finishes the round.
//!
//! ## Cancellation
//!
//! [`ReplicationScheduler::run_until_cancelled`] takes a
//! [`tokio::sync::watch::Receiver<bool>`] that the caller flips to
//! `true` to ask the scheduler to stop. Shipping watch (already in
//! tokio core, no new dep) instead of `CancellationToken` keeps the
//! dep surface minimal.
//!
//! ## Round timeout
//!
//! Each in-flight `SendThenWait` wait is bounded by `round_timeout`.
//! On expiry the scheduler logs the timeout, resets the coordinator's
//! session (the next interval tick starts fresh), and continues —
//! anti-entropy is *eventually consistent* by design, so a stuck
//! round is a missed cadence, not a fault. The next round will pick
//! up whatever state changed in the meantime.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};

use super::coordinator::{CoordinatorError, DriveStep, ReplicationCoordinator, RoundReport};
use super::protocol::EnvelopeKind;
use super::session::SessionRole;

/// Scheduler configuration shared across all coordinators it drives.
///
/// `cadence` is how often each Initiator coordinator starts a new
/// round. `round_timeout` is the max wall-clock time the scheduler
/// will wait on an inbound message between SendThenWait phases
/// before giving up on the round.
///
/// Defaults are deliberately conservative — small fleets / LAN /
/// quiet links — so the operator tunes UP for slower mediums (LoRa
/// packet-radio) and DOWN for hot federations. The
/// `Default` impl matches the prior `mod.rs` documentation guidance
/// ("every N seconds, per peer, per kind"; N=30s is the federation
/// MISSION's "near-realtime convergence" anchor).
#[derive(Debug, Clone, Copy)]
pub struct SchedulerConfig {
    pub cadence: Duration,
    pub round_timeout: Duration,
}

impl SchedulerConfig {
    pub const DEFAULT_CADENCE: Duration = Duration::from_secs(30);
    pub const DEFAULT_ROUND_TIMEOUT: Duration = Duration::from_secs(10);
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            cadence: Self::DEFAULT_CADENCE,
            round_timeout: Self::DEFAULT_ROUND_TIMEOUT,
        }
    }
}

/// What the scheduler observed running one round on one coordinator.
/// Surfaced via the run loop's `tracing` span so metrics / dashboards
/// see per-round outcome.
#[derive(Debug, Clone)]
pub enum RoundEvent {
    /// Round completed; the report carries admitted / refused /
    /// staleness for the metrics pipeline.
    Completed(RoundReport),
    /// Coordinator rejected the round (peer sent a malformed or
    /// out-of-state message). The scheduler reset the session and
    /// will retry on the next cadence tick.
    Refused,
    /// `round_timeout` elapsed waiting for an inbound message between
    /// SendThenWait phases. The scheduler reset the session.
    TimedOut,
    /// Transport / protocol error during the round. The scheduler
    /// logged it; the next interval tick will try fresh.
    Error(String),
}

/// Periodically drive anti-entropy rounds on a set of Initiator-side
/// coordinators.
///
/// One scheduler instance can hold many coordinators (one per
/// `(peer, kind)` pair this node is the initiator for). Each gets its
/// own tokio task with its own `interval`, so a slow peer's round
/// doesn't block other peers' cadence.
///
/// Constructing the scheduler does NOT spawn any tasks; the caller
/// chooses when to start the run loop via
/// [`Self::run_until_cancelled`].
///
/// ## Runtime control plane (CIRISEdge#173, v5.1.0)
///
/// Call [`Self::install_control_channel`] before starting the run
/// loop to obtain a [`SchedulerHandle`] that lets external code add
/// or remove Initiator coordinators *while the loop is running* —
/// no restart required. Without that call the scheduler keeps its
/// pre-v5.1 fixed-set semantics.
pub struct ReplicationScheduler {
    config: SchedulerConfig,
    coordinators: Vec<Arc<ReplicationCoordinator>>,
    command_rx: Option<mpsc::Receiver<SchedulerCommand>>,
}

/// Runtime control command for an actively-running scheduler.
///
/// Emitted by [`SchedulerHandle`] and consumed inside
/// [`ReplicationScheduler::run_with_events`].
pub enum SchedulerCommand {
    /// Spawn a new Initiator coordinator task. The coordinator's
    /// role must be [`SessionRole::Initiator`] (debug-asserted).
    AddInitiator(Arc<ReplicationCoordinator>),
    /// Stop the running task for the matching `(peer_key_id, kind)`
    /// coordinator, if present. No-op if the pair was never added.
    RemoveInitiator {
        peer_key_id: String,
        kind: EnvelopeKind,
    },
}

impl std::fmt::Debug for SchedulerCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AddInitiator(coord) => f
                .debug_struct("AddInitiator")
                .field("peer_key_id", &coord.peer_key_id())
                .field("kind", &coord.kind())
                .finish(),
            Self::RemoveInitiator { peer_key_id, kind } => f
                .debug_struct("RemoveInitiator")
                .field("peer_key_id", peer_key_id)
                .field("kind", kind)
                .finish(),
        }
    }
}

/// External handle for mutating a running scheduler's Initiator set.
///
/// Acquired via [`ReplicationScheduler::install_control_channel`]
/// BEFORE the run loop starts. Cheaply clonable. Sending on a closed
/// channel (the scheduler has shut down) returns an error.
#[derive(Clone, Debug)]
pub struct SchedulerHandle {
    command_tx: mpsc::Sender<SchedulerCommand>,
}

impl SchedulerHandle {
    /// Add an Initiator coordinator to the running scheduler. The
    /// scheduler spawns a new task on its next select iteration.
    /// Idempotent vs. an already-active `(peer_key_id, kind)`:
    /// duplicates are silently dropped inside the run loop.
    pub async fn add_initiator(
        &self,
        coord: Arc<ReplicationCoordinator>,
    ) -> Result<(), SchedulerCommandError> {
        self.command_tx
            .send(SchedulerCommand::AddInitiator(coord))
            .await
            .map_err(|_| SchedulerCommandError::SchedulerStopped)
    }

    /// Stop the running task for `(peer_key_id, kind)`. No-op if
    /// that pair isn't currently active.
    pub async fn remove_initiator(
        &self,
        peer_key_id: impl Into<String>,
        kind: EnvelopeKind,
    ) -> Result<(), SchedulerCommandError> {
        self.command_tx
            .send(SchedulerCommand::RemoveInitiator {
                peer_key_id: peer_key_id.into(),
                kind,
            })
            .await
            .map_err(|_| SchedulerCommandError::SchedulerStopped)
    }
}

/// Failure reason for [`SchedulerHandle`] command sends.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerCommandError {
    /// The scheduler's run loop has exited, so its command receiver
    /// dropped. Subsequent sends will keep failing.
    #[error("scheduler has stopped; runtime control channel is closed")]
    SchedulerStopped,
}

impl ReplicationScheduler {
    pub fn new(config: SchedulerConfig) -> Self {
        Self {
            config,
            coordinators: Vec::new(),
            command_rx: None,
        }
    }

    /// Install the runtime control channel (CIRISEdge#173). Returns
    /// the sender side as a [`SchedulerHandle`]; the scheduler keeps
    /// the receiver. Must be called before the run loop starts to
    /// take effect; calling twice replaces the prior receiver, which
    /// silently invalidates any earlier handle.
    ///
    /// Without this call the scheduler retains its pre-v5.1 fixed-set
    /// semantics — only coordinators added before `run_until_cancelled`
    /// via [`Self::add_initiator`] are driven.
    pub fn install_control_channel(&mut self) -> SchedulerHandle {
        let (command_tx, command_rx) = mpsc::channel(32);
        self.command_rx = Some(command_rx);
        SchedulerHandle { command_tx }
    }

    /// Register an Initiator-side coordinator with the scheduler.
    /// Panics in debug builds if the coordinator's role isn't
    /// [`SessionRole::Initiator`] — responder rounds are driven by
    /// the application's listen loop, not the scheduler.
    pub fn add_initiator(&mut self, coord: Arc<ReplicationCoordinator>) {
        debug_assert_eq!(
            coord.role(),
            SessionRole::Initiator,
            "scheduler drives Initiator coordinators only; \
             Responder rounds run inline in the listen loop"
        );
        self.coordinators.push(coord);
    }

    /// Number of registered coordinators.
    pub fn len(&self) -> usize {
        self.coordinators.len()
    }

    /// Whether the scheduler holds zero coordinators.
    pub fn is_empty(&self) -> bool {
        self.coordinators.is_empty()
    }

    /// Drive all registered coordinators until the caller flips
    /// `cancel` to `true`. Each coordinator runs as an independent
    /// tokio task; the function returns when all tasks have
    /// observed the cancel signal + exited their interval loops.
    ///
    /// `cancel` is a `tokio::sync::watch::Receiver<bool>`; the
    /// caller holds the [`tokio::sync::watch::Sender`] and calls
    /// `.send(true)` to ask for shutdown. The scheduler checks the
    /// signal on every iteration of every coordinator's loop, so
    /// shutdown latency is bounded by the slowest coordinator's
    /// `round_timeout`.
    ///
    /// Returns on clean shutdown. The scheduler does NOT propagate
    /// per-round errors — those are observed via the `tracing` spans
    /// each round emits (and via the optional `event_sink` channel
    /// callers can wire in via [`Self::run_with_events`]).
    pub async fn run_until_cancelled(self, cancel: watch::Receiver<bool>) {
        self.run_with_events(cancel, None).await;
    }

    /// Variant of [`Self::run_until_cancelled`] that also routes each
    /// round's [`RoundEvent`] into a caller-supplied channel. Useful
    /// for metrics / test assertions / [`crate::replication::summary::StalenessSignal`]
    /// telemetry consumers. Drop the receiver to stop receiving
    /// events; the scheduler tolerates a closed sink (the round
    /// loops continue).
    pub async fn run_with_events(
        mut self,
        mut cancel: watch::Receiver<bool>,
        event_sink: Option<mpsc::Sender<(String, RoundEvent)>>,
    ) {
        // Per-coord cancel senders, keyed by (peer_key_id, kind).
        // RemoveInitiator flips one entry; global cancel flips all.
        let mut per_coord: HashMap<(String, EnvelopeKind), watch::Sender<bool>> = HashMap::new();
        let mut handles = Vec::with_capacity(self.coordinators.len());

        for coord in self.coordinators.drain(..) {
            spawn_coord(
                &mut per_coord,
                &mut handles,
                coord,
                self.config.cadence,
                self.config.round_timeout,
                event_sink.clone(),
            );
        }

        let mut command_rx = self.command_rx.take();
        loop {
            tokio::select! {
                biased;
                _ = cancel.changed() => {
                    if *cancel.borrow() {
                        for (_, tx) in per_coord.drain() {
                            let _ = tx.send(true);
                        }
                        break;
                    }
                }
                Some(cmd) = async {
                    // SAFETY of unwrap: the `if` guard below is
                    // evaluated before this branch is polled, so
                    // command_rx is Some when we enter.
                    command_rx.as_mut().unwrap().recv().await
                }, if command_rx.is_some() => {
                    match cmd {
                        SchedulerCommand::AddInitiator(coord) => {
                            let key = (coord.peer_key_id().to_string(), coord.kind());
                            if per_coord.contains_key(&key) {
                                tracing::debug!(
                                    peer = %key.0,
                                    kind = ?key.1,
                                    "scheduler: AddInitiator ignored (already active)"
                                );
                                continue;
                            }
                            spawn_coord(
                                &mut per_coord,
                                &mut handles,
                                coord,
                                self.config.cadence,
                                self.config.round_timeout,
                                event_sink.clone(),
                            );
                        }
                        SchedulerCommand::RemoveInitiator { peer_key_id, kind } => {
                            if let Some(tx) = per_coord.remove(&(peer_key_id, kind)) {
                                let _ = tx.send(true);
                            }
                        }
                    }
                }
                else => {
                    // command_rx is None AND cancel is not changing —
                    // wait on cancel only.
                    let _ = cancel.changed().await;
                    if *cancel.borrow() {
                        for (_, tx) in per_coord.drain() {
                            let _ = tx.send(true);
                        }
                        break;
                    }
                }
            }
        }

        for h in handles {
            // join_all would be nicer but adds futures-util dep
            // outside our current set. Sequential .await is fine —
            // tasks cancel concurrently in response to the same
            // signal.
            let _ = h.await;
        }
    }
}

/// Spawn one coordinator task and record its per-coord cancel handle.
fn spawn_coord(
    per_coord: &mut HashMap<(String, EnvelopeKind), watch::Sender<bool>>,
    handles: &mut Vec<tokio::task::JoinHandle<()>>,
    coord: Arc<ReplicationCoordinator>,
    cadence: Duration,
    round_timeout: Duration,
    event_sink: Option<mpsc::Sender<(String, RoundEvent)>>,
) {
    debug_assert_eq!(
        coord.role(),
        SessionRole::Initiator,
        "scheduler spawns Initiator coordinators only"
    );
    let key = (coord.peer_key_id().to_string(), coord.kind());
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    per_coord.insert(key, cancel_tx);
    let h = tokio::spawn(async move {
        run_one_coordinator_forever(coord, cadence, round_timeout, &mut cancel_rx, event_sink)
            .await;
    });
    handles.push(h);
}

async fn run_one_coordinator_forever(
    coord: Arc<ReplicationCoordinator>,
    cadence: Duration,
    round_timeout: Duration,
    cancel: &mut watch::Receiver<bool>,
    event_sink: Option<tokio::sync::mpsc::Sender<(String, RoundEvent)>>,
) {
    let mut interval = tokio::time::interval(cadence);
    // `Burst` is the default; with `MissedTickBehavior::Skip` a
    // long-delayed task wouldn't fire bursts to catch up. We want
    // Skip — a stuck round eating cadence ticks shouldn't compound
    // into a burst of rounds the moment it unblocks.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let peer_id = coord.peer_key_id().to_string();
    let kind_str = format!("{:?}", coord.kind());

    loop {
        tokio::select! {
            biased;
            _ = cancel.changed() => {
                if *cancel.borrow() {
                    return;
                }
            }
            _ = interval.tick() => {
                let span = tracing::info_span!("anti_entropy_round", peer = %peer_id, kind = %kind_str);
                let _enter = span.enter();
                let event = match run_one_round(&coord, round_timeout).await {
                    Ok(DriveStep::Complete(report)) => RoundEvent::Completed(report),
                    Ok(DriveStep::Refused) => {
                        tracing::warn!("round refused; resetting session");
                        RoundEvent::Refused
                    }
                    Ok(DriveStep::SendThenWait(_)) => {
                        // This shouldn't happen — run_one_round loops
                        // until Complete or Refused. If it did, treat
                        // as a timeout so the next tick recovers.
                        tracing::warn!("scheduler returned mid-round; resetting");
                        RoundEvent::TimedOut
                    }
                    Err(RoundError::Timeout) => {
                        tracing::warn!("round timed out waiting for peer reply");
                        RoundEvent::TimedOut
                    }
                    Err(RoundError::Coordinator(e)) => {
                        tracing::warn!(error = %e, "coordinator error during round");
                        RoundEvent::Error(e.to_string())
                    }
                    Err(RoundError::InboundClosed) => {
                        tracing::warn!("inbound channel closed; cannot complete round");
                        RoundEvent::Error("inbound channel closed".to_string())
                    }
                };
                if let Some(sink) = &event_sink {
                    // Sink-closed isn't a fault — the metrics consumer
                    // dropped their receiver. Round loops continue.
                    let _ = sink.send((peer_id.clone(), event)).await;
                }
            }
        }
    }
}

#[derive(Debug)]
enum RoundError {
    Timeout,
    InboundClosed,
    Coordinator(CoordinatorError),
}

impl From<CoordinatorError> for RoundError {
    fn from(e: CoordinatorError) -> Self {
        Self::Coordinator(e)
    }
}

/// Drive a single round end-to-end on one coordinator: start_round →
/// loop { send_outbound; await inbound; drive_round_step } until
/// Complete or Refused.
async fn run_one_round(
    coord: &ReplicationCoordinator,
    round_timeout: Duration,
) -> Result<DriveStep, RoundError> {
    let mut step = coord.drive_round_step(None).await?;
    loop {
        let msgs = match step {
            DriveStep::SendThenWait(ref msgs) => msgs.clone(),
            _ => return Ok(step),
        };
        for m in &msgs {
            coord.send_message(m).await?;
        }
        let next = match tokio::time::timeout(round_timeout, coord.recv_inbound()).await {
            Ok(Some(msg)) => msg,
            Ok(None) => return Err(RoundError::InboundClosed),
            Err(_) => return Err(RoundError::Timeout),
        };
        step = coord.drive_round_step(Some(next)).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replication::coordinator::ReplicationCoordinator;
    use crate::replication::protocol::{EnvelopeKind, EnvelopeRef};
    use crate::replication::session::SessionRole;
    use crate::replication::summary::{LocalState, StalenessSignal, StateApplier, StateProvider};
    use crate::transport::{
        InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
    };
    use async_trait::async_trait;
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    fn h(seed: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = seed;
        a
    }

    /// In-memory transport mirroring the coordinator test fixture.
    /// Alice-and-Bob share two channels (one each direction); the
    /// scheduler's listen-loop equivalent here is a small task that
    /// drains the inbox into the matching coordinator's
    /// `deliver_inbound`.
    struct InMemTransport {
        peer_inbox: HashMap<String, tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
    }

    #[async_trait]
    impl Transport for InMemTransport {
        fn id(&self) -> TransportId {
            TransportId::HTTP
        }
        async fn send(
            &self,
            destination_key_id: &str,
            envelope_bytes: &[u8],
        ) -> Result<TransportSendOutcome, TransportError> {
            self.peer_inbox
                .get(destination_key_id)
                .ok_or_else(|| TransportError::Unreachable(destination_key_id.to_string()))?
                .send(envelope_bytes.to_vec())
                .map_err(|e| TransportError::Io(format!("inbox closed: {e}")))?;
            Ok(TransportSendOutcome::Delivered)
        }
        async fn listen(
            &self,
            _sink: tokio::sync::mpsc::Sender<InboundFrame>,
        ) -> Result<(), TransportError> {
            unimplemented!("test fixture drives inbox manually")
        }
    }

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

    struct RecordingApplier {
        known: HashMap<Vec<u8>, [u8; 32]>,
        local_hashes: std::collections::HashSet<[u8; 32]>,
    }
    impl StateApplier for RecordingApplier {
        fn apply_envelope(&mut self, _kind: EnvelopeKind, bytes: &[u8]) -> bool {
            let Some(hash) = self.known.get(bytes).copied() else {
                return false;
            };
            if self.local_hashes.contains(&hash) {
                return false;
            }
            self.local_hashes.insert(hash);
            true
        }
    }

    /// The scheduler default cadence + timeout are real wall-clock
    /// numbers; tests use much shorter values. We use real time
    /// (not `start_paused`) because the lib-test build doesn't pull
    /// tokio's `test-util` feature; the 10ms/500ms pair completes
    /// the round-trip tests in well under a second.
    fn fast_config() -> SchedulerConfig {
        SchedulerConfig {
            cadence: Duration::from_millis(10),
            round_timeout: Duration::from_millis(500),
        }
    }

    /// Smoke: register and len/is_empty track.
    #[test]
    fn add_initiator_tracks_len() {
        let mut s = ReplicationScheduler::new(fast_config());
        assert!(s.is_empty());
        let (alice_to_bob_tx, _alice_to_bob_rx) = tokio::sync::mpsc::unbounded_channel();
        let transport = Arc::new(InMemTransport {
            peer_inbox: HashMap::from([("bob".to_string(), alice_to_bob_tx)]),
        });
        let provider = Arc::new(StaticProvider {
            state: LocalState::new(),
            envelopes: HashMap::new(),
        });
        let applier: Arc<Mutex<dyn StateApplier>> = Arc::new(Mutex::new(RecordingApplier {
            known: HashMap::new(),
            local_hashes: std::collections::HashSet::new(),
        }));
        let coord = Arc::new(ReplicationCoordinator::new(
            transport,
            "bob",
            EnvelopeKind::Key,
            SessionRole::Initiator,
            provider,
            applier,
        ));
        s.add_initiator(coord);
        assert_eq!(s.len(), 1);
        assert!(!s.is_empty());
    }

    /// Defaults are sane.
    #[test]
    fn default_config_pins_30s_and_10s() {
        let c = SchedulerConfig::default();
        assert_eq!(c.cadence, Duration::from_secs(30));
        assert_eq!(c.round_timeout, Duration::from_secs(10));
    }

    /// End-to-end: scheduler drives Alice (Initiator) through a full
    /// anti-entropy round against Bob (Responder, driven manually as
    /// the listen loop would). Asserts the round completes with
    /// admitted=2 + StalenessSignal::InSync — the long-lived session
    /// + scheduler + inbound channel are all wired correctly.
    #[tokio::test]
    async fn scheduler_drives_initiator_round_to_completion() {
        // Build Alice-and-Bob channels (transport mailboxes).
        let (alice_to_bob_tx, mut alice_to_bob_rx) = tokio::sync::mpsc::unbounded_channel();
        let (bob_to_alice_tx, mut bob_to_alice_rx) = tokio::sync::mpsc::unbounded_channel();
        let alice_transport = Arc::new(InMemTransport {
            peer_inbox: HashMap::from([("bob".to_string(), alice_to_bob_tx)]),
        });
        let bob_transport = Arc::new(InMemTransport {
            peer_inbox: HashMap::from([("alice".to_string(), bob_to_alice_tx)]),
        });

        // Alice has env_1 + env_2; Bob has env_3 + env_4.
        let mut a_state = LocalState::new();
        a_state.insert(EnvelopeKind::Key, h(1), 1);
        a_state.insert(EnvelopeKind::Key, h(2), 2);
        let alice_provider = Arc::new(StaticProvider {
            state: a_state,
            envelopes: HashMap::from([(h(1), b"env_1".to_vec()), (h(2), b"env_2".to_vec())]),
        });
        let mut b_state = LocalState::new();
        b_state.insert(EnvelopeKind::Key, h(3), 3);
        b_state.insert(EnvelopeKind::Key, h(4), 4);
        let bob_provider = Arc::new(StaticProvider {
            state: b_state,
            envelopes: HashMap::from([(h(3), b"env_3".to_vec()), (h(4), b"env_4".to_vec())]),
        });
        let alice_applier: Arc<Mutex<dyn StateApplier>> = Arc::new(Mutex::new(RecordingApplier {
            known: HashMap::from([(b"env_3".to_vec(), h(3)), (b"env_4".to_vec(), h(4))]),
            local_hashes: [h(1), h(2)].into_iter().collect(),
        }));
        let bob_applier: Arc<Mutex<dyn StateApplier>> = Arc::new(Mutex::new(RecordingApplier {
            known: HashMap::from([(b"env_1".to_vec(), h(1)), (b"env_2".to_vec(), h(2))]),
            local_hashes: [h(3), h(4)].into_iter().collect(),
        }));

        let alice_coord = Arc::new(ReplicationCoordinator::new(
            alice_transport,
            "bob",
            EnvelopeKind::Key,
            SessionRole::Initiator,
            alice_provider,
            alice_applier,
        ));
        let bob_coord = Arc::new(ReplicationCoordinator::new(
            bob_transport,
            "alice",
            EnvelopeKind::Key,
            SessionRole::Responder,
            bob_provider,
            bob_applier,
        ));

        // Listen-loop simulation: drain Alice's outgoing mailbox →
        // parse → Bob.deliver_inbound; drain Bob's outgoing → parse
        // → Alice.deliver_inbound. Tokio task each.
        let bob_for_alice_route = bob_coord.clone();
        tokio::spawn(async move {
            while let Some(bytes) = alice_to_bob_rx.recv().await {
                let msg = ReplicationCoordinator::parse_inbound_bytes(&bytes).unwrap();
                let _ = bob_for_alice_route.deliver_inbound(msg);
            }
        });
        let alice_for_bob_route = alice_coord.clone();
        tokio::spawn(async move {
            while let Some(bytes) = bob_to_alice_rx.recv().await {
                let msg = ReplicationCoordinator::parse_inbound_bytes(&bytes).unwrap();
                let _ = alice_for_bob_route.deliver_inbound(msg);
            }
        });

        // Bob is the Responder; the application's listen-loop calls
        // drive_round_step(Some(msg)) inline as inbound arrives.
        // Simulate via a task: pull from Bob's recv_inbound, step
        // the responder session, send any outbound, repeat.
        let bob_drive = bob_coord.clone();
        tokio::spawn(async move {
            loop {
                let Some(msg) = bob_drive.recv_inbound().await else {
                    return;
                };
                let step = bob_drive.drive_round_step(Some(msg)).await.unwrap();
                if let DriveStep::SendThenWait(msgs) = step {
                    for m in &msgs {
                        bob_drive.send_message(m).await.unwrap();
                    }
                }
            }
        });

        // Wire the scheduler with Alice as the Initiator.
        let mut sched = ReplicationScheduler::new(fast_config());
        sched.add_initiator(alice_coord.clone());

        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(16);
        let sched_handle =
            tokio::spawn(async move { sched.run_with_events(cancel_rx, Some(event_tx)).await });

        // Real-time wait for the first RoundEvent. The 10ms cadence
        // + the small async hop chain finishes well under the 5s
        // bound on any sane host.
        let (peer, event) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("scheduler round event")
            .expect("event channel open");
        assert_eq!(peer, "bob");
        match event {
            RoundEvent::Completed(report) => {
                assert_eq!(report.kind, EnvelopeKind::Key);
                assert_eq!(report.admitted, 2);
                assert_eq!(report.refused, 0);
                assert_eq!(report.staleness, StalenessSignal::InSync);
            }
            o => panic!("expected Completed, got {o:?}"),
        }

        // Shut the scheduler down.
        cancel_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), sched_handle)
            .await
            .expect("scheduler shutdown")
            .expect("scheduler join");
    }

    /// Round timeout: the Initiator's peer never replies → the
    /// scheduler observes `TimedOut`, the session resets, and the
    /// next cadence tick fires a fresh round.
    #[tokio::test]
    async fn scheduler_reports_timeout_when_peer_silent() {
        let (alice_to_bob_tx, mut alice_to_bob_rx) = tokio::sync::mpsc::unbounded_channel();
        let alice_transport = Arc::new(InMemTransport {
            peer_inbox: HashMap::from([("bob".to_string(), alice_to_bob_tx)]),
        });
        // Black-hole the outbound traffic — Bob doesn't reply.
        tokio::spawn(async move { while alice_to_bob_rx.recv().await.is_some() {} });

        let provider = Arc::new(StaticProvider {
            state: LocalState::new(),
            envelopes: HashMap::new(),
        });
        let applier: Arc<Mutex<dyn StateApplier>> = Arc::new(Mutex::new(RecordingApplier {
            known: HashMap::new(),
            local_hashes: std::collections::HashSet::new(),
        }));
        let alice_coord = Arc::new(ReplicationCoordinator::new(
            alice_transport,
            "bob",
            EnvelopeKind::Key,
            SessionRole::Initiator,
            provider,
            applier,
        ));

        let config = SchedulerConfig {
            cadence: Duration::from_millis(10),
            round_timeout: Duration::from_millis(100),
        };
        let mut sched = ReplicationScheduler::new(config);
        sched.add_initiator(alice_coord);

        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(16);
        let sched_handle =
            tokio::spawn(async move { sched.run_with_events(cancel_rx, Some(event_tx)).await });

        // Real-time wait for the first TimedOut event. cadence + round_timeout
        // is ~110ms so 5s is comfortable headroom.
        let (peer, event) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("scheduler timeout event")
            .expect("channel open");
        assert_eq!(peer, "bob");
        assert!(
            matches!(event, RoundEvent::TimedOut),
            "expected TimedOut, got {event:?}"
        );

        cancel_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), sched_handle)
            .await
            .expect("shutdown")
            .expect("join");
    }

    /// Cancellation: the scheduler exits cleanly when `cancel` flips
    /// to true.
    #[tokio::test]
    async fn scheduler_exits_on_cancel() {
        let sched = ReplicationScheduler::new(fast_config());
        // Empty scheduler should be a no-op + exit immediately
        // (no coordinators means no tasks to wait on).
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let h = tokio::spawn(async move { sched.run_until_cancelled(cancel_rx).await });
        cancel_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), h)
            .await
            .expect("exit on cancel")
            .expect("join");
    }

    /// CIRISEdge#173 / v5.1.0 — `SchedulerHandle::add_initiator` on
    /// a running scheduler spawns a task that actively initiates
    /// rounds. Proof-of-life via `RoundEvent` emission: a coord
    /// targeting an unreachable peer produces `RoundEvent::Error`
    /// rounds (transport Unreachable) which can only happen if the
    /// task fired. Then `remove_initiator` stops the events.
    #[tokio::test]
    async fn control_channel_add_remove_drives_initiator_task() {
        let mut sched = ReplicationScheduler::new(fast_config());
        let control = sched.install_control_channel();
        let (event_tx, mut event_rx) = mpsc::channel::<(String, RoundEvent)>(64);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let sched_handle =
            tokio::spawn(async move { sched.run_with_events(cancel_rx, Some(event_tx)).await });

        // Build an Initiator coord pointing at a peer that doesn't
        // exist in the in-memory inbox. Every send fails with
        // TransportError::Unreachable → RoundEvent::Error per round.
        let transport: Arc<dyn Transport> = Arc::new(InMemTransport {
            peer_inbox: HashMap::new(),
        });
        let provider: Arc<dyn StateProvider> = Arc::new(StaticProvider {
            state: {
                let mut s = LocalState::new();
                s.insert(EnvelopeKind::Key, h(7), 7);
                s
            },
            envelopes: HashMap::new(),
        });
        let applier: Arc<Mutex<dyn StateApplier>> = Arc::new(Mutex::new(RecordingApplier {
            known: HashMap::new(),
            local_hashes: std::collections::HashSet::new(),
        }));
        let coord = Arc::new(ReplicationCoordinator::new(
            transport,
            "ghost-peer",
            EnvelopeKind::Key,
            SessionRole::Initiator,
            provider,
            applier,
        ));

        control
            .add_initiator(Arc::clone(&coord))
            .await
            .expect("send AddInitiator");

        // Wait for at least one event for ghost-peer to confirm the
        // task spawned + the cadence tick fired.
        let mut saw_add = false;
        for _ in 0..50 {
            if let Ok(Some((peer, _))) =
                tokio::time::timeout(Duration::from_millis(60), event_rx.recv()).await
            {
                if peer == "ghost-peer" {
                    saw_add = true;
                    break;
                }
            }
        }
        assert!(saw_add, "AddInitiator did not produce any round events");

        // Idempotent re-add: send the same coord again, no panic.
        control
            .add_initiator(Arc::clone(&coord))
            .await
            .expect("idempotent re-add");

        // Remove and assert events for ghost-peer eventually stop.
        control
            .remove_initiator("ghost-peer", EnvelopeKind::Key)
            .await
            .expect("send RemoveInitiator");

        // Drain a quiet window; an event landed before the remove
        // took effect is fine, but the stream must go silent for at
        // least one full cadence after remove.
        let drain_start = tokio::time::Instant::now();
        let mut last_event = drain_start;
        while drain_start.elapsed() < Duration::from_millis(400) {
            match tokio::time::timeout(Duration::from_millis(50), event_rx.recv()).await {
                Ok(Some((peer, _))) if peer == "ghost-peer" => {
                    last_event = tokio::time::Instant::now();
                }
                _ => {}
            }
        }
        assert!(
            last_event.elapsed() >= Duration::from_millis(100),
            "ghost-peer events did not cease after RemoveInitiator"
        );

        cancel_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), sched_handle)
            .await
            .expect("shutdown")
            .expect("join");
    }
}
