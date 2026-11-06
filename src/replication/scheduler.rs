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
//!   delivers framed bytes; the listen loop hands them to
//!   `ReplicationRegistry::route_inbound_bytes`, which reads the frame's
//!   v3 round metadata (CIRISEdge#634): a reply to a round WE opened goes
//!   into that round's inbox on our Initiator (`deliver_reply`); the
//!   peer's own round goes to the Responder for `(peer, kind)`
//!   (`deliver_inbound_framed`), built on first contact. One frame can
//!   never reach the wrong role.
//!
//! - **Outbound timer** — for each Initiator-side coordinator, a
//!   tokio task fires `interval.tick()` at the configured cadence and
//!   runs one round to completion (or timeout). That's this module. Every
//!   round is bracketed: opened by `drive_round_step(None)` (which mints
//!   the round id and its inbox) and closed by [`finish_round`] on every
//!   exit path — completed rounds `end_round`, everything else
//!   `abandon_round` (inbox dropped, session reset).
//!
//! Responder-side rounds need no scheduler: the runtime's
//! `spawn_responder_drive` task drains the responder's inbox, steps the
//! session (`drive_round_step_framed`, which rebinds and resets on a new
//! round) and queues each reply, stamped with the round it answers, on its
//! reply lane (CIRISEdge#943).
//!
//! ## Cancellation
//!
//! [`ReplicationScheduler::run_until_cancelled`] takes a
//! [`tokio::sync::watch::Receiver<bool>`] that the caller flips to
//! `true` to ask the scheduler to stop. Shipping watch (already in
//! tokio core, no new dep) instead of `CancellationToken` keeps the
//! dep surface minimal.
//!
//! ## A kick is bounded (CIRISEdge#740)
//!
//! `RoundNow` and `Propagate` kick every matching coordinator at once, and
//! every coordinator's first cadence tick fires the moment it is spawned —
//! so a kick (or a start) on a node with P peers over K planes would run
//! P × K rounds concurrently. Every round makes persist reads, and persist
//! runs each SQL call on tokio's blocking pool; with the read path async end
//! to end (#740) an unbounded fan-out can no longer wedge the pool, but it
//! can still fill it — 130 peers × 14 planes is 1,820 rounds queueing on a
//! 32-slot pool. So the scheduler drives at most
//! [`SchedulerConfig::max_concurrent_rounds`] rounds at a time, across every
//! coordinator it owns, through one [`RoundGate`]: a kicked coordinator that
//! finds the gate full WAITS for a permit (its kick is not lost — the
//! `Notify` holds it), then runs. No sleeps, no retry counts: the gate is a
//! semaphore and the wait is exactly as long as the rounds ahead of it. The
//! bound is chosen once and logged once at start; every wait is counted
//! ([`RoundBoundStats`]).
//!
//! ## A peer with no route backs off (CIRISEdge#794)
//!
//! A round that fails because the transport has NO ROUTE to its peer puts the
//! whole peer — every coordinator toward it — into one shared exponential
//! backoff with full jitter ([`super::no_route_backoff`]). While it holds, the
//! peer's coordinators skip ticks AND kicks without taking a gate permit; one
//! of them probes when the delay expires. Evidence that the peer is reachable
//! (a path, an identified link, a frame from it) clears the backoff and kicks
//! the peer's coordinators at once.
//!
//! ## Round timeout
//!
//! Each in-flight `SendThenWait` wait is bounded by `round_timeout`.
//! On expiry the scheduler logs the timeout, resets the coordinator's
//! session (the next interval tick starts fresh), and continues —
//! anti-entropy is *eventually consistent* by design, so a stuck
//! round is a missed cadence, not a fault. The next round will pick
//! up whatever state changed in the meantime.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::Instrument;

use tokio::sync::{mpsc, watch};

use super::coordinator::{CoordinatorError, DriveStep, ReplicationCoordinator, RoundReport};
use super::no_route_backoff::{Admission, NoRouteBackoff, NoRouteBackoffEntry, RoundClass};
use super::protocol::EnvelopeKind;
use super::session::SessionRole;
use crate::transport::TransportError;

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
    /// CIRISEdge#740 — at most this many `(peer, kind)` rounds in flight at
    /// once across EVERY coordinator this scheduler drives (kicked and
    /// cadence rounds alike). A round holds one permit from its open to its
    /// close, so a kick on a P-peer, K-plane node runs `min(P × K, this)`
    /// rounds concurrently and queues the rest behind the gate — counted,
    /// never dropped. `0` is raised to `1` (a bound of zero would be a
    /// scheduler that never runs a round). Default
    /// [`Self::DEFAULT_MAX_CONCURRENT_ROUNDS`]; see
    /// [`Self::max_concurrent_rounds_for`] for the rule.
    pub max_concurrent_rounds: usize,
}

impl SchedulerConfig {
    pub const DEFAULT_CADENCE: Duration = Duration::from_secs(30);
    pub const DEFAULT_ROUND_TIMEOUT: Duration = Duration::from_secs(10);
    /// CIRISEdge#740 — the default round bound, derived from the default
    /// blocking-pool ceiling by [`Self::max_concurrent_rounds_for`]: half of
    /// [`DEFAULT_MAX_BLOCKING_THREADS`](crate::runtime_budget::DEFAULT_MAX_BLOCKING_THREADS)
    /// (32), i.e. 16.
    pub const DEFAULT_MAX_CONCURRENT_ROUNDS: usize =
        Self::max_concurrent_rounds_for(crate::runtime_budget::DEFAULT_MAX_BLOCKING_THREADS);

    /// CIRISEdge#740 — the rule: at most HALF the blocking pool may be
    /// occupied by anti-entropy rounds at once, so a full fan-out can never
    /// take the last slot from persist's own connection waiters, the
    /// transport, or anything else that shares the pool.
    ///
    /// A round is sequential internally — it awaits one persist call at a
    /// time — so N in-flight rounds put at most N calls on the pool. The
    /// pre-#740 arithmetic was the other way round: each bridged read held a
    /// slot WHILE waiting for a slot, so 42 rounds needed 42 + 42 of 32.
    /// This rule assumes the read path is async end to end; that invariant
    /// is what `FSD/CIRIS_EDGE_TRANSPORT.md` §4 pins.
    ///
    /// A host that sizes its own pool (CIRISServer's `node_runtime`, edge's
    /// `RuntimeBudget`) should pass that size here.
    #[must_use]
    pub const fn max_concurrent_rounds_for(max_blocking_threads: usize) -> usize {
        let half = max_blocking_threads / 2;
        if half == 0 {
            1
        } else {
            half
        }
    }
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            cadence: Self::DEFAULT_CADENCE,
            round_timeout: Self::DEFAULT_ROUND_TIMEOUT,
            max_concurrent_rounds: Self::DEFAULT_MAX_CONCURRENT_ROUNDS,
        }
    }
}

/// CIRISEdge#740 — the one gate every round of one scheduler passes through:
/// a semaphore sized to [`SchedulerConfig::max_concurrent_rounds`], plus the
/// counters that make the bound observable. Shared by every coordinator task
/// the scheduler spawns (initial and hot-added).
#[derive(Debug)]
pub struct RoundGate {
    permits: tokio::sync::Semaphore,
    bound: usize,
    in_flight: AtomicUsize,
    peak_in_flight: AtomicUsize,
    waited: AtomicU64,
}

/// CIRISEdge#740 — a snapshot of [`RoundGate`]: the bound, how many rounds
/// are in flight now, the most that ever were, and how many rounds had to
/// wait for a permit since start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoundBoundStats {
    pub bound: usize,
    pub in_flight: usize,
    pub peak_in_flight: usize,
    pub waited: u64,
}

/// A round's permit: released — and the in-flight gauge decremented — on
/// drop, so every exit path out of a round (completion, timeout, error,
/// cancel, panic) returns the slot.
struct RoundPermit<'a> {
    gate: &'a RoundGate,
    _permit: tokio::sync::SemaphorePermit<'a>,
}

impl Drop for RoundPermit<'_> {
    fn drop(&mut self) {
        self.gate.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

impl RoundGate {
    fn new(bound: usize) -> Self {
        let bound = bound.max(1);
        Self {
            permits: tokio::sync::Semaphore::new(bound),
            bound,
            in_flight: AtomicUsize::new(0),
            peak_in_flight: AtomicUsize::new(0),
            waited: AtomicU64::new(0),
        }
    }

    /// Say the bound once, when the scheduler starts driving.
    fn log_bound(&self, coordinators: usize) {
        tracing::info!(
            max_concurrent_rounds = self.bound,
            coordinators,
            "scheduler: rounds are bounded — a kick or a start runs at most this many \
             (peer, kind) rounds at once; the rest queue behind the gate (CIRISEdge#740)"
        );
    }

    /// Take a permit, waiting behind the rounds ahead if the gate is full.
    async fn enter(&self, peer_id: &str, kind: &str) -> RoundPermit<'_> {
        let permit = if let Ok(p) = self.permits.try_acquire() {
            p
        } else {
            let waited = self.waited.fetch_add(1, Ordering::AcqRel) + 1;
            tracing::debug!(
                peer = %peer_id,
                kind = %kind,
                bound = self.bound,
                waited_total = waited,
                "round bound: gate full — this round waits for a permit (CIRISEdge#740)"
            );
            // The semaphore is never closed, so this cannot fail; a
            // closed gate would be a scheduler bug, not a round outcome.
            self.permits
                .acquire()
                .await
                .expect("round gate is never closed")
        };
        let now = self.in_flight.fetch_add(1, Ordering::AcqRel) + 1;
        self.peak_in_flight.fetch_max(now, Ordering::AcqRel);
        RoundPermit {
            gate: self,
            _permit: permit,
        }
    }

    /// The gate's current numbers.
    #[must_use]
    pub fn stats(&self) -> RoundBoundStats {
        RoundBoundStats {
            bound: self.bound,
            in_flight: self.in_flight.load(Ordering::Acquire),
            peak_in_flight: self.peak_in_flight.load(Ordering::Acquire),
            waited: self.waited.load(Ordering::Acquire),
        }
    }
}

/// The outer bound on one send of a round. A cold dial is at most 30 s and a
/// live transfer at most 120 s on the dial path, so this only ends a send the
/// transport itself never would: a live, progressing transfer is not severed.
pub const ROUND_SEND_TIMEOUT: Duration = Duration::from_secs(180);

/// A shaped link's sender waits up to 16 of its gaps for a row to leave
/// (`link_shaping::ROW_LEAVE_MAX_GAPS`); this is that, with a margin.
pub const PACING_SEND_GAPS: f64 = 17.0;

/// The bound on one send on a link with frame gap `gap`.
#[must_use]
pub fn pacing_send_timeout(gap: Option<Duration>) -> Duration {
    gap.map_or(ROUND_SEND_TIMEOUT, |g| {
        ROUND_SEND_TIMEOUT.max(g.mul_f64(PACING_SEND_GAPS))
    })
}

/// A round's place at the gate. The gate bounds what rounds cost the blocking
/// pool, and a round parked in a send costs it nothing, so a send gets as long
/// under the permit as a wait for a reply does (`hold`) and then gives the
/// permit back, keeps sending, and queues behind the rounds ahead before it
/// steps again. A dead peer's dial sits out 30 s per plane; held for that long
/// a few dead peers stopped every round to every live one.
///
/// The hold is not zero because the gate also paces a fan-out's dials: a start
/// or a kick still opens at most the bound's worth per hold. This is not the
/// reply lane of CIRISEdge#943: a responder has frames behind a reply to keep
/// stepping, and an initiator's round has nothing to do until its send lands,
/// so it keeps its send inline and gives up only what others need.
struct RoundSeat<'a> {
    gate: &'a RoundGate,
    peer_id: &'a str,
    kind: &'a str,
    permit: Option<RoundPermit<'a>>,
}

impl<'a> RoundSeat<'a> {
    async fn take(gate: &'a RoundGate, peer_id: &'a str, kind: &'a str) -> RoundSeat<'a> {
        let permit = Some(gate.enter(peer_id, kind).await);
        Self {
            gate,
            peer_id,
            kind,
            permit,
        }
    }

    /// Run one send of the round. Past `bound` it is a [`RoundError::Timeout`];
    /// the abandoned send is safe, sends being cancel-safe (CIRISEdge#853).
    async fn send<T>(
        &mut self,
        hold: Duration,
        bound: Duration,
        send: impl std::future::Future<Output = Result<T, CoordinatorError>>,
    ) -> Result<T, RoundError> {
        let bounded = tokio::time::timeout(bound, send);
        tokio::pin!(bounded);
        let outcome = if let Ok(landed) = tokio::time::timeout(hold, &mut bounded).await {
            landed
        } else {
            self.permit = None;
            tracing::debug!(
                peer = %self.peer_id,
                kind = %self.kind,
                hold_ms = u64::try_from(hold.as_millis()).unwrap_or(u64::MAX),
                "round send still parked — its permit goes back to the gate"
            );
            let landed = bounded.await;
            // Only a round that goes on reads again.
            if matches!(landed, Ok(Ok(_))) {
                self.permit = Some(self.gate.enter(self.peer_id, self.kind).await);
            }
            landed
        };
        match outcome {
            Ok(result) => result.map_err(RoundError::from),
            Err(_) => Err(RoundError::Timeout),
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
    /// The transport has no route to the peer (CIRISEdge#794): an offline
    /// client, which the backoff takes over, not a fault of the round.
    NoRoute(String),
}

impl RoundEvent {
    /// The `replication_round_outcomes_total` label this event books.
    #[must_use]
    pub fn outcome(&self) -> crate::observability::RoundOutcome {
        use crate::observability::RoundOutcome;
        match self {
            Self::Completed(_) => RoundOutcome::Completed,
            Self::Refused => RoundOutcome::Refused,
            Self::TimedOut => RoundOutcome::TimedOut,
            Self::Error(_) => RoundOutcome::Error,
            Self::NoRoute(_) => RoundOutcome::NoRoute,
        }
    }
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
    /// CIRISEdge#740 — the round bound, shared by every coordinator task.
    round_gate: Arc<RoundGate>,
    /// CIRISEdge#794 — the per-peer no-route backoff, shared by every
    /// coordinator task, the handle and the registry's inbound door.
    backoff: Arc<NoRouteBackoff>,
    /// The peers a coordinator is driven toward, for
    /// [`SchedulerHandle::drives_peer`].
    driven: Arc<std::sync::Mutex<HashSet<String>>>,
    /// CIRISEdge#440 — the resolved mesh-config read seam. When `Some`, each
    /// coordinator loop re-checks `antientropy.round_secs` ONCE per round
    /// (after the round, before the next tick is scheduled): a live relief
    /// replaces the interval so the NEW cadence governs the next round; the
    /// relief's expiry restores the configured cadence the same way. `None`
    /// (every pre-#440 construction) leaves the interval object untouched —
    /// byte-identical behavior.
    mesh_config: Option<Arc<crate::replication::mesh_config::MeshConfigReader>>,
    /// CIRISEdge P0 telemetry — the Edge's metrics bag, for the per-kind
    /// round-duration histogram. `None` (the default) records nothing.
    metrics: Option<crate::observability::EdgeMetrics>,
}

/// Runtime control command for an actively-running scheduler.
///
/// Emitted by [`SchedulerHandle`] and consumed inside
/// [`ReplicationScheduler::run_with_events`].
///
/// `#[non_exhaustive]` (CIRISEdge#776, as `WithholdReason` in v37): commands
/// are added as the runtime learns new kicks (`Kick` was), and a downstream
/// `match` must not break when one is.
#[non_exhaustive]
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
    /// v19.0.0 — fire a round NOW on every Initiator toward `peer_key_id`
    /// (or toward every peer, `None`), instead of at the next cadence tick.
    /// A kick during an in-flight round is held and runs right after it; a
    /// second kick meanwhile coalesces (one permit). The scheduled tick is
    /// reset after a kicked round, so a kick never doubles a round.
    RoundNow { peer_key_id: Option<String> },
    /// CIRISEdge#636 (production speed) — a round toward `from_peer` on
    /// `kind` just ADMITTED rows: fire a round on `kind` toward every OTHER
    /// peer now, so the rows hop on within a round-trip instead of a cadence
    /// tick (epidemic propagation). Coalesces like `RoundNow`; a round that
    /// admits nothing propagates nothing, so a quiet mesh stays quiet.
    Propagate {
        from_peer: String,
        kind: EnvelopeKind,
    },
    /// CIRISEdge#776 — fire a round NOW on the ONE Initiator `(peer_key_id,
    /// kind)`: a row this node refused from that peer was waiting on a
    /// dependency that just landed, so ask for it again now instead of at the
    /// next cadence tick. The same per-coordinator `Notify` as `RoundNow`, so
    /// it coalesces and never doubles a round. No-op if no such Initiator.
    Kick {
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
            Self::RoundNow { peer_key_id } => f
                .debug_struct("RoundNow")
                .field("peer_key_id", peer_key_id)
                .finish(),
            Self::Propagate { from_peer, kind } => f
                .debug_struct("Propagate")
                .field("from_peer", from_peer)
                .field("kind", kind)
                .finish(),
            Self::Kick { peer_key_id, kind } => f
                .debug_struct("Kick")
                .field("peer_key_id", peer_key_id)
                .field("kind", kind)
                .finish(),
        }
    }
}

/// One Initiator task's controls: its cancel, and its kick.
struct CoordControl {
    cancel: watch::Sender<bool>,
    kick: Arc<tokio::sync::Notify>,
}

/// The planes a peer must hold before it can attribute this node's frames, in
/// the order they land: a route row is refused until its signer's key is held.
/// Their frames are admitted unattributed (#402).
const BOOTSTRAP_ORDER: [EnvelopeKind; 3] = [
    EnvelopeKind::Key,
    EnvelopeKind::IdentityOccurrence,
    EnvelopeKind::TransportDestination,
];

/// How long a new peer's first Attestation round waits for [`BOOTSTRAP_ORDER`].
/// Past it the round runs: a plane that cannot land costs what it always did.
const BOOTSTRAP_HOLD: Duration = Duration::from_secs(5);

/// How often a held Attestation round looks, and asks the plane again. It also
/// lets a host finish adding a peer's planes.
const BOOTSTRAP_LOOK: Duration = Duration::from_millis(250);

/// The running [`BOOTSTRAP_ORDER`] coordinators, for a held Attestation round.
type BootstrapPlanes = Arc<
    std::sync::Mutex<
        HashMap<(String, EnvelopeKind), (Arc<ReplicationCoordinator>, Arc<tokio::sync::Notify>)>,
    >,
>;

/// **A new peer's first Attestation round waits until the peer can read it.**
/// It cannot attribute a frame until it holds this node's route row, and it
/// drops what it cannot attribute (`SkippedNoSourceKeyId`), which costs a whole
/// round timeout. Started with the bootstrap planes, that round is lost.
///
/// A round's end does not say the peer holds the row: the row may have been
/// refused for a key still on its way. An empty `Diff` does, on the peer's own
/// word, so each plane is asked until the peer lacks nothing of it, in order,
/// since a route refused for its key is out of the `Diff` until the key lands.
/// Bounded by [`BOOTSTRAP_HOLD`]. A peer with none of these planes has no wait.
async fn hold_for_bootstrap(coord: &ReplicationCoordinator, planes: &BootstrapPlanes) {
    if coord.kind() != EnvelopeKind::Attestation {
        return;
    }
    tokio::time::sleep(BOOTSTRAP_LOOK).await;
    let deadline = tokio::time::Instant::now() + BOOTSTRAP_HOLD - BOOTSTRAP_LOOK;
    for kind in BOOTSTRAP_ORDER {
        let plane = planes.lock().ok().and_then(|p| {
            p.get(&(coord.peer_key_id().to_owned(), kind))
                .map(|(c, k)| (Arc::clone(c), Arc::clone(k)))
        });
        let Some((plane, kick)) = plane else {
            continue;
        };
        let seen = plane.peer_lacks_nothing();
        while plane.peer_lacks_nothing() == seen {
            if tokio::time::Instant::now() >= deadline {
                tracing::info!(
                    waiting_on = ?kind,
                    "first Attestation round not held past the bound: the peer has not \
                     confirmed this plane"
                );
                return;
            }
            kick.notify_one();
            tokio::time::sleep(BOOTSTRAP_LOOK).await;
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
    /// CIRISEdge#740 — read access to the scheduler's round gate.
    round_gate: Arc<RoundGate>,
    /// CIRISEdge#794 — the scheduler's no-route backoff.
    backoff: Arc<NoRouteBackoff>,
    /// The peers a coordinator is driven toward (see [`Self::drives_peer`]).
    driven: Arc<std::sync::Mutex<HashSet<String>>>,
}

impl SchedulerHandle {
    /// CIRISEdge#740 — the round bound and its counters.
    #[must_use]
    pub fn round_bound(&self) -> RoundBoundStats {
        self.round_gate.stats()
    }

    /// CIRISEdge#794 — every peer backed off for having no route, with its
    /// next-attempt time and current window. Empty in the steady state.
    #[must_use]
    pub fn no_route_backoff(&self) -> Vec<NoRouteBackoffEntry> {
        self.backoff.snapshot()
    }

    /// CIRISEdge#794 — evidence that `peer_key_id` is reachable. Clears its
    /// no-route backoff, if any, and kicks its coordinators now. Never blocks;
    /// a no-op for a peer that is not backed off. The runtime feeds this from
    /// the transport's [`subscribe_reachability`](crate::transport::Transport::subscribe_reachability)
    /// and from every attributed inbound CRPL frame; a host with its own
    /// evidence may call it too.
    pub fn note_reachable(
        &self,
        peer_key_id: &str,
        evidence: crate::transport::ReachabilityEvidence,
    ) {
        self.backoff.note_reachable(peer_key_id, evidence);
    }

    /// CIRISEdge#794 — change the no-route backoff's window ceiling on a
    /// running scheduler (see [`ReplicationScheduler::with_no_route_backoff_cap`]).
    /// Takes effect at each backed-off peer's next window.
    pub fn set_no_route_backoff_cap(&self, cap: Duration) {
        self.backoff.set_cap(cap);
    }

    /// The window ceiling in force.
    #[must_use]
    pub fn no_route_backoff_cap(&self) -> Duration {
        self.backoff.cap()
    }

    /// The backoff itself, for the registry's inbound door.
    pub(crate) fn backoff(&self) -> Arc<NoRouteBackoff> {
        Arc::clone(&self.backoff)
    }

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

    /// v19.0.0 — fire a round NOW toward `peer_key_id` on every plane this
    /// node initiates with it (`None` = every peer). See
    /// [`SchedulerCommand::RoundNow`].
    pub async fn round_now(&self, peer_key_id: Option<&str>) -> Result<(), SchedulerCommandError> {
        self.command_tx
            .send(SchedulerCommand::RoundNow {
                peer_key_id: peer_key_id.map(str::to_owned),
            })
            .await
            .map_err(|_| SchedulerCommandError::SchedulerStopped)
    }

    /// Does this scheduler drive a coordinator toward `peer_key_id`? The
    /// answer to "is this a known replication peer", without a round-trip
    /// through the command channel.
    #[must_use]
    pub fn drives_peer(&self, peer_key_id: &str) -> bool {
        self.driven
            .lock()
            .is_ok_and(|driven| driven.contains(peer_key_id))
    }

    /// v44 (first-contact kick on a miss) — [`Self::round_now`] toward ONE
    /// peer, never blocking (`try_send`, the [`Self::try_kick`] shape): called
    /// from the serve path of a subject Pull that answered nothing for a
    /// subject this node can resolve to that peer, so the rows are asked for
    /// within a round-trip instead of at the next cadence tick. A full command
    /// channel drops the kick and the cadence still asks. Returns whether the
    /// kick was queued. See [`SchedulerCommand::RoundNow`].
    #[must_use]
    pub fn try_round_now(&self, peer_key_id: &str) -> bool {
        self.command_tx
            .try_send(SchedulerCommand::RoundNow {
                peer_key_id: Some(peer_key_id.to_owned()),
            })
            .is_ok()
    }

    /// A handle whose command channel the TEST holds the receiving end of, so
    /// a witness can observe the commands a caller queues without running a
    /// scheduler.
    #[cfg(test)]
    pub(crate) fn test_pair(driven: &[&str]) -> (Self, mpsc::Receiver<SchedulerCommand>) {
        let (command_tx, command_rx) = mpsc::channel(32);
        (
            Self {
                command_tx,
                round_gate: Arc::new(RoundGate::new(1)),
                backoff: Arc::new(NoRouteBackoff::new()),
                driven: Arc::new(std::sync::Mutex::new(
                    driven.iter().map(|p| (*p).to_owned()).collect(),
                )),
            },
            command_rx,
        )
    }

    /// CIRISEdge#776 — fire a round NOW on `(peer_key_id, kind)` only. Never
    /// blocks (`try_send`): it is called from the apply path; a full command
    /// channel drops the kick and the cadence still asks. Returns whether the
    /// kick was queued. See [`SchedulerCommand::Kick`].
    #[must_use]
    pub fn try_kick(&self, peer_key_id: &str, kind: EnvelopeKind) -> bool {
        self.command_tx
            .try_send(SchedulerCommand::Kick {
                peer_key_id: peer_key_id.to_owned(),
                kind,
            })
            .is_ok()
    }

    /// CIRISEdge#636 — rows just admitted from `from_peer` on `kind`: fire a
    /// round on `kind` toward every other peer. See
    /// [`SchedulerCommand::Propagate`].
    pub async fn propagate(
        &self,
        from_peer: &str,
        kind: EnvelopeKind,
    ) -> Result<(), SchedulerCommandError> {
        self.command_tx
            .send(SchedulerCommand::Propagate {
                from_peer: from_peer.to_owned(),
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
        if config.max_concurrent_rounds == 0 {
            tracing::warn!(
                "scheduler: max_concurrent_rounds(0) would never run a round; using 1 \
                 (history: CIRISEdge#740)"
            );
        }
        Self {
            config,
            coordinators: Vec::new(),
            command_rx: None,
            round_gate: Arc::new(RoundGate::new(config.max_concurrent_rounds)),
            backoff: Arc::new(NoRouteBackoff::new()),
            driven: Arc::default(),
            mesh_config: None,
            metrics: None,
        }
    }

    /// CIRISEdge P0 telemetry — install the Edge's metrics bag (builder), so
    /// every round this scheduler drives records its wall time into
    /// [`EdgeMetrics::replication_round_duration_seconds`](crate::observability::EdgeMetrics::replication_round_duration_seconds).
    /// `None` records nothing.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Option<crate::observability::EdgeMetrics>) -> Self {
        self.metrics = metrics;
        self
    }

    /// CIRISEdge#740 — the round bound and its counters.
    #[must_use]
    pub fn round_bound(&self) -> RoundBoundStats {
        self.round_gate.stats()
    }

    /// CIRISEdge#794 — see [`SchedulerHandle::no_route_backoff`].
    #[must_use]
    pub fn no_route_backoff(&self) -> Vec<NoRouteBackoffEntry> {
        self.backoff.snapshot()
    }

    /// CIRISEdge#794 — the ceiling of the per-peer no-route backoff window
    /// (builder). A peer the transport has no route to is retried after a
    /// delay drawn from `[0, window]`, the window doubling from
    /// [`NO_ROUTE_BACKOFF_INITIAL`](super::no_route_backoff::NO_ROUTE_BACKOFF_INITIAL)
    /// up to this. Without this call the cap is
    /// [`DEFAULT_NO_ROUTE_BACKOFF_CAP`](super::no_route_backoff::DEFAULT_NO_ROUTE_BACKOFF_CAP)
    /// (15 min); under 1 s is raised to 1 s. A running scheduler's cap is
    /// changed through [`SchedulerHandle::set_no_route_backoff_cap`].
    #[must_use]
    pub fn with_no_route_backoff_cap(self, cap: Duration) -> Self {
        self.backoff.set_cap(cap);
        self
    }

    /// Tests pin the jitter so the probe schedule is countable.
    #[cfg(test)]
    pub(crate) fn with_backoff_jitter(mut self, jitter: fn(Duration) -> Duration) -> Self {
        let pinned = NoRouteBackoff::with_jitter(jitter);
        pinned.set_cap(self.backoff.cap());
        self.backoff = Arc::new(pinned);
        self
    }

    /// CIRISEdge#440 — install the resolved mesh-config reader (builder); see
    /// the field doc. `None` keeps the exact fixed-cadence behavior.
    #[must_use]
    pub fn with_mesh_config(
        mut self,
        reader: Option<Arc<crate::replication::mesh_config::MeshConfigReader>>,
    ) -> Self {
        self.mesh_config = reader;
        self
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
        SchedulerHandle {
            command_tx,
            round_gate: Arc::clone(&self.round_gate),
            backoff: Arc::clone(&self.backoff),
            driven: Arc::clone(&self.driven),
        }
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
    #[allow(clippy::too_many_lines)] // one select loop: every command arm in one place
    pub async fn run_with_events(
        mut self,
        mut cancel: watch::Receiver<bool>,
        event_sink: Option<mpsc::Sender<(String, RoundEvent)>>,
    ) {
        // Per-coord cancel senders, keyed by (peer_key_id, kind).
        // RemoveInitiator flips one entry; global cancel flips all.
        let mut per_coord: HashMap<(String, EnvelopeKind), CoordControl> = HashMap::new();
        let mut handles = Vec::with_capacity(self.coordinators.len());

        // CIRISEdge#740 — the bound is chosen once, here, and said once.
        let round_gate = Arc::clone(&self.round_gate);
        round_gate.log_bound(self.coordinators.len());
        // CIRISEdge#794 — a peer leaving backoff wakes its coordinators here.
        let backoff = Arc::clone(&self.backoff);
        let mut wakes = backoff.take_wakes();

        let mesh_config = self.mesh_config.take();
        let metrics = self.metrics.take();
        let bootstrap = BootstrapPlanes::default();
        for coord in self.coordinators.drain(..) {
            note_driven(&self.driven, &coord);
            spawn_coord(
                &mut per_coord,
                &mut handles,
                coord,
                self.config.cadence,
                self.config.round_timeout,
                event_sink.clone(),
                mesh_config.clone(),
                Arc::clone(&round_gate),
                Arc::clone(&backoff),
                metrics.clone(),
                Arc::clone(&bootstrap),
            );
        }

        let mut command_rx = self.command_rx.take();
        loop {
            tokio::select! {
                biased;
                _ = cancel.changed() => {
                    if *cancel.borrow() {
                        for (_, c) in per_coord.drain() {
                            let _ = c.cancel.send(true);
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
                            note_driven(&self.driven, &coord);
                            spawn_coord(
                                &mut per_coord,
                                &mut handles,
                                coord,
                                self.config.cadence,
                                self.config.round_timeout,
                                event_sink.clone(),
                                mesh_config.clone(),
                                Arc::clone(&round_gate),
                                Arc::clone(&backoff),
                                metrics.clone(),
                                Arc::clone(&bootstrap),
                            );
                        }
                        SchedulerCommand::RemoveInitiator { peer_key_id, kind } => {
                            remove_initiator(
                                &mut per_coord,
                                &backoff,
                                &self.driven,
                                &peer_key_id,
                                kind,
                            );
                            if let Ok(mut planes) = bootstrap.lock() {
                                planes.remove(&(peer_key_id, kind));
                            }
                        }
                        SchedulerCommand::RoundNow { peer_key_id } => {
                            round_now_kick(&per_coord, peer_key_id.as_deref());
                        }
                        SchedulerCommand::Propagate { from_peer, kind } => {
                            propagate_kick(&per_coord, &from_peer, kind);
                        }
                        SchedulerCommand::Kick { peer_key_id, kind } => kick_one(&per_coord, peer_key_id, kind),
                    }
                }
                Some(wake) = async {
                    // SAFETY of unwrap: guarded by `if wakes.is_some()`.
                    wakes.as_mut().unwrap().recv().await
                }, if wakes.is_some() => {
                    wake_kick(&per_coord, &wake);
                }
                else => {
                    // command_rx is None AND cancel is not changing —
                    // wait on cancel only.
                    let _ = cancel.changed().await;
                    if *cancel.borrow() {
                        for (_, c) in per_coord.drain() {
                            let _ = c.cancel.send(true);
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
#[allow(clippy::too_many_arguments)] // one spawn site's wiring, every arg a distinct seam
fn spawn_coord(
    per_coord: &mut HashMap<(String, EnvelopeKind), CoordControl>,
    handles: &mut Vec<tokio::task::JoinHandle<()>>,
    coord: Arc<ReplicationCoordinator>,
    cadence: Duration,
    round_timeout: Duration,
    event_sink: Option<mpsc::Sender<(String, RoundEvent)>>,
    mesh_config: Option<Arc<crate::replication::mesh_config::MeshConfigReader>>,
    round_gate: Arc<RoundGate>,
    backoff: Arc<NoRouteBackoff>,
    metrics: Option<crate::observability::EdgeMetrics>,
    bootstrap: BootstrapPlanes,
) {
    debug_assert_eq!(
        coord.role(),
        SessionRole::Initiator,
        "scheduler spawns Initiator coordinators only"
    );
    let key = (coord.peer_key_id().to_string(), coord.kind());
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let kick = Arc::new(tokio::sync::Notify::new());
    per_coord.insert(
        key,
        CoordControl {
            cancel: cancel_tx,
            kick: Arc::clone(&kick),
        },
    );
    if BOOTSTRAP_ORDER.contains(&coord.kind()) {
        if let Ok(mut planes) = bootstrap.lock() {
            planes.insert(
                (coord.peer_key_id().to_owned(), coord.kind()),
                (Arc::clone(&coord), Arc::clone(&kick)),
            );
        }
    }
    let h = tokio::spawn(async move {
        run_one_coordinator_forever(
            coord,
            cadence,
            round_timeout,
            &mut cancel_rx,
            kick,
            event_sink,
            mesh_config,
            round_gate,
            backoff,
            metrics,
            bootstrap,
        )
        .await;
    });
    handles.push(h);
}

#[allow(clippy::too_many_arguments)] // the per-coordinator loop's wiring, one seam each
async fn run_one_coordinator_forever(
    coord: Arc<ReplicationCoordinator>,
    cadence: Duration,
    round_timeout: Duration,
    cancel: &mut watch::Receiver<bool>,
    kick: Arc<tokio::sync::Notify>,
    event_sink: Option<tokio::sync::mpsc::Sender<(String, RoundEvent)>>,
    mesh_config: Option<Arc<crate::replication::mesh_config::MeshConfigReader>>,
    round_gate: Arc<RoundGate>,
    backoff: Arc<NoRouteBackoff>,
    metrics: Option<crate::observability::EdgeMetrics>,
    bootstrap: BootstrapPlanes,
) {
    tokio::select! {
        biased;
        _ = cancel.changed() => {
            if *cancel.borrow() {
                return;
            }
        }
        () = hold_for_bootstrap(&coord, &bootstrap) => {}
    }
    let mut interval = tokio::time::interval(cadence);
    // `Burst` is the default; with `MissedTickBehavior::Skip` a
    // long-delayed task wouldn't fire bursts to catch up. We want
    // Skip — a stuck round eating cadence ticks shouldn't compound
    // into a burst of rounds the moment it unblocks.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // CIRISEdge#440 — the cadence currently governing `interval`. Compared
    // against the resolved relief after every round; only an actual CHANGE
    // rebuilds the interval, so a reader answering "no relief" forever never
    // perturbs the pre-#440 tick stream.
    let mut current_cadence = cadence;
    // CC 5.4.6 — when the re-dial drawn after a failed send is due. Until then
    // a kick does not dial: it would put a refused fleet back on one beat.
    let mut redial_at: Option<tokio::time::Instant> = None;

    let peer_id = coord.peer_key_id().to_string();
    let kind_str = format!("{:?}", coord.kind());
    let round = GatedRound {
        coord: &coord,
        round_timeout,
        event_sink: event_sink.as_ref(),
        peer_id: &peer_id,
        kind_str: &kind_str,
        round_gate: &round_gate,
        backoff: &backoff,
        metrics: metrics.as_ref(),
    };

    loop {
        tokio::select! {
            biased;
            _ = cancel.changed() => {
                if *cancel.borrow() {
                    return;
                }
            }
            () = kick.notified() => {
                // v19.0.0 — a caller could not wait for the cadence
                // (`ReplicationRuntime::sync_and_await`): run the round now
                // and push the next scheduled one a full cadence out, so a
                // kick never doubles a round.
                //
                // CIRISEdge#740 — behind the gate: a kick fans out to every
                // coordinator at once, and the gate is what turns that into
                // at most `max_concurrent_rounds` rounds in flight.
                //
                // CIRISEdge#790 — the span INSTRUMENTS the round's future; it
                // is never entered with a guard held across an await. A held
                // `Span::enter` guard stays on the worker thread's span stack
                // while the task is parked (on the gate, or in the round), so
                // every later round polled on that worker nested under it:
                // 9,495 spans deep on the canonical, then a stack overflow.
                //
                // CIRISEdge#794 — a kick does not bypass the no-route backoff:
                // a backed-off peer's coordinator ignores it (and takes no
                // permit). The schedule is then left alone, not reset.
                //
                // CC 5.4.6 — nor the re-dial drawn after a failed send: that
                // tick runs the round the kick wanted.
                if redial_at.is_some_and(|at| tokio::time::Instant::now() < at) {
                    tracing::trace!("kick held — this coordinator's re-dial is drawn (CC 5.4.6)");
                    continue;
                }
                let span = tracing::info_span!("anti_entropy_round", peer = %peer_id, kind = %kind_str, kicked = true);
                match round.run().instrument(span).await {
                    RoundRan::Skipped => {}
                    RoundRan::Ended => interval.reset(),
                    RoundRan::SendFailed => {
                        redial_at = Some(draw_redial(&mut interval, current_cadence));
                    }
                }
            }
            _ = interval.tick() => {
                // CIRISEdge#740 — behind the same gate: every coordinator's
                // first tick fires the moment it is spawned, so a start is a
                // fan-out too.
                // CIRISEdge#790 — instrumented, never entered (see the kick arm).
                let span = tracing::info_span!("anti_entropy_round", peer = %peer_id, kind = %kind_str);
                let ran = round.run().instrument(span).await;
                let relieved = match &mesh_config {
                    Some(reader) => reader.relief().await.round_cadence.unwrap_or(cadence),
                    None => cadence,
                };
                // CC 5.4.3 — on a shaped link the round interval follows the
                // frame gap (about 7.75 gaps), else ticks queue behind rounds
                // that each take several gaps.
                let target = pacing_interval(relieved, coord.pacing_gap());
                if target != current_cadence {
                    tracing::info!(
                        peer = %peer_id,
                        kind = %kind_str,
                        from_secs = current_cadence.as_secs_f64(),
                        to_secs = target.as_secs_f64(),
                        "anti-entropy cadence changed (mesh-config relief, CIRISEdge#440, or \
                         the shaped link's frame gap, CC 5.4.3)"
                    );
                    current_cadence = target;
                    interval = tokio::time::interval_at(
                        tokio::time::Instant::now() + target,
                        target,
                    );
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                }
                // After the cadence settles, so the draw is on the one in force.
                if ran == RoundRan::SendFailed {
                    redial_at = Some(draw_redial(&mut interval, current_cadence));
                }
            }
        }
    }
}

/// CC 5.4.6 (`FSD/EVENT_PATH_MODEL.md` §2.4) — a client retries jittered. The
/// tick is 30 s and the receiver's limiter a 10 s sliding window, so a dial
/// refused in the closed part comes back to the closed part, every time. After
/// a round whose send failed this coordinator's next dial is drawn from 0.5 to
/// 1.5 cadences, on a fresh draw per failure, and the tick carries on from
/// there. A healthy round never comes here, so its tick stays where it was.
///
/// Why not a wider draw, or a shared one: the floor keeps a fleet refused at
/// the same moment (a restart behind a closed limiter) from coming straight
/// back, and each draw being its own is what spreads them. The first tick is
/// left alone: a restart's own burst is what the budgets are sized for.
///
/// A kick waits out the draw only up to [`KICK_HOLD_MAX`]: the jitter is sized
/// for the default cadence, and on a long one a host's kick must not sit for half
/// an hour behind one refused dial. The returned instant is that hold.
fn draw_redial(interval: &mut tokio::time::Interval, cadence: Duration) -> tokio::time::Instant {
    let delay = redial_delay(cadence);
    interval.reset_after(delay);
    tokio::time::Instant::now() + delay.min(KICK_HOLD_MAX)
}

/// The longest a kick waits behind a drawn re-dial: the draw's top at the
/// default cadence.
const KICK_HOLD_MAX: Duration = Duration::from_secs(45);

/// Uniform over `[cadence / 2, cadence * 3 / 2]`, millisecond resolution.
fn redial_delay(cadence: Duration) -> Duration {
    use rand::Rng as _;
    let ms = u64::try_from(cadence.as_millis()).unwrap_or(u64::MAX / 2);
    Duration::from_millis(rand::thread_rng().gen_range(ms / 2..=ms.saturating_mul(3) / 2))
}

/// The Poisson p99 of one frame wait, in gaps (FSD/TRANSPORT_TIERS_MODEL.md).
pub const PACING_WAIT_GAPS: f64 = 4.74;
/// A round interval that lets a request/reply round complete, in gaps.
pub const PACING_INTERVAL_GAPS: f64 = 7.75;

/// The per-wait timeout on a link with frame gap `gap`: never below the
/// configured one, and at least [`PACING_WAIT_GAPS`] gaps.
#[must_use]
pub fn pacing_timeout(configured: Duration, gap: Option<Duration>) -> Duration {
    gap.map_or(configured, |g| configured.max(g.mul_f64(PACING_WAIT_GAPS)))
}

/// The round interval on a link with frame gap `gap`: never below the
/// configured cadence, and at least [`PACING_INTERVAL_GAPS`] gaps.
#[must_use]
pub fn pacing_interval(configured: Duration, gap: Option<Duration>) -> Duration {
    gap.map_or(configured, |g| {
        configured.max(g.mul_f64(PACING_INTERVAL_GAPS))
    })
}

/// How [`GatedRound::run`] went, for the loop that owns the tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoundRan {
    /// The peer is backed off, or another plane found it unroutable meanwhile.
    Skipped,
    /// The round ended, whatever the outcome.
    Ended,
    /// The round's send failed, so the next round is a dial ([`draw_redial`]).
    SendFailed,
}

/// One coordinator's round, as both the tick and the kick arm run it: past the
/// no-route backoff (CIRISEdge#794), then through the round gate (#740).
struct GatedRound<'a> {
    coord: &'a Arc<ReplicationCoordinator>,
    round_timeout: Duration,
    event_sink: Option<&'a tokio::sync::mpsc::Sender<(String, RoundEvent)>>,
    peer_id: &'a str,
    kind_str: &'a str,
    round_gate: &'a RoundGate,
    backoff: &'a NoRouteBackoff,
    /// CIRISEdge P0 telemetry — where the round's wall time is recorded.
    metrics: Option<&'a crate::observability::EdgeMetrics>,
}

impl GatedRound<'_> {
    /// Run the round unless the peer is backed off.
    async fn run(&self) -> RoundRan {
        // Decided BEFORE the gate: a backed-off coordinator never holds or
        // queues for a permit.
        let Admission::Run(ticket) = self.backoff.admit(self.peer_id, self.coord.kind()) else {
            tracing::trace!("round skipped — peer is in no-route backoff (CIRISEdge#794)");
            return RoundRan::Skipped;
        };
        let mut seat = RoundSeat::take(self.round_gate, self.peer_id, self.kind_str).await;
        // Another plane may have found the peer unroutable while this one
        // waited for its permit.
        if ticket.overtaken() {
            return RoundRan::Skipped;
        }
        // CIRISEdge P0 telemetry — the round's wall time, from holding the
        // permit to its outcome, whatever that outcome is: a round that
        // timed out after its full budget is exactly the one to see.
        let started = std::time::Instant::now();
        // CC 5.4.3 — on a shaped link a wait is paced by the link's frame
        // gap: the per-wait timeout is at least the Poisson p99 of one gap
        // (about 4.74 gaps), else every wait on a slow link times out.
        let round_timeout = pacing_timeout(self.round_timeout, self.coord.pacing_gap());
        let mut ended = RoundEnded::default();
        let class = round_and_report(
            self.coord,
            round_timeout,
            self.event_sink,
            self.peer_id,
            &mut seat,
            &mut ended,
        )
        .await;
        if let Some(m) = self.metrics {
            m.observe_round_duration(self.coord.kind(), started.elapsed());
        }
        tracing::info!(
            took_ms = started.elapsed().as_millis(),
            outcome = ended.outcome,
            error = ended.error.as_deref().unwrap_or(""),
            "anti-entropy round ended"
        );
        let ran = if matches!(class, RoundClass::SendFailed) {
            RoundRan::SendFailed
        } else {
            RoundRan::Ended
        };
        ticket.finish(class);
        ran
    }
}

/// CIRISEdge#794 — the no-route classification of a round error, typed.
fn round_class_of(e: &RoundError) -> RoundClass {
    match e {
        RoundError::Coordinator(CoordinatorError::Transport(t)) => {
            RoundClass::of_transport_error(t).unwrap_or(match t {
                // A dial was made or a link was used, and it failed.
                TransportError::Io(_)
                | TransportError::Timeout(_)
                | TransportError::LinkSealRefused { .. } => RoundClass::SendFailed,
                // Nothing went out: a ban, a body too large, an unreachable
                // medium. No address at all is the no-route class above.
                _ => RoundClass::Other,
            })
        }
        RoundError::Coordinator(_) | RoundError::Timeout | RoundError::InboundClosed => {
            RoundClass::Other
        }
    }
}

/// How a round ended, for its `anti-entropy round ended` line: the
/// `replication_round_outcomes_total` label, and an error's text.
struct RoundEnded {
    outcome: &'static str,
    error: Option<String>,
}

impl Default for RoundEnded {
    fn default() -> Self {
        Self {
            outcome: "skipped",
            error: None,
        }
    }
}

impl RoundEnded {
    /// What `event` says.
    fn of(event: &RoundEvent) -> Self {
        let error = match event {
            RoundEvent::Error(e) | RoundEvent::NoRoute(e) => Some(e.clone()),
            RoundEvent::Completed(_) | RoundEvent::Refused | RoundEvent::TimedOut => None,
        };
        Self {
            outcome: event.outcome().as_str(),
            error,
        }
    }
}

/// How often one `(peer, kind)` may say why its rounds fail.
const ROUND_ERROR_LOG_WINDOW: Duration = Duration::from_secs(300);

fn round_error_log() -> &'static crate::log_throttle::LogThrottle {
    static LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> = std::sync::OnceLock::new();
    LOG.get_or_init(|| crate::log_throttle::LogThrottle::new(1, ROUND_ERROR_LOG_WINDOW, 8192))
}

/// Say why a round failed, at most once per `(peer, kind)` in a window. The
/// round's span names both.
fn log_round_error(peer: &str, kind: EnvelopeKind, what: &'static str, error: &str) {
    if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
        round_error_log().check(&format!("{peer}:{kind:?}"))
    {
        tracing::info!(suppressed_prev, %error, "{what}");
    }
}

/// One anti-entropy round toward this coordinator's peer — the signer-recovery
/// attempt first, then the ordinary round — and its [`RoundEvent`] to the sink.
/// Shared by the cadence tick and the [`SchedulerCommand::RoundNow`] kick.
/// Returns how the round ended, for the no-route backoff (CIRISEdge#794).
async fn round_and_report(
    coord: &Arc<ReplicationCoordinator>,
    round_timeout: Duration,
    event_sink: Option<&tokio::sync::mpsc::Sender<(String, RoundEvent)>>,
    peer_id: &str,
    seat: &mut RoundSeat<'_>,
    ended: &mut RoundEnded,
) -> RoundClass {
    // FSD-SIGNER-RECOVERY D3 — a recovery round REPLACES this
    // tick's ordinary round; the two never overlap. It costs one
    // cadence tick per recovered key, and only on a tick where a
    // name is actually queued. At most one name per peer can exist
    // (D4), so recovery displaces at most one ordinary round per
    // peer before it is done.
    let recovery = match run_one_recovery_round(coord, round_timeout, seat).await {
        Ok(step) => step,
        Err(e) => {
            // Lifecycle — the transport is suspended: skip quietly. The
            // ordinary round would be refused the same way; nothing is
            // reported and no backoff moves.
            if matches!(round_class_of(&e), RoundClass::Suspended) {
                tracing::debug!("signer-recovery round skipped: transport suspended");
                return RoundClass::Suspended;
            }
            // CIRISEdge#794 — no route: the ordinary round would fail the
            // same way, so it does not run; the backoff takes over.
            if let RoundClass::NoRoute(error) = round_class_of(&e) {
                log_round_error(
                    peer_id,
                    coord.kind(),
                    "signer-recovery round: no route to peer (CIRISEdge#794)",
                    &error,
                );
                let event = RoundEvent::NoRoute(format!("transport: {error}"));
                *ended = RoundEnded::of(&event);
                if let Some(sink) = event_sink {
                    let _ = sink.send((peer_id.to_string(), event)).await;
                }
                return RoundClass::NoRoute(error);
            }
            // A failed recovery must not also cost this peer its
            // ordinary round. The row stays transient-refused and
            // re-notes its signer on the next offer (D6).
            tracing::warn!(
                error = ?e,
                "signer-recovery round failed; running ordinary \
                 anti-entropy this tick instead (FSD-SIGNER-RECOVERY D6)"
            );
            None
        }
    };
    if let Some(step) = recovery {
        let event = match step {
            DriveStep::Complete(report) | DriveStep::SendThenComplete(_, report) => {
                RoundEvent::Completed(report)
            }
            DriveStep::Refused => RoundEvent::Refused,
            DriveStep::SendThenWait(_) => RoundEvent::TimedOut,
        };
        *ended = RoundEnded::of(&event);
        if let Some(sink) = event_sink {
            let _ = sink.send((peer_id.to_string(), event)).await;
        }
        return RoundClass::Other;
    }
    let outcome = run_one_round(coord, round_timeout, seat).await;
    let class = match &outcome {
        Ok(_) => RoundClass::Other,
        Err(e) => round_class_of(e),
    };
    // Lifecycle — a round refused because the transport is suspended is not
    // an error of the round: skip quietly, no event, no backoff.
    if matches!(class, RoundClass::Suspended) {
        tracing::debug!("round skipped: transport suspended");
        return class;
    }
    let event = match outcome {
        // CIRISEdge#380 — run_one_round converts SendThenComplete to
        // Complete after sending; the merged arm is defensive if it
        // ever leaks through.
        Ok(DriveStep::Complete(report) | DriveStep::SendThenComplete(_, report)) => {
            tracing::info!("round completed");
            RoundEvent::Completed(report)
        }
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
        // CIRISEdge#794 — no route is logged once per backoff entry and
        // exit by the backoff, never once per round.
        Err(RoundError::Coordinator(e)) if matches!(class, RoundClass::NoRoute(_)) => {
            log_round_error(
                peer_id,
                coord.kind(),
                "round: no route to peer (CIRISEdge#794)",
                &e.to_string(),
            );
            RoundEvent::NoRoute(e.to_string())
        }
        Err(RoundError::Coordinator(e)) => {
            log_round_error(
                peer_id,
                coord.kind(),
                "coordinator error during round",
                &e.to_string(),
            );
            RoundEvent::Error(e.to_string())
        }
        Err(RoundError::InboundClosed) => {
            let error = "inbound channel closed";
            log_round_error(peer_id, coord.kind(), "round cannot complete", error);
            RoundEvent::Error(error.to_string())
        }
    };
    *ended = RoundEnded::of(&event);
    if let Some(sink) = event_sink {
        // Sink-closed isn't a fault — the metrics consumer
        // dropped their receiver. Round loops continue.
        let _ = sink.send((peer_id.to_string(), event)).await;
    }
    // CIRISEdge#440 — `antientropy.round_secs` relief, applied at
    // the round boundary: resolve once per round (a cache hit
    // within the reader's TTL), and rebuild the interval only on a
    // CHANGE. `interval_at(now + target, target)` schedules the
    // next round one full NEW cadence out — "a changed value takes
    // effect next round" — and the same comparison walks the
    // cadence back to the configured value when the relief's TTL
    // expires. Relief can only LENGTHEN the cadence
    // (relieve-never-expand, enforced in persist's fold), so this
    // can never speed rounds up past what the operator configured.
    class
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
/// Anti-entropy: INITIATE the exchange, then drive it to completion.
///
/// The initiating step is what sends this node's Summary. Recovery
/// ([`run_one_recovery_round`]) deliberately omits it — see
/// `docs/FSD_SIGNER_RECOVERY.md` §3, where sending a second Summary alongside a
/// Pull is the single fact that broke three earlier attempts.
/// CIRISEdge#776 — the `Kick` arm: the one coordinator `(peer, kind)`, if it
/// exists. Its `Notify` coalesces, so a kick never doubles a round.
fn kick_one(
    per_coord: &HashMap<(String, EnvelopeKind), CoordControl>,
    peer_key_id: String,
    kind: EnvelopeKind,
) {
    if let Some(c) = per_coord.get(&(peer_key_id, kind)) {
        c.kick.notify_one();
    }
}

/// v19.0.0 — the `RoundNow` arm: kick every coordinator toward `peer_key_id`
/// (every coordinator, `None`).
fn round_now_kick(
    per_coord: &HashMap<(String, EnvelopeKind), CoordControl>,
    peer_key_id: Option<&str>,
) {
    let mut kicked = 0usize;
    for ((peer, _kind), c) in per_coord {
        if peer_key_id.map_or(true, |p| p == peer) {
            c.kick.notify_one();
            kicked += 1;
        }
    }
    tracing::debug!(
        peer = ?peer_key_id,
        kicked,
        "scheduler: RoundNow — rounds fired ahead of the cadence"
    );
}

/// The `RemoveInitiator` arm: stop the one coordinator. CIRISEdge#794 — a peer
/// with no coordinator left is out of the send set; its backoff goes too.
fn remove_initiator(
    per_coord: &mut HashMap<(String, EnvelopeKind), CoordControl>,
    backoff: &NoRouteBackoff,
    driven: &std::sync::Mutex<HashSet<String>>,
    peer_key_id: &str,
    kind: EnvelopeKind,
) {
    if let Some(c) = per_coord.remove(&(peer_key_id.to_owned(), kind)) {
        let _ = c.cancel.send(true);
    }
    if !per_coord.keys().any(|(p, _)| p == peer_key_id) {
        backoff.forget(peer_key_id);
        if let Ok(mut driven) = driven.lock() {
            driven.remove(peer_key_id);
        }
    }
}

/// Record that a coordinator is about to be driven toward its peer.
fn note_driven(driven: &std::sync::Mutex<HashSet<String>>, coord: &ReplicationCoordinator) {
    if let Ok(mut driven) = driven.lock() {
        driven.insert(coord.peer_key_id().to_owned());
    }
}

/// CIRISEdge#794 — a peer left backoff: kick its coordinators now, except the
/// plane whose probe just ran.
fn wake_kick(
    per_coord: &HashMap<(String, EnvelopeKind), CoordControl>,
    wake: &super::no_route_backoff::Wake,
) {
    for ((peer, kind), c) in per_coord {
        if *peer == wake.peer_key_id && Some(*kind) != wake.except {
            c.kick.notify_one();
        }
    }
}

/// CIRISEdge#636 — the `Propagate` arm: kick every coordinator on `kind` whose
/// peer is not `from_peer`. A row admitted FROM a peer is offered to every
/// OTHER peer on its plane now, not at the next cadence tick.
fn propagate_kick(
    per_coord: &HashMap<(String, EnvelopeKind), CoordControl>,
    from_peer: &str,
    kind: EnvelopeKind,
) {
    let mut kicked = 0usize;
    for ((peer, k), c) in per_coord {
        if *k == kind && peer != from_peer {
            c.kick.notify_one();
            kicked += 1;
        }
    }
    if kicked > 0 {
        tracing::info!(
            from_peer = %from_peer,
            ?kind,
            kicked,
            "propagation kick — rows admitted from a peer are offered to every other peer \
             now, not at the next cadence tick (CIRISEdge#636)"
        );
    }
}

async fn run_one_round(
    coord: &ReplicationCoordinator,
    round_timeout: Duration,
    seat: &mut RoundSeat<'_>,
) -> Result<DriveStep, RoundError> {
    // `drive_round_step(None)` opens the round (mints its id, creates its
    // inbox); `finish_round` closes it on every exit path (CIRISEdge#634).
    let first = coord.drive_round_step(None).await?;
    let outcome = drive_exchange_to_completion(coord, round_timeout, first, seat).await;
    finish_round(coord, &outcome).await;
    outcome
}

/// Signer-key recovery: send ONE `Pull` and drive **only its reply** to
/// completion (FSD-SIGNER-RECOVERY D1/D2).
///
/// Returns `Ok(None)` when nothing was queued for this peer, which is the
/// common case — the caller then runs an ordinary round instead.
///
/// # Why this exists as a separate round type
///
/// An Initiator reads inbound messages only inside the drive loop, and the
/// loop's first step opens by sending a Summary. A Pull issued *around* an
/// ordinary round therefore leaves two exchanges outstanding whose replies are
/// both Summaries, with no request correlation — the scheduled reply could be
/// consumed as the Pull's, putting the peer's whole page into `pending_bodies`
/// on a node that had just chosen not to fetch bodies.
///
/// Entering the same loop with `SendThenWait(∅)` sends nothing and waits, so the
/// only reply it can consume is the Pull's. Combined with the per-peer scheduler
/// task being sequential — a recovery round REPLACES the tick's ordinary round —
/// at most one exchange is ever outstanding on a coordinator. That is the
/// correlation, achieved by construction rather than by a request id, and it
/// needs no wire change.
async fn run_one_recovery_round(
    coord: &ReplicationCoordinator,
    round_timeout: Duration,
    seat: &mut RoundSeat<'_>,
) -> Result<Option<DriveStep>, RoundError> {
    // CIRISEdge#634 — the Pull is a round-open too: mint the round FIRST so
    // the Pull is stamped with it and its Summary reply routes into this
    // round's inbox rather than the on-demand one.
    let round = coord.begin_round().await;
    let bound = pacing_send_timeout(coord.pacing_gap());
    let pulled = seat
        .send(round_timeout, bound, coord.send_recovery_ask())
        .await;
    let signer = match pulled {
        Ok(Some(signer)) => signer,
        Ok(None) => {
            coord.end_round().await;
            return Ok(None);
        }
        Err(e) => {
            coord.abandon_round().await;
            return Err(e);
        }
    };
    tracing::debug!(
        signer = %signer,
        round,
        "recovery round: asked this peer for its own Key (FSD-SIGNER-RECOVERY)"
    );
    // `SendThenWait(∅)`: send nothing, wait. The Pull is already on the wire and
    // this node must NOT put a Summary beside it.
    let outcome = drive_exchange_to_completion(
        coord,
        round_timeout,
        DriveStep::SendThenWait(Vec::new()),
        seat,
    )
    .await;
    finish_round(coord, &outcome).await;
    outcome.map(Some)
}

/// Close the driven round after [`drive_exchange_to_completion`] returns
/// (CIRISEdge#634 §5.1): a completed round is ended (its inbox dropped, the
/// id cleared) and any other exit — timeout, closed inbox, transport error,
/// a step that refused — is ABANDONED, which also resets the session so
/// nothing of the dead round is inherited. Either way a late reply naming
/// this round is dropped VISIBLY at the registry instead of parking in a
/// channel nobody reads.
async fn finish_round(coord: &ReplicationCoordinator, outcome: &Result<DriveStep, RoundError>) {
    match outcome {
        Ok(DriveStep::Complete(_)) => coord.end_round().await,
        Ok(DriveStep::SendThenWait(_) | DriveStep::SendThenComplete(_, _) | DriveStep::Refused)
        | Err(_) => coord.abandon_round().await,
    }
}

/// The send-and-wait loop shared by both round types, given its first step.
///
/// Owns no policy about what OPENS an exchange — that is the caller's choice and
/// the only difference between anti-entropy and recovery.
async fn drive_exchange_to_completion(
    coord: &ReplicationCoordinator,
    round_timeout: Duration,
    first_step: DriveStep,
    seat: &mut RoundSeat<'_>,
) -> Result<DriveStep, RoundError> {
    let bound = pacing_send_timeout(coord.pacing_gap());
    let mut step = first_step;
    loop {
        // CIRISEdge#380 — initiator-final: send the messages, then the round
        // is complete WITHOUT waiting (the peer's last Summary confirmed full
        // sync; there is nothing on the wire to wait for). This is what turns
        // a NAT'd initiator's steady-state from perpetual `error`/`timed_out`
        // into honest `completed` on the round-outcome instrument (#370).
        if let DriveStep::SendThenComplete(ref msgs, ref report) = step {
            let report = report.clone();
            for m in msgs {
                seat.send(round_timeout, bound, coord.send_message(m))
                    .await?;
            }
            return Ok(DriveStep::Complete(report));
        }
        let msgs = match step {
            DriveStep::SendThenWait(ref msgs) => msgs.clone(),
            _ => return Ok(step),
        };
        for m in &msgs {
            seat.send(round_timeout, bound, coord.send_message(m))
                .await?;
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
    use super::{RoundEnded, RoundEvent};

    /// The round-ended line carries why: canonical-1's 178 `error` outcomes
    /// left no reason anywhere (error 178, completed 0).
    #[test]
    fn a_round_ended_line_names_the_outcome_and_the_error() {
        let ended = RoundEnded::of(&RoundEvent::Error("transport: no route".to_owned()));
        assert_eq!(ended.outcome, "error");
        assert_eq!(ended.error.as_deref(), Some("transport: no route"));
        let ended = RoundEnded::of(&RoundEvent::NoRoute("transport: offline".to_owned()));
        assert_eq!(ended.outcome, "no_route");
        assert_eq!(ended.error.as_deref(), Some("transport: offline"));
        let ended = RoundEnded::of(&RoundEvent::TimedOut);
        assert_eq!((ended.outcome, ended.error), ("timed_out", None));
        assert_eq!(RoundEnded::default().outcome, "skipped");
    }

    use super::*;
    use crate::replication::coordinator::ReplicationCoordinator;
    use crate::replication::protocol::{EnvelopeKind, EnvelopeRef};
    use crate::replication::session::SessionRole;
    use crate::replication::summary::{
        ApplyOutcome, LocalState, StalenessSignal, StateApplier, StateProvider,
    };
    use crate::transport::{InboundFrame, Transport, TransportId, TransportSendOutcome};
    use async_trait::async_trait;
    use std::collections::HashMap;

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
    #[async_trait::async_trait]
    impl StateProvider for StaticProvider {
        async fn local_refs(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef> {
            self.state.refs_for(kind)
        }
        async fn fetch_envelope(&self, _kind: EnvelopeKind, h: &[u8; 32]) -> Option<Vec<u8>> {
            self.envelopes.get(h).cloned()
        }
    }

    /// CIRISEdge#370 — `apply_envelope` is `&self`; the recorded set lives
    /// behind `std::sync::Mutex` interior mutability. Recording semantics
    /// (admit-once, duplicate detection) are unchanged.
    struct RecordingApplier {
        known: HashMap<Vec<u8>, [u8; 32]>,
        local_hashes: std::sync::Mutex<std::collections::HashSet<[u8; 32]>>,
    }
    impl RecordingApplier {
        fn with(
            known: HashMap<Vec<u8>, [u8; 32]>,
            local_hashes: std::collections::HashSet<[u8; 32]>,
        ) -> Arc<dyn StateApplier> {
            Arc::new(Self {
                known,
                local_hashes: std::sync::Mutex::new(local_hashes),
            })
        }
    }
    #[async_trait::async_trait]
    impl StateApplier for RecordingApplier {
        async fn apply_envelope(
            &self,
            _kind: EnvelopeKind,
            bytes: &[u8],
            _source_peer: Option<&str>,
        ) -> ApplyOutcome {
            let Some(hash) = self.known.get(bytes).copied() else {
                return ApplyOutcome::refused("unknown bytes (test)");
            };
            let mut local_hashes = self.local_hashes.lock().unwrap();
            if local_hashes.contains(&hash) {
                return ApplyOutcome::Duplicate;
            }
            local_hashes.insert(hash);
            ApplyOutcome::Admitted
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
            ..SchedulerConfig::default()
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
        let applier = RecordingApplier::with(HashMap::new(), std::collections::HashSet::new());
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
    #[allow(clippy::too_many_lines)] // the full Alice↔Bob round fixture + its P0 duration check
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
        let alice_applier = RecordingApplier::with(
            HashMap::from([(b"env_3".to_vec(), h(3)), (b"env_4".to_vec(), h(4))]),
            [h(1), h(2)].into_iter().collect(),
        );
        let bob_applier = RecordingApplier::with(
            HashMap::from([(b"env_1".to_vec(), h(1)), (b"env_2".to_vec(), h(2))]),
            [h(3), h(4)].into_iter().collect(),
        );

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

        // Wire the scheduler with Alice as the Initiator. CIRISEdge P0
        // telemetry — with the Edge's metrics bag, so the round's wall time
        // is recorded where the round runs.
        let metrics = crate::observability::EdgeMetrics::new();
        let mut sched =
            ReplicationScheduler::new(fast_config()).with_metrics(Some(metrics.clone()));
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

        // CIRISEdge P0 telemetry — the completed round is in the Key plane's
        // duration histogram. The event is sent from inside the round, the
        // observation right after it returns, so wait for it briefly.
        let recorded = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(h) = metrics
                    .snapshot()
                    .replication_round_duration_seconds
                    .get(&EnvelopeKind::Key)
                {
                    break h.clone();
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the round's duration is recorded under its kind");
        assert!(recorded.count >= 1);
        assert_eq!(
            recorded.cumulative.last().copied(),
            Some(recorded.count),
            "+Inf is the count"
        );

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
        let applier = RecordingApplier::with(HashMap::new(), std::collections::HashSet::new());
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
            ..SchedulerConfig::default()
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
    /// CIRISEdge#634 §5.1 — a round that times out is ABANDONED: its inbox is
    /// gone, its id cleared, its session reset. Nothing is parked for the next
    /// round to mistake for its own reply.
    #[tokio::test]
    async fn a_timed_out_round_is_abandoned_not_parked() {
        let (alice_to_bob_tx, mut alice_to_bob_rx) = tokio::sync::mpsc::unbounded_channel();
        let alice_transport = Arc::new(InMemTransport {
            peer_inbox: HashMap::from([("bob".to_string(), alice_to_bob_tx)]),
        });
        // Silent bob: swallow everything.
        tokio::spawn(async move { while alice_to_bob_rx.recv().await.is_some() {} });
        let provider = Arc::new(StaticProvider {
            state: LocalState::new(),
            envelopes: HashMap::new(),
        });
        let applier = RecordingApplier::with(HashMap::new(), std::collections::HashSet::new());
        let coord = ReplicationCoordinator::new(
            alice_transport,
            "bob",
            EnvelopeKind::Key,
            SessionRole::Initiator,
            provider,
            applier,
        );

        let gate = RoundGate::new(1);
        let mut seat = RoundSeat::take(&gate, "peer", "kind").await;
        let outcome = run_one_round(&coord, Duration::from_millis(50), &mut seat).await;
        assert!(matches!(outcome, Err(RoundError::Timeout)), "{outcome:?}");
        assert_eq!(coord.current_round(), 0, "the dead round's id is cleared");
        assert_eq!(coord.inbound_depth(), 0, "no inbox survives the round");
        assert!(
            !coord.is_round_in_flight(),
            "a late reply now finds no round and is dropped at the registry"
        );

        // The next round is a fresh one — its own id, its own inbox.
        let first = coord.drive_round_step(None).await.unwrap();
        assert!(matches!(first, DriveStep::SendThenWait(_)));
        let fresh = coord.current_round();
        assert_ne!(fresh, 0);
        coord.abandon_round().await;
        assert_eq!(coord.current_round(), 0);
    }

    /// CIRISEdge#636 — `Propagate { from_peer, kind }` kicks every OTHER peer on
    /// that plane, and only that plane: with a long cadence, the kicked
    /// coordinators produce a round event and the excluded ones stay quiet.
    #[tokio::test]
    async fn propagate_kicks_every_other_peer_on_the_plane_and_nobody_else() {
        let mut sched = ReplicationScheduler::new(SchedulerConfig {
            cadence: Duration::from_secs(3600),
            round_timeout: Duration::from_millis(80),
            ..SchedulerConfig::default()
        });
        let control = sched.install_control_channel();
        let (event_tx, mut event_rx) = mpsc::channel::<(String, RoundEvent)>(64);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let sched_handle =
            tokio::spawn(async move { sched.run_with_events(cancel_rx, Some(event_tx)).await });

        let mk = |peer: &str, kind: EnvelopeKind| {
            let transport: Arc<dyn Transport> = Arc::new(InMemTransport {
                peer_inbox: HashMap::new(),
            });
            let provider: Arc<dyn StateProvider> = Arc::new(StaticProvider {
                state: LocalState::new(),
                envelopes: HashMap::new(),
            });
            let applier = RecordingApplier::with(HashMap::new(), std::collections::HashSet::new());
            Arc::new(ReplicationCoordinator::new(
                transport,
                peer,
                kind,
                SessionRole::Initiator,
                provider,
                applier,
            ))
        };
        for (peer, kind) in [
            ("alice", EnvelopeKind::Key),
            ("carol", EnvelopeKind::Key),
            ("carol", EnvelopeKind::Attestation),
        ] {
            control.add_initiator(mk(peer, kind)).await.expect("add");
        }
        // Drain the start-up rounds (each coordinator's first tick fires at once).
        let mut startup = 0;
        while startup < 3 {
            let (_, _) = tokio::time::timeout(Duration::from_secs(3), event_rx.recv())
                .await
                .expect("startup round")
                .expect("open");
            startup += 1;
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(300), event_rx.recv())
                .await
                .is_err(),
            "quiet once the start-up rounds are done"
        );

        // Rows admitted from alice on Key ⇒ carol/Key is kicked; alice/Key (the
        // source) and carol/Attestation (another plane) are not.
        control
            .propagate("alice", EnvelopeKind::Key)
            .await
            .expect("propagate");
        let (peer, event) = tokio::time::timeout(Duration::from_secs(3), event_rx.recv())
            .await
            .expect("the propagation round")
            .expect("open");
        assert_eq!(peer, "carol");
        assert!(
            matches!(event, RoundEvent::TimedOut | RoundEvent::Error(_)),
            "an unreachable in-mem peer: {event:?}"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(300), event_rx.recv())
                .await
                .is_err(),
            "no round toward the source peer or on another plane"
        );

        cancel_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), sched_handle)
            .await
            .expect("shutdown")
            .expect("join");
    }

    /// CIRISEdge#740 — a kick is bounded. N+1 coordinators are kicked at once
    /// under a bound of N: exactly N rounds enter their provider read, the
    /// (N+1)th waits behind the gate (counted in `waited`), and it runs the
    /// moment a permit frees — nothing is dropped, the peak never exceeds N.
    /// The provider parks each read on an awaited gate, so "in flight" here is
    /// a round genuinely inside its persist-shaped read, not a race window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::too_many_lines)] // one scenario: start, close, kick, observe, open, drain
    async fn a_kick_of_n_plus_one_rounds_runs_at_most_n_at_once() {
        const N: usize = 2;
        struct ParkingProvider {
            open: watch::Receiver<bool>,
            entered: Arc<std::sync::atomic::AtomicUsize>,
            entered_note: Arc<tokio::sync::Notify>,
        }
        #[async_trait::async_trait]
        impl StateProvider for ParkingProvider {
            async fn local_refs(&self, _kind: EnvelopeKind) -> Vec<EnvelopeRef> {
                self.entered.fetch_add(1, Ordering::AcqRel);
                self.entered_note.notify_waiters();
                let mut open = self.open.clone();
                while !*open.borrow_and_update() {
                    if open.changed().await.is_err() {
                        break;
                    }
                }
                Vec::new()
            }
            async fn fetch_envelope(&self, _kind: EnvelopeKind, _h: &[u8; 32]) -> Option<Vec<u8>> {
                None
            }
        }

        let mut sched = ReplicationScheduler::new(SchedulerConfig {
            cadence: Duration::from_secs(3600),
            round_timeout: Duration::from_millis(200),
            max_concurrent_rounds: N,
        });
        let control = sched.install_control_channel();
        let (event_tx, mut event_rx) = mpsc::channel::<(String, RoundEvent)>(64);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (open_tx, open_rx) = watch::channel(true);
        let entered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let entered_note = Arc::new(tokio::sync::Notify::new());
        let sched_handle =
            tokio::spawn(async move { sched.run_with_events(cancel_rx, Some(event_tx)).await });

        for i in 0..=N {
            let transport: Arc<dyn Transport> = Arc::new(InMemTransport {
                peer_inbox: HashMap::new(),
            });
            let provider: Arc<dyn StateProvider> = Arc::new(ParkingProvider {
                open: open_rx.clone(),
                entered: Arc::clone(&entered),
                entered_note: Arc::clone(&entered_note),
            });
            let applier = RecordingApplier::with(HashMap::new(), std::collections::HashSet::new());
            control
                .add_initiator(Arc::new(ReplicationCoordinator::new(
                    transport,
                    format!("peer-{i}"),
                    EnvelopeKind::Key,
                    SessionRole::Initiator,
                    provider,
                    applier,
                )))
                .await
                .expect("add");
        }
        // Start-up fan-out with the gate open: every coordinator's first tick.
        for _ in 0..=N {
            tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
                .await
                .expect("start-up round")
                .expect("open");
        }
        let base = entered.load(Ordering::Acquire);
        let base_waited = control.round_bound().waited;

        // Close the read gate and KICK every coordinator at once.
        open_tx.send_replace(false);
        control.round_now(None).await.expect("kick");

        // Exactly N rounds reach their read.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let note = entered_note.notified();
                if entered.load(Ordering::Acquire) >= base + N {
                    break;
                }
                note.await;
            }
        })
        .await
        .expect("N rounds enter their read");
        let stats = control.round_bound();
        assert_eq!(stats.bound, N);
        assert_eq!(stats.in_flight, N, "N rounds hold the gate: {stats:?}");
        // The (N+1)th is behind the gate, not inside a read: give it every
        // chance to (wrongly) enter.
        let extra = tokio::time::timeout(Duration::from_millis(300), async {
            loop {
                let note = entered_note.notified();
                if entered.load(Ordering::Acquire) > base + N {
                    break;
                }
                note.await;
            }
        })
        .await;
        assert!(
            extra.is_err(),
            "round N+1 entered its read while N held the gate"
        );
        assert_eq!(entered.load(Ordering::Acquire), base + N);
        assert!(
            control.round_bound().waited > base_waited,
            "the waiting round is counted: {:?}",
            control.round_bound()
        );

        // Open the gate: all N+1 rounds finish — the waiter was queued, not lost.
        open_tx.send_replace(true);
        for _ in 0..=N {
            tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
                .await
                .expect("kicked round")
                .expect("open");
        }
        assert_eq!(entered.load(Ordering::Acquire), base + N + 1);
        // A round emits its event BEFORE its permit guard drops at task end, so
        // `in_flight` reaches 0 a moment after the last event, not with it
        // (under a loaded `--lib` run the read raced the drop: in_flight 1).
        // Wait for the permits with a deadline; never assert on the race.
        let stats = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let s = control.round_bound();
                if s.in_flight == 0 {
                    break s;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| control.round_bound());
        assert_eq!(stats.in_flight, 0, "every permit returned: {stats:?}");
        assert_eq!(stats.peak_in_flight, N, "the bound was never exceeded");

        cancel_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), sched_handle)
            .await
            .expect("shutdown")
            .expect("join");
    }

    /// CIRISEdge#740 — a bound of zero is raised to one, never a scheduler that
    /// cannot run a round.
    #[test]
    fn a_zero_round_bound_is_raised_to_one() {
        let s = ReplicationScheduler::new(SchedulerConfig {
            max_concurrent_rounds: 0,
            ..SchedulerConfig::default()
        });
        assert_eq!(s.round_bound().bound, 1);
    }

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
        let applier = RecordingApplier::with(HashMap::new(), std::collections::HashSet::new());
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

    /// CIRISEdge#440 — build one black-holed Initiator (peer never replies, so
    /// every round is a fast `TimedOut` event) and run it under `config` with
    /// an optional mesh-config reader; return how many round events landed in
    /// `window`.
    async fn count_rounds_in_window(
        config: SchedulerConfig,
        mesh_config: Option<Arc<crate::replication::mesh_config::MeshConfigReader>>,
        window: Duration,
    ) -> usize {
        let (alice_to_bob_tx, mut alice_to_bob_rx) = tokio::sync::mpsc::unbounded_channel();
        let transport = Arc::new(InMemTransport {
            peer_inbox: HashMap::from([("bob".to_string(), alice_to_bob_tx)]),
        });
        tokio::spawn(async move { while alice_to_bob_rx.recv().await.is_some() {} });
        let provider = Arc::new(StaticProvider {
            state: LocalState::new(),
            envelopes: HashMap::new(),
        });
        let applier = RecordingApplier::with(HashMap::new(), std::collections::HashSet::new());
        let coord = Arc::new(ReplicationCoordinator::new(
            transport,
            "bob",
            EnvelopeKind::Key,
            SessionRole::Initiator,
            provider,
            applier,
        ));
        let mut sched = ReplicationScheduler::new(config).with_mesh_config(mesh_config);
        sched.add_initiator(coord);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(64);
        let sched_handle =
            tokio::spawn(async move { sched.run_with_events(cancel_rx, Some(event_tx)).await });
        let start = tokio::time::Instant::now();
        let mut rounds = 0usize;
        while start.elapsed() < window {
            if tokio::time::timeout(Duration::from_millis(50), event_rx.recv())
                .await
                .ok()
                .flatten()
                .is_some()
            {
                rounds += 1;
            }
        }
        cancel_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), sched_handle)
            .await
            .expect("shutdown")
            .expect("join");
        rounds
    }

    /// CIRISEdge#440 — `antientropy.round_secs` relief takes effect at the NEXT
    /// round boundary: with a live relief of 3600 s over a 20 ms configured
    /// cadence, exactly ONE round fires in the observation window (the first
    /// round runs, then the interval is rebuilt to the relieved cadence); the
    /// control (a reader answering NO relief — the absence contract) keeps the
    /// configured cadence and fires many.
    ///
    /// The reader here is `fixed_for_test` — the consumer-wiring half. The
    /// reader→fold→admission half (that a REAL admitted `round_secs` row
    /// produces exactly this `round_cadence: Some(...)` snapshot) is the
    /// field-provenance suite in `replication::mesh_config`.
    #[tokio::test]
    async fn cadence_relief_takes_effect_next_round_and_absence_keeps_cadence() {
        use crate::replication::mesh_config::{MeshConfigReader, MeshConfigRelief};
        use ciris_persist::federation::FederationDirectory;
        let dir: Arc<dyn FederationDirectory> =
            Arc::new(ciris_persist::store::test_backend::test_backend());

        let config = SchedulerConfig {
            cadence: Duration::from_millis(20),
            round_timeout: Duration::from_millis(40),
            ..SchedulerConfig::default()
        };
        let window = Duration::from_millis(800);

        let relieved_reader = Arc::new(MeshConfigReader::fixed_for_test(
            Arc::clone(&dir),
            MeshConfigRelief {
                round_cadence: Some(Duration::from_secs(3600)),
                ..MeshConfigRelief::NONE
            },
        ));
        let relieved = count_rounds_in_window(config, Some(relieved_reader), window).await;
        assert_eq!(
            relieved, 1,
            "under a round_secs relief the first round runs and the SECOND is \
             rescheduled to the relieved cadence — exactly one round in the window"
        );

        let none_reader = Arc::new(MeshConfigReader::fixed_for_test(
            Arc::clone(&dir),
            MeshConfigRelief::NONE,
        ));
        let unrelieved = count_rounds_in_window(config, Some(none_reader), window).await;
        assert!(
            unrelieved >= 3,
            "a reader answering NO relief must leave the configured cadence \
             untouched (absence = today); got {unrelieved} rounds"
        );
    }

    /// A provider that hands out exactly one queued signer, once — the shape
    /// `note_missing_signer` produces for the delivering peer's own key.
    struct RecoveryProvider {
        queued: std::sync::Mutex<Option<String>>,
    }
    #[async_trait::async_trait]
    impl StateProvider for RecoveryProvider {
        async fn local_refs(&self, _kind: EnvelopeKind) -> Vec<EnvelopeRef> {
            // Deliberately non-empty is unnecessary: invariant 1 is about what
            // a RECOVERY round puts on the wire, and it must send no Summary
            // even when this node has refs it would otherwise advertise.
            vec![EnvelopeRef {
                envelope_hash: [9u8; 32],
                seq: 1,
            }]
        }
        async fn fetch_envelope(&self, _kind: EnvelopeKind, _h: &[u8; 32]) -> Option<Vec<u8>> {
            None
        }
        fn take_missing_signer_for(&self, peer_key_id: &str) -> Option<String> {
            let mut q = self.queued.lock().unwrap();
            if q.as_deref() == Some(peer_key_id) {
                q.take()
            } else {
                None
            }
        }
    }

    fn recovery_coord(
        peer: &str,
        queued: Option<String>,
    ) -> (
        Arc<ReplicationCoordinator>,
        tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut inbox = HashMap::new();
        inbox.insert(peer.to_string(), tx);
        let transport = Arc::new(InMemTransport { peer_inbox: inbox });
        let provider = Arc::new(RecoveryProvider {
            queued: std::sync::Mutex::new(queued),
        });
        let applier = RecordingApplier::with(HashMap::new(), std::collections::HashSet::new());
        let coord = Arc::new(ReplicationCoordinator::new(
            transport,
            peer,
            EnvelopeKind::Key,
            SessionRole::Initiator,
            provider,
            applier,
        ));
        (coord, rx)
    }

    /// FSD-SIGNER-RECOVERY invariant 1 — **a recovery round sends no Summary.**
    ///
    /// This is the invariant three previous attempts violated, each in a
    /// different way, and it is the whole reason recovery is a separate round
    /// type. A Summary beside the Pull leaves two outstanding exchanges whose
    /// replies are indistinguishable, so the scheduled reply can be consumed as
    /// the Pull's — putting the peer's entire Key page into `pending_bodies` on
    /// a node that had just chosen not to fetch bodies.
    #[tokio::test]
    async fn a_recovery_round_puts_only_the_pull_on_the_wire() {
        let (coord, mut rx) = recovery_coord("peer-1", Some("peer-1".to_string()));

        // Times out waiting for a reply nobody sends; the wire is what matters.
        let gate = RoundGate::new(1);
        let mut place = RoundSeat::take(&gate, "peer", "kind").await;
        let _ = run_one_recovery_round(&coord, Duration::from_millis(50), &mut place).await;

        let mut sent = Vec::new();
        while let Ok(bytes) = rx.try_recv() {
            sent.push(bytes);
        }
        assert_eq!(
            sent.len(),
            1,
            "a recovery round must put EXACTLY ONE message on the wire; \
             {} were sent",
            sent.len()
        );
        let text = String::from_utf8_lossy(&sent[0]).to_string();
        assert!(
            text.contains("pull"),
            "the one message must be the Pull, got: {text}"
        );
        assert!(
            !text.contains("summary"),
            "a recovery round must NOT send a Summary — that is the ambiguity \
             that broke three earlier attempts (FSD §3), got: {text}"
        );
    }

    /// FSD-SIGNER-RECOVERY invariant 2 — nothing queued means no recovery
    /// exchange at all, so the tick runs an ordinary round instead.
    ///
    /// Without this the scheduler would burn a cadence tick per peer per round
    /// waiting for a reply to a Pull it never sent.
    #[tokio::test]
    async fn no_queued_signer_means_no_recovery_exchange() {
        let (coord, mut rx) = recovery_coord("peer-1", None);

        let gate = RoundGate::new(1);
        let mut seat = RoundSeat::take(&gate, "peer", "kind").await;
        let outcome = run_one_recovery_round(&coord, Duration::from_millis(50), &mut seat)
            .await
            .expect("no queued name is not an error");
        assert!(
            outcome.is_none(),
            "with nothing queued the caller must fall through to an ordinary round"
        );
        assert!(rx.try_recv().is_err(), "and nothing may be put on the wire");
    }

    /// FSD-SIGNER-RECOVERY invariant 3 — only the `Key` coordinator recovers.
    ///
    /// `start_pull` sends `PullMessage { kind: self.kind, .. }`, and the row
    /// every stalled record waits on is a Key row. A recovery Pull on another
    /// plane would ask a peer for the wrong thing entirely.
    #[tokio::test]
    async fn only_the_key_coordinator_recovers_a_signer() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut inbox = HashMap::new();
        inbox.insert("peer-1".to_string(), tx);
        let transport = Arc::new(InMemTransport { peer_inbox: inbox });
        let provider = Arc::new(RecoveryProvider {
            queued: std::sync::Mutex::new(Some("peer-1".to_string())),
        });
        let applier = RecordingApplier::with(HashMap::new(), std::collections::HashSet::new());
        let coord = Arc::new(ReplicationCoordinator::new(
            transport,
            "peer-1",
            EnvelopeKind::Attestation,
            SessionRole::Initiator,
            provider,
            applier,
        ));

        assert!(
            coord
                .send_recovery_pull()
                .await
                .expect("not an error")
                .is_none(),
            "a non-Key coordinator must not recover"
        );
        assert!(rx.try_recv().is_err(), "and must send nothing");
    }

    /// A transport whose every send fails as a refused dial fails in the field
    /// (`a_refused_dial_comes_back_off_the_beat` read this error off real
    /// links), or succeeds to a peer that never answers.
    struct DialLog {
        refused: std::sync::atomic::AtomicBool,
        at: std::sync::Mutex<Vec<tokio::time::Instant>>,
    }

    #[async_trait]
    impl Transport for DialLog {
        fn id(&self) -> TransportId {
            TransportId::HTTP
        }
        async fn send(
            &self,
            _destination_key_id: &str,
            _envelope_bytes: &[u8],
        ) -> Result<TransportSendOutcome, TransportError> {
            self.at.lock().unwrap().push(tokio::time::Instant::now());
            if self.refused.load(Ordering::SeqCst) {
                return Err(TransportError::Io(
                    "reticulum resource send: resource transfer failed: LinkClosed".to_owned(),
                ));
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

    /// Sends to `dead` never return; every other send lands, to a peer that
    /// does not answer.
    struct ParkedPeer {
        dead: String,
        live_sends: AtomicUsize,
    }

    #[async_trait]
    impl Transport for ParkedPeer {
        fn id(&self) -> TransportId {
            TransportId::HTTP
        }
        async fn send(
            &self,
            destination_key_id: &str,
            _envelope_bytes: &[u8],
        ) -> Result<TransportSendOutcome, TransportError> {
            if destination_key_id == self.dead {
                std::future::pending::<()>().await;
            }
            self.live_sends.fetch_add(1, Ordering::SeqCst);
            Ok(TransportSendOutcome::Delivered)
        }
        async fn listen(
            &self,
            _sink: tokio::sync::mpsc::Sender<InboundFrame>,
        ) -> Result<(), TransportError> {
            Ok(())
        }
    }

    /// A send that never returns gives its permit back after a round's budget
    /// and ends at its own bound, so the gate is never held for it and the
    /// coordinator is never parked for good.
    #[tokio::test(start_paused = true)]
    async fn a_parked_send_gives_back_its_permit_and_ends_at_its_bound() {
        let transport = Arc::new(ParkedPeer {
            dead: "dead".to_owned(),
            live_sends: AtomicUsize::new(0),
        });
        let coord = |peer: &str| {
            Arc::new(ReplicationCoordinator::new(
                Arc::clone(&transport) as Arc<dyn Transport>,
                peer,
                EnvelopeKind::Key,
                SessionRole::Initiator,
                Arc::new(StaticProvider {
                    state: LocalState::new(),
                    envelopes: HashMap::new(),
                }),
                RecordingApplier::with(HashMap::new(), std::collections::HashSet::new()),
            ))
        };
        let mut sched = ReplicationScheduler::new(SchedulerConfig {
            cadence: Duration::from_secs(30),
            round_timeout: Duration::from_secs(1),
            max_concurrent_rounds: 1,
        });
        sched.add_initiator(coord("dead"));
        sched.add_initiator(coord("live"));
        let (cancel, cancel_rx) = watch::channel(false);
        let (event_tx, mut events) = tokio::sync::mpsc::channel(64);
        let run =
            tokio::spawn(async move { sched.run_with_events(cancel_rx, Some(event_tx)).await });
        tokio::time::sleep(Duration::from_secs(175)).await;
        assert!(
            transport.live_sends.load(Ordering::SeqCst) >= 5,
            "the live peer keeps its rounds past the parked send"
        );
        tokio::time::sleep(Duration::from_secs(10)).await;
        let mut dead_ended = false;
        while let Ok((peer, event)) = events.try_recv() {
            if peer == "dead" {
                assert!(matches!(event, RoundEvent::TimedOut), "{event:?}");
                dead_ended = true;
            }
        }
        assert!(dead_ended, "the parked send ended at its bound");
        let _ = cancel.send(true);
        let _ = run.await;
    }

    #[test]
    fn a_send_on_a_shaped_link_is_bounded_by_its_gaps() {
        assert_eq!(pacing_send_timeout(None), ROUND_SEND_TIMEOUT);
        assert_eq!(
            pacing_send_timeout(Some(Duration::from_secs(1))),
            ROUND_SEND_TIMEOUT
        );
        let cellular = Duration::from_secs(47);
        assert!(pacing_send_timeout(Some(cellular)) > cellular.mul_f64(16.0));
    }

    const REDIAL_CADENCE: Duration = Duration::from_secs(30);

    /// One coordinator on a paused clock, with its log and a handle to kick it.
    fn dial_log_scheduler(
        refused: bool,
    ) -> (
        Arc<DialLog>,
        SchedulerHandle,
        watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    ) {
        let log = Arc::new(DialLog {
            refused: std::sync::atomic::AtomicBool::new(refused),
            at: std::sync::Mutex::default(),
        });
        let coord = Arc::new(ReplicationCoordinator::new(
            Arc::clone(&log) as Arc<dyn Transport>,
            "bob",
            EnvelopeKind::Key,
            SessionRole::Initiator,
            Arc::new(StaticProvider {
                state: LocalState::new(),
                envelopes: HashMap::new(),
            }),
            RecordingApplier::with(HashMap::new(), std::collections::HashSet::new()),
        ));
        let mut sched = ReplicationScheduler::new(SchedulerConfig {
            cadence: REDIAL_CADENCE,
            round_timeout: Duration::from_secs(1),
            ..SchedulerConfig::default()
        });
        sched.add_initiator(coord);
        let handle = sched.install_control_channel();
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let run = tokio::spawn(async move { sched.run_until_cancelled(cancel_rx).await });
        (log, handle, cancel_tx, run)
    }

    fn gaps_secs(log: &DialLog) -> Vec<f64> {
        log.at
            .lock()
            .unwrap()
            .windows(2)
            .map(|w| w[1].duration_since(w[0]).as_secs_f64())
            .collect()
    }

    /// CC 5.4.6 — every dial after a refused one is drawn from 0.5 to 1.5
    /// cadences, each on its own draw: a fleet refused at one moment spreads.
    #[tokio::test(start_paused = true)]
    async fn a_refused_dial_draws_its_next_dial_from_half_to_one_and_a_half_cadences() {
        let (log, _handle, cancel, run) = dial_log_scheduler(true);
        tokio::time::sleep(REDIAL_CADENCE * 40).await;
        let gaps = gaps_secs(&log);
        assert!(gaps.len() >= 20, "it keeps dialling: {gaps:.1?}");
        assert!(
            gaps.iter().all(|g| (15.0..=45.01).contains(g)),
            "every re-dial in the draw: {gaps:.1?}"
        );
        let (lo, hi) = gaps
            .iter()
            .fold((f64::MAX, 0.0_f64), |(l, h), g| (l.min(*g), h.max(*g)));
        assert!(hi - lo > 15.0, "fresh draws, not one offset: {gaps:.1?}");
        let _ = cancel.send(true);
        let _ = run.await;
    }

    /// The healthy tick stays: a send that left and a peer that stays silent is
    /// a timed-out round, not a refused dial, and the beat does not move.
    #[tokio::test(start_paused = true)]
    async fn a_round_whose_send_left_keeps_the_tick() {
        let (log, _handle, cancel, run) = dial_log_scheduler(false);
        tokio::time::sleep(REDIAL_CADENCE * 8).await;
        let gaps = gaps_secs(&log);
        assert!(gaps.len() >= 6, "{gaps:.1?}");
        assert!(
            gaps.iter().all(|g| (*g - 30.0).abs() < 0.01),
            "the tick is untouched: {gaps:.1?}"
        );
        let _ = cancel.send(true);
        let _ = run.await;
    }

    /// A kick does not beat the draw: on a restart every coordinator is kicked
    /// at once, and a kick that dialled would put a refused fleet back on one
    /// beat. The drawn tick runs the round the kick wanted.
    #[tokio::test(start_paused = true)]
    async fn a_kick_does_not_beat_a_drawn_redial() {
        let (log, handle, cancel, run) = dial_log_scheduler(true);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(log.at.lock().unwrap().len(), 1, "the first tick dialled");
        for _ in 0..10 {
            handle.round_now(None).await.expect("kick");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        assert_eq!(
            log.at.lock().unwrap().len(),
            1,
            "inside the draw's floor no kick dials"
        );
        tokio::time::sleep(Duration::from_secs(40)).await;
        assert!(log.at.lock().unwrap().len() >= 2, "the draw still fires");
        let _ = cancel.send(true);
        let _ = run.await;
    }
}

/// CIRISEdge#790 — the class gate: no `Span::enter` / `.entered()` guard is
/// bound anywhere in `src/`. In async code a guard held across an `.await`
/// leaves its span on the worker thread's stack while the task is parked, so
/// every span later opened on that worker nests under it without bound (the
/// canonical's 9,495-deep `anti_entropy_round` chain and its stack overflow).
/// Instrument the future (`.instrument(span)`) instead. No clippy lint catches
/// this, so the gate reads the source; it fails on the pre-#790 scheduler.
#[cfg(test)]
mod span_guard_790 {
    #[test]
    fn no_span_guard_is_bound_in_src_790() {
        fn walk(dir: &std::path::Path, out: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).expect("read src dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&path).expect("read source");
                    for (n, line) in text.lines().enumerate() {
                        let code = line.split("//").next().unwrap_or("");
                        let binds = code.contains("let ") && code.contains('=');
                        // Split literals, so this gate never matches itself.
                        let guard = code.contains(concat!("span", ".enter()"))
                            || code.contains(concat!(".enter", "ed()"));
                        if binds && guard {
                            out.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
                        }
                    }
                }
            }
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found = Vec::new();
        walk(&src, &mut found);
        assert!(
            found.is_empty(),
            "a tracing span guard is bound in src/ (CIRISEdge#790): instrument the \
             future with `.instrument(span)` instead of holding `span.enter()` / \
             `.entered()` across awaits:\n{}",
            found.join("\n")
        );
    }
}
