//! **CIRISEdge#794 — a peer the transport has no route to costs the backoff
//! schedule, not every plane on every tick and every kick.**
//!
//! Each witness drives a real [`ReplicationScheduler`] (every coordinator
//! task, the run loop, the round gate) against a scripted transport on a
//! paused tokio clock, so ten minutes of cadence run in milliseconds and
//! every count is exact. The backoff's jitter is pinned to the full window
//! (`|w| w`) where a test counts probes; witness (f) in
//! [`super::no_route_backoff`] covers the real draw.
//!
//! `cargo test --lib no_route_backoff`
//!
//! A lib-level module, not a `tests/` binary (CI disk; see
//! `late_device_768_tests`).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{broadcast, watch};

use super::coordinator::ReplicationCoordinator;
use super::protocol::{EnvelopeKind, EnvelopeRef, ReplicationMessage, SummaryMessage};
use super::registry::ReplicationRegistry;
use super::scheduler::{ReplicationScheduler, SchedulerConfig, SchedulerHandle};
use super::session::SessionRole;
use super::summary::{ApplyOutcome, StateApplier, StateProvider};
use crate::transport::{
    InboundFrame, PeerReachable, ReachabilityEvidence, Transport, TransportError, TransportId,
    TransportSendOutcome,
};

const CADENCE: Duration = Duration::from_secs(30);

/// How a scripted peer answers a send.
#[derive(Clone, Copy)]
enum Route {
    /// `NoRouteToPeer { has_path: false }` — the #794 condition.
    None,
    /// Delivered (and never answered: the round times out, a non-no-route
    /// outcome).
    Delivered,
    /// A transport error that is NOT route absence.
    Error,
    /// `NoDialCandidate` — no address known at all, what a server's peer with
    /// nothing in its live `peers` map answers.
    NoCandidate,
    /// `PeerBlackholed` — an operator's ban: its own treatment.
    Banned,
}

/// Counts every send per peer and answers per [`Route`]; emits reachability
/// evidence on demand, as the Reticulum transport does on an announce or an
/// identified link.
struct ScriptedTransport {
    routes: Mutex<HashMap<String, Route>>,
    sends: Mutex<HashMap<String, usize>>,
    reach: broadcast::Sender<PeerReachable>,
}

impl ScriptedTransport {
    fn new(routes: &[(&str, Route)]) -> Arc<Self> {
        Arc::new(Self {
            routes: Mutex::new(routes.iter().map(|(p, r)| ((*p).to_owned(), *r)).collect()),
            sends: Mutex::new(HashMap::new()),
            reach: broadcast::channel(16).0,
        })
    }
    fn set(&self, peer: &str, route: Route) {
        self.routes.lock().unwrap().insert(peer.to_owned(), route);
    }
    fn sends(&self, peer: &str) -> usize {
        self.sends.lock().unwrap().get(peer).copied().unwrap_or(0)
    }
}

#[async_trait]
impl Transport for ScriptedTransport {
    fn id(&self) -> TransportId {
        TransportId::RETICULUM_RS
    }
    async fn send(
        &self,
        destination_key_id: &str,
        _envelope_bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError> {
        *self
            .sends
            .lock()
            .unwrap()
            .entry(destination_key_id.to_owned())
            .or_default() += 1;
        let route = self
            .routes
            .lock()
            .unwrap()
            .get(destination_key_id)
            .copied()
            .unwrap_or(Route::Delivered);
        match route {
            Route::None => Err(TransportError::NoRouteToPeer {
                key_id: destination_key_id.to_owned(),
                target_dest: "00".repeat(16),
                has_path: false,
                paths: "<empty>".to_owned(),
            }),
            Route::Delivered => Ok(TransportSendOutcome::Delivered),
            Route::Error => Err(TransportError::Timeout(Duration::from_secs(5))),
            Route::NoCandidate => Err(TransportError::NoDialCandidate {
                key_id: destination_key_id.to_owned(),
            }),
            Route::Banned => Err(TransportError::PeerBlackholed {
                identity_hash: vec![0; 16],
                reason: None,
                until: None,
            }),
        }
    }
    async fn listen(
        &self,
        _sink: tokio::sync::mpsc::Sender<InboundFrame>,
    ) -> Result<(), TransportError> {
        Ok(())
    }
    fn subscribe_reachability(&self) -> Option<broadcast::Receiver<PeerReachable>> {
        Some(self.reach.subscribe())
    }
}

struct Empty;

/// As [`Empty`], counting each sweep: what a round pays before its send,
/// whether or not the send goes anywhere.
struct Sweeping {
    sweeps: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl StateProvider for Sweeping {
    async fn local_refs(&self, _kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        self.sweeps
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Vec::new()
    }
    async fn fetch_envelope(&self, _kind: EnvelopeKind, _h: &[u8; 32]) -> Option<Vec<u8>> {
        None
    }
}

#[async_trait]
impl StateProvider for Empty {
    async fn local_refs(&self, _kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        Vec::new()
    }
    async fn fetch_envelope(&self, _kind: EnvelopeKind, _h: &[u8; 32]) -> Option<Vec<u8>> {
        None
    }
}

#[async_trait]
impl StateApplier for Empty {
    async fn apply_envelope(
        &self,
        _kind: EnvelopeKind,
        _bytes: &[u8],
        _source_peer: Option<&str>,
    ) -> ApplyOutcome {
        ApplyOutcome::Duplicate
    }
}

/// A running scheduler with one Initiator per `(peer, kind)`.
struct Rig {
    transport: Arc<ScriptedTransport>,
    handle: SchedulerHandle,
    cancel: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Rig {
    fn start(transport: &Arc<ScriptedTransport>, peers: &[&str], kinds: &[EnvelopeKind]) -> Self {
        Self::start_with(
            transport,
            peers,
            kinds,
            &(Arc::new(Empty) as Arc<dyn StateProvider>),
        )
    }

    fn start_with(
        transport: &Arc<ScriptedTransport>,
        peers: &[&str],
        kinds: &[EnvelopeKind],
        provider: &Arc<dyn StateProvider>,
    ) -> Self {
        let mut sched = ReplicationScheduler::new(SchedulerConfig {
            cadence: CADENCE,
            round_timeout: Duration::from_secs(1),
            ..SchedulerConfig::default()
        })
        .with_backoff_jitter(|w| w);
        let handle = sched.install_control_channel();
        for peer in peers {
            for kind in kinds {
                sched.add_initiator(Arc::new(ReplicationCoordinator::new(
                    Arc::clone(transport) as Arc<dyn Transport>,
                    *peer,
                    *kind,
                    SessionRole::Initiator,
                    Arc::clone(provider),
                    Arc::new(Empty),
                )));
            }
        }
        let (cancel, cancel_rx) = watch::channel(false);
        let task = tokio::spawn(sched.run_until_cancelled(cancel_rx));
        Self {
            transport: Arc::clone(transport),
            handle,
            cancel,
            task,
        }
    }

    async fn stop(self) {
        let _ = self.cancel.send(true);
        let _ = self.task.await;
    }
}

/// Let every task that is ready run, without moving the clock past the rounds
/// it starts (a delivered round waits `round_timeout` = 1 s for its reply).
async fn settle() {
    tokio::time::sleep(Duration::from_millis(10)).await;
}

fn backed_off(h: &SchedulerHandle) -> Vec<String> {
    h.no_route_backoff()
        .into_iter()
        .map(|e| e.peer_key_id)
        .collect()
}

/// Witness (a) — an unroutable peer, every plane, ten minutes of cadence and a
/// kick burst every 10 s through EVERY kick entry point (`RoundNow` for the
/// peer, `RoundNow` for all, the #636 `Propagate`, the #776/#778 `try_kick`).
/// The transport sees the first fan-out (at most one round per plane, all
/// before any of them learned there is no route) plus the probes the schedule
/// allows: with the jitter pinned to the full window, probes at 30, 90, 210 and
/// 450 s; the next is due at 930 s, past the run. Before #794: one round per
/// plane per tick (21 × 19) plus one per plane per kick burst.
#[tokio::test(start_paused = true)]
async fn unroutable_peer_costs_the_backoff_schedule_across_every_kind_and_kick_794() {
    let kinds = EnvelopeKind::ALL;
    let t = ScriptedTransport::new(&[("gone", Route::None)]);
    let rig = Rig::start(&t, &["gone"], &kinds);
    for _ in 0..60 {
        rig.handle.round_now(Some("gone")).await.expect("round_now");
        rig.handle.round_now(None).await.expect("round_now all");
        rig.handle
            .propagate("elsewhere", EnvelopeKind::Attestation)
            .await
            .expect("propagate");
        assert!(
            rig.handle.try_kick("gone", EnvelopeKind::Key),
            "kick queued"
        );
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    let sends = rig.transport.sends("gone");
    assert!(
        (1 + 4..=kinds.len() + 4).contains(&sends),
        "an unroutable peer costs the first fan-out plus one probe per backoff \
         window, across ALL {} planes: {sends} sends (≤ {} allowed)",
        kinds.len(),
        kinds.len() + 4
    );
    let snap = rig.handle.no_route_backoff();
    assert_eq!(snap.len(), 1, "the peer is backed off: {snap:?}");
    assert_eq!(
        snap[0].failed_probes, 4,
        "probes at 30/90/210/450 s: {snap:?}"
    );
    assert_eq!(snap[0].current_delay, Duration::from_mins(8), "{snap:?}");
    rig.stop().await;
}

/// A peer with no dial candidate: every plane's sweep stops at the backoff,
/// ticks and kicks alike, and a route arriving resumes every plane at once.
/// Before: `NoDialCandidate` was `Unreachable`, classed `Other`, so each plane
/// swept on every tick and every kick with nothing to send to.
#[tokio::test(start_paused = true)]
async fn a_peer_with_no_candidate_stops_sweeping_and_a_route_resumes_it_at_once_794() {
    let kinds = [
        EnvelopeKind::Key,
        EnvelopeKind::Attestation,
        EnvelopeKind::TransportDestination,
    ];
    let sweeps = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let provider: Arc<dyn StateProvider> = Arc::new(Sweeping {
        sweeps: Arc::clone(&sweeps),
    });
    let swept = || sweeps.load(std::sync::atomic::Ordering::SeqCst);
    let t = ScriptedTransport::new(&[("nowhere", Route::NoCandidate)]);
    let rig = Rig::start_with(&t, &["nowhere"], &kinds, &provider);
    let (_fwd_cancel, fwd_cancel_rx) = watch::channel(false);
    super::runtime::spawn_reachability_forwarder(
        &(Arc::clone(&t) as Arc<dyn Transport>),
        &rig.handle,
        &fwd_cancel_rx,
    );
    settle().await;
    assert_eq!(
        backed_off(&rig.handle),
        ["nowhere"],
        "no candidate is no route"
    );
    let entry = swept();
    assert!(entry <= kinds.len(), "the first fan-out: {entry}");

    // Ten minutes of cadence and a kick burst every 10 s.
    for _ in 0..60 {
        rig.handle
            .round_now(Some("nowhere"))
            .await
            .expect("round_now");
        rig.handle
            .propagate("elsewhere", EnvelopeKind::Attestation)
            .await
            .expect("propagate");
        assert!(rig.handle.try_kick("nowhere", EnvelopeKind::Key), "kicked");
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    let idle = swept();
    assert!(
        idle <= entry + 4,
        "the probes at 30/90/210/450 s are all that swept: {entry} then {idle} \
         (a plane on every tick alone is {})",
        kinds.len() * 20
    );

    // The route arrives, well away from a tick and from the next probe.
    let before = (swept(), t.sends("nowhere"));
    t.set("nowhere", Route::Delivered);
    t.reach
        .send(PeerReachable::new(
            "nowhere",
            ReachabilityEvidence::PathLearned,
        ))
        .expect("the forwarder is subscribed");
    settle().await;
    assert!(backed_off(&rig.handle).is_empty(), "the backoff cleared");
    assert_eq!(
        t.sends("nowhere") - before.1,
        kinds.len(),
        "every plane ran at once"
    );
    assert_eq!(swept() - before.0, kinds.len());
    rig.stop().await;
}

/// A ban is not route absence. A banned peer's rounds keep their own treatment:
/// no shared backoff, and the planes stay on their cadence.
#[tokio::test(start_paused = true)]
async fn a_banned_peer_does_not_enter_the_backoff_794() {
    let kinds = [EnvelopeKind::Key, EnvelopeKind::Attestation];
    let t = ScriptedTransport::new(&[("banned", Route::Banned)]);
    let rig = Rig::start(&t, &["banned"], &kinds);
    tokio::time::sleep(CADENCE * 3).await;
    settle().await;
    assert!(backed_off(&rig.handle).is_empty());
    assert!(
        t.sends("banned") >= kinds.len() * 3,
        "still on its cadence: {} sends",
        t.sends("banned")
    );
    rig.stop().await;
}

/// Witness (b) — a path learned, then a link identified, for a backed-off
/// peer (the transport's own reachability events, through the runtime's
/// forwarder): the backoff clears at once and every plane runs promptly,
/// seconds before the next cadence tick or the backoff's own expiry.
#[tokio::test(start_paused = true)]
async fn path_learned_and_link_up_reset_the_backoff_and_run_every_plane_now_794() {
    let kinds = [
        EnvelopeKind::Key,
        EnvelopeKind::Attestation,
        EnvelopeKind::IdentityOccurrence,
    ];
    let t = ScriptedTransport::new(&[("gone", Route::None)]);
    let rig = Rig::start(&t, &["gone"], &kinds);
    let (_fwd_cancel, fwd_cancel_rx) = watch::channel(false);
    super::runtime::spawn_reachability_forwarder(
        &(Arc::clone(&t) as Arc<dyn Transport>),
        &rig.handle,
        &fwd_cancel_rx,
    );
    settle().await;
    assert_eq!(
        backed_off(&rig.handle),
        ["gone"],
        "the first fan-out found no route"
    );

    for evidence in [
        ReachabilityEvidence::PathLearned,
        ReachabilityEvidence::LinkUp,
    ] {
        // Well inside the 30 s window and away from a cadence tick.
        tokio::time::sleep(Duration::from_secs(5)).await;
        t.set("gone", Route::Delivered);
        let before = t.sends("gone");
        t.reach
            .send(PeerReachable::new("gone", evidence))
            .expect("the forwarder is subscribed");
        settle().await;
        assert!(
            backed_off(&rig.handle).is_empty(),
            "{evidence:?} clears the backoff"
        );
        assert_eq!(
            t.sends("gone") - before,
            kinds.len(),
            "{evidence:?}: every plane ran at once, not at the next tick"
        );
        // Lose the route again: the next tick (a cadence after the kicked
        // rounds finished, i.e. after their 1 s reply timeout) backs the peer
        // off afresh.
        t.set("gone", Route::None);
        tokio::time::sleep(CADENCE + Duration::from_secs(2)).await;
        settle().await;
        assert_eq!(backed_off(&rig.handle), ["gone"], "the route is gone again");
    }
    rig.stop().await;
}

/// Witness (c) — an attributed inbound CRPL frame from a backed-off peer
/// clears it at the registry's door, BEFORE the frame is routed, so the #776 /
/// #778 release kick its admission fires toward that peer is not swallowed.
#[tokio::test(start_paused = true)]
async fn inbound_frame_resets_and_the_release_kick_is_not_swallowed_794() {
    let kinds = [EnvelopeKind::Key, EnvelopeKind::IdentityOccurrence];
    let t = ScriptedTransport::new(&[("gone", Route::None)]);
    let rig = Rig::start(&t, &["gone"], &kinds);
    let registry = ReplicationRegistry::new();
    registry.install_no_route_backoff(&rig.handle);
    settle().await;
    assert_eq!(backed_off(&rig.handle), ["gone"]);

    // The device is back and its frame arrives (the peer's own round).
    tokio::time::sleep(Duration::from_secs(5)).await;
    t.set("gone", Route::Delivered);
    let frame = super::wire_frame::wrap(&ReplicationMessage::Summary(SummaryMessage {
        status: None,
        kind: EnvelopeKind::IdentityOccurrence,
        refs: vec![],
    }));
    let _ = registry.route_inbound_bytes("gone", &frame).await;
    assert!(
        backed_off(&rig.handle).is_empty(),
        "a frame from the peer clears its backoff as it is routed"
    );
    // Let the reset's rounds finish (they time out unanswered).
    tokio::time::sleep(Duration::from_secs(2)).await;
    let before = t.sends("gone");
    // The release kick toward the peer that sent the frame.
    assert!(rig
        .handle
        .try_kick("gone", EnvelopeKind::IdentityOccurrence));
    settle().await;
    assert_eq!(
        t.sends("gone") - before,
        1,
        "the release kick ran its round now, not at the next tick"
    );
    rig.stop().await;
}

/// Witness (d) — while one peer is backed off, a reachable peer's ticks and
/// kicks run exactly as before: the state is per peer.
#[tokio::test(start_paused = true)]
async fn a_reachable_peer_is_unaffected_by_another_peers_backoff_794() {
    let kinds = [
        EnvelopeKind::Key,
        EnvelopeKind::Attestation,
        EnvelopeKind::IdentityOccurrence,
    ];
    let t = ScriptedTransport::new(&[("gone", Route::None), ("here", Route::Delivered)]);
    let rig = Rig::start(&t, &["gone", "here"], &kinds);
    settle().await;
    assert_eq!(backed_off(&rig.handle), ["gone"]);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let gone_after_entry = t.sends("gone");

    let here = t.sends("here");
    rig.handle.round_now(None).await.expect("round_now");
    settle().await;
    assert_eq!(
        t.sends("here") - here,
        kinds.len(),
        "RoundNow(all) runs every plane to `here`"
    );

    tokio::time::sleep(Duration::from_secs(2)).await;
    let here = t.sends("here");
    rig.handle
        .propagate("elsewhere", EnvelopeKind::Key)
        .await
        .expect("propagate");
    settle().await;
    assert_eq!(
        t.sends("here") - here,
        1,
        "Propagate runs the Key plane to `here`"
    );

    tokio::time::sleep(Duration::from_secs(2)).await;
    let here = t.sends("here");
    assert!(rig.handle.try_kick("here", EnvelopeKind::Attestation));
    settle().await;
    assert_eq!(
        t.sends("here") - here,
        1,
        "Kick runs its one plane to `here`"
    );

    assert_eq!(
        t.sends("gone"),
        gone_after_entry,
        "none of those kicks reached the backed-off peer"
    );

    // Ticks: every plane to `here` keeps its cadence.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let here = t.sends("here");
    tokio::time::sleep(CADENCE).await;
    assert_eq!(
        t.sends("here") - here,
        kinds.len(),
        "one tick per plane to `here`"
    );

    assert_eq!(
        t.sends("gone"),
        gone_after_entry + 1,
        "none of those kicks or ticks reached the backed-off peer; its only round \
         is the one probe its schedule allows (at 30 s)"
    );
    rig.stop().await;
}

/// Witness (e) — a round error that is NOT route absence (here a transport
/// timeout) keeps today's behaviour: a round per plane per tick, every kick
/// honoured, nothing backed off.
#[tokio::test(start_paused = true)]
async fn a_non_no_route_error_does_not_back_off_794() {
    let kinds = [EnvelopeKind::Key, EnvelopeKind::Attestation];
    let t = ScriptedTransport::new(&[("flaky", Route::Error)]);
    let rig = Rig::start(&t, &["flaky"], &kinds);
    // A failed send re-dials in 15 to 45 s (CC 5.4.6, `draw_redial`), so every
    // plane keeps its rounds, at least one per 45 s, with no window growing.
    tokio::time::sleep(Duration::from_secs(155)).await;
    assert!(
        t.sends("flaky") >= 4 * kinds.len(),
        "every plane keeps dialling: {}",
        t.sends("flaky")
    );
    assert!(
        backed_off(&rig.handle).is_empty(),
        "only route absence backs off"
    );
    rig.stop().await;
}

/// The cap reaches the running scheduler through the builder and the handle,
/// never through `SchedulerConfig` (which gained no field).
#[test]
fn the_cap_is_set_by_builder_and_handle_not_by_config_794() {
    let mut sched = ReplicationScheduler::new(SchedulerConfig::default());
    let handle = sched.install_control_channel();
    assert_eq!(
        handle.no_route_backoff_cap(),
        super::DEFAULT_NO_ROUTE_BACKOFF_CAP
    );
    let mut sched = sched.with_no_route_backoff_cap(Duration::from_mins(20));
    let handle = sched.install_control_channel();
    assert_eq!(handle.no_route_backoff_cap(), Duration::from_mins(20));
    handle.set_no_route_backoff_cap(Duration::from_mins(25));
    assert_eq!(handle.no_route_backoff_cap(), Duration::from_mins(25));
}

/// A removed peer's backoff goes with its last coordinator.
#[tokio::test(start_paused = true)]
async fn removing_the_last_plane_forgets_the_backoff_794() {
    let kinds = [EnvelopeKind::Key, EnvelopeKind::Attestation];
    let t = ScriptedTransport::new(&[("gone", Route::None)]);
    let rig = Rig::start(&t, &["gone"], &kinds);
    settle().await;
    assert_eq!(backed_off(&rig.handle), ["gone"]);
    let mut left: HashSet<EnvelopeKind> = kinds.into_iter().collect();
    for kind in kinds {
        rig.handle
            .remove_initiator("gone", kind)
            .await
            .expect("remove");
        left.remove(&kind);
        settle().await;
        assert_eq!(
            backed_off(&rig.handle).is_empty(),
            left.is_empty(),
            "kept while a plane remains, forgotten with the last"
        );
    }
    rig.stop().await;
}
