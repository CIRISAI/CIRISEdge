//! **Suspend and resume in-process** — the mobile-background lifecycle
//! (step 1: a transport that can be put to sleep and woken without rebuilding
//! the `Edge` or the replication runtime).
//!
//! # Why
//!
//! Phones run edge. When the app is backgrounded the operating system forbids
//! relying on persistent background sockets:
//!
//! - Android Doze and App Standby defer network access and jobs for idle apps
//!   (<https://developer.android.com/training/monitoring-device-state/doze-standby>);
//! - Android 12+ refuses to start a foreground service from the background
//!   (<https://developer.android.com/develop/background-work/services/fgs/restrictions-bg-start>),
//!   so "keep a service up to hold the socket" is not available either;
//! - iOS throttles background updates and suspends the process
//!   (<https://developer.apple.com/documentation/usernotifications/pushing-background-updates-to-your-app>).
//!
//! So the host (CIRISServer's native module) calls `enter_background(deadline)`
//! → [`Edge::suspend`](crate::Edge::suspend) and `enter_foreground()` →
//! [`Edge::resume`](crate::Edge::resume). While suspended, edge holds no
//! socket, link or listener and runs no edge task; resume brings the node back
//! to replicating.
//!
//! # Design (interim, edge-only — until leviculum#90)
//!
//! Leviculum's `stop()`/`start()` take `&mut self` and edge holds its node as a
//! shared `Arc`, so the node itself cannot be stopped from edge today.
//! leviculum#90 makes them callable through `&self` (and stops the 1 Hz traffic
//! counter thread with the event loop). Until it lands, suspend is built from
//! what leviculum lets a shared handle do:
//!
//! 1. **Refuse sends.** Every send through the [`Transport`](super::Transport)
//!    surface, and every dial task, fails with
//!    [`TransportError::Suspended`](super::TransportError::Suspended); a send
//!    already in flight is cancelled with the same error (its future is
//!    dropped — sends are cancel-safe, CIRISEdge#853). The replication
//!    scheduler treats `Suspended` as "skip quietly, no backoff".
//! 2. **Close every link** (pooled, inbound, direct) at the node.
//! 3. **Park the listener.** The listen loop drains the events the closes
//!    raised, stops its announce timer, link reaper and attribution tick, ends
//!    its announce cold-start worker, and parks on the resume signal — a parked
//!    future with no timer, holding the node's event receiver so resume needs
//!    no second `listen`.
//! 4. **Detach the interfaces.** Every TCP client edge attached is a
//!    runtime-attached leviculum client whose handle, when dropped, ends its
//!    reconnect loop at whatever await it is parked on and closes its socket.
//!    (A config-loaded client cannot be detached cleanly: removing it through
//!    `remove_interface` drops its channels but leaves its reconnect loop
//!    running, and against a live peer it reconnects in a tight loop. That is
//!    why edge attaches TCP clients at runtime.) Connections a TCP *server*
//!    accepted are removed; the listening socket itself cannot be closed
//!    without stopping the node, so a node with a server reports
//!    `listener_open: true` and is never reported quiescent.
//!
//! What stays until leviculum#90: the node's own event loop (idle, no
//! interfaces) and its traffic-counter thread. [`SuspendReport::node_tasks`]
//! counts them, honestly. The swap to `node.stop()`/`node.start()` is one
//! internal function on the transport (`quiesce_node` / `wake_node`).
//!
//! Edge's own background loops (the durable outbound dispatcher, its sweeps,
//! the blackhole pruner) are stopped by [`Edge::suspend`](crate::Edge::suspend)
//! and respawned by resume, through [`PausableTasks`].

use std::future::Future;
#[cfg(feature = "_reticulum-module")]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "_reticulum-module")]
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "_reticulum-module")]
use tokio::sync::watch;

#[cfg(feature = "_reticulum-module")]
use super::TransportError;

/// What [`suspend`](crate::Edge::suspend) left behind, measured when it
/// returned (quiescent, or at its deadline).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuspendReport {
    /// The node was already suspended; nothing was done but the measurement.
    pub already_suspended: bool,
    /// No socket (link, interface, listener), no edge task and no send in
    /// flight. `false` means the deadline was hit or something cannot be
    /// closed in-process (a TCP server listener, a non-TCP interface).
    pub quiescent: bool,
    /// Wall time the call took.
    pub elapsed: Duration,
    /// Links still open at the node.
    pub links_open: usize,
    /// Interfaces still attached at the node (each one a socket or a device).
    pub interfaces_open: usize,
    /// A TCP server listening socket is still bound.
    pub listener_open: bool,
    /// `edge_tasks + node_tasks`.
    pub tasks_running: usize,
    /// Sends still in flight.
    pub sends_in_flight: usize,
    /// Edge tasks still running: active listen loops, announce workers, dial
    /// tasks and edge's background loops. A parked listener is not counted —
    /// it is a future waiting on the resume signal, with no timer.
    pub edge_tasks: usize,
    /// Leviculum's own tasks still alive: its event loop and its traffic
    /// counter thread (2 while the node runs). Idle with no interface; they
    /// go away with leviculum#90.
    pub node_tasks: usize,
}

impl SuspendReport {
    /// Fold another component's report into this one (an `Edge` with several
    /// transports, plus its own background loops).
    #[must_use]
    pub fn merge(mut self, other: &Self) -> Self {
        self.already_suspended &= other.already_suspended;
        self.quiescent &= other.quiescent;
        self.elapsed = self.elapsed.max(other.elapsed);
        self.links_open += other.links_open;
        self.interfaces_open += other.interfaces_open;
        self.listener_open |= other.listener_open;
        self.tasks_running += other.tasks_running;
        self.sends_in_flight += other.sends_in_flight;
        self.edge_tasks += other.edge_tasks;
        self.node_tasks += other.node_tasks;
        self
    }
}

#[cfg(feature = "_reticulum-module")]
/// One transport's suspend state: the send gate, the park signal its
/// listeners wait on, and the counters suspend reads to decide quiescence.
pub(crate) struct Lifecycle {
    /// `true` while suspended — the send gate, read on every send.
    suspended: AtomicBool,
    /// Mirrors `suspended` as a signal: in-flight sends and dial tasks race
    /// against it and are cancelled when it turns `true`.
    suspended_tx: watch::Sender<bool>,
    /// `true` asks every listen loop to park; `false` wakes them.
    park_tx: watch::Sender<bool>,
    /// Serializes suspend and resume.
    op: tokio::sync::Mutex<()>,
    sends_in_flight: AtomicUsize,
    edge_tasks: AtomicUsize,
    listeners: AtomicUsize,
    listeners_parked: AtomicUsize,
}

#[cfg(feature = "_reticulum-module")]
impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            suspended: AtomicBool::new(false),
            suspended_tx: watch::Sender::new(false),
            park_tx: watch::Sender::new(false),
            op: tokio::sync::Mutex::new(()),
            sends_in_flight: AtomicUsize::new(0),
            edge_tasks: AtomicUsize::new(0),
            listeners: AtomicUsize::new(0),
            listeners_parked: AtomicUsize::new(0),
        }
    }
}

#[cfg(feature = "_reticulum-module")]
/// Decrements its counter on drop — every exit, cancellation included.
pub(crate) struct CountGuard<'a>(&'a AtomicUsize);

#[cfg(feature = "_reticulum-module")]
impl Drop for CountGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(feature = "_reticulum-module")]
/// [`CountGuard`] for a task that owns an `Arc<Lifecycle>` (a spawned dial).
pub(crate) struct OwnedTaskGuard(Arc<Lifecycle>);

#[cfg(feature = "_reticulum-module")]
impl Drop for OwnedTaskGuard {
    fn drop(&mut self) {
        self.0.edge_tasks.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(feature = "_reticulum-module")]
impl Lifecycle {
    pub(crate) fn is_suspended(&self) -> bool {
        self.suspended.load(Ordering::Acquire)
    }

    pub(crate) async fn lock_op(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.op.lock().await
    }

    /// Close the send gate and cancel every in-flight send. Returns whether
    /// it was already closed.
    pub(crate) fn close_gate(&self) -> bool {
        let was = self.suspended.swap(true, Ordering::AcqRel);
        self.suspended_tx.send_replace(true);
        was
    }

    /// Reopen the send gate.
    pub(crate) fn open_gate(&self) {
        self.suspended.store(false, Ordering::Release);
        self.suspended_tx.send_replace(false);
    }

    /// Ask the listen loops to park (`true`) or wake (`false`).
    pub(crate) fn request_park(&self, park: bool) {
        self.park_tx.send_replace(park);
    }

    pub(crate) fn park_requested(&self) -> bool {
        *self.park_tx.borrow()
    }

    /// Resolves once a park has been requested.
    pub(crate) async fn park_signal(&self) {
        let mut rx = self.park_tx.subscribe();
        let _ = rx.wait_for(|park| *park).await;
    }

    /// Park a listen loop until resume. Counted while parked.
    pub(crate) async fn park_until_woken(&self) {
        self.listeners_parked.fetch_add(1, Ordering::AcqRel);
        let _parked = CountGuard(&self.listeners_parked);
        let mut rx = self.park_tx.subscribe();
        let _ = rx.wait_for(|park| !*park).await;
    }

    /// Resolves once the gate closes.
    async fn suspended_signal(&self) {
        let mut rx = self.suspended_tx.subscribe();
        let _ = rx.wait_for(|s| *s).await;
    }

    /// Run a send through the gate: refused while suspended, cancelled if a
    /// suspend lands while it runs, counted in flight either way.
    pub(crate) async fn guard<T, F>(&self, send: F) -> Result<T, TransportError>
    where
        F: Future<Output = Result<T, TransportError>>,
    {
        if self.is_suspended() {
            return Err(TransportError::Suspended);
        }
        self.sends_in_flight.fetch_add(1, Ordering::AcqRel);
        let _in_flight = CountGuard(&self.sends_in_flight);
        tokio::select! {
            biased;
            () = self.suspended_signal() => Err(TransportError::Suspended),
            r = send => r,
        }
    }

    /// [`Self::guard`] for a spawned task holding the lifecycle by `Arc`,
    /// counted as an edge task rather than a send.
    pub(crate) async fn guard_task<T, F>(self: Arc<Self>, task: F) -> Result<T, TransportError>
    where
        F: Future<Output = Result<T, TransportError>>,
    {
        if self.is_suspended() {
            return Err(TransportError::Suspended);
        }
        self.edge_tasks.fetch_add(1, Ordering::AcqRel);
        let _task = OwnedTaskGuard(Arc::clone(&self));
        tokio::select! {
            biased;
            () = self.suspended_signal() => Err(TransportError::Suspended),
            r = task => r,
        }
    }

    /// Count an edge task (an active listen loop, an announce worker) for
    /// as long as the guard lives.
    pub(crate) fn task(&self) -> CountGuard<'_> {
        self.edge_tasks.fetch_add(1, Ordering::AcqRel);
        CountGuard(&self.edge_tasks)
    }

    /// Count a listener (active or parked) for its whole life.
    pub(crate) fn listener(&self) -> CountGuard<'_> {
        self.listeners.fetch_add(1, Ordering::AcqRel);
        CountGuard(&self.listeners)
    }

    pub(crate) fn sends_in_flight(&self) -> usize {
        self.sends_in_flight.load(Ordering::Acquire)
    }

    pub(crate) fn edge_tasks(&self) -> usize {
        self.edge_tasks.load(Ordering::Acquire)
    }

    /// Listeners not (yet) parked.
    pub(crate) fn listeners_unparked(&self) -> usize {
        self.listeners
            .load(Ordering::Acquire)
            .saturating_sub(self.listeners_parked.load(Ordering::Acquire))
    }
}

/// Poll `done` every 10 ms until it holds or `deadline` passes. Runs only
/// inside a suspend call, so its timer ends with the call.
pub(crate) async fn settle<F, Fut>(deadline: tokio::time::Instant, mut done: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    loop {
        if done().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

type SpawnFn = Box<dyn Fn() -> tokio::task::JoinHandle<()> + Send + Sync>;

struct Pausable {
    spawn: SpawnFn,
    running: Option<tokio::task::AbortHandle>,
}

/// Background loops an [`Edge`](crate::Edge) can stop on suspend and spawn
/// again on resume: each is registered with the closure that spawns it.
#[derive(Default)]
pub(crate) struct PausableTasks {
    tasks: std::sync::Mutex<Vec<Pausable>>,
    paused: AtomicBool,
}

impl PausableTasks {
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Pausable>> {
        self.tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Spawn `spawn()` now and keep the closure to respawn it after a
    /// pause. Returns the spawned task's handle.
    pub(crate) fn register(
        &self,
        spawn: impl Fn() -> tokio::task::JoinHandle<()> + Send + Sync + 'static,
    ) -> tokio::task::JoinHandle<()> {
        let handle = spawn();
        let mut tasks = self.lock();
        if self.paused.load(Ordering::Acquire) {
            // Registered while paused: it must not run until resume.
            handle.abort();
            tasks.push(Pausable {
                spawn: Box::new(spawn),
                running: None,
            });
        } else {
            tasks.push(Pausable {
                spawn: Box::new(spawn),
                running: Some(handle.abort_handle()),
            });
        }
        handle
    }

    /// Abort every running loop and wait (to `deadline`) for each to end.
    /// Returns how many are still running.
    pub(crate) async fn pause(&self, deadline: tokio::time::Instant) -> usize {
        self.paused.store(true, Ordering::Release);
        let handles: Vec<tokio::task::AbortHandle> = self
            .lock()
            .iter()
            .filter_map(|p| p.running.clone())
            .collect();
        for h in &handles {
            h.abort();
        }
        settle(deadline, || {
            let done = handles.iter().all(tokio::task::AbortHandle::is_finished);
            async move { done }
        })
        .await;
        self.running()
    }

    /// Respawn every loop the pause stopped.
    pub(crate) fn resume(&self) {
        let mut tasks = self.lock();
        self.paused.store(false, Ordering::Release);
        for p in tasks.iter_mut() {
            let stopped = p
                .running
                .as_ref()
                .map_or(true, tokio::task::AbortHandle::is_finished);
            if stopped {
                p.running = Some((p.spawn)().abort_handle());
            }
        }
    }

    /// Loops running now.
    pub(crate) fn running(&self) -> usize {
        self.lock()
            .iter()
            .filter(|p| p.running.as_ref().is_some_and(|h| !h.is_finished()))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    #[cfg(feature = "_reticulum-module")]
    #[tokio::test]
    async fn a_guarded_send_is_refused_and_an_in_flight_one_cancelled() {
        let lc = Arc::new(Lifecycle::default());
        let held = {
            let lc = Arc::clone(&lc);
            tokio::spawn(async move {
                lc.guard(async {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    Ok::<_, TransportError>(())
                })
                .await
            })
        };
        let up = settle(tokio::time::Instant::now() + Duration::from_secs(5), || {
            let n = lc.sends_in_flight();
            async move { n == 1 }
        })
        .await;
        assert!(up, "the send is in flight");
        assert!(!lc.close_gate(), "the gate was open");
        let r = tokio::time::timeout(Duration::from_secs(5), held)
            .await
            .expect("the in-flight send is cancelled, not left to run")
            .expect("join");
        assert!(matches!(r, Err(TransportError::Suspended)), "{r:?}");
        assert_eq!(lc.sends_in_flight(), 0);
        let r = lc.guard(async { Ok::<_, TransportError>(()) }).await;
        assert!(matches!(r, Err(TransportError::Suspended)), "{r:?}");
        assert!(lc.close_gate(), "closing twice reports it was closed");
        lc.open_gate();
        assert!(lc
            .guard(async { Ok::<_, TransportError>(()) })
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn paused_tasks_stop_and_come_back() {
        let tasks = PausableTasks::default();
        let starts = Arc::new(AtomicUsize::new(0));
        let s = Arc::clone(&starts);
        let _first = tasks.register(move || {
            s.fetch_add(1, Ordering::AcqRel);
            tokio::spawn(async {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            })
        });
        assert_eq!(tasks.running(), 1);
        let left = tasks
            .pause(tokio::time::Instant::now() + Duration::from_secs(5))
            .await;
        assert_eq!(left, 0, "pause stops the loop");
        tasks.resume();
        assert_eq!(tasks.running(), 1, "resume respawns it");
        assert_eq!(starts.load(Ordering::Acquire), 2);
        tasks.resume();
        assert_eq!(starts.load(Ordering::Acquire), 2, "resume is idempotent");
    }
}
