//! **Per-peer backoff for peers the transport has no route to** (CIRISEdge#794).
//!
//! A round whose send fails with [`TransportError::NoRouteToPeer`] (the
//! transport held no path to the peer and nothing answered the broadcast link
//! request) puts that PEER — every coordinator toward it, on every plane — into
//! one shared backoff. While it holds, the peer's coordinators skip their
//! cadence ticks AND their kicks (`RoundNow`, `Propagate`, `Kick`): before this,
//! an offline device cost every plane a round on every tick and every kick,
//! ~2/s on the canonical.
//!
//! # Schedule
//!
//! Exponential with full jitter: the window starts at
//! [`NO_ROUTE_BACKOFF_INITIAL`] (30 s), doubles after every probe that still
//! finds no route, and is capped at
//! [`SchedulerConfig::no_route_backoff_cap`](super::scheduler::SchedulerConfig::no_route_backoff_cap).
//! Each delay is drawn uniformly from `[0, window]`, so a fleet of offline peers
//! does not retry in lockstep. When the delay expires, ONE coordinator toward
//! the peer claims the probe; the rest keep skipping until it resolves.
//!
//! # Leaving
//!
//! - **Evidence** ([`ReachabilityEvidence`]): a path learned or a link
//!   identified for the peer (the transport's
//!   [`subscribe_reachability`](crate::transport::Transport::subscribe_reachability)),
//!   or an attributed CRPL frame from it (the registry's inbound door). The
//!   backoff clears and every coordinator toward the peer is kicked at once.
//! - **Expiry**: the probe ended in anything but no-route. The other planes
//!   are kicked; the probing one just ran.
//!
//! Only route absence backs off. A timeout, a refusal or a protocol error
//! keeps the pre-#794 behaviour (a fresh round on the next tick). The peer is
//! never dropped from the send set: it is a member and catches up on return.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;

use super::protocol::EnvelopeKind;
use crate::transport::{ReachabilityEvidence, TransportError};

/// CIRISEdge#794 — the first backoff window after a peer is found unroutable.
pub const NO_ROUTE_BACKOFF_INITIAL: Duration = Duration::from_secs(30);

/// CIRISEdge#794 — why a peer left the no-route backoff.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackoffExit {
    /// The transport learned a path to the peer.
    PathLearned,
    /// A link to the peer came up and was identified.
    LinkUp,
    /// An attributed frame from the peer arrived.
    InboundFrame,
    /// The delay expired and the probe round found a route.
    Expiry,
}

impl BackoffExit {
    /// A stable token for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PathLearned => "path_learned",
            Self::LinkUp => "link_up",
            Self::InboundFrame => "inbound_frame",
            Self::Expiry => "expiry",
        }
    }
}

impl From<ReachabilityEvidence> for BackoffExit {
    fn from(e: ReachabilityEvidence) -> Self {
        match e {
            ReachabilityEvidence::PathLearned => Self::PathLearned,
            ReachabilityEvidence::LinkUp => Self::LinkUp,
            ReachabilityEvidence::InboundFrame => Self::InboundFrame,
        }
    }
}

/// CIRISEdge#794 — one backed-off peer, as the replication snapshot reports it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoRouteBackoffEntry {
    /// The peer's federation key id.
    pub peer_key_id: String,
    /// The current window: the delay before the next probe was drawn from
    /// `[0, current_delay]`.
    pub current_delay: Duration,
    /// How long until the next probe may run (zero once it is due).
    pub next_attempt_in: Duration,
    /// Wall-clock projection of the next attempt, unix milliseconds.
    pub next_attempt_unix_ms: i64,
    /// Probes that found no route since the peer entered backoff.
    pub failed_probes: u32,
    /// How long the peer has been backed off.
    pub backed_off_for: Duration,
    /// Whether a probe round toward the peer is in flight now.
    pub probing: bool,
}

/// How one round toward a peer ended, as far as the backoff cares.
#[derive(Debug)]
pub(crate) enum RoundClass {
    /// The transport has no route to the peer; carries the error for the log.
    NoRoute(String),
    /// Anything else: completed, refused, timed out, or another error.
    Other,
}

impl RoundClass {
    /// Typed, never by message: only `NoRouteToPeer` with `has_path: false`.
    pub(crate) fn of_transport_error(e: &TransportError) -> Option<Self> {
        match e {
            TransportError::NoRouteToPeer {
                has_path: false, ..
            } => Some(Self::NoRoute(e.to_string())),
            _ => None,
        }
    }
}

struct PeerState {
    window: Duration,
    next_attempt: Instant,
    since: Instant,
    failed_probes: u32,
    probing: bool,
}

/// A peer's backoff cleared: kick its coordinators, except `except` (the
/// plane whose probe just ran).
#[derive(Debug)]
pub(crate) struct Wake {
    pub(crate) peer_key_id: String,
    pub(crate) except: Option<EnvelopeKind>,
}

/// The shared no-route state of one scheduler: every coordinator task, the
/// scheduler's handle and the registry's inbound door hold the same `Arc`.
pub(crate) struct NoRouteBackoff {
    cap: Duration,
    peers: Mutex<HashMap<String, PeerState>>,
    /// Mirrors `peers.len()` so the per-frame evidence path takes no lock
    /// while nothing is backed off (the steady state).
    len: AtomicUsize,
    wake_tx: mpsc::UnboundedSender<Wake>,
    wake_rx: Mutex<Option<mpsc::UnboundedReceiver<Wake>>>,
    /// Draws a delay from `[0, window]`. Full jitter in production; tests
    /// pin it to make the schedule countable.
    jitter: fn(Duration) -> Duration,
}

impl std::fmt::Debug for NoRouteBackoff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoRouteBackoff")
            .field("cap", &self.cap)
            .field("backed_off", &self.len.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

/// Full jitter: uniform over `[0, window]`, millisecond resolution.
pub(crate) fn full_jitter(window: Duration) -> Duration {
    use rand::Rng as _;
    let ms = u64::try_from(window.as_millis()).unwrap_or(u64::MAX);
    Duration::from_millis(rand::thread_rng().gen_range(0..=ms))
}

/// The window after one more probe found no route: doubled, capped.
pub(crate) fn next_window(window: Duration, cap: Duration) -> Duration {
    window.saturating_mul(2).min(cap)
}

/// Whether a coordinator may run a round now.
pub(crate) enum Admission<'a> {
    /// The peer is backed off and its delay has not expired (or another
    /// plane holds the probe): skip, take no gate permit.
    Skip,
    /// Run; finish the ticket with the round's [`RoundClass`].
    Run(RoundTicket<'a>),
}

/// A round the backoff admitted. A probe's claim is released on drop if the
/// round never reports (cancelled mid-round), so the peer is never left with
/// a probe nobody runs.
pub(crate) struct RoundTicket<'a> {
    backoff: &'a NoRouteBackoff,
    peer: &'a str,
    kind: EnvelopeKind,
    probe: bool,
    finished: bool,
}

impl RoundTicket<'_> {
    /// An ordinary (non-probe) round whose peer entered backoff while it
    /// waited for a gate permit: it should not run.
    pub(crate) fn overtaken(&self) -> bool {
        !self.probe && self.backoff.is_backed_off(self.peer)
    }

    /// Record how the round ended.
    pub(crate) fn finish(mut self, class: RoundClass) {
        self.finished = true;
        self.backoff.record(self.peer, self.kind, self.probe, class);
    }
}

impl Drop for RoundTicket<'_> {
    fn drop(&mut self) {
        if self.probe && !self.finished {
            if let Some(s) = self.backoff.lock().get_mut(self.peer) {
                s.probing = false;
            }
        }
    }
}

impl NoRouteBackoff {
    pub(crate) fn new(cap: Duration) -> Self {
        Self::with_jitter(cap, full_jitter)
    }

    pub(crate) fn with_jitter(cap: Duration, jitter: fn(Duration) -> Duration) -> Self {
        let (wake_tx, wake_rx) = mpsc::unbounded_channel();
        Self {
            cap: cap.max(Duration::from_secs(1)),
            peers: Mutex::new(HashMap::new()),
            len: AtomicUsize::new(0),
            wake_tx,
            wake_rx: Mutex::new(Some(wake_rx)),
            jitter,
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, PeerState>> {
        self.peers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The scheduler's run loop takes the wake receiver once.
    pub(crate) fn take_wakes(&self) -> Option<mpsc::UnboundedReceiver<Wake>> {
        self.wake_rx
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    pub(crate) fn is_backed_off(&self, peer: &str) -> bool {
        self.len.load(Ordering::Acquire) != 0 && self.lock().contains_key(peer)
    }

    /// May a coordinator toward `peer` on `kind` run a round now?
    pub(crate) fn admit<'a>(&'a self, peer: &'a str, kind: EnvelopeKind) -> Admission<'a> {
        let probe = if self.len.load(Ordering::Acquire) == 0 {
            false
        } else {
            match self.lock().get_mut(peer) {
                None => false,
                Some(s) if s.probing || Instant::now() < s.next_attempt => {
                    return Admission::Skip;
                }
                Some(s) => {
                    s.probing = true;
                    true
                }
            }
        };
        Admission::Run(RoundTicket {
            backoff: self,
            peer,
            kind,
            probe,
            finished: false,
        })
    }

    fn record(&self, peer: &str, kind: EnvelopeKind, probe: bool, class: RoundClass) {
        let mut peers = self.lock();
        let backed_off = peers.contains_key(peer);
        match class {
            RoundClass::NoRoute(error) if !backed_off => {
                let window = NO_ROUTE_BACKOFF_INITIAL.min(self.cap);
                let delay = (self.jitter)(window);
                let now = Instant::now();
                peers.insert(
                    peer.to_owned(),
                    PeerState {
                        window,
                        next_attempt: now + delay,
                        since: now,
                        failed_probes: 0,
                        probing: false,
                    },
                );
                self.len.store(peers.len(), Ordering::Release);
                tracing::info!(
                    peer = %peer,
                    retry_in_secs = delay.as_secs_f64(),
                    window_secs = window.as_secs_f64(),
                    cap_secs = self.cap.as_secs_f64(),
                    error = %error,
                    "peer has NO ROUTE — every plane toward it backs off (ticks and kicks \
                     alike) until a path, a link or a frame from it shows up, or the delay \
                     expires; it stays in the send set (CIRISEdge#794)"
                );
            }
            RoundClass::NoRoute(_) if probe => {
                if let Some(s) = peers.get_mut(peer) {
                    s.window = next_window(s.window, self.cap);
                    let delay = (self.jitter)(s.window);
                    s.next_attempt = Instant::now() + delay;
                    s.failed_probes = s.failed_probes.saturating_add(1);
                    s.probing = false;
                    tracing::debug!(
                        peer = %peer,
                        retry_in_secs = delay.as_secs_f64(),
                        window_secs = s.window.as_secs_f64(),
                        failed_probes = s.failed_probes,
                        "no-route probe: still no route (CIRISEdge#794)"
                    );
                }
            }
            RoundClass::Other if probe && backed_off => {
                drop(peers);
                self.clear(peer, BackoffExit::Expiry, Some(kind));
            }
            // A round already in flight when another plane put the peer in
            // backoff (or one that cleared meanwhile): the state it finds stands.
            RoundClass::NoRoute(_) | RoundClass::Other => {}
        }
    }

    /// Evidence that `peer` is reachable. A no-op (and lock-free) unless the
    /// peer is backed off.
    pub(crate) fn note_reachable(&self, peer: &str, evidence: ReachabilityEvidence) {
        if self.len.load(Ordering::Acquire) == 0 {
            return;
        }
        self.clear(peer, evidence.into(), None);
    }

    fn clear(&self, peer: &str, reason: BackoffExit, except: Option<EnvelopeKind>) {
        let removed = {
            let mut peers = self.lock();
            let removed = peers.remove(peer);
            self.len.store(peers.len(), Ordering::Release);
            removed
        };
        let Some(state) = removed else { return };
        tracing::info!(
            peer = %peer,
            reason = reason.as_str(),
            backed_off_secs = state.since.elapsed().as_secs_f64(),
            failed_probes = state.failed_probes,
            "peer left no-route backoff — its planes run again now (CIRISEdge#794)"
        );
        let _ = self.wake_tx.send(Wake {
            peer_key_id: peer.to_owned(),
            except,
        });
    }

    /// The peer is no longer in the send set at all: drop its state silently.
    pub(crate) fn forget(&self, peer: &str) {
        let mut peers = self.lock();
        peers.remove(peer);
        self.len.store(peers.len(), Ordering::Release);
    }

    /// Every backed-off peer, sorted by key id.
    pub(crate) fn snapshot(&self) -> Vec<NoRouteBackoffEntry> {
        if self.len.load(Ordering::Acquire) == 0 {
            return Vec::new();
        }
        let now = Instant::now();
        let wall_ms = chrono::Utc::now().timestamp_millis();
        let mut out: Vec<NoRouteBackoffEntry> = self
            .lock()
            .iter()
            .map(|(peer, s)| {
                let next_attempt_in = s.next_attempt.saturating_duration_since(now);
                NoRouteBackoffEntry {
                    peer_key_id: peer.clone(),
                    current_delay: s.window,
                    next_attempt_in,
                    next_attempt_unix_ms: wall_ms
                        .saturating_add(i64::try_from(next_attempt_in.as_millis()).unwrap_or(0)),
                    failed_probes: s.failed_probes,
                    backed_off_for: now.saturating_duration_since(s.since),
                    probing: s.probing,
                }
            })
            .collect();
        out.sort_by(|a, b| a.peer_key_id.cmp(&b.peer_key_id));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CIRISEdge#794 witness (f) — every full-jitter draw lies in
    /// `[0, window]`, the window doubles from 30 s and stops at the cap, and
    /// the draws actually spread (not pinned to either end).
    #[test]
    fn full_jitter_draws_within_window_and_doubling_is_capped_794() {
        let cap = Duration::from_secs(15 * 60);
        let mut window = NO_ROUTE_BACKOFF_INITIAL;
        let mut windows = vec![window];
        for _ in 0..10 {
            window = next_window(window, cap);
            windows.push(window);
        }
        let secs: Vec<u64> = windows.iter().map(Duration::as_secs).collect();
        assert_eq!(
            secs,
            [30, 60, 120, 240, 480, 900, 900, 900, 900, 900, 900],
            "doubling from 30 s, capped at the configured cap"
        );
        for w in [NO_ROUTE_BACKOFF_INITIAL, cap] {
            let draws: Vec<Duration> = (0..2_000).map(|_| full_jitter(w)).collect();
            assert!(
                draws.iter().all(|d| *d <= w),
                "a draw exceeded its window {w:?}"
            );
            let lower = draws.iter().filter(|d| **d < w / 2).count();
            assert!(
                (600..=1_400).contains(&lower),
                "full jitter is uniform over [0, window]: {lower}/2000 fell in the lower half"
            );
        }
    }

    /// The probe claim is exclusive and released if its round never reports.
    #[tokio::test(start_paused = true)]
    async fn one_probe_at_a_time_and_an_abandoned_probe_releases_794() {
        let b = NoRouteBackoff::with_jitter(Duration::from_secs(900), |w| w);
        let no_route = || RoundClass::NoRoute("no route".into());
        match b.admit("p", EnvelopeKind::Key) {
            Admission::Run(t) => t.finish(no_route()),
            Admission::Skip => panic!("a peer not backed off runs"),
        }
        assert!(matches!(b.admit("p", EnvelopeKind::Key), Admission::Skip));
        tokio::time::advance(NO_ROUTE_BACKOFF_INITIAL).await;
        let probe = b.admit("p", EnvelopeKind::Key);
        assert!(
            matches!(probe, Admission::Run(_)),
            "the expired delay admits a probe"
        );
        assert!(
            matches!(b.admit("p", EnvelopeKind::Attestation), Admission::Skip),
            "a second plane does not probe beside the first"
        );
        drop(probe);
        assert!(
            matches!(b.admit("p", EnvelopeKind::Attestation), Admission::Run(_)),
            "a dropped (cancelled) probe releases its claim"
        );
    }
}
