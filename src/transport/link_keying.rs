//! CIRISEdge#947 — CC 5.3.3.5: **decapsulation runs outside any node-wide
//! lock and behind the receiver order**, because a stranger's first frame is
//! the cheapest way to make a node do expensive work.
//!
//! [`IDENTIFY_GRACE`]: crate::transport::link_seal::IDENTIFY_GRACE
//! [`DEFERRED_HANDSHAKES_MAX`]: crate::transport::link_seal::DEFERRED_HANDSHAKES_MAX
//!
//! [`LinkSeals::inbound`](crate::transport::link_seal::LinkSeals::inbound)
//! hands a reassembled handshake back as a job and moves the link to `Keying`.
//! From there:
//!
//! 1. **The receiver order** ([`ReceiverOrder`]), on the event path, cheap and
//!    allocation-light, runs in the order the route request runs it: per link
//!    (structural: a link yields at most one job, so a second handshake never
//!    reaches a budget), per sender, then node-wide. Node-wide comes LAST so
//!    one sender's refused attempts spend only that sender's budget, never
//!    the budget honest strangers need. Nothing past the handshake's tag has
//!    been read yet: the parse, like the decapsulation, happens in the keyer.
//! 2. **The keyer** ([`Keyer`]), a bounded pool off the event path. A job runs
//!    on the blocking pool with no seal lock held.
//! 3. **The event loop applies the outcome**
//!    ([`LinkSeals::finish_keying`](crate::transport::link_seal::LinkSeals::finish_keying)).
//!    One thread of control decides what a link's state becomes, and a ticket
//!    ties the outcome to the link's one `Keying` entry, so a link has exactly
//!    one keying outcome whatever raced it.
//!
//! # What identifies a sender, and why never an address
//!
//! The sender is the link's **proven RNS identity** (LINKIDENTIFY, a signature
//! over the link id). The dialler sends it first, but a loaded node can still
//! see the handshake ahead of it, so a handshake with no identity waits for
//! one, within [`IDENTIFY_GRACE`] and [`DEFERRED_HANDSHAKES_MAX`], rather than
//! be judged by that race. An address is never read: one NAT hosts many honest
//! peers, and each has its own identity, so none of them shares a budget with
//! another. A link still unidentified after that shares ONE slot
//! ([`HANDSHAKES_UNIDENTIFIED`]), because nothing else tells two such links
//! apart.
//!
//! Minting an identity costs an attacker a keypair, so the per-sender rate
//! only stops a sender that does not bother. Against a flood of fresh
//! identities the node-wide stranger rate is the bound, and within it an
//! honest stranger competes with the flood for a slot: it is refused and
//! re-dials. That rate bounds the work a stranger can cause. It cannot tell a
//! honest stranger from a fresh Sybil, nothing at this layer can.
//!
//! # Standing: live state, separate budgets
//!
//! A link has [standing](Sender::standing) when its proven identity is bound
//! to a key this node already answers for: a Rooted binding, or a key that
//! owns its binding and holds a seat on the active roster or a room or contact
//! standing. An announce alone does NOT give standing: it is free to mint.
//! All of it is read from the node's live tables, nothing is baked in, and
//! standing has its own node-wide budget and its own queue, drained first, so
//! a stranger flood cannot spend what a known peer's re-dial needs.
//!
//! # Saturation
//!
//! The queues are bounded and never grow: past [`DECAP_QUEUE_STRANGER`] /
//! [`DECAP_QUEUE_STANDING`] the NEW handshake is refused by name
//! ([`SealRefusal::DecapSaturated`]) and its link closed, because the jobs
//! ahead of it will finish in moments and a queue that grows is the same wedge
//! later. The dialler sees its link close and re-dials. A job whose link has
//! since closed or run out its budget is skipped unstarted, so a stale queue
//! costs nothing to drain.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use tokio::sync::mpsc;

use crate::transport::av_transit_handshake::{AvHandshakeError, LinkTransit};
use crate::transport::link_seal::{HandshakeJob, LinkSeals, SealRefusal};
use crate::transport::route_fetch::{RouteRequestLimiter, SenderRouteLimiter};

/// Most decapsulations running at once, whatever the host's size. The pool is
/// half the host's cores within this, at least one, so keying can never take
/// the whole machine: on the 2 vCPU a canonical runs on, one core stays free.
pub const DECAP_WORKERS_MAX: usize = 4;

/// Handshakes with standing waiting for a worker. Sized for a canonical's
/// peers re-dialling together after a restart, drained first: 500 links landing
/// at once clear with this and not with 256 (`FSD/EVENT_PATH_MODEL.md` §2.5).
/// It matters only when frames reach the keyer faster than it runs, and a job
/// that waits out [`KEYING_BUDGET`](crate::transport::link_seal::KEYING_BUDGET)
/// is skipped unstarted, so the bound on the wait is that budget, not this.
pub const DECAP_QUEUE_STANDING: usize = 1024;

/// Handshakes from strangers waiting for a worker: [`HANDSHAKES_STRANGER_NODE`],
/// the budget in front of it. A queue smaller than that budget refuses what the
/// budget admitted, after the slot is spent.
pub const DECAP_QUEUE_STRANGER: usize = 256;

/// Per [`ROUTE_REQUEST_WINDOW`](crate::transport::route_fetch::ROUTE_REQUEST_WINDOW):
/// strangers' handshakes admitted node-wide. A stranger who needs a route
/// fetch is first held to `ROUTE_REQUESTS_PER_WINDOW`, so this bound is
/// reached only by strangers already holding the row, and it sits far under
/// what the keyer can do: the bound is on the work each keyed link causes
/// after it, not on the decapsulation.
pub const HANDSHAKES_STRANGER_NODE: u32 = 256;

/// Per window: handshakes with standing admitted node-wide.
pub const HANDSHAKES_STANDING_NODE: u32 = 2048;

/// Per window, per proven identity without standing: room for one peer's
/// identity lanes and scoped links opening together, and its re-dials.
pub const HANDSHAKES_PER_STRANGER: usize = 16;

/// Per window, per proven identity with standing.
pub const HANDSHAKES_PER_STANDING: usize = 64;

/// Per window: every link with no proven identity, together. Every edge
/// identifies before it keys, so past the identify's grace this is reached only
/// by a link whose identify was lost, and by a flood that never identifies.
pub const HANDSHAKES_UNIDENTIFIED: usize = 16;

// The queue holds what the receiver order lets through in a burst.
const _: () = assert!(DECAP_QUEUE_STRANGER >= HANDSHAKES_STRANGER_NODE as usize);

/// What the event path knows about who sent a handshake.
#[derive(Debug, Clone, Copy)]
pub struct Sender<'a> {
    /// The link's proven RNS identity, hex; `None` before its LINKIDENTIFY.
    pub identity: Option<&'a str>,
    /// See [the module docs](self#standing-live-state-separate-budgets).
    pub standing: bool,
}

/// The receiver order for handshakes. See [the module docs](self).
#[derive(Debug)]
pub struct ReceiverOrder {
    strangers: RouteRequestLimiter,
    standing: RouteRequestLimiter,
    stranger_senders: SenderRouteLimiter,
    standing_senders: SenderRouteLimiter,
}

impl Default for ReceiverOrder {
    fn default() -> Self {
        Self {
            strangers: RouteRequestLimiter::new(HANDSHAKES_STRANGER_NODE),
            standing: RouteRequestLimiter::new(HANDSHAKES_STANDING_NODE),
            stranger_senders: SenderRouteLimiter::with_caps(
                HANDSHAKES_PER_STRANGER,
                HANDSHAKES_UNIDENTIFIED,
            ),
            standing_senders: SenderRouteLimiter::with_caps(
                HANDSHAKES_PER_STANDING,
                HANDSHAKES_UNIDENTIFIED,
            ),
        }
    }
}

impl ReceiverOrder {
    /// Admit one complete handshake, or refuse it by name. Per sender first,
    /// node-wide last: see [the module docs](self).
    ///
    /// # Errors
    /// [`SealRefusal::HandshakeSenderRate`] or
    /// [`SealRefusal::HandshakeNodeRate`].
    pub fn admit(&self, sender: Sender<'_>) -> Result<(), SealRefusal> {
        let (senders, node) = if sender.standing {
            (&self.standing_senders, &self.standing)
        } else {
            (&self.stranger_senders, &self.strangers)
        };
        if !senders.admit(sender.identity) {
            return Err(SealRefusal::HandshakeSenderRate {
                identified: sender.identity.is_some(),
                standing: sender.standing,
            });
        }
        if !node.admit() {
            return Err(SealRefusal::HandshakeNodeRate {
                standing: sender.standing,
                identified: sender.identity.is_some(),
            });
        }
        Ok(())
    }

    /// Test knob: the node-wide stranger rate.
    pub fn set_stranger_cap(&self, cap: u32) {
        self.strangers.set_cap(cap);
    }
}

/// A keying that ran: what the event loop applies.
#[derive(Debug)]
pub struct KeyingDone {
    /// The link.
    pub link: [u8; 16],
    /// The ticket of the `Keying` entry this outcome belongs to.
    pub ticket: u64,
    /// What `respond` answered.
    pub outcome: Result<(LinkTransit, String), AvHandshakeError>,
    /// Which budget it came through.
    pub standing: bool,
    /// When it joined the queue.
    pub queued_at: Instant,
}

#[derive(Debug, Default)]
struct Queues {
    standing: VecDeque<(HandshakeJob, Instant)>,
    strangers: VecDeque<(HandshakeJob, Instant)>,
    running: usize,
}

/// The bounded decapsulation pool. See [the module docs](self#saturation).
#[derive(Debug)]
pub struct Keyer {
    seals: Arc<LinkSeals>,
    queues: Mutex<Queues>,
    workers: usize,
    done: mpsc::UnboundedSender<KeyingDone>,
    metrics: OnceLock<crate::observability::EdgeMetrics>,
}

impl Keyer {
    /// A pool over `seals` sending outcomes to the returned receiver. The
    /// channel is unbounded in type only: it holds at most one outcome per
    /// admitted job, and admission is bounded by the queues.
    #[must_use]
    pub fn new(seals: Arc<LinkSeals>) -> (Arc<Self>, mpsc::UnboundedReceiver<KeyingDone>) {
        let cores = std::thread::available_parallelism().map_or(2, std::num::NonZeroUsize::get);
        Self::with_workers(seals, (cores / 2).clamp(1, DECAP_WORKERS_MAX))
    }

    fn with_workers(
        seals: Arc<LinkSeals>,
        workers: usize,
    ) -> (Arc<Self>, mpsc::UnboundedReceiver<KeyingDone>) {
        let (done, rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                seals,
                queues: Mutex::new(Queues::default()),
                workers,
                done,
                metrics: OnceLock::new(),
            }),
            rx,
        )
    }

    fn queues(&self) -> std::sync::MutexGuard<'_, Queues> {
        self.queues
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Count into the node's bag, the one the host reads: the seals' keyer is
    /// built before the Edge's bag exists.
    pub fn attach_metrics(&self, metrics: crate::observability::EdgeMetrics) {
        if self.metrics.set(metrics).is_ok() {
            self.publish(&self.queues());
        }
    }

    /// The gauges, set where the queues change, under their lock: a load, not
    /// a walk, for whoever reads them.
    fn publish(&self, q: &Queues) {
        if let Some(m) = self.metrics.get() {
            m.telemetry
                .set_keyer_queued(q.standing.len(), q.strangers.len());
            m.telemetry.set_keyer_workers(self.workers, q.running);
        }
    }

    fn count(&self, label: &'static str) {
        if let Some(m) = self.metrics.get() {
            m.inc_link_seal(label);
        }
    }

    /// Queue one admitted job, or refuse it: the queues never grow past their
    /// bounds.
    ///
    /// # Errors
    /// [`SealRefusal::DecapSaturated`].
    pub fn submit(self: &Arc<Self>, job: HandshakeJob, standing: bool) -> Result<(), SealRefusal> {
        let start_worker = {
            let mut q = self.queues();
            let (queue, bound) = if standing {
                (&mut q.standing, DECAP_QUEUE_STANDING)
            } else {
                (&mut q.strangers, DECAP_QUEUE_STRANGER)
            };
            if queue.len() >= bound {
                return Err(SealRefusal::DecapSaturated { standing });
            }
            queue.push_back((job, Instant::now()));
            let start = q.running < self.workers;
            if start {
                q.running += 1;
            }
            self.publish(&q);
            start
        };
        if start_worker {
            let me = Arc::clone(self);
            tokio::task::spawn_blocking(move || me.drain());
        }
        Ok(())
    }

    /// A worker: run jobs, standing first, until none wait. `running` changes
    /// only under the queue lock, in the same breath as the empty check and
    /// the push, so a job is never left with no worker coming.
    fn drain(&self) {
        loop {
            let next = {
                let mut q = self.queues();
                let standing = q.standing.pop_front().map(|j| (j, true));
                let next = standing.or_else(|| q.strangers.pop_front().map(|j| (j, false)));
                if next.is_none() {
                    q.running -= 1;
                }
                self.publish(&q);
                next
            };
            let Some(((job, queued_at), standing)) = next else {
                return;
            };
            // Unwinding here would lose a worker for good, which is the wedge
            // in slow motion: a panic is one refused link instead.
            let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.seals.decapsulate(&job)
            }));
            let outcome = match ran {
                Ok(Some(outcome)) => outcome,
                // The link closed or ran out its budget in the queue.
                Ok(None) => {
                    self.count(crate::observability::LINK_SEAL_KEYING_SKIPPED_STALE);
                    continue;
                }
                Err(_) => {
                    self.count(crate::observability::LINK_SEAL_KEYER_PANICKED);
                    tracing::error!(
                        link = %hex::encode(job.link()),
                        "the transit KEX panicked on a handshake; the link is refused and the \
                         worker lives (CIRISEdge#947)"
                    );
                    Err(AvHandshakeError::Malformed("the transit KEX panicked"))
                }
            };
            // choke-ok: the receiver goes only with the transport, and the
            // handshake budget refuses a link whose outcome never lands.
            let _ = self.done.send(KeyingDone {
                link: job.link(),
                ticket: job.ticket(),
                outcome,
                standing,
                queued_at,
            });
        }
    }

    /// Jobs waiting for a worker.
    #[must_use]
    pub fn depth(&self) -> usize {
        let q = self.queues();
        q.standing.len() + q.strangers.len()
    }

    /// The pool's size.
    #[must_use]
    pub fn workers(&self) -> usize {
        self.workers
    }
}

#[cfg(test)]
#[path = "link_keying/tests.rs"]
mod tests;
