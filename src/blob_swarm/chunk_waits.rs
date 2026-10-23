//! CIRISEdge#887 — the waits for chunk answers, and the answers that come late.
//!
//! A chunk fetch waits `per_request_timeout` for its answer. When the wait
//! ends first, the holder's answer is usually still on the way: a ~1 MB
//! `BlobChunkBody` behind a congested link (the reverse-path Resource is cut at
//! `REVERSE_PATH_MAX_TRANSFER` and re-sent). Before this module the late answer
//! found no waiter and was discarded at the dispatcher after the whole transfer
//! had been paid, and the retry asked the holder for the same chunk again,
//! doubling the load in exactly the window that was already too slow.
//!
//! Now a wait that times out leaves an [`Slot::Expired`] mark for one more
//! window. An answer that lands on the mark is KEPT ([`Slot::Landed`]), and the
//! next fetch of that chunk takes it without sending anything. Only a chunk
//! this node asked for and stopped waiting on can be kept, so an unsolicited
//! answer is still dropped, and the memory held is bounded by the requests
//! that timed out within one window.
//!
//! The HOLDER's half is [`ChunkWaits::begin_serve`]: while this node is still
//! sending a requester the answer for a chunk, a repeat request for the same
//! chunk from the same requester starts no second transfer. Without it every
//! requester timeout started another full ~1 MB send of a chunk already in
//! flight, and a restarted requester (same key, new process) doubled the load
//! again with the answers still headed to its dead predecessor. Transfers
//! then outlasted the reverse path's hard cap, were abandoned, restarted, and
//! nothing completed (the bigfile resume stall). The answer in flight reaches
//! the requester's retry, or its kept late answer, by the chunk's key.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

use crate::ChunkResult;

/// `(blob_sha256, chunk_sha256)`: the scheduler runs chunk fetches across
/// several blobs at once, and a chunk hash alone does not name the fetch.
pub(crate) type ChunkKey = ([u8; 32], [u8; 32]);

#[derive(Debug)]
enum Slot {
    /// A fetch is waiting on this sender.
    Waiting(oneshot::Sender<ChunkResult>),
    /// A fetch stopped waiting; an answer landing before `until` is kept.
    Expired { until: Instant },
    /// A late answer, kept for the next fetch of this chunk until `until`.
    Landed { result: ChunkResult, until: Instant },
}

/// What an arriving answer did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answered {
    /// It completed a waiting fetch.
    Delivered,
    /// It came after its fetch timed out and is kept for the retry.
    Kept,
    /// Nothing asked for it (or the keep window had passed): dropped.
    Unsolicited,
}

/// How a fetch registered.
#[derive(Debug)]
pub(crate) enum Wait {
    /// Send the request and wait on this receiver.
    Pending(oneshot::Receiver<ChunkResult>),
    /// The chunk's late answer is already here; nothing to send.
    AlreadyLanded(ChunkResult),
}

/// The waits for chunk answers, and the answers this node is serving. Held
/// under the edge's mutex.
#[derive(Debug, Default)]
pub(crate) struct ChunkWaits {
    slots: HashMap<ChunkKey, Slot>,
    /// `(requester key_id, chunk)` → when this node started answering it.
    serving: HashMap<(String, ChunkKey), Instant>,
}

/// The longest an answer is treated as in flight. The reply path's own
/// bounds end a send well inside this (the 45 s reverse-path cap plus the
/// dial fallback); this only reclaims an entry whose guard never ran.
pub(crate) const SERVE_IN_FLIGHT_MAX: Duration = Duration::from_secs(120);

impl ChunkWaits {
    /// Register a fetch of `key`. A kept late answer is handed over at once.
    /// Re-registering while another fetch waits replaces that waiter, which
    /// then sees a closed channel (the scheduler's per-peer cap keeps this
    /// out of normal operation).
    pub(crate) fn wait(&mut self, key: ChunkKey, now: Instant) -> Wait {
        self.prune(now);
        if let Some(Slot::Landed { .. }) = self.slots.get(&key) {
            if let Some(Slot::Landed { result, .. }) = self.slots.remove(&key) {
                return Wait::AlreadyLanded(result);
            }
        }
        let (tx, rx) = oneshot::channel();
        self.slots.insert(key, Slot::Waiting(tx));
        Wait::Pending(rx)
    }

    /// The request was never sent: drop the wait outright.
    pub(crate) fn forget(&mut self, key: &ChunkKey) {
        if matches!(self.slots.get(key), Some(Slot::Waiting(_))) {
            self.slots.remove(key);
        }
    }

    /// The fetch stopped waiting on `key` (its receiver is gone): keep a mark
    /// for `keep_for` so a late answer is not discarded. A NEWER waiter on the
    /// same key (its sender still open) is left alone.
    pub(crate) fn expire(&mut self, key: ChunkKey, now: Instant, keep_for: Duration) {
        self.prune(now);
        match self.slots.get(&key) {
            Some(Slot::Waiting(tx)) if !tx.is_closed() => {}
            Some(Slot::Waiting(_)) | None => {
                self.slots.insert(
                    key,
                    Slot::Expired {
                        until: now + keep_for,
                    },
                );
            }
            Some(Slot::Expired { .. } | Slot::Landed { .. }) => {}
        }
    }

    /// An answer for `key` arrived.
    pub(crate) fn answer(&mut self, key: ChunkKey, result: ChunkResult, now: Instant) -> Answered {
        match self.slots.remove(&key) {
            Some(Slot::Waiting(tx)) => match tx.send(result) {
                Ok(()) => Answered::Delivered,
                // The waiter is gone but has not marked the slot yet (its
                // timeout and this answer raced): keep it for the retry.
                Err(result) => {
                    self.slots.insert(
                        key,
                        Slot::Landed {
                            result,
                            until: now + KEEP_ON_RACE,
                        },
                    );
                    Answered::Kept
                }
            },
            Some(Slot::Expired { until }) if until > now => {
                self.slots.insert(key, Slot::Landed { result, until });
                Answered::Kept
            }
            Some(landed @ Slot::Landed { .. }) => {
                // A duplicate of a kept answer: keep the first.
                self.slots.insert(key, landed);
                Answered::Unsolicited
            }
            Some(Slot::Expired { .. }) | None => Answered::Unsolicited,
        }
    }

    /// HOLDER side: may this node start answering `requester` for `key`?
    /// `false` while an earlier answer for the same chunk to the same
    /// requester is still being sent (younger than `max_age`): the repeat
    /// request is coalesced into it. `true` records the start; the caller
    /// MUST call [`Self::end_serve`] when its send ends, however it ends.
    pub(crate) fn begin_serve(
        &mut self,
        requester: &str,
        key: ChunkKey,
        now: Instant,
        max_age: Duration,
    ) -> bool {
        self.serving
            .retain(|_, started| now.saturating_duration_since(*started) < max_age);
        let id = (requester.to_owned(), key);
        if self.serving.contains_key(&id) {
            return false;
        }
        self.serving.insert(id, now);
        true
    }

    /// HOLDER side: the answer for `key` to `requester` is no longer in flight.
    pub(crate) fn end_serve(&mut self, requester: &str, key: ChunkKey) {
        self.serving.remove(&(requester.to_owned(), key));
    }

    /// Drop marks and kept answers whose window has passed.
    fn prune(&mut self, now: Instant) {
        self.slots.retain(|_, slot| match slot {
            Slot::Waiting(_) => true,
            Slot::Expired { until } | Slot::Landed { until, .. } => *until > now,
        });
    }

    /// Test seam: complete a waiting fetch as if its answer arrived.
    pub(crate) fn complete_waiting(&mut self, key: &ChunkKey, result: ChunkResult) -> bool {
        if matches!(self.slots.get(key), Some(Slot::Waiting(_))) {
            if let Some(Slot::Waiting(tx)) = self.slots.remove(key) {
                let _ = tx.send(result);
                return true;
            }
        }
        false
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.slots.len()
    }
}

/// How long an answer that raced its own timeout is kept. The timeout's
/// `expire` normally sets the window; this covers the instant between the
/// receiver dropping and that call.
const KEEP_ON_RACE: Duration = Duration::from_secs(30);

#[cfg(test)]
mod tests {
    use super::*;

    const K: ChunkKey = ([1; 32], [2; 32]);

    fn bytes(r: &ChunkResult) -> &[u8] {
        match r {
            ChunkResult::Bytes(b) => b,
            ChunkResult::ChunkMiss { .. } => panic!("expected bytes"),
        }
    }

    #[test]
    fn an_answer_completes_its_waiting_fetch() {
        let mut w = ChunkWaits::default();
        let now = Instant::now();
        let Wait::Pending(mut rx) = w.wait(K, now) else {
            panic!("nothing landed yet")
        };
        assert_eq!(
            w.answer(K, ChunkResult::Bytes(vec![7]), now),
            Answered::Delivered
        );
        assert_eq!(bytes(&rx.try_recv().unwrap()), &[7]);
        assert_eq!(w.len(), 0);
    }

    /// The #887 failure: the answer lands after the wait gave up. It is kept,
    /// and the retry takes it without a second request.
    #[test]
    fn a_late_answer_is_kept_for_the_retry_887() {
        let mut w = ChunkWaits::default();
        let t0 = Instant::now();
        let Wait::Pending(rx) = w.wait(K, t0) else {
            panic!()
        };
        drop(rx); // the timeout consumed the receiver
        let t1 = t0 + Duration::from_secs(30);
        w.expire(K, t1, Duration::from_secs(30));
        assert_eq!(
            w.answer(K, ChunkResult::Bytes(vec![9]), t1 + Duration::from_secs(5)),
            Answered::Kept
        );
        match w.wait(K, t1 + Duration::from_secs(6)) {
            Wait::AlreadyLanded(r) => assert_eq!(bytes(&r), &[9]),
            Wait::Pending(_) => panic!("the kept answer must be handed over"),
        }
        assert_eq!(w.len(), 0, "handed over, not held twice");
    }

    #[test]
    fn a_late_answer_races_the_timeout_and_is_still_kept() {
        let mut w = ChunkWaits::default();
        let t0 = Instant::now();
        let Wait::Pending(rx) = w.wait(K, t0) else {
            panic!()
        };
        drop(rx); // receiver gone, `expire` not called yet
        assert_eq!(w.answer(K, ChunkResult::Bytes(vec![3]), t0), Answered::Kept);
        w.expire(K, t0, Duration::from_secs(30));
        assert!(matches!(w.wait(K, t0), Wait::AlreadyLanded(_)));
    }

    #[test]
    fn an_unsolicited_or_stale_answer_is_dropped() {
        let mut w = ChunkWaits::default();
        let t0 = Instant::now();
        assert_eq!(
            w.answer(K, ChunkResult::Bytes(vec![1]), t0),
            Answered::Unsolicited,
            "nothing asked for it"
        );
        let Wait::Pending(rx) = w.wait(K, t0) else {
            panic!()
        };
        drop(rx);
        w.expire(K, t0, Duration::from_secs(30));
        assert_eq!(
            w.answer(K, ChunkResult::Bytes(vec![1]), t0 + Duration::from_secs(31)),
            Answered::Unsolicited,
            "past the keep window"
        );
        assert_eq!(w.len(), 0);
    }

    #[test]
    fn a_kept_answer_expires_and_a_newer_waiter_is_never_displaced() {
        let mut w = ChunkWaits::default();
        let t0 = Instant::now();
        let Wait::Pending(rx) = w.wait(K, t0) else {
            panic!()
        };
        drop(rx);
        w.expire(K, t0, Duration::from_secs(30));
        w.answer(K, ChunkResult::Bytes(vec![1]), t0);
        // Not taken within the window: pruned on the next registration.
        let Wait::Pending(_rx2) = w.wait(K, t0 + Duration::from_secs(31)) else {
            panic!("an expired kept answer is not handed over")
        };
        // A newer waiter is live: an old fetch's `expire` leaves it alone.
        w.expire(K, t0 + Duration::from_secs(32), Duration::from_secs(30));
        assert!(w.complete_waiting(&K, ChunkResult::Bytes(vec![2])));
    }

    /// The holder half of #887: a repeat request for a chunk whose answer is
    /// still in flight to the same requester starts no second transfer; a
    /// different requester, a different chunk, or a finished answer does.
    #[test]
    fn a_repeat_request_is_coalesced_into_the_answer_in_flight_887() {
        let mut w = ChunkWaits::default();
        let t0 = Instant::now();
        let max = SERVE_IN_FLIGHT_MAX;
        assert!(
            w.begin_serve("bob", K, t0, max),
            "the first request is served"
        );
        assert!(
            !w.begin_serve("bob", K, t0 + Duration::from_secs(30), max),
            "bob's retry while the answer is in flight is coalesced"
        );
        assert!(
            w.begin_serve("carol", K, t0, max),
            "another requester is served"
        );
        assert!(
            w.begin_serve("bob", ([1; 32], [3; 32]), t0, max),
            "another chunk is served"
        );
        w.end_serve("bob", K);
        assert!(
            w.begin_serve("bob", K, t0 + Duration::from_secs(31), max),
            "after the answer ends, a new request is served"
        );
        assert!(
            w.begin_serve("bob", K, t0 + Duration::from_secs(31) + max, max),
            "an entry whose guard never ran is reclaimed after the bound"
        );
    }

    #[test]
    fn forget_drops_only_a_waiter() {
        let mut w = ChunkWaits::default();
        let t0 = Instant::now();
        let _rx = w.wait(K, t0);
        w.forget(&K);
        assert_eq!(w.len(), 0);
    }
}
