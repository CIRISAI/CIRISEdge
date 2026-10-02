//! CIRISEdge#779 — **a parked DAG is woken by its key, not by the clock.**
//!
//! A sealed DAG pull that holds its bytes but not this node's wrap (on the
//! manifest, #717, or on some chunk, #779) parks as
//! [`PullOutcome::DagAwaitingKey`](super::PullOutcome::DagAwaitingKey) and
//! books a retry. The retry ladder is bounded, and nothing re-offers the row
//! when the grant lands (the bridge offers a row once, on admission), so a
//! stall longer than the ladder left the file unpromoted for good even after
//! every grant arrived.
//!
//! This is the other half: the puller records what each parked DAG waits
//! on, and the bridge's key-grant door ([`super::PullSink::key_grant_admitted`])
//! marks the DAG woken when a set that wrote a wrap to this node names it.
//! The puller's tick dispatches each woken DAG once, from a fresh ladder.
//!
//! Bounded everywhere: at most `capacity` parked DAGs (the oldest is
//! dropped), one entry per key the DAG still waits on, and a wake is a flag,
//! so a thousand chunk grants landing inside one tick coalesce into one
//! re-pull of their DAG.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use ciris_persist::federation::Attestation;

/// What a parked DAG waits on.
#[derive(Debug, Clone)]
pub(crate) enum Awaiting {
    /// Content-axis wraps (self / family): the at-rest addresses of the rows
    /// (the manifest, or the chunks) this node holds no wrap for.
    Content(Vec<[u8; 32]>),
    /// An epoch-axis grant (`community_dek`): the manifest's sealed-under
    /// epoch, when the pointer names one.
    Epoch(Option<u64>),
}

#[derive(Debug)]
struct Parked {
    row: Attestation,
    awaiting: Awaiting,
    woken: bool,
    /// Insertion order, for eviction at capacity.
    order: u64,
}

#[derive(Debug, Default)]
struct Inner {
    parked: HashMap<[u8; 32], Parked>,
    /// Content key → the DAG waiting on it.
    by_key: HashMap<[u8; 32], [u8; 32]>,
    next_order: u64,
}

impl Inner {
    fn unindex(&mut self, dag: [u8; 32], awaiting: &Awaiting) {
        if let Awaiting::Content(keys) = awaiting {
            for k in keys {
                if self.by_key.get(k) == Some(&dag) {
                    self.by_key.remove(k);
                }
            }
        }
    }
}

/// The parked-DAG register, shared by the puller and its sink.
#[derive(Debug)]
pub(crate) struct KeyWaits {
    inner: Mutex<Inner>,
    capacity: usize,
}

impl KeyWaits {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            capacity: capacity.max(1),
        }
    }

    /// Record that the DAG at `dag` (referenced by `row`) is parked on
    /// `awaiting`. Replaces what it waited on before and keeps a pending
    /// wake: a grant that landed while this attempt was running must still
    /// re-pull it.
    pub(crate) fn park(&self, dag: [u8; 32], row: &Attestation, awaiting: Awaiting) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let woken = if let Some(old) = inner.parked.remove(&dag) {
            inner.unindex(dag, &old.awaiting);
            old.woken
        } else {
            if inner.parked.len() >= self.capacity {
                if let Some(oldest) = inner
                    .parked
                    .iter()
                    .min_by_key(|(_, p)| p.order)
                    .map(|(k, _)| *k)
                {
                    if let Some(p) = inner.parked.remove(&oldest) {
                        inner.unindex(oldest, &p.awaiting);
                    }
                    tracing::warn!(
                        dropped = %hex::encode(oldest),
                        "parked-DAG key register FULL — dropped the oldest; a grant for it \
                         no longer wakes its pull (CIRISEdge#779)"
                    );
                }
            }
            false
        };
        if let Awaiting::Content(keys) = &awaiting {
            for k in keys {
                inner.by_key.insert(*k, dag);
            }
        }
        let order = inner.next_order;
        inner.next_order += 1;
        inner.parked.insert(
            dag,
            Parked {
                row: row.clone(),
                awaiting,
                woken,
                order,
            },
        );
    }

    /// The DAG is done waiting (stored, held, or refused for good).
    pub(crate) fn forget(&self, dag: [u8; 32]) {
        if let Ok(mut inner) = self.inner.lock() {
            if let Some(p) = inner.parked.remove(&dag) {
                inner.unindex(dag, &p.awaiting);
            }
        }
    }

    /// A content-axis wrap to this node landed on the row at `sha`. Returns
    /// whether a parked DAG was waiting on it.
    pub(crate) fn wake_content(&self, sha: [u8; 32]) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        let Some(dag) = inner.by_key.remove(&sha) else {
            return false;
        };
        match inner.parked.get_mut(&dag) {
            Some(p) => {
                p.woken = true;
                true
            }
            None => false,
        }
    }

    /// An epoch-axis wrap to this node landed for `epoch`. Wakes every DAG
    /// parked on that epoch, or on an epoch its pointer does not name.
    /// Returns how many.
    pub(crate) fn wake_epoch(&self, epoch: u64) -> usize {
        let Ok(mut inner) = self.inner.lock() else {
            return 0;
        };
        let mut woke = 0;
        for p in inner.parked.values_mut() {
            if let Awaiting::Epoch(e) = p.awaiting {
                if e.map_or(true, |e| e == epoch) {
                    p.woken = true;
                    woke += 1;
                }
            }
        }
        woke
    }

    /// Every woken DAG not in `busy`, its flag cleared: the puller dispatches
    /// each once. A woken DAG still in flight keeps its flag for the next
    /// tick, so a wake that landed mid-attempt is never lost.
    pub(crate) fn take_woken(&self, busy: &HashSet<[u8; 32]>) -> Vec<([u8; 32], Attestation)> {
        let Ok(mut inner) = self.inner.lock() else {
            return Vec::new();
        };
        inner
            .parked
            .iter_mut()
            .filter(|(dag, p)| p.woken && !busy.contains(*dag))
            .map(|(dag, p)| {
                p.woken = false;
                (*dag, p.row.clone())
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn is_parked(&self, dag: [u8; 32]) -> bool {
        self.inner.lock().is_ok_and(|i| i.parked.contains_key(&dag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> Attestation {
        crate::blob_swarm::meaning::fixture::bare_row("self")
    }

    /// A thousand chunk grants for one DAG are one dispatch; a wake that
    /// lands while the DAG is in flight survives to the next tick; a wake
    /// for a key nobody waits on does nothing.
    #[test]
    fn wakes_coalesce_per_dag_and_survive_in_flight_779() {
        let waits = KeyWaits::new(4);
        let dag = [1u8; 32];
        let chunks: Vec<[u8; 32]> = (0..1000u16)
            .map(|i| {
                let mut k = [0u8; 32];
                k[..2].copy_from_slice(&i.to_be_bytes());
                k[31] = 9;
                k
            })
            .collect();
        waits.park(dag, &row(), Awaiting::Content(chunks.clone()));
        assert!(!waits.wake_content([7u8; 32]));
        for c in &chunks {
            assert!(waits.wake_content(*c));
        }
        assert!(!waits.wake_content(chunks[0]), "a key wakes once");
        let busy: HashSet<[u8; 32]> = [dag].into_iter().collect();
        assert!(waits.take_woken(&busy).is_empty(), "in flight: held over");
        assert_eq!(waits.take_woken(&HashSet::new()).len(), 1, "one dispatch");
        assert!(waits.take_woken(&HashSet::new()).is_empty());
        waits.forget(dag);
        assert!(!waits.is_parked(dag));
    }

    /// Re-parking keeps a pending wake; capacity drops the oldest.
    #[test]
    fn repark_keeps_the_wake_and_capacity_bounds_779() {
        let waits = KeyWaits::new(2);
        waits.park([1u8; 32], &row(), Awaiting::Content(vec![[10u8; 32]]));
        assert!(waits.wake_content([10u8; 32]));
        waits.park([1u8; 32], &row(), Awaiting::Content(vec![[11u8; 32]]));
        assert_eq!(waits.take_woken(&HashSet::new()).len(), 1);
        waits.park([2u8; 32], &row(), Awaiting::Epoch(Some(3)));
        waits.park([3u8; 32], &row(), Awaiting::Epoch(None));
        assert!(!waits.is_parked([1u8; 32]), "the oldest is dropped");
        assert!(!waits.wake_content([11u8; 32]), "with its keys");
        assert_eq!(waits.wake_epoch(3), 2, "its epoch, and an unnamed one");
        assert_eq!(waits.wake_epoch(4), 1, "only the unnamed one");
    }
}
