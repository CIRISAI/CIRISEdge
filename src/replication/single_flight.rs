//! **CIRISEdge#817 — single-flight refresh for the bridge's TTL memos.**
//!
//! The consent send-set memo and the owner-of memo each save a full-history
//! persist read. Neither was single-flight: when an entry expired while N peer
//! sweeps were running, every one of them missed at once and every one re-read
//! the same history, so the heap held N copies of it at the same instant. v38
//! sweeps finished inside the TTL windows and rarely met this; v40's slower
//! sweeps let both memos expire mid-round, which is where the operator-heavy
//! harness measured 408–432 MB against v38's 133 MB.
//!
//! [`SingleFlight::run`] makes a miss one read: the first caller for a key
//! computes, and every caller that arrives for the same key while that read is
//! in flight awaits its result. Nothing about freshness moves:
//!
//! - **No TTL is lengthened.** The memo is still read first, under its own
//!   TTL, exactly as before. A waiter receives a value read DURING its wait,
//!   which is younger than anything the memo could have served it.
//! - **An invalidation is never answered by a pre-invalidation read.**
//!   [`SingleFlight::invalidate`] forgets every flight in progress, so a caller
//!   arriving after it starts a fresh read, and bumps an epoch, so a flight that
//!   began before it does not STORE its (possibly stale) answer into the memo.
//!   Callers that joined that flight before the invalidation still get its
//!   answer, which is exactly what they would have got from their own
//!   concurrent read before this change.
//! - **Cancellation is safe.** A flight is a [`tokio::sync::OnceCell`]: if the
//!   computing caller is dropped mid-read, the next waiter runs its own read.
//!
//! The store runs under the flight table's lock and after the epoch check, so
//! an invalidation cannot slip between "is this flight still current?" and
//! "write the memo". Callers invalidate the flight table BEFORE clearing their
//! memo, which closes the other order.

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::OnceCell;

/// One key's in-flight read: the epoch it began in, and the cell its result
/// lands in.
type Flight<V> = (u64, Arc<OnceCell<V>>);

/// A per-key single-flight table. See the module docs.
#[derive(Debug)]
pub(crate) struct SingleFlight<K, V> {
    flights: Mutex<HashMap<K, Flight<V>>>,
    epoch: AtomicU64,
}

impl<K, V> Default for SingleFlight<K, V> {
    fn default() -> Self {
        Self {
            flights: Mutex::new(HashMap::new()),
            epoch: AtomicU64::new(0),
        }
    }
}

impl<K: Eq + Hash + Clone, V: Clone> SingleFlight<K, V> {
    /// A poisoned table is still a valid table: every critical section below
    /// is a map insert, lookup or removal, none of which can leave it torn.
    fn table(&self) -> MutexGuard<'_, HashMap<K, Flight<V>>> {
        self.flights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Run `compute` for `key` unless a read for `key` is already in flight,
    /// in which case await that read's result instead. The caller whose
    /// `compute` ran, and only that caller, then calls `store` with the result,
    /// provided no [`Self::invalidate`] happened since its flight began.
    ///
    /// The caller checks its memo BEFORE calling this, and `compute` should
    /// check it once more first thing: a flight that completed between the
    /// caller's miss and its arrival here has already filled it.
    pub(crate) async fn run<F, Fut, S>(&self, key: &K, compute: F, store: S) -> V
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = V>,
        S: FnOnce(&V),
    {
        let (epoch, cell) = {
            let mut table = self.table();
            let now = self.epoch.load(Ordering::SeqCst);
            table
                .entry(key.clone())
                .or_insert_with(|| (now, Arc::new(OnceCell::new())))
                .clone()
        };
        let computed_here = AtomicBool::new(false);
        let value = cell
            .get_or_init(|| async {
                computed_here.store(true, Ordering::Relaxed);
                compute().await
            })
            .await
            .clone();
        if computed_here.load(Ordering::Relaxed) {
            let mut table = self.table();
            if self.epoch.load(Ordering::SeqCst) == epoch {
                store(&value);
            }
            if table.get(key).is_some_and(|(_, c)| Arc::ptr_eq(c, &cell)) {
                table.remove(key);
            }
        }
        value
    }

    /// Forget every flight in progress: a caller arriving after this starts
    /// its own read, and a flight that began before it stores nothing. Call
    /// it BEFORE dropping the memo it guards.
    pub(crate) fn invalidate(&self) {
        let mut table = self.table();
        self.epoch.fetch_add(1, Ordering::SeqCst);
        table.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    /// N concurrent callers of one key cost ONE computation and all see its
    /// value; a later call after the flight lands computes again.
    #[tokio::test]
    async fn concurrent_callers_share_one_computation() {
        let sf: SingleFlight<&'static str, usize> = SingleFlight::default();
        let runs = AtomicUsize::new(0);
        let stores = AtomicUsize::new(0);
        let call = || {
            sf.run(
                &"k",
                || async {
                    let n = runs.fetch_add(1, Ordering::SeqCst) + 1;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    n
                },
                |_| {
                    stores.fetch_add(1, Ordering::SeqCst);
                },
            )
        };
        let got = futures::future::join_all((0..8).map(|_| call())).await;
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert_eq!(
            stores.load(Ordering::SeqCst),
            1,
            "only the computing caller stores"
        );
        assert!(got.iter().all(|v| *v == 1));
        assert_eq!(call().await, 2, "a landed flight is not served again");
    }

    /// An invalidation during a flight: the flight stores nothing, and a caller
    /// arriving after it computes afresh rather than joining the stale read.
    #[tokio::test]
    async fn an_invalidation_mid_flight_is_never_answered_by_the_old_read() {
        let sf: Arc<SingleFlight<&'static str, usize>> = Arc::default();
        let runs = Arc::new(AtomicUsize::new(0));
        let stored = Arc::new(Mutex::new(Vec::new()));
        let go = tokio::sync::Notify::new();
        let go = Arc::new(go);
        let first = {
            let (sf, runs, stored, go) = (sf.clone(), runs.clone(), stored.clone(), go.clone());
            tokio::spawn(async move {
                sf.run(
                    &"k",
                    || async {
                        runs.fetch_add(1, Ordering::SeqCst);
                        go.notified().await;
                        1
                    },
                    |v| stored.lock().unwrap().push(*v),
                )
                .await
            })
        };
        while runs.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        sf.invalidate();
        let second = sf
            .run(&"k", || async { 2 }, |v| stored.lock().unwrap().push(*v))
            .await;
        assert_eq!(second, 2, "the post-invalidation caller did its own read");
        go.notify_one();
        assert_eq!(first.await.unwrap(), 1);
        assert_eq!(
            *stored.lock().unwrap(),
            vec![2],
            "the pre-invalidation flight stored nothing"
        );
    }

    /// A computing caller dropped mid-read hands the flight to the next waiter.
    #[tokio::test]
    async fn a_cancelled_computation_passes_to_a_waiter() {
        let sf: SingleFlight<&'static str, usize> = SingleFlight::default();
        let cancelled = sf.run(
            &"k",
            || async {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                0
            },
            |_| {},
        );
        let r = tokio::time::timeout(Duration::from_millis(10), cancelled).await;
        assert!(r.is_err(), "the first read is still pending and is dropped");
        let v = sf.run(&"k", || async { 7 }, |_| {}).await;
        assert_eq!(v, 7);
    }
}
