//! **What a restart still knows about who it answers for** (v44 LTS), read off
//! the event path and paid for by what changed.
//!
//! The live `peers` map starts empty, so without this table every ordinary
//! peer's first link after a restart is judged a stranger
//! (`FSD/EVENT_PATH_MODEL.md` §2.3). The store is authority for the route,
//! never for trust (CIRISEdge#393): a replicated row's `Rooted` is its signer's
//! own claim. So a row counts only if it proves the same two things a live
//! binding has to: `rooted` is the claim AND a chain that roots here, walked as
//! a heal walks it; otherwise the key must have hybrid-signed this very route,
//! which is `owns_key`. A plain write-through of an announce proves neither,
//! since anyone can announce under anyone's key id.
//!
//! # Why this is not a walk every 30 s
//!
//! It was. Each pass listed every live route, folded it (a read per
//! destination), read every key's revocations and re-walked every row that had
//! failed, on a tick that did not wait for the last pass: at 18,060 live routes
//! a pass outlasted its tick and they stacked, ~15 MB per tick and linear to
//! 1,326 MB on the production copy.
//!
//! Now:
//!
//! - **One at a time.** A tick that finds a pass running is skipped and counted.
//! - **Bounded.** A pass stops at [`PASS_BUDGET`] and is cut at [`PASS_BOUND`];
//!   what it did not reach waits, and nothing it did reach is undone.
//! - **Driven by change.** Each tick drains persist's admission cursors, which a
//!   local write moves exactly as a replicated apply does, and judges only the
//!   keys they name: a new or retired route, a revocation, a key or a delegation
//!   landing. An empty tick costs two index reads.
//! - **A sweep behind.** Every [`SWEEP_EVERY`] the whole list is walked, a
//!   budget at a time across ticks, for what the cursors cannot show: an
//!   unsigned local row, a future-dated revocation taking effect, a postgres
//!   tie. It holds one copy of the list and frees it when it ends.
//! - **Failures are memoised** until [`UNPROVEN_TTL`], so a sweep does not
//!   re-walk them. A change naming the key drops the memo, so a row that has
//!   become valid gets standing on the next pass, not at the expiry.
//!
//! A hiccup never widens anything: a change read or a list the store did not
//! serve leaves nobody standing until it can be read again, and so does going
//! [`STALE_AFTER`] without one, because a table that is not being read is one a
//! revocation cannot reach.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use ciris_persist::federation::self_at_login::BindingProvenance;
use tokio::time::Instant;

use super::reticulum::{identity_of_transport, named_dest_of_transport, store_claim_roots_here};
use crate::observability as obs;
use crate::verify::{BindingCursors, HybridPolicy, LiveTransportBinding, RootingDirectory};

/// How long a pass works before it stops at the next row. Well inside the
/// 30 s tick, and leaves the store most of each tick.
pub(super) const PASS_BUDGET: Duration = Duration::from_secs(10);

/// Where a pass is cut, whatever it is waiting on: one read may overrun the
/// budget, none may hold the single flight past this.
pub(super) const PASS_BOUND: Duration = Duration::from_secs(20);

/// How often the whole list is walked. As the key-plane memos' TTL
/// ([`crate::replication`]'s `MEMO_TTL`), for the same reason.
pub(super) const SWEEP_EVERY: Duration = Duration::from_secs(600);

/// How long a row that proved nothing is left out of a sweep. Longer than
/// [`SWEEP_EVERY`], or the memo would never save a walk. A change naming the
/// key ends it at once; this bounds what no change names, a link upstream in a
/// chain.
pub(crate) const UNPROVEN_TTL: Duration = Duration::from_secs(1_800);

/// A table this long without a change read is forgotten.
pub(super) const STALE_AFTER: Duration = Duration::from_secs(600);

/// Rows per statement of the change read.
pub(super) const CHANGE_PAGE: u32 = 256;

/// Keys waiting to be judged before the change read stops for this pass. Its
/// cursors hold the place, so a burst costs passes, not memory.
const MAX_PENDING: usize = 4_096;

/// The cursors start this far back, as the key-plane memos' do: a row committed
/// while the first list is being read is past them.
const CURSOR_LAG: Duration = Duration::from_secs(60);

/// A binding persist holds for a proven transport identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PersistedStanding {
    pub(super) key_id: String,
    /// The row said Rooted and the key's chain roots HERE, re-walked.
    pub(super) rooted: bool,
}

/// Per proven transport identity, the bindings persist holds for it.
pub(super) type PersistedStandings = HashMap<[u8; 16], Vec<PersistedStanding>>;

/// A sweep in progress: its one copy of the list, and every key it covers.
struct Sweep {
    rows: VecDeque<LiveTransportBinding>,
    listed: HashSet<String>,
}

/// The pass's own state. Only the pass holding the flight touches it.
#[derive(Default)]
struct Walk {
    cursors: BindingCursors,
    last_read: Option<Instant>,
    pending: VecDeque<String>,
    queued: HashSet<String>,
    sweep: Option<Sweep>,
    swept_at: Option<Instant>,
    /// The next sweep cannot wait: a revocation named no key.
    sweep_now: bool,
    unproven: HashMap<String, Instant>,
    /// Where each key stands in the table.
    homes: HashMap<String, [u8; 16]>,
}

impl Walk {
    fn queue(&mut self, key: String) {
        if self.queued.insert(key.clone()) {
            self.pending.push_back(key);
        }
    }

    fn holds(&self, key: &str) -> bool {
        self.homes.contains_key(key) || self.unproven.contains_key(key)
    }

    fn sweep_due(&self, now: Instant) -> bool {
        self.sweep.is_none()
            && (self.sweep_now
                || self
                    .swept_at
                    .is_none_or(|at| now.saturating_duration_since(at) >= SWEEP_EVERY))
    }
}

/// How a pass ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PassEnd {
    /// Nothing is waiting.
    Done,
    /// The budget ran out with work left; the next pass carries on from there.
    OutOfBudget,
    /// A read the store did not serve: nobody stands until one is served.
    Failed,
    /// Cut at [`PASS_BOUND`].
    Cut,
    /// Another pass holds the flight.
    Skipped,
}

/// The persisted standing and the one pass allowed to refresh it.
#[derive(Default)]
pub(crate) struct StandingRefresh {
    /// The table the event path reads.
    pub(super) table: RwLock<PersistedStandings>,
    running: AtomicBool,
    walk: tokio::sync::Mutex<Walk>,
    wanted: std::sync::Mutex<Wanted>,
}

/// Peers a send found no address for, and those whose route has since landed.
#[derive(Default)]
struct Wanted {
    peers: HashMap<String, std::time::Instant>,
    landed: Vec<String>,
}

/// Peers remembered as wanted. A full set drops the oldest half: the only cost
/// of forgetting one is its next probe re-noting it.
const WANTED_TRACKED: usize = 1_024;

/// Holds the single flight; a cut or panicking pass gives it back.
struct Flight<'a>(&'a AtomicBool);

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl StandingRefresh {
    /// A send found no address for `key`. The no-route backoff now paces its
    /// retries, so its path ask must not wait on them: the cursors below see
    /// its route row land.
    pub(super) fn note_unaddressed(&self, key: &str) {
        let mut wanted = self.wanted.lock().unwrap_or_else(PoisonError::into_inner);
        if wanted.peers.len() >= WANTED_TRACKED && !wanted.peers.contains_key(key) {
            let mut ages: Vec<std::time::Instant> = wanted.peers.values().copied().collect();
            ages.sort_unstable();
            let cut = ages[ages.len() / 2];
            wanted.peers.retain(|_, at| *at > cut);
        }
        wanted
            .peers
            .insert(key.to_owned(), std::time::Instant::now());
    }

    /// Wanted peers whose route row landed since the last call.
    pub(super) fn take_landed(&self) -> Vec<String> {
        std::mem::take(
            &mut self
                .wanted
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .landed,
        )
    }

    fn note_route_landed(&self, key: &str) {
        let mut wanted = self.wanted.lock().unwrap_or_else(PoisonError::into_inner);
        if wanted.peers.remove(key).is_some() {
            wanted.landed.push(key.to_owned());
        }
    }

    /// One tick's pass. Single-flight and bounded: see the module docs.
    pub(crate) async fn pass(
        self: Arc<Self>,
        rooting: Arc<dyn RootingDirectory>,
        policy: HybridPolicy,
        metrics: Option<crate::observability::EdgeMetrics>,
    ) -> PassEnd {
        let book = |label: &'static str, n: u64| {
            if let Some(m) = &metrics {
                m.add_persisted_standing(label, n);
            }
        };
        if self
            .running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            book(obs::PERSISTED_STANDING_PASSES_SKIPPED, 1);
            tracing::debug!("persisted standing: the last pass is still running, tick skipped");
            return PassEnd::Skipped;
        }
        let _flight = Flight(&self.running);
        let began = Instant::now();
        let deadline = began + PASS_BUDGET;
        let cut = tokio::time::timeout(
            PASS_BOUND,
            self.run_pass(rooting.as_ref(), policy, deadline, &book),
        )
        .await;
        let end = cut.unwrap_or(PassEnd::Cut);
        book(obs::PERSISTED_STANDING_PASSES, 1);
        book(
            obs::PERSISTED_STANDING_PASS_MS,
            u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX),
        );
        match end {
            PassEnd::Cut => {
                book(obs::PERSISTED_STANDING_PASSES_CUT, 1);
                tracing::warn!(
                    bound_secs = PASS_BOUND.as_secs(),
                    "persisted standing: a directory read outlasted the pass bound; the pass is \
                     cut and the next tick carries on"
                );
            }
            PassEnd::Failed => book(obs::PERSISTED_STANDING_READ_FAILURES, 1),
            PassEnd::Done | PassEnd::OutOfBudget | PassEnd::Skipped => {}
        }
        end
    }

    /// A listener's start: passes back to back until the first sweep is done,
    /// so standing is not rationed by the tick while it is empty. Still one at
    /// a time; a tick landing meanwhile is skipped.
    pub(crate) async fn boot(
        self: Arc<Self>,
        rooting: Arc<dyn RootingDirectory>,
        policy: HybridPolicy,
        metrics: Option<crate::observability::EdgeMetrics>,
    ) {
        while Arc::clone(&self)
            .pass(Arc::clone(&rooting), policy, metrics.clone())
            .await
            == PassEnd::OutOfBudget
        {}
    }

    /// Tests: the sweep timer runs out now.
    #[cfg(test)]
    pub(crate) async fn force_sweep_for_test(&self) {
        self.walk.lock().await.sweep_now = true;
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, PersistedStandings> {
        self.table.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// The memo of what `key` was proven to be, while it stands.
    fn known(&self, walk: &Walk, key: &str) -> Option<bool> {
        let home = walk.homes.get(key)?;
        self.table
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(home)?
            .iter()
            .find(|b| b.key_id == key)
            .map(|b| b.rooted)
    }

    fn remove(&self, walk: &mut Walk, key: &str) {
        let Some(home) = walk.homes.remove(key) else {
            return;
        };
        let mut table = self.write();
        if let Some(bindings) = table.get_mut(&home) {
            bindings.retain(|b| b.key_id != key);
            if bindings.is_empty() {
                table.remove(&home);
            }
        }
    }

    fn install(&self, walk: &mut Walk, identity: [u8; 16], key: String, rooted: bool) {
        self.remove(walk, &key);
        walk.homes.insert(key.clone(), identity);
        self.write()
            .entry(identity)
            .or_default()
            .push(PersistedStanding {
                key_id: key,
                rooted,
            });
    }

    /// Nobody, until the next read: a failed read vouches for nothing.
    fn forget_all(&self, walk: &mut Walk) {
        self.write().clear();
        *walk = Walk::default();
    }

    /// Judge one row. `changed`: the row may have moved under what is
    /// remembered of it, so neither memo answers.
    async fn judge(
        &self,
        walk: &mut Walk,
        rooting: &dyn RootingDirectory,
        policy: HybridPolicy,
        row: &LiveTransportBinding,
        changed: bool,
    ) {
        // The identity must be the one this destination is derived from.
        let Some(identity) = (named_dest_of_transport(&row.transport_pubkey64)
            == Some(row.dest_hash))
        .then(|| identity_of_transport(&row.transport_pubkey64))
        .flatten() else {
            self.remove(walk, &row.key_id);
            return;
        };
        let key = &row.key_id;
        let now = Instant::now();
        if !changed && walk.unproven.get(key).is_some_and(|until| *until > now) {
            return;
        }
        let known = if changed { None } else { self.known(walk, key) };
        let rooted = match known {
            Some(rooted) => rooted,
            None => {
                let rooted = matches!(row.provenance, BindingProvenance::Rooted)
                    && store_claim_roots_here(rooting, key, policy).await;
                if !rooted
                    && !rooting
                        .hybrid_transport_binding_exists(key, row.dest_hash)
                        .await
                {
                    walk.unproven.insert(key.clone(), now + UNPROVEN_TTL);
                    self.remove(walk, key);
                    return;
                }
                rooted
            }
        };
        // Read last, and only for a row that proved something: the fold and
        // the revocations are a read each, and a row that proved nothing is
        // not in the table for them to take out.
        if rooting.binding_stands(row).await {
            walk.unproven.remove(key);
            self.install(walk, identity, key.clone(), rooted);
        } else {
            self.remove(walk, key);
        }
    }

    /// Everything a change names about `key`, read fresh.
    async fn rejudge(
        &self,
        walk: &mut Walk,
        rooting: &dyn RootingDirectory,
        policy: HybridPolicy,
        key: &str,
    ) {
        if let Some(sweep) = &mut walk.sweep {
            sweep.listed.insert(key.to_owned());
        }
        let Ok(rows) = rooting.live_bindings_of(key).await else {
            // Fail closed, and let the sweep bring it back.
            self.remove(walk, key);
            return;
        };
        if rows.is_empty() {
            self.remove(walk, key);
            walk.unproven.remove(key);
        }
        for row in &rows {
            self.judge(walk, rooting, policy, row, true).await;
        }
    }

    async fn run_pass(
        &self,
        rooting: &dyn RootingDirectory,
        policy: HybridPolicy,
        deadline: Instant,
        book: &(impl Fn(&'static str, u64) + Sync),
    ) -> PassEnd {
        let mut guard = self.walk.lock().await;
        let walk = &mut *guard;
        let now = Instant::now();
        if walk
            .last_read
            .is_some_and(|at| now.saturating_duration_since(at) >= STALE_AFTER)
        {
            tracing::warn!(
                after_secs = STALE_AFTER.as_secs(),
                "persisted standing: no change read landed in this long, so a revocation could \
                 not have reached this table: nobody stands until one does"
            );
            self.forget_all(walk);
        }
        if walk.cursors.routes.is_none() {
            let lag =
                chrono::Duration::from_std(CURSOR_LAG).unwrap_or_else(|_| chrono::Duration::zero());
            let from = chrono::Utc::now() - lag;
            walk.cursors = BindingCursors {
                routes: Some((from, String::new())),
                attestations: Some((from, String::new())),
            };
        }
        // What changed.
        while walk.pending.len() < MAX_PENDING {
            let mut cursors = walk.cursors.clone();
            let changes = match rooting.binding_changes(&mut cursors, CHANGE_PAGE).await {
                Ok(changes) => changes,
                Err(error) => {
                    tracing::warn!(%error, "persisted standing: changes could not be read; none stand this pass");
                    self.forget_all(walk);
                    return PassEnd::Failed;
                }
            };
            walk.cursors = cursors;
            walk.last_read = Some(Instant::now());
            walk.sweep_now |= changes.whole;
            for key in changes.routes {
                self.note_route_landed(&key);
                walk.queue(key);
            }
            for key in changes.subjects {
                if walk.holds(&key) {
                    walk.queue(key);
                }
            }
            if changes.drained || Instant::now() >= deadline {
                break;
            }
        }
        while let Some(key) = walk.pending.front().cloned() {
            if Instant::now() >= deadline {
                return PassEnd::OutOfBudget;
            }
            self.rejudge(walk, rooting, policy, &key).await;
            walk.pending.pop_front();
            walk.queued.remove(&key);
            book(obs::PERSISTED_STANDING_CHANGES_JUDGED, 1);
        }
        // The sweep behind.
        if walk.sweep_due(Instant::now()) {
            let rows = match rooting.live_binding_rows().await {
                Ok(rows) => rows,
                Err(error) => {
                    tracing::warn!(%error, "persisted standing could not be read; none this pass");
                    self.forget_all(walk);
                    return PassEnd::Failed;
                }
            };
            book(obs::PERSISTED_STANDING_SWEEPS, 1);
            walk.sweep_now = false;
            walk.swept_at = Some(Instant::now());
            walk.sweep = Some(Sweep {
                listed: rows.iter().map(|r| r.key_id.clone()).collect(),
                rows: rows.into(),
            });
        }
        loop {
            let Some(row) = walk.sweep.as_ref().and_then(|s| s.rows.front().cloned()) else {
                break;
            };
            if Instant::now() >= deadline {
                return PassEnd::OutOfBudget;
            }
            self.judge(walk, rooting, policy, &row, false).await;
            if let Some(sweep) = &mut walk.sweep {
                sweep.rows.pop_front();
            }
            book(obs::PERSISTED_STANDING_ROWS_WALKED, 1);
        }
        if let Some(sweep) = walk.sweep.take() {
            // A row the list no longer holds stops counting, and takes its
            // memo with it: both stay bounded by the rows that exist.
            let gone: Vec<String> = walk
                .homes
                .keys()
                .filter(|k| !sweep.listed.contains(*k))
                .cloned()
                .collect();
            for key in gone {
                self.remove(walk, &key);
            }
            let swept_now = Instant::now();
            walk.unproven
                .retain(|k, until| *until > swept_now && sweep.listed.contains(k));
        }
        PassEnd::Done
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::{BindingChanges, RootingVerdict};
    use ciris_persist::federation::rooting::{ProvenanceChain, RootingRejection};
    use ciris_persist::federation::self_at_login::BindingProvenance::{Advisory, Rooted};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// A directory scripted by row, counting what a pass costs and how many
    /// reads ran at once.
    #[derive(Default)]
    struct Rows {
        live: Mutex<Vec<LiveTransportBinding>>,
        signed: Mutex<Vec<String>>,
        revoked: Mutex<Vec<String>>,
        rooted: Mutex<Vec<String>>,
        changes: Mutex<VecDeque<BindingChanges>>,
        read_fails: AtomicBool,
        /// Every read takes this long.
        latency: Mutex<Duration>,
        /// `live_binding_rows` never answers.
        list_hangs: AtomicBool,
        /// `binding_changes` never answers.
        changes_hang: AtomicBool,
        lists: AtomicUsize,
        walks: AtomicUsize,
        stands: AtomicUsize,
        in_flight: AtomicUsize,
        most_in_flight: AtomicUsize,
    }

    impl Rows {
        async fn cost(&self) {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.most_in_flight.fetch_max(now, Ordering::SeqCst);
            let latency = *self.latency.lock().unwrap();
            if !latency.is_zero() {
                tokio::time::sleep(latency).await;
            }
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl RootingDirectory for Rows {
        async fn root_binding(&self, key_id: &str, _claimed: &str) -> RootingVerdict {
            self.cost().await;
            if self.rooted.lock().unwrap().iter().any(|k| k == key_id) {
                return RootingVerdict::Confirmed {
                    chain: test_chain(),
                };
            }
            RootingVerdict::Rejected {
                rejection: RootingRejection::UnknownKeyId {
                    key_id: key_id.to_owned(),
                },
            }
        }
        async fn provenance_chain(
            &self,
            key_id: &str,
        ) -> Result<ProvenanceChain, RootingRejection> {
            Err(RootingRejection::UnknownKeyId {
                key_id: key_id.to_owned(),
            })
        }
        async fn registered_pubkey_ed25519_base64(&self, _key_id: &str) -> Option<String> {
            Some("registered".to_owned())
        }
        async fn hybrid_transport_binding_exists(
            &self,
            key_id: &str,
            _dest_hash: [u8; 16],
        ) -> bool {
            self.walks.fetch_add(1, Ordering::SeqCst);
            self.cost().await;
            self.signed.lock().unwrap().iter().any(|k| k == key_id)
        }
        async fn live_binding_rows(&self) -> Result<Vec<LiveTransportBinding>, String> {
            self.lists.fetch_add(1, Ordering::SeqCst);
            if self.list_hangs.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            self.cost().await;
            if self.read_fails.load(Ordering::SeqCst) {
                return Err("down".to_owned());
            }
            Ok(self.live.lock().unwrap().clone())
        }
        async fn live_bindings_of(
            &self,
            key_id: &str,
        ) -> Result<Vec<LiveTransportBinding>, String> {
            self.cost().await;
            Ok(self
                .live
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.key_id == key_id)
                .cloned()
                .collect())
        }
        async fn binding_stands(&self, row: &LiveTransportBinding) -> bool {
            self.stands.fetch_add(1, Ordering::SeqCst);
            self.cost().await;
            !self.revoked.lock().unwrap().contains(&row.key_id)
        }
        async fn binding_changes(
            &self,
            _cursors: &mut BindingCursors,
            _page: u32,
        ) -> Result<BindingChanges, String> {
            if self.changes_hang.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            if self.read_fails.load(Ordering::SeqCst) {
                return Err("down".to_owned());
            }
            let mut next = self.changes.lock().unwrap().pop_front().unwrap_or_default();
            next.drained = true;
            Ok(next)
        }
    }

    fn test_chain() -> ProvenanceChain {
        ProvenanceChain {
            key_id: "subject".to_owned(),
            chain: Vec::new(),
            terminates_at_steward_bootstrap: true,
        }
    }

    fn row(key: &str, seed: u8, provenance: BindingProvenance) -> LiveTransportBinding {
        let pk = leviculum_core::Identity::from_private_key_bytes(&[seed; 64])
            .expect("an identity")
            .public_key_bytes();
        LiveTransportBinding {
            key_id: key.to_owned(),
            dest_hash: named_dest_of_transport(&pk).expect("a destination"),
            transport_pubkey64: pk,
            provenance,
        }
    }

    fn many(n: usize) -> Vec<LiveTransportBinding> {
        (0..n)
            .map(|i| {
                let mut r = row(&format!("key-{i}"), 7, Advisory);
                // Rows the pure identity check passes: the same identity under
                // many keys is what a claimant flood looks like.
                r.provenance = Advisory;
                r
            })
            .collect()
    }

    fn keys(refresh: &StandingRefresh) -> Vec<String> {
        let mut keys: Vec<String> = refresh
            .table
            .read()
            .unwrap()
            .values()
            .flatten()
            .map(|b| b.key_id.clone())
            .collect();
        keys.sort();
        keys
    }

    const POLICY: HybridPolicy = HybridPolicy::Ed25519Fallback;

    /// `span` of ordinary 30 s ticks: the change read stays fresh throughout.
    async fn ticks(refresh: &Arc<StandingRefresh>, dir: &Arc<Rows>, span: Duration) {
        let tick = Duration::from_secs(30);
        let mut left = span;
        while !left.is_zero() {
            tokio::time::advance(tick).await;
            pass(refresh, dir).await;
            left = left.saturating_sub(tick);
        }
    }

    async fn pass(refresh: &Arc<StandingRefresh>, dir: &Arc<Rows>) -> PassEnd {
        let dir: Arc<dyn RootingDirectory> = dir.clone();
        Arc::clone(refresh).pass(dir, POLICY, None).await
    }

    async fn boot(refresh: &Arc<StandingRefresh>, dir: &Arc<Rows>) {
        let dir: Arc<dyn RootingDirectory> = dir.clone();
        Arc::clone(refresh).boot(dir, POLICY, None).await;
    }

    #[tokio::test(start_paused = true)]
    async fn only_a_proven_binding_counts_and_a_gone_row_stops_counting() {
        let mut wrong = row("mismatched", 4, Advisory);
        wrong.dest_hash = [0xee; 16];
        let dir = Arc::new(Rows::default());
        *dir.live.lock().unwrap() = vec![
            row("announced", 1, Advisory),
            row("self-claimed-rooted", 2, Rooted),
            row("signed", 3, Advisory),
            wrong,
        ];
        *dir.signed.lock().unwrap() = vec!["signed".to_owned(), "mismatched".to_owned()];
        let refresh = Arc::new(StandingRefresh::default());
        assert_eq!(pass(&refresh, &dir).await, PassEnd::Done);
        assert_eq!(keys(&refresh), ["signed"]);
        assert!(
            !refresh
                .table
                .read()
                .unwrap()
                .values()
                .flatten()
                .any(|b| b.rooted),
            "a row's own Rooted is not a chain"
        );

        // Retired, revoked or superseded: the list stops holding it.
        dir.live.lock().unwrap().clear();
        ticks(&refresh, &dir, SWEEP_EVERY).await;
        assert!(keys(&refresh).is_empty(), "the memo keeps nothing alive");
    }

    #[tokio::test]
    async fn a_directory_that_cannot_be_read_leaves_nobody_standing() {
        let dir = Arc::new(Rows::default());
        *dir.live.lock().unwrap() = vec![row("signed", 3, Advisory)];
        *dir.signed.lock().unwrap() = vec!["signed".to_owned()];
        let refresh = Arc::new(StandingRefresh::default());
        pass(&refresh, &dir).await;
        assert_eq!(keys(&refresh), ["signed"]);
        dir.read_fails.store(true, Ordering::SeqCst);
        assert_eq!(pass(&refresh, &dir).await, PassEnd::Failed);
        assert!(keys(&refresh).is_empty());
    }

    /// The heap slope: a slow directory held a pass past its tick and the next
    /// one started beside it. One runs, the rest are skipped, and the skips
    /// are what the counter reads.
    #[tokio::test(start_paused = true)]
    async fn a_held_pass_cannot_stack() {
        let dir = Arc::new(Rows::default());
        *dir.live.lock().unwrap() = many(2_000);
        *dir.latency.lock().unwrap() = Duration::from_millis(50);
        let refresh = Arc::new(StandingRefresh::default());
        let metrics = crate::observability::EdgeMetrics::default();
        let mut passes = Vec::new();
        for _ in 0..40 {
            let rooting: Arc<dyn RootingDirectory> = dir.clone();
            passes.push(tokio::spawn(Arc::clone(&refresh).pass(
                rooting,
                POLICY,
                Some(metrics.clone()),
            )));
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        let mut skipped = 0;
        for p in passes {
            if p.await.unwrap() == PassEnd::Skipped {
                skipped += 1;
            }
        }
        assert_eq!(
            dir.most_in_flight.load(Ordering::SeqCst),
            1,
            "one directory read at a time: a pass never stacks on a pass"
        );
        assert!(skipped > 0, "ticks landed on a running pass");
        let ledger = metrics.persisted_standing();
        assert_eq!(
            ledger.get(obs::PERSISTED_STANDING_PASSES_SKIPPED).copied(),
            Some(skipped),
            "the skips are counted"
        );
        assert_eq!(
            dir.lists.load(Ordering::SeqCst),
            1,
            "one list, however many ticks: the memory a sweep holds is one copy"
        );
    }

    /// A pass stops at its budget however much is left, and the sweep ends
    /// over later passes without listing again.
    #[tokio::test(start_paused = true)]
    async fn a_pass_stops_at_its_budget_and_the_sweep_resumes() {
        let dir = Arc::new(Rows::default());
        *dir.live.lock().unwrap() = many(1_000);
        *dir.signed.lock().unwrap() = (0..1_000).map(|i| format!("key-{i}")).collect();
        *dir.latency.lock().unwrap() = Duration::from_millis(50);
        let refresh = Arc::new(StandingRefresh::default());
        let began = Instant::now();
        assert_eq!(pass(&refresh, &dir).await, PassEnd::OutOfBudget);
        assert!(
            began.elapsed() <= PASS_BUDGET + Duration::from_secs(1),
            "took {:?}",
            began.elapsed()
        );
        let first = keys(&refresh).len();
        assert!(first > 0 && first < 1_000, "partial: {first}");
        let mut rounds = 1;
        while pass(&refresh, &dir).await == PassEnd::OutOfBudget {
            rounds += 1;
            assert!(rounds < 20, "it finishes");
        }
        assert_eq!(keys(&refresh).len(), 1_000);
        assert_eq!(
            dir.lists.load(Ordering::SeqCst),
            1,
            "resumed, not restarted"
        );
    }

    /// A read that never answers cannot hold the flight past the bound.
    #[tokio::test(start_paused = true)]
    async fn a_read_that_never_answers_is_cut_at_the_bound() {
        let dir = Arc::new(Rows::default());
        dir.list_hangs.store(true, Ordering::SeqCst);
        let refresh = Arc::new(StandingRefresh::default());
        let began = Instant::now();
        assert_eq!(pass(&refresh, &dir).await, PassEnd::Cut);
        assert_eq!(began.elapsed(), PASS_BOUND);
        assert_ne!(
            pass(&refresh, &dir).await,
            PassEnd::Skipped,
            "a cut pass gives the flight back"
        );
    }

    /// An empty tick reads the changes and nothing else, whatever the table
    /// holds. This is the cost that replaced the walk.
    #[tokio::test(start_paused = true)]
    async fn a_tick_with_no_change_walks_nothing() {
        let dir = Arc::new(Rows::default());
        *dir.live.lock().unwrap() = many(500);
        *dir.signed.lock().unwrap() = (0..250).map(|i| format!("key-{i}")).collect();
        let refresh = Arc::new(StandingRefresh::default());
        boot(&refresh, &dir).await;
        assert_eq!(keys(&refresh).len(), 250);
        let (walks, stands) = (
            dir.walks.load(Ordering::SeqCst),
            dir.stands.load(Ordering::SeqCst),
        );
        for _ in 0..5 {
            tokio::time::advance(Duration::from_secs(30)).await;
            assert_eq!(pass(&refresh, &dir).await, PassEnd::Done);
        }
        assert_eq!(dir.walks.load(Ordering::SeqCst), walks);
        assert_eq!(dir.stands.load(Ordering::SeqCst), stands);
        assert_eq!(dir.lists.load(Ordering::SeqCst), 1);
    }

    /// A failure is memoised past a sweep, and a change naming the key ends
    /// the memo: standing on the very next pass, not at the expiry.
    #[tokio::test(start_paused = true)]
    async fn a_failed_row_is_not_rewalked_and_a_change_ends_its_memo() {
        let dir = Arc::new(Rows::default());
        *dir.live.lock().unwrap() = vec![row("late", 5, Advisory)];
        let refresh = Arc::new(StandingRefresh::default());
        assert_eq!(pass(&refresh, &dir).await, PassEnd::Done);
        assert!(keys(&refresh).is_empty());
        assert_eq!(dir.walks.load(Ordering::SeqCst), 1);

        // The next sweep leaves it alone.
        ticks(&refresh, &dir, SWEEP_EVERY).await;
        assert_eq!(dir.lists.load(Ordering::SeqCst), 2, "a sweep ran");
        assert_eq!(
            dir.walks.load(Ordering::SeqCst),
            1,
            "and did not re-walk the row"
        );

        // The route it needed lands.
        dir.signed.lock().unwrap().push("late".to_owned());
        dir.changes.lock().unwrap().push_back(BindingChanges {
            routes: vec!["late".to_owned()],
            ..Default::default()
        });
        pass(&refresh, &dir).await;
        assert_eq!(keys(&refresh), ["late"], "within one pass of the change");
    }

    /// The expiry is the backstop for what no change names.
    #[tokio::test(start_paused = true)]
    async fn an_unproven_row_is_walked_again_past_its_expiry() {
        let dir = Arc::new(Rows::default());
        *dir.live.lock().unwrap() = vec![row("late", 5, Advisory)];
        let refresh = Arc::new(StandingRefresh::default());
        pass(&refresh, &dir).await;
        dir.signed.lock().unwrap().push("late".to_owned());
        // Short of its expiry, a sweep leaves it unproven.
        ticks(&refresh, &dir, SWEEP_EVERY).await;
        assert!(keys(&refresh).is_empty(), "memoised");
        ticks(&refresh, &dir, UNPROVEN_TTL + SWEEP_EVERY).await;
        assert_eq!(keys(&refresh), ["late"]);
    }

    /// A key that lands or a delegation names a subject: one this table
    /// remembers is judged again, one it has never met costs nothing.
    #[tokio::test(start_paused = true)]
    async fn a_landing_key_rejudges_only_what_the_table_remembers() {
        let dir = Arc::new(Rows::default());
        *dir.live.lock().unwrap() = vec![row("claimed", 6, Rooted)];
        let refresh = Arc::new(StandingRefresh::default());
        pass(&refresh, &dir).await;
        assert!(keys(&refresh).is_empty());
        let walks = dir.walks.load(Ordering::SeqCst);
        dir.rooted.lock().unwrap().push("claimed".to_owned());
        dir.changes.lock().unwrap().push_back(BindingChanges {
            subjects: vec!["claimed".to_owned(), "a-stranger".to_owned()],
            ..Default::default()
        });
        pass(&refresh, &dir).await;
        assert_eq!(keys(&refresh), ["claimed"]);
        assert!(
            refresh
                .table
                .read()
                .unwrap()
                .values()
                .flatten()
                .all(|b| b.rooted),
            "its chain roots here now"
        );
        assert_eq!(
            dir.walks.load(Ordering::SeqCst),
            walks,
            "no stranger walked"
        );
    }

    /// A revocation reaches the table on the next tick, with no sweep.
    #[tokio::test(start_paused = true)]
    async fn a_revocation_drops_the_key_on_the_next_pass() {
        let dir = Arc::new(Rows::default());
        *dir.live.lock().unwrap() = vec![row("signed", 3, Advisory)];
        *dir.signed.lock().unwrap() = vec!["signed".to_owned()];
        let refresh = Arc::new(StandingRefresh::default());
        pass(&refresh, &dir).await;
        assert_eq!(keys(&refresh), ["signed"]);
        dir.revoked.lock().unwrap().push("signed".to_owned());
        dir.changes.lock().unwrap().push_back(BindingChanges {
            subjects: vec!["signed".to_owned()],
            ..Default::default()
        });
        tokio::time::advance(Duration::from_secs(30)).await;
        pass(&refresh, &dir).await;
        assert!(keys(&refresh).is_empty());
        assert_eq!(dir.lists.load(Ordering::SeqCst), 1, "no sweep needed");
    }

    /// A revocation that names no key cannot be pinned, so the sweep comes now.
    #[tokio::test(start_paused = true)]
    async fn a_revocation_naming_no_key_sweeps_now() {
        let dir = Arc::new(Rows::default());
        *dir.live.lock().unwrap() = vec![row("signed", 3, Advisory)];
        *dir.signed.lock().unwrap() = vec!["signed".to_owned()];
        let refresh = Arc::new(StandingRefresh::default());
        pass(&refresh, &dir).await;
        dir.revoked.lock().unwrap().push("signed".to_owned());
        dir.changes.lock().unwrap().push_back(BindingChanges {
            whole: true,
            ..Default::default()
        });
        pass(&refresh, &dir).await;
        assert_eq!(dir.lists.load(Ordering::SeqCst), 2);
        assert!(keys(&refresh).is_empty());
    }

    /// The late joiner: a peer a send found no address for is handed to the
    /// path ask when its route lands, and once. Anyone else's route is not.
    #[tokio::test(start_paused = true)]
    async fn a_wanted_peers_landing_route_is_handed_to_the_path_ask() {
        let dir = Arc::new(Rows::default());
        let refresh = Arc::new(StandingRefresh::default());
        pass(&refresh, &dir).await;
        refresh.note_unaddressed("late-joiner");
        assert!(refresh.take_landed().is_empty(), "no route yet");
        dir.changes.lock().unwrap().push_back(BindingChanges {
            routes: vec!["late-joiner".to_owned(), "anyone-else".to_owned()],
            ..Default::default()
        });
        pass(&refresh, &dir).await;
        assert_eq!(refresh.take_landed(), ["late-joiner"]);
        assert!(refresh.take_landed().is_empty(), "handed over once");
    }

    /// A pass cut for slowness keeps the table: a busy store is not a failed
    /// read. But a table no change read has reached in this long is one a
    /// revocation cannot reach either.
    #[tokio::test(start_paused = true)]
    async fn a_table_that_stops_being_read_is_forgotten() {
        let dir = Arc::new(Rows::default());
        *dir.live.lock().unwrap() = vec![row("signed", 3, Advisory)];
        *dir.signed.lock().unwrap() = vec!["signed".to_owned()];
        let refresh = Arc::new(StandingRefresh::default());
        pass(&refresh, &dir).await;
        assert_eq!(keys(&refresh), ["signed"]);
        dir.changes_hang.store(true, Ordering::SeqCst);
        assert_eq!(pass(&refresh, &dir).await, PassEnd::Cut);
        assert_eq!(keys(&refresh), ["signed"], "slow is not failed");
        tokio::time::advance(STALE_AFTER).await;
        assert_eq!(pass(&refresh, &dir).await, PassEnd::Cut);
        assert!(keys(&refresh).is_empty());
    }
}
