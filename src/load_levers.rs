//! **The host's shed levers** (`FSD/CIRIS_MESH.md` §7.7; Eric 2026-11-06).
//!
//! Edge implements the gauges and the levers; the server reads and pulls them
//! in concert with the rest of its own. Nothing here decides anything: with no
//! host pulling, every lever sits at 0 and the node serves its whole role.
//!
//! Three rules hold for every lever, and are why this is one small type:
//!
//! - **A lever is not a scram.** It moves one step at a time, at most one step
//!   up per [`RAISE_STEP`] and one down per [`RELEASE_STEP`], and each step
//!   halves a cost rather than ending it. v44's forwarding close is the
//!   counter-example: one refused dial became 48 retries.
//! - **A lever is a lease.** A pull holds for its lease and no longer. A dead
//!   or wedged server stops renewing, and the lever walks back to 0 on its
//!   own. The node falls back to serving.
//! - **Nothing a lever touches is refused.** Levers lengthen an interval,
//!   shorten a page or queue a pull; none answers anyone with a no. So nothing
//!   a lever does can be retried, and a release leaves no backlog of re-dials.
//!
//! What stays served at every level is the minimum viable role, and no lever
//! can name it: forwarding, subject Pulls, announces, and the rounds of
//! [`EnvelopeKind::walk_stretches`] false. A round owed to a peer
//! ([`PeerObligation`]) keeps its cadence too.
//!
//! The clock is tokio's, so a paused runtime can drive a lease in a test, and
//! it works outside a runtime too.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::time::Instant;

use crate::load_ladder::{PeerObligation, PeerObligations};
use crate::replication::EnvelopeKind;

/// The top step of every lever. Each step halves a cost, so the top is ⅛.
pub const MAX_LEVEL: u8 = 3;
/// Levers rise no faster than one step in this.
pub const RAISE_STEP: Duration = Duration::from_secs(10);
/// Levers fall no faster than one step in this: a default round cadence, so
/// every coordinator takes one interval at each step on the way down.
pub const RELEASE_STEP: Duration = Duration::from_secs(30);
/// The longest lease a pull can hold. A host renews; it never sets and leaves.
pub const LEASE_MAX: Duration = Duration::from_secs(300);
/// The smallest Attestation page the `page` lever leaves: fewer rows than this
/// would cost more rounds than it saved.
pub const PAGE_FLOOR: u32 = 32;

/// One of the host's levers. See `FSD/CIRIS_MESH.md` §7.7 for what each costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShedLever {
    /// The anti-entropy walk: cadence ticks of the planes
    /// [`EnvelopeKind::walk_stretches`] names, toward peers owed nothing, run
    /// at ×2 per level. Kicks are untouched.
    Walk,
    /// The Attestation advertise page, ½ per level, down to [`PAGE_FLOOR`].
    Page,
    /// The blob puller's concurrent pulls, ½ per level, never below one, and
    /// the durability pass at ×2 per level.
    Bulk,
}

impl ShedLever {
    /// Every lever.
    pub const ALL: [Self; 3] = [Self::Walk, Self::Page, Self::Bulk];

    /// The stable token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Walk => "walk",
            Self::Page => "page",
            Self::Bulk => "bulk",
        }
    }

    /// From its token.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|l| s.trim().eq_ignore_ascii_case(l.token()))
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Why a lever's level moved.
pub const LEVER_CAUSES: [&str; 3] = ["host", "released", "lease_expired"];

/// The `lever:cause` keys of `load_lever_changes_total`.
#[must_use]
pub fn lever_change_keys() -> Vec<String> {
    let mut out = Vec::with_capacity(ShedLever::ALL.len() * LEVER_CAUSES.len());
    for lever in ShedLever::ALL {
        for cause in LEVER_CAUSES {
            out.push(format!("{}:{cause}", lever.token()));
        }
    }
    out
}

/// One lever's lease. Pure: every read names the time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Lease {
    level: u8,
    want: u8,
    until_ms: u64,
    down_at_ms: u64,
    next_raise_ms: u64,
}

impl Lease {
    /// Walk `level` down to what the lease still asks for, one step per
    /// `release_ms`. A live lease at its level holds.
    fn settle(&mut self, now_ms: u64, release_ms: u64) {
        let want = if now_ms < self.until_ms { self.want } else { 0 };
        while self.level > want && now_ms >= self.down_at_ms {
            self.level -= 1;
            self.down_at_ms = self.down_at_ms.saturating_add(release_ms.max(1));
        }
    }

    /// The host asks for `level` for `lease_ms`. Raising takes one step per
    /// `raise_ms`; a pull below the level starts the paced walk down, and a
    /// renewal of that lower ask does not restart it.
    fn pull(&mut self, now_ms: u64, level: u8, lease_ms: u64, raise_ms: u64, release_ms: u64) {
        self.settle(now_ms, release_ms);
        self.want = level;
        self.until_ms = now_ms.saturating_add(lease_ms);
        if level > self.level && now_ms >= self.next_raise_ms {
            self.level += 1;
            self.next_raise_ms = now_ms.saturating_add(raise_ms);
        }
        if level >= self.level {
            self.down_at_ms = self.until_ms;
        } else {
            self.down_at_ms = self.down_at_ms.min(now_ms.saturating_add(release_ms));
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Slot {
    lease: Lease,
    told: u8,
}

/// A lever as a host reads it.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LeverStatus {
    /// The lever's token.
    pub lever: String,
    /// The level in force.
    pub level: u8,
    /// The level the host asks for; 0 once the lease is out.
    pub want: u8,
    /// Milliseconds left on the lease.
    pub lease_ms_left: u64,
}

/// A node's levers. One per metrics bag, so the scheduler, the bridge and the
/// puller read the set a host pulls without being handed it.
pub struct LoadLevers {
    epoch: Instant,
    slots: Mutex<[Slot; ShedLever::ALL.len()]>,
    raise_ms: AtomicU64,
    release_ms: AtomicU64,
    changes: Mutex<HashMap<String, u64>>,
    obligations: OnceLock<Arc<dyn PeerObligations>>,
}

impl std::fmt::Debug for LoadLevers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadLevers").finish_non_exhaustive()
    }
}

impl Default for LoadLevers {
    fn default() -> Self {
        Self {
            epoch: Instant::now(),
            slots: Mutex::new([Slot::default(); ShedLever::ALL.len()]),
            raise_ms: AtomicU64::new(millis(RAISE_STEP)),
            release_ms: AtomicU64::new(millis(RELEASE_STEP)),
            changes: Mutex::new(HashMap::new()),
            obligations: OnceLock::new(),
        }
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

impl LoadLevers {
    /// The pacing, for a harness that cannot wait out the real steps.
    pub fn set_steps(&self, raise: Duration, release: Duration) {
        self.raise_ms.store(millis(raise), Ordering::Relaxed);
        self.release_ms.store(millis(release), Ordering::Relaxed);
    }

    /// Install what the walk reads of a peer. With none, every peer is
    /// [`PeerObligation::Unresolved`], and no round stretches.
    pub fn install_obligations(&self, reader: Arc<dyn PeerObligations>) {
        let _ = self.obligations.set(reader);
    }

    fn now_ms(&self) -> u64 {
        millis(Instant::now().duration_since(self.epoch))
    }

    fn release(&self) -> u64 {
        self.release_ms.load(Ordering::Relaxed)
    }

    fn slots(&self) -> std::sync::MutexGuard<'_, [Slot; ShedLever::ALL.len()]> {
        self.slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Say a move once, however it was noticed: an INFO line and a counter.
    fn tell(&self, lever: ShedLever, slot: &mut Slot, now_ms: u64) {
        if slot.lease.level == slot.told {
            return;
        }
        let (from, to) = (slot.told, slot.lease.level);
        slot.told = to;
        let cause = if to > from {
            "host"
        } else if now_ms < slot.lease.until_ms {
            "released"
        } else {
            "lease_expired"
        };
        tracing::info!(
            lever = lever.token(),
            from,
            to,
            want = slot.lease.want,
            cause,
            "load lever moved (FSD CIRIS_MESH §7.7)"
        );
        *self
            .changes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(format!("{}:{cause}", lever.token()))
            .or_insert(0) += 1;
    }

    /// **Pull a lever toward `level` for `lease`.** Call it again to renew:
    /// raising moves one step per [`RAISE_STEP`], so a host asks for a level
    /// and renews until it is reached. `level` above [`MAX_LEVEL`] is the top;
    /// a `lease` over [`LEASE_MAX`] is [`LEASE_MAX`]. `level` 0 releases, one
    /// step per [`RELEASE_STEP`]. Returns the level in force now.
    pub fn pull(&self, lever: ShedLever, level: u8, lease: Duration) -> u8 {
        let now = self.now_ms();
        let (raise, release) = (self.raise_ms.load(Ordering::Relaxed), self.release());
        let mut slots = self.slots();
        let slot = &mut slots[lever.index()];
        slot.lease.pull(
            now,
            level.min(MAX_LEVEL),
            millis(lease.min(LEASE_MAX)),
            raise,
            release,
        );
        self.tell(lever, slot, now);
        slot.lease.level
    }

    /// The level in force.
    #[must_use]
    pub fn level(&self, lever: ShedLever) -> u8 {
        let now = self.now_ms();
        let release = self.release();
        let mut slots = self.slots();
        let slot = &mut slots[lever.index()];
        slot.lease.settle(now, release);
        self.tell(lever, slot, now);
        slot.lease.level
    }

    /// Every lever as a host reads it, settled, so a lease that ran out is
    /// said here even with nothing else reading the lever.
    #[must_use]
    pub fn status(&self) -> Vec<LeverStatus> {
        ShedLever::ALL
            .into_iter()
            .map(|lever| {
                let level = self.level(lever);
                let now = self.now_ms();
                let lease = self.slots()[lever.index()].lease;
                LeverStatus {
                    lever: lever.token().to_owned(),
                    level,
                    want: if now < lease.until_ms { lease.want } else { 0 },
                    lease_ms_left: lease.until_ms.saturating_sub(now),
                }
            })
            .collect()
    }

    /// `lever:cause` → moves so far.
    #[must_use]
    pub fn changes(&self) -> HashMap<String, u64> {
        self.changes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The factor on the cadence of `kind` toward `peer`: 1 unless the walk
    /// lever is pulled, the plane stretches, and the peer is owed nothing on a
    /// complete read. The read is made only with the lever pulled, and a read
    /// that failed stretches nothing ([`PeerObligation::Unresolved`]).
    pub async fn walk_stretch(&self, kind: EnvelopeKind, peer: &str) -> u32 {
        let level = self.level(ShedLever::Walk);
        if level == 0 || !kind.walk_stretches() {
            return 1;
        }
        let Some(reader) = self.obligations.get() else {
            return 1;
        };
        match reader.obligation_of(peer).await {
            PeerObligation::Ordinary => 1 << level,
            _ => 1,
        }
    }

    /// The Attestation page under the `page` lever.
    #[must_use]
    pub fn page_budget(&self, budget: u32) -> u32 {
        let shrunk = budget >> self.level(ShedLever::Page);
        shrunk.max(PAGE_FLOOR).min(budget)
    }

    /// Concurrent pulls under the `bulk` lever, never below one.
    #[must_use]
    pub fn bulk_in_flight(&self, max: usize) -> usize {
        (max >> self.level(ShedLever::Bulk)).max(1)
    }

    /// Run the durability pass on every nth of its ticks.
    #[must_use]
    pub fn durability_every(&self) -> u64 {
        1 << self.level(ShedLever::Bulk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAISE: u64 = 10_000;
    const RELEASE: u64 = 30_000;

    fn pulled(level: u8, lease_ms: u64) -> Lease {
        let mut l = Lease::default();
        let mut t = 0;
        for _ in 0..level {
            l.pull(t, level, lease_ms, RAISE, RELEASE);
            t += RAISE;
        }
        l.pull(t, level, lease_ms, RAISE, RELEASE);
        assert_eq!(l.level, level);
        l
    }

    #[test]
    fn a_pull_rises_one_step_per_raise_step_however_high_the_ask() {
        let mut l = Lease::default();
        l.pull(0, 3, 60_000, RAISE, RELEASE);
        assert_eq!(l.level, 1, "a pull is not a scram");
        l.pull(1_000, 3, 60_000, RAISE, RELEASE);
        assert_eq!(l.level, 1, "a renewal inside the step does not climb");
        l.pull(RAISE, 3, 60_000, RAISE, RELEASE);
        assert_eq!(l.level, 2);
    }

    /// The lease rule: a host that goes silent leaves a lever that walks home.
    #[test]
    fn a_lever_left_unrenewed_returns_to_serving() {
        let mut l = pulled(3, 60_000);
        let until = l.until_ms;
        l.settle(until - 1, RELEASE);
        assert_eq!(l.level, 3, "held for the whole lease");
        let mut seen = Vec::new();
        for s in 0..4 {
            l.settle(until + s * RELEASE, RELEASE);
            seen.push(l.level);
        }
        assert_eq!(seen, vec![2, 1, 0, 0], "one step each, then serving");
    }

    #[test]
    fn a_renewed_lever_holds_past_any_one_lease() {
        let mut l = pulled(2, 60_000);
        let mut t = l.until_ms - 1_000;
        for _ in 0..1_000 {
            l.pull(t, 2, 5_000, RAISE, RELEASE);
            t += 4_000;
        }
        assert_eq!(l.level, 2);
    }

    /// Release is paced, and renewing the lower ask cannot stall the walk.
    #[test]
    fn a_release_walks_down_one_step_at_a_time_through_renewals() {
        let mut l = pulled(3, 60_000);
        let t0 = RAISE * 3 + 1;
        let mut levels = Vec::new();
        for s in 0..=95 {
            l.pull(t0 + s * 1_000, 0, 60_000, RAISE, RELEASE);
            levels.push(l.level);
        }
        assert_eq!(levels[0], 3);
        assert_eq!(levels[29], 3, "no step before the first release step");
        assert_eq!(levels[30], 2);
        assert_eq!(levels[60], 1);
        assert_eq!(levels[90], 0);
        assert!(levels.windows(2).all(|w| w[0] >= w[1] && w[0] - w[1] <= 1));
    }

    #[test]
    fn a_lease_is_bounded_and_a_level_is_clamped() {
        let levers = LoadLevers::default();
        levers.set_steps(Duration::ZERO, Duration::ZERO);
        for _ in 0..8 {
            levers.pull(ShedLever::Bulk, 200, Duration::from_secs(86_400));
        }
        assert_eq!(levers.level(ShedLever::Bulk), MAX_LEVEL);
        let s = levers.status();
        assert!(s[ShedLever::Bulk.index()].lease_ms_left <= millis(LEASE_MAX));
    }

    /// No level reaches zero on anything a lever governs: graduated, always.
    #[test]
    fn no_lever_reaches_zero_at_its_top_step() {
        let levers = LoadLevers::default();
        levers.set_steps(Duration::ZERO, Duration::ZERO);
        for lever in ShedLever::ALL {
            for _ in 0..4 {
                levers.pull(lever, MAX_LEVEL, LEASE_MAX);
            }
        }
        assert_eq!(levers.bulk_in_flight(4), 1);
        assert_eq!(levers.bulk_in_flight(1), 1);
        assert_eq!(levers.page_budget(500), 62);
        assert_eq!(levers.page_budget(100), PAGE_FLOOR);
        assert_eq!(levers.page_budget(10), 10, "never above what was asked");
        assert_eq!(levers.durability_every(), 8);
    }

    #[test]
    fn untouched_levers_change_nothing() {
        let levers = LoadLevers::default();
        assert_eq!(levers.bulk_in_flight(4), 4);
        assert_eq!(levers.page_budget(500), 500);
        assert_eq!(levers.durability_every(), 1);
    }

    #[derive(Debug)]
    struct Owes(PeerObligation);

    #[async_trait::async_trait]
    impl PeerObligations for Owes {
        async fn obligation_of(&self, _peer: &str) -> PeerObligation {
            self.0
        }
    }

    async fn walk_at_top(owes: Option<PeerObligation>, kind: EnvelopeKind) -> u32 {
        let levers = LoadLevers::default();
        levers.set_steps(Duration::ZERO, Duration::ZERO);
        if let Some(o) = owes {
            levers.install_obligations(Arc::new(Owes(o)));
        }
        for _ in 0..4 {
            levers.pull(ShedLever::Walk, MAX_LEVEL, LEASE_MAX);
        }
        levers.walk_stretch(kind, "peer").await
    }

    #[tokio::test]
    async fn the_walk_stretches_only_ordinary_rounds_to_peers_owed_nothing() {
        use PeerObligation as O;
        let a = EnvelopeKind::Attestation;
        assert_eq!(walk_at_top(Some(O::Ordinary), a).await, 8);
        for owed in [O::OwnDevice, O::Seat, O::SendSet, O::Unresolved] {
            assert_eq!(walk_at_top(Some(owed), a).await, 1, "{owed:?}");
        }
        assert_eq!(walk_at_top(None, a).await, 1, "no read, nothing stretched");
    }

    /// The first-contact set never stretches, at the top step, for anyone.
    #[tokio::test]
    async fn the_minimum_viable_role_keeps_its_cadence_at_the_top_step() {
        for kind in EnvelopeKind::ALL {
            let expect = if kind.walk_stretches() { 8 } else { 1 };
            assert_eq!(
                walk_at_top(Some(PeerObligation::Ordinary), kind).await,
                expect,
                "{kind:?}"
            );
        }
        for kind in [
            EnvelopeKind::Key,
            EnvelopeKind::IdentityOccurrence,
            EnvelopeKind::Revocation,
            EnvelopeKind::IdentityOccurrenceRevocation,
            EnvelopeKind::Family,
            EnvelopeKind::Community,
        ] {
            assert!(!kind.walk_stretches(), "{kind:?}");
        }
    }

    #[test]
    fn every_move_is_said_with_its_cause() {
        let levers = LoadLevers::default();
        levers.set_steps(Duration::ZERO, Duration::ZERO);
        levers.pull(ShedLever::Walk, 1, Duration::from_secs(60));
        levers.pull(ShedLever::Walk, 0, Duration::from_secs(60));
        assert_eq!(levers.level(ShedLever::Walk), 0);
        let c = levers.changes();
        assert_eq!(c.get("walk:host"), Some(&1));
        assert_eq!(c.get("walk:released"), Some(&1));
        for k in c.keys() {
            assert!(lever_change_keys().contains(k), "{k}");
        }
    }
}
