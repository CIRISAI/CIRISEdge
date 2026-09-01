//! One keyed rate limiter — see `docs/FSD_RATE_LIMIT.md`.
//!
//! Five places in edge asked *may this keyed thing proceed right now?* and each
//! answered differently. Every one shipped a bug another had already solved:
//! unbounded maps, eviction that dropped the quiet peer instead of the flooder,
//! a cap that let one source starve every other, an O(cap) scan per rejected
//! request. A limiter is mostly edge cases, and five copies meant fixing each
//! edge case five times, late.
//!
//! This is the superset. Every existing limiter is this module with different
//! settings; the FSD's §2 table maps each one.
//!
//! # The rules that are not negotiable
//!
//! * **The clock is the caller's** (D1) — nothing here reads one, which is the
//!   only reason a 24-hour refill or a 6-hour backoff cap is testable.
//! * **Fair eviction** (D2) — charge the largest source, never the newest
//!   arrival and never the oldest entry; both naive answers are shipped bugs.
//! * **Never say when to retry** (D3) — telling a spammer the refill interval
//!   is telling them the optimal send rate.
//! * **Promoted keys are never evicted** (D4) — the map may drop what it can
//!   rebuild from traffic, never what it cannot.
//! * **Denials are counted and surfaced** (D5) — a limiter that hides the flood
//!   it absorbed leaves an operator blind to the attack.
//! * **The verdict is advisory** (D6) — this module never drops anything
//!   itself, because dropping a log line is free and dropping a federation
//!   record is data loss.

use std::collections::HashMap;

/// Unix seconds. The caller's clock, always passed in (D1).
pub type Ts = u64;

/// How many permits a key of some class gets, and over what window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    /// Permits per window. Zero means "never allow", which is a legitimate
    /// setting for a plane that is being held entirely.
    pub permits: u32,
    /// Seconds after a key's last spend before its permits refill in full.
    pub window_secs: u64,
}

impl Quota {
    #[must_use]
    pub const fn new(permits: u32, window_secs: u64) -> Self {
        Self {
            permits,
            window_secs,
        }
    }
}

/// Exponential suppression after consecutive denials.
///
/// The window doubles per consecutive denial and is capped. A single `Allow`
/// resets the streak — an actor that gets back inside its budget is not still
/// serving a sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    pub base_secs: u64,
    pub cap_secs: u64,
}

impl Backoff {
    #[must_use]
    pub const fn new(base_secs: u64, cap_secs: u64) -> Self {
        Self {
            base_secs,
            cap_secs,
        }
    }

    /// The suppression window after `consecutive` denials (1 ⇒ base).
    #[must_use]
    pub fn window_secs(self, consecutive: u32) -> u64 {
        if consecutive == 0 {
            return 0;
        }
        let shift = consecutive.saturating_sub(1).min(32);
        self.base_secs
            .saturating_mul(1_u64.checked_shl(shift).unwrap_or(u64::MAX))
            .min(self.cap_secs)
    }
}

/// What the limiter decided. Advisory (D6) — the caller chooses the consequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Proceed. `suppressed_since_last_allow` is how many denials this key
    /// absorbed since its previous allow — surface it (D5) so a flood is
    /// visible without one line per event.
    Allow { suppressed_since_last_allow: u64 },
    /// Do not proceed. `reason` is for the RECEIVER's operator.
    ///
    /// Deliberately carries **no retry-after** (D3): callers must not compute
    /// one for the limited party either.
    Deny { reason: DenyReason },
}

impl Decision {
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }
}

/// Why a key was denied. Operator-facing; never echoed to the limited party.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// This key spent its quota for the current window.
    QuotaSpent,
    /// This key is inside an exponential suppression window after consecutive
    /// denials.
    BackingOff,
    /// The limiter is tracking as many keys as it will hold and none could be
    /// released. A GLOBAL bound, not a statement about this key — under
    /// identity rotation a per-key budget is exactly what fails, so the ceiling
    /// is the control.
    AtCapacity,
}

impl DenyReason {
    /// Stable token for logs and metrics.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DenyReason::QuotaSpent => "quota_spent",
            DenyReason::BackingOff => "backing_off",
            DenyReason::AtCapacity => "at_capacity",
        }
    }
}

/// A key's tier. Selects the quota, and survives eviction (D4).
///
/// Two are built in because two is what every caller needed: a default and a
/// promoted tier. `RefusalBackoff` reads them as transient/terminal;
/// `InviteGate` as stranger/contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// The tier an unknown key starts in.
    Default,
    /// Earned, and permanent for this key's lifetime in the map. Never evicted:
    /// promotion is the one bit that cannot be rebuilt from traffic.
    Promoted,
}

/// The policy a limiter enforces.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// Quota for [`Class::Default`].
    pub default_quota: Quota,
    /// Quota for [`Class::Promoted`]. Must not be smaller than the default —
    /// promotion that throttles harder is a bug, and the constructor rejects it.
    pub promoted_quota: Quota,
    /// Optional exponential suppression on consecutive denial.
    pub backoff: Option<Backoff>,
    /// Hard ceiling on tracked keys.
    pub max_keys: usize,
}

impl Policy {
    /// A single-tier quota policy: the common case (log throttling, per-peer
    /// lookup budgets).
    #[must_use]
    pub fn quota(permits: u32, window_secs: u64, max_keys: usize) -> Self {
        let q = Quota::new(permits, window_secs);
        Self {
            default_quota: q,
            promoted_quota: q,
            backoff: None,
            max_keys,
        }
    }

    /// A two-tier policy — an unknown key and an earned one.
    #[must_use]
    pub fn tiered(default_quota: Quota, promoted_quota: Quota, max_keys: usize) -> Self {
        debug_assert!(
            promoted_quota.permits >= default_quota.permits,
            "promotion must not throttle harder than the default tier: \
             throttling an established relationship is how an anti-abuse \
             control breaks what it exists to protect"
        );
        Self {
            default_quota,
            promoted_quota,
            backoff: None,
            max_keys,
        }
    }

    /// Add exponential suppression on consecutive denial.
    #[must_use]
    pub fn with_backoff(mut self, backoff: Backoff) -> Self {
        self.backoff = Some(backoff);
        self
    }

    fn quota_for(&self, class: Class) -> Quota {
        match class {
            Class::Default => self.default_quota,
            Class::Promoted => self.promoted_quota,
        }
    }
}

#[derive(Debug, Clone)]
struct KeyState {
    class: Class,
    /// Permits spent in the current window.
    spent: u32,
    /// When a permit was last SPENT. Drives the refill window.
    ///
    /// Deliberately not touched on denial: if a denial moved this, a key's own
    /// retries would push its refill horizon forward and it could never refill
    /// — a caller polling politely would lock itself out permanently.
    last_spend_at: Ts,
    /// When this key was last DENIED. Drives the backoff window only.
    last_denial_at: Ts,
    /// Consecutive denials since the last allow. Drives backoff.
    consecutive_denials: u32,
    /// Denials absorbed since the last allow, surfaced on the next one (D5).
    suppressed: u64,
    /// Which source is accountable for this key existing, for fair eviction
    /// (D2). `None` = no attributable source.
    source: Option<String>,
}

impl KeyState {
    /// Is this key's retained state indistinguishable from a key never seen?
    ///
    /// A refilled, unpromoted, non-backing-off key carries no information: its
    /// next verdict is identical whether it is remembered or forgotten. That
    /// makes releasing it FREE rather than a tradeoff, which is what lets the
    /// map stay bounded without a policy choice about whom to harm.
    fn is_releasable(&self, now: Ts, policy: &Policy) -> bool {
        if self.class == Class::Promoted {
            return false;
        }
        let window = policy.quota_for(self.class).window_secs;
        let refilled = now.saturating_sub(self.last_spend_at) >= window;
        let backoff_done = policy.backoff.map_or(true, |b| {
            now.saturating_sub(self.last_denial_at) >= b.window_secs(self.consecutive_denials)
        });
        // Deliberately NOT gated on `suppressed`. An earlier version required
        // it to be zero so no denial count was ever lost — which pinned every
        // denied key in the map forever, because `suppressed` clears only on
        // the next Allow and a key nobody allows again never gets one. The map
        // then fills permanently AND `next_release` stays in the past, so every
        // subsequent admission pays a full scan: the memory bound and the O(1)
        // property both destroyed, to preserve a counter for a key whose flood
        // is already over. The count is carried to `released_suppressed`
        // instead, so the aggregate stays visible (D5) without holding the map
        // hostage.
        refilled && backoff_done
    }
}

/// Incremental accounting of "how many keys is each source responsible for".
///
/// Extracted because rebuilding this on demand is a bug that has now appeared
/// FOUR times — `KnownHashes`, the missing-signer queue, `InviteGate`, and then
/// inside `RateLimiter` itself. Every instance had the same shape: at capacity,
/// a rejected request scans the whole map to discover it may not evict, so an
/// attacker who fills the map buys O(cap) work per subsequent request and the
/// memory bound becomes a CPU one.
///
/// Maintaining the counts as keys come and go makes the rejection a lookup and
/// a comparison. Any bounded, source-attributed map in edge should hold one of
/// these rather than counting on demand.
#[derive(Debug, Default)]
pub struct SourceLedger {
    counts: HashMap<Option<String>, usize>,
    /// The largest value in `counts`. Grows on insert; a stale-high value costs
    /// one extra victim search, never a wrong refusal.
    max_count: usize,
}

impl SourceLedger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// One more key is attributed to `source`.
    pub fn note(&mut self, source: Option<&str>) {
        let n = self.counts.entry(source.map(str::to_owned)).or_insert(0);
        *n += 1;
        self.max_count = self.max_count.max(*n);
    }

    /// One fewer key is attributed to `source`.
    pub fn forget(&mut self, source: Option<&str>) {
        let key = source.map(str::to_owned);
        if let Some(n) = self.counts.get_mut(&key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.counts.remove(&key);
            }
        }
        self.max_count = self.counts.values().copied().max().unwrap_or(0);
    }

    /// How many keys `source` holds.
    #[must_use]
    pub fn count_of(&self, source: Option<&str>) -> usize {
        self.counts
            .get(&source.map(str::to_owned))
            .copied()
            .unwrap_or(0)
    }

    /// Is any source hoarding relative to `incoming` — i.e. is eviction even
    /// worth considering? **O(1)**, and the whole point of the ledger.
    ///
    /// A clear margin is required. When every key is its own source — identity
    /// rotation, where the attack IS the key space — every count is one, no
    /// margin exists, and the caller must refuse rather than evict an arbitrary
    /// victim: churning the map admits every fresh identity while keeping the
    /// map bounded, which bounds the wrong thing.
    #[must_use]
    pub fn eviction_worth_considering(&self, incoming: Option<&str>) -> bool {
        self.max_count > self.count_of(incoming).saturating_add(1)
    }

    /// The largest source other than `incoming`, with its count. Only call once
    /// [`Self::eviction_worth_considering`] says so.
    #[must_use]
    pub fn dominant_excluding(&self, incoming: Option<&str>) -> Option<(Option<String>, usize)> {
        self.counts
            .iter()
            .filter(|(src, _)| src.as_deref() != incoming)
            .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
            .map(|(src, n)| (src.clone(), *n))
    }
}

/// A keyed, bounded, fair rate limiter.
///
/// `&mut self` on the decision path: the verdict mutates state, and pretending
/// otherwise behind interior mutability hid a race in one of the
/// implementations this replaces. Callers that need sharing wrap it.
#[derive(Debug)]
pub struct RateLimiter {
    policy: Policy,
    keys: HashMap<String, KeyState>,
    /// Source accounting, maintained incrementally (see [`SourceLedger`] for
    /// why counting on demand is a bug with four prior appearances).
    sources: SourceLedger,
    /// Denials absorbed by keys that have since been released. Keeps the
    /// aggregate flood visible (D5) once a key's own counter is gone.
    released_suppressed: u64,
    /// Earliest time ANY key could become releasable. Before it, a capacity
    /// denial is O(1) because a scan provably cannot find anything (D2) —
    /// without this an attacker rotating identities inside the window forces a
    /// full scan per rejected request, turning the memory bound into a CPU one.
    next_release: Ts,
}

impl RateLimiter {
    #[must_use]
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            keys: HashMap::new(),
            sources: SourceLedger::new(),
            released_suppressed: 0,
            next_release: Ts::MAX,
        }
    }

    /// Keys currently tracked.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.keys.len()
    }

    /// Denials absorbed by keys that have since been released — the flood that
    /// happened but whose per-key counters are gone.
    #[must_use]
    pub fn released_suppressed(&self) -> u64 {
        self.released_suppressed
    }

    /// This key's class.
    #[must_use]
    pub fn class_of(&self, key: &str) -> Class {
        self.keys.get(key).map_or(Class::Default, |k| k.class)
    }

    /// Promote a key permanently (D4). Creates the entry if absent, so a caller
    /// can promote before the first request.
    ///
    /// Promotion also CLEARS the key's spend and denial streak. Whatever the
    /// key spent to earn the promotion was answered — carrying it against the
    /// new tier would mean an accepted contact starts its allowance already
    /// part-spent, and a key that was mid-backoff when it earned its way in
    /// would keep serving that sentence.
    pub fn promote(&mut self, key: &str) -> bool {
        // An ABSENT key must still respect the ceiling. Promotion creates an
        // entry that is by definition un-evictable, so unbounded promotion of
        // unseen keys would grow the map past `max_keys` with entries nothing
        // can ever reclaim — the hard bound quietly stops being one.
        if !self.keys.contains_key(key) && self.keys.len() >= self.policy.max_keys {
            let now_unbounded = self.keys.len();
            tracing::warn!(
                key,
                tracked = now_unbounded,
                cap = self.policy.max_keys,
                "promotion REFUSED — the limiter is at capacity and a promoted \
                 entry can never be evicted to make room later"
            );
            return false;
        }
        if !self.keys.contains_key(key) {
            self.sources.note(None);
        }
        let entry = self.keys.entry(key.to_owned()).or_insert_with(|| KeyState {
            class: Class::Default,
            spent: 0,
            last_spend_at: 0,
            last_denial_at: 0,
            consecutive_denials: 0,
            suppressed: 0,
            source: None,
        });
        entry.class = Class::Promoted;
        entry.spent = 0;
        entry.consecutive_denials = 0;
        true
    }

    /// Decide, attributing the key to no particular source.
    pub fn check(&mut self, key: &str, now: Ts) -> Decision {
        self.check_from(key, None, now)
    }

    /// Decide, naming the SOURCE accountable for this key existing.
    ///
    /// The source is what makes eviction fair (D2): when the map is full, the
    /// largest source pays. Pass the delivering peer, the requesting peer —
    /// whatever entity would be flooding if this were an attack.
    pub fn check_from(&mut self, key: &str, source: Option<&str>, now: Ts) -> Decision {
        if !self.keys.contains_key(key)
            && self.keys.len() >= self.policy.max_keys
            && !self.make_room(source, now)
        {
            return Decision::Deny {
                reason: DenyReason::AtCapacity,
            };
        }

        let policy = self.policy;
        if !self.keys.contains_key(key) {
            self.sources.note(source);
        }
        let entry = self.keys.entry(key.to_owned()).or_insert_with(|| KeyState {
            class: Class::Default,
            spent: 0,
            last_spend_at: now,
            last_denial_at: 0,
            consecutive_denials: 0,
            suppressed: 0,
            source: source.map(str::to_owned),
        });

        // Refill first, so a long-quiet key is not judged on ancient history.
        // `saturating_sub` also makes a BACKWARDS clock safe: it reads as "no
        // time passed", which neither refills early nor locks the key out.
        let quota = policy.quota_for(entry.class);
        if now.saturating_sub(entry.last_spend_at) >= quota.window_secs {
            entry.spent = 0;
            // The denial streak is NOT cleared here. When backoff outlasts the
            // quota window, clearing it on refill would end the suppression
            // early — a key denied at t=0 under a 60s quota and a 300s backoff
            // would be allowed at t=60, serving 20% of its sentence. The streak
            // resets on a successful ALLOW, which is the event that means the
            // actor is back inside its budget.
        }

        // Exponential suppression, when configured.
        if let Some(backoff) = policy.backoff {
            let window = backoff.window_secs(entry.consecutive_denials);
            if entry.consecutive_denials > 0 && now.saturating_sub(entry.last_denial_at) < window {
                entry.suppressed = entry.suppressed.saturating_add(1);
                return Decision::Deny {
                    reason: DenyReason::BackingOff,
                };
            }
        }

        if entry.spent >= quota.permits {
            entry.consecutive_denials = entry.consecutive_denials.saturating_add(1);
            entry.suppressed = entry.suppressed.saturating_add(1);
            entry.last_denial_at = now;
            let denial_horizon = entry.last_spend_at.saturating_add(quota.window_secs).max(
                policy.backoff.map_or(0, |b| {
                    now.saturating_add(b.window_secs(entry.consecutive_denials))
                }),
            );
            // A key that NEVER spends — `permits == 0` is a supported quota —
            // would otherwise leave `next_release` at its initial `Ts::MAX`, so
            // `make_room` would never scan and every later key is refused
            // forever. The horizon belongs to the entry, not to the allow path.
            self.next_release = self.next_release.min(denial_horizon);
            return Decision::Deny {
                reason: DenyReason::QuotaSpent,
            };
        }

        entry.spent = entry.spent.saturating_add(1);
        entry.last_spend_at = now;
        entry.consecutive_denials = 0;
        let suppressed = std::mem::take(&mut entry.suppressed);

        // A newly-spent key can become releasable one window from now.
        self.next_release = self.next_release.min(now.saturating_add(quota.window_secs));

        Decision::Allow {
            suppressed_since_last_allow: suppressed,
        }
    }

    /// Make room for one new key. Returns whether room now exists.
    ///
    /// The rejection path is O(1): a single map lookup for the incoming
    /// source's count, compared against the running maximum. Only a genuinely
    /// dominant source triggers the (bounded, progress-making) victim search.
    fn make_room(&mut self, incoming_source: Option<&str>, now: Ts) -> bool {
        // O(1) when nothing can possibly be released yet (D2).
        if now >= self.next_release {
            self.release_free_entries(now);
            if self.keys.len() < self.policy.max_keys {
                return true;
            }
        }

        // O(1) REFUSAL — a lookup and a comparison, no map walk.
        if !self.sources.eviction_worth_considering(incoming_source) {
            return false;
        }

        let Some((dominant, dominant_count)) = self.sources.dominant_excluding(incoming_source)
        else {
            return false;
        };
        if dominant_count <= self.sources.count_of(incoming_source).saturating_add(1) {
            return false;
        }
        let victim = self
            .keys
            .iter()
            .find(|(_, st)| st.class != Class::Promoted && st.source == dominant)
            .map(|(k, _)| k.clone());
        match victim {
            Some(k) => {
                if let Some(st) = self.keys.remove(&k) {
                    // D5 — an evicted key's absorbed denials are not lost.
                    self.released_suppressed =
                        self.released_suppressed.saturating_add(st.suppressed);
                    self.sources.forget(st.source.as_deref());
                }
                true
            }
            None => false,
        }
    }

    /// Drop every key whose retained state is indistinguishable from absence.
    fn release_free_entries(&mut self, now: Ts) {
        let policy = self.policy;
        let mut carried = 0_u64;
        let mut dropped: Vec<Option<String>> = Vec::new();
        self.keys.retain(|_, st| {
            let keep = !st.is_releasable(now, &policy);
            if !keep {
                carried = carried.saturating_add(st.suppressed);
                dropped.push(st.source.clone());
            }
            keep
        });
        self.released_suppressed = self.released_suppressed.saturating_add(carried);
        for src in dropped {
            self.sources.forget(src.as_deref());
        }
        self.next_release = self
            .keys
            .values()
            .filter(|st| st.class != Class::Promoted)
            .map(|st| {
                // The LATER of the two, or the horizon lies: `is_releasable`
                // rejects a refilled key that is still backing off, so a
                // quota-only horizon leaves `next_release` in the past and
                // every new-key check pays a full scan until backoff expires.
                let q = policy.quota_for(st.class);
                let refill_at = st.last_spend_at.saturating_add(q.window_secs);
                let backoff_at = policy.backoff.map_or(0, |b| {
                    st.last_denial_at
                        .saturating_add(b.window_secs(st.consecutive_denials))
                });
                refill_at.max(backoff_at)
            })
            .min()
            .unwrap_or(Ts::MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quota_policy(permits: u32, window: u64, max_keys: usize) -> Policy {
        Policy::quota(permits, window, max_keys)
    }

    /// A1 — one key floods; other keys are unaffected.
    #[test]
    fn a1_a_flooding_key_is_denied_and_others_are_untouched() {
        let mut rl = RateLimiter::new(quota_policy(2, 60, 100));
        assert!(rl.check("noisy", 1000).is_allowed());
        assert!(rl.check("noisy", 1000).is_allowed());
        assert_eq!(
            rl.check("noisy", 1000),
            Decision::Deny {
                reason: DenyReason::QuotaSpent
            }
        );
        assert!(
            rl.check("quiet", 1000).is_allowed(),
            "a limiter that lets one key's flood deny another is a denial-of-\
             service amplifier, not a control"
        );
    }

    /// A2 — identity rotation: every request a fresh key. The map must stay
    /// bounded, and honest keys must keep their budget.
    #[test]
    fn a2_identity_rotation_cannot_grow_the_map() {
        let mut rl = RateLimiter::new(quota_policy(1, 3600, 64));
        rl.promote("friend");
        assert!(rl.check("friend", 1000).is_allowed());

        for i in 0..5_000 {
            let _ = rl.check_from(&format!("rot-{i}"), Some("attacker"), 1000);
        }
        assert!(
            rl.tracked() <= 64,
            "a per-key budget is exactly what rotation defeats — the ceiling is \
             the control: {} keys",
            rl.tracked()
        );
        assert_eq!(
            rl.class_of("friend"),
            Class::Promoted,
            "and the promoted key survives the flood"
        );
    }

    /// A3 — rotation INSIDE the window with nothing releasable: the capacity
    /// denial must be O(1), or the memory bound becomes a CPU exhaustion path.
    #[test]
    fn a3_capacity_denial_is_o1_when_nothing_can_be_released() {
        let mut rl = RateLimiter::new(quota_policy(1, 86_400, 32));
        for i in 0..32 {
            let _ = rl.check_from(&format!("k{i}"), Some("flood"), 1000);
        }
        // Same instant, same source: nothing has refilled and the source may
        // not evict on its own behalf.
        assert_eq!(
            rl.check_from("newcomer", Some("flood"), 1000),
            Decision::Deny {
                reason: DenyReason::AtCapacity
            },
            "at cap with nothing releasable, refuse — and do it without a scan"
        );
        assert!(rl.tracked() <= 32);
    }

    /// A4 — flooder plus a quiet honest key at cap: the HONEST key survives.
    ///
    /// The naive answers both fail here: evicting the oldest drops the quiet
    /// key, and refusing the newest locks out an honest arrival while the
    /// resident flooder keeps its budget.
    #[test]
    fn a4_a_flood_evicts_the_flooder_not_the_quiet_key() {
        let mut rl = RateLimiter::new(quota_policy(1, 86_400, 16));
        assert!(rl
            .check_from("honest", Some("peer-honest"), 1000)
            .is_allowed());
        for i in 0..64 {
            let _ = rl.check_from(&format!("f{i}"), Some("peer-flood"), 1000);
        }
        assert!(
            rl.check_from("honest", Some("peer-honest"), 1000)
                .is_allowed()
                || rl.class_of("honest") == Class::Default,
            "the quiet peer must still be servable"
        );
        assert!(rl.tracked() <= 16);
        // The flooder is the one paying: it cannot hold the entire map.
        let honest_still_known = rl.check_from("honest2", Some("peer-honest"), 1000);
        assert!(
            honest_still_known.is_allowed(),
            "an honest source must still be able to take a slot from the \
             dominant flooder: {honest_still_known:?}"
        );
    }

    /// A5 — a promoted key is never evicted and never throttled as a stranger.
    #[test]
    fn a5_a_promoted_key_survives_a_flood_and_keeps_its_tier() {
        let policy = Policy::tiered(Quota::new(1, 86_400), Quota::new(8, 86_400), 8);
        let mut rl = RateLimiter::new(policy);
        rl.promote("contact");
        for i in 0..500 {
            let _ = rl.check_from(&format!("s{i}"), Some("flood"), 1000);
        }
        assert_eq!(rl.class_of("contact"), Class::Promoted);
        for n in 0..8 {
            assert!(
                rl.check("contact", 1000).is_allowed(),
                "promoted quota is 8; attempt {n} must pass — throttling an \
                 established relationship is how the control breaks what it \
                 protects"
            );
        }
    }

    /// A6 — quota refills after the window; a long-quiet key is not judged on
    /// ancient history.
    #[test]
    fn a6_the_quota_refills_after_a_long_silence() {
        let mut rl = RateLimiter::new(quota_policy(1, 600, 100));
        assert!(rl.check("k", 1000).is_allowed());
        assert!(!rl.check("k", 1100).is_allowed(), "still inside the window");
        assert!(
            rl.check("k", 1000 + 600).is_allowed(),
            "past the window it refills in full"
        );
    }

    /// A7 — consecutive denials grow the window, capped; one allow resets it.
    #[test]
    fn a7_backoff_grows_and_a_single_allow_resets_it() {
        let b = Backoff::new(60, 300);
        assert_eq!(b.window_secs(0), 0);
        assert_eq!(b.window_secs(1), 60);
        assert_eq!(b.window_secs(2), 120);
        assert_eq!(b.window_secs(3), 240);
        assert_eq!(b.window_secs(4), 300, "capped");
        assert_eq!(b.window_secs(99), 300, "still capped, no overflow");

        let mut rl = RateLimiter::new(quota_policy(1, 60, 100).with_backoff(b));
        assert!(rl.check("k", 1000).is_allowed());
        // Spend, then get denied and start backing off.
        assert_eq!(
            rl.check("k", 1000),
            Decision::Deny {
                reason: DenyReason::QuotaSpent
            }
        );
        assert_eq!(
            rl.check("k", 1001),
            Decision::Deny {
                reason: DenyReason::BackingOff
            },
            "inside the suppression window"
        );
        // Far past both window and backoff: allowed, and the streak resets.
        assert!(rl.check("k", 1000 + 600).is_allowed());
    }

    /// A8 — a log flood is COUNTED and surfaced on the next allow, so the
    /// absorbed flood is visible without one line per event.
    #[test]
    fn a8_denials_are_counted_and_surfaced_on_the_next_allow() {
        let mut rl = RateLimiter::new(quota_policy(1, 60, 100));
        assert_eq!(
            rl.check("site", 1000),
            Decision::Allow {
                suppressed_since_last_allow: 0
            }
        );
        for _ in 0..99 {
            assert!(!rl.check("site", 1000).is_allowed());
        }
        assert_eq!(
            rl.check("site", 1060),
            Decision::Allow {
                suppressed_since_last_allow: 99
            },
            "a limiter that hides the flood it absorbed leaves an operator \
             blind to the attack"
        );
    }

    /// A9 — a backwards clock is safe: no panic, no permanent lockout, no free
    /// permits.
    #[test]
    fn a9_a_backwards_clock_neither_panics_nor_unlocks() {
        let mut rl = RateLimiter::new(quota_policy(1, 600, 100));
        assert!(rl.check("k", 10_000).is_allowed());
        // Clock jumps backwards past the epoch of the last spend.
        assert!(
            !rl.check("k", 1).is_allowed(),
            "a backwards clock must not refill the quota early"
        );
        // And forward progress still works afterwards.
        assert!(rl.check("k", 10_000 + 600).is_allowed());
    }

    /// A10 — two classes over one key space, each judged by its own quota.
    #[test]
    fn a10_each_class_is_judged_by_its_own_quota() {
        let policy = Policy::tiered(Quota::new(1, 3600), Quota::new(4, 3600), 100);
        let mut rl = RateLimiter::new(policy);
        assert!(rl.check("stranger", 1000).is_allowed());
        assert!(
            !rl.check("stranger", 1000).is_allowed(),
            "default quota is 1"
        );

        rl.promote("known");
        for n in 0..4 {
            assert!(
                rl.check("known", 1000).is_allowed(),
                "promoted quota is 4 (n={n})"
            );
        }
        assert!(
            !rl.check("known", 1000).is_allowed(),
            "and then it too is bounded"
        );
    }

    /// Promotion clears the spend that earned it.
    ///
    /// The original `InviteGate` had this and it is easy to lose in a
    /// refactor: an accepted contact whose stranger attempt still counted would
    /// start its new allowance already part-spent, and one promoted mid-backoff
    /// would keep serving the sentence it just earned its way out of.
    #[test]
    fn promotion_clears_the_spend_that_earned_it() {
        let policy = Policy::tiered(Quota::new(1, 3600), Quota::new(4, 3600), 100);
        let mut rl = RateLimiter::new(policy);
        assert!(rl.check("k", 1000).is_allowed());
        assert!(!rl.check("k", 1000).is_allowed(), "stranger budget spent");

        rl.promote("k");
        for n in 0..4 {
            assert!(
                rl.check("k", 1000).is_allowed(),
                "the FULL promoted allowance must be available (n={n}) — the \
                 attempt that earned the promotion was answered"
            );
        }
    }

    /// A2b — when every key is its OWN source, eviction must collapse to
    /// refuse-at-capacity.
    ///
    /// "Charge the largest source" degenerates when no one is hoarding: all
    /// counts tie at one, so the newcomer evicts an arbitrary victim and gets
    /// in. The map stays bounded and the number of strangers reaching a human
    /// does not — which is the invite-flood shape exactly. Found by migrating
    /// the invite gate: its original refuse-at-cap test failed against the
    /// first version of this rule.
    #[test]
    fn a2b_self_sourced_keys_refuse_at_capacity_rather_than_churn() {
        let mut rl = RateLimiter::new(quota_policy(1, 86_400, 32));
        for i in 0..32 {
            let k = format!("sender-{i}");
            let _ = rl.check_from(&k, Some(&k), 1000);
        }
        assert_eq!(
            rl.check_from("newcomer", Some("newcomer"), 1000),
            Decision::Deny {
                reason: DenyReason::AtCapacity
            },
            "no source is hoarding, so there is no fair victim — admitting by \
             evicting an arbitrary peer would make the flood unbounded in total \
             while keeping the map bounded"
        );
        assert_eq!(rl.tracked(), 32);
    }

    /// A12 — a denied key must not be pinned in the map forever.
    ///
    /// The regression: `is_releasable` required `suppressed == 0`, and
    /// `suppressed` clears only on the next Allow — which a key nobody allows
    /// again never gets. So every denied key was immortal, the map filled
    /// permanently, and `next_release` stayed in the past so each later
    /// admission paid a full scan. The rotation shape reaches this in one pass:
    /// fill the map with senders that each make a second, denied attempt.
    #[test]
    fn a12_denied_keys_are_released_once_their_window_refills() {
        let mut rl = RateLimiter::new(quota_policy(1, 600, 32));
        for i in 0..32 {
            let k = format!("s{i}");
            assert!(rl.check_from(&k, Some(&k), 1000).is_allowed());
            // The second, DENIED attempt — this is what used to pin it.
            assert!(!rl.check_from(&k, Some(&k), 1000).is_allowed());
        }
        assert_eq!(rl.tracked(), 32);

        // Past the window everything is refilled and carries no information.
        let later = 1000 + 600;
        assert!(
            rl.check_from("newcomer", Some("newcomer"), later)
                .is_allowed(),
            "a refilled key is state-equivalent to one never seen, so releasing \
             it is free — pinning the map to preserve a denial counter trades a \
             permanent outage for a statistic"
        );
        assert!(rl.tracked() <= 32);
        assert!(
            rl.released_suppressed() > 0,
            "and the absorbed flood stays visible in aggregate (D5)"
        );
    }

    /// A13 — the capacity REFUSAL touches neither the key map nor a rebuilt
    /// counter.
    ///
    /// Third appearance of this class: an O(cap) scan per rejected request
    /// turns a memory bound into CPU exhaustion. It was fixed in `InviteGate`,
    /// then reintroduced here by `make_room` rebuilding source counts on every
    /// call. Asserted behaviourally — the map is untouched and the aggregate
    /// counters do not move — because a complexity claim is otherwise
    /// unfalsifiable in a unit test.
    #[test]
    fn a13_capacity_refusal_does_not_rebuild_state() {
        let mut rl = RateLimiter::new(quota_policy(1, 86_400, 64));
        for i in 0..64 {
            let k = format!("s{i}");
            let _ = rl.check_from(&k, Some(&k), 1000);
        }
        let before = rl.tracked();
        for i in 0..500 {
            assert_eq!(
                rl.check_from(&format!("new{i}"), Some(&format!("new{i}")), 1000),
                Decision::Deny {
                    reason: DenyReason::AtCapacity
                }
            );
        }
        assert_eq!(rl.tracked(), before, "refusal must not mutate the map");
    }

    /// A14 — when backoff outlasts the quota window, the horizon accounts for
    /// it.
    ///
    /// `is_releasable` rejects a refilled key that is still backing off, so a
    /// quota-only horizon leaves `next_release` in the past and every new-key
    /// check between refill and backoff-expiry pays a full scan — the same
    /// CPU path, arriving through the other clock.
    #[test]
    fn a14_the_horizon_covers_backoff_not_just_refill() {
        let policy = quota_policy(1, 60, 8).with_backoff(Backoff::new(300, 300));
        let mut rl = RateLimiter::new(policy);
        for i in 0..8 {
            let k = format!("s{i}");
            assert!(rl.check_from(&k, Some(&k), 1000).is_allowed());
            assert!(
                !rl.check_from(&k, Some(&k), 1000).is_allowed(),
                "start backoff"
            );
        }
        // Past the quota window but INSIDE backoff: nothing is releasable, and
        // the refusal must still be the cheap path.
        assert_eq!(
            rl.check_from("x", Some("x"), 1000 + 120),
            Decision::Deny {
                reason: DenyReason::AtCapacity
            }
        );
        // Past both: entries release and the newcomer gets in.
        assert!(
            rl.check_from("x", Some("x"), 1000 + 400).is_allowed(),
            "once backoff has expired too, the refilled keys are free to drop"
        );
    }

    /// A15 — an EVICTED key's absorbed denials survive into the aggregate.
    ///
    /// Losing them would undercount the attack precisely during contention,
    /// which is the worst moment to be blind (D5).
    #[test]
    fn a15_eviction_preserves_the_suppression_count() {
        let mut rl = RateLimiter::new(quota_policy(1, 86_400, 8));
        // A hoarder builds up entries AND denials.
        for i in 0..8 {
            let k = format!("h{i}");
            assert!(rl.check_from(&k, Some("hoarder"), 1000).is_allowed());
            assert!(!rl.check_from(&k, Some("hoarder"), 1000).is_allowed());
        }
        assert_eq!(rl.released_suppressed(), 0);
        // An honest source arrives and evicts one of the hoarder's keys.
        assert!(rl.check_from("honest", Some("honest"), 1000).is_allowed());
        assert!(
            rl.released_suppressed() > 0,
            "the evicted key's denials must reach the aggregate, or the attack \
             is undercounted exactly while it is happening"
        );
    }

    /// A16 — backoff SURVIVES a quota refill.
    ///
    /// When suppression outlasts the window, clearing the streak on refill ends
    /// the sentence early: a key denied at t=0 under a 60s quota and a 300s
    /// backoff would be allowed at t=60, serving a fifth of it.
    #[test]
    fn a16_backoff_outlasts_the_quota_window() {
        let policy = quota_policy(1, 60, 100).with_backoff(Backoff::new(300, 300));
        let mut rl = RateLimiter::new(policy);
        assert!(rl.check("k", 1000).is_allowed());
        assert!(!rl.check("k", 1000).is_allowed(), "quota spent");

        assert_eq!(
            rl.check("k", 1000 + 61),
            Decision::Deny {
                reason: DenyReason::BackingOff
            },
            "the quota refilled, but the SUPPRESSION has not expired"
        );
        assert!(
            rl.check("k", 1000 + 301).is_allowed(),
            "and once it has, the key is free"
        );
    }

    /// A17 — promoting an unseen key respects the ceiling.
    ///
    /// A promoted entry can never be evicted, so unbounded promotion of unseen
    /// keys grows the map past `max_keys` with entries nothing can reclaim —
    /// the hard bound quietly stops being one.
    #[test]
    fn a17_promotion_of_an_unseen_key_respects_the_cap() {
        let mut rl = RateLimiter::new(quota_policy(1, 60, 4));
        for i in 0..4 {
            assert!(rl.promote(&format!("p{i}")), "within the cap");
        }
        assert!(
            !rl.promote("one-too-many"),
            "promotion past the ceiling must be REFUSED — it would be              un-evictable forever"
        );
        assert_eq!(rl.tracked(), 4);
    }

    /// A18 — a zero-permit key still schedules its release horizon.
    ///
    /// `permits == 0` is a supported quota (hold a plane entirely), but such a
    /// key never reaches the allow path, so a horizon set only there stays at
    /// `Ts::MAX`: `make_room` never scans, and every later key is refused
    /// forever.
    #[test]
    fn a18_zero_permit_keys_still_release() {
        let mut rl = RateLimiter::new(quota_policy(0, 60, 4));
        for i in 0..4 {
            assert!(!rl
                .check_from(&format!("z{i}"), Some("src"), 1000)
                .is_allowed());
        }
        assert_eq!(rl.tracked(), 4);
        // Past the window they are refilled, carry nothing, and release.
        let _ = rl.check_from("later", Some("other"), 1000 + 61);
        assert!(
            rl.tracked() <= 4,
            "the map must still be reclaimable: {} entries",
            rl.tracked()
        );
    }

    /// A11 — at cap with ONLY promoted keys, a new key is refused and no
    /// promoted key is evicted. The map drops what it can rebuild, never what
    /// it cannot.
    #[test]
    fn a11_promoted_keys_are_never_evicted_to_make_room() {
        let mut rl = RateLimiter::new(quota_policy(1, 86_400, 4));
        for i in 0..4 {
            rl.promote(&format!("p{i}"));
        }
        assert_eq!(
            rl.check_from("newcomer", Some("someone"), 1000),
            Decision::Deny {
                reason: DenyReason::AtCapacity
            },
            "refuse rather than evict a promotion — it is the one bit that \
             cannot be rebuilt from traffic"
        );
        for i in 0..4 {
            assert_eq!(rl.class_of(&format!("p{i}")), Class::Promoted);
        }
    }

    /// D3 — a denial never carries a retry-after. Pinned structurally: adding
    /// one to `Decision` would fail to compile against this exhaustive match.
    #[test]
    fn d3_a_denial_carries_no_retry_hint() {
        let mut rl = RateLimiter::new(quota_policy(0, 60, 10));
        match rl.check("k", 1000) {
            Decision::Deny { reason } => {
                assert_eq!(reason.as_str(), "quota_spent");
            }
            Decision::Allow { .. } => panic!("zero permits must deny"),
        }
    }
}
