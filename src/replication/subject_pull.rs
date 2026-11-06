//! The bounded, windowed ledgers behind a subject `Pull`'s serve path.
//!
//! Three questions the serve path asks, one shape: a key remembered for a fixed
//! window, bounded, with O(1)-amortized expiry (docs/FSD_RATE_LIMIT.md D2 — no
//! scan a rejected request can force).
//!
//! - **Has this lookup been paid for?** (CIRISEdge#936, [`SubjectPullCharges`]):
//!   a server's subject Pull is five sessions for ONE subject, and a person's
//!   contact add re-asks it until the row lands. One charge per
//!   `(requester, subject, budget, window)`.
//! - **What did a Pull offer this requester?** (CC 5.4.6, [`PullOffers`]): the
//!   Pull's widened reach has to survive to the `Deliver` that answers it, and
//!   no further than that.
//! - **Did a miss already kick?** (`MissKicks`): one round per
//!   `(subject, [`MISS_KICK_WINDOW_SECS`])`.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

use crate::rate_limit::Ts;

/// How many entries each ledger holds. A peer id is attributed and the lookup
/// limiter bounds the rate, so this is a backstop, sized like
/// `IDENTIFIER_LOOKUP_MAX_PEERS`.
pub(crate) const LEDGER_CAP: usize = 16_384;

/// One round per subject per this many seconds, however many requesters miss.
pub(crate) const MISS_KICK_WINDOW_SECS: Ts = 60;

/// At most this many of a person's nodes are kicked by one miss.
pub(crate) const MISS_KICK_MAX_PEERS: usize = 8;

/// How long a Pull's offer stays fetchable. Longer than a Pull exchange, whose
/// Diff follows its Summary by one round trip; a requester that returns later
/// Pulls again and is charged for it.
pub(crate) const PULL_OFFER_TTL_SECS: Ts = 120;

/// A paid lookup answers this many times inside its window before it is charged
/// again. Four public planes times four re-asks a minute: the re-ask of a person
/// waiting on a contact is free, a loop asking one name forever is not.
pub(crate) const PAID_LOOKUP_ANSWERS: u32 = 24;

/// Keys remembered until a fixed expiry. Insertion order is expiry order for a
/// ledger with one TTL, so expiry pops the front.
pub(crate) struct WindowLedger<K, V> {
    entries: HashMap<K, (Ts, V)>,
    expiry: VecDeque<(Ts, K)>,
    cap: usize,
}

impl<K: Eq + Hash + Clone, V> WindowLedger<K, V> {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            entries: HashMap::new(),
            expiry: VecDeque::new(),
            cap,
        }
    }

    fn release(&mut self, now: Ts) {
        while self.expiry.front().is_some_and(|(at, _)| *at <= now) {
            if let Some((at, key)) = self.expiry.pop_front() {
                // A key re-inserted since has a later expiry and stays.
                if self.entries.get(&key).is_some_and(|(held, _)| *held == at) {
                    self.entries.remove(&key);
                }
            }
        }
    }

    pub(crate) fn get_mut(&mut self, key: &K, now: Ts) -> Option<&mut V> {
        self.release(now);
        self.entries.get_mut(key).map(|(_, v)| v)
    }

    pub(crate) fn contains(&mut self, key: &K, now: Ts) -> bool {
        self.get_mut(key, now).is_some()
    }

    pub(crate) fn remove(&mut self, key: &K) {
        self.entries.remove(key);
    }

    /// Remember `key` until `expires`. At capacity nothing is recorded and
    /// `false` comes back: every ledger here fails toward its gate running
    /// again, never toward a gate skipped.
    pub(crate) fn insert(&mut self, key: K, value: V, expires: Ts, now: Ts) -> bool {
        self.release(now);
        if self.entries.len() >= self.cap && !self.entries.contains_key(&key) {
            return false;
        }
        self.expiry.push_back((expires, key.clone()));
        self.entries.insert(key, (expires, value));
        true
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Which budget a subject Pull is charged to (CIRISEdge#936). Two, so a
/// requester's catch-up on the public planes can never spend the lookup a person
/// is waiting on, and the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum LookupBudget {
    PublicPlane,
    AnnouncedTestimony,
}

struct PaidLookup {
    allowed: bool,
    answers: u32,
}

/// One charge per `(requester, subject, budget, window)`. Remembers the VERDICT,
/// so the kinds of one lookup agree with each other for the window: a denied
/// lookup is not re-charged kind by kind into a deeper deficit.
pub(crate) struct SubjectPullCharges {
    paid: WindowLedger<(String, String, LookupBudget), PaidLookup>,
}

impl Default for SubjectPullCharges {
    fn default() -> Self {
        Self {
            paid: WindowLedger::new(LEDGER_CAP),
        }
    }
}

impl SubjectPullCharges {
    /// The verdict this lookup has already bought, or `None` when it must be
    /// charged: never seen this window, or asked past [`PAID_LOOKUP_ANSWERS`].
    pub(crate) fn prior_verdict(
        &mut self,
        requester: &str,
        subject: &str,
        budget: LookupBudget,
        now: Ts,
    ) -> Option<bool> {
        let key = (requester.to_owned(), subject.to_owned(), budget);
        let entry = self.paid.get_mut(&key, now)?;
        if entry.answers >= PAID_LOOKUP_ANSWERS {
            self.paid.remove(&key);
            return None;
        }
        entry.answers += 1;
        Some(entry.allowed)
    }

    /// Record the verdict a charge returned, good until `expires`.
    pub(crate) fn record(
        &mut self,
        requester: &str,
        subject: &str,
        budget: LookupBudget,
        allowed: bool,
        expires: Ts,
        now: Ts,
    ) {
        let key = (requester.to_owned(), subject.to_owned(), budget);
        let paid = PaidLookup {
            allowed,
            answers: 1,
        };
        self.paid.insert(key, paid, expires, now);
    }
}

/// What a subject Pull offered which requester, by content hash.
pub(crate) type PullOffers = WindowLedger<(String, [u8; 32]), ()>;

/// The subjects a miss has kicked a round for, this window.
pub(crate) type MissKicks = WindowLedger<String, ()>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lookup_is_charged_once_per_window_and_per_budget_936() {
        let mut c = SubjectPullCharges::default();
        let b = LookupBudget::AnnouncedTestimony;
        assert_eq!(c.prior_verdict("r", "s", b, 100), None, "first ask pays");
        c.record("r", "s", b, true, 160, 100);
        assert_eq!(c.prior_verdict("r", "s", b, 110), Some(true), "repaid free");
        assert_eq!(
            c.prior_verdict("r", "s", LookupBudget::PublicPlane, 110),
            None,
            "the other budget is its own charge"
        );
        assert_eq!(c.prior_verdict("r", "t", b, 110), None, "another subject");
        assert_eq!(c.prior_verdict("q", "s", b, 110), None, "another requester");
        assert_eq!(c.prior_verdict("r", "s", b, 160), None, "the next window");
    }

    #[test]
    fn a_denial_is_remembered_and_a_loop_on_one_name_pays_again_936() {
        let mut c = SubjectPullCharges::default();
        let b = LookupBudget::PublicPlane;
        c.record("r", "s", b, false, 160, 100);
        assert_eq!(c.prior_verdict("r", "s", b, 101), Some(false));

        c.record("r", "t", b, true, 160, 100);
        for _ in 1..PAID_LOOKUP_ANSWERS {
            assert_eq!(c.prior_verdict("r", "t", b, 101), Some(true));
        }
        assert_eq!(
            c.prior_verdict("r", "t", b, 101),
            None,
            "past its answers a paid lookup is charged again, or one name is an \
             unmetered directory read"
        );
    }

    #[test]
    fn a_ledger_is_bounded_and_fails_toward_running_the_gate() {
        let mut l: WindowLedger<u32, ()> = WindowLedger::new(2);
        assert!(l.insert(1, (), 10, 0));
        assert!(l.insert(2, (), 11, 0));
        assert!(!l.insert(3, (), 12, 0), "full: not recorded");
        assert!(!l.contains(&3, 0));
        assert!(l.insert(3, (), 20, 10), "1 expired, so 3 fits");
        assert_eq!(l.len(), 2);
        assert!(!l.contains(&1, 10));
    }

    #[test]
    fn a_reinserted_key_outlives_its_first_expiry() {
        let mut l: WindowLedger<u32, ()> = WindowLedger::new(4);
        l.insert(1, (), 10, 0);
        l.insert(1, (), 30, 5);
        assert!(l.contains(&1, 12), "the later expiry stands");
        assert!(!l.contains(&1, 30));
    }
}
