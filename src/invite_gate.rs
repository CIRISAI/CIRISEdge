//! CIRISEdge#554 — the receiver-side budget on unsolicited contact requests.
//!
//! # WHERE THIS RUNS — it is not called inside edge, deliberately
//!
//! A repo-wide search finds no caller, and that is the correct state rather
//! than an oversight: **edge has no inbound contact-request path to wire it
//! into.** The wire carries `Summary`/`Diff`/`Fetch`/`Deliver`/`Pull`/
//! `CursorPull` — anti-entropy verbs — and no invite verb at all. Contact
//! requests and chat are the SERVER's tier (`POST /v1/contacts`), which is also
//! where a human is shown the invite.
//!
//! Enforcing the budget at replication ADMISSION would be actively wrong. An
//! invite that arrives as a signed `Community` record is legitimate federation
//! state; refusing to admit it would withhold carriage of a correctly-signed
//! row on a rate heuristic — the silent-state-withholding class CIRISEdge#425
//! exists to make impossible. The thing being rate-limited is not the record's
//! ARRIVAL, it is its PRESENTATION to a person, and that decision lives where
//! the presenting happens.
//!
//! So this is a library the presenting tier calls, in the same position as
//! [`crate::contact::resolve`]. Wiring it here would mean inventing a call site
//! to make a search result look better.
//!
//! # The threat this covers, and why nothing else does
//!
//! An invite is low-volume, well-formed, correctly signed, and semantically
//! hostile. The existing defences are all about VOLUME — AV-10 (transport
//! flooding), AV-13 (body size), AV-48 (high-N low-T envelope flood, whose trust
//! threshold defaults to `0.0` bootstrap-permissive) — and none of them fire on
//! one polite message from a stranger. That class is not in the threat model.
//!
//! It gets worse with the federation-tier directory: once every identity is
//! promoted so the kill switch can reach it, mass invite spam stops needing a
//! target list, because the directory IS the target list.
//!
//! # Enforced at the RECEIVER
//!
//! A sender-side limit is advice. The budget lives where the cost lands.
//!
//! # Small budget, slow refill, and decay for strangers
//!
//! A stranger gets ONE attempt, not a retry loop: a second unanswered request is
//! not new information, it is pressure. Senders a receiver has never accepted
//! decay toward zero, so persistence costs the sender rather than the receiver.
//!
//! And the check happens BEFORE a human sees anything, so the cost of spam is
//! borne by the node and not by the person — which is the actual point. A filter
//! that shows you the spam and then reports it was suspicious has already failed.

/// Unix seconds.
///
/// Public because it appears in [`InviteGate::admit`]'s signature: a caller that
/// cannot NAME the type is a caller reading rustdoc for an alias it has no path
/// to. The clock is the caller's — the gate never reads one itself, so it stays
/// testable and a host can drive it from whatever time source it already trusts.
pub type Ts = u64;

/// What the gate decided, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteVerdict {
    /// Deliver it to the person.
    Allow,
    /// Drop it. The sender has spent its budget.
    ///
    /// Deliberately does NOT say when they may retry: telling a spammer the
    /// refill interval is telling them the optimal send rate.
    Refuse { reason: RefuseReason },
}

/// Why an invite was refused. For the RECEIVER's operator, never for the sender
/// — a refusal that explains itself over the wire is a tuning oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefuseReason {
    /// This sender has an unanswered request outstanding.
    AlreadyPending,
    /// This sender has spent its budget and has not been accepted before.
    BudgetSpent,
    /// CIRISEdge#554 — the receiver is already tracking as many strangers as it
    /// will hold, and none could be released. A GLOBAL bound, not a per-sender
    /// one: identity rotation defeats a per-sender budget by never reusing a
    /// sender, so without a ceiling the map is the attack surface.
    ReceiverAtCapacity,
}

impl RefuseReason {
    /// Stable token for the receiver's operator logs. Never shown to the
    /// sender: what a refused sender learns should be nothing at all.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RefuseReason::AlreadyPending => "already_pending",
            RefuseReason::BudgetSpent => "budget_spent",
            RefuseReason::ReceiverAtCapacity => "receiver_at_capacity",
        }
    }
}

/// Per-(sender, receiver) invite budget. One instance per receiving node.
///
/// A thin policy face over [`crate::rate_limit::RateLimiter`]
/// (`docs/FSD_RATE_LIMIT.md`): the budgets, the promotion rule and the
/// refusal vocabulary are this module's; the bounded map, the fair eviction,
/// the O(1) at-capacity path and the clock discipline are the shared
/// limiter's. Those were the parts this file got wrong twice.
#[derive(Debug)]
pub struct InviteGate {
    limiter: crate::rate_limit::RateLimiter,
}

impl InviteGate {
    /// A stranger gets ONE attempt. Not a rate — a standing invitation to
    /// nobody. If they are ignored, that is an answer.
    pub const STRANGER_BUDGET: u32 = 1;

    /// An accepted contact gets a real allowance. An established contact is not
    /// a stranger and must not be throttled like one — throttling replies is
    /// how an anti-spam control breaks the conversations it was meant to
    /// protect.
    pub const CONTACT_BUDGET: u32 = 8;

    /// How long until a spent budget refills.
    pub const REFILL_SECS: u64 = 86_400;

    /// How many senders one receiver tracks.
    pub const SENDER_CAP: usize = 65_536;

    #[must_use]
    pub fn new() -> Self {
        Self {
            limiter: crate::rate_limit::RateLimiter::new(crate::rate_limit::Policy::tiered(
                crate::rate_limit::Quota::new(Self::STRANGER_BUDGET, Self::REFILL_SECS),
                crate::rate_limit::Quota::new(Self::CONTACT_BUDGET, Self::REFILL_SECS),
                Self::SENDER_CAP,
            )),
        }
    }

    /// How many senders this receiver is currently tracking.
    #[must_use]
    pub fn tracked_senders(&self) -> usize {
        self.limiter.tracked()
    }

    /// Decide whether an invite from `sender` reaches the person.
    ///
    /// The clock is the caller's, so a 24-hour refill is testable.
    #[must_use]
    pub fn admit(&mut self, sender: &str, now: Ts) -> InviteVerdict {
        use crate::rate_limit::{Class, Decision, DenyReason};
        // Every sender is its own source: an invite flood IS identity rotation,
        // so there is no upstream party to charge the eviction to.
        match self.limiter.check_from(sender, Some(sender), now) {
            Decision::Allow { .. } => InviteVerdict::Allow,
            Decision::Deny { reason } => {
                let reason = match reason {
                    DenyReason::AtCapacity => RefuseReason::ReceiverAtCapacity,
                    // A stranger's single attempt is spent: they are WAITING on
                    // a human, not flooding. Saying so keeps the operator's
                    // diagnostic honest about which it is.
                    DenyReason::QuotaSpent | DenyReason::BackingOff => {
                        if self.limiter.class_of(sender) == Class::Promoted {
                            RefuseReason::BudgetSpent
                        } else {
                            RefuseReason::AlreadyPending
                        }
                    }
                };
                tracing::debug!(
                    sender,
                    reason = reason.as_str(),
                    "invite refused (CIRISEdge#554)"
                );
                InviteVerdict::Refuse { reason }
            }
        }
    }

    /// Record that this receiver ACCEPTED something from `sender`.
    ///
    /// Promotes them out of the stranger budget permanently, and makes them
    /// un-evictable: acceptance is the one bit that cannot be reconstructed
    /// from traffic, so the map may drop anything else first.
    pub fn mark_accepted(&mut self, sender: &str) {
        self.limiter.promote(sender);
    }
}

impl Default for InviteGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{InviteGate, InviteVerdict, RefuseReason};

    const T0: u64 = 1_000_000;

    /// A stranger gets ONE attempt. The second is pressure, not information.
    #[test]
    fn a_stranger_gets_exactly_one_attempt() {
        let mut g = InviteGate::new();
        assert_eq!(g.admit("stranger", T0), InviteVerdict::Allow);
        assert_eq!(
            g.admit("stranger", T0 + 1),
            InviteVerdict::Refuse {
                reason: RefuseReason::AlreadyPending
            }
        );
    }

    /// The refusal for a waiting stranger says PENDING, not "flood". An operator
    /// reading the log is looking at someone waiting for an answer, and calling
    /// that a flood would misdescribe the one case that is usually legitimate.
    #[test]
    fn a_waiting_stranger_is_pending_not_a_flood() {
        let mut g = InviteGate::new();
        let _spend = g.admit("stranger", T0);
        let InviteVerdict::Refuse { reason } = g.admit("stranger", T0 + 1) else {
            panic!("second attempt must refuse");
        };
        assert_eq!(reason, RefuseReason::AlreadyPending);
    }

    /// Accepting someone must stop throttling them. An anti-spam control that
    /// rations an established conversation has broken the thing it protects.
    #[test]
    fn accepting_a_contact_lifts_the_stranger_budget() {
        let mut g = InviteGate::new();
        let _spend = g.admit("frank", T0);
        assert!(matches!(
            g.admit("frank", T0 + 1),
            InviteVerdict::Refuse { .. }
        ));

        g.mark_accepted("frank");
        for i in 0..InviteGate::CONTACT_BUDGET {
            assert_eq!(
                g.admit("frank", T0 + 10 + u64::from(i)),
                InviteVerdict::Allow,
                "an accepted contact must not be throttled as a stranger"
            );
        }
    }

    /// Even an accepted contact is bounded — a compromised contact is the better
    /// attack precisely because it is trusted.
    #[test]
    fn an_accepted_contact_is_still_bounded() {
        let mut g = InviteGate::new();
        g.mark_accepted("frank");
        for i in 0..InviteGate::CONTACT_BUDGET {
            assert_eq!(g.admit("frank", T0 + u64::from(i)), InviteVerdict::Allow);
        }
        assert_eq!(
            g.admit("frank", T0 + 100),
            InviteVerdict::Refuse {
                reason: RefuseReason::BudgetSpent
            }
        );
    }

    /// A long-quiet sender is not judged on ancient history: the budget refills.
    /// Without this, one refused invite would bar someone forever, and a person
    /// who genuinely mistyped an ID once could never try again.
    #[test]
    fn the_budget_refills_after_a_long_silence() {
        let mut g = InviteGate::new();
        let _spend = g.admit("stranger", T0);
        assert!(matches!(
            g.admit("stranger", T0 + 1),
            InviteVerdict::Refuse { .. }
        ));
        assert_eq!(
            g.admit("stranger", T0 + InviteGate::REFILL_SECS),
            InviteVerdict::Allow
        );
    }

    /// Budgets are PER SENDER. One spammer must not consume the budget that
    /// makes a real contact request reach the person.
    #[test]
    fn one_sender_cannot_spend_anothers_budget() {
        let mut g = InviteGate::new();
        // Spend the spammer's budget many times over.
        for i in 0..50 {
            let _spend = g.admit("spammer", T0 + i);
        }
        assert_eq!(
            g.admit("real-person", T0 + 100),
            InviteVerdict::Allow,
            "a flood from one sender must not silence everyone else"
        );
    }

    /// CIRISEdge#554 — rotating identities must not grow the receiver without
    /// bound, and must not evict an established contact to do it.
    #[test]
    fn identity_rotation_cannot_grow_the_receiver_without_bound() {
        let mut gate = InviteGate::new();
        let t0: super::Ts = 1_000_000;

        // An established contact, seen once and accepted. This bit is the one
        // thing the gate cannot reconstruct, so it must survive everything.
        assert!(matches!(gate.admit("friend", t0), InviteVerdict::Allow));
        gate.mark_accepted("friend");

        // A flood of never-repeated senders, all at the same instant so none can
        // be released as refilled.
        for i in 0..(InviteGate::SENDER_CAP + 500) {
            let _ = gate.admit(&format!("rotating-{i}"), t0);
        }

        assert!(
            gate.tracked_senders() <= InviteGate::SENDER_CAP,
            "the map must stay bounded under identity rotation: {} entries",
            gate.tracked_senders()
        );
        assert!(
            matches!(
                gate.admit("another-stranger", t0),
                InviteVerdict::Refuse {
                    reason: RefuseReason::ReceiverAtCapacity
                }
            ),
            "at capacity with nothing releasable, a NEW stranger is refused \
             outright — the global bound is the control, since a per-sender \
             budget is exactly what rotation defeats"
        );

        // The established contact still gets through, and is not throttled as a
        // stranger.
        assert!(
            matches!(gate.admit("friend", t0), InviteVerdict::Allow),
            "an accepted contact must never be evicted or throttled by a flood \
             of strangers — that is the anti-spam control breaking the \
             conversations it exists to protect"
        );
    }

    /// Once a stranger's budget has refilled, its retained state is
    /// indistinguishable from never having been seen — so releasing it is free
    /// and reopens capacity.
    #[test]
    fn refilled_strangers_are_released_to_make_room() {
        let mut gate = InviteGate::new();
        let t0: super::Ts = 1_000_000;
        for i in 0..InviteGate::SENDER_CAP {
            let _ = gate.admit(&format!("old-{i}"), t0);
        }
        let later = t0 + InviteGate::REFILL_SECS + 1;
        assert!(
            matches!(gate.admit("newcomer", later), InviteVerdict::Allow),
            "after the refill window the old strangers are releasable, so a new \
             sender is admitted rather than refused at capacity"
        );
    }
}
