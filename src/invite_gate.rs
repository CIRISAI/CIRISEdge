//! CIRISEdge#554 — the receiver-side budget on unsolicited contact requests.
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

use std::collections::HashMap;

/// Unix seconds.
type Ts = u64;

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
}

/// Per-(sender, receiver) invite budget. One instance per receiving node.
#[derive(Debug, Default)]
pub struct InviteGate {
    senders: HashMap<String, SenderState>,
}

#[derive(Debug, Clone)]
struct SenderState {
    /// When the sender last spent an attempt.
    last_attempt: Ts,
    /// Attempts spent and not yet refilled.
    spent: u32,
    /// Has this receiver ever accepted anything from this sender?
    ///
    /// The single most important bit here. An established contact is not a
    /// stranger and must not be throttled like one — throttling replies is how
    /// an anti-spam control breaks the conversations it was meant to protect.
    ever_accepted: bool,
}

impl InviteGate {
    /// A stranger's budget. ONE: a second unanswered request is not new
    /// information.
    pub const STRANGER_BUDGET: u32 = 1;
    /// An accepted contact's budget. Higher because they are not a stranger, and
    /// still bounded because a compromised contact is the better attack.
    pub const CONTACT_BUDGET: u32 = 8;
    /// How long an unanswered attempt occupies the budget. Long on purpose: the
    /// thing being rate-limited is a human's attention, which does not refill in
    /// seconds.
    pub const REFILL_SECS: u64 = 86_400;

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decide whether an invite from `sender` reaches the person.
    #[must_use]
    pub fn admit(&mut self, sender: &str, now: Ts) -> InviteVerdict {
        let state = self
            .senders
            .entry(sender.to_owned())
            .or_insert(SenderState {
                last_attempt: 0,
                spent: 0,
                ever_accepted: false,
            });

        // Refill first, so a long-quiet sender is not judged on ancient history.
        if now.saturating_sub(state.last_attempt) >= Self::REFILL_SECS {
            state.spent = 0;
        }

        let budget = if state.ever_accepted {
            Self::CONTACT_BUDGET
        } else {
            Self::STRANGER_BUDGET
        };

        if state.spent >= budget {
            let reason = if state.ever_accepted {
                RefuseReason::BudgetSpent
            } else {
                // A stranger with one spent attempt has a request outstanding —
                // the more precise reason, and the one an operator reading a log
                // wants: this is not a flood, it is someone waiting.
                RefuseReason::AlreadyPending
            };
            tracing::debug!(
                sender,
                spent = state.spent,
                budget,
                ever_accepted = state.ever_accepted,
                "invite refused at the receiver's budget (CIRISEdge#554)"
            );
            return InviteVerdict::Refuse { reason };
        }

        state.spent += 1;
        state.last_attempt = now;
        InviteVerdict::Allow
    }

    /// Record that this receiver ACCEPTED something from `sender`.
    ///
    /// Promotes them out of stranger budget permanently. Called when consent is
    /// granted — an accepted contact should never be throttled as a stranger
    /// again, because the control exists to stop unwanted first contact, not to
    /// ration a conversation.
    pub fn mark_accepted(&mut self, sender: &str) {
        let entry = self
            .senders
            .entry(sender.to_owned())
            .or_insert(SenderState {
                last_attempt: 0,
                spent: 0,
                ever_accepted: false,
            });
        entry.ever_accepted = true;
        // Their outstanding attempt was answered; it should not still count.
        entry.spent = 0;
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
}
