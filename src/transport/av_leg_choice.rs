//! CIRISEdge#805 item 8, cut 2 — a subscriber chooses its leg: the publisher's
//! direct link when one is live, the relay member's otherwise, with ONE
//! delivery path at steady state.
//!
//! # The shape
//!
//! A subscriber can hear a stream on two legs: DIRECT (the publisher's own A/V
//! link, born on a punched interface, `direct_path`) and RELAY (a reachable
//! member that forwards). The choice is the SUBSCRIBER's, because only it knows
//! which leg is delivering:
//!
//! ```text
//!   RelayOnly ──direct leg up──▶ Overlap ──confirmed──▶ DirectOnly
//!       ▲                          (dedupe)  DropRelay       │
//!       └──────────── RejoinRelay ◀── direct closed / silent ┘
//! ```
//!
//! - **Make-before-break.** The relay is dropped only once the direct leg is
//!   CONFIRMED: [`DIRECT_CONFIRM_CHUNKS`] first-deliveries from it AND at least
//!   [`DIRECT_CONFIRM_DWELL`] since its first one, whichever is later, so a
//!   flapping path (or an audio stream's few quick packets) does not break the
//!   relay. During the overlap both legs deliver and the dedupe keeps one.
//! - **Dedupe above the legs.** Each leg's outer seal has its own per-link
//!   transit key and replay counter, which cannot see the other leg. The
//!   dedupe sits above the per-leg opens, on `(epoch, chunk_seq)` (the same
//!   key across legs), and is the ALM ring that already exists
//!   ([`DedupRing`] inside [`MultiParentSubscription`]): bounded, O(1) per
//!   chunk, one per stream. It is NOT reset on a switch, so a chunk that
//!   arrives on both sides of a switch is still caught.
//! - **Fallback.** The direct leg closing (the publisher's
//!   `fall_back_from_direct` closes it, and the inbound ends) or going silent
//!   for [`PARENT_SILENCE_HEAL_MS`](crate::transport::realtime_av_alm::PARENT_SILENCE_HEAL_MS)
//!   emits [`LegAction::RejoinRelay`].
//!
//! # The relay leg needs no new wire
//!
//! The subscriber OWNS its relay subscription: it dials the relay member's A/V
//! address (rejoin), and closes that link (drop). The relay admits a dialling
//! subscriber only if it is ENTITLED ([`relay_admits`]: CC 5.3.3.4, fan-out =
//! entitled ∩ reachable), and prunes one whose link is gone (the dispatcher's
//! `LinkGone`).

use std::time::Duration;

use crate::scope_addressing::{MemberStatus, ScopeAddressTable};
use crate::transport::realtime_av::{ChunkSeq, Epoch, StreamId};
use crate::transport::realtime_av_alm::{
    JoinPlan, MultiParentSubscription, ObserveOutcome, PeerKeyId,
};

/// First-deliveries the direct leg must make before the relay is dropped.
pub const DIRECT_CONFIRM_CHUNKS: u32 = 8;

/// The least time since the direct leg's first delivery before the relay is
/// dropped (a low-rate stream must not switch on a few quick packets).
pub const DIRECT_CONFIRM_DWELL: Duration = Duration::from_millis(250);

/// Which leg a chunk arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leg {
    /// The publisher's own link to this subscriber.
    Direct,
    /// The relay member's link to this subscriber.
    Relay,
}

/// What the subscriber's host does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegAction {
    /// The direct leg is confirmed: close the relay link (the relay prunes
    /// this subscriber).
    DropRelay,
    /// The direct leg is gone: dial the relay member again.
    RejoinRelay,
}

/// What became of one chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkVerdict {
    /// First sight: hand it to the consumer.
    Deliver,
    /// Already delivered from the other leg: drop it.
    Duplicate,
    /// From a leg this subscriber is not on (stale or injected): drop it,
    /// without touching the ring.
    UnknownLeg,
}

/// Where the choice stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegState {
    /// Only the relay leg.
    RelayOnly,
    /// Both legs; the direct one not yet confirmed.
    Overlap,
    /// Only the direct leg.
    DirectOnly,
}

/// CIRISEdge#805 item 8, cut 2 — one subscriber's leg choice for one stream.
/// Pure: every call takes `now_ms`; nothing reads a clock.
#[derive(Debug, Clone)]
pub struct LegChoice {
    sub: MultiParentSubscription,
    publisher: PeerKeyId,
    relay: PeerKeyId,
    state: LegState,
    direct_first_ms: Option<u64>,
    direct_delivered: u32,
}

impl LegChoice {
    /// A subscriber hearing `stream_id` from `publisher` through `relay`,
    /// starting on the relay leg.
    #[must_use]
    pub fn new(stream_id: StreamId, publisher: PeerKeyId, relay: PeerKeyId) -> Self {
        let plan = JoinPlan {
            primary_parent: relay.clone(),
            backup_parents: Vec::new(),
            stream_bitrate_mbps: 0.0,
        };
        Self {
            sub: MultiParentSubscription::new(stream_id, Vec::new(), plan),
            publisher,
            relay,
            state: LegState::RelayOnly,
            direct_first_ms: None,
            direct_delivered: 0,
        }
    }

    /// Where the choice stands.
    #[must_use]
    pub const fn state(&self) -> LegState {
        self.state
    }

    fn parent(&self, leg: Leg) -> &PeerKeyId {
        match leg {
            Leg::Direct => &self.publisher,
            Leg::Relay => &self.relay,
        }
    }

    /// The publisher's direct leg came up: overlap begins (a direct leg that
    /// is already up changes nothing).
    pub fn direct_up(&mut self, now_ms: u64) {
        if self.state != LegState::RelayOnly {
            return;
        }
        self.sub
            .add_parent_with_liveness(self.publisher.clone(), now_ms);
        self.direct_first_ms = None;
        self.direct_delivered = 0;
        self.state = LegState::Overlap;
    }

    /// The relay leg is back (after a [`LegAction::RejoinRelay`]).
    pub fn relay_rejoined(&mut self, now_ms: u64) {
        self.sub
            .add_parent_with_liveness(self.relay.clone(), now_ms);
    }

    /// A chunk arrived on `leg`. Returns its verdict and, when this chunk
    /// confirms the direct leg, [`LegAction::DropRelay`].
    pub fn on_chunk(
        &mut self,
        leg: Leg,
        epoch: Epoch,
        chunk_seq: ChunkSeq,
        now_ms: u64,
    ) -> (ChunkVerdict, Option<LegAction>) {
        let parent = self.parent(leg).clone();
        let verdict = match self.sub.observe_chunk(&parent, epoch, chunk_seq, now_ms) {
            ObserveOutcome::FirstDelivery => ChunkVerdict::Deliver,
            ObserveOutcome::Duplicate => ChunkVerdict::Duplicate,
            ObserveOutcome::UnknownParent => ChunkVerdict::UnknownLeg,
        };
        if leg != Leg::Direct || self.state != LegState::Overlap {
            return (verdict, None);
        }
        // Every chunk the direct leg carried counts toward confirming it,
        // first sight or not: a duplicate proves the leg delivers too.
        if verdict != ChunkVerdict::UnknownLeg {
            let first = *self.direct_first_ms.get_or_insert(now_ms);
            self.direct_delivered = self.direct_delivered.saturating_add(1);
            let dwelt = now_ms.saturating_sub(first) >= duration_ms(DIRECT_CONFIRM_DWELL);
            if self.direct_delivered >= DIRECT_CONFIRM_CHUNKS && dwelt {
                self.sub.apply_heal(
                    crate::transport::realtime_av_alm::HealApplyOutcome::RemoveParent(
                        self.relay.clone(),
                    ),
                );
                self.state = LegState::DirectOnly;
                return (verdict, Some(LegAction::DropRelay));
            }
        }
        (verdict, None)
    }

    /// The direct leg's link closed. Returns [`LegAction::RejoinRelay`] when
    /// the subscriber was relying on it alone; in the overlap the relay is
    /// still there and nothing needs doing.
    pub fn direct_closed(&mut self) -> Option<LegAction> {
        self.leave_direct()
    }

    /// Periodic check, every ~`HEARTBEAT_INTERVAL_MS`: a direct leg silent for
    /// [`PARENT_SILENCE_HEAL_MS`](crate::transport::realtime_av_alm::PARENT_SILENCE_HEAL_MS)
    /// is gone.
    pub fn tick(&mut self, now_ms: u64) -> Option<LegAction> {
        if self.state == LegState::RelayOnly {
            return None;
        }
        let silent = self
            .sub
            .tick(now_ms)
            .iter()
            .any(|a| matches!(a, crate::transport::realtime_av_alm::HealAction::ReParent { dead } if *dead == self.publisher));
        if silent {
            return self.leave_direct();
        }
        None
    }

    fn leave_direct(&mut self) -> Option<LegAction> {
        let was = self.state;
        if was == LegState::RelayOnly {
            return None;
        }
        self.sub.apply_heal(
            crate::transport::realtime_av_alm::HealApplyOutcome::RemoveParent(
                self.publisher.clone(),
            ),
        );
        self.state = LegState::RelayOnly;
        self.direct_first_ms = None;
        self.direct_delivered = 0;
        (was == LegState::DirectOnly).then_some(LegAction::RejoinRelay)
    }
}

fn duration_ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// CIRISEdge#805 item 8, cut 2 — the relay's admission rule for a subscriber
/// that DIALLED it (CC 5.3.3.4: fan-out = entitled ∩ reachable). `address` is
/// the relay's own address the subscriber dialled (its group names the
/// stream); the dialler is entitled iff it is a live member of that group in
/// the relay's table (current, next or previous epoch), the same room test
/// `ReticulumTransport::should_accept_direct` applies. No address: refused.
#[must_use]
pub fn relay_admits(
    table: &ScopeAddressTable,
    address: Option<&crate::scope_addressing::InboundAddress>,
    dialler: &str,
) -> bool {
    address.is_some_and(|a| {
        matches!(
            table.member_status(a.group().scope(), a.group().group_id(), dialler),
            MemberStatus::Addressable { .. }
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::realtime_av_alm::PARENT_SILENCE_HEAL_MS;

    const STREAM: StreamId = StreamId([0x5a; 32]);

    fn choice() -> LegChoice {
        LegChoice::new(STREAM, "pub".to_owned(), "relay".to_owned())
    }

    fn seq(n: u64) -> ChunkSeq {
        ChunkSeq(n)
    }

    #[test]
    fn the_relay_is_dropped_only_once_the_direct_leg_is_confirmed() {
        let mut c = choice();
        let e = Epoch(1);
        assert_eq!(
            c.on_chunk(Leg::Relay, e, seq(0), 0).0,
            ChunkVerdict::Deliver
        );
        assert_eq!(
            c.on_chunk(Leg::Direct, e, seq(1), 0).0,
            ChunkVerdict::UnknownLeg,
            "no direct leg yet"
        );
        c.direct_up(10);
        assert_eq!(c.state(), LegState::Overlap);
        // Eight quick direct chunks within the dwell: not yet.
        for n in 1..=DIRECT_CONFIRM_CHUNKS {
            let (v, a) = c.on_chunk(Leg::Direct, e, seq(u64::from(n)), 20);
            assert_eq!(v, ChunkVerdict::Deliver);
            assert_eq!(a, None, "chunk {n} inside the dwell");
            assert_eq!(
                c.on_chunk(Leg::Relay, e, seq(u64::from(n)), 20).0,
                ChunkVerdict::Duplicate,
                "the overlap is deduped"
            );
        }
        // Past the dwell, the next direct chunk confirms.
        let (v, a) = c.on_chunk(Leg::Direct, e, seq(9), 20 + 250);
        assert_eq!(v, ChunkVerdict::Deliver);
        assert_eq!(a, Some(LegAction::DropRelay));
        assert_eq!(c.state(), LegState::DirectOnly);
        assert_eq!(
            c.on_chunk(Leg::Relay, e, seq(10), 300).0,
            ChunkVerdict::UnknownLeg,
            "the relay leg is gone"
        );
    }

    #[test]
    fn a_long_dwell_with_few_chunks_waits_for_the_count() {
        let mut c = choice();
        c.direct_up(0);
        for n in 0..u64::from(DIRECT_CONFIRM_CHUNKS - 1) {
            assert_eq!(c.on_chunk(Leg::Direct, Epoch(1), seq(n), n * 1_000).1, None);
        }
        assert_eq!(
            c.on_chunk(Leg::Direct, Epoch(1), seq(99), 60_000).1,
            Some(LegAction::DropRelay)
        );
    }

    #[test]
    fn a_closed_direct_leg_rejoins_the_relay_and_the_ring_survives_the_switch() {
        let mut c = choice();
        c.direct_up(0);
        for n in 0..u64::from(DIRECT_CONFIRM_CHUNKS) {
            c.on_chunk(Leg::Direct, Epoch(1), seq(n), n * 100);
        }
        assert_eq!(c.state(), LegState::DirectOnly);
        assert_eq!(c.direct_closed(), Some(LegAction::RejoinRelay));
        assert_eq!(c.state(), LegState::RelayOnly);
        c.relay_rejoined(400);
        assert_eq!(
            c.on_chunk(Leg::Relay, Epoch(1), seq(3), 400).0,
            ChunkVerdict::Duplicate,
            "a chunk the direct leg delivered before the switch is still caught"
        );
        assert_eq!(
            c.on_chunk(Leg::Relay, Epoch(1), seq(8), 400).0,
            ChunkVerdict::Deliver
        );
    }

    #[test]
    fn closing_the_direct_leg_in_the_overlap_needs_no_rejoin() {
        let mut c = choice();
        c.direct_up(0);
        assert_eq!(c.direct_closed(), None, "the relay never left");
        assert_eq!(c.state(), LegState::RelayOnly);
    }

    #[test]
    fn a_silent_direct_leg_rejoins_the_relay() {
        let mut c = choice();
        c.direct_up(0);
        let mut last = 0;
        for n in 0..u64::from(DIRECT_CONFIRM_CHUNKS) {
            last = 1_000 + n * 100;
            c.on_chunk(Leg::Direct, Epoch(1), seq(n), last);
        }
        assert_eq!(c.state(), LegState::DirectOnly);
        assert_eq!(c.tick(last + PARENT_SILENCE_HEAL_MS - 1), None);
        assert_eq!(
            c.tick(last + PARENT_SILENCE_HEAL_MS + 1),
            Some(LegAction::RejoinRelay)
        );
    }

    #[test]
    fn the_relay_admits_only_a_live_member_of_the_dialled_group() {
        use std::sync::Arc;
        let table = ScopeAddressTable::new(Arc::new(crate::scope_addressing::ScopePrivacyDeriver));
        let scope = crate::CohortScope::Cohort {
            cohort_id: "room".to_owned(),
        };
        table
            .install_group(&scope, "g", 1, &[7u8; 32], &["relay", "member"])
            .expect("install");
        let own = table
            .send_address(&scope, "g", "relay")
            .expect("relay's own address");
        let dialled = table.accepts_inbound(own.as_bytes());
        assert!(relay_admits(&table, dialled.as_ref(), "member"));
        assert!(!relay_admits(&table, dialled.as_ref(), "outsider"));
        assert!(!relay_admits(&table, None, "member"), "no address: refused");
    }
}
