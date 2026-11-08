//! CC 5.4.6 items 4–5 — **the relay step** (FSD/ONION_ROUTING.md §6): what a
//! relay does with one onion packet that arrived on one link. Pure of I/O:
//! the transport hands in the packet and whether its link is shaped, and
//! gets back what to do or a refusal token.
//!
//! The acceptance order (`docs/onion_packet_wire.md` §5):
//! 1. the link is shaped, else [`tokens::UNSHAPED_LINK`] — before any
//!    cryptography (an unshaped link carries no onion packet);
//! 2. the packet peels under the current hop key or, for one period of
//!    rotation overlap, the previous one ([`packet::peel`]'s refusals);
//! 3. its period is this one or the last, else [`tokens::PERIOD_MISMATCH`];
//! 4. its encapsulation is new within two periods, else [`tokens::REPLAY`],
//!    and there is room for it in this period's replay set, else
//!    [`tokens::REPLAY_SET_FULL`] ([`REPLAY_BOUND`]);
//! 5. a forward fits under the hold bound, else [`tokens::HOLD_DEFERRED`].
//!
//! **The replay set is a hold** (CIRISEdge#955; CC 5.3.3.5 E1 rule 9: what a
//! node holds is bounded, refuses on overflow by name and never trims). Hop
//! keys are published, so anyone can mint valid packets with fresh
//! encapsulations; each would otherwise add an entry held for two periods.
//! The set therefore holds at most [`REPLAY_BOUND`] tags per period. Past it a
//! NEW tag is refused by name, never admitted by evicting a live one: evicting
//! would forget a tag a replay could then reuse. A replay of a tag already
//! held is still [`tokens::REPLAY`], full or not. The bound is a fixed
//! process bound derived from what the shaped links can legitimately carry,
//! not a lever.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::packet::{self, HopSecret, FLAG_FETCH, FLAG_FINAL, FLAG_MAILBOX};
use super::tokens;

/// The tag of an onion frame on a link: `CONP` ‖ the packet.
pub const ONION_FRAME_MAGIC: [u8; 4] = *b"CONP";

/// Whether `bytes` is an onion frame.
#[must_use]
pub fn is_onion_frame(bytes: &[u8]) -> bool {
    bytes.len() >= ONION_FRAME_MAGIC.len() && bytes[..ONION_FRAME_MAGIC.len()] == ONION_FRAME_MAGIC
}

/// The frame carrying `packet`.
#[must_use]
pub fn onion_frame(packet: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(ONION_FRAME_MAGIC.len() + packet.len());
    f.extend_from_slice(&ONION_FRAME_MAGIC);
    f.extend_from_slice(packet);
    f
}

/// CIRISEdge#955 — the byte rate onion packets can legitimately reach a relay
/// at: the highest class a shaped link is agreed at (`seat`,
/// `link_shaping::SEAT_BYTES_PER_S` = 33,000 B/s) on every one of the node
/// cap's eight links (`link_shaping::NODE_CAP_LINKS`). Cover is dropped at the
/// shaper and a real body is at most ρ of the rate, so this over-counts what
/// can arrive: the bound errs toward admitting.
pub const REPLAY_ADMITTED_BYTES_PER_S: u64 = 33_000 * 8;

/// CIRISEdge#955 — the most replay tags a relay holds for one period: the
/// admitted rate × the period ([`PERIOD_SECONDS`], 3,600 s) ÷ the fixed packet
/// size ([`packet::PACKET`], 15,296 B), rounded up: **62,134**. The set holds
/// this period's tags and the last's, so at most 124,268 tags; a `HashSet` of
/// 62,134 32-byte tags sits in 131,072 buckets of 33 bytes, about 4.1 MiB, so
/// the whole set stays under 8.3 MiB.
///
/// [`PERIOD_SECONDS`]: crate::transport::onion_layers::PERIOD_SECONDS
#[allow(clippy::cast_possible_truncation, clippy::cast_lossless)] // 62,134 fits; `From` is not const
pub const REPLAY_BOUND: usize = (REPLAY_ADMITTED_BYTES_PER_S
    * crate::transport::onion_layers::PERIOD_SECONDS)
    .div_ceil(packet::PACKET as u64) as usize;

const _: () = assert!(REPLAY_BOUND == 62_134);
// The bound's inputs are the shaping layer's own constants, not copies that
// can drift (the shaping layer is compiled only with the Reticulum module).
#[cfg(feature = "_reticulum-module")]
const _: () = assert!(
    REPLAY_ADMITTED_BYTES_PER_S
        == crate::transport::link_shaping::SEAT_BYTES_PER_S as u64
            * crate::transport::link_shaping::NODE_CAP_LINKS as u64
);

/// How many packets a relay holds waiting out their delay (FSD §6).
pub const DEFAULT_HOLD_BOUND: usize = 256;
/// The longest delay a relay honours; a longer one is clamped.
pub const MAX_HOLD_DELAY: Duration = Duration::from_secs(60);

/// What the relay does with a packet it accepted.
#[derive(Debug)]
pub enum RelayAction {
    /// Hold for `delay`, then send `packet` to `next_dest` over a shaped link.
    /// The hold slot is released when `hold` drops.
    Forward {
        /// The next hop's identity destination hash.
        next_dest: [u8; 16],
        /// The mixing delay.
        delay: Duration,
        /// The peeled packet.
        packet: Vec<u8>,
        /// The hold slot.
        hold: HoldSlot,
    },
    /// The final hop of a publication: store the payload (CC 5.4.6 item 2).
    Store {
        /// The publication bytes.
        payload: Vec<u8>,
    },
    /// The rendezvous seat: keep the body under the mailbox (CC 5.4.6 item 6).
    Mailbox {
        /// The body, still under the receiver's private layers.
        body: Vec<u8>,
        /// The packet is a fetch, not a deposit.
        fetch: bool,
    },
}

/// One held packet's slot under the hold bound; released on drop.
#[derive(Debug)]
pub struct HoldSlot(Arc<AtomicUsize>);

impl Drop for HoldSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The tags a relay has decapsulated this period and the last, at most
/// `bound` per period. See [the module docs](self).
#[derive(Debug)]
struct ReplaySet {
    period: u64,
    bound: usize,
    current: HashSet<[u8; 32]>,
    previous: HashSet<[u8; 32]>,
}

impl ReplaySet {
    fn new(bound: usize) -> Self {
        Self {
            period: 0,
            bound,
            current: HashSet::new(),
            previous: HashSet::new(),
        }
    }

    /// Admit `tag` seen in `period`.
    ///
    /// # Errors
    /// [`tokens::REPLAY`] when the tag is held (this period or the last);
    /// [`tokens::REPLAY_SET_FULL`] when this period already holds `bound`
    /// tags. Nothing held is ever evicted to make room.
    fn insert(&mut self, tag: [u8; 32], period: u64) -> Result<(), &'static str> {
        if period > self.period {
            if period == self.period + 1 {
                self.previous = std::mem::take(&mut self.current);
            } else {
                self.previous.clear();
                self.current.clear();
            }
            self.period = period;
        }
        if self.current.contains(&tag) || self.previous.contains(&tag) {
            return Err(tokens::REPLAY);
        }
        if self.current.len() >= self.bound {
            return Err(tokens::REPLAY_SET_FULL);
        }
        self.current.insert(tag);
        Ok(())
    }

    /// Tags held, this period and the last.
    fn len(&self) -> usize {
        self.current.len() + self.previous.len()
    }
}

/// A relay: its hop secrets, its replay set and its hold bound.
pub struct OnionRelay {
    current: HopSecret,
    previous: Option<HopSecret>,
    replay: Mutex<ReplaySet>,
    held: Arc<AtomicUsize>,
    hold_bound: usize,
}

impl std::fmt::Debug for OnionRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnionRelay")
            .field("held", &self.held.load(Ordering::Relaxed))
            .field("hold_bound", &self.hold_bound)
            .finish_non_exhaustive()
    }
}

#[allow(clippy::cast_possible_truncation)] // the period's low 32 bits, by design
const fn low32(p: u64) -> u32 {
    p as u32
}

impl OnionRelay {
    /// A relay holding `current` (and `previous` for one period of rotation
    /// overlap).
    #[must_use]
    pub fn new(current: HopSecret, previous: Option<HopSecret>) -> Self {
        Self {
            current,
            previous,
            replay: Mutex::new(ReplaySet::new(REPLAY_BOUND)),
            held: Arc::new(AtomicUsize::new(0)),
            hold_bound: DEFAULT_HOLD_BOUND,
        }
    }

    /// With a different hold bound.
    #[must_use]
    pub fn with_hold_bound(mut self, bound: usize) -> Self {
        self.hold_bound = bound;
        self
    }

    /// A smaller replay bound, so a test can fill the set with real packets.
    #[cfg(test)]
    pub(crate) fn with_replay_bound(self, bound: usize) -> Self {
        *self
            .replay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = ReplaySet::new(bound);
        self
    }

    /// The public hop key this relay answers to.
    #[must_use]
    pub fn hop_key(&self) -> &packet::HopKey {
        self.current.public()
    }

    /// CIRISEdge#955 — replay tags now held, this period and the last (at most
    /// twice [`REPLAY_BOUND`]).
    #[must_use]
    pub fn replay_tags_held(&self) -> usize {
        self.replay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Packets now held.
    #[must_use]
    pub fn held(&self) -> usize {
        self.held.load(Ordering::Acquire)
    }

    /// One packet that arrived on a link (`link_shaped`) in `now_period`.
    ///
    /// # Errors
    /// A refusal token, in the acceptance order of the module docs.
    pub fn accept(
        &self,
        pkt: &[u8],
        link_shaped: bool,
        now_period: u64,
    ) -> Result<RelayAction, &'static str> {
        if !link_shaped {
            return Err(tokens::UNSHAPED_LINK);
        }
        let peeled = match packet::peel(&self.current, pkt) {
            Err(packet::OnionError::HeaderOpenFailed) if self.previous.is_some() => {
                packet::peel(self.previous.as_ref().unwrap_or(&self.current), pkt)
            }
            other => other,
        }
        .map_err(|e| e.label())?;
        let p = peeled.block.period;
        if p != low32(now_period) && p != low32(now_period.wrapping_sub(1)) {
            return Err(tokens::PERIOD_MISMATCH);
        }
        self.replay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(peeled.replay_tag, now_period)?;
        let flags = peeled.block.flags;
        if flags & FLAG_FINAL != 0 {
            return Ok(RelayAction::Store {
                payload: peeled.payload().map_err(|e| e.label())?,
            });
        }
        if flags & FLAG_MAILBOX != 0 {
            return Ok(RelayAction::Mailbox {
                body: peeled.body().to_vec(),
                fetch: flags & FLAG_FETCH != 0,
            });
        }
        let prev = self.held.fetch_add(1, Ordering::AcqRel);
        let hold = HoldSlot(Arc::clone(&self.held));
        if prev >= self.hold_bound {
            return Err(tokens::HOLD_DEFERRED);
        }
        Ok(RelayAction::Forward {
            next_dest: peeled.block.next_dest,
            delay: Duration::from_millis(u64::from(peeled.block.delay_ms)).min(MAX_HOLD_DELAY),
            packet: peeled.packet,
            hold,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion::packet::{build_packet, HopSpec, RoutingBlock};

    fn relay(n: u8) -> HopSecret {
        HopSecret::from_xwing_seed(&[n; 32]).unwrap()
    }

    fn pkt(to: &HopSecret, period: u32, final_hop: bool) -> Vec<u8> {
        let mut hops = vec![HopSpec {
            key: to.public().clone(),
            block: RoutingBlock {
                next_dest: [7; 16],
                flags: 0,
                delay_ms: 65_000,
                period,
            },
        }];
        if final_hop {
            hops[0].block.flags = FLAG_FINAL;
        } else {
            let last = relay(99);
            hops.push(HopSpec {
                key: last.public().clone(),
                block: RoutingBlock {
                    next_dest: [0; 16],
                    flags: FLAG_FINAL,
                    delay_ms: 0,
                    period,
                },
            });
        }
        build_packet(&hops, b"p").unwrap()
    }

    /// CC 5.4.6 items 4–5 — **an unshaped link carries no onion packet**: the
    /// relay refuses it by name before touching the cryptography, and the
    /// same packet on a shaped link is accepted.
    #[test]
    fn a_relay_refuses_an_onion_packet_on_an_unshaped_link() {
        let r = relay(1);
        let p = pkt(&r, 10, false);
        let relay = OnionRelay::new(relay(1), None);
        assert_eq!(
            relay.accept(&p, false, 10).unwrap_err(),
            tokens::UNSHAPED_LINK
        );
        // Even garbage is refused as unshaped first: no crypto ran.
        assert_eq!(
            relay.accept(b"junk", false, 10).unwrap_err(),
            tokens::UNSHAPED_LINK
        );
        match relay.accept(&p, true, 10).expect("shaped") {
            RelayAction::Forward {
                next_dest, delay, ..
            } => {
                assert_eq!(next_dest, [7; 16]);
                assert_eq!(delay, MAX_HOLD_DELAY, "a 65 s delay is clamped to 60 s");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn replay_period_and_hold_bound_are_refused_by_name() {
        let r = relay(1);
        let relay = OnionRelay::new(relay(1), None).with_hold_bound(1);
        let p = pkt(&r, 10, false);
        let first = relay.accept(&p, true, 10).expect("first");
        assert_eq!(relay.held(), 1);
        assert_eq!(relay.accept(&p, true, 10).unwrap_err(), tokens::REPLAY);
        assert_eq!(
            relay.accept(&p, true, 11).unwrap_err(),
            tokens::REPLAY,
            "two periods"
        );
        let q = pkt(&r, 10, false);
        assert_eq!(
            relay.accept(&q, true, 10).unwrap_err(),
            tokens::HOLD_DEFERRED
        );
        drop(first);
        assert_eq!(relay.held(), 0);
        let old = pkt(&r, 7, false);
        assert_eq!(
            relay.accept(&old, true, 10).unwrap_err(),
            tokens::PERIOD_MISMATCH
        );
        let wrong = pkt(&relay_other(), 10, false);
        assert_eq!(
            relay.accept(&wrong, true, 10).unwrap_err(),
            "onion_hdr_open_failed"
        );
        let fin = pkt(&r, 10, true);
        assert!(matches!(
            relay.accept(&fin, true, 10),
            Ok(RelayAction::Store { payload }) if payload == b"p"
        ));
    }

    /// CIRISEdge#955 — **the bound is the admitted rate × the period**: eight
    /// shaped links at the highest class, each carrying back-to-back packets
    /// for a whole period, fit under it, and it is no looser than one packet
    /// per link of rounding.
    #[test]
    fn the_replay_bound_is_the_admitted_rate_over_one_period() {
        let per_link_per_period =
            33_000 * crate::transport::onion_layers::PERIOD_SECONDS / packet::PACKET as u64;
        let eight_links = usize::try_from(8 * per_link_per_period).unwrap();
        assert!(
            eight_links <= REPLAY_BOUND,
            "{eight_links} > {REPLAY_BOUND}"
        );
        assert!(
            REPLAY_BOUND - eight_links <= 8,
            "the bound is the rate, not slack"
        );
        assert_eq!(REPLAY_BOUND, 62_134);
    }

    fn tag(i: usize) -> [u8; 32] {
        let mut t = [0u8; 32];
        t[..8].copy_from_slice(&(i as u64).to_le_bytes());
        t[31] = 0xA5;
        t
    }

    /// CIRISEdge#955 — **a flood past the bound is refused by name and the set
    /// stays bounded** (CC 5.3.3.5 E1 rule 9), at the production bound: eight
    /// links each present three times their share of distinct tags in one
    /// period. Exactly [`REPLAY_BOUND`] are admitted, every other one is
    /// [`tokens::REPLAY_SET_FULL`], the table never grows past what the bound
    /// filled, and every admitted tag is still [`tokens::REPLAY`] afterwards,
    /// in this period and across the rotation into the next, whose own flood
    /// is bounded the same way.
    #[test]
    fn a_replay_flood_past_the_bound_is_refused_by_name_and_held_tags_stay_refused() {
        const LINKS: usize = 8;
        let mut set = ReplaySet::new(REPLAY_BOUND);
        let flood = 3 * REPLAY_BOUND;
        let (mut admitted, mut full) = (Vec::new(), 0usize);
        let mut filled_capacity = None;
        // Interleave the eight links' packets, as the shaped links deliver them.
        for i in 0..flood {
            let (link, seq) = (i % LINKS, i / LINKS);
            let t = tag(link * flood + seq);
            match set.insert(t, 10) {
                Ok(()) => admitted.push(t),
                Err(e) => {
                    assert_eq!(e, tokens::REPLAY_SET_FULL);
                    full += 1;
                    filled_capacity.get_or_insert(set.current.capacity());
                }
            }
        }
        assert_eq!(admitted.len(), REPLAY_BOUND);
        assert_eq!(full, flood - REPLAY_BOUND);
        assert_eq!(set.len(), REPLAY_BOUND);
        assert_eq!(
            Some(set.current.capacity()),
            filled_capacity,
            "the overflow allocated nothing"
        );
        // About 4.1 MiB per period at 33 bytes a bucket.
        assert!(set.current.capacity() * 33 <= 5 << 20);
        for t in &admitted {
            assert_eq!(
                set.insert(*t, 10),
                Err(tokens::REPLAY),
                "nothing was evicted"
            );
        }
        // The next period: last period's tags are still refused as replays,
        // and the new flood is bounded on its own.
        let mut admitted_next = 0usize;
        for i in 0..flood {
            match set.insert(tag(LINKS * flood + i), 11) {
                Ok(()) => admitted_next += 1,
                Err(e) => assert_eq!(e, tokens::REPLAY_SET_FULL),
            }
        }
        assert_eq!(admitted_next, REPLAY_BOUND);
        assert_eq!(set.len(), 2 * REPLAY_BOUND);
        for t in &admitted {
            assert_eq!(set.insert(*t, 11), Err(tokens::REPLAY), "across rotation");
        }
    }

    /// CIRISEdge#955 — the same through the relay step with real packets: at
    /// the bound a fresh packet is [`tokens::REPLAY_SET_FULL`], an admitted
    /// one is still [`tokens::REPLAY`], and the next period has room again
    /// while the last period's packets stay refused.
    #[test]
    fn a_full_replay_set_refuses_a_fresh_packet_and_still_refuses_a_replay() {
        let r = relay(1);
        let relay = OnionRelay::new(relay(1), None).with_replay_bound(2);
        let (a, b, c) = (pkt(&r, 10, true), pkt(&r, 10, true), pkt(&r, 10, true));
        assert!(matches!(
            relay.accept(&a, true, 10),
            Ok(RelayAction::Store { .. })
        ));
        assert!(matches!(
            relay.accept(&b, true, 10),
            Ok(RelayAction::Store { .. })
        ));
        assert_eq!(
            relay.accept(&c, true, 10).unwrap_err(),
            tokens::REPLAY_SET_FULL
        );
        assert_eq!(relay.accept(&a, true, 10).unwrap_err(), tokens::REPLAY);
        assert_eq!(relay.replay_tags_held(), 2);
        assert_eq!(relay.accept(&a, true, 11).unwrap_err(), tokens::REPLAY);
        assert_eq!(relay.accept(&b, true, 11).unwrap_err(), tokens::REPLAY);
        assert!(matches!(
            relay.accept(&c, true, 11),
            Ok(RelayAction::Store { .. })
        ));
        assert_eq!(relay.replay_tags_held(), 3);
    }

    fn relay_other() -> HopSecret {
        relay(2)
    }

    /// One period of rotation overlap: a packet built to the previous hop key
    /// still peels.
    #[test]
    fn the_previous_hop_key_is_honoured_for_one_overlap() {
        let old = relay(1);
        let p = pkt(&old, 10, true);
        let relay = OnionRelay::new(relay(2), Some(relay(1)));
        assert!(matches!(
            relay.accept(&p, true, 10),
            Ok(RelayAction::Store { .. })
        ));
    }
}
