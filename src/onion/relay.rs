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
//! 4. its encapsulation is new within two periods, else [`tokens::REPLAY`];
//! 5. a forward fits under the hold bound, else [`tokens::HOLD_DEFERRED`].

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

#[derive(Debug, Default)]
struct ReplaySet {
    period: u64,
    current: HashSet<[u8; 32]>,
    previous: HashSet<[u8; 32]>,
}

impl ReplaySet {
    /// Insert `tag` seen in `period`; `false` when already seen.
    fn insert(&mut self, tag: [u8; 32], period: u64) -> bool {
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
            return false;
        }
        self.current.insert(tag);
        true
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
            replay: Mutex::new(ReplaySet::default()),
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

    /// The public hop key this relay answers to.
    #[must_use]
    pub fn hop_key(&self) -> &packet::HopKey {
        self.current.public()
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
        if !self
            .replay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(peeled.replay_tag, now_period)
        {
            return Err(tokens::REPLAY);
        }
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
