//! What the ALM controller reads off the Reticulum transport (ALM stage 2):
//! per-link delivery telemetry (leviculum#35, the C1 meter's sender-side
//! input), per-link timed-frame expiries (leviculum#94, C5), and relay routes
//! learned (leviculum#91, the relay tier's candidates).
//!
//! The transport's event loop writes it; the call layer reads it once per
//! watch tick. Nothing here blocks the event loop: every write is a short
//! std-mutex section.

use std::collections::HashMap;
use std::sync::Mutex;

/// One A/V link's delivery telemetry, as leviculum reports it (leviculum#35).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct AvLinkStats {
    /// Cumulative bytes confirmed delivered.
    pub bytes_delivered: u64,
    /// Smoothed RTT (ms), once measured.
    pub srtt_ms: Option<f64>,
    /// Minimum RTT (ms), the propagation floor.
    pub min_rtt_ms: Option<u64>,
    /// Cumulative sends refused because the Channel window was full.
    pub busy_rejections: u64,
    /// Cumulative sends refused by the link pacer.
    pub pacing_rejections: u64,
    /// The Channel window now.
    pub window: usize,
    /// The Channel window's ceiling.
    pub window_max: usize,
    /// Channel messages sent and not yet proved delivered (the tx ring).
    pub tx_ring: usize,
    /// The newest Channel message's sequence, `None` before the link has a
    /// Channel (leviculum +ciris.3). Read after a send it is at or after
    /// that send's: the watermark a leave and a replacement wait on (v45).
    pub last_sent_seq: Option<u16>,
    /// The oldest Channel message still awaiting its delivery proof, `None`
    /// when every message sent was proved (leviculum +ciris.3).
    pub oldest_unacked_seq: Option<u16>,
}

impl AvLinkStats {
    /// Queueing delay above the propagation floor (ms): `srtt − min_rtt`.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn queue_delay_ms(&self) -> f64 {
        match (self.srtt_ms, self.min_rtt_ms) {
            (Some(s), Some(m)) => (s - m as f64).max(0.0),
            _ => 0.0,
        }
    }

    /// v45 — whether the Channel message sent as `seq`, and every one sent
    /// before it, was proved delivered: nothing is outstanding, or the
    /// oldest outstanding was sent after `seq` (16-bit serial order; the
    /// ring never holds more than the window, far below 2^15). The ring is
    /// send-ordered (leviculum +ciris.3), so later traffic still in flight
    /// does not hide the proof.
    #[must_use]
    pub fn delivered_through(&self, seq: u16) -> bool {
        self.oldest_unacked_seq.is_none_or(|oldest| {
            let d = oldest.wrapping_sub(seq);
            d != 0 && d < 0x8000
        })
    }
}

/// Timed frames on one link that never arrived fresh (leviculum#94).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExpiredCounts {
    /// This node's own frames past their deadline unconfirmed.
    pub sender: u64,
    /// The peer's frames that arrived as an expired marker.
    pub marked_by_peer: u64,
    /// The peer's frames that arrived too late and were dropped.
    pub arrived_late: u64,
}

/// One relay route leviculum learned (leviculum#91).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LearnedRelayRoute {
    /// The destination.
    pub destination: [u8; 16],
    /// The relay's transport id.
    pub relay: [u8; 16],
    /// The interface it was heard on.
    pub interface_index: usize,
    /// Hops through it.
    pub hops: u8,
}

/// Bound on remembered learned routes.
const LEARNED_CAP: usize = 1024;

/// The transport's ALM-side state.
#[derive(Debug, Default)]
pub struct AlmLinkState {
    expired: Mutex<HashMap<[u8; 16], ExpiredCounts>>,
    learned: Mutex<Vec<LearnedRelayRoute>>,
    learned_total: std::sync::atomic::AtomicU64,
}

impl AlmLinkState {
    /// A fresh state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Count one expiry on `link`.
    pub fn note_expired(&self, link: [u8; 16], sender: bool, marked: bool) {
        let mut m = Self::lock(&self.expired);
        let e = m.entry(link).or_default();
        if sender {
            e.sender += 1;
        } else if marked {
            e.marked_by_peer += 1;
        } else {
            e.arrived_late += 1;
        }
    }

    /// The expiries counted on `link` so far.
    #[must_use]
    pub fn expired(&self, link: &[u8; 16]) -> ExpiredCounts {
        Self::lock(&self.expired)
            .get(link)
            .copied()
            .unwrap_or_default()
    }

    /// Forget a closed link.
    pub fn forget(&self, link: &[u8; 16]) {
        Self::lock(&self.expired).remove(link);
    }

    /// Record a learned relay route.
    pub fn note_learned(&self, r: LearnedRelayRoute) {
        self.learned_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut v = Self::lock(&self.learned);
        v.retain(|x| !(x.destination == r.destination && x.relay == r.relay));
        if v.len() == LEARNED_CAP {
            v.remove(0);
        }
        v.push(r);
    }

    /// Relay routes learned for `destination`, newest last.
    #[must_use]
    pub fn learned_for(&self, destination: &[u8; 16]) -> Vec<LearnedRelayRoute> {
        Self::lock(&self.learned)
            .iter()
            .filter(|r| &r.destination == destination)
            .copied()
            .collect()
    }

    /// Relay routes learned so far (a counter).
    #[must_use]
    pub fn learned_total(&self) -> u64 {
        self.learned_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiries_count_per_link_and_kind() {
        let s = AlmLinkState::new();
        s.note_expired([1; 16], true, false);
        s.note_expired([1; 16], false, true);
        s.note_expired([1; 16], false, false);
        s.note_expired([2; 16], true, false);
        assert_eq!(
            s.expired(&[1; 16]),
            ExpiredCounts {
                sender: 1,
                marked_by_peer: 1,
                arrived_late: 1
            }
        );
        s.forget(&[1; 16]);
        assert_eq!(s.expired(&[1; 16]), ExpiredCounts::default());
        assert_eq!(s.expired(&[2; 16]).sender, 1);
    }

    #[test]
    fn learned_routes_dedupe_per_relay() {
        let s = AlmLinkState::new();
        let r = LearnedRelayRoute {
            destination: [3; 16],
            relay: [4; 16],
            interface_index: 1,
            hops: 2,
        };
        s.note_learned(r);
        s.note_learned(r);
        assert_eq!(s.learned_for(&[3; 16]).len(), 1);
        assert_eq!(s.learned_total(), 2);
    }

    #[test]
    fn queue_delay_is_srtt_above_the_floor() {
        let st = AvLinkStats {
            srtt_ms: Some(130.0),
            min_rtt_ms: Some(40),
            ..AvLinkStats::default()
        };
        assert!((st.queue_delay_ms() - 90.0).abs() < 1e-9);
        assert!(AvLinkStats::default().queue_delay_ms().abs() < 1e-9);
    }

    /// v45 — a send is proved once the oldest outstanding message is a
    /// later one, whatever is still in flight behind it, across the 2^16
    /// wrap.
    #[test]
    fn a_send_is_delivered_once_the_oldest_outstanding_is_later() {
        let at = |oldest: Option<u16>| AvLinkStats {
            oldest_unacked_seq: oldest,
            tx_ring: usize::from(oldest.is_some()) * 30,
            ..AvLinkStats::default()
        };
        assert!(at(None).delivered_through(7), "nothing outstanding");
        assert!(!at(Some(7)).delivered_through(7), "it is the oldest");
        assert!(!at(Some(6)).delivered_through(7), "an earlier one is out");
        assert!(at(Some(8)).delivered_through(7), "media behind it is out");
        assert!(at(Some(0)).delivered_through(0xFFFF), "across the wrap");
        assert!(at(Some(3)).delivered_through(0xFFFE));
        assert!(!at(Some(0xFFFF)).delivered_through(0));
    }
}
