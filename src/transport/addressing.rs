//! Federation addressing + replay-window primitives.
//!
//! Closes part of CIRISEdge#53 (Fed TM §3.3 Gap D: N1 cryptographic
//! addressing + sliding-window replay protection). The N2 multi-medium
//! transport plug — packet radio, additional non-IP media — ships as
//! follow-up work in a separate module (`transport/medium_registry.rs`
//! to be added) since the right shape there depends on the medium-
//! specific driver.
//!
//! ## N1 — addressing IS identity
//!
//! Per the Reticulum convention adopted in CIRISEdge's transport docs:
//!
//! ```text
//! destination = sha256(public_key)[..16]
//! ```
//!
//! 16 bytes is the Reticulum native destination width. SHA-256
//! truncation gives strong collision resistance against an attacker
//! trying to grind a different pubkey onto the same destination:
//! 64 bits of effective collision strength (birthday bound on a 128-bit
//! output, half-bit-width once an attacker controls the pubkey input).
//! That's enough to make eclipse / impersonation against a known target
//! cryptographically uneconomical: ~2^64 SHA-256 operations to grind a
//! pubkey hitting a chosen target.
//!
//! ## Replay window
//!
//! The CIRIS federation envelope carries a 64-bit sequence number
//! stamped by the sender per (sender, recipient) pair. Receivers track
//! the highest-seen sequence + a bitfield of the last N positions
//! (default 1024) to admit out-of-order arrivals but reject duplicates
//! AND stale envelopes that fall outside the window.
//!
//! This is the standard sliding-window construction (RFC 6479 / IPsec
//! anti-replay); see `ReplayWindow::admit`.

use sha2::{Digest, Sha256};

/// Reticulum destination width in bytes — the canonical wire form.
pub const RETICULUM_DEST_LEN: usize = 16;

/// Derive the canonical Reticulum destination from a federation
/// Ed25519 public key (CIRISEdge#53 §N1). 16 bytes is the truncated
/// SHA-256 prefix.
pub fn reticulum_destination_for_pubkey(pubkey: &[u8; 32]) -> [u8; RETICULUM_DEST_LEN] {
    let mut h = Sha256::new();
    h.update(pubkey);
    let full = h.finalize();
    let mut out = [0u8; RETICULUM_DEST_LEN];
    out.copy_from_slice(&full[..RETICULUM_DEST_LEN]);
    out
}

/// Same operation on raw pubkey bytes of arbitrary length, for media
/// (HTTP, packet radio) whose addressing also wants the
/// sha256-truncated-to-16 form. The 32-byte specialization above is
/// the hot path; this slice form is the general API.
pub fn destination_from_pubkey_bytes(pubkey: &[u8]) -> [u8; RETICULUM_DEST_LEN] {
    let mut h = Sha256::new();
    h.update(pubkey);
    let full = h.finalize();
    let mut out = [0u8; RETICULUM_DEST_LEN];
    out.copy_from_slice(&full[..RETICULUM_DEST_LEN]);
    out
}

/// Sliding-window replay tracker per (sender, recipient) pair. The
/// receiver instantiates one of these per remote peer it accepts
/// envelopes from; the window size controls how out-of-order delivery
/// is tolerated. Inspired by RFC 6479 (IPsec anti-replay) — bit-vector
/// over the last `window` sequence numbers.
///
/// Memory footprint is `window / 8` bytes plus a `u64`. With the default
/// `WINDOW_DEFAULT` of 1024, that's 128 bytes per peer — negligible
/// even at hundreds of peers.
///
/// Thread-safety: `&mut self` for `admit` — call sites either own the
/// `ReplayWindow` exclusively, or wrap in `tokio::sync::Mutex`.
#[derive(Debug)]
pub struct ReplayWindow {
    window: u64,
    /// Highest sequence number ever admitted. Stays at `None` before the
    /// first admission.
    highest: Option<u64>,
    /// Bitfield indexed by `highest - n` for n in `[0, window)`. Bit
    /// at index 0 always corresponds to `highest` itself. Stored as a
    /// `Vec<u64>` so a single bit-test/set is two ALU ops.
    bits: Vec<u64>,
}

/// Default window width — matches IPsec ESP's recommended depth and is
/// the right starting point for federation packet rates we expect today
/// (≪ 1024 envelopes/second/peer).
pub const WINDOW_DEFAULT: u64 = 1024;

/// Outcome of a `ReplayWindow::admit` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitOutcome {
    /// Envelope is new in the window — caller should process it.
    Fresh,
    /// Envelope's sequence number is older than `highest - window`.
    /// Reject — the receiver has no way to prove this isn't a replay.
    StaleBelowWindow,
    /// Envelope's sequence number has already been admitted (duplicate
    /// or replay). Reject.
    Duplicate,
}

impl ReplayWindow {
    /// New tracker with the default window width.
    pub fn new() -> Self {
        Self::with_window(WINDOW_DEFAULT)
    }

    /// New tracker with an explicit window width. Width must be a
    /// multiple of 64 and at least 64 (we store the bitfield in `u64`
    /// chunks; a smaller window doesn't justify the smaller storage
    /// for the constant-factor reduction in memory footprint).
    pub fn with_window(window: u64) -> Self {
        assert!(window >= 64, "ReplayWindow width must be at least 64");
        assert_eq!(
            window % 64,
            0,
            "ReplayWindow width must be a multiple of 64"
        );
        let words = (window / 64) as usize;
        Self {
            window,
            highest: None,
            bits: vec![0u64; words],
        }
    }

    /// Try to admit a sequence number into the window. Returns the
    /// outcome and, when admitting Fresh, marks the bit so subsequent
    /// duplicate attempts reject.
    pub fn admit(&mut self, seq: u64) -> AdmitOutcome {
        match self.highest {
            None => {
                // First-ever envelope from this peer — admit + set up
                // the bitfield with this position at index 0.
                self.highest = Some(seq);
                self.bits.fill(0);
                self.set_bit(0);
                AdmitOutcome::Fresh
            }
            Some(highest) if seq > highest => {
                // Advance the window forward by `delta` positions.
                // Shift the bitfield right (bit 0 stays at the new
                // highest, the old "bit at position highest" moves to
                // bit `delta`).
                let delta = seq - highest;
                self.shift_right(delta);
                self.highest = Some(seq);
                self.set_bit(0);
                AdmitOutcome::Fresh
            }
            Some(highest) => {
                // seq <= highest. Compute distance below highest.
                let distance = highest - seq;
                if distance >= self.window {
                    return AdmitOutcome::StaleBelowWindow;
                }
                if self.get_bit(distance) {
                    return AdmitOutcome::Duplicate;
                }
                self.set_bit(distance);
                AdmitOutcome::Fresh
            }
        }
    }

    fn set_bit(&mut self, distance: u64) {
        let word = (distance / 64) as usize;
        let bit = distance % 64;
        self.bits[word] |= 1u64 << bit;
    }

    fn get_bit(&self, distance: u64) -> bool {
        let word = (distance / 64) as usize;
        let bit = distance % 64;
        (self.bits[word] >> bit) & 1 != 0
    }

    /// Shift the entire bitfield right by `delta` bit positions. After
    /// the shift, bit 0 corresponds to the NEW highest, so the old
    /// "highest" sits at `delta`. Bits that fall off the high end
    /// (positions ≥ window) are discarded — those envelopes are now
    /// outside the window and `StaleBelowWindow` would refuse them
    /// anyway.
    fn shift_right(&mut self, delta: u64) {
        if delta >= self.window {
            // Window advanced past everything — fresh slate.
            self.bits.fill(0);
            return;
        }
        // Word-aligned + sub-word shift.
        let word_shift = (delta / 64) as usize;
        let bit_shift = (delta % 64) as u32;
        if word_shift > 0 {
            // Move data: bits[i] = bits[i - word_shift], with bits[0..word_shift] zeroed.
            let n = self.bits.len();
            for i in (word_shift..n).rev() {
                self.bits[i] = self.bits[i - word_shift];
            }
            for w in &mut self.bits[..word_shift] {
                *w = 0;
            }
        }
        if bit_shift > 0 {
            // In-word shift: carry bits from word[i-1]'s high end into word[i]'s low end.
            let n = self.bits.len();
            for i in (1..n).rev() {
                let lo = self.bits[i] << bit_shift;
                let hi = self.bits[i - 1] >> (64 - bit_shift);
                self.bits[i] = lo | hi;
            }
            self.bits[0] <<= bit_shift;
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// N1 spec: destination = sha256(pubkey)[..16].
    #[test]
    fn destination_is_sha256_truncated_to_16_bytes() {
        let pk = [0u8; 32];
        let d = reticulum_destination_for_pubkey(&pk);
        // sha256 of 32 zero bytes — first 16 bytes of the well-known digest.
        let expected_hex = "66687aadf862bd776c8fc18b8e9f8e20";
        assert_eq!(hex::encode(d), expected_hex);
        assert_eq!(d.len(), 16);
    }

    /// Different pubkeys → different destinations, and changing one bit
    /// in the input changes (very likely) all 16 output bytes —
    /// avalanche property of SHA-256.
    #[test]
    fn destination_is_deterministic_and_avalanches() {
        let pk_a = [0u8; 32];
        let mut pk_b = [0u8; 32];
        pk_b[0] = 1; // flip one bit
        let da = reticulum_destination_for_pubkey(&pk_a);
        let db = reticulum_destination_for_pubkey(&pk_b);
        assert_ne!(da, db);
        // Re-deriving gives the same answer.
        assert_eq!(da, reticulum_destination_for_pubkey(&pk_a));
        // Avalanche: at least half the bits in the output should differ.
        let differing_bits: u32 = da
            .iter()
            .zip(db.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum();
        assert!(
            differing_bits > 40,
            "expected strong avalanche, only {differing_bits} bits differ"
        );
    }

    /// `destination_from_pubkey_bytes` matches the 32-byte specialization.
    #[test]
    fn slice_form_matches_array_form() {
        let pk = [7u8; 32];
        assert_eq!(
            reticulum_destination_for_pubkey(&pk),
            destination_from_pubkey_bytes(&pk)
        );
    }

    /// First envelope is always Fresh; the second copy with the same
    /// sequence is a Duplicate.
    #[test]
    fn first_seen_then_duplicate() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.admit(100), AdmitOutcome::Fresh);
        assert_eq!(w.admit(100), AdmitOutcome::Duplicate);
    }

    /// Out-of-order arrivals within the window are accepted exactly once.
    #[test]
    fn out_of_order_within_window_accepted_once() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.admit(100), AdmitOutcome::Fresh);
        assert_eq!(w.admit(95), AdmitOutcome::Fresh);
        assert_eq!(w.admit(99), AdmitOutcome::Fresh);
        assert_eq!(w.admit(95), AdmitOutcome::Duplicate);
        assert_eq!(w.admit(99), AdmitOutcome::Duplicate);
    }

    /// Envelopes older than `highest - window` are refused as
    /// StaleBelowWindow — the receiver has no proof they weren't
    /// already seen and discarded.
    #[test]
    fn stale_below_window_rejected() {
        let mut w = ReplayWindow::with_window(64);
        assert_eq!(w.admit(1000), AdmitOutcome::Fresh);
        assert_eq!(w.admit(1000 - 64), AdmitOutcome::StaleBelowWindow);
        assert_eq!(w.admit(1000 - 65), AdmitOutcome::StaleBelowWindow);
    }

    /// Sequence numbers admitted before a large jump remain remembered
    /// only if they're still within the window after the jump.
    #[test]
    fn large_jump_invalidates_far_past_but_keeps_recent() {
        let mut w = ReplayWindow::with_window(64);
        assert_eq!(w.admit(10), AdmitOutcome::Fresh);
        assert_eq!(w.admit(20), AdmitOutcome::Fresh);
        // Jump well beyond the window.
        assert_eq!(w.admit(1000), AdmitOutcome::Fresh);
        // The pre-jump seqs are now stale-below-window.
        assert_eq!(w.admit(10), AdmitOutcome::StaleBelowWindow);
        assert_eq!(w.admit(20), AdmitOutcome::StaleBelowWindow);
        // But seqs within the new window still track correctly.
        assert_eq!(w.admit(990), AdmitOutcome::Fresh);
        assert_eq!(w.admit(990), AdmitOutcome::Duplicate);
    }

    /// Fuzz-style: random insertion order over a bounded sequence range
    /// produces no duplicate-Fresh outcomes (each seq is Fresh exactly
    /// once).
    #[test]
    fn random_insertion_order_fresh_exactly_once() {
        let mut w = ReplayWindow::with_window(1024);
        let mut seqs: Vec<u64> = (1..=512).collect();
        // Deterministic shuffle via a simple linear-congruential
        // permutation so the test stays reproducible without `rand`.
        let n = seqs.len();
        for i in 0..n {
            let j = (i * 31 + 7) % n;
            seqs.swap(i, j);
        }
        let mut fresh_count = 0;
        for s in &seqs {
            if matches!(w.admit(*s), AdmitOutcome::Fresh) {
                fresh_count += 1;
            }
        }
        assert_eq!(fresh_count, seqs.len(), "each seq should be Fresh once");
        // Re-admitting any of them now is a Duplicate.
        for s in &seqs {
            assert_eq!(w.admit(*s), AdmitOutcome::Duplicate);
        }
    }

    /// Admitting `seq + 1` after `seq` is the common steady-state case
    /// — the bit at position 0 should always be the new highest.
    #[test]
    fn monotonic_steady_state_steady_state() {
        let mut w = ReplayWindow::new();
        for i in 0..2048 {
            assert_eq!(w.admit(i), AdmitOutcome::Fresh, "step {i}");
        }
        // The most recent entry is a duplicate; one window-width back
        // is the boundary case (`distance == window` → StaleBelowWindow).
        assert_eq!(w.admit(2047), AdmitOutcome::Duplicate);
        assert_eq!(
            w.admit(2047u64.saturating_sub(WINDOW_DEFAULT)),
            AdmitOutcome::StaleBelowWindow
        );
    }

    /// Window-construction invariants.
    #[test]
    #[should_panic(expected = "ReplayWindow width must be at least 64")]
    fn rejects_window_below_64() {
        ReplayWindow::with_window(32);
    }

    #[test]
    #[should_panic(expected = "must be a multiple of 64")]
    fn rejects_window_not_multiple_of_64() {
        ReplayWindow::with_window(100);
    }
}
