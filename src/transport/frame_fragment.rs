//! CIRISEdge#414/CIRISAgent#932 — transport-layer frame fragmentation + reassembly.
//!
//! An anti-entropy `Deliver` frame carrying a large attestation is far larger
//! than a Reticulum link MDU (~431 B encrypted; a single `trace:complete:v1`
//! envelope can be up to ~1 MiB inline, and the JSON `Vec<Vec<u8>>` wire encoding
//! expands ~3–4×). Such a frame cannot take the packet path — the size gate at
//! `reticulum.rs` (`bytes.len() <= mdu`) is false — so it falls onto the Resource
//! path's one-transfer-per-link `Busy` gate and, on a NAT'd reverse-path-only
//! peer, is silently dropped. Small frames (control, Key/IdOcc) fit the MDU and
//! cross the same busy link as packets — exactly the observed asymmetry.
//!
//! This module is the transport-agnostic primitive that fixes it: split any
//! oversized frame into sub-MDU **fragments**, each of which rides the packet
//! path (which bypasses the `Busy` gate), and reassemble them at the receiver
//! before the frame is routed. It is used by BOTH the production Reticulum
//! transport AND the deterministic-simulation harness's `SimTransport`, so the
//! DST rig exercises the *real* fragmenter. Header shape mirrors leviculum's
//! `reticulum-core/src/framing/ble.rs` (a small fixed header + msg-id +
//! index/total).
//!
//! ## Reliability model
//! Fragments ride best-effort packets; a lost fragment means the frame does not
//! reassemble THIS round. That is not a stall: the anti-entropy protocol re-diffs
//! every round, so the whole frame is re-sent (re-fragmented) next round — the
//! same whole-frame retry unit the gossip protocol already relies on, but now the
//! frame can actually cross once its fragments arrive. The `Reassembler` bounds
//! memory against never-completing frames (lost fragments / attacker floods) with
//! an LRU cap on in-flight messages.
//!
//! ## The whole-frame-retry ceiling (honest limitation)
//! Because retry is at whole-frame granularity, a frame that needs THOUSANDS of
//! fragments has a vanishing per-round reassembly probability under sustained
//! packet loss (`(1-loss)^fragments` → 0). Two things keep this off the live path:
//! (1) the [`crate::replication::session::MAX_DELIVER_ENVELOPE_BYTES`] budget caps
//! a single `Deliver` so its fragment count stays bounded in the peer's holdings —
//! the amplification cliff (a peer with hundreds of attestations → one multi-MB
//! frame) cannot form; and (2) when the link is not mid-transfer the frame takes
//! the reliable Resource path (leviculum segments + ARQs), not this packet path —
//! this fragmenter is specifically the BUSY-link reverse-path carrier. The genuine
//! residual — a single very large frame on a *sustained-busy* lossy reverse-path
//! link — is closed only by fragment-level ARQ (selective NAK/retransmit), a
//! tracked follow-up; the `replication::sim` DST is the harness to build it on.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::collections::VecDeque;

/// Fragment magic — distinct from `wire_frame::REPLICATION_FRAME_MAGIC` (`CRPL`)
/// so the receiver can tell a fragment from a whole frame at a glance.
pub const FRAGMENT_MAGIC: [u8; 4] = *b"CFRG";

/// `magic[4] ‖ msg_id[8] ‖ total[u16 BE] ‖ index[u16 BE]`.
pub const FRAGMENT_HEADER_LEN: usize = 4 + 8 + 2 + 2;

/// The smallest MDU we will fragment for — below this the per-fragment payload
/// would be uselessly small. A real encrypted Reticulum link MDU (~431 B) is far
/// above this; it only guards a pathologically tiny link.
pub const MIN_FRAGMENTABLE_MDU: usize = FRAGMENT_HEADER_LEN + 16;

/// A frame is fragmented into at most `u16::MAX` pieces; at the ~431 B link MDU
/// that bounds a single frame at ~27 MB, well above the 8 MiB `MAX_BODY_BYTES`
/// reject ceiling — so every admissible frame fragments.
const MAX_FRAGMENTS: usize = u16::MAX as usize;

/// True iff `bytes` is a fragment (starts with [`FRAGMENT_MAGIC`]). A whole frame
/// (`CRPL…`) or a plain envelope never does.
#[must_use]
pub fn is_fragment(bytes: &[u8]) -> bool {
    bytes.len() >= FRAGMENT_HEADER_LEN && bytes[..4] == FRAGMENT_MAGIC
}

/// The deterministic per-frame id — first 8 bytes of `sha256(frame)`. Groups a
/// frame's fragments, dedups retransmits, and keeps the DST reproducible (no
/// randomness / clock). Distinct frames collide only on a sha256 8-byte prefix.
fn msg_id_of(frame: &[u8]) -> [u8; 8] {
    let digest = Sha256::digest(frame);
    let mut id = [0u8; 8];
    id.copy_from_slice(&digest[..8]);
    id
}

/// Split `frame` into packet-path-sized fragments for a link of `mdu` bytes.
///
/// A frame that already fits (`frame.len() <= mdu`) is returned **as-is, in one
/// piece, unwrapped** — the receiver routes it directly (it is not a `CFRG`
/// fragment). An oversized frame becomes N fragments, each `<= mdu`, carrying a
/// header + a `mdu - FRAGMENT_HEADER_LEN` slice of the frame. Returns `None` only
/// for a degenerate `mdu < MIN_FRAGMENTABLE_MDU` or a frame that would need more
/// than [`MAX_FRAGMENTS`] pieces (the caller then keeps its existing
/// oversized-drop path, now loud + counted).
#[must_use]
pub fn fragment(frame: &[u8], mdu: usize) -> Option<Vec<Vec<u8>>> {
    if frame.len() <= mdu {
        return Some(vec![frame.to_vec()]);
    }
    if mdu < MIN_FRAGMENTABLE_MDU {
        return None;
    }
    let payload = mdu - FRAGMENT_HEADER_LEN;
    let total = frame.len().div_ceil(payload);
    if total > MAX_FRAGMENTS {
        return None;
    }
    let msg_id = msg_id_of(frame);
    let total_u16 = u16::try_from(total).ok()?;
    let mut out = Vec::with_capacity(total);
    for (index, chunk) in frame.chunks(payload).enumerate() {
        // `index < total <= MAX_FRAGMENTS <= u16::MAX`, so this try_from never fails;
        // the `?` is a truncation-proof cast, not a runtime branch that fires.
        let index_u16 = u16::try_from(index).ok()?;
        let mut frag = Vec::with_capacity(FRAGMENT_HEADER_LEN + chunk.len());
        frag.extend_from_slice(&FRAGMENT_MAGIC);
        frag.extend_from_slice(&msg_id);
        frag.extend_from_slice(&total_u16.to_be_bytes());
        frag.extend_from_slice(&index_u16.to_be_bytes());
        frag.extend_from_slice(chunk);
        out.push(frag);
    }
    Some(out)
}

struct Partial {
    total: u16,
    chunks: HashMap<u16, Vec<u8>>,
}

/// Reassembles fragments (of possibly-interleaved frames) back into whole frames.
/// Bounded by an LRU cap on in-flight messages so lost fragments / floods cannot
/// grow memory without limit. Deterministic — no clock; eviction is by insertion
/// order, which the seeded DST drives reproducibly.
pub struct Reassembler {
    partials: HashMap<[u8; 8], Partial>,
    order: VecDeque<[u8; 8]>,
    max_in_flight: usize,
}

impl Reassembler {
    /// Default cap on concurrently-reassembling frames.
    pub const DEFAULT_MAX_IN_FLIGHT: usize = 256;

    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_MAX_IN_FLIGHT)
    }

    #[must_use]
    pub fn with_capacity(max_in_flight: usize) -> Self {
        Self {
            partials: HashMap::new(),
            order: VecDeque::new(),
            max_in_flight: max_in_flight.max(1),
        }
    }

    /// Feed one inbound packet. Returns:
    /// - `Some(frame)` — a whole (unfragmented) frame passes straight through, OR
    ///   this fragment completed a frame (the reassembled bytes);
    /// - `None` — a fragment that does not yet complete its frame (buffered), or a
    ///   malformed fragment (dropped).
    pub fn accept(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        if !is_fragment(packet) {
            return Some(packet.to_vec()); // a whole frame — route directly
        }
        let msg_id: [u8; 8] = packet[4..12].try_into().ok()?;
        let total = u16::from_be_bytes(packet[12..14].try_into().ok()?);
        let index = u16::from_be_bytes(packet[14..16].try_into().ok()?);
        if total == 0 || index >= total {
            return None; // malformed
        }
        let chunk = packet[FRAGMENT_HEADER_LEN..].to_vec();

        let entry = self.partials.entry(msg_id).or_insert_with(|| {
            self.order.push_back(msg_id);
            Partial {
                total,
                chunks: HashMap::new(),
            }
        });
        // A total mismatch across fragments of the "same" id (collision / attack)
        // — drop this frame's partial rather than reassemble corrupt bytes.
        if entry.total != total {
            self.partials.remove(&msg_id);
            self.order.retain(|id| *id != msg_id);
            return None;
        }
        entry.chunks.insert(index, chunk);
        if entry.chunks.len() == entry.total as usize {
            let mut partial = self.partials.remove(&msg_id).expect("just inserted");
            self.order.retain(|id| *id != msg_id);
            let mut frame = Vec::new();
            for i in 0..partial.total {
                // Every index 0..total is present (len == total, indices are
                // distinct and < total), so each `remove` yields Some.
                frame.extend_from_slice(&partial.chunks.remove(&i)?);
            }
            return Some(frame);
        }
        self.evict_if_over_cap();
        None
    }

    fn evict_if_over_cap(&mut self) {
        while self.order.len() > self.max_in_flight {
            if let Some(oldest) = self.order.pop_front() {
                self.partials.remove(&oldest);
            }
        }
    }

    /// In-flight (incomplete) frame count — diagnostics/tests.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.partials.len()
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
// Test fixtures fill frames with deterministic byte patterns (`(i % N) as u8`);
// the truncation is the intent, not a bug.
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    const MDU: usize = 431; // a realistic encrypted Reticulum link MDU

    #[test]
    fn small_frame_passes_through_unfragmented() {
        let frame = b"CRPL\x01 a small control frame".to_vec();
        let frags = fragment(&frame, MDU).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0], frame, "a <=mdu frame is sent as-is, not wrapped");
        assert!(!is_fragment(&frags[0]));
        // And it reassembles to itself (routes directly).
        let mut r = Reassembler::new();
        assert_eq!(r.accept(&frags[0]), Some(frame));
    }

    #[test]
    fn oversized_frame_round_trips() {
        // ~19 KB — the observed Attestation Deliver size.
        let frame: Vec<u8> = (0..19_000u32).map(|i| (i % 251) as u8).collect();
        let frags = fragment(&frame, MDU).unwrap();
        assert!(frags.len() > 1);
        for f in &frags {
            assert!(f.len() <= MDU, "every fragment fits the packet path");
            assert!(is_fragment(f));
        }
        let mut r = Reassembler::new();
        let mut got = None;
        for f in &frags {
            if let Some(frame) = r.accept(f) {
                got = Some(frame);
            }
        }
        assert_eq!(got.as_ref(), Some(&frame), "reassembles byte-exact");
        assert_eq!(r.in_flight(), 0, "completed frame is freed");
    }

    #[test]
    fn a_one_mib_single_envelope_frame_fragments_and_reassembles() {
        // The decisive case: a single inline-trace envelope larger than ANY link
        // MDU. Chunking-by-envelope cannot split it; fragmentation must.
        let frame: Vec<u8> = (0..1_048_576u32).map(|i| (i % 253) as u8).collect();
        let frags = fragment(&frame, MDU).unwrap();
        assert!(frags.len() > 2000);
        let mut r = Reassembler::new();
        let mut got = None;
        for f in &frags {
            got = r.accept(f).or(got);
        }
        assert_eq!(got, Some(frame));
    }

    #[test]
    fn reassembles_out_of_order_and_dedups_duplicates() {
        let frame: Vec<u8> = (0..5_000u32).map(|i| (i % 191) as u8).collect();
        let mut frags = fragment(&frame, MDU).unwrap();
        frags.reverse(); // out of order
        let mut r = Reassembler::new();
        let mut got = None;
        for f in &frags {
            got = r.accept(f).or(got);
            let _ = r.accept(f); // duplicate — must not corrupt or double-complete
        }
        assert_eq!(got, Some(frame));
    }

    #[test]
    fn a_missing_fragment_never_completes_and_is_bounded() {
        let frame: Vec<u8> = (0..5_000u32).map(|i| (i % 197) as u8).collect();
        let frags = fragment(&frame, MDU).unwrap();
        let mut r = Reassembler::new();
        // Drop the last fragment — reassembly must not complete (the round re-diffs).
        for f in &frags[..frags.len() - 1] {
            assert_eq!(r.accept(f), None);
        }
        assert_eq!(
            r.in_flight(),
            1,
            "the incomplete frame is buffered, not lost"
        );
    }

    #[test]
    fn interleaved_frames_reassemble_independently() {
        let a: Vec<u8> = (0..3_000u32).map(|i| (i % 131) as u8).collect();
        let b: Vec<u8> = (0..4_000u32).map(|i| (i % 137 + 1) as u8).collect();
        let fa = fragment(&a, MDU).unwrap();
        let fb = fragment(&b, MDU).unwrap();
        let mut r = Reassembler::new();
        let (mut ga, mut gb) = (None, None);
        // Interleave the two frames' fragments.
        for i in 0..fa.len().max(fb.len()) {
            if let Some(f) = fa.get(i) {
                ga = r.accept(f).or(ga);
            }
            if let Some(f) = fb.get(i) {
                gb = r.accept(f).or(gb);
            }
        }
        assert_eq!(ga, Some(a));
        assert_eq!(gb, Some(b));
    }

    #[test]
    fn in_flight_is_lru_bounded() {
        let mut r = Reassembler::with_capacity(4);
        // Start 10 distinct multi-fragment frames, feeding only the first fragment
        // of each so none completes. Only the last 4 may be retained.
        for n in 0..10u32 {
            let frame: Vec<u8> = (0..2_000u32)
                .map(|i| (i.wrapping_mul(n + 1) % 251) as u8)
                .collect();
            let frags = fragment(&frame, MDU).unwrap();
            r.accept(&frags[0]);
        }
        assert!(
            r.in_flight() <= 4,
            "LRU cap bounds memory under lost fragments"
        );
    }

    #[test]
    fn tiny_mdu_refuses_to_fragment() {
        let frame = vec![0u8; 1000];
        assert!(fragment(&frame, MIN_FRAGMENTABLE_MDU - 1).is_none());
    }
}
