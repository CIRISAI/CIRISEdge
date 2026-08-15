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
//! ## The whole-frame-retry ceiling — and its ARQ closure (CIRISEdge#422)
//! Because whole-frame retry is at whole-frame granularity, a frame that needs
//! THOUSANDS of fragments has a vanishing per-round reassembly probability under
//! sustained packet loss (`(1-loss)^fragments` → 0). Two things keep this off the
//! live path: (1) the [`crate::replication::session::MAX_DELIVER_ENVELOPE_BYTES`]
//! budget caps a single `Deliver` so its fragment count stays bounded in the
//! peer's holdings — the amplification cliff (a peer with hundreds of attestations
//! → one multi-MB frame) cannot form; and (2) when the link is not mid-transfer
//! the frame takes the reliable Resource path (leviculum segments + ARQs), not
//! this packet path — this fragmenter is specifically the BUSY-link reverse-path
//! carrier. The genuine residual — a single very large frame on a *sustained-busy*
//! lossy reverse-path link, where every fragment must ride packets so the per-round
//! reassembly odds `(1-loss)^fragments` → 0 and whole-frame retry converges only by
//! RE-SENDING the entire frame round after round (fragments accumulate across
//! rounds, but at whole-frame bandwidth cost) — is now closed by fragment-level ARQ
//! (below): the gap is recovered selectively, in-round, instead of re-fragmenting
//! and re-sending the whole frame each round.
//!
//! ## Fragment-level ARQ (CIRISEdge#422) — the selective path
//! Selective NAK/retransmit at fragment granularity, so a lossy multi-thousand-
//! fragment frame converges IN-round instead of re-sending the whole frame:
//!   - [`Reassembler::missing`] reports, per in-flight `msg_id`, exactly the
//!     fragment indices not yet received — it learns `total` from any ONE arrived
//!     fragment, so a single fragment is enough to enumerate the whole gap.
//!   - [`build_naks`] packs those indices into sub-MDU `CNAK` control packets the
//!     receiver sends back to the sender (chunked so each NAK itself fits the MDU
//!     and rides the same packet path); [`parse_nak`] reads them.
//!   - the sender holds its emitted fragment sets in a [`RetransmitBuffer`] and, on
//!     a NAK, re-sends ONLY the named indices ([`RetransmitBuffer::retransmit`]),
//!     NEVER the whole frame. A lost NAK or lost retransmit is just re-NAK'd next
//!     pass (each is itself a packet subject to the same loss), so recovery is a
//!     bounded selective loop, not a whole-frame gamble.
//!
//! The whole-frame re-diff path is PRESERVED as the fallback for the one case ARQ
//! cannot serve: a frame of which the receiver got ZERO fragments (no `total`, no
//! partial, nothing to NAK) still heals across rounds. The DST oracle
//! `replication::sim::fragment_arq_converges_worst_corner_without_whole_frame_resend`
//! drives the worst corner (large single frame ∧ high loss ∧ tiny MDU ∧ sustained
//! busy) and asserts convergence with the whole-frame re-send count at ZERO.

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

/// SECURITY / robustness (leviculum#39): the HARD per-piece byte ceiling on the
/// link Channel send path. Each fragment (and the whole-frame fast path) rides a
/// single `LinkHandle::try_send`, whose payload becomes the leviculum Channel
/// `Envelope`'s `data` — and that envelope's wire length field is a `u16`, so
/// `data.len()` can never exceed `u16::MAX`, **regardless of how large an MTU the
/// link negotiated**. `node.link_mdu()` reports the RAW negotiated MDU, which MTU
/// discovery can push far above this (a live node saw ~200 KB). Without this cap
/// the `frame.len() <= mdu` fast path handed a 113 KiB frame to a single
/// `try_send`, and leviculum's `Envelope` length assert panicked the delivery
/// thread ("envelope data length 115764 exceeds maximum 65535") — a `Result`-shaped
/// condition surfacing as a crash in a lock-holding thread, deafening the node.
/// [`fragment`] caps its effective MDU at this value so an oversized frame
/// FRAGMENTS (each piece `<= u16::MAX`) instead of going whole. This mirrors
/// leviculum#39's own `Channel::mdu(..).min(u16::MAX)` on the send guard, and
/// hardens edge against BOTH the pre-#39 panic and any future stricter refusal.
/// The 6-byte `CHANNEL_ENVELOPE_HEADER_SIZE` leviculum prepends is separate framing
/// not counted in the `u16` `data` length, so this ceiling is exact.
const WIRE_ENVELOPE_MAX_BYTES: usize = u16::MAX as usize;

/// SECURITY (v16 review, pre-attribution reassembly OOM): the receive side bounded
/// only the COUNT of in-flight partials (`max_in_flight`), never their bytes — so
/// a peer declaring `total = u16::MAX` and streaming fragments (withholding one so
/// the frame never completes) could pin ~27 MB in a SINGLE partial, and
/// `max_in_flight` of them ~7 GB, all before the link is even attributed. These
/// cap a single frame's accumulated payload (matching the transport `MAX_BODY_BYTES`
/// admissibility ceiling), and the TOTAL resident reassembly memory across all
/// partials — the hard bound regardless of partial count.
const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024; // == transport MAX_BODY_BYTES
const MAX_IN_FLIGHT_BYTES: usize = 4 * MAX_FRAME_BYTES; // 32 MiB global budget

/// CIRISEdge#422 — fragment-ARQ NAK magic. A third, distinct 4-byte tag so a
/// receiver tells a NAK (`CNAK`) from a whole frame (`CRPL`) or a data fragment
/// (`CFRG`) at a glance — a NAK is a TRANSPORT-level control packet, never a
/// replication message, so it is dispatched before frame reassembly and never
/// reaches `try_unwrap`.
pub const NAK_MAGIC: [u8; 4] = *b"CNAK";

/// NAK wire layout: `magic[4] ‖ msg_id[8] ‖ count[u16 BE] ‖ index[u16 BE] * count`.
/// The `count` indices name the fragments the receiver is still missing for
/// `msg_id`; the sender re-sends exactly those. `count` is bounded per packet so
/// the NAK itself fits the link MDU ([`max_nak_indices`]); a gap larger than one
/// NAK is split across several ([`build_naks`]).
pub const NAK_HEADER_LEN: usize = 4 + 8 + 2;

/// True iff `bytes` is a fragment (starts with [`FRAGMENT_MAGIC`]). A whole frame
/// (`CRPL…`) or a plain envelope never does.
#[must_use]
pub fn is_fragment(bytes: &[u8]) -> bool {
    bytes.len() >= FRAGMENT_HEADER_LEN && bytes[..4] == FRAGMENT_MAGIC
}

/// The `msg_id` a `CFRG` fragment belongs to (bytes `[4..12]`), or `None` if `frag`
/// is not a fragment. CIRISEdge#422 — the key both the [`RetransmitBuffer`] and the
/// NAK path group a frame's fragments under.
#[must_use]
pub fn msg_id_of_fragment(frag: &[u8]) -> Option<[u8; 8]> {
    if !is_fragment(frag) {
        return None;
    }
    frag[4..12].try_into().ok()
}

/// The fragment index a `CFRG` fragment carries (bytes `[14..16]`, BE), or `None` if
/// `frag` is not a fragment. CIRISEdge#422 — used to name the exact fragment in a
/// retransmit log line (this class must never be a silent drop).
#[must_use]
pub fn fragment_index(frag: &[u8]) -> Option<u16> {
    if !is_fragment(frag) {
        return None;
    }
    Some(u16::from_be_bytes([frag[14], frag[15]]))
}

/// True iff `bytes` is a fragment-ARQ NAK (starts with [`NAK_MAGIC`]). CIRISEdge#422.
#[must_use]
pub fn is_nak(bytes: &[u8]) -> bool {
    bytes.len() >= NAK_HEADER_LEN && bytes[..4] == NAK_MAGIC
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
///
/// The effective MDU is capped at [`WIRE_ENVELOPE_MAX_BYTES`] (leviculum#39): no
/// single link Channel send can carry more than `u16::MAX` bytes of payload no
/// matter how large the link MDU, so a frame above that ceiling FRAGMENTS rather
/// than riding the whole-frame fast path into a length-assert panic.
#[must_use]
pub fn fragment(frame: &[u8], mdu: usize) -> Option<Vec<Vec<u8>>> {
    // leviculum#39: never let the whole-frame fast path (or a fragment) exceed the
    // Channel Envelope's u16 wire ceiling, even on a large-MTU link.
    let mdu = mdu.min(WIRE_ENVELOPE_MAX_BYTES);
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

/// CIRISEdge#422 — how many fragment indices fit in one NAK packet for a link of
/// `mdu` bytes: `(mdu − header) / 2` (each index is a `u16`). Zero when the MDU is
/// too small to carry even one index — then the frame has no NAK path and heals via
/// the whole-frame re-diff fallback.
#[must_use]
pub fn max_nak_indices(mdu: usize) -> usize {
    mdu.saturating_sub(NAK_HEADER_LEN) / 2
}

/// Build the sub-MDU `CNAK` control packets that request the `missing` fragment
/// indices of `msg_id` from the sender. The index list is split across as many NAK
/// packets as needed so each fits `mdu` ([`max_nak_indices`]); an empty `missing`
/// or an MDU too small for a single index yields no packets (the caller then leaves
/// the frame to the whole-frame re-diff fallback — a decision it logs LOUD, never a
/// silent drop). Deterministic: packets follow `missing`'s order exactly.
#[must_use]
pub fn build_naks(msg_id: &[u8; 8], missing: &[u16], mdu: usize) -> Vec<Vec<u8>> {
    let per = max_nak_indices(mdu);
    if per == 0 || missing.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(missing.len().div_ceil(per));
    for batch in missing.chunks(per) {
        // `batch.len() <= per`, and `per` fits a `u16` for any realistic link MDU
        // (≤ ~131 KB) — the `unwrap_or` is a truncation-proof cast, not a live path.
        let count = u16::try_from(batch.len()).unwrap_or(u16::MAX);
        let mut nak = Vec::with_capacity(NAK_HEADER_LEN + batch.len() * 2);
        nak.extend_from_slice(&NAK_MAGIC);
        nak.extend_from_slice(msg_id);
        nak.extend_from_slice(&count.to_be_bytes());
        for &idx in batch {
            nak.extend_from_slice(&idx.to_be_bytes());
        }
        out.push(nak);
    }
    out
}

/// Parse a `CNAK` packet into its `(msg_id, requested_indices)`. `None` for a
/// non-NAK or a truncated/inconsistent packet (declared `count` overruns the body)
/// — a malformed NAK is dropped, never acted on.
#[must_use]
pub fn parse_nak(bytes: &[u8]) -> Option<([u8; 8], Vec<u16>)> {
    if !is_nak(bytes) {
        return None;
    }
    let msg_id: [u8; 8] = bytes[4..12].try_into().ok()?;
    let count = usize::from(u16::from_be_bytes(bytes[12..14].try_into().ok()?));
    let idx_bytes = &bytes[NAK_HEADER_LEN..];
    if idx_bytes.len() < count * 2 {
        return None; // truncated — declared more indices than the packet carries
    }
    let indices = idx_bytes[..count * 2]
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    Some((msg_id, indices))
}

struct Partial {
    total: u16,
    chunks: HashMap<u16, Vec<u8>>,
    /// Accumulated payload bytes across `chunks` (maintained by delta so a resent
    /// index never double-counts) — the per-frame ceiling is enforced against this.
    bytes: usize,
}

/// Reassembles fragments (of possibly-interleaved frames) back into whole frames.
/// Bounded by an LRU cap on in-flight messages so lost fragments / floods cannot
/// grow memory without limit. Deterministic — no clock; eviction is by insertion
/// order, which the seeded DST drives reproducibly.
pub struct Reassembler {
    partials: HashMap<[u8; 8], Partial>,
    order: VecDeque<[u8; 8]>,
    max_in_flight: usize,
    /// Sum of every partial's `bytes` — the global reassembly budget is enforced
    /// against this so total resident memory is bounded regardless of partial count.
    in_flight_bytes: usize,
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
            in_flight_bytes: 0,
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
        let chunk_len = chunk.len();

        // Ensure the partial exists. A total mismatch across fragments of the "same"
        // id (collision / attack) drops this frame's partial rather than reassemble
        // corrupt bytes. (Copy the existing `total` out so no borrow is held across
        // the removal below.)
        match self.partials.get(&msg_id).map(|p| p.total) {
            Some(t) if t != total => {
                let dropped = self.partials.remove(&msg_id).map_or(0, |p| p.bytes);
                self.in_flight_bytes = self.in_flight_bytes.saturating_sub(dropped);
                self.order.retain(|id| *id != msg_id);
                return None;
            }
            None => {
                self.order.push_back(msg_id);
                self.partials.insert(
                    msg_id,
                    Partial {
                        total,
                        chunks: HashMap::new(),
                        bytes: 0,
                    },
                );
            }
            Some(_) => {}
        }

        // Insert the chunk, maintaining byte accounting by DELTA (a resent index
        // replaces its previous bytes, never double-counts). Copy out what the
        // post-checks need, then the &mut is released before any removal.
        let entry = self
            .partials
            .get_mut(&msg_id)
            .expect("ensured present above");
        let prev_len = entry.chunks.insert(index, chunk).map_or(0, |v| v.len());
        entry.bytes = entry.bytes + chunk_len - prev_len;
        let entry_bytes = entry.bytes;
        let complete = entry.chunks.len() == entry.total as usize;
        self.in_flight_bytes = self.in_flight_bytes + chunk_len - prev_len;

        // SECURITY (v16 review): a single frame cannot exceed MAX_FRAME_BYTES — drop
        // the partial if a peer streams past it (e.g. total=u16::MAX, never completes).
        if entry_bytes > MAX_FRAME_BYTES {
            self.partials.remove(&msg_id);
            self.in_flight_bytes = self.in_flight_bytes.saturating_sub(entry_bytes);
            self.order.retain(|id| *id != msg_id);
            return None;
        }

        if complete {
            let mut partial = self.partials.remove(&msg_id).expect("just inserted");
            self.in_flight_bytes = self.in_flight_bytes.saturating_sub(partial.bytes);
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
        // Evict oldest partials until BOTH the count cap AND the global byte budget
        // hold — MAX_IN_FLIGHT_BYTES is the hard bound on total resident reassembly
        // memory regardless of how bytes are distributed across partials.
        while self.order.len() > self.max_in_flight || self.in_flight_bytes > MAX_IN_FLIGHT_BYTES {
            match self.order.pop_front() {
                Some(oldest) => {
                    let freed = self.partials.remove(&oldest).map_or(0, |p| p.bytes);
                    self.in_flight_bytes = self.in_flight_bytes.saturating_sub(freed);
                }
                None => break,
            }
        }
    }

    /// In-flight (incomplete) frame count — diagnostics/tests.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.partials.len()
    }

    /// CIRISEdge#422 — per in-flight frame, the fragment indices NOT yet received:
    /// the receiver's NAK source. It knows `total` from any one arrived fragment, so
    /// a single fragment is enough to enumerate the whole gap. Iterates the LRU
    /// `order` (insertion order), NOT the `HashMap`, so the NAK stream is
    /// DETERMINISTIC — a seeded DST reproduces it bit-for-bit. A complete frame is
    /// already gone from `partials` (removed on reassembly), so it is never listed.
    #[must_use]
    pub fn missing(&self) -> Vec<([u8; 8], Vec<u16>)> {
        let mut out = Vec::new();
        for msg_id in &self.order {
            let Some(partial) = self.partials.get(msg_id) else {
                continue;
            };
            let miss: Vec<u16> = (0..partial.total)
                .filter(|i| !partial.chunks.contains_key(i))
                .collect();
            if !miss.is_empty() {
                out.push((*msg_id, miss));
            }
        }
        out
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

/// CIRISEdge#422 — the SENDER-side half of fragment-level ARQ: the fragment sets a
/// node has emitted, keyed by `msg_id`, so a peer's NAK is served by re-sending only
/// the named fragments — NEVER by re-fragmenting the whole frame. LRU-bounded (a
/// peer that never completes cannot pin a sender's buffers), and deterministic:
/// eviction is by record order, which the seeded DST drives reproducibly.
pub struct RetransmitBuffer {
    frames: HashMap<[u8; 8], Vec<Vec<u8>>>,
    order: VecDeque<[u8; 8]>,
    max_in_flight: usize,
}

impl RetransmitBuffer {
    /// Default cap on concurrently-retransmittable frames held per sender. Smaller
    /// than the reassembler's cap: a sender only needs its own in-flight Delivers,
    /// not every peer's inbound stream.
    pub const DEFAULT_MAX_IN_FLIGHT: usize = 64;

    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_MAX_IN_FLIGHT)
    }

    #[must_use]
    pub fn with_capacity(max_in_flight: usize) -> Self {
        Self {
            frames: HashMap::new(),
            order: VecDeque::new(),
            max_in_flight: max_in_flight.max(1),
        }
    }

    /// Record a just-emitted fragment SET (the ordered output of [`fragment`]) so a
    /// later NAK can be served without re-fragmenting the whole frame. A set that is
    /// a single unwrapped whole frame (frame ≤ MDU — not a `CFRG` fragment) is NOT
    /// fragment-ARQ'able and is skipped; its loss heals via the whole-frame re-diff
    /// fallback. Idempotent per `msg_id` (re-recording the same frame overwrites,
    /// keeping its LRU position), and bounded so the buffer cannot grow without
    /// limit under a peer that never completes.
    pub fn record(&mut self, fragments: &[Vec<u8>]) {
        let Some(first) = fragments.first() else {
            return;
        };
        let Some(msg_id) = msg_id_of_fragment(first) else {
            return; // a single whole frame, not a CFRG set — no fragment ARQ
        };
        if self.frames.insert(msg_id, fragments.to_vec()).is_none() {
            self.order.push_back(msg_id);
        }
        while self.order.len() > self.max_in_flight {
            if let Some(oldest) = self.order.pop_front() {
                self.frames.remove(&oldest);
            }
        }
    }

    /// Re-materialise the fragment PACKETS the peer NAK'd for `msg_id` — only the
    /// named `indices`, never the whole set. An unknown `msg_id` (LRU-evicted or
    /// never recorded) or an out-of-range index contributes nothing for that index:
    /// a genuine shortfall the caller detects (served `<` requested) and logs LOUD,
    /// leaving the remainder to the whole-frame re-diff fallback. The fragment for
    /// index `i` is element `i` of the recorded set — [`fragment`] emits them in
    /// order — so the lookup is positional and O(1) per index.
    #[must_use]
    pub fn retransmit(&self, msg_id: &[u8; 8], indices: &[u16]) -> Vec<Vec<u8>> {
        let Some(set) = self.frames.get(msg_id) else {
            return Vec::new();
        };
        indices
            .iter()
            .filter_map(|&i| set.get(usize::from(i)).cloned())
            .collect()
    }

    /// Whether a frame's fragments are still held for retransmit (diagnostics/tests).
    #[must_use]
    pub fn holds(&self, msg_id: &[u8; 8]) -> bool {
        self.frames.contains_key(msg_id)
    }

    /// Frames currently held for retransmit — diagnostics/tests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Whether the buffer holds nothing — diagnostics/tests.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}

impl Default for RetransmitBuffer {
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
    fn large_mtu_link_fragments_below_the_u16_envelope_ceiling() {
        // leviculum#39 field regression: on a link whose negotiated MDU exceeds the
        // Channel Envelope's u16 wire ceiling, an oversized frame MUST fragment —
        // never ride the whole-frame fast path into a single `try_send` that panics
        // leviculum's `Envelope` length assert. Reproduces the live failure exactly:
        // a 115_764-byte frame on a ~200 KB-MDU link ("envelope data length 115764
        // exceeds maximum 65535").
        let link_mdu = 200_000usize; // MTU discovery can negotiate this
        let frame: Vec<u8> = (0..115_764u32).map(|i| (i % 239) as u8).collect();
        let frags = fragment(&frame, link_mdu).unwrap();
        assert!(
            frags.len() > 1,
            "the frame must fragment, not go whole — {} piece(s)",
            frags.len()
        );
        for f in &frags {
            assert!(
                f.len() <= WIRE_ENVELOPE_MAX_BYTES,
                "every piece fits the u16 Channel Envelope ceiling ({} <= {})",
                f.len(),
                WIRE_ENVELOPE_MAX_BYTES
            );
            assert!(is_fragment(f));
        }
        // And it still reassembles byte-exact through the CFRG path.
        let mut r = Reassembler::new();
        let mut got = None;
        for f in &frags {
            got = r.accept(f).or(got);
        }
        assert_eq!(got.as_ref(), Some(&frame), "reassembles byte-exact");
        assert_eq!(r.in_flight(), 0, "completed frame is freed");
    }

    #[test]
    fn frame_at_the_u16_ceiling_rides_whole_even_on_a_huge_link() {
        // A frame exactly at the envelope ceiling is still one deliverable unit; the
        // cap only bites ABOVE u16::MAX. (u16::MAX itself is an admissible data len.)
        let frame: Vec<u8> = (0..WIRE_ENVELOPE_MAX_BYTES as u32)
            .map(|i| (i % 233) as u8)
            .collect();
        let frags = fragment(&frame, 1_000_000).unwrap();
        assert_eq!(frags.len(), 1, "a ==ceiling frame is one whole piece");
        assert!(!is_fragment(&frags[0]));
        assert_eq!(frags[0].len(), WIRE_ENVELOPE_MAX_BYTES);
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
    fn accept_bounds_a_single_frame_at_max_frame_bytes() {
        // SECURITY (v16 review): a peer declares total=u16::MAX and streams
        // full-payload fragments while WITHHOLDING index 0, so the frame never
        // completes. The receive side must cap accumulated bytes at MAX_FRAME_BYTES
        // (dropping the partial) instead of pinning ~27 MB — the old path had NO
        // receive-side byte ceiling.
        fn frag(msg_id: [u8; 8], total: u16, index: u16, payload: &[u8]) -> Vec<u8> {
            let mut p = Vec::with_capacity(FRAGMENT_HEADER_LEN + payload.len());
            p.extend_from_slice(&FRAGMENT_MAGIC);
            p.extend_from_slice(&msg_id);
            p.extend_from_slice(&total.to_be_bytes());
            p.extend_from_slice(&index.to_be_bytes());
            p.extend_from_slice(payload);
            p
        }
        let mut r = Reassembler::new();
        let msg_id = [7u8; 8];
        let payload = vec![0xABu8; 4096];
        let mut peak = 0usize;
        // ~16 MiB streamed into ONE never-completing frame (index 0 withheld).
        for index in 1u16..=4096 {
            let out = r.accept(&frag(msg_id, u16::MAX, index, &payload));
            assert!(out.is_none(), "the frame never completes");
            peak = peak.max(r.in_flight_bytes);
        }
        assert!(
            peak <= MAX_FRAME_BYTES + payload.len(),
            "a single frame's reassembly is bounded at MAX_FRAME_BYTES (peak {peak})"
        );
        assert!(
            r.in_flight_bytes <= MAX_IN_FLIGHT_BYTES,
            "the global reassembly budget holds"
        );
    }

    #[test]
    fn tiny_mdu_refuses_to_fragment() {
        let frame = vec![0u8; 1000];
        assert!(fragment(&frame, MIN_FRAGMENTABLE_MDU - 1).is_none());
    }

    // ---- CIRISEdge#422 fragment-level ARQ primitives ----

    #[test]
    fn nak_round_trips_and_is_distinct_from_frame_and_fragment() {
        let msg_id = [0xAB, 0xCD, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let missing = vec![0u16, 3, 7, 42, 65_535];
        let naks = build_naks(&msg_id, &missing, MDU);
        assert_eq!(naks.len(), 1, "5 indices fit one NAK at a 431 B MDU");
        let nak = &naks[0];
        // A NAK is neither a whole frame (`CRPL`) nor a data fragment (`CFRG`).
        assert!(is_nak(nak));
        assert!(!is_fragment(nak));
        assert_ne!(
            &nak[..4],
            &crate::replication::wire_frame::REPLICATION_FRAME_MAGIC
        );
        let (got_id, got_missing) = parse_nak(nak).expect("well-formed NAK parses");
        assert_eq!(got_id, msg_id);
        assert_eq!(
            got_missing, missing,
            "indices survive the round trip in order"
        );
    }

    #[test]
    fn build_naks_splits_to_fit_the_mdu_and_refuses_a_tiny_one() {
        // 500 missing indices at a small MDU must split into several sub-MDU NAKs.
        let msg_id = [9u8; 8];
        let missing: Vec<u16> = (0..500u16).collect();
        let mdu = 200;
        let naks = build_naks(&msg_id, &missing, mdu);
        assert!(naks.len() > 1, "a large gap splits across multiple NAKs");
        for nak in &naks {
            assert!(nak.len() <= mdu, "every NAK fits the link MDU");
            assert!(is_nak(nak));
        }
        // Reassembling every NAK's indices reproduces the full gap, in order.
        let round_tripped: Vec<u16> = naks.iter().flat_map(|n| parse_nak(n).unwrap().1).collect();
        assert_eq!(round_tripped, missing);
        // An MDU too small to carry even one index yields no NAK — the frame then
        // heals via the whole-frame re-diff fallback.
        assert!(build_naks(&msg_id, &missing, NAK_HEADER_LEN + 1).is_empty());
        assert!(build_naks(&msg_id, &[], MDU).is_empty(), "no gap ⇒ no NAK");
    }

    #[test]
    fn parse_nak_rejects_a_truncated_packet() {
        let msg_id = [1u8; 8];
        let mut nak = build_naks(&msg_id, &[1u16, 2, 3], MDU).pop().unwrap();
        nak.truncate(nak.len() - 1); // drop a byte of the last index
        assert!(
            parse_nak(&nak).is_none(),
            "a truncated NAK is dropped, not acted on"
        );
    }

    #[test]
    fn reassembler_missing_reports_the_exact_gap() {
        let frame: Vec<u8> = (0..5_000u32).map(|i| (i % 251) as u8).collect();
        let frags = fragment(&frame, MDU).unwrap();
        let total = frags.len();
        let mut r = Reassembler::new();
        // Feed every fragment EXCEPT indices 2 and 5.
        for (i, f) in frags.iter().enumerate() {
            if i != 2 && i != 5 {
                r.accept(f);
            }
        }
        let missing = r.missing();
        assert_eq!(missing.len(), 1, "one in-flight frame");
        let (msg_id, gap) = &missing[0];
        assert_eq!(*msg_id, msg_id_of_fragment(&frags[0]).unwrap());
        assert_eq!(
            gap,
            &vec![2u16, 5],
            "exactly the dropped indices, ascending"
        );
        // Feeding a complete frame leaves nothing missing.
        assert!(total > 6);
    }

    #[test]
    fn retransmit_serves_only_named_indices() {
        let frame: Vec<u8> = (0..5_000u32).map(|i| (i % 251) as u8).collect();
        let frags = fragment(&frame, MDU).unwrap();
        let msg_id = msg_id_of_fragment(&frags[0]).unwrap();
        let mut retx = RetransmitBuffer::new();
        retx.record(&frags);
        assert!(retx.holds(&msg_id));
        // Ask for exactly indices 2 and 5 — get exactly those two fragment packets.
        let got = retx.retransmit(&msg_id, &[2, 5]);
        assert_eq!(got.len(), 2);
        assert_eq!(fragment_index(&got[0]), Some(2));
        assert_eq!(fragment_index(&got[1]), Some(5));
        // An unknown msg_id serves nothing (a shortfall the caller logs LOUD).
        assert!(retx.retransmit(&[0xFF; 8], &[0, 1]).is_empty());
        // A single whole frame (≤ MDU) is not retransmittable at fragment level.
        let small = fragment(b"CRPL\x01 tiny", MDU).unwrap();
        let mut r2 = RetransmitBuffer::new();
        r2.record(&small);
        assert!(
            r2.is_empty(),
            "a whole small frame is not fragment-ARQ'able"
        );
    }

    #[test]
    fn selective_arq_recovers_a_lossy_frame_without_a_whole_resend() {
        // End-to-end at the primitive level: fragment a frame, deliver it with a
        // scattered loss, then NAK→retransmit ONLY the gap and reassemble — proving
        // recovery costs far fewer than `total` fragments (no whole-frame re-send).
        let frame: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let frags = fragment(&frame, MDU).unwrap();
        let total = frags.len();
        assert!(total > 50);
        let mut sender = RetransmitBuffer::new();
        sender.record(&frags);
        let mut r = Reassembler::new();
        // Deliver every 4th fragment lost (indices 0,4,8,… dropped).
        let mut completed = None;
        for (i, f) in frags.iter().enumerate() {
            if i % 4 != 0 {
                completed = r.accept(f).or(completed);
            }
        }
        assert!(
            completed.is_none(),
            "with a quarter dropped it cannot complete yet"
        );
        // NAK the gap; the sender re-sends only those, and reassembly completes.
        let mut retransmitted = 0usize;
        for (msg_id, gap) in r.missing() {
            for nak in build_naks(&msg_id, &gap, MDU) {
                let (id, idxs) = parse_nak(&nak).unwrap();
                for f in sender.retransmit(&id, &idxs) {
                    retransmitted += 1;
                    completed = r.accept(&f).or(completed);
                }
            }
        }
        assert_eq!(
            completed.as_ref(),
            Some(&frame),
            "selective retransmit reassembles byte-exact"
        );
        assert!(
            retransmitted < total,
            "recovery re-sent {retransmitted} of {total} fragments — a SUBSET, not the whole frame",
        );
    }
}
