//! 45.1 (CC reading, rc18) — **frame fragmentation**: a media frame larger
//! than one chunk is split BEFORE the seal into fragments, each a whole
//! chunk (its own `chunk_seq`, inner and outer seal, source signature), and
//! reassembled by the receiver after the reorder window. The clear header,
//! relays, the DAG and the 5.3.3.4 pull see chunks only: nothing above the
//! plaintext changes. CC 5.3.3.2.3's "one chunk, one link payload" holds:
//! no sealed chunk is ever split.
//!
//! On a stream whose v2 binding signs `framing = 1`, every chunk whose
//! `codec_id` is not `0xFF` starts its plaintext with the marker
//! `frag_index u16_be ‖ frag_count u16_be` (a whole frame is `0 ‖ 1`, so the
//! layout never depends on size). Audio (`0xFF`) chunks never carry it. A
//! receiver picks the layout from the signed `codec_id` (verified with the
//! trailer before the inner seal opens), never from length.
//!
//! A frame's fragments take consecutive `chunk_seq`s in one epoch (the
//! publisher seals them under one lock, and the epoch rolls under it), all
//! with the frame's `codec_id` and layer. A missing fragment is a missing
//! chunk: the reorder window (and the pulls inside it) wait for it by
//! `chunk_seq`; only once that window gave it up is the frame dropped,
//! counted, never handed out partial.
//!
//! The refusals here are the receiver's alone: a relay never opens the inner
//! seal, so it never sees a marker.

use super::{ChunkLayer, Epoch, ReceivedFrame, StreamId};

/// The marker's length: `frag_index u16_be ‖ frag_count u16_be`.
pub const FRAGMENT_MARKER_LEN: usize = 4;

/// The most fragments one frame takes. A frame needing more is refused
/// before anything is sealed.
pub const MAX_FRAME_FRAGMENTS: usize = 256;

/// The marker for fragment `index` of `count`.
#[must_use]
pub fn marker(index: u16, count: u16) -> [u8; FRAGMENT_MARKER_LEN] {
    let i = index.to_be_bytes();
    let c = count.to_be_bytes();
    [i[0], i[1], c[0], c[1]]
}

/// Split `frame` into marked fragment plaintexts of at most `budget` bytes
/// each (the call's `chunk_plaintext_budget`, the marker included). `None`
/// when `budget` leaves no room past the marker, or the frame needs more
/// than [`MAX_FRAME_FRAGMENTS`]. An empty frame is one fragment.
#[must_use]
pub fn split(frame: &[u8], budget: usize) -> Option<Vec<Vec<u8>>> {
    let per = budget.checked_sub(FRAGMENT_MARKER_LEN).filter(|p| *p > 0)?;
    let count = frame.len().div_ceil(per).max(1);
    if count > MAX_FRAME_FRAGMENTS {
        return None;
    }
    let count16 = u16::try_from(count).ok()?;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let lo = i * per;
        let hi = (lo + per).min(frame.len());
        let mut p = Vec::with_capacity(FRAGMENT_MARKER_LEN + hi - lo);
        p.extend_from_slice(&marker(u16::try_from(i).ok()?, count16));
        p.extend_from_slice(&frame[lo..hi]);
        out.push(p);
    }
    Some(out)
}

/// The largest frame a framed stream takes at `budget`:
/// [`MAX_FRAME_FRAGMENTS`] × (`budget` − the marker).
#[must_use]
pub fn max_frame_len(budget: usize) -> usize {
    budget.saturating_sub(FRAGMENT_MARKER_LEN) * MAX_FRAME_FRAGMENTS
}

/// Why a released chunk of a framed stream did not become (part of) a
/// frame. Receiver-only: a relay never opens the inner seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameRefusal {
    /// The plaintext is shorter than the marker.
    MarkerShort,
    /// `frag_count` is 0 or over [`MAX_FRAME_FRAGMENTS`].
    CountInvalid,
    /// `frag_index` ≥ `frag_count`.
    IndexInvalid,
    /// A fragment's `frag_count` differs from its frame's.
    CountMismatch,
    /// A fragment's `codec_id` or layer differs from its frame's.
    LayerMismatch,
    /// A fragment's epoch differs from its frame's: the run would cross the
    /// epoch.
    CrossesEpoch,
    /// A frame missing a fragment the reorder window gave up on: dropped
    /// whole (counted once per frame).
    Incomplete,
}

impl FrameRefusal {
    /// The stable token (receiver-only; documented in
    /// `docs/av_chunk_auth_wire.md`).
    #[must_use]
    pub const fn token(self) -> &'static str {
        use crate::observability as o;
        match self {
            Self::MarkerShort => o::AV_FRAME_MARKER_SHORT,
            Self::CountInvalid => o::AV_FRAME_COUNT_INVALID,
            Self::IndexInvalid => o::AV_FRAME_INDEX_INVALID,
            Self::CountMismatch => o::AV_FRAME_COUNT_MISMATCH,
            Self::LayerMismatch => o::AV_FRAME_LAYER_MISMATCH,
            Self::CrossesEpoch => o::AV_FRAME_CROSSES_EPOCH,
            Self::Incomplete => o::AV_FRAME_INCOMPLETE,
        }
    }

    /// Every token, for the metric registry.
    pub const ALL: [Self; 7] = [
        Self::MarkerShort,
        Self::CountInvalid,
        Self::IndexInvalid,
        Self::CountMismatch,
        Self::LayerMismatch,
        Self::CrossesEpoch,
        Self::Incomplete,
    ];
}

/// One frame being put back together.
struct Partial {
    epoch: Epoch,
    first_seq: u64,
    count: u16,
    next: u16,
    codec_id: u8,
    layer: ChunkLayer,
    head: ReceivedFrame,
    bytes: Vec<u8>,
}

/// One stream's reassembly, fed the stream's framed chunks in the reorder
/// window's release order (`chunk_seq` ascending, gaps already given up).
#[derive(Default)]
pub struct Reassembler {
    partial: Option<Partial>,
    /// The frame (epoch, first seq) whose start was lost: its later
    /// fragments are dropped without counting it again.
    orphan: Option<(Epoch, u64)>,
}

/// What one released chunk came to.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reassembled {
    /// A whole frame, when this chunk completed one.
    pub frame: Option<ReceivedFrame>,
    /// What was dropped on the way (each counted once).
    pub refused: Vec<FrameRefusal>,
}

impl Reassembler {
    /// Take one released chunk of a framed stream (a non-`0xFF` one: the
    /// caller passes audio through).
    pub fn push(&mut self, chunk: ReceivedFrame) -> Reassembled {
        let mut out = Reassembled::default();
        let Some((index, count)) = parse(&chunk.bytes) else {
            self.abandon(&mut out);
            out.refused.push(FrameRefusal::MarkerShort);
            return out;
        };
        if count == 0 || usize::from(count) > MAX_FRAME_FRAGMENTS {
            self.abandon(&mut out);
            out.refused.push(FrameRefusal::CountInvalid);
            return out;
        }
        if index >= count {
            self.abandon(&mut out);
            out.refused.push(FrameRefusal::IndexInvalid);
            return out;
        }
        let seq = chunk.chunk_seq.0;
        let frame_start = seq.checked_sub(u64::from(index));
        if let Some(p) = &self.partial {
            if index == 0 {
                // A new frame while one is open: the open one lost its tail.
                self.abandon(&mut out);
            } else if chunk.epoch != p.epoch {
                self.partial = None;
                out.refused.push(FrameRefusal::CrossesEpoch);
                self.orphan = frame_start.map(|f| (chunk.epoch, f));
                return out;
            } else if seq != p.first_seq + u64::from(index) || index != p.next {
                // A fragment the window gave up on lies between: the open
                // frame is incomplete, and this fragment's frame (another
                // one, or the same past the hole) has lost its start.
                let same = frame_start == Some(p.first_seq);
                self.abandon(&mut out);
                if !same {
                    self.orphan_once(&mut out, chunk.epoch, frame_start);
                } else {
                    self.orphan = frame_start.map(|f| (chunk.epoch, f));
                }
                return out;
            } else if count != p.count {
                self.partial = None;
                out.refused.push(FrameRefusal::CountMismatch);
                self.orphan = frame_start.map(|f| (chunk.epoch, f));
                return out;
            } else if chunk.codec_id != p.codec_id || chunk.layer != p.layer {
                self.partial = None;
                out.refused.push(FrameRefusal::LayerMismatch);
                self.orphan = frame_start.map(|f| (chunk.epoch, f));
                return out;
            }
        }
        if index == 0 {
            self.orphan = None;
            let payload = chunk.bytes[FRAGMENT_MARKER_LEN..].to_vec();
            if count == 1 {
                out.frame = Some(ReceivedFrame {
                    bytes: payload,
                    ..chunk
                });
                return out;
            }
            self.partial = Some(Partial {
                epoch: chunk.epoch,
                first_seq: seq,
                count,
                next: 1,
                codec_id: chunk.codec_id,
                layer: chunk.layer,
                bytes: payload,
                head: chunk,
            });
            return out;
        }
        let Some(p) = self.partial.as_mut() else {
            self.orphan_once(&mut out, chunk.epoch, frame_start);
            return out;
        };
        p.bytes
            .extend_from_slice(&chunk.bytes[FRAGMENT_MARKER_LEN..]);
        p.next += 1;
        if p.next == p.count {
            let p = self.partial.take().expect("open");
            out.frame = Some(ReceivedFrame {
                bytes: p.bytes,
                ..p.head
            });
        }
        out
    }

    /// The open frame, if any, is dropped incomplete.
    fn abandon(&mut self, out: &mut Reassembled) {
        if self.partial.take().is_some() {
            out.refused.push(FrameRefusal::Incomplete);
        }
    }

    /// A fragment whose frame's start never arrived: that frame counts as
    /// incomplete once, its later fragments silently.
    fn orphan_once(&mut self, out: &mut Reassembled, epoch: Epoch, start: Option<u64>) {
        let key = start.map(|f| (epoch, f));
        if key.is_none() || self.orphan != key {
            out.refused.push(FrameRefusal::Incomplete);
        }
        self.orphan = key;
    }
}

/// The marker of a framed chunk's plaintext: `(frag_index, frag_count)`.
#[must_use]
pub fn parse(plaintext: &[u8]) -> Option<(u16, u16)> {
    let m = plaintext.get(..FRAGMENT_MARKER_LEN)?;
    Some((
        u16::from_be_bytes([m[0], m[1]]),
        u16::from_be_bytes([m[2], m[3]]),
    ))
}

/// The per-stream reassemblers of one call, keyed by stream.
#[derive(Default)]
pub struct Reassemblers {
    streams: std::collections::HashMap<StreamId, Reassembler>,
}

impl Reassemblers {
    /// Take one released chunk: an unframed stream's (`framing` 0) or an
    /// audio (`0xFF`) chunk passes through as a frame; a framed stream's
    /// other chunks go through the stream's reassembler.
    pub fn push(&mut self, chunk: ReceivedFrame, framing: u8) -> Reassembled {
        if framing != crate::transport::av_chunk_auth::FRAMING_FRAGMENTS
            || chunk.codec_id == crate::transport::realtime_av::CODEC_OPAQUE
        {
            return Reassembled {
                frame: Some(chunk),
                refused: Vec::new(),
            };
        }
        self.streams.entry(chunk.stream).or_default().push(chunk)
    }

    /// Keep only the streams `live` says are still bound; the rest (ended,
    /// replaced, evicted) are forgotten, an open frame dropped incomplete.
    pub fn retain(&mut self, live: impl Fn(StreamId) -> bool) -> Vec<FrameRefusal> {
        let gone: Vec<StreamId> = self.streams.keys().copied().filter(|s| !live(*s)).collect();
        gone.into_iter().flat_map(|s| self.forget(s)).collect()
    }

    /// Forget `stream` (it ended or was replaced); an open frame is dropped
    /// incomplete.
    pub fn forget(&mut self, stream: StreamId) -> Vec<FrameRefusal> {
        let mut out = Reassembled::default();
        if let Some(mut r) = self.streams.remove(&stream) {
            r.abandon(&mut out);
        }
        out.refused
    }
}

#[cfg(test)]
#[path = "frame_tests.rs"]
mod tests;
