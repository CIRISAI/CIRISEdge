//! v45 (CC reading, rc18) — **frame fragmentation**: a media frame larger
//! than one chunk is split BEFORE the seal into fragments, each a whole
//! chunk (its own `chunk_seq`, inner and outer seal, source signature), and
//! reassembled by the receiver after the reorder window. The clear header,
//! relays, the DAG and the 5.3.3.4 pull see chunks only: nothing above the
//! plaintext changes. CC 5.3.3.2.3's "one chunk, one link payload" holds:
//! no sealed chunk is ever split.
//!
//! On a stream whose v2 binding signs `framing = 1`, every chunk whose
//! `codec_id` is not `0xFF` starts its plaintext with the marker
//! `frag_index u16_be ‖ frag_count u16_be ‖ frame_seq u32_be` (a whole frame
//! is `0 ‖ 1 ‖ k`, so the layout never depends on size). `frame_seq` counts
//! the stream's frames per (codec class, layer) from 0 for the stream's whole
//! life (the layer being the whole `ChunkLayer` triple, spatial, temporal and
//! quality, the bytes a relay's layer filter reads), across epoch rolls (Eric 2026-11-10): one stream shares one
//! `chunk_seq` across audio and video and restarts it each epoch, so only
//! `frame_seq` tells a lost video frame (of a layer the receiver was being
//! sent) from lost audio or a layer it was never sent. Audio (`0xFF`) chunks never carry it. A
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

/// The marker's length: `frag_index u16_be ‖ frag_count u16_be ‖ frame_seq
/// u32_be`.
pub const FRAGMENT_MARKER_LEN: usize = 8;

/// The most fragments one frame takes (CC reading, rc18: `frag_count` ≤
/// 4096, still a `u16`). A frame needing more is refused before anything is
/// sealed.
pub const MAX_FRAME_FRAGMENTS: usize = 4096;

/// The largest reassembled frame (1 MiB): a larger one is refused before
/// sealing, and a receiver drops a frame whose fragments pass it. A 1080p
/// desktop keyframe fits at every MTU.
pub const MAX_FRAME_BYTES: usize = 1 << 20;

/// The marker for fragment `index` of `count` of the class's frame
/// `frame_seq`.
#[must_use]
pub fn marker(index: u16, count: u16, frame_seq: u32) -> [u8; FRAGMENT_MARKER_LEN] {
    let i = index.to_be_bytes();
    let c = count.to_be_bytes();
    let f = frame_seq.to_be_bytes();
    [i[0], i[1], c[0], c[1], f[0], f[1], f[2], f[3]]
}

/// Split `frame` into marked fragment plaintexts of at most `budget` bytes
/// each (the call's `chunk_plaintext_budget`, the marker included). `None`
/// when `budget` leaves no room past the marker, the frame is over
/// [`MAX_FRAME_BYTES`], or it needs more than [`MAX_FRAME_FRAGMENTS`]. An
/// empty frame is one fragment.
#[must_use]
pub fn split(frame: &[u8], budget: usize, frame_seq: u32) -> Option<Vec<Vec<u8>>> {
    if frame.len() > MAX_FRAME_BYTES {
        return None;
    }
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
        p.extend_from_slice(&marker(u16::try_from(i).ok()?, count16, frame_seq));
        p.extend_from_slice(&frame[lo..hi]);
        out.push(p);
    }
    Some(out)
}

/// The largest frame a framed stream takes at `budget`:
/// [`MAX_FRAME_FRAGMENTS`] × (`budget` − the marker), capped at
/// [`MAX_FRAME_BYTES`].
#[must_use]
pub fn max_frame_len(budget: usize) -> usize {
    (budget.saturating_sub(FRAGMENT_MARKER_LEN) * MAX_FRAME_FRAGMENTS).min(MAX_FRAME_BYTES)
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
    /// A fragment's `frame_seq` differs from its frame's.
    FrameSeqMismatch,
    /// A frame missing a fragment the reorder window gave up on: dropped
    /// whole (counted once per frame).
    Incomplete,
    /// A frame whose fragments pass [`MAX_FRAME_BYTES`].
    TooLarge,
    /// A framed stream's non-audio chunk whose framing never became known: it
    /// was released while only the stream's v1 binding was held, and its v2
    /// binding did not follow within the hold. Dropped, never parsed as
    /// unframed.
    FramingUnknown,
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
            Self::FrameSeqMismatch => o::AV_FRAME_SEQ_MISMATCH,
            Self::Incomplete => o::AV_FRAME_INCOMPLETE,
            Self::TooLarge => o::AV_FRAME_TOO_LARGE,
            Self::FramingUnknown => o::AV_FRAME_FRAMING_UNKNOWN,
        }
    }

    /// Every token, for the metric registry.
    pub const ALL: [Self; 10] = [
        Self::MarkerShort,
        Self::CountInvalid,
        Self::IndexInvalid,
        Self::CountMismatch,
        Self::LayerMismatch,
        Self::CrossesEpoch,
        Self::FrameSeqMismatch,
        Self::Incomplete,
        Self::TooLarge,
        Self::FramingUnknown,
    ];
}

/// One frame being put back together.
struct Partial {
    epoch: Epoch,
    first_seq: u64,
    frame_seq: u32,
    count: u16,
    next: u16,
    codec_id: u8,
    layer: ChunkLayer,
    head: ReceivedFrame,
    bytes: Vec<u8>,
}

/// One (stream, layer)'s reassembly, fed that layer's framed chunks in the
/// reorder window's release order (`chunk_seq` ascending, gaps already given
/// up). One frame is open at most.
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
        let Some((index, count, frame_seq)) = parse(&chunk.bytes) else {
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
            } else if frame_seq != p.frame_seq {
                self.partial = None;
                out.refused.push(FrameRefusal::FrameSeqMismatch);
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
                    frame_seq: Some(frame_seq),
                    ..chunk
                });
                return out;
            }
            self.partial = Some(Partial {
                epoch: chunk.epoch,
                first_seq: seq,
                frame_seq,
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
        if p.bytes.len() + chunk.bytes.len() - FRAGMENT_MARKER_LEN > MAX_FRAME_BYTES {
            let start = p.first_seq;
            self.partial = None;
            self.orphan = Some((chunk.epoch, start));
            out.refused.push(FrameRefusal::TooLarge);
            return out;
        }
        p.bytes
            .extend_from_slice(&chunk.bytes[FRAGMENT_MARKER_LEN..]);
        p.next += 1;
        if p.next == p.count {
            let p = self.partial.take().expect("open");
            // The frame is its first fragment's: its `chunk_seq`, epoch,
            // layer and signed source timestamp.
            out.frame = Some(ReceivedFrame {
                bytes: p.bytes,
                frame_seq: Some(p.frame_seq),
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

/// The marker of a framed chunk's plaintext: `(frag_index, frag_count,
/// frame_seq)`.
#[must_use]
pub fn parse(plaintext: &[u8]) -> Option<(u16, u16, u32)> {
    let m = plaintext.get(..FRAGMENT_MARKER_LEN)?;
    Some((
        u16::from_be_bytes([m[0], m[1]]),
        u16::from_be_bytes([m[2], m[3]]),
        u32::from_be_bytes([m[4], m[5], m[6], m[7]]),
    ))
}

/// The reassemblers of one call, one per (stream, layer).
#[derive(Default)]
pub struct Reassemblers {
    /// One reassembler per (stream, layer): for `av1` one frame is one layer
    /// of a temporal unit, and on a datagram leg layer 1's first fragments
    /// may come before layer 0's last, so a per-stream slot would drop the
    /// base layer (CC rc18).
    slots: std::collections::HashMap<(StreamId, ChunkLayer), Reassembler>,
    /// The newest `frame_seq` handed out per (stream, codec class, layer),
    /// with the receive view it came in.
    last_frame: std::collections::HashMap<(StreamId, u8, ChunkLayer), (u32, u64)>,
    /// Frames never handed out, per (codec class, layer): gaps in
    /// `frame_seq` (Eric 2026-11-10). A base-layer gap is the one that means
    /// "freeze until the next keyframe".
    lost: std::collections::BTreeMap<(u8, (u8, u8, u8)), u64>,
    /// Each stream's receive view: bumped by the call whenever what this
    /// node is sent OF THAT STREAM may change (its own layer request for it,
    /// a parent's shed or decision on it). A gap is counted only between two
    /// frames of one view: a layer this node was not being sent for a while
    /// is no loss, and a loss on a layer it was steadily getting always is.
    views: std::collections::HashMap<StreamId, u64>,
}

/// The most (stream, layer) slots one stream holds at once: past it, the
/// slot with the oldest open frame is closed (that frame dropped,
/// `av_frame_incomplete`). An SVC stream has far fewer layers.
pub const MAX_LAYER_SLOTS_PER_STREAM: usize = 16;

impl Reassemblers {
    /// Take one released chunk: an unframed stream's (`framing` 0) or an
    /// audio (`0xFF`) chunk passes through as a frame; a framed stream's
    /// other chunks go through its (stream, layer) reassembler.
    pub fn push(&mut self, chunk: ReceivedFrame, framing: u8) -> Reassembled {
        if framing != crate::transport::av_chunk_auth::FRAMING_FRAGMENTS
            || chunk.codec_id == crate::transport::realtime_av::CODEC_OPAQUE
        {
            return Reassembled {
                frame: Some(chunk),
                refused: Vec::new(),
            };
        }
        let key = (chunk.stream, chunk.layer);
        let mut early = Vec::new();
        // A later fragment that continues another layer's open frame of the
        // same stream: the frame changed layer mid-run.
        if let Some((index, _, _)) = parse(&chunk.bytes).filter(|(i, _, _)| *i > 0) {
            let seq = chunk.chunk_seq.0;
            let own_open = self.slots.get(&key).is_some_and(|r| r.partial.is_some());
            if !own_open {
                let other = self.slots.iter().find_map(|(k, r)| {
                    (k.0 == chunk.stream && k.1 != chunk.layer)
                        .then_some(r.partial.as_ref())
                        .flatten()
                        .filter(|p| {
                            p.epoch == chunk.epoch
                                && p.first_seq + u64::from(index) == seq
                                && p.next == index
                        })
                        .map(|_| *k)
                });
                if let Some(k) = other {
                    if let Some(r) = self.slots.get_mut(&k) {
                        r.partial = None;
                        r.orphan = None;
                    }
                    let slot = self.slots.entry(key).or_default();
                    slot.orphan = seq.checked_sub(u64::from(index)).map(|f| (chunk.epoch, f));
                    return Reassembled {
                        frame: None,
                        refused: vec![FrameRefusal::LayerMismatch],
                    };
                }
            }
        }
        if !self.slots.contains_key(&key) {
            early.extend(self.make_room(chunk.stream));
        }
        let mut out = self.slots.entry(key).or_default().push(chunk);
        early.append(&mut out.refused);
        out.refused = early;
        if let Some(f) = &out.frame {
            self.note_frame_seq(f);
        }
        out
    }

    /// `stream`'s receive view now (see the field).
    pub fn set_view(&mut self, stream: StreamId, view: u64) {
        self.views.insert(stream, view);
    }

    /// A frame handed out: a gap since its (stream, class, layer)'s last one
    /// is that many frames of that layer lost, counted only when both ends
    /// of the gap came in one receive view. The first frame of a layer (a
    /// joiner's missed prefix, a layer newly admitted) starts its count; an
    /// older one changes nothing. `frame_seq` runs for the stream's life, so
    /// an epoch roll is no gap.
    fn note_frame_seq(&mut self, f: &ReceivedFrame) {
        let Some(k) = f.frame_seq else {
            return;
        };
        let key = (f.stream, f.codec_id, f.layer);
        let view = self.views.get(&f.stream).copied().unwrap_or(0);
        match self.last_frame.get(&key).copied() {
            Some((last, v)) => {
                let d = k.wrapping_sub(last);
                if d == 0 || d >= 0x8000_0000 {
                    return;
                }
                if d > 1 && v == view {
                    let layer = (f.layer.spatial, f.layer.temporal, f.layer.quality);
                    *self.lost.entry((f.codec_id, layer)).or_insert(0) += u64::from(d - 1);
                }
                self.last_frame.insert(key, (k, view));
            }
            None => {
                self.last_frame.insert(key, (k, view));
            }
        }
    }

    /// Frames lost so far per (codec class, layer `(s, t, q)`): gaps in
    /// `frame_seq` on layers this node was being sent.
    #[must_use]
    pub fn lost_by_layer(&self) -> std::collections::BTreeMap<(u8, (u8, u8, u8)), u64> {
        self.lost.clone()
    }

    /// Keep a new slot within [`MAX_LAYER_SLOTS_PER_STREAM`] for `stream`:
    /// drop an idle slot, else close the one with the oldest open frame.
    fn make_room(&mut self, stream: StreamId) -> Vec<FrameRefusal> {
        let keys: Vec<(StreamId, ChunkLayer)> = self
            .slots
            .keys()
            .filter(|k| k.0 == stream)
            .copied()
            .collect();
        if keys.len() < MAX_LAYER_SLOTS_PER_STREAM {
            return Vec::new();
        }
        if let Some(idle) = keys
            .iter()
            .find(|k| self.slots.get(k).is_some_and(|r| r.partial.is_none()))
        {
            self.slots.remove(idle);
            return Vec::new();
        }
        let oldest = keys.into_iter().min_by_key(|k| {
            self.slots
                .get(k)
                .and_then(|r| r.partial.as_ref())
                .map_or((u64::MAX, u64::MAX), |p| (p.epoch.0, p.first_seq))
        });
        let mut out = Reassembled::default();
        if let Some(k) = oldest {
            if let Some(mut r) = self.slots.remove(&k) {
                r.abandon(&mut out);
            }
        }
        out.refused
    }

    /// Keep only the streams `live` says are still bound; the rest (ended,
    /// replaced, evicted) are forgotten, open frames dropped incomplete.
    pub fn retain(&mut self, live: impl Fn(StreamId) -> bool) -> Vec<FrameRefusal> {
        let mut gone: Vec<StreamId> = self
            .slots
            .keys()
            .map(|k| k.0)
            .filter(|s| !live(*s))
            .collect();
        gone.sort_unstable();
        gone.dedup();
        gone.into_iter().flat_map(|s| self.forget(s)).collect()
    }

    /// How many frames are open across every stream: the receiver's
    /// reassembly gauge.
    #[must_use]
    pub fn open(&self) -> usize {
        self.slots.values().filter(|r| r.partial.is_some()).count()
    }

    /// How many frames `stream` has open (at most one per layer).
    #[must_use]
    pub fn open_for(&self, stream: StreamId) -> usize {
        self.slots
            .iter()
            .filter(|(k, r)| k.0 == stream && r.partial.is_some())
            .count()
    }

    /// Forget `stream` (it ended or was replaced); its open frames are
    /// dropped incomplete.
    pub fn forget(&mut self, stream: StreamId) -> Vec<FrameRefusal> {
        self.last_frame.retain(|(s, _, _), _| *s != stream);
        self.views.remove(&stream);
        let keys: Vec<(StreamId, ChunkLayer)> = self
            .slots
            .keys()
            .filter(|k| k.0 == stream)
            .copied()
            .collect();
        let mut out = Reassembled::default();
        for k in keys {
            if let Some(mut r) = self.slots.remove(&k) {
                r.abandon(&mut out);
            }
        }
        out.refused
    }
}

/// What a receiver knows of a released chunk's framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingState {
    /// Known: the `(stream, epoch)`'s v2 binding signed this framing, or the
    /// stream is known never to carry one (its publisher does not take v2,
    /// or this receiver does not).
    Known(u8),
    /// Only the v1 binding is held and a v2 one may still be in flight: the
    /// chunk waits (bounded) and is never parsed as unframed.
    Pending,
}

/// v45 (CC rc18: a receiver never parses a framed chunk as unframed) —
/// non-audio chunks whose framing is [`FramingState::Pending`] wait here,
/// in order per `(stream, epoch)`, until the v2 binding installs (then they
/// go on with its framing) or the hold passes (then they are dropped and
/// counted [`FrameRefusal::FramingUnknown`]). Audio (`0xFF`) never carries
/// the marker and never waits.
#[derive(Default)]
pub struct FramingGate {
    held: std::collections::BTreeMap<
        (StreamId, u64),
        std::collections::VecDeque<(std::time::Instant, ReceivedFrame)>,
    >,
}

impl FramingGate {
    /// Take one released chunk in `state`; what goes on now, each with its
    /// framing.
    pub fn admit(
        &mut self,
        chunk: ReceivedFrame,
        state: FramingState,
        now: std::time::Instant,
    ) -> Vec<(ReceivedFrame, u8)> {
        if chunk.codec_id == crate::transport::realtime_av::CODEC_OPAQUE {
            return vec![(chunk, crate::transport::av_chunk_auth::FRAMING_NONE)];
        }
        let key = (chunk.stream, chunk.epoch.0);
        match state {
            FramingState::Known(f) => {
                let mut out = self.flush(key, f);
                out.push((chunk, f));
                out
            }
            FramingState::Pending => {
                self.held.entry(key).or_default().push_back((now, chunk));
                Vec::new()
            }
        }
    }

    /// Re-read every held `(stream, epoch)`: a known framing releases its
    /// chunks in order; a chunk held `hold` or longer is dropped. Returns
    /// what goes on, and how many were dropped.
    pub fn tick(
        &mut self,
        now: std::time::Instant,
        hold: std::time::Duration,
        state: impl Fn(&ReceivedFrame) -> FramingState,
    ) -> (Vec<(ReceivedFrame, u8)>, u64) {
        let keys: Vec<(StreamId, u64)> = self.held.keys().copied().collect();
        let mut out = Vec::new();
        let mut dropped = 0;
        for key in keys {
            let Some(st) = self
                .held
                .get(&key)
                .and_then(|q| q.front())
                .map(|(_, c)| state(c))
            else {
                continue;
            };
            match st {
                FramingState::Known(f) => out.extend(self.flush(key, f)),
                FramingState::Pending => {
                    if let Some(q) = self.held.get_mut(&key) {
                        while q
                            .front()
                            .is_some_and(|(t, _)| now.saturating_duration_since(*t) >= hold)
                        {
                            q.pop_front();
                            dropped += 1;
                        }
                        if q.is_empty() {
                            self.held.remove(&key);
                        }
                    }
                }
            }
        }
        (out, dropped)
    }

    /// When the oldest held chunk's hold runs out, if any is held.
    #[must_use]
    pub fn next_deadline(&self, hold: std::time::Duration) -> Option<std::time::Instant> {
        self.held
            .values()
            .filter_map(|q| q.front().map(|(t, _)| *t + hold))
            .min()
    }

    fn flush(&mut self, key: (StreamId, u64), framing: u8) -> Vec<(ReceivedFrame, u8)> {
        self.held
            .remove(&key)
            .map(|q| q.into_iter().map(|(_, c)| (c, framing)).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
#[path = "frame_tests.rs"]
mod tests;
