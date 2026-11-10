//! v45 — frame fragmentation witnesses (CC reading, rc18).

use super::*;
use crate::transport::av_chunk_auth::{FRAMING_FRAGMENTS, FRAMING_NONE};
use crate::transport::realtime_av::{
    ChunkSeq, CODEC_AV1_SVC, CODEC_OPAQUE, CODEC_TEMPORAL_LAYERED,
};

const S: StreamId = StreamId([5; 32]);

fn chunk(epoch: u64, seq: u64, codec_id: u8, layer: ChunkLayer, bytes: Vec<u8>) -> ReceivedFrame {
    ReceivedFrame {
        publisher: "pub".into(),
        stream: S,
        epoch: Epoch(epoch),
        chunk_seq: ChunkSeq(seq),
        codec_id,
        layer,
        bytes,
        frame_seq: None,
        source_ts_ms: 0,
    }
}

const L0: ChunkLayer = ChunkLayer {
    spatial: 0,
    temporal: 0,
    quality: 0,
};
const L1: ChunkLayer = ChunkLayer {
    spatial: 0,
    temporal: 1,
    quality: 0,
};

/// A frame of `len` bytes, `seed`-patterned.
fn frame_bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| seed.wrapping_add(u8::try_from(i % 251).unwrap()))
        .collect()
}

/// The frame's fragments as released chunks from `seq`, video at `layer`.
fn fragments(
    frame: &[u8],
    budget: usize,
    epoch: u64,
    seq: u64,
    layer: ChunkLayer,
) -> Vec<ReceivedFrame> {
    split(frame, budget, 0)
        .expect("fits")
        .into_iter()
        .enumerate()
        .map(|(i, p)| {
            chunk(
                epoch,
                seq + u64::try_from(i).unwrap(),
                CODEC_TEMPORAL_LAYERED,
                layer,
                p,
            )
        })
        .collect()
}

/// The marker is `frag_index u16_be ‖ frag_count u16_be`, first in the
/// plaintext; a whole frame is `0 ‖ 1`, so the layout never depends on size.
#[test]
fn the_marker_is_index_then_count_and_a_whole_frame_is_zero_of_one() {
    assert_eq!(marker(0, 1, 0), [0, 0, 0, 1, 0, 0, 0, 0]);
    assert_eq!(marker(3, 256, 0x0102_0304), [0, 3, 1, 0, 1, 2, 3, 4]);
    assert_eq!(parse(&[0, 7, 0, 9, 0, 0, 0, 5, 0xaa]), Some((7, 9, 5)));
    assert_eq!(parse(&[0, 7, 0, 9, 0, 0, 0]), None, "shorter than 8");
    let one = split(b"tiny", 1_000, 0).expect("fits");
    assert_eq!(one, vec![[&marker(0, 1, 0)[..], b"tiny"].concat()]);
    assert_eq!(
        split(b"", 1_000, 0).expect("fits"),
        vec![marker(0, 1, 0).to_vec()]
    );
}

/// A 40 KB keyframe at a ~1,100 B budget is ⌈40000 / (b − 4)⌉ fragments,
/// each at most the budget, the marker counting. The caps (CC reading
/// rc18): 4096 fragments and 1 MiB, whichever binds first; one byte past
/// `max_frame_len` is refused before anything is sealed. At MTU 500 (budget
/// 244, 236 media bytes a fragment) the fragment cap binds at 966,656 B; at
/// MTU 1400 (budget 1,140) the 1 MiB cap does.
#[test]
fn a_keyframe_splits_to_the_budget_and_the_cap_is_256() {
    let budget = 1_100;
    let frame = frame_bytes(40_000, 3);
    let parts = split(&frame, budget, 0).expect("fits");
    assert_eq!(
        parts.len(),
        40_000usize.div_ceil(budget - FRAGMENT_MARKER_LEN)
    );
    for (i, p) in parts.iter().enumerate() {
        assert!(p.len() <= budget);
        assert_eq!(
            parse(p),
            Some((
                u16::try_from(i).unwrap(),
                u16::try_from(parts.len()).unwrap(),
                0
            ))
        );
    }
    assert_eq!(max_frame_len(244), 4096 * 236, "MTU 500: the fragment cap");
    assert_eq!(max_frame_len(244), 966_656);
    assert_eq!(
        max_frame_len(1_140),
        MAX_FRAME_BYTES,
        "MTU 1400: the 1 MiB cap"
    );
    let small = 244;
    let max = max_frame_len(small);
    assert_eq!(
        split(&frame_bytes(max, 1), small, 0).expect("fits").len(),
        4096
    );
    assert!(
        split(&frame_bytes(max + 1, 1), small, 0).is_none(),
        "4097 fragments"
    );
    let max = max_frame_len(budget);
    assert_eq!(max, MAX_FRAME_BYTES);
    assert!(split(&frame_bytes(max, 1), budget, 0).is_some());
    assert!(
        split(&frame_bytes(max + 1, 1), budget, 0).is_none(),
        "over 1 MiB"
    );
    assert!(
        split(b"x", FRAGMENT_MARKER_LEN, 0).is_none(),
        "no room past the marker"
    );
}

/// The fragments, released in order, come back as the one frame,
/// byte-identical, with the first fragment's seq, codec and layer.
#[test]
fn fragments_in_order_are_one_frame() {
    let frame = frame_bytes(5_000, 9);
    let mut r = Reassembler::default();
    let parts = fragments(&frame, 1_000, 2, 10, L1);
    let n = parts.len();
    for (i, c) in parts.into_iter().enumerate() {
        let out = r.push(c);
        assert!(out.refused.is_empty());
        if i + 1 < n {
            assert!(out.frame.is_none(), "never partial");
        } else {
            let f = out.frame.expect("whole");
            assert_eq!(f.bytes, frame);
            assert_eq!(f.chunk_seq, ChunkSeq(10));
            assert_eq!((f.codec_id, f.layer), (CODEC_TEMPORAL_LAYERED, L1));
        }
    }
}

/// A fragment the reorder window gave up on: the frame is dropped,
/// counted once, never handed out partial; the next frame plays.
#[test]
fn a_missing_fragment_drops_its_frame_once_and_the_next_plays() {
    let a = frame_bytes(3_000, 1);
    let b = frame_bytes(2_500, 2);
    let mut parts = fragments(&a, 1_000, 1, 0, L0);
    let next_seq = u64::try_from(parts.len()).unwrap();
    parts.remove(1);
    parts.extend(fragments(&b, 1_000, 1, next_seq, L0));
    let mut r = Reassembler::default();
    let mut frames = Vec::new();
    let mut refused = Vec::new();
    for c in parts {
        let out = r.push(c);
        frames.extend(out.frame);
        refused.extend(out.refused);
    }
    assert_eq!(refused, [FrameRefusal::Incomplete], "the torn frame, once");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].bytes, b, "the next frame whole");
}

/// The lost fragment is the FIRST: the frame's later fragments are orphans,
/// counted once for the frame.
#[test]
fn a_lost_first_fragment_counts_its_frame_once() {
    let a = frame_bytes(4_000, 4);
    let mut parts = fragments(&a, 1_000, 1, 0, L0);
    parts.remove(0);
    let mut r = Reassembler::default();
    let refused: Vec<_> = parts.into_iter().flat_map(|c| r.push(c).refused).collect();
    assert_eq!(refused, [FrameRefusal::Incomplete]);
}

/// The receiver-only refusals, by name: a count of 0 or over 256, an index
/// at or past the count, a count that changes within a frame, a codec or
/// layer that changes within a frame, a run that crosses the epoch, and a
/// chunk shorter than the marker.
#[test]
fn each_malformed_marker_is_refused_by_name() {
    let refuse = |chunks: Vec<ReceivedFrame>| -> Vec<&'static str> {
        let mut r = Reassembler::default();
        chunks
            .into_iter()
            .flat_map(|c| r.push(c).refused)
            .map(FrameRefusal::token)
            .collect()
    };
    let v = CODEC_TEMPORAL_LAYERED;
    let with = |seq: u64, m: [u8; 8], layer: ChunkLayer, epoch: u64| {
        chunk(epoch, seq, v, layer, [&m[..], b"x"].concat())
    };
    assert_eq!(
        refuse(vec![with(0, marker(0, 0, 0), L0, 1)]),
        ["av_frame_count_invalid"]
    );
    assert_eq!(
        refuse(vec![with(0, marker(0, 4097, 0), L0, 1)]),
        ["av_frame_count_invalid"]
    );
    assert!(
        refuse(vec![with(0, marker(0, 4096, 0), L0, 1)]).is_empty(),
        "4096 is legal"
    );
    assert_eq!(
        refuse(vec![with(0, marker(3, 3, 0), L0, 1)]),
        ["av_frame_index_invalid"]
    );
    assert_eq!(
        refuse(vec![
            with(0, marker(0, 3, 0), L0, 1),
            with(1, marker(1, 4, 0), L0, 1)
        ]),
        ["av_frame_count_mismatch"]
    );
    assert_eq!(
        refuse(vec![
            with(0, marker(0, 2, 0), L0, 1),
            with(1, marker(1, 2, 0), L1, 1)
        ]),
        ["av_frame_layer_mismatch"]
    );
    assert_eq!(
        refuse(vec![
            with(0, marker(0, 2, 0), L0, 1),
            with(1, marker(1, 2, 0), L0, 2)
        ]),
        ["av_frame_crosses_epoch"]
    );
    assert_eq!(
        refuse(vec![chunk(1, 0, v, L0, vec![0, 0, 0])]),
        ["av_frame_marker_short"]
    );
    assert_eq!(
        refuse(vec![
            with(0, marker(0, 2, 4), L0, 1),
            with(1, marker(1, 2, 5), L0, 1)
        ]),
        ["av_frame_seq_mismatch"]
    );
    for t in FrameRefusal::ALL {
        assert!(t.token().starts_with("av_frame_"));
    }
}

/// CC (rc18): on a framed stream the marker is on every chunk whose
/// codec_id is not 0xFF; audio never carries it, and an unframed stream
/// carries none. Interleaved audio and video both play.
#[test]
fn a_framed_stream_marks_video_and_never_audio() {
    let mut rs = Reassemblers::default();
    let video = frame_bytes(2_200, 7);
    let opus = b"20 ms of opus".to_vec();
    let mut got = Vec::new();
    // Audio, then a video frame's fragments, then audio again (the
    // publisher's lock keeps a frame's fragments consecutive).
    let mut seq = 0;
    let mut feed = |c: ReceivedFrame, framing: u8, rs: &mut Reassemblers| {
        let out = rs.push(c, framing);
        assert!(out.refused.is_empty(), "{:?}", out.refused);
        got.extend(out.frame);
    };
    feed(
        chunk(1, seq, CODEC_OPAQUE, L0, opus.clone()),
        FRAMING_FRAGMENTS,
        &mut rs,
    );
    seq += 1;
    for c in fragments(&video, 1_000, 1, seq, L0) {
        seq += 1;
        feed(c, FRAMING_FRAGMENTS, &mut rs);
    }
    feed(
        chunk(1, seq, CODEC_OPAQUE, L0, opus.clone()),
        FRAMING_FRAGMENTS,
        &mut rs,
    );
    // An unframed stream's video is the frame as sealed.
    feed(
        chunk(1, 99, CODEC_TEMPORAL_LAYERED, L0, video.clone()),
        FRAMING_NONE,
        &mut rs,
    );
    let bytes: Vec<Vec<u8>> = got.into_iter().map(|f| f.bytes).collect();
    assert_eq!(bytes, vec![opus.clone(), video.clone(), opus, video]);
}

/// A stream that ends or is replaced mid-frame drops the open frame,
/// counted.
#[test]
fn forgetting_a_stream_mid_frame_drops_the_open_frame() {
    let mut rs = Reassemblers::default();
    let mut parts = fragments(&frame_bytes(3_000, 5), 1_000, 1, 0, L0);
    parts.truncate(2);
    for c in parts {
        assert!(rs.push(c, FRAMING_FRAGMENTS).frame.is_none());
    }
    assert_eq!(rs.forget(S), [FrameRefusal::Incomplete]);
    assert!(rs.forget(S).is_empty());
}

/// A frame whose fragments pass 1 MiB is dropped `av_frame_too_large`; a
/// (stream, layer) holds one open frame at most, and the gauge says so.
#[test]
fn a_frame_past_one_mib_is_dropped_and_one_frame_is_open_per_stream() {
    let mut r = Reassembler::default();
    let big = vec![0u8; 600_000];
    let first = chunk(
        1,
        0,
        CODEC_TEMPORAL_LAYERED,
        L0,
        [&marker(0, 3, 0)[..], &big].concat(),
    );
    let second = chunk(
        1,
        1,
        CODEC_TEMPORAL_LAYERED,
        L0,
        [&marker(1, 3, 0)[..], &big].concat(),
    );
    assert!(r.push(first).refused.is_empty());
    assert_eq!(r.push(second).refused, [FrameRefusal::TooLarge]);
    let mut rs = Reassemblers::default();
    for c in fragments(&frame_bytes(3_000, 2), 1_000, 1, 0, L0)
        .into_iter()
        .take(2)
    {
        let _ = rs.push(c, FRAMING_FRAGMENTS);
    }
    assert_eq!(rs.open(), 1, "one open frame for the layer");
    assert_eq!(rs.open_for(S), 1);
    let next = fragments(&frame_bytes(3_000, 3), 1_000, 1, 10, L0);
    let out = rs.push(next[0].clone(), FRAMING_FRAGMENTS);
    assert_eq!(
        out.refused,
        [FrameRefusal::Incomplete],
        "a new frame closes the old"
    );
    assert_eq!(rs.open(), 1, "still one");
}

/// CC rc18 — the framing race closed: v1 is held, then a framed stream's
/// chunks are released, then its v2 binding arrives late. No chunk goes on
/// as unframed while the framing is unknown; once v2 is in, the held chunks
/// go on in order with its framing and the frames come out whole. Audio
/// never waits. A v2 that never comes drops the held chunks past the hold,
/// counted, and still nothing is parsed unframed.
#[test]
fn v1_then_chunks_then_late_v2_never_parses_a_framed_chunk_unframed() {
    use std::time::{Duration, Instant};
    let hold = Duration::from_millis(400);
    let t = Instant::now();
    let mut gate = FramingGate::default();
    let mut rs = Reassemblers::default();
    let frame = frame_bytes(2_500, 8);
    let parts = fragments(&frame, 1_000, 1, 0, L0);
    let opus = chunk(1, 99, CODEC_OPAQUE, L0, b"opus".to_vec());
    // Only v1 held: every video chunk waits; audio goes on.
    let mut out = Vec::new();
    for c in parts.clone() {
        out.extend(gate.admit(c, FramingState::Pending, t));
    }
    let audio = gate.admit(opus.clone(), FramingState::Pending, t);
    assert_eq!(audio, vec![(opus, FRAMING_NONE)], "audio never waits");
    assert!(
        out.is_empty(),
        "nothing parsed while the framing is unknown"
    );
    let (none, dropped) = gate.tick(t + hold / 2, hold, |_| FramingState::Pending);
    assert!(none.is_empty() && dropped == 0, "still within the hold");
    // v2 lands (framing 1): the held chunks go on in order, framed.
    let (late, dropped) = gate.tick(t + hold / 2, hold, |_| {
        FramingState::Known(FRAMING_FRAGMENTS)
    });
    assert_eq!(dropped, 0);
    assert_eq!(late.len(), parts.len());
    let mut frames = Vec::new();
    for (c, f) in late {
        assert_eq!(f, FRAMING_FRAGMENTS);
        frames.extend(rs.push(c, f).frame);
    }
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].bytes, frame, "whole once v2 arrived");
    // A v2 that never comes: dropped past the hold, counted, never unframed.
    let mut gate = FramingGate::default();
    for c in parts.clone() {
        assert!(gate.admit(c, FramingState::Pending, t).is_empty());
    }
    assert_eq!(gate.next_deadline(hold), Some(t + hold));
    let (none, dropped) = gate.tick(t + hold, hold, |_| FramingState::Pending);
    assert!(none.is_empty());
    assert_eq!(dropped, u64::try_from(parts.len()).unwrap());
    assert_eq!(gate.next_deadline(hold), None);
    // A later chunk with a known framing releases the held ones first.
    let mut gate = FramingGate::default();
    let _ = gate.admit(parts[0].clone(), FramingState::Pending, t);
    let out = gate.admit(parts[1].clone(), FramingState::Known(FRAMING_FRAGMENTS), t);
    let seqs: Vec<u64> = out.iter().map(|(c, _)| c.chunk_seq.0).collect();
    assert_eq!(seqs, [0, 1], "in order");
}

/// CC rc18 — one open frame per (stream, layer), not per stream: for `av1`
/// one frame is one layer of a temporal unit, and on a datagram leg layer
/// 1's first fragments may come before layer 0's last. Layer-0 and layer-1
/// fragments interleaved across the frame boundary: both frames whole,
/// neither dropped; the gauge counts both open meanwhile.
#[test]
fn interleaved_layers_each_keep_their_open_frame() {
    let mut rs = Reassemblers::default();
    let base = frame_bytes(2_500, 1);
    let enh = frame_bytes(2_200, 2);
    let l0 = fragments(&base, 1_000, 1, 0, L0);
    let n0 = u64::try_from(l0.len()).unwrap();
    let l1 = fragments(&enh, 1_000, 1, n0, L1);
    assert_eq!((l0.len(), l1.len()), (3, 3));
    // L0[0], L0[1], L1[0], L1[1], L0[2], L1[2].
    let order = [
        l0[0].clone(),
        l0[1].clone(),
        l1[0].clone(),
        l1[1].clone(),
        l0[2].clone(),
        l1[2].clone(),
    ];
    let mut frames = Vec::new();
    for (i, c) in order.into_iter().enumerate() {
        let out = rs.push(c, FRAMING_FRAGMENTS);
        assert!(out.refused.is_empty(), "chunk {i}: {:?}", out.refused);
        if i == 3 {
            assert_eq!(rs.open_for(S), 2, "a frame open on each layer");
        }
        frames.extend(out.frame);
    }
    let got: Vec<(ChunkLayer, Vec<u8>)> = frames.into_iter().map(|f| (f.layer, f.bytes)).collect();
    assert_eq!(got, vec![(L0, base), (L1, enh)], "both whole");
    assert_eq!(rs.open(), 0);
}

/// A stream's layer slots are bounded: past the bound, a new layer closes
/// the slot with the oldest open frame, counted.
#[test]
fn layer_slots_per_stream_are_bounded() {
    let mut rs = Reassemblers::default();
    let mut refused = Vec::new();
    for q in 0..=u8::try_from(MAX_LAYER_SLOTS_PER_STREAM).unwrap() {
        let layer = ChunkLayer {
            spatial: 0,
            temporal: 0,
            quality: q,
        };
        let c = chunk(
            1,
            u64::from(q) * 10,
            CODEC_TEMPORAL_LAYERED,
            layer,
            [&marker(0, 2, 0)[..], b"x"].concat(),
        );
        refused.extend(rs.push(c, FRAMING_FRAGMENTS).refused);
    }
    assert_eq!(
        refused,
        [FrameRefusal::Incomplete],
        "the oldest open frame, once"
    );
    assert_eq!(rs.open_for(S), MAX_LAYER_SLOTS_PER_STREAM);
}

/// Eric 2026-11-10 — one stream shares one chunk_seq across audio and
/// video, so the marker's per-class `frame_seq` is what tells a lost video
/// frame from lost audio: video frames 0, 1, 3 handed out (2 never came) is
/// one 0x04 frame lost; the audio between them, unmarked, is counted
/// nothing. The first frame a receiver sees starts the count.
#[test]
fn a_lost_video_frame_is_a_frame_seq_gap_and_audio_is_unaffected() {
    let mut rs = Reassemblers::default();
    let mut seq = 40;
    let mut got = Vec::new();
    for k in [0u32, 1, 3] {
        let a = chunk(1, seq, CODEC_OPAQUE, L0, b"opus".to_vec());
        seq += 1;
        got.extend(rs.push(a, FRAMING_FRAGMENTS).frame);
        for p in split(&frame_bytes(1_500, 3), 1_000, k).expect("fits") {
            let out = rs.push(
                chunk(1, seq, CODEC_TEMPORAL_LAYERED, L0, p),
                FRAMING_FRAGMENTS,
            );
            seq += 1;
            got.extend(out.frame);
        }
    }
    let video: Vec<Option<u32>> = got
        .iter()
        .filter(|f| f.codec_id == CODEC_TEMPORAL_LAYERED)
        .map(|f| f.frame_seq)
        .collect();
    assert_eq!(video, [Some(0), Some(1), Some(3)]);
    assert!(
        got.iter()
            .filter(|f| f.codec_id == CODEC_OPAQUE)
            .all(|f| f.frame_seq.is_none()),
        "audio carries no frame_seq"
    );
    assert_eq!(
        rs.lost_by_layer(),
        [((CODEC_TEMPORAL_LAYERED, (0, 0, 0)), 1)]
            .into_iter()
            .collect(),
        "one base video frame lost, under layer (0,0,0); no audio"
    );
}

/// The frame's video at `layer` with its marker `frame_seq`.
fn video_frame(seq: &mut u64, epoch: u64, layer: ChunkLayer, k: u32) -> Vec<ReceivedFrame> {
    let out: Vec<ReceivedFrame> = split(&frame_bytes(600, 4), 1_000, k)
        .expect("fits")
        .into_iter()
        .map(|p| chunk(epoch, *seq, CODEC_AV1_SVC, layer, p))
        .collect();
    *seq += u64::try_from(out.len()).unwrap();
    out
}

fn push_all(rs: &mut Reassemblers, frames: Vec<ReceivedFrame>) {
    for c in frames {
        assert!(rs.push(c, FRAMING_FRAGMENTS).refused.is_empty());
    }
}

/// `frame_seq` runs per (stream, class, layer) for the stream's life, so an
/// SVC stream capped to its base (layer 1 never sent) books no loss, and a
/// cap that lifts mid-stream (a new receive view) books none for the frames
/// it was not sent; a lost base frame is counted under (0,0,0).
#[test]
fn layers_a_receiver_is_not_sent_are_no_loss_and_a_lost_base_frame_is() {
    let mut rs = Reassemblers::default();
    let mut seq = 0;
    // Capped to base: layer-0 frames 0..4 only (the publisher counted
    // layer 1 too, on its own counter).
    for k in 0..4 {
        let f = video_frame(&mut seq, 1, L0, k);
        push_all(&mut rs, f);
    }
    assert!(rs.lost_by_layer().is_empty(), "base-only: no false loss");
    // Layer 1 admitted (view 1): its frames 10, 11 (it was not sent 0..9).
    rs.set_view(1);
    for k in [10, 11] {
        let f = video_frame(&mut seq, 1, L1, k);
        push_all(&mut rs, f);
    }
    // Capped again (view 2), then lifted (view 3): layer-1 frame 20 next.
    rs.set_view(3);
    let f = video_frame(&mut seq, 1, L1, 20);
    push_all(&mut rs, f);
    assert!(
        rs.lost_by_layer().is_empty(),
        "frames of a layer this node was not being sent are no loss"
    );
    // Base frame 4 falls across the view change (not counted); within view
    // 3, frame 6 is lost between 5 and 7.
    let f = video_frame(&mut seq, 1, L0, 5);
    push_all(&mut rs, f);
    let f = video_frame(&mut seq, 1, L0, 7);
    push_all(&mut rs, f);
    assert_eq!(
        rs.lost_by_layer(),
        [((CODEC_AV1_SVC, (0, 0, 0)), 1)].into_iter().collect(),
        "base frame 6 lost"
    );
}

/// `frame_seq` does not restart at an epoch roll (chunk_seq does): frames 0,
/// 1 in epoch 1 and 2, 3 in epoch 2 are no gap; frame 5 in epoch 3 after 3
/// is one frame lost across the roll.
#[test]
fn frame_seq_carries_across_an_epoch_roll_with_no_false_gap() {
    let mut rs = Reassemblers::default();
    let mut frames = Vec::new();
    for (epoch, k, start) in [(1, 0, 0), (1, 1, 1), (2, 2, 0), (2, 3, 1)] {
        let mut seq = start;
        for c in video_frame(&mut seq, epoch, L0, k) {
            frames.extend(rs.push(c, FRAMING_FRAGMENTS).frame);
        }
    }
    assert_eq!(frames.len(), 4);
    assert!(rs.lost_by_layer().is_empty(), "the roll is no gap");
    let mut seq = 0;
    for c in video_frame(&mut seq, 3, L0, 5) {
        let _ = rs.push(c, FRAMING_FRAGMENTS);
    }
    assert_eq!(
        rs.lost_by_layer(),
        [((CODEC_AV1_SVC, (0, 0, 0)), 1)].into_iter().collect(),
        "frame 4, lost across the roll, is counted"
    );
}

/// The reassembled frame is its first fragment's: chunk_seq, epoch, layer
/// and the signed source timestamp (each fragment's trailer signs its own;
/// the first one's is the frame's).
#[test]
fn a_reassembled_frame_carries_its_first_fragments_seq_and_source_ts() {
    let mut rs = Reassemblers::default();
    let parts = split(&frame_bytes(2_500, 6), 1_000, 7).expect("fits");
    let mut out = None;
    for (i, p) in parts.into_iter().enumerate() {
        let mut c = chunk(
            2,
            100 + u64::try_from(i).unwrap(),
            CODEC_TEMPORAL_LAYERED,
            L0,
            p,
        );
        c.source_ts_ms = 1_790_000_000_000 + u64::try_from(i).unwrap();
        out = rs.push(c, FRAMING_FRAGMENTS).frame.or(out);
    }
    let f = out.expect("whole");
    assert_eq!(f.chunk_seq, ChunkSeq(100));
    assert_eq!(f.source_ts_ms, 1_790_000_000_000);
    assert_eq!(f.frame_seq, Some(7));
}
