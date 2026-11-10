//! 45.1 — frame fragmentation witnesses (CC reading, rc18).

use super::*;
use crate::transport::av_chunk_auth::{FRAMING_FRAGMENTS, FRAMING_NONE};
use crate::transport::realtime_av::{ChunkSeq, CODEC_OPAQUE, CODEC_TEMPORAL_LAYERED};

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
    split(frame, budget)
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
    assert_eq!(marker(0, 1), [0, 0, 0, 1]);
    assert_eq!(marker(3, 256), [0, 3, 1, 0]);
    assert_eq!(parse(&[0, 7, 0, 9, 0xaa]), Some((7, 9)));
    assert_eq!(parse(&[0, 7, 0]), None);
    let one = split(b"tiny", 1_000).expect("fits");
    assert_eq!(one, vec![[&marker(0, 1)[..], b"tiny"].concat()]);
    assert_eq!(
        split(b"", 1_000).expect("fits"),
        vec![marker(0, 1).to_vec()]
    );
}

/// A 40 KB keyframe at a ~1,100 B budget is ⌈40000 / (b − 4)⌉ fragments,
/// each at most the budget, the marker counting; 256 is the cap, and one
/// byte past `max_frame_len` is refused before anything is sealed.
#[test]
fn a_keyframe_splits_to_the_budget_and_the_cap_is_256() {
    let budget = 1_100;
    let frame = frame_bytes(40_000, 3);
    let parts = split(&frame, budget).expect("fits");
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
                u16::try_from(parts.len()).unwrap()
            ))
        );
    }
    let max = max_frame_len(budget);
    assert_eq!(max, 256 * (budget - 4));
    assert_eq!(
        split(&frame_bytes(max, 1), budget).expect("fits").len(),
        256
    );
    assert!(
        split(&frame_bytes(max + 1, 1), budget).is_none(),
        "257 fragments"
    );
    assert!(
        split(b"x", FRAGMENT_MARKER_LEN).is_none(),
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
    let with = |seq: u64, m: [u8; 4], layer: ChunkLayer, epoch: u64| {
        chunk(epoch, seq, v, layer, [&m[..], b"x"].concat())
    };
    assert_eq!(
        refuse(vec![with(0, marker(0, 0), L0, 1)]),
        ["av_frame_count_invalid"]
    );
    assert_eq!(
        refuse(vec![with(0, marker(0, 257), L0, 1)]),
        ["av_frame_count_invalid"]
    );
    assert_eq!(
        refuse(vec![with(0, marker(3, 3), L0, 1)]),
        ["av_frame_index_invalid"]
    );
    assert_eq!(
        refuse(vec![
            with(0, marker(0, 3), L0, 1),
            with(1, marker(1, 4), L0, 1)
        ]),
        ["av_frame_count_mismatch"]
    );
    assert_eq!(
        refuse(vec![
            with(0, marker(0, 2), L0, 1),
            with(1, marker(1, 2), L1, 1)
        ]),
        ["av_frame_layer_mismatch"]
    );
    assert_eq!(
        refuse(vec![
            with(0, marker(0, 2), L0, 1),
            with(1, marker(1, 2), L0, 2)
        ]),
        ["av_frame_crosses_epoch"]
    );
    assert_eq!(
        refuse(vec![chunk(1, 0, v, L0, vec![0, 0, 0])]),
        ["av_frame_marker_short"]
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
