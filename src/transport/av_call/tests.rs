use std::sync::Arc;

use ciris_persist::encrypted_kv::XChaChaKvStore;

use super::*;
use crate::mls::cohort_group::mint_cohort_key_material;
use crate::mls::ScopeStateProvider;
use crate::transport::av_keep::UnwiredRegistrar;
use crate::transport::realtime_av::{open_av_inner as open_inner, CODEC_OPAQUE};

const S1: StreamId = StreamId([0x51; 32]);
const S2: StreamId = StreamId([0x52; 32]);

fn frame(stream: StreamId, epoch: u64, seq: u64) -> ReceivedFrame {
    ReceivedFrame {
        publisher: "pub".to_owned(),
        stream,
        epoch: Epoch(epoch),
        chunk_seq: ChunkSeq(seq),
        codec_id: CODEC_OPAQUE,
        layer: ChunkLayer::BASE,
        bytes: format!("{epoch}:{seq}").into_bytes(),
    }
}

fn keys(out: &[ReceivedFrame]) -> Vec<(u64, u64)> {
    out.iter().map(|f| (f.epoch.0, f.chunk_seq.0)).collect()
}

/// In order on one leg: released at once, nothing buffered.
#[test]
fn in_order_frames_release_at_once() {
    let mut w = ReorderWindow::new();
    let t = Instant::now();
    for s in 0..5 {
        assert_eq!(keys(&w.push(frame(S1, 1, s), t)), vec![(1, s)]);
    }
    assert_eq!(w.counts().released, 5);
    assert_eq!(w.next_deadline(), None);
}

/// **The delayed-relay-leg witness (A8).** The direct leg loses every third
/// chunk; the relay leg carries every chunk, 60 ms late. The window holds the
/// direct copies past each gap until the relay copy fills it, so the stream
/// comes out strictly increasing with nothing skipped, and every relay copy
/// of a chunk already held is a counted duplicate.
#[test]
fn a_delayed_relay_leg_is_reordered_not_skipped() {
    let mut w = ReorderWindow::new();
    let t0 = Instant::now();
    let mut arrivals: Vec<(Instant, ReceivedFrame)> = Vec::new();
    for s in 0..30u64 {
        let sent = t0 + Duration::from_millis(33 * s);
        if s % 3 != 1 {
            arrivals.push((sent + Duration::from_millis(5), frame(S1, 4, s)));
        }
        arrivals.push((sent + Duration::from_millis(65), frame(S1, 4, s)));
    }
    arrivals.sort_by_key(|(at, _)| *at);
    let mut out = Vec::new();
    for (at, f) in arrivals {
        out.extend(w.tick(at));
        out.extend(w.push(f, at));
    }
    out.extend(w.tick(t0 + Duration::from_secs(5)));
    let got = keys(&out);
    let want: Vec<(u64, u64)> = (0..30).map(|s| (4, s)).collect();
    assert_eq!(got, want, "strictly increasing, every chunk once");
    let c = w.counts();
    assert_eq!(c.skipped, 0, "the window waited out the relay leg's lag");
    assert_eq!(
        c.duplicates, 20,
        "every relay copy of a direct chunk is a duplicate"
    );
    let win = w.window_for(S1);
    assert!(
        win >= Duration::from_millis(60) && win <= REORDER_WINDOW_MAX,
        "{win:?}"
    );
}

/// The window never waits out loss: a chunk missing on every leg is skipped
/// at its deadline and counted, and the stream moves on.
#[test]
fn a_chunk_lost_on_every_leg_is_skipped_at_its_deadline() {
    let mut w = ReorderWindow::new();
    let t = Instant::now();
    assert_eq!(keys(&w.push(frame(S1, 1, 0), t)), vec![(1, 0)]);
    assert!(w.push(frame(S1, 1, 2), t).is_empty(), "held behind the gap");
    assert!(w.push(frame(S1, 1, 3), t).is_empty());
    let deadline = w.next_deadline().expect("a gap is pending");
    assert!(deadline <= t + REORDER_WINDOW_MAX);
    assert!(w.tick(deadline - Duration::from_millis(1)).is_empty());
    assert_eq!(keys(&w.tick(deadline)), vec![(1, 2), (1, 3)]);
    assert_eq!(w.counts().skipped, 1);
    // The lost chunk turning up after its slot is late, not released.
    assert!(w.push(frame(S1, 1, 1), deadline).is_empty());
    assert_eq!(w.counts().late, 1);
}

/// The window is clamped: a huge measured gap caps at 400 ms, a tiny one
/// floors at 40 ms.
#[test]
fn the_window_is_clamped() {
    let mut w = ReorderWindow::new();
    let t = Instant::now();
    for s in 0..40 {
        let _ = w.push(frame(S1, 1, s), t);
        let _ = w.push(frame(S1, 1, s), t + Duration::from_secs(3));
    }
    assert_eq!(w.window_for(S1), REORDER_WINDOW_MAX);
    for s in 0..40 {
        let _ = w.push(frame(S2, 1, s), t);
        let _ = w.push(frame(S2, 1, s), t);
    }
    assert_eq!(w.window_for(S2), REORDER_WINDOW_MIN);
}

/// Streams are independent; an epoch roll (chunk_seq back to 0) releases in
/// `(epoch, chunk_seq)` order after the old epoch's tail.
#[test]
fn streams_are_independent_and_an_epoch_roll_orders_after_the_old_tail() {
    let mut w = ReorderWindow::new();
    let t = Instant::now();
    let _ = w.push(frame(S1, 1, 0), t);
    let _ = w.push(frame(S2, 7, 0), t);
    assert!(
        w.push(frame(S1, 2, 0), t).is_empty(),
        "the new epoch waits for the old tail"
    );
    assert_eq!(keys(&w.push(frame(S1, 1, 1), t)), vec![(1, 1)]);
    let out = w.tick(t + REORDER_WINDOW_MAX);
    assert_eq!(keys(&out), vec![(2, 0)]);
    assert_eq!(keys(&w.push(frame(S2, 7, 1), t)), vec![(7, 1)]);
}

#[test]
fn the_stream_hello_round_trips_and_nothing_else_parses() {
    let id = StreamId([9; 32]);
    assert_eq!(decode_hello(&encode_hello(id)), Some(id));
    assert_eq!(decode_hello(&[0u8; STREAM_HELLO_LEN]), None);
    assert_eq!(
        decode_hello(&encode_hello(id)[..STREAM_HELLO_LEN - 1]),
        None
    );
}

/// A call never reuses a stream id: a fresh join nonce is a fresh stream.
#[test]
fn every_join_is_a_new_stream() {
    let a = call_stream_id("room", "node-a", &[1; 32]);
    let b = call_stream_id("room", "node-a", &[2; 32]);
    assert_ne!(a, b);
    assert_ne!(call_stream_id("room", "node-b", &[1; 32]), a);
    assert_eq!(call_id_for_room("room"), call_id_for_room("room"));
    assert!(crate::av_addressing::is_av_stream_group(&call_group_id(
        call_id_for_room("room")
    )));
}

// ─── A3: the room's commits roll every stream ───────────────────────

fn store(tag: &[u8]) -> ScopeStateProvider {
    ScopeStateProvider::new(Arc::new(XChaChaKvStore::open_in_memory(tag).unwrap()))
}

fn ring(group: &CohortGroup) -> KeyRing {
    KeyRing {
        room_group: group.clone(),
        held: StdMutex::new(HashMap::new()),
    }
}

/// **A3.** A room of A and B; A publishes. C joins (an Add commit): A's
/// stream rolls (new DEK, chunk_seq 0), and C cannot open the last pre-Add
/// chunk. Then B is removed: A rolls again, and B cannot open the first
/// post-Remove chunk, while C can.
#[tokio::test]
async fn every_add_and_every_remove_rolls_the_stream() {
    let room = "room-a3";
    let a = CohortGroup::create(store(b"a3-a"), room, "node-a", 16)
        .await
        .unwrap();
    let (mb, kpb) = mint_cohort_key_material("node-b").unwrap();
    let add_b = a.add_member("node-b", kpb).await.unwrap();
    let b = CohortGroup::join(store(b"a3-b"), room, mb, add_b.welcome().unwrap(), 16)
        .await
        .unwrap();

    let stream = call_stream_id(room, "node-a", &[7; 32]);
    let e1 = Epoch(a.epoch().await);
    let (mut publisher, outcome) = KeptAvPublisher::create_room_keyed(
        stream,
        room,
        e1,
        stream_epoch_dek(&a, stream, e1).await.unwrap(),
        AvKeep::Unkept,
        AvKeepTarget {
            cohort_scope: "community".to_owned(),
            group_key_id: room.to_owned(),
        },
        Arc::new(UnwiredRegistrar) as Arc<dyn StreamDekRegistrar>,
        None,
    )
    .await
    .unwrap();
    assert_eq!(outcome, KeepOutcome::NotKept);
    let (_, pre_add_0) = publisher
        .seal_next(b"pre-0", CODEC_OPAQUE, ChunkLayer::BASE)
        .unwrap();
    let (seq, pre_add) = publisher
        .seal_next(b"pre-1", CODEC_OPAQUE, ChunkLayer::BASE)
        .unwrap();
    assert_eq!(seq, ChunkSeq(1));
    let ring_b = ring(&b);
    let dek = ring_b.dek(stream, e1).await.expect("B holds epoch 1");
    assert_eq!(open_inner(&pre_add_0, &dek).unwrap(), b"pre-0");

    // C joins: A commits the Add, B applies it, C joins from the Welcome.
    let (mc, kpc) = mint_cohort_key_material("node-c").unwrap();
    let add_c = a.add_member("node-c", kpc).await.unwrap();
    let _ = b.apply_remote_commit(add_c.commit()).await.unwrap();
    let c = CohortGroup::join(store(b"a3-c"), room, mc, add_c.welcome().unwrap(), 16)
        .await
        .unwrap();
    let e2 = Epoch(a.epoch().await);
    assert!(e2.0 > e1.0, "the Add moved the room's epoch");
    publisher
        .roll_room_epoch(e2, stream_epoch_dek(&a, stream, e2).await.unwrap())
        .await
        .unwrap();
    let (seq, post_add) = publisher
        .seal_next(b"post-add", CODEC_OPAQUE, ChunkLayer::BASE)
        .unwrap();
    assert_eq!(seq, ChunkSeq(0), "chunk_seq restarts at the roll (#846)");
    let ring_c = ring(&c);
    assert!(
        ring_c.dek(stream, e1).await.is_none(),
        "the joiner holds no key for any pre-Add epoch"
    );
    let c_e2 = ring_c.dek(stream, e2).await.expect("C holds the new epoch");
    assert!(
        open_inner(&pre_add, &c_e2).is_err(),
        "the joiner cannot open pre-Add chunks"
    );
    assert_eq!(open_inner(&post_add, &c_e2).unwrap(), b"post-add");
    let b_e2 = ring_b.dek(stream, e2).await.expect("B followed the Add");
    assert_eq!(open_inner(&post_add, &b_e2).unwrap(), b"post-add");

    // B is removed: A commits, C applies; B never sees the new epoch.
    let rm_b = a.remove_member("node-b").await.unwrap();
    let _ = c.apply_remote_commit(rm_b.commit()).await.unwrap();
    let e3 = Epoch(a.epoch().await);
    publisher
        .roll_room_epoch(e3, stream_epoch_dek(&a, stream, e3).await.unwrap())
        .await
        .unwrap();
    let (_, post_rm) = publisher
        .seal_next(b"post-rm", CODEC_OPAQUE, ChunkLayer::BASE)
        .unwrap();
    assert!(
        ring_b.dek(stream, e3).await.is_none(),
        "the departed member cannot derive the post-Remove key"
    );
    assert!(
        open_inner(&post_rm, &b_e2).is_err(),
        "nor open with its last key"
    );
    let c_e3 = ring_c.dek(stream, e3).await.expect("C follows the Remove");
    assert_eq!(open_inner(&post_rm, &c_e3).unwrap(), b"post-rm");
    // The publisher refuses to roll backward or sideways.
    assert!(publisher
        .roll_room_epoch(e3, stream_epoch_dek(&a, stream, e3).await.unwrap())
        .await
        .is_err());
}

/// A room-keyed publisher never commits: the per-stream MLS verbs are the
/// room's, refused by name.
#[tokio::test]
async fn a_room_keyed_publisher_never_commits() {
    let a = CohortGroup::create(store(b"rk-a"), "room-rk", "node-a", 16)
        .await
        .unwrap();
    let e = Epoch(a.epoch().await);
    let stream = call_stream_id("room-rk", "node-a", &[3; 32]);
    let mut p = crate::transport::realtime_av_runtime::AvPublisher::from_room_key(
        stream,
        "room-rk",
        e,
        stream_epoch_dek(&a, stream, e).await.unwrap(),
        Vec::new(),
    )
    .unwrap();
    assert!(p.session().is_none());
    assert!(matches!(
        p.advance_epoch(crate::transport::realtime_av_session::RosterDelta::Leave(
            "x".to_owned()
        )),
        Err(crate::transport::realtime_av_runtime::AvRuntimeError::RoomKeyed { .. })
    ));
}
