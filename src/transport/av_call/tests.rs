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
    assert!(w
        .tick(deadline.checked_sub(Duration::from_millis(1)).unwrap())
        .is_empty());
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

// ─── 44.1: a room whose leaves are persons ────────────────────────────

/// An owner-binding door over a fixed `(node, owner)` table (persist's
/// `owner_of` / `nodes_owned_by`, which agree by construction).
struct Bound(Vec<(&'static str, &'static str)>);

#[async_trait::async_trait]
impl CallOwners for Bound {
    async fn owner_of(&self, node: &str) -> Option<String> {
        self.0
            .iter()
            .find(|(n, _)| *n == node)
            .map(|(_, o)| (*o).to_owned())
    }
    async fn nodes_owned_by(&self, person: &str) -> Result<Vec<String>, String> {
        Ok(self
            .0
            .iter()
            .filter(|(_, o)| *o == person)
            .map(|(n, _)| (*n).to_owned())
            .collect())
    }
}

/// A roster holding exactly these keys active.
struct Active(Vec<&'static str>);

#[async_trait::async_trait]
impl RoomRoster for Active {
    async fn is_active_member(&self, _room: &str, key_id: &str) -> Result<bool, String> {
        Ok(self.0.contains(&key_id))
    }
}

/// A group whose leaves are `leaves`, founded by the first.
async fn group_of(tag: &[u8], room: &str, leaves: &[&str]) -> CohortGroup {
    let g = CohortGroup::create(store(tag), room, leaves[0], 16)
        .await
        .unwrap();
    for leaf in &leaves[1..] {
        let (_material, kp) = mint_cohort_key_material(leaf).unwrap();
        // Only the leaf set is read: the commit has no one to fan out to.
        let _ = g.add_member(leaf, kp).await.unwrap();
    }
    g
}

/// The call's members: each person leaf becomes the nodes it owns, a leaf
/// that owns none stands as itself, in leaf order, once each.
#[tokio::test]
async fn call_members_are_the_leaves_nodes() {
    let owners = Bound(vec![
        ("node-a1", "person-a"),
        ("node-a2", "person-a"),
        ("node-b", "person-b"),
    ]);
    let leaves: Vec<String> = ["person-a", "node-x", "person-b", "person-c"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    assert_eq!(
        call_members(&leaves, &owners).await.unwrap(),
        vec!["node-a1", "node-a2", "node-x", "node-b", "person-c"]
    );
}

/// The join's admission over both leaf models.
#[tokio::test]
async fn admit_takes_a_node_for_its_verified_owner_only() {
    let room = "room-pl";
    let owners = Bound(vec![
        ("node-a", "person-a"),
        ("node-b", "person-b"),
        ("node-z", "person-z"),
    ]);
    let persons = group_of(b"pl-p", room, &["person-a", "person-b"]).await;
    let roster = Active(vec!["person-a", "person-b"]);
    // A node attending as itself is in the room as its owner: the roster is
    // asked about the person.
    let (leaves, members) = admit(room, "node-a", "node-a", &persons, &roster, &owners)
        .await
        .expect("node-a for person-a");
    assert_eq!(leaves, vec!["person-a", "person-b"]);
    assert_eq!(members, vec!["node-a", "node-b"]);
    // Attending as its owner.
    admit(room, "node-b", "person-b", &persons, &roster, &owners)
        .await
        .expect("node-b as person-b");
    // Its owner is no leaf.
    assert!(matches!(
        admit(room, "node-z", "node-z", &persons, &roster, &owners).await,
        Err(CallError::NotARoomMember { key_id, .. }) if key_id == "node-z"
    ));
    // It acts for a leaf it is not bound to.
    assert!(matches!(
        admit(room, "node-z", "person-a", &persons, &roster, &owners).await,
        Err(CallError::NotARoomMember { key_id, .. }) if key_id == "node-z" || key_id == "person-a"
    ));
    assert!(matches!(
        admit(room, "node-a", "person-b", &persons, &roster, &owners).await,
        Err(CallError::NotARoomMember { key_id, .. }) if key_id == "person-b"
    ));
    // The owner is a leaf but not on the active roster.
    assert!(matches!(
        admit(room, "node-a", "node-a", &persons, &Active(vec!["person-b"]), &owners).await,
        Err(CallError::ConsentMissing { key_id, .. }) if key_id == "person-a"
    ));
    // Node leaves: unchanged.
    let nodes = group_of(b"pl-n", room, &["node-a", "node-b"]).await;
    let (_, members) = admit(
        room,
        "node-a",
        "node-a",
        &nodes,
        &Active(vec!["node-a"]),
        &owners,
    )
    .await
    .expect("a node leaf");
    assert_eq!(members, vec!["node-a", "node-b"]);
    admit(room, "node-b", "person-b", &nodes, &roster, &owners)
        .await
        .expect("a node leaf attending as its owner");
}

/// **44.1** — a room and its call, installed for the same members at the
/// same epoch in one table, never collide: the call's addresses are derived
/// from the call's own secret, not the room's (the field refusal was
/// `address collision on member … (epoch 1) — reused exporter_secret?`).
#[tokio::test]
async fn a_call_s_addresses_are_never_its_room_s() {
    use crate::scope_addressing::{ScopeAddressTable, ScopePrivacyDeriver};
    let room = "room-addr";
    let g = group_of(b"addr", room, &["node-a", "node-b"]).await;
    let table = ScopeAddressTable::new(Arc::new(ScopePrivacyDeriver));
    // The room, as `ensure_room_addresses` installs it.
    let room_snap = crate::cohort_addressing::snapshot(&g).await.unwrap();
    let room_scope = crate::cohort_addressing::scope_for(room);
    table
        .install_group(
            &room_scope,
            &room_snap.group_id,
            room_snap.epoch,
            &room_snap.destination_secret,
            &room_snap.members,
        )
        .expect("the room's addresses");
    // Its call, for the same members at the same epoch.
    let call_group = call_group_id(call_id_for_room(room));
    let call_snap = room_snapshot(&g, &call_group, &room_snap.members)
        .await
        .unwrap();
    assert_eq!(call_snap.epoch, room_snap.epoch);
    assert_ne!(call_snap.destination_secret, room_snap.destination_secret);
    let call_scope = CohortScope::Cohort {
        cohort_id: room.to_owned(),
    };
    table
        .install_group(
            &call_scope,
            &call_group,
            call_snap.epoch,
            &call_snap.destination_secret,
            &call_snap.members,
        )
        .expect("the call installs beside its room");
    for m in ["node-a", "node-b"] {
        let at_room = table
            .send_address(&room_scope, &room_snap.group_id, m)
            .unwrap();
        let at_call = table.send_address(&call_scope, &call_group, m).unwrap();
        assert_ne!(at_room, at_call, "{m}'s call address is its room address");
    }
    // Deterministic, and bound to the call's group id.
    let again = room_snapshot(&g, &call_group, &room_snap.members)
        .await
        .unwrap();
    assert_eq!(again.destination_secret, call_snap.destination_secret);
    assert_ne!(
        crate::transport::av_call_key::call_destination_secret(
            &room_snap.destination_secret,
            &call_group_id(call_id_for_room("room-other")),
        )
        .unwrap(),
        call_snap.destination_secret
    );
}

/// CC 5.3.3.2.1 (rc17) — for `0x04` (temporal-layered) `t = 0` is the base:
/// what a standby child, a shed leg and a tier-2 own call carry, as `(0, 0,
/// 0)` is for every layered class and every chunk is for codec-opaque.
#[test]
fn temporal_layer_zero_is_the_base_for_standby_and_shed() {
    use crate::transport::realtime_av::{ChunkLayer, CODEC_TEMPORAL_LAYERED};
    let t = |temporal| ChunkLayer {
        spatial: 0,
        temporal,
        quality: 0,
    };
    assert!(is_base_or_audio(CODEC_TEMPORAL_LAYERED, t(0)));
    for e in 1..=3 {
        assert!(!is_base_or_audio(CODEC_TEMPORAL_LAYERED, t(e)), "t={e}");
    }
    assert!(is_base_or_audio(CODEC_OPAQUE, ChunkLayer::BASE));
}

/// A binding as `Attendance` reads it: only its verified fields matter
/// (`publisher`, `stream`, `replaces`, `end`).
fn attendance_binding(
    publisher: &str,
    stream: u8,
    replaces: Option<u8>,
    end: Option<crate::transport::av_chunk_auth::SignedEnd>,
) -> StreamKeyBinding {
    StreamKeyBinding {
        room: "room".to_owned(),
        publisher: publisher.to_owned(),
        join_nonce: [stream; 32],
        stream: StreamId([stream; 32]),
        epoch: Epoch(1),
        chunk_key: [0; 32],
        sig_ed25519: Vec::new(),
        sig_ml_dsa_65: Vec::new(),
        codecs: None,
        replaces: replaces.map(|r| StreamId([r; 32])),
        end,
        final_seq: end.map(|_| 0),
        kind: 0,
        framing: 0,
    }
}

/// The `StreamAdded` a first binding of `publisher`'s stream `[s; 32]` is.
fn added(publisher: &str, s: u8) -> Vec<CallEvent> {
    vec![CallEvent::StreamAdded {
        publisher: publisher.to_owned(),
        stream: StreamId([s; 32]),
        kind: 0,
    }]
}

/// 45.1 — a signed end's verdict waits [`END_VERDICT_AFTER`] (the longest
/// reorder window) after it lands: not due a moment before, due at it, once.
#[test]
fn a_signed_end_waits_the_reorder_window_for_its_verdict() {
    use crate::transport::av_chunk_auth::SignedEnd;
    assert_eq!(END_VERDICT_AFTER, REORDER_WINDOW_MAX);
    let mut a = Attendance::default();
    let t = Instant::now();
    let end = attendance_binding("bob", 1, None, Some(SignedEnd::Left));
    a.defer_end(&end, t);
    assert!(
        a.due_ends(t + END_VERDICT_AFTER - Duration::from_millis(1))
            .is_empty(),
        "a tail chunk may still be in the window"
    );
    let due = a.due_ends(t + END_VERDICT_AFTER);
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].stream, end.stream);
    assert!(a.due_ends(t + END_VERDICT_AFTER * 4).is_empty(), "once");
}

/// 45.1 — a signed end is `AttendeeLeft` with its cause (and whether its tail
/// arrived), once per (attendee, stream); `Removed` and `Lost` fire once too,
/// and never after a signed end.
#[test]
fn a_signed_end_is_attendee_left_with_its_cause_once() {
    use crate::transport::av_chunk_auth::SignedEnd;
    let mut a = Attendance::default();
    let s1 = StreamId([1; 32]);
    assert_eq!(
        a.on_bound(
            "me",
            &attendance_binding("bob", 1, None, None),
            None,
            true,
            false
        ),
        added("bob", 1),
        "a first binding is StreamAdded, never presence"
    );
    assert_eq!(a.streams.get("bob"), Some(&vec![s1]));
    let ev = a.on_bound(
        "me",
        &attendance_binding("bob", 1, None, Some(SignedEnd::Backgrounded)),
        None,
        true,
        true,
    );
    assert_eq!(
        ev,
        [CallEvent::AttendeeLeft {
            key_id: "bob".into(),
            stream: s1,
            cause: LeaveCause::Backgrounded,
            truncated: true,
        }]
    );
    assert!(a.streams.get("bob").is_none());
    assert!(
        a.left("bob", s1, LeaveCause::Lost, true, false).is_none(),
        "once"
    );
    // Removed, once.
    let s2 = StreamId([2; 32]);
    let _ = a.on_bound(
        "me",
        &attendance_binding("carol", 2, None, None),
        None,
        true,
        false,
    );
    assert_eq!(
        a.left("carol", s2, LeaveCause::Removed, true, false),
        Some(CallEvent::AttendeeLeft {
            key_id: "carol".into(),
            stream: s2,
            cause: LeaveCause::Removed,
            truncated: false,
        })
    );
    assert!(a
        .left("carol", s2, LeaveCause::Removed, true, false)
        .is_none());
    // Own bindings say nothing.
    assert!(a
        .on_bound(
            "me",
            &attendance_binding("me", 3, None, Some(SignedEnd::Left)),
            None,
            true,
            false
        )
        .is_empty());
}

/// CC: `end = 0` is not proof of presence. A stream this node never heard a
/// chunk of (a late joiner handed an old binding of a stream since gone) is
/// no attendee: neither its end nor its loss nor its removal is an
/// `AttendeeLeft`, and it stays ended (it never fires later).
#[test]
fn a_binding_alone_is_no_presence() {
    use crate::transport::av_chunk_auth::SignedEnd;
    let mut a = Attendance::default();
    let s = StreamId([4; 32]);
    let _ = a.on_bound(
        "me",
        &attendance_binding("dave", 4, None, None),
        None,
        false,
        false,
    );
    assert!(a.left("dave", s, LeaveCause::Lost, false, false).is_none());
    assert!(
        a.left("dave", s, LeaveCause::Removed, true, false)
            .is_none(),
        "ended"
    );
    let ev = a.on_bound(
        "me",
        &attendance_binding("erin", 5, None, Some(SignedEnd::Left)),
        None,
        false,
        false,
    );
    assert!(ev.is_empty(), "a signed end of a stream never heard");
}

/// 45.1 — a share is a second stream with no `replaces`: binding it ends
/// nothing and replaces nothing. Its signed end is `StreamEnded` (the camera
/// stays live, no leave); the camera's end, now the last stream, is
/// `AttendeeLeft`. Lost or removed with both live: one `AttendeeLeft`,
/// naming the oldest (the camera).
#[test]
fn a_share_is_a_second_stream_and_its_end_is_no_leave() {
    use crate::transport::av_chunk_auth::SignedEnd;
    let mut a = Attendance::default();
    let (cam, share) = (StreamId([1; 32]), StreamId([7; 32]));
    for s in [1, 7] {
        let ev = a.on_bound(
            "me",
            &attendance_binding("bob", s, None, None),
            None,
            true,
            false,
        );
        assert_eq!(
            ev,
            added("bob", s),
            "a share is no replacement and no leave"
        );
    }
    assert_eq!(a.streams.get("bob"), Some(&vec![cam, share]));
    let ev = a.on_bound(
        "me",
        &attendance_binding("bob", 7, None, Some(SignedEnd::Ended)),
        None,
        true,
        false,
    );
    assert_eq!(
        ev,
        [CallEvent::StreamEnded {
            publisher: "bob".into(),
            stream: share,
            cause: LeaveCause::Ended,
            truncated: false,
        }]
    );
    assert_eq!(
        a.streams.get("bob"),
        Some(&vec![cam]),
        "the camera is untouched"
    );
    let ev = a.on_bound(
        "me",
        &attendance_binding("bob", 1, None, Some(SignedEnd::Backgrounded)),
        None,
        true,
        false,
    );
    assert_eq!(
        ev,
        [CallEvent::AttendeeLeft {
            key_id: "bob".into(),
            stream: cam,
            cause: LeaveCause::Backgrounded,
            truncated: false,
        }]
    );
    // Carol: camera heard, share never heard; lost with both live.
    let (c_cam, c_share) = (StreamId([2; 32]), StreamId([8; 32]));
    for s in [2, 8] {
        let _ = a.on_bound(
            "me",
            &attendance_binding("carol", s, None, None),
            None,
            true,
            false,
        );
    }
    let ev = a.leave_all("carol", LeaveCause::Lost, |s| s == c_cam);
    assert_eq!(
        ev,
        Some(CallEvent::AttendeeLeft {
            key_id: "carol".into(),
            stream: c_cam,
            cause: LeaveCause::Lost,
            truncated: false,
        })
    );
    assert!(a
        .leave_all("carol", LeaveCause::Removed, |_| true)
        .is_none());
    assert!(
        a.left("carol", c_share, LeaveCause::Left, true, false)
            .is_none(),
        "once"
    );
    // A share never heard ends with no event; the attendee stays.
    let _ = a.on_bound(
        "me",
        &attendance_binding("dan", 3, None, None),
        None,
        true,
        false,
    );
    let _ = a.on_bound(
        "me",
        &attendance_binding("dan", 9, None, None),
        None,
        false,
        false,
    );
    assert!(a
        .left("dan", StreamId([9; 32]), LeaveCause::Left, false, false)
        .is_none());
    assert_eq!(a.streams.get("dan"), Some(&vec![StreamId([3; 32])]));
    // CC (rc18): `end = 3` on the LAST stream is still no leave (presence is
    // reachability): StreamEnded, and erin still attends until lost.
    let _ = a.on_bound(
        "me",
        &attendance_binding("erin", 4, None, None),
        None,
        true,
        false,
    );
    let ev = a.on_bound(
        "me",
        &attendance_binding("erin", 4, None, Some(SignedEnd::Ended)),
        None,
        true,
        false,
    );
    assert_eq!(
        ev,
        [CallEvent::StreamEnded {
            publisher: "erin".into(),
            stream: StreamId([4; 32]),
            cause: LeaveCause::Ended,
            truncated: false,
        }]
    );
    assert_eq!(a.streams.get("erin"), Some(&Vec::new()), "still attending");
    assert_eq!(
        a.leave_all("erin", LeaveCause::Lost, |_| false),
        Some(CallEvent::AttendeeLeft {
            key_id: "erin".into(),
            stream: StreamId([4; 32]),
            cause: LeaveCause::Lost,
            truncated: false,
        }),
        "lost later: one AttendeeLeft naming its last stream"
    );
    // A leave value on a non-final stream is that stream's end only.
    for s in [10, 11] {
        let _ = a.on_bound(
            "me",
            &attendance_binding("finn", s, None, None),
            None,
            true,
            false,
        );
    }
    let ev = a.on_bound(
        "me",
        &attendance_binding("finn", 11, None, Some(SignedEnd::Left)),
        None,
        true,
        false,
    );
    assert!(matches!(
        ev.as_slice(),
        [CallEvent::StreamEnded {
            cause: LeaveCause::Left,
            ..
        }]
    ));
    assert!(matches!(
        a.on_bound(
            "me",
            &attendance_binding("finn", 10, None, Some(SignedEnd::Left)),
            None,
            true,
            false
        )
        .as_slice(),
        [CallEvent::AttendeeLeft {
            cause: LeaveCause::Left,
            ..
        }]
    ));
}

/// 45.1 — a signed `replaces` of the same publisher's stream is
/// `StreamReplaced` and no leave; the old stream can then never leave. A
/// `replaces` naming a stream another publisher's binding named is no
/// replacement; a second stream with no `replaces` ends nothing.
#[test]
fn a_replacement_is_not_a_leave() {
    let mut a = Attendance::default();
    let _ = a.on_bound(
        "me",
        &attendance_binding("bob", 1, None, None),
        None,
        true,
        false,
    );
    let ev = a.on_bound(
        "me",
        &attendance_binding("bob", 2, Some(1), None),
        Some("bob"),
        true,
        false,
    );
    assert_eq!(
        ev,
        [CallEvent::StreamReplaced {
            publisher: "bob".into(),
            old: StreamId([1; 32]),
            new: StreamId([2; 32]),
        }]
    );
    assert_eq!(a.streams.get("bob"), Some(&vec![StreamId([2; 32])]));
    assert!(
        a.left("bob", StreamId([1; 32]), LeaveCause::Lost, true, false)
            .is_none(),
        "the replaced stream never leaves"
    );
    let _ = a.on_bound(
        "me",
        &attendance_binding("carol", 5, None, None),
        None,
        true,
        false,
    );
    let ev = a.on_bound(
        "me",
        &attendance_binding("mallory", 6, Some(5), None),
        Some("carol"),
        true,
        false,
    );
    assert_eq!(
        ev,
        added("mallory", 6),
        "no replacement of another's stream"
    );
    assert!(!a.ended.contains(&("carol".to_owned(), StreamId([5; 32]))));
    let ev = a.on_bound(
        "me",
        &attendance_binding("carol", 7, None, None),
        None,
        true,
        false,
    );
    assert_eq!(ev, added("carol", 7));
    assert!(!a.ended.contains(&("carol".to_owned(), StreamId([5; 32]))));
}
