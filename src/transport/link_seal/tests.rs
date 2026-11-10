use super::*;

use crate::transport::av_transit_handshake::{HANDSHAKE_FRAME_VERSION, HANDSHAKE_MAGIC};

const LINK: [u8; 16] = [0x5e; 16];
const DIALLER: &str = "dialler-key";
const DIALLED: &str = "dialled-key";
const LIMIT: usize = 400;

fn seals(seed: u8, id: &str) -> LinkSeals {
    LinkSeals::new(
        TransitKexSecret::from_root_seed(&[seed; 64]).expect("transit secret"),
        id,
    )
}

/// One frame, and when it is a handshake's last part, its keying run to the
/// end: what the event loop does around [`LinkSeals::inbound`].
fn feed(s: &LinkSeals, lane: Lane, bytes: &[u8], we_dialled: bool) -> Inbound {
    match s.inbound(LINK, lane, bytes, we_dialled, None) {
        Inbound::Handshake(job) => {
            let outcome = s.decapsulate(&job).expect("the link waits on this job");
            s.finish_keying(job.link(), job.ticket(), outcome)
        }
        other => other,
    }
}

/// A dialler and a dialled end, keyed on `LINK` through the table's own
/// handshake path.
fn keyed_pair() -> (LinkSeals, LinkSeals) {
    let a = seals(0x11, DIALLER);
    let b = seals(0x22, DIALLED);
    a.begin_initiator(LINK);
    assert!(b.begin_responder(LINK));
    let (frames, transit) = a
        .initiate(LINK, DIALLER, DIALLED, b.secret().pair(), LIMIT)
        .expect("initiate");
    let mut keyed = None;
    for f in &frames {
        assert!(f.len() <= LIMIT);
        match feed(&b, Lane::Channel, f, false) {
            Inbound::Pending => {}
            Inbound::Keyed { claimed } => keyed = Some(claimed),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(keyed.as_deref(), Some(DIALLER));
    a.install_initiator(LINK, transit);
    (a, b)
}

/// leviculum#102 — datagrams are overtaken and lost on the wire: each opens
/// in any order, once, and a Channel frame's counter is never theirs.
#[test]
fn datagrams_open_out_of_order_once_on_their_own_lane() {
    let (a, b) = keyed_pair();
    let frames: Vec<Vec<u8>> = (0u8..6)
        .map(|i| a.seal(LINK, Lane::Datagram, &[i; 40]).expect("seal"))
        .collect();
    // The Channel's counter moves on its own: its window is not the datagrams'.
    let ch = a.seal(LINK, Lane::Channel, b"chan").expect("seal");
    for i in [5usize, 0, 3, 1] {
        match b.open(LINK, Lane::Datagram, &frames[i]) {
            Inbound::Open(p) => assert_eq!(p, vec![u8::try_from(i).unwrap(); 40]),
            other => panic!("datagram {i} out of order: {other:?}"),
        }
    }
    assert!(
        matches!(b.open(LINK, Lane::Datagram, &frames[3]), Inbound::Drop(_)),
        "a replayed datagram is dropped, the link kept"
    );
    assert!(b.is_sealed(LINK), "a replay does not refuse the link");
    match feed(&b, Lane::Channel, &ch, false) {
        Inbound::Open(p) => assert_eq!(p, b"chan"),
        other => panic!("{other:?}"),
    }
    // A datagram frame read as another lane does not open: the lane is bound.
    assert!(matches!(
        b.open(LINK, Lane::Resource, &frames[2]),
        Inbound::Refuse(_)
    ));
}

/// leviculum#102 — the lane is bound into the AEAD (nonce byte 0 and AAD byte
/// 1): a Datagram-lane frame offered to the Channel's open fails to
/// authenticate, and a Channel frame offered to the Datagram open does too,
/// even at a counter the other lane's window has never seen. Each refusal
/// closes the link, as any frame that fails to open does.
#[test]
fn a_frame_never_opens_on_the_other_of_channel_and_datagram() {
    for (sent_on, offered_to) in [
        (Lane::Datagram, Lane::Channel),
        (Lane::Channel, Lane::Datagram),
    ] {
        let (a, b) = keyed_pair();
        // Counter 0 on its own lane: the other lane's window is still empty,
        // so only the lane binding can refuse it.
        let frame = a.seal(LINK, sent_on, b"media or row").expect("seal");
        let out = if offered_to == Lane::Channel {
            feed(&b, Lane::Channel, &frame, false)
        } else {
            b.open(LINK, Lane::Datagram, &frame)
        };
        assert!(
            matches!(out, Inbound::Refuse(SealRefusal::OpenFailed)),
            "a {sent_on:?} frame offered to {offered_to:?} must fail to open: {out:?}"
        );
        assert!(!b.is_sealed(LINK), "the refusal closes the link");
    }
}

#[test]
fn frames_open_in_both_directions_on_every_lane_e1() {
    let (a, b) = keyed_pair();
    for lane in [
        Lane::Channel,
        Lane::Resource,
        Lane::Request,
        Lane::Response,
        Lane::Datagram,
    ] {
        let up = a.seal(LINK, lane, b"row bytes up").expect("seal up");
        let bin = if lane.is_msgpack() { 2 } else { 0 };
        assert_eq!(up.len(), b"row bytes up".len() + SEAL_OVERHEAD + bin);
        assert!(!contains(&up, b"row bytes up"), "no plaintext on the wire");
        match feed(&b, lane, &up, false) {
            Inbound::Open(p) => assert_eq!(p, b"row bytes up"),
            other => panic!("{other:?}"),
        }
        let down = b.seal(LINK, lane, b"row bytes down").expect("seal down");
        match a.open(LINK, lane, &down) {
            Inbound::Open(p) => assert_eq!(p, b"row bytes down"),
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(b.claimed_initiator(LINK).as_deref(), Some(DIALLER));
    assert_eq!(
        a.claimed_initiator(LINK),
        None,
        "the dialler checks no claim"
    );
}

#[test]
fn nothing_is_sealed_before_keys_e1() {
    let a = seals(0x11, DIALLER);
    a.begin_initiator(LINK);
    assert!(matches!(
        a.seal(LINK, Lane::Channel, b"x"),
        Err(SealRefusal::Unsealed)
    ));
    let b = seals(0x22, DIALLED);
    b.begin_responder(LINK);
    assert!(matches!(
        b.seal(LINK, Lane::Channel, b"x"),
        Err(SealRefusal::Unsealed)
    ));
    assert!(matches!(
        seals(0x33, "x").seal(LINK, Lane::Channel, b"x"),
        Err(SealRefusal::Unsealed)
    ));
}

#[test]
fn a_non_ctkx_first_frame_is_refused_and_the_link_stays_refused_e1() {
    let b = seals(0x22, DIALLED);
    b.begin_responder(LINK);
    match feed(&b, Lane::Channel, b"{\"plaintext\":true}", false) {
        Inbound::Refuse(r) => {
            assert_eq!(
                r.label(),
                crate::observability::LINK_SEAL_REFUSED_NOT_A_HANDSHAKE
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        feed(&b, Lane::Channel, b"more", false),
        Inbound::Closed
    ));
    assert!(
        !b.begin_responder(LINK),
        "a refused link is not re-admitted"
    );
}

#[test]
fn a_resource_before_the_handshake_is_held_and_opens_once_keyed_e1() {
    let a = seals(0x11, DIALLER);
    let b = seals(0x22, DIALLED);
    a.begin_initiator(LINK);
    assert!(b.begin_responder(LINK));
    let (frames, transit) = a
        .initiate(LINK, DIALLER, DIALLED, b.secret().pair(), LIMIT)
        .expect("initiate");
    a.install_initiator(LINK, transit);
    let (last, first) = frames.split_last().expect("a handshake");
    for f in first {
        assert!(matches!(
            feed(&b, Lane::Channel, f, false),
            Inbound::Pending
        ));
    }
    // The dialler's Resource overtakes its last handshake part (another
    // event plane): held sealed, not dropped.
    let row = a.seal(LINK, Lane::Resource, b"resource row").expect("seal");
    assert!(matches!(
        b.open(LINK, Lane::Resource, &row),
        Inbound::HeldBeforeKeys
    ));
    match feed(&b, Lane::Channel, last, false) {
        Inbound::Keyed { claimed } => assert_eq!(claimed, DIALLER),
        other => panic!("{other:?}"),
    }
    let held = b.take_before_keys(LINK);
    assert_eq!(held, vec![row], "the held Resource, once, in order");
    match b.open(LINK, Lane::Resource, &held[0]) {
        Inbound::Open(p) => assert_eq!(p, b"resource row"),
        other => panic!("{other:?}"),
    }
    assert!(b.take_before_keys(LINK).is_empty(), "nothing held after");

    // Past the hold's bound: dropped by name.
    let c = seals(0x33, DIALLED);
    assert!(c.begin_responder(LINK));
    let big = vec![0u8; HELD_BYTES_MAX + 1];
    match c.open(LINK, Lane::Resource, &big) {
        Inbound::Drop(label) => {
            assert_eq!(label, crate::observability::LINK_SEAL_DROPPED_BEFORE_KEYS);
        }
        other => panic!("{other:?}"),
    }
    // Other lanes before keys are still dropped (a request needs its
    // request context to be answered).
    match c.open(LINK, Lane::Request, b"anything") {
        Inbound::Drop(label) => {
            assert_eq!(label, crate::observability::LINK_SEAL_DROPPED_BEFORE_KEYS);
        }
        other => panic!("{other:?}"),
    }
    // A budget that runs out discards the hold.
    assert!(matches!(
        c.open(LINK, Lane::Resource, b"held"),
        Inbound::HeldBeforeKeys
    ));
    assert!(c.expire(LINK));
    assert!(
        c.take_before_keys(LINK).is_empty(),
        "the expired link holds nothing"
    );

    // On a link this node dialled and has not keyed, the responder spoke
    // first: refused.
    let d = seals(0x11, DIALLER);
    d.begin_initiator(LINK);
    assert!(matches!(
        d.open(LINK, Lane::Resource, b"anything"),
        Inbound::Refuse(SealRefusal::Unsealed)
    ));
}

#[test]
fn an_oversize_declaration_is_refused_e1() {
    let b = seals(0x22, DIALLED);
    let mut start = HANDSHAKE_MAGIC.to_vec();
    start.push(HANDSHAKE_FRAME_VERSION);
    start.push(0x00);
    start.extend_from_slice(&u32::MAX.to_be_bytes());
    start.extend_from_slice(&[1u8; 64]);
    match feed(&b, Lane::Channel, &start, false) {
        Inbound::Refuse(r) => {
            assert_eq!(r.label(), crate::observability::LINK_SEAL_REFUSED_TOO_LARGE);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_frame_before_the_dialler_keyed_is_refused_e1() {
    let a = seals(0x11, DIALLER);
    a.begin_initiator(LINK);
    match feed(&a, Lane::Channel, b"early", true) {
        Inbound::Refuse(r) => assert_eq!(
            r.label(),
            crate::observability::LINK_SEAL_REFUSED_FRAME_BEFORE_KEYS
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_budget_expires_only_an_awaiting_link_e1() {
    let b = seals(0x22, DIALLED);
    b.begin_responder(LINK);
    assert!(b.expire(LINK));
    assert!(!b.expire(LINK), "counted once");
    let (_a, b) = keyed_pair();
    assert!(!b.expire(LINK), "a keyed link is not expired");
}

#[test]
fn a_tampered_frame_fails_to_open_and_refuses_the_link_e1() {
    let (a, b) = keyed_pair();
    let mut up = a.seal(LINK, Lane::Channel, b"payload").expect("seal");
    let last = up.len() - 1;
    up[last] ^= 1;
    match feed(&b, Lane::Channel, &up, false) {
        Inbound::Refuse(r) => {
            assert_eq!(
                r.label(),
                crate::observability::LINK_SEAL_REFUSED_OPEN_FAILED
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(!b.is_sealed(LINK));
}

#[test]
fn the_wrong_role_key_does_not_open_e1() {
    let (a, b) = keyed_pair();
    let up = a.seal(LINK, Lane::Channel, b"payload").expect("seal");
    // The dialler's own open key is the other direction's: it cannot open
    // what it sealed.
    assert!(matches!(
        a.open(LINK, Lane::Channel, &up),
        Inbound::Refuse(SealRefusal::OpenFailed)
    ));
    // A link with no keys of its own opens nothing either.
    let other = [0x77; 16];
    b.begin_initiator(other);
    assert!(matches!(
        b.open(other, Lane::Channel, &up),
        Inbound::Refuse(SealRefusal::Unsealed)
    ));
}

#[test]
fn a_frame_on_the_wrong_lane_does_not_open_e1() {
    let (a, b) = keyed_pair();
    let up = a.seal(LINK, Lane::Resource, b"payload").expect("seal");
    assert!(matches!(
        feed(&b, Lane::Channel, &up, false),
        Inbound::Refuse(SealRefusal::OpenFailed)
    ));
}

#[test]
fn a_replayed_frame_is_dropped_and_the_link_kept_e1() {
    let (a, b) = keyed_pair();
    let f0 = a.seal(LINK, Lane::Channel, b"zero").expect("seal");
    let f1 = a.seal(LINK, Lane::Channel, b"one").expect("seal");
    assert!(matches!(
        feed(&b, Lane::Channel, &f1, false),
        Inbound::Open(_)
    ));
    // Reordered within the window: accepted once.
    assert!(matches!(
        feed(&b, Lane::Channel, &f0, false),
        Inbound::Open(_)
    ));
    match feed(&b, Lane::Channel, &f0, false) {
        Inbound::Drop(label) => assert_eq!(label, crate::observability::LINK_SEAL_DROPPED_REPLAY),
        other => panic!("{other:?}"),
    }
    assert!(b.is_sealed(LINK));
}

#[test]
fn the_replay_window_slides_e1() {
    let mut w = ReplayWindow::default();
    assert!(w.accept(5));
    assert!(!w.accept(5));
    assert!(w.accept(5 + REPLAY_WINDOW));
    assert!(!w.accept(5), "fell out of the window");
    assert!(w.accept(6));
    assert!(!w.accept(6));
}

#[test]
fn only_an_opaque_request_is_first_contact_e1() {
    let req = br#"{"message_type":"OpaqueRequest","signing_key_id":"dev","body":{"kind":2}}"#;
    assert_eq!(
        first_contact_sender(req),
        Some(FirstContactSender {
            signer: "dev".to_owned(),
            record_key_id: None,
        })
    );
    assert!(first_contact_sender(
        br#"{"message_type":"OpaqueResponse","signing_key_id":"dev","body":{}}"#
    )
    .is_none());
    assert!(first_contact_sender(b"CRPL\x01binary").is_none());
}

/// A first-contact request whose `key:record:v1` row introduces `record`,
/// signed (as the envelope says) by `signer`.
fn request_introducing(signer: &str, record: &ciris_persist::federation::KeyRecord) -> Vec<u8> {
    let row =
        ciris_persist::federation::key_plane::plan_key_record_row(record, &None).expect("row");
    let body = crate::messages::OpaqueRequestWire {
        kind: 2,
        payload: Vec::new(),
        key_record: None,
        key_record_row: Some(row),
        challenge: None,
    };
    serde_json::to_vec(&serde_json::json!({
        "message_type": "OpaqueRequest",
        "signing_key_id": signer,
        "body": body,
    }))
    .expect("json")
}

#[tokio::test]
async fn an_unattributed_link_admits_only_its_initiators_own_request_e1() {
    let record = crate::replication::bridge::tests::minted_key_record(
        "seal-fc-dev",
        ciris_persist::federation::types::identity_type::NODE,
        0x61,
    )
    .await;
    let dev = record.key_id.clone();
    // Signed by, and introducing (through its key:record:v1 row), the
    // handshake's initiator: admitted.
    let own = request_introducing(&dev, &record);
    assert_eq!(
        first_contact_sender(&own).and_then(|s| s.record_key_id),
        Some(dev.clone()),
        "the introduced key is read through carried_key_id"
    );
    assert!(admit_unattributed_frame(&dev, &own).is_ok());
    // Signed by another key.
    let other_signer = br#"{"message_type":"OpaqueRequest","signing_key_id":"mallory","body":{}}"#;
    let refused = admit_unattributed_frame(&dev, other_signer).unwrap_err();
    assert_eq!(
        refused.label(),
        crate::observability::LINK_SEAL_REFUSED_FIRST_CONTACT_SIGNER
    );
    // Signed by the initiator but introducing another key.
    let mallory = crate::replication::bridge::tests::minted_key_record(
        "seal-fc-mallory",
        ciris_persist::federation::types::identity_type::NODE,
        0x62,
    )
    .await;
    let other_record = request_introducing(&dev, &mallory);
    assert!(matches!(
        admit_unattributed_frame(&dev, &other_record),
        Err(SealRefusal::FirstContactSignerMismatch { .. })
    ));
    assert!(matches!(
        admit_unattributed_frame(
            &dev,
            br#"{"message_type":"OpaqueEvent","signing_key_id":"dev","body":{}}"#
        ),
        Err(SealRefusal::FirstContactOnly)
    ));
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// leviculum asserts a request's or response's data is ONE msgpack value:
/// those lanes ride as a msgpack `bin` holding the sealed frame, and open
/// back to the caller's own value.
#[test]
fn request_and_response_lanes_ride_as_one_msgpack_bin_e1() {
    let (a, b) = keyed_pair();
    for (lane, len) in [
        (Lane::Request, 1usize),
        (Lane::Response, 300),
        (Lane::Request, 70_000),
    ] {
        let plain = vec![0xc0u8; len];
        let wire = a.seal(LINK, lane, &plain).expect("seal");
        assert!(matches!(wire[0], 0xc4..=0xc6), "a msgpack bin");
        assert_eq!(
            msgpack_unbin(&wire).map(<[u8]>::len),
            Some(len + SEAL_OVERHEAD)
        );
        match b.open(LINK, lane, &wire) {
            Inbound::Open(p) => assert_eq!(p, plain),
            other => panic!("{other:?}"),
        }
    }
    assert!(matches!(
        b.open(LINK, Lane::Request, &[0xc0]),
        Inbound::Refuse(SealRefusal::OpenFailed)
    ));
}

/// The burst that failed `link_pool_819` on macOS: a 256 KiB Resource on a
/// fresh lane overtook the lane's last handshake part. Sealed, it is 256 KiB
/// plus the seal, and the old 256 KiB bound dropped it after its sender had
/// counted it delivered. One frame of the largest size edge carries fits.
#[test]
fn a_whole_envelope_that_overtakes_the_handshake_is_held_and_opens() {
    let a = seals(0x11, DIALLER);
    let b = seals(0x22, DIALLED);
    a.begin_initiator(LINK);
    assert!(b.begin_responder(LINK));
    let (frames, transit) = a
        .initiate(LINK, DIALLER, DIALLED, b.secret().pair(), LIMIT)
        .expect("initiate");
    a.install_initiator(LINK, transit);
    let (last, first) = frames.split_last().expect("a handshake");
    for f in first {
        assert!(matches!(
            feed(&b, Lane::Channel, f, false),
            Inbound::Pending
        ));
    }
    let body = vec![0x5a_u8; 256 * 1024];
    let row = a.seal(LINK, Lane::Resource, &body).expect("seal");
    assert!(
        matches!(b.open(LINK, Lane::Resource, &row), Inbound::HeldBeforeKeys),
        "a {}-byte sealed Resource is held, not dropped",
        row.len()
    );
    assert!(matches!(
        feed(&b, Lane::Channel, last, false),
        Inbound::Keyed { .. }
    ));
    let held = b.take_before_keys(LINK);
    match b.open(LINK, Lane::Resource, &held[0]) {
        Inbound::Open(p) => assert_eq!(p, body),
        other => panic!("{other:?}"),
    }

    // The largest frame edge carries fits one link's hold, too.
    let c = seals(0x33, DIALLED);
    assert!(c.begin_responder(LINK));
    assert!(matches!(
        c.open(LINK, Lane::Resource, &vec![0u8; HELD_BYTES_MAX]),
        Inbound::HeldBeforeKeys
    ));
    assert!(
        c.hold(LINK, true, vec![0; HELD_BYTES_MAX]),
        "the identity hold takes one largest frame too"
    );
}

/// Links that never finish their handshake cannot pin unbounded memory:
/// past [`HELD_BYTES_NODE_MAX`] across links, a frame is dropped by name.
#[test]
fn the_holds_are_bounded_across_links() {
    let c = seals(0x33, DIALLED);
    let fit = HELD_BYTES_NODE_MAX / HELD_BYTES_MAX;
    for i in 0..=fit {
        let link = [u8::try_from(i).expect("few links"); 16];
        assert!(c.begin_responder(link));
        let out = c.open(link, Lane::Resource, &vec![0u8; HELD_BYTES_MAX]);
        if i < fit {
            assert!(matches!(out, Inbound::HeldBeforeKeys), "link {i}: {out:?}");
        } else {
            assert!(
                matches!(out, Inbound::Drop(l) if l == crate::observability::LINK_SEAL_DROPPED_BEFORE_KEYS),
                "past the node bound: {out:?}"
            );
        }
    }
    let d = seals(0x44, DIALLED);
    for i in 0..fit {
        let link = [u8::try_from(i).expect("few links"); 16];
        assert!(d.hold(link, false, vec![0; HELD_BYTES_MAX]), "link {i}");
    }
    assert!(!d.hold([0xee; 16], false, vec![0; HELD_BYTES_MAX]));
}

#[test]
fn the_identity_hold_is_bounded_and_replays_in_order_e1() {
    let b = seals(0x22, DIALLED);
    assert!(b.hold(LINK, false, b"one".to_vec()));
    assert!(b.hold(LINK, true, b"two".to_vec()));
    assert!(
        !b.hold(LINK, false, vec![0; HELD_BYTES_MAX]),
        "a frame past the byte bound does not fit"
    );
    assert_eq!(
        b.take_held(LINK),
        vec![(false, b"one".to_vec()), (true, b"two".to_vec())],
        "oldest first"
    );
    assert!(b.take_held(LINK).is_empty(), "taken once");
    for _ in 0..HELD_FRAMES_MAX {
        assert!(b.hold(LINK, false, b"x".to_vec()));
    }
    assert!(!b.hold(LINK, false, b"x".to_vec()), "past the frame bound");
    b.forget(&LINK);
    assert!(b.take_held(LINK).is_empty(), "a closed link holds nothing");
}

#[test]
fn the_attribution_hold_keeps_order_and_refuses_at_its_budget_e1() {
    let b = seals(0x22, DIALLED);
    assert!(!b.any_awaiting_attribution());
    assert!(b.hold(LINK, true, b"before-identify".to_vec()));
    assert!(
        !b.awaits_attribution(LINK),
        "an identity hold is not an attribution hold"
    );
    assert!(b
        .hold_for_attribution(LINK, b"one".to_vec(), SealRefusal::FirstContactOnly)
        .is_ok());
    assert!(b
        .hold_for_attribution(LINK, b"two".to_vec(), SealRefusal::OpenFailed)
        .is_ok());
    assert!(b.awaits_attribution(LINK) && b.any_awaiting_attribution());
    assert_eq!(b.awaiting_attribution(), vec![LINK]);
    let now = std::time::Instant::now();
    assert!(
        b.attribution_expired(LINK, now).is_none(),
        "budget left: still waiting"
    );
    assert_eq!(
        b.take_held(LINK),
        vec![
            (true, b"before-identify".to_vec()),
            (false, b"one".to_vec()),
            (false, b"two".to_vec())
        ],
        "released oldest first"
    );
    assert!(!b.awaits_attribution(LINK), "released: nothing waits");
    assert!(b
        .hold_for_attribution(LINK, b"three".to_vec(), SealRefusal::FirstContactOnly)
        .is_ok());
    assert!(b
        .hold_for_attribution(LINK, b"four".to_vec(), SealRefusal::OpenFailed)
        .is_ok());
    let spent = std::time::Instant::now() + ATTRIBUTION_HOLD_BUDGET;
    assert!(
        matches!(
            b.attribution_expired(LINK, spent),
            Some(SealRefusal::FirstContactOnly)
        ),
        "the first frame's refusal, once the budget is spent"
    );
    assert!(
        b.take_held(LINK).is_empty(),
        "an expired wait discards its frames"
    );
    for _ in 0..HELD_FRAMES_MAX {
        assert!(b
            .hold_for_attribution(LINK, b"x".to_vec(), SealRefusal::FirstContactOnly)
            .is_ok());
    }
    assert!(
        matches!(
            b.hold_for_attribution(LINK, b"x".to_vec(), SealRefusal::OpenFailed),
            Err(SealRefusal::FirstContactOnly)
        ),
        "past the bound: refused now, with the first refusal"
    );
}

/// The handshake parts for a fresh dialler, for a link of `b`'s.
fn parts_for(link: [u8; 16], b: &LinkSeals) -> Vec<Vec<u8>> {
    let a = seals(0x11, DIALLER);
    a.begin_initiator(link);
    a.initiate(link, DIALLER, DIALLED, b.secret().pair(), LIMIT)
        .expect("initiate")
        .0
}

/// `link`'s handshake fed whole: its job, the link keying.
fn keying(b: &LinkSeals, link: [u8; 16]) -> HandshakeJob {
    assert!(b.begin_responder(link));
    let mut job = None;
    for f in parts_for(link, b) {
        match b.inbound(link, Lane::Channel, &f, false, None) {
            Inbound::Pending => {}
            Inbound::Handshake(j) => job = Some(j),
            other => panic!("{other:?}"),
        }
    }
    job.expect("the last part yields the job")
}

fn frame_event(link: [u8; 16], n: u8) -> NodeEvent {
    NodeEvent::LinkDataReceived {
        link_id: leviculum_core::LinkId::new(link),
        data: vec![n],
    }
}

#[test]
fn inbound_never_decapsulates_947() {
    let b = seals(0x22, DIALLED);
    let job = keying(&b, LINK);
    assert_eq!(b.decapsulations(), 0, "the last part only hands a job back");
    assert!(b.is_keying(LINK));
    assert!(!b.is_sealed(LINK));
    assert!(matches!(
        b.seal(LINK, Lane::Channel, b"x"),
        Err(SealRefusal::Unsealed)
    ));
    let outcome = b.decapsulate(&job).expect("live");
    assert_eq!(b.decapsulations(), 1);
    assert!(b.is_keying(LINK), "keys wait for the event loop");
    assert!(matches!(
        b.finish_keying(LINK, job.ticket(), outcome),
        Inbound::Keyed { .. }
    ));
    assert!(b.is_sealed(LINK));
}

#[test]
fn a_link_has_one_keying_outcome_947() {
    let b = seals(0x22, DIALLED);
    let job = keying(&b, LINK);
    let outcome = b.decapsulate(&job).expect("live");
    // The budget gets there first: the outcome is discarded, keys never land.
    assert!(b.expire(LINK));
    assert!(matches!(
        b.finish_keying(LINK, job.ticket(), outcome),
        Inbound::Closed
    ));
    assert!(!b.is_sealed(LINK));
    assert!(b.decapsulate(&job).is_none(), "a dead job does not run");

    // A closed link's id coming back keying does not take the old outcome.
    let c = seals(0x22, DIALLED);
    let old = keying(&c, LINK);
    let outcome = c.decapsulate(&old).expect("live");
    c.forget(&LINK);
    let new = keying(&c, LINK);
    assert_ne!(old.ticket(), new.ticket());
    assert!(matches!(
        c.finish_keying(LINK, old.ticket(), outcome),
        Inbound::Closed
    ));
    assert!(
        c.is_keying(LINK),
        "the new keying still waits on its own job"
    );
}

#[test]
fn a_failed_keying_refuses_the_link_once_947() {
    let b = seals(0x22, DIALLED);
    assert!(b.begin_responder(LINK));
    let garbage =
        crate::transport::av_transit_handshake::fragment(&[0x01; 900], LIMIT).expect("frames");
    let mut job = None;
    for f in garbage {
        if let Inbound::Handshake(j) = b.inbound(LINK, Lane::Channel, &f, false, None) {
            job = Some(j);
        }
    }
    let job = job.expect("framing whole");
    let outcome = b.decapsulate(&job).expect("live");
    assert!(outcome.is_err(), "not a handshake");
    assert!(matches!(
        b.finish_keying(LINK, job.ticket(), outcome),
        Inbound::Refuse(SealRefusal::Handshake(_))
    ));
    assert!(matches!(
        feed(&b, Lane::Channel, b"late", false),
        Inbound::Closed
    ));
}

#[test]
fn a_keying_link_is_never_expired_before_its_budget_and_route_budget_carries_947() {
    let b = seals(0x22, DIALLED);
    let _job = keying(&b, LINK);
    assert!(b
        .keying_budget_left(LINK)
        .is_some_and(|l| l > Duration::ZERO));

    let c = seals(0x22, DIALLED);
    assert!(c.begin_responder(LINK));
    let req = route_fetch::encode_request(&route_fetch::RouteRequest {
        key_id: DIALLED.to_owned(),
        holds_key_record: false,
    });
    assert!(matches!(
        c.inbound(LINK, Lane::Channel, &req, false, None),
        Inbound::RouteRequested { .. }
    ));
    for f in parts_for(LINK, &c) {
        let _ = c.inbound(LINK, Lane::Channel, &f, false, None);
    }
    assert!(c.is_keying(LINK));
    assert!(
        c.route_budget_left(LINK).is_some(),
        "the route fetch's budget survives into keying"
    );
}

#[test]
fn frames_wait_on_keying_in_order_and_go_with_the_link_947() {
    let b = seals(0x22, DIALLED);
    let _job = keying(&b, LINK);
    for n in 0..3 {
        b.park(LINK, frame_event(LINK, n), 1).expect("room");
    }
    let order: Vec<u8> = b
        .take_parked(LINK)
        .into_iter()
        .map(|e| match e {
            NodeEvent::LinkDataReceived { data, .. } => data[0],
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(order, vec![0, 1, 2]);
    assert!(b.take_parked(LINK).is_empty());

    b.park(LINK, frame_event(LINK, 9), 1).expect("room");
    b.forget(&LINK);
    assert!(
        b.take_parked(LINK).is_empty(),
        "a closed link holds nothing"
    );
    assert_eq!(b.parked().bytes, 0);
}

#[test]
fn a_link_that_outruns_its_keying_hold_is_refused_by_name_947() {
    let b = seals(0x22, DIALLED);
    let _job = keying(&b, LINK);
    for n in 0..KEYING_HELD_FRAMES_MAX {
        b.park(LINK, frame_event(LINK, 0), 1)
            .unwrap_or_else(|e| panic!("frame {n}: {e}"));
    }
    let refused = b
        .park(LINK, frame_event(LINK, 0), 1)
        .expect_err("past the frame bound");
    assert_eq!(
        refused.label(),
        crate::observability::LINK_SEAL_REFUSED_KEYING_HOLD
    );
    assert_eq!(
        b.parked().bytes,
        0,
        "the node-wide count let go of the link"
    );

    let c = seals(0x22, DIALLED);
    c.begin_responder(LINK);
    assert!(c
        .park(LINK, frame_event(LINK, 0), HELD_BYTES_MAX + 1)
        .is_err());
    // Node-wide: other links' holds fill the bound.
    for i in 0..8u8 {
        let l = [i + 1; 16];
        c.park(l, frame_event(l, 0), HELD_BYTES_MAX).expect("room");
    }
    assert!(c.park([0xee; 16], frame_event(LINK, 0), 1).is_err());
}

#[test]
fn the_awaiting_cap_refuses_the_oldest_by_count_947() {
    let b = seals(0x22, DIALLED);
    b.set_awaiting_caps(2, AWAITING_BYTES_MAX);
    assert!(b.begin_responder([1; 16]));
    assert!(b.begin_responder([2; 16]));
    assert!(b.take_evicted().is_empty());
    assert!(b.begin_responder([3; 16]));
    assert_eq!(b.take_evicted(), vec![[1; 16]], "the oldest gives way");
    // It is refused: a frame still in flight finds it closed.
    assert!(matches!(
        b.inbound([1; 16], Lane::Channel, b"late", false, None),
        Inbound::Closed
    ));
    // The newest stayed and can key; leaving `Awaiting` frees its slot.
    let parts = parts_for([3; 16], &b);
    for f in &parts {
        let _ = b.inbound([3; 16], Lane::Channel, f, false, None);
    }
    assert!(b.is_keying([3; 16]));
    assert!(b.begin_responder([4; 16]));
    assert!(b.take_evicted().is_empty(), "keying is not awaiting");
    // A link first heard of at its first frame is counted the same.
    assert!(b.begin_responder([5; 16]));
    assert_eq!(b.take_evicted(), vec![[2; 16]]);
    let _ = b.inbound([6; 16], Lane::Channel, b"CTKX", false, None);
    assert_eq!(b.take_evicted(), vec![[4; 16]]);
}

#[test]
fn the_awaiting_cap_refuses_the_oldest_by_bytes_947() {
    let b = seals(0x22, DIALLED);
    let parts = parts_for([1; 16], &b);
    assert!(parts.len() > 2, "a handshake of several parts");
    b.set_awaiting_caps(AWAITING_LINKS_MAX, parts[0].len() * 2);
    assert!(b.begin_responder([1; 16]));
    assert!(matches!(
        b.inbound([1; 16], Lane::Channel, &parts[0], false, None),
        Inbound::Pending
    ));
    let other = parts_for([2; 16], &b);
    assert!(b.begin_responder([2; 16]));
    let _ = b.inbound([2; 16], Lane::Channel, &other[0], false, None);
    assert!(b.take_evicted().is_empty(), "both fit");
    let _ = b.inbound([2; 16], Lane::Channel, &other[1], false, None);
    assert_eq!(b.take_evicted(), vec![[1; 16]], "the oldest pays");
    let links = b.links();
    assert_eq!(
        links.ledger.bytes, links.ledger.links[&[2; 16]].1,
        "the evicted link's bytes left the ledger"
    );
}

#[test]
fn the_ledger_follows_every_way_out_of_awaiting_947() {
    let b = seals(0x22, DIALLED);
    let parts = parts_for([1; 16], &b);
    for (i, out) in ["refuse", "expire", "forget", "bad frame"]
        .iter()
        .enumerate()
    {
        let l = [u8::try_from(i).unwrap() + 1; 16];
        assert!(b.begin_responder(l));
        let _ = b.inbound(l, Lane::Channel, &parts[0], false, None);
        assert!(b.links().ledger.bytes > 0, "{out}");
        match *out {
            "refuse" => b.refuse(l),
            "expire" => assert!(b.expire(l)),
            "forget" => b.forget(&l),
            _ => assert!(matches!(
                b.inbound(l, Lane::Channel, b"not a part", false, None),
                Inbound::Refuse(_)
            )),
        }
        assert_eq!(b.links().ledger.links.len(), 0, "{out}");
        assert_eq!(b.links().ledger.by_age.len(), 0, "{out}");
        assert_eq!(b.links().ledger.bytes, 0, "{out}");
    }
}

#[test]
fn a_route_request_is_charged_to_its_sender_before_the_node_947() {
    let b = seals(0x22, DIALLED);
    let req = route_fetch::encode_request(&route_fetch::RouteRequest {
        key_id: DIALLED.to_owned(),
        holds_key_record: false,
    });
    let cap = route_fetch::ROUTE_REQUESTS_PER_SENDER;
    let mut refused = 0;
    for i in 0..u8::try_from(route_fetch::ROUTE_REQUESTS_PER_WINDOW).unwrap() {
        let l = [i; 16];
        assert!(b.begin_responder(l));
        if matches!(
            b.inbound(l, Lane::Channel, &req, false, Some("one-prober")),
            Inbound::Refuse(_)
        ) {
            refused += 1;
        }
    }
    assert_eq!(
        refused,
        usize::try_from(route_fetch::ROUTE_REQUESTS_PER_WINDOW).unwrap() - cap
    );
    // The prober spent only its own budget: an honest stranger still gets in.
    assert!(b.begin_responder([0xfe; 16]));
    assert!(matches!(
        b.inbound([0xfe; 16], Lane::Channel, &req, false, Some("honest")),
        Inbound::RouteRequested { .. }
    ));
}

#[test]
fn a_handshake_waits_for_its_identify_boundedly_and_goes_with_its_link_947() {
    let b = seals(0x22, DIALLED);
    let job = keying(&b, LINK);
    let ticket = job.ticket();
    b.defer_handshake(job).expect("room");
    assert!(b.any_deferred());
    assert!(b.take_overdue_deferred().is_empty(), "within its grace");
    assert_eq!(b.take_deferred(LINK).expect("waiting").ticket(), ticket);
    assert!(b.take_deferred(LINK).is_none(), "one job, once");

    let job = keying(&b, [2; 16]);
    b.defer_handshake(job).expect("room");
    b.forget(&[2; 16]);
    assert!(!b.any_deferred(), "a closed link's job goes with it");

    let job = keying(&b, [3; 16]);
    b.defer_handshake(job).expect("room");
    assert!(b.expire([3; 16]));
    assert!(!b.any_deferred(), "so does an expired one");

    for i in 0..DEFERRED_HANDSHAKES_MAX {
        let l = [
            u8::try_from(i).unwrap(),
            0xaa,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        b.defer_handshake(HandshakeJob {
            link: l,
            ticket: 0,
            handshake: Vec::new(),
        })
        .expect("room");
    }
    assert!(b
        .defer_handshake(HandshakeJob {
            link: [0xfe; 16],
            ticket: 0,
            handshake: Vec::new(),
        })
        .is_err());
}
