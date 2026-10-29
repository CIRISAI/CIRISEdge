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
        match b.inbound(LINK, Lane::Channel, f, false) {
            Inbound::Pending => {}
            Inbound::Keyed { claimed } => keyed = Some(claimed),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(keyed.as_deref(), Some(DIALLER));
    a.install_initiator(LINK, transit);
    (a, b)
}

#[test]
fn frames_open_in_both_directions_on_every_lane_e1() {
    let (a, b) = keyed_pair();
    for lane in [Lane::Channel, Lane::Resource, Lane::Request, Lane::Response] {
        let up = a.seal(LINK, lane, b"row bytes up").expect("seal up");
        let bin = if lane.is_msgpack() { 2 } else { 0 };
        assert_eq!(up.len(), b"row bytes up".len() + SEAL_OVERHEAD + bin);
        assert!(!contains(&up, b"row bytes up"), "no plaintext on the wire");
        match b.inbound(LINK, lane, &up, false) {
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
    match b.inbound(LINK, Lane::Channel, b"{\"plaintext\":true}", false) {
        Inbound::Refuse(r) => {
            assert_eq!(
                r.label(),
                crate::observability::LINK_SEAL_REFUSED_NOT_A_HANDSHAKE
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        b.inbound(LINK, Lane::Channel, b"more", false),
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
            b.inbound(LINK, Lane::Channel, f, false),
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
    match b.inbound(LINK, Lane::Channel, last, false) {
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
    match b.inbound(LINK, Lane::Channel, &start, false) {
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
    match a.inbound(LINK, Lane::Channel, b"early", true) {
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
    match b.inbound(LINK, Lane::Channel, &up, false) {
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
        b.inbound(LINK, Lane::Channel, &up, false),
        Inbound::Refuse(SealRefusal::OpenFailed)
    ));
}

#[test]
fn a_replayed_frame_is_dropped_and_the_link_kept_e1() {
    let (a, b) = keyed_pair();
    let f0 = a.seal(LINK, Lane::Channel, b"zero").expect("seal");
    let f1 = a.seal(LINK, Lane::Channel, b"one").expect("seal");
    assert!(matches!(
        b.inbound(LINK, Lane::Channel, &f1, false),
        Inbound::Open(_)
    ));
    // Reordered within the window: accepted once.
    assert!(matches!(
        b.inbound(LINK, Lane::Channel, &f0, false),
        Inbound::Open(_)
    ));
    match b.inbound(LINK, Lane::Channel, &f0, false) {
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
            b.inbound(LINK, Lane::Channel, f, false),
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
        b.inbound(LINK, Lane::Channel, last, false),
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
