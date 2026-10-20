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
fn a_resource_before_the_handshake_is_dropped_e1() {
    let b = seals(0x22, DIALLED);
    b.begin_responder(LINK);
    // Dropped, not refused: another event plane may overtake the handshake.
    match b.open(LINK, Lane::Resource, b"anything") {
        Inbound::Drop(label) => {
            assert_eq!(label, crate::observability::LINK_SEAL_DROPPED_BEFORE_KEYS);
        }
        other => panic!("{other:?}"),
    }
    // On a link this node dialled and has not keyed, the responder spoke
    // first: refused.
    let a = seals(0x11, DIALLER);
    a.begin_initiator(LINK);
    assert!(matches!(
        a.open(LINK, Lane::Resource, b"anything"),
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
