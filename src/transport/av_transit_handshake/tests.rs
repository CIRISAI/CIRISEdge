use super::*;

use crate::transport::realtime_av::{
    open_av_outer, seal_av_inner, seal_av_outer, ChunkLayer, ChunkSeq, Epoch, EpochDek, StreamId,
    CODEC_OPAQUE,
};

const LINK: [u8; 16] = [0x6c; 16];
const RELAY: &str = "relay-key";
const SUBSCRIBER: &str = "subscriber-key";
/// The base-MTU leg's Channel limit (MTU 500, less the link seal).
const CHANNEL_LIMIT: usize = 400;

fn relay_secret() -> TransitKexSecret {
    TransitKexSecret::from_root_seed(&[0x42; 64]).expect("relay transit secret")
}

/// Reassemble `frames` at the responder, as the link layer does.
fn reassemble(frames: &[Vec<u8>]) -> Result<Vec<u8>, AvHandshakeError> {
    let mut r = Reassembler::new();
    for f in frames {
        if let Some(bytes) = r.push(f)? {
            return Ok(bytes);
        }
    }
    Err(AvHandshakeError::Timeout(HANDSHAKE_BUDGET))
}

/// The subscriber dials the relay: it initiates against the relay's pair;
/// the relay responds and checks the claim against `proven`.
fn handshake(
    claimed: &str,
    addressed_to: &str,
    proven: &str,
) -> (
    Result<LinkTransit, AvHandshakeError>,
    Result<LinkTransit, AvHandshakeError>,
) {
    let secret = relay_secret();
    let initiated = initiate(&LINK, claimed, addressed_to, secret.pair(), CHANNEL_LIMIT);
    let (initiated, frames) = match initiated {
        Ok((frames, t)) => (Ok(t), frames),
        Err(e) => return (Err(e), Err(AvHandshakeError::Malformed("no frames"))),
    };
    assert!(frames.iter().all(|f| f.len() <= CHANNEL_LIMIT));
    let responded = reassemble(&frames)
        .and_then(|bytes| respond(&bytes, &LINK, RELAY, &secret))
        .and_then(|(t, claim)| check_claim(&claim, proven).map(|()| t));
    (initiated, responded)
}

/// Media sealed by one end under its seal key opens at the other end under
/// its open key, in BOTH directions, and the two directions' keys differ.
#[test]
fn keys_line_up_by_role_and_both_directions_open() {
    let (sub, relay) = handshake(SUBSCRIBER, RELAY, SUBSCRIBER);
    let (sub, relay) = (sub.expect("initiate"), relay.expect("respond"));
    assert_eq!(sub.role(), TransitRole::Initiator);
    assert_eq!(relay.role(), TransitRole::Responder);
    assert_eq!(sub.seal_key(), relay.open_key());
    assert_eq!(relay.seal_key(), sub.open_key());
    assert_ne!(sub.seal_key(), sub.open_key(), "one key per direction");

    let dek = EpochDek::from_bytes([0x44; 32]);
    let inner = seal_av_inner(
        b"frame",
        &dek,
        StreamId([9; 32]),
        Epoch(1),
        ChunkSeq(0),
        CODEC_OPAQUE,
        ChunkLayer::BASE,
    )
    .expect("inner");
    // The relay leg's media direction: relay (responder) → subscriber.
    let down = seal_av_outer(&inner, &relay.seal_key(), &LINK, 0).expect("seal down");
    assert!(open_av_outer(&down, &sub.open_key(), &LINK, 0).is_ok());
    assert!(
        open_av_outer(&down, &sub.seal_key(), &LINK, 0).is_err(),
        "the subscriber's SEAL key does not open the relay's frames"
    );
    // And the other direction (a publisher dialling its relay).
    let up = seal_av_outer(&inner, &sub.seal_key(), &LINK, 0).expect("seal up");
    assert!(open_av_outer(&up, &relay.open_key(), &LINK, 0).is_ok());
    assert!(open_av_outer(&up, &relay.seal_key(), &LINK, 0).is_err());
}

/// Pinned to verify's role names, not just to each other: the responder
/// seals with `responder_to_initiator`, the initiator with
/// `initiator_to_responder`.
#[test]
fn keys_are_verifys_by_role() {
    let secret = relay_secret();
    let (hs, keys) = transit_kex::initiate(
        &LINK,
        SUBSCRIBER,
        RELAY,
        &secret.pair().x25519,
        &secret.pair().ml_kem_768[..],
    )
    .expect("initiate");
    let sub = LinkTransit::from_keys(&keys, TransitRole::Initiator);
    let (relay, claim) = respond(&hs.to_bytes(), &LINK, RELAY, &secret).expect("respond");
    assert_eq!(claim, SUBSCRIBER);
    assert_eq!(sub.seal_key(), *keys.initiator_to_responder());
    assert_eq!(sub.open_key(), *keys.responder_to_initiator());
    assert_eq!(relay.seal_key(), *keys.responder_to_initiator());
    assert_eq!(relay.open_key(), *keys.initiator_to_responder());
}

/// The handshake spans several Channel messages at the base MTU, none over
/// the limit, and reassembles exactly.
#[test]
fn fragments_fit_the_channel_and_reassemble() {
    for len in [1usize, 400, 1200, 1300, 4096, MAX_HANDSHAKE_BYTES] {
        let bytes: Vec<u8> = (0..len)
            .map(|i| u8::try_from(i % 251).expect("< 251"))
            .collect();
        let frames = fragment(&bytes, CHANNEL_LIMIT).expect("fragment");
        assert!(frames.iter().all(|f| f.len() <= CHANNEL_LIMIT));
        let mut r = Reassembler::new();
        let mut done = None;
        for (i, f) in frames.iter().enumerate() {
            let out = r.push(f).expect("push");
            assert_eq!(out.is_some(), i + 1 == frames.len());
            done = out.or(done);
        }
        assert_eq!(done.expect("complete"), bytes);
    }
    assert!(fragment(&vec![0; MAX_HANDSHAKE_BYTES + 1], CHANNEL_LIMIT).is_err());
}

/// The handshake's claimed initiator is not the link's proven peer: refused,
/// and no key is returned.
#[test]
fn a_claim_that_is_not_the_links_peer_is_refused() {
    let (initiated, responded) = handshake("mallory-key", RELAY, SUBSCRIBER);
    assert!(initiated.is_ok(), "the liar can always send");
    match responded {
        Err(AvHandshakeError::ClaimMismatch { claimed, proven }) => {
            assert_eq!(claimed, "mallory-key");
            assert_eq!(proven, SUBSCRIBER);
        }
        other => panic!("expected ClaimMismatch, got {other:?}"),
    }
}

/// A handshake addressed to another relay key is refused by name.
#[test]
fn a_handshake_for_another_responder_is_refused() {
    let (_, responded) = handshake(SUBSCRIBER, "other-relay", SUBSCRIBER);
    assert!(matches!(
        responded,
        Err(AvHandshakeError::ResponderMismatch)
    ));
}

/// A handshake naming another construction (a classical-only suite) is
/// refused by name as a suite refusal, never answered.
#[test]
fn a_classical_only_suite_is_refused_by_name() {
    let secret = relay_secret();
    let (hs, _) = transit_kex::initiate(
        &LINK,
        SUBSCRIBER,
        RELAY,
        &secret.pair().x25519,
        &secret.pair().ml_kem_768[..],
    )
    .expect("initiate");
    let mut bytes = hs.to_bytes();
    // The suite identifier is length-prefixed at the head of the body;
    // rename it to a classical-only construction of the same length.
    let id_len = usize::from(bytes[0]);
    let classical = b"transit_x25519_only_hkdf_sha256_____";
    bytes[1..=id_len].copy_from_slice(&classical[..id_len]);
    let refused = respond(&bytes, &LINK, RELAY, &secret).map(|_| ());
    assert!(
        matches!(refused, Err(AvHandshakeError::Suite)),
        "{refused:?}"
    );
    assert_eq!(
        AvHandshakeError::Suite.label(),
        crate::observability::LINK_SEAL_REFUSED_SUITE
    );
}

/// An oversized declaration is refused at the START frame, before a byte is
/// buffered; a part past the declared length is refused too.
#[test]
fn an_oversized_handshake_is_refused_before_buffering() {
    let mut start = HANDSHAKE_MAGIC.to_vec();
    start.push(HANDSHAKE_FRAME_VERSION);
    start.push(KIND_START);
    start.extend_from_slice(&(64u32 * 1024 * 1024).to_be_bytes());
    start.extend_from_slice(&[0u8; 400]);
    let mut r = Reassembler::new();
    assert!(matches!(
        r.push(&start),
        Err(AvHandshakeError::TooLarge { declared, max })
            if declared == 64 * 1024 * 1024 && max == MAX_HANDSHAKE_BYTES
    ));
    assert_eq!(
        r.buffered(),
        0,
        "nothing buffered for a refused declaration"
    );

    // A part that runs past the declared length.
    let mut frames = fragment(&[7u8; 600], CHANNEL_LIMIT).expect("fragment");
    frames[1].extend_from_slice(&[7u8; 8]);
    let mut r = Reassembler::new();
    r.push(&frames[0]).expect("start");
    assert!(matches!(
        r.push(&frames[1]),
        Err(AvHandshakeError::Malformed(_))
    ));
}

/// A complete frame set whose body is cut short fails the KEX parse.
#[test]
fn a_truncated_handshake_is_refused() {
    let secret = relay_secret();
    let (hs, _) = transit_kex::initiate(
        &LINK,
        SUBSCRIBER,
        RELAY,
        &secret.pair().x25519,
        &secret.pair().ml_kem_768[..],
    )
    .expect("initiate");
    let bytes = hs.to_bytes();
    let frames = fragment(&bytes[..bytes.len() - 10], CHANNEL_LIMIT).expect("fragment");
    let refused = reassemble(&frames).and_then(|b| respond(&b, &LINK, RELAY, &secret));
    assert!(matches!(refused, Err(AvHandshakeError::Kex(_))));
}

/// A peer that skips the KEX and sends anything else first is refused by
/// name.
#[test]
fn a_frame_in_the_handshakes_place_is_refused() {
    let mut r = Reassembler::new();
    assert!(matches!(
        r.push(&[0x11u8; 120]),
        Err(AvHandshakeError::NotAHandshake)
    ));
}

/// Two handshakes on the same link (same `link_id`, same parties) derive
/// different keys: each handshake draws a fresh one-time key.
#[test]
fn two_handshakes_on_the_same_link_derive_different_keys() {
    let (a_sub, a_relay) = handshake(SUBSCRIBER, RELAY, SUBSCRIBER);
    let (b_sub, b_relay) = handshake(SUBSCRIBER, RELAY, SUBSCRIBER);
    let (a_sub, a_relay, b_sub, b_relay) = (
        a_sub.unwrap(),
        a_relay.unwrap(),
        b_sub.unwrap(),
        b_relay.unwrap(),
    );
    assert_eq!(a_sub.open_key(), a_relay.seal_key());
    assert_eq!(b_sub.open_key(), b_relay.seal_key());
    assert_ne!(a_relay.seal_key(), b_relay.seal_key());
    assert_ne!(a_relay.open_key(), b_relay.open_key());
}

/// The link id the KEX binds: the 16-byte RNS id, nothing else.
#[test]
fn only_a_sixteen_byte_link_id_is_bound() {
    assert!(kex_link_id(&LINK).is_ok());
    assert!(matches!(
        kex_link_id(SUBSCRIBER.as_bytes()),
        Err(AvHandshakeError::LinkIdLength(_))
    ));
}
