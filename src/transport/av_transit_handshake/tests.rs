use super::*;

use tokio::sync::{mpsc, Mutex};

use crate::transport::realtime_av::{
    open_av_outer, seal_av_inner, seal_av_outer, ChunkLayer, ChunkSeq, Epoch, EpochDek, StreamId,
    CODEC_OPAQUE,
};

const LINK: [u8; 16] = [0x6c; 16];
const RELAY: &str = "relay-key";
const SUBSCRIBER: &str = "subscriber-key";
/// The base-MTU A/V leg's Channel limit (MTU 500).
const CHANNEL_LIMIT: usize = 425;

/// One end of an in-memory link: frames sent here arrive on the paired
/// [`Inbound`].
struct Outbound(mpsc::UnboundedSender<InboundWireFrame>);

#[async_trait::async_trait]
impl AvLinkSender for Outbound {
    async fn send(&self, bytes: &[u8]) -> Result<(), AvDispatcherError> {
        self.0
            .send(InboundWireFrame {
                dropped_before: 0,
                bytes: bytes.to_vec(),
            })
            .map_err(|_| AvDispatcherError::SendFailed("closed".into()))
    }
}

struct Inbound(Mutex<mpsc::UnboundedReceiver<InboundWireFrame>>);

#[async_trait::async_trait]
impl AvLinkReceiver for Inbound {
    async fn recv(&self) -> Result<Vec<u8>, AvDispatcherError> {
        self.recv_frame().await.map(|f| f.bytes)
    }
    async fn recv_frame(&self) -> Result<InboundWireFrame, AvDispatcherError> {
        self.0
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| AvDispatcherError::RecvFailed("closed".into()))
    }
}

fn link() -> (Outbound, Inbound) {
    let (tx, rx) = mpsc::unbounded_channel();
    (Outbound(tx), Inbound(Mutex::new(rx)))
}

fn relay_secret() -> TransitKexSecret {
    TransitKexSecret::from_root_seed(&[0x42; 64]).expect("relay transit secret")
}

/// The subscriber dials the relay: it initiates against the relay's pair;
/// the relay responds and checks the claim against `proven`.
async fn handshake(
    claimed: &str,
    addressed_to: &str,
    proven: &str,
) -> (
    Result<LinkTransit, AvHandshakeError>,
    Result<LinkTransit, AvHandshakeError>,
) {
    let secret = relay_secret();
    let (tx, rx) = link();
    let initiated = initiate_on_link(
        &tx,
        CHANNEL_LIMIT,
        &LINK,
        claimed,
        addressed_to,
        secret.pair(),
    )
    .await;
    let responded = respond_on_link(&rx, &LINK, RELAY, &secret, proven).await;
    (initiated, responded)
}

fn frame(bytes: Vec<u8>) -> InboundWireFrame {
    InboundWireFrame {
        dropped_before: 0,
        bytes,
    }
}

/// Media sealed by one end under its seal key opens at the other end under
/// its open key, in BOTH directions, and the two directions' keys differ.
#[tokio::test]
async fn keys_line_up_by_role_and_both_directions_open() {
    let (sub, relay) = handshake(SUBSCRIBER, RELAY, SUBSCRIBER).await;
    let (sub, relay) = (sub.expect("initiate"), relay.expect("respond"));
    assert_eq!(sub.role(), TransitRole::Initiator);
    assert_eq!(relay.role(), TransitRole::Responder);
    assert_eq!(sub.seal_key(), relay.open_key());
    assert_eq!(relay.seal_key(), sub.open_key());
    assert_ne!(sub.seal_key(), sub.open_key(), "one key per direction");
    // Pinned to verify's role names, not just to each other: the relay
    // (responder) seals with `responder_to_initiator`, which the subscriber
    // (initiator) opens with; the initiator seals `initiator_to_responder`.
    assert_eq!(relay.seal_key(), *relay.keys.responder_to_initiator());
    assert_eq!(sub.open_key(), *sub.keys.responder_to_initiator());
    assert_eq!(sub.seal_key(), *sub.keys.initiator_to_responder());
    assert_eq!(relay.open_key(), *relay.keys.initiator_to_responder());

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
            let out = r.push(&frame(f.clone())).expect("push");
            assert_eq!(out.is_some(), i + 1 == frames.len());
            done = out.or(done);
        }
        assert_eq!(done.expect("complete"), bytes);
    }
    assert!(fragment(&vec![0; MAX_HANDSHAKE_BYTES + 1], CHANNEL_LIMIT).is_err());
}

/// The handshake's claimed initiator is not the link's proven peer: refused,
/// and no key is returned.
#[tokio::test]
async fn a_claim_that_is_not_the_links_peer_is_refused() {
    let (initiated, responded) = handshake("mallory-key", RELAY, SUBSCRIBER).await;
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
#[tokio::test]
async fn a_handshake_for_another_responder_is_refused() {
    let (_, responded) = handshake(SUBSCRIBER, "other-relay", SUBSCRIBER).await;
    assert!(matches!(
        responded,
        Err(AvHandshakeError::ResponderMismatch)
    ));
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
        r.push(&frame(start)),
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
    r.push(&frame(frames[0].clone())).expect("start");
    assert!(matches!(
        r.push(&frame(frames[1].clone())),
        Err(AvHandshakeError::Malformed(_))
    ));
}

/// An oversized handshake over a real receiver: refused on its first frame,
/// though the peer keeps sending.
#[tokio::test]
async fn an_oversized_handshake_on_the_link_is_refused_at_once() {
    let (tx, rx) = link();
    let mut start = HANDSHAKE_MAGIC.to_vec();
    start.push(HANDSHAKE_FRAME_VERSION);
    start.push(KIND_START);
    start.extend_from_slice(&u32::MAX.to_be_bytes());
    start.extend_from_slice(&[1u8; 400]);
    tx.send(&start).await.expect("send");
    for _ in 0..1000 {
        let mut cont = HANDSHAKE_MAGIC.to_vec();
        cont.push(HANDSHAKE_FRAME_VERSION);
        cont.push(KIND_CONTINUATION);
        cont.extend_from_slice(&[1u8; 400]);
        tx.send(&cont).await.expect("send");
    }
    let refused = respond_on_link(&rx, &LINK, RELAY, &relay_secret(), SUBSCRIBER).await;
    assert!(matches!(refused, Err(AvHandshakeError::TooLarge { .. })));
}

/// A truncated handshake: the link closes with parts missing (refused, not
/// waited on), and a complete frame set whose body is cut short fails the
/// KEX parse.
#[tokio::test]
async fn a_truncated_handshake_is_refused() {
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

    // Parts missing, then the link closes.
    let (tx, rx) = link();
    let frames = fragment(&bytes, CHANNEL_LIMIT).expect("fragment");
    assert!(frames.len() > 2);
    tx.send(&frames[0]).await.expect("send");
    drop(tx);
    assert!(matches!(
        respond_on_link(&rx, &LINK, RELAY, &secret, SUBSCRIBER).await,
        Err(AvHandshakeError::LinkClosed(_))
    ));

    // Framing complete, body cut short.
    let (tx, rx) = link();
    for f in fragment(&bytes[..bytes.len() - 10], CHANNEL_LIMIT).expect("fragment") {
        tx.send(&f).await.expect("send");
    }
    assert!(matches!(
        respond_on_link(&rx, &LINK, RELAY, &secret, SUBSCRIBER).await,
        Err(AvHandshakeError::Kex(_))
    ));
}

/// A peer that skips the KEX and sends media first is refused by name.
#[tokio::test]
async fn media_in_the_handshakes_place_is_refused() {
    let (tx, rx) = link();
    tx.send(&[0x11u8; 120]).await.expect("send");
    assert!(matches!(
        respond_on_link(&rx, &LINK, RELAY, &relay_secret(), SUBSCRIBER).await,
        Err(AvHandshakeError::NotAHandshake)
    ));
}

/// A handshake frame the transport dropped refuses the handshake.
#[test]
fn a_dropped_handshake_frame_is_refused() {
    let frames = fragment(&[3u8; 900], CHANNEL_LIMIT).expect("fragment");
    let mut r = Reassembler::new();
    r.push(&frame(frames[0].clone())).expect("start");
    assert!(matches!(
        r.push(&InboundWireFrame {
            dropped_before: 1,
            bytes: frames[2].clone(),
        }),
        Err(AvHandshakeError::FrameDropped { dropped: 1 })
    ));
}

/// Two admissions on the same link (same `link_id`, same parties) derive
/// different keys: each handshake draws a fresh one-time key, so a
/// `link_seq` restart under the new handshake never repeats a nonce under a
/// used key.
#[tokio::test]
async fn two_admissions_on_the_same_link_derive_different_keys() {
    let (a_sub, a_relay) = handshake(SUBSCRIBER, RELAY, SUBSCRIBER).await;
    let (b_sub, b_relay) = handshake(SUBSCRIBER, RELAY, SUBSCRIBER).await;
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
