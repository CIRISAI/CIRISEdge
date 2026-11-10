//! C3 on the wire — the ALM control frame (ALM stage 2).
//!
//! One frame carries one [`ControlMsg`] for one stream, on the existing A/V
//! link between the two members (under the link's E1 seal; it takes no A/V
//! outer seal and no hop counter, like a binding part). It replaces the
//! `CallOptions::relay` flood: a forwarder sends a stream only to the
//! subscribers it ADMITTED for it.
//!
//! ```text
//! frame = "CALM" ‖ version(1) ‖ kind(1) ‖ body
//!
//! CAPS        0x01  caps u32_be
//! SUBSCRIBE   0x02  stream[32] ‖ role u8 ‖ flags u8 (bit 0: forward-capable,
//!                   bit 1: layer cap follows; bits 2-7 ignored)
//!                   [‖ mode u8 (1: at most) ‖ max_spatial u8 ‖ max_temporal u8
//!                    ‖ max_quality u8]                     (45.1, the cap)
//! UNSUBSCRIBE 0x03  stream[32]
//! ADMIT       0x04  stream[32] ‖ role u8
//! REFUSE      0x05  stream[32] ‖ reason u8 ‖ retry_after_ms u32_be
//! SHED        0x06  stream[32] ‖ reason u8
//! OFFER       0x07  stream[32] ‖ depth u8 ‖ forwarding u8
//!                   ‖ headroom_bps u64_be ‖ forwarder_headroom_bps u64_be
//!                   ‖ upstream_latency_ms u32_be
//!                   ‖ n u8 ‖ n × (len u16_be ‖ utf8 key id)   (ancestry, root first)
//! ```
//!
//! **The SUBSCRIBE layer cap** (45.1; CC reads it as conformant in direction,
//! a correction to 5.3.3.2.4's carriage sentence pending): a receiver asks
//! its parent on the tree for at most `(spatial, temporal, quality)` of a
//! stream (CC 5.3.3.4: a relay forwards only the layers asked for). Mode 1
//! (the three maxima, a `ReceiverLayerPolicy`) is the only mode: mode 2 (audio
//! only) would go below the base cell 5.3.3.2.4 makes the minimum and waits
//! on the presence floor, so it, like every other mode, is malformed. A
//! re-SUBSCRIBE changes the cap or (bit 1 clear) withdraws it. It is sent
//! only to a peer whose `CAPS` carry [`CAP_LAYER_REQUEST`], which a node
//! advertises only when its host turned the lever on (off by default until
//! the CC correction lands); a peer without it never sees the extra bytes,
//! which a pre-45.1 decoder would refuse as trailing.
//!
//! `role`: 0 primary, 1 standby. Reason codes: [`RefuseReason::code`],
//! [`ShedReason::code`]. Who SENT a frame is never in it: the link names its
//! peer (the attributed, keyed end), so a subscriber cannot subscribe in
//! another's name and a forwarder cannot offer as another.
//!
//! **Capability-gated.** A peer that does not speak C3 would read a `CALM`
//! frame as a chunk that fails to open, so nothing here is sent to a peer
//! until it has said it speaks it: the RESPONDER of each A/V link sends
//! `CAPS` first, on the reverse direction of the link it accepted (a pre-C3
//! dialler never reads that direction, so it is harmless there), and the
//! dialler answers with its own `CAPS` only after hearing one. [`CAP_C3_V1`]
//! gates every other frame kind; [`CAP_TIMED_FRAMES`] says the peer's
//! leviculum takes Channel frames with a deadline (0xFD00/0xFD01, leviculum
//! v0.33+), so media to it may ride `try_send_timed`. [`CAP_LINK_DATAGRAMS`]
//! says the peer's leviculum takes unordered link datagrams and its edge
//! routes them to the A/V receive path (leviculum#102, v0.34.0+ciris.2), so
//! media to it may ride `try_send_unordered`. A peer without the bit gets
//! none: a leviculum without #102 drops a datagram unread and the sender
//! cannot tell, so the bit's absence means "no datagrams".
//!
//! A stream id whose first five bytes read `"CALM" 0x01` is never minted
//! ([`collides_with_control_frame`]), so a chunk is never taken for a frame.

use super::{AdmitDecision, ControlMsg, Offer, RefuseReason, Role, ShedReason, SubscribeRequest};
use crate::transport::realtime_av::ReceiverLayerPolicy;
use crate::transport::realtime_av::StreamId;

/// The tag every C3 frame opens with.
pub const CONTROL_MAGIC: [u8; 4] = *b"CALM";
/// The framing version this build speaks.
pub const CONTROL_VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 1;

/// Speaks C3 v1 (subscribe/admit/refuse/shed/offer).
pub const CAP_C3_V1: u32 = 1 << 0;
/// Its leviculum takes timed Channel frames (leviculum#94, v0.33+).
pub const CAP_TIMED_FRAMES: u32 = 1 << 1;
/// It offers to relay (a member relay: it forwards streams it receives).
pub const CAP_RELAY: u32 = 1 << 2;
/// It takes media as unordered link datagrams (leviculum#102,
/// v0.34.0+ciris.2): its leviculum decodes `PacketContext::Datagram` and its
/// edge routes `NodeEvent::LinkDatagramReceived` to the A/V receive path.
pub const CAP_LINK_DATAGRAMS: u32 = 1 << 3;

/// It takes a layer cap on `SUBSCRIBE` (45.1) and applies it. OFF by
/// default until CC's 5.3.3.2.4 correction lands: only a node whose host
/// turned the lever on advertises it, and nobody sends a cap to a peer
/// without it.
pub const CAP_LAYER_REQUEST: u32 = 1 << 4;

/// It parses a v2 stream key binding (`ciris-edge:av-stream-key:v2`, the
/// binding that names the codec). A v1-only peer refuses a v2 binding as
/// malformed, so a publisher sends v2 only to a peer with this bit (and v1
/// to every peer).
pub const CAP_BINDING_V2: u32 = 1 << 5;

/// What this build advertises (relay added per call; `CAP_LAYER_REQUEST`
/// only behind the host's lever).
pub const CAPS_THIS_BUILD: u32 = CAP_C3_V1 | CAP_TIMED_FRAMES | CAP_LINK_DATAGRAMS | CAP_BINDING_V2;

const KIND_CAPS: u8 = 0x01;
const KIND_SUBSCRIBE: u8 = 0x02;
const KIND_UNSUBSCRIBE: u8 = 0x03;
const KIND_ADMIT: u8 = 0x04;
const KIND_REFUSE: u8 = 0x05;
const KIND_SHED: u8 = 0x06;
const KIND_OFFER: u8 = 0x07;

/// `SUBSCRIBE` flags: the requester can forward.
const SUB_FORWARD_CAPABLE: u8 = 1 << 0;
/// `SUBSCRIBE` flags: a layer cap follows.
const SUB_LAYER_CAP: u8 = 1 << 1;
/// The one layer-cap mode: at most these three maxima.
const LAYER_CAP_AT_MOST: u8 = 1;

/// Most ancestry entries an offer may carry.
pub const MAX_ANCESTRY: usize = 8;
/// Longest key id in an offer's ancestry.
pub const MAX_KEY_ID_LEN: usize = 256;

/// Whether a stream id would read as a C3 frame.
#[must_use]
pub fn collides_with_control_frame(stream: StreamId) -> bool {
    stream.0[..4] == CONTROL_MAGIC && stream.0[4] == CONTROL_VERSION
}

/// Whether `frame` is a C3 frame (by its tag).
#[must_use]
pub fn is_control_frame(frame: &[u8]) -> bool {
    frame.len() >= HEADER_LEN && frame[..4] == CONTROL_MAGIC && frame[4] == CONTROL_VERSION
}

/// Whether `frame` is one a periodic resend replaces (an `OFFER`): every
/// other kind changes state on one side only and must arrive.
#[must_use]
pub fn is_periodic(frame: &[u8]) -> bool {
    frame.len() > 5 && frame[5] == KIND_OFFER
}

/// A decoded C3 frame.
#[derive(Debug, Clone, PartialEq)]
pub enum WireFrame {
    /// The sender's capability bits.
    Caps(u32),
    /// A control message about one stream; peer fields are the link's peer.
    Control(super::ControlFrame<String>),
}

/// Why a frame was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// Not a C3 frame.
    #[error("not a C3 frame")]
    NotControl,
    /// A kind this build does not know.
    #[error("unknown C3 kind {0:#04x}")]
    UnknownKind(u8),
    /// Truncated, over-long, or a field out of range.
    #[error("malformed C3 frame")]
    Malformed,
}

impl WireError {
    /// The stable refusal token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::NotControl => "alm_c3_not_control",
            Self::UnknownKind(_) => "alm_c3_unknown_kind",
            Self::Malformed => "alm_c3_malformed",
        }
    }
}

fn header(kind: u8, cap: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(HEADER_LEN + cap);
    v.extend_from_slice(&CONTROL_MAGIC);
    v.push(CONTROL_VERSION);
    v.push(kind);
    v
}

const fn role_code(r: Role) -> u8 {
    match r {
        Role::Primary => 0,
        Role::Standby => 1,
    }
}

const fn role_of(c: u8) -> Option<Role> {
    match c {
        0 => Some(Role::Primary),
        1 => Some(Role::Standby),
        _ => None,
    }
}

/// Encode a `CAPS` frame.
#[must_use]
pub fn encode_caps(caps: u32) -> Vec<u8> {
    let mut v = header(KIND_CAPS, 4);
    v.extend_from_slice(&caps.to_be_bytes());
    v
}

/// Encode one control message about `stream`. The message's peer fields
/// (subscriber, offer `from`) are not encoded: the link names them.
#[must_use]
pub fn encode(stream: StreamId, msg: &ControlMsg<String>) -> Vec<u8> {
    match msg {
        ControlMsg::Subscribe(r) => {
            let mut v = header(KIND_SUBSCRIBE, 38);
            v.extend_from_slice(&stream.0);
            v.push(role_code(r.role));
            let fc = if r.forward_capable {
                SUB_FORWARD_CAPABLE
            } else {
                0
            };
            match r.layers {
                Some(p) => {
                    v.push(fc | SUB_LAYER_CAP);
                    v.extend_from_slice(&[
                        LAYER_CAP_AT_MOST,
                        p.max_spatial,
                        p.max_temporal,
                        p.max_quality,
                    ]);
                }
                None => v.push(fc),
            }
            v
        }
        ControlMsg::Unsubscribe { .. } => {
            let mut v = header(KIND_UNSUBSCRIBE, 32);
            v.extend_from_slice(&stream.0);
            v
        }
        ControlMsg::Decision(AdmitDecision::Admit { role }) => {
            let mut v = header(KIND_ADMIT, 33);
            v.extend_from_slice(&stream.0);
            v.push(role_code(*role));
            v
        }
        ControlMsg::Decision(AdmitDecision::Refuse {
            reason,
            retry_after_ms,
        }) => {
            let mut v = header(KIND_REFUSE, 37);
            v.extend_from_slice(&stream.0);
            v.push(reason.code());
            v.extend_from_slice(
                &u32::try_from(*retry_after_ms)
                    .unwrap_or(u32::MAX)
                    .to_be_bytes(),
            );
            v
        }
        ControlMsg::Shed { reason } => {
            let mut v = header(KIND_SHED, 33);
            v.extend_from_slice(&stream.0);
            v.push(reason.code());
            v
        }
        ControlMsg::Offer(o) => {
            let mut v = header(KIND_OFFER, 64);
            v.extend_from_slice(&stream.0);
            v.push(o.depth);
            v.push(u8::from(o.forwarding));
            v.extend_from_slice(&o.headroom_bps.to_be_bytes());
            v.extend_from_slice(&o.forwarder_headroom_bps.to_be_bytes());
            v.extend_from_slice(&o.upstream_latency_ms.to_be_bytes());
            let n = o.ancestry.len().min(MAX_ANCESTRY);
            v.push(u8::try_from(n).unwrap_or(0));
            for a in o.ancestry.iter().take(n) {
                let b = &a.as_bytes()[..a.len().min(MAX_KEY_ID_LEN)];
                v.extend_from_slice(&u16::try_from(b.len()).unwrap_or(0).to_be_bytes());
                v.extend_from_slice(b);
            }
            v
        }
    }
}

struct R<'a>(&'a [u8]);

impl R<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], WireError> {
        if self.0.len() < n {
            return Err(WireError::Malformed);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, WireError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64, WireError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }
    fn stream(&mut self) -> Result<StreamId, WireError> {
        let mut a = [0u8; 32];
        a.copy_from_slice(self.take(32)?);
        Ok(StreamId(a))
    }
    fn end(&self) -> Result<(), WireError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(WireError::Malformed)
        }
    }
}

/// Decode a frame heard from `peer` (the link's attributed peer, which fills
/// every peer field of the message).
///
/// # Errors
/// [`WireError`].
pub fn decode(frame: &[u8], peer: &str) -> Result<WireFrame, WireError> {
    if !is_control_frame(frame) {
        return Err(WireError::NotControl);
    }
    let kind = frame[5];
    let mut r = R(&frame[HEADER_LEN..]);
    let out = match kind {
        KIND_CAPS => WireFrame::Caps(r.u32()?),
        KIND_SUBSCRIBE => {
            let stream = r.stream()?;
            let role = role_of(r.u8()?).ok_or(WireError::Malformed)?;
            // Bits 2-7 are ignored (docs/alm_calm_wire.md §3): a later bit is
            // read as nothing, as a pre-45.1 decoder read bit 1.
            let flags = r.u8()?;
            let layers = if flags & SUB_LAYER_CAP == 0 {
                None
            } else {
                if r.u8()? != LAYER_CAP_AT_MOST {
                    return Err(WireError::Malformed);
                }
                Some(ReceiverLayerPolicy {
                    max_spatial: r.u8()?,
                    max_temporal: r.u8()?,
                    max_quality: r.u8()?,
                })
            };
            WireFrame::Control(super::ControlFrame {
                stream,
                msg: ControlMsg::Subscribe(SubscribeRequest {
                    subscriber: peer.to_owned(),
                    role,
                    forward_capable: flags & SUB_FORWARD_CAPABLE != 0,
                    layers,
                }),
            })
        }
        KIND_UNSUBSCRIBE => WireFrame::Control(super::ControlFrame {
            stream: r.stream()?,
            msg: ControlMsg::Unsubscribe {
                subscriber: peer.to_owned(),
            },
        }),
        KIND_ADMIT => {
            let stream = r.stream()?;
            let role = role_of(r.u8()?).ok_or(WireError::Malformed)?;
            WireFrame::Control(super::ControlFrame {
                stream,
                msg: ControlMsg::Decision(AdmitDecision::Admit { role }),
            })
        }
        KIND_REFUSE => {
            let stream = r.stream()?;
            let reason = RefuseReason::from_code(r.u8()?).ok_or(WireError::Malformed)?;
            let retry_after_ms = u64::from(r.u32()?);
            WireFrame::Control(super::ControlFrame {
                stream,
                msg: ControlMsg::Decision(AdmitDecision::Refuse {
                    reason,
                    retry_after_ms,
                }),
            })
        }
        KIND_SHED => {
            let stream = r.stream()?;
            let reason = ShedReason::from_code(r.u8()?).ok_or(WireError::Malformed)?;
            WireFrame::Control(super::ControlFrame {
                stream,
                msg: ControlMsg::Shed { reason },
            })
        }
        KIND_OFFER => {
            let stream = r.stream()?;
            let depth = r.u8()?;
            let forwarding = r.u8()? == 1;
            let headroom_bps = r.u64()?;
            let forwarder_headroom_bps = r.u64()?;
            let upstream_latency_ms = r.u32()?;
            let n = usize::from(r.u8()?);
            if n > MAX_ANCESTRY {
                return Err(WireError::Malformed);
            }
            let mut ancestry = Vec::with_capacity(n);
            for _ in 0..n {
                let len = usize::from(r.u16()?);
                if len == 0 || len > MAX_KEY_ID_LEN {
                    return Err(WireError::Malformed);
                }
                let s = std::str::from_utf8(r.take(len)?).map_err(|_| WireError::Malformed)?;
                ancestry.push(s.to_owned());
            }
            WireFrame::Control(super::ControlFrame {
                stream,
                msg: ControlMsg::Offer(Offer {
                    from: peer.to_owned(),
                    depth,
                    ancestry,
                    headroom_bps,
                    forwarder_headroom_bps,
                    upstream_latency_ms,
                    forwarding,
                }),
            })
        }
        k => return Err(WireError::UnknownKind(k)),
    };
    r.end()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s() -> StreamId {
        StreamId([7u8; 32])
    }

    #[allow(clippy::needless_pass_by_value)]
    fn rt(msg: ControlMsg<String>) {
        let bytes = encode(s(), &msg);
        assert!(is_control_frame(&bytes));
        let WireFrame::Control(f) = decode(&bytes, "peer-a").expect("decodes") else {
            panic!("not a control frame");
        };
        assert_eq!(f.stream, s());
        assert_eq!(f.msg, msg);
    }

    #[test]
    fn every_kind_round_trips_with_the_link_peer_filled_in() {
        rt(ControlMsg::Subscribe(SubscribeRequest {
            subscriber: "peer-a".into(),
            role: Role::Standby,
            forward_capable: true,
            layers: None,
        }));
        rt(ControlMsg::Unsubscribe {
            subscriber: "peer-a".into(),
        });
        rt(ControlMsg::Decision(AdmitDecision::Admit {
            role: Role::Primary,
        }));
        rt(ControlMsg::Decision(AdmitDecision::Refuse {
            reason: RefuseReason::ClassRefused,
            retry_after_ms: 1234,
        }));
        rt(ControlMsg::Shed {
            reason: ShedReason::LoadShed,
        });
        rt(ControlMsg::Offer(Offer {
            from: "peer-a".into(),
            depth: 2,
            ancestry: vec!["root".into(), "mid".into()],
            headroom_bps: 3_000_000,
            forwarder_headroom_bps: 4_000_000,
            upstream_latency_ms: 77,
            forwarding: true,
        }));
        rt(ControlMsg::Subscribe(SubscribeRequest {
            subscriber: "peer-a".into(),
            role: Role::Primary,
            forward_capable: false,
            layers: Some(ReceiverLayerPolicy {
                max_spatial: 1,
                max_temporal: 2,
                max_quality: 0,
            }),
        }));
        assert_eq!(
            decode(&encode_caps(CAPS_THIS_BUILD | CAP_RELAY), "x"),
            Ok(WireFrame::Caps(CAPS_THIS_BUILD | CAP_RELAY))
        );
    }

    #[test]
    fn the_sender_can_not_name_another_subscriber() {
        let bytes = encode(
            s(),
            &ControlMsg::Subscribe(SubscribeRequest {
                subscriber: "someone-else".into(),
                role: Role::Primary,
                forward_capable: false,
            }),
        );
        let Ok(WireFrame::Control(f)) = decode(&bytes, "the-link-peer") else {
            panic!()
        };
        assert!(matches!(
            f.msg,
            ControlMsg::Subscribe(SubscribeRequest { ref subscriber, .. }) if subscriber == "the-link-peer"
        ));
    }

    #[test]
    fn malformed_and_foreign_frames_are_refused_by_name() {
        let mut caps = encode_caps(1);
        caps.push(0);
        assert_eq!(decode(&caps, "p"), Err(WireError::Malformed));
        assert_eq!(decode(b"CSKB\x01xxxx", "p"), Err(WireError::NotControl));
        assert_eq!(
            decode(b"CALM\x01\x7f", "p"),
            Err(WireError::UnknownKind(0x7f))
        );
        let mut refuse = encode(
            s(),
            &ControlMsg::Decision(AdmitDecision::Refuse {
                reason: RefuseReason::Capacity,
                retry_after_ms: 1,
            }),
        );
        refuse[6 + 32] = 0xEE;
        assert_eq!(decode(&refuse, "p"), Err(WireError::Malformed));
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&CONTROL_MAGIC);
        id[4] = CONTROL_VERSION;
        assert!(collides_with_control_frame(StreamId(id)));
        assert!(!collides_with_control_frame(s()));
    }

    /// **CALM KAT vectors** (for the CC, `docs/alm_calm_wire.md` §7): one
    /// frame of each kind from fixed inputs, asserted byte-for-byte, and each
    /// decoding back with the LINK peer (`node-kat-b`) in every peer field.
    ///
    /// Inputs: stream `00 01 02 … 1f`; CAPS = C3 v1 | timed | relay (7);
    /// SUBSCRIBE standby, forward-capable; ADMIT primary; REFUSE
    /// `relay_class_refused:video` (code 5), retry 1500 ms; SHED
    /// `load_shed:audio` (code 3); OFFER depth 1, forwarding, headroom
    /// 2 000 000, forwarder headroom 3 000 000, upstream latency 42 ms,
    /// ancestry `["node-kat-a"]`.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn calm_kat_vectors() {
        type Case<'a> = (&'a str, Vec<u8>, Option<ControlMsg<String>>);
        let mut id = [0u8; 32];
        for (i, b) in id.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("small");
        }
        let st = StreamId(id);
        let peer = "node-kat-b";
        let msgs: Vec<Case<'_>> = vec![
            (
                "CAPS",
                encode_caps(CAP_C3_V1 | CAP_TIMED_FRAMES | CAP_RELAY),
                None,
            ),
            (
                "SUBSCRIBE",
                Vec::new(),
                Some(ControlMsg::Subscribe(SubscribeRequest {
                    subscriber: peer.into(),
                    role: Role::Standby,
                    forward_capable: true,
                })),
            ),
            (
                "UNSUBSCRIBE",
                Vec::new(),
                Some(ControlMsg::Unsubscribe {
                    subscriber: peer.into(),
                }),
            ),
            (
                "ADMIT",
                Vec::new(),
                Some(ControlMsg::Decision(AdmitDecision::Admit {
                    role: Role::Primary,
                })),
            ),
            (
                "REFUSE",
                Vec::new(),
                Some(ControlMsg::Decision(AdmitDecision::Refuse {
                    reason: RefuseReason::ClassRefused,
                    retry_after_ms: 1500,
                })),
            ),
            (
                "SHED",
                Vec::new(),
                Some(ControlMsg::Shed {
                    reason: ShedReason::LoadShed,
                }),
            ),
            (
                "OFFER",
                Vec::new(),
                Some(ControlMsg::Offer(Offer {
                    from: peer.into(),
                    depth: 1,
                    ancestry: vec!["node-kat-a".into()],
                    headroom_bps: 2_000_000,
                    forwarder_headroom_bps: 3_000_000,
                    upstream_latency_ms: 42,
                    forwarding: true,
                })),
            ),
        ];
        let want = [
            ("CAPS", "43414c4d010100000007"),
            ("SUBSCRIBE", "43414c4d0102000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0101"),
            ("UNSUBSCRIBE", "43414c4d0103000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            ("ADMIT", "43414c4d0104000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00"),
            ("REFUSE", "43414c4d0105000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f05000005dc"),
            ("SHED", "43414c4d0106000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f03"),
            ("OFFER", "43414c4d0107000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f010100000000001e848000000000002dc6c00000002a01000a6e6f64652d6b61742d61"),
        ];
        for ((name, caps_bytes, msg), (wname, whex)) in msgs.into_iter().zip(want) {
            assert_eq!(name, wname);
            let bytes = match &msg {
                Some(m) => encode(st, m),
                None => caps_bytes,
            };
            println!(
                "KAT CALM {name} ({} B) = {}",
                bytes.len(),
                hex::encode(&bytes)
            );
            assert_eq!(hex::encode(&bytes), whex, "KAT CALM {name}");
            match (decode(&bytes, peer).expect("decodes"), msg) {
                (WireFrame::Caps(c), None) => assert_eq!(c, 7),
                (WireFrame::Control(f), Some(m)) => {
                    assert_eq!(f.stream, st);
                    assert_eq!(f.msg, m);
                }
                other => panic!("{name}: {other:?}"),
            }
        }
    }

    /// KAT — the 45.1 SUBSCRIBE layer cap, byte for byte: stream 07 x 32,
    /// primary, forward-capable, at most (1, 2, 0). Also the frame without
    /// a cap (unchanged from v1, 40 bytes) and the refusals: mode 2 (audio
    /// only, off), any other mode, a short cap, and a trailing byte. An
    /// unknown flag bit is ignored, as the v1 rule says.
    #[test]
    fn subscribe_layer_cap_kat() {
        let req = |layers| {
            ControlMsg::Subscribe(SubscribeRequest {
                subscriber: "x".to_owned(),
                role: Role::Primary,
                forward_capable: true,
                layers,
            })
        };
        let cap = ReceiverLayerPolicy {
            max_spatial: 1,
            max_temporal: 2,
            max_quality: 0,
        };
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let with = encode(s(), &req(Some(cap)));
        assert_eq!(
            hex(&with),
            format!("43414c4d0102{}0003{}", "07".repeat(32), "01010200")
        );
        assert_eq!(with.len(), HEADER_LEN + 32 + 2 + 4);
        let without = encode(s(), &req(None));
        assert_eq!(
            hex(&without),
            format!("43414c4d0102{}0001", "07".repeat(32))
        );
        assert_eq!(
            decode(&with, "x"),
            Ok(WireFrame::Control(super::super::ControlFrame {
                stream: s(),
                msg: req(Some(cap)),
            }))
        );
        let cap_at = HEADER_LEN + 32 + 2;
        for mode in [0u8, 2, 3, 0xff] {
            let mut f = with.clone();
            f[cap_at] = mode;
            assert_eq!(decode(&f, "x"), Err(WireError::Malformed), "mode {mode}");
        }
        let mut f = with.clone();
        f[HEADER_LEN + 33] |= 1 << 2;
        assert_eq!(
            decode(&f, "x"),
            decode(&with, "x"),
            "an unknown flag bit is ignored"
        );
        assert_eq!(
            decode(&with[..with.len() - 1], "x"),
            Err(WireError::Malformed),
            "short cap"
        );
        let mut f = with;
        f.push(0);
        assert_eq!(decode(&f, "x"), Err(WireError::Malformed), "trailing byte");
    }
}
