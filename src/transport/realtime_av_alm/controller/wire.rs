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
//! SUBSCRIBE   0x02  stream[32] ‖ role u8 ‖ flags u8 (bit 0: forward-capable)
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
//! v0.33+), so media to it may ride `try_send_timed`.
//!
//! A stream id whose first five bytes read `"CALM" 0x01` is never minted
//! ([`collides_with_control_frame`]), so a chunk is never taken for a frame.

use super::{AdmitDecision, ControlMsg, Offer, RefuseReason, Role, ShedReason, SubscribeRequest};
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

/// What this build advertises (relay added per call).
pub const CAPS_THIS_BUILD: u32 = CAP_C3_V1 | CAP_TIMED_FRAMES;

const KIND_CAPS: u8 = 0x01;
const KIND_SUBSCRIBE: u8 = 0x02;
const KIND_UNSUBSCRIBE: u8 = 0x03;
const KIND_ADMIT: u8 = 0x04;
const KIND_REFUSE: u8 = 0x05;
const KIND_SHED: u8 = 0x06;
const KIND_OFFER: u8 = 0x07;

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
            let mut v = header(KIND_SUBSCRIBE, 34);
            v.extend_from_slice(&stream.0);
            v.push(role_code(r.role));
            v.push(u8::from(r.forward_capable));
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
            let flags = r.u8()?;
            WireFrame::Control(super::ControlFrame {
                stream,
                msg: ControlMsg::Subscribe(SubscribeRequest {
                    subscriber: peer.to_owned(),
                    role,
                    forward_capable: flags & 1 == 1,
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
}
