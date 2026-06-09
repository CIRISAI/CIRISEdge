//! Wire-frame prefix for replication messages on the
//! [`crate::transport::Transport`] surface.
//!
//! Solves the inbound-dispatch question raised in PR #70 (`coordinator.rs`
//! module docs): the application's [`Transport::listen`] loop receives
//! bytes from a single channel that carries multiple payload kinds
//! (signed federation envelopes, replication protocol messages,
//! eventually key_grant blobs / takedown notices / etc.). The receiver
//! needs to route by payload kind without parsing every byte as every
//! possible shape.
//!
//! ## Design — magic-prefix dispatch
//!
//! Replication messages carry a 4-byte magic at the front:
//!
//! ```text
//!   ┌────┬──────────────────────────────────────────────┐
//!   │MAG │  ReplicationMessage::to_bytes() — JSON       │
//!   │ 4B │                                              │
//!   └────┴──────────────────────────────────────────────┘
//! ```
//!
//! The magic is `b"CRPL"` ("CIRis RePLication") — chosen because no
//! existing federation envelope shape starts with this prefix (signed
//! envelopes start with `{` for JSON, `0x80..0xBF` for CBOR map tags,
//! etc.).
//!
//! ## Why this and not a top-level FramedKind enum
//!
//! The alternative would be a `FramedKind { Envelope, Replication, ... }`
//! enum at the application/Transport boundary, with every send call
//! site wrapping its payload in the enum. That's *cleaner* but invasive
//! — every existing `Edge::send` / `dispatch_inbound` site would need
//! to learn the new wrapping convention. The magic-prefix approach is
//! **purely additive**: replication wraps its bytes, the existing send
//! paths stay unchanged, and the receiver's dispatcher does:
//!
//! ```text
//!   if bytes starts with REPLICATION_FRAME_MAGIC:
//!       hand to ReplicationCoordinator::feed_inbound_bytes
//!   else:
//!       existing signed-envelope dispatch (unchanged)
//! ```
//!
//! When future wire kinds need their own routing (key_grant streams,
//! takedown notices), they pick their own magic. The receiver's
//! dispatcher grows linearly — one branch per wire kind. The
//! `FramedKind` enum approach grows the same number of branches but
//! requires touching every existing send site to opt in; this approach
//! only touches the sites that need the new wire kind.

use super::protocol::{ProtocolError, ReplicationMessage};

/// 4-byte magic prefix that identifies a replication frame on the
/// transport. ASCII `CRPL` ("CIRis RePLication") — no signed federation
/// envelope shape starts with these four bytes, so the prefix is
/// unambiguously a replication frame.
pub const REPLICATION_FRAME_MAGIC: [u8; 4] = *b"CRPL";

/// Wrap a [`ReplicationMessage`] in the wire frame ready to hand to
/// [`crate::transport::Transport::send`]. Allocates one `Vec` of
/// exactly `4 + msg.to_bytes().len()` bytes.
pub fn wrap(msg: &ReplicationMessage) -> Vec<u8> {
    let body = msg.to_bytes();
    let mut out = Vec::with_capacity(REPLICATION_FRAME_MAGIC.len() + body.len());
    out.extend_from_slice(&REPLICATION_FRAME_MAGIC);
    out.extend_from_slice(&body);
    out
}

/// Inverse of [`wrap`]. Returns:
///
/// - `Ok(Some(msg))` — bytes start with [`REPLICATION_FRAME_MAGIC`]
///   and the JSON body decodes cleanly. The caller routes to the
///   replication path.
/// - `Ok(None)` — bytes don't start with the magic. The caller falls
///   through to its non-replication dispatch (existing signed-envelope
///   handler, key_grant handler, etc.).
/// - `Err(ProtocolError)` — bytes DO start with the magic but the JSON
///   body is malformed. This is a protocol violation by the sender; the
///   caller surfaces it (typically: drop the frame + log).
///
/// The trichotomy is deliberate: a non-replication frame is NOT an
/// error from this function's POV — it's a successful "this isn't
/// ours" answer. A malformed replication frame IS an error because the
/// magic prefix promised replication-shaped bytes that didn't deliver.
pub fn try_unwrap(bytes: &[u8]) -> Result<Option<ReplicationMessage>, ProtocolError> {
    if bytes.len() < REPLICATION_FRAME_MAGIC.len() {
        return Ok(None);
    }
    if bytes[..REPLICATION_FRAME_MAGIC.len()] != REPLICATION_FRAME_MAGIC {
        return Ok(None);
    }
    let body = &bytes[REPLICATION_FRAME_MAGIC.len()..];
    ReplicationMessage::from_bytes(body).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replication::protocol::{EnvelopeKind, SummaryMessage};

    /// wrap/try_unwrap round-trips a Summary message.
    #[test]
    fn wrap_unwrap_round_trip() {
        let msg = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Attestation,
            refs: vec![],
        });
        let framed = wrap(&msg);
        // First 4 bytes are the magic.
        assert_eq!(&framed[..4], &REPLICATION_FRAME_MAGIC);
        // try_unwrap recovers the original.
        let unwrapped = try_unwrap(&framed).expect("decode").expect("magic match");
        assert_eq!(unwrapped, msg);
    }

    /// Bytes without the magic prefix return `Ok(None)` — the caller
    /// routes to its non-replication dispatch.
    #[test]
    fn non_replication_bytes_yield_none() {
        // Signed federation envelopes typically start with `{` (JSON) or
        // similar — neither byte sequence collides with CRPL.
        let cases: &[&[u8]] = &[
            b"{\"agent\":\"alice\"}",
            b"\x80\xa1cfoo", // some CBOR-shaped bytes
            b"random garbage with no structure",
            b"CRP",   // 3-byte prefix — too short to even check the 4-byte magic
            b"CRPM!", // 4 bytes but not CRPL
            b"crpl",  // lowercase — case-sensitive, doesn't match
            b"",      // empty
        ];
        for bytes in cases {
            let r = try_unwrap(bytes).expect("not an error");
            assert!(r.is_none(), "expected None for {bytes:?}");
        }
    }

    /// Bytes with the magic but malformed JSON body yield
    /// `Err(ProtocolError)` — the sender broke the contract.
    #[test]
    fn magic_with_malformed_body_is_protocol_error() {
        let mut bytes = REPLICATION_FRAME_MAGIC.to_vec();
        bytes.extend_from_slice(b"{not valid json");
        let r = try_unwrap(&bytes);
        assert!(matches!(r, Err(ProtocolError::Decode(_))));
    }

    /// Bytes with the magic but with a JSON body that's a valid JSON
    /// object but NOT a `ReplicationMessage` (unknown tag) — same
    /// `Err(ProtocolError)` shape per [`ReplicationMessage::from_bytes`].
    #[test]
    fn magic_with_unknown_replication_tag_is_protocol_error() {
        let mut bytes = REPLICATION_FRAME_MAGIC.to_vec();
        bytes.extend_from_slice(br#"{"type":"hostile_takeover","payload":42}"#);
        let r = try_unwrap(&bytes);
        assert!(matches!(r, Err(ProtocolError::Decode(_))));
    }

    /// All four `ReplicationMessage` variants round-trip through
    /// wrap/try_unwrap.
    #[test]
    fn all_variants_round_trip() {
        use crate::replication::protocol::{
            DeliverMessage, DiffMessage, EnvelopeRef, FetchMessage,
        };
        let h = [7u8; 32];
        let cases = vec![
            ReplicationMessage::Summary(SummaryMessage {
                kind: EnvelopeKind::Key,
                refs: vec![EnvelopeRef {
                    envelope_hash: h,
                    seq: 1,
                }],
            }),
            ReplicationMessage::Diff(DiffMessage {
                kind: EnvelopeKind::Attestation,
                want: vec![h],
            }),
            ReplicationMessage::Fetch(FetchMessage {
                kind: EnvelopeKind::Revocation,
                want: vec![h, h],
            }),
            ReplicationMessage::Deliver(DeliverMessage {
                kind: EnvelopeKind::Community,
                envelopes: vec![b"signed_envelope_bytes".to_vec()],
            }),
        ];
        for msg in cases {
            let framed = wrap(&msg);
            let unwrapped = try_unwrap(&framed).expect("decode").expect("magic");
            assert_eq!(unwrapped, msg);
        }
    }

    /// Magic-prefix detection is robust against `bytes` shorter than
    /// the magic — no panic, no false-positive.
    #[test]
    fn short_input_safe() {
        for len in 0..REPLICATION_FRAME_MAGIC.len() {
            let r = try_unwrap(&REPLICATION_FRAME_MAGIC[..len]);
            assert!(matches!(r, Ok(None)));
        }
    }

    /// Magic ALONE (no body) is a protocol error — `from_bytes` on an
    /// empty buffer rejects.
    #[test]
    fn magic_only_no_body_is_protocol_error() {
        let bytes = REPLICATION_FRAME_MAGIC.to_vec();
        let r = try_unwrap(&bytes);
        assert!(matches!(r, Err(ProtocolError::Decode(_))));
    }
}
