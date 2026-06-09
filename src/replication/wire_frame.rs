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
//! ## Design — magic-prefix + version-byte dispatch (v1 wire format)
//!
//! Replication messages carry a 5-byte preamble at the front:
//!
//! ```text
//!   ┌────┬────┬──────────────────────────────────────────────┐
//!   │MAG │VER │  ReplicationMessage::to_bytes() — JSON       │
//!   │ 4B │ 1B │                                              │
//!   └────┴────┴──────────────────────────────────────────────┘
//! ```
//!
//! - `MAG` is `b"CRPL"` ("CIRis RePLication") — chosen because no
//!   existing federation envelope shape starts with this prefix
//!   (signed envelopes start with `{` for JSON, `0x80..0xBF` for
//!   CBOR map tags, etc.).
//! - `VER` is `WIRE_PROTOCOL_VERSION` (currently `0x01`) — locks v1
//!   wire-stable. See [`FSD/REPLICATION_WIRE_FORMAT_V1.md`](../../FSD/REPLICATION_WIRE_FORMAT_V1.md)
//!   §3.5. Future versions: `0x02` reserved for the CIRIS 2.0 cut
//!   when CIRISRegistry#58 Phase 2 operational-data envelopes
//!   (orgs / users / licenses / partners) need new
//!   [`super::EnvelopeKind`]s.
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
//!       version_byte = bytes[4]
//!       match version_byte:
//!           0x01 -> hand to ReplicationCoordinator (v1 codec)
//!           _    -> Err(UnknownVersion)
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
//!
//! ## Version-byte rollover (v1 → v2 path)
//!
//! Per FSD §5, v2 will introduce operational-data CEG envelopes
//! (orgs / users / licenses / partners) for Spock removal (CIRISRegistry
//! #58 Phase 2). A node speaking v2 will:
//!
//! - SEND `VER = 0x02` frames carrying the v2 codec (which may add
//!   message variants, new `EnvelopeKind`s, or change message
//!   field encodings)
//! - RECEIVE both `VER = 0x01` (legacy) and `VER = 0x02` frames; the
//!   `try_unwrap` dispatch routes by version
//!
//! v1 nodes that see `VER = 0x02` return `ProtocolError::UnknownVersion(0x02)`
//! and the round fails — the sender's scheduler observes the failure
//! and either drops the peer or downgrades. There's no silent
//! misinterpretation.

use super::protocol::{ProtocolError, ReplicationMessage};

/// 4-byte magic prefix that identifies a replication frame on the
/// transport. ASCII `CRPL` ("CIRis RePLication") — no signed federation
/// envelope shape starts with these four bytes, so the prefix is
/// unambiguously a replication frame.
pub const REPLICATION_FRAME_MAGIC: [u8; 4] = *b"CRPL";

/// Replication wire-protocol version. Locked to `0x01` for v1 per
/// `FSD/REPLICATION_WIRE_FORMAT_V1.md` §3.5. Bumps to `0x02` for
/// the CIRIS 2.0 cut (operational-data envelopes per
/// CIRISRegistry#58 Phase 2).
pub const WIRE_PROTOCOL_VERSION: u8 = 0x01;

/// Length of the wire-frame preamble (`MAG` + `VER`). The body
/// follows starting at offset `PREAMBLE_LEN`.
pub const PREAMBLE_LEN: usize = REPLICATION_FRAME_MAGIC.len() + 1;

/// Wrap a [`ReplicationMessage`] in the wire frame ready to hand to
/// [`crate::transport::Transport::send`]. Allocates one `Vec` of
/// exactly `PREAMBLE_LEN + msg.to_bytes().len()` bytes.
///
/// The frame uses the current [`WIRE_PROTOCOL_VERSION`] byte. To wrap
/// at a specific version (e.g. for cross-version interop testing),
/// use [`wrap_at_version`].
pub fn wrap(msg: &ReplicationMessage) -> Vec<u8> {
    wrap_at_version(msg, WIRE_PROTOCOL_VERSION)
}

/// Wrap a message at a specific protocol version. Production code
/// always wraps at `WIRE_PROTOCOL_VERSION` via [`wrap`]; this entry
/// point exists for tests + future cross-version interop drivers.
pub fn wrap_at_version(msg: &ReplicationMessage, version: u8) -> Vec<u8> {
    let body = msg.to_bytes();
    let mut out = Vec::with_capacity(PREAMBLE_LEN + body.len());
    out.extend_from_slice(&REPLICATION_FRAME_MAGIC);
    out.push(version);
    out.extend_from_slice(&body);
    out
}

/// Inverse of [`wrap`]. Returns:
///
/// - `Ok(Some(msg))` — bytes start with [`REPLICATION_FRAME_MAGIC`],
///   the version byte matches [`WIRE_PROTOCOL_VERSION`], and the JSON
///   body decodes cleanly. The caller routes to the replication path.
/// - `Ok(None)` — bytes don't start with the magic. The caller falls
///   through to its non-replication dispatch (existing signed-envelope
///   handler, key_grant handler, etc.).
/// - `Err(ProtocolError::UnknownVersion(v))` — bytes start with the
///   magic but the version byte is unrecognized. Protocol violation
///   or a peer running a newer wire codec; the caller drops the
///   frame + logs.
/// - `Err(ProtocolError::Decode(_))` — bytes have the magic + a known
///   version but the JSON body is malformed. Protocol violation by
///   the sender.
///
/// The four-way distinction is deliberate: a non-replication frame is
/// NOT an error (it's a successful "this isn't ours" answer); an
/// unknown-version frame IS an error (the magic promised replication-
/// shaped bytes but we can't speak that version yet); a malformed body
/// IS an error (sender broke its own contract).
pub fn try_unwrap(bytes: &[u8]) -> Result<Option<ReplicationMessage>, ProtocolError> {
    if bytes.len() < REPLICATION_FRAME_MAGIC.len() {
        return Ok(None);
    }
    if bytes[..REPLICATION_FRAME_MAGIC.len()] != REPLICATION_FRAME_MAGIC {
        return Ok(None);
    }
    if bytes.len() < PREAMBLE_LEN {
        // Magic present but no version byte — caller's framing is
        // broken or this is a pre-v1 dev frame. Treat as a protocol
        // error since the magic asserted "this is replication."
        return Err(ProtocolError::Decode(
            "replication frame truncated — magic present but version byte missing".into(),
        ));
    }
    let version = bytes[REPLICATION_FRAME_MAGIC.len()];
    if version != WIRE_PROTOCOL_VERSION {
        return Err(ProtocolError::UnknownVersion(version));
    }
    let body = &bytes[PREAMBLE_LEN..];
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
        // Fifth byte is the wire-protocol version.
        assert_eq!(framed[4], WIRE_PROTOCOL_VERSION);
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

    /// Bytes with the magic + correct version byte but malformed JSON
    /// body yield `Err(ProtocolError::Decode)` — the sender broke
    /// the contract.
    #[test]
    fn magic_with_malformed_body_is_protocol_error() {
        let mut bytes = REPLICATION_FRAME_MAGIC.to_vec();
        bytes.push(WIRE_PROTOCOL_VERSION);
        bytes.extend_from_slice(b"{not valid json");
        let r = try_unwrap(&bytes);
        assert!(matches!(r, Err(ProtocolError::Decode(_))));
    }

    /// Bytes with the magic + correct version but with a JSON body
    /// that's a valid JSON object but NOT a `ReplicationMessage`
    /// (unknown tag) — same `Err(ProtocolError::Decode)` shape per
    /// [`ReplicationMessage::from_bytes`].
    #[test]
    fn magic_with_unknown_replication_tag_is_protocol_error() {
        let mut bytes = REPLICATION_FRAME_MAGIC.to_vec();
        bytes.push(WIRE_PROTOCOL_VERSION);
        bytes.extend_from_slice(br#"{"type":"hostile_takeover","payload":42}"#);
        let r = try_unwrap(&bytes);
        assert!(matches!(r, Err(ProtocolError::Decode(_))));
    }

    /// Bytes with the magic but an unknown version byte yield
    /// `Err(ProtocolError::UnknownVersion(v))`. Exercises the v1→v2
    /// rollover path: a v1 receiver seeing a v2 frame surfaces the
    /// typed unknown-version error so the scheduler can decide
    /// whether to drop the peer or downgrade.
    #[test]
    fn unknown_version_byte_is_typed_error() {
        let mut v2_bytes = REPLICATION_FRAME_MAGIC.to_vec();
        v2_bytes.push(0x02); // v2 — not yet supported
        v2_bytes.extend_from_slice(br#"{"type":"summary","kind":"key","refs":[]}"#);
        let r = try_unwrap(&v2_bytes);
        assert!(matches!(r, Err(ProtocolError::UnknownVersion(0x02))));

        // Same for a future v0xFF — caps at u8 max.
        let mut vff_bytes = REPLICATION_FRAME_MAGIC.to_vec();
        vff_bytes.push(0xFF);
        vff_bytes.extend_from_slice(b"{}");
        let r = try_unwrap(&vff_bytes);
        assert!(matches!(r, Err(ProtocolError::UnknownVersion(0xFF))));
    }

    /// Magic present but truncated before the version byte yields a
    /// Decode error — magic asserted "this is replication" so the
    /// caller surfaces the protocol violation instead of silently
    /// treating it as non-replication.
    #[test]
    fn magic_without_version_byte_is_decode_error() {
        let bytes = REPLICATION_FRAME_MAGIC.to_vec(); // exactly 4 bytes, no VER
        let r = try_unwrap(&bytes);
        assert!(matches!(r, Err(ProtocolError::Decode(_))));
    }

    /// `wrap_at_version` lets test fixtures forge cross-version frames.
    /// Round-trip via the current version works; forged v2 frames
    /// surface UnknownVersion.
    #[test]
    fn wrap_at_version_forges_cross_version_frames() {
        let msg = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Key,
            refs: vec![],
        });
        // Current version — round-trips.
        let v1 = wrap_at_version(&msg, WIRE_PROTOCOL_VERSION);
        assert_eq!(try_unwrap(&v1).unwrap().unwrap(), msg);
        // Forged v2 — surfaces UnknownVersion.
        let v2 = wrap_at_version(&msg, 0x02);
        assert!(matches!(
            try_unwrap(&v2),
            Err(ProtocolError::UnknownVersion(0x02))
        ));
    }

    /// All four `ReplicationMessage` variants round-trip through
    /// wrap/try_unwrap. Exercises all 9 `EnvelopeKind` variants too
    /// — one per variant to catch any serde-tag regression.
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
                kind: EnvelopeKind::IdentityOccurrence,
                envelopes: vec![b"signed_envelope_bytes".to_vec()],
            }),
            ReplicationMessage::Summary(SummaryMessage {
                kind: EnvelopeKind::Family,
                refs: vec![],
            }),
            ReplicationMessage::Summary(SummaryMessage {
                kind: EnvelopeKind::Community,
                refs: vec![],
            }),
            ReplicationMessage::Summary(SummaryMessage {
                kind: EnvelopeKind::IdentityOccurrenceRevocation,
                refs: vec![],
            }),
            ReplicationMessage::Summary(SummaryMessage {
                kind: EnvelopeKind::FamilyMembershipRevocation,
                refs: vec![],
            }),
            ReplicationMessage::Summary(SummaryMessage {
                kind: EnvelopeKind::CommunityMembershipRevocation,
                refs: vec![],
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
