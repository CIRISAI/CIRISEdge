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
//! ## Version-byte rollover (v1 → v2 path — ACTIVE per v2.0.0)
//!
//! v2 introduces 3 operational-data CEG envelopes per CEG 1.0-RC2
//! §5.6.8.13 (CIRISRegistry#70): `organization` / `org_membership` /
//! `partner_record` (User PII never federates; License+Partner collapse
//! into PartnerRecord per FSD §5.2). A v2 node:
//!
//! - SENDS `VER = 0x02` frames carrying messages whose `kind` is one
//!   of the 3 operational variants. The v1 message shapes
//!   (Summary/Diff/Fetch/Deliver) are unchanged — v2 reuses them.
//! - SENDS `VER = 0x01` frames for the 10 v1 kinds (Key through
//!   LocationProof) — preserves v1 peer interop without a flag-day.
//!   The version selection is per-message, keyed off the message's
//!   `EnvelopeKind`. See [`wrap_for_kind`].
//! - RECEIVES both `VER = 0x01` and `VER = 0x02` frames; [`try_unwrap`]
//!   dispatches both. Body decode is identical for both versions —
//!   the version byte's purpose is the kind-tag namespace it permits.
//!
//! v1 nodes that see `VER = 0x02` return `ProtocolError::UnknownVersion(0x02)`
//! and drop the frame. v1 nodes that receive a `VER = 0x01` frame
//! carrying an unknown kind tag (one of the 3 v2 variants) return
//! `ProtocolError::Decode` at serde — this can't happen if the sender
//! routes via [`wrap_for_kind`] (it never emits v2 kinds at v1
//! framing), but the receiver's defense-in-depth catches a
//! misconfigured peer.
//!
//! ## v2 envelope_hash basis is JCS — at the bridge layer, not here
//!
//! Per FSD §3.2.2, v2's `envelope_hash` is `sha256(JCS(Signed*Record))`
//! for the 3 operational kinds — closes the §3.2.1 deferred-interop
//! path. This module is wire-layer plumbing; the JCS computation lives
//! in the bridge (`bridge::v2_envelope_hash`). The v1 trust kinds
//! continue to use `persist_row_hash` per FSD §3.1 (v1 wire stays
//! unchanged, peer-by-peer compatible).

use super::protocol::{ProtocolError, ReplicationMessage};

/// 4-byte magic prefix that identifies a replication frame on the
/// transport. ASCII `CRPL` ("CIRis RePLication") — no signed federation
/// envelope shape starts with these four bytes, so the prefix is
/// unambiguously a replication frame.
pub const REPLICATION_FRAME_MAGIC: [u8; 4] = *b"CRPL";

/// Replication wire-protocol version for v1 — the 10 trust-data kinds
/// (Key / Attestation / Revocation / IdentityOccurrence / Family /
/// Community / IdentityOccurrenceRevocation / FamilyMembershipRevocation /
/// CommunityMembershipRevocation / LocationProof). Locked per
/// `FSD/REPLICATION_WIRE_FORMAT_V1.md` §3.5; remains wire-stable
/// indefinitely so v1 peers stay interoperable across the v1→v2
/// transition (FSD §3.7).
pub const WIRE_PROTOCOL_VERSION: u8 = 0x01;

/// Replication wire-protocol version for v2 — adds the 3 operational-
/// data kinds (Organization / OrgMembership / PartnerRecord) per CEG
/// 1.0-RC2 §5.6.8.13 (CIRISRegistry#70). v2 reuses the v1 message
/// shapes (Summary / Diff / Fetch / Deliver) but extends the
/// [`super::EnvelopeKind`] tag namespace; the version byte's role is
/// to gate which tags the receiver expects.
///
/// FSD §3.2.2 also flips the `envelope_hash` basis for v2-emitted
/// envelopes from `persist_row_hash` to `sha256(JCS(Signed*Record))`
/// — the JCS computation lives in
/// [`crate::replication::bridge`] (the v2 hash basis is a bridge
/// concern, not a wire-frame concern; this module just routes the
/// version byte).
pub const WIRE_PROTOCOL_VERSION_V2: u8 = 0x02;

/// Length of the wire-frame preamble (`MAG` + `VER`). The body
/// follows starting at offset `PREAMBLE_LEN`.
pub const PREAMBLE_LEN: usize = REPLICATION_FRAME_MAGIC.len() + 1;

/// Wrap a [`ReplicationMessage`] in the wire frame ready to hand to
/// [`crate::transport::Transport::send`]. Allocates one `Vec` of
/// exactly `PREAMBLE_LEN + msg.to_bytes().len()` bytes.
///
/// **Defaults to v1 framing.** For v2.0.0+ correct outbound version
/// selection (per the FSD §3.7 peer-by-peer transition), use
/// [`wrap_for_kind`] — it picks the wire version automatically based
/// on the message's [`super::EnvelopeKind`]. Direct use of `wrap` is
/// safe for code that knows it's exchanging v1-only kinds.
pub fn wrap(msg: &ReplicationMessage) -> Vec<u8> {
    wrap_at_version(msg, WIRE_PROTOCOL_VERSION)
}

/// Wrap a [`ReplicationMessage`] at the wire version appropriate for
/// its [`super::EnvelopeKind`].
///
/// The 10 v1 kinds emit at `0x01`; the 3 v2 operational kinds
/// (Organization / OrgMembership / PartnerRecord) emit at `0x02`. The
/// version selection is per-message — a sender freely mixes v1 frames
/// and v2 frames within the same peer connection, and the receiver's
/// [`try_unwrap`] dispatch handles both. This is the FSD §3.7 peer-by-
/// peer transition mechanism: v1-only peers reject v2-framed messages
/// at the UnknownVersion error, but continue to handle v1 frames
/// from the same v2-capable sender.
///
/// All `ReplicationMessage` variants carry their `kind` in their inner
/// payload; this helper extracts it via [`ReplicationMessage::kind`].
pub fn wrap_for_kind(msg: &ReplicationMessage) -> Vec<u8> {
    wrap_at_version(msg, msg.kind().min_wire_version())
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
    // v2.0.0 (CEG 1.0-RC2 §5.6.8.13 / FSD §5.2) — accept both v1 and v2
    // framing. The message body decode is version-agnostic; the version
    // byte gates which kind-tag namespace the receiver expects. A
    // mismatched body (e.g. a v2 kind tag in a v1 frame, which a
    // well-behaved sender never emits but a misconfigured peer might)
    // surfaces as `ProtocolError::Decode` at the serde layer below.
    if version != WIRE_PROTOCOL_VERSION && version != WIRE_PROTOCOL_VERSION_V2 {
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
    /// `Err(ProtocolError::UnknownVersion(v))`. Exercises the v2→v3+
    /// rollover path: a v2 receiver seeing a v3 frame surfaces the
    /// typed unknown-version error so the scheduler can decide
    /// whether to drop the peer or downgrade. v1 + v2 are both
    /// recognized as of v2.0.0 (FSD §3.7 peer-by-peer transition).
    #[test]
    fn unknown_version_byte_is_typed_error() {
        // v3 — reserved for a future cut beyond CEG 1.0-RC2.
        let mut v3_bytes = REPLICATION_FRAME_MAGIC.to_vec();
        v3_bytes.push(0x03);
        v3_bytes.extend_from_slice(br#"{"type":"summary","kind":"key","refs":[]}"#);
        let r = try_unwrap(&v3_bytes);
        assert!(matches!(r, Err(ProtocolError::UnknownVersion(0x03))));

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
    /// Round-trip via either recognized version works; forged v3+
    /// frames surface UnknownVersion.
    #[test]
    fn wrap_at_version_forges_cross_version_frames() {
        let msg = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Key,
            refs: vec![],
        });
        // v1 — round-trips (v1 trust kind on v1 framing).
        let v1 = wrap_at_version(&msg, WIRE_PROTOCOL_VERSION);
        assert_eq!(try_unwrap(&v1).unwrap().unwrap(), msg);
        // v2 — also round-trips (v2 receiver accepts v1 kinds at v2
        // framing too; the version byte gates which tags are
        // permitted, not which message shapes).
        let v2 = wrap_at_version(&msg, WIRE_PROTOCOL_VERSION_V2);
        assert_eq!(try_unwrap(&v2).unwrap().unwrap(), msg);
        // Forged v3 — surfaces UnknownVersion.
        let v3 = wrap_at_version(&msg, 0x03);
        assert!(matches!(
            try_unwrap(&v3),
            Err(ProtocolError::UnknownVersion(0x03))
        ));
    }

    /// All four `ReplicationMessage` variants round-trip through
    /// wrap/try_unwrap. Exercises all 13 `EnvelopeKind` variants (10 v1
    /// trust kinds + 3 v2 operational kinds) — one per variant to catch
    /// any serde-tag regression. v2 kinds wrap via `wrap_for_kind`
    /// (auto-selects 0x02 framing per their `min_wire_version`).
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
            ReplicationMessage::Summary(SummaryMessage {
                kind: EnvelopeKind::LocationProof,
                refs: vec![],
            }),
            // v2 kinds — round-trip via wrap_for_kind (selects 0x02).
            ReplicationMessage::Summary(SummaryMessage {
                kind: EnvelopeKind::Organization,
                refs: vec![EnvelopeRef {
                    envelope_hash: h,
                    seq: 1,
                }],
            }),
            ReplicationMessage::Diff(DiffMessage {
                kind: EnvelopeKind::OrgMembership,
                want: vec![h],
            }),
            ReplicationMessage::Deliver(DeliverMessage {
                kind: EnvelopeKind::PartnerRecord,
                envelopes: vec![b"signed_partner_bytes".to_vec()],
            }),
        ];
        for msg in cases {
            let framed = wrap_for_kind(&msg);
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

    /// v2.0.0 / FSD §3.7 — `wrap_for_kind` selects the version byte
    /// per the message's [`EnvelopeKind::min_wire_version`]: 0x01 for
    /// the 10 v1 trust kinds, 0x02 for the 3 v2 operational kinds.
    #[test]
    fn wrap_for_kind_selects_version_per_kind() {
        // v1 trust kind → 0x01 framing.
        let msg_v1 = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Key,
            refs: vec![],
        });
        let framed = wrap_for_kind(&msg_v1);
        assert_eq!(framed[REPLICATION_FRAME_MAGIC.len()], WIRE_PROTOCOL_VERSION);

        // v2 operational kind → 0x02 framing.
        let msg_v2 = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Organization,
            refs: vec![],
        });
        let framed = wrap_for_kind(&msg_v2);
        assert_eq!(
            framed[REPLICATION_FRAME_MAGIC.len()],
            WIRE_PROTOCOL_VERSION_V2
        );

        // OrgMembership → 0x02.
        let msg_v2 = ReplicationMessage::Diff(crate::replication::protocol::DiffMessage {
            kind: EnvelopeKind::OrgMembership,
            want: vec![],
        });
        let framed = wrap_for_kind(&msg_v2);
        assert_eq!(
            framed[REPLICATION_FRAME_MAGIC.len()],
            WIRE_PROTOCOL_VERSION_V2
        );

        // PartnerRecord → 0x02.
        let msg_v2 = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::PartnerRecord,
            refs: vec![],
        });
        let framed = wrap_for_kind(&msg_v2);
        assert_eq!(
            framed[REPLICATION_FRAME_MAGIC.len()],
            WIRE_PROTOCOL_VERSION_V2
        );
    }

    /// v2.0.0 acceptance: v2 framing also round-trips the v1 trust
    /// kinds (the version byte gates which tags are *permitted*, not
    /// which message *shapes*). This guarantees a v2-capable sender
    /// can address a v2-capable peer with v1-kind messages under v2
    /// framing without spec drift.
    #[test]
    fn v2_framing_accepts_v1_kinds() {
        let msg = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Key,
            refs: vec![],
        });
        let v2 = wrap_at_version(&msg, WIRE_PROTOCOL_VERSION_V2);
        let unwrapped = try_unwrap(&v2).expect("decode").expect("magic");
        assert_eq!(unwrapped, msg);
    }
}
