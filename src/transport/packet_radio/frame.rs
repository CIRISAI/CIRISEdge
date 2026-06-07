//! Wire-frame codec for the packet-radio transport.
//!
//! The framer wraps a federation envelope with the bare minimum a
//! datagram-over-radio medium needs to deliver it reliably:
//!
//! ```text
//!   0    4               20       28        32                32+payload_len   end
//!   ┌────┬───────────────┬────────┬─────────┬─────────────────┬────────────────┐
//!   │MAG │  destination  │  seq   │payload  │   payload       │   crc32        │
//!   │ 4B │     16B       │  8B u64│  4B u32 │   ...           │   4B IEEE      │
//!   └────┴───────────────┴────────┴─────────┴─────────────────┴────────────────┘
//! ```
//!
//! - **`MAG`** is a fixed 4-byte sync word so a noisy radio receiver
//!   can resynchronize on frame boundaries without false-positives
//!   gating on payload content.
//! - **`destination`** is [`crate::transport::addressing::destination_from_pubkey_bytes`]
//!   over the recipient's federation pubkey — 16 bytes, sha256-
//!   truncated. Closes N1 of CIRISEdge#53.
//! - **`seq`** is the sender's per-(destination) monotonic counter,
//!   fed to the receiver's [`crate::transport::addressing::ReplayWindow`]
//!   for anti-replay.
//! - **`payload_len`** is u32-be; max value bounded by [`MAX_PAYLOAD_LEN`]
//!   (256 KiB — well above any expected federation envelope, well below
//!   memory-pressure thresholds even on small embedded radios).
//! - **`crc32`** is a CRC-32 IEEE checksum over the entire prefix +
//!   payload. The CRC is for *transport-layer corruption detection only*
//!   — security integrity is the outer AEAD's job (CIRISEdge#54 KEX
//!   session-key over [`crate::transport::realtime_av`] framing, or
//!   the application-layer signed envelope inside `payload`).
//!
//! ## Why this shape and not COBS / HDLC / SLIP
//!
//! Packet radios divide neatly into "the modem hands you bytes; you
//! frame them in software" vs "the modem already frames for you". The
//! commodity Semtech SX127x / SX126x LoRa families fall in the second
//! bucket (the modem delivers complete LoRa packets, max 255 bytes
//! payload, with on-chip CRC). For those, this framer's job is purely
//! to wrap the *application* envelope with enough metadata for the
//! receiver to route it — the on-air framing is the modem's problem.
//!
//! For the "raw byte stream" case (serial-attached AX.25, half-duplex
//! VHF data modes), a separate `byte_stream` adapter would COBS-stuff
//! these frames into a stream. That adapter is not part of this PR;
//! the [`PacketRadioDriver`] trait abstracts over both shapes.
//!
//! ## Security note
//!
//! A frame whose CRC checks but whose AEAD payload doesn't decrypt is
//! the in-band tamper case. The transport surfaces it as a successful
//! `decode_frame` (the bytes were on-wire correct) and the application
//! layer rejects on AEAD failure. This is intentional: CRC isn't a MAC,
//! and pretending otherwise would invite a bad-protocol-design
//! anti-pattern where consumers gate trust on CRC validity.

use crc32fast::Hasher;

/// 4-byte magic: ASCII "CIRP" ("CIRIS-Packet-radio"). Lets a receiver
/// resync after noise.
pub const FRAME_MAGIC: [u8; 4] = *b"CIRP";

/// Header is fixed-size: magic + destination + seq + payload_len.
pub const HEADER_LEN: usize = 4 + 16 + 8 + 4;

/// Trailer is the CRC-32 over everything that precedes it.
pub const TRAILER_LEN: usize = 4;

/// Minimum frame size = header + trailer (an empty payload is valid;
/// the application layer decides whether to emit one).
pub const MIN_FRAME_LEN: usize = HEADER_LEN + TRAILER_LEN;

/// Soft cap on payload size. 256 KiB is well above a federation
/// envelope's plausible size (signatures + body + canonical-bytes
/// padding) and well below what an embedded radio host can buffer.
/// Frames larger than this are rejected at encode time so a buggy
/// caller can't strand a multi-MB allocation in the radio's transmit
/// queue.
pub const MAX_PAYLOAD_LEN: usize = 256 * 1024;

/// A decoded frame, exposing the fields the transport layer cares
/// about. The payload is borrowed from the source byte slice when
/// `decode_frame_view` is used (zero-copy receive path); `decode_frame`
/// is the owned variant that allocates.
#[derive(Debug, PartialEq, Eq)]
pub struct DecodedFrame<'a> {
    pub destination: [u8; 16],
    pub seq: u64,
    pub payload: &'a [u8],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame too short: got {got} bytes, need at least {need}")]
    TooShort { got: usize, need: usize },
    #[error("magic mismatch: got {got:?}, expected {expected:?}")]
    BadMagic { got: [u8; 4], expected: [u8; 4] },
    #[error("payload length {len} exceeds maximum {max}")]
    PayloadTooLarge { len: usize, max: usize },
    #[error(
        "payload length {claimed} doesn't match frame size (frame has {actual} payload bytes)"
    )]
    PayloadLenMismatch { claimed: usize, actual: usize },
    #[error("crc mismatch: got {got:#010x}, computed {computed:#010x}")]
    BadCrc { got: u32, computed: u32 },
}

/// Encode an envelope into a frame ready to hand to a
/// [`crate::transport::packet_radio::driver::PacketRadioDriver::send_frame`].
///
/// Allocates one `Vec` of exactly `HEADER_LEN + payload.len() + TRAILER_LEN`
/// bytes. Returns `Err(FrameError::PayloadTooLarge)` if `payload`
/// exceeds [`MAX_PAYLOAD_LEN`].
pub fn encode_frame(
    destination: &[u8; 16],
    seq: u64,
    payload: &[u8],
) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(FrameError::PayloadTooLarge {
            len: payload.len(),
            max: MAX_PAYLOAD_LEN,
        });
    }
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len() + TRAILER_LEN);
    out.extend_from_slice(&FRAME_MAGIC);
    out.extend_from_slice(destination);
    out.extend_from_slice(&seq.to_be_bytes());
    // `payload.len()` is bounded by MAX_PAYLOAD_LEN above (well under u32::MAX),
    // so the truncation cannot occur in practice; assert it for compiler proof.
    let payload_len_u32 = u32::try_from(payload.len()).expect("bounded by MAX_PAYLOAD_LEN");
    out.extend_from_slice(&payload_len_u32.to_be_bytes());
    out.extend_from_slice(payload);
    let mut hasher = Hasher::new();
    hasher.update(&out);
    let crc = hasher.finalize();
    out.extend_from_slice(&crc.to_be_bytes());
    Ok(out)
}

/// Zero-copy decode: returns a view into the source buffer. Use this
/// on the receive path where the source buffer outlives the decoded
/// view. `decode_frame` is the owned variant.
pub fn decode_frame_view(bytes: &[u8]) -> Result<DecodedFrame<'_>, FrameError> {
    if bytes.len() < MIN_FRAME_LEN {
        return Err(FrameError::TooShort {
            got: bytes.len(),
            need: MIN_FRAME_LEN,
        });
    }
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&bytes[0..4]);
    if magic != FRAME_MAGIC {
        return Err(FrameError::BadMagic {
            got: magic,
            expected: FRAME_MAGIC,
        });
    }
    let mut destination = [0u8; 16];
    destination.copy_from_slice(&bytes[4..20]);
    let mut seq_bytes = [0u8; 8];
    seq_bytes.copy_from_slice(&bytes[20..28]);
    let seq = u64::from_be_bytes(seq_bytes);
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&bytes[28..32]);
    let payload_len = u32::from_be_bytes(len_bytes) as usize;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(FrameError::PayloadTooLarge {
            len: payload_len,
            max: MAX_PAYLOAD_LEN,
        });
    }
    let expected_total = HEADER_LEN + payload_len + TRAILER_LEN;
    if bytes.len() != expected_total {
        // Frame's claimed payload length doesn't match the actual buffer.
        // This is most often a truncated frame from a noisy radio link;
        // the alternative interpretation is "extra garbage past the
        // frame," equally a corruption signal.
        return Err(FrameError::PayloadLenMismatch {
            claimed: payload_len,
            actual: bytes.len().saturating_sub(HEADER_LEN + TRAILER_LEN),
        });
    }
    let payload = &bytes[HEADER_LEN..HEADER_LEN + payload_len];
    let mut hasher = Hasher::new();
    hasher.update(&bytes[..HEADER_LEN + payload_len]);
    let computed = hasher.finalize();
    let mut crc_bytes = [0u8; 4];
    crc_bytes.copy_from_slice(&bytes[HEADER_LEN + payload_len..HEADER_LEN + payload_len + 4]);
    let got = u32::from_be_bytes(crc_bytes);
    if got != computed {
        return Err(FrameError::BadCrc { got, computed });
    }
    Ok(DecodedFrame {
        destination,
        seq,
        payload,
    })
}

/// Owned form of the decoded frame — same fields as
/// [`DecodedFrame`] but with a copied payload, suitable for handing
/// off to another tokio task.
#[derive(Debug, PartialEq, Eq)]
pub struct OwnedDecodedFrame {
    pub destination: [u8; 16],
    pub seq: u64,
    pub payload: Vec<u8>,
}

/// Owned decode — copies the payload into its own `Vec` so the caller
/// can drop the source buffer. Convenience over `decode_frame_view`
/// for the listen-loop path that hands the bytes off to a different
/// task.
pub fn decode_frame(bytes: &[u8]) -> Result<OwnedDecodedFrame, FrameError> {
    let view = decode_frame_view(bytes)?;
    Ok(OwnedDecodedFrame {
        destination: view.destination,
        seq: view.seq,
        payload: view.payload.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_dest() -> [u8; 16] {
        let mut d = [0u8; 16];
        for (i, b) in d.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xFF).unwrap().wrapping_mul(7);
        }
        d
    }

    /// Round-trip — the frame encodes and decodes byte-exact.
    #[test]
    fn encode_decode_round_trip() {
        let dest = fake_dest();
        let payload = b"hello federation, this is a signed envelope";
        let frame = encode_frame(&dest, 42, payload).expect("encode");
        let view = decode_frame_view(&frame).expect("decode");
        assert_eq!(view.destination, dest);
        assert_eq!(view.seq, 42);
        assert_eq!(view.payload, payload);
    }

    /// Empty payload is valid (no application use case today but the
    /// protocol shouldn't reject it — frame metadata IS the message).
    #[test]
    fn empty_payload_round_trips() {
        let dest = fake_dest();
        let frame = encode_frame(&dest, 0, b"").expect("encode");
        assert_eq!(frame.len(), MIN_FRAME_LEN);
        let view = decode_frame_view(&frame).expect("decode");
        assert_eq!(view.payload, b"");
    }

    /// Max-size payload — encode succeeds, decode succeeds.
    #[test]
    fn max_payload_round_trips() {
        let dest = fake_dest();
        let payload = vec![0xAB; MAX_PAYLOAD_LEN];
        let frame = encode_frame(&dest, u64::MAX, &payload).expect("encode");
        let view = decode_frame_view(&frame).expect("decode");
        assert_eq!(view.seq, u64::MAX);
        assert_eq!(view.payload.len(), MAX_PAYLOAD_LEN);
    }

    /// One-over-max-size payload — encode refuses.
    #[test]
    fn oversize_payload_refused_at_encode() {
        let dest = fake_dest();
        let payload = vec![0u8; MAX_PAYLOAD_LEN + 1];
        let r = encode_frame(&dest, 0, &payload);
        assert!(
            matches!(
                r,
                Err(FrameError::PayloadTooLarge {
                    len,
                    max
                }) if len == MAX_PAYLOAD_LEN + 1 && max == MAX_PAYLOAD_LEN
            ),
            "got {r:?}"
        );
    }

    /// Truncated frame — too short for even the header.
    #[test]
    fn truncated_frame_refused() {
        let r = decode_frame_view(&[0u8; MIN_FRAME_LEN - 1]);
        assert!(matches!(r, Err(FrameError::TooShort { .. })));
    }

    /// Magic mismatch — receiver was synced wrong, frame should refuse
    /// before computing the CRC (so the receiver knows it's resync,
    /// not corruption).
    #[test]
    fn bad_magic_refused() {
        let dest = fake_dest();
        let mut frame = encode_frame(&dest, 1, b"x").expect("encode");
        frame[0] = b'X'; // corrupt the magic
        let r = decode_frame_view(&frame);
        assert!(matches!(r, Err(FrameError::BadMagic { .. })));
    }

    /// CRC tamper — flipping a single payload bit must fail decode.
    /// This is the transport-layer corruption-detection contract.
    #[test]
    fn payload_corruption_caught_by_crc() {
        let dest = fake_dest();
        let payload = b"the bytes that matter";
        let mut frame = encode_frame(&dest, 1, payload).expect("encode");
        // Flip a bit in the payload region.
        let payload_start = HEADER_LEN;
        frame[payload_start] ^= 0x01;
        let r = decode_frame_view(&frame);
        assert!(matches!(r, Err(FrameError::BadCrc { .. })));
    }

    /// CRC tamper — same shape, header byte flipped (still detected).
    #[test]
    fn header_corruption_caught_by_crc() {
        let dest = fake_dest();
        let mut frame = encode_frame(&dest, 1, b"x").expect("encode");
        // Flip a bit in the seq region.
        frame[20] ^= 0x80;
        let r = decode_frame_view(&frame);
        assert!(matches!(r, Err(FrameError::BadCrc { .. })));
    }

    /// Length mismatch — receiver got a frame whose claimed payload
    /// length doesn't match its actual buffer size.
    #[test]
    fn length_mismatch_refused() {
        let dest = fake_dest();
        let frame = encode_frame(&dest, 1, b"hello").expect("encode");
        let truncated = &frame[..frame.len() - 1];
        let r = decode_frame_view(truncated);
        // Either PayloadLenMismatch or BadCrc — both are correct refusals.
        // (Depending on whether the missing byte was payload or trailer.)
        assert!(
            matches!(
                r,
                Err(FrameError::PayloadLenMismatch { .. } | FrameError::BadCrc { .. })
            ),
            "got {r:?}"
        );
    }

    /// Per-frame CRC depends on the seq number, so two frames with
    /// identical payloads but different seqs produce different bytes
    /// (anti-replay relies on this — a replayed frame would have the
    /// same seq, no point in tampering it).
    #[test]
    fn seq_change_changes_crc() {
        let dest = fake_dest();
        let payload = b"identical payload";
        let f1 = encode_frame(&dest, 1, payload).expect("encode 1");
        let f2 = encode_frame(&dest, 2, payload).expect("encode 2");
        assert_ne!(f1, f2);
    }

    /// owned vs zero-copy decode produce equivalent results.
    #[test]
    fn owned_decode_matches_view_decode() {
        let dest = fake_dest();
        let payload = b"compare paths";
        let frame = encode_frame(&dest, 7, payload).expect("encode");
        let view = decode_frame_view(&frame).expect("view decode");
        let owned = decode_frame(&frame).expect("owned decode");
        assert_eq!(owned.destination, view.destination);
        assert_eq!(owned.seq, view.seq);
        assert_eq!(owned.payload, view.payload);
    }
}
