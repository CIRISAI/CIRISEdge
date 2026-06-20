//! §3.1 fixed-size emission envelope (CIRISEdge#175, v6.1.0).
//!
//! Every outbound substrate envelope — real and synthetic cover —
//! conforms to this shape:
//!
//! ```text
//!   ┌─────────────┬──────────────────────────────────────────────────┐
//!   │  24-byte    │  XChaCha20-Poly1305(scope_key, nonce,            │
//!   │  XChaCha    │      EmissionHeader || payload_chunk             │
//!   │  nonce      │  ) || 16-byte tag                                │
//!   └─────────────┴──────────────────────────────────────────────────┘
//!                                  ENVELOPE_BYTES = 1400 (one MTU)
//! ```
//!
//! `EmissionHeader` is AEAD-protected (not authenticated-only header /
//! AAD) so even the envelope-type discriminant (`real` vs. `cover`),
//! the scope tag, and the fragmentation indices are opaque to wire
//! observers. The only fields outside the AEAD are the 24-byte nonce
//! (random per-emission) and the implicit ciphertext length, which by
//! construction is always exactly `ENVELOPE_BYTES - NONCE_LEN`.
//!
//! # Wire-format invariants
//!
//! - `ENVELOPE_BYTES` is **wire-format constant**. Changing it is a
//!   substrate-wide protocol break (every peer's wire observer sees
//!   1400-byte envelopes; a 1500-byte envelope is a different
//!   protocol). Pinned at v6.1.0; CIRISConformance §9 vector pins
//!   the value.
//! - `EmissionHeader` uses a hand-rolled fixed-width little-endian
//!   layout for cross-impl stability and zero-dep (deliberately
//!   avoiding `bincode` / `serde_cbor` to keep the wire shape
//!   inspection-trivial). The layout is exactly the field order
//!   below, totalling `EmissionHeader::ENCODED_LEN = 54` bytes;
//!   zero-padded to [`HEADER_BYTES`] in the AEAD plaintext.
//! - The wire-protected fields' encoded length is bounded by
//!   [`HEADER_BYTES`] so the payload chunk always fits in
//!   `MAX_PAYLOAD_BYTES = ENVELOPE_BYTES - NONCE_LEN - TAG_LEN -
//!   HEADER_BYTES`.

use ciris_crypto::xchacha;

/// Wire-format envelope size — one MTU, matching §2.4 RaptorQ symbol.
/// **DO NOT CHANGE** without a coordinated substrate-wide wire break.
pub const ENVELOPE_BYTES: usize = 1400;

/// Reserved space for the `EmissionHeader` inside the AEAD
/// plaintext. The actual encoded length is
/// [`EmissionHeader::ENCODED_LEN`] (`u8 + u8 + 32 + u32 + u32 +
/// u32 + u64 = 54` bytes); the slack rounds up to a power-of-two
/// for forward-compat header extensions.
pub const HEADER_BYTES: usize = 64;

/// Maximum payload bytes per envelope, after subtracting the
/// 24-byte nonce, 16-byte Poly1305 tag, and `HEADER_BYTES` header
/// reserved-space.
pub const MAX_PAYLOAD_BYTES: usize =
    ENVELOPE_BYTES - xchacha::NONCE_LEN - xchacha::TAG_LEN - HEADER_BYTES;

/// Envelope discriminant. AEAD-protected — wire observers cannot
/// distinguish `Real` from `Cover` without the scope key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EnvelopeType {
    /// A real publication envelope. The payload chunk is one slice
    /// of a `(fragment_id, fragment_index)` fragment set.
    Real = 1,
    /// A synthetic cover envelope (FSD §3.1). The payload chunk is
    /// padding (typically pseudo-random bytes from the peer-local
    /// CSPRNG so even the under-encryption bytes look like real
    /// ciphertext to an opponent who somehow obtains the scope key
    /// after-the-fact).
    Cover = 2,
}

impl EnvelopeType {
    fn to_u8(self) -> u8 {
        self as u8
    }
    fn from_u8(b: u8) -> Result<Self, EmissionEnvelopeError> {
        match b {
            1 => Ok(Self::Real),
            2 => Ok(Self::Cover),
            other => Err(EmissionEnvelopeError::HeaderCodec(format!(
                "unknown envelope_type discriminant: {other}"
            ))),
        }
    }
}

/// Scope tag carried in the AEAD-protected header. Independent of
/// [`crate::cohort_scope::CohortScope`]'s wire form — this is the
/// scheduler's internal indexing tag, not the substrate wire scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EmissionScopeTag {
    /// `self` scope (FSD §2.1 — InvisibleEncrypted, self-cohort).
    SelfScope = 1,
    /// `family` scope (FSD §2.1 — InvisibleEncrypted, family-cohort).
    Family = 2,
    /// `community` / `affiliations` scope (FSD §2.1 — CommunityDek).
    Community = 3,
    /// `federation` scope (FSD §2.1 — Commons / plaintext). Federation
    /// emissions still ride the §3.1 cover layer for sender-side
    /// volume cover; the scope key is the federation-public key.
    Federation = 4,
}

impl EmissionScopeTag {
    fn to_u8(self) -> u8 {
        self as u8
    }
    fn from_u8(b: u8) -> Result<Self, EmissionEnvelopeError> {
        match b {
            1 => Ok(Self::SelfScope),
            2 => Ok(Self::Family),
            3 => Ok(Self::Community),
            4 => Ok(Self::Federation),
            other => Err(EmissionEnvelopeError::HeaderCodec(format!(
                "unknown scope discriminant: {other}"
            ))),
        }
    }
}

/// The 1.4 KB envelope's AEAD-protected header.
///
/// `record_id` is the [`crate::scope_privacy::derive_record_id`]
/// output for the publication this envelope is one fragment of (or
/// all-zeros for cover envelopes). `fragment_id` + `fragment_index`
/// + `fragment_count` form the §3.1 reassembly window key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmissionHeader {
    /// Envelope discriminant.
    pub envelope_type: EnvelopeType,
    /// Scope tag.
    pub scope: EmissionScopeTag,
    /// Per-publication record_id (FSD §2.4 HMAC-SHA3 record_id).
    /// `[0u8; 32]` for cover envelopes.
    pub record_id: [u8; 32],
    /// Fragment-set identifier (per-publication; unique within
    /// the emitter's recent history).
    pub fragment_id: u32,
    /// Zero-indexed fragment position within `fragment_count`.
    pub fragment_index: u32,
    /// Total fragments in this publication's fragment set.
    /// `1` for single-envelope publications. `0` for cover.
    pub fragment_count: u32,
    /// Emission unix-millis timestamp. Used by the reassembler to
    /// drop fragments whose window has expired.
    pub emitted_at_unix_ms: u64,
}

impl EmissionHeader {
    /// Hand-rolled fixed-width LE encoding length: `u8 + u8 + 32 +
    /// u32 + u32 + u32 + u64 = 54` bytes.
    pub const ENCODED_LEN: usize = 1 + 1 + 32 + 4 + 4 + 4 + 8;

    fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[0] = self.envelope_type.to_u8();
        out[1] = self.scope.to_u8();
        out[2..34].copy_from_slice(&self.record_id);
        out[34..38].copy_from_slice(&self.fragment_id.to_le_bytes());
        out[38..42].copy_from_slice(&self.fragment_index.to_le_bytes());
        out[42..46].copy_from_slice(&self.fragment_count.to_le_bytes());
        out[46..54].copy_from_slice(&self.emitted_at_unix_ms.to_le_bytes());
        out
    }

    fn decode(buf: &[u8; Self::ENCODED_LEN]) -> Result<Self, EmissionEnvelopeError> {
        let envelope_type = EnvelopeType::from_u8(buf[0])?;
        let scope = EmissionScopeTag::from_u8(buf[1])?;
        let mut record_id = [0u8; 32];
        record_id.copy_from_slice(&buf[2..34]);
        let fragment_id = u32::from_le_bytes(buf[34..38].try_into().unwrap());
        let fragment_index = u32::from_le_bytes(buf[38..42].try_into().unwrap());
        let fragment_count = u32::from_le_bytes(buf[42..46].try_into().unwrap());
        let emitted_at_unix_ms = u64::from_le_bytes(buf[46..54].try_into().unwrap());
        Ok(Self {
            envelope_type,
            scope,
            record_id,
            fragment_id,
            fragment_index,
            fragment_count,
            emitted_at_unix_ms,
        })
    }
}

impl EmissionHeader {
    /// Construct a header for a real publication fragment.
    #[must_use]
    pub fn real(
        scope: EmissionScopeTag,
        record_id: [u8; 32],
        fragment_id: u32,
        fragment_index: u32,
        fragment_count: u32,
        emitted_at_unix_ms: u64,
    ) -> Self {
        Self {
            envelope_type: EnvelopeType::Real,
            scope,
            record_id,
            fragment_id,
            fragment_index,
            fragment_count,
            emitted_at_unix_ms,
        }
    }

    /// Construct a header for a synthetic cover envelope.
    #[must_use]
    pub fn cover(scope: EmissionScopeTag, emitted_at_unix_ms: u64) -> Self {
        Self {
            envelope_type: EnvelopeType::Cover,
            scope,
            record_id: [0u8; 32],
            fragment_id: 0,
            fragment_index: 0,
            fragment_count: 0,
            emitted_at_unix_ms,
        }
    }

    /// `true` iff the header is a cover envelope.
    #[must_use]
    pub fn is_cover(&self) -> bool {
        matches!(self.envelope_type, EnvelopeType::Cover)
    }
}

/// A sealed emission envelope — exactly [`ENVELOPE_BYTES`] on the
/// wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmissionEnvelope {
    /// 24-byte XChaCha20 nonce + ciphertext + 16-byte Poly1305 tag.
    /// Total length is always [`ENVELOPE_BYTES`].
    pub bytes: Vec<u8>,
}

/// Errors from the emission envelope seal/unseal path.
#[derive(Debug, thiserror::Error)]
pub enum EmissionEnvelopeError {
    /// Payload exceeded [`MAX_PAYLOAD_BYTES`].
    #[error("payload too large for one envelope: {payload_len} > {max}")]
    PayloadTooLarge {
        /// Caller-provided payload length.
        payload_len: usize,
        /// The maximum allowed.
        max: usize,
    },
    /// Header codec failure (unknown discriminant or corrupt
    /// fixed-width frame).
    #[error("header codec: {0}")]
    HeaderCodec(String),
    /// Wire-format envelope was not [`ENVELOPE_BYTES`] long.
    #[error("malformed envelope: expected {expected} bytes, got {got}")]
    MalformedLength {
        /// `ENVELOPE_BYTES`.
        expected: usize,
        /// Caller's input length.
        got: usize,
    },
    /// AEAD seal / open failed (tampering, wrong key, malformed
    /// ciphertext).
    #[error("AEAD failure: {0}")]
    Aead(String),
}

/// Encode the header into a fixed-width buffer (zero-padded to
/// `HEADER_BYTES`). The first `EmissionHeader::ENCODED_LEN` bytes
/// are the canonical header; the remaining bytes are reserved
/// forward-compat slack.
///
/// Infallible — the `ENCODED_LEN < HEADER_BYTES` invariant is
/// static. Retained as a function (not inlined into `seal_envelope`)
/// for symmetry with [`decode_header`].
fn encode_header(header: &EmissionHeader) -> [u8; HEADER_BYTES] {
    // Static invariant: `ENCODED_LEN < HEADER_BYTES`. Verified by
    // the env-runtime test `header_encoded_len_fits_with_slack`
    // below — moving it out of the function body keeps clippy from
    // tripping on the constant-assert.
    let encoded = header.encode();
    let mut buf = [0u8; HEADER_BYTES];
    buf[..EmissionHeader::ENCODED_LEN].copy_from_slice(&encoded);
    buf
}

fn decode_header(buf: &[u8; HEADER_BYTES]) -> Result<EmissionHeader, EmissionEnvelopeError> {
    let mut frame = [0u8; EmissionHeader::ENCODED_LEN];
    frame.copy_from_slice(&buf[..EmissionHeader::ENCODED_LEN]);
    EmissionHeader::decode(&frame)
}

/// Seal a real or cover envelope under `scope_key`.
///
/// `payload` MUST be at most [`MAX_PAYLOAD_BYTES`]. The function
/// zero-pads the payload to `MAX_PAYLOAD_BYTES` before sealing so
/// every envelope is exactly [`ENVELOPE_BYTES`] on the wire.
///
/// `nonce` is the 24-byte XChaCha nonce. Callers MUST draw this from
/// a CSPRNG; 192-bit nonces collide with negligible probability under
/// random draw (FSD §3.1's CSPRNG seed source applies).
///
/// # Errors
///
/// - [`EmissionEnvelopeError::PayloadTooLarge`] — payload over budget.
/// - [`EmissionEnvelopeError::HeaderTooLarge`] / `HeaderCodec` —
///   header serialization failure.
/// - [`EmissionEnvelopeError::Aead`] — AEAD seal failure (rare).
pub fn seal_envelope(
    scope_key: &[u8; 32],
    nonce: &[u8; xchacha::NONCE_LEN],
    header: &EmissionHeader,
    payload: &[u8],
) -> Result<EmissionEnvelope, EmissionEnvelopeError> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(EmissionEnvelopeError::PayloadTooLarge {
            payload_len: payload.len(),
            max: MAX_PAYLOAD_BYTES,
        });
    }

    let header_buf = encode_header(header);

    // plaintext = HEADER (HEADER_BYTES) || PAYLOAD (zero-padded to
    // MAX_PAYLOAD_BYTES). Total plaintext length is a constant
    // (MAX_PAYLOAD_BYTES + HEADER_BYTES) so the ciphertext + tag
    // length is the same constant + TAG_LEN, and the total wire
    // length is ENVELOPE_BYTES once the nonce is prepended.
    let mut plaintext = Vec::with_capacity(HEADER_BYTES + MAX_PAYLOAD_BYTES);
    plaintext.extend_from_slice(&header_buf);
    // Zero-pad payload up to MAX_PAYLOAD_BYTES. (For cover envelopes
    // the caller can pass CSPRNG bytes as `payload` if it prefers a
    // pseudo-random under-encryption pattern; the wire-observable
    // ciphertext is uniformly pseudo-random in either case.)
    plaintext.extend_from_slice(payload);
    plaintext.resize(HEADER_BYTES + MAX_PAYLOAD_BYTES, 0);

    let ciphertext = xchacha::seal(scope_key, nonce, &plaintext)
        .map_err(|e| EmissionEnvelopeError::Aead(e.to_string()))?;

    let mut wire = Vec::with_capacity(ENVELOPE_BYTES);
    wire.extend_from_slice(nonce);
    wire.extend_from_slice(&ciphertext);

    debug_assert_eq!(
        wire.len(),
        ENVELOPE_BYTES,
        "sealed envelope must be exactly ENVELOPE_BYTES"
    );

    Ok(EmissionEnvelope { bytes: wire })
}

/// Unseal a wire envelope under `scope_key`. Returns the recovered
/// header + payload chunk (with trailing zero-padding stripped to
/// the header's `payload_len` field — except cover envelopes always
/// return an empty payload).
///
/// The caller learns: the header (`type`, scope, fragmentation
/// indices), and for real envelopes the payload chunk.
///
/// # Errors
///
/// - [`EmissionEnvelopeError::MalformedLength`] — input not
///   exactly `ENVELOPE_BYTES`.
/// - [`EmissionEnvelopeError::Aead`] — AEAD open failure (wrong key,
///   tampering, malformed ciphertext).
/// - [`EmissionEnvelopeError::HeaderCodec`] — header decode failure
///   (corrupt or future-version envelope).
pub fn unseal_envelope(
    scope_key: &[u8; 32],
    wire: &[u8],
) -> Result<(EmissionHeader, Vec<u8>), EmissionEnvelopeError> {
    if wire.len() != ENVELOPE_BYTES {
        return Err(EmissionEnvelopeError::MalformedLength {
            expected: ENVELOPE_BYTES,
            got: wire.len(),
        });
    }
    let nonce: [u8; xchacha::NONCE_LEN] = wire[..xchacha::NONCE_LEN]
        .try_into()
        .expect("nonce slice is exactly NONCE_LEN");
    let ciphertext = &wire[xchacha::NONCE_LEN..];
    let plaintext = xchacha::open(scope_key, &nonce, ciphertext)
        .map_err(|e| EmissionEnvelopeError::Aead(e.to_string()))?;

    debug_assert_eq!(
        plaintext.len(),
        HEADER_BYTES + MAX_PAYLOAD_BYTES,
        "decrypted plaintext is HEADER_BYTES + MAX_PAYLOAD_BYTES"
    );
    let header_buf: [u8; HEADER_BYTES] = plaintext[..HEADER_BYTES]
        .try_into()
        .expect("header slice is exactly HEADER_BYTES");
    let header = decode_header(&header_buf)?;

    let payload = if header.is_cover() {
        Vec::new()
    } else {
        // Real payload bytes — we don't store the per-fragment
        // payload_len in the header (the fragmenter's
        // `chunk.payload_len` is the source of truth and rides on
        // the [`crate::emission::fragment::FragmentSet`] wrapper).
        // The unseal path returns the full zero-padded slice; the
        // reassembler trims trailing zeros based on its own
        // bookkeeping. This avoids a header field whose only purpose
        // would be redundant.
        plaintext[HEADER_BYTES..].to_vec()
    };
    Ok((header, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The encode_header invariant: ENCODED_LEN < HEADER_BYTES.
    // Static const-assert — fires at compile time if violated.
    const _: () = {
        assert!(EmissionHeader::ENCODED_LEN < HEADER_BYTES);
    };

    #[test]
    fn envelope_size_is_pinned() {
        // FSD §3.1 wire-format invariant — DO NOT CHANGE.
        assert_eq!(ENVELOPE_BYTES, 1400);
    }

    #[test]
    fn round_trip_real_envelope() {
        let key = [0x42u8; 32];
        let nonce = [0x07u8; xchacha::NONCE_LEN];
        let header = EmissionHeader::real(
            EmissionScopeTag::Community,
            [0xAA; 32],
            42,
            0,
            1,
            1_700_000_000_000,
        );
        let payload = b"hello scope-native privacy".to_vec();
        let sealed = seal_envelope(&key, &nonce, &header, &payload).unwrap();
        assert_eq!(sealed.bytes.len(), ENVELOPE_BYTES);

        let (got_header, got_payload) = unseal_envelope(&key, &sealed.bytes).unwrap();
        assert_eq!(got_header, header);
        // Trailing zero-padding present; first N bytes match.
        assert_eq!(&got_payload[..payload.len()], &payload[..]);
        assert_eq!(got_payload.len(), MAX_PAYLOAD_BYTES);
    }

    #[test]
    fn round_trip_cover_envelope_returns_empty_payload() {
        let key = [0x55u8; 32];
        let nonce = [0x12u8; xchacha::NONCE_LEN];
        let header = EmissionHeader::cover(EmissionScopeTag::Federation, 1_700_000_000_000);
        let sealed = seal_envelope(&key, &nonce, &header, b"").unwrap();
        assert_eq!(sealed.bytes.len(), ENVELOPE_BYTES);

        let (got_header, payload) = unseal_envelope(&key, &sealed.bytes).unwrap();
        assert!(got_header.is_cover());
        assert!(payload.is_empty(), "cover envelope returns empty payload");
    }

    #[test]
    fn wire_size_invariant_holds_for_max_payload() {
        let key = [0x42u8; 32];
        let nonce = [0u8; xchacha::NONCE_LEN];
        let header = EmissionHeader::real(EmissionScopeTag::SelfScope, [1; 32], 0, 0, 1, 0);
        let payload = vec![0xAA; MAX_PAYLOAD_BYTES];
        let sealed = seal_envelope(&key, &nonce, &header, &payload).unwrap();
        assert_eq!(sealed.bytes.len(), ENVELOPE_BYTES);
    }

    #[test]
    fn rejects_oversized_payload() {
        let key = [0u8; 32];
        let nonce = [0u8; xchacha::NONCE_LEN];
        let header = EmissionHeader::real(EmissionScopeTag::Family, [0; 32], 0, 0, 1, 0);
        let payload = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let err = seal_envelope(&key, &nonce, &header, &payload).unwrap_err();
        assert!(matches!(err, EmissionEnvelopeError::PayloadTooLarge { .. }));
    }

    #[test]
    fn rejects_malformed_wire_length() {
        let key = [0u8; 32];
        let bogus = vec![0u8; ENVELOPE_BYTES - 1];
        let err = unseal_envelope(&key, &bogus).unwrap_err();
        assert!(matches!(err, EmissionEnvelopeError::MalformedLength { .. }));
    }

    #[test]
    fn wrong_key_fails_aead() {
        let key = [0x11u8; 32];
        let wrong = [0x22u8; 32];
        let nonce = [0x07u8; xchacha::NONCE_LEN];
        let header = EmissionHeader::cover(EmissionScopeTag::Family, 0);
        let sealed = seal_envelope(&key, &nonce, &header, b"").unwrap();
        let err = unseal_envelope(&wrong, &sealed.bytes).unwrap_err();
        assert!(matches!(err, EmissionEnvelopeError::Aead(_)));
    }

    #[test]
    fn real_and_cover_wire_indistinguishable_in_size() {
        let key = [0x33u8; 32];
        let nonce_a = [0xAAu8; xchacha::NONCE_LEN];
        let nonce_b = [0xBBu8; xchacha::NONCE_LEN];
        let real_hdr = EmissionHeader::real(EmissionScopeTag::Community, [0; 32], 0, 0, 1, 0);
        let cover_hdr = EmissionHeader::cover(EmissionScopeTag::Community, 0);
        let real = seal_envelope(&key, &nonce_a, &real_hdr, b"hello").unwrap();
        let cover = seal_envelope(&key, &nonce_b, &cover_hdr, b"").unwrap();
        assert_eq!(real.bytes.len(), cover.bytes.len());
        assert_eq!(real.bytes.len(), ENVELOPE_BYTES);
    }
}
