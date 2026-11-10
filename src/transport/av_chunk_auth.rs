//! Source authentication for a room call's chunks (CIRISEdge#805).
//!
//! # Why
//!
//! A call's stream DEK is derived from the room's MLS exporter
//! ([`crate::transport::av_call_key`]), so every member of the room can derive
//! every stream's key. That is the call model: members decrypt each other.
//! But a shared group key authenticates the GROUP, not the sender. The inner
//! AEAD alone cannot tell the stream's publisher from any other member. This
//! is the known shared-key caveat of SFrame-style group media. This module
//! closes it. Members can still decrypt, but only a stream's publisher can
//! produce chunks a receiver or a member relay accepts as that stream's.
//!
//! # Construction
//!
//! **A per-epoch chunk key.** At stream start and at every epoch roll, the
//! publisher generates an ephemeral Ed25519 key ([`ChunkSigner`]) for that
//! `(stream, epoch)`. It signs every chunk it seals in that epoch and is
//! dropped at the next roll.
//!
//! **Bound by the publisher's hybrid federation identity.** The public half
//! rides in a [`StreamKeyBinding`]: `(room, publisher key id, join nonce,
//! stream id, epoch, chunk key)`, signed with the publisher's full
//! Ed25519 + ML-DSA-65 hybrid signature ([`crate::identity::sign_bound_hybrid`]).
//! A receiver accepts a binding only when:
//! - its room is the call's room;
//! - its publisher is a member of the room's MLS group;
//! - its stream id is `call_stream_id(room, publisher, join_nonce)`. A stream
//!   id names its publisher, so no member can bind a key to another member's
//!   stream, even with a valid signature of its own;
//! - the hybrid signature verifies against persist's directory row for the
//!   publisher (`HybridPolicy::Strict`).
//!
//! No signed artifact bound a stream before this. The call row
//! (`chat:call:v1`) names the call, not the stream, may be refused, and
//! replicates through persist on its own schedule. The stream hello names the
//! stream but is unsigned and reaches only first-hand receivers. So the
//! binding is a new artifact. It is the smallest one that reaches every
//! member before media flows: the publisher sends it on every leg right after
//! the stream hello, again on every leg at each epoch roll (before the first
//! chunk of the new epoch, under the same lock that seals chunks), and again
//! every [`BINDING_REANNOUNCE`] so a binding lost to an inbound queue overflow
//! is replaced. A member relay (`CallOptions::relay`, a room member) forwards the
//! bindings it verifies, and sends the ones it holds on legs it dials. Bindings ride
//! only member-to-member A/V legs, never a non-member transport forwarder's (E1-opaque).
//!
//! A binding is about 3.6 KB (the ML-DSA-65 signature is 3309 bytes), more than
//! one Channel message, so it rides as [`BINDING_PART_MAGIC`] parts sized to
//! each link ([`StreamKeyBinding::parts`]) and is reassembled per link
//! ([`BindingAssembler`]). A part is told from a chunk by its 5-byte prefix. A
//! chunk's first bytes are its stream id, and a publisher never mints a stream
//! id with that prefix ([`collides_with_binding_part`]).
//!
//! **Each chunk carries a 64-byte Ed25519 signature** appended to its inner
//! ciphertext, over
//!
//! ```text
//! "ciris-edge:av-chunk-sig:v1" ‖ stream_id[32] ‖ u64_be(epoch) ‖ u64_be(chunk_seq)
//!     ‖ codec_id ‖ spatial ‖ temporal ‖ quality ‖ inner_aead_ciphertext
//! ```
//!
//! The signature sits inside the outer (hop) seal and outside the inner (E2E)
//! seal. So a member relay, which opens only the outer seal, can check it without
//! the DEK. The chunk header is unchanged; the dispatcher and the relay forward
//! the inner unit byte for byte as before.
//!
//! **Checking a chunk** ([`ChunkAuth::check`]) is a map lookup of the bound key
//! for the chunk's `(stream, epoch)` plus one Ed25519 verification. There is no
//! persist read and no hybrid verification per chunk: the hybrid check runs
//! once per binding, at stream setup and epoch roll, and its result is cached.
//! A chunk with no bound key, or a bad signature, is dropped and counted, and
//! never delivered or relayed. Because the signature covers the stream id, the
//! epoch and the sequence number, a chunk replayed under another stream id or
//! epoch fails it.
//!
//! **Epochs.** A receiver holds bound keys for the two newest epochs of each
//! stream, as the DEK ring does, so chunks in flight across a roll still
//! verify. A key is valid only for the epoch it was bound to: a chunk stamped
//! with the new epoch but signed by the old key is refused, and once the
//! stream moves two epochs on, the old key is gone.
//!
//! # Post-quantum position
//!
//! The per-chunk signature is classical Ed25519. That is sufficient because
//! authentication only has to hold while the stream is live: a forgery must be
//! made before receivers stop accepting the epoch, so a future quantum
//! adversary gains nothing from harvested traffic (harvest-now-decrypt-later
//! is an attack on secrecy, not authentication). Secrecy stays with the inner
//! seal and its MLS-derived DEK. The long-lived link from the publisher's
//! identity to the ephemeral key is the binding, and that is hybrid-signed
//! (Ed25519 + ML-DSA-65), so it holds against a quantum adversary too.
//!
//! # The chunk format
//!
//! The binding and the trailer are part of the A/V chunk format, not an
//! option: a chunk without a verified binding or trailer is refused. The
//! layout is written out, with KAT vectors, in `docs/av_chunk_auth_wire.md`.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use base64::Engine as _;
use ciris_crypto::{ClassicalSigner as _, Ed25519Signer, Ed25519Verifier};
use sha2::{Digest as _, Sha256};

use crate::identity::LocalSigner;
use crate::transport::av_call::call_stream_id;
use crate::transport::realtime_av::{inner_sealed_from_parts, Epoch, InnerSealed, StreamId};

/// The chunk's Ed25519 source signature.
pub const CHUNK_SIG_LEN: usize = 64;

/// The publisher's source timestamp (UNIX ms, `u64_be`) the trailer carries
/// ahead of the signature (ALM stage 2: the C1 meter's latency input).
pub const CHUNK_SOURCE_TS_LEN: usize = 8;

/// The bytes a chunk's trailer adds to its inner unit:
/// `source_ms u64_be ‖ signature[64]`.
pub const CHUNK_TRAILER_LEN: usize = CHUNK_SOURCE_TS_LEN + CHUNK_SIG_LEN;

/// The ML-DSA-65 signature length (FIPS 204) a [`StreamKeyBinding`] must carry;
/// enforced at parse like Ed25519's 64 (CC 5.3.3.2.3, CC 2.6.3).
pub const ML_DSA_65_SIG_LEN: usize = 3309;

/// The domain tag of a chunk's source signature. `v2` (ALM stage 2) adds the
/// source timestamp to the signed bytes; a `v1` trailer does not verify.
const CHUNK_SIG_DOMAIN: &[u8] = b"ciris-edge:av-chunk-sig:v2";

/// The domain tag of a v1 binding's hybrid signature.
const BINDING_DOMAIN: &[u8] = b"ciris-edge:av-stream-key:v1";
/// The domain tag of a v2 binding's hybrid signature (it names the codec).
const BINDING_DOMAIN_V2: &[u8] = b"ciris-edge:av-stream-key:v2";

/// The v1 binding's encoding version (no codec).
const BINDING_VERSION: u8 = 1;
/// The v2 binding's encoding version: v1's fields, then a signed codec token.
pub const BINDING_VERSION_V2: u8 = 2;

/// A registered codec token a v2 binding names (the token table is a CC
/// reading (rc17) of 5.3.3.2.1–.3, pending text). The chunk header's
/// `codec_id` carries only the LAYER class (0x04 is rc17 text); the binding
/// names the codec of each class, in a [`CodecMap`] fixed for the stream's
/// life (a codec change is `Call::replace_stream`: a new join nonce, a new
/// stream).
///
/// A token names the whole payload format, codec and bitstream framing (CC
/// reading, rc18): what one chunk's (or one reassembled frame's) plaintext
/// is. Three are registered; any other spelling binds as an undecodable
/// class (the unknown-token rule), never malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodecToken {
    /// AV1 under `0x01` (SVC): one temporal unit's low-overhead-format OBUs
    /// for one layer.
    Av1,
    /// H.264 under `0x04` (temporal-layered, one spatial layer): one Annex B
    /// access unit.
    H264,
    /// Opus (audio) under `0xFF` (codec-opaque): one Opus packet (RFC 6716).
    Opus,
}

impl CodecToken {
    /// Every registered token.
    pub const ALL: [Self; 3] = [Self::Av1, Self::H264, Self::Opus];

    /// The token's wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Av1 => "av1",
            Self::H264 => "h264",
            Self::Opus => "opus",
        }
    }

    /// The token for a wire spelling; `None` for anything unregistered
    /// (`opaque` is not a token).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == s)
    }

    /// The layer class (`realtime_av::CODEC_*`) the codec rides under.
    #[must_use]
    pub const fn class(self) -> u8 {
        use crate::transport::realtime_av::{CODEC_AV1_SVC, CODEC_OPAQUE, CODEC_TEMPORAL_LAYERED};
        match self {
            Self::Av1 => CODEC_AV1_SVC,
            Self::H264 => CODEC_TEMPORAL_LAYERED,
            Self::Opus => CODEC_OPAQUE,
        }
    }
}

/// The most classes a v2 binding's codec map may name.
pub const MAX_CODEC_CLASSES: usize = 8;

/// The longest codec token a v2 binding may carry (bytes, ASCII).
pub const MAX_TOKEN_LEN: usize = 32;

/// One codec token as a v2 binding carries it: printable ASCII, 1 to
/// [`MAX_TOKEN_LEN`] bytes. A token this build does not know is kept as
/// written (it names a codec registered after this build).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Token {
    bytes: [u8; MAX_TOKEN_LEN],
    len: u8,
}

impl Token {
    /// The token spelled `s`.
    ///
    /// # Errors
    /// [`BindingError::Malformed`] when `s` is empty, longer than
    /// [`MAX_TOKEN_LEN`], or not printable ASCII.
    pub fn new(s: &str) -> Result<Self, BindingError> {
        let b = s.as_bytes();
        if b.is_empty() || b.len() > MAX_TOKEN_LEN || !b.iter().all(|c| c.is_ascii_graphic()) {
            return Err(BindingError::Malformed("codec token"));
        }
        let mut bytes = [0u8; MAX_TOKEN_LEN];
        bytes[..b.len()].copy_from_slice(b);
        Ok(Self {
            bytes,
            len: u8::try_from(b.len()).unwrap_or(0),
        })
    }

    /// Its spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Printable ASCII by construction.
        std::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("")
    }

    /// The registered token it spells, if this build knows it.
    #[must_use]
    pub fn known(&self) -> Option<CodecToken> {
        CodecToken::parse(self.as_str())
    }
}

impl From<CodecToken> for Token {
    fn from(t: CodecToken) -> Self {
        Self::new(t.as_str()).unwrap_or(Self {
            bytes: [0; MAX_TOKEN_LEN],
            len: 0,
        })
    }
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.as_str())
    }
}

/// What a codec map says of one layer class on this receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassCodec {
    /// The map names no codec for the class: its chunks are refused.
    Absent,
    /// A registered codec this build decodes.
    Known(CodecToken),
    /// A token this build does not know: the binding stands, and this
    /// receiver drops the class's chunks locally (counted).
    Undecodable,
}

/// A v2 binding's codec map (CC reading (rc17) of 5.3.3.2.1–.3, pending
/// text): one token per layer class the stream uses, sorted by class, no class
/// twice. A registered token must sit under its own class; an unregistered one
/// binds as an undecodable class here, so a codec registered later never
/// takes the audio away from an older receiver. `{0x04: h264, 0xFF: opus}`
/// is a phone's audio-and-video stream, `{0xFF: opus}` an audio-only one. A
/// chunk whose class has no entry is refused. Fixed for the stream's life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CodecMap {
    items: [(u8, Token); MAX_CODEC_CLASSES],
    len: u8,
}

impl CodecMap {
    /// The map of registered `tokens`, each under its class.
    ///
    /// # Errors
    /// [`BindingError::Malformed`] when it is empty, longer than
    /// [`MAX_CODEC_CLASSES`], or names a class twice.
    pub fn new(tokens: impl IntoIterator<Item = CodecToken>) -> Result<Self, BindingError> {
        Self::with_entries(tokens.into_iter().map(|t| (t.class(), Token::from(t))))
    }

    /// The map of raw `(class, token)` entries, as a binding carries them:
    /// an unregistered token is kept as undecodable; a registered one must
    /// sit under its own class.
    ///
    /// # Errors
    /// [`BindingError::Malformed`]: the map is empty, longer than
    /// [`MAX_CODEC_CLASSES`], or names a class twice, or a registered token
    /// sits under another class.
    pub fn with_entries(
        entries: impl IntoIterator<Item = (u8, Token)>,
    ) -> Result<Self, BindingError> {
        let mut v: Vec<(u8, Token)> = entries.into_iter().collect();
        v.sort_by_key(|(c, _)| *c);
        if v.is_empty() || v.len() > MAX_CODEC_CLASSES {
            return Err(BindingError::Malformed("codec map size"));
        }
        if v.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(BindingError::Malformed("codec map class twice"));
        }
        if v.iter()
            .any(|(c, t)| t.known().is_some_and(|k| k.class() != *c))
        {
            return Err(BindingError::Malformed("codec class"));
        }
        Ok(Self::from_sorted(&v))
    }

    fn from_sorted(v: &[(u8, Token)]) -> Self {
        let filler = Token {
            bytes: [0; MAX_TOKEN_LEN],
            len: 0,
        };
        let mut items = [(0u8, filler); MAX_CODEC_CLASSES];
        items[..v.len()].copy_from_slice(v);
        Self {
            items,
            len: u8::try_from(v.len()).unwrap_or(0),
        }
    }

    /// The entries, sorted by class.
    #[must_use]
    pub fn entries(&self) -> &[(u8, Token)] {
        &self.items[..usize::from(self.len)]
    }

    /// What the map says of `class` on this receiver.
    #[must_use]
    pub fn class_codec(&self, class: u8) -> ClassCodec {
        match self.entries().iter().find(|(c, _)| *c == class) {
            None => ClassCodec::Absent,
            Some((_, t)) => t.known().map_or(ClassCodec::Undecodable, ClassCodec::Known),
        }
    }

    /// The registered codec `class` rides under, if the map names one this
    /// build knows.
    #[must_use]
    pub fn token_for(&self, class: u8) -> Option<CodecToken> {
        match self.class_codec(class) {
            ClassCodec::Known(t) => Some(t),
            _ => None,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.len);
        for (class, token) in self.entries() {
            out.push(*class);
            put_str(out, token.as_str());
        }
    }

    /// `None` for an empty map (`count` 0).
    fn decode(r: &mut Reader<'_>) -> Result<Option<Self>, BindingError> {
        let n = usize::from(r.array::<1>()?[0]);
        if n == 0 {
            return Ok(None);
        }
        if n > MAX_CODEC_CLASSES {
            return Err(BindingError::Malformed("codec map size"));
        }
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            let class = r.array::<1>()?[0];
            let len = r.len16()?;
            if len == 0 || len > MAX_TOKEN_LEN {
                return Err(BindingError::Malformed("codec token"));
            }
            let raw = std::str::from_utf8(r.take(len)?)
                .map_err(|_| BindingError::Malformed("codec token"))?;
            let token = Token::new(raw)?;
            if token.known().is_some_and(|k| k.class() != class) {
                return Err(BindingError::Malformed("codec class"));
            }
            if v.last().is_some_and(|(c, _): &(u8, Token)| *c >= class) {
                return Err(BindingError::Malformed("codec map order"));
            }
            v.push((class, token));
        }
        Ok(Some(Self::from_sorted(&v)))
    }
}

impl std::fmt::Display for CodecMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts: Vec<String> = self
            .entries()
            .iter()
            .map(|(c, t)| format!("{c:#04x}:{}", t.as_str()))
            .collect();
        write!(f, "{{{}}}", parts.join(","))
    }
}

/// `final_seq` when the publisher sealed no chunk in the epoch.
pub const FINAL_SEQ_NONE: u64 = u64::MAX;

/// What a v2 binding's `end` member says: the publisher's own signed word
/// that its stream ends, and why (v45). A receiver acts on a leave only from
/// this verified field, never from an unsigned control frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignedEnd {
    /// The attendee left the call (on its last stream: a leave).
    Left,
    /// The attendee's app went to the background (on its last stream: a
    /// leave).
    Backgrounded,
    /// v45 (CC reading, rc18) — this stream ended, and nothing more: no
    /// leave, whatever streams the member has left (a share stopped).
    Ended,
}

impl SignedEnd {
    const fn code(self) -> u8 {
        match self {
            Self::Left => 1,
            Self::Backgrounded => 2,
            Self::Ended => 3,
        }
    }

    fn from_code(c: u8) -> Result<Option<Self>, BindingError> {
        match c {
            0 => Ok(None),
            1 => Ok(Some(Self::Left)),
            2 => Ok(Some(Self::Backgrounded)),
            3 => Ok(Some(Self::Ended)),
            _ => Err(BindingError::Malformed("end")),
        }
    }

    /// Whether this end says the member left (1, 2), not only the stream (3).
    #[must_use]
    pub const fn is_leave(self) -> bool {
        !matches!(self, Self::Ended)
    }
}

/// v45 (CC reading, rc18) — the v2 `kind` member: what the stream is to a
/// receiver's layout. It gates nothing (admission, keys, sealing, the
/// trailer, shedding, keeping). A v1 binding reads as media; an unknown
/// value under v2 renders as media and is never refused.
pub const STREAM_KIND_MEDIA: u8 = 0;
/// A share (a desktop or window), `Call::add_stream`.
pub const STREAM_KIND_SHARE: u8 = 1;

/// v45 (CC reading, rc18) — the v2 `framing` member: 0, one media frame per
/// chunk and no marker; 1, every chunk whose `codec_id` is not `0xFF`
/// carries the 8-byte fragment marker (`av_call::frame`). A
/// v1 binding reads as 0. Fixed per (stream, epoch).
pub const FRAMING_NONE: u8 = 0;
/// See [`FRAMING_NONE`].
pub const FRAMING_FRAGMENTS: u8 = 1;

/// The tag that starts every binding part: `"CSKB" ‖ version ‖ id[8] ‖ index ‖
/// count ‖ payload`.
pub const BINDING_PART_MAGIC: [u8; 4] = *b"CSKB";
const BINDING_PART_VERSION: u8 = 1;
const PART_HEADER_LEN: usize = 4 + 1 + 8 + 1 + 1;

/// The largest binding a receiver reassembles.
const MAX_BINDING_LEN: usize = 8 * 1024;
/// The most parts one binding may take.
const MAX_PARTS: usize = 64;
/// Bindings a receiver reassembles at once, per link.
const MAX_PENDING: usize = 4;
/// The longest room or key id a binding may name.
const MAX_ID_LEN: usize = 1024;
/// Bound streams a receiver holds per publisher (a rejoin is a new stream).
const MAX_STREAMS_PER_PUBLISHER: usize = 4;
/// Ended streams a receiver remembers (their signed end is final).
const ENDED_REMEMBERED: usize = 256;
/// Binding ids a receiver remembers as verified, so a re-sent binding costs a
/// hash, not a hybrid verification.
const SEEN_IDS: usize = 128;

/// How often a publisher re-sends its current binding on every leg.
pub const BINDING_REANNOUNCE: Duration = Duration::from_secs(10);

/// The part size used when a link reports no Channel limit (an in-memory seam).
const FALLBACK_PART_LIMIT: usize = 1024;

/// Whether a stream id's first bytes would read as a binding part. A
/// publisher never mints such a stream ([`crate::transport::av_call`]'s
/// `start_stream` draws again).
#[must_use]
pub fn collides_with_binding_part(stream: StreamId) -> bool {
    stream.0[..4] == BINDING_PART_MAGIC && stream.0[4] == BINDING_PART_VERSION
}

/// The bytes a chunk's source signature covers: the header fields, the
/// publisher's source timestamp, then the inner AEAD.
#[must_use]
pub fn chunk_sig_message(inner: &InnerSealed, inner_aead: &[u8], source_ms: u64) -> Vec<u8> {
    let layer = inner.layer();
    let mut m = Vec::with_capacity(CHUNK_SIG_DOMAIN.len() + 32 + 8 + 8 + 4 + 8 + inner_aead.len());
    m.extend_from_slice(CHUNK_SIG_DOMAIN);
    m.extend_from_slice(&inner.stream_id().0);
    m.extend_from_slice(&inner.epoch().0.to_be_bytes());
    m.extend_from_slice(&inner.chunk_seq().0.to_be_bytes());
    m.push(inner.codec_id());
    m.push(layer.spatial);
    m.push(layer.temporal);
    m.push(layer.quality);
    m.extend_from_slice(&source_ms.to_be_bytes());
    m.extend_from_slice(inner_aead);
    m
}

/// Wall-clock UNIX milliseconds (the publisher's source timestamp).
#[must_use]
pub fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn with_ciphertext(inner: &InnerSealed, ciphertext: Vec<u8>) -> InnerSealed {
    inner_sealed_from_parts(
        inner.stream_id(),
        inner.epoch(),
        inner.chunk_seq(),
        inner.codec_id(),
        inner.layer(),
        ciphertext,
    )
}

// ─── refusal tokens ─────────────────────────────────────────────────

/// **The stable refusal tokens** of chunk source authentication: the one
/// spelling a relay and a receiver use in logs (`reason = …`) and as
/// `av_plane` counter labels. Each names one refusal; never renamed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AvAuthRefusal {
    /// A binding part with a bad header, an inconsistent part count, a
    /// reassembly over the bound, or a reassembly that does not hash to its id.
    BindingPartMalformed,
    /// A reassembled binding that does not parse.
    BindingMalformed,
    /// A binding for another room than the call's.
    BindingOtherRoom,
    /// A binding whose publisher is not in the room's MLS group.
    BindingPublisherNotMember,
    /// A binding whose stream id is not derived from its publisher and nonce.
    BindingStreamNotDerived,
    /// A binding whose hybrid signature did not verify.
    BindingSignatureUnverified,
    /// A binding for an epoch older than the two the receiver holds.
    BindingStaleEpoch,
    /// A v2 binding naming another codec than its stream is bound to.
    BindingCodecChanged,
    /// A binding for a stream whose signed end was already verified.
    BindingStreamEnded,
    /// A chunk too short to carry its 64-byte trailer.
    ChunkTrailerMissing,
    /// A chunk whose trailer does not verify under the bound key.
    ChunkTrailerInvalid,
    /// A chunk for a `(stream, epoch)` with no verified binding.
    ChunkUnbound,
    /// A chunk whose layer class the stream's v2 codec map does not name.
    ChunkClassUnlisted,
    /// A chunk of a class whose codec this receiver does not know (dropped
    /// here, the binding standing).
    ChunkClassUndecodable,
    /// A chunk whose `chunk_seq` is past its stream's signed `final_seq`.
    ChunkPastEnd,
}

impl AvAuthRefusal {
    /// Every token, in declaration order.
    pub const ALL: [Self; 15] = [
        Self::BindingPartMalformed,
        Self::BindingMalformed,
        Self::BindingOtherRoom,
        Self::BindingPublisherNotMember,
        Self::BindingStreamNotDerived,
        Self::BindingSignatureUnverified,
        Self::BindingStaleEpoch,
        Self::BindingCodecChanged,
        Self::BindingStreamEnded,
        Self::ChunkTrailerMissing,
        Self::ChunkTrailerInvalid,
        Self::ChunkUnbound,
        Self::ChunkClassUnlisted,
        Self::ChunkClassUndecodable,
        Self::ChunkPastEnd,
    ];

    /// The token's stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BindingPartMalformed => "av_binding_part_malformed",
            Self::BindingMalformed => "av_binding_malformed",
            Self::BindingOtherRoom => "av_binding_other_room",
            Self::BindingPublisherNotMember => "av_binding_publisher_not_member",
            Self::BindingStreamNotDerived => "av_binding_stream_not_derived",
            Self::BindingSignatureUnverified => "av_binding_signature_unverified",
            Self::BindingStaleEpoch => "av_binding_stale_epoch",
            Self::BindingCodecChanged => "av_binding_codec_changed",
            Self::BindingStreamEnded => "av_binding_stream_ended",
            Self::ChunkTrailerMissing => "av_chunk_trailer_missing",
            Self::ChunkTrailerInvalid => "av_chunk_trailer_invalid",
            Self::ChunkUnbound => "av_chunk_unbound",
            Self::ChunkClassUnlisted => "av_chunk_class_unlisted",
            Self::ChunkClassUndecodable => "av_chunk_class_undecodable",
            Self::ChunkPastEnd => "av_chunk_past_end",
        }
    }
}

impl std::fmt::Display for AvAuthRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── the publisher's key ────────────────────────────────────────────

/// Why a chunk key or binding could not be made.
#[derive(Debug, thiserror::Error)]
pub enum ChunkKeyError {
    /// The RNG or the Ed25519 signer refused.
    #[error("chunk key: {0}")]
    Crypto(String),
    /// The federation signer refused the binding.
    #[error("stream key binding: {0}")]
    Binding(String),
    /// The chunk is sealed under another stream or epoch than this key's.
    #[error("chunk key is for epoch {key}, the chunk is sealed in epoch {chunk}")]
    WrongEpoch {
        /// The key's epoch.
        key: u64,
        /// The chunk's.
        chunk: u64,
    },
}

/// A publisher's ephemeral chunk key for one `(stream, epoch)`.
pub struct ChunkSigner {
    stream: StreamId,
    epoch: Epoch,
    key: Ed25519Signer,
    public: [u8; 32],
}

impl std::fmt::Debug for ChunkSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkSigner")
            .field("epoch", &self.epoch)
            .field("public", &hex::encode(self.public))
            .finish_non_exhaustive()
    }
}

impl ChunkSigner {
    /// A fresh key for `stream` at `epoch`.
    ///
    /// # Errors
    /// [`ChunkKeyError::Crypto`] when the RNG refuses.
    pub fn generate(stream: StreamId, epoch: Epoch) -> Result<Self, ChunkKeyError> {
        let key = Ed25519Signer::random().map_err(|e| ChunkKeyError::Crypto(e.to_string()))?;
        let public = key.verifying_key().to_bytes();
        Ok(Self {
            stream,
            epoch,
            key,
            public,
        })
    }

    /// A key from a fixed seed: a witness that needs the SAME key at two
    /// epochs (the old key signing a new epoch's chunk).
    #[cfg(test)]
    pub(crate) fn from_seed(stream: StreamId, epoch: Epoch, seed: [u8; 32]) -> Self {
        let key = Ed25519Signer::from_seed(&seed).expect("32-byte seed");
        let public = key.verifying_key().to_bytes();
        Self {
            stream,
            epoch,
            key,
            public,
        }
    }

    /// The key's public half.
    #[must_use]
    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    /// The epoch this key signs.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Append the trailer (the source timestamp, now, and this key's
    /// signature) to `inner`'s ciphertext.
    ///
    /// # Errors
    /// As [`Self::sign_at`].
    pub fn sign(&self, inner: &InnerSealed) -> Result<InnerSealed, ChunkKeyError> {
        self.sign_at(inner, unix_ms_now())
    }

    /// Append the trailer `source_ms ‖ signature` to `inner`'s ciphertext;
    /// the signature covers the timestamp.
    ///
    /// # Errors
    /// [`ChunkKeyError::WrongEpoch`] when `inner` is another stream's or
    /// epoch's; [`ChunkKeyError::Crypto`] when signing fails.
    pub fn sign_at(
        &self,
        inner: &InnerSealed,
        source_ms: u64,
    ) -> Result<InnerSealed, ChunkKeyError> {
        if inner.stream_id() != self.stream || inner.epoch() != self.epoch {
            return Err(ChunkKeyError::WrongEpoch {
                key: self.epoch.0,
                chunk: inner.epoch().0,
            });
        }
        let ct = inner.inner_ciphertext();
        let sig = self
            .key
            .sign(&chunk_sig_message(inner, ct, source_ms))
            .map_err(|e| ChunkKeyError::Crypto(e.to_string()))?;
        let mut signed = Vec::with_capacity(ct.len() + CHUNK_TRAILER_LEN);
        signed.extend_from_slice(ct);
        signed.extend_from_slice(&source_ms.to_be_bytes());
        signed.extend_from_slice(&sig);
        Ok(with_ciphertext(inner, signed))
    }
}

// ─── the binding ────────────────────────────────────────────────────

/// A publisher's hybrid-signed statement that `chunk_key` signs its stream's
/// chunks in `epoch` (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamKeyBinding {
    /// The room (community key id) the call lives in.
    pub room: String,
    /// The publisher's key id: the room member whose stream it is.
    pub publisher: String,
    /// The join nonce the stream id was derived from.
    pub join_nonce: [u8; 32],
    /// The stream.
    pub stream: StreamId,
    /// The epoch the key signs.
    pub epoch: Epoch,
    /// The Ed25519 public key that signs the stream's chunks in `epoch`.
    pub chunk_key: [u8; 32],
    /// The Ed25519 half of the publisher's hybrid signature.
    pub sig_ed25519: Vec<u8>,
    /// The ML-DSA-65 half (over the signed bytes ‖ the Ed25519 signature).
    pub sig_ml_dsa_65: Vec<u8>,
    /// The stream's codec map: `Some` makes this a v2 binding (signed under
    /// the v2 domain), `None` a v1 one, which names no codec (and carries
    /// neither `replaces` nor `end`).
    pub codecs: Option<CodecMap>,
    /// v2: the publisher's earlier stream this one replaces in place
    /// (`Call::replace_stream`). Only this signed field says so.
    pub replaces: Option<StreamId>,
    /// v2: the publisher's signed word that the stream ends, and why. Final:
    /// once a receiver has verified it, it takes no further binding for the
    /// stream (a return is a new stream).
    pub end: Option<SignedEnd>,
    /// v2, with `end`: the last `chunk_seq` the publisher sealed in this
    /// epoch ([`FINAL_SEQ_NONE`]: none), in place of 5.3.3.1's terminator. A
    /// relay cannot drop the tail unseen, and nothing past it plays.
    pub final_seq: Option<u64>,
    /// v2: the stream's kind ([`STREAM_KIND_MEDIA`], [`STREAM_KIND_SHARE`],
    /// or a value this build does not know, read as media).
    pub kind: u8,
    /// v2: the stream's framing ([`FRAMING_NONE`] or [`FRAMING_FRAGMENTS`]).
    pub framing: u8,
    /// v45 — encoded as v2 even when every v2 member is its default (a
    /// v45 publisher signs a v2 binding for every stream, so its framing,
    /// 0 included, is stated). Set by [`Self::sign_v2`] with members and by
    /// parsing a v2 encoding.
    pub explicit_v2: bool,
}

/// Why a binding was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BindingError {
    /// The bytes are not a binding.
    #[error("malformed stream key binding: {0}")]
    Malformed(&'static str),
    /// The binding is for another room.
    #[error("the binding is for room {0}, not this call's")]
    OtherRoom(String),
    /// The publisher is not in the room's MLS group.
    #[error("{0} is not a member of the room")]
    NotAMember(String),
    /// The stream id is not the publisher's.
    #[error("stream id is not derived from publisher {0} and the binding's nonce")]
    NotThePublishersStream(String),
    /// The hybrid signature did not verify.
    #[error("publisher signature: {0}")]
    Signature(String),
    /// Older than the epochs this receiver holds for the stream.
    #[error("binding for epoch {0} is older than the stream's held epochs")]
    Stale(u64),
    /// A v2 binding naming another codec than the one already bound to its
    /// stream: one codec per stream for its life.
    /// A binding for a stream whose signed end this receiver verified: the
    /// end is final.
    #[error("the stream ended (a signed end was verified); a return is a new stream")]
    StreamEnded,
    #[error("the stream is bound to codecs {held}, not {got}")]
    CodecChanged {
        /// The codec map the stream is bound to.
        held: String,
        /// The codec map this binding names.
        got: String,
    },
}

impl BindingError {
    /// The refusal's stable token.
    #[must_use]
    pub const fn refusal(&self) -> AvAuthRefusal {
        match self {
            Self::Malformed(_) => AvAuthRefusal::BindingMalformed,
            Self::OtherRoom(_) => AvAuthRefusal::BindingOtherRoom,
            Self::NotAMember(_) => AvAuthRefusal::BindingPublisherNotMember,
            Self::NotThePublishersStream(_) => AvAuthRefusal::BindingStreamNotDerived,
            Self::Signature(_) => AvAuthRefusal::BindingSignatureUnverified,
            Self::Stale(_) => AvAuthRefusal::BindingStaleEpoch,
            Self::CodecChanged { .. } => AvAuthRefusal::BindingCodecChanged,
            Self::StreamEnded => AvAuthRefusal::BindingStreamEnded,
        }
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    let len = u16::try_from(s.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&s.as_bytes()[..usize::from(len)]);
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    let len = u16::try_from(b.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&b[..usize::from(len)]);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], BindingError> {
        if self.0.len() < n {
            return Err(BindingError::Malformed("truncated"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], BindingError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }
    fn len16(&mut self) -> Result<usize, BindingError> {
        Ok(usize::from(u16::from_be_bytes(self.array::<2>()?)))
    }
    fn string(&mut self) -> Result<String, BindingError> {
        let n = self.len16()?;
        if n == 0 || n > MAX_ID_LEN {
            return Err(BindingError::Malformed("id length"));
        }
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| BindingError::Malformed("utf-8"))
    }
}

/// The members a v2 binding adds to v1's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Members {
    /// The stream's codec map (`None`: a stream that declared none; allowed
    /// only with `replaces` or `end`).
    pub codecs: Option<CodecMap>,
    /// The publisher's earlier stream this one replaces in place.
    pub replaces: Option<StreamId>,
    /// The publisher's signed word that the stream ends.
    pub end: Option<SignedEnd>,
    /// With `end`: the last `chunk_seq` sealed in the epoch.
    pub final_seq: Option<u64>,
    /// The stream's kind ([`STREAM_KIND_MEDIA`] by default).
    pub kind: u8,
    /// The stream's framing ([`FRAMING_NONE`] by default).
    pub framing: u8,
}

impl StreamKeyBinding {
    /// The bytes before the signatures (the encoding's first half).
    fn unsigned_body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 4 + self.room.len() + self.publisher.len() + 112);
        out.push(self.version());
        put_str(&mut out, &self.room);
        put_str(&mut out, &self.publisher);
        out.extend_from_slice(&self.join_nonce);
        out.extend_from_slice(&self.stream.0);
        out.extend_from_slice(&self.epoch.0.to_be_bytes());
        out.extend_from_slice(&self.chunk_key);
        if self.version() == BINDING_VERSION_V2 {
            match &self.codecs {
                Some(codecs) => codecs.encode(&mut out),
                // An end statement (or a replacement) of a stream that
                // declared no codecs: an empty map.
                None => out.push(0),
            }
            match self.replaces {
                Some(old) => {
                    out.push(1);
                    out.extend_from_slice(&old.0);
                }
                None => out.push(0),
            }
            out.push(self.end.map_or(0, SignedEnd::code));
            if self.end.is_some() {
                out.extend_from_slice(&self.final_seq.unwrap_or(FINAL_SEQ_NONE).to_be_bytes());
            }
            out.push(self.kind);
            out.push(self.framing);
        }
        out
    }

    /// The encoding version: 2 when the binding names a codec, else 1.
    #[must_use]
    pub const fn version(&self) -> u8 {
        if self.explicit_v2
            || self.codecs.is_some()
            || self.replaces.is_some()
            || self.end.is_some()
            || self.kind != STREAM_KIND_MEDIA
            || self.framing != FRAMING_NONE
        {
            BINDING_VERSION_V2
        } else {
            BINDING_VERSION
        }
    }

    /// The version of an encoded binding (its first byte), without parsing.
    #[must_use]
    pub fn version_of(wire: &[u8]) -> Option<u8> {
        wire.first().copied()
    }

    /// The bytes the publisher's hybrid signature covers: a domain tag, then
    /// the unsigned body.
    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut out = if self.version() == BINDING_VERSION_V2 {
            BINDING_DOMAIN_V2.to_vec()
        } else {
            BINDING_DOMAIN.to_vec()
        };
        out.extend_from_slice(&self.unsigned_body());
        out
    }

    /// Bind `chunk_key` for `stream` at `epoch`, signed by `signer`, whose
    /// key id is the stream's publisher.
    ///
    /// # Errors
    /// [`ChunkKeyError::Binding`] when `stream` is not `signer`'s stream for
    /// `room` and `join_nonce`, or the hybrid signature fails.
    pub async fn sign(
        signer: &LocalSigner,
        room: &str,
        join_nonce: [u8; 32],
        stream: StreamId,
        epoch: Epoch,
        chunk_key: [u8; 32],
    ) -> Result<Self, ChunkKeyError> {
        Self::sign_v2(signer, room, join_nonce, stream, epoch, chunk_key, None).await
    }

    /// [`Self::sign`] with the v2 members (`Some`: a v2 binding naming the
    /// codec map, and `replaces` / `end` when set).
    ///
    /// # Errors
    /// As [`Self::sign`].
    pub async fn sign_v2(
        signer: &LocalSigner,
        room: &str,
        join_nonce: [u8; 32],
        stream: StreamId,
        epoch: Epoch,
        chunk_key: [u8; 32],
        v2: Option<V2Members>,
    ) -> Result<Self, ChunkKeyError> {
        let explicit_v2 = v2.is_some();
        let (codecs, replaces, end, final_seq, kind, framing) = match v2 {
            Some(m) => (
                m.codecs,
                m.replaces,
                m.end,
                m.final_seq.filter(|_| m.end.is_some()),
                m.kind,
                m.framing,
            ),
            None => (None, None, None, None, STREAM_KIND_MEDIA, FRAMING_NONE),
        };
        if call_stream_id(room, &signer.key_id, &join_nonce) != stream {
            return Err(ChunkKeyError::Binding(format!(
                "stream is not {}'s in room {room}",
                signer.key_id
            )));
        }
        let mut b = Self {
            room: room.to_owned(),
            publisher: signer.key_id.clone(),
            join_nonce,
            stream,
            epoch,
            chunk_key,
            sig_ed25519: Vec::new(),
            sig_ml_dsa_65: Vec::new(),
            codecs,
            replaces,
            end,
            final_seq: final_seq.or_else(|| end.map(|_| FINAL_SEQ_NONE)),
            kind,
            framing,
            explicit_v2,
        };
        let (ed_b64, pq_b64) =
            crate::identity::sign_bound_hybrid(signer, &b.signed_bytes(), "stream key binding")
                .await
                .map_err(ChunkKeyError::Binding)?;
        let pq_b64 = pq_b64.ok_or_else(|| ChunkKeyError::Binding("no ML-DSA-65 half".into()))?;
        let b64 = base64::engine::general_purpose::STANDARD;
        b.sig_ed25519 = b64
            .decode(ed_b64)
            .map_err(|e| ChunkKeyError::Binding(e.to_string()))?;
        b.sig_ml_dsa_65 = b64
            .decode(pq_b64)
            .map_err(|e| ChunkKeyError::Binding(e.to_string()))?;
        Ok(b)
    }

    /// The encoding: the unsigned body, then each signature length-prefixed.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.unsigned_body();
        put_bytes(&mut out, &self.sig_ed25519);
        put_bytes(&mut out, &self.sig_ml_dsa_65);
        out
    }

    /// Inverse of [`Self::to_bytes`].
    ///
    /// # Errors
    /// [`BindingError::Malformed`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, BindingError> {
        if b.len() > MAX_BINDING_LEN {
            return Err(BindingError::Malformed("too long"));
        }
        let mut r = Reader(b);
        let version = r.array::<1>()?[0];
        if version != BINDING_VERSION && version != BINDING_VERSION_V2 {
            return Err(BindingError::Malformed("version"));
        }
        let room = r.string()?;
        let publisher = r.string()?;
        let join_nonce = r.array::<32>()?;
        let stream = StreamId(r.array::<32>()?);
        let epoch = Epoch(u64::from_be_bytes(r.array::<8>()?));
        let chunk_key = r.array::<32>()?;
        let (codecs, replaces, end, final_seq, kind, framing) = if version == BINDING_VERSION_V2 {
            let codecs = CodecMap::decode(&mut r)?;
            let replaces = match r.array::<1>()?[0] {
                0 => None,
                1 => Some(StreamId(r.array::<32>()?)),
                _ => return Err(BindingError::Malformed("replaces")),
            };
            let end = SignedEnd::from_code(r.array::<1>()?[0])?;
            let final_seq = match end {
                Some(_) => Some(u64::from_be_bytes(r.array::<8>()?)),
                None => None,
            };
            // 7e kind: any value (an unknown one renders as media); 7f
            // framing: the chunk layout, so only a known one.
            let kind = r.array::<1>()?[0];
            let framing = r.array::<1>()?[0];
            if framing > FRAMING_FRAGMENTS {
                return Err(BindingError::Malformed("framing"));
            }
            // v45 — a v2 binding always states its kind and framing, so one
            // with no map, no replacement and no end still says something:
            // "framing 0". A v45 publisher signs one for every stream, so a
            // v2 receiver knows a stream's framing before parsing a chunk.
            (codecs, replaces, end, final_seq, kind, framing)
        } else {
            (None, None, None, None, STREAM_KIND_MEDIA, FRAMING_NONE)
        };
        let n = r.len16()?;
        let sig_ed25519 = r.take(n)?.to_vec();
        let n = r.len16()?;
        let sig_ml_dsa_65 = r.take(n)?.to_vec();
        if !r.0.is_empty() {
            return Err(BindingError::Malformed("trailing bytes"));
        }
        // CC 5.3.3.2.3 / CC 2.6.3: both fixed lengths MUST hold at parse.
        if sig_ed25519.len() != 64 || sig_ml_dsa_65.len() != ML_DSA_65_SIG_LEN {
            return Err(BindingError::Malformed("signature length"));
        }
        Ok(Self {
            room,
            publisher,
            join_nonce,
            stream,
            epoch,
            chunk_key,
            sig_ed25519,
            sig_ml_dsa_65,
            codecs,
            replaces,
            end,
            final_seq,
            kind,
            framing,
            explicit_v2: version == BINDING_VERSION_V2,
        })
    }

    /// The id a binding's parts carry: the first 8 bytes of SHA-256 over its
    /// encoding.
    #[must_use]
    pub fn id_of(wire: &[u8]) -> [u8; 8] {
        let d = Sha256::digest(wire);
        let mut id = [0u8; 8];
        id.copy_from_slice(&d[..8]);
        id
    }

    /// The encoding `wire` as Channel messages of at most `limit` bytes each
    /// ([`FALLBACK_PART_LIMIT`] when `None`). Empty when `limit` is too small
    /// for a part or the binding would take more than [`MAX_PARTS`].
    #[must_use]
    pub fn parts(wire: &[u8], limit: Option<usize>) -> Vec<Vec<u8>> {
        let limit = limit.unwrap_or(FALLBACK_PART_LIMIT);
        let Some(payload) = limit.checked_sub(PART_HEADER_LEN).filter(|p| *p >= 64) else {
            return Vec::new();
        };
        let chunks: Vec<&[u8]> = wire.chunks(payload).collect();
        let Ok(count) = u8::try_from(chunks.len()) else {
            return Vec::new();
        };
        if chunks.is_empty() || chunks.len() > MAX_PARTS {
            return Vec::new();
        }
        let id = Self::id_of(wire);
        chunks
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let mut p = Vec::with_capacity(PART_HEADER_LEN + c.len());
                p.extend_from_slice(&BINDING_PART_MAGIC);
                p.push(BINDING_PART_VERSION);
                p.extend_from_slice(&id);
                p.push(u8::try_from(i).unwrap_or(u8::MAX));
                p.push(count);
                p.extend_from_slice(c);
                p
            })
            .collect()
    }

    /// Check everything but the signature: the room, the stream id's
    /// derivation from the publisher, and the publisher's membership.
    ///
    /// # Errors
    /// [`BindingError::OtherRoom`], [`BindingError::NotThePublishersStream`],
    /// [`BindingError::NotAMember`].
    pub fn check_shape(&self, room: &str, members: &[String]) -> Result<(), BindingError> {
        if self.room != room {
            return Err(BindingError::OtherRoom(self.room.clone()));
        }
        if call_stream_id(&self.room, &self.publisher, &self.join_nonce) != self.stream {
            return Err(BindingError::NotThePublishersStream(self.publisher.clone()));
        }
        if !members.contains(&self.publisher) {
            return Err(BindingError::NotAMember(self.publisher.clone()));
        }
        Ok(())
    }

    /// Verify the publisher's hybrid signature through `verifier`.
    ///
    /// # Errors
    /// [`BindingError::Signature`].
    pub async fn verify_signature(
        &self,
        verifier: &dyn StreamKeyVerifier,
    ) -> Result<(), BindingError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        verifier
            .verify_publisher_signature(
                &self.signed_bytes(),
                &self.publisher,
                &b64.encode(&self.sig_ed25519),
                &b64.encode(&self.sig_ml_dsa_65),
            )
            .await
            .map_err(BindingError::Signature)
    }
}

/// Verifies a publisher's hybrid signature over a binding, against the
/// publisher's federation key. Blanket-implemented over persist's directory
/// (`HybridPolicy::Strict`: both halves must verify).
#[async_trait::async_trait]
pub trait StreamKeyVerifier: Send + Sync {
    /// Verify `ed25519_sig_b64` + `ml_dsa_65_sig_b64` over `signed` as
    /// `key_id`'s.
    ///
    /// # Errors
    /// Why it did not verify.
    async fn verify_publisher_signature(
        &self,
        signed: &[u8],
        key_id: &str,
        ed25519_sig_b64: &str,
        ml_dsa_65_sig_b64: &str,
    ) -> Result<(), String>;
}

#[async_trait::async_trait]
impl<F: ciris_persist::federation::FederationDirectory + ?Sized> StreamKeyVerifier for F {
    async fn verify_publisher_signature(
        &self,
        signed: &[u8],
        key_id: &str,
        ed25519_sig_b64: &str,
        ml_dsa_65_sig_b64: &str,
    ) -> Result<(), String> {
        use ciris_persist::prelude::{HybridPolicy, VerifyOutcome};
        match ciris_persist::prelude::verify_hybrid_via_directory(
            self,
            signed,
            key_id,
            ed25519_sig_b64,
            Some(ml_dsa_65_sig_b64),
            HybridPolicy::Strict,
            None,
        )
        .await
        {
            Ok(VerifyOutcome::HybridVerified) => Ok(()),
            Ok(other) => Err(format!("not hybrid-verified: {other:?}")),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// [`StreamKeyVerifier`] over a shared persist directory handle (a
/// `dyn FederationDirectory` cannot itself be made a `dyn StreamKeyVerifier`).
pub struct DirectoryKeys(pub Arc<dyn ciris_persist::federation::FederationDirectory>);

#[async_trait::async_trait]
impl StreamKeyVerifier for DirectoryKeys {
    async fn verify_publisher_signature(
        &self,
        signed: &[u8],
        key_id: &str,
        ed25519_sig_b64: &str,
        ml_dsa_65_sig_b64: &str,
    ) -> Result<(), String> {
        self.0
            .as_ref()
            .verify_publisher_signature(signed, key_id, ed25519_sig_b64, ml_dsa_65_sig_b64)
            .await
    }
}

// ─── reassembly ─────────────────────────────────────────────────────

/// What one inbound frame was, to the [`BindingAssembler`].
#[derive(Debug, PartialEq, Eq)]
pub enum Part {
    /// Not a binding part: a chunk.
    NotAPart,
    /// A part; the binding is not complete yet.
    Incomplete,
    /// The last missing part: the binding's encoding.
    Complete(Vec<u8>),
    /// A malformed part, dropped.
    Malformed,
}

struct Pending {
    id: [u8; 8],
    count: u8,
    parts: Vec<Option<Vec<u8>>>,
    bytes: usize,
}

/// Reassembles one link's binding parts, bounded: at most [`MAX_PENDING`]
/// bindings in flight (the oldest is dropped), each at most
/// [`MAX_BINDING_LEN`] bytes in at most [`MAX_PARTS`] parts.
#[derive(Default)]
pub struct BindingAssembler {
    pending: VecDeque<Pending>,
}

impl BindingAssembler {
    /// Whether `frame` is a binding part (its 5-byte prefix).
    #[must_use]
    pub fn is_part(frame: &[u8]) -> bool {
        frame.len() >= PART_HEADER_LEN
            && frame[..4] == BINDING_PART_MAGIC
            && frame[4] == BINDING_PART_VERSION
    }

    /// Take one inbound frame.
    pub fn push(&mut self, frame: &[u8]) -> Part {
        if !Self::is_part(frame) {
            return Part::NotAPart;
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(&frame[5..13]);
        let (index, count) = (frame[13], frame[14]);
        let payload = &frame[PART_HEADER_LEN..];
        if count == 0 || usize::from(count) > MAX_PARTS || index >= count || payload.is_empty() {
            return Part::Malformed;
        }
        let slot = if let Some(i) = self.pending.iter().position(|p| p.id == id) {
            i
        } else {
            if self.pending.len() >= MAX_PENDING {
                self.pending.pop_front();
            }
            self.pending.push_back(Pending {
                id,
                count,
                parts: vec![None; usize::from(count)],
                bytes: 0,
            });
            self.pending.len() - 1
        };
        let p = &mut self.pending[slot];
        if p.count != count {
            self.pending.remove(slot);
            return Part::Malformed;
        }
        if p.parts[usize::from(index)].is_none() {
            p.bytes += payload.len();
            if p.bytes > MAX_BINDING_LEN {
                self.pending.remove(slot);
                return Part::Malformed;
            }
            p.parts[usize::from(index)] = Some(payload.to_vec());
        }
        if p.parts.iter().any(Option::is_none) {
            return Part::Incomplete;
        }
        let Some(p) = self.pending.remove(slot) else {
            return Part::Malformed;
        };
        let wire: Vec<u8> = p.parts.into_iter().flatten().flatten().collect();
        if StreamKeyBinding::id_of(&wire) != p.id {
            return Part::Malformed;
        }
        Part::Complete(wire)
    }
}

// ─── the receiver's bound keys ──────────────────────────────────────

/// A verified binding as a receiver holds it.
#[derive(Debug, Clone)]
pub struct Bound {
    /// The stream's publisher.
    pub publisher: Arc<str>,
    /// Its chunk key for the epoch.
    pub key: [u8; 32],
    /// The binding's v1 encoding, to forward (`None` when only a v2 one came).
    pub wire: Option<Arc<Vec<u8>>>,
    /// Its v2 encoding (it names the codec), to forward to peers that take
    /// v2.
    pub wire_v2: Option<Arc<Vec<u8>>>,
    /// v45 — the epoch's framing, from its v2 binding ([`FRAMING_NONE`]
    /// while only a v1 one came).
    pub framing: u8,
}

/// Why a chunk was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChunkAuthError {
    /// No verified binding for the chunk's `(stream, epoch)`.
    #[error("no bound chunk key for the chunk's stream and epoch")]
    Unbound,
    /// The inner unit is too short to carry the 64-byte trailer.
    #[error("chunk carries no source signature")]
    TrailerMissing,
    /// The trailer does not verify under the stream's bound key.
    #[error("chunk signature does not verify under the stream's bound key")]
    TrailerInvalid,
    /// The stream's v2 binding names no codec for the chunk's layer class.
    #[error("the stream's codec map has no entry for the chunk's class")]
    ClassUnlisted,
    /// The stream's map names a codec for the class this receiver does not
    /// know: dropped here, the binding standing.
    #[error("the stream's codec for the chunk's class is not one this receiver decodes")]
    ClassUndecodable,
    /// The chunk's `chunk_seq` is past its stream's signed `final_seq`.
    #[error("the chunk is past its stream's signed end")]
    PastEnd,
}

impl ChunkAuthError {
    /// The refusal's stable token.
    #[must_use]
    pub const fn refusal(self) -> AvAuthRefusal {
        match self {
            Self::Unbound => AvAuthRefusal::ChunkUnbound,
            Self::TrailerMissing => AvAuthRefusal::ChunkTrailerMissing,
            Self::TrailerInvalid => AvAuthRefusal::ChunkTrailerInvalid,
            Self::ClassUnlisted => AvAuthRefusal::ChunkClassUnlisted,
            Self::ClassUndecodable => AvAuthRefusal::ChunkClassUndecodable,
            Self::PastEnd => AvAuthRefusal::ChunkPastEnd,
        }
    }

    /// Missing or invalid trailer: not the publisher's chunk.
    #[must_use]
    pub const fn is_forged(self) -> bool {
        matches!(self, Self::TrailerMissing | Self::TrailerInvalid)
    }
}

/// What [`ChunkAuth`] counted.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ChunkAuthCounts {
    /// Chunks whose signature verified.
    pub verified: u64,
    /// Chunks dropped: missing or invalid trailer.
    pub forged: u64,
    /// Chunks dropped: no bound key.
    pub unbound: u64,
    /// Bindings verified and installed.
    pub bindings_installed: u64,
    /// Bindings refused.
    pub bindings_refused: u64,
    /// Chunks dropped: their class's codec is one this receiver does not
    /// know (v45).
    pub undecodable: u64,
    /// Chunks refused: past their stream's signed `final_seq` (v45).
    pub past_end: u64,
    /// Signed ends whose `final_seq` this receiver never received up to:
    /// a tail dropped on the way (v45).
    pub truncated: u64,
}

#[derive(Default)]
struct Held {
    bound: HashMap<(StreamId, u64), Bound>,
    /// Per publisher, its bound streams, oldest first.
    streams: HashMap<Arc<str>, VecDeque<StreamId>>,
    /// Binding ids already verified and installed.
    seen: VecDeque<[u8; 8]>,
    /// The codec each stream's v2 bindings named: one per stream for its
    /// life.
    codecs: HashMap<StreamId, CodecMap>,
    /// Streams whose signed end was verified: `(epoch, final_seq)`. Kept
    /// apart from the bound streams (and bounded on its own), so a replayed
    /// old end can neither evict a live stream nor end a new one.
    ended: HashMap<StreamId, (u64, u64)>,
    ended_order: VecDeque<StreamId>,
    /// Ended streams whose tail never fully arrived.
    truncated: std::collections::HashSet<StreamId>,
    /// v45 — streams a verified `replaces` named (still bound for their
    /// overlap): the first a publisher's newest-streams bound evicts, oldest
    /// first, so a live stream is never pushed out by replacements.
    retired: std::collections::HashSet<StreamId>,
    /// The highest verified `chunk_seq` per `(stream, epoch)`.
    highest: HashMap<(StreamId, u64), u64>,
}

/// What a completed binding came to.
#[derive(Debug, Clone)]
pub enum BindingOutcome {
    /// Verified now and installed.
    Installed(StreamKeyBinding),
    /// Already verified on an earlier copy; nothing new.
    Known(StreamKeyBinding),
    /// Refused.
    Refused(BindingError),
}

/// A receiver's (and a relay's) chunk keys: the verified bindings of the
/// call's streams, at most the two newest epochs per stream and
/// [`MAX_STREAMS_PER_PUBLISHER`] streams per publisher.
pub struct ChunkAuth {
    room: String,
    held: StdMutex<Held>,
    verified: AtomicU64,
    forged: AtomicU64,
    unbound: AtomicU64,
    installed: AtomicU64,
    refused: AtomicU64,
    undecodable: AtomicU64,
    past_end: AtomicU64,
    truncated: AtomicU64,
}

impl ChunkAuth {
    /// No bindings yet, for `room`'s call.
    #[must_use]
    pub fn new(room: &str) -> Self {
        Self {
            room: room.to_owned(),
            held: StdMutex::new(Held::default()),
            verified: AtomicU64::new(0),
            forged: AtomicU64::new(0),
            unbound: AtomicU64::new(0),
            installed: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            undecodable: AtomicU64::new(0),
            past_end: AtomicU64::new(0),
            truncated: AtomicU64::new(0),
        }
    }

    fn held(&self) -> std::sync::MutexGuard<'_, Held> {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The counters so far.
    #[must_use]
    pub fn counts(&self) -> ChunkAuthCounts {
        ChunkAuthCounts {
            verified: self.verified.load(Ordering::Relaxed),
            forged: self.forged.load(Ordering::Relaxed),
            unbound: self.unbound.load(Ordering::Relaxed),
            bindings_installed: self.installed.load(Ordering::Relaxed),
            bindings_refused: self.refused.load(Ordering::Relaxed),
            undecodable: self.undecodable.load(Ordering::Relaxed),
            past_end: self.past_end.load(Ordering::Relaxed),
            truncated: self.truncated.load(Ordering::Relaxed),
        }
    }

    /// Take a completed binding's encoding: parse, check (`members` is the
    /// room's MLS group), verify the publisher's hybrid signature (once per
    /// binding), and install it.
    pub async fn accept_binding(
        &self,
        wire: &[u8],
        members: &[String],
        verifier: &dyn StreamKeyVerifier,
    ) -> BindingOutcome {
        let id = StreamKeyBinding::id_of(wire);
        let binding = match StreamKeyBinding::from_bytes(wire) {
            Ok(b) => b,
            Err(e) => return self.refuse(e),
        };
        if self.held().seen.contains(&id) {
            return BindingOutcome::Known(binding);
        }
        // A signed end is final: a later binding for the stream costs no
        // hybrid verification and changes nothing.
        if self.held().ended.contains_key(&binding.stream) {
            return self.refuse(BindingError::StreamEnded);
        }
        if let Err(e) = binding.check_shape(&self.room, members) {
            return self.refuse(e);
        }
        if let Err(e) = binding.verify_signature(verifier).await {
            return self.refuse(e);
        }
        match self.install(&binding, Arc::new(wire.to_vec())) {
            Ok(()) => {
                self.remember(id);
                self.installed.fetch_add(1, Ordering::Relaxed);
                BindingOutcome::Installed(binding)
            }
            Err(e) => self.refuse(e),
        }
    }

    fn remember(&self, id: [u8; 8]) {
        let mut held = self.held();
        if held.seen.len() >= SEEN_IDS {
            held.seen.pop_front();
        }
        held.seen.push_back(id);
    }

    /// A refusal is not remembered: the cause may pass (a member list that
    /// lags the room, a directory that has not yet learned the publisher's
    /// key), and the checks before the hybrid verification cost no lookup.
    fn refuse(&self, e: BindingError) -> BindingOutcome {
        self.refused.fetch_add(1, Ordering::Relaxed);
        BindingOutcome::Refused(e)
    }

    /// Install a VERIFIED binding (the caller verified it). Keeps the two
    /// newest epochs of its stream and the publisher's newest streams.
    ///
    /// # Errors
    /// [`BindingError::Stale`] for an epoch older than the two held.
    pub(crate) fn install(
        &self,
        binding: &StreamKeyBinding,
        wire: Arc<Vec<u8>>,
    ) -> Result<(), BindingError> {
        let mut held = self.held();
        let stream = binding.stream;
        let epoch = binding.epoch.0;
        // A signed end is final: no further binding for the stream.
        if held.ended.contains_key(&stream) {
            return Err(BindingError::StreamEnded);
        }
        let mut epochs: Vec<u64> = held
            .bound
            .keys()
            .filter(|(s, _)| *s == stream)
            .map(|(_, e)| *e)
            .collect();
        epochs.sort_unstable();
        if epochs.len() >= 2 && epoch < epochs[epochs.len() - 2] {
            return Err(BindingError::Stale(epoch));
        }
        // One codec map per stream for its life (CC reading (rc17), pending
        // text): a v2 binding naming another map than the stream's is
        // refused, in any epoch. A codec change is a new join nonce, hence a
        // new stream.
        if let Some(got) = &binding.codecs {
            match held.codecs.get(&stream) {
                Some(held_map) if held_map != got => {
                    return Err(BindingError::CodecChanged {
                        held: held_map.to_string(),
                        got: got.to_string(),
                    });
                }
                Some(_) => {}
                None => {
                    held.codecs.insert(stream, *got);
                }
            }
        }
        let publisher: Arc<str> = Arc::from(binding.publisher.as_str());
        let v2 = binding.version() == BINDING_VERSION_V2;
        // The v1 and v2 encodings of one (stream, epoch) bind the same key:
        // keep both, to forward each to the peers that take it.
        let (mut wire_v1, mut wire_v2, mut framing) = match held.bound.get(&(stream, epoch)) {
            Some(b) if b.key == binding.chunk_key => (b.wire.clone(), b.wire_v2.clone(), b.framing),
            _ => (None, None, FRAMING_NONE),
        };
        if v2 {
            wire_v2 = Some(wire);
            framing = binding.framing;
        } else {
            wire_v1 = Some(wire);
        }
        held.bound.insert(
            (stream, epoch),
            Bound {
                publisher: Arc::clone(&publisher),
                key: binding.chunk_key,
                wire: wire_v1,
                wire_v2,
                framing,
            },
        );
        // The two newest epochs of the stream.
        epochs.push(epoch);
        epochs.sort_unstable();
        epochs.dedup();
        if epochs.len() > 2 {
            for e in &epochs[..epochs.len() - 2] {
                held.bound.remove(&(stream, *e));
                held.highest.remove(&(stream, *e));
            }
        }
        // The publisher's newest streams. An ended stream leaves the list (it
        // is bound only until its verdict, `settle_end`), so ending a share
        // never pushes out the camera.
        // A replacement retires the stream it names (the same publisher's).
        if let Some(old) = binding.replaces.filter(|o| *o != stream) {
            if held
                .streams
                .get(&publisher)
                .is_some_and(|l| l.contains(&old))
            {
                held.retired.insert(old);
            }
        }
        let evicted = {
            let Held {
                streams, retired, ..
            } = &mut *held;
            let list = streams.entry(publisher).or_default();
            list.retain(|s| *s != stream);
            if binding.end.is_none() {
                list.push_back(stream);
            }
            if list.len() > MAX_STREAMS_PER_PUBLISHER {
                // The oldest retired stream goes first; a live one only when
                // none is retired.
                let at = list.iter().position(|s| retired.contains(s)).unwrap_or(0);
                list.remove(at)
            } else {
                None
            }
        };
        if let Some(old) = evicted {
            held.retired.remove(&old);
            held.bound.retain(|(s, _), _| *s != old);
            held.codecs.remove(&old);
            held.highest.retain(|(s, _), _| *s != old);
        }
        // The signed end. Whether its tail arrived is settled later
        // ([`Self::settle_end`]): chunks up to `final_seq` still in flight
        // when the end lands are not a truncation.
        if binding.end.is_some() {
            let final_seq = binding.final_seq.unwrap_or(FINAL_SEQ_NONE);
            held.ended.insert(stream, (epoch, final_seq));
            held.ended_order.push_back(stream);
            while held.ended_order.len() > ENDED_REMEMBERED {
                if let Some(old) = held.ended_order.pop_front() {
                    held.ended.remove(&old);
                    held.truncated.remove(&old);
                    held.highest.retain(|(s, _), _| *s != old);
                }
            }
        }
        Ok(())
    }

    /// v45 — the truncation verdict on `stream`'s signed end, taken once
    /// the reorder window after the end has passed (the caller's clock):
    /// `true` when this receiver never verified a chunk up to the end's
    /// `final_seq` (a dropped tail). Only chunks at or below `final_seq`
    /// count: one past it is refused and never recorded. Counted once per
    /// stream; `false` for a stream with no verified end, or an end that
    /// names no tail (`final_seq` none).
    pub fn settle_end(&self, stream: StreamId) -> bool {
        let mut held = self.held();
        let Some((epoch, final_seq)) = held.ended.get(&stream).copied() else {
            return false;
        };
        let got = held.highest.get(&(stream, epoch)).copied();
        let short = final_seq != FINAL_SEQ_NONE && got.is_none_or(|h| h < final_seq);
        if short && held.truncated.insert(stream) {
            self.truncated.fetch_add(1, Ordering::Relaxed);
        }
        // Past the verdict nothing of it plays: its keys go. Its highest seq
        // stays (presence) until the ended set forgets it.
        held.bound.retain(|(s, _), _| *s != stream);
        held.codecs.remove(&stream);
        short
    }

    /// The bound key for `(stream, epoch)`, if any.
    #[must_use]
    pub fn bound(&self, stream: StreamId, epoch: Epoch) -> Option<Bound> {
        self.held().bound.get(&(stream, epoch.0)).cloned()
    }

    /// Every held binding whose publisher is not `except`, to send on a new
    /// leg (a relay's): each v1 encoding, and each v2 one too when the peer
    /// takes v2 (`v2_ok`).
    #[must_use]
    pub fn bindings_except(&self, except: &str, v2_ok: bool) -> Vec<Arc<Vec<u8>>> {
        self.held()
            .bound
            .values()
            .filter(|b| &*b.publisher != except)
            .flat_map(|b| {
                let v2 = b.wire_v2.clone().filter(|_| v2_ok);
                b.wire.clone().into_iter().chain(v2)
            })
            .collect()
    }

    /// v45 — `(stream, epoch)`'s framing when its v2 binding is installed;
    /// `None` while only its v1 binding is (or none).
    #[must_use]
    pub fn v2_framing(&self, stream: StreamId, epoch: Epoch) -> Option<u8> {
        self.held()
            .bound
            .get(&(stream, epoch.0))
            .filter(|b| b.wire_v2.is_some())
            .map(|b| b.framing)
    }

    /// v45 — whether any epoch of `stream` is bound here.
    #[must_use]
    pub fn is_bound(&self, stream: StreamId) -> bool {
        self.held().bound.keys().any(|(s, _)| *s == stream)
    }

    /// Whether this receiver ever verified a chunk of `stream`: its presence,
    /// which a binding alone never proves (an old `end = 0` binding of a
    /// stream that has since gone is no attendee).
    #[must_use]
    pub fn heard(&self, stream: StreamId) -> bool {
        self.held().highest.keys().any(|(s, _)| *s == stream)
    }

    /// Whether `stream`'s signed end named a `final_seq` this receiver never
    /// received up to (a dropped tail).
    #[must_use]
    pub fn truncated(&self, stream: StreamId) -> bool {
        self.held().truncated.contains(&stream)
    }

    /// The codec map `stream`'s v2 bindings named, if any came.
    #[must_use]
    pub fn codecs_of(&self, stream: StreamId) -> Option<CodecMap> {
        self.held().codecs.get(&stream).copied()
    }

    /// **The per-chunk check**: the chunk's signature (its last
    /// [`CHUNK_SIG_LEN`] bytes) under the key bound to its `(stream, epoch)`.
    /// Returns the publisher and the chunk with the trailer removed, ready
    /// for the inner open. A map lookup and one Ed25519 verification; nothing
    /// else.
    ///
    /// # Errors
    /// As [`Self::check_timed`].
    pub fn check(&self, inner: &InnerSealed) -> Result<(Arc<str>, InnerSealed), ChunkAuthError> {
        self.check_timed(inner).map(|(p, i, _)| (p, i))
    }

    /// [`Self::check`], also returning the publisher's signed source
    /// timestamp (UNIX ms).
    ///
    /// # Errors
    /// [`ChunkAuthError::Unbound`], [`ChunkAuthError::TrailerMissing`] or
    /// [`ChunkAuthError::TrailerInvalid`], each counted.
    pub fn check_timed(
        &self,
        inner: &InnerSealed,
    ) -> Result<(Arc<str>, InnerSealed, u64), ChunkAuthError> {
        let Some(bound) = self.bound(inner.stream_id(), inner.epoch()) else {
            self.unbound.fetch_add(1, Ordering::Relaxed);
            return Err(ChunkAuthError::Unbound);
        };
        let ct = inner.inner_ciphertext();
        let Some(split) = ct.len().checked_sub(CHUNK_TRAILER_LEN) else {
            self.forged.fetch_add(1, Ordering::Relaxed);
            return Err(ChunkAuthError::TrailerMissing);
        };
        let (aead, trailer) = ct.split_at(split);
        let (ts, sig) = trailer.split_at(CHUNK_SOURCE_TS_LEN);
        let mut tsb = [0u8; CHUNK_SOURCE_TS_LEN];
        tsb.copy_from_slice(ts);
        let source_ms = u64::from_be_bytes(tsb);
        let ok = Ed25519Verifier::new()
            .verify_strict(&bound.key, &chunk_sig_message(inner, aead, source_ms), sig)
            .unwrap_or(false);
        if !ok {
            self.forged.fetch_add(1, Ordering::Relaxed);
            return Err(ChunkAuthError::TrailerInvalid);
        }
        {
            let mut held = self.held();
            let stream = inner.stream_id();
            // CC reading (rc17) of 5.3.3.2.1, pending text: a stream that
            // named its codecs carries only those classes; a class whose
            // codec this build does not know is dropped here. A v1-only
            // stream (no map) is not checked: v44 sends video as 0x01 under
            // v1.
            if let Some(map) = held.codecs.get(&stream) {
                match map.class_codec(inner.codec_id()) {
                    ClassCodec::Absent => {
                        self.unbound.fetch_add(1, Ordering::Relaxed);
                        return Err(ChunkAuthError::ClassUnlisted);
                    }
                    ClassCodec::Undecodable => {
                        self.undecodable.fetch_add(1, Ordering::Relaxed);
                        return Err(ChunkAuthError::ClassUndecodable);
                    }
                    ClassCodec::Known(_) => {}
                }
            }
            // Nothing past a signed end plays.
            let epoch = inner.epoch().0;
            let seq = inner.chunk_seq().0;
            if let Some((e, final_seq)) = held.ended.get(&stream).copied() {
                if e == epoch && (final_seq == FINAL_SEQ_NONE || seq > final_seq) {
                    self.past_end.fetch_add(1, Ordering::Relaxed);
                    return Err(ChunkAuthError::PastEnd);
                }
            }
            let h = held.highest.entry((stream, epoch)).or_insert(seq);
            *h = (*h).max(seq);
        }
        self.verified.fetch_add(1, Ordering::Relaxed);
        Ok((
            bound.publisher,
            with_ciphertext(inner, aead.to_vec()),
            source_ms,
        ))
    }
}

#[cfg(test)]
#[path = "av_chunk_auth/tests.rs"]
mod tests;
