//! Realtime A/V mesh profile — direct Reticulum Links for low-latency
//! group communication (CIRISEdge#62, CEG 0.13 §10.5.8).
//!
//! Closes the missing transport profile for **realtime group
//! communication** — group video, voice, desktop/screen sharing. The
//! broadcast pull path (§10.5.5 E2) ships sealed A/V chunks at 1–10s
//! latency: unusable for interactive calls. This module is the
//! complementary low-latency profile that owns small/medium rooms via
//! direct RNS Links.
//!
//! The mesh is infeasible above `N_mesh_max(uplink, codec, layer)`
//! participants per CEG §10.5.8 / `docs/FEDERATION_SCALING_MODEL.md` §4.
//! For 720p30 on a typical consumer connection this is ~13; for the
//! BLINKING_DOT receiver-layer policy it is >200. Above the mesh cap a
//! stream crosses over to the SFU relay
//! ([`super::realtime_av_relay::RelayNode`]); the per-(stream_id,
//! epoch) DEK and chunk-seal layouts defined here are the same as
//! that surface, only the transport profile differs.
//!
//! ## Two-layer crypto
//!
//! Per CEG §10.5.5 E1, every realtime chunk is sealed twice:
//!
//! ```text
//! wire = OuterAEAD( OuterTransitKey, OuterNonce,
//!           InnerAEAD( EpochDek, InnerNonce, chunk_plaintext ) )
//! ```
//!
//! - **Inner (epoch DEK)** is per `(stream_id, epoch)` and shared
//!   across the whole mesh. End-to-end secrecy: even a relay or
//!   compromised hop cannot read plaintext.
//! - **Outer (transit key)** is per direct RNS Link, set up via the
//!   hybrid X25519+ML-KEM-768 KEX from [`crate::transport::federation_session`]
//!   (CIRISEdge#54). Hop authenticity + replay protection: a transit
//!   attacker cannot inject a chunk targeted at a participant they
//!   don't have a Link to.
//!
//! Both AEAD primitives are AES-256-GCM via `ring` (centralized in
//! `ciris_crypto::aes_gcm`). PQ posture: hybrid for transit (#54);
//! the epoch DEK is itself distributed via the [key-grant
//! wrap](https://github.com/CIRISAI/CIRISVerify) surface which is
//! already hybrid-PQC (X25519+ML-KEM-768 wrap), so the full path is
//! hybrid-PQC end-to-end.
//!
//! ## Fan-out — presence drives reach
//!
//! Realtime fan-out filters by **entitled ∧ reachable** per CEG
//! §10.5.6 D6. Entitlement (am I allowed to receive stream X?) is the
//! caller's responsibility (per-stream ACL via key_grant). Reachability
//! (is the participant actually reachable right now?) is queried from
//! the existing [`crate::reachability::ReachabilityTracker`]; for
//! realtime the relevant TTL drops from minutes to seconds, so this
//! module owns a tightened ratio threshold ([`REALTIME_MIN_RATIO`])
//! that callers can override.
//!
//! ## Fan-out optimization (inner-once / outer-N)
//!
//! Sending one frame to N mesh participants via [`seal_av_chunk`] N
//! times re-does the **inner** AEAD work N times, but the inner seal
//! is identical across the whole mesh (the inner nonce is
//! `(stream_id, epoch, chunk_seq)` only — no per-Link input — and the
//! epoch DEK is mesh-wide). [`seal_av_inner`] computes the inner half
//! once; [`seal_av_outer`] applies the per-Link outer seal N times.
//! Measured ~1.98× speedup at N=50, 16 KiB frames (CIRISEdge#122).
//!
//! Wire shape is byte-identical to N × [`seal_av_chunk`] — pure
//! sender-side optimization, no codec implication.
//!
//! ## What this module IS
//!
//! - Single-chunk seal / open ([`seal_av_chunk`], [`open_av_chunk`]).
//! - Fan-out seal split ([`seal_av_inner`] + [`seal_av_outer`], #122).
//! - Wire shape definitions ([`SealedAvChunk`], [`StreamId`], [`Epoch`],
//!   [`EpochDek`]).
//! - The mesh-participant filter ([`RealtimeFanout::plan`]) over the
//!   existing reachability tracker.
//!
//! ## What this module is NOT (separate work, well-scoped follow-ups)
//!
//! - **The RNS Link send/recv plumbing.** That code lives in
//!   `transport/reticulum.rs` and integrates the [`SealedAvChunk`]
//!   bytes into the existing `link_open` / outbound packet path. The
//!   [`SealedAvChunk::to_bytes`] / `from_bytes` codec is the contract.
//! - **The broadcast pull profile interop.** A stream with both pull
//!   viewers + mesh participants uses the same chunk-seal shape; the
//!   pull-path serializer is a separate surface that lifts the
//!   `(stream_id, epoch, chunk_seq, sealed_bytes)` tuple from this
//!   module into its own delivery wire. No re-encryption required.
//! - **Epoch rotation** (`(stream_id, epoch) → next_epoch`). The DEK
//!   distribution surface is `key_grant` + the broadcast-pull
//!   discovery; this module consumes the rotated DEK but does not
//!   drive the rotation.

use ciris_crypto::aes_gcm;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::reachability::ReachabilityTracker;
use crate::transport::TransportId;

/// Per-stream identity — 32 bytes, derived by callers as `sha256(stream_meta)`.
/// The exact derivation lives upstream (lens / agent UX); this module treats
/// it as an opaque key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(pub [u8; 32]);

/// Monotonic epoch counter per stream. Each epoch corresponds to one
/// `EpochDek`. Rotation cadence is per-stream policy (typical: every
/// 60s or every Nth chunk, whichever first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Epoch(pub u64);

/// 32-byte end-to-end DEK for a `(stream_id, epoch)` pair. Distributed
/// to entitled participants via the `key_grant` wrap surface
/// (X25519+ML-KEM-768 hybrid PQC at the wrap layer, AES-256-GCM at the
/// chunk layer once the DEK lands at the participant).
///
/// Zeroized on drop; `Debug` redacts.
pub struct EpochDek([u8; 32]);

impl EpochDek {
    /// Construct from caller-owned bytes (the key_grant unwrap output).
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    /// Borrow the raw bytes — for the AEAD path only.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for EpochDek {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for EpochDek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochDek")
            .field("bytes", &"<redacted 32B>")
            .finish()
    }
}

/// Newtype around the chunk sequence number per `(stream_id, epoch)`.
/// Used for deterministic nonce derivation — see [`derive_inner_nonce`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChunkSeq(pub u64);

// ─── CIRISEdge#128 — codec namespace + per-receiver layer policy ─────
//
// The chunk wire gains a 1-byte `codec_id` + 3-byte [`ChunkLayer`] block
// after the 48-byte header. Each axis of [`ChunkLayer`] is monotonic:
// layer 0 is the base — lowest fidelity along that axis, always required
// to reconstruct anything — and each increment doubles the bandwidth
// contribution of that axis. A chunk with `spatial = 2` IS the spatial
// layer-2 enhancement only; receivers reconstruct from the prefix
// `0..=max_spatial × 0..=max_temporal × 0..=max_quality`.
//
// SVC base-layer invariant: `ChunkLayer { 0, 0, 0 }` is the "blinking
// dot" — the minimum a receiver can subscribe to. AV1 SVC (the default
// codec in 2026 — Google Meet / Teams / WebRTC ship it) supports up to
// 3 spatial × 4 temporal × multiple SNR layers concurrently.

/// AV1 SVC — the production-grade scalable codec; default for realtime
/// mesh video (CIRISEdge#128).
pub const CODEC_AV1_SVC: u8 = 0x01;

/// JPEG XS layered — reserved for low-latency intra-only / broadcast use
/// cases. Not yet wired on edge.
pub const CODEC_JPEG_XS: u8 = 0x02;

/// Symmetric multiple-description coding — reserved for the future
/// HNDL fragment-loss-resilient research track.
pub const CODEC_MDC: u8 = 0x03;

/// Codec-opaque — v3.7.0 wire compatibility marker. A chunk with
/// `codec_id == CODEC_OPAQUE` carries no scalable-coding semantics; its
/// `layer` MUST be `ChunkLayer { 0, 0, 0 }` and receivers MUST admit it
/// unconditionally regardless of their `ReceiverLayerPolicy`. This is
/// the value the read-side stamps when parsing a pre-#128 wire that
/// lacks the trailing 4-byte block.
pub const CODEC_OPAQUE: u8 = 0xFF;

/// SVC layer descriptor — three monotonic axes addressing the
/// scalable-coding cell of a single chunk.
///
/// Each axis is encoded as a `u8` where 0 is the base layer for that
/// axis. Receivers reconstruct from the prefix
/// `0..=max_spatial × 0..=max_temporal × 0..=max_quality` of cells —
/// i.e. lower layers are *required* and higher layers are *additive*.
/// The "blinking dot" is `ChunkLayer { spatial: 0, temporal: 0,
/// quality: 0 }`: the lowest-fidelity keyframes at the lowest framerate
/// and SNR, the minimum a participant can subscribe to.
///
/// Wire shape: 3 bytes (spatial, temporal, quality), placed in the
/// chunk header immediately after the 1-byte `codec_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChunkLayer {
    /// SVC spatial layer (0 = base resolution; each increment doubles
    /// pixel count along the spatial axis).
    pub spatial: u8,
    /// SVC temporal layer (0 = base framerate; each increment doubles
    /// the framerate contribution).
    pub temporal: u8,
    /// SVC SNR / quality layer (0 = base quantizer; each increment
    /// refines the residual at the same resolution + framerate).
    pub quality: u8,
}

impl ChunkLayer {
    /// The base layer cell — `(0, 0, 0)`. Always required for any
    /// reconstruction; corresponds to the "blinking dot" UX.
    pub const BASE: Self = Self {
        spatial: 0,
        temporal: 0,
        quality: 0,
    };
}

/// Per-receiver layer-admission policy. A receiver advertises this over
/// the existing `federation_session` / `key_grant` entitlement surface
/// (not a new wire); the sender uses it to drop chunks above the policy
/// without re-encoding the stream.
///
/// Combines cleanly with the inner-once / outer-N fan-out optimization
/// (CIRISEdge#122): `seal_av_inner` runs once per chunk regardless of
/// receivers, and `seal_av_outer` runs only for the (receiver, chunk)
/// pairs the receiver's policy admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReceiverLayerPolicy {
    /// Maximum acceptable spatial layer. A chunk with `spatial >
    /// max_spatial` is dropped.
    pub max_spatial: u8,
    /// Maximum acceptable temporal layer.
    pub max_temporal: u8,
    /// Maximum acceptable quality (SNR) layer.
    pub max_quality: u8,
}

impl ReceiverLayerPolicy {
    /// "Blinking dot" — accepts only the base cell `(0, 0, 0)`. Lowest
    /// possible bandwidth and the user-facing extreme of dyadic
    /// degradation (CIRISEdge#128).
    pub const BLINKING_DOT: Self = Self {
        max_spatial: 0,
        max_temporal: 0,
        max_quality: 0,
    };

    /// Uncapped — admits every layer the codec produces. The default
    /// for non-bandwidth-constrained receivers.
    pub const UNCAPPED: Self = Self {
        max_spatial: u8::MAX,
        max_temporal: u8::MAX,
        max_quality: u8::MAX,
    };

    /// Return `true` iff `layer` is within this receiver's per-axis
    /// caps.
    ///
    /// Semantics — `admits` is purely the per-axis layer test. A chunk
    /// tagged with [`CODEC_OPAQUE`] carries no scalable-coding
    /// semantics and MUST be admitted by the caller unconditionally
    /// regardless of policy; the fan-out filter (Layer 2 task T5)
    /// handles that short-circuit before consulting `admits`.
    #[must_use]
    pub fn admits(self, layer: ChunkLayer) -> bool {
        layer.spatial <= self.max_spatial
            && layer.temporal <= self.max_temporal
            && layer.quality <= self.max_quality
    }
}

/// The wire shape that lands on each RNS Link's payload. Same shape
/// the broadcast pull path serializes into its own delivery wire
/// (see module docs § "What this module is NOT").
///
/// CIRISEdge#128 adds the `codec_id` + `layer` block. Both are clear
/// metadata in the header, NOT inputs to the AEAD: a hop can drop a
/// chunk based on `(codec_id, layer)` without compromising the inner
/// DEK's end-to-end secrecy, and tampering with those fields just
/// causes the receiver to mis-decode or drop — it can't break crypto.
/// This is deliberate: layer-policy stripping at relay hops is the
/// architectural use case.
#[derive(Debug, Clone)]
pub struct SealedAvChunk {
    pub stream_id: StreamId,
    pub epoch: Epoch,
    pub chunk_seq: ChunkSeq,
    /// Codec discriminator — see [`CODEC_AV1_SVC`] / [`CODEC_JPEG_XS`]
    /// / [`CODEC_MDC`] / [`CODEC_OPAQUE`]. CIRISEdge#128.
    pub codec_id: u8,
    /// SVC layer descriptor. For `codec_id == CODEC_OPAQUE`, this MUST
    /// be `ChunkLayer { 0, 0, 0 }` and the chunk is admitted
    /// unconditionally by any [`ReceiverLayerPolicy`].
    pub layer: ChunkLayer,
    /// The double-sealed ciphertext: outer AEAD wraps inner AEAD wraps
    /// chunk plaintext. Both layers are AES-256-GCM (12B nonce + 16B
    /// tag, standard ring layout).
    pub double_sealed_ciphertext: Vec<u8>,
}

/// Length of the fixed-position chunk header (`stream_id` + `epoch` +
/// `chunk_seq`). Stable across v3.7.0 / v3.8.0.
pub const CHUNK_HEADER_LEN: usize = 48;

/// Length of the CIRISEdge#128 codec + layer block that follows the
/// fixed header on new wires. 1 byte `codec_id` + 3 bytes
/// [`ChunkLayer`] = 4 bytes. Absent on a v3.7.0 wire — the read side
/// defaults to `codec_id = CODEC_OPAQUE` + `layer = ChunkLayer::BASE`
/// when only the 48-byte header is present.
pub const CHUNK_CODEC_LAYER_LEN: usize = 4;

impl SealedAvChunk {
    /// Concrete wire encoding — fixed-shape header, codec + layer
    /// metadata, then ciphertext.
    ///
    /// ```text
    /// 0..32   stream_id
    /// 32..40  epoch        (big-endian u64)
    /// 40..48  chunk_seq    (big-endian u64)
    /// 48..49  codec_id     (CIRISEdge#128)
    /// 49..50  spatial      (CIRISEdge#128)
    /// 50..51  temporal     (CIRISEdge#128)
    /// 51..52  quality      (CIRISEdge#128)
    /// 52..    double_sealed_ciphertext
    /// ```
    ///
    /// New writes always include the 4-byte codec+layer block. The
    /// read side ([`Self::from_bytes`]) accepts the v3.7.0 wire shape
    /// (no trailing codec+layer bytes) by defaulting to
    /// `codec_id = CODEC_OPAQUE` + `layer = ChunkLayer::BASE`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            CHUNK_HEADER_LEN + CHUNK_CODEC_LAYER_LEN + self.double_sealed_ciphertext.len(),
        );
        out.extend_from_slice(&self.stream_id.0);
        out.extend_from_slice(&self.epoch.0.to_be_bytes());
        out.extend_from_slice(&self.chunk_seq.0.to_be_bytes());
        out.push(self.codec_id);
        out.push(self.layer.spatial);
        out.push(self.layer.temporal);
        out.push(self.layer.quality);
        out.extend_from_slice(&self.double_sealed_ciphertext);
        out
    }

    /// Inverse of [`Self::to_bytes`]. Returns `Err` if the input is
    /// shorter than the 52-byte header + codec+layer block.
    ///
    /// **v4.6.1 (Codex P1 fix)** — drops the prior length-only v3.7.0
    /// "backward-compat" branch. The branch was structurally unreachable
    /// for any real v3.7.0 wire (any AEAD-sealed chunk carries ≥16-byte
    /// GCM tag → ≥64-byte wire → always fell into the v3.8.0+ branch and
    /// misparsed 4 ciphertext bytes as `codec_id` + `ChunkLayer`). The
    /// "real-world v3.7.0 wires always carry the AES-GCM tag" caveat
    /// was correct; the branch was therefore dead code that misparsed
    /// every wire that wasn't synthetic-header-only.
    ///
    /// The substrate has been at v3.8.0+ for the entire CEWP-1.0 era
    /// (~6 months at v4.6.1); no production peers write the bare
    /// 48-byte header shape. Wires shorter than 52 bytes are now an
    /// explicit error.
    pub fn from_bytes(b: &[u8]) -> Result<Self, RealtimeAvError> {
        const WIRE_HEADER_LEN: usize = CHUNK_HEADER_LEN + CHUNK_CODEC_LAYER_LEN;
        if b.len() < WIRE_HEADER_LEN {
            return Err(RealtimeAvError::WireTooShort {
                got: b.len(),
                need: WIRE_HEADER_LEN,
            });
        }
        let mut stream_id = [0u8; 32];
        stream_id.copy_from_slice(&b[0..32]);
        let mut epoch_bytes = [0u8; 8];
        epoch_bytes.copy_from_slice(&b[32..40]);
        let epoch = Epoch(u64::from_be_bytes(epoch_bytes));
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&b[40..48]);
        let chunk_seq = ChunkSeq(u64::from_be_bytes(seq_bytes));

        // CIRISEdge#128 — codec+layer block at bytes 48..52, locked
        // since v3.8.0. Ciphertext is bytes 52..end.
        let codec_id = b[48];
        let layer = ChunkLayer {
            spatial: b[49],
            temporal: b[50],
            quality: b[51],
        };

        Ok(Self {
            stream_id: StreamId(stream_id),
            epoch,
            chunk_seq,
            codec_id,
            layer,
            double_sealed_ciphertext: b[WIRE_HEADER_LEN..].to_vec(),
        })
    }
}

/// Errors the realtime path can surface to callers.
#[derive(Debug, thiserror::Error)]
pub enum RealtimeAvError {
    #[error("inner AEAD failed: {0:?}")]
    InnerAead(ciris_crypto::CryptoError),
    #[error("outer AEAD failed: {0:?}")]
    OuterAead(ciris_crypto::CryptoError),
    #[error("sealed wire too short: got {got} bytes, need at least {need}")]
    WireTooShort { got: usize, need: usize },
}

/// Derive the inner-AEAD nonce deterministically from `(stream_id,
/// epoch, chunk_seq)`. The nonce is 12 bytes (the AES-GCM standard).
/// Determinism lets a fresh listener join a stream mid-flight and
/// recover plaintext for any chunk it can fetch — no per-chunk
/// nonce delivery needed.
///
/// Construction: SHA-256(label || stream_id || epoch || chunk_seq)[..12]
/// where `label = b"CIRIS-AV-INNER-V1"`. The label binds the nonce
/// to this module's purpose so a future inner-nonce derivation for a
/// different surface cannot collide.
pub fn derive_inner_nonce(stream_id: StreamId, epoch: Epoch, chunk_seq: ChunkSeq) -> [u8; 12] {
    let mut h = Sha256::new();
    h.update(b"CIRIS-AV-INNER-V1");
    h.update(stream_id.0);
    h.update(epoch.0.to_be_bytes());
    h.update(chunk_seq.0.to_be_bytes());
    let full = h.finalize();
    let mut out = [0u8; 12];
    out.copy_from_slice(&full[..12]);
    out
}

/// Derive the outer-AEAD nonce per Link from `(link_id, link_seq)`.
/// The `link_seq` is monotonic per RNS Link and prevents replay across
/// the transit hop. Construction follows the same shape as
/// [`derive_inner_nonce`] with a distinct label.
pub fn derive_outer_nonce(link_id: &[u8], link_seq: u64) -> [u8; 12] {
    let mut h = Sha256::new();
    h.update(b"CIRIS-AV-OUTER-V1");
    h.update(link_id);
    h.update(link_seq.to_be_bytes());
    let full = h.finalize();
    let mut out = [0u8; 12];
    out.copy_from_slice(&full[..12]);
    out
}

/// The inner-sealed half of a chunk — E2E ciphertext shared across the
/// whole mesh, *before* the per-Link outer seal is applied. Produced by
/// [`seal_av_inner`] once per `(stream_id, epoch, chunk_seq)` and
/// consumed N times by [`seal_av_outer`] (one per mesh participant).
///
/// Carries the chunk header (`stream_id` / `epoch` / `chunk_seq`) so
/// the outer step can stamp it into the wire shape without re-threading
/// those values through the call site.
///
/// CIRISEdge#122 fan-out optimization — see module docs § "Fan-out
/// optimization (inner-once / outer-N)".
#[derive(Debug, Clone)]
pub struct InnerSealed {
    stream_id: StreamId,
    epoch: Epoch,
    chunk_seq: ChunkSeq,
    /// CIRISEdge#128 codec discriminator carried through to the outer
    /// seal so the resulting [`SealedAvChunk`] stamps the correct
    /// codec_id without re-threading it through the call site.
    codec_id: u8,
    /// CIRISEdge#128 layer descriptor — same flow-through purpose as
    /// `codec_id`.
    layer: ChunkLayer,
    /// Inner AES-256-GCM ciphertext: `AEAD(epoch_dek, inner_nonce, plaintext)`.
    inner_ciphertext: Vec<u8>,
}

impl InnerSealed {
    /// Read access for the stream identity header — callers occasionally
    /// route the inner-sealed ciphertext through application logic
    /// (e.g. caching, repartitioning) before applying the per-Link outer
    /// seal.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }
    pub fn chunk_seq(&self) -> ChunkSeq {
        self.chunk_seq
    }
    /// CIRISEdge#128 — codec discriminator carried through to the
    /// outer seal.
    pub fn codec_id(&self) -> u8 {
        self.codec_id
    }
    /// CIRISEdge#128 — layer descriptor carried through to the outer
    /// seal.
    pub fn layer(&self) -> ChunkLayer {
        self.layer
    }
    /// Borrow the inner ciphertext. Still sealed under the epoch DEK —
    /// safe to ferry across the mesh.
    pub fn inner_ciphertext(&self) -> &[u8] {
        &self.inner_ciphertext
    }
}

/// Seal the **inner** AEAD layer only — E2E sealed under the epoch DEK,
/// independent of any Link. Produces an [`InnerSealed`] that can be
/// fed to [`seal_av_outer`] once per mesh participant. CIRISEdge#122
/// fan-out optimization: at room scale (N≈50) cuts sender CPU per
/// chunk roughly in half because the inner AEAD work is amortized
/// across the whole mesh instead of repeated per Link.
///
/// The inner nonce derivation is identical to [`seal_av_chunk`]'s
/// inner step, so the on-wire bytes are byte-identical to N calls to
/// `seal_av_chunk` with the same `(stream_id, epoch, chunk_seq,
/// codec_id, layer)` and per-link `(transit_key, link_id, link_seq)`
/// — fan-out optimization is a pure compute-side change, no
/// wire-format implication.
///
/// CIRISEdge#128 — `codec_id` + `layer` are clear-metadata only: they
/// flow through to the resulting [`SealedAvChunk`] header verbatim and
/// do NOT participate in the AEAD (`aad` is unchanged from v3.7.0).
/// This is deliberate: layer-policy stripping at relay hops doesn't
/// compromise the inner DEK's E2E secrecy, and tampering with those
/// fields just causes the receiver to mis-decode or drop — not break
/// crypto.
#[allow(clippy::too_many_arguments)]
pub fn seal_av_inner(
    plaintext: &[u8],
    epoch_dek: &EpochDek,
    stream_id: StreamId,
    epoch: Epoch,
    chunk_seq: ChunkSeq,
    codec_id: u8,
    layer: ChunkLayer,
) -> Result<InnerSealed, RealtimeAvError> {
    let inner_nonce = derive_inner_nonce(stream_id, epoch, chunk_seq);
    let inner_ciphertext = aes_gcm::encrypt(epoch_dek.as_bytes(), &inner_nonce, plaintext)
        .map_err(RealtimeAvError::InnerAead)?;
    Ok(InnerSealed {
        stream_id,
        epoch,
        chunk_seq,
        codec_id,
        layer,
        inner_ciphertext,
    })
}

/// Reconstruct an [`InnerSealed`] from its parts. Internal-shape
/// helper for cross-wheel PyO3 callers (CIRISEdge#123) — Python passes
/// the inner ciphertext bytes + header fields back through the FFI
/// boundary, and the outer-seal step rebuilds the handle here.
///
/// Rust callers should use [`seal_av_inner`] directly; this is the
/// bytes-in escape hatch for the published Python wheel.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn inner_sealed_from_parts(
    stream_id: StreamId,
    epoch: Epoch,
    chunk_seq: ChunkSeq,
    codec_id: u8,
    layer: ChunkLayer,
    inner_ciphertext: Vec<u8>,
) -> InnerSealed {
    InnerSealed {
        stream_id,
        epoch,
        chunk_seq,
        codec_id,
        layer,
        inner_ciphertext,
    }
}

/// Seal the **outer** AEAD layer for one Link, given a pre-computed
/// [`InnerSealed`]. The companion to [`seal_av_inner`].
///
/// Apply this once per mesh participant. The inner ciphertext is
/// shared across the whole mesh; only the outer nonce + transit key
/// differ per Link.
///
/// CIRISEdge#128 — the `codec_id` + `layer` carried on the
/// [`InnerSealed`] flow through to the resulting [`SealedAvChunk`]
/// unchanged. They are clear header metadata, NOT AEAD inputs.
pub fn seal_av_outer(
    inner: &InnerSealed,
    transit_key: &[u8; 32],
    link_id: &[u8],
    link_seq: u64,
) -> Result<SealedAvChunk, RealtimeAvError> {
    let outer_nonce = derive_outer_nonce(link_id, link_seq);
    let outer_sealed = aes_gcm::encrypt(transit_key, &outer_nonce, &inner.inner_ciphertext)
        .map_err(RealtimeAvError::OuterAead)?;
    Ok(SealedAvChunk {
        stream_id: inner.stream_id,
        epoch: inner.epoch,
        chunk_seq: inner.chunk_seq,
        codec_id: inner.codec_id,
        layer: inner.layer,
        double_sealed_ciphertext: outer_sealed,
    })
}

/// Seal a chunk for one mesh participant. Applies the two-layer
/// crypto in inside-out order: inner DEK seal first (E2E), then outer
/// transit-key seal (hop). Returns the on-wire bytes ready for the
/// RNS Link's outbound queue.
///
/// `link_id` + `link_seq` are caller-owned per-Link state — the
/// outer nonce binds the ciphertext to this exact Link, so a transit
/// attacker holding ciphertext from Link X cannot replay it onto
/// Link Y even if they have Link Y's transit key (different nonces
/// → AEAD rejects on decrypt).
///
/// For mesh fan-out (one frame → N participants) prefer
/// [`seal_av_inner`] + N × [`seal_av_outer`] — the inner AEAD work is
/// identical across the mesh and amortizes (~2× sender CPU win at
/// N=50, CIRISEdge#122). `seal_av_chunk` remains the right call for
/// N=1 paths and the wire-shape compose primitive.
///
/// CIRISEdge#128 — `codec_id` + `layer` are clear-metadata fields
/// stamped into the resulting [`SealedAvChunk`] header. They do NOT
/// participate in the AEAD (the inner DEK seal sees plaintext only,
/// the outer transit-key seal sees the inner ciphertext only). Pass
/// [`CODEC_OPAQUE`] + [`ChunkLayer::BASE`] for v3.7.0-compatible
/// codec-opaque chunks; pass [`CODEC_AV1_SVC`] + the encoder-emitted
/// `ChunkLayer` for AV1 SVC streams.
#[allow(clippy::too_many_arguments)]
pub fn seal_av_chunk(
    plaintext: &[u8],
    transit_key: &[u8; 32],
    link_id: &[u8],
    link_seq: u64,
    epoch_dek: &EpochDek,
    stream_id: StreamId,
    epoch: Epoch,
    chunk_seq: ChunkSeq,
    codec_id: u8,
    layer: ChunkLayer,
) -> Result<SealedAvChunk, RealtimeAvError> {
    let inner = seal_av_inner(
        plaintext, epoch_dek, stream_id, epoch, chunk_seq, codec_id, layer,
    )?;
    seal_av_outer(&inner, transit_key, link_id, link_seq)
}

/// Inverse of [`seal_av_chunk`]. Unwraps outer transit-key seal then
/// inner DEK seal; the receiver supplies both keys + the per-Link
/// `link_seq` it tracks in its own anti-replay window (typically the
/// [`crate::transport::addressing::ReplayWindow`] from #53).
#[allow(clippy::too_many_arguments)]
pub fn open_av_chunk(
    sealed: &SealedAvChunk,
    transit_key: &[u8; 32],
    link_id: &[u8],
    link_seq: u64,
    epoch_dek: &EpochDek,
) -> Result<Vec<u8>, RealtimeAvError> {
    let outer_nonce = derive_outer_nonce(link_id, link_seq);
    let inner_sealed =
        aes_gcm::decrypt(transit_key, &outer_nonce, &sealed.double_sealed_ciphertext)
            .map_err(RealtimeAvError::OuterAead)?;
    let inner_nonce = derive_inner_nonce(sealed.stream_id, sealed.epoch, sealed.chunk_seq);
    aes_gcm::decrypt(epoch_dek.as_bytes(), &inner_nonce, &inner_sealed)
        .map_err(RealtimeAvError::InnerAead)
}

/// Open ONLY the per-link outer AEAD, recovering the still-E2E-sealed
/// inner chunk. The relay holds no [`EpochDek`]; the inner layer is
/// never opened here — only the outer hop is removed.
///
/// This is the relay→relay primitive: an interior peer in a multi-tier
/// ALM tree receives a [`SealedAvChunk`] over its inbound link, opens
/// the outer AEAD with the inbound transit key, recovers the
/// [`InnerSealed`] (inner ciphertext + chunk header), then re-seals
/// with [`seal_av_outer`] for each downstream link.
///
/// The chunk header (`stream_id` / `epoch` / `chunk_seq`) and the
/// `codec_id` + `layer` clear-metadata block are carried through from
/// the inbound wire onto the recovered [`InnerSealed`] verbatim, so a
/// downstream [`seal_av_outer`] stamps an identical header — the
/// inner-once / outer-N composition (CIRISEdge#122) holds across
/// arbitrary relay hops.
///
/// # E2E invariant
///
/// The inner ciphertext bytes are NEVER mutated by this function. A
/// publisher's inner ciphertext is byte-identical through arbitrary
/// numbers of outer hops — relay→relay→relay→...→viewer. The inner
/// AEAD seal (under the epoch DEK) is opaque to this function; it is
/// the exact value [`InnerSealed::inner_ciphertext`] returns at the
/// publisher.
pub fn open_av_outer(
    sealed: &SealedAvChunk,
    transit_key: &[u8; 32],
    link_id: &[u8],
    link_seq: u64,
) -> Result<InnerSealed, RealtimeAvError> {
    let outer_nonce = derive_outer_nonce(link_id, link_seq);
    let inner_ciphertext =
        aes_gcm::decrypt(transit_key, &outer_nonce, &sealed.double_sealed_ciphertext)
            .map_err(RealtimeAvError::OuterAead)?;
    Ok(InnerSealed {
        stream_id: sealed.stream_id,
        epoch: sealed.epoch,
        chunk_seq: sealed.chunk_seq,
        codec_id: sealed.codec_id,
        layer: sealed.layer,
        inner_ciphertext,
    })
}

/// Default reachability ratio below which a participant is dropped
/// from the realtime fan-out. 0.5 = "succeeded at least half the time
/// over the last `window_seconds`". Realtime is bursty and packet-loss
/// sensitive; participants barely reachable should fall off rather
/// than receive a degraded stream.
pub const REALTIME_MIN_RATIO: f64 = 0.5;

/// A participant in a realtime mesh stream. The caller threads peer
/// identity + the per-Link transit key here; this module's fan-out
/// planner then filters by reachability without owning identity or
/// session state itself.
///
/// CIRISEdge#128 (Layer 2) — [`Self::layer_policy`] carries the
/// per-receiver layer-admission policy advertised by the participant.
/// The default ([`ReceiverLayerPolicy::UNCAPPED`]) preserves the
/// pre-#128 fan-out semantics: every reachable participant receives
/// every chunk regardless of `(codec_id, layer)`. Constructing this
/// struct via field-init shorthand will still need an explicit
/// `layer_policy` value; [`Self::new`] is provided as a convenience
/// that defaults to `UNCAPPED` for callers that don't care about
/// layer policy.
#[derive(Debug, Clone)]
pub struct MeshParticipant {
    pub peer_key_id: String,
    /// Bytes of the established RNS Link to this peer — the same
    /// `link_id` threaded into [`derive_outer_nonce`].
    pub link_id: Vec<u8>,
    /// CIRISEdge#128 — per-receiver layer-admission policy. Defaults
    /// to [`ReceiverLayerPolicy::UNCAPPED`] for compatibility with the
    /// pre-#128 fan-out path (every reachable participant gets every
    /// chunk).
    pub layer_policy: ReceiverLayerPolicy,
}

impl MeshParticipant {
    /// Construct a participant with the default
    /// [`ReceiverLayerPolicy::UNCAPPED`] policy. Equivalent to the
    /// pre-#128 two-field constructor.
    #[must_use]
    pub fn new(peer_key_id: String, link_id: Vec<u8>) -> Self {
        Self {
            peer_key_id,
            link_id,
            layer_policy: ReceiverLayerPolicy::UNCAPPED,
        }
    }
}

/// Stateless fan-out planner. Given the candidate participants for a
/// stream and the live reachability tracker, returns the subset that
/// is currently reachable above [`REALTIME_MIN_RATIO`].
pub struct RealtimeFanout;

impl RealtimeFanout {
    /// Filter `participants` to those whose `(peer_key_id,
    /// transport_id)` ratio is at least `min_ratio` in the
    /// reachability tracker's snapshot. Participants with no
    /// reachability history are EXCLUDED — a never-attempted peer is
    /// not "known reachable", and realtime is too latency-sensitive
    /// to ship to a cold peer.
    #[must_use]
    pub fn plan(
        participants: &[MeshParticipant],
        tracker: &ReachabilityTracker,
        transport_id: TransportId,
        min_ratio: f64,
    ) -> Vec<MeshParticipant> {
        participants
            .iter()
            .filter(|p| {
                let snap = tracker.snapshot(&p.peer_key_id);
                snap.get(&transport_id)
                    .is_some_and(|m| m.ratio() >= min_ratio)
            })
            .cloned()
            .collect()
    }

    /// CIRISEdge#128 (Layer 2) — layer-aware fan-out filter.
    ///
    /// Composes the reachability rule of [`Self::plan`] with the
    /// per-participant [`ReceiverLayerPolicy`] against the current
    /// chunk's [`ChunkLayer`]. A participant is admitted iff BOTH:
    ///
    /// 1. Their `(peer_key_id, transport_id)` snapshot in the
    ///    reachability tracker has a ratio at least `min_ratio` —
    ///    identical to [`Self::plan`]'s filter (participants with no
    ///    reachability history are EXCLUDED).
    /// 2. `participant.layer_policy.admits(chunk_layer)` is `true` —
    ///    the participant's policy accepts the chunk's
    ///    `(spatial, temporal, quality)` cell.
    ///
    /// This is additive — [`Self::plan`] is unchanged. Use this when
    /// fanning out scalable-codec chunks (AV1 SVC / JPEG XS layered /
    /// MDC). Use [`Self::plan`] when every participant should receive
    /// every chunk regardless of layer (e.g. CODEC_OPAQUE flows, or
    /// non-scalable codecs).
    ///
    /// # Compose with the inner-once / outer-N fan-out optimization
    ///
    /// The intended call site composes with [`seal_av_inner`] +
    /// [`seal_av_outer`] (CIRISEdge#122) — `seal_av_inner` runs once
    /// per chunk regardless of receivers, then `seal_av_outer` runs
    /// only for the participants this method admits:
    ///
    /// ```ignore
    /// use ciris_edge::transport::realtime_av::{
    ///     seal_av_inner, seal_av_outer, ChunkLayer, RealtimeFanout,
    ///     CODEC_AV1_SVC,
    /// };
    ///
    /// let layer = ChunkLayer { spatial: 1, temporal: 2, quality: 0 };
    /// // Seal once for the whole mesh.
    /// let inner = seal_av_inner(
    ///     plaintext, &epoch_dek, stream_id, epoch, chunk_seq,
    ///     CODEC_AV1_SVC, layer,
    /// )?;
    /// // Filter participants by reachability AND per-receiver policy.
    /// let admitted = RealtimeFanout::plan_layered(
    ///     &participants, layer, &tracker, transport_id, 0.5,
    /// );
    /// // Apply the per-Link outer seal only for admitted receivers.
    /// for p in &admitted {
    ///     let sealed = seal_av_outer(&inner, &transit_key(p), &p.link_id, link_seq(p))?;
    ///     send_on_link(&p.link_id, sealed);
    /// }
    /// # Ok::<(), ciris_edge::transport::realtime_av::RealtimeAvError>(())
    /// ```
    ///
    /// # CODEC_OPAQUE callers
    ///
    /// A chunk tagged with [`CODEC_OPAQUE`] carries no scalable-coding
    /// semantics and is always `ChunkLayer::BASE` per the module
    /// invariant. The `BASE` cell is admitted by every
    /// [`ReceiverLayerPolicy`] (including [`ReceiverLayerPolicy::BLINKING_DOT`]),
    /// so `plan_layered` is equivalent to [`Self::plan`] for opaque
    /// chunks — callers may use either method.
    #[must_use]
    pub fn plan_layered(
        participants: &[MeshParticipant],
        chunk_layer: ChunkLayer,
        tracker: &ReachabilityTracker,
        transport_id: TransportId,
        min_ratio: f64,
    ) -> Vec<MeshParticipant> {
        participants
            .iter()
            .filter(|p| {
                let snap = tracker.snapshot(&p.peer_key_id);
                let reachable = snap
                    .get(&transport_id)
                    .is_some_and(|m| m.ratio() >= min_ratio);
                reachable && p.layer_policy.admits(chunk_layer)
            })
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reachability::AttemptOutcome;

    fn dummy_stream() -> StreamId {
        StreamId([7u8; 32])
    }

    fn dummy_dek() -> EpochDek {
        EpochDek::from_bytes([3u8; 32])
    }

    fn dummy_transit() -> [u8; 32] {
        [11u8; 32]
    }

    /// Acceptance criterion 1 — direct RNS Link chunk delivery
    /// (low-latency form). Verified by the seal/open round-trip — if
    /// the cipher round-trips, the on-link bytes round-trip.
    #[test]
    fn seal_open_round_trip() {
        let plaintext = b"a/v frame plaintext (e.g. opus encoded audio + vp9 video keyframe)";
        let dek = dummy_dek();
        let sealed = seal_av_chunk(
            plaintext,
            &dummy_transit(),
            b"link-0001",
            42,
            &dek,
            dummy_stream(),
            Epoch(1),
            ChunkSeq(100),
            CODEC_OPAQUE,
            ChunkLayer::BASE,
        )
        .expect("seal");
        let opened =
            open_av_chunk(&sealed, &dummy_transit(), b"link-0001", 42, &dek).expect("open");
        assert_eq!(opened, plaintext);
    }

    /// Acceptance criterion 2 — two-layer crypto verified by tampering
    /// each layer in isolation and confirming the AEAD refuses.
    #[test]
    fn wrong_transit_key_fails_outer_aead() {
        let dek = dummy_dek();
        let sealed = seal_av_chunk(
            b"x",
            &dummy_transit(),
            b"link",
            0,
            &dek,
            dummy_stream(),
            Epoch(0),
            ChunkSeq(0),
            CODEC_OPAQUE,
            ChunkLayer::BASE,
        )
        .expect("seal");
        let r = open_av_chunk(&sealed, &[99u8; 32], b"link", 0, &dek);
        assert!(matches!(r, Err(RealtimeAvError::OuterAead(_))));
    }

    /// Tamper the epoch DEK only — inner AEAD must refuse, outer
    /// AEAD will have already opened. This proves the two layers are
    /// genuinely independent (compromising the hop transit key
    /// without compromising the epoch DEK does NOT yield plaintext).
    #[test]
    fn wrong_epoch_dek_fails_inner_aead() {
        let dek_good = dummy_dek();
        let dek_bad = EpochDek::from_bytes([99u8; 32]);
        let sealed = seal_av_chunk(
            b"x",
            &dummy_transit(),
            b"link",
            0,
            &dek_good,
            dummy_stream(),
            Epoch(0),
            ChunkSeq(0),
            CODEC_OPAQUE,
            ChunkLayer::BASE,
        )
        .expect("seal");
        let r = open_av_chunk(&sealed, &dummy_transit(), b"link", 0, &dek_bad);
        assert!(matches!(r, Err(RealtimeAvError::InnerAead(_))));
    }

    /// link_id replay: a chunk sealed for Link A cannot be opened on
    /// Link B even with Link B's transit key (different outer nonce
    /// derivation). Defense against a transit attacker shuffling
    /// frames across Links they control.
    #[test]
    fn link_id_change_fails_outer_aead() {
        let dek = dummy_dek();
        let sealed = seal_av_chunk(
            b"x",
            &dummy_transit(),
            b"link-A",
            0,
            &dek,
            dummy_stream(),
            Epoch(0),
            ChunkSeq(0),
            CODEC_OPAQUE,
            ChunkLayer::BASE,
        )
        .expect("seal");
        let r = open_av_chunk(&sealed, &dummy_transit(), b"link-B", 0, &dek);
        assert!(matches!(r, Err(RealtimeAvError::OuterAead(_))));
    }

    /// link_seq replay: a chunk sealed with link_seq=42 cannot be
    /// opened as link_seq=43. Defense against in-Link replay.
    #[test]
    fn link_seq_change_fails_outer_aead() {
        let dek = dummy_dek();
        let sealed = seal_av_chunk(
            b"x",
            &dummy_transit(),
            b"link",
            42,
            &dek,
            dummy_stream(),
            Epoch(0),
            ChunkSeq(0),
            CODEC_OPAQUE,
            ChunkLayer::BASE,
        )
        .expect("seal");
        let r = open_av_chunk(&sealed, &dummy_transit(), b"link", 43, &dek);
        assert!(matches!(r, Err(RealtimeAvError::OuterAead(_))));
    }

    /// Wire codec round-trips through bytes — header + body
    /// preserved. New (v3.8.0) wire shape including the codec+layer
    /// block.
    #[test]
    fn wire_round_trip() {
        let dek = dummy_dek();
        let sealed = seal_av_chunk(
            b"hello, mesh",
            &dummy_transit(),
            b"link",
            7,
            &dek,
            StreamId([0xAB; 32]),
            Epoch(0x1234_5678_9ABC_DEF0),
            ChunkSeq(0xFEDC_BA98_7654_3210),
            CODEC_AV1_SVC,
            ChunkLayer {
                spatial: 2,
                temporal: 3,
                quality: 1,
            },
        )
        .expect("seal");
        let wire = sealed.to_bytes();
        let parsed = SealedAvChunk::from_bytes(&wire).expect("parse");
        assert_eq!(parsed.stream_id, sealed.stream_id);
        assert_eq!(parsed.epoch, sealed.epoch);
        assert_eq!(parsed.chunk_seq, sealed.chunk_seq);
        assert_eq!(parsed.codec_id, CODEC_AV1_SVC);
        assert_eq!(
            parsed.layer,
            ChunkLayer {
                spatial: 2,
                temporal: 3,
                quality: 1,
            }
        );
        assert_eq!(
            parsed.double_sealed_ciphertext,
            sealed.double_sealed_ciphertext
        );
        // And the parsed form opens identically.
        let opened = open_av_chunk(&parsed, &dummy_transit(), b"link", 7, &dek).expect("open");
        assert_eq!(opened, b"hello, mesh");
    }

    /// Truncated wire input refused cleanly. v4.6.1 (Codex P1)
    /// requires the v3.8.0+ header+codec+layer shape — minimum 52
    /// bytes — so anything below that is now WireTooShort.
    #[test]
    fn wire_too_short_refused() {
        let r = SealedAvChunk::from_bytes(&[0u8; 47]);
        assert!(matches!(
            r,
            Err(RealtimeAvError::WireTooShort { got: 47, need: 52 })
        ));
        // Boundary: 51 bytes is also too short post v4.6.1.
        let r = SealedAvChunk::from_bytes(&[0u8; 51]);
        assert!(matches!(
            r,
            Err(RealtimeAvError::WireTooShort { got: 51, need: 52 })
        ));
    }

    /// Inner nonce determinism — same (stream, epoch, seq) → same
    /// nonce. This is the property that lets a fresh listener join
    /// mid-stream and decrypt cached chunks.
    #[test]
    fn inner_nonce_is_deterministic() {
        let n1 = derive_inner_nonce(StreamId([1; 32]), Epoch(5), ChunkSeq(99));
        let n2 = derive_inner_nonce(StreamId([1; 32]), Epoch(5), ChunkSeq(99));
        assert_eq!(n1, n2);
        // And different inputs → different nonces.
        let n3 = derive_inner_nonce(StreamId([1; 32]), Epoch(5), ChunkSeq(100));
        assert_ne!(n1, n3);
        let n4 = derive_inner_nonce(StreamId([2; 32]), Epoch(5), ChunkSeq(99));
        assert_ne!(n1, n4);
    }

    /// EpochDek Debug output redacts the bytes — no accidental log leaks.
    #[test]
    fn epoch_dek_debug_redacted() {
        let dek = EpochDek::from_bytes([42u8; 32]);
        let s = format!("{dek:?}");
        assert!(s.contains("<redacted"), "DEK leaked in Debug: {s}");
    }

    /// Acceptance criterion 3 — reachability drives fan-out. A
    /// participant whose ratio falls below the threshold is dropped
    /// from the plan.
    #[test]
    fn fanout_drops_unreachable_participants() {
        let tracker = ReachabilityTracker::new(60);
        let transport_id = TransportId("reticulum");
        // Alice — clean reachable history (10/10 success).
        for _ in 0..10 {
            tracker.record_attempt("alice", transport_id, AttemptOutcome::SendSuccess);
        }
        // Bob — flaky (3/10 success).
        for _ in 0..3 {
            tracker.record_attempt("bob", transport_id, AttemptOutcome::SendSuccess);
        }
        for _ in 0..7 {
            tracker.record_attempt(
                "bob",
                transport_id,
                AttemptOutcome::SendFailure {
                    error_class: "timeout".into(),
                },
            );
        }
        // Carol — unknown (no recorded attempts).
        let participants = vec![
            MeshParticipant::new("alice".into(), b"link-A".to_vec()),
            MeshParticipant::new("bob".into(), b"link-B".to_vec()),
            MeshParticipant::new("carol".into(), b"link-C".to_vec()),
        ];
        let plan = RealtimeFanout::plan(&participants, &tracker, transport_id, REALTIME_MIN_RATIO);
        let ids: Vec<&str> = plan.iter().map(|p| p.peer_key_id.as_str()).collect();
        assert_eq!(ids, vec!["alice"], "only alice meets REALTIME_MIN_RATIO");
    }

    /// #122 fan-out split: composing `seal_av_inner` + `seal_av_outer`
    /// produces byte-identical wire to `seal_av_chunk` for the same
    /// inputs. Load-bearing — guarantees the optimization is a pure
    /// compute-side change with zero wire-format implication.
    #[test]
    fn inner_outer_split_matches_single_chunk_wire() {
        let plaintext = b"frame bytes";
        let dek = dummy_dek();
        let stream = dummy_stream();
        let epoch = Epoch(7);
        let cseq = ChunkSeq(99);
        let transit = dummy_transit();
        let link = b"link-A";
        let lseq = 42u64;
        let codec = CODEC_AV1_SVC;
        let layer = ChunkLayer {
            spatial: 1,
            temporal: 2,
            quality: 0,
        };

        let single = seal_av_chunk(
            plaintext, &transit, link, lseq, &dek, stream, epoch, cseq, codec, layer,
        )
        .expect("single");
        let inner =
            seal_av_inner(plaintext, &dek, stream, epoch, cseq, codec, layer).expect("inner");
        let split = seal_av_outer(&inner, &transit, link, lseq).expect("outer");

        assert_eq!(single.stream_id, split.stream_id);
        assert_eq!(single.epoch, split.epoch);
        assert_eq!(single.chunk_seq, split.chunk_seq);
        assert_eq!(single.codec_id, split.codec_id);
        assert_eq!(single.layer, split.layer);
        assert_eq!(
            single.double_sealed_ciphertext, split.double_sealed_ciphertext,
            "fan-out split changed the wire bytes"
        );
    }

    /// #122 fan-out: ONE `seal_av_inner` + N `seal_av_outer` calls for
    /// distinct Links each produce a sealed chunk that opens correctly
    /// on its own Link — exactly mirroring N independent
    /// `seal_av_chunk` calls.
    #[test]
    fn inner_once_outer_n_fanout_opens_per_link() {
        let plaintext = b"mesh frame";
        let dek = dummy_dek();
        let stream = dummy_stream();
        let epoch = Epoch(3);
        let cseq = ChunkSeq(10);
        let transit = dummy_transit();

        let inner = seal_av_inner(
            plaintext,
            &dek,
            stream,
            epoch,
            cseq,
            CODEC_OPAQUE,
            ChunkLayer::BASE,
        )
        .expect("inner");
        let links: Vec<(&[u8], u64)> = vec![
            (b"link-A", 100),
            (b"link-B", 200),
            (b"link-C", 300),
            (b"link-D", 400),
        ];
        for (link_id, link_seq) in links {
            let sealed = seal_av_outer(&inner, &transit, link_id, link_seq).expect("outer");
            // Each per-Link wire opens with the matching Link state.
            let opened = open_av_chunk(&sealed, &transit, link_id, link_seq, &dek).expect("open");
            assert_eq!(opened, plaintext);
            // And refuses on a different Link's state — outer nonce
            // is per-Link.
            let r = open_av_chunk(&sealed, &transit, b"link-X", link_seq, &dek);
            assert!(matches!(r, Err(RealtimeAvError::OuterAead(_))));
        }
    }

    /// #122 — the InnerSealed accessor surface preserves the chunk
    /// header so a caller can route the inner ciphertext through
    /// app-level logic (cache, repartition) before applying the
    /// per-Link outer seal.
    #[test]
    fn inner_sealed_header_accessors() {
        let dek = dummy_dek();
        let stream = StreamId([0xAB; 32]);
        let epoch = Epoch(0xDEAD_BEEF);
        let cseq = ChunkSeq(0x00C0_FFEE);
        let layer = ChunkLayer {
            spatial: 1,
            temporal: 2,
            quality: 3,
        };
        let inner =
            seal_av_inner(b"x", &dek, stream, epoch, cseq, CODEC_AV1_SVC, layer).expect("inner");
        assert_eq!(inner.stream_id(), stream);
        assert_eq!(inner.epoch(), epoch);
        assert_eq!(inner.chunk_seq(), cseq);
        assert_eq!(inner.codec_id(), CODEC_AV1_SVC);
        assert_eq!(inner.layer(), layer);
        assert!(!inner.inner_ciphertext().is_empty());
    }

    /// Threshold tunability — a stricter threshold (0.9) drops bob
    /// even if bob was at 0.5 exactly.
    #[test]
    fn fanout_threshold_tunable() {
        let tracker = ReachabilityTracker::new(60);
        let transport_id = TransportId("reticulum");
        // 5/10 success — exactly the default threshold.
        for _ in 0..5 {
            tracker.record_attempt("bob", transport_id, AttemptOutcome::SendSuccess);
        }
        for _ in 0..5 {
            tracker.record_attempt(
                "bob",
                transport_id,
                AttemptOutcome::SendFailure {
                    error_class: "x".into(),
                },
            );
        }
        let participants = vec![MeshParticipant::new("bob".into(), b"l".to_vec())];
        // At default threshold, bob is in.
        let plan_default =
            RealtimeFanout::plan(&participants, &tracker, transport_id, REALTIME_MIN_RATIO);
        assert_eq!(plan_default.len(), 1);
        // At 0.9, bob is out.
        let plan_strict = RealtimeFanout::plan(&participants, &tracker, transport_id, 0.9);
        assert!(plan_strict.is_empty());
    }

    // ─── CIRISEdge#128 — codec + per-receiver layer policy ───────

    /// **v4.6.1 (Codex P1 fix)** — replaces the prior
    /// `from_bytes_accepts_v3_7_0_wire_shape` test that asserted the
    /// dead-code length-only fallback. v3.7.0-shape header-only wires
    /// (<52 bytes total) are now rejected with `WireTooShort`. The
    /// v3.8.0+ wire (header + codec + layer block, 52+ bytes) is the
    /// only accepted shape.
    ///
    /// Rationale: the prior fallback was structurally unreachable for
    /// any real v3.7.0 wire — real wires carry AES-GCM tag (≥16
    /// bytes) → ≥64 bytes total → always hit the v3.8.0+ branch →
    /// misparsed the first 4 ciphertext bytes as `codec_id` + layer.
    ///
    /// Length disambiguation — the read side requires at least
    /// [`CHUNK_CODEC_LAYER_LEN`] trailing bytes to interpret the
    /// codec+layer block. Any wire with `48 <= len <
    /// 48 + CHUNK_CODEC_LAYER_LEN` is treated as a v3.7.0 header-only
    /// wire (`codec_id = CODEC_OPAQUE` + `layer = ChunkLayer::BASE`)
    /// and the bytes 48.. are the (possibly empty) ciphertext.
    ///
    #[test]
    fn from_bytes_rejects_v3_7_0_header_only_shape_post_codex_fix() {
        // v4.6.1: header-only wires (no codec+layer block) MUST be
        // rejected with WireTooShort. This is the inverse of the
        // dead-code v3.7.0 compat branch.
        let mut header_only = Vec::new();
        header_only.extend_from_slice(&[0x42; 32]); // stream_id
        header_only.extend_from_slice(&0xDEAD_BEEF_u64.to_be_bytes()); // epoch
        header_only.extend_from_slice(&0xC0FF_EE12_u64.to_be_bytes()); // chunk_seq
        assert_eq!(header_only.len(), CHUNK_HEADER_LEN);

        match SealedAvChunk::from_bytes(&header_only) {
            Err(RealtimeAvError::WireTooShort { got, need }) => {
                assert_eq!(got, CHUNK_HEADER_LEN);
                assert_eq!(need, CHUNK_HEADER_LEN + CHUNK_CODEC_LAYER_LEN);
            }
            other => panic!("expected WireTooShort, got {other:?}"),
        }

        // 49..51 bytes also rejected.
        for partial_len in 1..CHUNK_CODEC_LAYER_LEN {
            let mut partial = header_only.clone();
            partial.extend(std::iter::repeat_n(0x99u8, partial_len));
            assert!(matches!(
                SealedAvChunk::from_bytes(&partial),
                Err(RealtimeAvError::WireTooShort { .. })
            ));
        }
    }

    /// New-shape (v3.8.0) wire round-trips: write new → read new
    /// preserves codec_id + layer + ciphertext.
    #[test]
    fn v3_8_0_wire_round_trip_new_to_new() {
        let dek = dummy_dek();
        let layer = ChunkLayer {
            spatial: 1,
            temporal: 2,
            quality: 3,
        };
        let sealed = seal_av_chunk(
            b"new-shape payload",
            &dummy_transit(),
            b"link-X",
            17,
            &dek,
            StreamId([0x55; 32]),
            Epoch(0x0123_4567_89AB_CDEF),
            ChunkSeq(0xFEDC_BA98_7654_3210),
            CODEC_JPEG_XS,
            layer,
        )
        .expect("seal");
        // The new wire is 4 bytes longer than the v3.7.0 wire for the
        // same plaintext.
        let wire = sealed.to_bytes();
        assert_eq!(
            wire.len(),
            CHUNK_HEADER_LEN + CHUNK_CODEC_LAYER_LEN + sealed.double_sealed_ciphertext.len()
        );
        // codec_id at byte 48, layer at 49..52.
        assert_eq!(wire[48], CODEC_JPEG_XS);
        assert_eq!(wire[49], 1);
        assert_eq!(wire[50], 2);
        assert_eq!(wire[51], 3);
        let parsed = SealedAvChunk::from_bytes(&wire).expect("parse");
        assert_eq!(parsed.codec_id, CODEC_JPEG_XS);
        assert_eq!(parsed.layer, layer);
        let opened = open_av_chunk(&parsed, &dummy_transit(), b"link-X", 17, &dek).expect("open");
        assert_eq!(opened, b"new-shape payload");
    }

    /// `ReceiverLayerPolicy::admits` truth table — BLINKING_DOT
    /// accepts only the base cell; UNCAPPED accepts everything; a
    /// custom policy accepts the prefix-closed cube and rejects
    /// outside.
    #[test]
    fn receiver_layer_policy_admits_truth_table() {
        let base = ChunkLayer::BASE;
        let mid = ChunkLayer {
            spatial: 1,
            temporal: 2,
            quality: 0,
        };
        let high = ChunkLayer {
            spatial: 2,
            temporal: 3,
            quality: 1,
        };

        // BLINKING_DOT — only the base cell admitted.
        assert!(ReceiverLayerPolicy::BLINKING_DOT.admits(base));
        assert!(!ReceiverLayerPolicy::BLINKING_DOT.admits(mid));
        assert!(!ReceiverLayerPolicy::BLINKING_DOT.admits(high));

        // UNCAPPED — everything admitted.
        assert!(ReceiverLayerPolicy::UNCAPPED.admits(base));
        assert!(ReceiverLayerPolicy::UNCAPPED.admits(mid));
        assert!(ReceiverLayerPolicy::UNCAPPED.admits(high));
        assert!(ReceiverLayerPolicy::UNCAPPED.admits(ChunkLayer {
            spatial: u8::MAX,
            temporal: u8::MAX,
            quality: u8::MAX,
        }));

        // Custom policy — prefix-closed cube up to (1, 2, 0).
        let custom = ReceiverLayerPolicy {
            max_spatial: 1,
            max_temporal: 2,
            max_quality: 0,
        };
        assert!(custom.admits(base));
        assert!(custom.admits(mid)); // exactly on the bound
        assert!(!custom.admits(high)); // spatial=2 > max_spatial=1
        assert!(!custom.admits(ChunkLayer {
            spatial: 0,
            temporal: 3,
            quality: 0,
        })); // temporal=3 > max_temporal=2
        assert!(!custom.admits(ChunkLayer {
            spatial: 0,
            temporal: 0,
            quality: 1,
        })); // quality=1 > max_quality=0
    }

    /// `seal_av_chunk` propagates `codec_id` + `layer` to the
    /// resulting [`SealedAvChunk`] without modification. They are
    /// clear metadata, not AEAD inputs.
    #[test]
    fn seal_av_chunk_propagates_codec_id_and_layer() {
        let dek = dummy_dek();
        let layer = ChunkLayer {
            spatial: 2,
            temporal: 1,
            quality: 3,
        };
        let sealed = seal_av_chunk(
            b"x",
            &dummy_transit(),
            b"link",
            0,
            &dek,
            dummy_stream(),
            Epoch(0),
            ChunkSeq(0),
            CODEC_AV1_SVC,
            layer,
        )
        .expect("seal");
        assert_eq!(sealed.codec_id, CODEC_AV1_SVC);
        assert_eq!(sealed.layer, layer);

        // The inner-once / outer-N split must propagate identically.
        let inner = seal_av_inner(
            b"x",
            &dek,
            dummy_stream(),
            Epoch(0),
            ChunkSeq(0),
            CODEC_MDC,
            ChunkLayer {
                spatial: 0,
                temporal: 0,
                quality: 1,
            },
        )
        .expect("inner");
        assert_eq!(inner.codec_id(), CODEC_MDC);
        assert_eq!(inner.layer().quality, 1);
        let outer = seal_av_outer(&inner, &dummy_transit(), b"link", 0).expect("outer");
        assert_eq!(outer.codec_id, CODEC_MDC);
        assert_eq!(outer.layer.quality, 1);
    }

    /// Codec namespace constants reflect the CEG §10.5.8 slotting
    /// proposed in CIRISEdge#128. Locking the wire-byte values down so
    /// a future refactor doesn't silently renumber.
    #[test]
    fn codec_id_namespace_values_locked() {
        assert_eq!(CODEC_AV1_SVC, 0x01);
        assert_eq!(CODEC_JPEG_XS, 0x02);
        assert_eq!(CODEC_MDC, 0x03);
        assert_eq!(CODEC_OPAQUE, 0xFF);
    }

    // ─── CIRISEdge#128 (Layer 2 task A) — layer-aware fan-out ───
    //
    // `RealtimeFanout::plan_layered` filters by BOTH reachability and
    // per-participant `ReceiverLayerPolicy` against the chunk's
    // `ChunkLayer`. The tests below pin each leg of that AND
    // independently, and then the joint case.

    /// Build a participant with an explicit `layer_policy` — the new
    /// field is what `plan_layered` consults.
    fn participant_with_policy(
        peer_key_id: &str,
        link_id: &[u8],
        policy: ReceiverLayerPolicy,
    ) -> MeshParticipant {
        MeshParticipant {
            peer_key_id: peer_key_id.into(),
            link_id: link_id.to_vec(),
            layer_policy: policy,
        }
    }

    /// Record N successful + M failed attempts so a given peer's ratio
    /// becomes `N / (N + M)` on the supplied transport.
    fn record_ratio(
        tracker: &ReachabilityTracker,
        peer: &str,
        transport: TransportId,
        successes: u32,
        failures: u32,
    ) {
        for _ in 0..successes {
            tracker.record_attempt(peer, transport, AttemptOutcome::SendSuccess);
        }
        for _ in 0..failures {
            tracker.record_attempt(
                peer,
                transport,
                AttemptOutcome::SendFailure {
                    error_class: "x".into(),
                },
            );
        }
    }

    /// Reachability leg in isolation — alice reachable, bob unreachable,
    /// both `UNCAPPED` so the policy leg is a no-op. Only alice
    /// admitted.
    #[test]
    fn fanout_layered_drops_unreachable() {
        let tracker = ReachabilityTracker::new(60);
        let transport_id = TransportId("reticulum");
        // Alice — 10/10 success.
        record_ratio(&tracker, "alice", transport_id, 10, 0);
        // Bob — 1/10 success, well below default 0.5.
        record_ratio(&tracker, "bob", transport_id, 1, 9);
        let participants = vec![
            participant_with_policy("alice", b"link-A", ReceiverLayerPolicy::UNCAPPED),
            participant_with_policy("bob", b"link-B", ReceiverLayerPolicy::UNCAPPED),
        ];
        let chunk_layer = ChunkLayer {
            spatial: 2,
            temporal: 2,
            quality: 2,
        };
        let admitted = RealtimeFanout::plan_layered(
            &participants,
            chunk_layer,
            &tracker,
            transport_id,
            REALTIME_MIN_RATIO,
        );
        let ids: Vec<&str> = admitted.iter().map(|p| p.peer_key_id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["alice"],
            "bob is unreachable so plan_layered must drop bob"
        );
    }

    /// Policy leg in isolation — both reachable, alice `UNCAPPED`,
    /// bob `BLINKING_DOT`; chunk above (0, 0, 0). Only alice admitted.
    #[test]
    fn fanout_layered_drops_by_policy() {
        let tracker = ReachabilityTracker::new(60);
        let transport_id = TransportId("reticulum");
        record_ratio(&tracker, "alice", transport_id, 10, 0);
        record_ratio(&tracker, "bob", transport_id, 10, 0);
        let participants = vec![
            participant_with_policy("alice", b"link-A", ReceiverLayerPolicy::UNCAPPED),
            participant_with_policy("bob", b"link-B", ReceiverLayerPolicy::BLINKING_DOT),
        ];
        let chunk_layer = ChunkLayer {
            spatial: 2,
            temporal: 2,
            quality: 2,
        };
        let admitted = RealtimeFanout::plan_layered(
            &participants,
            chunk_layer,
            &tracker,
            transport_id,
            REALTIME_MIN_RATIO,
        );
        let ids: Vec<&str> = admitted.iter().map(|p| p.peer_key_id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["alice"],
            "bob's BLINKING_DOT policy refuses spatial=2 chunk"
        );
    }

    /// Joint case — alice reachable + UNCAPPED, bob reachable but
    /// BLINKING_DOT, carol unreachable but UNCAPPED. Only alice
    /// admitted (the other two are dropped by exactly one leg each).
    #[test]
    fn fanout_layered_drops_by_both() {
        let tracker = ReachabilityTracker::new(60);
        let transport_id = TransportId("reticulum");
        record_ratio(&tracker, "alice", transport_id, 10, 0);
        record_ratio(&tracker, "bob", transport_id, 10, 0);
        // Carol — unreachable (no recorded attempts).
        let participants = vec![
            participant_with_policy("alice", b"link-A", ReceiverLayerPolicy::UNCAPPED),
            participant_with_policy("bob", b"link-B", ReceiverLayerPolicy::BLINKING_DOT),
            participant_with_policy("carol", b"link-C", ReceiverLayerPolicy::UNCAPPED),
        ];
        let chunk_layer = ChunkLayer {
            spatial: 1,
            temporal: 1,
            quality: 0,
        };
        let admitted = RealtimeFanout::plan_layered(
            &participants,
            chunk_layer,
            &tracker,
            transport_id,
            REALTIME_MIN_RATIO,
        );
        let ids: Vec<&str> = admitted.iter().map(|p| p.peer_key_id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["alice"],
            "joint reachability AND policy filter — only alice survives both legs"
        );
    }

    /// `ChunkLayer::BASE` (0, 0, 0) is admitted by every policy
    /// including `BLINKING_DOT` per the `admits` truth table. All
    /// reachable participants receive a BASE chunk, even those with
    /// the most restrictive policy.
    #[test]
    fn fanout_layered_blinking_dot_admitted_everywhere() {
        let tracker = ReachabilityTracker::new(60);
        let transport_id = TransportId("reticulum");
        record_ratio(&tracker, "alice", transport_id, 10, 0);
        record_ratio(&tracker, "bob", transport_id, 10, 0);
        record_ratio(&tracker, "carol", transport_id, 10, 0);
        let participants = vec![
            participant_with_policy("alice", b"link-A", ReceiverLayerPolicy::UNCAPPED),
            participant_with_policy("bob", b"link-B", ReceiverLayerPolicy::BLINKING_DOT),
            participant_with_policy(
                "carol",
                b"link-C",
                ReceiverLayerPolicy {
                    max_spatial: 0,
                    max_temporal: 0,
                    max_quality: 0,
                },
            ),
        ];
        let admitted = RealtimeFanout::plan_layered(
            &participants,
            ChunkLayer::BASE,
            &tracker,
            transport_id,
            REALTIME_MIN_RATIO,
        );
        let ids: Vec<&str> = admitted.iter().map(|p| p.peer_key_id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["alice", "bob", "carol"],
            "BASE chunk admitted by every policy (BLINKING_DOT included)"
        );
    }

    /// `ReceiverLayerPolicy::UNCAPPED` admits every layer the codec
    /// produces, so `plan_layered` with all participants UNCAPPED
    /// reduces to `plan` for the same reachability inputs — modulo
    /// `chunk_layer`, which is irrelevant when every policy is
    /// UNCAPPED.
    #[test]
    fn fanout_layered_uncapped_admits_everything() {
        let tracker = ReachabilityTracker::new(60);
        let transport_id = TransportId("reticulum");
        record_ratio(&tracker, "alice", transport_id, 10, 0);
        record_ratio(&tracker, "bob", transport_id, 1, 9); // below threshold
        record_ratio(&tracker, "dave", transport_id, 10, 0);
        // Erin — no history, must be excluded (cold peer rule).
        let participants = vec![
            participant_with_policy("alice", b"link-A", ReceiverLayerPolicy::UNCAPPED),
            participant_with_policy("bob", b"link-B", ReceiverLayerPolicy::UNCAPPED),
            participant_with_policy("dave", b"link-D", ReceiverLayerPolicy::UNCAPPED),
            participant_with_policy("erin", b"link-E", ReceiverLayerPolicy::UNCAPPED),
        ];

        // Walk a representative cross-section of layer cells; the
        // admitted set must be invariant in `chunk_layer` when every
        // participant is UNCAPPED.
        let layer_cells = [
            ChunkLayer::BASE,
            ChunkLayer {
                spatial: 2,
                temporal: 3,
                quality: 1,
            },
            ChunkLayer {
                spatial: u8::MAX,
                temporal: u8::MAX,
                quality: u8::MAX,
            },
        ];
        let plan_baseline =
            RealtimeFanout::plan(&participants, &tracker, transport_id, REALTIME_MIN_RATIO);
        let baseline_ids: Vec<&str> = plan_baseline
            .iter()
            .map(|p| p.peer_key_id.as_str())
            .collect();
        for chunk_layer in layer_cells {
            let admitted = RealtimeFanout::plan_layered(
                &participants,
                chunk_layer,
                &tracker,
                transport_id,
                REALTIME_MIN_RATIO,
            );
            let ids: Vec<&str> = admitted.iter().map(|p| p.peer_key_id.as_str()).collect();
            assert_eq!(
                ids, baseline_ids,
                "UNCAPPED-everywhere plan_layered must equal plan at layer {chunk_layer:?}"
            );
        }
    }
}
