//! Realtime A/V mesh profile — direct Reticulum Links for low-latency
//! group communication (CIRISEdge#62, CEG 0.13 §10.5.8).
//!
//! Closes the missing transport profile for **realtime group
//! communication** — group video, voice, desktop/screen sharing. The
//! broadcast pull path (§10.5.5 E2) ships sealed A/V chunks at 1–10s
//! latency: unusable for interactive calls. This module is the
//! complementary low-latency profile that owns small/medium rooms
//! (≤ ~50 participants) via direct RNS Links.
//!
//! Large rooms (≫50 participants) cross over to SFU relay at the
//! Phase 1.x trees-of-relays surface; the per-(stream_id, epoch) DEK
//! and chunk-seal layouts defined here are the same as that surface,
//! only the transport profile differs.
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

/// The wire shape that lands on each RNS Link's payload. Same shape
/// the broadcast pull path serializes into its own delivery wire
/// (see module docs § "What this module is NOT").
#[derive(Debug, Clone)]
pub struct SealedAvChunk {
    pub stream_id: StreamId,
    pub epoch: Epoch,
    pub chunk_seq: ChunkSeq,
    /// The double-sealed ciphertext: outer AEAD wraps inner AEAD wraps
    /// chunk plaintext. Both layers are AES-256-GCM (12B nonce + 16B
    /// tag, standard ring layout).
    pub double_sealed_ciphertext: Vec<u8>,
}

impl SealedAvChunk {
    /// Concrete wire encoding — fixed-shape header then ciphertext.
    ///
    /// ```text
    /// 0..32  stream_id
    /// 32..40 epoch       (big-endian u64)
    /// 40..48 chunk_seq   (big-endian u64)
    /// 48..   double_sealed_ciphertext
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48 + self.double_sealed_ciphertext.len());
        out.extend_from_slice(&self.stream_id.0);
        out.extend_from_slice(&self.epoch.0.to_be_bytes());
        out.extend_from_slice(&self.chunk_seq.0.to_be_bytes());
        out.extend_from_slice(&self.double_sealed_ciphertext);
        out
    }

    /// Inverse of [`Self::to_bytes`]. Returns `Err` if the input is
    /// shorter than the 48-byte header.
    pub fn from_bytes(b: &[u8]) -> Result<Self, RealtimeAvError> {
        if b.len() < 48 {
            return Err(RealtimeAvError::WireTooShort {
                got: b.len(),
                need: 48,
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
        Ok(Self {
            stream_id: StreamId(stream_id),
            epoch,
            chunk_seq,
            double_sealed_ciphertext: b[48..].to_vec(),
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
/// `seal_av_chunk` with the same `(stream_id, epoch, chunk_seq)` and
/// per-link `(transit_key, link_id, link_seq)` — fan-out optimization
/// is a pure compute-side change, no wire-format implication.
pub fn seal_av_inner(
    plaintext: &[u8],
    epoch_dek: &EpochDek,
    stream_id: StreamId,
    epoch: Epoch,
    chunk_seq: ChunkSeq,
) -> Result<InnerSealed, RealtimeAvError> {
    let inner_nonce = derive_inner_nonce(stream_id, epoch, chunk_seq);
    let inner_ciphertext = aes_gcm::encrypt(epoch_dek.as_bytes(), &inner_nonce, plaintext)
        .map_err(RealtimeAvError::InnerAead)?;
    Ok(InnerSealed {
        stream_id,
        epoch,
        chunk_seq,
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
pub fn inner_sealed_from_parts(
    stream_id: StreamId,
    epoch: Epoch,
    chunk_seq: ChunkSeq,
    inner_ciphertext: Vec<u8>,
) -> InnerSealed {
    InnerSealed {
        stream_id,
        epoch,
        chunk_seq,
        inner_ciphertext,
    }
}

/// Seal the **outer** AEAD layer for one Link, given a pre-computed
/// [`InnerSealed`]. The companion to [`seal_av_inner`].
///
/// Apply this once per mesh participant. The inner ciphertext is
/// shared across the whole mesh; only the outer nonce + transit key
/// differ per Link.
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
) -> Result<SealedAvChunk, RealtimeAvError> {
    let inner = seal_av_inner(plaintext, epoch_dek, stream_id, epoch, chunk_seq)?;
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
#[derive(Debug, Clone)]
pub struct MeshParticipant {
    pub peer_key_id: String,
    /// Bytes of the established RNS Link to this peer — the same
    /// `link_id` threaded into [`derive_outer_nonce`].
    pub link_id: Vec<u8>,
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
        )
        .expect("seal");
        let r = open_av_chunk(&sealed, &dummy_transit(), b"link", 43, &dek);
        assert!(matches!(r, Err(RealtimeAvError::OuterAead(_))));
    }

    /// Wire codec round-trips through bytes — header + body
    /// preserved.
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
        )
        .expect("seal");
        let wire = sealed.to_bytes();
        let parsed = SealedAvChunk::from_bytes(&wire).expect("parse");
        assert_eq!(parsed.stream_id, sealed.stream_id);
        assert_eq!(parsed.epoch, sealed.epoch);
        assert_eq!(parsed.chunk_seq, sealed.chunk_seq);
        assert_eq!(
            parsed.double_sealed_ciphertext,
            sealed.double_sealed_ciphertext
        );
        // And the parsed form opens identically.
        let opened = open_av_chunk(&parsed, &dummy_transit(), b"link", 7, &dek).expect("open");
        assert_eq!(opened, b"hello, mesh");
    }

    /// Truncated wire input refused cleanly.
    #[test]
    fn wire_too_short_refused() {
        let r = SealedAvChunk::from_bytes(&[0u8; 47]);
        assert!(matches!(
            r,
            Err(RealtimeAvError::WireTooShort { got: 47, need: 48 })
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
            MeshParticipant {
                peer_key_id: "alice".into(),
                link_id: b"link-A".to_vec(),
            },
            MeshParticipant {
                peer_key_id: "bob".into(),
                link_id: b"link-B".to_vec(),
            },
            MeshParticipant {
                peer_key_id: "carol".into(),
                link_id: b"link-C".to_vec(),
            },
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

        let single = seal_av_chunk(plaintext, &transit, link, lseq, &dek, stream, epoch, cseq)
            .expect("single");
        let inner = seal_av_inner(plaintext, &dek, stream, epoch, cseq).expect("inner");
        let split = seal_av_outer(&inner, &transit, link, lseq).expect("outer");

        assert_eq!(single.stream_id, split.stream_id);
        assert_eq!(single.epoch, split.epoch);
        assert_eq!(single.chunk_seq, split.chunk_seq);
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

        let inner = seal_av_inner(plaintext, &dek, stream, epoch, cseq).expect("inner");
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
        let inner = seal_av_inner(b"x", &dek, stream, epoch, cseq).expect("inner");
        assert_eq!(inner.stream_id(), stream);
        assert_eq!(inner.epoch(), epoch);
        assert_eq!(inner.chunk_seq(), cseq);
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
        let participants = vec![MeshParticipant {
            peer_key_id: "bob".into(),
            link_id: b"l".to_vec(),
        }];
        // At default threshold, bob is in.
        let plan_default =
            RealtimeFanout::plan(&participants, &tracker, transport_id, REALTIME_MIN_RATIO);
        assert_eq!(plan_default.len(), 1);
        // At 0.9, bob is out.
        let plan_strict = RealtimeFanout::plan(&participants, &tracker, transport_id, 0.9);
        assert!(plan_strict.is_empty());
    }
}
