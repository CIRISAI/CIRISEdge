//! Realtime A/V codec wiring (v3.9.0 Layer 1 — CIRISEdge#133).
//!
//! Wraps the production-grade Rust codec stack into the substrate's
//! per-symbol / per-chunk shape. Each sub-module is independently
//! feature-gated; substrate consumers who don't need a particular
//! codec pay zero binary-size cost.
//!
//! ## Sub-modules
//!
//! - [`fountain`] — RaptorQ (RFC 6330) wrap/unwrap. Turns opaque
//!   payload bytes into N source + K repair symbols matching
//!   CIRISPersist v8.0.0's `FountainSymbolV1`. Codec-agnostic; any
//!   downstream encoder (AV1, Opus, raw bytes) flows through here.
//!   Feature: `codec-fountain` (L1-A).
//!
//! - [`av1`] — rav1e (encoder) + dav1d (decoder) AV1 video codec.
//!   Sits BETWEEN raw YUV frames and the fountain wrap; produces OBU
//!   bytes the wrap layer turns into fountain symbols. Feature:
//!   `codec-av1` (L1-B).
//!
//! - [`opus_voice`] — libopus 1.x voice codec (the WebRTC / Discord /
//!   Mumble baseline; 5–26.5 ms algorithmic delay) for the mesh's
//!   voice lane. Feature: `codec-opus` (L1-C).
//!
//! The consent-decay scheduler that drives content-id eviction at the
//! tier above lives at `src/holonomic/consent_decay.rs` (L1-D) — it
//! is orthogonal to the codec layer and gates on
//! `holonomic-consent-decay`.
//!
//! ## What this layer is NOT
//!
//! - **A transport.** The codec module produces / consumes byte
//!   buffers; the mesh / relay surface seals + transports them.
//! - **Stream-format spec owner.** The container shape
//!   (per-frame `(stream_id, epoch, chunk_seq, sealed_bytes)`) lives
//!   in [`super::realtime_av`]. This layer's outputs feed into that
//!   container as `chunk_plaintext`.

#[cfg(feature = "codec-fountain")]
pub mod fountain;

#[cfg(feature = "codec-av1")]
pub mod av1;

#[cfg(feature = "codec-opus")]
pub mod opus_voice;
