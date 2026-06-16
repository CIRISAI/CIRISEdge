//! Holonomic substrate — the edge-side primitives that drive
//! federation-level self-reconstitution of fountain-coded content.
//!
//! The v3.8.0 substrate (PR #131) put the wire-format machinery for
//! holographic / sub-stream-fanned content in place; v3.9.0 onward
//! layers the holonomic policy machinery on top — scheduling,
//! priority recomputation, and the witness chains that v3.10.0
//! consumes. See `docs/ROADMAP_TO_V4.md` for the cut sequence.
//!
//! ## Current contents
//!
//! - [`consent_decay`] — per-content_id Consensual Evolution Protocol
//!   decay scheduler. Walks fountain content_ids periodically;
//!   recomputes target [`DecayTier`](consent_decay::DecayTier) from
//!   (now, admitted_at, consent_class, revoked_at); pushes tier
//!   changes through the [`PersistHandle`](consent_decay::PersistHandle)
//!   FFI trait. The trait is stubbed at v3.9.0 L1 pending the persist
//!   v8.x surface; the scheduler logic is fully wired and tested.

#[cfg(feature = "holonomic-consent-decay")]
pub mod consent_decay;
