//! Identity binding — Reticulum address ↔ persist steward seed.
//!
//! Mission: bind the peer's network address to its persist-managed
//! cryptographic identity, with the seed never crossing the FFI
//! boundary. PoB §3.2: addressing IS identity — the Reticulum
//! destination is `sha256(public_key)[..16]`, computed from the same
//! key that signs `federation_keys` rows in persist.
//! ([`MISSION.md`](../../MISSION.md) §2 `identity/`.)
//!
//! Anti-pattern: edge loading the seed at startup and caching it. The
//! seed lives in persist's OS-keyring (CIRISPersist v0.1.3+ AV-25
//! closure); edge holds the `Engine` handle and calls into persist
//! for sign / public-key-derive operations. The seed bytes never
//! enter edge's process memory. AV-17 heap-scan property test
//! enforces this empirically.
//!
//! Implementation lands in a subsequent commit alongside the verify
//! pipeline wire-up.
