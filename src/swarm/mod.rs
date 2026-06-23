//! Federation-level fountain swarm orchestration runtime — v5.2.0
//! lit, v7.0.0 collapsed onto persist v10.0.0.
//!
//! Closes the live-wiring gap identified in CIRISEdge#143. The
//! holonomic substrate primitives ([`crate::holonomic::swarm_rarity`])
//! are unit-tested in isolation; this module is what makes peers
//! actually do the federation-coordinated work at runtime:
//!
//! - **Publisher**: periodically iterate the operator's held fountain
//!   `content_id`s, build a
//!   [`crate::holonomic::swarm_rarity::FountainHoldingClaim`] for
//!   each, sign it via the local federation signer, and emit it to
//!   the cohort over the canonical transport.
//! - **Converger**: every `observe_cadence`, walk the in-memory
//!   observed-claims map and:
//!     * if observed_count exceeds `target_holders × (1 + grace_pct)`
//!       and the local symbol is "common", call
//!       `FederationDirectory::evict_fountain_content_to_tier`
//!       (the persist N5 path, promoted to the public surface in
//!       v10.0.0);
//!     * if observed_count drops below `min_viable`, emit a repair
//!       telemetry signal (a future cut wires the blob_swarm fetch
//!       path off this);
//!     * if consent is revoked, call
//!       `FederationDirectory::evict_fountain_content_hard_delete`
//!       (also promoted in v10.0.0).
//!
//! ## v7.0.0 adapter collapse (CIRISEdge#194 / CIRISPersist#270)
//!
//! Persist v10.0.0 promoted `list_held_fountain_content`,
//! `evict_fountain_content_to_tier`, and
//! `evict_fountain_content_hard_delete` to required methods on
//! [`ciris_persist::federation::FederationDirectory`]. Two of the three
//! v5.2.0 adapter traits drop here:
//!
//! - `FountainTierEvict` — **deleted** (runtime now calls
//!   `directory.evict_fountain_content_to_tier(...)` directly).
//! - `PersistFountainEvictHardDelete` — **deleted** (runtime now calls
//!   `directory.evict_fountain_content_hard_delete(...)` directly; the
//!   substrate-tier sync trait [`FountainEvictHardDelete`] in
//!   `holonomic::swarm_rarity` stays — it's the typed §8.1.11.3 N5
//!   policy/audit surface, NOT the adapter surface).
//!
//! [`FountainHoldingsSource`] **survives** because persist's
//! `list_held_fountain_content` returns
//! [`ciris_persist::fountain::FountainHeldMeta`] with `held_symbols` as
//! a *count*, not the per-symbol `symbol_id` list the
//! [`crate::holonomic::swarm_rarity::FountainHoldingClaim`] canonical
//! bytes ship. The per-symbol IDs are an operator-local view
//! (publisher's symbol-store) that production wires alongside the
//! directory.
//!
//! See [`runtime`] for the live runtime + scheduler.

pub mod diversity;
pub mod persist_fountain_evict;
pub mod runtime;

pub use diversity::{
    diversity_contribution, diversity_scores_for, NullRttObserver, PeerRttObserver,
    RttObserverHandle, TopologyRttObserver,
};
pub use persist_fountain_evict::{
    FountainEvictError, FountainEvictHardDelete, FountainHoldingsSource, HeldFountainContent,
    NoopFountainHoldingsSource,
};
pub use runtime::{
    FountainSwarmRuntime, ObservedClaim, SwarmEvent, SwarmRuntimeConfig, SwarmRuntimeEventSink,
    SwarmRuntimeOptions,
};
