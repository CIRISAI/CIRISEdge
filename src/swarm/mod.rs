//! Federation-level fountain swarm orchestration runtime — v5.2.0.
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
//!       and the local symbol is "common",
//!       [`should_eject_above_target`] → call
//!       [`FountainTierEvict::evict_fountain_content_to_tier`]
//!       (the persist N5 path);
//!     * if observed_count drops below `min_viable`, emit a repair
//!       telemetry signal (a future cut wires the blob_swarm fetch
//!       path off this);
//!     * if consent is revoked, call
//!       [`crate::holonomic::swarm_rarity::FountainEvictHardDelete::evict_fountain_content_hard_delete`].
//!
//! ## Persist surface gap (recorded for upstream)
//!
//! CIRISPersist v9.0.x does NOT expose:
//!
//! - `list_fountain_holdings()` — the operator's view of "which
//!   `content_id`s am I currently holding?" against the federation
//!   directory trait.
//! - `evict_fountain_content_to_tier` / `evict_fountain_content_hard_delete`
//!   on `Arc<dyn FederationDirectory>` (only on the concrete
//!   `Engine`, gated behind backend cargo features).
//!
//! Until persist v9.x lands those surfaces on the public trait, the
//! runtime is built against in-tree trait surfaces ([`FountainHoldingsSource`],
//! [`FountainTierEvict`]) plus the existing
//! [`crate::holonomic::swarm_rarity::FountainEvictHardDelete`]. The
//! production deployment wires concrete impls of these traits over
//! its persist `Engine` handle; the test surface implements them
//! against in-memory state. **This is the documented scope-down per
//! the v5.2.0 cut spec** (CIRISEdge#143).
//!
//! See [`runtime`] for the live runtime + scheduler.

pub mod persist_fountain_evict;
pub mod runtime;

pub use persist_fountain_evict::{
    FountainEvictError, FountainEvictHardDelete, FountainHoldingsSource, FountainTierEvict,
    HeldFountainContent, NoopFountainHoldingsSource, PersistFountainEvictHardDelete,
};
pub use runtime::{
    FountainSwarmRuntime, ObservedClaim, SwarmEvent, SwarmRuntimeConfig, SwarmRuntimeEventSink,
};
