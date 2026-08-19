//! Edge-side adapter shapes for the v5.2.0 swarm orchestration runtime.
//!
//! ## v7.0.0 (CIRISEdge#194) collapse
//!
//! Persist v10.0.0 (CIRISPersist#270) promoted three methods —
//! `list_held_fountain_content` / `evict_fountain_content_to_tier` /
//! `evict_fountain_content_hard_delete` — to **required methods** on the
//! public `FederationDirectory` trait. The v5.2.0-era adapter traits that
//! bridged onto the concrete `Backend` (`FountainTierEvict`,
//! `PersistFountainEvictHardDelete`) and the `PersistFountainEvictHardDelete`
//! production wrapper are no longer needed: `FountainSwarmRuntime` calls
//! the directory directly for both eviction surfaces.
//!
//! ## What still lives here
//!
//! [`FountainHoldingsSource`] is the ONE adapter that survives. Persist's
//! `list_held_fountain_content` returns
//! [`ciris_persist::fountain::FountainHeldMeta`] — manifest essentials
//! plus a `held_symbols` *count*, but NOT the per-symbol `symbol_id` list
//! the substrate's [`crate::holonomic::swarm_rarity::FountainHoldingClaim`]
//! ships in its canonical bytes. The set of currently-held `symbol_ids`
//! lives in the operator's local symbol store, not in the public directory
//! surface — so an edge-side trait surface remains the right shape for
//! that view.
//!
//! Re-exported substrate-tier [`FountainEvictHardDelete`] /
//! [`FountainEvictError`] continue to live in
//! [`crate::holonomic::swarm_rarity`] for the §8.1.11.3 N5 typed
//! deletion-SLA primitive (substrate-tier policy/audit surface, not the
//! adapter-tier surface dropped above).

use async_trait::async_trait;

pub use crate::holonomic::swarm_rarity::{FountainEvictError, FountainEvictHardDelete};

/// A single fountain content unit the operator is currently holding.
/// Returned by [`FountainHoldingsSource::list_held_fountain_content`]
/// (the v5.2.0 publisher walks the returned vec to build claims).
///
/// Carries the per-symbol `symbol_id` list — the field persist v10.0.0's
/// `list_held_fountain_content` does not expose (it returns
/// `FountainHeldMeta` with counts only, not per-symbol IDs). The source
/// trait fills that gap from whatever the operator holds locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldFountainContent {
    /// The persist `fountain_contents.content_id`. Opaque substrate
    /// identifier (typically the manifest sha256 hex).
    pub content_id: String,
    /// The persist `fountain_contents.corpus_kind` discriminator
    /// (passed through opaquely to eviction calls).
    pub corpus_kind: String,
    /// The fountain `symbol_id`s the operator currently retains for
    /// this content. The publisher signs a
    /// [`crate::holonomic::swarm_rarity::FountainHoldingClaim`] over
    /// this set.
    pub symbol_ids: Vec<u32>,
}

/// Operator-side view of "what fountain content am I currently
/// holding?". The v5.2.0 publisher consults this on every
/// `publish_cadence` tick.
///
/// # Why this trait survived the v10.0.0 collapse
///
/// Persist v10.0.0 promoted `list_held_fountain_content` to the public
/// `FederationDirectory` surface but the returned `FountainHeldMeta`
/// carries `held_symbols` as a **count**, not the per-`symbol_id` list
/// the [`crate::holonomic::swarm_rarity::FountainHoldingClaim`]'s
/// canonical bytes require. The per-symbol IDs are an operator-local
/// view (the symbol-bytes store the publisher keeps adjacent to the
/// directory); they are not a directory-surface concern.
///
/// Production wires a thin impl that reads its concrete symbol-store
/// (joining `directory.list_held_fountain_content(local_pubkey).await`
/// with the local per-content symbol-id map for the same `(content_id,
/// corpus_kind)` rows). [`NoopFountainHoldingsSource`] keeps tests +
/// bootstrap nodes drivable on hosts that hold nothing yet.
#[async_trait]
pub trait FountainHoldingsSource: Send + Sync {
    /// Enumerate the operator's currently-held fountain content units.
    /// Order is implementation-defined; the runtime sorts internally
    /// where determinism matters (the
    /// [`crate::holonomic::swarm_rarity::FountainHoldingClaim`]
    /// canonical bytes pre-sort `symbol_ids` ascending).
    async fn list_held_fountain_content(
        &self,
    ) -> Result<Vec<HeldFountainContent>, FountainEvictError>;

    /// CIRISEdge#499 — the SCOPE this held content lives in, so the
    /// publisher can decide which peers may be told the holding exists.
    ///
    /// **Edge never infers a content's scope.** Content classification is
    /// the persist-backed consumer's, exactly as it is on the blob plane
    /// ([`BlobChunkSource::chunk_scope`](crate::blob_swarm::BlobChunkSource::chunk_scope),
    /// whose shape this deliberately mirrors — one seam shape for the two
    /// planes, not two). `None` means *undeterminable*, and is NEVER read
    /// as `Public`: on a scope-native node it withholds the announcement
    /// ([`HoldingRefusal::ScopeUndeterminable`](super::scope::HoldingRefusal::ScopeUndeterminable)).
    ///
    /// The default returns `None`, which keeps every existing
    /// implementation compiling AND keeps its behaviour byte-identical:
    /// the publish gate is armed only where a
    /// [`ScopeAddressTable`](crate::scope_addressing::ScopeAddressTable)
    /// is installed, and a deployment with no table announces every
    /// holding regardless of what this returns. A consumer that installs
    /// an address table MUST override this or its holdings plane fails
    /// closed — which is the correct order of operations: publish a
    /// scoped holding only once you can say what scope it is in.
    ///
    /// Synchronous on purpose: it is consulted once per held content on
    /// the publish tick, between `.await` points, and an `async` seam here
    /// would invite a lock guard to be held across one (CIRISEdge#217).
    fn content_scope(&self, _content_id: &str) -> Option<crate::blob_swarm::ContentScope> {
        None
    }
}

/// A `FountainHoldingsSource` that returns an empty list. Used in
/// `init_edge_runtime` when no concrete source has been wired —
/// keeps the runtime spawnable on hosts that don't yet hold any
/// fountain content (or whose persist handle doesn't yet expose the
/// listing API). Tests and tier-1 deployments wire the real source.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopFountainHoldingsSource;

#[async_trait]
impl FountainHoldingsSource for NoopFountainHoldingsSource {
    async fn list_held_fountain_content(
        &self,
    ) -> Result<Vec<HeldFountainContent>, FountainEvictError> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_holdings_source_returns_empty() {
        let src = NoopFountainHoldingsSource;
        assert!(src
            .list_held_fountain_content()
            .await
            .expect("ok")
            .is_empty());
    }
}
