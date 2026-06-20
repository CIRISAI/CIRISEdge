//! Production-side trait surfaces + adapter for the v5.2.0 swarm
//! orchestration runtime.
//!
//! Three trait surfaces participate here:
//!
//! - [`crate::holonomic::swarm_rarity::FountainEvictHardDelete`] —
//!   the §8.1.11.3 N5 hard-delete primitive (already defined in the
//!   substrate module; reused here unchanged).
//! - [`FountainTierEvict`] — the tier-eviction sibling
//!   ([`PersistEngine::evict_fountain_content_to_tier`] is the
//!   persist-side concrete; until it appears on the public
//!   `Arc<dyn FederationDirectory>` trait, the runtime threads an
//!   `Arc<dyn FountainTierEvict>` for production wiring).
//! - [`FountainHoldingsSource`] — the operator's "what content_ids
//!   am I currently holding?" view. Persist v9.0.x does NOT yet
//!   expose this on its public surface; the runtime threads an
//!   `Arc<dyn FountainHoldingsSource>` so production can wire it
//!   once persist lands the iteration API.
//!
//! ## Production adapter
//!
//! [`PersistFountainEvictHardDelete`] is a thin wrapper that holds
//! an `Arc<dyn FountainEvictHardDelete>` (the production caller
//! constructs this from its persist `Engine` handle). It exists so
//! `Edge::run` / `init_edge_runtime` can pass *one* handle through
//! the bootstrap and the runtime stays decoupled from the concrete
//! engine type.

use std::sync::Arc;

use async_trait::async_trait;

pub use crate::holonomic::swarm_rarity::{FountainEvictError, FountainEvictHardDelete};

/// A single fountain content unit the operator is currently holding.
/// Returned by [`FountainHoldingsSource::list_held_fountain_content`]
/// (the v5.2.0 publisher walks the returned vec to build claims).
///
/// Mirrors the shape persist's eventual `list_fountain_holdings` API
/// is expected to return — content_id + corpus_kind + the symbol_ids
/// the operator currently retains for that content.
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
/// **Persist v9.0.x gap**: there is currently no public listing API
/// on `Arc<dyn FederationDirectory>` that returns this view. Until
/// persist v9.x lands one, production deployments implement this
/// trait against their concrete persist `Engine` handle (or against
/// whatever cohabitation surface their host exposes); the test
/// surface ([`NoopFountainHoldingsSource`] + the in-tree
/// `Vec`-backed test impls) drives the runtime in isolation.
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

/// The tier-eviction sibling of
/// [`FountainEvictHardDelete`]. Maps onto persist's
/// `evict_fountain_content_to_tier(content_id, corpus_kind, tier)`
/// concrete API. The `tier` parameter is the persist
/// `FountainTier` discriminator as a stable string label
/// (`"full" | "t2" | "t3" | "t4" | "t5"`) so the trait surface
/// does NOT depend on which backend cfg-features are enabled.
///
/// **Persist v9.0.x gap**: like
/// [`FountainEvictHardDelete`], not exposed on
/// `Arc<dyn FederationDirectory>`. Production wires a concrete
/// impl that calls into its `Engine` handle.
#[async_trait]
pub trait FountainTierEvict: Send + Sync {
    /// Evict `content_id` (in the named corpus) down to the keep-
    /// count for the named tier. The persist eviction surface
    /// applies the change on its next maintenance pass — this call
    /// does NOT block on the eviction itself. Returns `Ok(())` on
    /// acceptance.
    ///
    /// # Errors
    ///
    /// Returns [`FountainEvictError::HardDeleteFailed`] (the error
    /// type is shared across the hard-delete + tier-evict surfaces
    /// for v5.2.0 — a future cut may split it once persist's
    /// public surface stabilizes).
    async fn evict_fountain_content_to_tier(
        &self,
        content_id: &str,
        corpus_kind: &str,
        tier: &str,
    ) -> Result<(), FountainEvictError>;
}

/// Production-side adapter that satisfies [`FountainEvictHardDelete`]
/// by delegating to an inner trait object. Constructor + the trait
/// impl. Edge's bootstrap (`Edge::run` / `init_edge_runtime`)
/// constructs one of these from the persist `Engine` handle the
/// host exposes; the runtime holds the `Arc<dyn FountainEvictHardDelete>`
/// and never sees the concrete engine type.
///
/// The `inner` trait object MUST be a concrete impl that calls into
/// persist's `evict_fountain_content_hard_delete`; the v5.2.0 in-tree
/// impl is a passthrough so production callers can substitute a real
/// engine adapter without touching the runtime.
pub struct PersistFountainEvictHardDelete {
    inner: Arc<dyn FountainEvictHardDelete + Send + Sync>,
}

impl std::fmt::Debug for PersistFountainEvictHardDelete {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistFountainEvictHardDelete")
            .finish_non_exhaustive()
    }
}

impl PersistFountainEvictHardDelete {
    /// Construct from any inner [`FountainEvictHardDelete`] impl.
    /// The production caller passes its persist `Engine`-backed
    /// adapter; the test surface passes the substrate module's
    /// fake evictor.
    #[must_use]
    pub fn new(inner: Arc<dyn FountainEvictHardDelete + Send + Sync>) -> Self {
        Self { inner }
    }
}

impl FountainEvictHardDelete for PersistFountainEvictHardDelete {
    fn evict_fountain_content_hard_delete(
        &self,
        content_id: &str,
        corpus_kind: &str,
    ) -> Result<(), FountainEvictError> {
        self.inner
            .evict_fountain_content_hard_delete(content_id, corpus_kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// In-memory `FountainEvictHardDelete` that records the calls —
    /// the substrate-tier `swarm_rarity` tests already exercise the
    /// trait shape, this one is for the adapter passthrough check.
    #[derive(Default)]
    struct Recorder {
        calls: Mutex<Vec<(String, String)>>,
    }
    impl FountainEvictHardDelete for Recorder {
        fn evict_fountain_content_hard_delete(
            &self,
            content_id: &str,
            corpus_kind: &str,
        ) -> Result<(), FountainEvictError> {
            self.calls
                .lock()
                .unwrap()
                .push((content_id.to_string(), corpus_kind.to_string()));
            Ok(())
        }
    }

    #[test]
    fn adapter_delegates_to_inner() {
        let rec: Arc<Recorder> = Arc::new(Recorder::default());
        let adapter = PersistFountainEvictHardDelete::new(rec.clone());
        adapter
            .evict_fountain_content_hard_delete("c1", "fountain-corpus")
            .expect("ok");
        adapter
            .evict_fountain_content_hard_delete("c2", "fountain-corpus")
            .expect("ok");
        let calls = rec.calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![
                ("c1".to_string(), "fountain-corpus".to_string()),
                ("c2".to_string(), "fountain-corpus".to_string()),
            ]
        );
    }

    #[test]
    fn adapter_surfaces_inner_failure() {
        struct Failing;
        impl FountainEvictHardDelete for Failing {
            fn evict_fountain_content_hard_delete(
                &self,
                _: &str,
                _: &str,
            ) -> Result<(), FountainEvictError> {
                Err(FountainEvictError::HardDeleteFailed("inner-fail".into()))
            }
        }
        let adapter = PersistFountainEvictHardDelete::new(Arc::new(Failing));
        let err = adapter
            .evict_fountain_content_hard_delete("c1", "f")
            .expect_err("must surface");
        assert!(matches!(err, FountainEvictError::HardDeleteFailed(_)));
    }

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
