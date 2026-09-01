//! The serving-tier axis (`docs/ROLE_MATRIX.md` Axis 3) — resolved, cached,
//! and impossible to confuse with `AgentMode` again.
//!
//! # Why this module exists
//!
//! Retention shipped keyed on `AgentMode` in v18.12.1. `AgentMode` is the
//! LOCAL-RESOURCES posture — listener binding, outbound queue size — and says
//! nothing about whether a node was conferred the directory role. The result: a
//! node set to `server` for queue reasons silently held the federation
//! directory hash-first, and a node actually conferred `infra:serve` running
//! `proxy` never did. The one-variable-two-jobs bug, on the axis whose whole
//! point is *which nodes hold the directory*.
//!
//! The serving tier is a DIRECTORY fact (CC 4, "two granters"): the **owner**
//! confers `infra:serve` (a mesh server — may store & serve to help the mesh);
//! the **trust root** blesses it (a canonical — additionally trusted for
//! bootstrap, the moment trust cannot yet be verified). It is orthogonal to
//! `AgentMode`, to `identity_type` (an agent node can be a full server), and it
//! is resolver-relative at the canonical rung (Axis 5: the same blessing
//! resolves differently under different roots).

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

/// Where a node stands on the serving axis. Ordered: `Canonical` may do
/// everything `MeshServer` may.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ServeTier {
    /// No conferral. Holds its own records; answers a subject Pull only for
    /// the subject itself and for its own record.
    None = 0,
    /// Owner-conferred `infra:serve` — `delegates_to(owner → node,
    /// [infra:serve])`. May store & serve to help the mesh: hold the directory
    /// hash-first, answer third-party identifier Pulls, serve bodies by hash.
    /// Needs no one's trust to do it — everything served is a
    /// self-authenticating signed envelope, re-verified at the receiver's own
    /// admission gate.
    MeshServer = 1,
    /// Root-blessed (the 2-of-3 accord co-scrub over a `canonical,node`
    /// registration envelope bearing `roles: ["infra:serve"]` — CC 4.4.3.8).
    /// Additionally trusted for BOOTSTRAP: the `CanonicalBootstrapPeer` set,
    /// rooting a fresh fleet, the E3 trace-plane serve gate.
    Canonical = 2,
}

impl ServeTier {
    /// May this node hold the directory and answer identifier lookups —
    /// the ROLE_MATRIX "≥ mesh server" predicate that retention, known-hash
    /// recording, and the third-party Pull arm all key on?
    #[must_use]
    pub fn may_store_and_serve(self) -> bool {
        self >= ServeTier::MeshServer
    }

    /// Is this node in the set a fresh fleet may lean on before verification
    /// is possible? (Bootstrap and the trace plane. Nothing below `Canonical`
    /// qualifies, and even this is resolver-relative — see Axis 5.)
    #[must_use]
    pub fn trusted_for_bootstrap(self) -> bool {
        self == ServeTier::Canonical
    }

    /// Stable string for logs and metrics.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ServeTier::None => "none",
            ServeTier::MeshServer => "mesh_server",
            ServeTier::Canonical => "canonical",
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            2 => ServeTier::Canonical,
            1 => ServeTier::MeshServer,
            _ => ServeTier::None,
        }
    }
}

/// Resolves a subject's serving tier. Injectable so the decision logic is
/// testable over every tier without a directory, and so the production
/// resolution can grow the mesh-server rung when CIRISPersist#788 ships
/// without touching a single consumer.
#[async_trait::async_trait]
pub trait ServeTierResolver: Send + Sync {
    /// Resolve the tier, fail-closed.
    ///
    /// The Exhibit-C contract: a READ FAILURE must not be reported as "no
    /// tier" — implementations log the distinction; the returned tier is
    /// conservative either way because every consumer treats `None` as the
    /// safe state (hold bodies, serve only your own record).
    async fn resolve(&self, subject_key_id: &str) -> ServeTier;
}

/// The production resolver: persist's two canonical legs today, the
/// mesh-server rung fail-closed pending CIRISPersist#788.
///
/// | rung | resolution | status |
/// |---|---|---|
/// | canonical | leg A (`has_accord_conferred_role` — the co-scrub re-derived from the row's own cryptography) ∧ leg B (`capability_roots_to_trusted_root` — chains to THIS resolver's root) | live |
/// | mesh server | the owner's `delegates_to` bearing `infra:serve` | **fail-closed**: persist has no resolver for the owner-conferred rung (`claims_role` is *visibility, never conferral*), so a row that claims the role but cannot be verified resolves `None` with a WARN naming CIRISPersist#788 |
///
/// Fail-closed is the right degradation: an unrecognized mesh server holds
/// bodies and serves only its own record — it under-helps the mesh, it never
/// over-claims a role.
pub struct DirectoryServeTierResolver {
    directory: Arc<dyn ciris_persist::federation::FederationDirectory>,
    /// Axis 5 — the trust base the canonical rung resolves against. Canonical
    /// is a property of the (node, resolver) pair, not of the node.
    resolver_key_id: String,
}

impl DirectoryServeTierResolver {
    #[must_use]
    pub fn new(
        directory: Arc<dyn ciris_persist::federation::FederationDirectory>,
        resolver_key_id: String,
    ) -> Self {
        Self {
            directory,
            resolver_key_id,
        }
    }
}

#[async_trait::async_trait]
impl ServeTierResolver for DirectoryServeTierResolver {
    async fn resolve(&self, subject_key_id: &str) -> ServeTier {
        use ciris_persist::federation::admission::has_accord_conferred_role;
        use ciris_persist::federation::trust_root::capability_roots_to_trusted_root;

        // Leg A — the accord co-scrub, re-derived from the record's own
        // cryptography on every call so a withdrawn blessing bites immediately.
        let leg_a = match has_accord_conferred_role(
            &*self.directory,
            subject_key_id,
            crate::replication::bridge::FederationDirectoryReplicationBridge::SERVE_CAPABILITY,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                // Exhibit C — a read failure is NOT "no role". Say so, resolve
                // conservatively.
                tracing::warn!(
                    subject = %subject_key_id,
                    error = %e,
                    "serve-tier leg A read FAILED — resolving conservatively to \
                     tier none; this is a transient read error, not a statement \
                     about the subject's blessing"
                );
                false
            }
        };
        if leg_a {
            // Leg B — the blessing must chain to THIS resolver's trusted root.
            match capability_roots_to_trusted_root(
                &*self.directory,
                &self.resolver_key_id,
                subject_key_id,
                crate::replication::bridge::FederationDirectoryReplicationBridge::SERVE_CAPABILITY,
            )
            .await
            {
                Ok(Some(_grant)) => return ServeTier::Canonical,
                Ok(None) => {
                    // Blessed under SOME root, but not one this resolver
                    // trusts. Axis 5 working as designed, worth a debug line.
                    tracing::debug!(
                        subject = %subject_key_id,
                        "accord-conferred infra:serve does not chain to this \
                         resolver's trusted root — canonical elsewhere, not here"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        subject = %subject_key_id,
                        error = %e,
                        "serve-tier leg B read FAILED — resolving conservatively \
                         below canonical"
                    );
                }
            }
        }

        // Mesh-server rung — CIRISPersist#788. `claims_role` is visibility,
        // never conferral; without the owner-grant resolver the honest answer
        // is `None`, loudly, so an operator who conferred the role knows why
        // the node is not yet acting on it.
        match self.directory.lookup_public_key(subject_key_id).await {
            Ok(Some(row))
                if row.claims_role(
                    crate::replication::bridge::FederationDirectoryReplicationBridge::SERVE_CAPABILITY,
                ) =>
            {
                tracing::warn!(
                    subject = %subject_key_id,
                    "row CLAIMS infra:serve but the owner-conferred rung has no \
                     resolver yet (CIRISPersist#788) — resolving tier NONE, \
                     fail-closed: this node will hold bodies and serve only its \
                     own record until the conferral can be verified"
                );
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    subject = %subject_key_id,
                    error = %e,
                    "serve-tier claim probe read FAILED (informational only — \
                     the resolution was already tier none)"
                );
            }
        }
        ServeTier::None
    }
}

/// The bridge-side cache: sync reads on hot paths, async refresh on paths that
/// can afford it.
///
/// `retention()` and `note_known_hashes` sit on the apply loop and are sync by
/// design; a graph walk there is the wrong shape (CIRISPersist#788 Ask 2 is
/// the eventual projection). Until then: async bridge methods call
/// [`Self::refresh_if_stale`] (once per [`Self::TTL`]), sync methods read the
/// last resolved value. Fail-closed start: an unresolved cache reads
/// [`ServeTier::None`], so a canonical serves conservatively for its first
/// seconds rather than a bystander serving expansively.
pub struct CachedServeTier {
    tier: AtomicU8,
    /// Millis since an arbitrary process-start epoch, 0 = never resolved.
    resolved_at_ms: std::sync::atomic::AtomicU64,
    epoch: std::time::Instant,
    /// Single-flight gate. Concurrent callers crossing a stale boundary would
    /// otherwise each start an independent directory walk, and whichever
    /// finished LAST would win — so a walk begun against older state could
    /// overwrite a newer result and mark that stale decision fresh for another
    /// full TTL. If a conferral had just been withdrawn, that re-enables
    /// serving; if one had just been granted, it suppresses it.
    ///
    /// Holding this across the await is deliberate: the second caller waits and
    /// then finds the cache fresh, which is exactly the intent (one walk per
    /// window), and the wait is bounded by one directory resolution.
    refresh_lock: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for CachedServeTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedServeTier")
            .field("tier", &self.read().as_str())
            .finish_non_exhaustive()
    }
}

impl CachedServeTier {
    /// How long a resolved tier is trusted before an async path re-resolves.
    /// A revoked conferral therefore bites within a minute on serving
    /// decisions; retention of already-held bodies is unaffected by design
    /// (dropping bodies on a tier downgrade would be data loss, not policy).
    pub const TTL: std::time::Duration = std::time::Duration::from_secs(60);

    #[must_use]
    pub fn new() -> Self {
        Self {
            tier: AtomicU8::new(ServeTier::None as u8),
            resolved_at_ms: std::sync::atomic::AtomicU64::new(0),
            epoch: std::time::Instant::now(),
            refresh_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// The last resolved tier ([`ServeTier::None`] until first resolution).
    #[must_use]
    pub fn read(&self) -> ServeTier {
        ServeTier::from_u8(self.tier.load(Ordering::Relaxed))
    }

    /// Is the cached tier within its TTL?
    fn is_fresh(&self) -> bool {
        let resolved_at = self.resolved_at_ms.load(Ordering::Relaxed);
        if resolved_at == 0 {
            return false;
        }
        let now_ms = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
        let ttl_ms = u64::try_from(Self::TTL.as_millis()).unwrap_or(u64::MAX);
        now_ms.saturating_sub(resolved_at) < ttl_ms
    }

    /// Overwrite (tests, and the refresh path).
    pub fn store(&self, tier: ServeTier) {
        self.tier.store(tier as u8, Ordering::Relaxed);
        let now_ms = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
        // 0 means "never"; a resolve in the first millisecond still counts.
        self.resolved_at_ms.store(now_ms.max(1), Ordering::Relaxed);
    }

    /// Re-resolve through `resolver` if the cache is stale. Concurrent callers
    /// may race to refresh; the result is idempotent and the extra walk is
    /// bounded by TTL, so no lock is held across the await.
    pub async fn refresh_if_stale(&self, resolver: &dyn ServeTierResolver, subject_key_id: &str) {
        if self.is_fresh() {
            return;
        }
        // SINGLE-FLIGHT. One walk per window, and the last writer is the one
        // that started last — without this, a refresh begun against older state
        // could land after a newer one and revive a withdrawn conferral for a
        // whole TTL.
        let _flight = self.refresh_lock.lock().await;
        // Re-check under the gate: a caller that queued behind the walk we were
        // waiting on has nothing to do.
        if self.is_fresh() {
            return;
        }
        let tier = resolver.resolve(subject_key_id).await;
        let prev = self.read();
        if tier != prev {
            tracing::info!(
                from = prev.as_str(),
                to = tier.as_str(),
                "serve tier changed (ROLE_MATRIX axis 3)"
            );
        }
        self.store(tier);
    }
}

impl Default for CachedServeTier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two predicates ARE the matrix's tier column — exhaustive so a
    /// fourth tier cannot silently inherit either power.
    #[test]
    fn the_tier_predicates_match_the_role_matrix() {
        for tier in [ServeTier::None, ServeTier::MeshServer, ServeTier::Canonical] {
            assert_eq!(
                tier.may_store_and_serve(),
                tier >= ServeTier::MeshServer,
                "store-and-serve is the ≥ mesh-server predicate"
            );
            assert_eq!(
                tier.trusted_for_bootstrap(),
                tier == ServeTier::Canonical,
                "bootstrap trust is canonical-only — a mesh server helps AFTER \
                 trust exists, a canonical is leaned on BEFORE it can be verified"
            );
        }
    }

    /// Fail-closed start: an unresolved cache is tier `None`.
    #[test]
    fn an_unresolved_cache_reads_tier_none() {
        let cache = CachedServeTier::new();
        assert_eq!(cache.read(), ServeTier::None);
        assert!(!cache.read().may_store_and_serve());
    }

    /// The cache honors its TTL: within it, the resolver is not consulted.
    #[tokio::test]
    async fn a_fresh_cache_does_not_re_resolve() {
        struct Counting(std::sync::atomic::AtomicUsize);
        #[async_trait::async_trait]
        impl ServeTierResolver for Counting {
            async fn resolve(&self, _s: &str) -> ServeTier {
                self.0.fetch_add(1, Ordering::SeqCst);
                ServeTier::Canonical
            }
        }
        let cache = CachedServeTier::new();
        let resolver = Counting(std::sync::atomic::AtomicUsize::new(0));
        cache.refresh_if_stale(&resolver, "me").await;
        cache.refresh_if_stale(&resolver, "me").await;
        cache.refresh_if_stale(&resolver, "me").await;
        assert_eq!(
            resolver.0.load(Ordering::SeqCst),
            1,
            "one resolution inside the TTL — the hot path must not walk the \
             graph per call"
        );
        assert_eq!(cache.read(), ServeTier::Canonical);
    }
}
