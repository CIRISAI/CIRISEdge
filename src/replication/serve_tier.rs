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
    /// [infra:serve])`. Stores and serves to help the mesh: carries the
    /// directory as HASHES and serves bodies BY HASH. It does not answer
    /// identifier lookups, because answering one requires the body and it has
    /// chosen not to hold them.
    /// Needs no one's trust to do it — everything served is a
    /// self-authenticating signed envelope, re-verified at the receiver's own
    /// admission gate.
    MeshServer = 1,
    /// Root-blessed (the 2-of-3 accord co-scrub over a `canonical,node`
    /// registration envelope bearing `roles: ["infra:serve"]` — CC 4.4.3.8).
    /// Holds the directory as BODIES, so it is the tier that can answer an
    /// identifier lookup — "which records do you hold for subject S" — and the
    /// one place bulk harvesting is possible, one named subject at a time.
    /// Additionally trusted for BOOTSTRAP: the `CanonicalBootstrapPeer` set,
    /// rooting a fresh fleet, the E3 trace-plane serve gate.
    Canonical = 2,
}

impl ServeTier {
    /// Does this node carry the directory as HASHES, fetching bodies on
    /// demand? Mesh servers only.
    ///
    /// Not a ladder: a canonical does NOT hash-first, because it must hold the
    /// bodies (see [`Self::answers_identifier_lookups`]). The two roles carry
    /// the directory differently rather than one carrying more of it.
    #[must_use]
    pub fn holds_hash_directory(self) -> bool {
        self == ServeTier::MeshServer
    }

    /// Does this node answer an identifier lookup — "which records do you hold
    /// for subject S"? **Canonicals only**, and the reason is mechanical
    /// before it is policy.
    ///
    /// Answering requires the BODY: `subject_holdings_inner` resolves a subject
    /// through `lookup_public_key`, and persist's own subject-scoped reads are
    /// built from the held records — `wire_refs_for_subject` reads
    /// `list_signed_key_records_since`, and the Key plane has no subject-indexed
    /// signed read at all. There is no body-free identifier path anywhere in
    /// the stack. So a hash-first node CANNOT answer, whatever it is entitled
    /// to, and pretending otherwise is what made the earlier
    /// "≥ mesh server" rule unsatisfiable.
    ///
    /// That mechanical fact also lands the anti-harvest property in the right
    /// place. Bulk enumeration is only possible where bodies are, so bodies
    /// concentrate at canonicals — few, accountable, rate-limited — while mesh
    /// servers carry hashes and can be scraped for "these records exist" and
    /// nothing more. The identifier Pull cannot enumerate on its own: the
    /// requester must NAME the subject, so it confirms people it already knows
    /// rather than discovering new ones.
    ///
    /// Friction on a plane that is public by construction, not confidentiality
    /// (CC 1.13.3.1).
    #[must_use]
    pub fn answers_identifier_lookups(self) -> bool {
        self == ServeTier::Canonical
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

impl ServeTier {
    /// Map persist's rung onto edge's.
    ///
    /// The two enums are deliberately separate types with identical shape:
    /// edge's is what its own decision table keys on, and a compile error here
    /// is how a future rung added on either side gets noticed. An exhaustive
    /// match, so adding one is a deliberate edit rather than a silent default.
    #[must_use]
    fn from_persist(tier: ciris_persist::federation::trust_root::ServeTier) -> Self {
        use ciris_persist::federation::trust_root::ServeTier as P;
        match tier {
            P::None => ServeTier::None,
            P::MeshServer => ServeTier::MeshServer,
            P::Canonical => ServeTier::Canonical,
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

/// The production resolver — both rungs live, delegated to persist
/// (CIRISPersist#788, v38.8.0).
///
/// | rung | resolution |
/// |---|---|
/// | mesh server | the subject claims `infra:serve` **and** its owner granted it, via a live `delegates_to(owner → subject)` bearing that scope. CC 4's first granter, and resolver-INDEPENDENT: an owner's conferral over its own node is not relative to who is asking |
/// | canonical | the 2-of-3 accord co-scrub over a `canonical,node` envelope, with the granting root walking to a trust root THIS resolver accepts. CC 4's second granter, and resolver-RELATIVE — two nodes can correctly disagree about whether the same key is canonical |
///
/// Both re-derive from the records' own cryptography on every call, so a
/// withdrawn conferral bites immediately. `claims_role` alone still buys
/// nothing: lifting an envelope-attested role creates VISIBILITY, never
/// conferral.
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
        // CIRISPersist#788 (v38.8.0) — persist owns BOTH rungs now, and edge
        // asks rather than re-deriving. That was always the right split: the
        // walk reuses persist's ONE scope-parse and ONE CEG-tombstone fold, and
        // forking either into a consumer doubles the policy the FSD insists
        // lives in a single authority.
        match ciris_persist::federation::trust_root::resolve_serve_tier(
            &*self.directory,
            subject_key_id,
            &self.resolver_key_id,
        )
        .await
        {
            Ok(tier) => ServeTier::from_persist(tier),
            Err(e) => {
                // Exhibit C, and persist states the same contract: a READ
                // FAILURE is not "no serve standing". Reporting a transient
                // failure as a confident statement about the subject sends an
                // operator looking in the wrong place. The tier is conservative
                // either way, because every consumer treats `None` as the safe
                // state — hold bodies, serve only your own record.
                tracing::warn!(
                    subject = %subject_key_id,
                    error = %e,
                    "serve-tier resolution FAILED — resolving conservatively to \
                     tier none; this is a transient read error, not a statement \
                     about the subject's conferral"
                );
                ServeTier::None
            }
        }
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
                tier.holds_hash_directory(),
                tier == ServeTier::MeshServer,
                "only a mesh server carries the directory as hashes — a \
                 canonical holds bodies, because answering an identifier lookup \
                 requires one"
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
        assert!(!cache.read().holds_hash_directory());
        assert!(!cache.read().answers_identifier_lookups());
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
