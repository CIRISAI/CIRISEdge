//! `ReplicationDirectory` — the narrow API the replication module needs
//! from a federation directory backing.
//!
//! Layer (c) sub-step 1 of CIRISEdge#65. Layer (a) (protocol +
//! state machine) shipped in PR #69; layer (b) (transport binding +
//! coordinator) shipped in PR #70.
//!
//! ## Why a narrow trait
//!
//! Persist's `ciris_persist::FederationDirectory` exposes ~25 methods
//! across keys / attestations / revocations / identity_occurrences /
//! families / communities / pending / etc. The replication module
//! needs ~3 of those: enumerate refs per `EnvelopeKind` for a cohort
//! of key_ids, fetch byte-exact signed envelope by content hash, and
//! apply byte-exact signed envelope to local state. This module
//! defines `ReplicationDirectory` exposing only those three; the
//! production wiring (a blanket impl over `Arc<dyn FederationDirectory>`)
//! lives behind an FFI boundary and lands as a follow-up sub-step in
//! a subsequent PR.
//!
//! ## Why the production wiring is a follow-up
//!
//! Three integration concerns the blanket impl resolves:
//!
//! 1. **No persist-side "list all envelopes by kind" API.** The
//!    FederationDirectory trait has `list_attestations_for(key_id)` +
//!    `list_attestations_by(key_id)` + `revocations_for(key_id)`, all
//!    cohort-scoped. The production adapter accepts a
//!    `cohort_provider: Arc<dyn Fn() -> Vec<String>>` callback that
//!    yields the operator-configured key_ids we care about (federation
//!    peers we want to anti-entropy with), enumerates per-key, and
//!    deduplicates via the content hash.
//!
//! 2. **No persist-side `lookup_by_hash()` API.** Production wiring
//!    maintains an in-memory `HashMap<[u8; 32], Vec<u8>>` populated
//!    from the same enumeration. Acceptable cost: federation envelope
//!    counts are O(thousands) per node, not O(billions); the cache is
//!    cheap.
//!
//! 3. **PyO3 init.** Edge constructs runtime objects in
//!    `init_edge_runtime(engine, ...)` via the executor_capsule +
//!    federation_directory_capsule FFI bridges. The replication
//!    coordinator + adapter need to be plumbed into that init path
//!    behind a feature gate so the PyO3 wheel can wire them. The
//!    `ReplicationDirectory` trait defined here is the contract the
//!    init path consumes.
//!
//! Each of these is its own engineering quantum. Shipping the trait
//! design + a `MockReplicationDirectory` for in-edge tests + the
//! `StateProvider` / `StateApplier` adapter impl unblocks layer (b)
//! integration testing in advance of those final wiring sub-steps.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use super::protocol::{EnvelopeKind, EnvelopeRef};
use super::summary::{StateApplier, StateProvider};

/// Narrow API the replication module needs from a federation directory
/// backing. Implementations:
///
/// - `MockReplicationDirectory` (this module, test-only) — in-memory
///   shim used by replication tests.
/// - `FederationDirectoryAdapter` (production wiring — separate PR)
///   wraps `Arc<dyn ciris_persist::FederationDirectory>` + a cohort
///   provider callback.
#[async_trait]
pub trait ReplicationDirectory: Send + Sync {
    /// Enumerate the local envelope refs for `kind`. Implementations
    /// scope to the operator-configured cohort of interest; the
    /// trait makes no statement about WHICH cohort — that's the
    /// implementation's job.
    async fn list_envelope_refs(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef>;

    /// CIRISEdge#379 — RECIPIENT-AWARE enumeration: the refs `peer` may
    /// receive. Defaults to the peer-blind [`Self::list_envelope_refs`];
    /// implementations with per-recipient policy (the bridge's `observer`-
    /// capability gate on the trace scores-attestation plane) override.
    /// `None` = projection-only view (tests / diagnostics), ungated.
    async fn list_envelope_refs_for_peer(
        &self,
        kind: EnvelopeKind,
        _peer_key_id: Option<&str>,
    ) -> Vec<EnvelopeRef> {
        self.list_envelope_refs(kind).await
    }

    /// Return the byte-exact signed envelope for `(kind,
    /// envelope_hash)`, or `None` if the envelope isn't in local state.
    /// Called during the `Deliver`-message construction step.
    async fn fetch_envelope_bytes(
        &self,
        kind: EnvelopeKind,
        envelope_hash: &[u8; 32],
    ) -> Option<Vec<u8>>;

    /// CIRISEdge#379 — RECIPIENT-AWARE fetch: the serve-side twin of
    /// [`Self::list_envelope_refs_for_peer`], so a peer excluded from the
    /// listing cannot obtain a gated envelope anyway by Diff/Fetch-ing its
    /// hash directly (learned out-of-band). Defaults to the peer-blind
    /// fetch; the bridge overrides.
    async fn fetch_envelope_bytes_for_peer(
        &self,
        kind: EnvelopeKind,
        envelope_hash: &[u8; 32],
        _peer_key_id: Option<&str>,
    ) -> Option<Vec<u8>> {
        self.fetch_envelope_bytes(kind, envelope_hash).await
    }

    /// Apply one envelope to local state. The implementation verifies
    /// the signed envelope's signature + canonical-bytes hash before
    /// admitting; if validation fails the apply silently returns
    /// `false` (the merge layer in persist is the canonical anti-
    /// rollback authority). Returns `true` if the apply admitted a
    /// new envelope (changed local state), `false` if it was a
    /// duplicate or refused.
    async fn apply_envelope_bytes(&self, kind: EnvelopeKind, envelope_bytes: &[u8]) -> bool;
}

/// Adapter that lifts an `Arc<dyn ReplicationDirectory>` into the
/// sync [`StateProvider`] + async [`StateApplier`] surfaces the
/// session machinery expects.
///
/// The session machinery uses synchronous traits (the state machine
/// is itself synchronous — it just produces messages); this adapter
/// bridges to the async `ReplicationDirectory` by using
/// `tokio::runtime::Handle::current().block_on(...)` inside the
/// sync impls. SAFE because:
///
/// - The session is driven from inside an async tokio context (the
///   coordinator's `drive_round_step` is `async fn`).
/// - The `block_on` calls are short — typed lookups against the
///   directory or its cache, no I/O loops.
/// - The directory's own implementation owns its locking; the adapter
///   doesn't add synchronization beyond what the trait obliges.
///
/// If the calling thread is NOT inside a tokio runtime, the
/// `Handle::current()` call panics with a clear message — same
/// behavior as any other tokio-coupled sync interface.
pub struct DirectoryStateAdapter {
    inner: Arc<dyn ReplicationDirectory>,
    /// CIRISEdge#379 — the peer this provider serves. When set, listing +
    /// fetch route through the recipient-aware trait methods so per-peer
    /// policy (the `observer`-capability gate on trace attestations) applies
    /// on BOTH the advertise and the serve path. `None` = peer-blind
    /// (projection-only view; tests).
    peer_key_id: Option<String>,
}

impl DirectoryStateAdapter {
    pub fn new(inner: Arc<dyn ReplicationDirectory>) -> Self {
        Self {
            inner,
            peer_key_id: None,
        }
    }

    /// CIRISEdge#379 — bind this provider to the peer it serves (builder).
    #[must_use]
    pub fn with_peer(mut self, peer_key_id: impl Into<String>) -> Self {
        self.peer_key_id = Some(peer_key_id.into());
        self
    }
}

impl StateProvider for DirectoryStateAdapter {
    fn local_refs(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        let inner = Arc::clone(&self.inner);
        let peer = self.peer_key_id.clone();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                inner
                    .list_envelope_refs_for_peer(kind, peer.as_deref())
                    .await
            })
        })
    }

    fn fetch_envelope(&self, kind: EnvelopeKind, envelope_hash: &[u8; 32]) -> Option<Vec<u8>> {
        let inner = Arc::clone(&self.inner);
        let hash = *envelope_hash;
        let peer = self.peer_key_id.clone();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                inner
                    .fetch_envelope_bytes_for_peer(kind, &hash, peer.as_deref())
                    .await
            })
        })
    }
}

impl StateApplier for DirectoryStateAdapter {
    fn apply_envelope(&mut self, _kind: EnvelopeKind, _envelope_bytes: &[u8]) -> bool {
        // NOTE: This impl is the *read* half of the adapter — the
        // `Session` machinery currently borrows the applier `&mut`,
        // which conflicts with the borrow-checker on a shared
        // `Arc<DirectoryStateAdapter>`. The production wiring uses a
        // separate `Arc<Mutex<dyn StateApplier>>` shape (the
        // coordinator's `apply_envelope` is gated by the mutex).
        //
        // For the `&mut self` apply surface, see
        // `MutableDirectoryStateAdapter` below — the same adapter
        // body, exposed through `&mut self` so the coordinator's
        // `Mutex<dyn StateApplier>` shape composes.
        unreachable!(
            "DirectoryStateAdapter::apply_envelope on shared self — \
             use MutableDirectoryStateAdapter (held inside Mutex) for the apply path"
        )
    }
}

/// Mutable-self variant of [`DirectoryStateAdapter`] for the
/// `Arc<Mutex<dyn StateApplier>>` shape the coordinator owns.
/// The implementations are identical to the shared-self read path;
/// keeping them as distinct types makes the borrow story crystal
/// clear at the type level.
pub struct MutableDirectoryStateAdapter {
    inner: Arc<dyn ReplicationDirectory>,
}

impl MutableDirectoryStateAdapter {
    pub fn new(inner: Arc<dyn ReplicationDirectory>) -> Self {
        Self { inner }
    }
}

impl StateApplier for MutableDirectoryStateAdapter {
    fn apply_envelope(&mut self, kind: EnvelopeKind, envelope_bytes: &[u8]) -> bool {
        let inner = Arc::clone(&self.inner);
        let bytes = envelope_bytes.to_vec();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async move { inner.apply_envelope_bytes(kind, &bytes).await })
        })
    }
}

/// Type alias for the mock's storage shape: `(kind, envelope_hash) →
/// (signed_bytes, seq)`. Aliased to keep the type-complexity lint
/// happy + make the storage shape explicit at the type-system level.
type MockStorage = HashMap<(EnvelopeKind, [u8; 32]), (Vec<u8>, u64)>;

/// In-memory mock for the in-edge replication tests. Holds envelope
/// state keyed by `(kind, envelope_hash)`. Useful for end-to-end
/// session tests that don't want to depend on persist.
pub struct MockReplicationDirectory {
    /// See [`MockStorage`]. Stored inside an `RwLock` so the trait
    /// impls can be invoked concurrently from multiple sessions
    /// (mirrors the production wiring's locking model — the
    /// directory's underlying storage owns the lock).
    inner: RwLock<MockStorage>,
}

impl MockReplicationDirectory {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Seed the mock with an envelope. Tests use this to set up
    /// "alice has these envelopes" / "bob has these other envelopes"
    /// scenarios.
    pub async fn seed(
        &self,
        kind: EnvelopeKind,
        envelope_hash: [u8; 32],
        bytes: Vec<u8>,
        seq: u64,
    ) {
        let mut m = self.inner.write().await;
        m.insert((kind, envelope_hash), (bytes, seq));
    }

    /// How many envelopes for a kind — diagnostic helper for tests.
    pub async fn count(&self, kind: EnvelopeKind) -> usize {
        self.inner
            .read()
            .await
            .keys()
            .filter(|(k, _)| *k == kind)
            .count()
    }
}

impl Default for MockReplicationDirectory {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ReplicationDirectory for MockReplicationDirectory {
    async fn list_envelope_refs(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        let m = self.inner.read().await;
        let mut refs: Vec<EnvelopeRef> = m
            .iter()
            .filter(|((k, _), _)| *k == kind)
            .map(|((_, h), (_, s))| EnvelopeRef {
                envelope_hash: *h,
                seq: *s,
            })
            .collect();
        // BTreeMap-stable ordering matches the [`LocalState::refs_for`]
        // shape so tests that pin exact byte order remain
        // deterministic.
        refs.sort_by_key(|r| r.envelope_hash);
        refs
    }

    async fn fetch_envelope_bytes(
        &self,
        kind: EnvelopeKind,
        envelope_hash: &[u8; 32],
    ) -> Option<Vec<u8>> {
        let m = self.inner.read().await;
        m.get(&(kind, *envelope_hash)).map(|(b, _)| b.clone())
    }

    async fn apply_envelope_bytes(&self, kind: EnvelopeKind, envelope_bytes: &[u8]) -> bool {
        use sha2::{Digest, Sha256};
        // Production directories validate the signed envelope's
        // signature; the mock just content-hashes and stores. The
        // hash IS the lookup key, so storing keyed by hash means a
        // second apply of identical bytes is a no-op (matches the
        // production "duplicate → no-op via R1/Q1 dedupe" semantics).
        let hash: [u8; 32] = Sha256::digest(envelope_bytes).into();
        let mut m = self.inner.write().await;
        let key = (kind, hash);
        if m.contains_key(&key) {
            return false; // duplicate
        }
        // Seq tracking in the mock is best-effort — we use the current
        // highest-seq-for-kind + 1 so test scenarios that care about
        // monotonic seqs get them.
        let next_seq = m
            .iter()
            .filter(|((k, _), _)| *k == kind)
            .map(|(_, (_, s))| *s)
            .max()
            .unwrap_or(0)
            + 1;
        m.insert(key, (envelope_bytes.to_vec(), next_seq));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(seed: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = seed;
        a
    }

    /// Seed + list_envelope_refs round-trip + sorted output.
    #[tokio::test]
    async fn seed_and_list_returns_sorted_refs() {
        let dir = MockReplicationDirectory::new();
        // Insert out-of-order seeds.
        dir.seed(EnvelopeKind::Key, h(9), b"e9".to_vec(), 1).await;
        dir.seed(EnvelopeKind::Key, h(1), b"e1".to_vec(), 2).await;
        dir.seed(EnvelopeKind::Key, h(5), b"e5".to_vec(), 3).await;
        // Different kind should NOT appear in the Key list.
        dir.seed(EnvelopeKind::Attestation, h(2), b"a2".to_vec(), 7)
            .await;
        let refs = dir.list_envelope_refs(EnvelopeKind::Key).await;
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[0].envelope_hash, h(1));
        assert_eq!(refs[1].envelope_hash, h(5));
        assert_eq!(refs[2].envelope_hash, h(9));
        assert_eq!(dir.count(EnvelopeKind::Attestation).await, 1);
    }

    /// fetch_envelope_bytes returns the seeded bytes; absent hash
    /// returns None.
    #[tokio::test]
    async fn fetch_returns_bytes_or_none() {
        let dir = MockReplicationDirectory::new();
        dir.seed(EnvelopeKind::Revocation, h(7), b"rev7".to_vec(), 10)
            .await;
        let got = dir
            .fetch_envelope_bytes(EnvelopeKind::Revocation, &h(7))
            .await;
        assert_eq!(got, Some(b"rev7".to_vec()));
        let missing = dir
            .fetch_envelope_bytes(EnvelopeKind::Revocation, &h(99))
            .await;
        assert_eq!(missing, None);
        // Different kind, same hash → None.
        let wrong_kind = dir.fetch_envelope_bytes(EnvelopeKind::Key, &h(7)).await;
        assert_eq!(wrong_kind, None);
    }

    /// apply_envelope_bytes admits new envelopes, refuses duplicates.
    #[tokio::test]
    async fn apply_admits_new_refuses_duplicates() {
        let dir = MockReplicationDirectory::new();
        // First apply admits.
        let first = dir
            .apply_envelope_bytes(EnvelopeKind::Key, b"envelope_one")
            .await;
        assert!(first);
        assert_eq!(dir.count(EnvelopeKind::Key).await, 1);
        // Same bytes again — duplicate.
        let second = dir
            .apply_envelope_bytes(EnvelopeKind::Key, b"envelope_one")
            .await;
        assert!(!second);
        assert_eq!(dir.count(EnvelopeKind::Key).await, 1);
        // Different bytes — admitted.
        let third = dir
            .apply_envelope_bytes(EnvelopeKind::Key, b"envelope_two")
            .await;
        assert!(third);
        assert_eq!(dir.count(EnvelopeKind::Key).await, 2);
    }

    /// apply_envelope_bytes computes content hash internally, so an
    /// envelope whose seeded hash matches its bytes is the duplicate
    /// case at the next apply.
    #[tokio::test]
    async fn apply_after_seed_with_matching_hash_is_duplicate() {
        use sha2::{Digest, Sha256};
        let dir = MockReplicationDirectory::new();
        let payload = b"federation envelope bytes";
        let hash: [u8; 32] = Sha256::digest(payload).into();
        dir.seed(EnvelopeKind::Attestation, hash, payload.to_vec(), 5)
            .await;
        // Apply identical bytes → duplicate.
        let r = dir
            .apply_envelope_bytes(EnvelopeKind::Attestation, payload)
            .await;
        assert!(!r);
        assert_eq!(dir.count(EnvelopeKind::Attestation).await, 1);
    }

    /// DirectoryStateAdapter (read path) bridges the async trait to
    /// the sync StateProvider via block_in_place. The test holds the
    /// concrete Arc<MockReplicationDirectory> for seeding AND passes
    /// it as Arc<dyn> to the adapter.
    #[tokio::test(flavor = "multi_thread")]
    async fn directory_state_adapter_reads_through() {
        let mock = Arc::new(MockReplicationDirectory::new());
        mock.seed(EnvelopeKind::Key, h(3), b"e3".to_vec(), 1).await;
        let dir: Arc<dyn ReplicationDirectory> = Arc::clone(&mock) as Arc<dyn ReplicationDirectory>;
        let adapter = DirectoryStateAdapter::new(dir);
        let refs = adapter.local_refs(EnvelopeKind::Key);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].envelope_hash, h(3));
        let bytes = adapter.fetch_envelope(EnvelopeKind::Key, &h(3));
        assert_eq!(bytes, Some(b"e3".to_vec()));
    }

    /// MutableDirectoryStateAdapter (write path) bridges the async
    /// trait to the &mut self StateApplier.
    #[tokio::test(flavor = "multi_thread")]
    async fn mutable_directory_state_adapter_writes_through() {
        let mock = Arc::new(MockReplicationDirectory::new());
        let dir: Arc<dyn ReplicationDirectory> = Arc::clone(&mock) as Arc<dyn ReplicationDirectory>;
        let mut adapter = MutableDirectoryStateAdapter::new(dir);
        let admitted = adapter.apply_envelope(EnvelopeKind::Revocation, b"rev_bytes");
        assert!(admitted);
        assert_eq!(mock.count(EnvelopeKind::Revocation).await, 1);
    }

    /// Round-trip via the adapters: seed via mock, list via adapter,
    /// apply via adapter, re-list shows the new envelope.
    #[tokio::test(flavor = "multi_thread")]
    async fn adapters_round_trip_via_session_shape() {
        let mock = Arc::new(MockReplicationDirectory::new());
        mock.seed(EnvelopeKind::Attestation, h(1), b"e1".to_vec(), 1)
            .await;
        let dir: Arc<dyn ReplicationDirectory> = Arc::clone(&mock) as Arc<dyn ReplicationDirectory>;
        let provider = DirectoryStateAdapter::new(Arc::clone(&dir));
        let mut applier = MutableDirectoryStateAdapter::new(dir);
        // Initial list shows the seed.
        assert_eq!(provider.local_refs(EnvelopeKind::Attestation).len(), 1);
        // Apply a new envelope.
        let admitted = applier.apply_envelope(EnvelopeKind::Attestation, b"e_new");
        assert!(admitted);
        // List now shows two.
        assert_eq!(provider.local_refs(EnvelopeKind::Attestation).len(), 2);
        // Duplicate apply refused.
        let dup = applier.apply_envelope(EnvelopeKind::Attestation, b"e_new");
        assert!(!dup);
        assert_eq!(provider.local_refs(EnvelopeKind::Attestation).len(), 2);
    }
}
