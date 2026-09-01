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
use super::summary::{ApplyOutcome, StateApplier, StateProvider};

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

    /// CIRISEdge#416 — the RAW holdings for `kind`: the content-hash of EVERY
    /// row present in local state, with NO projection / advertise filtering and
    /// NO recipient reasoning. This is the RECEIVE axis's set — "what do I hold"
    /// — as distinct from [`Self::list_envelope_refs`] ("what would I advertise",
    /// projection-filtered). The anti-entropy `want = remote ∖ holdings` diff
    /// depends on the convergence invariant *after admitting an envelope, its hash
    /// appears here*; a projection-filtered listing breaks it, so a held-but-not-
    /// advertised row (e.g. a `self`/`family` attestation from another producer,
    /// on the Attestation plane) would stay in `want` forever and stall the round.
    /// Defaults to [`Self::list_envelope_refs`] for planes whose advertise view
    /// equals their holdings; the bridge overrides the Attestation plane.
    async fn list_holdings(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        self.list_envelope_refs(kind).await
    }

    /// CIRISEdge#462 — the RECEIVE-axis SERVE reader: the refs held for `kind`
    /// where `subject_key_id` is the data-subject (records ABOUT it) or, on the
    /// Attestation plane, the sender (records BY it — authorship recovery).
    /// Answers an inbound subject-scoped Pull, reaching the `SelfOwn` plane the
    /// advertise projection never offers (a fedID pulling its own testimony onto
    /// a node no peer would ever *advertise* it to).
    ///
    /// `peer_key_id` is the AUTHENTICATED requester. The implementation MUST
    /// serve only a requester entitled to the subject's rows (this cut:
    /// requester == subject, fail-closed) and MUST withhold peer-authored
    /// `capacity:*` scores about the subject (the G2 self-revocation-hole carve).
    /// The refs it returns hash the SAME struct the wire index keys on, so the
    /// unchanged Diff/Deliver flow — re-gated per record by
    /// [`Self::fetch_envelope_bytes_for_peer`] — carries the bytes. Defaults to
    /// empty: only the production bridge answers a subject pull.
    async fn subject_holdings(
        &self,
        _kind: EnvelopeKind,
        _subject_key_id: &str,
        _peer_key_id: Option<&str>,
    ) -> Vec<EnvelopeRef> {
        Vec::new()
    }

    /// CIRISEdge#474 — the accord-quorum-evidence CURSOR serve reader: the
    /// byte-exact bundles held with `evidence_at > since`, JSON-serialized ready to
    /// wrap in a `Deliver`. Answers an inbound `CursorPull` for a plane that has NO
    /// content-hash index (so no Diff/Fetch round-trip — the responder delivers
    /// directly). Bounded by the impl's page limit; the requester re-pulls from its
    /// new high-water to drain a backlog. Defaults to empty: only the production
    /// bridge (holding the persist `FederationDirectory`) answers it.
    ///
    /// CIRISEdge#531 — `peer_key_id` is the AUTHENTICATED requester, and it is
    /// here for the DEPTH bound rather than for policy: the responder keeps a
    /// per-peer serve watermark so a byte-budgeted page continues on the next
    /// round instead of re-serving page one forever (edge initiators open every
    /// cursor round from `since: None`, so without a responder-side position a
    /// truncated page would never be passed). `None` = unattributed: one
    /// budgeted page from the declared floor, no position kept.
    async fn accord_evidence_since(
        &self,
        _kind: EnvelopeKind,
        _since: Option<chrono::DateTime<chrono::Utc>>,
        _peer_key_id: Option<&str>,
    ) -> Vec<Vec<u8>> {
        Vec::new()
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

    /// CIRISEdge#544 — has this node already refused `(kind, envelope_hash)`
    /// recently enough that the round should NOT ask for it again?
    ///
    /// Deliberately **synchronous**: it is an in-memory probe of the
    /// implementation's own refusal memory, consulted once per wanted hash per
    /// round, and routing it through the adapter's `block_on` would put a
    /// runtime hop on the hot path of a pure map lookup. It must never do I/O.
    ///
    /// Defaults to `false` (ask for everything, the pre-#544 behaviour) so the
    /// mock and any host impl need no change; the bridge overrides it with the
    /// [`RefusalBackoff`](super::refusal_backoff::RefusalBackoff) its apply path
    /// populates.
    /// CIRISEdge#552 — how much of `kind` this node keeps. Defaults to
    /// `Bodies`, the pre-#552 behaviour; the bridge overrides it from config.
    fn retention(&self, _kind: EnvelopeKind) -> super::retention::Retention {
        super::retention::Retention::Bodies
    }

    /// CIRISEdge#552 — learn hashes whose bodies this node did not fetch.
    fn note_known_hashes(
        &self,
        _kind: EnvelopeKind,
        _hashes: &[[u8; 32]],
        _advertised_by: Option<&str>,
    ) {
    }

    /// CIRISEdge#552 (B) — a transient refusal named a signer this node may not
    /// hold. Recording it is all that happens here: admission stays LOCAL and
    /// still fails transient, because the revocation admission path is the one
    /// path that must never depend on a peer answering. Something out of band
    /// pulls the key; the #544 backoff then re-offers the row and it admits.
    ///
    /// Sync by design, like [`Self::note_known_hashes`] — it sits on the apply
    /// loop. Whether the key is genuinely absent is decided at the DRAIN, which
    /// can afford the store lookup this cannot.
    fn note_missing_signer(
        &self,
        _kind: EnvelopeKind,
        _signer_key_id: &str,
        _source_peer: Option<&str>,
    ) {
    }

    /// CIRISEdge#552 (B) — see [`StateProvider::take_missing_signers`].
    ///
    /// [`StateProvider::take_missing_signers`]:
    ///     super::summary::StateProvider::take_missing_signers
    /// CIRISEdge#552 (B) — see [`StateProvider::take_missing_signer_for`].
    ///
    /// [`StateProvider::take_missing_signer_for`]:
    ///     super::summary::StateProvider::take_missing_signer_for
    fn take_missing_signer_for(&self, _peer_key_id: &str) -> Option<String> {
        None
    }

    fn retry_suppressed(&self, _kind: EnvelopeKind, _envelope_hash: &[u8; 32]) -> bool {
        false
    }

    /// Apply one envelope to local state. The implementation verifies the signed
    /// envelope's signature + canonical-bytes hash before admitting; the merge
    /// layer in persist is the canonical anti-rollback authority. Returns an
    /// [`ApplyOutcome`] (CIRISEdge#425): `Admitted` if a NEW envelope changed local
    /// state, else a `Refused`/`Deserialize` carrying WHY — never a silent drop.
    ///
    /// CIRISEdge#426 — `source_peer` is the authenticated sender (E3-gated
    /// upstream). The consent plane was send-only because this identity never
    /// reached here; carrying it makes a per-peer RECEIVE decision expressible.
    async fn apply_envelope_bytes(
        &self,
        kind: EnvelopeKind,
        envelope_bytes: &[u8],
        source_peer: Option<&str>,
    ) -> ApplyOutcome;
}

/// Adapter that lifts an `Arc<dyn ReplicationDirectory>` into the
/// sync [`StateProvider`] surface the session machinery expects (the
/// apply half lives on [`MutableDirectoryStateAdapter`]).
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

    /// CIRISEdge#414 + #416 — the node's REAL holdings for the round's RECEIVE
    /// diff: [`ReplicationDirectory::list_holdings`], the RAW per-kind
    /// content-hash set with NO projection / advertise filtering and NO recipient
    /// reasoning. #414 correctly moved the SEND gate off the receive axis but
    /// wired this to `list_envelope_refs` — still the *advertise* view; #416 fixes
    /// it to true holdings, so `want` shrinks after admission and the round
    /// converges. The per-peer #396 send gate + projection stay on the offer
    /// ([`Self::local_refs`]) and delivery (`fetch_envelope_bytes_for_peer`).
    fn local_holdings(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        let inner = Arc::clone(&self.inner);
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async move { inner.list_holdings(kind).await })
        })
    }

    /// CIRISEdge#544 — forward the want-suppression question to the directory,
    /// which is the ONE shared bridge every per-peer provider sits on. No
    /// `block_on`: the trait method is sync precisely so this stays a map probe.
    /// Node-wide by construction — peer A's refusal removes the row from peer
    /// B's `want` too, which is the point (the verdict is about this node's
    /// state, not about who carried the bytes).
    /// CIRISEdge#552 — FORWARD, do not answer.
    ///
    /// This adapter is the production `StateProvider`, and until it forwarded
    /// these the whole feature was inert: every node took the trait default
    /// (`Bodies`) no matter what the bridge was configured to do. Nothing broke,
    /// which is exactly why it went unnoticed — a retention policy that is never
    /// consulted looks identical to one that decides "keep everything".
    fn retention(&self, kind: EnvelopeKind) -> super::retention::Retention {
        self.inner.retention(kind)
    }

    fn note_known_hashes(
        &self,
        kind: EnvelopeKind,
        hashes: &[[u8; 32]],
        advertised_by: Option<&str>,
    ) {
        self.inner.note_known_hashes(kind, hashes, advertised_by);
    }

    fn note_missing_signer(
        &self,
        kind: EnvelopeKind,
        signer_key_id: &str,
        source_peer: Option<&str>,
    ) {
        self.inner
            .note_missing_signer(kind, signer_key_id, source_peer);
    }

    fn take_missing_signer_for(&self, peer_key_id: &str) -> Option<String> {
        self.inner.take_missing_signer_for(peer_key_id)
    }

    fn retry_suppressed(&self, kind: EnvelopeKind, envelope_hash: &[u8; 32]) -> bool {
        self.inner.retry_suppressed(kind, envelope_hash)
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

    /// CIRISEdge#462 — answer a subject-scoped Pull. Routes to
    /// [`ReplicationDirectory::subject_holdings`] with the bound `peer_key_id`
    /// (the authenticated requester) so the impl's entitlement gate (requester ==
    /// subject) and the G2 capacity carve both apply.
    fn subject_refs(&self, kind: EnvelopeKind, subject_key_id: &str) -> Vec<EnvelopeRef> {
        let inner = Arc::clone(&self.inner);
        let subject = subject_key_id.to_owned();
        let peer = self.peer_key_id.clone();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                inner
                    .subject_holdings(kind, &subject, peer.as_deref())
                    .await
            })
        })
    }

    /// CIRISEdge#474 — serve an accord-quorum-evidence cursor pull, bridging the
    /// async persist read into the sync provider surface (same `block_on` pattern
    /// as [`Self::subject_refs`]). Returns the serialized bundles past `since`.
    fn accord_evidence_since(
        &self,
        kind: EnvelopeKind,
        since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Vec<Vec<u8>> {
        let inner = Arc::clone(&self.inner);
        // CIRISEdge#531 — the bound peer travels with the pull so the impl can
        // keep a per-peer serve watermark under the page's byte budget.
        let peer = self.peer_key_id.clone();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                inner
                    .accord_evidence_since(kind, since, peer.as_deref())
                    .await
            })
        })
    }
}

/// The apply half of [`DirectoryStateAdapter`], kept as a distinct type so
/// the provider (peer-BOUND: #379 observer gate) and applier (peer-BLIND:
/// `source_peer` arrives per-call) surfaces stay separate at the type level.
///
/// CIRISEdge#370 — `apply_envelope` is `&self` and this adapter is a
/// STATELESS wrapper over `Arc<dyn ReplicationDirectory>`, so ONE shared
/// `Arc<dyn StateApplier>` serves every per-peer coordinator with NO
/// wrapping mutex. (The historical name survives from the `&mut self` era,
/// when the coordinator had to hold it inside `Arc<Mutex<dyn StateApplier>>`
/// — the lock protected nothing and serialized every peer's applies through
/// one hold-across-the-whole-message critical section with `block_on` DB
/// I/O inside; the store owns the real concurrency control.)
pub struct MutableDirectoryStateAdapter {
    inner: Arc<dyn ReplicationDirectory>,
}

impl MutableDirectoryStateAdapter {
    pub fn new(inner: Arc<dyn ReplicationDirectory>) -> Self {
        Self { inner }
    }
}

impl StateApplier for MutableDirectoryStateAdapter {
    fn apply_envelope(
        &self,
        kind: EnvelopeKind,
        envelope_bytes: &[u8],
        source_peer: Option<&str>,
    ) -> ApplyOutcome {
        let inner = Arc::clone(&self.inner);
        let bytes = envelope_bytes.to_vec();
        let peer = source_peer.map(str::to_owned);
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                inner
                    .apply_envelope_bytes(kind, &bytes, peer.as_deref())
                    .await
            })
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

    async fn apply_envelope_bytes(
        &self,
        kind: EnvelopeKind,
        envelope_bytes: &[u8],
        _source_peer: Option<&str>,
    ) -> ApplyOutcome {
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
            return ApplyOutcome::Duplicate;
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
        ApplyOutcome::Admitted
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
    /// CIRISEdge#552 (B) — the adapter must FORWARD the missing-signer seam.
    ///
    /// This test exists because of how #552 (A) failed: `retention()` was
    /// implemented on the bridge, defaulted on the trait, and never forwarded
    /// here — so production took the default and six review rounds ran against
    /// a feature that could not execute. A default-bodied trait method that
    /// nothing forwards is indistinguishable from a working one until you look
    /// for the call. So: assert the forward, in both directions.
    #[test]
    fn the_adapter_forwards_the_missing_signer_seam() {
        #[derive(Default)]
        struct RecordingDir {
            noted: std::sync::Mutex<Vec<String>>,
        }
        #[async_trait::async_trait]
        impl ReplicationDirectory for RecordingDir {
            async fn list_envelope_refs(&self, _k: EnvelopeKind) -> Vec<EnvelopeRef> {
                Vec::new()
            }
            async fn fetch_envelope_bytes(
                &self,
                _k: EnvelopeKind,
                _h: &[u8; 32],
            ) -> Option<Vec<u8>> {
                None
            }
            async fn apply_envelope_bytes(
                &self,
                _k: EnvelopeKind,
                _b: &[u8],
                _p: Option<&str>,
            ) -> ApplyOutcome {
                ApplyOutcome::Admitted
            }
            fn note_missing_signer(
                &self,
                _k: EnvelopeKind,
                signer: &str,
                source_peer: Option<&str>,
            ) {
                self.noted
                    .lock()
                    .unwrap()
                    .push(format!("{signer}@{}", source_peer.unwrap_or("-")));
            }
            fn take_missing_signer_for(&self, peer: &str) -> Option<String> {
                Some(format!("drained-for-{peer}"))
            }
        }

        let inner = Arc::new(RecordingDir::default());
        let adapter =
            DirectoryStateAdapter::new(Arc::clone(&inner) as Arc<dyn ReplicationDirectory>);

        StateProvider::note_missing_signer(
            &adapter,
            EnvelopeKind::Attestation,
            "steward-xyz",
            Some("peer-src"),
        );
        assert_eq!(
            inner.noted.lock().unwrap().as_slice(),
            ["steward-xyz@peer-src"],
            "note_missing_signer must reach the inner directory — an unforwarded \
             seam silently takes the no-op default (the #552 A inertness bug)"
        );
        assert_eq!(
            StateProvider::take_missing_signer_for(&adapter, "peer-src").as_deref(),
            Some("drained-for-peer-src"),
            "take_missing_signer_for must reach the inner directory too, carrying \
             the peer it is routing for"
        );
    }

    #[tokio::test]
    async fn apply_admits_new_refuses_duplicates() {
        let dir = MockReplicationDirectory::new();
        // First apply admits.
        let first = dir
            .apply_envelope_bytes(EnvelopeKind::Key, b"envelope_one", None)
            .await;
        assert!(first.is_admitted());
        assert_eq!(dir.count(EnvelopeKind::Key).await, 1);
        // Same bytes again — duplicate.
        let second = dir
            .apply_envelope_bytes(EnvelopeKind::Key, b"envelope_one", None)
            .await;
        assert!(!second.is_admitted(), "duplicate must not admit");
        assert_eq!(dir.count(EnvelopeKind::Key).await, 1);
        // Different bytes — admitted.
        let third = dir
            .apply_envelope_bytes(EnvelopeKind::Key, b"envelope_two", None)
            .await;
        assert!(third.is_admitted());
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
            .apply_envelope_bytes(EnvelopeKind::Attestation, payload, None)
            .await;
        assert!(!r.is_admitted(), "matching-hash re-apply is a duplicate");
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
    /// trait to the `&self` StateApplier (#370).
    #[tokio::test(flavor = "multi_thread")]
    async fn mutable_directory_state_adapter_writes_through() {
        let mock = Arc::new(MockReplicationDirectory::new());
        let dir: Arc<dyn ReplicationDirectory> = Arc::clone(&mock) as Arc<dyn ReplicationDirectory>;
        let adapter = MutableDirectoryStateAdapter::new(dir);
        let admitted = adapter.apply_envelope(EnvelopeKind::Revocation, b"rev_bytes", None);
        assert!(admitted.is_admitted());
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
        let applier = MutableDirectoryStateAdapter::new(dir);
        // Initial list shows the seed.
        assert_eq!(provider.local_refs(EnvelopeKind::Attestation).len(), 1);
        // Apply a new envelope.
        let admitted = applier.apply_envelope(EnvelopeKind::Attestation, b"e_new", None);
        assert!(admitted.is_admitted());
        // List now shows two.
        assert_eq!(provider.local_refs(EnvelopeKind::Attestation).len(), 2);
        // Duplicate apply refused.
        let dup = applier.apply_envelope(EnvelopeKind::Attestation, b"e_new", None);
        assert!(!dup.is_admitted(), "duplicate apply must not admit");
        assert_eq!(provider.local_refs(EnvelopeKind::Attestation).len(), 2);
    }
}
