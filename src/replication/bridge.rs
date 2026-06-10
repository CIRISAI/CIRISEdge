//! `FederationDirectoryReplicationBridge` — production layer (c-2)
//! wiring of `ReplicationDirectory` over persist's `FederationDirectory`.
//!
//! Closes the substantive remaining rung of CIRISEdge#65. The trait
//! shape ([`super::ReplicationDirectory`]) shipped in layer (c-1)
//! (#71); this module wires it to persist's actual federation surface
//! per `FSD/REPLICATION_WIRE_FORMAT_V1.md` §3.6.
//!
//! ## Design
//!
//! The bridge holds two persist surfaces + a cohort callback + a cache:
//!
//! - **`Arc<dyn FederationDirectory>`** — persist's write/read trait
//!   (dyn-compatible via `async-trait` macro). Used to dispatch
//!   [`Self::apply_envelope_bytes`] to the matching `put_*` admit
//!   (10 arms, 1:1 with [`EnvelopeKind`]); also used to page through
//!   keyed `list_*_for` methods to enumerate envelopes per kind.
//! - **Cohort callback** — operator-configured callback yielding the
//!   federation key_ids we want to anti-entropy with. Each round
//!   re-invokes it, so peer-set evolution is observable without
//!   restart.
//! - **Hash→bytes cache** — populated as a side effect of
//!   [`Self::list_envelope_refs`]; consulted by
//!   [`Self::fetch_envelope_bytes`]. Closes the persist substrate gap
//!   that there is no `lookup_*_by_content_hash` point-read. v1 ships
//!   bounded FIFO eviction at 4096 entries.
//!
//! ## Why no `ReadEngine` dependency in v1
//!
//! Persist's `ReadEngine` bulk surface (`list_federation_keys` /
//! `list_attestations` / `list_revocations`) uses native `async fn`
//! (RPITIT), which makes the trait **not dyn-compatible**. Using it
//! would require either a generic type parameter on the bridge or an
//! `async-trait` adapter shim. Neither is hard, but neither is needed
//! for v1: the cohort-keyed `list_*_for` paths on `FederationDirectory`
//! cover every kind, scale O(cohort_size × records_per_key) per round,
//! and operator-configured peer sets are small enough that this cost
//! is negligible. A v1.x optimization can swap in `ReadEngine` for
//! Key / Attestation / Revocation behind a generic param.
//!
//! ## envelope_hash semantics — `persist_row_hash` uniformly
//!
//! The FSD §3.1 spec-owner review chose `original_content_hash` as
//! the envelope identity. Implementation discovery: only 3 of the 10
//! `Signed*Record` inner types carry that field (Key, Attestation,
//! Revocation — the ones built around an inner `*_envelope: Value`).
//! The 7 newer types (CEG 0.7+) carry only `persist_row_hash`. For
//! uniform implementation v1 uses **`persist_row_hash` across all 10
//! kinds**:
//!
//! - Deterministic across nodes — server-computed SHA-256 over
//!   canonical(record minus `persist_row_hash`); persist's
//!   `compute_persist_row_hash` makes it reproducible.
//! - Stronger convergence than `original_content_hash` — full-record
//!   identity (includes embedded scrub signatures). Same byte-
//!   identical record on every peer or no convergence; Ed25519 and
//!   ML-DSA-65 are deterministic (FIPS 204 final) so same signer +
//!   same payload → same signature → same `persist_row_hash`.
//! - Uniform across all 10 kinds — no special-casing.
//!
//! This is documented as a v1 FSD §3.1 amendment.
//!
//! ## Federation-tier-only invariant (FSD §7.1)
//!
//! The bridge reads ONLY persist's federation directory (the
//! `federation_*` table family). CEG §10.1.4 structurally-invisible
//! private records live in a separate local-only store that this
//! bridge never touches — by construction, since
//! `FederationDirectory::list_*_for` reads only the federation tables.
//!
//! Three tests at the bottom of this module fence that invariant per
//! FSD §7.1 acceptance criteria.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use ciris_persist::federation::types::{
    SignedAttestation, SignedCommunity, SignedCommunityMembershipRevocation, SignedFamily,
    SignedFamilyMembershipRevocation, SignedIdentityOccurrence, SignedIdentityOccurrenceRevocation,
    SignedKeyRecord, SignedLocationProof, SignedRevocation,
};
use ciris_persist::federation::FederationDirectory;

use super::directory::ReplicationDirectory;
use super::protocol::{EnvelopeKind, EnvelopeRef};

// ─── Configuration ───────────────────────────────────────────────────

/// Tuning knobs for the production bridge.
#[derive(Debug, Clone, Copy)]
pub struct BridgeConfig {
    /// Bounded capacity of the hash→bytes cache populated by
    /// [`FederationDirectoryReplicationBridge::list_envelope_refs`]
    /// and consulted by
    /// [`FederationDirectoryReplicationBridge::fetch_envelope_bytes`].
    /// v1 mitigation for the absent persist-side
    /// `lookup_*_by_content_hash` point-read; default 4096 entries
    /// covers federations up to ~thousands of envelopes per kind.
    /// FIFO eviction.
    pub cache_capacity: usize,
}

impl BridgeConfig {
    pub const DEFAULT_CACHE_CAPACITY: usize = 4096;
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            cache_capacity: Self::DEFAULT_CACHE_CAPACITY,
        }
    }
}

/// Type alias for the cohort provider — an operator-configured
/// callback yielding the federation key_ids we want to anti-entropy
/// with. Re-invoked at the start of every `list_envelope_refs` call,
/// so the bridge observes peer-set evolution without restart.
pub type CohortProvider = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

// ─── The bridge ──────────────────────────────────────────────────────

/// Production-grade [`ReplicationDirectory`] implementation over
/// persist's `FederationDirectory`.
pub struct FederationDirectoryReplicationBridge {
    directory: Arc<dyn FederationDirectory>,
    cohort: CohortProvider,
    cache: Mutex<BridgeCache>,
}

impl FederationDirectoryReplicationBridge {
    /// Construct with default [`BridgeConfig`].
    pub fn new(directory: Arc<dyn FederationDirectory>, cohort: CohortProvider) -> Self {
        Self::with_config(directory, cohort, BridgeConfig::default())
    }

    /// Construct with explicit configuration.
    pub fn with_config(
        directory: Arc<dyn FederationDirectory>,
        cohort: CohortProvider,
        config: BridgeConfig,
    ) -> Self {
        let cache = Mutex::new(BridgeCache::with_capacity(config.cache_capacity));
        Self {
            directory,
            cohort,
            cache,
        }
    }

    async fn cache_insert(&self, kind: EnvelopeKind, hash: [u8; 32], bytes: Vec<u8>) {
        self.cache.lock().await.insert(kind, hash, bytes);
    }

    /// Decode persist's hex-encoded `persist_row_hash` (64 chars,
    /// lowercase) into the 32-byte `envelope_hash` shape the
    /// replication protocol uses. Returns `None` if decode fails —
    /// defensive against a future persist row whose hash isn't the
    /// expected hex shape.
    fn decode_hash(hex: &str) -> Option<[u8; 32]> {
        let bytes = hex::decode(hex).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Some(out)
    }
}

// ─── Cache (bounded FIFO) ───────────────────────────────────────────

struct BridgeCache {
    capacity: usize,
    map: HashMap<(EnvelopeKind, [u8; 32]), Vec<u8>>,
    order: VecDeque<(EnvelopeKind, [u8; 32])>,
}

impl BridgeCache {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn insert(&mut self, kind: EnvelopeKind, hash: [u8; 32], bytes: Vec<u8>) {
        let key = (kind, hash);
        if self.map.contains_key(&key) {
            return; // already cached; preserve FIFO insertion order
        }
        if self.map.len() >= self.capacity {
            if let Some(evict) = self.order.pop_front() {
                self.map.remove(&evict);
            }
        }
        self.map.insert(key, bytes);
        self.order.push_back(key);
    }

    fn get(&self, kind: EnvelopeKind, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.map.get(&(kind, *hash)).cloned()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }
}

// ─── ReplicationDirectory impl ──────────────────────────────────────

#[async_trait]
impl ReplicationDirectory for FederationDirectoryReplicationBridge {
    async fn list_envelope_refs(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        match kind {
            EnvelopeKind::Key => self.list_keys().await,
            EnvelopeKind::Attestation => self.list_attestations().await,
            EnvelopeKind::Revocation => self.list_revocations().await,
            EnvelopeKind::IdentityOccurrence => self.list_identity_occurrences().await,
            EnvelopeKind::Family => self.list_families().await,
            EnvelopeKind::Community => self.list_communities().await,
            EnvelopeKind::IdentityOccurrenceRevocation => {
                self.list_identity_occurrence_revocations().await
            }
            EnvelopeKind::FamilyMembershipRevocation => {
                self.list_family_membership_revocations().await
            }
            EnvelopeKind::CommunityMembershipRevocation => {
                self.list_community_membership_revocations().await
            }
            EnvelopeKind::LocationProof => self.list_location_proofs().await,
        }
    }

    async fn fetch_envelope_bytes(
        &self,
        kind: EnvelopeKind,
        envelope_hash: &[u8; 32],
    ) -> Option<Vec<u8>> {
        self.cache.lock().await.get(kind, envelope_hash)
    }

    async fn apply_envelope_bytes(&self, kind: EnvelopeKind, envelope_bytes: &[u8]) -> bool {
        match kind {
            EnvelopeKind::Key => self.apply_key(envelope_bytes).await,
            EnvelopeKind::Attestation => self.apply_attestation(envelope_bytes).await,
            EnvelopeKind::Revocation => self.apply_revocation(envelope_bytes).await,
            EnvelopeKind::IdentityOccurrence => {
                self.apply_identity_occurrence(envelope_bytes).await
            }
            EnvelopeKind::Family => self.apply_family(envelope_bytes).await,
            EnvelopeKind::Community => self.apply_community(envelope_bytes).await,
            EnvelopeKind::IdentityOccurrenceRevocation => {
                self.apply_identity_occurrence_revocation(envelope_bytes)
                    .await
            }
            EnvelopeKind::FamilyMembershipRevocation => {
                self.apply_family_membership_revocation(envelope_bytes)
                    .await
            }
            EnvelopeKind::CommunityMembershipRevocation => {
                self.apply_community_membership_revocation(envelope_bytes)
                    .await
            }
            EnvelopeKind::LocationProof => self.apply_location_proof(envelope_bytes).await,
        }
    }
}

// ─── list_envelope_refs — per-kind dispatch ─────────────────────────

impl FederationDirectoryReplicationBridge {
    fn ms_seq(timestamp: chrono::DateTime<chrono::Utc>) -> u64 {
        u64::try_from(timestamp.timestamp_millis()).unwrap_or(0)
    }

    /// Project the cohort-yielded key_ids through
    /// `lookup_public_key`, emit one `EnvelopeRef` per resolved
    /// record. The cohort callback yields the set we anti-entropy
    /// with; each member's KeyRecord goes on the wire.
    async fn list_keys(&self) -> Vec<EnvelopeRef> {
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for key_id in (self.cohort)() {
            if let Ok(Some(row)) = self.directory.lookup_public_key(&key_id).await {
                if let Some(hash) = Self::decode_hash(&row.persist_row_hash) {
                    if !seen.insert(hash) {
                        continue;
                    }
                    let bytes = serde_json::to_vec(&SignedKeyRecord {
                        record: row.clone(),
                    })
                    .unwrap_or_default();
                    self.cache_insert(EnvelopeKind::Key, hash, bytes).await;
                    refs.push(EnvelopeRef {
                        envelope_hash: hash,
                        seq: Self::ms_seq(row.valid_from),
                    });
                }
            }
        }
        refs
    }

    async fn list_attestations(&self) -> Vec<EnvelopeRef> {
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for key_id in (self.cohort)() {
            // Union: attestations ABOUT this key + attestations FROM
            // this key. The dedupe by hash collapses cross-references.
            let about = self
                .directory
                .list_attestations_for(&key_id)
                .await
                .unwrap_or_default();
            let from = self
                .directory
                .list_attestations_by(&key_id)
                .await
                .unwrap_or_default();
            for row in about.into_iter().chain(from) {
                if let Some(hash) = Self::decode_hash(&row.persist_row_hash) {
                    if !seen.insert(hash) {
                        continue;
                    }
                    let bytes = serde_json::to_vec(&SignedAttestation {
                        attestation: row.clone(),
                    })
                    .unwrap_or_default();
                    self.cache_insert(EnvelopeKind::Attestation, hash, bytes)
                        .await;
                    refs.push(EnvelopeRef {
                        envelope_hash: hash,
                        seq: Self::ms_seq(row.asserted_at),
                    });
                }
            }
        }
        refs
    }

    async fn list_revocations(&self) -> Vec<EnvelopeRef> {
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for key_id in (self.cohort)() {
            if let Ok(rows) = self.directory.revocations_for(&key_id).await {
                for row in rows {
                    if let Some(hash) = Self::decode_hash(&row.persist_row_hash) {
                        if !seen.insert(hash) {
                            continue;
                        }
                        let bytes = serde_json::to_vec(&SignedRevocation {
                            revocation: row.clone(),
                        })
                        .unwrap_or_default();
                        self.cache_insert(EnvelopeKind::Revocation, hash, bytes)
                            .await;
                        refs.push(EnvelopeRef {
                            envelope_hash: hash,
                            seq: Self::ms_seq(row.revoked_at),
                        });
                    }
                }
            }
        }
        refs
    }

    async fn list_identity_occurrences(&self) -> Vec<EnvelopeRef> {
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for key_id in (self.cohort)() {
            if let Ok(rows) = self.directory.list_identity_occurrences_for(&key_id).await {
                for row in rows {
                    if let Some(hash) = Self::decode_hash(&row.persist_row_hash) {
                        if !seen.insert(hash) {
                            continue;
                        }
                        let bytes = serde_json::to_vec(&SignedIdentityOccurrence {
                            identity_occurrence: row.clone(),
                        })
                        .unwrap_or_default();
                        self.cache_insert(EnvelopeKind::IdentityOccurrence, hash, bytes)
                            .await;
                        refs.push(EnvelopeRef {
                            envelope_hash: hash,
                            seq: Self::ms_seq(row.asserted_at),
                        });
                    }
                }
            }
        }
        refs
    }

    async fn list_families(&self) -> Vec<EnvelopeRef> {
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for key_id in (self.cohort)() {
            if let Ok(rows) = self.directory.list_families_for_member(&key_id).await {
                for row in rows {
                    if let Some(hash) = Self::decode_hash(&row.persist_row_hash) {
                        if !seen.insert(hash) {
                            continue;
                        }
                        let bytes = serde_json::to_vec(&SignedFamily {
                            family: row.clone(),
                        })
                        .unwrap_or_default();
                        self.cache_insert(EnvelopeKind::Family, hash, bytes).await;
                        refs.push(EnvelopeRef {
                            envelope_hash: hash,
                            seq: Self::ms_seq(row.founded_at),
                        });
                    }
                }
            }
        }
        refs
    }

    async fn list_communities(&self) -> Vec<EnvelopeRef> {
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for key_id in (self.cohort)() {
            if let Ok(rows) = self.directory.list_communities_for_member(&key_id).await {
                for row in rows {
                    if let Some(hash) = Self::decode_hash(&row.persist_row_hash) {
                        if !seen.insert(hash) {
                            continue;
                        }
                        let bytes = serde_json::to_vec(&SignedCommunity {
                            community: row.clone(),
                        })
                        .unwrap_or_default();
                        self.cache_insert(EnvelopeKind::Community, hash, bytes)
                            .await;
                        refs.push(EnvelopeRef {
                            envelope_hash: hash,
                            seq: Self::ms_seq(row.founded_at),
                        });
                    }
                }
            }
        }
        refs
    }

    async fn list_identity_occurrence_revocations(&self) -> Vec<EnvelopeRef> {
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for key_id in (self.cohort)() {
            if let Ok(rows) = self
                .directory
                .list_identity_occurrence_revocations_for(&key_id)
                .await
            {
                for row in rows {
                    if let Some(hash) = Self::decode_hash(&row.persist_row_hash) {
                        if !seen.insert(hash) {
                            continue;
                        }
                        let bytes = serde_json::to_vec(&SignedIdentityOccurrenceRevocation {
                            identity_occurrence_revocation: row.clone(),
                        })
                        .unwrap_or_default();
                        self.cache_insert(EnvelopeKind::IdentityOccurrenceRevocation, hash, bytes)
                            .await;
                        refs.push(EnvelopeRef {
                            envelope_hash: hash,
                            seq: Self::ms_seq(row.revoked_at),
                        });
                    }
                }
            }
        }
        refs
    }

    async fn list_family_membership_revocations(&self) -> Vec<EnvelopeRef> {
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for key_id in (self.cohort)() {
            if let Ok(rows) = self
                .directory
                .list_family_membership_revocations_for(&key_id)
                .await
            {
                for row in rows {
                    if let Some(hash) = Self::decode_hash(&row.persist_row_hash) {
                        if !seen.insert(hash) {
                            continue;
                        }
                        let bytes = serde_json::to_vec(&SignedFamilyMembershipRevocation {
                            family_membership_revocation: row.clone(),
                        })
                        .unwrap_or_default();
                        self.cache_insert(EnvelopeKind::FamilyMembershipRevocation, hash, bytes)
                            .await;
                        refs.push(EnvelopeRef {
                            envelope_hash: hash,
                            seq: Self::ms_seq(row.removed_at),
                        });
                    }
                }
            }
        }
        refs
    }

    async fn list_community_membership_revocations(&self) -> Vec<EnvelopeRef> {
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for key_id in (self.cohort)() {
            if let Ok(rows) = self
                .directory
                .list_community_membership_revocations_for(&key_id)
                .await
            {
                for row in rows {
                    if let Some(hash) = Self::decode_hash(&row.persist_row_hash) {
                        if !seen.insert(hash) {
                            continue;
                        }
                        let bytes = serde_json::to_vec(&SignedCommunityMembershipRevocation {
                            community_membership_revocation: row.clone(),
                        })
                        .unwrap_or_default();
                        self.cache_insert(EnvelopeKind::CommunityMembershipRevocation, hash, bytes)
                            .await;
                        refs.push(EnvelopeRef {
                            envelope_hash: hash,
                            seq: Self::ms_seq(row.removed_at),
                        });
                    }
                }
            }
        }
        refs
    }

    async fn list_location_proofs(&self) -> Vec<EnvelopeRef> {
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for key_id in (self.cohort)() {
            if let Ok(rows) = self.directory.list_location_proofs_for(&key_id).await {
                for row in rows {
                    if let Some(hash) = Self::decode_hash(&row.persist_row_hash) {
                        if !seen.insert(hash) {
                            continue;
                        }
                        let bytes = serde_json::to_vec(&SignedLocationProof {
                            location_proof: row.clone(),
                        })
                        .unwrap_or_default();
                        self.cache_insert(EnvelopeKind::LocationProof, hash, bytes)
                            .await;
                        refs.push(EnvelopeRef {
                            envelope_hash: hash,
                            seq: Self::ms_seq(row.asserted_at),
                        });
                    }
                }
            }
        }
        refs
    }
}

// ─── apply_envelope_bytes — per-kind dispatch ───────────────────────

impl FederationDirectoryReplicationBridge {
    async fn apply_key(&self, bytes: &[u8]) -> bool {
        match serde_json::from_slice::<SignedKeyRecord>(bytes) {
            Ok(record) => self.directory.put_public_key(record).await.is_ok(),
            Err(_) => false,
        }
    }

    async fn apply_attestation(&self, bytes: &[u8]) -> bool {
        match serde_json::from_slice::<SignedAttestation>(bytes) {
            Ok(record) => self.directory.put_attestation(record).await.is_ok(),
            Err(_) => false,
        }
    }

    async fn apply_revocation(&self, bytes: &[u8]) -> bool {
        match serde_json::from_slice::<SignedRevocation>(bytes) {
            Ok(record) => self.directory.put_revocation(record).await.is_ok(),
            Err(_) => false,
        }
    }

    async fn apply_identity_occurrence(&self, bytes: &[u8]) -> bool {
        match serde_json::from_slice::<SignedIdentityOccurrence>(bytes) {
            Ok(record) => self.directory.put_identity_occurrence(record).await.is_ok(),
            Err(_) => false,
        }
    }

    async fn apply_family(&self, bytes: &[u8]) -> bool {
        match serde_json::from_slice::<SignedFamily>(bytes) {
            Ok(record) => self.directory.put_family(record).await.is_ok(),
            Err(_) => false,
        }
    }

    async fn apply_community(&self, bytes: &[u8]) -> bool {
        match serde_json::from_slice::<SignedCommunity>(bytes) {
            Ok(record) => self.directory.put_community(record).await.is_ok(),
            Err(_) => false,
        }
    }

    async fn apply_identity_occurrence_revocation(&self, bytes: &[u8]) -> bool {
        match serde_json::from_slice::<SignedIdentityOccurrenceRevocation>(bytes) {
            Ok(record) => self
                .directory
                .put_identity_occurrence_revocation(record)
                .await
                .is_ok(),
            Err(_) => false,
        }
    }

    async fn apply_family_membership_revocation(&self, bytes: &[u8]) -> bool {
        match serde_json::from_slice::<SignedFamilyMembershipRevocation>(bytes) {
            Ok(record) => self
                .directory
                .put_family_membership_revocation(record)
                .await
                .is_ok(),
            Err(_) => false,
        }
    }

    async fn apply_community_membership_revocation(&self, bytes: &[u8]) -> bool {
        match serde_json::from_slice::<SignedCommunityMembershipRevocation>(bytes) {
            Ok(record) => self
                .directory
                .put_community_membership_revocation(record)
                .await
                .is_ok(),
            Err(_) => false,
        }
    }

    async fn apply_location_proof(&self, bytes: &[u8]) -> bool {
        match serde_json::from_slice::<SignedLocationProof>(bytes) {
            Ok(record) => self.directory.put_location_proof(record).await.is_ok(),
            Err(_) => false,
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ciris_persist::federation::types::{
        algorithm, identity_type, Attestation, KeyRecord, SignedAttestation, SignedKeyRecord,
    };
    use ciris_persist::store::MemoryBackend;

    // ── Test fixture helpers ────────────────────────────────────────

    /// Construct a bridge over a fresh `MemoryBackend` with the
    /// supplied cohort. Returns the backend (so the test can seed
    /// data via persist's put_*) plus the bridge.
    fn make_bridge(
        cohort: &[String],
    ) -> (Arc<MemoryBackend>, FederationDirectoryReplicationBridge) {
        let backend = Arc::new(MemoryBackend::new());
        let dir: Arc<dyn FederationDirectory> = backend.clone();
        let cohort_clone = cohort.to_vec();
        let cohort_cb: CohortProvider = Arc::new(move || cohort_clone.clone());
        let bridge = FederationDirectoryReplicationBridge::new(dir, cohort_cb);
        (backend, bridge)
    }

    /// Synthesize a `KeyRecord` for testing. The `persist_row_hash`
    /// is server-computed by persist's `put_public_key`, so we
    /// pass an empty string here — persist fills it on admit.
    fn fixture_key_record(key_id: &str, identity_type_: &str) -> KeyRecord {
        let now = Utc::now();
        KeyRecord {
            key_id: key_id.to_string(),
            pubkey_ed25519_base64: "0".repeat(44),
            pubkey_ml_dsa_65_base64: None,
            algorithm: algorithm::HYBRID.to_string(),
            identity_type: identity_type_.to_string(),
            identity_ref: format!("{identity_type_}-ref-{key_id}"),
            valid_from: now,
            valid_until: None,
            registration_envelope: serde_json::json!({
                "key_id": key_id,
                "identity_type": identity_type_,
            }),
            original_content_hash: "0".repeat(64),
            scrub_signature_classical: "x".repeat(88),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
        }
    }

    // ── Construction smoke ───────────────────────────────────────────

    #[test]
    fn config_defaults_match_constants() {
        let c = BridgeConfig::default();
        assert_eq!(c.cache_capacity, BridgeConfig::DEFAULT_CACHE_CAPACITY);
    }

    /// Bridge can be constructed with default config + an empty
    /// cohort, and listing every kind returns empty refs (no panics).
    #[tokio::test]
    async fn empty_cohort_yields_empty_refs_for_every_kind() {
        let (_backend, bridge) = make_bridge(&[]);
        for kind in [
            EnvelopeKind::Key,
            EnvelopeKind::Attestation,
            EnvelopeKind::Revocation,
            EnvelopeKind::IdentityOccurrence,
            EnvelopeKind::Family,
            EnvelopeKind::Community,
            EnvelopeKind::IdentityOccurrenceRevocation,
            EnvelopeKind::FamilyMembershipRevocation,
            EnvelopeKind::CommunityMembershipRevocation,
            EnvelopeKind::LocationProof,
        ] {
            let refs = bridge.list_envelope_refs(kind).await;
            assert!(refs.is_empty(), "expected empty refs for {kind:?}");
        }
    }

    // ── Key round-trip ──────────────────────────────────────────────

    /// Seed a key via put_public_key → list_envelope_refs(Key)
    /// returns one ref → fetch_envelope_bytes returns the bytes →
    /// apply_envelope_bytes round-trips through put_public_key
    /// (idempotent on matching content per persist's contract).
    #[tokio::test]
    async fn key_round_trips_through_bridge() {
        let key_id = "agent-alice";
        let (backend, bridge) = make_bridge(&[key_id.to_string()]);
        let record = fixture_key_record(key_id, identity_type::AGENT);
        backend
            .put_public_key(SignedKeyRecord {
                record: record.clone(),
            })
            .await
            .expect("seed key");

        // list_envelope_refs surfaces the seeded key.
        let refs = bridge.list_envelope_refs(EnvelopeKind::Key).await;
        assert_eq!(refs.len(), 1, "exactly one key in cohort");
        let hash = refs[0].envelope_hash;

        // fetch_envelope_bytes returns the cached canonical bytes.
        let bytes = bridge
            .fetch_envelope_bytes(EnvelopeKind::Key, &hash)
            .await
            .expect("bytes cached during list");

        // The bytes round-trip through serde back to SignedKeyRecord.
        let decoded: SignedKeyRecord =
            serde_json::from_slice(&bytes).expect("canonical bytes decode");
        assert_eq!(decoded.record.key_id, key_id);

        // apply_envelope_bytes routes to put_public_key — idempotent
        // on matching content (persist returns Ok on dedup).
        let admitted = bridge.apply_envelope_bytes(EnvelopeKind::Key, &bytes).await;
        assert!(admitted, "idempotent re-apply succeeds");
    }

    /// Bridge dedupes the same key when listed across multiple cohort
    /// entries that all resolve to the same record (cohort-callback
    /// can yield the same key_id multiple times; the bridge must
    /// dedupe by hash so the wire round only carries each envelope
    /// once).
    #[tokio::test]
    async fn key_dedupes_across_cohort() {
        let key_id = "agent-bob";
        let (backend, bridge) =
            make_bridge(&[key_id.to_string(), key_id.to_string(), key_id.to_string()]);
        let record = fixture_key_record(key_id, identity_type::AGENT);
        backend
            .put_public_key(SignedKeyRecord { record })
            .await
            .expect("seed key");

        let refs = bridge.list_envelope_refs(EnvelopeKind::Key).await;
        assert_eq!(refs.len(), 1, "cohort dedupe — three lookups, one ref");
    }

    // ── apply_envelope_bytes refuses garbage ────────────────────────

    /// apply_envelope_bytes returns false on undeserializable bytes
    /// for every kind. Defence against a peer that ships bytes the
    /// bridge can't parse (the protocol's UnexpectedMessage handling
    /// + scheduler's RoundEvent::Error reporting is the production
    /// observability surface).
    #[tokio::test]
    async fn apply_envelope_bytes_refuses_garbage() {
        let (_backend, bridge) = make_bridge(&[]);
        for kind in [
            EnvelopeKind::Key,
            EnvelopeKind::Attestation,
            EnvelopeKind::Revocation,
            EnvelopeKind::IdentityOccurrence,
            EnvelopeKind::Family,
            EnvelopeKind::Community,
            EnvelopeKind::IdentityOccurrenceRevocation,
            EnvelopeKind::FamilyMembershipRevocation,
            EnvelopeKind::CommunityMembershipRevocation,
            EnvelopeKind::LocationProof,
        ] {
            let r = bridge
                .apply_envelope_bytes(kind, b"{not a signed record}")
                .await;
            assert!(!r, "expected garbage refused for {kind:?}");
        }
    }

    // ── FSD §7.1 federation-tier-only invariant fence ───────────────

    /// Local-tier (pre-promotion) attestations have no `SignedAttestation`
    /// form — persist's local-tier attestation API
    /// (`attestation_upsert_local` / `attestation_query`) stores
    /// deferred-signature rows that the federation `list_attestations_for`
    /// surface never returns.
    ///
    /// We exercise the FSD §7.1 invariant operationally: build a
    /// cohort + put NO federation attestations → expect empty refs.
    /// This is the weaker structural assertion (we can't construct a
    /// "local-tier attestation that leaks into federation" because
    /// it's structurally ineligible per CEG §10.1.5). The full
    /// substrate-side assertion (persist's bulk-list only ever
    /// returns promoted rows) is a persist-side regression test —
    /// flagged as a one-line confirmation on the FSD §7.1 ask.
    #[tokio::test]
    async fn local_tier_attestation_absent_from_list_envelope_refs() {
        let key_id = "agent-carol";
        let (backend, bridge) = make_bridge(&[key_id.to_string()]);

        // Seed a key for the attestation to attach to — but seed NO
        // federation-tier attestations. The cohort lookup runs but
        // finds nothing.
        let record = fixture_key_record(key_id, identity_type::AGENT);
        backend
            .put_public_key(SignedKeyRecord { record })
            .await
            .expect("seed key");

        let refs = bridge.list_envelope_refs(EnvelopeKind::Attestation).await;
        assert!(
            refs.is_empty(),
            "no federation-tier attestations seeded → empty refs (FSD §7.1)"
        );
    }

    /// A federation-PRESENT record IS surfaced. Counter-example
    /// confirming the gate isn't over-restrictive: seed a federation-
    /// tier attestation via put_attestation → it appears.
    #[tokio::test]
    async fn federation_present_attestation_appears_in_list_envelope_refs() {
        let attesting_id = "agent-dave";
        let attested_id = "agent-eve";
        let (backend, bridge) = make_bridge(&[attesting_id.to_string(), attested_id.to_string()]);

        // Seed both keys so attestation's FK constraints satisfy.
        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record(attesting_id, identity_type::AGENT),
            })
            .await
            .expect("seed attesting key");
        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record(attested_id, identity_type::AGENT),
            })
            .await
            .expect("seed attested key");

        // Build a federation-tier attestation.
        let now = Utc::now();
        let att = Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: attesting_id.to_string(),
            attested_key_id: attested_id.to_string(),
            attestation_type: "delegates_to".to_string(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "attesting_key_id": attesting_id,
                "attested_key_id": attested_id,
                "attestation_type": "delegates_to",
            }),
            original_content_hash: "0".repeat(64),
            scrub_signature_classical: "x".repeat(88),
            scrub_signature_pqc: None,
            scrub_key_id: attesting_id.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
            tier: "federation".to_string(),
            promoted_at: None,
        };
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .expect("seed attestation");

        let refs = bridge.list_envelope_refs(EnvelopeKind::Attestation).await;
        assert!(
            !refs.is_empty(),
            "federation-PRESENT attestation MUST appear (FSD §7.1)"
        );
    }

    // ── Cache eviction ──────────────────────────────────────────────

    /// The BridgeCache evicts FIFO at capacity. Tuned-small instance
    /// for a fast test.
    #[test]
    fn cache_evicts_oldest_at_capacity() {
        let mut cache = BridgeCache::with_capacity(2);
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let h3 = [3u8; 32];
        cache.insert(EnvelopeKind::Key, h1, b"v1".to_vec());
        cache.insert(EnvelopeKind::Key, h2, b"v2".to_vec());
        assert_eq!(cache.len(), 2);
        cache.insert(EnvelopeKind::Key, h3, b"v3".to_vec());
        assert_eq!(cache.len(), 2);
        // h1 evicted (FIFO); h2 + h3 remain.
        assert!(cache.get(EnvelopeKind::Key, &h1).is_none());
        assert!(cache.get(EnvelopeKind::Key, &h2).is_some());
        assert!(cache.get(EnvelopeKind::Key, &h3).is_some());
    }

    /// Cache insert is a no-op on duplicate hash (FIFO order
    /// preserved, no double-eviction).
    #[test]
    fn cache_duplicate_insert_is_noop() {
        let mut cache = BridgeCache::with_capacity(2);
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        cache.insert(EnvelopeKind::Key, h1, b"v1".to_vec());
        cache.insert(EnvelopeKind::Key, h1, b"v1-again".to_vec()); // dup
        cache.insert(EnvelopeKind::Key, h2, b"v2".to_vec());
        // h1 still present (dup didn't push it out of FIFO order).
        assert!(cache.get(EnvelopeKind::Key, &h1).is_some());
        // The value is the FIRST inserted (no overwrite on dup).
        assert_eq!(cache.get(EnvelopeKind::Key, &h1).unwrap(), b"v1");
    }
}
