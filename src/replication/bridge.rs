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

use ciris_persist::federation::operational::{
    SignedOrgMembership, SignedOrganization, SignedPartnerRecord,
};
use ciris_persist::federation::types::{
    SignedAttestation, SignedCommunity, SignedCommunityMembershipRevocation, SignedFamily,
    SignedFamilyMembershipRevocation, SignedIdentityOccurrence, SignedIdentityOccurrenceRevocation,
    SignedKeyRecord, SignedLocationProof, SignedRevocation,
};
use ciris_persist::federation::FederationDirectory;
use ciris_verify_core::threshold::ThresholdMember;

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
    /// Page size for the v2 operational kinds' bulk-list sweep
    /// (`list_organizations_since` / `list_org_memberships_since` /
    /// `list_partner_records_since`). v2.0.0 ships unlimited single-page
    /// (`u32::MAX`) by default — federations of operational records are
    /// O(orgs × partners), far below the wire MTU concern that motivated
    /// pagination. Operators with very large operational rosters tune
    /// this downward and accept multiple round trips per round.
    pub operational_page_limit: u32,
}

impl BridgeConfig {
    pub const DEFAULT_CACHE_CAPACITY: usize = 4096;
    /// Default for [`Self::operational_page_limit`].
    pub const DEFAULT_OPERATIONAL_PAGE_LIMIT: u32 = u32::MAX;
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            cache_capacity: Self::DEFAULT_CACHE_CAPACITY,
            operational_page_limit: Self::DEFAULT_OPERATIONAL_PAGE_LIMIT,
        }
    }
}

/// Type alias for the cohort provider — an operator-configured
/// callback yielding the federation key_ids we want to anti-entropy
/// with. Re-invoked at the start of every `list_envelope_refs` call,
/// so the bridge observes peer-set evolution without restart.
pub type CohortProvider = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

/// Type alias for the v2 key-directory provider — an operator-configured
/// callback yielding the current federation key_directory
/// (`Vec<ThresholdMember>`). Re-invoked on each operational admit so
/// admission sees the live directory. Used by persist's
/// `put_organization` / `put_org_membership` admit surfaces for the
/// single-signer role-chain authority check (Verify v5.1.0's
/// `resolve_role_authority`). When `None`, the bridge refuses to admit
/// operational-kind envelopes (returns `false` from `apply_*`) —
/// fail-closed.
pub type KeyDirectoryProvider = Arc<dyn Fn() -> Vec<ThresholdMember> + Send + Sync>;

/// Type alias for the v2 root-stewards provider — an operator-configured
/// callback yielding the federation's bootstrap steward `member_id`s.
/// Used by persist's `put_organization` / `put_org_membership` admit
/// surfaces to anchor the role-chain at trust root (the founder set
/// per CEG §9.1). When `None`, the bridge refuses to admit operational-
/// kind envelopes — fail-closed.
pub type RootStewardsProvider = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

/// Type alias for the v2 steward-roster provider — an operator-configured
/// callback yielding the current federation steward roster
/// (`Vec<ThresholdMember>`). Used by persist's `put_partner_record`
/// admit surface for the M-of-N steward quorum verification. When
/// `None`, the bridge refuses to admit `partner_record` envelopes —
/// fail-closed.
pub type StewardRosterProvider = Arc<dyn Fn() -> Vec<ThresholdMember> + Send + Sync>;

/// v2 (CEG 1.0-RC2 §5.6.8.13 / FSD §5.2) — operational-data admission
/// providers bundle. Operators set this at bridge construction time to
/// enable v2 operational-kind admission; leaving it `None` keeps the
/// bridge v1-only (operational `apply_*` returns `false`, gracefully
/// declining to admit).
#[derive(Clone)]
pub struct OperationalProviders {
    /// The federation key_directory — `Vec<ThresholdMember>`. See
    /// [`KeyDirectoryProvider`].
    pub key_directory: KeyDirectoryProvider,
    /// The federation bootstrap stewards' `member_id`s. See
    /// [`RootStewardsProvider`].
    pub root_stewards: RootStewardsProvider,
    /// The federation steward roster — `Vec<ThresholdMember>`. See
    /// [`StewardRosterProvider`].
    pub steward_roster: StewardRosterProvider,
}

// ─── The bridge ──────────────────────────────────────────────────────

/// Production-grade [`ReplicationDirectory`] implementation over
/// persist's `FederationDirectory`.
pub struct FederationDirectoryReplicationBridge {
    directory: Arc<dyn FederationDirectory>,
    cohort: CohortProvider,
    /// CIRISEdge#257 — the Key-plane publish-set selector. When `Some`,
    /// [`Self::list_keys`] projects THIS set (the node's OWN record + held
    /// rooting-relevant / anchored records) instead of the `cohort`. A
    /// node is never in its own consent cohort, so without this it would
    /// never advertise its own scrub-signed key record and no verifier
    /// could ever root it — the mesh-seed blocker. `None` preserves the
    /// pre-#257 cohort-members'-own projection (back-compat). The server
    /// supplies the selector (own + anchored) via
    /// [`Self::with_key_selector`]; edge only provides the hook (all
    /// replication logic lives in edge — the engine does not hard-code
    /// the Key-plane projection).
    key_selector: Option<CohortProvider>,
    cache: Mutex<BridgeCache>,
    config: BridgeConfig,
    /// v2 operational-data admission providers. `None` = v2 admission
    /// fail-closed; operational kinds' `apply_*` returns `false` without
    /// touching persist. Set via [`Self::with_operational`] or
    /// [`Self::with_config_and_operational`].
    operational: Option<OperationalProviders>,
}

impl FederationDirectoryReplicationBridge {
    /// Construct with default [`BridgeConfig`], **v1-only** (no v2
    /// operational-kind admission). For v2 operational admission, use
    /// [`Self::with_operational`].
    pub fn new(directory: Arc<dyn FederationDirectory>, cohort: CohortProvider) -> Self {
        Self::with_config(directory, cohort, BridgeConfig::default())
    }

    /// Construct with explicit configuration, **v1-only**.
    pub fn with_config(
        directory: Arc<dyn FederationDirectory>,
        cohort: CohortProvider,
        config: BridgeConfig,
    ) -> Self {
        let cache = Mutex::new(BridgeCache::with_capacity(config.cache_capacity));
        Self {
            directory,
            cohort,
            key_selector: None,
            cache,
            config,
            operational: None,
        }
    }

    /// Construct with default [`BridgeConfig`] **+ v2 operational
    /// admission enabled**. The operational providers (key_directory /
    /// root_stewards / steward_roster) are required for the bridge to
    /// admit `organization` / `org_membership` / `partner_record`
    /// envelopes; without them, the operational-kind `apply_*` returns
    /// `false` (fail-closed; v1 kinds remain unaffected).
    pub fn with_operational(
        directory: Arc<dyn FederationDirectory>,
        cohort: CohortProvider,
        operational: OperationalProviders,
    ) -> Self {
        Self::with_config_and_operational(directory, cohort, BridgeConfig::default(), operational)
    }

    /// Construct with explicit configuration **+ v2 operational
    /// admission enabled**.
    pub fn with_config_and_operational(
        directory: Arc<dyn FederationDirectory>,
        cohort: CohortProvider,
        config: BridgeConfig,
        operational: OperationalProviders,
    ) -> Self {
        let cache = Mutex::new(BridgeCache::with_capacity(config.cache_capacity));
        Self {
            directory,
            cohort,
            key_selector: None,
            cache,
            config,
            operational: Some(operational),
        }
    }

    /// CIRISEdge#257 — install the Key-plane publish-set selector. When
    /// set, [`Self::list_keys`] advertises the key_ids THIS callback yields
    /// (the node's OWN record + held anchored records) rather than the
    /// cohort's members'-own. `None` restores the cohort projection. The
    /// server computes the own+anchored set (it holds the anchor knowledge);
    /// edge just projects it through `lookup_public_key` — the KERI
    /// publish-own model (the controller publishes its own establishment
    /// record; verifiers pull-and-verify).
    #[must_use]
    pub fn with_key_selector(mut self, selector: Option<CohortProvider>) -> Self {
        self.key_selector = selector;
        self
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
            EnvelopeKind::Organization => self.list_organizations().await,
            EnvelopeKind::OrgMembership => self.list_org_memberships().await,
            EnvelopeKind::PartnerRecord => self.list_partner_records().await,
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
            EnvelopeKind::Organization => self.apply_organization(envelope_bytes).await,
            EnvelopeKind::OrgMembership => self.apply_org_membership(envelope_bytes).await,
            EnvelopeKind::PartnerRecord => self.apply_partner_record(envelope_bytes).await,
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

    /// Project the Key-plane publish set through `lookup_public_key`, emit
    /// one `EnvelopeRef` per resolved record. The set is the
    /// [`Self::key_selector`] (CIRISEdge#257 — the node's OWN record + held
    /// anchored records, KERI publish-own) when installed, else the
    /// `cohort` (pre-#257 cohort-members'-own). The projection is identical
    /// either way; only the set of key_ids differs.
    async fn list_keys(&self) -> Vec<EnvelopeRef> {
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let publish_set = self.key_selector.as_ref().unwrap_or(&self.cohort);
        for key_id in publish_set() {
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

    // ─── v6.2.0 (#179, CIRISPersist#249 Cut D) — generic cohort fan-out ──
    //
    // The 9 per-kind blocks below collapsed into a single
    // [`Self::fan_out_for_member`] combinator + 9 call sites. The
    // structural pattern is uniform across kinds (cohort iterate → per-key
    // `list_*_for` → `persist_row_hash` decode → HashSet dedupe → wrap in
    // `Signed*` → cache + emit `EnvelopeRef`); only the per-row
    // projections (timestamp accessor, hash accessor) and the wrapper
    // differ. Persist v9.3.0 keeps the `list_*_for_member` surface
    // uniform across kinds, so one parameterized combinator replaces the
    // hand-unrolled cases without changing wire-format behavior.
    //
    // `Row`-generic by inference: the closures fix the row type per call
    // site without requiring dyn-compatibility on the directory trait.
    // Async via boxed future on the per-key fetch (the directory trait is
    // already `async_trait`-boxed).
    async fn fan_out_for_member<Row, Signed, FetchFut, F, W, H>(
        &self,
        kind: EnvelopeKind,
        mut fetch: F,
        wrap: W,
        timestamp: impl Fn(&Row) -> chrono::DateTime<chrono::Utc>,
        hash: H,
    ) -> Vec<EnvelopeRef>
    where
        F: FnMut(String) -> FetchFut,
        FetchFut: std::future::Future<Output = Vec<Row>>,
        W: Fn(&Row) -> Signed,
        Signed: serde::Serialize,
        H: Fn(&Row) -> &str,
    {
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for key_id in (self.cohort)() {
            let rows = fetch(key_id).await;
            for row in rows {
                let Some(envelope_hash) = Self::decode_hash(hash(&row)) else {
                    continue;
                };
                if !seen.insert(envelope_hash) {
                    continue;
                }
                let signed = wrap(&row);
                let bytes = serde_json::to_vec(&signed).unwrap_or_default();
                self.cache_insert(kind, envelope_hash, bytes).await;
                refs.push(EnvelopeRef {
                    envelope_hash,
                    seq: Self::ms_seq(timestamp(&row)),
                });
            }
        }
        refs
    }

    async fn list_attestations(&self) -> Vec<EnvelopeRef> {
        // Union: attestations ABOUT this key + attestations FROM this key.
        // The dedupe by hash collapses cross-references. This is the only
        // kind whose per-key list is the chain of two `list_*` reads;
        // every other kind hits one `list_*_for` surface.
        self.fan_out_for_member(
            EnvelopeKind::Attestation,
            |key_id| async move {
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
                about.into_iter().chain(from).collect()
            },
            |row| SignedAttestation {
                attestation: row.clone(),
            },
            |row| row.asserted_at,
            |row| row.persist_row_hash.as_str(),
        )
        .await
    }

    async fn list_revocations(&self) -> Vec<EnvelopeRef> {
        self.fan_out_for_member(
            EnvelopeKind::Revocation,
            |key_id| async move {
                self.directory
                    .revocations_for(&key_id)
                    .await
                    .unwrap_or_default()
            },
            |row| SignedRevocation {
                revocation: row.clone(),
            },
            |row| row.revoked_at,
            |row| row.persist_row_hash.as_str(),
        )
        .await
    }

    async fn list_identity_occurrences(&self) -> Vec<EnvelopeRef> {
        self.fan_out_for_member(
            EnvelopeKind::IdentityOccurrence,
            |key_id| async move {
                self.directory
                    .list_identity_occurrences_for(&key_id)
                    .await
                    .unwrap_or_default()
            },
            |row| SignedIdentityOccurrence {
                identity_occurrence: row.clone(),
            },
            |row| row.asserted_at,
            |row| row.persist_row_hash.as_str(),
        )
        .await
    }

    async fn list_families(&self) -> Vec<EnvelopeRef> {
        self.fan_out_for_member(
            EnvelopeKind::Family,
            |key_id| async move {
                self.directory
                    .list_families_for_member(&key_id)
                    .await
                    .unwrap_or_default()
            },
            |row| SignedFamily {
                family: row.clone(),
            },
            |row| row.founded_at,
            |row| row.persist_row_hash.as_str(),
        )
        .await
    }

    async fn list_communities(&self) -> Vec<EnvelopeRef> {
        self.fan_out_for_member(
            EnvelopeKind::Community,
            |key_id| async move {
                self.directory
                    .list_communities_for_member(&key_id)
                    .await
                    .unwrap_or_default()
            },
            |row| SignedCommunity {
                community: row.clone(),
            },
            |row| row.founded_at,
            |row| row.persist_row_hash.as_str(),
        )
        .await
    }

    async fn list_identity_occurrence_revocations(&self) -> Vec<EnvelopeRef> {
        self.fan_out_for_member(
            EnvelopeKind::IdentityOccurrenceRevocation,
            |key_id| async move {
                self.directory
                    .list_identity_occurrence_revocations_for(&key_id)
                    .await
                    .unwrap_or_default()
            },
            |row| SignedIdentityOccurrenceRevocation {
                identity_occurrence_revocation: row.clone(),
            },
            |row| row.revoked_at,
            |row| row.persist_row_hash.as_str(),
        )
        .await
    }

    async fn list_family_membership_revocations(&self) -> Vec<EnvelopeRef> {
        self.fan_out_for_member(
            EnvelopeKind::FamilyMembershipRevocation,
            |key_id| async move {
                self.directory
                    .list_family_membership_revocations_for(&key_id)
                    .await
                    .unwrap_or_default()
            },
            |row| SignedFamilyMembershipRevocation {
                family_membership_revocation: row.clone(),
            },
            |row| row.removed_at,
            |row| row.persist_row_hash.as_str(),
        )
        .await
    }

    async fn list_community_membership_revocations(&self) -> Vec<EnvelopeRef> {
        self.fan_out_for_member(
            EnvelopeKind::CommunityMembershipRevocation,
            |key_id| async move {
                self.directory
                    .list_community_membership_revocations_for(&key_id)
                    .await
                    .unwrap_or_default()
            },
            |row| SignedCommunityMembershipRevocation {
                community_membership_revocation: row.clone(),
            },
            |row| row.removed_at,
            |row| row.persist_row_hash.as_str(),
        )
        .await
    }

    async fn list_location_proofs(&self) -> Vec<EnvelopeRef> {
        self.fan_out_for_member(
            EnvelopeKind::LocationProof,
            |key_id| async move {
                self.directory
                    .list_location_proofs_for(&key_id)
                    .await
                    .unwrap_or_default()
            },
            |row| SignedLocationProof {
                location_proof: row.clone(),
            },
            |row| row.asserted_at,
            |row| row.persist_row_hash.as_str(),
        )
        .await
    }

    // ── v2 operational-data list_* ─────────────────────────────────
    //
    // v2 operational kinds enumerate via persist's
    // `list_organizations_since` / `list_org_memberships_since` /
    // `list_signed_partner_records_since` (cursor + limit; CIRISPersist
    // v5.1.0 shipped the first two and v5.2.0 / #194 shipped the third
    // explicitly "for CIRISEdge#65 v2 bidirectional partner_record"
    // — closes the v2.0.0 admit-only carve-out). Each row's wire
    // `envelope_hash` is `sha256(JCS(Signed*Record))` per FSD §3.2.2 —
    // JCS-conformant, edge-defined, reproducible by any non-persist
    // CEG implementer (the §3.2.1 deferred-interop fix).
    //
    // The page limit is operator-tunable via [`BridgeConfig::operational_page_limit`];
    // default `u32::MAX` covers federations whose operational rosters
    // (orgs × memberships × licenses) fit in a single page.
    //
    // Skipping with `continue` on a row whose JCS hash can't be computed
    // is safe: the row exists in persist but won't be advertised on the
    // wire this round; the next round retries. Logging that skip is a
    // v2.0.x follow-up (matches the v1 trust-kinds' silent-skip on
    // decode_hash failure).

    async fn list_organizations(&self) -> Vec<EnvelopeRef> {
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let limit = self.config.operational_page_limit;
        if let Ok(rows) = self.directory.list_organizations_since(None, limit).await {
            for row in rows {
                let signed = SignedOrganization {
                    organization: row.clone(),
                };
                let Some(hash) = v2_envelope_hash(&signed) else {
                    continue;
                };
                if !seen.insert(hash) {
                    continue;
                }
                let bytes = serde_json::to_vec(&signed).unwrap_or_default();
                self.cache_insert(EnvelopeKind::Organization, hash, bytes)
                    .await;
                refs.push(EnvelopeRef {
                    envelope_hash: hash,
                    seq: Self::ms_seq(row.asserted_at),
                });
            }
        }
        refs
    }

    async fn list_org_memberships(&self) -> Vec<EnvelopeRef> {
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let limit = self.config.operational_page_limit;
        if let Ok(rows) = self.directory.list_org_memberships_since(None, limit).await {
            for row in rows {
                let signed = SignedOrgMembership {
                    org_membership: row.clone(),
                };
                let Some(hash) = v2_envelope_hash(&signed) else {
                    continue;
                };
                if !seen.insert(hash) {
                    continue;
                }
                let bytes = serde_json::to_vec(&signed).unwrap_or_default();
                self.cache_insert(EnvelopeKind::OrgMembership, hash, bytes)
                    .await;
                refs.push(EnvelopeRef {
                    envelope_hash: hash,
                    seq: Self::ms_seq(row.asserted_at),
                });
            }
        }
        refs
    }

    async fn list_partner_records(&self) -> Vec<EnvelopeRef> {
        // v2.0.1 — `partner_record` is now **bidirectional**.
        //
        // CIRISPersist v5.2.0 (CIRISPersist#194) shipped the
        // `list_signed_partner_records_since` surface that returns the
        // full `SignedPartnerRecord` wrapper — row + steward_signatures
        // + threshold — straight from persist's V072 storage. That
        // closes the admit-only carve-out v2.0.0 documented: edge can
        // now enumerate locally-held partner_records with a JCS hash
        // that reproduces on every peer, completing the anti-entropy
        // convergence loop for this kind.
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let limit = self.config.operational_page_limit;
        if let Ok(signed_rows) = self
            .directory
            .list_signed_partner_records_since(None, limit)
            .await
        {
            for signed in signed_rows {
                let Some(hash) = v2_envelope_hash(&signed) else {
                    continue;
                };
                if !seen.insert(hash) {
                    continue;
                }
                let asserted_at = signed.partner_record.asserted_at;
                let bytes = serde_json::to_vec(&signed).unwrap_or_default();
                self.cache_insert(EnvelopeKind::PartnerRecord, hash, bytes)
                    .await;
                refs.push(EnvelopeRef {
                    envelope_hash: hash,
                    seq: Self::ms_seq(asserted_at),
                });
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

    // ── v2 operational-data apply_* ────────────────────────────────
    //
    // The 3 v2 operational kinds (CEG 1.0-RC2 §5.6.8.13) gate on the
    // [`OperationalProviders`] callbacks being set at bridge
    // construction. Without them, admission fail-closes (returns
    // `false`); persist is not touched. With them, the bridge resolves
    // the live `key_directory` / `root_stewards` / `steward_roster` via
    // the operator-supplied closures and passes them to persist's
    // `put_*` admit surface. Persist + verify perform the 4-check
    // admission pipeline (skew-bound, no-payment-processor identifiers,
    // authority, set-semantics) — edge stays agnostic per the FSD §5.2
    // commitment "merge policy stays persist-side per §10.1.6 declared
    // intents."

    async fn apply_organization(&self, bytes: &[u8]) -> bool {
        let Some(ops) = self.operational.as_ref() else {
            return false;
        };
        let Ok(signed) = serde_json::from_slice::<SignedOrganization>(bytes) else {
            return false;
        };
        let key_directory = (ops.key_directory)();
        let root_stewards = (ops.root_stewards)();
        self.directory
            .put_organization(signed, key_directory.as_slice(), root_stewards.as_slice())
            .await
            .is_ok()
    }

    async fn apply_org_membership(&self, bytes: &[u8]) -> bool {
        let Some(ops) = self.operational.as_ref() else {
            return false;
        };
        let Ok(signed) = serde_json::from_slice::<SignedOrgMembership>(bytes) else {
            return false;
        };
        let key_directory = (ops.key_directory)();
        let root_stewards = (ops.root_stewards)();
        self.directory
            .put_org_membership(signed, key_directory.as_slice(), root_stewards.as_slice())
            .await
            .is_ok()
    }

    async fn apply_partner_record(&self, bytes: &[u8]) -> bool {
        let Some(ops) = self.operational.as_ref() else {
            return false;
        };
        let Ok(signed) = serde_json::from_slice::<SignedPartnerRecord>(bytes) else {
            return false;
        };
        let steward_roster = (ops.steward_roster)();
        self.directory
            .put_partner_record(signed, steward_roster.as_slice())
            .await
            .is_ok()
    }
}

// ─── v2 envelope_hash basis — JCS (FSD §3.2.2) ──────────────────────
//
// v2 closes the §3.2.1 deferred-interop path: operational-kind
// `envelope_hash` is `sha256(JCS(Signed*Record))`, edge-defined +
// CEG-§0.9-conformant. This is the SAME computation any non-persist
// CEG implementation can reproduce — no `persist_row_hash` dependency.
//
// The function lives at module scope rather than as a method so the
// `list_organizations` / `list_org_memberships` / `list_partner_records`
// sweeps can call it without borrowing `self`.

/// Compute the v2 envelope_hash for a serde-`Serialize`-able value.
/// Per FSD §3.2.2: `sha256(JCS(value))`. Edge calls
/// [`ciris_verify_core::jcs::canonicalize`] for the JCS step — the
/// canonical-bytes encoding is not edge's to define (FSD §3.2). Returns
/// `None` if either step fails (serialization → JSON Value, JCS
/// canonicalization); the caller skips the envelope rather than emit a
/// non-reproducible hash.
fn v2_envelope_hash<T: serde::Serialize>(value: &T) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let json_value = serde_json::to_value(value).ok()?;
    let canonical = ciris_verify_core::jcs::canonicalize(&json_value).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    Some(hasher.finalize().into())
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use chrono::Utc;
    use ciris_crypto::{ClassicalSigner as _, Ed25519Signer, MlDsa65Signer, PqcSigner as _};
    use ciris_persist::federation::types::{
        algorithm, identity_type, Attestation, KeyRecord, SignedAttestation, SignedKeyRecord,
    };
    use ciris_persist::store::MemoryBackend;
    use sha2::{Digest as _, Sha256};

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

    // ── v6.3.2 (CIRISEdge#166) — real hybrid PQC fixture sigs ───────
    //
    // Mirrors persist's `federation::tier_ingest::test_support` shape
    // (pub(crate) over there). Deterministic per-key_id keypair plus
    // the same V2Jcs (RFC 8785) canonicalizer persist's
    // `ceg_produce_canonicalize` wraps — edge depends on
    // ciris-verify-core directly so the canonical bytes match without
    // persist exposing the helper.

    /// Deterministic 32-byte seed for `key_id`.
    fn seed_for(key_id: &str) -> [u8; 32] {
        let mut seed = [0x11u8; 32];
        for (i, b) in key_id.bytes().take(32).enumerate() {
            seed[i] = b;
        }
        seed
    }

    /// `key_id`'s registered hybrid pubkeys, base64.
    fn hybrid_pubkeys(key_id: &str) -> (String, Option<String>) {
        let ed = Ed25519Signer::from_seed(&seed_for(key_id)).expect("ed seed");
        let mldsa = Box::new(MlDsa65Signer::from_seed(&seed_for(key_id)).expect("mldsa seed"));
        let ed_pk = B64.encode(ed.public_key().expect("ed pk"));
        let mldsa_pk = B64.encode(mldsa.public_key().expect("mldsa pk"));
        (ed_pk, Some(mldsa_pk))
    }

    /// Hybrid-sign `envelope` with `signing_key_id`'s deterministic
    /// keys; returns `(original_content_hash, ed_sig_b64,
    /// Some(mldsa_sig_b64))`. PQC half signs the bound payload
    /// (canonical || ed_sig).
    fn sign_attestation_envelope(
        signing_key_id: &str,
        envelope: &serde_json::Value,
    ) -> (String, String, Option<String>) {
        let ed = Ed25519Signer::from_seed(&seed_for(signing_key_id)).expect("ed seed");
        let mldsa =
            Box::new(MlDsa65Signer::from_seed(&seed_for(signing_key_id)).expect("mldsa seed"));
        let canonical = ciris_verify_core::jcs::canonicalize(envelope).expect("jcs canonicalize");
        let original_content_hash = hex::encode(Sha256::digest(&canonical));
        let ed_sig = ed.sign(&canonical).expect("ed sign");
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = mldsa.sign(&bound).expect("mldsa sign");
        (
            original_content_hash,
            B64.encode(&ed_sig),
            Some(B64.encode(&pqc_sig)),
        )
    }

    /// Synthesize a `KeyRecord` for testing. The `persist_row_hash`
    /// is server-computed by persist's `put_public_key`, so we
    /// pass an empty string here — persist fills it on admit.
    ///
    /// v6.3.2: pubkeys now derived from `hybrid_pubkeys(key_id)` so
    /// federation-tier attestations signed by this key verify under
    /// persist v9.0.0's `verify_federation_tier_ingest`. Scrub
    /// fields stay placeholders — `put_public_key` does NOT
    /// hybrid-verify the registration row.
    fn fixture_key_record(key_id: &str, identity_type_: &str) -> KeyRecord {
        let now = Utc::now();
        let (ed_pk, mldsa_pk) = hybrid_pubkeys(key_id);
        KeyRecord {
            key_id: key_id.to_string(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
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
            consent_role: None,
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

    /// CIRISEdge#257 — the Key-plane selector publishes the node's OWN
    /// record + a third-party anchored record even though neither is in the
    /// node's consent cohort (KERI publish-own). Without the selector,
    /// `list_keys` projects the cohort and would never carry them — the
    /// mesh-seed blocker (a verifier can't root a key it never received).
    #[tokio::test]
    async fn key_selector_publishes_own_and_anchored_not_cohort() {
        let cohort_member = "peer-in-cohort";
        let own_key = "this-node-own";
        let anchored = "third-party-anchored";

        // Cohort contains ONLY the peer — never own / anchored (a node is
        // not in its own consent cohort).
        let (backend, bridge) = make_bridge(&[cohort_member.to_string()]);
        for k in [cohort_member, own_key, anchored] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(k, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }

        // Pre-#257 projection: the cohort → only the cohort member's own.
        let cohort_refs = bridge.list_envelope_refs(EnvelopeKind::Key).await;
        assert_eq!(
            cohort_refs.len(),
            1,
            "cohort projection advertises only cohort members' own"
        );

        // Install the Key-plane publish set {own, anchored}: publish-own.
        let publish_set = vec![own_key.to_string(), anchored.to_string()];
        let selector: CohortProvider = Arc::new(move || publish_set.clone());
        let bridge = bridge.with_key_selector(Some(selector));
        let refs = bridge.list_envelope_refs(EnvelopeKind::Key).await;
        assert_eq!(
            refs.len(),
            2,
            "selector advertises the node's own + the anchored record, not the cohort"
        );
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

        // Build a federation-tier attestation with real hybrid sigs
        // (v6.3.2 / CIRISEdge#166 — passes persist v9.0.0's
        // verify_federation_tier_ingest).
        let now = Utc::now();
        let envelope = serde_json::json!({
            "attesting_key_id": attesting_id,
            "attested_key_id": attested_id,
            "attestation_type": "delegates_to",
        });
        let (hash, ed_sig, pqc_sig) = sign_attestation_envelope(attesting_id, &envelope);
        let att = Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: attesting_id.to_string(),
            attested_key_id: attested_id.to_string(),
            attestation_type: "delegates_to".to_string(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: hash,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
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

    // ── v2 operational-data (FSD §5.2 / CEG 1.0-RC2 §5.6.8.13) ──────

    /// JCS envelope_hash is deterministic: hashing the same serializable
    /// value twice yields identical bytes. The federation invariant —
    /// peer A and peer B both compute the same `envelope_hash` from the
    /// same on-wire bytes — depends on this.
    #[test]
    fn v2_envelope_hash_is_deterministic() {
        let value = serde_json::json!({
            "organization": {
                "attestation_id": "att-1",
                "org_id": "org-acme",
                "name": "ACME",
                "status": "active",
            }
        });
        let h1 = v2_envelope_hash(&value).expect("hash 1");
        let h2 = v2_envelope_hash(&value).expect("hash 2");
        assert_eq!(h1, h2);
    }

    /// JCS canonicalization sorts keys lexicographically — different
    /// key ordering in the input value produces identical canonical
    /// bytes and thus identical hashes. This is what makes M-of-N
    /// steward quorum admission converge per RC2 §5.6.8.13 (the
    /// Verify-raised "byte-identical JCS" catch).
    #[test]
    fn v2_envelope_hash_is_key_order_invariant() {
        let a = serde_json::json!({
            "alpha": 1,
            "beta": 2,
            "gamma": 3,
        });
        let b = serde_json::json!({
            "gamma": 3,
            "alpha": 1,
            "beta": 2,
        });
        let ha = v2_envelope_hash(&a).expect("hash a");
        let hb = v2_envelope_hash(&b).expect("hash b");
        assert_eq!(
            ha, hb,
            "JCS sorts keys — same logical object MUST hash identically"
        );
    }

    /// JCS canonicalization distinguishes different values — two
    /// envelopes with different content MUST hash to different bytes.
    /// Sanity check that v2_envelope_hash isn't degenerate.
    #[test]
    fn v2_envelope_hash_differentiates_distinct_values() {
        let a = serde_json::json!({"org_id": "alice"});
        let b = serde_json::json!({"org_id": "bob"});
        let ha = v2_envelope_hash(&a).expect("hash a");
        let hb = v2_envelope_hash(&b).expect("hash b");
        assert_ne!(ha, hb);
    }

    /// Without `OperationalProviders` configured, `apply_organization`
    /// fail-closes (returns `false`) — v2 admission requires the
    /// operator to wire up `key_directory` + `root_stewards`. Verifies
    /// the v1-bridge constructors don't accidentally admit v2 envelopes.
    #[tokio::test]
    async fn apply_organization_fail_closes_without_operational_providers() {
        let (_backend, bridge) = make_bridge(&["k1".into()]);
        // Bridge constructed via `new` (no operational providers).
        // Even if the bytes happen to deserialize cleanly, admission
        // must refuse.
        let bytes = br#"{"organization": {
            "attestation_id": "att-1",
            "org_id": "org-acme",
            "name": "ACME",
            "org_type": "internal",
            "status": "active",
            "asserted_at": "2026-06-10T20:00:00Z",
            "attesting_key_id": "k1",
            "signed_envelope": {},
            "ed25519_signature_base64": ""
        }}"#;
        let admitted = bridge
            .apply_envelope_bytes(EnvelopeKind::Organization, bytes)
            .await;
        assert!(
            !admitted,
            "v2 operational admission MUST fail-close without OperationalProviders"
        );
    }

    /// Same fail-closed invariant for `org_membership`.
    #[tokio::test]
    async fn apply_org_membership_fail_closes_without_operational_providers() {
        let (_backend, bridge) = make_bridge(&["k1".into()]);
        let bytes = br#"{"org_membership": {
            "attestation_id": "att-1",
            "user_id": "u1",
            "org_id": "org-acme",
            "role": "viewer",
            "status": "active",
            "asserted_at": "2026-06-10T20:00:00Z",
            "attesting_key_id": "k1",
            "signed_envelope": {},
            "ed25519_signature_base64": ""
        }}"#;
        let admitted = bridge
            .apply_envelope_bytes(EnvelopeKind::OrgMembership, bytes)
            .await;
        assert!(!admitted);
    }

    /// Same fail-closed invariant for `partner_record`.
    #[tokio::test]
    async fn apply_partner_record_fail_closes_without_operational_providers() {
        let (_backend, bridge) = make_bridge(&["k1".into()]);
        let bytes = br#"{
            "partner_record": {
                "attestation_id":"att-1","license_id":"lic-1","partner_id":"p-1","org_id":"org-1",
                "license_type":"community","max_autonomy_tier":"A0","requires_supervisor":false,
                "deployment_limit":1,"offline_grace_hours":24,"status":"active","revision":1,
                "issued_at":"2026-06-10T20:00:00Z","expires_at":"2027-06-10T20:00:00Z",
                "asserted_at":"2026-06-10T20:00:00Z","signed_envelope":{}
            },
            "steward_signatures": [],
            "threshold": 0
        }"#;
        let admitted = bridge
            .apply_envelope_bytes(EnvelopeKind::PartnerRecord, bytes)
            .await;
        assert!(!admitted);
    }

    /// v2.0.1 — bidirectional `partner_record` replication lights up.
    /// Persist v5.2.0's `list_signed_partner_records_since` returns the
    /// full `SignedPartnerRecord` wrapper with `steward_signatures`
    /// inline (CIRISPersist#194 / V072), so a peer-cached envelope
    /// re-emits as the same bytes the original sender hashed. Tests
    /// against an empty backend (no rows) confirms the no-rows path
    /// returns an empty ref set without panic. The deeper convergence
    /// (sender's hash = receiver's hash from peer's
    /// `list_signed_partner_records_since` output) is fenced by the
    /// JCS-determinism + key-order-invariance tests above + persist's
    /// own V072 cohabitation convergence_roundtrip test.
    #[tokio::test]
    async fn v2_list_partner_records_handles_empty_backend() {
        let (_backend, bridge) = make_bridge(&[]);
        let refs = bridge.list_envelope_refs(EnvelopeKind::PartnerRecord).await;
        assert!(
            refs.is_empty(),
            "empty backend yields empty ref set (no panics, no errors)"
        );
    }
}
