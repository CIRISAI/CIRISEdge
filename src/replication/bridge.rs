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

use ciris_persist::federation::namespace::{self, AuthorityClass, Projection, ReplicatedKind};
use ciris_persist::federation::operational::{
    SignedOrgMembership, SignedOrganization, SignedPartnerRecord,
};
use ciris_persist::federation::register::ReplicatedKeyOutcome;
use ciris_persist::federation::self_at_login::TransportDestination;
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
    /// CIRISEdge#311 — the SELF-plane publish set. Collapses the #257
    /// `key_selector` + #305 `occurrence_selector` into ONE provider: both were
    /// the same `Projection::SelfOwn` re-implemented per plane. When `Some`, the
    /// unified engine advertises the node's OWN records for the key_ids THIS
    /// callback yields across every `SelfOwn` kind — `KeyRecord` (#257),
    /// `IdentityOccurrence` (#305, carries the content-tier `encryption_pubkeys`
    /// for KEX), and `TransportDestination` (reachability). `None` preserves the
    /// pre-#257/#305 cohort projection (back-compat). The server supplies the
    /// set (own + anchored); edge only provides the hook — all replication
    /// policy is resolved by persist's `namespace::projection_for`.
    self_provider: Option<CohortProvider>,
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
            self_provider: None,
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
            self_provider: None,
            cache,
            config,
            operational: Some(operational),
        }
    }

    /// CIRISEdge#311 — install the SELF-plane publish set (collapses the #257
    /// `with_key_selector` + #305 `with_occurrence_selector` into one). When
    /// set, the unified engine advertises the key_ids THIS callback yields
    /// across every `Projection::SelfOwn` kind (`KeyRecord`,
    /// `IdentityOccurrence`, `TransportDestination`) — the KERI publish-own
    /// model: the controller publishes its own establishment record + KEX
    /// occurrence + reachability; verifiers pull-and-verify. `None` restores
    /// the pre-#257/#305 cohort projection. The server computes the
    /// own+anchored set (it holds the anchor knowledge); edge only provides the
    /// hook — projection itself is resolved by persist's `projection_for`.
    #[must_use]
    pub fn with_self_provider(mut self, selector: Option<CohortProvider>) -> Self {
        self.self_provider = selector;
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
            // #311 — the five `ReplicatedKind`s ride the unified engine
            // (projection_for + list_signed_records). Key + IdentityOccurrence +
            // TransportDestination project SelfOwn (publish-own); Attestation
            // projects Cohort (about+by preserved); IdentityOccurrenceRevocation
            // is a tombstone → Global (anti-rollback).
            EnvelopeKind::Key => {
                self.list_replicated(EnvelopeKind::Key, ReplicatedKind::KeyRecord)
                    .await
            }
            EnvelopeKind::IdentityOccurrence => {
                self.list_replicated(
                    EnvelopeKind::IdentityOccurrence,
                    ReplicatedKind::IdentityOccurrence,
                )
                .await
            }
            EnvelopeKind::TransportDestination => {
                self.list_replicated(
                    EnvelopeKind::TransportDestination,
                    ReplicatedKind::TransportDestination,
                )
                .await
            }
            EnvelopeKind::IdentityOccurrenceRevocation => {
                self.list_replicated(
                    EnvelopeKind::IdentityOccurrenceRevocation,
                    ReplicatedKind::IdentityOccurrenceRevocation,
                )
                .await
            }
            EnvelopeKind::Attestation => self.list_attestations().await,
            EnvelopeKind::Revocation => self.list_revocations().await,
            EnvelopeKind::Family => self.list_families().await,
            EnvelopeKind::Community => self.list_communities().await,
            EnvelopeKind::Organization => self.list_organizations().await,
            EnvelopeKind::OrgMembership => self.list_org_memberships().await,
            EnvelopeKind::PartnerRecord => self.list_partner_records().await,
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
            EnvelopeKind::TransportDestination => {
                self.apply_transport_destination(envelope_bytes).await
            }
        }
    }
}

// ─── list_envelope_refs — per-kind dispatch ─────────────────────────

impl FederationDirectoryReplicationBridge {
    fn ms_seq(timestamp: chrono::DateTime<chrono::Utc>) -> u64 {
        u64::try_from(timestamp.timestamp_millis()).unwrap_or(0)
    }

    // ─── #311 — the unified replication-policy engine ──────────────────
    //
    // One projection-driven loop replaces `list_keys` (+ #257 key_selector),
    // `list_identity_occurrences` (+ #305 occurrence_selector), and the
    // `list_identity_occurrence_revocations` fan-out. For each
    // `ReplicatedKind`, persist's `projection_for` decides the subject set
    // and `list_signed_records` reads it byte-exact; a per-kind adapter
    // re-wraps the (sometimes bare) canonical JSON back into the existing
    // `Signed*` wire shape so the wire bytes + `persist_row_hash` identity are
    // unchanged for the pre-existing kinds (v9.9↔v9.10 convergence holds).

    /// The projection inputs for a `ReplicatedKind` — `(cohort_scope,
    /// authority, is_tombstone)` fed to persist's [`namespace::projection_for`]
    /// so the policy is resolved by persist, not hard-coded here. The identity
    /// plane (key / occurrence / transport) is `SelfIdentity`-authored `self`
    /// scope → `SelfOwn`; attestations are `ProducerSteward` gossip → `Cohort`;
    /// the occurrence-revocation is a tombstone → `Global` (anti-rollback, the
    /// [`namespace::is_withdraw_or_revocation`] fix).
    fn projection_inputs(kind: ReplicatedKind) -> (&'static str, AuthorityClass, bool) {
        match kind {
            ReplicatedKind::KeyRecord
            | ReplicatedKind::IdentityOccurrence
            | ReplicatedKind::TransportDestination => ("self", AuthorityClass::SelfIdentity, false),
            ReplicatedKind::IdentityOccurrenceRevocation => {
                ("self", AuthorityClass::SelfIdentity, true)
            }
            // `Attestation` (producer gossip → `Cohort`) and — since
            // `ReplicatedKind` is `#[non_exhaustive]` — any future persist kind
            // both default to the conservative `Cohort` relay (never silently
            // SelfOwn or Global) until edge learns to handle them explicitly.
            _ => ("community", AuthorityClass::ProducerSteward, false),
        }
    }

    /// The subject set to sweep for a resolved [`Projection`]. `SelfOwn` uses
    /// the node's OWN publish set ([`Self::self_provider`] — collapsing the #257
    /// and #305 selectors, falling back to the cohort for pre-selector
    /// back-compat); `Cohort` uses the anti-entropy cohort; `Global` uses
    /// own-union-cohort, the widest set the node can enumerate, so a tombstone
    /// is never dropped when its subject exits the cohort (anti-rollback).
    fn subjects_for_projection(&self, projection: Projection) -> Vec<String> {
        match projection {
            Projection::SelfOwn => {
                let set = self.self_provider.as_ref().unwrap_or(&self.cohort);
                set()
            }
            Projection::Cohort => (self.cohort)(),
            Projection::Global => {
                let mut subjects: Vec<String> =
                    self.self_provider.as_ref().map(|p| p()).unwrap_or_default();
                subjects.extend((self.cohort)());
                subjects
            }
        }
    }

    /// Parse an RFC3339 timestamp field out of a record's canonical JSON into
    /// the `ms_seq` monotonic hint. Missing/unparseable is 0 (best-effort; the
    /// `seq` is only a receiver short-circuit, persist's merge is canonical).
    fn ms_seq_from(field: Option<&serde_json::Value>) -> u64 {
        field
            .and_then(serde_json::Value::as_str)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map_or(0, |dt| Self::ms_seq(dt.with_timezone(&chrono::Utc)))
    }

    /// Adapt one `SignedReplicatedRecord`'s `canonical_json` into the tuple the
    /// engine emits: `(wire_bytes, envelope_hash, seq)`. The re-wrap keeps the
    /// wire shape byte-compatible with the pre-#311 per-plane emitters —
    /// `list_signed_records` returns the BARE inner type for key / attestation /
    /// occurrence-revocation (`lookup_public_key` → `KeyRecord`, not
    /// `SignedKeyRecord`), so those are re-nested under their `Signed*` field;
    /// `IdentityOccurrence` is already the signed container; the unsigned
    /// `TransportDestination` carries no `persist_row_hash`, so it hashes over
    /// its JCS canonical bytes like the v2 operational kinds. Returns `None`
    /// (skip this record) if the hash field is absent/malformed.
    fn adapt_record(
        kind: ReplicatedKind,
        canonical_json: &serde_json::Value,
    ) -> Option<(Vec<u8>, [u8; 32], u64)> {
        match kind {
            ReplicatedKind::KeyRecord => {
                let hash = Self::decode_hash(canonical_json.get("persist_row_hash")?.as_str()?)?;
                let seq = Self::ms_seq_from(canonical_json.get("valid_from"));
                let wire = serde_json::json!({ "record": canonical_json });
                Some((serde_json::to_vec(&wire).ok()?, hash, seq))
            }
            ReplicatedKind::IdentityOccurrence => {
                let inner = canonical_json.get("identity_occurrence")?;
                let hash = Self::decode_hash(inner.get("persist_row_hash")?.as_str()?)?;
                let seq = Self::ms_seq_from(inner.get("asserted_at"));
                Some((serde_json::to_vec(canonical_json).ok()?, hash, seq))
            }
            ReplicatedKind::TransportDestination => {
                let hash = v2_envelope_hash(canonical_json)?;
                let seq = Self::ms_seq_from(canonical_json.get("asserted_at"));
                Some((serde_json::to_vec(canonical_json).ok()?, hash, seq))
            }
            ReplicatedKind::Attestation => {
                let hash = Self::decode_hash(canonical_json.get("persist_row_hash")?.as_str()?)?;
                let seq = Self::ms_seq_from(canonical_json.get("asserted_at"));
                let wire = serde_json::json!({ "attestation": canonical_json });
                Some((serde_json::to_vec(&wire).ok()?, hash, seq))
            }
            ReplicatedKind::IdentityOccurrenceRevocation => {
                // CIRISEdge#326 / CIRISPersist#421 (persist v16) — the revocation
                // kind is now the SIGNED CONTAINER (`{identity_occurrence_revocation,
                // attesting_key_id, signed_envelope, signature}`), the same #418
                // discipline as IdentityOccurrence — NOT a bare row. It is
                // re-published BYTE-EXACT: edge holds the transport signer, not
                // the identity key, so it can neither re-sign nor synthesize the
                // signature — only re-wrap what was signed-put. (Pre-v16 this arm
                // re-wrapped a bare row; against v16 that would double-wrap it,
                // AND reading `persist_row_hash` at the top level now misses — it
                // is nested — which would silently drop every revocation from the
                // wire.)
                let inner = canonical_json.get("identity_occurrence_revocation")?;
                let hash = Self::decode_hash(inner.get("persist_row_hash")?.as_str()?)?;
                let seq = Self::ms_seq_from(inner.get("revoked_at"));
                Some((serde_json::to_vec(canonical_json).ok()?, hash, seq))
            }
            // `#[non_exhaustive]` — a kind edge doesn't yet adapt is skipped
            // (not advertised) rather than emitted in an unknown wire shape.
            _ => None,
        }
    }

    /// The engine loop for one `ReplicatedKind`: resolve its projection, sweep
    /// the subject set, `list_signed_records` per subject, then adapt, dedupe,
    /// cache, and emit an `EnvelopeRef` for each. `edge_kind` is the wire
    /// [`EnvelopeKind`] the refs are cached under (1:1 with `kind`).
    async fn list_replicated(
        &self,
        edge_kind: EnvelopeKind,
        kind: ReplicatedKind,
    ) -> Vec<EnvelopeRef> {
        let (scope, authority, is_tombstone) = Self::projection_inputs(kind);
        let projection = namespace::projection_for(scope, authority, is_tombstone);
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for subject in self.subjects_for_projection(projection) {
            let records = self
                .directory
                .list_signed_records(kind, &subject)
                .await
                .unwrap_or_default();
            for rec in records {
                let Some((bytes, hash, seq)) = Self::adapt_record(kind, &rec.canonical_json) else {
                    continue;
                };
                if !seen.insert(hash) {
                    continue;
                }
                self.cache_insert(edge_kind, hash, bytes).await;
                refs.push(EnvelopeRef {
                    envelope_hash: hash,
                    seq,
                });
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
        subjects: Vec<String>,
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
        for key_id in subjects {
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

    /// v10 — resolve ONE attestation's replication policy dynamically from its
    /// actual CEG fields (persist#425), then decide whether THIS node advertises
    /// it. The `scores`/Attestation plane is the one plane whose policy varies
    /// per record: a `dimension` (CC 2.1 — carried inside `attestation_envelope`)
    /// selects the [`namespace::authority_for`] class across all 95 families, the
    /// top-level `cohort_scope` selects the audience, and `attestation_type`
    /// selects tombstone status. `namespace::projection_for` then resolves the
    /// projection, which the list side applies exhaustively:
    ///
    /// - [`Global`](Projection::Global) — always advertise. Trust-root commons
    ///   (`provenance:build_manifest:*` and any future `AccordCoScrub` family at
    ///   a commons scope) reach the whole federation, as do every
    ///   withdraws/recants tombstone (anti-rollback).
    /// - [`Cohort`](Projection::Cohort) — advertise (hold-and-forward relay).
    /// - [`SelfOwn`](Projection::SelfOwn) — advertise **iff THIS node produced
    ///   it** (`attesting_key_id ∈ self_set`). A `self`/`family`-scoped
    ///   attestation is published by its own subject (KERI publish-own), never
    ///   relayed by a third party — the structural-invisibility discipline.
    ///
    /// Unknown/absent dimensions fall to `authority_for`'s `ProducerSteward`
    /// default and unknown scopes to `projection_for`'s `Cohort` negative
    /// default, so every record resolves (no panic, never silently GLOBAL).
    fn attestation_is_advertised(
        canonical_json: &serde_json::Value,
        self_set: &HashSet<String>,
    ) -> bool {
        // CC 2.1: the `dimension` lives inside the attestation envelope; the
        // audience + relation fields are the top-level persist columns.
        let dimension = canonical_json
            .pointer("/attestation_envelope/dimension")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let cohort_scope = canonical_json
            .get("cohort_scope")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let attestation_type = canonical_json
            .get("attestation_type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let authority = namespace::registry::authority_for(dimension).class;
        let is_tombstone = namespace::is_withdraw_or_revocation(attestation_type);
        match namespace::projection_for(cohort_scope, authority, is_tombstone) {
            Projection::Global | Projection::Cohort => true,
            Projection::SelfOwn => canonical_json
                .get("attesting_key_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|producer| self_set.contains(producer)),
        }
    }

    async fn list_attestations(&self) -> Vec<EnvelopeRef> {
        // v10 — per-record dynamic policy for the scores/Attestation plane.
        // Each attestation's projection is resolved from its ACTUAL dimension
        // (across all 95 namespace families), cohort_scope, and attestation_type
        // via [`Self::attestation_is_advertised`], NOT the coarse per-kind
        // default #311 used — so an infra / canonical / build-manifest
        // attestation (`AccordCoScrub` trust root) now reaches the whole
        // federation, a self/family attestation is published-own, and a
        // withdraws tombstone gossips GLOBAL.
        //
        // Sweep the WIDEST subject set (own ∪ cohort) so no record whose
        // per-record projection would include it is missed. `list_signed_records`
        // is about-only, so `list_attestations_by` supplements the by-half
        // (coverage preserved from #311). Both halves ride the same
        // `adapt_record` re-wrap → wire shape + `persist_row_hash` identity match
        // the pre-#311 emitter exactly.
        let self_set: HashSet<String> = self
            .self_provider
            .as_ref()
            .map(|p| p())
            .unwrap_or_default()
            .into_iter()
            .collect();
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for subject in self.subjects_for_projection(Projection::Global) {
            // about — via the uniform signed read (`list_attestations_for`).
            let about = self
                .directory
                .list_signed_records(ReplicatedKind::Attestation, &subject)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|rec| rec.canonical_json);
            // by — supplement so coverage doesn't narrow (bare `Attestation`).
            let by = self
                .directory
                .list_attestations_by(&subject)
                .await
                .unwrap_or_default()
                .into_iter()
                .filter_map(|att| serde_json::to_value(att).ok());
            for canonical_json in about.chain(by) {
                if !Self::attestation_is_advertised(&canonical_json, &self_set) {
                    continue;
                }
                let Some((bytes, hash, seq)) =
                    Self::adapt_record(ReplicatedKind::Attestation, &canonical_json)
                else {
                    continue;
                };
                if !seen.insert(hash) {
                    continue;
                }
                self.cache_insert(EnvelopeKind::Attestation, hash, bytes)
                    .await;
                refs.push(EnvelopeRef {
                    envelope_hash: hash,
                    seq,
                });
            }
        }
        refs
    }

    async fn list_revocations(&self) -> Vec<EnvelopeRef> {
        // #311 tombstone fix — key revocations project `Global` (own ∪ cohort),
        // not cohort-only RELAY, so a revocation is never out-run by the stale
        // record it retracts even after the subject exits the cohort.
        self.fan_out_for_member(
            EnvelopeKind::Revocation,
            self.subjects_for_projection(Projection::Global),
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

    async fn list_families(&self) -> Vec<EnvelopeRef> {
        self.fan_out_for_member(
            EnvelopeKind::Family,
            (self.cohort)(),
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
            (self.cohort)(),
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

    async fn list_family_membership_revocations(&self) -> Vec<EnvelopeRef> {
        // #311 tombstone fix — membership revocation projects `Global`.
        self.fan_out_for_member(
            EnvelopeKind::FamilyMembershipRevocation,
            self.subjects_for_projection(Projection::Global),
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
        // #311 tombstone fix — membership revocation projects `Global`.
        self.fan_out_for_member(
            EnvelopeKind::CommunityMembershipRevocation,
            self.subjects_for_projection(Projection::Global),
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
            (self.cohort)(),
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
        // #277 — route the replicated Key plane through persist's
        // upgrade-aware `apply_replicated_key_record` (CIRISPersist#375,
        // dyn-reachable on `FederationDirectory` since v13.0.1) instead of
        // the `ON CONFLICT DO NOTHING` `put_public_key`. An anchor-scrubbed
        // record now *upgrades* a stale self-signed row over anti-entropy
        // (owner_of-gated, monotonic, fail-closed) rather than being
        // silently dropped — so the KERI publish-own Key plane rides
        // replication end-to-end (retires CIRISServer#150's adopt-scrubbed
        // endpoint once the owner-cohort Key plane lands).
        //
        // `apply_envelope_bytes`'s bool means "admitted a NEW envelope that
        // changed local state" (see `ReplicationDirectory::apply_envelope_bytes`),
        // so only `Inserted`/`Upgraded` count as progress. `Unchanged`
        // (byte-identical duplicate) and `Refused` (not admitted: pubkey
        // swap, downgrade, re-scrub, ambiguous owner, unverifiable sig) are
        // deterministic non-progress ⇒ `false`, matching the duplicate/
        // refused contract and keeping anti-entropy convergence honest.
        match serde_json::from_slice::<SignedKeyRecord>(bytes) {
            Ok(record) => matches!(
                self.directory.apply_replicated_key_record(record).await,
                Ok(ReplicatedKeyOutcome::Inserted | ReplicatedKeyOutcome::Upgraded)
            ),
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

    /// #311 — admit a replicated `TransportDestination` (reachability row).
    /// The wire bytes are the bare (unsigned) `TransportDestination` the engine
    /// emitted; `put_transport_destination` is idempotent/last-writer per V078
    /// (a stale address is dropped + re-registered, never signed or revoked).
    async fn apply_transport_destination(&self, bytes: &[u8]) -> bool {
        match serde_json::from_slice::<TransportDestination>(bytes) {
            Ok(dest) => self
                .directory
                .put_transport_destination(&dest)
                .await
                .is_ok(),
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
            additional_scrubs: Vec::new(),
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
            EnvelopeKind::TransportDestination,
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

        // apply_envelope_bytes routes the Key plane through
        // apply_replicated_key_record (#277). On MemoryBackend (the trait
        // default) a matching-content apply is a first-seen Ok ⇒ Inserted
        // ⇒ admitted; the Unchanged/Refused ⇒ false distinction only
        // surfaces on the scrub-upgrade-aware SqliteBackend (persist owns
        // that classification test).
        let admitted = bridge.apply_envelope_bytes(EnvelopeKind::Key, &bytes).await;
        assert!(admitted, "matching-content apply admits on MemoryBackend");
    }

    /// CIRISEdge#257 — the Key-plane selector publishes the node's OWN
    /// record + a third-party anchored record even though neither is in the
    /// node's consent cohort (KERI publish-own). Without the selector,
    /// `list_keys` projects the cohort and would never carry them — the
    /// mesh-seed blocker (a verifier can't root a key it never received).
    #[tokio::test]
    async fn self_provider_publishes_own_and_anchored_not_cohort() {
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

        // Install the SELF publish set {own, anchored}: publish-own. #311 — one
        // `self_provider` drives every SelfOwn kind (here: Key) via the engine.
        let publish_set = vec![own_key.to_string(), anchored.to_string()];
        let selector: CohortProvider = Arc::new(move || publish_set.clone());
        let bridge = bridge.with_self_provider(Some(selector));
        let refs = bridge.list_envelope_refs(EnvelopeKind::Key).await;
        assert_eq!(
            refs.len(),
            2,
            "self_provider advertises the node's own + the anchored record, not the cohort"
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
            EnvelopeKind::TransportDestination,
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

    // ── #311 — the unified engine's policy mapping + wire-shape re-wrap ──

    /// Each `ReplicatedKind`'s `projection_inputs` resolve (via persist's
    /// `projection_for`) to the projection the concept assigns: the identity
    /// plane publishes-own, attestations relay over the cohort, and the
    /// occurrence-revocation tombstone gossips GLOBAL (anti-rollback — the fix
    /// for the RELAY mis-projection).
    #[test]
    fn projection_inputs_resolve_to_expected_projections() {
        type B = FederationDirectoryReplicationBridge;
        for k in [
            ReplicatedKind::KeyRecord,
            ReplicatedKind::IdentityOccurrence,
            ReplicatedKind::TransportDestination,
        ] {
            let (s, a, t) = B::projection_inputs(k);
            assert_eq!(
                namespace::projection_for(s, a, t),
                Projection::SelfOwn,
                "{k:?} → SelfOwn (publish-own)"
            );
        }
        let (s, a, t) = B::projection_inputs(ReplicatedKind::Attestation);
        assert_eq!(namespace::projection_for(s, a, t), Projection::Cohort);
        let (s, a, t) = B::projection_inputs(ReplicatedKind::IdentityOccurrenceRevocation);
        assert!(t, "occurrence-revocation is a tombstone");
        assert_eq!(
            namespace::projection_for(s, a, t),
            Projection::Global,
            "tombstone → Global (anti-rollback, never out-run by the stale record)"
        );
    }

    /// The engine re-wraps the BARE `KeyRecord` that `list_signed_records`
    /// returns back into the `SignedKeyRecord` (`{"record": …}`) wire shape,
    /// and keeps `persist_row_hash` as the envelope identity — so the wire
    /// bytes deserialize on the receiver's `apply_key` and the hash is
    /// unchanged vs the pre-#311 emitter (v9.9↔v9.10 convergence holds).
    #[test]
    fn adapt_record_key_rewraps_to_signed_shape_keeping_hash() {
        let prh = "ab".repeat(32); // 64 hex chars → 32 bytes
        let bare = serde_json::json!({
            "key_id": "k1",
            "persist_row_hash": prh,
            "valid_from": "2026-07-11T00:00:00Z",
        });
        let (bytes, hash, _seq) =
            FederationDirectoryReplicationBridge::adapt_record(ReplicatedKind::KeyRecord, &bare)
                .expect("adapt bare KeyRecord");
        // Re-nested under "record" — deserializes as SignedKeyRecord.
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("wire json");
        assert_eq!(v["record"]["key_id"], "k1", "re-wrapped to SignedKeyRecord");
        // Wire identity == decoded persist_row_hash (stable across versions).
        assert_eq!(hex::encode(hash), prh, "hash stays persist_row_hash");
    }

    /// CIRISEdge#326 / CIRISPersist#421 (persist v16) — the revocation kind is a
    /// SIGNED CONTAINER, re-published byte-exact (edge can't re-sign). Fences the
    /// SILENT break: pre-v16 this arm read `persist_row_hash` at the top level
    /// and re-wrapped a bare row; against v16's container that lookup misses, so
    /// `adapt_record` would return `None` and every revocation would vanish from
    /// the wire with no compile error (the engine speaks `serde_json::Value`).
    #[test]
    fn adapt_record_revocation_is_the_signed_container_republished_byte_exact() {
        let prh = "cd".repeat(32); // 64 hex chars → 32 bytes
        let container = serde_json::json!({
            "identity_occurrence_revocation": {
                "occurrence_key_id": "occ-1",
                "persist_row_hash": prh,
                "revoked_at": "2026-07-12T00:00:00Z",
            },
            "attesting_key_id": "signer-1",
            "signed_envelope": { "kind": "identity_occurrence_revocation" },
            "signature": "sig-b64",
        });
        let (bytes, hash, _seq) = FederationDirectoryReplicationBridge::adapt_record(
            ReplicatedKind::IdentityOccurrenceRevocation,
            &container,
        )
        .expect("adapt signed revocation container");

        // Emitted BYTE-EXACT — the signature container survives (not double-wrapped).
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("wire json");
        assert_eq!(v["signature"], "sig-b64", "signature preserved");
        assert_eq!(v["attesting_key_id"], "signer-1");
        assert!(
            v.get("identity_occurrence_revocation")
                .and_then(|r| r.get("identity_occurrence_revocation"))
                .is_none(),
            "must NOT be double-wrapped"
        );
        // Hash read from the NESTED row, not the top level.
        assert_eq!(hex::encode(hash), prh);
    }

    // ── v10 — per-record dynamic policy for the scores/Attestation plane ──

    type Bridge = FederationDirectoryReplicationBridge;

    /// Build an attestation `canonical_json` with the fields the resolver reads:
    /// `dimension` inside `attestation_envelope` (CC 2.1), the rest top-level.
    fn att_json(
        dimension: &str,
        cohort_scope: &str,
        attestation_type: &str,
        attesting_key_id: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "attesting_key_id": attesting_key_id,
            "attestation_type": attestation_type,
            "cohort_scope": cohort_scope,
            "attestation_envelope": { "dimension": dimension },
        })
    }

    fn set_of(keys: &[&str]) -> HashSet<String> {
        keys.iter().map(|s| (*s).to_string()).collect()
    }

    /// A trust-root (`provenance:build_manifest:*` → `AccordCoScrub`) attestation
    /// at a commons scope reaches the WHOLE federation — advertised even though
    /// this node didn't produce it. This is the v10 fix: infra / canonical /
    /// build-manifest attestations were stuck at coarse `Cohort` before.
    #[test]
    fn attestation_trust_root_commons_is_global_advertised() {
        let a = att_json(
            "provenance:build_manifest:linux-x86_64",
            "federation",
            "scores",
            "some-builder",
        );
        assert!(
            Bridge::attestation_is_advertised(&a, &HashSet::new()),
            "trust-root build-manifest attestation reaches the whole federation regardless of producer"
        );
    }

    /// A `self`-scoped attestation is publish-own: advertised iff THIS node
    /// produced it, never relayed by a third party.
    #[test]
    fn attestation_self_scoped_advertised_only_when_produced_here() {
        let a = att_json("trust:reliability:v1", "self", "scores", "node-own");
        assert!(
            Bridge::attestation_is_advertised(&a, &set_of(&["node-own"])),
            "self-scoped: advertised when THIS node produced it (publish-own)"
        );
        assert!(
            !Bridge::attestation_is_advertised(&a, &set_of(&["someone-else"])),
            "self-scoped: NOT relayed by a third party"
        );
    }

    /// A `community`-scoped attestation relays over the cohort — advertised
    /// regardless of the self set.
    #[test]
    fn attestation_community_scoped_relays_over_cohort() {
        let a = att_json("trust:reliability:v1", "community", "scores", "peer");
        assert!(Bridge::attestation_is_advertised(&a, &HashSet::new()));
    }

    /// A `withdraws` tombstone gossips GLOBAL (anti-rollback) even at `self`
    /// scope and even if this node didn't produce it — a revocation can never be
    /// out-run by the stale record it retracts.
    #[test]
    fn attestation_withdraws_is_tombstone_global() {
        let a = att_json("trust:reliability:v1", "self", "withdraws", "peer");
        assert!(
            Bridge::attestation_is_advertised(&a, &HashSet::new()),
            "withdraws tombstone → Global regardless of scope/producer"
        );
    }

    /// Every one of the 95 families resolves — an unknown or absent dimension
    /// falls to `authority_for`'s `ProducerSteward` default and an unknown scope
    /// to `projection_for`'s `Cohort` negative default (never a panic, never
    /// silently Global/SelfOwn).
    #[test]
    fn attestation_unknown_or_absent_dimension_defaults_to_cohort() {
        let unknown = att_json("totally:unknown:prefix", "community", "scores", "peer");
        assert!(Bridge::attestation_is_advertised(&unknown, &HashSet::new()));
        // Dimension absent entirely (e.g. a `delegates_to` relation).
        let absent = serde_json::json!({
            "attesting_key_id": "peer",
            "attestation_type": "delegates_to",
            "cohort_scope": "community",
        });
        assert!(
            Bridge::attestation_is_advertised(&absent, &HashSet::new()),
            "absent dimension still resolves (no panic)"
        );
    }

    /// The resolver DISCRIMINATES — a non-trust-root producer's commons-scoped
    /// attestation relays over the cohort (advertised), but the same producer's
    /// `self`-scoped attestation is filtered when this node didn't make it. Only
    /// a trust-root authority promotes a commons scope to Global.
    #[test]
    fn attestation_resolver_discriminates_by_authority_and_scope() {
        let commons = att_json("trust:reliability:v1", "federation", "scores", "peer");
        assert!(
            Bridge::attestation_is_advertised(&commons, &HashSet::new()),
            "non-trust-root federation scope relays over cohort"
        );
        let self_scoped = att_json("trust:reliability:v1", "self", "scores", "peer");
        assert!(
            !Bridge::attestation_is_advertised(&self_scoped, &HashSet::new()),
            "self-scoped from a non-producer is filtered — resolver is not blanket-advertising"
        );
    }

    /// **Exhaustiveness proof** — EVERY family in persist's vendored namespace
    /// registry (all `VENDORED_N_FAMILIES`) resolves a projection through the
    /// resolver at every `cohort_scope`, with no panic. This is what "all the
    /// namespaces replicate" means concretely: replication policy is defined for
    /// the ENTIRE namespace, not a hand-picked subset.
    #[test]
    fn every_registry_family_resolves_a_projection() {
        let scopes = [
            "self",
            "family",
            "community",
            "affiliations",
            "species",
            "biosphere",
            "federation",
            "", // absent/unknown scope → Cohort negative default
        ];
        let families = namespace::registry::entries();
        assert_eq!(
            families.len(),
            namespace::registry::VENDORED_N_FAMILIES,
            "resolver covers the full vendored family set"
        );
        for entry in families {
            for scope in scopes {
                // Must resolve (no panic) for both a live score and a tombstone.
                let scored = att_json(&entry.prefix, scope, "scores", "peer");
                let tombstone = att_json(&entry.prefix, scope, "withdraws", "peer");
                let _ = Bridge::attestation_is_advertised(&scored, &HashSet::new());
                assert!(
                    Bridge::attestation_is_advertised(&tombstone, &HashSet::new()),
                    "every family's withdraws tombstone gossips Global ({})",
                    entry.prefix
                );
            }
        }
    }
}
