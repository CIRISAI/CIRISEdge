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
//! - **Hash→bytes cache** — bounded FIFO (4096 entries). Since
//!   CIRISEdge#397 it is populated + consulted ONLY for the `Revocation`
//!   plane (the one kind persist does not index); every other plane's
//!   fetch is the content-hash point-read below.
//!
//! ## envelope_hash semantics — content-hash (CIRISEdge#397)
//!
//! The envelope identity is each row's **content-hash**:
//! `sha256(serde_json::to_vec(row))` ([`content_hash_of`]), byte-exact
//! with persist's `wire_index::content_hash_of`. The `row` is whatever
//! element type the corresponding `list_signed_*_since` /
//! `list_attestations_since` bulk read returns (the `Signed*` wrapper for
//! most planes; the BARE `Attestation` / `Organization` / `OrgMembership`
//! for the three persist indexes bare). Because persist's
//! `signed_wire_index` keys `(kind, content_hash)` on the SAME bytes and
//! its `lookup_signed_record_by_content_hash` point-read reloads +
//! re-serializes that same row, the advertised hash equals `sha256` of the
//! served bytes equals the point-read key — end to end, by construction.
//!
//! This retires the pre-#397 `persist_row_hash` / JCS `v2_envelope_hash`
//! bases and the per-subject `list_*_for` fan-out: each plane now reads ONE
//! bulk since-cursor page per round.
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

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use super::resolved_state::{ResolvedPeerSet, ResolvedRecipient};
use ciris_persist::federation::admission::has_effective_role;
use ciris_persist::federation::consent_grammar::{self, ConsentTransferPolicy};
use ciris_persist::federation::namespace::{self, Projection};
use ciris_persist::federation::operational::{
    OrgMembership, Organization, SignedOrgMembership, SignedOrganization, SignedPartnerRecord,
};
use ciris_persist::federation::register::ReplicatedKeyOutcome;
use ciris_persist::federation::trust_root::capability_roots_to_trusted_root;
use ciris_persist::federation::types::delegation_scope;
use ciris_persist::federation::types::{
    Attestation, SignedAttestation, SignedCommunity, SignedCommunityMembershipRevocation,
    SignedFamily, SignedFamilyMembershipRevocation, SignedIdentityOccurrence,
    SignedIdentityOccurrenceRevocation, SignedKeyRecord, SignedLocationProof, SignedRevocation,
};
use ciris_persist::federation::FederationDirectory;
use ciris_verify_core::threshold::ThresholdMember;

use super::directory::ReplicationDirectory;
use super::protocol::{EnvelopeKind, EnvelopeRef};

// ─── Configuration ───────────────────────────────────────────────────

/// Tuning knobs for the production bridge.
#[derive(Debug, Clone, Copy)]
pub struct BridgeConfig {
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
    /// Default for [`Self::operational_page_limit`].
    pub const DEFAULT_OPERATIONAL_PAGE_LIMIT: u32 = u32::MAX;
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
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
    config: BridgeConfig,
    /// v2 operational-data admission providers. `None` = v2 admission
    /// fail-closed; operational kinds' `apply_*` returns `false` without
    /// touching persist. Set via [`Self::with_operational`] or
    /// [`Self::with_config_and_operational`].
    operational: Option<OperationalProviders>,
    /// CIRISEdge#386 — this node's OWN federation key_id: the `user` half of
    /// the trust-root walk ("does the recipient's capability root to a root
    /// *I* trust?"). `None` fail-closes the trace serve gate — without a local
    /// identity there is no "I" whose trust could be evaluated. Supplied by
    /// `ReplicationRuntimeConfig::local_key_id`.
    local_key_id: Option<String>,
    /// CIRISEdge#400 — memoized consent send-set (`list_consent_peers(local)`),
    /// with the [`Instant`] it was resolved. The item-1 fan-out bound must
    /// re-resolve *per round* but NOT *per envelope*: v14.2.0 called
    /// `resolve_attestation_recipient` inside `fetch_envelope_bytes_for_peer`,
    /// so an N-envelope Deliver did N `list_consent_peers` reads inside the
    /// unbounded reply assembly and blew the 10 s round budget (100% round
    /// timeouts). This memo collapses a round's advertise + N fetches to ONE
    /// read; the [`CONSENT_SEND_SET_MEMO_TTL`] window sits under the anti-entropy
    /// cadence so a between-round withdraw still takes effect next round.
    consent_memo: Mutex<Option<(ResolvedPeerSet, Instant)>>,
}

/// CIRISEdge#400 — how long a memoized consent send-set stays fresh. Chosen to
/// span one anti-entropy round's assembly steps (advertise → Diff → Deliver,
/// bounded by the scheduler's 10 s round budget) while staying well under the
/// default 30 s cadence, so the item-1 bound still re-resolves every round.
const CONSENT_SEND_SET_MEMO_TTL: Duration = Duration::from_secs(10);

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
        Self {
            directory,
            cohort,
            self_provider: None,
            local_key_id: None,
            config,
            operational: None,
            consent_memo: Mutex::new(None),
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
        Self {
            directory,
            cohort,
            self_provider: None,
            local_key_id: None,
            config,
            operational: Some(operational),
            consent_memo: Mutex::new(None),
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

    /// CIRISEdge#386 — bind this node's own federation key_id (builder). The
    /// `user` half of the trust-root walk that gates `trace:*` serving; without
    /// it the gate fail-closes and logs a WARN, since a missing local identity
    /// is a wiring fault rather than a policy decision.
    #[must_use]
    pub fn with_local_key_id(mut self, local_key_id: Option<String>) -> Self {
        self.local_key_id = local_key_id;
        self
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

// ─── ReplicationDirectory impl ──────────────────────────────────────

#[async_trait]
impl ReplicationDirectory for FederationDirectoryReplicationBridge {
    async fn list_envelope_refs(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        match kind {
            // CIRISEdge#397 §1+§2 — the five primary signed planes advertise
            // via persist v21.2.0's bulk since-cursor reads, hashing each row by
            // its content-hash (`sha256(serde_json::to_vec(row))`) so the wire
            // hash == the point-read key. Key + IdentityOccurrence +
            // TransportDestination project SelfOwn (publish-own); Attestation is
            // per-record (`attestation_is_advertised`); IdentityOccurrenceRevocation
            // is a tombstone → Global (anti-rollback).
            EnvelopeKind::Key => self.list_keys().await,
            EnvelopeKind::IdentityOccurrence => self.list_identity_occurrences().await,
            EnvelopeKind::TransportDestination => self.list_transport_destinations().await,
            EnvelopeKind::IdentityOccurrenceRevocation => {
                self.list_identity_occurrence_revocations().await
            }
            EnvelopeKind::Attestation => self.list_attestations(None).await,
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
        // CIRISEdge#397 §3 — the content-hash point-read. Every indexed kind
        // (all 13 except `Revocation`) resolves its bytes from persist's
        // `signed_wire_index` keyed on `(kind, content_hash)`. Because edge
        // advertised `sha256(serde_json::to_vec(row))` and persist reloads +
        // re-serializes that SAME row, the returned bytes hash back to
        // `envelope_hash` by construction.
        if let Some(k) = kind.persist_index_kind() {
            return self
                .directory
                .lookup_signed_record_by_content_hash(k, &hex::encode(envelope_hash))
                .await
                .ok()
                .flatten();
        }
        // CIRISEdge#396 item 3 — `Revocation` is the ONE kind persist does not
        // content-hash-index; it rides the `persist_row_hash` wire. Resolve it
        // with NO cache: this retires the last in-memory fetch cache, so every
        // plane's fetch is now a direct persist read.
        if kind == EnvelopeKind::Revocation {
            return self.fetch_revocation_bytes(envelope_hash).await;
        }
        None
    }

    /// CIRISEdge#379 — recipient-aware listing: the Attestation plane routes
    /// through the `infra:serve`-gated sweep; every other kind is peer-invariant.
    async fn list_envelope_refs_for_peer(
        &self,
        kind: EnvelopeKind,
        peer_key_id: Option<&str>,
    ) -> Vec<EnvelopeRef> {
        match (kind, peer_key_id) {
            (EnvelopeKind::Attestation, Some(peer)) => self.list_attestations(Some(peer)).await,
            _ => self.list_envelope_refs(kind).await,
        }
    }

    /// CIRISEdge#379 — recipient-aware fetch: the serve-side twin of the
    /// listing gate, so a peer excluded from the listing cannot obtain a
    /// `trace:*` envelope anyway by Diff/Fetch-ing a hash it learned
    /// out-of-band.
    async fn fetch_envelope_bytes_for_peer(
        &self,
        kind: EnvelopeKind,
        envelope_hash: &[u8; 32],
        peer_key_id: Option<&str>,
    ) -> Option<Vec<u8>> {
        let bytes = self.fetch_envelope_bytes(kind, envelope_hash).await?;
        if kind == EnvelopeKind::Attestation {
            if let Some(peer) = peer_key_id {
                // CIRISEdge#396 item 1 — the same consent-membership bound the
                // listing applies, so a peer excluded from the advertise cannot
                // obtain an attestation by fetching a hash it learned
                // out-of-band. Fail-closed: no `ResolvedRecipient`, no bytes.
                let recipient = self.resolve_attestation_recipient(peer).await?;
                // #379 `infra:serve` + #396 item 6 `recipient_capability`, over
                // the WIRE bytes — the direct-fetch twins of the listing gates,
                // so the fetch path narrows exactly as the advertise path did.
                // The wire is the BARE `Attestation` (§3); tolerate the legacy
                // `{"attestation": …}` wrap for a peer still on the old wire.
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    let inner = value.get("attestation").unwrap_or(&value);
                    if Self::attestation_requires_serve(inner)
                        && !self.peer_has_serve_capability(recipient.as_str()).await
                    {
                        tracing::debug!(
                            peer,
                            envelope_hash = %hex::encode(&envelope_hash[..8]),
                            "trace attestation withheld — recipient lacks an effective \
                             `infra:serve` capability (CIRISEdge#379)"
                        );
                        return None;
                    }
                    if self
                        .recipient_capability_withholds(
                            inner,
                            recipient.as_str(),
                            &mut HashMap::new(),
                        )
                        .await
                    {
                        return None;
                    }
                }
            }
        }
        Some(bytes)
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

    // ─── CIRISEdge#397 §1+§2 — the primary-plane since-cursor engine ───────
    //
    // Each of the 5 primary signed planes (Key / IdentityOccurrence /
    // TransportDestination / IdentityOccurrenceRevocation / Attestation) reads
    // ONE bulk `list_signed_<kind>_since(None, limit)` page per round (retiring
    // the per-subject `list_signed_records` fan-out), filters in-memory to its
    // projection subject set — the EXACT scoping the pre-#397 fan-out applied
    // (Key/IdOcc/TransportDest = SelfOwn; IdOccRevocation = Global; Attestation
    // per-record via `attestation_is_advertised`) — and advertises each row by
    // its content-hash (`sha256(serde_json::to_vec(row))`, [`content_hash_of`]),
    // which persist's `signed_wire_index` keys on, so the wire hash IS the
    // point-read key. These planes no longer cache (the point-read is the fetch).

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

    /// CIRISEdge#397 §1+§2 — advertise a bulk since-cursor page: keep the rows
    /// `in_scope` (the plane's projection subject filter), advertise each by its
    /// content-hash ([`content_hash_of`] — `sha256(serde_json::to_vec(row))`,
    /// the exact value persist's `signed_wire_index` keys on), and dedupe by
    /// hash. No caching — [`Self::fetch_envelope_bytes`]'s point-read is the
    /// serve path for every plane but `Revocation`.
    fn advertise_since<S, IN, TS>(rows: &[S], in_scope: IN, seq_of: TS) -> Vec<EnvelopeRef>
    where
        S: serde::Serialize,
        IN: Fn(&S) -> bool,
        TS: Fn(&S) -> u64,
    {
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for row in rows.iter().filter(|r| in_scope(r)) {
            let Some((hash, _bytes)) = content_hash_of(row) else {
                continue;
            };
            if !seen.insert(hash) {
                continue;
            }
            refs.push(EnvelopeRef {
                envelope_hash: hash,
                seq: seq_of(row),
            });
        }
        refs
    }

    /// Key plane — `SelfOwn` (publish-own): the node's OWN establishment
    /// records. Scope filter is the `SelfOwn` publish set; seq is `valid_from`.
    async fn list_keys(&self) -> Vec<EnvelopeRef> {
        let subjects: HashSet<String> = self
            .subjects_for_projection(Projection::SelfOwn)
            .into_iter()
            .collect();
        let rows = self
            .directory
            .list_signed_key_records_since(None, self.config.operational_page_limit)
            .await
            .unwrap_or_default();
        Self::advertise_since(
            &rows,
            |row| subjects.contains(&row.record.key_id),
            |row| Self::ms_seq(row.record.valid_from),
        )
    }

    /// IdentityOccurrence plane — `SelfOwn` (publish-own): the node's OWN KEX
    /// occurrences. Scope filter is the `SelfOwn` publish set (keyed by the
    /// occurrence key_id); seq is `asserted_at`.
    async fn list_identity_occurrences(&self) -> Vec<EnvelopeRef> {
        let subjects: HashSet<String> = self
            .subjects_for_projection(Projection::SelfOwn)
            .into_iter()
            .collect();
        let rows = self
            .directory
            .list_signed_identity_occurrences_since(None, self.config.operational_page_limit)
            .await
            .unwrap_or_default();
        Self::advertise_since(
            &rows,
            |row| subjects.contains(&row.identity_occurrence.occurrence_key_id),
            |row| Self::ms_seq(row.identity_occurrence.asserted_at),
        )
    }

    /// TransportDestination plane — `SelfOwn` (publish-own): the node's OWN
    /// reachability routes. Scope filter is the `SelfOwn` publish set (keyed by
    /// the occurrence key_id); seq is the durable supersession `epoch`
    /// (CIRISPersist#443), falling back to `asserted_at` for a pre-#443
    /// producer whose projection reads epoch 0.
    async fn list_transport_destinations(&self) -> Vec<EnvelopeRef> {
        let subjects: HashSet<String> = self
            .subjects_for_projection(Projection::SelfOwn)
            .into_iter()
            .collect();
        let rows = self
            .directory
            .list_signed_transport_destinations_since(None, self.config.operational_page_limit)
            .await
            .unwrap_or_default();
        Self::advertise_since(
            &rows,
            |row| subjects.contains(&row.transport_destination.occurrence_key_id),
            |row| {
                if row.transport_destination.epoch > 0 {
                    row.transport_destination.epoch
                } else {
                    Self::ms_seq(row.transport_destination.asserted_at)
                }
            },
        )
    }

    /// IdentityOccurrenceRevocation plane — tombstone → `Global` (anti-rollback,
    /// never out-run by the stale occurrence it retracts). Scope filter is the
    /// widest own∪cohort set (keyed by the occurrence key_id); seq is
    /// `revoked_at`.
    async fn list_identity_occurrence_revocations(&self) -> Vec<EnvelopeRef> {
        let subjects: HashSet<String> = self
            .subjects_for_projection(Projection::Global)
            .into_iter()
            .collect();
        let rows = self
            .directory
            .list_signed_identity_occurrence_revocations_since(
                None,
                self.config.operational_page_limit,
            )
            .await
            .unwrap_or_default();
        Self::advertise_since(
            &rows,
            |row| subjects.contains(&row.identity_occurrence_revocation.occurrence_key_id),
            |row| Self::ms_seq(row.identity_occurrence_revocation.revoked_at),
        )
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
    async fn fan_out_for_member<Row, FetchFut, F, H>(
        &self,
        subjects: Vec<String>,
        mut fetch: F,
        timestamp: impl Fn(&Row) -> chrono::DateTime<chrono::Utc>,
        hash: H,
    ) -> Vec<EnvelopeRef>
    where
        F: FnMut(String) -> FetchFut,
        FetchFut: std::future::Future<Output = Vec<Row>>,
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
                refs.push(EnvelopeRef {
                    envelope_hash,
                    seq: Self::ms_seq(timestamp(&row)),
                });
            }
        }
        refs
    }

    /// CIRISEdge#396 item 3 — resolve a `Revocation` tombstone's wire bytes
    /// without a cache: scan the same `Global` subject set the advertise
    /// ([`Self::list_revocations`]) walks, match on `persist_row_hash`, and
    /// re-serialize the `SignedRevocation` exactly as [`Self::fan_out_for_member`]
    /// did on the advertise. A revocation is an immutable tombstone, so the
    /// re-read can never drift from what was advertised — the byte-exactness the
    /// point-read gives the indexed planes, achieved here by re-derivation.
    async fn fetch_revocation_bytes(&self, envelope_hash: &[u8; 32]) -> Option<Vec<u8>> {
        for subject in self.subjects_for_projection(Projection::Global) {
            let rows = self
                .directory
                .revocations_for(&subject)
                .await
                .unwrap_or_default();
            for row in rows {
                if Self::decode_hash(row.persist_row_hash.as_str()) == Some(*envelope_hash) {
                    return serde_json::to_vec(&SignedRevocation { revocation: row }).ok();
                }
            }
        }
        None
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

    /// CIRISEdge#386 — the capability a peer must hold to receive `trace:*`
    /// scores-attestations (CIRISPersist#473/v18). The contextual-integrity
    /// Recipient parameter: promotion (`attestation_promote`) consents to
    /// sharing with infrastructure blessed to SERVE, not with every cohort peer.
    ///
    /// v13.11.0 corrects the v13.10.0 token. #379 shipped a bare `"observer"`
    /// string, which is **not a federation capability token anywhere in the
    /// stack** (persist's only `observer` is the unrelated `wa_cert` WA role).
    /// The token the fleet actually confers — named by CIRISPersist#480, the
    /// CIRISServer Trust Root card, and CC 4.4.3.4.3 — is
    /// [`delegation_scope::INFRA_SERVE`]. Sourced from persist's const so the
    /// two sides cannot drift again.
    pub const SERVE_CAPABILITY: &'static str = delegation_scope::INFRA_SERVE;

    /// CIRISEdge#379 — does this attestation row require the recipient to hold
    /// [`Self::SERVE_CAPABILITY`]? True iff its `dimension` (CC 2.1 — inside
    /// `attestation_envelope`) is in the `trace:*` namespace.
    fn attestation_requires_serve(canonical_json: &serde_json::Value) -> bool {
        canonical_json
            .pointer("/attestation_envelope/dimension")
            .and_then(|v| v.as_str())
            .is_some_and(|d| d.starts_with("trace:"))
    }

    /// CIRISEdge#379 — `[`Self::attestation_requires_serve`]` over WIRE bytes
    /// (BARE `Attestation`, tolerating the legacy `{"attestation": …}` wrap;
    /// parse failure → `false`). Since CIRISEdge#396 v14.2 the production
    /// fetch twin ([`Self::fetch_envelope_bytes_for_peer`]) parses the wire once
    /// and reuses the value for BOTH the #379 and item-6 gates, so this thin
    /// re-parse survives only as a test utility (`locate_trace_hash`).
    #[cfg(test)]
    fn envelope_requires_serve(bytes: &[u8]) -> bool {
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return false;
        };
        let inner = v.get("attestation").unwrap_or(&v);
        Self::attestation_requires_serve(inner)
    }

    /// CIRISEdge#386 — may `peer_key_id` receive `trace:*` rows?
    ///
    /// **The gate is the trust root, not the bare capability.** We serve iff the
    /// peer's [`Self::SERVE_CAPABILITY`] is granted by a root THIS node itself
    /// trusts — persist's [`capability_roots_to_trusted_root`] (CIRISPersist#483)
    /// walks live `delegates_to(root → peer)` edges carrying the scope and, for
    /// each candidate root, evaluates `trust_root_valid` **from our own records**
    /// (live `delegates_to(us → root)`, root self-declaration, fresh
    /// `accord:lifecycle`, no halt latched).
    ///
    /// Two properties follow, both of which a bare-role check cannot give:
    /// - two nodes serve each other only under a **common** trusted root, so the
    ///   Recipient parameter is evaluated relative to the sender's own trust
    ///   rather than a global namespace; and
    /// - **un-trust is immediate and nuclear** — withdrawing our
    ///   `delegates_to(us → root)` edge stops serving every peer that rooted
    ///   through it on the very next call, with no cached flag to go stale.
    ///
    /// Any error, unknown peer, or absent local identity → `false` (fail-closed:
    /// an unresolvable recipient gets no gated rows). Because a dead gate is
    /// exactly how v13.10.0 failed, each refusal reason is logged distinctly at
    /// DEBUG (and a missing `local_key_id` at WARN, since that one is a wiring
    /// fault that would silently dark the whole plane).
    ///
    /// **Both planes are required (AND, never OR).** Alongside the trust-root
    /// walk, the peer's record must ALSO carry an accord-conferred
    /// `infra:serve` resolved through persist's self-authenticating read
    /// ([`has_effective_role`], CIRISPersist#440) — the record's scrub set must
    /// still verify to the accord family m-of-n against the live roster, with no
    /// un-superseded V104 tombstone. The two planes are deliberately not
    /// conflated (persist's `trust_root` module doc: a delegation SCOPE token
    /// inside a `delegates_to` envelope is NOT the accord-conferred ROLE on a
    /// `federation_keys` row), so requiring both means a recipient must be
    /// blessed by the accord AND rooted in a root we personally trust. An OR
    /// would have restored an accord-role bypass around the un-trust property.
    ///
    /// Consequence, accepted deliberately: the baked canonical seed still ships
    /// `roles: []` (CIRISPersist#480), so the trace plane stays dark until the
    /// fleet re-genesises with an `infra:serve`-blessed canonical. That is the
    /// intended sequencing — a plane that cannot yet flow is preferable to one
    /// that flows under a weaker gate, and unlike v13.10.0 this darkness is
    /// deliberate, logged per-leg, and covered by an ALLOW-path test.
    async fn peer_has_serve_capability(&self, peer_key_id: &str) -> bool {
        // Leg A — accord plane. Re-derived from the record's own cryptography
        // on every call, so a withdrawn blessing takes effect immediately.
        if !has_effective_role(&*self.directory, peer_key_id, Self::SERVE_CAPABILITY)
            .await
            .unwrap_or(false)
        {
            tracing::debug!(
                peer_key_id,
                "trace attestation withheld — recipient has no accord-conferred, still-verifying \
                 `infra:serve` (leg A; CIRISPersist#480 re-genesis pending)"
            );
            return false;
        }
        // Leg B — pluggable-trust-root plane.
        let Some(local) = self.local_key_id.as_deref() else {
            tracing::warn!(
                peer_key_id,
                "trace attestation withheld — replication runtime has no `local_key_id`, so the \
                 CIRISEdge#386 trust-root gate cannot be evaluated. This darks the trace plane; \
                 wire ReplicationRuntimeConfig::local_key_id (CIRISServer#300)."
            );
            return false;
        };
        match capability_roots_to_trusted_root(
            &*self.directory,
            local,
            peer_key_id,
            Self::SERVE_CAPABILITY,
        )
        .await
        {
            Ok(Some(grant)) => {
                tracing::debug!(
                    peer_key_id,
                    root_key_id = %grant.root_key_id,
                    grant_attestation_id = %grant.grant_attestation_id,
                    "trace attestation permitted — recipient's `infra:serve` roots to a trusted root"
                );
                true
            }
            Ok(None) => {
                tracing::debug!(
                    peer_key_id,
                    local_key_id = local,
                    "trace attestation withheld — recipient's `infra:serve` roots to no root this \
                     node trusts (CIRISEdge#386)"
                );
                false
            }
            Err(e) => {
                tracing::debug!(
                    peer_key_id,
                    error = %e,
                    "trace attestation withheld — trust-root walk failed (fail-closed)"
                );
                false
            }
        }
    }

    /// CIRISEdge#396 item 6 — the `recipient_capability` serve control (the
    /// #393 gate-first pattern). True iff serving `canonical_json` to `peer`
    /// would violate a `recipient_capability` restriction the DATA PRODUCER
    /// attached to its own `consent:replication:v1` grant.
    ///
    /// **Not gated on the server.** persist's closed consent grammar
    /// ([`consent_grammar::RestrictionOp::RecipientCapability`]) is parsed +
    /// admitted today; the grammar itself documents this op as *"enforced at
    /// the SERVE layer (P3), not at promotion time"* — promotion applies no
    /// transform for it, so THIS gate is its enforcer. The server merely starts
    /// PRODUCING such restrictions later; until it does, every grant carries an
    /// empty `restrictions` set and this returns `false` (fail-open-when-absent)
    /// — the row serves exactly as before, with no window where a restriction
    /// exists but isn't enforced.
    ///
    /// The owner whose grant governs a row is its `attesting_key_id`; we read
    /// that owner's LIVE grants via [`FederationDirectory::list_live_consent_grants_by`]
    /// (persist folds `withdraws`/`recants` at write time — a revoked grant is
    /// already gone, never re-derived here). For every grant whose
    /// `attestation_prefixes` [`consent_grammar::covers`] this row's dimension,
    /// the recipient must hold each named `capability` via the SAME
    /// accord-conferred, self-re-verifying [`has_effective_role`] read the #379
    /// serve gate's leg A uses — a self-asserted `roles:[…]` entry does not
    /// satisfy it. Missing capability → withhold (fail-closed). A malformed
    /// grant parses to nothing and covers nothing (persist's whole-grant
    /// fail-closed doctrine), so it can never widen the served set.
    ///
    /// `grant_cache` memoizes each owner's parsed policies for the lifetime of
    /// one listing sweep, so a plane of same-owner rows costs one grant read.
    async fn recipient_capability_withholds(
        &self,
        canonical_json: &serde_json::Value,
        peer: &str,
        grant_cache: &mut HashMap<String, Vec<ConsentTransferPolicy>>,
    ) -> bool {
        // The row's dimension (CC 2.1 — inside `attestation_envelope`) and its
        // owner. A row with neither cannot be covered by any grant → unrestricted.
        let Some(dimension) = canonical_json
            .pointer("/attestation_envelope/dimension")
            .and_then(|v| v.as_str())
        else {
            return false;
        };
        let Some(owner) = canonical_json
            .get("attesting_key_id")
            .and_then(|v| v.as_str())
        else {
            return false;
        };
        if !grant_cache.contains_key(owner) {
            let policies = self
                .directory
                .list_live_consent_grants_by(owner)
                .await
                .unwrap_or_default()
                .iter()
                .filter_map(|grant| {
                    consent_grammar::parse_grant_payload(&grant.attestation_envelope).ok()
                })
                .collect();
            grant_cache.insert(owner.to_string(), policies);
        }
        // Collect required capabilities WITHOUT holding the cache borrow across
        // the `has_effective_role` awaits below.
        let required: Vec<String> = grant_cache[owner]
            .iter()
            .filter(|policy| consent_grammar::covers(&policy.attestation_prefixes, dimension))
            .flat_map(|policy| {
                policy.restrictions.iter().filter_map(|op| match op {
                    consent_grammar::RestrictionOp::RecipientCapability { capability } => {
                        Some(capability.clone())
                    }
                    // `StripField` is applied at PROMOTION (persist strips the
                    // field before the row is promoted), so it is a no-op at the
                    // serve layer. A future restriction variant lands here as a
                    // compile error — the deliberate prompt to decide whether it
                    // needs serve-side enforcement too.
                    consent_grammar::RestrictionOp::StripField { .. } => None,
                })
            })
            .collect();
        for capability in required {
            if !has_effective_role(&*self.directory, peer, &capability)
                .await
                .unwrap_or(false)
            {
                tracing::debug!(
                    peer_key_id = peer,
                    capability = %capability,
                    dimension,
                    "trace attestation withheld — recipient lacks a producer-required \
                     `recipient_capability` (CIRISEdge#396 item 6)"
                );
                return true;
            }
        }
        false
    }

    /// CIRISEdge#396 item 1 — resolve `peer` against this node's live consent
    /// send-set (persist's `list_consent_peers` E7 projection, revocation-folded).
    /// `Some(ResolvedRecipient)` iff consent includes it; `None` (fail-closed)
    /// when there is no `local_key_id` to resolve against, the consent view
    /// won't resolve, or the peer is not consent-included. The Attestation plane
    /// — the only consentable plane — serves a peer ONLY with a
    /// `ResolvedRecipient` in hand, so both the advertise ([`Self::list_attestations`])
    /// and the direct-fetch ([`Self::fetch_envelope_bytes_for_peer`]) paths funnel
    /// through here; a peer excluded from the listing cannot obtain an
    /// attestation by Diff/Fetch-ing its hash out-of-band.
    async fn resolve_attestation_recipient(&self, peer: &str) -> Option<ResolvedRecipient> {
        let Some(local) = self.local_key_id.as_deref() else {
            tracing::warn!(
                peer,
                "attestation plane withheld — no `local_key_id` to resolve the CIRISEdge#396 \
                 consent send-set; wire ReplicationRuntimeConfig::local_key_id"
            );
            return None;
        };
        let Some(set) = self.resolved_peer_set(local).await else {
            tracing::debug!(
                peer,
                "attestation plane withheld — consent send-set unresolved (fail-closed)"
            );
            return None;
        };
        let resolved = set.recipient(peer);
        if resolved.is_none() {
            tracing::debug!(
                peer,
                "attestation plane withheld — recipient is not in this node's live \
                 consent:replication send-set (CIRISEdge#396 item 1)"
            );
        }
        resolved
    }

    /// CIRISEdge#400 — the memoized consent send-set. Returns the live
    /// `list_consent_peers(local)` projection, re-reading persist only when the
    /// memo is empty or older than [`CONSENT_SEND_SET_MEMO_TTL`]. A round's
    /// advertise + N `fetch_envelope_bytes_for_peer` calls therefore share ONE
    /// read instead of N (the v14.2.0 regression that blew the round budget),
    /// while a between-round withdraw still re-resolves next round. `None` (the
    /// caller fails closed) only on a directory error. The `Arc`-backed
    /// [`ResolvedPeerSet`] makes the memo-hit clone O(1); the `std` mutex is
    /// never held across the `await`.
    async fn resolved_peer_set(&self, local: &str) -> Option<ResolvedPeerSet> {
        if let Ok(memo) = self.consent_memo.lock() {
            if let Some((set, resolved_at)) = memo.as_ref() {
                if resolved_at.elapsed() < CONSENT_SEND_SET_MEMO_TTL {
                    return Some(set.clone());
                }
            }
        }
        let peers = match self.directory.list_consent_peers(local).await {
            Ok(peers) => peers,
            Err(e) => {
                tracing::debug!(error = %e, "consent send-set read failed (fail-closed)");
                return None;
            }
        };
        let set = ResolvedPeerSet::from_consent_peers(peers);
        if let Ok(mut memo) = self.consent_memo.lock() {
            *memo = Some((set.clone(), Instant::now()));
        }
        Some(set)
    }

    async fn list_attestations(&self, recipient: Option<&str>) -> Vec<EnvelopeRef> {
        // CIRISEdge#397 §1+§2 — the scores/Attestation plane reads ONE bulk
        // `list_attestations_since(None, limit)` page per round. That surface is
        // already **federation-tier only** (the E5 invariant) and cursored on the
        // VISIBILITY timestamp `COALESCE(promoted_at, asserted_at)` — so a
        // consent-promoted trace (§2) is included the moment it becomes
        // federation-visible, retiring the per-subject about/by sweep.
        //
        // The per-record policy is UNCHANGED: each attestation's projection is
        // resolved from its ACTUAL dimension (all 95 families), cohort_scope, and
        // attestation_type via [`Self::attestation_is_advertised`] — a trust-root
        // build-manifest reaches the whole federation, a self/family attestation
        // is published-own, a withdraws tombstone gossips GLOBAL. The #379 trace
        // RECIPIENT serve gate is likewise preserved verbatim.
        //
        // The wire hash is the BARE `Attestation`'s content-hash
        // ([`content_hash_of`]) — the exact bytes persist's `signed_wire_index`
        // keys on and its point-read serves; the plane no longer caches.
        // CIRISEdge#396 item 1 — the consent-membership fan-out bound (the
        // by-construction funnel; the Attestation plane is the ONLY consentable
        // plane). Edge advertises attestations to a peer ONLY if persist's live
        // consent projection includes it. Resolved once per sweep and
        // re-resolved every sweep, so a between-round `withdraws`/`recants`
        // takes effect at the next send (nuclear un-trust). `None` recipient =
        // projection-only/local view (ungated; tests). A `Some(peer)` that does
        // not resolve withholds the WHOLE plane (fail-closed). The resulting
        // `ResolvedRecipient` (consent-membership proof) is what the per-record
        // #379 + item-6 gates operate on — serving an unresolved peer is
        // unrepresentable.
        let resolved_recipient = match recipient {
            None => None,
            Some(peer) => match self.resolve_attestation_recipient(peer).await {
                Some(resolved) => Some(resolved),
                None => return Vec::new(),
            },
        };
        let self_set: HashSet<String> = self
            .self_provider
            .as_ref()
            .map(|p| p())
            .unwrap_or_default()
            .into_iter()
            .collect();
        let attestations = self
            .directory
            .list_attestations_since(None, self.config.operational_page_limit)
            .await
            .unwrap_or_default();
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        // CIRISEdge#379 — lazily-resolved recipient capability (one directory
        // lookup per listing sweep, and only when a gated row is encountered).
        let mut serve_allowed: Option<bool> = None;
        // CIRISEdge#396 item 6 — per-owner parsed consent grants, memoized for
        // this sweep so a same-owner plane costs one grant read.
        let mut grant_cache: HashMap<String, Vec<ConsentTransferPolicy>> = HashMap::new();
        for att in &attestations {
            let Ok(canonical_json) = serde_json::to_value(att) else {
                continue;
            };
            if !Self::attestation_is_advertised(&canonical_json, &self_set) {
                continue;
            }
            // CIRISEdge#379 — RECIPIENT gate (the contextual-integrity
            // Recipient parameter): a `trace:*` scores-attestation is
            // listed for a peer ONLY if that peer's KeyRecord advertises
            // an effective `infra:serve` capability. Non-trace rows are
            // untouched; a `None` recipient (projection-only view / tests)
            // is ungated — every production provider is peer-bound
            // (`DirectoryStateAdapter::with_peer`).
            if let Some(peer) = resolved_recipient.as_ref() {
                // The peer already cleared the item-1 consent-membership bound
                // (it holds a `ResolvedRecipient`); these gates further narrow
                // WHAT this consent-included peer receives.
                if Self::attestation_requires_serve(&canonical_json) {
                    if serve_allowed.is_none() {
                        serve_allowed = Some(self.peer_has_serve_capability(peer.as_str()).await);
                    }
                    if serve_allowed != Some(true) {
                        continue;
                    }
                }
                // CIRISEdge#396 item 6 — producer-declared `recipient_capability`
                // restrictions (any dimension a live grant covers, not just
                // `trace:*`). Fail-open when the producer declared none.
                if self
                    .recipient_capability_withholds(
                        &canonical_json,
                        peer.as_str(),
                        &mut grant_cache,
                    )
                    .await
                {
                    continue;
                }
            }
            let Some((hash, _bytes)) = content_hash_of(att) else {
                continue;
            };
            if !seen.insert(hash) {
                continue;
            }
            refs.push(EnvelopeRef {
                envelope_hash: hash,
                seq: Self::ms_seq(att.asserted_at),
            });
        }
        refs
    }

    async fn list_revocations(&self) -> Vec<EnvelopeRef> {
        // #311 tombstone fix — key revocations project `Global` (own ∪ cohort),
        // not cohort-only RELAY, so a revocation is never out-run by the stale
        // record it retracts even after the subject exits the cohort.
        self.fan_out_for_member(
            self.subjects_for_projection(Projection::Global),
            |key_id| async move {
                self.directory
                    .revocations_for(&key_id)
                    .await
                    .unwrap_or_default()
            },
            |row| row.revoked_at,
            |row| row.persist_row_hash.as_str(),
        )
        .await
    }

    // ── CIRISEdge#504 — the 5 E4 keyless-declaration planes advertise via
    //    persist v21.1.0's SIGNED, since-cursor bulk reads ──────────────────
    //
    // v21 #502 E4 gave these planes an authority signature (`authority_key_id`
    // + hybrid scrub sigs on the `Signed*` wrapper), which edge — NOT the
    // authority — cannot produce. persist self-signs on write and now exposes
    // `list_signed_<kind>_since(since, limit) -> Vec<Signed*>` (mirroring the
    // org/orgmembership/partner reads), so edge serves those wrappers BYTE-EXACT.
    // CIRISEdge#397: the wire hash is now each wrapper's content-hash
    // ([`content_hash_of`] — `sha256(serde_json::to_vec(Signed*))`), the exact
    // value persist's `signed_wire_index` keys on for these kinds, so the
    // advertised hash IS the point-read key (fetch is the point-read, no cache).
    // This also retires the per-member `fan_out_for_member` for these 5: ONE
    // paginated read per plane per round instead of O(cohort) round-trips
    // (CIRISPersist#504 hot-path floor).
    //
    // ADVERTISE SCOPE is preserved from the pre-v21 fan_out per the §4.3
    // 14-kind table: Family / Community / LocationProof are **Cohort**-scoped
    // (filtered in-memory to rows touching a cohort member — the bulk read is
    // over edge's OWN directory, so reading-then-filtering leaks nothing), and
    // the two membership-revocation planes are **Global** (advertised whole,
    // matching the pre-v21 `subjects_for_projection(Global)` subject set).

    /// The operator-configured cohort as a set, for the Cohort-scoped advertise
    /// filters.
    fn cohort_set(&self) -> HashSet<String> {
        (self.cohort)().into_iter().collect()
    }

    async fn list_families(&self) -> Vec<EnvelopeRef> {
        let cohort = self.cohort_set();
        let rows = self
            .directory
            .list_signed_families_since(None, self.config.operational_page_limit)
            .await
            .unwrap_or_default();
        Self::advertise_since(
            &rows,
            |s| s.family.members.iter().any(|m| cohort.contains(&m.key_id)),
            |s| Self::ms_seq(s.family.founded_at),
        )
    }

    async fn list_communities(&self) -> Vec<EnvelopeRef> {
        let cohort = self.cohort_set();
        let rows = self
            .directory
            .list_signed_communities_since(None, self.config.operational_page_limit)
            .await
            .unwrap_or_default();
        Self::advertise_since(
            &rows,
            |s| {
                s.community
                    .members
                    .iter()
                    .any(|m| cohort.contains(&m.key_id))
            },
            |s| Self::ms_seq(s.community.founded_at),
        )
    }

    async fn list_family_membership_revocations(&self) -> Vec<EnvelopeRef> {
        // #311 tombstone fix — membership revocation projects `Global`
        // (advertised whole, no cohort filter).
        let rows = self
            .directory
            .list_signed_family_membership_revocations_since(
                None,
                self.config.operational_page_limit,
            )
            .await
            .unwrap_or_default();
        Self::advertise_since(
            &rows,
            |_| true,
            |s| Self::ms_seq(s.family_membership_revocation.removed_at),
        )
    }

    async fn list_community_membership_revocations(&self) -> Vec<EnvelopeRef> {
        // #311 tombstone fix — membership revocation projects `Global`
        // (advertised whole, no cohort filter).
        let rows = self
            .directory
            .list_signed_community_membership_revocations_since(
                None,
                self.config.operational_page_limit,
            )
            .await
            .unwrap_or_default();
        Self::advertise_since(
            &rows,
            |_| true,
            |s| Self::ms_seq(s.community_membership_revocation.removed_at),
        )
    }

    async fn list_location_proofs(&self) -> Vec<EnvelopeRef> {
        let cohort = self.cohort_set();
        let rows = self
            .directory
            .list_signed_location_proofs_since(None, self.config.operational_page_limit)
            .await
            .unwrap_or_default();
        Self::advertise_since(
            &rows,
            |s| cohort.contains(&s.location_proof.subject_key_id),
            |s| Self::ms_seq(s.location_proof.asserted_at),
        )
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
        // CIRISEdge#397 — advertise the BARE `Organization` row's content-hash.
        // Persist's `signed_wire_index` keys `Organization` on
        // `content_hash_of(&Organization)` (the bare row `list_organizations_since`
        // returns — the row carries its own inline single-signer signature, so
        // there is NO separate signed-since surface), and its point-read reloads +
        // re-serializes that SAME bare row. Hashing the wrapper here would
        // advertise a hash the point-read can never resolve. The receiver's
        // `apply_organization` re-wraps the bare row for `put_organization`.
        let rows = self
            .directory
            .list_organizations_since(None, self.config.operational_page_limit)
            .await
            .unwrap_or_default();
        Self::advertise_since(&rows, |_| true, |row| Self::ms_seq(row.asserted_at))
    }

    async fn list_org_memberships(&self) -> Vec<EnvelopeRef> {
        // CIRISEdge#397 — advertise the BARE `OrgMembership` row's content-hash;
        // same bare-row basis as `list_organizations` (persist indexes + reloads
        // the bare row). `apply_org_membership` re-wraps on the receive side.
        let rows = self
            .directory
            .list_org_memberships_since(None, self.config.operational_page_limit)
            .await
            .unwrap_or_default();
        Self::advertise_since(&rows, |_| true, |row| Self::ms_seq(row.asserted_at))
    }

    async fn list_partner_records(&self) -> Vec<EnvelopeRef> {
        // v2.0.1 — `partner_record` is **bidirectional**. CIRISPersist#194's
        // `list_signed_partner_records_since` returns the full
        // `SignedPartnerRecord` wrapper (row + steward_signatures + threshold).
        // CIRISEdge#397 — advertise that wrapper's content-hash
        // ([`content_hash_of`]); persist's `signed_wire_index` keys `PartnerRecord`
        // on `content_hash_of(&SignedPartnerRecord)` and its point-read reloads +
        // re-serializes the SAME wrapper, so advertise-hash == point-read here.
        let rows = self
            .directory
            .list_signed_partner_records_since(None, self.config.operational_page_limit)
            .await
            .unwrap_or_default();
        Self::advertise_since(
            &rows,
            |_| true,
            |s| Self::ms_seq(s.partner_record.asserted_at),
        )
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
        // CIRISEdge#397 — the wire is now the BARE `Attestation` (the shape
        // persist's content-hash index/point-read serves), so deserialize that
        // first and re-wrap; fall back to the pre-v14.1 `SignedAttestation`
        // `{"attestation": …}` wrap for a peer still on the old wire.
        let signed = serde_json::from_slice::<Attestation>(bytes)
            .map(|attestation| SignedAttestation { attestation })
            .or_else(|_| serde_json::from_slice::<SignedAttestation>(bytes));
        match signed {
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

    /// CIRISEdge#338 / CIRISPersist#443 (v17.0.0) — admit a replicated route.
    ///
    /// The wire bytes are now the SIGNED CONTAINER `SignedTransportDestination`
    /// (`{transport_destination, attesting_key_id, signed_envelope, signature}`),
    /// NOT a bare row. This closes the CIRISEdge#337 CRITICAL-2 confused-deputy:
    /// the old path deserialized a bare `TransportDestination` and wrote it with
    /// an attacker-chosen `binding_provenance = Rooted` for ANY `occurrence_key_id`,
    /// with no signature and no authority check. `put_signed_transport_destination`
    /// authenticates the whole thing in persist — the hybrid signature over
    /// `JCS(signed_envelope)` against the attesting key's PINNED federation
    /// pubkeys, then `signer_acts_for(attesting_key_id, occurrence_key_id)` (a peer
    /// cannot sign a victim's route with its own unrelated key), and
    /// `binding_provenance` is read ONLY from inside the verified envelope, never
    /// a wire field. Supersession is `(epoch, asserted_at)`-monotonic, so a
    /// replayed older frame is `Refused`, not applied.
    ///
    /// `Refused { reason }` is fail-closed and re-offerable — it is NOT a
    /// transport error (the record is simply inadmissible: older epoch, or a
    /// same-`(epoch, asserted_at)` content conflict), so we return `true`
    /// (the frame was handled; do not retry-storm the sender). A genuine gate
    /// failure (bad signature / unknown attesting key / not-acts-for) surfaces
    /// as `Err` from persist → `false` → the frame is rejected. A parse failure
    /// (a pre-v17 bare row from an un-upgraded peer) is also `false` — such a
    /// peer's routes simply do not replicate until it adopts v17, which is the
    /// intended breaking behavior, not a silent bare-row admit.
    async fn apply_transport_destination(&self, bytes: &[u8]) -> bool {
        use ciris_persist::federation::self_at_login::{
            SignedTransportDestination, TransportDestinationApplyOutcome,
        };
        match serde_json::from_slice::<SignedTransportDestination>(bytes) {
            Ok(signed) => match self
                .directory
                .put_signed_transport_destination(&signed)
                .await
            {
                Ok(TransportDestinationApplyOutcome::Refused { reason }) => {
                    // Bounded: keyed on the low-cardinality refusal reason, never
                    // the attacker-influenced key_id / dest (CIRISEdge#337 §4).
                    tracing::debug!(
                        occurrence_key_id = %signed.transport_destination.occurrence_key_id,
                        reason = %reason,
                        "replicated route refused (fail-closed, re-offerable): stale epoch \
                         or content conflict — not applied (CIRISEdge#338)"
                    );
                    true
                }
                Ok(_) => true,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "replicated route REJECTED by the authenticated apply gate — \
                         signature / attesting-key / acts-for failure (CIRISEdge#337 CRITICAL-2)"
                    );
                    false
                }
            },
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

    // CIRISEdge#504 / persist v21 #502 E9 — persist now resolves the steward
    // roster from its OWN registered directory (never a caller-passed roster:
    // that was itself a classical FK-existence edge). So `put_organization` /
    // `put_org_membership` / `put_partner_record` no longer take
    // key_directory/root_stewards/steward_roster args. The `operational` gate
    // stays the opt-in for whether THIS edge participates in operational-kind
    // admission at all — admission SCOPE is unchanged, only the (now
    // persist-internal) roster plumbing is dropped. The `OperationalProviders`
    // roster fields are vestigial post-E9; the server drops computing them when
    // it adopts v14.
    async fn apply_organization(&self, bytes: &[u8]) -> bool {
        if self.operational.is_none() {
            return false;
        }
        // CIRISEdge#397 — the content-hash point-read serves the BARE
        // `Organization` row (the shape `list_organizations_since` returns + the
        // `signed_wire_index` keys on); deserialize that and re-wrap for
        // `put_organization`, falling back to the pre-v14.1 `SignedOrganization`
        // `{"organization": …}` wrap for a peer still on the old wire.
        let signed = serde_json::from_slice::<Organization>(bytes)
            .map(|organization| SignedOrganization { organization })
            .or_else(|_| serde_json::from_slice::<SignedOrganization>(bytes));
        match signed {
            Ok(s) => self.directory.put_organization(s).await.is_ok(),
            Err(_) => false,
        }
    }

    async fn apply_org_membership(&self, bytes: &[u8]) -> bool {
        if self.operational.is_none() {
            return false;
        }
        // CIRISEdge#397 — same bare-row wire as `apply_organization`: deserialize
        // the BARE `OrgMembership` and re-wrap, falling back to the pre-v14.1
        // `SignedOrgMembership` wrap.
        let signed = serde_json::from_slice::<OrgMembership>(bytes)
            .map(|org_membership| SignedOrgMembership { org_membership })
            .or_else(|_| serde_json::from_slice::<SignedOrgMembership>(bytes));
        match signed {
            Ok(s) => self.directory.put_org_membership(s).await.is_ok(),
            Err(_) => false,
        }
    }

    async fn apply_partner_record(&self, bytes: &[u8]) -> bool {
        if self.operational.is_none() {
            return false;
        }
        let Ok(signed) = serde_json::from_slice::<SignedPartnerRecord>(bytes) else {
            return false;
        };
        self.directory.put_partner_record(signed).await.is_ok()
    }
}

/// CIRISEdge#397 / persist v21.2.0 (#507) — the content-hash contract: return
/// the wire bytes edge serves for `value` AND their sha256, computed EXACTLY as
/// persist's `wire_index::content_hash_of`: `sha256(serde_json::to_vec(value))`
/// (NO JCS — the raw `to_vec` bytes of the signed wrapper element the
/// `list_signed_*_since` reads return). Serving these same bytes makes
/// advertise-hash = served-bytes = the point-read's `content_hash`, so a Diff'd
/// peer fetches byte-identical what was advertised
/// ([`ciris_persist::federation::FederationDirectory::lookup_signed_record_by_content_hash`]).
fn content_hash_of<T: serde::Serialize>(value: &T) -> Option<([u8; 32], Vec<u8>)> {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(value).ok()?;
    let hash: [u8; 32] = Sha256::digest(&bytes).into();
    Some((hash, bytes))
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
        algorithm, identity_type, Attestation, KeyRecord, Revocation, SignedAttestation,
        SignedKeyRecord,
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
        assert_eq!(
            c.operational_page_limit,
            BridgeConfig::DEFAULT_OPERATIONAL_PAGE_LIMIT
        );
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

    /// CIRISEdge#337 CRITICAL-2 — the confused-deputy closure. A WELL-FORMED
    /// BARE `TransportDestination` (valid JSON of the bare route row — the exact
    /// shape the pre-v17 apply path deserialized and wrote with an attacker-set
    /// `binding_provenance = Rooted` for ANY key_id, with no signature and no
    /// authority check) must now be REFUSED. Only a `SignedTransportDestination`
    /// container that clears persist's hybrid-sig + `signer_acts_for` gate is
    /// admitted. This is the route-table half of the AV-42 saga: a peer can no
    /// longer inject a route for a victim's key_id over replication.
    #[tokio::test]
    async fn apply_transport_destination_refuses_a_bare_unsigned_route() {
        use ciris_persist::federation::self_at_login::{BindingProvenance, TransportDestination};

        let (backend, bridge) = make_bridge(&[]);

        // A perfectly well-formed bare route claiming a Rooted binding for a
        // victim key_id — no signature, no authority. The confused-deputy input.
        let bare = TransportDestination {
            occurrence_key_id: "victim-key".to_string(),
            transport_kind: "reticulum".to_string(),
            destination: hex::encode([0xaa; 16]),
            asserted_at: chrono::Utc::now(),
            last_seen_at: None,
            transport_ed25519_pubkey_base64: Some(
                base64::engine::general_purpose::STANDARD.encode([0xbb; 32]),
            ),
            transport_x25519_pubkey_base64: Some(
                base64::engine::general_purpose::STANDARD.encode([0xcc; 32]),
            ),
            binding_provenance: BindingProvenance::Rooted, // attacker-chosen
            epoch: u64::MAX,                               // attacker-chosen ceiling
            retired_at: None,
        };
        let bytes = serde_json::to_vec(&bare).expect("serialize bare route");

        let admitted = bridge
            .apply_envelope_bytes(EnvelopeKind::TransportDestination, &bytes)
            .await;

        assert!(
            !admitted,
            "a bare unsigned TransportDestination must be REFUSED — admitting it is the \
             CIRISEdge#337 CRITICAL-2 confused-deputy route-hijack",
        );

        // And nothing was written for the victim.
        let rows = backend
            .list_transport_destinations_for("victim-key")
            .await
            .expect("list");
        assert!(
            rows.is_empty(),
            "a refused bare route must not touch persist; found {} row(s)",
            rows.len(),
        );
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

    // ── CIRISEdge#397 — the load-bearing round-trip invariant ────────

    /// **The wire-critical proof.** For the Key and Attestation planes, the
    /// `envelope_hash` `list_envelope_refs` advertises MUST equal `sha256` of the
    /// exact bytes `fetch_envelope_bytes` returns for it — end-to-end, over the
    /// same `MemoryBackend` the other bridge tests use (which self-indexes the
    /// `signed_wire_index` on put, so no rebuild is needed). This closes the
    /// advertise-hash == served-bytes == point-read loop CIRISEdge#397 establishes.
    #[tokio::test]
    async fn advertise_hash_equals_sha256_of_fetched_bytes() {
        let key_id = "agent-roundtrip";
        let attester = "agent-attester";
        let (backend, bridge) = make_bridge(&[key_id.to_string(), attester.to_string()]);

        // A signed KeyRecord via the signed put path (indexes under "Key").
        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record(key_id, identity_type::AGENT),
            })
            .await
            .expect("seed key");
        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record(attester, identity_type::AGENT),
            })
            .await
            .expect("seed attester key");

        // A federation-tier (tier="federation") Attestation via put_attestation
        // (indexes under "Attestation"; cohort_scope="federation" → advertised).
        let now = Utc::now();
        let envelope = serde_json::json!({
            "attesting_key_id": attester,
            "attested_key_id": key_id,
            "attestation_type": "delegates_to",
        });
        let (hash, ed_sig, pqc_sig) = sign_attestation_envelope(attester, &envelope);
        backend
            .put_attestation(SignedAttestation {
                attestation: Attestation {
                    attestation_id: uuid::Uuid::new_v4().to_string(),
                    attesting_key_id: attester.to_string(),
                    attested_key_id: key_id.to_string(),
                    attestation_type: "delegates_to".to_string(),
                    weight: None,
                    asserted_at: now,
                    expires_at: None,
                    attestation_envelope: envelope,
                    original_content_hash: hash,
                    scrub_signature_classical: ed_sig,
                    scrub_signature_pqc: pqc_sig,
                    scrub_key_id: attester.to_string(),
                    scrub_timestamp: now,
                    pqc_completed_at: None,
                    persist_row_hash: String::new(),
                    subject_key_ids: Vec::new(),
                    withdraws_admission_rule: None,
                    cohort_scope: "federation".to_string(),
                    tier: "federation".to_string(),
                    promoted_at: None,
                },
            })
            .await
            .expect("seed federation-tier attestation");

        for kind in [EnvelopeKind::Key, EnvelopeKind::Attestation] {
            let refs = bridge.list_envelope_refs(kind).await;
            assert!(!refs.is_empty(), "{kind:?} advertises at least one ref");
            for r in &refs {
                let bytes = bridge
                    .fetch_envelope_bytes(kind, &r.envelope_hash)
                    .await
                    .unwrap_or_else(|| {
                        panic!("{kind:?} point-read must serve the advertised hash")
                    });
                let served: [u8; 32] = Sha256::digest(&bytes).into();
                assert_eq!(
                    served, r.envelope_hash,
                    "{kind:?}: advertised envelope_hash MUST equal sha256(fetched bytes)"
                );
            }
        }
    }

    // ── CIRISEdge#386 — infra:serve recipient gate (trace plane) ──

    /// Seed one `delegates_to(attester → subject)` carrying `scope`, and
    /// return its `attestation_id` (so a test can tombstone that exact edge).
    async fn seed_delegates_to(
        backend: &MemoryBackend,
        attester: &str,
        subject: &str,
        scope: &serde_json::Value,
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": attester,
            "attested_key_id": subject,
            "attestation_type": "delegates_to",
            "scope": scope,
        });
        seed_raw_attestation(backend, &id, attester, subject, "delegates_to", envelope).await;
        id
    }

    /// Seed a root's SELF-CHARTER — `delegates_to(root → root)`. persist v19
    /// (CIRISPersist#488) tightened this shape twice, and both are enforced at
    /// admission, so the fixture carries what the field must carry:
    /// `scope` must contain BOTH `infra:serve` AND `infra:attest` (the finalized
    /// charter minimum; v18's OR is gone), and the envelope must carry a
    /// well-formed `pre_rotation_commitment` — sha256 over the canonicalized,
    /// sorted pre-committed successor key set — without which root-key
    /// compromise is unrecoverable by construction (the KERI prior-art lesson).
    /// Built with persist's own `pre_rotation_commitment` helper rather than a
    /// hand-rolled digest, so the fixture cannot drift from the verifier.
    async fn seed_root_charter(
        backend: &MemoryBackend,
        root: &str,
        successor_keys: &[String],
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let commitment =
            ciris_persist::federation::trust_root::pre_rotation_commitment(successor_keys)
                .expect("pre-rotation commitment");
        let envelope = serde_json::json!({
            "id": id,
            "references_attestation_id": id,
            "attesting_key_id": root,
            "attested_key_id": root,
            "attestation_type": "delegates_to",
            "scope": ["infra:serve", "infra:attest"],
            "pre_rotation_commitment": commitment,
        });
        seed_raw_attestation(backend, &id, root, root, "delegates_to", envelope).await;
        id
    }

    /// Seed a fresh `accord:lifecycle:v1` scores row ABOUT `root` — the
    /// liveness leg of `trust_root_valid`.
    async fn seed_accord_lifecycle(backend: &MemoryBackend, attester: &str, root: &str) {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": attester,
            "attested_key_id": root,
            "attestation_type": "scores",
            "dimension": "accord:lifecycle:v1",
            "score": 1.0,
            "confidence": 0.9,
        });
        seed_raw_attestation(backend, &id, attester, root, "scores", envelope).await;
    }

    /// Seed a `withdraws` composer tombstoning `target_id` — the CEG un-trust
    /// primitive. Shape mirrors persist's own `fix_withdraws` witness: the
    /// composer references its target through `references_attestation_id`
    /// (CEG §3.2, read by `precedence::references_attestation_id_from_envelope`)
    /// and is attested BY the issuer ABOUT itself, since same-attester authority
    /// is what admits a withdrawal of one's own edge.
    #[cfg(feature = "test-anchor")]
    async fn seed_withdraws(backend: &MemoryBackend, attester: &str, target_id: &str) {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": attester,
            "attested_key_id": attester,
            "attestation_type": "withdraws",
            "references_attestation_id": target_id,
            "withdrawal_reason": "test: operator un-trusts the root",
        });
        seed_raw_attestation(backend, &id, attester, attester, "withdraws", envelope).await;
    }

    /// Seed ONE `trace:complete:v1` scores row in the shape persist v18.1.0's
    /// Information-Type validator admits (trace_id + agent_id_hash + trace).
    #[cfg(feature = "test-anchor")]
    async fn seed_trace_attestation(backend: &MemoryBackend, producer: &str) {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": producer,
            "attested_key_id": producer,
            "attestation_type": "scores",
            "dimension": "trace:complete:v1",
            "trace_id": "t-fixture-1",
            "agent_id_hash": "ah-fixture-1",
            "trace": { "steps": [] },
        });
        seed_raw_attestation(backend, &id, producer, producer, "scores", envelope).await;
    }

    /// Find the seeded trace row by CONTENT in the bridge's own projection —
    /// robust to however many trust-graph rows share the plane.
    async fn locate_trace_hash(bridge: &FederationDirectoryReplicationBridge) -> [u8; 32] {
        let all = bridge.list_envelope_refs(EnvelopeKind::Attestation).await;
        let mut found = None;
        for r in &all {
            let bytes = bridge
                .fetch_envelope_bytes(EnvelopeKind::Attestation, &r.envelope_hash)
                .await
                .expect("projection-only fetch");
            if FederationDirectoryReplicationBridge::envelope_requires_serve(&bytes) {
                assert!(found.is_none(), "exactly one trace row was seeded");
                found = Some(r.envelope_hash);
            }
        }
        found.expect("the seeded trace row appears in the local view")
    }

    async fn seed_raw_attestation(
        backend: &MemoryBackend,
        id: &str,
        attester: &str,
        subject: &str,
        attestation_type: &str,
        envelope: serde_json::Value,
    ) {
        let now = Utc::now();
        let (hash, ed_sig, pqc_sig) = sign_attestation_envelope(attester, &envelope);
        let att = Attestation {
            attestation_id: id.to_string(),
            attesting_key_id: attester.to_string(),
            attested_key_id: subject.to_string(),
            attestation_type: attestation_type.to_string(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: hash,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: attester.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec![subject.to_string()],
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
            tier: "federation".to_string(),
            promoted_at: None,
        };
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .expect("seed trust-graph attestation");
    }

    /// Seed a producer's `consent:replication:v1` grant carrying a single
    /// `recipient_capability` restriction over `prefix`, naming `recipient` as
    /// the consented peer — so persist's E7 projection sources a live row from
    /// it and [`FederationDirectory::list_live_consent_grants_by`] returns it.
    async fn seed_consent_grant(
        backend: &MemoryBackend,
        producer: &str,
        recipient: &str,
        prefix: &str,
        capability: &str,
    ) {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": producer,
            "attested_key_id": recipient,
            "attestation_type": "scores",
            "dimension": "consent:replication:v1",
            "payload": {
                "grants": "transfer",
                "attestation_prefixes": [prefix],
                "restrictions": [{ "op": "recipient_capability", "capability": capability }],
            },
        });
        seed_raw_attestation(backend, &id, producer, recipient, "scores", envelope).await;
    }

    /// Seed a bare `consent:replication:v1` grant (NO restrictions) by `granter`
    /// naming `peer` — the minimum that puts `peer` in
    /// `list_consent_peers(granter)` so it clears the CIRISEdge#396 item-1
    /// membership bound WITHOUT a `recipient_capability` that would separately
    /// trip item 6. Use when a test needs a peer to be consent-included but is
    /// exercising a DIFFERENT gate.
    async fn seed_consent_membership(backend: &MemoryBackend, granter: &str, peer: &str) {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": granter,
            "attested_key_id": peer,
            "attestation_type": "scores",
            "dimension": "consent:replication:v1",
            "payload": {
                "grants": "transfer",
                "attestation_prefixes": ["trace:"],
            },
        });
        seed_raw_attestation(backend, &id, granter, peer, "scores", envelope).await;
    }

    /// Seed a hybrid-signed `Revocation` of `revoked` by `revoking` (both must
    /// be registered keys). persist computes `persist_row_hash` on put — the
    /// value the Revocation plane advertises + the cache-free fetch scan matches.
    async fn seed_revocation(backend: &MemoryBackend, revoking: &str, revoked: &str) {
        let now = Utc::now();
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "revocation_id": id,
            "revoked_key_id": revoked,
            "revoking_key_id": revoking,
        });
        let (hash, ed_sig, pqc_sig) = sign_attestation_envelope(revoking, &envelope);
        let revocation = Revocation {
            revocation_id: id,
            revoked_key_id: revoked.to_string(),
            revoking_key_id: revoking.to_string(),
            reason: None,
            revoked_at: now,
            effective_at: now,
            revocation_envelope: envelope,
            original_content_hash: hash,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: revoking.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            observed_region: String::new(),
            persist_row_hash: String::new(),
        };
        backend
            .put_revocation(SignedRevocation { revocation })
            .await
            .expect("seed revocation");
    }

    /// CIRISEdge#396 item 3 — the Revocation plane (the one kind persist does
    /// not content-hash-index) fetches with NO cache: `fetch_envelope_bytes`
    /// re-derives the tombstone's bytes by scanning the same `Global` subject
    /// set the advertise walked. A revocation advertised by `list_revocations`
    /// must therefore fetch back byte-for-byte through the point-read surface.
    #[tokio::test]
    async fn revocation_fetch_is_cache_free_round_trip() {
        let revoking = "revoker-node";
        let revoked = "revoked-key";
        // `revoked` must be in the cohort so the Global-projection scan reaches it.
        let (backend, bridge) = make_bridge(&[revoking.to_string(), revoked.to_string()]);
        for key_id in [revoking, revoked] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(key_id, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        seed_revocation(&backend, revoking, revoked).await;

        let refs = bridge.list_revocations().await;
        assert!(!refs.is_empty(), "the seeded revocation is advertised");
        for r in &refs {
            let bytes = bridge
                .fetch_envelope_bytes(EnvelopeKind::Revocation, &r.envelope_hash)
                .await
                .expect("cache-free revocation fetch resolves the advertised hash");
            let parsed: SignedRevocation =
                serde_json::from_slice(&bytes).expect("fetched bytes are a SignedRevocation");
            assert_eq!(
                parsed.revocation.revoked_key_id, revoked,
                "the re-derived bytes are the advertised revocation"
            );
        }
    }

    /// A `trace:complete:v1` row's canonical JSON in EXACTLY the shape
    /// `list_attestations` feeds the item-6 gate — `serde_json::to_value` over an
    /// `Attestation` ([[feedback_test_field_provenance]]: the gate reads
    /// `/attestation_envelope/dimension` and `attesting_key_id` off THIS value).
    /// Built directly rather than round-tripped through `put_attestation` because
    /// admitting a real `trace:*` row needs persist's `test-anchor` relaxation
    /// (a `#[cfg]`-gated lib test never runs in CI's lanes); the gate reads the
    /// projected value, not the store, so this isolates item 6 faithfully.
    fn trace_row_json(producer: &str) -> serde_json::Value {
        let now = Utc::now();
        let envelope = serde_json::json!({
            "id": "trace-fixture-1",
            "attesting_key_id": producer,
            "attested_key_id": producer,
            "attestation_type": "scores",
            "dimension": "trace:complete:v1",
            "trace_id": "t-fixture-1",
            "agent_id_hash": "ah-fixture-1",
            "trace": { "steps": [] },
        });
        let att = Attestation {
            attestation_id: "trace-fixture-1".to_string(),
            attesting_key_id: producer.to_string(),
            attested_key_id: producer.to_string(),
            attestation_type: "scores".to_string(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: producer.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
            tier: "federation".to_string(),
            promoted_at: None,
        };
        serde_json::to_value(&att).expect("serialize trace row")
    }

    /// CIRISEdge#396 item 6 — the `recipient_capability` serve control (the #393
    /// gate-first pattern), asserted against the inputs the serve gate actually
    /// reads. Like the #379 gate, the ALLOW path (recipient HOLDS the capability)
    /// needs a live accord co-scrub whose minting helper is private to persist
    /// (CIRISPersist#484), so the load-bearing WITHHOLD path + the two SERVE
    /// paths are locked here; the ALLOW path lands with the same fleet
    /// re-genesis that lights the #379 ALLOW path.
    #[tokio::test]
    async fn recipient_capability_serve_control() {
        let producer = "agent-producer";
        // A recipient whose record EXISTS but carries no accord-conferred role —
        // `has_effective_role(_, "trace:read")` is false for it. (Seeding the key
        // means the WITHHOLD below is because the record lacks the capability, not
        // because the key is absent — the same provenance discipline the #379
        // test uses to refuse a self-asserted `roles:[…]` peer.)
        let recipient = "peer-no-capability";
        let (backend, bridge) = make_bridge(&[producer.to_string(), recipient.to_string()]);
        // Both keys registered: the producer's so `put_attestation` can verify
        // its grant's hybrid signature, the recipient's so `has_effective_role`
        // reads a real (role-less) record — not a missing one.
        for key_id in [producer, recipient] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(key_id, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        let trace_json = trace_row_json(producer);

        // (a) No grant → no restriction → SERVE (fail-open-when-absent: the
        //     fleet's servers emit no `recipient_capability` yet, and the plane
        //     must flow exactly as it did before this control shipped).
        assert!(
            !bridge
                .recipient_capability_withholds(&trace_json, recipient, &mut HashMap::new())
                .await,
            "no consent grant declares a restriction → the row must serve"
        );

        // (b) A grant COVERING `trace:` with a `recipient_capability` the
        //     recipient lacks → WITHHOLD. This is the load-bearing case: the
        //     instant the producer's restriction materializes, enforcement lights
        //     up with no window where the restriction exists but isn't enforced.
        seed_consent_grant(&backend, producer, recipient, "trace:", "trace:read").await;
        assert!(
            bridge
                .recipient_capability_withholds(&trace_json, recipient, &mut HashMap::new())
                .await,
            "covering grant + recipient lacks the required capability → withhold"
        );

        // (c) A restriction on a grant that does NOT cover the row's dimension →
        //     SERVE (the `covers()` gate; a `capacity:` grant never gates a
        //     `trace:` row). Fresh backend so no `trace:`-covering grant lingers.
        let (backend2, bridge2) = make_bridge(&[producer.to_string(), recipient.to_string()]);
        for key_id in [producer, recipient] {
            backend2
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(key_id, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        let trace_json2 = trace_row_json(producer);
        seed_consent_grant(&backend2, producer, recipient, "capacity:", "trace:read").await;
        assert!(
            !bridge2
                .recipient_capability_withholds(&trace_json2, recipient, &mut HashMap::new())
                .await,
            "grant prefix `capacity:` does not cover a `trace:` row → serve"
        );
    }

    /// Seed a federation-tier `delegates_to` attestation the plane advertises —
    /// no `trace:` dimension (so the #379 gate is inert) and no envelope
    /// `dimension` at all (so no consent grant's `covers` can trip item 6),
    /// leaving item 1 (consent membership) as the ONLY differentiator. Returns
    /// the attestation id.
    async fn seed_advertised_attestation(backend: &MemoryBackend, producer: &str) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": producer,
            "attested_key_id": producer,
            "attestation_type": "delegates_to",
            "scope": { "grant": ["infra:attest"] },
        });
        seed_raw_attestation(backend, &id, producer, producer, "delegates_to", envelope).await;
        id
    }

    /// CIRISEdge#396 item 1 — the consent-membership fan-out bound. The
    /// Attestation plane is served to a peer ONLY if persist's live consent
    /// projection (`list_consent_peers`, E7) includes it. Asserted against the
    /// actual advertise path: a consent-included peer receives the plane; a peer
    /// absent from the send-set receives NOTHING (the whole plane withheld,
    /// fail-closed) — the by-construction bound `resolved_state.rs` enforces.
    #[tokio::test]
    async fn consent_membership_fan_out_bound() {
        let local = "this-node";
        let producer = "agent-producer";
        let peer_in = "peer-consented";
        let peer_out = "peer-unconsented";
        let (backend, bridge) = make_bridge(&[
            local.to_string(),
            producer.to_string(),
            peer_in.to_string(),
            peer_out.to_string(),
        ]);
        let bridge = bridge.with_local_key_id(Some(local.to_string()));
        for key_id in [local, producer, peer_in, peer_out] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(key_id, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        seed_advertised_attestation(&backend, producer).await;
        // `local` consents to replicate to `peer_in` only (the grant names it →
        // list_consent_peers(local) ∋ peer_in). Prefix "trace:" so the grant's
        // own recipient_capability can never cover the dimensionless row above.
        seed_consent_grant(&backend, local, peer_in, "trace:", "trace:read").await;

        // Projection-only baseline (ungated) proves the row IS advertised.
        let baseline = bridge.list_attestations(None).await;
        assert!(
            !baseline.is_empty(),
            "the seeded federation attestation is advertised in the local view"
        );

        // (a) consent-INCLUDED peer → receives the advertised plane (item 1 passes).
        let included = bridge.list_attestations(Some(peer_in)).await;
        assert_eq!(
            included.len(),
            baseline.len(),
            "a consent-included peer receives the advertised attestations"
        );

        // (b) consent-EXCLUDED peer → the WHOLE plane is withheld (item 1).
        let excluded = bridge.list_attestations(Some(peer_out)).await;
        assert!(
            excluded.is_empty(),
            "a peer absent from the consent send-set receives no attestations (CIRISEdge#396 item 1)"
        );
    }

    /// CIRISEdge#396 item 1 — fail-closed when the send-set is unresolvable: a
    /// bridge with no `local_key_id` cannot compute `list_consent_peers(local)`,
    /// so it withholds the attestation plane from every peer rather than
    /// serving unbounded (the #386 leg-B posture).
    #[tokio::test]
    async fn fan_out_fail_closed_without_local_key_id() {
        let local = "this-node";
        let producer = "agent-producer";
        let peer = "peer-consented";
        let (backend, bridge) =
            make_bridge(&[local.to_string(), producer.to_string(), peer.to_string()]);
        // NOTE: deliberately NO `with_local_key_id`.
        for key_id in [local, producer, peer] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(key_id, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        seed_advertised_attestation(&backend, producer).await;
        seed_consent_grant(&backend, local, peer, "trace:", "trace:read").await;

        // The row is advertised in the ungated view...
        assert!(
            !bridge.list_attestations(None).await.is_empty(),
            "the row is advertised projection-only"
        );
        // ...but WITHOUT a local_key_id the peer-bound serve fails closed.
        assert!(
            bridge.list_attestations(Some(peer)).await.is_empty(),
            "no local_key_id → consent send-set unresolvable → whole plane withheld (fail-closed)"
        );
    }

    /// CIRISEdge#400 — the consent send-set is memoized across a round window,
    /// so a round's advertise + N fetches share ONE `list_consent_peers` read
    /// instead of N. This is the regression witness: v14.2.0 re-read persist
    /// per envelope inside the unbounded reply assembly, blowing the 10 s round
    /// budget (100% round timeouts). Two resolves within the TTL must return the
    /// SAME `Arc`-backed set — a re-read would allocate a distinct one.
    #[tokio::test]
    async fn consent_send_set_is_memoized_within_the_round_window() {
        let local = "this-node";
        let peer = "peer-consented";
        let (backend, bridge) = make_bridge(&[local.to_string(), peer.to_string()]);
        let bridge = bridge.with_local_key_id(Some(local.to_string()));
        for key_id in [local, peer] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(key_id, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        seed_consent_membership(&backend, local, peer).await;

        let set1 = bridge.resolved_peer_set(local).await.expect("resolve 1");
        let set2 = bridge.resolved_peer_set(local).await.expect("resolve 2");
        assert!(
            set1.ptr_eq(&set2),
            "second resolve within the TTL is a memo HIT, not a per-envelope re-read (CIRISEdge#400)"
        );
        // ...and the memoized set is the real consent membership.
        assert!(
            set1.recipient(peer).is_some(),
            "the memoized set resolves the consent-included peer"
        );
    }

    /// The v13.10.0 gate this replaces was wrong TWICE, and this test is
    /// written against the inputs the FIELD produces so it cannot be wrong the
    /// same way again ([[feedback_test_field_provenance]] in anger):
    ///
    /// 1. **Wrong token** — it keyed on a bare `"observer"` string that is not
    ///    a federation capability anywhere in the stack, so the plane was
    ///    fail-closed DEAD for every peer. Now [`Self::SERVE_CAPABILITY`] is
    ///    persist's own `delegation_scope::INFRA_SERVE` const — the two sides
    ///    cannot drift apart again without a compile error.
    /// 2. **Unsound derivation** — it read claim-presence off the `roles`
    ///    vector, which persist documents as self-assertable on pre-v17.0.0
    ///    rows. The `self_asserted_*` assertions below are the regression
    ///    lock: a peer that simply WRITES `roles:["infra:serve"]` into its own
    ///    record, with no accord co-scrub behind it, is refused. The old gate
    ///    would have served it every trace on the node.
    ///
    /// **Known coverage gap (deliberate, not an oversight).** The ALLOW path is
    /// not asserted here: a record that satisfies `has_effective_role` must
    /// carry a live 2-of-3 accord-family co-scrub over its canonical
    /// registration bytes, and persist's minting helpers for that
    /// (`register_founder` / `signed_canonical_record`) are private to its own
    /// test module. Faking it with a hand-built record would re-create exactly
    /// the false confidence being fixed, so it is left to the layer that can
    /// prove it: CIRISPersist#484 (export the helper) and the field acceptance
    /// check on CIRISPersist#480 — `has_effective_role(dir, canonical,
    /// "infra:serve") == true` read on a MOBILE edge's own directory after the
    /// re-blessing ceremony, not on the server that minted it.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // seed + both peers + both paths, one coherent scenario
    async fn trace_attestation_gated_on_serve_capability() {
        let producer = "agent-mobile";
        // A peer that SELF-ASSERTS the capability: its record literally carries
        // `roles:["infra:serve"]`, with no accord co-scrub behind it — the
        // shape v13.10.0's claim-presence check would have admitted.
        let self_asserted_peer = "peer-self-asserted-serve";
        let plain_peer = "peer-no-capability";
        // The trust graph: `root` grants `infra:serve`, and WE trust `root`.
        let local = "this-node";
        let root = "trust-root-1";
        let lifecycle_attester = "accord-holder-1";
        let trusted_peer = "canonical-under-our-root";
        let (backend, bridge) = make_bridge(&[
            producer.to_string(),
            trusted_peer.to_string(),
            self_asserted_peer.to_string(),
            plain_peer.to_string(),
        ]);
        let bridge = bridge.with_local_key_id(Some(local.to_string()));

        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record(producer, identity_type::AGENT),
            })
            .await
            .expect("seed producer key");
        let mut self_asserted_rec = fixture_key_record(self_asserted_peer, identity_type::AGENT);
        self_asserted_rec.roles =
            vec![FederationDirectoryReplicationBridge::SERVE_CAPABILITY.to_string()];
        backend
            .put_public_key(SignedKeyRecord {
                record: self_asserted_rec,
            })
            .await
            .expect("seed self-asserting key");
        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record(plain_peer, identity_type::AGENT),
            })
            .await
            .expect("seed plain key");
        for (k, it) in [
            (local, identity_type::NODE),
            (root, identity_type::NODE),
            (trusted_peer, identity_type::NODE),
            (lifecycle_attester, identity_type::ACCORD_HOLDER),
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(k, it),
                })
                .await
                .expect("seed trust-graph key");
        }

        // The CIRISEdge#386 trust graph, in the shape persist's own #483
        // witness uses (field provenance — these are the exact rows
        // `capability_roots_to_trusted_root` walks):
        //   1. delegates_to(root → root, scope infra:*)   — root self-declares
        //   2. delegates_to(local → root)                 — WE trust the root
        //   3. accord:lifecycle scores about root, fresh  — root is live
        //   4. delegates_to(root → trusted_peer, infra:serve) — the grant
        let trust_edge_id = seed_root_charter(&backend, root, &[format!("{root}-successor")]).await;
        let our_trust_edge = seed_delegates_to(
            &backend,
            local,
            root,
            &serde_json::json!(["infra:attest", "infra:serve"]),
        )
        .await;
        let _ = trust_edge_id;
        seed_accord_lifecycle(&backend, lifecycle_attester, root).await;
        seed_delegates_to(
            &backend,
            root,
            trusted_peer,
            &serde_json::json!(["infra:serve"]),
        )
        .await;

        // CIRISEdge#396 item 1 — this test isolates the #386 per-ROW infra:serve
        // gate, so every peer it probes must first clear the per-PEER consent
        // membership bound: `local` consents to replicate to each (a bare grant,
        // no `recipient_capability`, so item 6 stays inert here). Without this,
        // item 1 would blanket-withhold the whole plane and mask the per-row gate.
        for peer in [self_asserted_peer, trusted_peer, plain_peer] {
            seed_consent_membership(&backend, local, peer).await;
        }

        // A trace scores-attestation (self-subject, federation tier =
        // promoted) + a NON-trace attestation for the control.
        let now = Utc::now();
        for (attestation_type, dimension) in [
            ("scores", Some("trace:complete:v1")),
            ("delegates_to", None),
        ] {
            let mut envelope = serde_json::json!({
                "attesting_key_id": producer,
                "attested_key_id": producer,
                "attestation_type": attestation_type,
            });
            if let Some(d) = dimension {
                // The persist v18.1.0 trace:* Information-Type validator
                // (CIRISPersist#479) enforces the inline shape at admission:
                // trace_id + agent_id_hash strings + a `trace` object.
                envelope["dimension"] = serde_json::json!(d);
                envelope["trace_id"] = serde_json::json!("t-fixture-1");
                envelope["agent_id_hash"] = serde_json::json!("ah-fixture-1");
                envelope["trace"] = serde_json::json!({ "steps": [] });
            }
            let (hash, ed_sig, pqc_sig) = sign_attestation_envelope(producer, &envelope);
            let att = Attestation {
                attestation_id: uuid::Uuid::new_v4().to_string(),
                attesting_key_id: producer.to_string(),
                attested_key_id: producer.to_string(),
                attestation_type: attestation_type.to_string(),
                weight: None,
                asserted_at: now,
                expires_at: None,
                attestation_envelope: envelope,
                original_content_hash: hash,
                scrub_signature_classical: ed_sig,
                scrub_signature_pqc: pqc_sig,
                scrub_key_id: producer.to_string(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                subject_key_ids: vec![producer.to_string()],
                withdraws_admission_rule: None,
                cohort_scope: "federation".to_string(),
                tier: "federation".to_string(),
                promoted_at: None,
            };
            backend
                .put_attestation(SignedAttestation { attestation: att })
                .await
                .expect("seed attestation");
        }

        // Identify the trace row by CONTENT, not by counting — the trust-graph
        // rows seeded above live in this same plane, so any count is brittle.
        let trace_hash = locate_trace_hash(&bridge).await;

        // Every peer WITHOUT both legs is refused the trace row, on BOTH paths,
        // while non-trace rows keep flowing to them (the gate is per-row):
        //   - self_asserted_peer: writes `roles:["infra:serve"]` into its own
        //     record with no accord co-scrub — the shape v13.10.0 served.
        //   - trust_rooted_peer:  genuinely rooted under a root we trust, but
        //     NOT accord-conferred — proves leg A is a required conjunct.
        //   - plain_peer:         neither.
        for peer in [self_asserted_peer, trusted_peer, plain_peer] {
            let refs = bridge
                .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(peer))
                .await;
            assert!(
                !refs.iter().any(|r| r.envelope_hash == trace_hash),
                "{peer} must NOT be offered the trace attestation — it lacks the \
                 accord-conferred `infra:serve` (CIRISEdge#386 leg A)"
            );
            assert!(
                !refs.is_empty(),
                "{peer} still receives the non-trace rows — the gate is per-row, \
                 not a blanket refusal"
            );
            assert!(
                bridge
                    .fetch_envelope_bytes_for_peer(
                        EnvelopeKind::Attestation,
                        &trace_hash,
                        Some(peer)
                    )
                    .await
                    .is_none(),
                "{peer} must not obtain the trace envelope by hash either \
                 (out-of-band Diff/Fetch bypass, CIRISEdge#379)"
            );
        }
        let _ = our_trust_edge;
    }

    /// CIRISEdge#386 — the ALLOW path, and the proof that BOTH legs are
    /// required. Gated on `test-anchor` because minting a record that satisfies
    /// `has_effective_role` needs a genuine 2-of-3 accord-family co-scrub, which
    /// persist exports only behind that fence (CIRISPersist#484). Edge CI runs a
    /// dedicated `test-anchor` lane, so this is real coverage — not a test that
    /// quietly never runs.
    ///
    /// This is the assertion whose ABSENCE let v13.10.0 ship a permanently-dark
    /// gate with a green suite.
    #[cfg(feature = "test-anchor")]
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // roster + trust graph + allow/deny/un-trust: one scenario
    async fn trace_serve_requires_accord_blessing_and_trusted_root() {
        use ciris_persist::federation::accord_test_support::{
            register_accord_holder, signed_canonical_record_with_roles, Identity,
        };
        // The roster key_ids `has_effective_role` resolves against. Persist's
        // own `accord_holder_roster_key_ids` is private, but it is derived from
        // this public genesis accessor — so we mint identities under exactly
        // those key_ids and the co-scrub verifies against the real roster.
        use ciris_persist::federation::genesis::effective_accord_holder_records;

        let producer = "agent-mobile";
        let local = "this-node";
        let root = "trust-root-1";
        let lifecycle_attester = "accord-holder-live";
        // Blessed by the accord AND rooted under a root we trust → served.
        let full_peer = "canonical-blessed-and-rooted";
        // Blessed by the accord but rooted nowhere we trust → refused (leg B).
        let blessed_only = "canonical-blessed-not-rooted";
        let (backend, bridge) = make_bridge(&[
            producer.to_string(),
            full_peer.to_string(),
            blessed_only.to_string(),
        ]);
        let bridge = bridge.with_local_key_id(Some(local.to_string()));

        // The live accord family, registered at their PINNED pubkeys so the
        // co-scrub verifies against the real roster.
        let holders: Vec<Identity> = effective_accord_holder_records()
            .iter()
            .map(|r| Identity::new(&r.record.key_id))
            .collect();
        assert!(
            holders.len() >= 2,
            "the accord family must resolve to at least a 2-of-n roster"
        );
        for h in &holders {
            register_accord_holder(&*backend, h)
                .await
                .expect("register accord holder");
        }
        let scrubbers = [&holders[0], &holders[1]];

        for (k, it) in [
            (producer, identity_type::AGENT),
            (local, identity_type::NODE),
            (root, identity_type::NODE),
            (lifecycle_attester, identity_type::ACCORD_HOLDER),
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(k, it),
                })
                .await
                .expect("seed key");
        }
        // Both candidate recipients carry a GENUINE 2-of-3 accord co-scrub
        // conferring `infra:serve` — leg A holds for both.
        for peer in [full_peer, blessed_only] {
            let rec = signed_canonical_record_with_roles(
                peer,
                identity_type::NODE,
                vec![FederationDirectoryReplicationBridge::SERVE_CAPABILITY.to_string()],
                serde_json::json!({ "key_id": peer }),
                &scrubbers,
            );
            backend
                .put_public_key(SignedKeyRecord { record: rec })
                .await
                .expect("seed co-scrubbed recipient");
        }

        // Trust graph: root self-declares, WE trust it, it is live, and it
        // grants `infra:serve` to full_peer ONLY.
        seed_root_charter(&backend, root, &[format!("{root}-successor")]).await;
        let our_trust_edge = seed_delegates_to(
            &backend,
            local,
            root,
            &serde_json::json!(["infra:attest", "infra:serve"]),
        )
        .await;
        seed_accord_lifecycle(&backend, lifecycle_attester, root).await;
        seed_delegates_to(
            &backend,
            root,
            full_peer,
            &serde_json::json!(["infra:serve"]),
        )
        .await;

        seed_trace_attestation(&backend, producer).await;
        let trace_hash = locate_trace_hash(&bridge).await;

        // ALLOW — accord-blessed AND rooted under a root we trust.
        assert!(
            bridge
                .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(full_peer))
                .await
                .iter()
                .any(|r| r.envelope_hash == trace_hash),
            "a recipient with an accord-conferred `infra:serve` that ALSO roots to \
             a root this node trusts receives the trace row"
        );
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(
                    EnvelopeKind::Attestation,
                    &trace_hash,
                    Some(full_peer)
                )
                .await
                .is_some(),
            "...and can fetch its bytes"
        );

        // DENY — accord-blessed but rooted nowhere we trust (leg B required).
        assert!(
            !bridge
                .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(blessed_only))
                .await
                .iter()
                .any(|r| r.envelope_hash == trace_hash),
            "an accord blessing alone is NOT sufficient — the capability must root \
             to a root this node trusts (CIRISEdge#386 leg B)"
        );

        // NUCLEAR UN-TRUST — withdrawing OUR `delegates_to(local → root)` edge
        // stops serving every peer that rooted through it, immediately, with
        // nothing else in the graph changed and no cache to go stale. This is
        // the property an OR-composition would have destroyed.
        seed_withdraws(&backend, local, &our_trust_edge).await;
        assert!(
            !bridge
                .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(full_peer))
                .await
                .iter()
                .any(|r| r.envelope_hash == trace_hash),
            "un-trusting the root stops serving traces to peers that rooted through it"
        );
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(
                    EnvelopeKind::Attestation,
                    &trace_hash,
                    Some(full_peer)
                )
                .await
                .is_none(),
            "un-trust closes the fetch path too, not just the listing"
        );
    }

    // ── v2 operational-data (FSD §5.2 / CEG 1.0-RC2 §5.6.8.13) ──────

    /// CIRISEdge#397 — `content_hash_of` is `sha256(serde_json::to_vec(value))`:
    /// deterministic (a federation invariant — two peers hash the same on-wire
    /// bytes identically), returns those exact bytes alongside the hash, and
    /// discriminates distinct values. Byte-exact with persist's
    /// `wire_index::content_hash_of`, the lockstep fact the point-read depends on.
    #[test]
    fn content_hash_of_hashes_the_to_vec_bytes() {
        let value = serde_json::json!({
            "organization": { "attestation_id": "att-1", "org_id": "org-acme" }
        });
        let (h1, bytes1) = content_hash_of(&value).expect("hash 1");
        let (h2, _bytes2) = content_hash_of(&value).expect("hash 2");
        assert_eq!(h1, h2, "deterministic");
        // The returned bytes ARE serde_json::to_vec, and the hash is their sha256.
        assert_eq!(bytes1, serde_json::to_vec(&value).unwrap());
        assert_eq!(<[u8; 32]>::from(Sha256::digest(&bytes1)), h1);
        // Distinct values → distinct hashes.
        let (hb, _) = content_hash_of(&serde_json::json!({"org_id": "bob"})).expect("hash b");
        let (hc, _) = content_hash_of(&serde_json::json!({"org_id": "alice"})).expect("hash c");
        assert_ne!(hb, hc);
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
