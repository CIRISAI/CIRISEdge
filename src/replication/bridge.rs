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
use ciris_persist::federation::admission::has_accord_conferred_role;
use ciris_persist::federation::consent_grammar::{self, ConsentTransferPolicy};
use ciris_persist::federation::namespace::{self, Projection};
use ciris_persist::federation::operational::{
    OrgMembership, Organization, SignedOrgMembership, SignedOrganization, SignedPartnerRecord,
};
use ciris_persist::federation::register::{KeyRefusalReason, ReplicatedKeyOutcome};
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
use super::summary::ApplyOutcome;

// ─── CIRISEdge#423 → #425 — apply-refusal diagnostics, now by construction ──
//
// The `apply_*` family once collapsed BOTH failure arms of "deserialize the
// delivered bytes, then admit the record" to a silent `false`: a malformed
// envelope was dropped with `Err(_) => false` (reason discarded), and an admission
// REFUSAL — with its typed reason (`FederationTierUnverified`, …) — collapsed to
// `false` too. #423 made each arm log LOUDLY at the bridge; but that fix MISSED
// three sites in this very file (the `if self.operational.is_none() { return
// false }` early returns sit ABOVE the helpers), which is the argument for a
// STRUCTURAL cure. #425: every `apply_*` now returns an [`ApplyOutcome`] carrying
// its reason, and the SINGLE choke point `session::on_deliver` logs it. A future
// `apply_*` branch cannot add a silent `return false` — `ApplyOutcome` is
// `#[must_use]` and there is no `false` to return. These helpers just BUILD the
// reason string (the logging lives at the choke point, so no double-log).

/// The `Deserialize` reason for a delivered envelope that failed to parse: the
/// wire-bytes hash (correlates with the delivered frame) + the serde error.
fn apply_deser_reason(plane: &str, bytes: &[u8], err: &serde_json::Error) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "{plane}: deserialize failed (bytes={}, wire_hash={}): {err}",
        bytes.len(),
        hex::encode(Sha256::digest(bytes)),
    )
}

/// The `Refused` reason for a well-formed envelope a gate declined: the record's
/// content hash (the value persist's `signed_wire_index` keys on — correlates with
/// the offered `EnvelopeRef` + a direct `put_*`) + the typed refusal token
/// ([`ciris_persist::federation::Error::kind`]).
/// CIRISEdge#441 — the removal-class planes: every kind whose rows REMOVE
/// standing (revocations + membership revocations). Attestation-plane
/// `withdraws`/`recants` rows are the named follow-up (they need content
/// inspection at the ref tier; kind-level covers the four typed planes).
#[must_use]
pub fn is_removal_kind(kind: EnvelopeKind) -> bool {
    matches!(
        kind,
        EnvelopeKind::Revocation
            | EnvelopeKind::IdentityOccurrenceRevocation
            | EnvelopeKind::FamilyMembershipRevocation
            | EnvelopeKind::CommunityMembershipRevocation
    )
}

fn apply_refusal_reason(
    plane: &str,
    content_hash: &str,
    err: &ciris_persist::federation::Error,
) -> String {
    format!(
        "{plane}: admission refused (content_hash={content_hash}, refusal={}): {err}",
        err.kind(),
    )
}

/// persist v24.2.0 (CIRISPersist#565) — map the typed Key-plane apply outcome to
/// edge's [`ApplyOutcome`], returning alongside it the stable refusal TOKEN to
/// count on the receive-plane mirror ledger (`None` when nothing was refused).
///
/// Pure so the whole mapping is unit-testable over [`KeyRefusalReason::ALL`]
/// without a backend. Two load-bearing decisions:
///
/// - **Both duplicate halves map to `Duplicate`** (persist's #565 finding, not
///   just the ask): a byte-identical re-offer already resolved `Unchanged` at
///   the `persist_row_hash` comparison, and `AlreadyAnchoredIdentical` is its
///   sibling — a same-envelope-DIFFERENT-BYTES legitimate re-encoding of a
///   record this node already anchors (every baked-seed node re-offered the
///   canonical's own record hits it). Before v24.2.0 that read as a
///   security-shaped refusal on the COMMON path. Neither half counts on the
///   refusal ledger: the receiver already holds what was offered.
/// - **The reason is the branch**: the refusal message carries persist's stable
///   token (`pubkey_swap`, `downgrade`, …) — the #565 twin of the #433 rule.
///   Consumers key on the token constant, never on message prose.
fn key_outcome_to_apply(
    result: Result<ReplicatedKeyOutcome, ciris_persist::federation::Error>,
    content_hash: &str,
) -> (ApplyOutcome, Option<&'static str>) {
    match result {
        Ok(
            ReplicatedKeyOutcome::Inserted
            | ReplicatedKeyOutcome::Upgraded
            | ReplicatedKeyOutcome::Superseded,
        ) => (ApplyOutcome::Admitted, None),
        Ok(
            ReplicatedKeyOutcome::Unchanged
            | ReplicatedKeyOutcome::Refused {
                reason: KeyRefusalReason::AlreadyAnchoredIdentical,
            },
        ) => (ApplyOutcome::Duplicate, None),
        Ok(ReplicatedKeyOutcome::Refused { reason }) => (
            ApplyOutcome::Refused(format!(
                "Key: admission refused ({}; content_hash={content_hash})",
                reason.as_str()
            )),
            Some(reason.as_str()),
        ),
        Err(e) => (
            ApplyOutcome::Refused(apply_refusal_reason("Key", content_hash, &e)),
            None,
        ),
    }
}

static SERVE_GATE_WITHHELD_LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> =
    std::sync::OnceLock::new();

/// CIRISEdge#425 Exhibit A — a serve-gate refusal WITHHOLDS an entire plane (every
/// `trace:*` attestation) from a peer. That is a `warn!`, never `debug!`: a node at
/// default log levels was silently withholding every trace FOREVER, indistinguishable
/// from "there was nothing to send" (the round reported `completed`, `envelopes_sent=0`
/// — perfect health, zero carriage). Throttled to a FLOOR — a few per five minutes
/// per (peer, reason), a PERIODIC repeat that resets each window, NEVER to silence:
/// a persistently-dark plane is exactly the failure you must not go quiet about.
fn serve_gate_withheld_log() -> &'static crate::log_throttle::LogThrottle {
    SERVE_GATE_WITHHELD_LOG
        .get_or_init(|| crate::log_throttle::LogThrottle::new(3, Duration::from_secs(300), 256))
}

/// CIRISEdge#425 — a single-shape plane: deserialize `$ty`, admit via `$put`, and
/// yield an [`ApplyOutcome`] (never a silent `false`). `Ok(())` from persist means
/// admitted-or-idempotent-dedupe (matching the old `is_ok()`); a gate `Err`
/// becomes `Refused(reason)`; a parse failure becomes `Deserialize(reason)`.
macro_rules! apply_signed_plane {
    ($self:expr, $plane:literal, $bytes:expr, $ty:ty, $put:ident) => {
        match serde_json::from_slice::<$ty>($bytes) {
            Ok(record) => {
                let content_hash =
                    content_hash_of(&record).map_or_else(String::new, |(h, _)| hex::encode(h));
                match $self.directory.$put(record).await {
                    Ok(()) => ApplyOutcome::Admitted,
                    Err(e) => {
                        ApplyOutcome::Refused(apply_refusal_reason($plane, &content_hash, &e))
                    }
                }
            }
            Err(e) => ApplyOutcome::Deserialize(apply_deser_reason($plane, $bytes, &e)),
        }
    };
}

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

/// CIRISEdge#440 ask 3 — one author's memoized quarantine consult within a
/// single sweep/fetch. A tri-state on purpose: `Withheld` and `ReadError` both
/// withhold, but they are DIFFERENT facts booking DIFFERENT
/// [`crate::observability::WithholdReason`]s (#433 — a reason is a branch,
/// never a disjunction), and collapsing them to a `bool` at the memo would
/// re-create exactly the fold this ledger exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuarantineConsult {
    /// No live withhold marker governs the author.
    Clear,
    /// A live `quarantine:withheld:v1` marker governs the author.
    Withheld,
    /// The consult failed; fail-closed for this sweep, reported as a read
    /// error.
    ReadError,
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
    /// CIRISEdge#433 — the live metrics handle backing the WITHHOLD LEDGER + the
    /// replication-plane served counter. `None` makes every increment a no-op, so
    /// the (extensive) test constructions below stay untouched; every PRODUCTION
    /// construction site threads `Edge`'s handle in via [`Self::with_metrics`].
    metrics: Option<crate::observability::EdgeMetrics>,
    /// CIRISEdge#430 — observer called with the revoked `key_id` after an
    /// ADMITTED Revocation apply. The transit gate's event-driven cache
    /// invalidation rides this (an in-band un-trust must drop cached hop
    /// verdicts before any TTL would); the bridge knows nothing about who
    /// listens. `None` ⇒ no listener (tests, non-A/V deployments).
    revocation_observer: Option<RevocationObserver>,
    /// CIRISEdge#440 — the resolved mesh-config read seam. `Some` lets a root's
    /// TTL'd relief shrink the since-page limit
    /// ([`Self::effective_page_limit`]) and pause the `trace:*` plane
    /// (`feature.trace_replication=0` ⇒ the advertise sweep + direct-fetch twin
    /// withhold, booking [`crate::observability::WithholdReason::ConfigPaused`]).
    /// `None` — every test construction and any host without a `local_key_id` —
    /// is byte-identical pre-#440 behavior (relief, not a gate).
    mesh_config: Option<Arc<crate::replication::mesh_config::MeshConfigReader>>,
}

/// CIRISEdge#430 — the revoked-key listener installed via
/// [`FederationDirectoryReplicationBridge::with_revocation_observer`]: called
/// with the revoked `key_id` after each ADMITTED Revocation apply.
pub type RevocationObserver = Arc<dyn Fn(&str) + Send + Sync>;

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
            metrics: None,
            revocation_observer: None,
            mesh_config: None,
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
            metrics: None,
            revocation_observer: None,
            mesh_config: None,
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

    /// CIRISEdge#433 — install the live metrics handle (builder), enabling the
    /// withhold ledger + the replication-plane served counter.
    /// [`crate::observability::EdgeMetrics`] is `Clone` and `Arc`-backed, so the
    /// bridge shares the SAME counters the rest of the edge writes.
    ///
    /// Takes an `Option` to match its two sibling builders
    /// ([`Self::with_self_provider`] / [`Self::with_local_key_id`]), which both
    /// carry an operator-supplied `Option` straight through from
    /// `ReplicationRuntimeConfig`. `None` makes every increment a no-op.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Option<crate::observability::EdgeMetrics>) -> Self {
        self.metrics = metrics;
        self
    }

    /// CIRISEdge#430 — install the revoked-key observer (called with the revoked
    /// `key_id` after an ADMITTED Revocation apply). The transit gate's
    /// `TransitGate::invalidate`
    /// is the intended listener; the TTL remains the backstop when no observer
    /// is wired.
    #[must_use]
    pub fn with_revocation_observer(mut self, observer: Option<RevocationObserver>) -> Self {
        self.revocation_observer = observer;
        self
    }

    /// CIRISEdge#440 — install the resolved mesh-config reader (builder). An
    /// `Option` like its siblings: the runtime threads `Some` only when it has
    /// a `local_key_id` to fold for; `None` keeps every consumer on its exact
    /// pre-#440 path.
    #[must_use]
    pub fn with_mesh_config(
        mut self,
        reader: Option<Arc<crate::replication::mesh_config::MeshConfigReader>>,
    ) -> Self {
        self.mesh_config = reader;
        self
    }

    /// CIRISEdge#440 — the since-page limit this sweep runs under:
    /// the configured [`BridgeConfig::operational_page_limit`], shrunk to a
    /// live `antientropy.page_limit` relief when one is resolved. `min`, never
    /// replacement — relief can only shrink a page (relieve-never-expand,
    /// enforced again here against the configured value in case the operator's
    /// limit is already tighter than the relieved one). One cached read per
    /// round-ish window (the reader's TTL), not per row.
    async fn effective_page_limit(&self) -> u32 {
        match &self.mesh_config {
            None => self.config.operational_page_limit,
            Some(reader) => reader
                .relief()
                .await
                .page_limit
                .map_or(self.config.operational_page_limit, |relieved| {
                    relieved.min(self.config.operational_page_limit)
                }),
        }
    }

    /// CIRISEdge#440 — is the `trace:*` plane paused by a live
    /// `feature.trace_replication=0` relief? `false` on every absence path.
    async fn trace_plane_paused(&self) -> bool {
        match &self.mesh_config {
            None => false,
            Some(reader) => reader.relief().await.trace_replication_paused,
        }
    }

    /// CIRISEdge#440 — book ONE `ConfigPaused` withhold + its named, throttled
    /// WARN. Shared by the advertise sweep (booked once per sweep) and the
    /// direct-fetch twin (booked per refused fetch); `site` keeps the two
    /// throttle keys distinct so neither exit can silence the other's log.
    fn withhold_config_paused(&self, peer_label: &str, site: &str) {
        self.withhold(
            crate::observability::WithholdReason::ConfigPaused,
            peer_label,
            "feature.trace_replication=0",
        );
        if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
            serve_gate_withheld_log().check(&format!("{peer_label}:{site}"))
        {
            tracing::warn!(
                peer = peer_label,
                suppressed_prev,
                site,
                "trace plane PAUSED by mesh config — a trust root relieved \
                 `feature.trace_replication` to 0, so `trace:*` rows are withheld \
                 until the relief expires or is superseded (CIRISEdge#440)"
            );
        }
    }

    /// CIRISEdge#433 — record ONE withhold against the ledger. A no-op when no
    /// metrics handle is installed, so every gate below can call it
    /// unconditionally and no test construction has to care.
    ///
    /// Called at the BRANCH, never at a join point: the ledger's contract is that
    /// the reason is the branch, not a disjunction over the reasons that might
    /// have applied.
    fn withhold(&self, reason: crate::observability::WithholdReason, peer: &str, detail: &str) {
        if let Some(m) = self.metrics.as_ref() {
            m.inc_withhold(reason, peer, detail);
        }
    }

    /// CIRISEdge#433 — the short, low-cardinality `detail` for a hash-addressed
    /// withhold: the kind plus an 8-byte hash prefix (the same prefix the #379
    /// withheld-trace log already carries, so a ledger entry and a log line join).
    fn withhold_detail(kind: EnvelopeKind, envelope_hash: &[u8; 32]) -> String {
        format!(
            "{}:{}",
            kind.as_wire_str(),
            hex::encode(&envelope_hash[..8])
        )
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
        let refs = self.list_envelope_refs_inner(kind).await;
        // CIRISEdge#441 — removal-class rows enter the receipt ledger the
        // moment they are advertisable; the serve exit records offers and
        // the coordinator's Summary observer records protocol-native acks.
        if is_removal_kind(kind) {
            if let Some(m) = self.metrics.as_ref() {
                for r in &refs {
                    m.removal_track(kind, r.envelope_hash);
                }
            }
        }
        refs
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

    /// CIRISEdge#416 — RAW holdings for the RECEIVE-diff axis. The Attestation
    /// plane uses the unfiltered [`Self::list_attestation_holdings`] ("what I
    /// hold"), NOT the projection-filtered advertise view; every other plane's
    /// advertise view equals its holdings for round convergence, so they keep the
    /// default ([`Self::list_envelope_refs`]).
    async fn list_holdings(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        match kind {
            EnvelopeKind::Attestation => self.list_attestation_holdings().await,
            _ => self.list_envelope_refs(kind).await,
        }
    }

    /// CIRISEdge#474 — serve an accord-quorum-evidence cursor pull. The plane has
    /// no content-hash `signed_wire_index`, so this is its ONLY serve path: read
    /// persist's `list_signed_accord_quorum_evidence_since` (ordered `(evidence_at,
    /// proposal_digest)`, bounded by the page limit) and JSON-serialize each bundle
    /// exactly as the apply side (`apply_accord_quorum_evidence`) deserializes it —
    /// the byte-for-byte round trip persist's re-tally admit expects. A read error
    /// is a loud empty (the round re-pulls next pass), never a panic. Non-cursor
    /// kinds return empty: they converge over Summary/Diff/Fetch, not here.
    async fn accord_evidence_since(
        &self,
        kind: EnvelopeKind,
        since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Vec<Vec<u8>> {
        if kind != EnvelopeKind::AccordQuorumEvidence {
            return Vec::new();
        }
        let limit = self.effective_page_limit().await;
        match self
            .directory
            .list_signed_accord_quorum_evidence_since(since, limit)
            .await
        {
            Ok(bundles) => bundles
                .iter()
                .filter_map(|b| serde_json::to_vec(b).ok())
                .collect(),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "accord-quorum-evidence cursor serve read failed (CIRISEdge#474)"
                );
                Vec::new()
            }
        }
    }

    /// CIRISEdge#462 — serve a subject-scoped RECEIVE-axis Pull. Entitlement is
    /// FAIL-CLOSED: a Pull for subject `S` is answered only to a requester
    /// authenticated AS `S` (`peer_key_id == Some(S)`). A requester `P ≠ S` — or
    /// an unattributed one — gets nothing, and it says so. (Owner-delegation, a
    /// node key pulling for its owner fedID, needs `owner_of` and is a deliberate
    /// follow-up, not silently permitted here.) The refs themselves come from
    /// [`Self::subject_holdings_inner`], which hashes the SAME struct the wire
    /// index keys on and applies the G2 capacity carve.
    async fn subject_holdings(
        &self,
        kind: EnvelopeKind,
        subject_key_id: &str,
        peer_key_id: Option<&str>,
    ) -> Vec<EnvelopeRef> {
        match peer_key_id {
            Some(p) if p == subject_key_id => {
                self.subject_holdings_inner(kind, subject_key_id).await
            }
            other => {
                tracing::warn!(
                    subject = %subject_key_id,
                    requester = ?other,
                    kind = ?kind,
                    "subject Pull refused: requester is not the subject — serving nothing \
                     (#462 fail-closed; owner-delegation via owner_of is a follow-up)"
                );
                Vec::new()
            }
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
        // CIRISEdge#433 / #429 — the requester asked for a hash we just claimed to
        // hold and we cannot resolve it to bytes. This is the bridge-level ORIGIN
        // of the advertised-then-unfetchable event `session::pack_bounded_deliver`
        // reports in its `dropped` set (every entry there is this `None`); counting
        // it HERE keeps it disjoint from the policy gates below — "we could not
        // find it" never hides inside "we chose not to serve it". The `detail`
        // string is built INSIDE the branch: this is the per-envelope serve path,
        // and the happy path must not pay for an attribution nobody reads.
        let Some(bytes) = self.fetch_envelope_bytes(kind, envelope_hash).await else {
            self.withhold(
                crate::observability::WithholdReason::EnvelopeUnfetchable,
                peer_key_id.unwrap_or("<unattributed>"),
                &Self::withhold_detail(kind, envelope_hash),
            );
            return None;
        };
        if kind == EnvelopeKind::Attestation {
            // CIRISEdge#440 — the direct-fetch twins of the advertise-sweep
            // pause + quarantine gates, so a peer cannot obtain a paused
            // `trace:*` row or a quarantined author's row by Diff/Fetch-ing a
            // hash it learned out-of-band (the same twin discipline #379/#396
            // established). Parse tolerance matches the sweep: an unparseable
            // wire row is not gated here (the existing gates below keep their
            // own parse-and-tolerate shape untouched).
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                let inner = value.get("attestation").unwrap_or(&value);
                let peer_label = peer_key_id.unwrap_or("<unattributed>");
                if Self::attestation_requires_serve(inner) && self.trace_plane_paused().await {
                    self.withhold_config_paused(peer_label, "config-paused-fetch");
                    return None;
                }
                if self
                    .author_quarantine_withholds(inner, &mut HashMap::new(), peer_label)
                    .await
                {
                    return None;
                }
            }
            if let Some(peer) = peer_key_id {
                // v16 review: FIRST-PARTY right overrides #396 producer-advertise-
                // consent. If `peer` is this attestation's AUTHOR or DATA-SUBJECT it is
                // fetching its OWN testimony — the same first-party carve the subject-
                // Pull LIST gate (`pull_ref_is_serveable`) applies — so list and fetch
                // AGREE (no advertised-then-unfetchable, no ref disclosed-then-withheld).
                // For a first-party fetch the recipient IS the peer; #396 item-1
                // consent-membership and item-6 recipient_capability do not apply. The
                // E3 trace serve-cap gate below STILL does (a subject pulling its own
                // `trace:*` row needs `infra:serve`, exactly as the list requires).
                let first_party = serde_json::from_slice::<serde_json::Value>(&bytes)
                    .ok()
                    .is_some_and(|v| {
                        Self::attestation_is_first_party_to(
                            v.get("attestation").unwrap_or(&v),
                            peer,
                        )
                    });
                // #396 item 1 — the same consent-membership bound the listing applies,
                // so a THIRD-party peer excluded from the advertise cannot obtain an
                // attestation by fetching a hash it learned out-of-band. Fail-closed:
                // no `ResolvedRecipient`, no bytes. (#433: `resolve_attestation_recipient`
                // books its OWN branch's reason — no re-count here.)
                let recipient: String = if first_party {
                    peer.to_owned()
                } else {
                    self.resolve_attestation_recipient(peer)
                        .await?
                        .as_str()
                        .to_owned()
                };
                // #379 `infra:serve` + #396 item 6 `recipient_capability`, over the WIRE
                // bytes — the direct-fetch twins of the listing gates. The wire is the
                // BARE `Attestation` (§3); tolerate the legacy `{"attestation": …}` wrap.
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    let inner = value.get("attestation").unwrap_or(&value);
                    if Self::attestation_requires_serve(inner)
                        && !self.peer_has_serve_capability(&recipient).await
                    {
                        // #433: `peer_has_serve_capability` books the specific leg
                        // (no-role / read-error / not-rooted / walk-error) — its
                        // `bool` return is exactly the disjunction the ledger must
                        // not report, so this site logs and does not count.
                        tracing::debug!(
                            peer,
                            envelope_hash = %hex::encode(&envelope_hash[..8]),
                            "trace attestation withheld — recipient lacks an effective \
                             `infra:serve` capability (CIRISEdge#379)"
                        );
                        return None;
                    }
                    // #396 item 6 — recipient_capability gates a THIRD-party recipient
                    // (an author-chosen audience). A first-party subject/author is not
                    // such a recipient, so it does not apply (matches the list gate).
                    if !first_party
                        && self
                            .recipient_capability_withholds(inner, &recipient, &mut HashMap::new())
                            .await
                    {
                        // #433 — item 6 was the purest silent withhold on this path.
                        // Countable now, booked inside `recipient_capability_withholds`
                        // at the deciding branch, so this site does not re-count.
                        return None;
                    }
                }
            }
        }
        // CIRISEdge#433 — the replication plane's metric-visible moment. This is
        // where the bridge hands the wire bytes back to `pack_bounded_deliver`;
        // every gate has cleared and local state resolved the row, so THIS layer's
        // part of the transaction is definitely complete. Mirrors the CIRISEdge#28
        // precedent (`edge.rs`: "durable enqueue is the metric-visible moment"):
        // count where success is definite for the layer doing the counting, not at
        // a peer acknowledgement this layer never observes. Two known, deliberate
        // imprecisions, both bounded and both in the honest direction: the caller
        // may drop the LAST fetched envelope when it would exceed
        // `MAX_DELIVER_ENVELOPE_BYTES` (at most one per Deliver, re-served next
        // round), and a Deliver frame lost in flight still counts as served — the
        // same semantics `envelopes_sent_total` has carried since v0.19.0.
        if let Some(m) = self.metrics.as_ref() {
            m.inc_replication_served(kind);
            // CIRISEdge#441 — a removal-class serve is an OFFER in the receipt
            // ledger: this peer was handed the row; the ack arrives when its
            // own next Summary advertises the hash.
            if is_removal_kind(kind) {
                if let Some(p) = peer_key_id {
                    m.removal_offer(
                        kind,
                        *envelope_hash,
                        p,
                        u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0),
                    );
                }
            }
        }
        Some(bytes)
    }

    async fn apply_envelope_bytes(
        &self,
        kind: EnvelopeKind,
        envelope_bytes: &[u8],
        source_peer: Option<&str>,
    ) -> ApplyOutcome {
        // CIRISEdge#426 — the authenticated sender now REACHES the apply layer (it
        // was dropped upstream, which made the consent plane send-only). The actual
        // per-peer write enforcement lives in persist v22's put-gates + AV-76
        // per-peer quota (a Sybil's forged/self-emitted rows are refused there and
        // surface as a loud `Refused` via the #425 choke point); this trace records
        // that the receive is attributed, so a per-peer edge policy is now
        // expressible on top of a peer that is present rather than discarded.
        tracing::trace!(
            kind = ?kind,
            source_peer = source_peer.unwrap_or("<unattributed>"),
            "apply_envelope_bytes: receiving from attributed peer (CIRISEdge#426)"
        );
        // persist v24.2.0 / #565 — the receive-plane mirror's kind axis: every
        // `Refused` leaving this choke is counted per envelope kind (the #425
        // choke already logs it; now it is also a metrics-scrape fact). The
        // typed Key-plane token axis books inside `apply_key`.
        let outcome = self.dispatch_apply(kind, envelope_bytes).await;
        // CIRISEdge#457 — the receive plane now books EVERY outcome at this
        // choke, not just refusals: an accepted apply (Admitted = new state)
        // and a duplicate (already held) are counted distinctly, so "applied
        // all N" and "offered nothing" no longer both read `{}` (the #433
        // distinct-states rule, on the receive side; the mirror of #434).
        if let Some(m) = &self.metrics {
            match &outcome {
                ApplyOutcome::Admitted => m.inc_applied(kind),
                ApplyOutcome::Duplicate => m.inc_duplicate(kind),
                ApplyOutcome::Refused(_) => m.inc_apply_refusal_kind(kind),
                // Deserialize is a malformed-bytes drop, not an apply outcome
                // on a well-formed row — it stays uncounted here (the choke's
                // `on_deliver` logs it loud; a metrics kind-count of undecodable
                // bytes would conflate wire corruption with a policy decision).
                ApplyOutcome::Deserialize(_) => {}
            }
        }
        outcome
    }
}

impl FederationDirectoryReplicationBridge {
    async fn list_envelope_refs_inner(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef> {
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
            // CIRISEdge#474 — the accord-quorum-evidence plane is NEVER advertised
            // by content-hash: it has no `signed_wire_index` entry
            // (`persist_index_kind` → None), so a ref here would be listed-then-
            // unfetchable (the LIST-vs-FETCH divergence class). It converges over
            // the dedicated cursor path (`CursorPull` → `Deliver`) instead.
            EnvelopeKind::AccordQuorumEvidence => Vec::new(),
        }
    }

    /// CIRISEdge#462 — the subject-scoped RECEIVE-axis ref builder (entitlement
    /// already checked by [`Self::subject_holdings`]). For each replicated kind
    /// it calls the SAME per-subject persist read `list_signed_records` composes,
    /// but hashes the returned STRUCT with [`content_hash_of`] — the wire index
    /// keys on `sha256(to_vec(row))`, whereas `list_signed_records`' `to_value`
    /// canonical JSON re-orders keys (no serde_json `preserve_order`) and would
    /// not resolve through the content-hash fetch path. So the refs here are the
    /// index's own hashes by construction, and the unchanged Diff/Deliver flow
    /// (re-gated per record by `fetch_envelope_bytes_for_peer`) serves them.
    /// (CIRISPersist#634 asks for a subject-scoped wire-index read that would
    /// return these index hashes directly and retire this compose-and-rehash.)
    ///
    /// The Attestation plane sweeps BOTH testimonial axes: `list_attestations_for`
    /// (records ABOUT the subject — the revocation-reachability set, with the G2
    /// [`Self::is_non_retainable_score`] carve) and `list_attestations_by`
    /// (records BY the subject — authorship recovery, no carve: mine to recover).
    /// Non-replicated / cohort kinds are not subject-pullable and return empty.
    async fn subject_holdings_inner(
        &self,
        kind: EnvelopeKind,
        subject_key_id: &str,
    ) -> Vec<EnvelopeRef> {
        let mut refs: Vec<EnvelopeRef> = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut push = |hash: [u8; 32], seq: u64| {
            if seen.insert(hash) {
                refs.push(EnvelopeRef {
                    envelope_hash: hash,
                    seq,
                });
            }
        };
        match kind {
            EnvelopeKind::Key => {
                if let Ok(Some(record)) = self.directory.lookup_public_key(subject_key_id).await {
                    let seq = Self::ms_seq(record.valid_from);
                    if let Some((hash, _)) = content_hash_of(&SignedKeyRecord { record }) {
                        push(hash, seq);
                    }
                }
            }
            EnvelopeKind::IdentityOccurrence => {
                for row in self
                    .directory
                    .list_signed_identity_occurrences_for(subject_key_id)
                    .await
                    .unwrap_or_default()
                {
                    let seq = Self::ms_seq(row.identity_occurrence.asserted_at);
                    if let Some((hash, _)) = content_hash_of(&row) {
                        push(hash, seq);
                    }
                }
            }
            EnvelopeKind::TransportDestination => {
                for row in self
                    .directory
                    .list_signed_transport_destinations_for(subject_key_id)
                    .await
                    .unwrap_or_default()
                {
                    let td = &row.transport_destination;
                    let seq = if td.epoch > 0 {
                        td.epoch
                    } else {
                        Self::ms_seq(td.asserted_at)
                    };
                    if let Some((hash, _)) = content_hash_of(&row) {
                        push(hash, seq);
                    }
                }
            }
            EnvelopeKind::IdentityOccurrenceRevocation => {
                for row in self
                    .directory
                    .list_signed_identity_occurrence_revocations_for(subject_key_id)
                    .await
                    .unwrap_or_default()
                {
                    let seq = Self::ms_seq(row.identity_occurrence_revocation.revoked_at);
                    if let Some((hash, _)) = content_hash_of(&row) {
                        push(hash, seq);
                    }
                }
            }
            EnvelopeKind::Attestation => {
                // DATA-SUBJECT axis — records ABOUT the subject (the 84-family
                // revocation-reachability set), MINUS the G2 self-non-retainable
                // scores.
                for att in self
                    .directory
                    .list_attestations_for(subject_key_id)
                    .await
                    .unwrap_or_default()
                {
                    if Self::is_non_retainable_score(&att) {
                        continue;
                    }
                    let seq = Self::ms_seq(att.asserted_at);
                    if let Some((hash, _)) = content_hash_of(&att) {
                        if self.pull_ref_is_serveable(&att, subject_key_id).await {
                            push(hash, seq);
                        }
                    }
                }
                // SENDER axis — records BY the subject (authorship recovery). No
                // G2 carve (an attestation I authored is mine to recover, even a
                // `capacity:*` score I asserted about someone else) — but the SAME
                // serve gate, so a ref and its bytes always agree.
                for att in self
                    .directory
                    .list_attestations_by(subject_key_id)
                    .await
                    .unwrap_or_default()
                {
                    let seq = Self::ms_seq(att.asserted_at);
                    if let Some((hash, _)) = content_hash_of(&att) {
                        if self.pull_ref_is_serveable(&att, subject_key_id).await {
                            push(hash, seq);
                        }
                    }
                }
            }
            // Revocation (key-level), the cohort planes (Family/Community/
            // LocationProof), the membership-revocation planes, and the
            // operational trio are not subject-scoped-pullable via this axis.
            _ => {}
        }
        refs
    }

    /// CIRISEdge#462 — may this Attestation ref be disclosed to the requester
    /// (== the subject)? A Pull answers with refs, and a ref discloses the row's
    /// existence (hash + seq), so a row the requester could not be SERVED must not
    /// be LISTED — else the Summary is an info-leak and an advertised-then-
    /// unfetchable #429.
    ///
    /// The gate is deliberately NARROWER than the advertise/`fetch_envelope_bytes_for_peer`
    /// path: it applies the E3 CONFIDENTIALITY gates (the `trace:*` plane pause,
    /// author quarantine, and the `trace:* → infra:serve` capability check) but
    /// NOT the #396 producer-advertise-consent bound (`resolve_attestation_recipient`).
    /// A peer receiving another producer's advertised attestation is #396-gated;
    /// a SUBJECT pulling its OWN testimony is not — its first-party right to obtain
    /// the rows it must act on (a conferred duty, a revocation target) overrides a
    /// producer's choice of advertise-recipients. So `delegates_to`/`trust:confers`
    /// about the subject serve unconditionally, while a `trace:*` row still
    /// requires the subject to hold `infra:serve`. `peer == subject` here (enforced
    /// by [`Self::subject_holdings`]).
    async fn pull_ref_is_serveable(&self, att: &Attestation, requester: &str) -> bool {
        let Ok(value) = serde_json::to_value(att) else {
            return false; // an unserializable row is not disclosed
        };
        if Self::attestation_requires_serve(&value) {
            // `trace:*` — E3 confidentiality. Withheld while the plane is paused,
            // and served only to a subject that itself holds `infra:serve`.
            if self.trace_plane_paused().await {
                return false;
            }
            if !self.peer_has_serve_capability(requester).await {
                return false;
            }
        }
        // A quarantined author's row is withheld on every path.
        !self
            .author_quarantine_withholds(&value, &mut HashMap::new(), requester)
            .await
    }

    /// CIRISEdge#462 — the G2 self-revocation-hole carve, resolved by CONSUMING
    /// persist's authoritative retainability ALLOWLIST (CIRISPersist#635,
    /// [`is_subject_retainable`](ciris_persist::federation::namespace::is_subject_retainable)):
    /// a data-subject-axis attestation whose DIMENSION is a score is withheld
    /// UNLESS persist affirms the subject is necessarily its author (`emit_authority`
    /// — trace:*, transport:{kind}, the substrate self-reports, …). Landing a score
    /// ABOUT me onto the node where I am the sole writer is safe only when I am its
    /// author; otherwise it conflates read-copy with write-authority (the G2 hole).
    ///
    /// This REPLACES the earlier `consent_gated_claim` (capacity-only) carve, which
    /// UNDER-carved: it withheld only the consent-gated family and let every other
    /// peer-authored score through. `is_subject_retainable` is an allowlist, so it
    /// is FAIL-CLOSED — an unknown / new / renamed scored family reads
    /// non-retainable and is carved, not silently pulled. (Consequence per #635: a
    /// family edge legitimately needs to pull that is missing from the allowlist
    /// shrinks the pull SILENTLY; that is a persist ask — tell them to add it, do
    /// not assume persist knows.)
    ///
    /// CONFERRALS ARE RETAINED BY TYPE, not by dimension: a `delegates_to` (the
    /// moderation-duty shape #462 exists to recover) is signed by the conferring
    /// authority — the subject cannot forge it, so a retained copy grants no write
    /// authority. This holds EVEN when the conferral is dimension-bearing: the
    /// `self_at_login` shape carries `dimension:
    /// "self:delegates_to:agent_occurrence:v1"` (src/edge.rs), which is NOT in
    /// persist's retainable allowlist. The subject's OWN authored scores (the sender
    /// axis) are likewise untouched — a score I authored is mine to recover.
    ///
    /// INVARIANT (corrected — Codex on #470): key the carve on the SCORES PLANE, not
    /// on has-a-dimension. The earlier "scores are dimension-bearing, conferrals are
    /// dimensionless" reading was FALSE — `self_at_login` is a dimension-bearing
    /// conferral — and the has-dimension gate would carve that delegation out of the
    /// very pull the receive axis exists to serve. The reliable discriminator is
    /// `attestation_type`: every peer-authored claim (reputation / capacity /
    /// moderation) rides `attestation_type == "scores"` with a distinguishing
    /// dimension; conferrals ride `delegates_to` / `trust:confers`. So the carve is
    /// `type == scores AND !is_subject_retainable(dimension)`. The one thing to keep
    /// true across both repos: persist keeps peer-authored claims on the scores
    /// plane and conferrals off it.
    fn is_non_retainable_score(att: &Attestation) -> bool {
        // Only the SCORES plane is carveable. A conferral (delegates_to /
        // trust:confers) is authority-signed — unforgeable by the subject — so it is
        // retained by TYPE regardless of dimension, INCLUDING the dimension-bearing
        // self_at_login shape (`self:delegates_to:agent_occurrence:v1`, src/edge.rs),
        // which is NOT in persist's retainable allowlist. Gating on the dimension
        // alone would carve that delegation OUT of the pull the receive axis exists
        // to recover (Codex on #470).
        //
        // FAIL-CLOSED on the scores axis: a scores row is carved UNLESS it carries a
        // dimension that is EXPLICITLY retainable. A scores row with an absent or
        // non-string `/dimension` (legacy / malformed) is therefore carved, not
        // served — the earlier `!is_subject_retainable(dim)` form fell OPEN on a
        // missing dimension, reopening G2 for that input (Codex on #470, round 2).
        att.attestation_type == ciris_persist::federation::types::attestation_type::SCORES
            && !att
                .attestation_envelope
                .pointer("/dimension")
                .and_then(serde_json::Value::as_str)
                .is_some_and(ciris_persist::federation::namespace::is_subject_retainable)
    }

    /// The per-kind apply dispatch behind the #425 choke —
    /// [`StateApplier::apply_envelope_bytes`] wraps this with the #426
    /// source-peer trace and the #565 refusal counter.
    async fn dispatch_apply(&self, kind: EnvelopeKind, envelope_bytes: &[u8]) -> ApplyOutcome {
        match kind {
            EnvelopeKind::Key => self.apply_key(envelope_bytes).await,
            EnvelopeKind::Attestation => self.apply_attestation(envelope_bytes).await,
            EnvelopeKind::Revocation => {
                let outcome = self.apply_revocation(envelope_bytes).await;
                // CIRISEdge#430 — an ADMITTED revocation is the event-driven
                // invalidation signal for cached trust verdicts (the transit
                // gate's hop cache). Fired only on admit (a refused/duplicate
                // revocation changed no trust state); the re-deserialize is
                // once per admitted revocation, a rare event. TTLs remain the
                // backstop when no observer is installed.
                if outcome.is_admitted() {
                    if let Some(observer) = &self.revocation_observer {
                        if let Ok(r) = serde_json::from_slice::<SignedRevocation>(envelope_bytes) {
                            observer(&r.revocation.revoked_key_id);
                        }
                    }
                }
                outcome
            }
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
            EnvelopeKind::AccordQuorumEvidence => {
                self.apply_accord_quorum_evidence(envelope_bytes).await
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
    fn advertise_since<S, IN, TS>(&self, rows: &[S], in_scope: IN, seq_of: TS) -> Vec<EnvelopeRef>
    where
        S: serde::Serialize,
        IN: Fn(&S) -> bool,
        TS: Fn(&S) -> u64,
    {
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for row in rows.iter().filter(|r| in_scope(r)) {
            let Some((hash, _bytes)) = content_hash_of(row) else {
                // CIRISEdge#425 — a row that will not serialize is silently absent
                // from the advertise set (peers never learn it exists, so it never
                // replicates). Near-impossible for these types, but a real
                // silent-withhold if it ever fires — so it speaks.
                tracing::warn!(
                    "advertise_since: a row could not be serialized to its content \
                     hash and is OMITTED from the advertise set — it will not replicate \
                     (CIRISEdge#425)"
                );
                // CIRISEdge#433 — and it COUNTS. This is what took `&self`: a plane
                // going dark for a non-policy reason is the one withhold an
                // operator has no other way to see, since there is no peer and no
                // gate to correlate against.
                self.withhold(
                    crate::observability::WithholdReason::RowNotSerializable,
                    "<unattributed>",
                    "advertise_since: content_hash_of failed",
                );
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
            .list_signed_key_records_since(None, self.effective_page_limit().await)
            .await
            .unwrap_or_default();
        self.advertise_since(
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
            .list_signed_identity_occurrences_since(None, self.effective_page_limit().await)
            .await
            .unwrap_or_default();
        self.advertise_since(
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
            .list_signed_transport_destinations_since(None, self.effective_page_limit().await)
            .await
            .unwrap_or_default();
        self.advertise_since(
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
                self.effective_page_limit().await,
            )
            .await
            .unwrap_or_default();
        self.advertise_since(
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
            // #433 — keep the subject for the withhold attribution below; `fetch`
            // consumes the owned `String`.
            let subject = key_id.clone();
            let rows = fetch(key_id).await;
            for row in rows {
                let Some(envelope_hash) = Self::decode_hash(hash(&row)) else {
                    // CIRISEdge#433 — the row exists but its `persist_row_hash` is
                    // not 32 hex bytes, so it is absent from the advertise set and
                    // will never replicate. Was a bare `continue`; now countable.
                    // Distinct from `RowNotSerializable`: the row serializes fine,
                    // its persist-side hash is the wrong shape.
                    self.withhold(
                        crate::observability::WithholdReason::RowHashUndecodable,
                        &subject,
                        "fan_out_for_member: persist_row_hash not 32 hex bytes",
                    );
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
    ///
    /// ── CIRISEdge#352 (pushdown verdict, persist v24.2.0) ──────────────
    ///
    /// This per-record projection deliberately stays EDGE-SIDE. #352 asked to
    /// push it into persist v17.4.0's `list_scores`, but persist itself moved
    /// first: v17.5.0 (CIRISPersist#455) split the read surfaces and made the
    /// split contractual —
    ///
    /// - `list_scores` is the CALLER-GATED consumer view (§4.3 visibility
    ///   gate on `cohort_scope`/`attested_key_id` resolved from the caller,
    ///   plus `Live`-lifecycle folding and the V106 subject join). Persist's
    ///   own `list_attestation_log` doc names wiring the sweep through it as
    ///   the CIRISEdge#336 failure shape ("silently narrows"): a relay must
    ///   see rows attested *between other parties*, which a caller-relative
    ///   gate hides.
    /// - `list_attestation_log` — the read persist DESIGNATES for
    ///   replication — carries NO projection axes by contract: "gossip policy
    ///   (what to actually advertise) lives at the consumer tier (edge
    ///   `projection_for`), never here."
    /// - `AttestationFilter` cannot express the decision anyway: it has no
    ///   `cohort_scope` axis (that axis exists only on `FederationKeyFilter`)
    ///   and composes AND-only, while this predicate is a negated conjunction
    ///   — advertise UNLESS (scope ∈ {self, family} ∧ ¬tombstone ∧ producer ∉
    ///   self_set). And the one axis it does offer, `dimension_prefixes`, is
    ///   a no-op here: `authority_for(dimension)` only picks Global-vs-Cohort,
    ///   BOTH of which advertise.
    ///
    /// The equivalence pin any future pushdown must keep green:
    /// `advertise_projection_boundary_and_ledger_are_pinned`.
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
    /// ([`has_accord_conferred_role`], CIRISPersist#440) — the record's scrub set must
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
        // CIRISEdge#425 Exhibit A/C — every arm below WITHHOLDS the whole trace
        // plane; each is a throttled `warn!` (a floor, not silence), and — Exhibit
        // C — a directory READ ERROR is reported as such, NOT folded into "no role"
        // (a transient failure reported as a confident statement about the peer's
        // blessing is worse than silence: it sends you looking in the wrong place).
        //
        // CIRISEdge#433 carries that same split into the LEDGER. This fn returns a
        // `bool`, which is precisely the disjunction the ledger must not report —
        // so each leg books its own reason HERE, at the branch, and the callers
        // (`fetch_envelope_bytes_for_peer`, `list_attestations`) do not re-count.
        // The counter is unthrottled even though the log is: a floor is right for
        // log volume, but a metric that under-counts is a metric that lies.
        use crate::observability::WithholdReason;
        let withhold = |reason: WithholdReason, reason_tag: &str, msg: String| {
            self.withhold(reason, peer_key_id, reason_tag);
            if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                serve_gate_withheld_log().check(&format!("{peer_key_id}:{reason_tag}"))
            {
                tracing::warn!(peer_key_id, suppressed_prev, "{msg}");
            }
        };

        // Leg A — accord plane. Re-derived from the record's own cryptography on
        // every call, so a withdrawn blessing takes effect immediately. Exhibit C:
        // split `Err` (transient read failure) from `Ok(false)` (genuinely no role).
        match has_accord_conferred_role(&*self.directory, peer_key_id, Self::SERVE_CAPABILITY).await
        {
            Ok(true) => {}
            Ok(false) => {
                withhold(
                    WithholdReason::ServeCapabilityMissing,
                    "legA-no-role",
                    "trace attestation WITHHELD (leg A) — recipient has no accord-conferred, \
                     still-verifying `infra:serve`. The fleet must re-genesis with an \
                     infra:serve-blessed canonical (CIRISPersist#480)."
                        .to_string(),
                );
                return false;
            }
            Err(e) => {
                withhold(
                    WithholdReason::ServeCapabilityReadError,
                    "legA-read-error",
                    format!(
                        "trace attestation WITHHELD (leg A) — the `infra:serve` DIRECTORY READ \
                         FAILED (fail-closed). This is a transient read error, NOT a statement \
                         that the peer lacks the role: {e}"
                    ),
                );
                return false;
            }
        }

        // Leg B — pluggable-trust-root plane.
        let Some(local) = self.local_key_id.as_deref() else {
            withhold(
                WithholdReason::LocalIdentityMissing,
                "legB-no-local-key",
                "trace attestation WITHHELD (leg B) — replication runtime has no `local_key_id`, \
                 so the CIRISEdge#386 trust-root gate cannot be evaluated. This darks the trace \
                 plane; wire ReplicationRuntimeConfig::local_key_id (CIRISServer#300)."
                    .to_string(),
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
                // The SUCCESS path — routine, quiet.
                tracing::debug!(
                    peer_key_id,
                    root_key_id = %grant.root_key_id,
                    grant_attestation_id = %grant.grant_attestation_id,
                    "trace attestation permitted — recipient's `infra:serve` roots to a trusted root"
                );
                true
            }
            Ok(None) => {
                // The walk needs THREE inputs; `Ok(None)` doesn't say which is
                // absent, so enumerate them as an actionable checklist (CIRISEdge#425).
                withhold(
                    WithholdReason::ServeCapabilityNotRooted,
                    "legB-no-trusted-root",
                    format!(
                        "trace attestation WITHHELD (leg B) — recipient's `infra:serve` roots to \
                         no root this node (local_key_id={local}) trusts. One of THREE inputs is \
                         missing: (1) a scoped `delegates_to(root → {peer_key_id})` grant, (2) \
                         this node's own `delegates_to({local} → root)` trust edge, or (3) a live \
                         root charter with a pre-rotation commitment (CIRISEdge#386)."
                    ),
                );
                false
            }
            Err(e) => {
                withhold(
                    WithholdReason::TrustRootWalkError,
                    "legB-walk-error",
                    format!(
                        "trace attestation WITHHELD (leg B) — the trust-root walk FAILED \
                         (fail-closed). Transient read/verify error, not a trust verdict: {e}"
                    ),
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
    /// accord-conferred, self-re-verifying [`has_accord_conferred_role`] read the #379
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
        // the `has_accord_conferred_role` awaits below.
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
            if !has_accord_conferred_role(&*self.directory, peer, &capability)
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
                // CIRISEdge#433 — booked at the branch, on the ADVERTISE side. The
                // direct-fetch twin books at its own call site (this fn is shared,
                // and each path withholds one row per call, so the two never
                // double-count a single decision).
                self.withhold(
                    crate::observability::WithholdReason::RecipientCapabilityRestriction,
                    peer,
                    dimension,
                );
                return true;
            }
        }
        false
    }

    /// CIRISEdge#440 ask 3 — is this row's AUTHOR under a live tier-2
    /// quarantine (`quarantine:withheld:v1`, persist's marker fold)?
    ///
    /// The offer-side twin of persist's own `filter_withheld_rows` serve
    /// consult (which persist applies on `list_attestation_log`, the #455
    /// relay read — but NOT on `list_attestations_since`, the read this
    /// bridge's advertise sweep uses; without this gate a quarantined author's
    /// rows would still be OFFERED). Same two properties, kept deliberately:
    ///
    /// - **The marker plane is never withheld** — a row on a quarantine marker
    ///   dimension passes unconditionally, even about a withheld author. A
    ///   marker that stops replicating cannot be folded by the rest of the
    ///   mesh, and a release that stops replicating makes a quarantine
    ///   permanent by accident.
    /// - **Rows are retained locally** — this gates the advertise/serve exits
    ///   only; [`Self::list_attestation_holdings`] (the receive-diff axis) is
    ///   untouched, which is what "withhold-from-serving, rows retained,
    ///   reversible" means.
    ///
    /// One directory read per DISTINCT author per sweep (`memo`), mirroring
    /// persist's own memo shape. Each branch books its OWN reason (#433):
    /// a withheld author books `QuarantinedAuthor`; a FAILED consult books
    /// `QuarantineReadError` and fails closed (a transient error must not
    /// leak a row the markers may withhold) — never both for one row.
    async fn author_quarantine_withholds(
        &self,
        canonical_json: &serde_json::Value,
        memo: &mut HashMap<String, QuarantineConsult>,
        peer_label: &str,
    ) -> bool {
        use crate::observability::WithholdReason;
        // The convergence carve-out: marker rows always pass.
        let dimension = canonical_json
            .pointer("/attestation_envelope/dimension")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if ciris_persist::federation::quarantine::is_marker_dimension(dimension) {
            return false;
        }
        let Some(author) = canonical_json
            .get("attesting_key_id")
            .and_then(|v| v.as_str())
        else {
            // No author to consult about — nothing to withhold on this axis.
            return false;
        };
        let consult = if let Some(c) = memo.get(author) {
            *c
        } else {
            let c = match ciris_persist::federation::quarantine::is_withheld(
                &*self.directory,
                author,
                chrono::Utc::now(),
            )
            .await
            {
                Ok(true) => QuarantineConsult::Withheld,
                Ok(false) => QuarantineConsult::Clear,
                Err(e) => {
                    if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                        serve_gate_withheld_log().check(&format!("quarantine-read:{author}"))
                    {
                        tracing::warn!(
                            author,
                            suppressed_prev,
                            error = %e,
                            "quarantine consult FAILED for a row's author — withholding \
                             the author's rows from the offer (fail-closed; a transient \
                             read error, NOT a quarantine verdict; CIRISEdge#440)"
                        );
                    }
                    QuarantineConsult::ReadError
                }
            };
            memo.insert(author.to_string(), c);
            c
        };
        match consult {
            QuarantineConsult::Clear => false,
            QuarantineConsult::Withheld => {
                self.withhold(WithholdReason::QuarantinedAuthor, peer_label, author);
                tracing::debug!(
                    author,
                    peer = peer_label,
                    "row withheld from the offer — its author is under a live \
                     quarantine:withheld marker; the row is retained locally and the \
                     withhold lifts on a release marker (CIRISEdge#440 ask 3)"
                );
                true
            }
            QuarantineConsult::ReadError => {
                self.withhold(WithholdReason::QuarantineReadError, peer_label, author);
                true
            }
        }
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
    /// CIRISEdge#433 — each of the three `None` branches books its OWN
    /// [`crate::observability::WithholdReason`]. They are NOT interchangeable: a
    /// wiring fault (no local identity), a transient read failure, and a peer the
    /// operator genuinely did not consent to are three different things to go
    /// look at. Booked here rather than at the two call sites
    /// ([`Self::fetch_envelope_bytes_for_peer`] and [`Self::list_attestations`])
    /// because only here is the branch visible — and so a withhold is counted
    /// exactly once.
    /// Whether the authenticated `peer` is FIRST-PARTY to this attestation `inner`
    /// (the BARE wire value): its author (`attesting_key_id`), its primary subject
    /// (`attested_key_id`), or in its data-subject set (`subject_key_ids`). All three
    /// are bound into the SIGNED envelope (#643), and the link authenticates `peer`,
    /// so a match means the peer genuinely authored-or-is-the-subject-of the row.
    ///
    /// v16 review: first-party right overrides #396 producer-advertise-consent. The
    /// subject-Pull LIST gate (`pull_ref_is_serveable`) already drops #396 (a subject
    /// pulls its own testimony from a node no peer would ever advertise it to); the
    /// FETCH must AGREE, else the ref is listed-then-withheld (advertised-then-
    /// unfetchable + a disclosed ref the subject can't obtain).
    fn attestation_is_first_party_to(inner: &serde_json::Value, peer: &str) -> bool {
        let is = |field: &str| inner.get(field).and_then(serde_json::Value::as_str) == Some(peer);
        is("attesting_key_id")
            || is("attested_key_id")
            || inner
                .get("subject_key_ids")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|arr| arr.iter().any(|s| s.as_str() == Some(peer)))
    }

    async fn resolve_attestation_recipient(&self, peer: &str) -> Option<ResolvedRecipient> {
        use crate::observability::WithholdReason;
        let Some(local) = self.local_key_id.as_deref() else {
            tracing::warn!(
                peer,
                "attestation plane withheld — no `local_key_id` to resolve the CIRISEdge#396 \
                 consent send-set; wire ReplicationRuntimeConfig::local_key_id"
            );
            self.withhold(
                WithholdReason::LocalIdentityMissing,
                peer,
                "consent-send-set: no local_key_id",
            );
            return None;
        };
        let Some(set) = self.resolved_peer_set(local).await else {
            tracing::debug!(
                peer,
                "attestation plane withheld — consent send-set unresolved (fail-closed)"
            );
            self.withhold(
                WithholdReason::SendSetUnresolved,
                peer,
                "list_consent_peers read failed",
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
            self.withhold(
                WithholdReason::RecipientNotInSendSet,
                peer,
                "attestation: not consent-included",
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

    /// CIRISEdge#416 — the RAW Attestation holdings: the content-hash of EVERY
    /// federation-tier attestation in local state, with NO `attestation_is_advertised`
    /// projection filter, NO `self_set`, NO recipient gates. This is the RECEIVE
    /// axis's "what do I hold" — distinct from [`Self::list_attestations`]'s "what
    /// would I advertise". Using the advertise view for the round's
    /// `want = remote ∖ holdings` diff meant a held-but-not-advertised row (a
    /// `self`/`family` attestation from ANOTHER producer, which projects `SelfOwn`
    /// and is advertised only by its own producer) was permanently absent from the
    /// node's own holdings view — so it stayed in `want` every round and the round
    /// never converged (CIRISAgent#932 responder-driver stall). The convergence
    /// invariant this restores: after admitting an attestation, its hash is here.
    /// Cheaper than the advertise sweep — it drops the per-row projection resolution.
    async fn list_attestation_holdings(&self) -> Vec<EnvelopeRef> {
        // CIRISEdge#440 — deliberately the RAW configured limit, NOT
        // `effective_page_limit`. This is the receive-diff "what I hold" axis:
        // shrinking it under a page-limit relief would hide held rows from the
        // node's own `want = remote ∖ holdings` diff, making it re-want rows it
        // already holds — MORE wire traffic under a congestion relief, the
        // exact inversion of what the knob is for. Relief bounds what we OFFER
        // and SERVE, never what we admit knowing about ourselves.
        let attestations = self
            .directory
            .list_attestations_since(None, self.config.operational_page_limit)
            .await
            .unwrap_or_default();
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for att in &attestations {
            // Skip only an unparseable/unhashable row (never a projection filter).
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
            .list_attestations_since(None, self.effective_page_limit().await)
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
        let peer_label = recipient.unwrap_or("<unattributed>");
        // CIRISEdge#440 — the trace-plane pause, resolved ONCE per sweep (the
        // reader's own TTL makes even that a cache hit round-to-round), and the
        // per-author quarantine memo (one directory read per DISTINCT author).
        let trace_paused = self.trace_plane_paused().await;
        let mut trace_pause_booked = false;
        let mut quarantine_memo: HashMap<String, QuarantineConsult> = HashMap::new();
        for att in &attestations {
            let Ok(canonical_json) = serde_json::to_value(att) else {
                // CIRISEdge#433 — an attestation that will not project to a
                // `Value` is invisible to every gate below AND absent from the
                // advertise set. Was a bare `continue`.
                self.withhold(
                    crate::observability::WithholdReason::RowNotSerializable,
                    peer_label,
                    "list_attestations: to_value failed",
                );
                continue;
            };
            // NOTE (#433, deliberate): the projection filter below is NOT a
            // withhold. `attestation_is_advertised` defines which rows this node
            // is the publisher OF (a `self`/`family` row is published by its own
            // subject, never relayed) — a row it excludes was never eligible, so
            // counting it would flood the ledger with by-design non-events every
            // sweep and bury the gates that ARE decisions. The audit trail for
            // projection lives in `namespace::projection_for`, not here.
            if !Self::attestation_is_advertised(&canonical_json, &self_set) {
                continue;
            }
            // CIRISEdge#440 — the mesh-config pause: `feature.trace_replication`
            // relieved to 0 withholds every `trace:*` row from the advertise.
            // Booked ONCE per sweep (the decision is one per-sweep fact, not one
            // per row — the same shape the #379 serve-allowed memo takes), with
            // a named, throttled WARN; the pause lifts on the relief row's TTL
            // or a superseding row, with no operator action on this node.
            if trace_paused && Self::attestation_requires_serve(&canonical_json) {
                if !trace_pause_booked {
                    trace_pause_booked = true;
                    self.withhold_config_paused(peer_label, "config-paused-advertise");
                }
                continue;
            }
            // CIRISEdge#440 ask 3 — quarantined-author rows are withheld from
            // the offer (retained locally; markers themselves always pass).
            if self
                .author_quarantine_withholds(&canonical_json, &mut quarantine_memo, peer_label)
                .await
            {
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
                // CIRISEdge#433 — cleared every gate, then could not be hashed:
                // eligible and not served, which is the ledger's exact definition.
                self.withhold(
                    crate::observability::WithholdReason::RowNotSerializable,
                    peer_label,
                    "list_attestations: content_hash_of failed",
                );
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
            .list_signed_families_since(None, self.effective_page_limit().await)
            .await
            .unwrap_or_default();
        self.advertise_since(
            &rows,
            |s| s.family.members.iter().any(|m| cohort.contains(&m.key_id)),
            |s| Self::ms_seq(s.family.founded_at),
        )
    }

    async fn list_communities(&self) -> Vec<EnvelopeRef> {
        let cohort = self.cohort_set();
        let rows = self
            .directory
            .list_signed_communities_since(None, self.effective_page_limit().await)
            .await
            .unwrap_or_default();
        self.advertise_since(
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
                self.effective_page_limit().await,
            )
            .await
            .unwrap_or_default();
        self.advertise_since(
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
                self.effective_page_limit().await,
            )
            .await
            .unwrap_or_default();
        self.advertise_since(
            &rows,
            |_| true,
            |s| Self::ms_seq(s.community_membership_revocation.removed_at),
        )
    }

    async fn list_location_proofs(&self) -> Vec<EnvelopeRef> {
        let cohort = self.cohort_set();
        let rows = self
            .directory
            .list_signed_location_proofs_since(None, self.effective_page_limit().await)
            .await
            .unwrap_or_default();
        self.advertise_since(
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
            .list_organizations_since(None, self.effective_page_limit().await)
            .await
            .unwrap_or_default();
        self.advertise_since(&rows, |_| true, |row| Self::ms_seq(row.asserted_at))
    }

    async fn list_org_memberships(&self) -> Vec<EnvelopeRef> {
        // CIRISEdge#397 — advertise the BARE `OrgMembership` row's content-hash;
        // same bare-row basis as `list_organizations` (persist indexes + reloads
        // the bare row). `apply_org_membership` re-wraps on the receive side.
        let rows = self
            .directory
            .list_org_memberships_since(None, self.effective_page_limit().await)
            .await
            .unwrap_or_default();
        self.advertise_since(&rows, |_| true, |row| Self::ms_seq(row.asserted_at))
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
            .list_signed_partner_records_since(None, self.effective_page_limit().await)
            .await
            .unwrap_or_default();
        self.advertise_since(
            &rows,
            |_| true,
            |s| Self::ms_seq(s.partner_record.asserted_at),
        )
    }
}

// ─── apply_envelope_bytes — per-kind dispatch ───────────────────────

impl FederationDirectoryReplicationBridge {
    async fn apply_key(&self, bytes: &[u8]) -> ApplyOutcome {
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
        // CIRISEdge#425 — the typed `ReplicatedKeyOutcome` maps cleanly to
        // `ApplyOutcome`: `Inserted`/`Upgraded`/`Superseded` changed local state
        // (progress); `Unchanged` is a byte-identical duplicate (routine, quiet).
        //
        // persist v24.2.0 (CIRISPersist#565) — `Refused { reason }` now NAMES the
        // branch that fired (a closed, append-only 9-token enum), so the message
        // carries the verdict's evidence instead of the whole five-cause
        // disjunction we used to print. We key on the enum constant, never the
        // message string (the two-lists-that-disagree rule). A persist `Err` /
        // deserialize failure carry their reason. The choke point (`on_deliver`)
        // logs every non-`Admitted`; the receive-plane mirror of the #433 withhold
        // ledger counts every refusal by its token.
        match serde_json::from_slice::<SignedKeyRecord>(bytes) {
            Ok(record) => {
                let content_hash =
                    content_hash_of(&record).map_or_else(String::new, |(h, _)| hex::encode(h));
                let (outcome, refusal_token) = key_outcome_to_apply(
                    self.directory.apply_replicated_key_record(record).await,
                    &content_hash,
                );
                if let Some(token) = refusal_token {
                    if let Some(m) = &self.metrics {
                        m.inc_key_apply_refusal(token);
                    }
                }
                outcome
            }
            Err(e) => ApplyOutcome::Deserialize(apply_deser_reason("Key", bytes, &e)),
        }
    }

    async fn apply_attestation(&self, bytes: &[u8]) -> ApplyOutcome {
        // CIRISEdge#397 — the wire is now the BARE `Attestation` (the shape
        // persist's content-hash index/point-read serves), so deserialize that
        // first and re-wrap; fall back to the pre-v14.1 `SignedAttestation`
        // `{"attestation": …}` wrap for a peer still on the old wire.
        let signed = serde_json::from_slice::<Attestation>(bytes)
            .map(|attestation| SignedAttestation { attestation })
            .or_else(|_| serde_json::from_slice::<SignedAttestation>(bytes));
        match signed {
            Ok(record) => {
                // Hash the BARE attestation — the value persist's content-hash
                // index (and edge's `advertise_since`) keys on (#397), so the reason
                // correlates with the offered `EnvelopeRef` AND a direct
                // `put_attestation` of the same row.
                let content_hash = content_hash_of(&record.attestation)
                    .map_or_else(String::new, |(h, _)| hex::encode(h));
                match self.directory.put_attestation(record).await {
                    Ok(()) => ApplyOutcome::Admitted,
                    Err(e) => ApplyOutcome::Refused(apply_refusal_reason(
                        "Attestation",
                        &content_hash,
                        &e,
                    )),
                }
            }
            Err(e) => ApplyOutcome::Deserialize(apply_deser_reason("Attestation", bytes, &e)),
        }
    }

    async fn apply_revocation(&self, bytes: &[u8]) -> ApplyOutcome {
        apply_signed_plane!(self, "Revocation", bytes, SignedRevocation, put_revocation)
    }

    async fn apply_identity_occurrence(&self, bytes: &[u8]) -> ApplyOutcome {
        apply_signed_plane!(
            self,
            "IdentityOccurrence",
            bytes,
            SignedIdentityOccurrence,
            put_identity_occurrence
        )
    }

    // ── CIRISEdge#394 (E4 lockstep verdict) — edge is PASS-THROUGH on the
    // five authority-signed declaration planes ──────────────────────────
    //
    // Family / Community / FamilyMembershipRevocation /
    // CommunityMembershipRevocation / LocationProof carry an authority
    // signature persist v21.0.0+ (CIRISPersist#502 E4) verifies FAIL-CLOSED
    // at admission (hybrid Ed25519 + bound-form ML-DSA-65,
    // `HybridPolicy::Strict`, over
    // `ceg_produce_canonicalize(record.signing_envelope())`, against the
    // authority's REGISTERED pubkeys — `verify_family_admission` et al.).
    // Edge PRODUCES none of these records: no constructor of the five
    // `Signed*` wrappers exists anywhere in edge, and the pyo3
    // `apply_envelope` surface hands over PRE-SIGNED bytes from the rider.
    // So edge's lockstep duty is byte-transparency, not signing:
    //
    //   * RECEIVE (the `apply_*` below): typed deserialize → persist
    //     `put_*`. The three wrapper fields (`authority_key_id`,
    //     `scrub_signature_classical`, `scrub_signature_pqc`) flow through
    //     the typed struct unmodified; persist's gate is the admission
    //     oracle.
    //   * SERVE (`list_*` + `fetch_envelope_bytes`): served bytes come from
    //     persist's `signed_wire_index` — persist's OWN serialization of the
    //     stored row, never re-signed or re-shaped by edge.
    //
    // Pinned by `e4_*_forward_path_preserves_authority_signature` (the five
    // positive round trips, re-admission on a second node as the oracle) and
    // `e4_unsigned_declarations_refuse_at_admission` (the fail-closed half)
    // in the tests module below.
    async fn apply_family(&self, bytes: &[u8]) -> ApplyOutcome {
        apply_signed_plane!(self, "Family", bytes, SignedFamily, put_family)
    }

    async fn apply_community(&self, bytes: &[u8]) -> ApplyOutcome {
        apply_signed_plane!(self, "Community", bytes, SignedCommunity, put_community)
    }

    async fn apply_identity_occurrence_revocation(&self, bytes: &[u8]) -> ApplyOutcome {
        apply_signed_plane!(
            self,
            "IdentityOccurrenceRevocation",
            bytes,
            SignedIdentityOccurrenceRevocation,
            put_identity_occurrence_revocation
        )
    }

    async fn apply_family_membership_revocation(&self, bytes: &[u8]) -> ApplyOutcome {
        apply_signed_plane!(
            self,
            "FamilyMembershipRevocation",
            bytes,
            SignedFamilyMembershipRevocation,
            put_family_membership_revocation
        )
    }

    async fn apply_community_membership_revocation(&self, bytes: &[u8]) -> ApplyOutcome {
        apply_signed_plane!(
            self,
            "CommunityMembershipRevocation",
            bytes,
            SignedCommunityMembershipRevocation,
            put_community_membership_revocation
        )
    }

    async fn apply_location_proof(&self, bytes: &[u8]) -> ApplyOutcome {
        apply_signed_plane!(
            self,
            "LocationProof",
            bytes,
            SignedLocationProof,
            put_location_proof
        )
    }

    /// CIRISEdge#474 — RECEIVE half of the accord-quorum-evidence cursor plane.
    /// This does NOT go through [`apply_signed_plane!`]: there is no `Signed*`
    /// wrapper and no `put_*`. The delivered bytes are a persist
    /// [`AccordQuorumEvidence`](ciris_persist::federation::accord_carriage::AccordQuorumEvidence)
    /// bundle; `apply_replicated_accord_evidence` **re-tallies** it against THIS
    /// node's own accord roster (never the sender's verdict), fail-closed with
    /// [`Error::AccordEvidenceUnverified`](ciris_persist::federation::Error), and
    /// is idempotent on replay. Progress (`Admitted`) iff a new participation
    /// landed OR a withdrawal tombstone was re-derived locally; a byte-identical
    /// replay (`participations_admitted == 0`, no new tombstone) is `Duplicate`,
    /// exactly as the anti-entropy loop counts one — never a silent no-op.
    async fn apply_accord_quorum_evidence(&self, bytes: &[u8]) -> ApplyOutcome {
        use ciris_persist::federation::accord_carriage::AccordQuorumEvidence;
        let evidence: AccordQuorumEvidence = match serde_json::from_slice(bytes) {
            Ok(e) => e,
            Err(e) => {
                return ApplyOutcome::Deserialize(apply_deser_reason(
                    "AccordQuorumEvidence",
                    bytes,
                    &e,
                ))
            }
        };
        match self
            .directory
            .apply_replicated_accord_evidence(&evidence)
            .await
        {
            Ok(admission) => {
                if admission.participations_admitted > 0
                    || !admission.withdrawals_projected.is_empty()
                {
                    ApplyOutcome::Admitted
                } else {
                    ApplyOutcome::Duplicate
                }
            }
            Err(e) => ApplyOutcome::Refused(format!(
                "AccordQuorumEvidence: admission refused (refusal={}): {e}",
                e.kind(),
            )),
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
    async fn apply_transport_destination(&self, bytes: &[u8]) -> ApplyOutcome {
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
                    // Fail-closed + re-offerable: a stale epoch is routine, but a
                    // same-`(epoch, asserted_at)` CONTENT conflict is a split-truth
                    // signal that must be loud (CIRISEdge#425 MEDIUM). We keep the
                    // frame "handled" (return `Admitted`) either way so it does not
                    // retry-storm the sender, but a conflict WARNs while a stale
                    // epoch DEBUGs. Keyed on the low-cardinality reason, never the
                    // attacker-influenced key_id / dest (CIRISEdge#337 §4).
                    if reason.contains("conflict") {
                        tracing::warn!(
                            occurrence_key_id = %signed.transport_destination.occurrence_key_id,
                            reason = %reason,
                            "replicated route CONTENT CONFLICT at same (epoch, asserted_at) — \
                             split-truth signal, not applied (CIRISEdge#338/#425)"
                        );
                    } else {
                        tracing::debug!(
                            occurrence_key_id = %signed.transport_destination.occurrence_key_id,
                            reason = %reason,
                            "replicated route refused (fail-closed, re-offerable): stale epoch \
                             — not applied (CIRISEdge#338)"
                        );
                    }
                    ApplyOutcome::Admitted
                }
                Ok(_) => ApplyOutcome::Admitted,
                Err(e) => ApplyOutcome::Refused(format!(
                    "TransportDestination: authenticated apply gate rejected (signature / \
                     attesting-key / acts-for, CIRISEdge#337 CRITICAL-2): {e}"
                )),
            },
            // A pre-v17 bare row from an un-upgraded peer (intended breaking
            // behavior) — no longer silent (CIRISEdge#425).
            Err(e) => {
                ApplyOutcome::Deserialize(apply_deser_reason("TransportDestination", bytes, &e))
            }
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
    async fn apply_organization(&self, bytes: &[u8]) -> ApplyOutcome {
        // CIRISEdge#425 Exhibit B — this early return was one of the THREE sites
        // #423 missed because it sits ABOVE the loud helpers. An edge built without
        // `OperationalProviders` silently declined every delivered Organization,
        // while the round reported healthy. Now it yields a reason the choke logs.
        if self.operational.is_none() {
            return ApplyOutcome::refused(
                "Organization: operational providers not configured on this edge — \
                 operational-kind admission is opted out",
            );
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
            Ok(s) => {
                let content_hash = content_hash_of(&s.organization)
                    .map_or_else(String::new, |(h, _)| hex::encode(h));
                match self.directory.put_organization(s).await {
                    Ok(()) => ApplyOutcome::Admitted,
                    Err(e) => ApplyOutcome::Refused(apply_refusal_reason(
                        "Organization",
                        &content_hash,
                        &e,
                    )),
                }
            }
            Err(e) => ApplyOutcome::Deserialize(apply_deser_reason("Organization", bytes, &e)),
        }
    }

    async fn apply_org_membership(&self, bytes: &[u8]) -> ApplyOutcome {
        // CIRISEdge#425 Exhibit B — the second escaped early return.
        if self.operational.is_none() {
            return ApplyOutcome::refused(
                "OrgMembership: operational providers not configured on this edge — \
                 operational-kind admission is opted out",
            );
        }
        // CIRISEdge#397 — same bare-row wire as `apply_organization`: deserialize
        // the BARE `OrgMembership` and re-wrap, falling back to the pre-v14.1
        // `SignedOrgMembership` wrap.
        let signed = serde_json::from_slice::<OrgMembership>(bytes)
            .map(|org_membership| SignedOrgMembership { org_membership })
            .or_else(|_| serde_json::from_slice::<SignedOrgMembership>(bytes));
        match signed {
            Ok(s) => {
                let content_hash = content_hash_of(&s.org_membership)
                    .map_or_else(String::new, |(h, _)| hex::encode(h));
                match self.directory.put_org_membership(s).await {
                    Ok(()) => ApplyOutcome::Admitted,
                    Err(e) => ApplyOutcome::Refused(apply_refusal_reason(
                        "OrgMembership",
                        &content_hash,
                        &e,
                    )),
                }
            }
            Err(e) => ApplyOutcome::Deserialize(apply_deser_reason("OrgMembership", bytes, &e)),
        }
    }

    async fn apply_partner_record(&self, bytes: &[u8]) -> ApplyOutcome {
        // CIRISEdge#425 Exhibit B — the third escaped early return.
        if self.operational.is_none() {
            return ApplyOutcome::refused(
                "PartnerRecord: operational providers not configured on this edge — \
                 operational-kind admission is opted out",
            );
        }
        apply_signed_plane!(
            self,
            "PartnerRecord",
            bytes,
            SignedPartnerRecord,
            put_partner_record
        )
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
    use chrono::SubsecRound as _;
    use chrono::Utc;
    use ciris_crypto::{ClassicalSigner as _, Ed25519Signer, MlDsa65Signer, PqcSigner as _};
    use ciris_persist::federation::types::{
        algorithm, identity_type, Attestation, Community, CommunityMember,
        CommunityMembershipRevocation, Family, FamilyMember, FamilyMembershipRevocation, KeyRecord,
        LocationProof, Revocation, SignedAttestation, SignedKeyRecord,
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
            capability_roles: Vec::new(),
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
        let admitted = bridge
            .apply_envelope_bytes(EnvelopeKind::Key, &bytes, None)
            .await;
        assert!(
            admitted.is_admitted(),
            "matching-content apply admits on MemoryBackend, got {admitted:?}"
        );
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

    /// CIRISEdge#416 — the RECEIVE-diff convergence invariant: an attestation the
    /// node HOLDS must appear in `list_attestation_holdings()` (holdings) EVEN
    /// WHEN it is not in `list_attestations(None)` (the advertise view). The
    /// load-bearing case is a `self`-scoped row from ANOTHER producer: it projects
    /// `SelfOwn` and is advertised only by its own producer, so on this node it is
    /// held-but-not-advertised. Before #416 the receive diff used the advertise
    /// view, so this row stayed in `want` forever and the round never converged.
    #[tokio::test]
    async fn holdings_include_held_but_not_advertised_rows() {
        let this_node = "this-node";
        let other_producer = "other-producer";
        let (backend, bridge) = make_bridge(&[this_node.to_string(), other_producer.to_string()]);
        for k in [this_node, other_producer] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(k, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        // A federation-tier, SELF-scoped attestation authored by `other_producer`
        // — held here, advertisable only by its own producer. The dimension is
        // incidental to this test (it asserts SCOPE projection, not dimension), so
        // it uses a self-descriptive `identity:*` dimension: CIRISPersist v22's
        // AV-62 anti-Goodhart gate forbids a SELF-attested `capacity:*` row (you
        // can't rate your own reputation), which the old `capacity:example:v1`
        // fixture tripped — but self-attesting one's own identity is legitimate.
        let now = Utc::now().trunc_subsecs(6);
        let attestation_id = uuid::Uuid::new_v4().to_string();
        let mut envelope = serde_json::json!({
            "attesting_key_id": other_producer,
            "attested_key_id": other_producer,
            "attestation_type": "scores",
            "dimension": "identity:example:v1",
            "cohort_scope": "self",
        });
        bind_attestation_envelope(
            &mut envelope,
            now,
            &attestation_id,
            other_producer,
            "scores",
            other_producer,
            &[other_producer],
            "self",
        );
        let (hash_hex, ed_sig, pqc_sig) = sign_attestation_envelope(other_producer, &envelope);
        let att = Attestation {
            attestation_id,
            attesting_key_id: other_producer.to_string(),
            attested_key_id: other_producer.to_string(),
            attestation_type: "scores".to_string(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: hash_hex,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: other_producer.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec![other_producer.to_string()],
            withdraws_admission_rule: None,
            additional_scrubs: Vec::new(),
            cohort_scope: "self".to_string(),
            tier: "federation".to_string(),
            promoted_at: None,
        };
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .expect("seed self-scoped attestation");
        // This node publishes only its OWN — NOT other_producer's. (The single
        // seeded row is the only attestation in local state.)
        let publish_set = vec![this_node.to_string()];
        let selector: CohortProvider = Arc::new(move || publish_set.clone());
        let bridge = bridge.with_self_provider(Some(selector));

        // The ADVERTISE view (projection-filtered) EXCLUDES the row — a self-scoped
        // row from another producer is held-but-not-own, so it is not advertised.
        let advertised = bridge.list_attestations(None).await;
        assert!(
            advertised.is_empty(),
            "a self-scoped row from another producer must NOT be advertised here, got {advertised:?}"
        );
        // The HOLDINGS view (raw, #416) INCLUDES it — the convergence invariant:
        // the round's `want = remote ∖ holdings` can now shrink for this row after
        // admission, where the pre-#416 advertise-filtered view left it stuck.
        let holdings = bridge.list_attestation_holdings().await;
        assert_eq!(
            holdings.len(),
            1,
            "list_attestation_holdings MUST contain the held row (#416 convergence \
             invariant) even though the advertise view excludes it"
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

    /// persist v24.2.0 / CIRISPersist#565 — the pure outcome mapping, exhaustive
    /// over `KeyRefusalReason::ALL`: both duplicate halves (`Unchanged` AND
    /// `already_anchored_identical`) map to `Duplicate` with NO ledger token
    /// (mapping only the new variant would leave the common baked-seed re-offer
    /// path misreported); every other reason maps to `Refused` whose message
    /// carries the stable token, which is also returned for the receive-plane
    /// mirror to count.
    #[test]
    fn key_outcome_mapping_is_exhaustive_and_names_the_branch() {
        // The three progress outcomes admit, no token.
        for o in [
            ReplicatedKeyOutcome::Inserted,
            ReplicatedKeyOutcome::Upgraded,
            ReplicatedKeyOutcome::Superseded,
        ] {
            let (a, t) = key_outcome_to_apply(Ok(o), "h");
            assert!(matches!(a, ApplyOutcome::Admitted), "{a:?}");
            assert!(t.is_none());
        }
        // Both duplicate halves: Duplicate, never counted as a refusal.
        let (a, t) = key_outcome_to_apply(Ok(ReplicatedKeyOutcome::Unchanged), "h");
        assert!(matches!(a, ApplyOutcome::Duplicate), "{a:?}");
        assert!(t.is_none());
        let (a, t) = key_outcome_to_apply(
            Ok(ReplicatedKeyOutcome::Refused {
                reason: KeyRefusalReason::AlreadyAnchoredIdentical,
            }),
            "h",
        );
        assert!(
            matches!(a, ApplyOutcome::Duplicate),
            "already_anchored_identical is the receiver ALREADY HOLDING what was \
             offered (a re-encoding of an anchored record) — Duplicate, not a \
             security-shaped refusal; got {a:?}"
        );
        assert!(t.is_none());
        // Every OTHER reason: Refused carrying the stable token, token returned.
        for &reason in KeyRefusalReason::ALL {
            if matches!(reason, KeyRefusalReason::AlreadyAnchoredIdentical) {
                continue;
            }
            let (a, t) = key_outcome_to_apply(Ok(ReplicatedKeyOutcome::Refused { reason }), "h");
            let ApplyOutcome::Refused(msg) = &a else {
                panic!("{} must map to Refused, got {a:?}", reason.as_str());
            };
            assert!(
                msg.contains(reason.as_str()),
                "the refusal message must carry the branch token {}: {msg}",
                reason.as_str()
            );
            assert_eq!(t, Some(reason.as_str()), "the mirror counts the token");
        }
    }

    /// persist v24.2.0 / #565 — the wire drive: a pubkey swap offered through
    /// the real apply choke books on BOTH receive-plane mirror axes (kind +
    /// stable token) and surfaces the branch in the refusal message.
    #[tokio::test]
    async fn a_pubkey_swap_books_on_both_receive_mirror_axes() {
        let (backend, bridge, metrics) = make_metered_bridge(&[]);
        // The node already holds k1 at its canonical pubkeys...
        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record("k1", identity_type::NODE),
            })
            .await
            .expect("seed k1");
        // ...and a peer offers k1 under DIFFERENT pubkeys (the hijack shape).
        let mut swapped = fixture_key_record("k1", identity_type::NODE);
        let (other_ed, other_mldsa) = hybrid_pubkeys("attacker-keys");
        swapped.pubkey_ed25519_base64 = other_ed;
        swapped.pubkey_ml_dsa_65_base64 = other_mldsa;
        let bytes =
            serde_json::to_vec(&SignedKeyRecord { record: swapped }).expect("serialize offer");

        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::Key, &bytes, Some("peer-x"))
            .await;
        let ApplyOutcome::Refused(msg) = &outcome else {
            panic!("a pubkey swap must be Refused, got {outcome:?}");
        };
        // WHICH branch classifies is persist's unit (certified upstream; on the
        // MemoryBackend this shape currently books `store_conflict` — its
        // plan-free write site — where the planned sqlite/postgres paths name
        // `pubkey_swap`). EDGE's unit is coherence: the message carries exactly
        // one stable token from the closed set, and BOTH mirror axes book it.
        let snap = metrics.snapshot();
        let booked: Vec<&str> = snap
            .key_apply_refusals_by_reason
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(booked.len(), 1, "exactly one token booked: {booked:?}");
        let token = booked[0];
        assert!(
            KeyRefusalReason::ALL.iter().any(|r| r.as_str() == token),
            "the booked token is from the closed contract set: {token}"
        );
        assert!(
            msg.contains(token),
            "the message names the SAME branch the ledger booked ({token}): {msg}"
        );
        assert_eq!(
            snap.apply_refusals_by_kind.get(&EnvelopeKind::Key).copied(),
            Some(1),
            "the kind axis books at the #425 choke"
        );
        assert_eq!(
            snap.key_apply_refusals_by_reason.get(token).copied(),
            Some(1),
            "the token axis books the typed branch once"
        );
    }

    /// CIRISEdge#430 — an ADMITTED revocation fires the revocation observer
    /// with the REVOKED key_id (the transit gate's event-driven cache
    /// invalidation signal); a non-admitted apply (garbage) never fires it.
    ///
    ///
    /// `test-anchor`-gated: persist v30.8.0 (CIRISPersist#628 / CIRISConstitution#87)
    /// requires a THIRD-PARTY revocation's revoker to hold `slash` conferred by a
    /// root THIS NODE trusts, and standing up a valid trust root needs the accord
    /// roster helpers persist exports only behind `test-anchor` (the same fence
    /// #386's ALLOW-path twin uses; its CI lane runs the whole lib, so this is
    /// real coverage). The test MUST stay third-party (revoked ≠ revoking) — its
    /// whole value is proving the observer fires with the REVOKED key, not the
    /// revoker's, so a self-revocation or empty-revoker shortcut would hide a
    /// fire-with-the-wrong-field bug. We model the FULL production-shaped
    /// authorized graph on purpose: the `slash`-wielding revoker is a `user`
    /// (CC 4.4.3.4.3 — infrastructure has no agency), a trusted external root
    /// confers `slash` on it, and only then does edge's apply path admit the
    /// revocation and fire the observer. That is exactly what a real node will
    /// see, so a green here is confidence the prod path behaves as intended.
    #[cfg(feature = "test-anchor")]
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // roster + trust graph + authorized revocation: one scenario
    async fn admitted_revocation_fires_the_observer_with_the_revoked_key() {
        use ciris_persist::federation::accord_test_support::{register_accord_holder, Identity};
        use ciris_persist::federation::genesis::effective_accord_holder_records;

        let (backend, bridge) = make_bridge(&[]);
        let local = "self-node";
        let root = "trust-root";
        let lifecycle_attester = "accord-holder-live";
        // The revoker is a USER: only agency-bearing identities may hold `slash`.
        let revoker = "revoker-user";
        let target = "bad-peer";

        // The live accord family, registered at their pinned pubkeys so the
        // root's accord:lifecycle row verifies against the real roster.
        let holders: Vec<Identity> = effective_accord_holder_records()
            .iter()
            .map(|r| Identity::new(&r.record.key_id))
            .collect();
        for h in &holders {
            register_accord_holder(&*backend, h)
                .await
                .expect("register accord holder");
        }

        // Register the identities. The revoker is a USER (agency); local/root are
        // infrastructure; the lifecycle attester is an ACCORD_HOLDER and must
        // carry attestation_evidence (CIRISPersist v22 #543/#513).
        for (k, it) in [
            (local, identity_type::NODE),
            (root, identity_type::NODE),
            (revoker, identity_type::USER),
            (target, identity_type::NODE),
            (lifecycle_attester, identity_type::ACCORD_HOLDER),
        ] {
            let mut record = fixture_key_record(k, it);
            if it == identity_type::ACCORD_HOLDER {
                record.attestation_evidence = Some(serde_json::json!({
                    "platform_attestation": {
                        "Android": {
                            "key_attestation_chain": [
                                [0x30, 0x82, 0x01, 0x00],
                                [0x30, 0x82, 0x02, 0x00],
                            ],
                            "play_integrity_token": "eyJhbGciOiJIUzI1NiJ9.fake.token",
                            "strongbox_backed": true,
                        }
                    },
                    "nonce_captured_at": Utc::now().to_rfc3339(),
                }));
            }
            backend
                .put_public_key(SignedKeyRecord { record })
                .await
                .expect("seed key");
        }

        // The authorized trust graph, exactly the production shape
        // `check_revocation_authority` walks: root self-declares (charter), THIS
        // NODE trusts it, it is live, and it confers `slash` on the revoker.
        backend.set_node_key_id(local);
        seed_root_charter(&backend, root, &[format!("{root}-successor")]).await;
        seed_delegates_to(
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
            revoker,
            &serde_json::json!([ciris_persist::federation::admission::DELEGATION_SCOPE_SLASH]),
        )
        .await;

        let fired: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&fired);
        let bridge = bridge.with_revocation_observer(Some(Arc::new(move |k: &str| {
            sink.lock().expect("observer sink").push(k.to_string());
        })));

        let now = Utc::now().trunc_subsecs(6);
        let mut rev = ciris_persist::federation::types::Revocation {
            revocation_id: "rev-1".to_string(),
            revoked_key_id: target.to_string(),
            revoking_key_id: revoker.to_string(),
            reason: None,
            revoked_at: now,
            effective_at: now,
            revocation_envelope: serde_json::json!({}),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: revoker.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            observed_region: "us".to_string(),
            revoked_after: None,
        };
        ciris_persist::federation::admission::bind_revocation_into_envelope(&mut rev)
            .expect("bind revocation envelope");
        let (hash, ed_sig, pqc_sig) = sign_attestation_envelope(revoker, &rev.revocation_envelope);
        rev.original_content_hash = hash;
        rev.scrub_signature_classical = ed_sig;
        rev.scrub_signature_pqc = pqc_sig;
        let bytes =
            serde_json::to_vec(&SignedRevocation { revocation: rev }).expect("serialize rev");
        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::Revocation, &bytes, None)
            .await;
        assert!(
            outcome.is_admitted(),
            "the fixture revocation must admit (else the observer half is untested): {outcome:?}"
        );
        assert_eq!(
            *fired.lock().expect("read sink"),
            vec!["bad-peer".to_string()],
            "the observer fires ONCE with the REVOKED key_id"
        );

        // A non-admitted apply (garbage) never fires the observer.
        let _ = bridge
            .apply_envelope_bytes(EnvelopeKind::Revocation, b"{not a revocation}", None)
            .await;
        assert_eq!(
            fired.lock().expect("read sink").len(),
            1,
            "a refused/undeserializable revocation fires nothing"
        );
    }

    /// CIRISEdge#457 — the receive plane's distinct-states discriminator:
    /// an accepted apply books `replication_applied_total`, a duplicate books
    /// `replication_duplicate_total`, and BOTH are empty on a node that was
    /// offered nothing — so "applied all N" and "received nothing" no longer
    /// render identically (the last uncounted limb of the #433 arc, receive
    /// side; the mirror of #434).
    #[tokio::test]
    async fn accepted_apply_and_duplicate_are_counted_distinctly_from_idle() {
        let (_backend, bridge, metrics) = make_metered_bridge(&[]);
        // (a) IDLE — nothing offered: both accepted-apply counters empty.
        let idle = metrics.snapshot();
        assert!(
            idle.replication_applied_total.is_empty()
                && idle.replication_duplicate_total.is_empty(),
            "an idle node books no accepted applies"
        );
        // (b) Apply a FRESH (never-seeded) Key row → Admitted → applied_total.
        let rec = fixture_key_record("fresh-457", identity_type::NODE);
        let bytes = serde_json::to_vec(&SignedKeyRecord {
            record: rec.clone(),
        })
        .expect("serialize key");
        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::Key, &bytes, Some("peer-457"))
            .await;
        assert!(outcome.is_admitted(), "fresh row admits: {outcome:?}");
        let snap = metrics.snapshot();
        assert_eq!(
            snap.replication_applied_total
                .get(&EnvelopeKind::Key)
                .copied(),
            Some(1),
            "an accepted apply is now counted — the state that used to read {{}} \
             is now distinguishable from idle (CIRISEdge#457)"
        );
        // The applied axis is distinct from the duplicate axis — an admit
        // books ONLY applied, never both (the #433 distinct-states rule).
        assert!(
            snap.replication_duplicate_total.is_empty(),
            "an Admitted apply books applied_total, not duplicate_total"
        );
    }

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
                .apply_envelope_bytes(kind, b"{not a signed record}", None)
                .await;
            assert!(
                !r.is_admitted(),
                "expected garbage refused for {kind:?}, got {r:?}"
            );
            // CIRISEdge#425 — garbage must classify as a NAMED non-admit (a reason
            // the choke point logs), never a bare drop.
            assert!(
                matches!(r, ApplyOutcome::Refused(_) | ApplyOutcome::Deserialize(_)),
                "garbage must be a named Refused/Deserialize for {kind:?}, got {r:?}"
            );
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
            .apply_envelope_bytes(EnvelopeKind::TransportDestination, &bytes, None)
            .await;

        assert!(
            !admitted.is_admitted(),
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

    // ── CIRISEdge#394 (E4 lockstep) — the pass-through verdict pins ──
    //
    // Edge produces NONE of the five authority-signed declaration planes
    // (Family / Community / FamilyMembershipRevocation /
    // CommunityMembershipRevocation / LocationProof) — see the verdict
    // comment on `apply_family`. These tests pin the property that verdict
    // rests on: a record signed EXACTLY per persist's E4 contract
    // (hybrid-sign `record.signing_envelope()` as the registered authority)
    // survives edge's full forward path — apply (persist ADMITS, the
    // fail-closed oracle) → advertise → fetch → RE-ADMISSION on a second
    // node — with the three wrapper fields byte-identical throughout.
    //
    // Fixture signing mirrors persist's pub(crate)
    // `federation::tier_ingest::test_support::sign_*`: the generic hybrid
    // envelope signer (`sign_attestation_envelope`, despite its name) is the
    // SAME construction persist verifies — JCS canonical bytes, Ed25519 over
    // canonical, ML-DSA-65 over `canonical ‖ ed25519_sig`.

    /// Register a deterministic hybrid fixture key for each `(id,
    /// identity_type)`, so the authority resolves at `verify_*_admission` and
    /// the FK'd ids exist. The identity_type matters on the Community plane:
    /// an `agent`-role member must be steward-bound (CC 3.2 / CC 3.4.7.1),
    /// while a `user`-role member self-anchors — the fixtures register
    /// community members as `user`.
    async fn register_fixture_keys(backend: &MemoryBackend, keys: &[(&str, &str)]) {
        for (k, ty) in keys {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(k, ty),
                })
                .await
                .expect("register fixture key");
        }
    }

    /// Hybrid-sign a [`Family`] for submission as `authority_key_id` —
    /// persist's `tier_ingest::test_support::sign_family` shape.
    fn sign_family_fixture(authority_key_id: &str, family: Family) -> SignedFamily {
        let (_h, classical, pqc) =
            sign_attestation_envelope(authority_key_id, &family.signing_envelope());
        SignedFamily {
            family,
            authority_key_id: authority_key_id.to_string(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
        }
    }

    /// Hybrid-sign a [`Community`] — mirrors [`sign_family_fixture`].
    fn sign_community_fixture(authority_key_id: &str, community: Community) -> SignedCommunity {
        let (_h, classical, pqc) =
            sign_attestation_envelope(authority_key_id, &community.signing_envelope());
        SignedCommunity {
            community,
            authority_key_id: authority_key_id.to_string(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
        }
    }

    /// Hybrid-sign a [`FamilyMembershipRevocation`] — mirrors
    /// [`sign_family_fixture`].
    fn sign_family_membership_revocation_fixture(
        authority_key_id: &str,
        revocation: FamilyMembershipRevocation,
    ) -> SignedFamilyMembershipRevocation {
        let (_h, classical, pqc) =
            sign_attestation_envelope(authority_key_id, &revocation.signing_envelope());
        SignedFamilyMembershipRevocation {
            family_membership_revocation: revocation,
            authority_key_id: authority_key_id.to_string(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
        }
    }

    /// Hybrid-sign a [`CommunityMembershipRevocation`] — mirrors
    /// [`sign_family_fixture`].
    fn sign_community_membership_revocation_fixture(
        authority_key_id: &str,
        revocation: CommunityMembershipRevocation,
    ) -> SignedCommunityMembershipRevocation {
        let (_h, classical, pqc) =
            sign_attestation_envelope(authority_key_id, &revocation.signing_envelope());
        SignedCommunityMembershipRevocation {
            community_membership_revocation: revocation,
            authority_key_id: authority_key_id.to_string(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
        }
    }

    /// Hybrid-sign a [`LocationProof`] — mirrors [`sign_family_fixture`].
    fn sign_location_proof_fixture(
        authority_key_id: &str,
        proof: LocationProof,
    ) -> SignedLocationProof {
        let (_h, classical, pqc) =
            sign_attestation_envelope(authority_key_id, &proof.signing_envelope());
        SignedLocationProof {
            location_proof: proof,
            authority_key_id: authority_key_id.to_string(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
        }
    }

    /// A minimal admissible [`Family`]: `founder_only` is a canonical
    /// `consensus_protocol` form and every member key_id must be registered
    /// (persist `validate_family_members`); `family_key_id` itself is
    /// keyless (persist v24.0.0 dropped that FK).
    fn fixture_family(family_key_id: &str, member_key_id: &str) -> Family {
        Family {
            family_key_id: family_key_id.to_string(),
            family_name: "E4 Pin Household".to_string(),
            members: vec![FamilyMember {
                key_id: member_key_id.to_string(),
                joined_at: "2026-07-01T00:00:00Z".parse().expect("rfc3339"),
                role: None,
            }],
            founded_at: "2026-07-01T00:00:00Z".parse().expect("rfc3339"),
            consensus_protocol: "founder_only".to_string(),
            consensus_protocol_entrenched: false,
            persist_row_hash: String::new(),
        }
    }

    /// A minimal admissible [`Community`] — structural mirror of
    /// [`fixture_family`].
    fn fixture_community(community_key_id: &str, member_key_id: &str) -> Community {
        Community {
            community_key_id: community_key_id.to_string(),
            community_name: "E4 Pin Co-op".to_string(),
            members: vec![CommunityMember {
                key_id: member_key_id.to_string(),
                joined_at: "2026-07-01T00:00:00Z".parse().expect("rfc3339"),
                role: None,
            }],
            founded_at: "2026-07-01T00:00:00Z".parse().expect("rfc3339"),
            consensus_protocol: "founder_only".to_string(),
            policy_blob: None,
            persist_row_hash: String::new(),
        }
    }

    /// Drive ONE E4 plane through edge's complete forward path and assert
    /// the pass-through verdict:
    ///
    /// 1. node A applies the pre-signed wire bytes → persist ADMITS (the
    ///    v21.0.0 fail-closed verify is the oracle that the bytes edge
    ///    forwarded still carry a valid authority signature);
    /// 2. A advertises exactly one ref and serves bytes that hash back to
    ///    the advertised hash (byte-integrity of the serve half);
    /// 3. the three E4 wrapper fields and the signed canonical envelope
    ///    survive the apply→store→serve round trip unmodified (persist
    ///    stamps only the server-computed `persist_row_hash`, which is
    ///    excluded from the signed envelope by construction);
    /// 4. node B re-admits the bytes A SERVED — the lockstep property
    ///    itself: what edge passes on remains admissible at the next hop.
    async fn pin_e4_forward_path<T>(
        kind: EnvelopeKind,
        cohort: &[&str],
        registered_keys: &[(&str, &str)],
        signed: &T,
        wrapper_fields_of: impl Fn(&T) -> (String, String, Option<String>),
        signing_envelope_of: impl Fn(&T) -> serde_json::Value,
    ) where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let cohort: Vec<String> = cohort.iter().map(|s| (*s).to_string()).collect();

        // Node A — the forwarding edge.
        let (backend_a, bridge_a) = make_bridge(&cohort);
        register_fixture_keys(&backend_a, registered_keys).await;
        let wire = serde_json::to_vec(signed).expect("signed wrapper serializes");
        let outcome = bridge_a.apply_envelope_bytes(kind, &wire, None).await;
        assert!(
            outcome.is_admitted(),
            "persist must ADMIT the pre-signed {kind:?} edge forwarded \
             (E4 fail-closed oracle); got {outcome:?}"
        );

        // Serve half: advertise + fetch, hash-integral.
        let refs = bridge_a.list_envelope_refs(kind).await;
        assert_eq!(refs.len(), 1, "exactly one advertised {kind:?} envelope");
        let served = bridge_a
            .fetch_envelope_bytes(kind, &refs[0].envelope_hash)
            .await
            .expect("advertised envelope must be fetchable");
        let served_hash: [u8; 32] = Sha256::digest(&served).into();
        assert_eq!(
            served_hash, refs[0].envelope_hash,
            "served bytes must hash back to the advertised hash"
        );

        // Signature preservation through the round trip.
        let decoded: T = serde_json::from_slice(&served).expect("served bytes decode");
        assert_eq!(
            wrapper_fields_of(&decoded),
            wrapper_fields_of(signed),
            "authority_key_id + scrub signatures must survive byte-identical"
        );
        assert_eq!(
            signing_envelope_of(&decoded),
            signing_envelope_of(signed),
            "the signed canonical envelope must survive the forward path"
        );

        // Node B — re-admission of what A served IS the lockstep property.
        let (backend_b, bridge_b) = make_bridge(&cohort);
        register_fixture_keys(&backend_b, registered_keys).await;
        let outcome_b = bridge_b.apply_envelope_bytes(kind, &served, None).await;
        assert!(
            outcome_b.is_admitted(),
            "node B must re-admit the {kind:?} bytes node A served; got {outcome_b:?}"
        );
    }

    #[tokio::test]
    async fn e4_family_forward_path_preserves_authority_signature() {
        let signed = sign_family_fixture("e4-authority", fixture_family("e4-family", "e4-member"));
        pin_e4_forward_path(
            EnvelopeKind::Family,
            &["e4-member"], // cohort-scoped advertise: a member must be in cohort
            &[
                ("e4-authority", identity_type::AGENT),
                ("e4-member", identity_type::AGENT),
            ],
            &signed,
            |s: &SignedFamily| {
                (
                    s.authority_key_id.clone(),
                    s.scrub_signature_classical.clone(),
                    s.scrub_signature_pqc.clone(),
                )
            },
            |s| s.family.signing_envelope(),
        )
        .await;
    }

    #[tokio::test]
    async fn e4_community_forward_path_preserves_authority_signature() {
        let signed = sign_community_fixture(
            "e4-authority",
            fixture_community("e4-community", "e4-member"),
        );
        pin_e4_forward_path(
            EnvelopeKind::Community,
            &["e4-member"],
            // CC 3.2 steward-binding gate: a non-infra community member must
            // root in an accountable human — a `user`-role member self-anchors.
            // And unlike the KEYLESS family (persist v24.0.0 dropped that FK),
            // `community_key_id` must itself exist in federation_keys.
            &[
                ("e4-authority", identity_type::AGENT),
                ("e4-community", identity_type::AGENT),
                ("e4-member", identity_type::USER),
            ],
            &signed,
            |s: &SignedCommunity| {
                (
                    s.authority_key_id.clone(),
                    s.scrub_signature_classical.clone(),
                    s.scrub_signature_pqc.clone(),
                )
            },
            |s| s.community.signing_envelope(),
        )
        .await;
    }

    #[tokio::test]
    async fn e4_family_membership_revocation_forward_path_preserves_authority_signature() {
        // FK: family_key_id AND removed_identity_key_id must exist in
        // federation_keys (persist checks both at put).
        let signed = sign_family_membership_revocation_fixture(
            "e4-authority",
            FamilyMembershipRevocation {
                family_key_id: "e4-family".to_string(),
                removed_identity_key_id: "e4-member".to_string(),
                removed_at: "2026-07-02T00:00:00Z".parse().expect("rfc3339"),
                effective_at: "2026-07-02T00:00:00Z".parse().expect("rfc3339"),
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
            },
        );
        pin_e4_forward_path(
            EnvelopeKind::FamilyMembershipRevocation,
            &[], // tombstone plane advertises Global — no cohort needed
            &[
                ("e4-authority", identity_type::AGENT),
                ("e4-family", identity_type::AGENT),
                ("e4-member", identity_type::AGENT),
            ],
            &signed,
            |s: &SignedFamilyMembershipRevocation| {
                (
                    s.authority_key_id.clone(),
                    s.scrub_signature_classical.clone(),
                    s.scrub_signature_pqc.clone(),
                )
            },
            |s| s.family_membership_revocation.signing_envelope(),
        )
        .await;
    }

    #[tokio::test]
    async fn e4_community_membership_revocation_forward_path_preserves_authority_signature() {
        // effective_at must NOT be future-dated (SecReview F4: community
        // removal is immediate for forward secrecy).
        let signed = sign_community_membership_revocation_fixture(
            "e4-authority",
            CommunityMembershipRevocation {
                community_key_id: "e4-community".to_string(),
                removed_identity_key_id: "e4-member".to_string(),
                removed_at: "2026-07-02T00:00:00Z".parse().expect("rfc3339"),
                effective_at: "2026-07-02T00:00:00Z".parse().expect("rfc3339"),
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
            },
        );
        pin_e4_forward_path(
            EnvelopeKind::CommunityMembershipRevocation,
            &[],
            &[
                ("e4-authority", identity_type::AGENT),
                ("e4-community", identity_type::AGENT),
                ("e4-member", identity_type::AGENT),
            ],
            &signed,
            |s: &SignedCommunityMembershipRevocation| {
                (
                    s.authority_key_id.clone(),
                    s.scrub_signature_classical.clone(),
                    s.scrub_signature_pqc.clone(),
                )
            },
            |s| s.community_membership_revocation.signing_envelope(),
        )
        .await;
    }

    #[tokio::test]
    async fn e4_location_proof_forward_path_preserves_authority_signature() {
        // "87283472bffffff" is a canonical resolution-7 H3 cell (verified
        // against h3o 0.7.1, the version in this build's dependency graph) —
        // within the §0.8.1 rough-only bound persist enforces at admission.
        let signed = sign_location_proof_fixture(
            "e4-authority",
            LocationProof {
                subject_key_id: "e4-subject".to_string(),
                cell_id: "87283472bffffff".to_string(),
                cell_resolution: 7,
                asserted_at: "2026-07-01T00:00:00Z".parse().expect("rfc3339"),
                valid_until: None,
                attestation_evidence: None,
                withdrawn_at: None,
                persist_row_hash: String::new(),
            },
        );
        pin_e4_forward_path(
            EnvelopeKind::LocationProof,
            &["e4-subject"], // cohort-scoped advertise keys on the subject
            &[
                ("e4-authority", identity_type::AGENT),
                ("e4-subject", identity_type::AGENT),
            ],
            &signed,
            |s: &SignedLocationProof| {
                (
                    s.authority_key_id.clone(),
                    s.scrub_signature_classical.clone(),
                    s.scrub_signature_pqc.clone(),
                )
            },
            |s| s.location_proof.signing_envelope(),
        )
        .await;
    }

    /// CIRISEdge#394 — the fail-closed half of the pass-through verdict. An
    /// UNSIGNED declaration (empty wrapper fields — the exact legacy shape a
    /// pre-v21 producer emitted) DECODES fine (the wrapper fields are
    /// additive `#[serde(default)]`) and is REFUSED at admission: a named
    /// `Refused`, never `Admitted` and never a wire-shape `Deserialize`
    /// error. Edge adds no signing of its own, so nothing on the edge side
    /// can heal — or mask — a stripped authority signature.
    #[tokio::test]
    async fn e4_unsigned_declarations_refuse_at_admission() {
        let (backend, bridge) = make_bridge(&[]);
        // Every FK'd id exists, so the ONLY failing gate is the E4 verify
        // (which runs FIRST on every put_* — verify-before-mutation).
        register_fixture_keys(
            &backend,
            &[
                ("e4-family", identity_type::AGENT),
                ("e4-community", identity_type::AGENT),
                ("e4-member", identity_type::USER),
                ("e4-subject", identity_type::AGENT),
            ],
        )
        .await;

        let unsigned: Vec<(EnvelopeKind, Vec<u8>)> = vec![
            (
                EnvelopeKind::Family,
                serde_json::to_vec(&SignedFamily {
                    family: fixture_family("e4-family", "e4-member"),
                    authority_key_id: String::new(),
                    scrub_signature_classical: String::new(),
                    scrub_signature_pqc: None,
                })
                .expect("serialize"),
            ),
            (
                EnvelopeKind::Community,
                serde_json::to_vec(&SignedCommunity {
                    community: fixture_community("e4-community", "e4-member"),
                    authority_key_id: String::new(),
                    scrub_signature_classical: String::new(),
                    scrub_signature_pqc: None,
                })
                .expect("serialize"),
            ),
            (
                EnvelopeKind::FamilyMembershipRevocation,
                serde_json::to_vec(&SignedFamilyMembershipRevocation {
                    family_membership_revocation: FamilyMembershipRevocation {
                        family_key_id: "e4-family".to_string(),
                        removed_identity_key_id: "e4-member".to_string(),
                        removed_at: "2026-07-02T00:00:00Z".parse().expect("rfc3339"),
                        effective_at: "2026-07-02T00:00:00Z".parse().expect("rfc3339"),
                        reason: None,
                        witness_set: Vec::new(),
                        persist_row_hash: String::new(),
                    },
                    authority_key_id: String::new(),
                    scrub_signature_classical: String::new(),
                    scrub_signature_pqc: None,
                })
                .expect("serialize"),
            ),
            (
                EnvelopeKind::CommunityMembershipRevocation,
                serde_json::to_vec(&SignedCommunityMembershipRevocation {
                    community_membership_revocation: CommunityMembershipRevocation {
                        community_key_id: "e4-community".to_string(),
                        removed_identity_key_id: "e4-member".to_string(),
                        removed_at: "2026-07-02T00:00:00Z".parse().expect("rfc3339"),
                        effective_at: "2026-07-02T00:00:00Z".parse().expect("rfc3339"),
                        reason: None,
                        witness_set: Vec::new(),
                        persist_row_hash: String::new(),
                    },
                    authority_key_id: String::new(),
                    scrub_signature_classical: String::new(),
                    scrub_signature_pqc: None,
                })
                .expect("serialize"),
            ),
            (
                EnvelopeKind::LocationProof,
                serde_json::to_vec(&SignedLocationProof {
                    location_proof: LocationProof {
                        subject_key_id: "e4-subject".to_string(),
                        cell_id: "87283472bffffff".to_string(),
                        cell_resolution: 7,
                        asserted_at: "2026-07-01T00:00:00Z".parse().expect("rfc3339"),
                        valid_until: None,
                        attestation_evidence: None,
                        withdrawn_at: None,
                        persist_row_hash: String::new(),
                    },
                    authority_key_id: String::new(),
                    scrub_signature_classical: String::new(),
                    scrub_signature_pqc: None,
                })
                .expect("serialize"),
            ),
        ];
        for (kind, bytes) in unsigned {
            let outcome = bridge.apply_envelope_bytes(kind, &bytes, None).await;
            assert!(
                matches!(outcome, ApplyOutcome::Refused(_)),
                "an unsigned {kind:?} must be REFUSED at persist's E4 gate \
                 (not admitted, not a wire-shape error); got {outcome:?}"
            );
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
        let now = Utc::now().trunc_subsecs(6);
        let attestation_id = uuid::Uuid::new_v4().to_string();
        let mut envelope = serde_json::json!({
            "attesting_key_id": attesting_id,
            "attested_key_id": attested_id,
            "attestation_type": "delegates_to",
        });
        bind_attestation_envelope(
            &mut envelope,
            now,
            &attestation_id,
            attesting_id,
            "delegates_to",
            attested_id,
            &[],
            "federation",
        );
        let (hash, ed_sig, pqc_sig) = sign_attestation_envelope(attesting_id, &envelope);
        let att = Attestation {
            attestation_id,
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
            additional_scrubs: Vec::new(),
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
        let now = Utc::now().trunc_subsecs(6);
        let attestation_id = uuid::Uuid::new_v4().to_string();
        let mut envelope = serde_json::json!({
            "attesting_key_id": attester,
            "attested_key_id": key_id,
            "attestation_type": "delegates_to",
        });
        bind_attestation_envelope(
            &mut envelope,
            now,
            &attestation_id,
            attester,
            "delegates_to",
            key_id,
            &[],
            "federation",
        );
        let (hash, ed_sig, pqc_sig) = sign_attestation_envelope(attester, &envelope);
        backend
            .put_attestation(SignedAttestation {
                attestation: Attestation {
                    attestation_id,
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
                    additional_scrubs: Vec::new(),
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
    /// (Un-`cfg`d for CIRISEdge#433: the withhold-ledger tests below seed the same
    /// gated row on the default feature set, so this is no longer test-anchor-only.)
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
        seed_scoped_attestation(
            backend,
            id,
            attester,
            subject,
            attestation_type,
            "federation",
            envelope,
        )
        .await;
    }

    /// CIRISEdge#352 — [`seed_raw_attestation`] with an explicit
    /// `cohort_scope`, for tests exercising the advertise projection across
    /// the audience axis. `self` / `affiliations` / `federation` are the
    /// membership-free scopes MemoryBackend's write gate admits without
    /// family/community rows (`family`/`community` require seeded
    /// membership).
    /// CIRISPersist#598 + #643 (v31.0.0) — stamp the SIGNED bindings an attestation
    /// envelope must now carry before signing, so the scrub signature covers them:
    /// the `asserted_at` instant (the fold orders on it) and the `row` mirror of the
    /// typed columns (else a relay rewrites attestation_id/attester/type/subject/
    /// cohort while the signature still verifies — the subject-blindness class).
    /// `subject_key_ids` omitted ⇔ the column is empty; `weight` omitted ⇔ NULL.
    /// The single sink every attestation fixture routes through.
    #[allow(clippy::too_many_arguments)] // mirrors the attestation's typed-column set
    fn bind_attestation_envelope(
        envelope: &mut serde_json::Value,
        asserted_at: chrono::DateTime<chrono::Utc>,
        attestation_id: &str,
        attesting_key_id: &str,
        attestation_type: &str,
        attested_key_id: &str,
        subject_key_ids: &[&str],
        cohort_scope: &str,
    ) {
        let Some(obj) = envelope.as_object_mut() else {
            return;
        };
        obj.entry("asserted_at")
            .or_insert_with(|| serde_json::json!(asserted_at.to_rfc3339()));
        let mut row = serde_json::json!({
            "attestation_id": attestation_id,
            "attesting_key_id": attesting_key_id,
            "attestation_type": attestation_type,
            "attested_key_id": attested_key_id,
            "cohort_scope": cohort_scope,
        });
        if !subject_key_ids.is_empty() {
            row["subject_key_ids"] = serde_json::json!(subject_key_ids);
        }
        obj.entry("row").or_insert(row);
    }

    async fn seed_scoped_attestation(
        backend: &MemoryBackend,
        id: &str,
        attester: &str,
        subject: &str,
        attestation_type: &str,
        cohort_scope: &str,
        mut envelope: serde_json::Value,
    ) {
        // CIRISPersist#598 (v31.0.0): truncate to MICROSECONDS — postgres TIMESTAMPTZ
        // can't store sub-µs, so a producer that mints ns precision makes an op
        // sequence a strict order on sqlite/memory but a TIE on postgres. The fold
        // refuses ns rows outright.
        let now = Utc::now().trunc_subsecs(6);
        // #598: the fold orders on the `asserted_at` COLUMN, so that instant must be
        // SIGNED — stamp it into the envelope (matching the column) before signing,
        // or the row is REFUSED as an unbound replay. RFC3339, the shape persist's
        // own fixtures bind.
        bind_attestation_envelope(
            &mut envelope,
            now,
            id,
            attester,
            attestation_type,
            subject,
            &[subject],
            cohort_scope,
        );
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
            additional_scrubs: Vec::new(),
            cohort_scope: cohort_scope.to_string(),
            tier: "federation".to_string(),
            promoted_at: None,
        };
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .expect("seed trust-graph attestation");
    }

    /// CIRISEdge#462 — build a minimal `Attestation` carrying `dimension` inside
    /// its envelope (CC 2.1), for the pure G2-carve predicate test. All other
    /// fields are placeholders — only `attestation_envelope/dimension` is read.
    fn att_with_dimension(dimension: Option<&str>) -> Attestation {
        let now = Utc::now();
        Attestation {
            attestation_id: "t".into(),
            attesting_key_id: "a".into(),
            attested_key_id: "s".into(),
            attestation_type: "scores".into(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: match dimension {
                Some(d) => serde_json::json!({ "dimension": d }),
                None => serde_json::json!({}),
            },
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: "a".into(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec!["s".into()],
            withdraws_admission_rule: None,
            additional_scrubs: Vec::new(),
            cohort_scope: "federation".into(),
            tier: "federation".into(),
            promoted_at: None,
        }
    }

    /// CIRISEdge#462 — the G2 carve is persist's authoritative retainability
    /// ALLOWLIST (`is_subject_retainable`, CIRISPersist#635), keyed on authorship.
    /// A scored dimension is carved UNLESS persist affirms the subject is its
    /// author. This is FAIL-CLOSED: unlike the earlier capacity-only carve, ANY
    /// peer-authored score — capacity, capacity_assurance, moderation, or an
    /// unknown/new family — is withheld. Self-authored scores (trace:*) and
    /// dimensionless conferrals (delegates_to) are kept.
    #[test]
    fn g2_carve_is_persist_retainability_allowlist() {
        use FederationDirectoryReplicationBridge as B;
        // Peer-authored scores about the subject — ALL carved (fail-closed
        // allowlist), including families the old capacity-only carve missed.
        for carved in [
            "capacity:core_identity:v1",       // the canonical G2 reputation score
            "capacity_assurance:composite:v1", // the old carve LET THIS THROUGH
            "moderation:removal:v1",           // ditto — now correctly carved
            "some_future:score:v9",            // unknown family → fail-closed → carved
        ] {
            assert!(
                B::is_non_retainable_score(&att_with_dimension(Some(carved))),
                "{carved} is not in persist's retainable allowlist — carved (G2, fail-closed)"
            );
        }
        // Self-authored (allowlisted) scores are kept here (trace:* is separately
        // E3-gated at fetch).
        assert!(
            !B::is_non_retainable_score(&att_with_dimension(Some("trace:coherence:v1"))),
            "trace:* is self-emission-mandatory (retainable); kept here, E3-gated at fetch"
        );
        // FAIL-CLOSED: a SCORES row with NO dimension is carved, not served — a
        // missing/malformed dimension must never fall open on the data-subject axis
        // (Codex on #470 round 2). `att_with_dimension` builds attestation_type=scores.
        assert!(
            B::is_non_retainable_score(&att_with_dimension(None)),
            "a scores row with no dimension is carved (fail-closed); it is NOT a conferral"
        );
    }

    /// Codex on #470 — the carve keys on the SCORES PLANE, not on has-a-dimension.
    /// `self_at_login` proves conferrals CAN be dimension-bearing
    /// (`self:delegates_to:agent_occurrence:v1`, src/edge.rs), and that dimension is
    /// NOT in persist's retainable allowlist — so a has-dimension gate would carve
    /// the delegation OUT of the very pull the receive axis exists to recover. The
    /// control proves the discriminator is `attestation_type`, not the dimension.
    #[test]
    fn g2_carve_keeps_dimension_bearing_conferrals() {
        use FederationDirectoryReplicationBridge as B;
        let dim = "self:delegates_to:agent_occurrence:v1";
        let mut conferral = att_with_dimension(Some(dim));
        conferral.attestation_type = "delegates_to".into();
        assert!(
            !B::is_non_retainable_score(&conferral),
            "a dimension-bearing delegates_to conferral is retained by TYPE, never carved"
        );
        // Control: the SAME non-retainable dimension on a SCORES-type row IS carved.
        assert!(
            B::is_non_retainable_score(&att_with_dimension(Some(dim))),
            "the same non-retainable dimension on a scores-type row is still carved (fail-closed)"
        );
        // A DIMENSIONLESS conferral is kept by TYPE — NOT because it lacks a
        // dimension (a dimensionless SCORES row is carved, fail-closed).
        let mut dimensionless_conferral = att_with_dimension(None);
        dimensionless_conferral.attestation_type = "delegates_to".into();
        assert!(
            !B::is_non_retainable_score(&dimensionless_conferral),
            "a dimensionless conferral is kept by TYPE (the moderation-duty shape)"
        );
    }

    /// v16 review (#3): the FETCH first-party classifier. Author (sender axis),
    /// primary subject, and any co-subject are first-party; an unrelated peer is not.
    #[test]
    fn attestation_is_first_party_to_matches_author_and_subject() {
        use FederationDirectoryReplicationBridge as B;
        let att = serde_json::json!({
            "attesting_key_id": "author-A",
            "attested_key_id": "subject-S",
            "subject_key_ids": ["subject-S", "co-subject-C"],
            "dimension": "x",
        });
        assert!(B::attestation_is_first_party_to(&att, "author-A")); // sender axis
        assert!(B::attestation_is_first_party_to(&att, "subject-S")); // primary subject
        assert!(B::attestation_is_first_party_to(&att, "co-subject-C")); // data-subject set
        assert!(!B::attestation_is_first_party_to(&att, "stranger-X")); // still #396-gated
                                                                        // Missing fields must not false-positive into a first-party bypass.
        assert!(!B::attestation_is_first_party_to(
            &serde_json::json!({}),
            "anyone"
        ));
    }

    /// v16 review (#3): the FETCH honors first-party right, matching the Pull LIST
    /// gate. A subject fetching a `delegates_to` ABOUT itself gets the bytes even
    /// though the node granted it NO #396 consent-membership — while a third party
    /// with no consent is still withheld. Closes the list-wider-than-fetch gap (a
    /// ref listed then unfetchable).
    #[tokio::test]
    async fn first_party_fetch_overrides_producer_advertise_consent() {
        let local = "this-node";
        let producer = "author-A";
        let subject = "subject-S";
        let stranger = "stranger-X";
        let (backend, bridge) = make_bridge(&[
            local.to_string(),
            producer.to_string(),
            subject.to_string(),
            stranger.to_string(),
        ]);
        let bridge = bridge.with_local_key_id(Some(local.to_string()));
        for kid in [local, producer, subject, stranger] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(kid, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        // A delegates_to ABOUT the subject, authored by the producer, with NO consent
        // grant/membership for anyone → #396 withholds every THIRD party.
        seed_delegates_to(
            &backend,
            producer,
            subject,
            &serde_json::json!(["infra:serve"]),
        )
        .await;

        // The subject's own Pull LISTS the ref (entitlement fail-closed to the subject).
        let refs = bridge
            .subject_holdings(EnvelopeKind::Attestation, subject, Some(subject))
            .await;
        assert!(!refs.is_empty(), "the subject lists its own delegates_to");
        let hash = refs[0].envelope_hash;

        // FIRST-PARTY: the subject fetches its own testimony despite no #396 consent.
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, &hash, Some(subject))
                .await
                .is_some(),
            "the data-subject fetches its own row — first-party overrides #396"
        );
        // THIRD-PARTY: a stranger with no consent-membership is still withheld.
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, &hash, Some(stranger))
                .await
                .is_none(),
            "a third party without #396 consent still cannot fetch it (the gate holds)"
        );
    }

    /// CIRISEdge#462 — the subject-scoped serve reader answers the SUBJECT with
    /// its testimony across BOTH axes (ABOUT-me via the data-subject axis +
    /// authored-BY-me via the sender axis), never leaks another subject's rows,
    /// and serves NOTHING to a requester that is not the subject (fail-closed).
    #[tokio::test]
    async fn subject_pull_serves_both_axes_and_fails_closed() {
        let subject = "eric-moore-v2-portable";
        let other = "some-other-subject";
        let (backend, bridge) = make_bridge(&[subject.to_string()]);

        // Every attester AND attested key must exist in federation_keys to seed
        // a delegates_to attestation.
        for kid in [subject, other, "peer-attester"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(kid, "user"),
                })
                .await
                .expect("register attester key");
        }

        // ABOUT the subject — the data-subject axis.
        seed_delegates_to(
            &backend,
            "peer-attester",
            subject,
            &serde_json::json!(["infra:serve"]),
        )
        .await;
        // BY the subject about someone else — the sender axis (authorship recovery).
        seed_delegates_to(
            &backend,
            subject,
            other,
            &serde_json::json!(["infra:serve"]),
        )
        .await;
        // About a DIFFERENT subject, by a peer — neither of S's axes; must not leak.
        seed_delegates_to(
            &backend,
            "peer-attester",
            other,
            &serde_json::json!(["infra:serve"]),
        )
        .await;

        let refs = bridge
            .subject_holdings(EnvelopeKind::Attestation, subject, Some(subject))
            .await;
        assert_eq!(
            refs.len(),
            2,
            "subject pull = {{about-me (data-subject), by-me (sender)}}; the other \
             subject's peer-authored row never leaks"
        );

        // Fail-closed entitlement: a requester ≠ subject, or an unattributed one,
        // gets nothing.
        assert!(
            bridge
                .subject_holdings(EnvelopeKind::Attestation, subject, Some("intruder"))
                .await
                .is_empty(),
            "a Pull for S by a requester ≠ S serves nothing (#462 fail-closed)"
        );
        assert!(
            bridge
                .subject_holdings(EnvelopeKind::Attestation, subject, None)
                .await
                .is_empty(),
            "an unattributed Pull serves nothing"
        );
    }

    /// CIRISEdge#462 — seed `subject`'s `consent:state:granted` for `covers` on
    /// the `analyze` scope, so a peer-authored `capacity:*` row about `subject`
    /// clears persist's `check_capacity_consent_admission` gate
    /// (`resolve_scoped_consent(attester, subject, "analyze") == Granted`). Lets
    /// the G2 test admit REAL capacity data rather than assert on a synthetic
    /// struct.
    async fn seed_analyze_consent(backend: &MemoryBackend, subject: &str, covers: &str) {
        let id = uuid::Uuid::new_v4().to_string();
        seed_scoped_attestation(
            backend,
            &id,
            subject,
            covers,
            "scores",
            "federation",
            serde_json::json!({ "dimension": "consent:state:granted:v1", "scope": ["analyze"] }),
        )
        .await;
    }

    /// CIRISEdge#462 — the G2 carve holds on REAL admitted capacity data and is
    /// AXIS-SPECIFIC. Modeled as store mutations so the security assumption is
    /// proven on the real serve path, not just the predicate:
    ///   MUTATION 1 — a peer-authored `capacity:*` score ABOUT me is carved from
    ///     the pull (it must NEVER land on the node where I am the sole writer:
    ///     the G2 self-revocation-hole shape).
    ///   MUTATION 2 — a `capacity:*` score I AUTHORED about someone else IS
    ///     recoverable (the carve must not be over-broad and eat my own
    ///     authorship).
    #[tokio::test]
    async fn g2_carve_holds_on_real_capacity_data_and_is_axis_specific() {
        let subject = "subject-s";
        let peer = "peer-p";
        let other = "other-t";
        let (backend, bridge) = make_bridge(&[subject.to_string()]);
        for kid in [subject, peer, other] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(kid, "user"),
                })
                .await
                .expect("register key");
        }
        // Consents that let the capacity rows admit: S grants P (so P may score
        // S); T grants S (so S may score T). Both are `scores` attestations that
        // also ride S's pull axes — so we snapshot the BASELINE after seeding them
        // and assert only the DELTAS the two capacity mutations produce.
        seed_analyze_consent(&backend, subject, peer).await;
        seed_analyze_consent(&backend, other, subject).await;
        // A benign attestation ABOUT S (data-subject axis).
        seed_delegates_to(&backend, peer, subject, &serde_json::json!(["infra:serve"])).await;

        let baseline = bridge
            .subject_holdings(EnvelopeKind::Attestation, subject, Some(subject))
            .await
            .len();

        // MUTATION 1 — a peer-authored capacity score ABOUT S. It admits (S
        // granted P), but the pull must be UNCHANGED: the score is carved.
        seed_scoped_attestation(
            &backend,
            "cap-p-about-s",
            peer,
            subject,
            "scores",
            "federation",
            serde_json::json!({ "dimension": "capacity:core_identity:v1" }),
        )
        .await;
        assert_eq!(
            bridge
                .subject_holdings(EnvelopeKind::Attestation, subject, Some(subject))
                .await
                .len(),
            baseline,
            "G2: a peer-authored capacity score ABOUT me is carved — it must not be pullable \
             onto my own node (the self-revocation-hole shape)"
        );

        // MUTATION 2 — a capacity score S AUTHORED about T (sender axis). It
        // admits (T granted S), and the pull MUST gain it: authorship recovery,
        // the carve is not over-broad.
        seed_scoped_attestation(
            &backend,
            "cap-s-about-t",
            subject,
            other,
            "scores",
            "federation",
            serde_json::json!({ "dimension": "capacity:integrity:v1" }),
        )
        .await;
        assert_eq!(
            bridge
                .subject_holdings(EnvelopeKind::Attestation, subject, Some(subject))
                .await
                .len(),
            baseline + 1,
            "axis-specific: a capacity score I AUTHORED (sender axis) is recoverable — the carve \
             must not eat my own authorship"
        );
    }

    /// CIRISEdge#462 — entitlement DISCRIMINATES, it is not deny-all. Two legit
    /// registered subjects each hold testimony: each pulls its OWN and gets it;
    /// neither can pull the OTHER's (the impersonation mutation). This is the
    /// fail-closed gate proving it still serves the rightful subject.
    #[tokio::test]
    async fn subject_pull_entitlement_discriminates() {
        let s = "subject-s";
        let t = "subject-t";
        let (backend, bridge) = make_bridge(&[s.to_string(), t.to_string()]);
        for kid in [s, t, "peer-p"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(kid, "user"),
                })
                .await
                .expect("register key");
        }
        // Each subject has one attestation ABOUT it.
        seed_delegates_to(&backend, "peer-p", s, &serde_json::json!(["infra:serve"])).await;
        seed_delegates_to(&backend, "peer-p", t, &serde_json::json!(["infra:serve"])).await;

        let s_pulls_s = bridge
            .subject_holdings(EnvelopeKind::Attestation, s, Some(s))
            .await;
        let t_pulls_t = bridge
            .subject_holdings(EnvelopeKind::Attestation, t, Some(t))
            .await;
        assert!(!s_pulls_s.is_empty(), "S pulling S gets S's testimony");
        assert!(
            !t_pulls_t.is_empty(),
            "T pulling T gets T's testimony (not deny-all)"
        );

        // The impersonation mutation: S authenticated, pulling T's subject — and
        // vice versa — gets NOTHING. The gate discriminates on the subject.
        assert!(
            bridge
                .subject_holdings(EnvelopeKind::Attestation, t, Some(s))
                .await
                .is_empty(),
            "S must not pull T's testimony (impersonation blocked)"
        );
        assert!(
            bridge
                .subject_holdings(EnvelopeKind::Attestation, s, Some(t))
                .await
                .is_empty(),
            "T must not pull S's testimony (impersonation blocked)"
        );
    }

    /// CIRISEdge#462 (Codex #463 Finding 2) — a Pull ref must not DISCLOSE a row
    /// the requester could not be served. A `trace:*` row is E3-confidential
    /// (`infra:serve` only); a subject WITHOUT that capability must not even learn
    /// the row exists (its hash + seq) — so it is gated OUT of the Summary, not
    /// merely withheld at Deliver. A non-trace attestation about the subject (its
    /// first-party testimony) is served regardless — the pull gate is E3
    /// confidentiality, NOT the #396 producer-advertise-consent bound.
    #[tokio::test]
    async fn subject_pull_gates_trace_refs_it_cannot_serve() {
        let subject = "subject-s";
        let (backend, bridge) = make_bridge(&[subject.to_string()]);
        for kid in [subject, "peer-p"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(kid, "user"),
                })
                .await
                .expect("register key");
        }
        // Non-trace testimony ABOUT the subject — served (first-party right; not
        // #396-gated).
        seed_delegates_to(
            &backend,
            "peer-p",
            subject,
            &serde_json::json!(["infra:serve"]),
        )
        .await;
        let before = bridge
            .subject_holdings(EnvelopeKind::Attestation, subject, Some(subject))
            .await
            .len();
        assert_eq!(
            before, 1,
            "the subject's non-trace testimony is served (not gated by the producer's #396 consent)"
        );

        // A trace:* row about the subject (self-emitted). The subject holds no
        // infra:serve capability, so the row must NOT appear in the pull refs —
        // no hash/seq disclosure of a row that Deliver would withhold.
        seed_trace_attestation(&backend, subject).await;
        let after = bridge
            .subject_holdings(EnvelopeKind::Attestation, subject, Some(subject))
            .await
            .len();
        assert_eq!(
            after, before,
            "a trace:* row the requester cannot be served is gated OUT of the Pull refs \
             (E3 confidentiality — no ref info-leak)"
        );
    }

    /// CIRISPersist#659 (v31.0.0) — SPOOFING PROOF (the Revocation plane).
    ///
    /// A signed revocation now binds `revoked_key_id` (and its sibling typed
    /// columns) INTO the signed envelope. Pre-v31 that column was UNSIGNED, so a
    /// single genuine revocation could be re-pointed at ANY key: a relay repaints
    /// the column, the scrub signature still verifies over the (now-mismatched)
    /// envelope, and the row de-admits whatever the column names — one signature,
    /// unbounded reach (the subject-blindness class: possession of a signed blob
    /// conferred authority over a key the signer never named). This exercises the
    /// binding gate directly — `check_revocation_envelope_binding`, which EVERY
    /// store's admit path (memory / sqlite / postgres / tier_ingest) runs — proving
    /// the honestly bound row passes while the paste is refused, and isolating the
    /// subject-binding fix from the ORTHOGONAL slash-authority gate (a third-party
    /// `put_revocation` also requires the revoker hold `slash` from a trusted root:
    /// defense in depth, but not what #659 closes). Authority is bound to the
    /// SIGNATURE, never to custody of the row.
    #[test]
    fn v31_revocation_paste_cannot_deadmit_an_unintended_key() {
        // Build a well-formed, signed revocation of `revoked`, tagged `id`.
        let build = |id: &str, revoked: &str| {
            let now = Utc::now().trunc_subsecs(6);
            let mut rev = Revocation {
                revocation_id: id.to_string(),
                revoked_key_id: revoked.to_string(),
                revoking_key_id: "revoker".to_string(),
                reason: None,
                revoked_at: now,
                effective_at: now,
                revocation_envelope: serde_json::json!({}),
                original_content_hash: String::new(),
                scrub_signature_classical: String::new(),
                scrub_signature_pqc: None,
                scrub_key_id: "revoker".to_string(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                observed_region: "us".to_string(),
                persist_row_hash: String::new(),
                revoked_after: None,
            };
            // persist's OWN binder stamps the typed columns into the envelope, so
            // the member set can never drift from the verifier.
            ciris_persist::federation::admission::bind_revocation_into_envelope(&mut rev)
                .expect("bind revocation envelope");
            let (hash, ed_sig, pqc_sig) =
                sign_attestation_envelope("revoker", &rev.revocation_envelope);
            rev.original_content_hash = hash;
            rev.scrub_signature_classical = ed_sig;
            rev.scrub_signature_pqc = pqc_sig;
            rev
        };

        // CONTROL: the honestly-bound revocation PASSES the binding gate. Every
        // store's admit path (memory / sqlite / postgres / tier_ingest) runs
        // exactly this check, so it is the real gate, not a stand-in.
        let honest = build("rev-honest", "victim-A");
        ciris_persist::federation::admission::check_revocation_envelope_binding(&honest)
            .expect("an honestly-bound revocation satisfies the column-to-envelope binding");

        // ATTACK: sign a revocation of victim-A, then repaint the target column to
        // victim-B. The signed envelope still pins victim-A.
        let mut pasted = build("rev-spoof", "victim-A");
        pasted.revoked_key_id = "victim-B".to_string();

        let err = ciris_persist::federation::admission::check_revocation_envelope_binding(&pasted)
            .expect_err(
                "a revocation signed to de-admit victim-A must NOT de-admit victim-B once its \
                 column is repainted — pre-v31 the unsigned column pasted onto ANY key (#659)",
            );
        let msg = format!("{err:?}");
        assert!(
            msg.contains("RevocationEnvelopeUnbound") || msg.contains("revoked_key_id"),
            "refused for the RIGHT reason (revoked_key_id column ≠ signed envelope), got: {msg}"
        );
    }

    /// CIRISPersist#643 (v31.0.0) — SPOOFING PROOF (the Attestation/conferral plane).
    ///
    /// A `delegates_to` conferral now binds `attested_key_id` + `subject_key_ids`
    /// into the signed `row` mirror. Pre-v31 those columns were UNSIGNED, so a
    /// single genuine conferral (say `infra:serve` granted to grantee-A) could be
    /// lifted onto ANY key — repaint the target column and the authority the signer
    /// never granted rides the same signature. persist's own doc flags
    /// `subject_key_ids` as the column that "grants revocation authority", so
    /// lifting it is the highest-value forgery; this proves v31 refuses the lift
    /// while the honest conferral admits.
    #[tokio::test]
    async fn v31_conferral_paste_cannot_lift_authority_onto_another_key() {
        let (backend, _bridge) = make_bridge(&[]);
        for kid in ["root", "grantee-A", "grantee-B"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(kid, "user"),
                })
                .await
                .expect("register key");
        }

        // Build a signed delegates_to(root → attested, scope infra:serve).
        let build = |id: &str, attested: &str| {
            let now = Utc::now().trunc_subsecs(6);
            let mut envelope = serde_json::json!({
                "id": id,
                "attesting_key_id": "root",
                "attested_key_id": attested,
                "attestation_type": "delegates_to",
                "scope": ["infra:serve"],
            });
            bind_attestation_envelope(
                &mut envelope,
                now,
                id,
                "root",
                "delegates_to",
                attested,
                &[attested],
                "federation",
            );
            let (hash, ed_sig, pqc_sig) = sign_attestation_envelope("root", &envelope);
            Attestation {
                attestation_id: id.to_string(),
                attesting_key_id: "root".to_string(),
                attested_key_id: attested.to_string(),
                attestation_type: "delegates_to".to_string(),
                weight: None,
                asserted_at: now,
                expires_at: None,
                attestation_envelope: envelope,
                original_content_hash: hash,
                scrub_signature_classical: ed_sig,
                scrub_signature_pqc: pqc_sig,
                scrub_key_id: "root".to_string(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                subject_key_ids: vec![attested.to_string()],
                withdraws_admission_rule: None,
                additional_scrubs: Vec::new(),
                cohort_scope: "federation".to_string(),
                tier: "federation".to_string(),
                promoted_at: None,
            }
        };

        // CONTROL: the honest conferral onto grantee-A ADMITS.
        backend
            .put_attestation(SignedAttestation {
                attestation: build("att-honest", "grantee-A"),
            })
            .await
            .expect("an honestly-bound conferral admits");

        // ATTACK: sign a conferral onto grantee-A, then repaint BOTH target columns
        // to grantee-B. The signed `row` mirror still pins grantee-A.
        let mut pasted = build("att-spoof", "grantee-A");
        pasted.attested_key_id = "grantee-B".to_string();
        pasted.subject_key_ids = vec!["grantee-B".to_string()];

        let err = backend
            .put_attestation(SignedAttestation {
                attestation: pasted,
            })
            .await
            .expect_err(
                "a delegates_to signed to grant grantee-A must NOT grant grantee-B once its \
                 target columns are repainted — pre-v31 the unsigned columns lifted authority \
                 onto ANY key (#643)",
            );
        let msg = format!("{err:?}");
        // v16 review: assert the #643 row-column binding gate refused it SPECIFICALLY
        // — check_row_column_binding names the divergent member. A bare
        // "InvalidArgument" is NOT enough: many other put_attestation gates
        // (cohort-scope, #510 consent-grammar, canonicalize) Debug-format the same,
        // so accepting it would let this test stay green even if the paste were
        // refused by an unrelated gate (false confidence).
        assert!(
            msg.contains("subject_key_ids") || msg.contains("attested_key_id"),
            "must be refused by the #643 row-column binding (naming the divergent \
             attested_key_id/subject_key_ids), not an incidental InvalidArgument, got: {msg}"
        );
    }

    /// CIRISEdge#462 — the load-bearing hash-match invariant: every ref
    /// `subject_holdings` emits resolves through the SAME content-hash fetch path
    /// a `Deliver` uses (`fetch_envelope_bytes` → persist's `signed_wire_index`).
    /// If the pull's struct-hashing (`content_hash_of` on the `_for`-read struct)
    /// ever diverged from what the index keys on, this would surface as
    /// advertised-then-unfetchable and a Pull would deliver nothing. Proven across
    /// the Key plane (lookup + `SignedKeyRecord` wrap) and the Attestation plane.
    #[tokio::test]
    async fn subject_pull_refs_resolve_through_fetch() {
        let subject = "eric-moore-v2-portable";
        let (backend, bridge) = make_bridge(&[subject.to_string()]);
        // Register the subject's key (also the Key-plane row) + a peer attester,
        // then seed an attestation ABOUT the subject.
        for kid in [subject, "peer-attester"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(kid, "user"),
                })
                .await
                .expect("register key");
        }
        seed_delegates_to(
            &backend,
            "peer-attester",
            subject,
            &serde_json::json!(["infra:serve"]),
        )
        .await;

        for kind in [EnvelopeKind::Key, EnvelopeKind::Attestation] {
            let refs = bridge.subject_holdings(kind, subject, Some(subject)).await;
            assert!(
                !refs.is_empty(),
                "{kind:?}: a subject Pull must surface at least one ref"
            );
            for r in &refs {
                assert!(
                    bridge
                        .fetch_envelope_bytes(kind, &r.envelope_hash)
                        .await
                        .is_some(),
                    "{kind:?}: pull ref {} must resolve through the content-hash fetch path \
                     (hash-match with the wire index; else advertised-then-unfetchable)",
                    hex::encode(r.envelope_hash),
                );
            }
        }
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
        let now = Utc::now().trunc_subsecs(6); // #598 microsecond floor
        let id = uuid::Uuid::new_v4().to_string();
        let mut revocation = Revocation {
            revocation_id: id,
            revoked_key_id: revoked.to_string(),
            revoking_key_id: revoking.to_string(),
            reason: None,
            revoked_at: now,
            effective_at: now,
            revocation_envelope: serde_json::json!({}),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: revoking.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            observed_region: "us".to_string(), // #598-era: must be {us,eu,apac}, not empty
            persist_row_hash: String::new(),
            revoked_after: None,
        };
        // CIRISPersist#659 (v31.0.0): bind the typed columns (revoked_key_id, reason,
        // revoked_at, …) into the signed envelope — else a relay could paste one
        // signed revocation onto ANY key. Use persist's OWN binder so the member set
        // never drifts, then sign the now-bound envelope.
        ciris_persist::federation::admission::bind_revocation_into_envelope(&mut revocation)
            .expect("bind revocation envelope");
        let (hash, ed_sig, pqc_sig) =
            sign_attestation_envelope(revoking, &revocation.revocation_envelope);
        revocation.original_content_hash = hash;
        revocation.scrub_signature_classical = ed_sig;
        revocation.scrub_signature_pqc = pqc_sig;
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
        // persist v30.8.0 (CIRISPersist#628) — a third-party revocation now needs
        // the revoker authorized with `slash` from a trusted root. This test is
        // about the cache-free FETCH round trip (#396 item 3), where the
        // revocation's authority is irrelevant — so seed a SELF-revocation
        // (`revoking == revoked`, the path v30.8.0 leaves untouched) rather than
        // drag a conferral fixture into a fetch-mechanics test. `revoking` still
        // seeds a distinct key above (harmless); the fetched row's revoked_key_id
        // is what this asserts.
        seed_revocation(&backend, revoked, revoked).await;

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
            additional_scrubs: Vec::new(),
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
        // `has_accord_conferred_role(_, "trace:read")` is false for it. (Seeding the key
        // means the WITHHOLD below is because the record lacks the capability, not
        // because the key is absent — the same provenance discipline the #379
        // test uses to refuse a self-asserted `roles:[…]` peer.)
        let recipient = "peer-no-capability";
        let (backend, bridge) = make_bridge(&[producer.to_string(), recipient.to_string()]);
        // Both keys registered: the producer's so `put_attestation` can verify
        // its grant's hybrid signature, the recipient's so `has_accord_conferred_role`
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
    /// not asserted here: a record that satisfies `has_accord_conferred_role` must
    /// carry a live 2-of-3 accord-family co-scrub over its canonical
    /// registration bytes, and persist's minting helpers for that
    /// (`register_founder` / `signed_canonical_record`) are private to its own
    /// test module. Faking it with a hand-built record would re-create exactly
    /// the false confidence being fixed, so it is left to the layer that can
    /// prove it: CIRISPersist#484 (export the helper) and the field acceptance
    /// check on CIRISPersist#480 — `has_accord_conferred_role(dir, canonical,
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
        self_asserted_rec.capability_roles =
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
            let mut record = fixture_key_record(k, it);
            // CIRISPersist v22 (#543 / the FIPS anti-Sybil floor #513) — an
            // `accord:*` attestation now requires its attester to be a hardware-
            // attested ACCORD_HOLDER: the key must carry `attestation_evidence` at
            // registration AND the attester's identity_type must be ACCORD_HOLDER
            // (so the lifecycle attester cannot be downgraded to a plain NODE). Seed
            // the exact fresh Android/Strongbox blob persist's
            // `test_support::fresh_accord_holder_evidence` emits — inlined so this
            // test does not have to gate on the `test-anchor` feature.
            if it == identity_type::ACCORD_HOLDER {
                record.attestation_evidence = Some(serde_json::json!({
                    "platform_attestation": {
                        "Android": {
                            "key_attestation_chain": [
                                [0x30, 0x82, 0x01, 0x00],
                                [0x30, 0x82, 0x02, 0x00],
                            ],
                            "play_integrity_token": "eyJhbGciOiJIUzI1NiJ9.fake.token",
                            "strongbox_backed": true,
                        }
                    },
                    "nonce_captured_at": Utc::now().to_rfc3339(),
                }));
            }
            backend
                .put_public_key(SignedKeyRecord { record })
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
        let now = Utc::now().trunc_subsecs(6);
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
            let attestation_id = uuid::Uuid::new_v4().to_string();
            bind_attestation_envelope(
                &mut envelope,
                now,
                &attestation_id,
                producer,
                attestation_type,
                producer,
                &[producer],
                "federation",
            );
            let (hash, ed_sig, pqc_sig) = sign_attestation_envelope(producer, &envelope);
            let att = Attestation {
                attestation_id,
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
                additional_scrubs: Vec::new(),
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
    /// `has_accord_conferred_role` needs a genuine 2-of-3 accord-family co-scrub, which
    /// persist exports only behind that fence (CIRISPersist#484). Edge CI runs a
    /// dedicated `test-anchor` lane (#435), so this is real coverage — not a
    /// test that quietly never runs. (#435 is the proof that clause must be a
    /// CI job, not a doc claim: while no lane ran it, this test silently missed
    /// TWO fixture waves — the v22 ACCORD_HOLDER evidence blob and the #396
    /// item-1 consent-membership bound — and sat broken at HEAD.)
    ///
    /// This is the assertion whose ABSENCE let v13.10.0 ship a permanently-dark
    /// gate with a green suite.
    ///
    /// Also asserts the #433 ledger's leg-B arm: the blessed-but-not-rooted
    /// DENY books `ServeCapabilityNotRooted` — the one WithholdReason only
    /// reachable through this lane (leg A must PASS first).
    #[cfg(feature = "test-anchor")]
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // roster + trust graph + allow/deny/un-trust: one scenario
    async fn trace_serve_requires_accord_blessing_and_trusted_root() {
        use ciris_persist::federation::accord_test_support::{
            register_accord_holder, signed_canonical_record_with_roles, Identity,
        };
        // CIRISPersist v31.0.0 (#467): the helper now stamps the SUBJECT BINDING
        // (pubkeys) into the envelope before signing, so a signature can no longer
        // be lifted onto a different key_id. This fixture doesn't spoof, so the
        // placeholder subject + no-PQC is the byte-preserving update.
        use ciris_persist::federation::operational::test_support::PLACEHOLDER_SUBJECT_ED25519_BASE64;
        // The roster key_ids `has_accord_conferred_role` resolves against. Persist's
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
        let (backend, bridge, metrics) = make_metered_bridge(&[
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
            let mut record = fixture_key_record(k, it);
            // CIRISPersist v22 (#543/#513) — an ACCORD_HOLDER key must carry
            // `attestation_evidence` at registration. Same inlined Android/
            // Strongbox blob as the sibling non-anchored test above (#435: the
            // v22 adopt fixed the sibling and missed this anchored twin).
            if it == identity_type::ACCORD_HOLDER {
                record.attestation_evidence = Some(serde_json::json!({
                    "platform_attestation": {
                        "Android": {
                            "key_attestation_chain": [
                                [0x30, 0x82, 0x01, 0x00],
                                [0x30, 0x82, 0x02, 0x00],
                            ],
                            "play_integrity_token": "eyJhbGciOiJIUzI1NiJ9.fake.token",
                            "strongbox_backed": true,
                        }
                    },
                    "nonce_captured_at": Utc::now().to_rfc3339(),
                }));
            }
            backend
                .put_public_key(SignedKeyRecord { record })
                .await
                .expect("seed key");
        }
        // Both candidate recipients carry a GENUINE 2-of-3 accord co-scrub
        // conferring `infra:serve` — leg A holds for both.
        for peer in [full_peer, blessed_only] {
            let rec = signed_canonical_record_with_roles(
                peer,
                identity_type::NODE,
                PLACEHOLDER_SUBJECT_ED25519_BASE64,
                None,
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

        // CIRISEdge#396 item 1 — this test isolates the #386 per-ROW infra:serve
        // gate, so both probed peers must first clear the per-PEER consent
        // membership bound (a bare grant, no `recipient_capability`, so item 6
        // stays inert here). The sibling deny-path test gained this block when
        // #396 landed; this anchored twin missed it while no CI lane ran it —
        // half of #435's failure 2.
        for peer in [full_peer, blessed_only] {
            seed_consent_membership(&backend, local, peer).await;
        }

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
        // #433 — that leg-B DENY is a WITHHOLD, booked at its branch. This is
        // the only test that can reach `ServeCapabilityNotRooted` (leg A must
        // pass first, which needs the co-scrub this lane mints), so the ledger
        // arm is proven here or nowhere.
        assert!(
            metrics.withholds(crate::observability::WithholdReason::ServeCapabilityNotRooted) >= 1,
            "the blessed-but-not-rooted deny must book ServeCapabilityNotRooted \
             in the withhold ledger (CIRISEdge#433)"
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
        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::Organization, bytes, None)
            .await;
        // CIRISEdge#425 — fail-closed AND named: the escaped early return now yields
        // a `Refused` reason the choke point logs, not a silent `false`.
        assert!(
            matches!(&outcome, ApplyOutcome::Refused(r) if r.contains("operational providers")),
            "v2 operational admission MUST fail-close with a NAMED refusal without \
             OperationalProviders, got {outcome:?}"
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
        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::OrgMembership, bytes, None)
            .await;
        assert!(
            matches!(&outcome, ApplyOutcome::Refused(r) if r.contains("operational providers")),
            "org_membership must fail-close with a named refusal, got {outcome:?}"
        );
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
        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::PartnerRecord, bytes, None)
            .await;
        assert!(
            matches!(&outcome, ApplyOutcome::Refused(r) if r.contains("operational providers")),
            "partner_record must fail-close with a named refusal, got {outcome:?}"
        );
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

    // ── CIRISEdge#433 — the withhold ledger ─────────────────────────
    //
    // Field-provenance discipline ([[feedback_test_field_provenance]]): each test
    // below drives the REAL gate through the bridge with a directory state that
    // makes that branch fire, then asserts the LEDGER counted that branch. None
    // of them call `inc_withhold` directly — a green test on a hand-fed reason
    // would prove only that the counter increments, not that the gate reaches it.
    // (The single exception is the ring-buffer bound smoke test in
    // `observability.rs`, where the bound itself is the unit under test.)

    /// A bridge over a fresh `MemoryBackend` with a LIVE metrics handle attached
    /// — the production shape (`ReplicationRuntime::start` threads `Edge`'s
    /// handle in). Returns the handle so a test can read the ledger back.
    fn make_metered_bridge(
        cohort: &[String],
    ) -> (
        Arc<MemoryBackend>,
        FederationDirectoryReplicationBridge,
        crate::observability::EdgeMetrics,
    ) {
        let (backend, bridge) = make_bridge(cohort);
        let metrics = crate::observability::EdgeMetrics::new();
        (backend, bridge.with_metrics(Some(metrics.clone())), metrics)
    }

    /// The scaffold BOTH halves of the discriminator share: registered keys for
    /// every party, and `local`'s bare consent grant naming `peer` so the #396
    /// item-1 membership bound passes. Identical configuration on both sides
    /// means the ONLY difference between "idle" and "withholding" is whether a
    /// gated row exists — which is exactly the distinction #433 exists to make
    /// visible.
    async fn seed_serve_scaffold(backend: &MemoryBackend, local: &str, producer: &str, peer: &str) {
        for key_id in [local, producer, peer] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(key_id, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        seed_consent_membership(backend, local, peer).await;
    }

    /// CIRISEdge#455 — the FULL field signature, reproduced and NAMED: on a
    /// canonical whose `infra:serve` is claimed but not accord-conferred (the
    /// un-re-genesised fleet state), a `trace:*` row is
    ///   (1) present in the GLOBAL advertise (the harness's "but it IS among
    ///       the refs the agent advertises" observation — true and misleading:
    ///       that read is peer-blind),
    ///   (2) ABSENT from the PER-PEER offer the wire Summary is actually built
    ///       from (`DirectoryStateAdapter::local_refs` →
    ///       `list_envelope_refs_for_peer`), so the receiver never wants it,
    ///       never fetches it, and reports NOTHING — the "neither admitted nor
    ///       refused" silence at the canonical,
    ///   (3) while consent rows still cross the same offer (the "admitted: 5"),
    ///   (4) and the AGENT's withhold ledger names the branch:
    ///       `serve_capability_missing` — the reason the ledger's own docs
    ///       predicted for a dark trace plane (CIRISPersist#480).
    /// Not a want/Diff/Deliver defect: the row never enters the offer.
    #[tokio::test]
    async fn trace_offered_globally_but_withheld_per_peer_is_the_455_signature() {
        use crate::observability::WithholdReason;
        let local = "this-node";
        let producer = "agent-producer";
        let canonical = "canonical-claimed-not-conferred";
        let cohort = [
            local.to_string(),
            producer.to_string(),
            canonical.to_string(),
        ];
        let (backend, bridge, metrics) = make_metered_bridge(&cohort);
        let bridge = bridge.with_local_key_id(Some(local.to_string()));
        for (k, it) in [
            (local, identity_type::NODE),
            (producer, identity_type::AGENT),
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(k, it),
                })
                .await
                .expect("seed key");
        }
        // The canonical CLAIMS infra:serve in its own record — no accord
        // co-scrub (persist admits the claim; conferral is read-time).
        let mut rec = fixture_key_record(canonical, identity_type::NODE);
        rec.capability_roles =
            vec![FederationDirectoryReplicationBridge::SERVE_CAPABILITY.to_string()];
        backend
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .expect("seed canonical");
        seed_consent_membership(&backend, local, canonical).await;
        seed_trace_attestation(&backend, producer).await;
        let trace_hash = locate_trace_hash(&bridge).await;

        // (1) The peer-BLIND advertise contains the trace — the harness's
        // observation, reproduced.
        assert!(
            bridge
                .list_envelope_refs(EnvelopeKind::Attestation)
                .await
                .iter()
                .any(|r| r.envelope_hash == trace_hash),
            "(1) globally advertised"
        );
        // (2)+(3) The per-peer offer — what the wire Summary is built from —
        // omits the trace but still carries the consent row.
        let offer = bridge
            .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(canonical))
            .await;
        assert!(
            !offer.iter().any(|r| r.envelope_hash == trace_hash),
            "(2) absent from the per-peer offer — the receiver never wants it"
        );
        assert!(
            !offer.is_empty(),
            "(3) consent rows still cross — the round completes and admits"
        );
        // (4) The ledger names the branch on the AGENT side.
        assert!(
            metrics
                .snapshot()
                .withholds_by_reason
                .get(&WithholdReason::ServeCapabilityMissing)
                .copied()
                .unwrap_or(0)
                >= 1,
            "(4) the withhold ledger books serve_capability_missing — the \
             silence has a name, on the sender"
        );
    }

    /// CIRISEdge#433, the discriminator property from the issue — **two states,
    /// now distinguishable**.
    ///
    /// Before this cut, a node withholding every `trace:*` row from every peer
    /// reported exactly what a node with nothing to send reported: zero sent,
    /// round `completed`, perfect health, zero carriage. Both bridges here are
    /// configured IDENTICALLY (same keys, same consent grant, same peer lacking
    /// `infra:serve`); the only difference is that one holds a trace row. That
    /// used to be invisible. It is now the difference between an empty ledger
    /// and `serve_capability_missing >= 1`.
    #[tokio::test]
    async fn idle_and_withholding_bridges_are_distinguishable() {
        use crate::observability::WithholdReason;
        let local = "this-node";
        let producer = "agent-producer";
        let peer = "peer-no-capability";
        let cohort = [local.to_string(), producer.to_string(), peer.to_string()];

        // (a) IDLE — fully wired, consent-included peer, and NOTHING held back:
        //     every row it advertises, it serves.
        let (idle_backend, idle_bridge, idle_metrics) = make_metered_bridge(&cohort);
        let idle_bridge = idle_bridge.with_local_key_id(Some(local.to_string()));
        seed_serve_scaffold(&idle_backend, local, producer, peer).await;
        let idle_refs = idle_bridge
            .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(peer))
            .await;
        for r in &idle_refs {
            assert!(
                idle_bridge
                    .fetch_envelope_bytes_for_peer(
                        EnvelopeKind::Attestation,
                        &r.envelope_hash,
                        Some(peer)
                    )
                    .await
                    .is_some(),
                "the idle bridge holds nothing back"
            );
        }
        let idle = idle_metrics.snapshot();
        assert!(
            idle.withholds_by_reason.is_empty(),
            "an IDLE node withholds nothing — its ledger is empty, got {:?}",
            idle.withholds_by_reason
        );
        assert_eq!(
            idle.replication_envelopes_served_total
                .get(&EnvelopeKind::Attestation)
                .copied()
                .unwrap_or(0),
            idle_refs.len() as u64,
            "an IDLE node's carriage equals what it advertised"
        );

        // (b) WITHHOLDING — same wiring, plus one `trace:*` row the peer may not
        //     have (it holds no accord-conferred `infra:serve`).
        let (hold_backend, hold_bridge, hold_metrics) = make_metered_bridge(&cohort);
        let hold_bridge = hold_bridge.with_local_key_id(Some(local.to_string()));
        seed_serve_scaffold(&hold_backend, local, producer, peer).await;
        seed_trace_attestation(&hold_backend, producer).await;
        let trace_hash = locate_trace_hash(&hold_bridge).await;

        // Drive the REAL advertise gate, then the REAL serve gate.
        let held_refs = hold_bridge
            .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(peer))
            .await;
        assert!(
            !held_refs.iter().any(|r| r.envelope_hash == trace_hash),
            "the trace row is withheld from a peer with no `infra:serve`"
        );
        assert!(
            hold_bridge
                .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, &trace_hash, Some(peer))
                .await
                .is_none(),
            "...on the direct-fetch path too"
        );

        let held = hold_metrics.snapshot();
        assert!(
            held.withholds_by_reason
                .get(&WithholdReason::ServeCapabilityMissing)
                .copied()
                .unwrap_or(0)
                >= 1,
            "the WITHHOLDING node books the branch that decided, got {:?}",
            held.withholds_by_reason
        );
        assert_eq!(
            held.replication_envelopes_served_total
                .get(&EnvelopeKind::Attestation)
                .copied()
                .unwrap_or(0),
            0,
            "and it served NOTHING — the state that used to look identical to idle"
        );

        // The property, stated directly: the two nodes' reports now differ.
        assert_ne!(
            idle.withholds_by_reason, held.withholds_by_reason,
            "an idle node and a withholding node must not report the same thing"
        );
    }

    /// CIRISEdge#433 — a serve that MOVES a row bumps
    /// `replication_envelopes_served_total`, keyed by the same `EnvelopeKind` the
    /// wire uses. This is the mirror-image defect: `inc_sent` is called only from
    /// `src/edge.rs`, so before this counter a node that moved N rows through
    /// anti-entropy rounds reported `envelopes_sent_total: 0` — reporting broken
    /// while working.
    #[tokio::test]
    async fn a_serve_that_moves_rows_bumps_the_replication_served_counter() {
        let local = "this-node";
        let producer = "agent-producer";
        let peer = "peer-consented";
        let (backend, bridge, metrics) =
            make_metered_bridge(&[local.to_string(), producer.to_string(), peer.to_string()]);
        let bridge = bridge.with_local_key_id(Some(local.to_string()));
        seed_serve_scaffold(&backend, local, producer, peer).await;
        // A NON-trace row: no `trace:` dimension, so the #379/#386 gate is inert
        // and this exercises the SERVE path, not a withhold.
        seed_advertised_attestation(&backend, producer).await;

        let refs = bridge
            .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(peer))
            .await;
        assert!(
            !refs.is_empty(),
            "the row is advertised to the consented peer"
        );
        for r in &refs {
            assert!(
                bridge
                    .fetch_envelope_bytes_for_peer(
                        EnvelopeKind::Attestation,
                        &r.envelope_hash,
                        Some(peer)
                    )
                    .await
                    .is_some(),
                "every advertised row serves"
            );
        }

        let snap = metrics.snapshot();
        assert_eq!(
            snap.replication_envelopes_served_total
                .get(&EnvelopeKind::Attestation)
                .copied()
                .unwrap_or(0),
            refs.len() as u64,
            "one bump per envelope the bridge handed to the wire path"
        );
        assert!(
            snap.withholds_by_reason.is_empty(),
            "a clean serve withholds nothing, got {:?}",
            snap.withholds_by_reason
        );
    }

    /// CIRISEdge#433 / #396 item 1 — a peer absent from the live consent send-set
    /// books `RecipientNotInSendSet`, driven through the REAL advertise path (the
    /// `consent_membership_fan_out_bound` scenario, now with a ledger on it).
    #[tokio::test]
    async fn recipient_not_in_send_set_is_booked_at_the_branch() {
        use crate::observability::WithholdReason;
        let local = "this-node";
        let producer = "agent-producer";
        let peer_in = "peer-consented";
        let peer_out = "peer-unconsented";
        let (backend, bridge, metrics) = make_metered_bridge(&[
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
        seed_consent_membership(&backend, local, peer_in).await;

        // The consent-INCLUDED peer serves cleanly — no withhold.
        assert!(!bridge.list_attestations(Some(peer_in)).await.is_empty());
        assert!(
            metrics.snapshot().withholds_by_reason.is_empty(),
            "the consented peer's plane is not a withhold"
        );

        // The consent-EXCLUDED peer loses the WHOLE plane — and it is counted.
        assert!(bridge.list_attestations(Some(peer_out)).await.is_empty());
        let snap = metrics.snapshot();
        assert_eq!(
            snap.withholds_by_reason
                .get(&WithholdReason::RecipientNotInSendSet)
                .copied()
                .unwrap_or(0),
            1,
            "the item-1 bound books ONE plane-wide withhold, got {:?}",
            snap.withholds_by_reason
        );
        // The reason is the BRANCH: no other reason fired.
        assert_eq!(
            snap.withholds_by_reason.len(),
            1,
            "exactly one reason, not a disjunction: {:?}",
            snap.withholds_by_reason
        );
        let recent = &snap.recent_withholds;
        assert_eq!(recent.last().expect("a recent entry").peer_key_id, peer_out);
    }

    /// CIRISEdge#433 — a bridge with no `local_key_id` cannot resolve the consent
    /// send-set, so it fail-closes; that is a WIRING fault, and the ledger says so
    /// (`LocalIdentityMissing`) rather than blaming the peer's consent. Driven
    /// through the real advertise path (`fan_out_fail_closed_without_local_key_id`).
    #[tokio::test]
    async fn missing_local_identity_is_booked_as_a_wiring_fault_not_a_consent_verdict() {
        use crate::observability::WithholdReason;
        let local = "this-node";
        let producer = "agent-producer";
        let peer = "peer-consented";
        let (backend, bridge, metrics) =
            make_metered_bridge(&[local.to_string(), producer.to_string(), peer.to_string()]);
        // NOTE: deliberately NO `with_local_key_id` — the field condition.
        seed_serve_scaffold(&backend, local, producer, peer).await;
        seed_advertised_attestation(&backend, producer).await;

        assert!(
            bridge.list_attestations(Some(peer)).await.is_empty(),
            "no local_key_id → the whole plane is withheld (fail-closed)"
        );
        let snap = metrics.snapshot();
        assert_eq!(
            snap.withholds_by_reason
                .get(&WithholdReason::LocalIdentityMissing)
                .copied()
                .unwrap_or(0),
            1
        );
        assert!(
            !snap
                .withholds_by_reason
                .contains_key(&WithholdReason::RecipientNotInSendSet),
            "a wiring fault must NOT be reported as 'the peer is unconsented' — \
             that sends the operator looking in the wrong place"
        );
    }

    /// CIRISEdge#433 / #396 item 6 — a producer-declared `recipient_capability`
    /// the recipient lacks books `RecipientCapabilityRestriction`, and the ring
    /// records the offending DIMENSION. Driven through the real gate with the
    /// canonical value the advertise sweep feeds it.
    #[tokio::test]
    async fn recipient_capability_restriction_is_booked_with_its_dimension() {
        use crate::observability::WithholdReason;
        let producer = "agent-producer";
        let recipient = "peer-no-capability";
        let (backend, bridge, metrics) =
            make_metered_bridge(&[producer.to_string(), recipient.to_string()]);
        for key_id in [producer, recipient] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(key_id, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        let trace_json = trace_row_json(producer);

        // No grant → no restriction → SERVE, and nothing is booked.
        assert!(
            !bridge
                .recipient_capability_withholds(&trace_json, recipient, &mut HashMap::new())
                .await
        );
        assert!(metrics.snapshot().withholds_by_reason.is_empty());

        // A covering grant naming a capability the recipient lacks → WITHHOLD.
        seed_consent_grant(&backend, producer, recipient, "trace:", "trace:read").await;
        assert!(
            bridge
                .recipient_capability_withholds(&trace_json, recipient, &mut HashMap::new())
                .await
        );
        let snap = metrics.snapshot();
        assert_eq!(
            snap.withholds_by_reason
                .get(&WithholdReason::RecipientCapabilityRestriction)
                .copied()
                .unwrap_or(0),
            1
        );
        let last = snap.recent_withholds.last().expect("a recent entry");
        assert_eq!(last.peer_key_id, recipient);
        assert_eq!(
            last.detail, "trace:complete:v1",
            "the ring attributes the offending dimension, not the whole envelope"
        );
    }

    /// CIRISEdge#433 / #429 — a hash the requester asks for that local state
    /// cannot resolve books `EnvelopeUnfetchable`, kept DISJOINT from every
    /// policy gate. This is the bridge-level origin of the
    /// advertised-then-unfetchable event `session::pack_bounded_deliver` reports
    /// in its `dropped` set: "we could not find it" must never hide inside "we
    /// chose not to serve it".
    #[tokio::test]
    async fn an_unfetchable_hash_is_booked_separately_from_every_policy_gate() {
        use crate::observability::WithholdReason;
        let local = "this-node";
        let producer = "agent-producer";
        let peer = "peer-consented";
        let (backend, bridge, metrics) =
            make_metered_bridge(&[local.to_string(), producer.to_string(), peer.to_string()]);
        let bridge = bridge.with_local_key_id(Some(local.to_string()));
        seed_serve_scaffold(&backend, local, producer, peer).await;

        // A hash that was never seeded — the #429 field condition (stale
        // wire-index / pruned row / hash skew).
        let missing = [0x5au8; 32];
        assert!(bridge
            .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, &missing, Some(peer))
            .await
            .is_none());
        let snap = metrics.snapshot();
        assert_eq!(
            snap.withholds_by_reason
                .get(&WithholdReason::EnvelopeUnfetchable)
                .copied()
                .unwrap_or(0),
            1
        );
        assert_eq!(
            snap.withholds_by_reason.len(),
            1,
            "an unfetchable row is NOT a consent / capability verdict: {:?}",
            snap.withholds_by_reason
        );
        assert_eq!(
            snap.recent_withholds.last().expect("a recent entry").detail,
            format!("attestation:{}", hex::encode(&missing[..8])),
            "the ring carries kind + hash prefix, joinable with the #379 log line"
        );
    }

    /// CIRISEdge#352 — seed the five-row projection matrix for the pin test
    /// below and return the ids in seeding order:
    ///
    /// 1. federation-scoped scores by OTHER → Cohort/Global      → IN
    /// 2. affiliations-scoped scores by OTHER → Cohort           → IN
    /// 3. self-scoped scores by NODE (publish-own)               → IN
    /// 4. self-scoped scores by OTHER (foreign producer — the
    ///    structural-invisibility case)                          → OUT
    /// 5. self-scoped withdraws by OTHER tombstoning row 4:
    ///    anti-rollback overrides the scope → Global             → IN
    ///
    /// Dimension is `identity:example:v1` throughout (self-attesting one's
    /// own identity passes admission; the dimension is deliberately
    /// projection-irrelevant — `authority_for` only picks Global-vs-Cohort,
    /// both advertised).
    async fn seed_projection_matrix(
        backend: &MemoryBackend,
        node: &str,
        other: &str,
    ) -> [&'static str; 5] {
        let identity_scores = |id: &str, attester: &str| {
            serde_json::json!({
                "id": id,
                "attesting_key_id": attester,
                "attested_key_id": attester,
                "attestation_type": "scores",
                "dimension": "identity:example:v1",
            })
        };
        let in_fed = "att-352-in-federation";
        seed_scoped_attestation(
            backend,
            in_fed,
            other,
            other,
            "scores",
            "federation",
            identity_scores(in_fed, other),
        )
        .await;
        let in_affil = "att-352-in-affiliations";
        seed_scoped_attestation(
            backend,
            in_affil,
            other,
            other,
            "scores",
            "affiliations",
            identity_scores(in_affil, other),
        )
        .await;
        let in_self_own = "att-352-in-self-own";
        seed_scoped_attestation(
            backend,
            in_self_own,
            node,
            node,
            "scores",
            "self",
            identity_scores(in_self_own, node),
        )
        .await;
        let out_self_foreign = "att-352-out-self-foreign";
        seed_scoped_attestation(
            backend,
            out_self_foreign,
            other,
            other,
            "scores",
            "self",
            identity_scores(out_self_foreign, other),
        )
        .await;
        let in_tombstone = "att-352-in-tombstone";
        seed_scoped_attestation(
            backend,
            in_tombstone,
            other,
            other,
            "withdraws",
            "self",
            serde_json::json!({
                "id": in_tombstone,
                "attesting_key_id": other,
                "attested_key_id": other,
                "attestation_type": "withdraws",
                "references_attestation_id": out_self_foreign,
                "withdrawal_reason": "test: producer withdraws its own self-scoped edge",
            }),
        )
        .await;
        [
            in_fed,
            in_affil,
            in_self_own,
            out_self_foreign,
            in_tombstone,
        ]
    }

    /// CIRISEdge#352 — the advertise-projection pushdown verdict, pinned as
    /// an equivalence test over a seeded directory.
    ///
    /// The projection stays edge-side on the pinned persist (v24.2.0) — see
    /// the verdict block on
    /// [`FederationDirectoryReplicationBridge::attestation_is_advertised`] —
    /// so this test is the byte-identity pin any future pushdown must keep
    /// green: over a directory holding rows on BOTH sides of the projection,
    /// the advertised `(hash, seq)` set must equal the exact expected set
    /// derived from the seeded state. The IN/OUT verdict per row is
    /// HARD-CODED from the CC replication contract (persist
    /// `namespace::projection_for`), never computed by re-running the filter
    /// under test; the hashes come from the rows persist actually holds
    /// (the store stamps server-side fields — `persist_row_hash`,
    /// `withdraws_admission_rule` — that the content-hash covers).
    ///
    /// The #433 ledger boundary rides the same state: the projection DEFINES
    /// eligibility, so a row it excludes was never eligible and the sweep
    /// books NOTHING for it — while the row still appears in the RAW
    /// holdings view, proving its absence from the advertise set is the
    /// projection, not admission or serialization.
    #[tokio::test]
    async fn advertise_projection_boundary_and_ledger_are_pinned() {
        let node = "this-node";
        let other = "other-producer";
        let cohort = [node.to_string(), other.to_string()];
        let (backend, bridge, metrics) = make_metered_bridge(&cohort);
        // The node's OWN publish set — the SelfOwn axis of the projection.
        let publish_set = vec![node.to_string()];
        let selector: CohortProvider = Arc::new(move || publish_set.clone());
        let bridge = bridge.with_self_provider(Some(selector));
        for key_id in [node, other] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(key_id, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        let [in_fed, in_affil, in_self_own, out_self_foreign, in_tombstone] =
            seed_projection_matrix(&backend, node, other).await;

        // Derive the EXPECTED set from the state persist actually holds,
        // keyed by the hard-coded verdicts above.
        let held = backend
            .list_attestations_since(None, 100)
            .await
            .expect("read back seeded rows");
        assert_eq!(
            held.len(),
            5,
            "all five rows were ADMITTED — the OUT verdict below is the projection, not admission"
        );
        let expected_in = [in_fed, in_affil, in_self_own, in_tombstone];
        let expected: std::collections::BTreeSet<([u8; 32], u64)> = held
            .iter()
            .filter(|row| expected_in.contains(&row.attestation_id.as_str()))
            .map(|row| {
                let (hash, _bytes) = content_hash_of(row).expect("held row hashes");
                (
                    hash,
                    FederationDirectoryReplicationBridge::ms_seq(row.asserted_at),
                )
            })
            .collect();
        assert_eq!(expected.len(), 4);
        let out_hash = held
            .iter()
            .find(|row| row.attestation_id == out_self_foreign)
            .map(|row| content_hash_of(row).expect("held row hashes").0)
            .expect("the OUT row is held");

        // Equivalence: the advertise view (the exact entry the round's
        // `list_envelope_refs` dispatches; `None` recipient = projection-only)
        // equals the expected (hash, seq) set — nothing more, nothing less.
        let advertised = bridge.list_envelope_refs(EnvelopeKind::Attestation).await;
        let advertised_set: std::collections::BTreeSet<([u8; 32], u64)> = advertised
            .iter()
            .map(|r| (r.envelope_hash, r.seq))
            .collect();
        assert_eq!(advertised.len(), advertised_set.len(), "no duplicate refs");
        assert_eq!(
            advertised_set, expected,
            "the advertised (hash, seq) set is exactly the projection's expected set"
        );

        // The RAW holdings view (receive axis, #416) still carries the OUT
        // row: its absence above is the PROJECTION at work.
        let holdings = bridge.list_holdings(EnvelopeKind::Attestation).await;
        assert!(
            holdings.iter().any(|r| r.envelope_hash == out_hash),
            "the out-of-projection row IS held (receive axis)"
        );
        assert_eq!(holdings.len(), 5, "holdings carry every admitted row");

        // #433 boundary: the projection DEFINES eligibility. A row it
        // excludes was never eligible, so the sweep books NOTHING — not
        // `RowNotSerializable`, not `RowHashUndecodable`, not anything.
        let snap = metrics.snapshot();
        assert!(
            snap.withholds_by_reason.is_empty(),
            "a by-design projection non-event books no withhold, got {:?}",
            snap.withholds_by_reason
        );
    }

    // ── CIRISEdge#440 — mesh-config consumption + quarantine-aware offers ──

    /// Seed the mesh-config plane's trust scaffolding for `node`: the root's
    /// key record + the node's `delegates_to(node → root)` subscription edge
    /// ("the trust edge is the subscription", persist's `trusted_roots_of`).
    async fn seed_mesh_config_root(backend: &MemoryBackend, node: &str, root: &str) {
        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record(root, identity_type::NODE),
            })
            .await
            .expect("seed mesh-config root key");
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": node,
            "attested_key_id": root,
            "attestation_type": "delegates_to",
            // Infra duty scopes only — the reject-agency-on-node-key gate
            // (persist #236) refuses agency conferrals on node-typed keys.
            "scope": ["infra:attest", "infra:serve"],
        });
        seed_raw_attestation(backend, &id, node, root, "delegates_to", envelope).await;
    }

    /// Seed one root-authored mesh-config relief row through the REAL
    /// replication-plane admission (`put_attestation` — the door edge's own
    /// `apply_attestation` uses; persist: "the read-time clamp in
    /// `fold_mesh_config` is what holds for rows that arrive on the
    /// replication plane"). Built with persist's own `mesh_config_envelope`
    /// so the shape cannot drift from the fold's `parse_row`.
    async fn seed_mesh_config_relief(
        backend: &MemoryBackend,
        root: &str,
        key: ciris_persist::federation::MeshConfigKey,
        value: i64,
    ) {
        let envelope = ciris_persist::federation::mesh_config::mesh_config_envelope(
            key,
            value,
            root,
            ciris_persist::federation::MeshConfigForm::Emergency,
            Some(Utc::now() + chrono::Duration::hours(1)),
            "delegation-test-1",
            None,
            "test congestion relief",
        );
        let id = uuid::Uuid::new_v4().to_string();
        seed_raw_attestation(backend, &id, root, root, "scores", envelope).await;
    }

    /// A `MeshConfigReader` over the SAME backend the bridge reads, resolving
    /// for `node` with the production default baseline shape and TTL zero
    /// (every consult re-folds, so a just-seeded row is visible immediately).
    fn mesh_reader_over(
        backend: &Arc<MemoryBackend>,
        node: &str,
    ) -> Arc<crate::replication::mesh_config::MeshConfigReader> {
        let dir: Arc<dyn FederationDirectory> = Arc::clone(backend) as _;
        Arc::new(
            crate::replication::mesh_config::MeshConfigReader::new(
                dir,
                node.to_string(),
                crate::replication::mesh_config::MeshConfigReader::baseline_for(
                    std::time::Duration::from_secs(30),
                    BridgeConfig::DEFAULT_OPERATIONAL_PAGE_LIMIT,
                ),
            )
            .with_ttl(std::time::Duration::ZERO),
        )
    }

    /// ABSENCE — a bridge with a reader over an EMPTY mesh-config plane
    /// advertises and serves byte-identically to a bridge with no reader at
    /// all: same refs, same bytes, per plane. This is the "config is RELIEF,
    /// not a gate" contract as an executable statement.
    #[tokio::test]
    async fn empty_mesh_config_plane_is_byte_identical_to_no_reader() {
        let local = "this-node";
        let producer = "agent-producer";
        let cohort = [local.to_string(), producer.to_string()];
        let (backend, plain_bridge) = make_bridge(&cohort);
        seed_serve_scaffold(&backend, local, producer, "peer-consented").await;
        seed_trace_attestation(&backend, producer).await;
        // The mesh-config trust scaffolding EXISTS (root subscribed) but the
        // plane carries no relief rows — the fold resolves everything to
        // baseline.
        seed_mesh_config_root(&backend, local, "mc-root").await;

        let dir: Arc<dyn FederationDirectory> = Arc::clone(&backend) as _;
        let cohort_vec = cohort.to_vec();
        let cohort_cb: CohortProvider = Arc::new(move || cohort_vec.clone());
        let read_bridge = FederationDirectoryReplicationBridge::new(dir, cohort_cb)
            .with_mesh_config(Some(mesh_reader_over(&backend, local)));

        for kind in [
            EnvelopeKind::Key,
            EnvelopeKind::Attestation,
            EnvelopeKind::Revocation,
        ] {
            let mut plain = plain_bridge.list_envelope_refs(kind).await;
            let mut read = read_bridge.list_envelope_refs(kind).await;
            plain.sort_by_key(|r| r.envelope_hash);
            read.sort_by_key(|r| r.envelope_hash);
            assert_eq!(
                plain, read,
                "{kind:?}: an empty plane must not change the advertise set"
            );
            for r in &plain {
                let a = plain_bridge
                    .fetch_envelope_bytes(kind, &r.envelope_hash)
                    .await;
                let b = read_bridge
                    .fetch_envelope_bytes(kind, &r.envelope_hash)
                    .await;
                assert_eq!(a, b, "{kind:?}: byte-identical serve under an empty plane");
            }
        }
    }

    /// FIELD PROVENANCE, end to end — a root-authored
    /// `feature.trace_replication=0` relief row admitted through the real
    /// replication-plane door pauses the trace plane: the advertise sweep
    /// withholds the `trace:*` row (non-trace rows untouched), the
    /// direct-fetch twin refuses the hash, and BOTH book
    /// `WithholdReason::ConfigPaused` — the #433 rule: a named branch, never
    /// silence.
    #[tokio::test]
    async fn trace_replication_pause_withholds_trace_rows_and_books_config_paused() {
        use crate::observability::WithholdReason;
        let local = "this-node";
        let producer = "agent-producer";
        let cohort = [local.to_string(), producer.to_string()];
        let (backend, bridge, metrics) = make_metered_bridge(&cohort);
        seed_serve_scaffold(&backend, local, producer, "peer-consented").await;
        seed_trace_attestation(&backend, producer).await;
        seed_mesh_config_root(&backend, local, "mc-root").await;

        // Locate the trace hash while the plane is un-paused (reader wired,
        // no relief row yet — also proves the reader alone changes nothing).
        let bridge = bridge.with_mesh_config(Some(mesh_reader_over(&backend, local)));
        let trace_hash = locate_trace_hash(&bridge).await;
        let before = bridge.list_envelope_refs(EnvelopeKind::Attestation).await;
        assert!(
            before.iter().any(|r| r.envelope_hash == trace_hash),
            "un-paused: the trace row advertises"
        );

        // The relief row, through the real door.
        seed_mesh_config_relief(
            &backend,
            "mc-root",
            ciris_persist::federation::MeshConfigKey::FeatureTraceReplication,
            0,
        )
        .await;

        let after = bridge.list_envelope_refs(EnvelopeKind::Attestation).await;
        assert!(
            !after.iter().any(|r| r.envelope_hash == trace_hash),
            "paused: the trace row is withheld from the advertise"
        );
        assert!(
            !after.is_empty(),
            "paused: NON-trace rows (consent grant, trust edges, the relief \
             row itself) still advertise — the pause is trace-scoped"
        );
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, &trace_hash, None)
                .await
                .is_none(),
            "paused: the direct-fetch twin refuses the trace hash"
        );
        assert!(
            metrics.withholds(WithholdReason::ConfigPaused) >= 2,
            "the pause books config_paused on BOTH exits (sweep + fetch twin)"
        );
    }

    /// FIELD PROVENANCE, end to end — a root-authored
    /// `antientropy.page_limit` relief bounds the bridge's since-page:
    /// the Key plane's advertise shrinks to the relieved limit, and the same
    /// relief expiring (TTL'd emergency row filtered at read time) restores
    /// the configured (unbounded) page.
    #[tokio::test]
    async fn page_limit_relief_bounds_the_since_page() {
        let local = "this-node";
        let producers = ["key-a", "key-b", "key-c"];
        let cohort: Vec<String> = std::iter::once(local.to_string())
            .chain(producers.iter().map(|s| (*s).to_string()))
            .collect();
        let (backend, bridge) = make_bridge(&cohort);
        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record(local, identity_type::NODE),
            })
            .await
            .expect("seed local key");
        for p in producers {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(p, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        seed_mesh_config_root(&backend, local, "mc-root").await;
        let bridge = bridge.with_mesh_config(Some(mesh_reader_over(&backend, local)));

        assert_eq!(
            bridge.list_envelope_refs(EnvelopeKind::Key).await.len(),
            4,
            "no relief: the full page (local + the three producers; mc-root is \
             outside the cohort projection)"
        );

        seed_mesh_config_relief(
            &backend,
            "mc-root",
            ciris_persist::federation::MeshConfigKey::AntientropyPageLimit,
            2,
        )
        .await;
        assert_eq!(
            bridge.list_envelope_refs(EnvelopeKind::Key).await.len(),
            2,
            "relieved: the since-page is bounded to the relieved limit"
        );
    }

    /// CIRISEdge#440 ask 3 — quarantine-aware offers, end to end against
    /// persist's REAL marker fold:
    ///   (1) a `quarantine:withheld:v1` marker about author A withholds A's
    ///       rows from the ADVERTISE while B's still flow,
    ///   (2) the ledger books `quarantined_author` (named, never silent),
    ///   (3) A's rows are KEPT LOCALLY — the raw holdings view still carries
    ///       them (tier 2: withhold-from-serving, rows retained),
    ///   (4) the direct-fetch twin refuses A's hash,
    ///   (5) the MARKER ROW ITSELF still advertises (the convergence
    ///       carve-out: a quarantine that stopped replicating could not be
    ///       folded, and a release that stopped replicating would make a
    ///       reversible control irreversible),
    ///   (6) a `quarantine:released:v1` marker LIFTS the withhold — reversible,
    ///       exactly the fediverse-silence / Tor-flag precedent the issue
    ///       names.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // the six-property scenario is one coherent story
    async fn quarantined_author_rows_withheld_from_offer_kept_locally_and_reversible() {
        use crate::observability::WithholdReason;
        let local = "this-node";
        let author_a = "author-quarantined";
        let author_b = "author-clear";
        let moderator = "quarantine-authority";
        let cohort = [
            local.to_string(),
            author_a.to_string(),
            author_b.to_string(),
        ];
        let commons = "mod-commons";
        let (backend, bridge, metrics) = make_metered_bridge(&cohort);
        // The moderator is USER-typed (steward-bound clause 1) — the slash
        // gate persist runs on EVERY quarantine marker put (`put_attestation`
        // → `check_delegated_duty_scores_admission`) resolves duty-holders
        // from the marker's community's steward-bound authority set, so the
        // marker below is admitted under the REAL authority walk, not waved in.
        for (k, it) in [
            (local, identity_type::NODE),
            (author_a, identity_type::AGENT),
            (author_b, identity_type::AGENT),
            (moderator, identity_type::USER),
            (commons, identity_type::USER),
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(k, it),
                })
                .await
                .expect("seed key");
        }
        // The community whose authority set holds the `slash` duty: the
        // moderator is its founder.
        backend
            .put_community(sign_community_fixture(
                moderator,
                Community {
                    community_key_id: commons.to_string(),
                    community_name: "quarantine test commons".to_string(),
                    members: vec![CommunityMember {
                        key_id: moderator.to_string(),
                        joined_at: Utc::now(),
                        role: Some("founder".to_string()),
                    }],
                    founded_at: Utc::now(),
                    consensus_protocol: "majority".to_string(),
                    policy_blob: None,
                    persist_row_hash: String::new(),
                },
            ))
            .await
            .expect("seed moderation commons");
        // One ordinary scores row per author (an open-vocabulary dimension —
        // Cohort projection, so both advertise peer-blind).
        for author in [author_a, author_b] {
            let id = uuid::Uuid::new_v4().to_string();
            let envelope = serde_json::json!({
                "id": id,
                "attesting_key_id": author,
                "attested_key_id": author,
                "attestation_type": "scores",
                "dimension": "credits:test:v1",
                "score": 1.0,
            });
            seed_raw_attestation(&backend, &id, author, author, "scores", envelope).await;
        }
        // Map advertised hash → author while nothing is withheld.
        let mut hash_of: HashMap<String, [u8; 32]> = HashMap::new();
        for r in bridge.list_envelope_refs(EnvelopeKind::Attestation).await {
            let bytes = bridge
                .fetch_envelope_bytes(EnvelopeKind::Attestation, &r.envelope_hash)
                .await
                .expect("fetch advertised row");
            let v: serde_json::Value = serde_json::from_slice(&bytes).expect("wire json");
            if v.pointer("/attestation_envelope/dimension")
                .and_then(|d| d.as_str())
                == Some("credits:test:v1")
            {
                let author = v["attesting_key_id"].as_str().expect("author").to_string();
                hash_of.insert(author, r.envelope_hash);
            }
        }
        let a_hash = hash_of[author_a];
        let b_hash = hash_of[author_b];

        // The withhold marker, via persist's own envelope builder + the real
        // replication-plane door.
        let marker_id = uuid::Uuid::new_v4().to_string();
        let marker_env = ciris_persist::federation::quarantine::withhold_envelope(
            author_a,
            commons,
            "delegation-test-1",
            "test: withhold-from-serving",
        );
        seed_raw_attestation(
            &backend, &marker_id, moderator, author_a, "scores", marker_env,
        )
        .await;

        // (1) + (5): A withheld, B flows, the marker itself advertises.
        let offer = bridge.list_envelope_refs(EnvelopeKind::Attestation).await;
        assert!(
            !offer.iter().any(|r| r.envelope_hash == a_hash),
            "(1) the quarantined author's row is withheld from the offer"
        );
        assert!(
            offer.iter().any(|r| r.envelope_hash == b_hash),
            "(1) the clear author's row still flows"
        );
        let marker_advertised = {
            let mut found = false;
            for r in &offer {
                if let Some(bytes) = bridge
                    .fetch_envelope_bytes(EnvelopeKind::Attestation, &r.envelope_hash)
                    .await
                {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        if v.pointer("/attestation_envelope/dimension")
                            .and_then(|d| d.as_str())
                            == Some("quarantine:withheld:v1")
                        {
                            found = true;
                        }
                    }
                }
            }
            found
        };
        assert!(marker_advertised, "(5) the marker plane is never withheld");
        // (2) named, never silent.
        assert!(
            metrics.withholds(WithholdReason::QuarantinedAuthor) >= 1,
            "(2) the ledger books quarantined_author"
        );
        // (3) rows retained: the raw holdings (receive axis) still carry A.
        assert!(
            bridge
                .list_holdings(EnvelopeKind::Attestation)
                .await
                .iter()
                .any(|r| r.envelope_hash == a_hash),
            "(3) tier 2 retains the row locally"
        );
        // (4) the direct-fetch twin refuses A's hash.
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, &a_hash, None)
                .await
                .is_none(),
            "(4) the fetch twin withholds too — no out-of-band bypass"
        );

        // (6) REVERSIBLE: a release marker lifts the withhold.
        let release_id = uuid::Uuid::new_v4().to_string();
        let release_env = ciris_persist::federation::quarantine::release_envelope(
            author_a,
            commons,
            &marker_id,
            "delegation-test-1",
            "test: released",
        );
        seed_raw_attestation(
            &backend,
            &release_id,
            moderator,
            author_a,
            "scores",
            release_env,
        )
        .await;
        assert!(
            bridge
                .list_envelope_refs(EnvelopeKind::Attestation)
                .await
                .iter()
                .any(|r| r.envelope_hash == a_hash),
            "(6) a release marker lifts the withhold — the control is reversible"
        );
    }
}
