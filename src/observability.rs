//! Observability — structured logs + OTLP metrics + health probes.
//!
//! Mission: every message in or out is auditable. Federation trust
//! requires that any peer can answer "what did you receive, what did
//! you send, what was the verify outcome, when, from whom" — without
//! forensic archaeology.
//! ([`MISSION.md`](../../MISSION.md) §2 `observability/`.)
//!
//! # CIRISEdge#28 v0.19.0 — Observability surface
//!
//! Three load-bearing capabilities ship in this cut:
//!
//! 1. **Tracing spans** — `tracing::instrument` annotations on every
//!    `Edge::send*` / `dispatch_inbound` / transport `send` call site,
//!    with structured fields (`recipient_key_id`, `message_type`,
//!    `delivery_class`, `transport_id`, `signing_key_id`,
//!    `body_sha256_prefix`, `verify_outcome`, `attempt_n`). Consumers
//!    (CIRISLens, CIRISAgent UI) tail the tracing-subscriber-emitted
//!    structured logs and join on the same fields persist's forensic
//!    indices key on.
//!
//! 2. **EdgeMetrics struct** — a snapshot-able counter / gauge bag
//!    living on [`crate::Edge`]. Every send / receive / verify-failure
//!    / transport-bytes path increments the appropriate counter; the
//!    `metrics_snapshot` reads project the live state into a typed
//!    `EdgeMetricsBundle` consumers (PyO3 / UniFFI) can render. The
//!    struct uses `Arc<parking_lot::RwLock<HashMap<...>>>` per the
//!    Cargo.toml note — `parking_lot` is already a v0.11.0 dep
//!    (CIRISEdge#29 `ReachabilityTracker`); `dashmap` is intentionally
//!    NOT pulled (extra license surface + the contention pattern
//!    counter-bumps produce doesn't justify a sharded map).
//!
//! 3. **Pymethod surface** — [`crate::ffi::pyo3::PyEdge::metrics_snapshot`]
//!    returns a Python `dict` of `dict`s; consumers call it repeatedly
//!    for change-detection. The shape is documented on the pymethod.
//!
//! # Structured log fields (per-message)
//!
//! - `signing_key_id` — sender's federation_keys.key_id
//! - `body_sha256_prefix` — joins to persist's forensic indices
//!   (Bridge already trained on this join key during the v0.2.x
//!   debug)
//! - `verify_result` — typed reject code or `verified`
//! - `handler_duration_ms` — handler-time, excludes verify
//! - `transport` — TransportId (http / reticulum-rs / lora / ...)
//!
//! # Counter labels
//!
//! Stable label cardinality:
//!
//! - `envelopes_sent_total[MessageType]` — every successful send/enqueue
//! - `envelopes_received_total[MessageType]` — every verified inbound envelope
//! - `send_failures_total[(TransportId, ErrorClass)]` — typed transport faults
//! - `verify_failures_total[VerifyErrorClass]` — typed verify pipeline rejects
//! - `transport_bytes_in_total[TransportId]` — bytes-counted by the
//!   listener side
//! - `transport_bytes_out_total[TransportId]` — bytes-counted by the
//!   send side
//!
//! Gauges:
//!
//! - `durable_queue_depth[DeliveryClass]` — count of currently-queued
//!   send_durable / send_mandatory / send_federation envelopes
//! - `peer_reachability_ratio[(peer_key_id, medium)]` — rolling
//!   reachability window ratio, mirror of `ReachabilityTracker::snapshot_all`

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use parking_lot::RwLock;

use crate::messages::MessageType;
use crate::replication::protocol::EnvelopeKind;
use crate::transport::TransportId;

/// Classification of a `VerifyError` for metrics labelling. Mirrors
/// the discriminator on [`crate::verify::VerifyError`] but is `Copy +
/// Eq + Hash` so it can sit in a `HashMap` key. Strings (the typed
/// `VerifyError` payload) are deliberately excluded — high-cardinality
/// label values explode metric storage downstream (Prometheus / OTLP),
/// and the classification is the load-bearing dimension consumers
/// alert on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerifyErrorClass {
    BodyTooLarge,
    SchemaInvalid,
    UnsupportedSchemaVersion,
    Misrouted,
    ReplayDetected,
    UnknownKey,
    SignatureMismatch,
    PqcPendingStrictReject,
    CanonicalizationFailed,
    VerifyUnavailable,
    ContentIntegrity,
}

impl VerifyErrorClass {
    /// Snake-case stable label string. Used as the dict-key on the
    /// PyO3 `metrics_snapshot` surface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BodyTooLarge => "body_too_large",
            Self::SchemaInvalid => "schema_invalid",
            Self::UnsupportedSchemaVersion => "unsupported_schema_version",
            Self::Misrouted => "misrouted",
            Self::ReplayDetected => "replay_detected",
            Self::UnknownKey => "unknown_key",
            Self::SignatureMismatch => "signature_mismatch",
            Self::PqcPendingStrictReject => "pqc_pending_strict_reject",
            Self::CanonicalizationFailed => "canonicalization_failed",
            Self::VerifyUnavailable => "verify_unavailable",
            Self::ContentIntegrity => "content_integrity",
        }
    }

    /// Classify a live [`crate::verify::VerifyError`] for counter
    /// labelling. Lives here (not on `VerifyError`) so the metrics
    /// taxonomy can evolve independently of the typed error tree.
    #[must_use]
    pub fn from_verify_error(e: &crate::verify::VerifyError) -> Self {
        use crate::verify::VerifyError as V;
        match e {
            V::BodyTooLarge { .. } => Self::BodyTooLarge,
            V::SchemaInvalid(_) => Self::SchemaInvalid,
            V::UnsupportedSchemaVersion(_) => Self::UnsupportedSchemaVersion,
            V::Misrouted => Self::Misrouted,
            V::ReplayDetected => Self::ReplayDetected,
            V::UnknownKey(_) => Self::UnknownKey,
            V::SignatureMismatch(_) => Self::SignatureMismatch,
            V::PqcPendingStrictReject => Self::PqcPendingStrictReject,
            V::CanonicalizationFailed(_) => Self::CanonicalizationFailed,
            V::VerifyUnavailable(_) => Self::VerifyUnavailable,
            V::ContentIntegrity { .. } => Self::ContentIntegrity,
        }
    }
}

/// Delivery-class discriminator for the durable-queue gauge.
/// Distinct from [`crate::handler::Delivery`] (the type-level message
/// trait) — this is the runtime label used in the metric key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeliveryClass {
    Ephemeral,
    Durable,
    Mandatory,
    Federation,
}

impl DeliveryClass {
    /// Snake-case stable label string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ephemeral => "ephemeral",
            Self::Durable => "durable",
            Self::Mandatory => "mandatory",
            Self::Federation => "federation",
        }
    }
}

/// Terminal outcome of a single anti-entropy replication round, as the
/// scheduler's per-coordinator run loop observed it (the metrics-facing
/// projection of [`crate::replication::scheduler::RoundEvent`]). It is
/// `Copy + Eq + Hash` so it sits in the counter `HashMap` key; the
/// [`crate::replication::RoundReport`] payload the `Completed` event
/// carries is deliberately dropped here — high-cardinality per-round
/// detail belongs on the tracing span, not the counter label.
///
/// CIRISEdge#370 — this is the instrument that makes the transport
/// concurrency ceiling measurable in the field. Below the saturation
/// cliff rounds `Completed`; once inbound crypto + outbound sends
/// serialize on leviculum's single `Mutex<StdNodeCore>` past the peer
/// count one link can service, rounds shift to `TimedOut`. A climbing
/// `timed_out` share against a flat `completed` count is the signature
/// of the ceiling — a throughput wall, not a per-peer latency gradient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoundOutcome {
    /// The round drove to `Complete` — the peer replied and the
    /// diff/deliver phases finished within `round_timeout`.
    Completed,
    /// The coordinator refused the round (malformed / out-of-state
    /// peer message); the scheduler reset the session.
    Refused,
    /// `round_timeout` elapsed waiting for the peer's reply between
    /// SendThenWait phases — the dominant saturation signal.
    TimedOut,
    /// A transport / protocol / inbound-closed error aborted the round.
    Error,
}

impl RoundOutcome {
    /// Snake-case stable label string. Used as the dict-key on the
    /// PyO3 `metrics_snapshot` surface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Refused => "refused",
            Self::TimedOut => "timed_out",
            Self::Error => "error",
        }
    }
}

/// CIRISEdge#433 — the closed taxonomy of *withhold* reasons: every branch on a
/// serving path where a row WAS eligible to go and did not.
///
/// # Why this exists
///
/// The metrics surface counted successes (`envelopes_sent_total`), failures
/// (`send_failures_total`), and drops (back-pressure / low-trust) — but a gate
/// deciding "I will not serve this row to this peer" emitted nothing countable.
/// A withholding node therefore reported EXACTLY what an idle node reported:
/// `envelopes_sent_total: 0`, round `completed`, perfect health, zero carriage.
/// That is the #423–#429 silent-refusal arc's last uncounted limb, and the
/// mirror image of the replication-plane send blindness
/// [`EdgeMetrics::replication_envelopes_served_total`] closes.
///
/// # The two properties this type enforces
///
/// 1. **A withhold is an event, not a non-event.** Every `return None` /
///    `continue` on a serving path in [`crate::replication::bridge`] increments
///    one of these.
/// 2. **The reason is the BRANCH, not a disjunction.** Each variant maps to ONE
///    code branch (documented per-variant with the gate it belongs to), so a
///    `bool`-returning gate that folds five refusal legs into `false` — as
///    `peer_has_serve_capability` did — reports each leg separately. Collapsing
///    "the peer has no role" into "the directory read failed" is exactly the
///    class of confident-but-wrong report #425 Exhibit C called out.
///
/// `Copy + Eq + Hash` so it sits in the counter `HashMap` key. The peer and any
/// per-event detail ride the bounded [`WithholdRecord`] ring, never the label —
/// unbounded label cardinality explodes downstream metric storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WithholdReason {
    /// The requested `(kind, envelope_hash)` did not resolve to bytes in local
    /// state. This is the bridge-level origin of the #429
    /// *advertised-then-unfetchable* event: every hash the responder's
    /// `pack_bounded_deliver` reports in its `dropped` set is a `None` from
    /// [`crate::replication::bridge::FederationDirectoryReplicationBridge`]'s
    /// recipient-aware fetch, and this is that `None` — stale wire-index, pruned
    /// row, or hash skew. Deliberately distinct from every policy gate below, so
    /// "we chose not to" never hides inside "we could not find it".
    EnvelopeUnfetchable,
    /// The bridge has no `local_key_id`, so the `I` whose consent / trust would
    /// be evaluated does not exist. Fail-closed at two sites that share this ONE
    /// condition and ONE operator remedy (wire
    /// `ReplicationRuntimeConfig::local_key_id`): the #396 item-1 consent
    /// send-set resolution and the #386 leg-B trust-root walk. A wiring fault,
    /// not a policy decision — the `detail` names which site observed it.
    LocalIdentityMissing,
    /// The consent send-set (`list_consent_peers(local)`, persist's E7
    /// projection) could not be read. Fail-closed: a transient directory error
    /// is NOT a statement that the peer is unconsented (#396 item 1).
    SendSetUnresolved,
    /// The send-set resolved and the peer is NOT in it — the #396 item-1
    /// consent-membership fan-out bound, working as designed. The whole
    /// Attestation plane is withheld from this peer.
    RecipientNotInSendSet,
    /// #379/#386 leg A — the recipient holds no accord-conferred, still-verifying
    /// `infra:serve`. A `trace:*` row is withheld. This is the reason a fleet
    /// that has not re-genesised with an `infra:serve`-blessed canonical sees a
    /// dark trace plane (CIRISPersist#480).
    ServeCapabilityMissing,
    /// #386 leg A — the `infra:serve` DIRECTORY READ failed. #425 Exhibit C:
    /// reported as a read error, never folded into [`Self::ServeCapabilityMissing`],
    /// because a transient failure reported as a confident statement about the
    /// peer's blessing sends the operator looking in the wrong place.
    ServeCapabilityReadError,
    /// #386 leg B — the recipient's `infra:serve` roots to no root THIS node
    /// trusts. One of three inputs is absent: the root→peer scoped grant, our own
    /// trust edge to that root, or a live root charter.
    ServeCapabilityNotRooted,
    /// #386 leg B — the trust-root walk itself errored. Same Exhibit C split as
    /// [`Self::ServeCapabilityReadError`]: transient, not a trust verdict.
    TrustRootWalkError,
    /// #396 item 6 — the DATA PRODUCER attached a `recipient_capability`
    /// restriction to its own `consent:replication:v1` grant covering this row's
    /// dimension, and the recipient does not hold that capability.
    RecipientCapabilityRestriction,
    /// A row present in local state could not be serialized to its content hash
    /// (`content_hash_of` / `serde_json::to_value` returned nothing), so it is
    /// OMITTED from the advertise set and will never replicate. Near-impossible
    /// for these types — which is exactly why it must speak if it ever fires.
    RowNotSerializable,
    /// A row's `persist_row_hash` was not decodable as 32 hex-encoded bytes, so
    /// the row is absent from the advertise set. Distinct from
    /// [`Self::RowNotSerializable`]: the row serializes fine, its persist-side
    /// hash is the wrong shape.
    RowHashUndecodable,
    /// #440 — the mesh-config plane relieved `feature.trace_replication` to `0`
    /// (a root's TTL'd congestion relief, persist's per-root most-restrictive
    /// fold), so `trace:*` rows are withheld from the advertise sweep and the
    /// direct-fetch twin. A POLICY pause with an expiry, not a fault: it lifts
    /// on the row's TTL or a superseding row, with no operator action here.
    ConfigPaused,
    /// #440 ask 3 — the row's AUTHOR is under a live `quarantine:withheld:v1`
    /// marker (persist's tier-2 withhold-from-serving fold, CIRISPersist#570
    /// ask 5): the row is withheld from peers while retained locally
    /// (reversible — a `quarantine:released:v1` marker lifts it). The marker
    /// plane itself is never withheld (a quarantine that stops replicating
    /// could not be folded, and a release that stops replicating would make a
    /// reversible control irreversible).
    QuarantinedAuthor,
    /// #440 ask 3 — the quarantine consult for the row's author FAILED
    /// (fail-closed: the row is withheld). The #425 Exhibit C split, again:
    /// a transient read error is NOT a statement that the author is
    /// quarantined, and folding it into [`Self::QuarantinedAuthor`] would send
    /// the operator to review a marker that does not exist.
    QuarantineReadError,
    /// Workstream F — an `accord:*` row was withheld because this node holds no
    /// FAMILY under the accord root, so persist's
    /// [`RelayVerdict`](ciris_persist::federation::trust_root::RelayVerdict)
    /// reported `roster_resolvable: false`: **"I cannot judge"**. Its own
    /// variant, never folded into [`Self::AccordRelaySignerNotSeated`] — an
    /// unjudgeable root and an unseated signer are different things to go fix
    /// (sync the family record vs. look at the signer), and CIRISPersist#713
    /// wrote a mutation specifically to keep them apart.
    AccordRelayRosterUnresolvable,
    /// Workstream F — the accord roster resolved and the row's
    /// `attesting_key_id` holds no live seat on it (revocation-folded).
    /// Trusting a root does not make every key naming it authoritative.
    AccordRelaySignerNotSeated,
    /// Workstream F — no live `delegates_to(self → accord root)`: this node
    /// never granted the root, or has cut the edge. CC 4.2.1 — *"a node that
    /// never trusted the accord … is simply not reached"*. This is the leg the
    /// `accord:*` `Global` projection row runs over on its own, and the reason
    /// the relay predicate exists.
    AccordRelayNoTrustEdge,
    /// Workstream F — the relay verdict was NOT RESOLVED (never primed, expired,
    /// or invalidated and not yet re-resolved), so the sync serve gate refused
    /// fail-closed. Deliberately distinct from every decided refusal above: this
    /// says *"we never ran the check"*, which is a wiring/timing fact, not a
    /// statement about the signer or the root.
    AccordRelayUnresolved,
    /// CIRISEdge#499 (blob plane) — an inbound `BlobChunkFetch` was refused
    /// because the responder could not determine the blob's SCOPE, so it could
    /// not evaluate whether this requester is entitled to it. Fail-closed, and
    /// its own branch: "I do not know what this content is" is a wiring fact
    /// (`BlobChunkSource::chunk_scope` unwired or returning `None`) with an
    /// operator remedy, not a statement about the requester.
    BlobScopeUndeterminable,
    /// CIRISEdge#499 (blob plane) — the blob's scope does not admit the scope
    /// the request ARRIVED on, per the #48-A
    /// [`allows_recipient_scope`](crate::cohort_scope::CohortScope::allows_recipient_scope)
    /// predicate. The canonical case: family-scoped content requested over the
    /// federation address, where reaching a public discovery endpoint proves
    /// nothing about family membership. This is the gate working as designed.
    BlobArrivalScopeInsufficient,
    /// CIRISEdge#499 (blob plane) — the arrival SCOPE matched but the request
    /// arrived on an address derived from a DIFFERENT group's MLS
    /// `exporter_secret`. Its own branch because the scope predicate
    /// structurally cannot see it (`Family` vs `Family` is a match), and yet
    /// possession of one family's group secret proves nothing about another's —
    /// folding this into [`Self::BlobArrivalScopeInsufficient`] would report a
    /// cross-group access attempt as an ordinary scope mismatch.
    BlobArrivalGroupMismatch,
}

impl WithholdReason {
    /// Snake-case stable label string. Used as the dict-key on the PyO3
    /// `metrics_snapshot` surface; stable across releases.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EnvelopeUnfetchable => "envelope_unfetchable",
            Self::LocalIdentityMissing => "local_identity_missing",
            Self::SendSetUnresolved => "send_set_unresolved",
            Self::RecipientNotInSendSet => "recipient_not_in_send_set",
            Self::ServeCapabilityMissing => "serve_capability_missing",
            Self::ServeCapabilityReadError => "serve_capability_read_error",
            Self::ServeCapabilityNotRooted => "serve_capability_not_rooted",
            Self::TrustRootWalkError => "trust_root_walk_error",
            Self::RecipientCapabilityRestriction => "recipient_capability_restriction",
            Self::RowNotSerializable => "row_not_serializable",
            Self::RowHashUndecodable => "row_hash_undecodable",
            Self::ConfigPaused => "config_paused",
            Self::QuarantinedAuthor => "quarantined_author",
            Self::QuarantineReadError => "quarantine_read_error",
            Self::AccordRelayRosterUnresolvable => "accord_relay_roster_unresolvable",
            Self::AccordRelaySignerNotSeated => "accord_relay_signer_not_seated",
            Self::AccordRelayNoTrustEdge => "accord_relay_no_trust_edge",
            Self::AccordRelayUnresolved => "accord_relay_unresolved",
            Self::BlobScopeUndeterminable => "blob_scope_undeterminable",
            Self::BlobArrivalScopeInsufficient => "blob_arrival_scope_insufficient",
            Self::BlobArrivalGroupMismatch => "blob_arrival_group_mismatch",
        }
    }
}

impl std::fmt::Display for WithholdReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// CIRISEdge#441 — per-(removal-row, peer) delivery state. The single most-
/// repeated PKI lesson is that revocation does not arrive (CRL/OCSP soft-
/// fail); every CIRIS removal primitive rides a pull-only plane, so absence
/// of delivery was invisible. The three states are deliberately distinct —
/// collapsing them is how "unverified" gets read as "delivered", the exact
/// failure receipts exist to expose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalDeliveryState {
    /// The row exists locally; this peer has never been served it.
    NeverOffered,
    /// Served to the peer (packed into a Deliver) at the contained unix-ms
    /// instant; no evidence the peer holds it yet.
    Offered(u64),
    /// The peer's own subsequent Summary advertised the row's hash — the
    /// protocol-native receipt (a Summary IS a signed-session statement of
    /// holdings; no new wire). Unix-ms of the observing Summary.
    Acked(u64),
}

/// CIRISEdge#441 — the removal-receipt ledger: per removal-class row, the
/// per-peer delivery state. NOT a delivery guarantee — the instrument that
/// makes non-delivery visible ("peers that should have this and have not
/// acked"). Bounded: at most [`REMOVAL_LEDGER_CAP`] rows (oldest evicted);
/// peers per row bounded by observed cohort.
#[derive(Debug, Default)]
pub struct RemovalReceiptLedger {
    /// (kind, envelope_hash) → per-peer state. `VecDeque` tracks insertion
    /// order for eviction.
    rows: HashMap<(EnvelopeKind, [u8; 32]), HashMap<String, RemovalDeliveryState>>,
    order: VecDeque<(EnvelopeKind, [u8; 32])>,
}

/// CIRISEdge#441 — how many removal rows the ledger tracks (oldest evicted).
/// Removal primitives are rare; 1024 covers years of fleet churn.
pub const REMOVAL_LEDGER_CAP: usize = 1024;

impl RemovalReceiptLedger {
    /// A removal-class row exists locally (seen at advertise assembly).
    /// Idempotent; evicts oldest past the cap.
    pub fn track(&mut self, kind: EnvelopeKind, hash: [u8; 32]) {
        let key = (kind, hash);
        if self.rows.contains_key(&key) {
            return;
        }
        while self.rows.len() >= REMOVAL_LEDGER_CAP {
            if let Some(old) = self.order.pop_front() {
                self.rows.remove(&old);
            } else {
                break;
            }
        }
        self.rows.insert(key, HashMap::new());
        self.order.push_back(key);
    }

    /// The row was SERVED to `peer` (the bridge's recipient-aware serve
    /// exit). Never downgrades an existing `Acked`.
    pub fn offer(&mut self, kind: EnvelopeKind, hash: [u8; 32], peer: &str, now_ms: u64) {
        self.track(kind, hash);
        if let Some(peers) = self.rows.get_mut(&(kind, hash)) {
            let e = peers
                .entry(peer.to_string())
                .or_insert(RemovalDeliveryState::NeverOffered);
            if !matches!(e, RemovalDeliveryState::Acked(_)) {
                *e = RemovalDeliveryState::Offered(now_ms);
            }
        }
    }

    /// `peer`'s Summary for `kind` advertised `hashes` — every tracked row
    /// among them is now `Acked` for that peer (including rows we never
    /// offered: the peer got it elsewhere, which is still a receipt).
    pub fn ack_from_summary(
        &mut self,
        peer: &str,
        kind: EnvelopeKind,
        hashes: &[[u8; 32]],
        now_ms: u64,
    ) {
        for h in hashes {
            if let Some(peers) = self.rows.get_mut(&(kind, *h)) {
                peers.insert(peer.to_string(), RemovalDeliveryState::Acked(now_ms));
            }
        }
    }

    /// The delta read: every tracked row with, per known peer, its state.
    /// A peer in the serving cohort that appears NOWHERE for a row is
    /// `NeverOffered` by definition — the caller composes that against its
    /// cohort list (the ledger only knows peers it has observed).
    #[must_use]
    pub fn delta(&self) -> Vec<RemovalRowDelta> {
        self.order
            .iter()
            .filter_map(|key| {
                let peers = self.rows.get(key)?;
                let offered = peers
                    .values()
                    .filter(|s| matches!(s, RemovalDeliveryState::Offered(_)))
                    .count();
                let acked = peers
                    .values()
                    .filter(|s| matches!(s, RemovalDeliveryState::Acked(_)))
                    .count();
                let mut unacked_peers: Vec<String> = peers
                    .iter()
                    .filter(|(_, s)| !matches!(s, RemovalDeliveryState::Acked(_)))
                    .map(|(p, _)| p.clone())
                    .collect();
                unacked_peers.sort();
                unacked_peers.truncate(16);
                Some(RemovalRowDelta {
                    kind: key.0,
                    envelope_hash: key.1,
                    offered,
                    acked,
                    unacked_peers,
                })
            })
            .collect()
    }
}

/// CIRISEdge#441 — one row of the removal-delivery delta read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalRowDelta {
    /// The removal plane.
    pub kind: EnvelopeKind,
    /// The row's envelope hash.
    pub envelope_hash: [u8; 32],
    /// Peers offered-but-unacked.
    pub offered: usize,
    /// Peers with a Summary-evidenced receipt.
    pub acked: usize,
    /// Offered/known peers still lacking an ack (sorted, capped at 16).
    pub unacked_peers: Vec<String>,
}

/// CIRISEdge#433 — one entry in the bounded recent-withholds ring: the
/// attribution a bare counter cannot carry, WITHOUT turning on debug logging.
///
/// `detail` is a short, low-cardinality descriptor built at the call site (the
/// envelope kind plus a hash prefix, or the gate leg) — never a full envelope,
/// never peer-supplied content. The ring itself is capped at
/// [`RECENT_WITHHOLDS_CAP`], so the memory this costs is bounded regardless of
/// how long a node withholds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithholdRecord {
    /// The branch that withheld.
    pub reason: WithholdReason,
    /// The recipient the row was withheld from (`<unattributed>` when the
    /// withhold is peer-blind, e.g. an unserializable row on the advertise
    /// sweep).
    pub peer_key_id: String,
    /// Short attribution — envelope kind + hash prefix, or the gate leg.
    pub detail: String,
}

/// CIRISEdge#433 — how many recent withholds the attribution ring keeps. Fixed
/// (not tunable) and small: this is a *what just happened* window for an
/// operator reading a snapshot, not a log. Oldest is evicted first.
pub const RECENT_WITHHOLDS_CAP: usize = 64;

/// The live counter/gauge bag every [`crate::Edge`] owns.
///
/// # Concurrency
///
/// Every field is `Arc<RwLock<HashMap<_, _>>>` over `parking_lot::RwLock`
/// — uncontended write path is ~20ns (parking_lot is already on the
/// dep graph for [`crate::ReachabilityTracker`]; no new license surface).
/// `dashmap` was rejected for the same Cargo.toml-§125 reasoning the
/// reachability tracker captured: extra license surface, contention-
/// tuning we don't need.
///
/// # Cloning
///
/// `EdgeMetrics` is `Clone`; every field is an `Arc`, so a clone is
/// cheap. [`crate::Edge`] stores one and threads clones into
/// `dispatch_inbound` / the durable dispatcher loop / transport listen
/// loops.
#[derive(Debug, Clone, Default)]
pub struct EdgeMetrics {
    /// Per-[`MessageType`] count of envelopes the local edge has
    /// successfully signed + offered to a transport (or enqueued, for
    /// durable / mandatory / federation classes). Incremented at the
    /// success exit of [`crate::Edge::send`] / `send_durable` /
    /// `send_mandatory` / `send_federation`.
    pub envelopes_sent_total: Arc<RwLock<HashMap<MessageType, u64>>>,
    /// Per-[`MessageType`] count of envelopes the local edge has
    /// successfully verified at the inbound path. Incremented in
    /// `dispatch_inbound` after a successful `VerifyPipeline::verify`,
    /// keyed on the verified envelope's `message_type` field.
    pub envelopes_received_total: Arc<RwLock<HashMap<MessageType, u64>>>,
    /// Per-(transport, error-class) count of failed sends. The
    /// `String` is the snake-case error class produced by the same
    /// `transport_error_class` mapping the reachability tracker uses
    /// (`unreachable`, `timeout`, `config`, `io`, `body_too_large`,
    /// `peer_blackholed`).
    pub send_failures_total: Arc<RwLock<HashMap<(TransportId, String), u64>>>,
    /// Per-[`VerifyErrorClass`] count of inbound verify rejects.
    /// Incremented in `dispatch_inbound` when `VerifyPipeline::verify`
    /// returns `Err`.
    pub verify_failures_total: Arc<RwLock<HashMap<VerifyErrorClass, u64>>>,
    /// Gauge — current count of in-flight durable-class envelopes
    /// per delivery class. Incremented at enqueue, decremented at
    /// dispatch (success OR terminal abandon).
    ///
    /// **Note**: v0.19.0 wires the increment side only — the
    /// dispatcher's terminal-state handling lives on persist's
    /// `OutboundHandle` surface, and the bookkeeping there isn't
    /// edge-internal. The gauge captures cumulative enqueues and
    /// consumers diff it against the persist-side `queue_depth` UDL
    /// read for the resident count. The metric name was held stable
    /// for downstream consumers; the semantic gap is documented on
    /// the pymethod surface.
    pub durable_queue_depth: Arc<RwLock<HashMap<DeliveryClass, u64>>>,
    /// Per-transport byte count for inbound frames. Incremented by
    /// the inbound listener side when it pushes an [`crate::transport::InboundFrame`].
    pub transport_bytes_in_total: Arc<RwLock<HashMap<TransportId, u64>>>,
    /// Per-transport byte count for outbound envelopes. Incremented
    /// at the success exit of [`crate::transport::Transport::send`]
    /// invocations (`Edge::send` direct path, durable dispatcher loop).
    pub transport_bytes_out_total: Arc<RwLock<HashMap<TransportId, u64>>>,
    /// Gauge — per-(peer, medium) reachability ratio. Mirror of the
    /// reachability tracker; consumers can read the mirror without
    /// reaching across to [`crate::ReachabilityTracker`].
    pub peer_reachability_ratio: Arc<RwLock<HashMap<(String, String), f64>>>,
    /// CIRISEdge#48-B (v0.19.6) — count of inbound envelopes dropped
    /// at `dispatch_inbound` because the verified sender's trust
    /// score fell below [`crate::EdgeConfig::trust_threshold`].
    /// Incremented only on the dispatch-time drop path; envelopes
    /// admitted at-or-above threshold do NOT touch this counter.
    /// Single `Arc<AtomicU64>` (not a per-key bag) — the offending
    /// `signing_key_id` already rides on the matching
    /// `EventKind::TrustShortCircuited` event.
    pub inbound_dropped_low_trust: Arc<std::sync::atomic::AtomicU64>,
    /// CIRISEdge#370 — per-[`RoundOutcome`] count of anti-entropy
    /// replication rounds the scheduler has driven to a terminal state
    /// (Completed / Refused / TimedOut / Error). Incremented once per
    /// round by [`crate::replication::runtime::ReplicationRuntime::start`]'s
    /// scheduler event-sink consumer, active only when a live metrics
    /// handle is set on [`crate::replication::ReplicationRuntimeConfig`].
    /// A `timed_out` share that climbs with active-peer count is the
    /// field signature of the transport concurrency ceiling — the whole
    /// reason this counter exists.
    pub replication_round_outcomes_total: Arc<RwLock<HashMap<RoundOutcome, u64>>>,
    /// CIRISEdge#373 — cumulative count of inbound replication frames dropped
    /// because the target coordinator's bounded inbound channel was full
    /// (`RegistryError::BackPressure`). Before this counter the drop was a bare
    /// `tracing::warn!` — 100% of a churning mobile's Attestation trace was
    /// destroyed *silently*. A non-zero value means a responder reply stalled
    /// long enough to park the inbound drain (pairs with #370: the round would
    /// also show `timed_out`). Single `Arc<AtomicU64>`; the offending peer + kind
    /// ride the matching throttled WARN.
    pub replication_inbound_backpressure_drops: Arc<std::sync::atomic::AtomicU64>,
    /// CIRISEdge#433 — the WITHHOLD LEDGER: per-[`WithholdReason`] count of rows
    /// a serving-path gate declined to serve. Shaped exactly like
    /// [`Self::send_failures_total`] (same `Arc<RwLock<HashMap<_, _>>>` lock
    /// discipline, same clone-on-snapshot). Before it, a node withholding every
    /// `trace:*` row from every peer was indistinguishable from a node with
    /// nothing to send — both reported zero. Now they differ: an idle node's
    /// ledger is empty, a withholding node's is not.
    pub withholds_by_reason: Arc<RwLock<HashMap<WithholdReason, u64>>>,
    /// CIRISEdge#433 — bounded ring ([`RECENT_WITHHOLDS_CAP`] entries, oldest
    /// evicted) of recent [`WithholdRecord`]s. The counter says HOW MANY and WHY;
    /// this says TO WHOM and ABOUT WHAT, at bounded cardinality and with no need
    /// to turn on debug logging in the field.
    pub recent_withholds: Arc<RwLock<VecDeque<WithholdRecord>>>,
    /// persist v24.2.0 / CIRISPersist#565 — the RECEIVE-plane mirror of the
    /// withhold ledger, kind axis: per-[`EnvelopeKind`] count of envelopes this
    /// node REFUSED to apply (the #425 choke's `ApplyOutcome::Refused`, every
    /// plane, typed-or-stringy alike). Same inversion, other direction: not
    /// "did anything fail?" but "did anything move, and if not, what stopped
    /// it?" — asked of what we were OFFERED rather than what we serve.
    pub apply_refusals_by_kind: Arc<RwLock<HashMap<EnvelopeKind, u64>>>,
    /// CIRISEdge#457 — the receive plane's ACCEPTED-apply counters, the last
    /// uncounted limb of the #433 arc: `apply_refusals_by_kind` booked
    /// refusals but nothing booked an accepted apply, so "applied all N" and
    /// "offered nothing" both read `{}`. Two distinct counters, never
    /// collapsed (the #433 distinct-states rule): `applied` = a NEW row that
    /// changed local state (`ApplyOutcome::Admitted`), `duplicate` = a row
    /// already held (`ApplyOutcome::Duplicate`, routine, no state change).
    /// Together with `apply_refusals_by_kind` the receive plane now answers
    /// "did anything arrive, and what happened to it" from a scrape.
    pub replication_applied_total: Arc<RwLock<HashMap<EnvelopeKind, u64>>>,
    /// CIRISEdge#457 — per-kind count of already-held rows an apply saw
    /// (`ApplyOutcome::Duplicate`). Distinct from `replication_applied_total`
    /// so "applied new" and "already had it" never collapse.
    pub replication_duplicate_total: Arc<RwLock<HashMap<EnvelopeKind, u64>>>,
    /// persist v24.2.0 / CIRISPersist#565 — the receive-plane mirror, reason
    /// axis for the one plane persist types today: Key-plane policy refusals
    /// counted by persist's STABLE token (`pubkey_swap`, `downgrade`, …; a
    /// closed, append-only 9-token contract — bounded cardinality by
    /// construction). Duplicate halves (`Unchanged`,
    /// `already_anchored_identical`) never count here: the receiver already
    /// holds what was offered. Extends per-plane as persist types more
    /// refusals.
    pub key_apply_refusals_by_reason: Arc<RwLock<HashMap<String, u64>>>,
    /// CIRISEdge#441 — the removal-receipt ledger (revocation-class rows'
    /// per-peer delivery states; the pull-plane's missing arrival
    /// instrument). Fed by the bridge's serve exit (offers) + the
    /// coordinator's Summary observer (protocol-native acks).
    pub removal_receipts: Arc<RwLock<RemovalReceiptLedger>>,
    /// CIRISEdge#433 — per-[`EnvelopeKind`] count of envelopes the REPLICATION
    /// plane served to a peer. The mirror-image defect of the withhold blindness:
    /// [`Self::envelopes_sent_total`] is bumped only from `src/edge.rs`
    /// application/durable paths, so a node that moved 56 trace rows through
    /// anti-entropy rounds reported `envelopes_sent_total: 0` — reporting broken
    /// while working, exactly as the withhold ledger fixes working-while-reporting-
    /// idle. Keyed on the SAME [`EnvelopeKind`] the replication wire uses (one
    /// kind list, not two).
    pub replication_envelopes_served_total: Arc<RwLock<HashMap<EnvelopeKind, u64>>>,
}

impl EdgeMetrics {
    /// Construct an empty metric bag.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the `envelopes_sent_total` counter for `mt`.
    pub fn inc_sent(&self, mt: &MessageType) {
        let mut guard = self.envelopes_sent_total.write();
        *guard.entry(mt.clone()).or_insert(0) += 1;
    }

    /// Increment the `envelopes_received_total` counter for `mt`.
    pub fn inc_received(&self, mt: &MessageType) {
        let mut guard = self.envelopes_received_total.write();
        *guard.entry(mt.clone()).or_insert(0) += 1;
    }

    /// Increment the `send_failures_total` counter for the
    /// (transport, error-class) pair.
    pub fn inc_send_failure(&self, transport: TransportId, error_class: &str) {
        let mut guard = self.send_failures_total.write();
        *guard
            .entry((transport, error_class.to_string()))
            .or_insert(0) += 1;
    }

    /// Increment the `verify_failures_total` counter for `class`.
    pub fn inc_verify_failure(&self, class: VerifyErrorClass) {
        let mut guard = self.verify_failures_total.write();
        *guard.entry(class).or_insert(0) += 1;
    }

    /// Add `bytes` to the inbound byte counter for `transport`.
    pub fn add_bytes_in(&self, transport: TransportId, bytes: u64) {
        let mut guard = self.transport_bytes_in_total.write();
        *guard.entry(transport).or_insert(0) += bytes;
    }

    /// Add `bytes` to the outbound byte counter for `transport`.
    pub fn add_bytes_out(&self, transport: TransportId, bytes: u64) {
        let mut guard = self.transport_bytes_out_total.write();
        *guard.entry(transport).or_insert(0) += bytes;
    }

    /// Record an enqueue against the durable-queue gauge.
    pub fn inc_durable_queue(&self, class: DeliveryClass) {
        let mut guard = self.durable_queue_depth.write();
        *guard.entry(class).or_insert(0) += 1;
    }

    /// CIRISEdge#370 — increment the anti-entropy round-outcome counter
    /// for `outcome`. Called once per terminated round by the runtime's
    /// scheduler event-sink consumer (see
    /// [`crate::replication::runtime::ReplicationRuntime::start`]).
    pub fn inc_round_outcome(&self, outcome: RoundOutcome) {
        let mut guard = self.replication_round_outcomes_total.write();
        *guard.entry(outcome).or_insert(0) += 1;
    }

    /// CIRISEdge#373 — increment the inbound-backpressure-drop counter. Called
    /// once per dropped frame at the `route_replication_frame` back-pressure
    /// path, so the previously-silent 100% trace loss is countable.
    pub fn inc_inbound_backpressure_drop(&self) {
        self.replication_inbound_backpressure_drops
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// CIRISEdge#373 — read the inbound-backpressure-drop counter (tests +
    /// snapshot projection).
    #[must_use]
    pub fn inbound_backpressure_drops(&self) -> u64 {
        self.replication_inbound_backpressure_drops
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// CIRISEdge#48-B (v0.19.6) — increment the
    /// `inbound_dropped_low_trust` counter. Called from
    /// `dispatch_inbound` once per drop.
    pub fn inc_inbound_dropped_low_trust(&self) {
        self.inbound_dropped_low_trust
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// CIRISEdge#48-B (v0.19.6) — read the
    /// `inbound_dropped_low_trust` counter. Used by tests + the
    /// metrics snapshot projection.
    #[must_use]
    pub fn inbound_dropped_low_trust(&self) -> u64 {
        self.inbound_dropped_low_trust
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// CIRISEdge#433 — record ONE withhold: bump the per-reason counter and push
    /// the attribution onto the bounded ring.
    ///
    /// `peer` is the recipient the row was withheld from (`<unattributed>` for a
    /// peer-blind advertise-sweep withhold); `detail` is a SHORT descriptor — the
    /// envelope kind plus a hash prefix, or the gate leg. Never a full envelope:
    /// the ring is an attribution window, not a log sink, and its entries must
    /// stay bounded in size as well as in count.
    ///
    /// The two locks are taken sequentially, never nested — the counter guard is
    /// a statement temporary, matching [`Self::inc_send_failure`]'s discipline.
    pub fn inc_withhold(&self, reason: WithholdReason, peer: &str, detail: &str) {
        *self.withholds_by_reason.write().entry(reason).or_insert(0) += 1;
        let mut ring = self.recent_withholds.write();
        while ring.len() >= RECENT_WITHHOLDS_CAP {
            ring.pop_front();
        }
        ring.push_back(WithholdRecord {
            reason,
            peer_key_id: peer.to_string(),
            detail: detail.to_string(),
        });
    }

    /// CIRISEdge#433 — read the withhold count for `reason` (tests + consumers
    /// that want one reason without cloning the whole map).
    #[must_use]
    pub fn withholds(&self, reason: WithholdReason) -> u64 {
        self.withholds_by_reason
            .read()
            .get(&reason)
            .copied()
            .unwrap_or(0)
    }

    /// CIRISEdge#433 — increment the replication-plane served counter for `kind`.
    ///
    /// Called at the bridge's serve exit — the moment the bridge hands the wire
    /// bytes back to the pack path. Mirrors the CIRISEdge#28 precedent at
    /// `edge.rs` "durable enqueue is the metric-visible moment": the counter marks
    /// the point where THIS layer's part of the transaction is definitely
    /// complete, not the point where the peer acknowledged it.
    pub fn inc_replication_served(&self, kind: EnvelopeKind) {
        let mut guard = self.replication_envelopes_served_total.write();
        *guard.entry(kind).or_insert(0) += 1;
    }

    /// CIRISEdge#441 — record a removal-class row exists (advertise assembly).
    pub fn removal_track(&self, kind: EnvelopeKind, hash: [u8; 32]) {
        self.removal_receipts.write().track(kind, hash);
    }

    /// CIRISEdge#441 — record a removal-class row served to `peer`.
    pub fn removal_offer(&self, kind: EnvelopeKind, hash: [u8; 32], peer: &str, now_ms: u64) {
        self.removal_receipts
            .write()
            .offer(kind, hash, peer, now_ms);
    }

    /// CIRISEdge#441 — fold a peer's Summary into the receipt ledger (the
    /// protocol-native ack: a Summary is the peer's own statement of holdings).
    pub fn removal_ack_from_summary(
        &self,
        peer: &str,
        kind: EnvelopeKind,
        hashes: &[[u8; 32]],
        now_ms: u64,
    ) {
        self.removal_receipts
            .write()
            .ack_from_summary(peer, kind, hashes, now_ms);
    }

    /// persist v24.2.0 / #565 — count one refused apply on `kind` (the
    /// receive-plane mirror's kind axis, bumped at the #425 choke).
    pub fn inc_apply_refusal_kind(&self, kind: EnvelopeKind) {
        let mut guard = self.apply_refusals_by_kind.write();
        *guard.entry(kind).or_insert(0) += 1;
    }

    /// CIRISEdge#457 — count one ACCEPTED apply that changed local state
    /// (`ApplyOutcome::Admitted`) on `kind`, at the same #425 choke as the
    /// refusal counter.
    pub fn inc_applied(&self, kind: EnvelopeKind) {
        let mut guard = self.replication_applied_total.write();
        *guard.entry(kind).or_insert(0) += 1;
    }

    /// CIRISEdge#457 — count one already-held apply (`ApplyOutcome::Duplicate`)
    /// on `kind` — distinct from `inc_applied` so the two never collapse.
    pub fn inc_duplicate(&self, kind: EnvelopeKind) {
        let mut guard = self.replication_duplicate_total.write();
        *guard.entry(kind).or_insert(0) += 1;
    }

    /// persist v24.2.0 / #565 — count one TYPED Key-plane policy refusal by
    /// persist's stable token. `token` comes from `KeyRefusalReason::as_str()`
    /// — a closed, append-only set, so this map's cardinality is bounded by
    /// the persist contract, never by traffic.
    pub fn inc_key_apply_refusal(&self, token: &str) {
        let mut guard = self.key_apply_refusals_by_reason.write();
        *guard.entry(token.to_string()).or_insert(0) += 1;
    }

    /// Update the per-peer reachability ratio gauge. Replaces (does
    /// not accumulate) — the underlying tracker computes the rolling
    /// ratio and the gauge mirrors it.
    pub fn set_peer_reachability(&self, peer_key_id: &str, medium: &str, ratio: f64) {
        let mut guard = self.peer_reachability_ratio.write();
        guard.insert((peer_key_id.to_string(), medium.to_string()), ratio);
    }

    /// Snapshot all counters + gauges as plain `HashMap`s — the
    /// projection consumers (PyO3 / UniFFI / Prometheus exposition)
    /// render into their respective wire shapes. Each `HashMap` is a
    /// fresh clone of the live state; the live map is unlocked
    /// immediately after the clone so emitters aren't blocked across
    /// the projection step.
    #[must_use]
    pub fn snapshot(&self) -> EdgeMetricsBundle {
        EdgeMetricsBundle {
            envelopes_sent_total: self.envelopes_sent_total.read().clone(),
            envelopes_received_total: self.envelopes_received_total.read().clone(),
            send_failures_total: self.send_failures_total.read().clone(),
            verify_failures_total: self.verify_failures_total.read().clone(),
            durable_queue_depth: self.durable_queue_depth.read().clone(),
            transport_bytes_in_total: self.transport_bytes_in_total.read().clone(),
            transport_bytes_out_total: self.transport_bytes_out_total.read().clone(),
            peer_reachability_ratio: self.peer_reachability_ratio.read().clone(),
            inbound_dropped_low_trust: self.inbound_dropped_low_trust(),
            replication_round_outcomes_total: self.replication_round_outcomes_total.read().clone(),
            replication_inbound_backpressure_drops: self.inbound_backpressure_drops(),
            withholds_by_reason: self.withholds_by_reason.read().clone(),
            recent_withholds: self.recent_withholds.read().iter().cloned().collect(),
            replication_envelopes_served_total: self
                .replication_envelopes_served_total
                .read()
                .clone(),
            apply_refusals_by_kind: self.apply_refusals_by_kind.read().clone(),
            key_apply_refusals_by_reason: self.key_apply_refusals_by_reason.read().clone(),
            replication_applied_total: self.replication_applied_total.read().clone(),
            replication_duplicate_total: self.replication_duplicate_total.read().clone(),
            removal_delivery: self.removal_receipts.read().delta(),
        }
    }
}

/// Point-in-time projection of [`EdgeMetrics`]. Returned by
/// [`EdgeMetrics::snapshot`]; consumed by the PyO3 / UniFFI projection
/// methods. Owned `HashMap`s — emitters can keep writing through the
/// underlying `Arc<RwLock<_>>` while a consumer renders the bundle.
#[derive(Debug, Clone, Default)]
pub struct EdgeMetricsBundle {
    pub envelopes_sent_total: HashMap<MessageType, u64>,
    pub envelopes_received_total: HashMap<MessageType, u64>,
    pub send_failures_total: HashMap<(TransportId, String), u64>,
    pub verify_failures_total: HashMap<VerifyErrorClass, u64>,
    pub durable_queue_depth: HashMap<DeliveryClass, u64>,
    pub transport_bytes_in_total: HashMap<TransportId, u64>,
    pub transport_bytes_out_total: HashMap<TransportId, u64>,
    pub peer_reachability_ratio: HashMap<(String, String), f64>,
    /// CIRISEdge#48-B (v0.19.6) — cumulative count of envelopes
    /// dropped at `dispatch_inbound` due to trust short-circuit.
    pub inbound_dropped_low_trust: u64,
    /// CIRISEdge#370 — cumulative per-outcome anti-entropy round count
    /// (keyed by [`RoundOutcome`]). Empty until the runtime is started
    /// with a live metrics handle configured.
    pub replication_round_outcomes_total: HashMap<RoundOutcome, u64>,
    /// CIRISEdge#373 — cumulative inbound frames dropped on coordinator
    /// channel back-pressure (previously a silent WARN).
    pub replication_inbound_backpressure_drops: u64,
    /// CIRISEdge#433 — cumulative per-reason withhold count. Empty on an IDLE
    /// node; non-empty on a WITHHOLDING one. That difference is the whole point.
    pub withholds_by_reason: HashMap<WithholdReason, u64>,
    /// CIRISEdge#433 — the recent-withholds attribution window, oldest first,
    /// at most [`RECENT_WITHHOLDS_CAP`] entries.
    pub recent_withholds: Vec<WithholdRecord>,
    /// CIRISEdge#433 — cumulative per-kind count of envelopes the replication
    /// plane actually served (the counter `envelopes_sent_total` never saw).
    pub replication_envelopes_served_total: HashMap<EnvelopeKind, u64>,
    /// persist v24.2.0 / #565 — refused applies per envelope kind (the
    /// receive-plane mirror, kind axis).
    pub apply_refusals_by_kind: HashMap<EnvelopeKind, u64>,
    /// persist v24.2.0 / #565 — typed Key-plane policy refusals by persist's
    /// stable token (closed, append-only 9-token contract).
    pub key_apply_refusals_by_reason: HashMap<String, u64>,
    /// CIRISEdge#457 — per-kind accepted applies that changed local state.
    pub replication_applied_total: HashMap<EnvelopeKind, u64>,
    /// CIRISEdge#457 — per-kind already-held applies (distinct from applied).
    pub replication_duplicate_total: HashMap<EnvelopeKind, u64>,
    /// CIRISEdge#441 — the removal-delivery delta: per tracked removal row,
    /// offered/acked counts + peers still lacking a receipt.
    pub removal_delivery: Vec<RemovalRowDelta>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::MessageType;
    use crate::transport::TransportId;

    #[test]
    fn inc_sent_accumulates_per_message_type() {
        let m = EdgeMetrics::new();
        m.inc_sent(&MessageType::OpaqueEvent);
        m.inc_sent(&MessageType::OpaqueEvent);
        m.inc_sent(&MessageType::FederationAnnouncement);
        let snap = m.snapshot();
        assert_eq!(snap.envelopes_sent_total[&MessageType::OpaqueEvent], 2);
        assert_eq!(
            snap.envelopes_sent_total[&MessageType::FederationAnnouncement],
            1
        );
    }

    #[test]
    fn send_failure_keyed_by_transport_and_error_class() {
        let m = EdgeMetrics::new();
        m.inc_send_failure(TransportId::RETICULUM_RS, "unreachable");
        m.inc_send_failure(TransportId::RETICULUM_RS, "unreachable");
        m.inc_send_failure(TransportId::HTTP, "timeout");
        let snap = m.snapshot();
        assert_eq!(
            snap.send_failures_total[&(TransportId::RETICULUM_RS, "unreachable".to_string())],
            2
        );
        assert_eq!(
            snap.send_failures_total[&(TransportId::HTTP, "timeout".to_string())],
            1
        );
    }

    #[test]
    fn verify_failure_class_from_verify_error_taxonomy() {
        use crate::verify::VerifyError;
        let cases = [
            (VerifyError::Misrouted, VerifyErrorClass::Misrouted),
            (
                VerifyError::ReplayDetected,
                VerifyErrorClass::ReplayDetected,
            ),
            (
                VerifyError::UnknownKey("k".into()),
                VerifyErrorClass::UnknownKey,
            ),
            (
                VerifyError::SignatureMismatch("s".into()),
                VerifyErrorClass::SignatureMismatch,
            ),
        ];
        for (e, want) in cases {
            assert_eq!(VerifyErrorClass::from_verify_error(&e), want);
        }
    }

    #[test]
    fn round_outcomes_accumulate_per_outcome() {
        // CIRISEdge#370 — the field instrument: each terminal round outcome
        // increments its own counter, and the snapshot renders them keyed by
        // the stable snake-case label the PyO3 surface uses.
        let m = EdgeMetrics::new();
        m.inc_round_outcome(RoundOutcome::Completed);
        m.inc_round_outcome(RoundOutcome::Completed);
        m.inc_round_outcome(RoundOutcome::TimedOut);
        m.inc_round_outcome(RoundOutcome::TimedOut);
        m.inc_round_outcome(RoundOutcome::TimedOut);
        m.inc_round_outcome(RoundOutcome::Refused);
        let snap = m.snapshot();
        assert_eq!(
            snap.replication_round_outcomes_total[&RoundOutcome::Completed],
            2
        );
        assert_eq!(
            snap.replication_round_outcomes_total[&RoundOutcome::TimedOut],
            3
        );
        assert_eq!(
            snap.replication_round_outcomes_total[&RoundOutcome::Refused],
            1
        );
        // Never-emitted outcome stays absent (not zero-initialised) — the map
        // is a sparse bag, mirroring the other per-key counters.
        assert!(!snap
            .replication_round_outcomes_total
            .contains_key(&RoundOutcome::Error));
        assert_eq!(RoundOutcome::TimedOut.as_str(), "timed_out");
    }

    #[test]
    fn bytes_in_out_counted_per_transport() {
        let m = EdgeMetrics::new();
        m.add_bytes_in(TransportId::RETICULUM_RS, 1024);
        m.add_bytes_in(TransportId::RETICULUM_RS, 2048);
        m.add_bytes_out(TransportId::HTTP, 512);
        let snap = m.snapshot();
        assert_eq!(
            snap.transport_bytes_in_total[&TransportId::RETICULUM_RS],
            3072
        );
        assert_eq!(snap.transport_bytes_out_total[&TransportId::HTTP], 512);
    }

    /// CIRISEdge#457 — the accepted-apply counters book on their own axes
    /// (the choke's match arms: Admitted→applied, Duplicate→duplicate). Direct
    /// smoke; the bridge test drives the Admitted path through the real apply.
    #[test]
    fn applied_and_duplicate_counters_are_independent() {
        let m = EdgeMetrics::new();
        m.inc_applied(EnvelopeKind::Key);
        m.inc_applied(EnvelopeKind::Key);
        m.inc_duplicate(EnvelopeKind::Attestation);
        let snap = m.snapshot();
        assert_eq!(
            snap.replication_applied_total
                .get(&EnvelopeKind::Key)
                .copied(),
            Some(2)
        );
        assert_eq!(
            snap.replication_duplicate_total
                .get(&EnvelopeKind::Attestation)
                .copied(),
            Some(1)
        );
        assert!(!snap
            .replication_applied_total
            .contains_key(&EnvelopeKind::Attestation));
    }

    /// CIRISEdge#441 — the receipt ledger's three-state contract, driven with
    /// the shapes the seams produce: track at advertise, offer at serve,
    /// ack from the peer's own Summary. The states are never collapsed —
    /// that collapse is how "unverified" reads as "delivered".
    #[test]
    fn removal_receipts_distinguish_never_offered_offered_and_acked() {
        let mut l = RemovalReceiptLedger::default();
        let h = [7u8; 32];
        let k = EnvelopeKind::Revocation;
        l.track(k, h);
        // Tracked, nobody offered: delta row exists, empty peers.
        let d = l.delta();
        assert_eq!((d.len(), d[0].offered, d[0].acked), (1, 0, 0));
        // Offered to peer-a: visible as offered-unacked.
        l.offer(k, h, "peer-a", 1_000);
        let d = l.delta();
        assert_eq!((d[0].offered, d[0].acked), (1, 0));
        assert_eq!(d[0].unacked_peers, vec!["peer-a".to_string()]);
        // peer-a's next Summary advertises the hash: the protocol-native ack.
        l.ack_from_summary("peer-a", k, &[h], 2_000);
        let d = l.delta();
        assert_eq!((d[0].offered, d[0].acked), (0, 1));
        assert!(d[0].unacked_peers.is_empty());
        // A peer we never offered acks via Summary (got it elsewhere) — still
        // a receipt; and an ack is never downgraded by a later offer.
        l.ack_from_summary("peer-b", k, &[h], 3_000);
        l.offer(k, h, "peer-b", 4_000);
        let d = l.delta();
        assert_eq!(d[0].acked, 2, "an ack survives a later offer");
        // Un-tracked hashes in a Summary are ignored (no unbounded growth).
        l.ack_from_summary("peer-a", k, &[[9u8; 32]], 5_000);
        assert_eq!(l.delta().len(), 1);
    }

    /// CIRISEdge#441 — the ledger cap: oldest rows evict; the ledger can
    /// never grow past [`REMOVAL_LEDGER_CAP`].
    #[test]
    fn removal_receipts_cap_evicts_oldest() {
        let mut l = RemovalReceiptLedger::default();
        for i in 0..(REMOVAL_LEDGER_CAP + 5) {
            let mut h = [0u8; 32];
            h[..8].copy_from_slice(&(i as u64).to_be_bytes());
            l.track(EnvelopeKind::Revocation, h);
        }
        assert_eq!(l.delta().len(), REMOVAL_LEDGER_CAP);
        let mut h0 = [0u8; 32];
        h0[..8].copy_from_slice(&0u64.to_be_bytes());
        assert!(
            !l.delta().iter().any(|r| r.envelope_hash == h0),
            "the oldest row evicted"
        );
    }

    /// CIRISEdge#433 — the ring-buffer BOUND is the unit under test here, so this
    /// is the one test in the cut that calls `inc_withhold` directly (every
    /// per-reason test drives the real gate through the bridge instead). A ledger
    /// that grew without limit would be a memory leak on exactly the node that is
    /// withholding hardest — the failure mode this cap exists to prevent.
    #[test]
    fn recent_withholds_ring_is_capped_and_evicts_oldest() {
        let m = EdgeMetrics::new();
        for i in 0..(RECENT_WITHHOLDS_CAP + 10) {
            m.inc_withhold(
                WithholdReason::ServeCapabilityMissing,
                &format!("peer-{i}"),
                "legA-no-role",
            );
        }
        let snap = m.snapshot();
        // The COUNTER is exact — the cap bounds attribution, never the count.
        assert_eq!(
            snap.withholds_by_reason[&WithholdReason::ServeCapabilityMissing],
            (RECENT_WITHHOLDS_CAP + 10) as u64,
            "the cap bounds the ring, not the counter — a metric that under-counts lies"
        );
        assert_eq!(snap.recent_withholds.len(), RECENT_WITHHOLDS_CAP);
        // Oldest evicted, newest retained, order preserved (oldest first).
        assert_eq!(snap.recent_withholds[0].peer_key_id, "peer-10");
        assert_eq!(
            snap.recent_withholds[RECENT_WITHHOLDS_CAP - 1].peer_key_id,
            format!("peer-{}", RECENT_WITHHOLDS_CAP + 9)
        );
        assert_eq!(snap.recent_withholds[0].detail, "legA-no-role");
    }

    /// CIRISEdge#433 — the snake_case labels are the PyO3 dict keys downstream
    /// consumers alert on; pin the ones the issue named so a rename is a
    /// deliberate edit, not an accident.
    #[test]
    fn withhold_reason_labels_are_stable() {
        assert_eq!(
            WithholdReason::ServeCapabilityMissing.as_str(),
            "serve_capability_missing"
        );
        assert_eq!(
            WithholdReason::RecipientNotInSendSet.as_str(),
            "recipient_not_in_send_set"
        );
        assert_eq!(
            WithholdReason::SendSetUnresolved.as_str(),
            "send_set_unresolved"
        );
        assert_eq!(
            WithholdReason::RecipientCapabilityRestriction.as_str(),
            "recipient_capability_restriction"
        );
        // Display agrees with as_str, so `{reason}` in a log joins to the metric.
        assert_eq!(
            WithholdReason::EnvelopeUnfetchable.to_string(),
            "envelope_unfetchable"
        );
    }

    #[test]
    fn peer_reachability_gauge_replaces_not_accumulates() {
        let m = EdgeMetrics::new();
        m.set_peer_reachability("peer-1", "reticulum-rs", 0.5);
        m.set_peer_reachability("peer-1", "reticulum-rs", 0.9);
        let snap = m.snapshot();
        let v = snap.peer_reachability_ratio[&("peer-1".to_string(), "reticulum-rs".to_string())];
        assert!((v - 0.9).abs() < f64::EPSILON);
    }
}
