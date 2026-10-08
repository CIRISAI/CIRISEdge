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
///
/// `#[non_exhaustive]` (v37.0.0): new named refusals are added as the serve
/// gates grow (#713, #718, #717 each added one, and each forced a MAJOR bump
/// on every downstream exhaustive match). A consumer matches the reasons it
/// treats specially and routes the rest through a `_` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
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
    /// The consent send-set (`consent_peers_by_principals(local)`, persist's E7
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
    /// CIRISEdge#659 — the recipient is ATTRIBUTED but not ROOTED: this node and
    /// the peer hold no valid trust root in common through their owner-bindings
    /// (`FSD/CIRIS_EDGE_TRANSPORT.md` §5.3). Nothing is served below Rooted; the
    /// peer may still deliver. Not a read error: an unreadable directory is
    /// [`Self::TrustRootWalkError`].
    RecipientNotRooted,
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
    /// CIRISPersist#731 — the wire value is not an
    /// [`Attestation`](ciris_persist::federation::Attestation) at all: it does
    /// not deserialize into persist's row type, so there is no row to hand the
    /// relay verb and nothing to ask. Withheld — LOUD and named, never a silent
    /// `continue` (CIRISEdge#425/#433). A producer/serialization fault, not a
    /// trust statement.
    AccordRelayObjectUnreadable,
    /// CIRISPersist#733 — the row deserialized, but its signed
    /// [`RowMirror`](ciris_persist::federation::envelope::RowMirror) is ABSENT
    /// (a pre-#643 unstamped row) or DIVERGES from the typed columns, so the
    /// columns assert nothing: persist's
    /// [`check_row_column_binding`](ciris_persist::federation::admission::check_row_column_binding)
    /// refuses it and its own relay verb treats that as *"I cannot judge"*.
    ///
    /// Never folded into [`Self::AccordRelayObjectUnreadable`]: a DIVERGENCE is a
    /// security event (a relay rewriting a signed row's identity, verb, signer or
    /// subject while the signature still verifies — CIRISPersist#643's whole
    /// class), while a missing mirror is a producer-vintage problem. Different
    /// findings, different remedies.
    AccordRelayMirrorUnbound,
    /// CIRISPersist#733 — persist's own classifier says the row is not on the
    /// `accord:*` family at all
    /// ([`AccordRootClaim::NotAccord`](ciris_persist::federation::trust_root::AccordRootClaim)),
    /// so it "is not this predicate's to judge" and the verb refuses it.
    /// Structurally unreachable through the serve path (the `accord:*` early-out
    /// runs persist's own `attestation_family` first) and booked anyway, so a
    /// classifier disagreement surfaces as a NAMED withhold rather than as an
    /// allow.
    AccordRelayObjectNotAccord,
    /// CIRISPersist#733 — the row is on the `accord:*` family and **nothing in
    /// it names the accord this object acts under**: no signed `accord_root`
    /// key, and not the one dimension whose fallback rule persist defines. A
    /// pre-#733 row or an unadopted producer's. "Which root?" has no
    /// object-derived answer, and answering it from construction state instead
    /// is precisely the permissive failure #731 reports — so it refuses. The
    /// durable narrowing #733 accepted, not a local misconfiguration.
    AccordRelayObjectRootUnnamed,
    /// CIRISPersist#733 — **ONE ARTIFACT ASSERTING TWO ACCORDS**: the row's
    /// signed `accord_root` key and the drill-dimension rule name DIFFERENT
    /// roots. Neither is preferred (preferring the key lets an emitter relabel a
    /// heartbeat's accord; preferring the column makes the new field
    /// decorative), so the row is refused rather than resolved.
    ///
    /// Reachable at RELAY even though persist's write door refuses the same
    /// shape: that door protects rows this node ADMITS, and relaying is exactly
    /// when a node handles rows it never admitted. Its own variant, never folded
    /// into [`Self::AccordRelayObjectRootUnnamed`] — "names none" sends an
    /// operator to add a key, "names two" sends them to remove one.
    AccordRelayObjectRootDisagrees,
    /// CIRISEdge#499 (blob plane) — an inbound `BlobChunkFetch` was refused
    /// because the responder could not determine the blob's SCOPE, so it could
    /// not evaluate whether this requester is entitled to it. Fail-closed, and
    /// its own branch: "I do not know what this content is" is a wiring fact
    /// (`BlobChunkSource::chunk_scope` unwired or returning `None`) with an
    /// operator remedy, not a statement about the requester.
    BlobScopeUndeterminable,
    /// CIRISEdge#717 (blob plane) — an inbound `BlobChunkFetch` named a DAG
    /// the requester IS entitled to (`blob_sha256`, the scope gate's input)
    /// and a `chunk_sha256` that is not one of that DAG's chunks in this
    /// node's store. The scope gate authorizes by the NAMED file, so a chunk
    /// outside it is a request for content the gate never judged — a chunk of
    /// another room's file, named under a file of this one. Refused at the
    /// serve door ([`crate::blob_swarm::ChunkSourceRefusal::ChunkNotInNamedDag`]).
    ChunkNotInNamedDag,
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
    /// CIRISEdge#718 (CC 5.4.6, CIRISConstitution#132) — a `BlobChunkFetch` on
    /// the identity-plane link carried an in-link scope discriminator naming
    /// NO derived address this node holds (unknown bytes, another member's
    /// address, or any discriminator on a node without a table). Refused by
    /// name at `BlobScopeRouter::scoped_arrival`.
    BlobDiscriminatorUnheld,
    /// CIRISEdge#718 — a `BlobChunkFetch` arrived ON a derived address AND
    /// carried a discriminator: a mismatch (a body on the derived address needs
    /// none; one that carries it names a path it did not take).
    BlobDiscriminatorOnDerivedAddress,
    /// CIRISEdge#499 (swarm holdings plane) — the publisher could not determine
    /// a held content's SCOPE on a scope-native node, so it cannot know which
    /// peers are entitled to learn the holding exists. Fail-closed, and its own
    /// branch: "I do not know what this content is" is a wiring fact
    /// ([`FountainHoldingsSource::content_scope`](crate::swarm::FountainHoldingsSource::content_scope)
    /// unwired or returning `None`) with an operator remedy, not a statement
    /// about any peer.
    HoldingScopeUndeterminable,
    /// CIRISEdge#499 (swarm holdings plane) — the host declared a scope GROUP at
    /// `Public` cohort scope. A private roster paired with a public audience is a
    /// contradiction, not a configuration, and is refused before any roster
    /// lookup — never folded into [`Self::HoldingScopePeerNotInRoster`], which
    /// would send an operator to edit a membership list instead of the
    /// declaration.
    HoldingScopePublicGroup,
    /// CIRISEdge#499 (swarm holdings plane) — persist's
    /// `projection_for(Plane::FountainContent, …)` bound this holding's audience
    /// to the record's OWN roster (`Cohort` over a named group, or the
    /// structurally-invisible `SelfOwn`) and the peer holds no derived address in
    /// that group at any live epoch. **The leak this cut closes**: before it, a
    /// family- or community-scoped holding — content id AND symbol ids — was
    /// announced on a timer to every peer the cohort callback returned.
    HoldingScopePeerNotInRoster,
    /// CIRISEdge#499 (swarm holdings plane) — the projection named an audience
    /// KIND the publisher has no peer-set mechanism for on this plane
    /// (`Capability` / `Subject`, which `Plane::FountainContent` has no cell for
    /// today). Structurally unreachable against persist v37's table and booked
    /// fail-closed anyway, so a future persist widening surfaces as a NAMED
    /// withhold rather than as an allow.
    HoldingScopeProjectionUnsupported,
    /// CIRISPersist#744 (swarm holdings plane) — the gate is ARMED (a scope
    /// address table is installed) but no `FederationDirectory` is wired, so
    /// neither `holdings_authority` nor `resolve_projection_recipients` can be
    /// asked. A WIRING fault, not a policy decision. Refused rather than
    /// falling back to the pre-#744 hard-coded `ProducerSteward`, which would
    /// resurrect the under-advertisement defect invisibly.
    HoldingScopeDirectoryMissing,
    /// CIRISPersist#744 (swarm holdings plane) — persist's `holdings_authority`
    /// errored: the accord-co-scrub trust-root walk over the PUBLISHER's key
    /// could not be completed. Never folded into a `ProducerSteward` default —
    /// a read that failed is not a statement that the publisher is a plain
    /// producer (the #425 Exhibit C split, on the authority axis).
    HoldingScopeAuthorityUnresolved,
    /// CIRISPersist#744 (swarm holdings plane) — persist's
    /// `resolve_projection_recipients` returned `set_resolvable: false`:
    /// **"I cannot judge"** this record's recipient set. Its own variant,
    /// never folded into [`Self::HoldingScopePeerNotInRoster`] — persist keeps
    /// the two bools separate precisely so an admission of ignorance is not
    /// reported as an accusation about the peer, and the remedies differ (fix
    /// a roster table or a group registration vs. fix a membership list).
    HoldingScopeRecipientSetUnresolved,
    /// CIRISPersist#744 (swarm holdings plane) — persist's
    /// `resolve_projection_recipients` returned `Err`. Distinct from
    /// [`Self::HoldingScopeRecipientSetUnresolved`], which is a VERDICT persist
    /// reached deliberately; this is an infrastructure fault. Persist retains
    /// the `Result` for exactly this split.
    HoldingScopeRecipientReadError,

    // ── CIRISEdge#169 — the LXMF propagation HOST serve path ────────────
    //
    // These ten are the refusal taxonomy of
    // [`crate::transport::lxmf_serve`]: this node acting as an LXMF
    // propagation node, holding and serving THIRD-PARTY mail. They are
    // defined unconditionally rather than under the serve path's own
    // `cfg`, because the withhold taxonomy is a stable operator-facing
    // vocabulary: a snapshot's reason set must not change shape with the
    // build's feature flags, and cfg-gating variants would fork
    // `parameter_of`'s exhaustive match across feature combinations —
    // the proper-subset build hazard this repo keeps re-learning. A
    // default build simply never constructs them.
    /// #169 — a propagation request arrived and this node does NOT operate
    /// as a propagation node ([`crate::transport::lxmf_serve::PropagationAudience::Disabled`],
    /// the default). Serving strangers' mail is an explicit operator act,
    /// so the OFF state is a named refusal rather than an unhandled path:
    /// an operator who believes they enabled propagation and sees this
    /// reason is looking at the answer.
    LxmfPropagationDisabled,
    /// #169 — the destination is not one this node holds mail for. Fires
    /// on BOTH legs of the same roster (`detail` names which): an upload
    /// whose recipient is off-roster, and a `/get` from a requester who is
    /// off-roster. One condition, one remedy — put the destination on the
    /// roster — so one reason.
    LxmfDestinationNotServed,
    /// #169 — a `/get` arrived on a link whose remote identity edge could
    /// not resolve, so there is no destination to scope the mailbox to.
    /// Fail-closed: an unattributed request is never answered with mail,
    /// because "whose mailbox is this" has no answer.
    LxmfRequesterUnidentified,
    /// #169 — the requester asked for a transient ID that is parked for a
    /// DIFFERENT destination. This is the cross-recipient mailbox probe
    /// the per-destination index exists to defeat; it is reported rather
    /// than merely omitted, because it is the one `/get` miss that is
    /// evidence of an attack rather than of a race.
    LxmfMailboxScopeMismatch,
    /// #169 — an upload's proof-of-work propagation stamp did not meet the
    /// cost this node advertises in its
    /// [`PropagationNodeAnnounce`](leviculum_lxmf::PropagationNodeAnnounce).
    /// The advertised cost IS the node's published term of carriage; an
    /// upload that has not paid it has not met the rule it was offered.
    LxmfStampBelowCost,
    /// #169 — the bytes do not decode as the LXMF propagation wire this
    /// endpoint speaks (`detail` names the leg: `/get` request body or
    /// upload envelope). Distinct from [`Self::LxmfPeerSyncUnsupported`]:
    /// these bytes are malformed, those are well-formed and for another
    /// endpoint.
    LxmfWireUnparseable,
    /// #169 — a well-formed MULTI-message upload: the node-to-node
    /// `/offer` peer-sync form, which `leviculum-lxmf` deliberately does
    /// not implement (leviculum#209) and reports as
    /// `PropagationError::MultipleMessages`. Its own reason because the
    /// remedy is not "fix your client" but "you have pointed a peer sync
    /// at a node that serves clients only".
    LxmfPeerSyncUnsupported,
    /// #169 — a byte or count ceiling refused carriage before any work was
    /// done (`detail` names which: request body, upload envelope, the
    /// transient-ID list in one request, or the per-response transfer
    /// cap). A propagation node serves strangers by definition, so every
    /// buffer it fills on their behalf has an explicit ceiling, and
    /// hitting one is an event.
    LxmfFrameOversized,
    /// #169 — the mailbox is at a retention ceiling (total bytes, messages
    /// for this destination, or distinct destinations) and the upload was
    /// REFUSED rather than admitted by evicting. Refusing is the security
    /// property: a node that evicted to admit would let an attacker flush
    /// a victim's pending mail with junk uploads, turning a capacity bound
    /// into a censorship lever. Contrast
    /// [`crate::transport::store_and_forward`], which DOES evict
    /// oldest-first — it queues this node's OWN outbound envelopes, where
    /// there is no third party to censor.
    LxmfMailboxFull,
    /// #169 — a parked message reached the retention window without being
    /// collected and was evicted undelivered. The bounded-retention
    /// promise kept, and kept LOUDLY: a propagation node that dropped
    /// third-party mail silently would be indistinguishable from one that
    /// never received it.
    LxmfRetentionExpired,
    /// CIRISEdge#682 (CC 5.4.6, CIRISServer#655) — an `IdentityOccurrence` or
    /// `TransportDestination` row about an OWNED node that is **not announced**
    /// (no live owner-binding `owner → node` at `cohort_scope: federation`),
    /// asked for by a peer that is not one of that owner's own nodes. The
    /// darknet half of the per-node announce ruling: an unannounced device is
    /// reachable by its person's own nodes and by whoever they hand a code to,
    /// never listed. Booked on the advertise, the direct-fetch twin and the
    /// subject-Pull alike (`detail` names which). Not a fault — the peer is
    /// outside the audience the owner chose.
    IdentityRowNodeNotAnnounced,
    /// CIRISEdge#682 — the announce state of the node an identity-plane row is
    /// about could not be decided (`owner_of` ambiguous or a directory read
    /// failed). Fail-closed: the row is served only to the node itself, because
    /// "I could not read whether you announced" is not "you announced".
    /// Distinct from [`Self::IdentityRowNodeNotAnnounced`] so an operator is
    /// sent to the directory, not to the announce wizard.
    IdentityRowAnnounceUnresolved,
    /// CIRISEdge#758 (CC 5.4.6) — a `Family` / `Community` RECORD asked for (on
    /// the advertise or the direct-fetch twin) by a peer whose person
    /// (`owner_of(peer)`, the peer itself when unowned) is neither a live
    /// member of that group nor the invitee (`subject_key_ids`) of a live
    /// `membership:proposal:v1` into it held on this node. The construction
    /// hides a group's existence and membership from outsiders; a founder's
    /// node offering the record to every peer disclosed both. Not a fault —
    /// the peer is outside the group. `detail` names the plane and the site.
    GroupRecordNotMemberOrInvitee,
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
            Self::RecipientNotRooted => "recipient_not_rooted",
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
            Self::AccordRelayObjectUnreadable => "accord_relay_object_unreadable",
            Self::AccordRelayMirrorUnbound => "accord_relay_mirror_unbound",
            Self::AccordRelayObjectNotAccord => "accord_relay_object_not_accord",
            Self::AccordRelayObjectRootUnnamed => "accord_relay_object_root_unnamed",
            Self::AccordRelayObjectRootDisagrees => "accord_relay_object_root_disagrees",
            Self::BlobScopeUndeterminable => "blob_scope_undeterminable",
            Self::ChunkNotInNamedDag => "chunk_not_in_named_dag",
            Self::BlobArrivalScopeInsufficient => "blob_arrival_scope_insufficient",
            Self::BlobArrivalGroupMismatch => "blob_arrival_group_mismatch",
            Self::BlobDiscriminatorUnheld => "blob_discriminator_unheld",
            Self::BlobDiscriminatorOnDerivedAddress => "blob_discriminator_on_derived_address",
            Self::HoldingScopeUndeterminable => "holding_scope_undeterminable",
            Self::HoldingScopePublicGroup => "holding_scope_public_group",
            Self::HoldingScopePeerNotInRoster => "holding_scope_peer_not_in_roster",
            Self::HoldingScopeDirectoryMissing => "holding_scope_directory_missing",
            Self::HoldingScopeAuthorityUnresolved => "holding_scope_authority_unresolved",
            Self::HoldingScopeRecipientSetUnresolved => "holding_scope_recipient_set_unresolved",
            Self::HoldingScopeRecipientReadError => "holding_scope_recipient_read_error",
            Self::HoldingScopeProjectionUnsupported => "holding_scope_projection_unsupported",
            Self::LxmfPropagationDisabled => "lxmf_propagation_disabled",
            Self::LxmfDestinationNotServed => "lxmf_destination_not_served",
            Self::LxmfRequesterUnidentified => "lxmf_requester_unidentified",
            Self::LxmfMailboxScopeMismatch => "lxmf_mailbox_scope_mismatch",
            Self::LxmfStampBelowCost => "lxmf_stamp_below_cost",
            Self::LxmfWireUnparseable => "lxmf_wire_unparseable",
            Self::LxmfPeerSyncUnsupported => "lxmf_peer_sync_unsupported",
            Self::LxmfFrameOversized => "lxmf_frame_oversized",
            Self::LxmfMailboxFull => "lxmf_mailbox_full",
            Self::LxmfRetentionExpired => "lxmf_retention_expired",
            Self::IdentityRowNodeNotAnnounced => "identity_row_node_not_announced",
            Self::IdentityRowAnnounceUnresolved => "identity_row_announce_unresolved",
            Self::GroupRecordNotMemberOrInvitee => "group_record_not_member_or_invitee",
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

/// CIRISEdge#763 — the `blob_serve_refusals` tag for a chunk serve refused
/// `Withdrawn`: every reference to the file was withdrawn (CC 2.3), by edge's
/// revocation register or persist's tombstone fold.
pub const BLOB_SERVE_REFUSED_WITHDRAWN: &str = "withdrawn";

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
/// CIRISEdge P0 telemetry (CIRISServer `FSD/UNIFIED_TELEMETRY.md` §4) — the
/// upper bounds, in seconds, of
/// [`EdgeMetrics::replication_round_duration_seconds`]'s buckets. A final
/// `+Inf` bucket is implicit. OTel/Prometheus metric name:
/// [`REPLICATION_ROUND_DURATION_METRIC`].
pub const REPLICATION_ROUND_DURATION_BUCKETS_SECONDS: &[f64] =
    &[0.1, 0.5, 1.0, 5.0, 15.0, 60.0, 300.0];

/// The exported name of the round-duration histogram (`_bucket` / `_count` /
/// `_sum` series, label `kind`).
pub const REPLICATION_ROUND_DURATION_METRIC: &str = "edge_replication_round_duration_seconds";

/// CIRISEdge P0 telemetry — the upper bounds, in seconds, of
/// [`EdgeMetrics::sweep_permit_wait_seconds`]'s buckets. A final `+Inf`
/// bucket is implicit. Metric name: [`SWEEP_PERMIT_WAIT_METRIC`].
pub const SWEEP_PERMIT_WAIT_BUCKETS_SECONDS: &[f64] = &[0.01, 0.1, 1.0, 5.0, 30.0];

/// The exported name of the advertise-sweep permit-wait histogram.
pub const SWEEP_PERMIT_WAIT_METRIC: &str = "edge_sweep_permit_wait_seconds";

/// A fixed-bucket duration histogram: one counter per bucket plus a `+Inf`
/// bucket, a count and an exact nanosecond sum. No histogram crate — the
/// buckets are fixed at the call site's `const`, so recording is an index
/// search over a handful of bounds and two additions.
///
/// The bounds are passed in rather than stored so `Default` (which
/// [`EdgeMetrics`] derives) is the empty histogram; the counts grow to
/// `bounds.len() + 1` on the first observation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FixedHistogram {
    /// NON-cumulative per-bucket counts; the last entry is `+Inf`.
    counts: Vec<u64>,
    /// Exact sum of every observation, in nanoseconds (saturating).
    sum_ns: u64,
}

impl FixedHistogram {
    /// Record one observation of `d` against `bounds` (ascending seconds).
    /// A value lands in the FIRST bucket whose bound is `>=` it (Prometheus
    /// `le` semantics); one above every bound lands in `+Inf`.
    pub fn observe(&mut self, bounds: &[f64], d: std::time::Duration) {
        if self.counts.len() != bounds.len() + 1 {
            self.counts.resize(bounds.len() + 1, 0);
        }
        let secs = d.as_secs_f64();
        let idx = bounds
            .iter()
            .position(|b| secs <= *b)
            .unwrap_or(bounds.len());
        self.counts[idx] = self.counts[idx].saturating_add(1);
        let ns = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
        self.sum_ns = self.sum_ns.saturating_add(ns);
    }

    /// The point-in-time projection, with CUMULATIVE bucket counts as a
    /// Prometheus/OTel exporter emits them.
    #[must_use]
    pub fn snapshot(&self, bounds: &'static [f64]) -> HistogramSnapshot {
        let mut cumulative = Vec::with_capacity(bounds.len() + 1);
        let mut running = 0u64;
        for i in 0..=bounds.len() {
            running = running.saturating_add(self.counts.get(i).copied().unwrap_or(0));
            cumulative.push(running);
        }
        #[allow(clippy::cast_precision_loss)]
        let sum_seconds = self.sum_ns as f64 / 1e9;
        HistogramSnapshot {
            bounds,
            cumulative,
            count: running,
            sum_seconds,
        }
    }
}

/// Snapshot of one [`FixedHistogram`].
#[derive(Debug, Clone, PartialEq)]
pub struct HistogramSnapshot {
    /// The finite upper bounds, seconds, ascending.
    pub bounds: &'static [f64],
    /// CUMULATIVE count per bucket: `cumulative[i]` = observations `<=
    /// bounds[i]`; the final entry (index `bounds.len()`) is `+Inf` and
    /// equals [`Self::count`].
    pub cumulative: Vec<u64>,
    /// Number of observations (`_count`).
    pub count: u64,
    /// Sum of every observation in seconds (`_sum`).
    pub sum_seconds: f64,
}

impl HistogramSnapshot {
    /// `(le label, cumulative count)` for every bucket including `+Inf`,
    /// as the bindings and an exporter render them (`"0.1"`, …, `"+Inf"`).
    #[must_use]
    pub fn buckets(&self) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = self
            .bounds
            .iter()
            .zip(&self.cumulative)
            .map(|(b, n)| (format!("{b}"), *n))
            .collect();
        out.push(("+Inf".to_string(), self.count));
        out
    }
}

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
    /// destroyed *silently*. CIRISEdge#634: the WARN names the ROLE whose inbox
    /// was full — a responder's means its driver stalled on a reply send long
    /// enough to park the drain (pairs with #370: the round would also show
    /// `timed_out`); an initiator's means replies outran the round being
    /// driven. Pre-#634 every drop read as the former while most were a
    /// peer's round-open queuing into an initiator nobody was draining.
    /// Single `Arc<AtomicU64>`; the offending peer + kind + role ride the
    /// matching throttled WARN.
    pub replication_inbound_backpressure_drops: Arc<std::sync::atomic::AtomicU64>,
    /// CIRISEdge#662 — the same drops, by the ROLE whose inbox was full
    /// (`"responder"` / `"initiator"`). The total could not say which; the
    /// canonical's 76-a-day were all responder-side, and that is the question
    /// the issue asked.
    pub replication_inbound_backpressure_drops_by_role: Arc<RwLock<HashMap<String, u64>>>,
    /// CIRISEdge#634 — cumulative inbound CRPL frames routed to a RESPONDER
    /// (the peer's round: an initiator-marked v3 frame or a legacy v1/v2 one).
    /// Pairs with `replication_routed_to_initiator_total`: on a healthy mutual
    /// pair BOTH climb; a node that only ever sees one side has the other
    /// direction dark.
    pub replication_routed_to_responder_total: Arc<std::sync::atomic::AtomicU64>,
    /// CIRISEdge#634 — cumulative inbound CRPL replies routed into one of our
    /// INITIATORS' round inboxes (a responder-marked v3 frame naming a round
    /// we are driving).
    pub replication_routed_to_initiator_total: Arc<std::sync::atomic::AtomicU64>,
    /// CIRISEdge#634 — cumulative CRPL replies DROPPED at the registry because
    /// they answered no round we are driving (`ReplyDropReason`: no initiator /
    /// no round in flight / round mismatch). Pre-#634 these frames queued into
    /// an initiator's channel and read as "a responder reply stalled". One per
    /// timed-out round from a slow peer is the honest steady state; a value
    /// climbing while `round_outcomes_total[completed]` does not is a peer
    /// answering rounds too late to count.
    pub replication_reply_dropped_total: Arc<std::sync::atomic::AtomicU64>,
    /// CIRISEdge#636 — bootstrap-door decisions per outcome label
    /// (`attributed` / `unbound` / `not_applicable`): how each bootstrap-kind
    /// Deliver on an identified link was attributed. A healthy first contact
    /// shows a few `unbound` (the records that carry the binding, before persist
    /// admits it) then `attributed`; `not_applicable` is the steady state (the
    /// link was attributed by its announce before any Deliver). The door never
    /// drops, so there is no drop label.
    pub bootstrap_door_outcomes: Arc<RwLock<HashMap<&'static str, u64>>>,
    /// CIRISEdge#728 — inbound frames the Reticulum transport REFUSED at its
    /// receive-side choke point (`drop_inbound`, #425), by the low-cardinality
    /// reason tag. Today's one counted tag is `identity_frame_on_scoped_link`:
    /// a replication / announce / bundle frame that arrived on a link dialled
    /// to a scope-derived address (`FSD/CIRIS_EDGE_TRANSPORT.md` §3.5). A
    /// non-zero count names a peer whose sender still selects links by peer
    /// alone (pre-#728); it is never the generic attribution miss.
    pub transport_inbound_drops: Arc<RwLock<HashMap<&'static str, u64>>>,
    /// CIRISEdge#683 — the opaque-plane first-contact door, per label
    /// (`FIRST_CONTACT.md` §2.2): `first_contact_admitted`,
    /// `first_contact_known_key`, every `first_contact_*` refusal, and
    /// `first_contact_unsolicited_introductions` on the requester's side. The
    /// refusals are drops; this ledger is how an operator reads them.
    pub first_contact_outcomes: Arc<RwLock<HashMap<&'static str, u64>>>,
    /// CIRISEdge#640 — blob holders dropped from a pull's candidate set, by the
    /// router's refusal BRANCH (`ScopeRouteRefusal::reason_tag`):
    /// `blob_group_not_installed` (the host's lifecycle never installed the
    /// room — the remedy is an install), `blob_holder_not_in_group` (roster
    /// policy), `blob_holder_sealed_out` (a rotation closed before the holder
    /// re-keyed), `blob_no_address_table`, `blob_scope_undeterminable`,
    /// `blob_public_is_not_scoped`. Pre-#640 the first three were one number.
    pub blob_route_refusals: Arc<RwLock<HashMap<&'static str, u64>>>,
    /// CIRISEdge#640 — `BlobChunkFetch`es this node received and did not
    /// serve, by branch: the scope-admission tags (`blob_serve_scope_undeterminable`,
    /// `blob_serve_arrival_scope_insufficient`, `blob_serve_group_mismatch`, …)
    /// and `no_chunk_source_wired`. The serve-side twin of `blob_route_refusals`;
    /// the withhold ledger carries the same events keyed coarser.
    pub blob_serve_refusals: Arc<RwLock<HashMap<&'static str, u64>>>,
    /// CIRISEdge#718 (CC 5.4.6 at `4fd2e9e`, CIRISConstitution#132) — which link
    /// each scoped body rode, chosen ONCE per send from the path table:
    /// `send:derived_address` (a one-hop path — the zero-observer path),
    /// `send:identity_link` (only a forwarder's path — the members' E2E
    /// identity-plane link, the room discriminated inside it),
    /// `send:path_unknown_derived` (no path — never a forwarder on a guess);
    /// and on the serve side `serve:identity_link_admitted` (a discriminator
    /// resolved to THIS node's own address and stamped as the arrival). Both
    /// branches are counted so neither can go silent; the refusals ride
    /// `blob_serve_refusals` (`blob_serve_discriminator_*`).
    pub blob_scoped_carriers: Arc<RwLock<HashMap<&'static str, u64>>>,
    /// CIRISEdge#646 — where a pull found its holders, by `scope:source`:
    /// `self:author_nodes` / `family:author_nodes` (the row's author's nodes,
    /// no discovery — CC 5.2) vs `community:claim_index` /
    /// `federation:claim_index` (`list_holders`). The one line that proves a
    /// self/family pull never touched the directory.
    pub blob_pull_sources: Arc<RwLock<HashMap<&'static str, u64>>>,
    /// CIRISEdge#717 — pulls that fetched (or would have fetched) bytes and
    /// refused to STORE them, by reason: `size_mismatch` (a whole blob whose
    /// length is not the one its pointer implies, CC 5.3.2.5) and the DAG
    /// pull's rungs (`FSD/CONTENT_TRANSFER.md` §6.7): `dag_manifest_mismatch`,
    /// `dag_total_size_mismatch`, `dag_over_cap`, `dag_chunk_mismatch`,
    /// `dag_chunk_missing` (`blob_swarm::DagPullRefusal::tag`). Nothing is
    /// stored on any; a non-zero count is a file that is not on this device.
    pub blob_pull_refusals: Arc<RwLock<HashMap<&'static str, u64>>>,
    /// CIRISEdge#739 — the chunk-DAG pull's per-phase clock, `(total ns,
    /// samples)` by phase, so a run can say WHERE a pull's time went rather
    /// than only how long it took (`FSD/CONTENT_TRANSFER.md` §6.7.5). On the
    /// PULLING node: `dag_fetch_wait` (dispatch of a chunk request → its
    /// verified bytes in hand: the wire, the holder's serve, and this node's
    /// inbound verify), `dag_adopt` (`adopt_sealed_chunk`), `dag_promote`;
    /// on any node: `inbound_verify_chunk_body` (the hybrid verify + body
    /// parse of a `BlobChunkBody` envelope) and `serve_chunk` (a
    /// `BlobChunkFetch` answered: the store read, the signed response, the
    /// send). A closed key set; each key is a `&'static str` at its one
    /// producer.
    pub blob_dag_phases: Arc<RwLock<HashMap<&'static str, (u64, u64)>>>,
    /// CIRISEdge#739 — the chunk-DAG pull's chunk ledger by outcome:
    /// `adopted` (fetched, verified, `adopt_sealed_chunk` returned),
    /// `skipped_held` (already at its position with the manifest's sha when
    /// the walk started — a resume), `in_flight_peak` (the most requests the
    /// pipeline had outstanding at once, a gauge kept as a high-water mark).
    /// `adopted` summed across a pull and its resumes equals the manifest's
    /// chunk count exactly once — the witness for "each chunk adopted exactly
    /// once".
    pub blob_dag_chunks: Arc<RwLock<HashMap<&'static str, u64>>>,
    /// CIRISEdge#738 — CC 5.3.3.6 delivery receipts for files, by tag
    /// (`receipts`): `emitted` / `not_emitted_*` on the receiving node;
    /// `admitted` and the named refusals (`receipt_root_unpublished`,
    /// `receipt_tree_size_short`, `receipt_epoch_mismatch`,
    /// `receipt_signer_not_member`, `receipt_duplicate`, `receipt_malformed`,
    /// `receipt_file_unknown`, `receipt_substrate`) on the author's; and
    /// `re_offer_suppressed_receipted` — a row not re-offered to a peer that
    /// receipted it in full.
    pub delivery_receipts: Arc<RwLock<HashMap<&'static str, u64>>>,
    /// CIRISEdge#530 — cumulative count of UNRETAINED peer bindings evicted from
    /// the live announce-intake map under **capacity backpressure** (the
    /// `MAX_PEERS` cap in `transport::reticulum`).
    ///
    /// The house pattern for this table class (leviculum#49) requires that
    /// evictions-under-pressure are **never silent**: a fleet sitting at cap is
    /// otherwise indistinguishable from a fleet with room, and the only prior
    /// signal was a `tracing::debug!` that production does not run at. A
    /// monotonically climbing value means announce intake is saturated and the
    /// node is shedding the least-recently-seen advisory routing hints — benign
    /// in isolation (the mesh re-announces, and an Advisory binding is a routing
    /// hint, never trust), but the field signature of advisory-admit pollution
    /// (an attacker or a QA runner minting keypairs) when it climbs fast.
    ///
    /// Counts ONLY pressure evictions of the unretained (`Advisory`) population.
    /// A `Rooted` binding is pinned and never evicted, so it can never appear
    /// here. Single `Arc<AtomicU64>` (not a per-key bag) — the evicted `key_id`
    /// rides on the matching throttled DEBUG line, and keying by peer would make
    /// cardinality grow with exactly the pollution this counts.
    pub announce_intake_evictions: Arc<std::sync::atomic::AtomicU64>,
    /// CIRISEdge#819 — the Reticulum dial pools' size, ONE entry PER
    /// TRANSPORT INSTANCE (keyed by its metrics source id, as
    /// `known_destination_evictions` is): `(total pooled links, the most
    /// pooled for any one destination)`, set by that transport's pool reaper
    /// each pass. Read as [`Self::link_pool_links`] (the sum) and
    /// [`Self::link_pool_max_per_destination`] (the max), so one transport's
    /// pass never overwrites another's (Codex, #821). A gauge: steady under
    /// load and back toward zero when quiet; a climb that never comes back
    /// down is the #819 link leak.
    pub link_pool_sizes: Arc<RwLock<HashMap<u64, (u64, u64)>>>,
    /// CIRISEdge#819 — pooled links closed because they sat idle past the
    /// pool's idle bound.
    pub link_pool_closed_idle_expired: Arc<std::sync::atomic::AtomicU64>,
    /// CIRISEdge#819 — pooled links closed because their destination's pool
    /// already held its cap of idle lanes.
    pub link_pool_closed_pool_full: Arc<std::sync::atomic::AtomicU64>,
    /// CIRISEdge#819 — pooled links dropped from a pool because the link
    /// itself closed (the peer, leviculum's reap, or another teardown).
    pub link_pool_closed_link_closed: Arc<std::sync::atomic::AtomicU64>,
    /// CIRISEdge#853 — established Reticulum links by direction, ONE entry PER
    /// TRANSPORT INSTANCE (keyed by its metrics source id, as
    /// `link_pool_sizes` is): `(inbound, outbound)` — links a peer opened to
    /// this node, and links this node dialled. Set on every link establish and
    /// close. Read as [`Self::inbound_links`] / [`Self::outbound_links`]. An
    /// `inbound` that climbs while the pools stay small is the #853 leak: the
    /// node is the responder for peers that never let their links go.
    pub link_directions: Arc<RwLock<HashMap<u64, (u64, u64)>>>,
    /// CIRISEdge#853 — inbound links this node closed because they sat idle
    /// past the inbound idle bound.
    pub inbound_link_closed_idle_expired: Arc<std::sync::atomic::AtomicU64>,
    /// CIRISEdge#853 — inbound links that closed otherwise (the peer, leviculum's
    /// own reap, or another teardown).
    pub inbound_link_closed_link_closed: Arc<std::sync::atomic::AtomicU64>,
    /// CIRISEdge#627 — links that came up IDENTIFIED before their announcer had
    /// a binding. Under announce-on-link + inline Stage 1 this is 0 in steady
    /// state; nonzero means the ordering the design guarantees broke.
    pub link_before_binding: Arc<std::sync::atomic::AtomicU64>,
    /// CIRISEdge#627 — first-seen announces whose Stage 2 (rooting walk) was
    /// dropped at a full priority lane. Must read 0 in every harness run.
    pub announce_queue_drop_first_seen: Arc<std::sync::atomic::AtomicU64>,
    /// CIRISEdge#722 — reverse-path frames that SKIPPED Channel-first because
    /// they cut to more than `CHANNEL_FIRST_MAX_FRAGMENTS` and went straight to
    /// the Resource path. A routing decision, so it is counted (and logged) —
    /// before #722 it was a silent `filter`, indistinguishable in the log from a
    /// Channel send that never happened.
    pub channel_first_skipped_over_cap: Arc<std::sync::atomic::AtomicU64>,
    /// CIRISEdge#627 — Stage-1 latency of the most recent first-seen bind
    /// (announce receipt → binding installed + links bound), milliseconds.
    /// A gauge of the last value, not a histogram: the question it answers is
    /// "is Stage 1 still directory-free?" — it should sit at 0–2 ms.
    pub announce_to_binding_ms_last: Arc<std::sync::atomic::AtomicU64>,
    /// CIRISEdge#547 — unix seconds at which the last anti-entropy round
    /// TERMINATED. `0` means "no round has completed since boot".
    ///
    /// These exist to answer ONE question without touching the store: is this
    /// runtime still making progress? A canonical ran 22 hours hung — one thread
    /// in `wait_on_page_bit_common` holding persist's single connection mutex,
    /// six parked behind it — and went unnoticed because the health surface that
    /// would have reported it reads the store, so it was inside the failure it
    /// was meant to detect.
    ///
    /// PLAIN ATOMICS, deliberately, not the `RwLock<HashMap>` the counters
    /// beside them use. A liveness signal must share no lock with any path that
    /// can block on I/O; if it did, a convoy would make the liveness read hang
    /// exactly when its answer matters. Reading these can never block.
    pub last_round_completed_unix: Arc<std::sync::atomic::AtomicU64>,
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
    /// CIRISEdge#459 (persist v36.0.0 / CIRISPersist#624) — the receive-plane
    /// mirror, reason axis for the ATTESTATION plane: policy refusals counted by
    /// persist's stable `AttestationRefusalReason` token
    /// (`conflicting_attestation`, `store_conflict`; a closed, append-only
    /// contract — bounded cardinality by construction). The duplicate halves
    /// (`Unchanged`, `Deduplicated`, `already_present_identical`) never count
    /// here: the receiver already holds what was offered. The same-id-
    /// different-bytes conflict that used to read `federation_backend` (a raw
    /// SQL constraint) is now a named mesh fact.
    pub attestation_apply_refusals_by_reason: Arc<RwLock<HashMap<String, u64>>>,
    /// CIRISEdge#522 (persist v38.2.0) — the receive plane's **door-class**
    /// axis: per-[`crate::replication::bridge::ApplyRefusalClass`] count of
    /// applies refused by one of the three doors that moved in persist
    /// v38.2.0. Keyed by the class's stable `as_str()` token, so cardinality
    /// is bounded by that closed enum, never by traffic — the same contract
    /// [`Self::key_apply_refusals_by_reason`] holds on the Key plane.
    ///
    /// # The state this exists to make visible
    ///
    /// [`Self::apply_refusals_by_kind`] answers "how many Attestation applies
    /// were refused". After v38.2.0 that number silently mixes three
    /// different situations: a node mid-sync whose community roster has not
    /// landed yet (self-healing, expected, `retry_after_roster`), a
    /// peer pushing rows about third parties into a cohort plane
    /// (`third_party_row`, a policy verdict someone should read), and two
    /// authorities disagreeing about one `community_key_id`
    /// (`community_roster_fork`, a fork). Before this ledger they were one
    /// number and one WARN each; a transient refusal nobody could name is
    /// exactly the silent-narrowing class this repo keeps closing.
    ///
    /// Booked at the bridge's single `refuse` site, alongside — never instead
    /// of — the kind axis, so a class-carrying refusal appears on both.
    pub apply_refusals_by_class: Arc<RwLock<HashMap<String, u64>>>,
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
    /// CIRISEdge P0 telemetry — wall time of each anti-entropy round the
    /// scheduler drives, per [`EnvelopeKind`], from the moment the round
    /// holds its round-gate permit to its outcome (completed, refused, timed
    /// out or errored — a round that failed slowly is the one to see).
    /// Buckets: [`REPLICATION_ROUND_DURATION_BUCKETS_SECONDS`]. Cardinality
    /// is bounded by the closed `EnvelopeKind` set.
    pub replication_round_duration_seconds: Arc<RwLock<HashMap<EnvelopeKind, FixedHistogram>>>,
    /// CIRISEdge P0 telemetry — how long a bulk advertise sweep waited for
    /// its `SweepGate` permit (CIRISEdge#531's node-wide sweep bound), one
    /// observation per BOUNDED acquire. A rising tail means sweeps are
    /// queueing behind the bound — the shape the canonical's slow
    /// diagnosis could not see. Buckets: [`SWEEP_PERMIT_WAIT_BUCKETS_SECONDS`].
    pub sweep_permit_wait_seconds: Arc<RwLock<FixedHistogram>>,
}

/// A `&'static str`-keyed counter map, cloned out with owned keys for the
/// snapshot (the lock is held only for the copy).
fn owned_keys<V: Copy>(map: &RwLock<HashMap<&'static str, V>>) -> HashMap<String, V> {
    map.read()
        .iter()
        .map(|(k, v)| ((*k).to_string(), *v))
        .collect()
}

impl EdgeMetrics {
    /// Construct an empty metric bag.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// CIRISEdge#809 — are `self` and `other` handles to the SAME bag
    /// (clones share every `Arc`), as opposed to two bags with equal
    /// counts? Used to detect a transport counting into a bag the Edge
    /// does not read.
    #[must_use]
    pub fn is_same_bag(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.envelopes_sent_total, &other.envelopes_sent_total)
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
        // CIRISEdge#547 — stamp progress BEFORE taking the counter lock. The
        // stamp is the liveness signal and must not be able to wait on anything;
        // ordering it first means even a contended counter map cannot delay the
        // evidence that this runtime is alive.
        Self::stamp_now(&self.last_round_completed_unix);
        let mut guard = self.replication_round_outcomes_total.write();
        *guard.entry(outcome).or_insert(0) += 1;
    }

    /// Wall-clock seconds into an atomic. Monotonically advanced only: a clock
    /// that steps backwards must never make progress look older than it is,
    /// because "no progress for N seconds" is the whole signal.
    fn stamp_now(slot: &std::sync::atomic::AtomicU64) {
        use std::sync::atomic::Ordering;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let _ = slot.fetch_max(now, Ordering::Relaxed);
    }

    /// CIRISEdge#547 — the store-free liveness view.
    ///
    /// Unix seconds of the last completed round, `0` for "none since boot".
    /// Reads ONE atomic: no store, no lock that a store-touching path holds, no
    /// allocation. A caller can compute "seconds since progress" and answer a
    /// health probe while the replication runtime is fully convoyed — which is
    /// precisely the state this exists to make visible. On the hung canonical
    /// this would have read 22 hours stale from the first minute.
    #[must_use]
    pub fn last_round_completed_unix(&self) -> u64 {
        self.last_round_completed_unix
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// CIRISEdge#373 — increment the inbound-backpressure-drop counter. Called
    /// once per dropped frame at the `route_replication_frame` back-pressure
    /// path, so the previously-silent 100% trace loss is countable.
    pub fn inc_inbound_backpressure_drop(&self) {
        self.replication_inbound_backpressure_drops
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// CIRISEdge#662 — count an inbound-backpressure drop under its role.
    pub fn inc_inbound_backpressure_drop_by_role(&self, role: &str) {
        let mut guard = self.replication_inbound_backpressure_drops_by_role.write();
        *guard.entry(role.to_owned()).or_insert(0) += 1;
    }

    /// CIRISEdge#373 — read the inbound-backpressure-drop counter (tests +
    /// snapshot projection).
    #[must_use]
    pub fn inbound_backpressure_drops(&self) -> u64 {
        self.replication_inbound_backpressure_drops
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// CIRISEdge#634 — a frame was routed to a responder.
    pub fn inc_routed_to_responder(&self) {
        self.replication_routed_to_responder_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// CIRISEdge#634 — a reply was routed into an initiator's round inbox.
    pub fn inc_routed_to_initiator(&self) {
        self.replication_routed_to_initiator_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// CIRISEdge#634 — a reply answered no driven round and was dropped.
    pub fn inc_reply_dropped(&self) {
        self.replication_reply_dropped_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// CIRISEdge#634 — read the three route counters as
    /// `(to_responder, to_initiator, reply_dropped)`.
    #[must_use]
    pub fn route_counters(&self) -> (u64, u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        (
            self.replication_routed_to_responder_total.load(Relaxed),
            self.replication_routed_to_initiator_total.load(Relaxed),
            self.replication_reply_dropped_total.load(Relaxed),
        )
    }

    /// CIRISEdge#763 — book one chunk-source refusal at the serve door:
    /// [`BLOB_SERVE_REFUSED_WITHDRAWN`] for a file every reference to which
    /// was withdrawn (CC 2.3 at the bytes plane). Other refusals are booked
    /// where they are decided.
    pub fn book_chunk_source_refusal(&self, refusal: &crate::blob_swarm::ChunkSourceRefusal) {
        if *refusal == crate::blob_swarm::ChunkSourceRefusal::Withdrawn {
            self.inc_blob_serve_refusal(BLOB_SERVE_REFUSED_WITHDRAWN);
        }
    }

    /// CIRISEdge#640 — count one unserved `BlobChunkFetch` by its branch tag.
    pub fn inc_blob_serve_refusal(&self, reason_tag: &'static str) {
        *self
            .blob_serve_refusals
            .write()
            .entry(reason_tag)
            .or_insert(0) += 1;
    }

    /// CIRISEdge#646 — count one pull's holder source by its `scope:source` tag.
    pub fn inc_blob_pull_source(&self, tag: &'static str) {
        *self.blob_pull_sources.write().entry(tag).or_insert(0) += 1;
    }

    /// CIRISEdge#717 — count one pull that refused to store, by reason tag.
    pub fn inc_blob_pull_refusal(&self, reason_tag: &'static str) {
        *self
            .blob_pull_refusals
            .write()
            .entry(reason_tag)
            .or_insert(0) += 1;
    }

    /// CIRISEdge#739 — add one sample to a chunk-DAG phase clock.
    pub fn add_blob_dag_phase(&self, phase: &'static str, elapsed: std::time::Duration) {
        let ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        let mut phases = self.blob_dag_phases.write();
        let slot = phases.entry(phase).or_insert((0, 0));
        slot.0 = slot.0.saturating_add(ns);
        slot.1 = slot.1.saturating_add(1);
    }

    /// CIRISEdge#739 — count chunks in the DAG pull's ledger by outcome.
    pub fn add_blob_dag_chunks(&self, outcome: &'static str, n: u64) {
        let mut chunks = self.blob_dag_chunks.write();
        let slot = chunks.entry(outcome).or_insert(0);
        *slot = slot.saturating_add(n);
    }

    /// CIRISEdge#739 — raise a high-water mark in the DAG pull's ledger.
    pub fn max_blob_dag_chunks(&self, gauge: &'static str, value: u64) {
        let mut chunks = self.blob_dag_chunks.write();
        let slot = chunks.entry(gauge).or_insert(0);
        *slot = (*slot).max(value);
    }

    /// CIRISEdge#738 — count one delivery-receipt event by its tag.
    pub fn inc_delivery_receipt(&self, tag: &'static str) {
        *self.delivery_receipts.write().entry(tag).or_insert(0) += 1;
    }

    /// CIRISEdge#640 — count one blob-route refusal by its branch tag.
    pub fn inc_blob_route_refusal(&self, reason_tag: &'static str) {
        *self
            .blob_route_refusals
            .write()
            .entry(reason_tag)
            .or_insert(0) += 1;
    }

    /// CIRISEdge#718 — count one scoped-carrier choice (or identity-link
    /// admission) by its tag.
    pub fn inc_blob_scoped_carrier(&self, tag: &'static str) {
        *self.blob_scoped_carriers.write().entry(tag).or_insert(0) += 1;
    }

    /// CIRISEdge#636 — count one bootstrap-door decision by its label.
    pub fn inc_bootstrap_door(&self, decision: &'static str) {
        *self
            .bootstrap_door_outcomes
            .write()
            .entry(decision)
            .or_insert(0) += 1;
    }

    /// CIRISEdge#728 — count one transport receive-side refusal by its
    /// `drop_inbound` reason tag.
    pub fn inc_transport_inbound_drop(&self, reason_tag: &'static str) {
        *self
            .transport_inbound_drops
            .write()
            .entry(reason_tag)
            .or_insert(0) += 1;
    }

    /// CIRISEdge#728 — the transport receive-side refusals by reason tag
    /// (tests + the operator readback).
    #[must_use]
    pub fn transport_inbound_drops(&self) -> HashMap<String, u64> {
        self.transport_inbound_drops
            .read()
            .iter()
            .map(|(k, v)| ((*k).to_string(), *v))
            .collect()
    }

    /// CIRISEdge#683 — count one first-contact door outcome by its label.
    pub fn inc_first_contact(&self, label: &'static str) {
        *self
            .first_contact_outcomes
            .write()
            .entry(label)
            .or_insert(0) += 1;
    }

    /// CIRISEdge#530 — increment the announce-intake pressure-eviction counter.
    /// Called once per evicted UNRETAINED binding at the `MAX_PEERS` cap, so the
    /// previously `debug!`-only eviction is countable in production.
    pub fn inc_announce_intake_eviction(&self) {
        self.announce_intake_evictions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// CIRISEdge#530 — read the announce-intake pressure-eviction counter
    /// (tests + the metrics snapshot projection).
    #[must_use]
    pub fn announce_intake_evictions(&self) -> u64 {
        self.announce_intake_evictions
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// CIRISEdge#819 — set one transport's dial-pool gauges: its total
    /// pooled links and its largest pool for one destination. `source` is the
    /// transport's process-unique metrics source id.
    pub fn set_link_pool_size(&self, source: u64, total: u64, max_per_destination: u64) {
        self.link_pool_sizes
            .write()
            .insert(source, (total, max_per_destination));
    }

    /// CIRISEdge#819 — pooled links across every transport that has reported.
    #[must_use]
    pub fn link_pool_links(&self) -> u64 {
        self.link_pool_sizes
            .read()
            .values()
            .fold(0u64, |acc, (total, _)| acc.saturating_add(*total))
    }

    /// CIRISEdge#819 — the largest pool for one destination, across every
    /// transport that has reported.
    #[must_use]
    pub fn link_pool_max_per_destination(&self) -> u64 {
        self.link_pool_sizes
            .read()
            .values()
            .map(|(_, max)| *max)
            .max()
            .unwrap_or(0)
    }

    /// CIRISEdge#819 — count `n` pooled links closed for `reason`.
    pub fn add_link_pool_closed(&self, reason: LinkPoolCloseReason, n: u64) {
        let counter = match reason {
            LinkPoolCloseReason::IdleExpired => &self.link_pool_closed_idle_expired,
            LinkPoolCloseReason::PoolFull => &self.link_pool_closed_pool_full,
            LinkPoolCloseReason::LinkClosed => &self.link_pool_closed_link_closed,
        };
        counter.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
    }

    /// CIRISEdge#819 — pooled links closed, by reason token, every reason
    /// present (a zero is an answer).
    #[must_use]
    pub fn link_pool_closed_by_reason(&self) -> HashMap<String, u64> {
        [
            (
                LinkPoolCloseReason::IdleExpired,
                &self.link_pool_closed_idle_expired,
            ),
            (
                LinkPoolCloseReason::PoolFull,
                &self.link_pool_closed_pool_full,
            ),
            (
                LinkPoolCloseReason::LinkClosed,
                &self.link_pool_closed_link_closed,
            ),
        ]
        .into_iter()
        .map(|(r, c)| {
            (
                r.as_str().to_owned(),
                c.load(std::sync::atomic::Ordering::Relaxed),
            )
        })
        .collect()
    }

    /// CIRISEdge#853 — set one transport's link-direction gauges. `source` is
    /// the transport's process-unique metrics source id.
    pub fn set_link_directions(&self, source: u64, inbound: u64, outbound: u64) {
        self.link_directions
            .write()
            .insert(source, (inbound, outbound));
    }

    /// CIRISEdge#853 — established links a peer opened to this node, across
    /// every transport that has reported.
    #[must_use]
    pub fn inbound_links(&self) -> u64 {
        self.link_directions
            .read()
            .values()
            .fold(0u64, |acc, (inbound, _)| acc.saturating_add(*inbound))
    }

    /// CIRISEdge#853 — established links this node dialled, across every
    /// transport that has reported.
    #[must_use]
    pub fn outbound_links(&self) -> u64 {
        self.link_directions
            .read()
            .values()
            .fold(0u64, |acc, (_, outbound)| acc.saturating_add(*outbound))
    }

    /// CIRISEdge#853 — count `n` inbound links closed for `reason`.
    pub fn add_inbound_link_closed(&self, reason: InboundLinkCloseReason, n: u64) {
        let counter = match reason {
            InboundLinkCloseReason::IdleExpired => &self.inbound_link_closed_idle_expired,
            InboundLinkCloseReason::LinkClosed => &self.inbound_link_closed_link_closed,
        };
        counter.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
    }

    /// CIRISEdge#853 — inbound links closed, by reason token, every reason
    /// present (a zero is an answer).
    #[must_use]
    pub fn inbound_link_closed_by_reason(&self) -> HashMap<String, u64> {
        [
            (
                InboundLinkCloseReason::IdleExpired,
                &self.inbound_link_closed_idle_expired,
            ),
            (
                InboundLinkCloseReason::LinkClosed,
                &self.inbound_link_closed_link_closed,
            ),
        ]
        .into_iter()
        .map(|(r, c)| {
            (
                r.as_str().to_owned(),
                c.load(std::sync::atomic::Ordering::Relaxed),
            )
        })
        .collect()
    }

    /// CIRISEdge#627 — a link came up identified before its announcer was bound.
    pub fn inc_link_before_binding(&self) {
        self.link_before_binding
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    /// CIRISEdge#627 — read `link_before_binding`.
    #[must_use]
    pub fn link_before_binding(&self) -> u64 {
        self.link_before_binding
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    /// CIRISEdge#627 — a first-seen announce's Stage 2 was dropped at capacity.
    pub fn inc_announce_queue_drop_first_seen(&self) {
        self.announce_queue_drop_first_seen
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    /// CIRISEdge#627 — read `announce_queue_drop_first_seen`.
    #[must_use]
    pub fn announce_queue_drop_first_seen(&self) -> u64 {
        self.announce_queue_drop_first_seen
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    /// CIRISEdge#722 — a reverse-path frame skipped Channel-first (over the
    /// fragment cap) and went to the Resource path.
    pub fn inc_channel_first_skipped_over_cap(&self) {
        self.channel_first_skipped_over_cap
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    /// CIRISEdge#722 — read `channel_first_skipped_over_cap`.
    #[must_use]
    pub fn channel_first_skipped_over_cap(&self) -> u64 {
        self.channel_first_skipped_over_cap
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    /// CIRISEdge#627 — record the latest Stage-1 announce→binding latency.
    pub fn record_announce_to_binding_ms(&self, ms: u64) {
        self.announce_to_binding_ms_last
            .store(ms, std::sync::atomic::Ordering::Relaxed);
    }
    /// CIRISEdge#627 — read the latest Stage-1 latency.
    #[must_use]
    pub fn announce_to_binding_ms_last(&self) -> u64 {
        self.announce_to_binding_ms_last
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

    /// CIRISEdge#459 — count one TYPED Attestation-plane policy refusal by
    /// persist's stable token (`AttestationRefusalReason::as_str()` — a closed,
    /// append-only set, so cardinality is bounded by the persist contract).
    pub fn inc_attestation_apply_refusal(&self, token: &str) {
        let mut guard = self.attestation_apply_refusals_by_reason.write();
        *guard.entry(token.to_string()).or_insert(0) += 1;
    }

    /// CIRISEdge#522 — count one v38.2.0 door-class refusal by its stable
    /// token. `token` comes from
    /// [`ApplyRefusalClass::as_str`](crate::replication::bridge::ApplyRefusalClass::as_str)
    /// — a closed set, so this map's cardinality is bounded by that enum.
    pub fn inc_apply_refusal_class(&self, token: &str) {
        let mut guard = self.apply_refusals_by_class.write();
        *guard.entry(token.to_string()).or_insert(0) += 1;
    }

    /// Update the per-peer reachability ratio gauge. Replaces (does
    /// not accumulate) — the underlying tracker computes the rolling
    /// ratio and the gauge mirrors it.
    pub fn set_peer_reachability(&self, peer_key_id: &str, medium: &str, ratio: f64) {
        let mut guard = self.peer_reachability_ratio.write();
        guard.insert((peer_key_id.to_string(), medium.to_string()), ratio);
    }

    /// CIRISEdge P0 telemetry — record one anti-entropy round's wall time
    /// for `kind` into [`Self::replication_round_duration_seconds`].
    pub fn observe_round_duration(&self, kind: EnvelopeKind, d: std::time::Duration) {
        self.replication_round_duration_seconds
            .write()
            .entry(kind)
            .or_default()
            .observe(REPLICATION_ROUND_DURATION_BUCKETS_SECONDS, d);
    }

    /// CIRISEdge P0 telemetry — record one advertise-sweep permit wait into
    /// [`Self::sweep_permit_wait_seconds`].
    pub fn observe_sweep_permit_wait(&self, d: std::time::Duration) {
        self.sweep_permit_wait_seconds
            .write()
            .observe(SWEEP_PERMIT_WAIT_BUCKETS_SECONDS, d);
    }

    /// Snapshot all counters + gauges as plain `HashMap`s — the
    /// projection consumers (PyO3 / UniFFI / Prometheus exposition)
    /// render into their respective wire shapes. Each `HashMap` is a
    /// fresh clone of the live state; the live map is unlocked
    /// immediately after the clone so emitters aren't blocked across
    /// the projection step.
    #[must_use]
    #[allow(clippy::too_many_lines)] // one flat field-by-field projection
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
            replication_inbound_backpressure_drops_by_role: self
                .replication_inbound_backpressure_drops_by_role
                .read()
                .clone(),
            blob_serve_refusals: self
                .blob_serve_refusals
                .read()
                .iter()
                .map(|(k, v)| ((*k).to_string(), *v))
                .collect(),
            blob_pull_sources: self
                .blob_pull_sources
                .read()
                .iter()
                .map(|(k, v)| ((*k).to_string(), *v))
                .collect(),
            blob_pull_refusals: self
                .blob_pull_refusals
                .read()
                .iter()
                .map(|(k, v)| ((*k).to_string(), *v))
                .collect(),
            blob_dag_phases: owned_keys(&self.blob_dag_phases),
            blob_dag_chunks: owned_keys(&self.blob_dag_chunks),
            delivery_receipts: owned_keys(&self.delivery_receipts),
            blob_route_refusals: self
                .blob_route_refusals
                .read()
                .iter()
                .map(|(k, v)| ((*k).to_string(), *v))
                .collect(),
            blob_scoped_carriers: self
                .blob_scoped_carriers
                .read()
                .iter()
                .map(|(k, v)| ((*k).to_string(), *v))
                .collect(),
            bootstrap_door_outcomes: self
                .bootstrap_door_outcomes
                .read()
                .iter()
                .map(|(k, v)| ((*k).to_string(), *v))
                .collect(),
            transport_inbound_drops: self.transport_inbound_drops(),
            first_contact_outcomes: self
                .first_contact_outcomes
                .read()
                .iter()
                .map(|(k, v)| ((*k).to_string(), *v))
                .collect(),
            replication_routed_to_responder_total: self.route_counters().0,
            replication_routed_to_initiator_total: self.route_counters().1,
            replication_reply_dropped_total: self.route_counters().2,
            announce_intake_evictions: self.announce_intake_evictions(),
            link_pool_links: self.link_pool_links(),
            link_pool_max_per_destination: self.link_pool_max_per_destination(),
            link_pool_closed_by_reason: self.link_pool_closed_by_reason(),
            inbound_links: self.inbound_links(),
            outbound_links: self.outbound_links(),
            inbound_link_closed_by_reason: self.inbound_link_closed_by_reason(),
            link_before_binding: self.link_before_binding(),
            announce_queue_drop_first_seen: self.announce_queue_drop_first_seen(),
            channel_first_skipped_over_cap: self.channel_first_skipped_over_cap(),
            announce_to_binding_ms_last: self.announce_to_binding_ms_last(),
            withholds_by_reason: self.withholds_by_reason.read().clone(),
            recent_withholds: self.recent_withholds.read().iter().cloned().collect(),
            replication_envelopes_served_total: self
                .replication_envelopes_served_total
                .read()
                .clone(),
            apply_refusals_by_kind: self.apply_refusals_by_kind.read().clone(),
            key_apply_refusals_by_reason: self.key_apply_refusals_by_reason.read().clone(),
            attestation_apply_refusals_by_reason: self
                .attestation_apply_refusals_by_reason
                .read()
                .clone(),
            apply_refusals_by_class: self.apply_refusals_by_class.read().clone(),
            replication_applied_total: self.replication_applied_total.read().clone(),
            replication_duplicate_total: self.replication_duplicate_total.read().clone(),
            removal_delivery: self.removal_receipts.read().delta(),
            replication_round_duration_seconds: self
                .replication_round_duration_seconds
                .read()
                .iter()
                .map(|(k, h)| (*k, h.snapshot(REPLICATION_ROUND_DURATION_BUCKETS_SECONDS)))
                .collect(),
            sweep_permit_wait_seconds: self
                .sweep_permit_wait_seconds
                .read()
                .snapshot(SWEEP_PERMIT_WAIT_BUCKETS_SECONDS),
        }
    }
}

/// CIRISEdge#819 — why a pooled Reticulum link left its pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkPoolCloseReason {
    /// Idle past the pool's idle bound; edge closed it.
    IdleExpired,
    /// Released into a pool already holding its cap of idle lanes; edge
    /// closed it.
    PoolFull,
    /// The link closed on its own (the peer, leviculum's reap, or another
    /// teardown) and its pool entry was dropped.
    LinkClosed,
}

impl LinkPoolCloseReason {
    /// The stable token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdleExpired => "idle_expired",
            Self::PoolFull => "pool_full",
            Self::LinkClosed => "link_closed",
        }
    }
}

/// CIRISEdge#853 — why an INBOUND Reticulum link (one a peer opened to this
/// node) closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InboundLinkCloseReason {
    /// Idle past the inbound idle bound; edge closed it.
    IdleExpired,
    /// The link closed on its own (the peer, leviculum's reap, or another
    /// teardown).
    LinkClosed,
}

impl InboundLinkCloseReason {
    /// The stable token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdleExpired => "idle_expired",
            Self::LinkClosed => "link_closed",
        }
    }
}

/// Point-in-time projection of [`EdgeMetrics`]. Returned by
/// [`EdgeMetrics::snapshot`]; consumed by the PyO3 / UniFFI projection
/// methods. Owned `HashMap`s — emitters can keep writing through the
/// underlying `Arc<RwLock<_>>` while a consumer renders the bundle.
///
/// A field added here MUST be added to [`EDGE_METRICS_BUNDLE_FIELDS`]'s
/// macro list too (the build fails otherwise), and the binding parity tests
/// then fail until BOTH the PyO3 and the UniFFI snapshot project it.
#[derive(Debug, Clone)]
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
    /// CIRISEdge#662 — the same, by role (`"responder"` / `"initiator"`).
    pub replication_inbound_backpressure_drops_by_role: HashMap<String, u64>,
    /// CIRISEdge#640 — blob holders dropped from a pull by refusal branch.
    pub blob_route_refusals: HashMap<String, u64>,
    /// CIRISEdge#640 — `BlobChunkFetch`es received and not served, by branch.
    pub blob_serve_refusals: HashMap<String, u64>,
    /// CIRISEdge#718 — which link each scoped body rode (`send:*`) and
    /// identity-link admissions (`serve:identity_link_admitted`).
    pub blob_scoped_carriers: HashMap<String, u64>,
    /// CIRISEdge#646 — where each pull found its holders, `scope:source`.
    pub blob_pull_sources: HashMap<String, u64>,
    /// CIRISEdge#717 — pulls that refused to store, by reason.
    pub blob_pull_refusals: HashMap<String, u64>,
    /// CIRISEdge#739 — chunk-DAG phase clocks, `(total ns, samples)` by phase.
    pub blob_dag_phases: HashMap<String, (u64, u64)>,
    /// CIRISEdge#739 — chunk-DAG chunk ledger by outcome (`adopted`,
    /// `skipped_held`, `in_flight_peak`).
    pub blob_dag_chunks: HashMap<String, u64>,
    /// CIRISEdge#738 — delivery receipts for files, by tag.
    pub delivery_receipts: HashMap<String, u64>,
    /// CIRISEdge#636 — bootstrap-door decisions by label (`attributed` /
    /// `unbound` / `not_applicable`). The door never drops.
    pub bootstrap_door_outcomes: HashMap<String, u64>,
    /// CIRISEdge#728 — transport receive-side refusals by `drop_inbound`
    /// reason tag (`identity_frame_on_scoped_link`, …).
    pub transport_inbound_drops: HashMap<String, u64>,
    /// CIRISEdge#683 — the opaque-plane first-contact door by label.
    pub first_contact_outcomes: HashMap<String, u64>,
    /// CIRISEdge#634 — inbound frames routed to a responder (the peer's round).
    pub replication_routed_to_responder_total: u64,
    /// CIRISEdge#634 — replies routed into an initiator's round inbox.
    pub replication_routed_to_initiator_total: u64,
    /// CIRISEdge#634 — replies dropped at the registry: no round we are
    /// driving answers to them.
    pub replication_reply_dropped_total: u64,
    /// CIRISEdge#530 — cumulative UNRETAINED peer bindings evicted from the live
    /// announce-intake map under capacity backpressure. Zero on a node with room;
    /// climbing on one at cap. `Rooted` bindings are pinned and never counted.
    pub announce_intake_evictions: u64,
    /// CIRISEdge#819 — pooled Reticulum links (identity + scoped), at the
    /// transport's last pool-reaper pass.
    pub link_pool_links: u64,
    /// CIRISEdge#819 — the largest pool for one destination at that pass.
    pub link_pool_max_per_destination: u64,
    /// CIRISEdge#819 — pooled links closed, by [`LinkPoolCloseReason`] token
    /// (`idle_expired`, `pool_full`, `link_closed`); every token present.
    pub link_pool_closed_by_reason: HashMap<String, u64>,
    /// CIRISEdge#853 — established links a peer opened to this node.
    pub inbound_links: u64,
    /// CIRISEdge#853 — established links this node dialled.
    pub outbound_links: u64,
    /// CIRISEdge#853 — inbound links closed, by [`InboundLinkCloseReason`]
    /// token (`idle_expired`, `link_closed`); every token present.
    pub inbound_link_closed_by_reason: HashMap<String, u64>,
    /// CIRISEdge#627 — links identified before their announcer was bound.
    /// 0 in steady state; nonzero = the announce-before-link ordering broke.
    pub link_before_binding: u64,
    /// CIRISEdge#627 — first-seen announces shed at a full priority lane. 0.
    pub announce_queue_drop_first_seen: u64,
    /// CIRISEdge#722 — reverse-path frames sent Resource-first because they
    /// exceeded `CHANNEL_FIRST_MAX_FRAGMENTS` (every hybrid-signed row does at a
    /// 500-byte MTU: the ML-DSA-65 signature alone outweighs eight fragments).
    pub channel_first_skipped_over_cap: u64,
    /// CIRISEdge#627 — latest Stage-1 announce→binding latency, ms (0–2 expected).
    pub announce_to_binding_ms_last: u64,
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
    /// CIRISEdge#459 — typed Attestation-plane policy refusals by persist's
    /// stable `AttestationRefusalReason` token (closed, append-only).
    pub attestation_apply_refusals_by_reason: HashMap<String, u64>,
    /// CIRISEdge#522 — snapshot of
    /// [`EdgeMetrics::apply_refusals_by_class`]: the three v38.2.0 apply-door
    /// classes by their stable tokens.
    pub apply_refusals_by_class: HashMap<String, u64>,
    /// CIRISEdge#457 — per-kind accepted applies that changed local state.
    pub replication_applied_total: HashMap<EnvelopeKind, u64>,
    /// CIRISEdge#457 — per-kind already-held applies (distinct from applied).
    pub replication_duplicate_total: HashMap<EnvelopeKind, u64>,
    /// CIRISEdge#441 — the removal-delivery delta: per tracked removal row,
    /// offered/acked counts + peers still lacking a receipt.
    pub removal_delivery: Vec<RemovalRowDelta>,
    /// CIRISEdge P0 telemetry — anti-entropy round wall time per kind
    /// (exported as [`REPLICATION_ROUND_DURATION_METRIC`]).
    pub replication_round_duration_seconds: HashMap<EnvelopeKind, HistogramSnapshot>,
    /// CIRISEdge P0 telemetry — advertise-sweep permit wait (exported as
    /// [`SWEEP_PERMIT_WAIT_METRIC`]).
    pub sweep_permit_wait_seconds: HistogramSnapshot,
}

/// CIRISEdge P0 telemetry — an [`EdgeMetricsBundle`] flattened to two
/// string-keyed maps, the shape the UniFFI `EdgeMetricsSnapshot` carries
/// (and any flat exporter can). Built by [`EdgeMetricsBundle::flatten`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FlatMetrics {
    /// Counters and integer gauges.
    pub counters: HashMap<String, u64>,
    /// Real-valued gauges (ratios, histogram sums in seconds).
    pub gauges: HashMap<String, f64>,
}

impl FlatMetrics {
    /// A labelled `u64` family: `name` = the sum over labels (present even
    /// when the family is empty, so the name is always projected), and
    /// `name.<label>` = each entry.
    fn family<'a, L: std::fmt::Display + 'a>(
        &mut self,
        name: &str,
        entries: impl IntoIterator<Item = (L, &'a u64)>,
    ) {
        let mut total = 0u64;
        for (label, v) in entries {
            total = total.saturating_add(*v);
            self.counters.insert(format!("{name}.{label}"), *v);
        }
        self.counters.insert(name.to_string(), total);
    }

    /// One histogram under `prefix`: `prefix.bucket.<le>` (cumulative),
    /// `prefix.count`, and the gauge `prefix.sum` (seconds).
    fn histogram(&mut self, prefix: &str, h: &HistogramSnapshot) {
        for (le, n) in h.buckets() {
            self.counters.insert(format!("{prefix}.bucket.{le}"), n);
        }
        self.counters.insert(format!("{prefix}.count"), h.count);
        self.gauges.insert(format!("{prefix}.sum"), h.sum_seconds);
    }
}

impl EdgeMetricsBundle {
    /// CIRISEdge P0 telemetry — flatten every field into dotted keys. Each
    /// field `f` of [`EDGE_METRICS_BUNDLE_FIELDS`] appears as the key `f`
    /// (a scalar's value; a labelled family's total; a list's length; a
    /// histogram's observation count) — present even when nothing was
    /// recorded — and labelled detail as `f.<label>`. The UniFFI binding
    /// projects exactly this, so it can never drop a field PyO3 carries.
    ///
    /// Shapes beyond `f.<label>`:
    /// - `send_failures_total.<transport>:<class>`;
    ///   `peer_reachability_ratio.<peer>:<medium>` is a GAUGE (the ratio),
    ///   and the counter `peer_reachability_ratio` is the entry count.
    /// - `blob_dag_phases.<phase>.total_ns` / `.samples`; the base key is
    ///   the total sample count.
    /// - `recent_withholds` is the attribution window's length (the
    ///   per-reason counts are `withholds_by_reason`; the string detail is
    ///   PyO3-only, a `u64` map cannot carry it).
    /// - `removal_delivery` is the tracked row count, with
    ///   `.offered_total` / `.acked_total` / `.unacked_peers_total`.
    /// - `replication_round_duration_seconds.<kind>.bucket.<le>` /
    ///   `.count` / gauge `.sum`; `sweep_permit_wait_seconds.bucket.<le>` /
    ///   `.count` / gauge `.sum`.
    // Straight-line field→key emission, one block per bundle field; its
    // length grows with the bundle, not with branching.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn flatten(&self) -> FlatMetrics {
        let mut f = FlatMetrics::default();
        f.family(
            "envelopes_sent_total",
            self.envelopes_sent_total
                .iter()
                .map(|(k, v)| (format!("{k:?}"), v)),
        );
        f.family(
            "envelopes_received_total",
            self.envelopes_received_total
                .iter()
                .map(|(k, v)| (format!("{k:?}"), v)),
        );
        f.family(
            "send_failures_total",
            self.send_failures_total
                .iter()
                .map(|((t, c), v)| (format!("{}:{c}", t.0), v)),
        );
        f.family(
            "verify_failures_total",
            self.verify_failures_total
                .iter()
                .map(|(k, v)| (k.as_str(), v)),
        );
        f.family(
            "durable_queue_depth",
            self.durable_queue_depth
                .iter()
                .map(|(k, v)| (k.as_str(), v)),
        );
        f.family(
            "transport_bytes_in_total",
            self.transport_bytes_in_total.iter().map(|(k, v)| (k.0, v)),
        );
        f.family(
            "transport_bytes_out_total",
            self.transport_bytes_out_total.iter().map(|(k, v)| (k.0, v)),
        );
        for ((peer, medium), ratio) in &self.peer_reachability_ratio {
            f.gauges
                .insert(format!("peer_reachability_ratio.{peer}:{medium}"), *ratio);
        }
        f.counters.insert(
            "peer_reachability_ratio".to_string(),
            self.peer_reachability_ratio.len() as u64,
        );
        f.counters.insert(
            "inbound_dropped_low_trust".to_string(),
            self.inbound_dropped_low_trust,
        );
        f.family(
            "replication_round_outcomes_total",
            self.replication_round_outcomes_total
                .iter()
                .map(|(k, v)| (k.as_str(), v)),
        );
        f.counters.insert(
            "replication_inbound_backpressure_drops".to_string(),
            self.replication_inbound_backpressure_drops,
        );
        f.family(
            "replication_inbound_backpressure_drops_by_role",
            &self.replication_inbound_backpressure_drops_by_role,
        );
        f.family("blob_route_refusals", &self.blob_route_refusals);
        f.family("blob_serve_refusals", &self.blob_serve_refusals);
        f.family("blob_scoped_carriers", &self.blob_scoped_carriers);
        // CIRISEdge#819 / #820 — the dial pools.
        f.counters
            .insert("link_pool_links".to_string(), self.link_pool_links);
        f.counters.insert(
            "link_pool_max_per_destination".to_string(),
            self.link_pool_max_per_destination,
        );
        f.family(
            "link_pool_closed_by_reason",
            &self.link_pool_closed_by_reason,
        );
        // CIRISEdge#853 — links by direction, and inbound closes by reason.
        f.counters
            .insert("inbound_links".to_string(), self.inbound_links);
        f.counters
            .insert("outbound_links".to_string(), self.outbound_links);
        f.family(
            "inbound_link_closed_by_reason",
            &self.inbound_link_closed_by_reason,
        );
        f.family("blob_pull_sources", &self.blob_pull_sources);
        f.family("blob_pull_refusals", &self.blob_pull_refusals);
        let mut dag_samples = 0u64;
        for (phase, (total_ns, samples)) in &self.blob_dag_phases {
            dag_samples = dag_samples.saturating_add(*samples);
            f.counters
                .insert(format!("blob_dag_phases.{phase}.total_ns"), *total_ns);
            f.counters
                .insert(format!("blob_dag_phases.{phase}.samples"), *samples);
        }
        f.counters
            .insert("blob_dag_phases".to_string(), dag_samples);
        f.family("blob_dag_chunks", &self.blob_dag_chunks);
        f.family("delivery_receipts", &self.delivery_receipts);
        f.family("bootstrap_door_outcomes", &self.bootstrap_door_outcomes);
        f.family("transport_inbound_drops", &self.transport_inbound_drops);
        f.family("first_contact_outcomes", &self.first_contact_outcomes);
        for (name, v) in [
            (
                "replication_routed_to_responder_total",
                self.replication_routed_to_responder_total,
            ),
            (
                "replication_routed_to_initiator_total",
                self.replication_routed_to_initiator_total,
            ),
            (
                "replication_reply_dropped_total",
                self.replication_reply_dropped_total,
            ),
            ("announce_intake_evictions", self.announce_intake_evictions),
            ("link_before_binding", self.link_before_binding),
            (
                "announce_queue_drop_first_seen",
                self.announce_queue_drop_first_seen,
            ),
            (
                "channel_first_skipped_over_cap",
                self.channel_first_skipped_over_cap,
            ),
            (
                "announce_to_binding_ms_last",
                self.announce_to_binding_ms_last,
            ),
        ] {
            f.counters.insert(name.to_string(), v);
        }
        f.family(
            "withholds_by_reason",
            self.withholds_by_reason
                .iter()
                .map(|(k, v)| (k.as_str(), v)),
        );
        f.counters.insert(
            "recent_withholds".to_string(),
            self.recent_withholds.len() as u64,
        );
        for (name, map) in [
            (
                "replication_envelopes_served_total",
                &self.replication_envelopes_served_total,
            ),
            ("apply_refusals_by_kind", &self.apply_refusals_by_kind),
            ("replication_applied_total", &self.replication_applied_total),
            (
                "replication_duplicate_total",
                &self.replication_duplicate_total,
            ),
        ] {
            f.family(name, map.iter().map(|(k, v)| (k.as_wire_str(), v)));
        }
        f.family(
            "key_apply_refusals_by_reason",
            &self.key_apply_refusals_by_reason,
        );
        f.family(
            "attestation_apply_refusals_by_reason",
            &self.attestation_apply_refusals_by_reason,
        );
        f.family("apply_refusals_by_class", &self.apply_refusals_by_class);
        let (mut offered, mut acked, mut unacked) = (0u64, 0u64, 0u64);
        for row in &self.removal_delivery {
            offered = offered.saturating_add(row.offered as u64);
            acked = acked.saturating_add(row.acked as u64);
            unacked = unacked.saturating_add(row.unacked_peers.len() as u64);
        }
        f.counters.insert(
            "removal_delivery".to_string(),
            self.removal_delivery.len() as u64,
        );
        f.counters
            .insert("removal_delivery.offered_total".to_string(), offered);
        f.counters
            .insert("removal_delivery.acked_total".to_string(), acked);
        f.counters
            .insert("removal_delivery.unacked_peers_total".to_string(), unacked);
        let mut rounds = 0u64;
        for (kind, h) in &self.replication_round_duration_seconds {
            rounds = rounds.saturating_add(h.count);
            f.histogram(
                &format!("replication_round_duration_seconds.{}", kind.as_wire_str()),
                h,
            );
        }
        f.counters
            .insert("replication_round_duration_seconds".to_string(), rounds);
        f.histogram("sweep_permit_wait_seconds", &self.sweep_permit_wait_seconds);
        f.counters.insert(
            "sweep_permit_wait_seconds".to_string(),
            self.sweep_permit_wait_seconds.count,
        );
        f
    }
}

impl Default for EdgeMetricsBundle {
    fn default() -> Self {
        EdgeMetrics::new().snapshot()
    }
}

/// Declares [`EDGE_METRICS_BUNDLE_FIELDS`] from one list AND destructures
/// [`EdgeMetricsBundle`] exhaustively against the same list, so a field
/// added to the bundle but not to the list is a compile error, never a
/// silent omission from the binding parity tests.
macro_rules! edge_metrics_bundle_fields {
    ($($field:ident),* $(,)?) => {
        /// Every [`EdgeMetricsBundle`] field name, in declaration order. Both
        /// binding snapshots (PyO3 `metrics_snapshot()` dict keys; UniFFI
        /// counter/gauge keys, as the name itself or a `name.` prefix) must
        /// carry each one; the parity tests walk this list.
        pub const EDGE_METRICS_BUNDLE_FIELDS: &[&str] = &[$(stringify!($field)),*];

        #[allow(dead_code)]
        fn edge_metrics_bundle_fields_are_exhaustive(bundle: &EdgeMetricsBundle) {
            let EdgeMetricsBundle { $($field: _),* } = bundle;
        }
    };
}

edge_metrics_bundle_fields!(
    envelopes_sent_total,
    envelopes_received_total,
    send_failures_total,
    verify_failures_total,
    durable_queue_depth,
    transport_bytes_in_total,
    transport_bytes_out_total,
    peer_reachability_ratio,
    inbound_dropped_low_trust,
    replication_round_outcomes_total,
    replication_inbound_backpressure_drops,
    replication_inbound_backpressure_drops_by_role,
    blob_route_refusals,
    blob_serve_refusals,
    blob_scoped_carriers,
    link_pool_links,
    link_pool_max_per_destination,
    link_pool_closed_by_reason,
    inbound_links,
    outbound_links,
    inbound_link_closed_by_reason,
    blob_pull_sources,
    blob_pull_refusals,
    blob_dag_phases,
    blob_dag_chunks,
    delivery_receipts,
    bootstrap_door_outcomes,
    transport_inbound_drops,
    first_contact_outcomes,
    replication_routed_to_responder_total,
    replication_routed_to_initiator_total,
    replication_reply_dropped_total,
    announce_intake_evictions,
    link_before_binding,
    announce_queue_drop_first_seen,
    channel_first_skipped_over_cap,
    announce_to_binding_ms_last,
    withholds_by_reason,
    recent_withholds,
    replication_envelopes_served_total,
    apply_refusals_by_kind,
    key_apply_refusals_by_reason,
    attestation_apply_refusals_by_reason,
    apply_refusals_by_class,
    replication_applied_total,
    replication_duplicate_total,
    removal_delivery,
    replication_round_duration_seconds,
    sweep_permit_wait_seconds,
);

#[cfg(test)]
mod liveness_tests {
    //! CIRISEdge#547 — the store-free liveness stamp.
    use super::{EdgeMetrics, RoundOutcome};
    use std::sync::atomic::Ordering;

    /// Before any round completes the answer is "nothing since boot" — a
    /// distinct state from "a round completed at the epoch", which a bare
    /// timestamp would conflate.
    #[test]
    fn no_completed_round_reads_as_zero_not_a_stale_timestamp() {
        let m = EdgeMetrics::default();
        assert_eq!(m.last_round_completed_unix(), 0);
    }

    /// A terminated round stamps progress, whatever its outcome. A round that
    /// ended badly still proves the runtime is turning — which is the question
    /// this answers, and the reason it is not gated on success.
    #[test]
    fn any_terminated_round_stamps_progress() {
        let m = EdgeMetrics::default();
        m.inc_round_outcome(RoundOutcome::Completed);
        assert!(m.last_round_completed_unix() > 0);
    }

    /// The subtle one. The stamp advances MONOTONICALLY: a clock stepping
    /// backwards (NTP correction, a VM restored from a snapshot) must never make
    /// progress look older than it is, because "no progress for N seconds" is the
    /// entire signal and an inflated N is a false alarm on a healthy node —
    /// which is how a liveness probe gets muted by its own operators.
    #[test]
    fn a_backwards_clock_cannot_age_the_stamp() {
        let m = EdgeMetrics::default();
        let future = 4_000_000_000u64;
        m.last_round_completed_unix.store(future, Ordering::Relaxed);
        // A stamp taken "now" is far in the past relative to that value.
        m.inc_round_outcome(RoundOutcome::Completed);
        assert_eq!(
            m.last_round_completed_unix(),
            future,
            "fetch_max must keep the newer stamp; a regressing clock must not age it"
        );
    }
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

#[cfg(test)]
mod p0_telemetry_tests {
    //! CIRISEdge P0 telemetry (CIRISServer `FSD/UNIFIED_TELEMETRY.md` §4):
    //! the two duration histograms and the flat projection's parity.
    use super::{
        EdgeMetrics, EdgeMetricsBundle, EDGE_METRICS_BUNDLE_FIELDS,
        REPLICATION_ROUND_DURATION_BUCKETS_SECONDS, SWEEP_PERMIT_WAIT_BUCKETS_SECONDS,
    };
    use crate::replication::EnvelopeKind;
    use std::time::Duration;

    /// Known round durations land in the right `le` buckets (cumulative),
    /// the count and the exact sum, per kind, and reach the snapshot.
    #[test]
    fn round_durations_land_in_their_buckets_per_kind() {
        let m = EdgeMetrics::new();
        // 0.05 → le 0.1; 0.1 (on the bound) → le 0.1; 3 → le 5;
        // 301 → +Inf only.
        for ms in [50, 100, 3_000, 301_000] {
            m.observe_round_duration(EnvelopeKind::Attestation, Duration::from_millis(ms));
        }
        m.observe_round_duration(EnvelopeKind::Key, Duration::from_secs(20));
        let snap = m.snapshot();
        let att = &snap.replication_round_duration_seconds[&EnvelopeKind::Attestation];
        assert_eq!(att.bounds, REPLICATION_ROUND_DURATION_BUCKETS_SECONDS);
        // le:      0.1 0.5 1  5  15 60 300 +Inf
        assert_eq!(att.cumulative, vec![2, 2, 2, 3, 3, 3, 3, 4]);
        assert_eq!(att.count, 4);
        assert!(
            (att.sum_seconds - 304.15).abs() < 1e-9,
            "{}",
            att.sum_seconds
        );
        let key = &snap.replication_round_duration_seconds[&EnvelopeKind::Key];
        assert_eq!(key.cumulative, vec![0, 0, 0, 0, 0, 1, 1, 1]);
        assert_eq!(
            key.buckets().last(),
            Some(&("+Inf".to_string(), 1)),
            "the +Inf bucket is the count"
        );
        assert!(
            !snap
                .replication_round_duration_seconds
                .contains_key(&EnvelopeKind::Revocation),
            "a kind with no rounds has no series"
        );
    }

    /// Permit waits land in their buckets; an empty histogram snapshots as
    /// all-zero buckets (present, not absent).
    #[test]
    fn sweep_permit_waits_land_in_their_buckets() {
        let m = EdgeMetrics::new();
        let empty = m.snapshot().sweep_permit_wait_seconds;
        assert_eq!(empty.bounds, SWEEP_PERMIT_WAIT_BUCKETS_SECONDS);
        assert_eq!(empty.cumulative, vec![0; 6]);
        assert_eq!(empty.count, 0);
        for ms in [0, 5, 20, 2_000, 60_000] {
            m.observe_sweep_permit_wait(Duration::from_millis(ms));
        }
        let snap = m.snapshot().sweep_permit_wait_seconds;
        // le:     0.01 0.1 1 5 30 +Inf
        assert_eq!(snap.cumulative, vec![2, 3, 3, 4, 4, 5]);
        assert_eq!(snap.count, 5);
        assert!((snap.sum_seconds - 62.025).abs() < 1e-9);
        let labels: Vec<String> = snap.buckets().into_iter().map(|(le, _)| le).collect();
        assert_eq!(labels, ["0.01", "0.1", "1", "5", "30", "+Inf"]);
    }

    /// PARITY (the UniFFI side): every bundle field is a key of the flat
    /// projection, on an EMPTY bundle — a field nothing has recorded into
    /// is still projected, so "absent" can never be confused with "zero".
    /// `EDGE_METRICS_BUNDLE_FIELDS` is tied to the struct at compile time.
    #[test]
    fn flatten_projects_every_bundle_field_even_when_empty() {
        let flat = EdgeMetricsBundle::default().flatten();
        let missing: Vec<&&str> = EDGE_METRICS_BUNDLE_FIELDS
            .iter()
            .filter(|f| !flat.counters.contains_key(**f) && !flat.gauges.contains_key(**f))
            .collect();
        assert!(missing.is_empty(), "flatten() omits: {missing:?}");
    }

    /// The flat projection carries labelled detail and totals.
    #[test]
    fn flatten_carries_labels_totals_and_histograms() {
        let m = EdgeMetrics::new();
        m.inc_durable_queue(super::DeliveryClass::Durable);
        m.inc_durable_queue(super::DeliveryClass::Durable);
        m.inc_link_before_binding();
        m.observe_round_duration(EnvelopeKind::Attestation, Duration::from_millis(700));
        m.observe_sweep_permit_wait(Duration::from_millis(50));
        let flat = m.snapshot().flatten();
        assert_eq!(flat.counters["durable_queue_depth"], 2);
        assert_eq!(flat.counters["durable_queue_depth.durable"], 2);
        assert_eq!(flat.counters["link_before_binding"], 1);
        assert_eq!(flat.counters["replication_round_duration_seconds"], 1);
        assert_eq!(
            flat.counters["replication_round_duration_seconds.attestation.bucket.0.5"],
            0
        );
        assert_eq!(
            flat.counters["replication_round_duration_seconds.attestation.bucket.1"],
            1
        );
        assert_eq!(
            flat.counters["replication_round_duration_seconds.attestation.count"],
            1
        );
        assert!(
            (flat.gauges["replication_round_duration_seconds.attestation.sum"] - 0.7).abs() < 1e-9
        );
        assert_eq!(flat.counters["sweep_permit_wait_seconds"], 1);
        assert_eq!(flat.counters["sweep_permit_wait_seconds.bucket.0.1"], 1);
        assert_eq!(flat.counters["sweep_permit_wait_seconds.bucket.+Inf"], 1);
    }

    /// CIRISEdge#809 — clones are one bag; two `new()`s are two, even with
    /// equal counts.
    #[test]
    fn is_same_bag_tells_a_clone_from_a_twin() {
        let a = EdgeMetrics::new();
        assert!(a.is_same_bag(&a.clone()));
        assert!(!a.is_same_bag(&EdgeMetrics::new()));
    }
}

#[cfg(test)]
mod link_pool_gauge_tests {
    use super::EdgeMetrics;

    /// CIRISEdge#819 (Codex on #821) — two transports sharing one metrics bag
    /// each keep their own pool sizes: the total is their sum and the
    /// per-destination figure their max, and one transport's pass (here, its
    /// pool emptying) never wipes the other's. With one shared value the last
    /// writer won, so this read 0 / 0 after transport 2's empty pass.
    #[test]
    fn pool_gauges_aggregate_across_transports_819() {
        let m = EdgeMetrics::new();
        m.set_link_pool_size(1, 5, 3);
        m.set_link_pool_size(2, 4, 2);
        assert_eq!(m.link_pool_links(), 9);
        assert_eq!(m.link_pool_max_per_destination(), 3);
        m.set_link_pool_size(2, 0, 0);
        let b = m.snapshot();
        assert_eq!(b.link_pool_links, 5, "transport 1's lanes still count");
        assert_eq!(b.link_pool_max_per_destination, 3);
        m.set_link_pool_size(1, 0, 0);
        assert_eq!(m.snapshot().link_pool_links, 0);
    }
}
